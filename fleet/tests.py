import copy
import json
import time
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from .alias_sync import alias_plan, execute_alias_plan
from .auth import SubjectOIDCBackend
from .models import Alias, AuditEvent, Firewall, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError, OPNsenseClient, flatten
from .reconcile import plan_for, validate_snapshot

EMPTY = {"schema_version": 1, "rules": [], "aliases": []}

class FleetTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="One", base_url="https://one.example.test", credential_prefix="ONE")
        self.other = Firewall.objects.create(name="Two", base_url="https://two.example.test", credential_prefix="TWO")
        self.interface = LogicalInterface.objects.create(name="VL10")
        for fw, local in [(self.fw, "opt2"), (self.other, "opt4")]:
            InterfaceMapping.objects.create(firewall=fw, logical_interface=self.interface, device_interface=local)
            Snapshot.objects.create(firewall=fw, data=copy.deepcopy(EMPTY))
        self.rule = Rule.objects.create(name="DNS", interface=self.interface, protocol="UDP", destination_port="53")

    def test_logical_interfaces_translate_per_device(self):
        self.assertEqual(plan_for(self.fw)["operations"][0]["payload"]["interface"], "opt2")
        self.assertEqual(plan_for(self.other)["operations"][0]["payload"]["interface"], "opt4")

    def test_scope_defaults_all_and_can_select_none_or_one(self):
        self.assertTrue(self.rule.applies_to(self.other))
        self.rule.scope = "selected"; self.rule.save()
        self.assertEqual(plan_for(self.fw)["operations"], [])
        self.rule.firewalls.add(self.fw)
        self.assertEqual(len(plan_for(self.fw)["operations"]), 1)
        self.assertEqual(plan_for(self.other)["operations"], [])

    def test_missing_mapping_blocks_entire_plan(self):
        self.fw.interface_mappings.all().delete()
        plan = plan_for(self.fw)
        self.assertIn("missing interface mapping", plan["errors"][0])
        self.assertEqual(plan["operations"], [])

    def test_logical_network_references_translate(self):
        self.rule.source = "@VL10:net"; self.rule.destination = "@VL10:ip"; self.rule.save()
        rule = plan_for(self.other)["operations"][0]["payload"]
        self.assertEqual(rule["source_net"], "opt4")
        self.assertEqual(rule["destination_net"], "opt4ip")

    def test_alias_order_and_duplicate_content_are_not_drift(self):
        Alias.objects.create(name="DNS", content="10.0.0.2\n10.0.0.1\n10.0.0.1")
        snapshot = self.fw.snapshots.first()
        snapshot.data["aliases"] = [{"name": "DNS", "type": "host", "content": "10.0.0.1\n10.0.0.2"}]
        snapshot.save()
        item = next(i for i in plan_for(self.fw)["items"] if i["kind"] == "alias")
        self.assertEqual(item["status"], "in_sync")

    def test_alias_scope_exclusion_blocks_reference(self):
        alias = Alias.objects.create(name="DNS", content="10.0.0.1", scope="selected")
        alias.firewalls.add(self.fw)
        self.rule.destination = "DNS"; self.rule.save()
        self.assertTrue(plan_for(self.other)["errors"])
        self.assertFalse(plan_for(self.fw)["errors"])

    def test_nested_alias_cycle_is_blocked(self):
        Alias.objects.create(name="A", content="B")
        Alias.objects.create(name="B", content="A")
        self.assertIn("Alias dependency cycle detected.", plan_for(self.fw)["errors"])

    def test_nested_aliases_are_created_dependency_first(self):
        Alias.objects.create(name="AParent", content="ZChild")
        Alias.objects.create(name="ZChild", content="10.0.0.1")
        ops = alias_plan(self.fw)["operations"]
        self.assertEqual([op["payload"]["name"] for op in ops], ["ZChild", "AParent"])

    def test_sequence_conflicts_block_plan(self):
        Rule.objects.create(name="Conflict", interface=self.interface, sequence=self.rule.sequence)
        self.assertTrue(plan_for(self.fw)["errors"])
        self.assertFalse(plan_for(self.fw)["operations"])

    def test_local_rules_preserved_and_retired_rules_reported(self):
        data = copy.deepcopy(EMPTY)
        data["rules"] = [dict(description="Manual rule", interface="wan", sequence="1"),
                         dict(description="[opnmanager:gone] Retired", interface="wan", sequence="2")]
        Snapshot.objects.create(firewall=self.fw, data=data)
        statuses = [i["status"] for i in plan_for(self.fw)["items"]]
        self.assertIn("local_only", statuses)
        self.assertIn("out_of_scope", statuses)
        self.assertFalse(any(op["action"] == "delete" for op in plan_for(self.fw)["operations"]))

    def test_rule_drift_fields_and_duplicate_marker(self):
        payload = plan_for(self.fw)["operations"][0]["payload"]
        data = copy.deepcopy(EMPTY)
        data["rules"] = [{**payload, "action": "block"}]
        snapshot = Snapshot.objects.create(firewall=self.fw, data=data)
        item = plan_for(self.fw)["items"][0]
        self.assertEqual(item["changes"], [{"field": "action", "actual": "block", "desired": "pass"}])
        snapshot.data["rules"].append(payload); snapshot.save()
        self.assertTrue(plan_for(self.fw)["errors"])

    def test_no_snapshot_and_disabled_device_block(self):
        self.fw.snapshots.all().delete()
        self.assertTrue(plan_for(self.fw)["errors"])
        self.other.enabled = False; self.other.save()
        self.assertEqual(plan_for(self.other)["operations"], [])

    def test_https_origins_only(self):
        for url in ["http://one.test", "https://user:pass@one.test", "https://one.test/path", "https://one.test/?key=secret"]:
            self.fw.base_url = url
            with self.assertRaises(ValidationError): self.fw.full_clean()

    def test_snapshot_schema_rejects_partial_or_nested_data(self):
        for data in [{}, {"schema_version": 1, "rules": [], "aliases": [{}]}, {**EMPTY, "rules": [{"description": {}}]}]:
            with self.assertRaises(ValueError): validate_snapshot(data)

    def test_anonymous_and_unprivileged_views(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        user = get_user_model().objects.create_user("noaccess", password="Long-enough-passphrase")
        self.client.force_login(user)
        for url in ["/", f"/firewalls/{self.fw.pk}/", f"/firewalls/{self.fw.pk}/plan/"]:
            self.assertEqual(self.client.get(url).status_code, 403)

    def viewer(self):
        user = get_user_model().objects.create_user("viewer", password="Long-enough-passphrase")
        user.user_permissions.add(Permission.objects.get(codename="view_firewall"))
        self.client.force_login(user)
        return user

    def test_viewer_can_review_but_cannot_import_or_pull(self):
        self.viewer()
        for url in ["/", f"/firewalls/{self.fw.pk}/", f"/firewalls/{self.fw.pk}/plan/"]:
            self.assertEqual(self.client.get(url).status_code, 200)
        for action in ["import", "pull"]:
            self.assertEqual(self.client.post(f"/firewalls/{self.fw.pk}/{action}/").status_code, 403)

    def test_operator_import_audited_and_invalid_json_rejected(self):
        user = self.viewer()
        user.user_permissions.add(Permission.objects.get(codename="refresh_firewall"))
        url = f"/firewalls/{self.fw.pk}/import/"
        self.assertEqual(self.client.post(url, {"snapshot": SimpleUploadedFile("bad.json", b"broken")}).status_code, 400)
        self.assertEqual(self.client.post(url, {"snapshot": SimpleUploadedFile("good.json", json.dumps(EMPTY).encode())}).status_code, 302)
        self.assertTrue(AuditEvent.objects.filter(action="snapshot.import").exists())

    def test_alias_sync_rejects_changed_device_without_writes(self):
        Alias.objects.create(name="Shared", content="10.0.0.1")
        client = Mock()
        client.snapshot.return_value = {**EMPTY, "aliases": [{"name": "surprise", "type": "host", "content": "1.1.1.1"}]}
        with self.assertRaisesMessage(DeviceError, "Device aliases changed"):
            execute_alias_plan(self.fw, alias_plan(self.fw)["approval_sha256"], client, "test")
        client.save_alias.assert_not_called()

    def test_alias_sync_rejects_changed_policy_without_writes(self):
        alias = Alias.objects.create(name="Shared", content="10.0.0.1")
        plan = alias_plan(self.fw)
        alias.content = "10.0.0.2"; alias.save()
        client = Mock()
        with self.assertRaisesMessage(DeviceError, "Plan changed"):
            execute_alias_plan(self.fw, plan["approval_sha256"], client, "test")
        client.snapshot.assert_not_called()

    def test_alias_sync_upserts_reconfigures_and_verifies(self):
        Alias.objects.create(name="Shared", content="10.0.0.1")
        plan = alias_plan(self.fw)
        client = Mock()
        observed = {**EMPTY, "aliases": [{**plan["operations"][0]["payload"], "uuid": "a"}]}
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), observed]
        self.assertEqual(execute_alias_plan(self.fw, plan["approval_sha256"], client, "test"), 1)
        client.save_alias.assert_called_once()
        client.reconfigure_aliases.assert_called_once()
        self.assertTrue(AuditEvent.objects.filter(action="alias.sync.completed").exists())
        self.assertEqual(self.fw.snapshots.first().data, observed)

    def test_alias_sync_failure_records_partial_state(self):
        Alias.objects.create(name="Shared", content="10.0.0.1")
        client = Mock(); client.snapshot.return_value = copy.deepcopy(EMPTY)
        client.save_alias.side_effect = DeviceError("failed")
        with self.assertRaises(DeviceError):
            execute_alias_plan(self.fw, alias_plan(self.fw)["approval_sha256"], client, "test")
        client.reconfigure_aliases.assert_not_called()
        self.assertTrue(AuditEvent.objects.filter(action="alias.sync.failed").exists())

    @patch.dict("os.environ", {"ONE_API_KEY": "key", "ONE_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_real_adapter_paths_tls_and_option_normalization(self, session):
        session.return_value.get.side_effect = [Mock(status_code=200, json=lambda: {"filter": {"rules": {"rule": {"abc": {
            "description": "Rule", "interface": {"opt2": {"selected": 1}, "opt3": {"selected": 0}}, "sequence": "100"}}}}}),
            Mock(status_code=200, json=lambda: {"aliases": {"alias": []}})]
        client = OPNsenseClient(self.fw)
        data = client.snapshot()
        self.assertEqual(data["rules"][0]["interface"], "opt2")
        self.assertIs(session.return_value.verify, True)
        self.assertTrue(session.return_value.get.call_args_list[0].args[0].endswith("/api/firewall/filter/get"))
        self.assertFalse(session.return_value.get.call_args.kwargs["allow_redirects"])

    @patch.dict("os.environ", {"ONE_API_KEY": "key", "ONE_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_alias_save_uses_supported_payload(self, session):
        session.return_value.post.return_value = Mock(status_code=200, json=lambda: {"result": "saved"})
        OPNsenseClient(self.fw).save_alias({"action": "update", "remote_uuid": "uuid", "payload": {"name": "A"}})
        call = session.return_value.post.call_args
        self.assertTrue(call.args[0].endswith("/alias/set_item/uuid"))
        self.assertEqual(call.kwargs["json"], {"alias": {"name": "A"}})

@override_settings(OIDC_OP_TOKEN_ENDPOINT="https://id.test/token", OIDC_OP_USER_ENDPOINT="https://id.test/userinfo",
    OIDC_OP_JWKS_ENDPOINT="https://id.test/keys", OIDC_RP_CLIENT_ID="client", OIDC_RP_CLIENT_SECRET="test",
    OIDC_RP_SIGN_ALGO="RS256", OIDC_ISSUER="https://id.test")
class OIDCTests(TestCase):
    def setUp(self): self.backend = SubjectOIDCBackend()
    def test_subject_account_does_not_link_to_existing_email(self):
        get_user_model().objects.create_user("admin", email="same@example.test", is_superuser=True)
        claims = {"sub": "new", "email": "same@example.test", "email_verified": True}
        self.assertFalse(self.backend.filter_users_by_claims(claims).exists())
        user = self.backend.create_user(claims)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.has_usable_password())
        self.assertEqual(self.backend.get_username(claims), self.backend.get_username({**claims, "email": "new@example.test"}))
    def test_unverified_email_and_missing_subject_rejected(self):
        self.assertFalse(self.backend.verify_claims({"email": "a@example.test", "sub": "a"}))
        self.assertFalse(self.backend.verify_claims({"email": "a@example.test", "email_verified": True}))
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_issuer_audience_and_expiry_checked(self, verify):
        valid = {"iss": "https://id.test", "aud": "client", "sub": "one", "exp": time.time() + 300, "iat": time.time()}
        verify.return_value = valid
        self.assertEqual(self.backend.verify_token("test"), valid)
        for change in [{"iss": "wrong"}, {"aud": "wrong"}, {"exp": 1}, {"iat": time.time() + 1000}, {"azp": "wrong"}, {"sub": ""}]:
            verify.return_value = {**valid, **change}
            with self.assertRaises(SuspiciousOperation): self.backend.verify_token("test")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.get_userinfo")
    def test_userinfo_subject_must_match_id_token(self, get_info):
        get_info.return_value = {"sub": "another"}
        with self.assertRaises(SuspiciousOperation): self.backend.get_userinfo("a", "b", {"sub": "original"})

class LocalAccountTests(TestCase):
    def bootstrap(self):
        from io import StringIO
        from django.core.management import call_command
        output = StringIO()
        call_command("bootstrap_admin", stdout=output)
        text = output.getvalue()
        password = text.split("Temporary password: ")[1].splitlines()[0]
        return get_user_model().objects.get(username="admin"), password

    def test_bootstrap_creates_admin_and_forces_password_change(self):
        from .models import LocalAccountState
        user, password = self.bootstrap()
        self.assertTrue(user.is_superuser and user.is_staff)
        self.assertTrue(user.check_password(password))
        self.assertTrue(LocalAccountState.objects.get(user=user).must_change_password)
        response = self.client.post("/accounts/login/", {"username": "admin", "password": password}, follow=True)
        self.assertContains(response, "Set your password.")
        for url in ["/", "/admin/", "/settings/", "/firewalls/99/plan/"]:
            self.assertRedirects(self.client.get(url), "/accounts/password_change/", fetch_redirect_response=False)
        new_password = "A-different-password-with-entropy-7285!"
        response = self.client.post("/accounts/password_change/", {"old_password": password,
            "new_password1": new_password, "new_password2": new_password}, follow=True)
        self.assertContains(response, "Firewall inventory")
        self.assertFalse(LocalAccountState.objects.get(user=user).must_change_password)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password))
        self.assertContains(self.client.get("/settings/"), "Manage users")
        self.assertEqual(self.client.get("/admin/").status_code, 200)

    def test_setup_is_idempotent_and_never_prints_or_resets_existing_password(self):
        from io import StringIO
        from django.core.management import call_command
        user, password = self.bootstrap()
        original = user.password
        output = StringIO()
        call_command("bootstrap_admin", stdout=output)
        user.refresh_from_db()
        self.assertEqual(user.password, original)
        self.assertNotIn(password, output.getvalue())
        self.assertNotIn("Temporary password:", output.getvalue())

    def test_existing_ordinary_admin_user_is_never_promoted(self):
        from django.core.management import call_command, CommandError
        user = get_user_model().objects.create_user("admin", password="Ordinary-user-password")
        with self.assertRaisesMessage(CommandError, "already in use"):
            call_command("bootstrap_admin")
        user.refresh_from_db()
        self.assertFalse(user.is_superuser)

    def test_existing_nondefault_administrator_is_preserved(self):
        from io import StringIO
        from django.core.management import call_command
        get_user_model().objects.create_superuser("existing", password="Existing-admin-password")
        call_command("bootstrap_admin", stdout=StringIO())
        self.assertFalse(get_user_model().objects.filter(username="admin").exists())

    def test_same_weak_or_wrong_old_password_does_not_unlock(self):
        from .models import LocalAccountState
        user, password = self.bootstrap()
        self.client.force_login(user)
        for old, new in [(password, password), (password, "password"), ("wrong", "Strong-new-password-37498!")]:
            response = self.client.post("/accounts/password_change/", {"old_password": old,
                "new_password1": new, "new_password2": new})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.context["form"].errors)
            self.assertTrue(LocalAccountState.objects.get(user=user).must_change_password)

    def test_password_change_requires_csrf(self):
        from django.test import Client
        user, password = self.bootstrap()
        client = Client(enforce_csrf_checks=True)
        client.force_login(user)
        self.assertEqual(client.post("/accounts/password_change/", {"old_password": password}).status_code, 403)

    def test_settings_requires_login_and_hides_admin_links_for_viewers(self):
        self.assertEqual(self.client.get("/settings/").status_code, 302)
        user = get_user_model().objects.create_user("basic")
        self.client.force_login(user)
        response = self.client.get("/settings/")
        self.assertContains(response, "Change your password")
        self.assertNotContains(response, 'href="/admin/auth/user/"')
        self.assertNotContains(response, 'href="/admin/fleet/firewall/"')

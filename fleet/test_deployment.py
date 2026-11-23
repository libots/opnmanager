import copy
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from .alias_patterns import expand_entry
from .deployment import deployment_plan, execute_deployment
from .models import Alias, AuditEvent, Firewall, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError, OPNsenseClient
from .testing import make_rule

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}


class ExtendedPatterns(SimpleTestCase):
    def test_requested_bracketed_cidr(self):
        self.assertEqual(
            expand_entry("fd5b:47d4:9272:[20-22]35::/64", "network"),
            [f"fd5b:47d4:9272:{v}35::/64" for v in ["20", "21", "22"]],
        )
        self.assertEqual(expand_entry("10.20-22.35.0/24", "network"), [f"10.{v}.35.0/24" for v in range(20, 23)])

    def test_digit_wildcards_prefix_masking_and_invalid_brackets(self):
        self.assertEqual(len(expand_entry("2001:db8:20x5::/64", "network")), 16)
        self.assertEqual(expand_entry("2001:db8::[20-22]35/64", "network"), ["2001:db8::/64"])
        for value in ["fd00:[22-20]35::/64", "fd00:[0000-ffff]35::/64", "fd00:[20-22::/64", "fd00:xxxx:xxxx::/64"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                expand_entry(value, "network")


class DeploymentTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=logical, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        self.first = make_rule(logical, name="First", sequence=100)
        self.second = make_rule(logical, name="Second", sequence=200)

    def test_only_selected_rule_is_saved_applied_and_verified(self):
        plan = deployment_plan(self.fw)
        row = plan["rows"][0]
        client = Mock()
        client.snapshot.side_effect = [
            copy.deepcopy(EMPTY),
            {**EMPTY, "rules": [{**row["operation"]["payload"], "uuid": "remote"}]},
        ]
        self.assertEqual(execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test"), 1)
        client.save_rule.assert_called_once_with(row["operation"])
        client.apply_rules.assert_called_once()
        self.assertTrue(AuditEvent.objects.filter(action="rules.deploy.completed").exists())
        self.assertIn("--- firewall/current", [line["text"] for line in row["diff"]])

    def test_stale_device_or_policy_and_unknown_selection_rejected(self):
        plan = deployment_plan(self.fw)
        client = Mock()
        client.snapshot.return_value = {
            **EMPTY,
            "rules": [{"description": "Other", "interface": "lan", "sequence": "300"}],
        }
        with self.assertRaisesMessage(DeviceError, "Device configuration changed"):
            execute_deployment(self.fw, plan["approval_sha256"], [str(self.first.pk)], client, "test")
        client.save_rule.assert_not_called()
        with self.assertRaisesMessage(DeviceError, "Select one"):
            execute_deployment(self.fw, plan["approval_sha256"], ["unknown"], client, "test")
        self.first.name = "Changed"
        self.first.save()
        with self.assertRaisesMessage(DeviceError, "plan changed"):
            execute_deployment(self.fw, plan["approval_sha256"], [str(self.first.pk)], client, "test")

    def test_failed_apply_is_audited_and_does_not_claim_success(self):
        plan = deployment_plan(self.fw)
        client = Mock()
        client.snapshot.return_value = copy.deepcopy(EMPTY)
        client.apply_rules.side_effect = DeviceError("failed")
        with self.assertRaises(DeviceError):
            execute_deployment(self.fw, plan["approval_sha256"], [str(self.first.pk)], client, "test")
        self.assertTrue(AuditEvent.objects.filter(action="rules.deploy.failed").exists())
        self.assertFalse(AuditEvent.objects.filter(action="rules.deploy.completed").exists())

    def test_missing_definitions_block_rules(self):
        Alias.objects.create(name="Required", content="10.0.0.1")
        self.first.source = "Required"
        self.first.save()
        rows = deployment_plan(self.fw)["rows"]
        self.assertTrue(rows[0]["errors"])
        self.assertFalse(rows[1]["errors"])

    def test_gui_permission_confirmation_and_shared_navigation(self):
        user = get_user_model().objects.create_superuser("admin-test", password="Test-only-password")
        self.client.force_login(user)
        response = self.client.get(f"/firewalls/{self.fw.pk}/deploy/")
        self.assertContains(response, "Fleet: Review &amp; Deploy")
        self.assertContains(response, "ui.js")
        self.assertContains(self.client.get("/admin/"), "opn-sidebar")
        self.assertContains(self.client.get("/admin/fleet/alias/add/"), "admin-shell.css")
        basic = get_user_model().objects.create_user("basic")
        self.client.force_login(basic)
        self.assertEqual(self.client.post(f"/firewalls/{self.fw.pk}/deploy/").status_code, 403)

    def test_conflicting_selected_positions_fail_before_device_access(self):
        self.second.sequence = self.first.sequence
        self.second.save()
        plan = deployment_plan(self.fw)
        client = Mock()
        with self.assertRaisesMessage(DeviceError, "unblocked"):
            execute_deployment(
                self.fw, plan["approval_sha256"], [str(self.first.pk), str(self.second.pk)], client, "test"
            )
        client.snapshot.assert_not_called()

    def test_sequence_shared_with_unselected_manager_rule_blocks_both(self):
        self.second.sequence = self.first.sequence
        self.second.save()
        rows = {row["name"]: row for row in deployment_plan(self.fw)["rows"]}
        self.assertIn("Sequence 100 on lan is also used by manager rule Second.", " ".join(rows["First"]["errors"]))
        self.assertIn("also used by manager rule First", " ".join(rows["Second"]["errors"]))

    def test_sequence_shared_with_device_local_rule_blocks(self):
        snapshot = self.fw.snapshots.first()
        snapshot.data = {
            **EMPTY,
            "rules": [{"description": "Local SSH", "interface": "lan,opt1", "sequence": "0100", "uuid": "l"}],
        }
        snapshot.save()
        rows = {row["name"]: row for row in deployment_plan(self.fw)["rows"]}
        self.assertIn("also used by device rule Local SSH", " ".join(rows["First"]["errors"]))
        self.assertFalse(rows["Second"]["errors"])

    def test_rules_own_current_device_row_is_not_a_collision(self):
        payload = next(r for r in deployment_plan(self.fw)["rows"] if r["name"] == "First")["operation"]["payload"]
        snapshot = self.fw.snapshots.first()
        snapshot.data = {**EMPTY, "rules": [{**payload, "action": "block", "uuid": "remote"}]}
        snapshot.save()
        row = next(r for r in deployment_plan(self.fw)["rows"] if r["name"] == "First")
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["operation"]["action"], "update")

    def test_second_deployment_is_blocked_while_first_holds_lock(self):
        from .locks import device_write_lock

        plan = deployment_plan(self.fw)
        client = Mock()
        with device_write_lock(self.fw.pk, "A rule deployment"):
            with self.assertRaisesMessage(DeviceError, "A rule deployment is already running"):
                execute_deployment(self.fw, plan["approval_sha256"], [str(self.first.pk)], client, "test")
        client.snapshot.assert_not_called()

    def test_every_device_write_workflow_shares_one_lock(self):
        from .alias_sync import execute_alias_plan
        from .definition_sync import execute_definition_plan
        from .locks import device_write_lock
        from .models import VirtualIP
        from .system_management import execute_vip_apply, execute_vip_delete, firmware_action

        client = Mock()
        vip = VirtualIP.objects.create(name="Service", interface=self.first.interfaces.get(), network="192.0.2.5/24")
        calls = {
            "alias sync": lambda: execute_alias_plan(self.fw, "x", client, "test"),
            "definition sync": lambda: execute_definition_plan(self.fw, "x", client, "test"),
            "firmware": lambda: firmware_action(self.fw, "check", client, "test"),
            "rule deploy": lambda: execute_deployment(self.fw, "x", [], client, "test"),
            "vip apply": lambda: execute_vip_apply(self.fw, vip, "x", client, "test"),
            "vip delete": lambda: execute_vip_delete(self.fw, "x", "x", client, "test"),
        }
        with device_write_lock(self.fw.pk, "A rule deployment"):
            for name, call in calls.items():
                with self.subTest(name), self.assertRaisesMessage(DeviceError, "A rule deployment is already running"):
                    call()
        self.assertEqual(client.method_calls, [])
        other = Firewall.objects.create(name="Other", base_url="https://other.test", credential_prefix="OTHER")
        with device_write_lock(self.fw.pk, "A rule deployment"), device_write_lock(other.pk, "A firmware request"):
            pass  # different firewalls never contend

    def test_lock_is_released_after_failure(self):
        from .locks import device_write_lock

        with self.assertRaises(RuntimeError), device_write_lock(self.fw.pk, "A rule deployment"):
            raise RuntimeError
        with device_write_lock(self.fw.pk, "A firmware request"):
            pass

    @patch.dict("os.environ", {"TEST_API_KEY": "key", "TEST_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_rule_write_and_apply_endpoints(self, session):
        session.return_value.post.return_value = Mock(status_code=200, json=lambda: {"result": "saved"})
        client = OPNsenseClient(self.fw)
        client.save_rule({"action": "update", "remote_uuid": "uuid", "payload": {"description": "Test"}})
        self.assertTrue(session.return_value.post.call_args.args[0].endswith("/filter/set_rule/uuid"))
        session.return_value.post.return_value = Mock(status_code=200, json=lambda: {"status": "OK\n"})
        client.apply_rules()
        self.assertTrue(session.return_value.post.call_args.args[0].endswith("/filter/apply"))


class ProtectedApplyTests(TestCase):
    """Rule deploys always run inside an OPNsense savepoint with automatic rollback."""

    def setUp(self):
        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=logical, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        self.rule = make_rule(logical, name="First", sequence=100)
        self.plan = deployment_plan(self.fw)
        self.row = self.plan["rows"][0]

    def device(self, readback):
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.return_value = "1700000000.1234"
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), readback]
        return client

    def run_deploy(self, client):
        return execute_deployment(self.fw, self.plan["approval_sha256"], [self.row["id"]], client, "test")

    def test_savepoint_precedes_writes_and_rollback_is_cancelled_after_verified_readback(self):
        client = self.device({**EMPTY, "rules": [{**self.row["operation"]["payload"], "uuid": "remote"}]})
        self.run_deploy(client)
        names = [call[0] for call in client.method_calls]
        self.assertEqual(names, ["snapshot", "savepoint", "save_rule", "apply_rules", "snapshot", "cancel_rollback"])
        client.apply_rules.assert_called_once_with("1700000000.1234")
        client.cancel_rollback.assert_called_once_with("1700000000.1234")
        client.revert.assert_not_called()
        self.assertIn("1700000000.1234", AuditEvent.objects.get(action="rules.deploy.completed").detail)

    def test_readback_mismatch_reverts_and_never_confirms(self):
        client = self.device(copy.deepcopy(EMPTY))
        with self.assertRaisesMessage(DeviceError, "previous rule configuration was restored"):
            self.run_deploy(client)
        client.revert.assert_called_once_with("1700000000.1234")
        client.cancel_rollback.assert_not_called()
        self.assertFalse(Snapshot.objects.filter(source="api").exists())

    def test_lost_connectivity_after_apply_relies_on_automatic_rollback(self):
        client = self.device(None)
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), DeviceError("connection failed.")]
        client.revert.side_effect = DeviceError("connection failed.")
        with self.assertRaisesMessage(DeviceError, "restore the previous rules automatically within 60 seconds"):
            self.run_deploy(client)
        client.cancel_rollback.assert_not_called()
        self.assertTrue(AuditEvent.objects.filter(action="rules.deploy.failed").exists())

    def test_failed_confirmation_is_reported_as_unconfirmed(self):
        client = self.device({**EMPTY, "rules": [{**self.row["operation"]["payload"], "uuid": "remote"}]})
        client.cancel_rollback.side_effect = DeviceError("could not be confirmed")
        with self.assertRaisesMessage(DeviceError, "could not be confirmed"):
            self.run_deploy(client)
        self.assertTrue(AuditEvent.objects.filter(action="rules.deploy.unconfirmed").exists())
        self.assertFalse(AuditEvent.objects.filter(action="rules.deploy.completed").exists())

    def test_missing_savepoint_blocks_before_any_write(self):
        client = self.device(None)
        client.savepoint.side_effect = DeviceError("No rule writes were made")
        with self.assertRaises(DeviceError):
            self.run_deploy(client)
        client.save_rule.assert_not_called()
        client.apply_rules.assert_not_called()

    @patch.dict("os.environ", {"TEST_API_KEY": "key", "TEST_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_savepoint_endpoints(self, session):
        post = session.return_value.post
        client = OPNsenseClient(self.fw)
        post.return_value = Mock(status_code=200, json=lambda: {"revision": "1700000000.1234"})
        self.assertEqual(client.savepoint(), "1700000000.1234")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/savepoint"))
        post.return_value = Mock(status_code=200, json=lambda: {"status": "ok"})
        client.apply_rules("1700000000.1234")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/apply/1700000000.1234"))
        client.cancel_rollback("1700000000.1234")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/cancel_rollback/1700000000.1234"))
        client.revert("1700000000.1234")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/revert/1700000000.1234"))
        post.return_value = Mock(status_code=200, json=lambda: {})
        with self.assertRaisesMessage(DeviceError, "No rule writes were made"):
            client.savepoint()


class PlannerQueryTests(TestCase):
    """Planning cost must not grow with the number of rules (it used to be quadratic)."""

    def test_deployment_plan_query_count_is_independent_of_rule_count(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        from .models import Category, FirewallGroup, InterfaceGroup

        fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        group = FirewallGroup.objects.create(name="Branches")
        group.firewalls.add(fw)
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=fw, logical_interface=logical, device_interface="lan")
        interface_group = InterfaceGroup.objects.create(name="ALL_LAN")
        interface_group.members.add(logical)
        category = Category.objects.create(name="Ops")
        Snapshot.objects.create(firewall=fw, data=copy.deepcopy(EMPTY))

        def add_rules(start, count):
            for i in range(start, start + count):
                Alias.objects.create(name=f"A{i}", content="10.0.0.1", scope="selected").firewall_groups.add(group)
                rule = make_rule(logical, name=f"R{i}", sequence=i + 1, source=f"A{i}")
                rule.categories.add(category)
                rule.interface_groups.add(interface_group)

        def count_queries():
            with CaptureQueriesContext(connection) as queries:
                deployment_plan(fw)
            return len(queries)

        add_rules(0, 5)
        small = count_queries()
        add_rules(5, 40)
        self.assertEqual(count_queries(), small)


class RetireRuleTests(TestCase):
    def setUp(self):
        from .rule_identity import short_marker

        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        self.logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.logical, device_interface="lan")
        self.kept = make_rule(self.logical, name="Kept", sequence=100)
        gone = make_rule(self.logical, name="Gone", sequence=200)
        self.gone_tag = "Gone " + short_marker(gone.pk)
        gone.delete()
        self.device_rules = [
            {"description": self.gone_tag, "interface": "lan", "sequence": "200", "uuid": "gone-uuid"},
            {"description": "Local rule", "interface": "lan", "sequence": "300", "uuid": "local-uuid"},
        ]
        Snapshot.objects.create(firewall=self.fw, data={**EMPTY, "rules": copy.deepcopy(self.device_rules)})

    def test_only_orphaned_managed_rules_are_offered(self):
        plan = deployment_plan(self.fw)
        self.assertEqual([c["uuid"] for c in plan["retire"]], ["gone-uuid"])
        self.assertEqual([o["id"] for o in plan["retire"][0]["options"]], ["disable:gone-uuid", "delete:gone-uuid"])

    def test_targeted_rule_that_fails_to_plan_is_never_offered(self):
        from .rule_identity import short_marker

        unmapped = LogicalInterface.objects.create(name="UNMAPPED")
        broken = make_rule(unmapped, name="Broken", sequence=400)
        snapshot = self.fw.snapshots.first()
        snapshot.data["rules"].append(
            {"description": "Broken " + short_marker(broken.pk), "uuid": "b", "interface": "", "sequence": "400"}
        )
        snapshot.save()
        plan = deployment_plan(self.fw)
        self.assertNotIn("b", [c["uuid"] for c in plan["retire"]])

    def test_scoped_away_rule_is_offered(self):
        from .rule_identity import short_marker

        self.kept.scope = "selected"
        self.kept.save()
        snapshot = self.fw.snapshots.first()
        snapshot.data["rules"].append(
            {"description": "Kept " + short_marker(self.kept.pk), "uuid": "k", "interface": "lan", "sequence": "100"}
        )
        snapshot.save()
        self.assertIn("k", [c["uuid"] for c in deployment_plan(self.fw)["retire"]])

    def run_retire(self, choice, readback_rules):
        plan = deployment_plan(self.fw)
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.return_value = "1.1"
        client.snapshot.side_effect = [
            {**EMPTY, "rules": copy.deepcopy(self.device_rules)},
            {**EMPTY, "rules": readback_rules},
        ]
        execute_deployment(self.fw, plan["approval_sha256"], [choice], client, "test")
        return client

    def test_delete_is_protected_and_verified(self):
        client = self.run_retire("delete:gone-uuid", [self.device_rules[1]])
        client.delete_rule.assert_called_once_with("gone-uuid")
        client.save_rule.assert_not_called()
        client.cancel_rollback.assert_called_once_with("1.1")

    def test_disable_is_verified_and_failed_readback_reverts(self):
        with self.assertRaisesMessage(DeviceError, "readback did not match"):
            self.run_retire("disable:gone-uuid", copy.deepcopy(self.device_rules))
        client = self.run_retire("disable:gone-uuid", [{**self.device_rules[0], "enabled": "0"}, self.device_rules[1]])
        client.disable_rule.assert_called_once_with("gone-uuid")
        # Once disabled, only deletion is offered.
        self.assertEqual([o["id"] for o in deployment_plan(self.fw)["retire"][0]["options"]], ["delete:gone-uuid"])

    def test_both_actions_for_one_rule_are_refused(self):
        plan = deployment_plan(self.fw)
        with self.assertRaisesMessage(DeviceError, "not both"):
            execute_deployment(
                self.fw, plan["approval_sha256"], ["disable:gone-uuid", "delete:gone-uuid"], Mock(), "test"
            )

    @patch.dict("os.environ", {"TEST_API_KEY": "key", "TEST_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_retire_endpoints(self, session):
        post = session.return_value.post
        client = OPNsenseClient(self.fw)
        post.return_value = Mock(status_code=200, json=lambda: {"result": "deleted"})
        client.delete_rule("u")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/del_rule/u"))
        post.return_value = Mock(status_code=200, json=lambda: {"result": "Disabled", "changed": True})
        client.disable_rule("u")
        self.assertTrue(post.call_args.args[0].endswith("/api/firewall/filter/toggle_rule/u/0"))
        post.return_value = Mock(status_code=200, json=lambda: {"result": "not found"})
        with self.assertRaises(DeviceError):
            client.delete_rule("u")

    def test_deploy_page_renders_retire_choices(self):
        self.client.force_login(get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1"))
        response = self.client.get(f"/firewalls/{self.fw.pk}/deploy/")
        self.assertContains(response, "Retire managed rules")
        self.assertContains(response, 'value="delete:gone-uuid"')


class SnapshotRetentionTests(TestCase):
    def test_only_newest_snapshots_are_kept_per_firewall(self):
        from django.test import override_settings

        fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        other = Firewall.objects.create(name="Other", base_url="https://other.test", credential_prefix="OTHER")
        with override_settings(SNAPSHOT_RETENTION=3):
            Snapshot.objects.create(firewall=other, data=copy.deepcopy(EMPTY))
            created = [Snapshot.objects.create(firewall=fw, data=copy.deepcopy(EMPTY)).pk for _ in range(5)]
        self.assertEqual(sorted(fw.snapshots.values_list("pk", flat=True)), created[-3:])
        self.assertEqual(fw.snapshots.first().pk, created[-1])
        self.assertEqual(other.snapshots.count(), 1)

    def test_zero_keeps_everything(self):
        from django.test import override_settings

        fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        with override_settings(SNAPSHOT_RETENTION=0):
            for _ in range(4):
                Snapshot.objects.create(firewall=fw, data=copy.deepcopy(EMPTY))
        self.assertEqual(fw.snapshots.count(), 4)


class InterfaceWarningDeployTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        lan = LogicalInterface.objects.create(name="LAN")
        self.dmz = LogicalInterface.objects.create(name="DMZ")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=lan, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        self.rule = Rule.objects.create(name="Both", sequence=100)
        self.rule.interfaces.set([lan, self.dmz])

    def device(self, payload):
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.return_value = "1.1"
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), {**EMPTY, "rules": [{**payload, "uuid": "r"}]}]
        return client

    def test_warned_rule_needs_explicit_confirmation(self):
        plan = deployment_plan(self.fw)
        row = plan["rows"][0]
        self.assertTrue(plan["has_warnings"])
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["operation"]["payload"]["interface"], "lan")
        client = self.device(row["operation"]["payload"])
        with self.assertRaisesMessage(DeviceError, "Confirm the warnings for Both"):
            execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test")
        client.save_rule.assert_not_called()
        execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test", accept_warnings=True)
        client.save_rule.assert_called_once()

    def test_deploy_page_leaves_warned_rules_unchecked_and_offers_confirmation(self):
        self.client.force_login(get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1"))
        response = self.client.get(f"/firewalls/{self.fw.pk}/deploy/")
        self.assertContains(response, "interface DMZ is not mapped on this firewall")
        self.assertContains(response, 'name="accept_warnings"')
        self.assertNotContains(response, f'value="{self.rule.pk}" checked')


class ConfigHistoryFallbackTests(TestCase):
    """OPNsense 26.7 removed filter savepoints; pushes fall back to configuration history only when allowed."""

    def setUp(self):
        from .opnsense_errors import SavepointUnsupported

        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=logical, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        make_rule(logical, name="First", sequence=100)
        self.unsupported = SavepointUnsupported("no filter savepoint API. No rule writes were made.")

    def device(self, readback_ok=True):
        plan = deployment_plan(self.fw)
        row = plan["rows"][0]
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.side_effect = self.unsupported
        client.latest_config_backup.return_value = "config-1763712000.1234.xml"
        readback = {**EMPTY, "rules": [{**row["operation"]["payload"], "uuid": "r"}]} if readback_ok else EMPTY
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), copy.deepcopy(readback)]
        return plan, row, client

    def test_missing_savepoint_stops_before_writes_and_is_remembered(self):
        from .deployment import rollback_mode

        self.assertEqual(rollback_mode(self.fw), "unknown")
        plan, row, client = self.device()
        with self.assertRaisesMessage(DeviceError, "Push without automatic rollback"):
            execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test")
        client.save_rule.assert_not_called()
        client.apply_rules.assert_not_called()
        self.assertEqual(rollback_mode(self.fw), "config_history")
        self.assertEqual(deployment_plan(self.fw)["rollback"], "config_history")

    def test_allowed_push_records_history_entry_and_skips_rollback_calls(self):
        plan, row, client = self.device()
        execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test", allow_unprotected=True)
        names = [call[0] for call in client.method_calls]
        self.assertEqual(
            names, ["snapshot", "savepoint", "latest_config_backup", "save_rule", "apply_rules", "snapshot"]
        )
        client.apply_rules.assert_called_once_with(None)
        client.cancel_rollback.assert_not_called()
        detail = AuditEvent.objects.get(action="rules.deploy.completed").detail
        self.assertIn("config history config-1763712000.1234.xml, no automatic rollback", detail)

    def test_failed_verification_restores_configuration_history(self):
        plan, row, client = self.device(readback_ok=False)
        with self.assertRaisesMessage(DeviceError, "restored from configuration history (config-1763712000.1234.xml)"):
            execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test", allow_unprotected=True)
        client.revert_config.assert_called_once_with("config-1763712000.1234.xml")
        client.revert.assert_not_called()

    def test_failed_history_revert_tells_the_person_how_to_recover(self):
        plan, row, client = self.device(readback_ok=False)
        client.revert_config.side_effect = DeviceError("unreachable")
        with self.assertRaisesMessage(DeviceError, "System: Configuration: History"):
            execute_deployment(self.fw, plan["approval_sha256"], [row["id"]], client, "test", allow_unprotected=True)

    def test_deploy_page_offers_opt_in_once_mode_is_known(self):
        from .models import DeviceInventory

        self.client.force_login(get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1"))
        self.assertNotContains(self.client.get(f"/firewalls/{self.fw.pk}/deploy/"), 'name="allow_unprotected"')
        DeviceInventory.objects.create(firewall=self.fw, data={"rule_rollback": "config_history"})
        response = self.client.get(f"/firewalls/{self.fw.pk}/deploy/")
        self.assertContains(response, "No automatic rollback on this firewall.")
        self.assertContains(response, 'name="allow_unprotected"')

    @patch.dict("os.environ", {"TEST_API_KEY": "key", "TEST_API_SECRET": "secret"})
    @patch("fleet.opnsense.requests.Session")
    def test_client_detects_removed_savepoint_and_uses_backup_api(self, session):
        from .opnsense_errors import SavepointUnsupported

        client = OPNsenseClient(self.fw)
        session.return_value.post.return_value = Mock(status_code=404)
        with self.assertRaises(SavepointUnsupported) as caught:
            client.savepoint()
        self.assertIn("No rule writes were made", str(caught.exception))
        self.assertNotIn("uncertain", str(caught.exception))
        session.return_value.get.return_value = Mock(
            status_code=200, json=lambda: {"items": [{"id": "config-2.xml"}, {"id": "config-1.xml"}]}
        )
        self.assertEqual(client.latest_config_backup(), "config-2.xml")
        self.assertTrue(session.return_value.get.call_args.args[0].endswith("/api/core/backup/backups/this"))
        session.return_value.post.side_effect = [
            Mock(status_code=200, json=lambda: {"status": "reverted"}),
            Mock(status_code=200, json=lambda: {"status": "OK"}),
        ]
        client.revert_config("config-2.xml")
        urls = [call.args[0] for call in session.return_value.post.call_args_list[-2:]]
        self.assertTrue(urls[0].endswith("/api/core/backup/revert_backup/config-2.xml"))
        self.assertTrue(urls[1].endswith("/api/firewall/filter/apply"))
        session.return_value.get.return_value = Mock(status_code=200, json=lambda: {"items": []})
        with self.assertRaisesMessage(DeviceError, "no configuration history"):
            client.latest_config_backup()


class CombinedDeploymentTests(TestCase):
    """Definitions and rules reviewed on one page and applied by one job."""

    def setUp(self):
        from .models import Category

        self.Category = Category
        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=logical, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        Alias.objects.create(name="Needed", content="10.0.0.1")
        self.rule = make_rule(logical, name="Uses alias", sequence=100, source="Needed")

    def client_for(self, plan, *, categories=()):
        """A device that accepts the definitions, then the rule, reading each back."""
        definitions = plan["definitions"]["operations"]
        synced = {
            **EMPTY,
            "aliases": [
                {**op["payload"], "uuid": "a-" + op["payload"]["name"]} for op in definitions if op["kind"] == "alias"
            ],
            "categories": [{"name": name, "color": color, "uuid": "c-" + name} for name, color in categories],
        }
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.return_value = "1.1"
        pushed = []
        client.save_rule.side_effect = lambda op: pushed.append(op["payload"])
        # Definition preflight, definition readback, rule preflight, rule readback.
        states = iter([copy.deepcopy(EMPTY), copy.deepcopy(synced), copy.deepcopy(synced), None])

        def snapshot():
            value = next(states)
            return value if value is not None else {**synced, "rules": [{**pushed[0], "uuid": "r"}]}

        client.snapshot.side_effect = snapshot
        return client, pushed

    def test_rule_waiting_on_definitions_is_selectable_and_deploys_after_them(self):
        from .deployment import combined_plan, execute_combined

        plan = combined_plan(self.fw)
        row = plan["rules"]["rows"][0]
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["after_definitions"], "alias Needed")
        client, pushed = self.client_for(plan)
        result = execute_combined(self.fw, plan["approval_sha256"], [row["id"]], client, "test")
        self.assertEqual(result, (1, 1))
        names = [call[0] for call in client.mock_calls]
        self.assertLess(names.index("save_definition"), names.index("save_rule"))
        self.assertEqual(pushed[0]["source_net"], "Needed")
        self.assertTrue(AuditEvent.objects.filter(action="definitions.sync.completed").exists())
        self.assertTrue(AuditEvent.objects.filter(action="rules.deploy.completed").exists())

    def test_new_category_is_resolved_to_its_uuid_after_synchronization(self):
        from .deployment import combined_plan, execute_combined

        category = self.Category.objects.create(name="Web", color="aabbcc")
        self.rule.categories.add(category)
        plan = combined_plan(self.fw)
        row = plan["rules"]["rows"][0]
        self.assertEqual(row["operation"]["payload"]["categories"], "@category:Web")
        client, pushed = self.client_for(plan, categories=[("Web", "aabbcc")])
        self.assertEqual(execute_combined(self.fw, plan["approval_sha256"], [row["id"]], client, "test"), (2, 1))
        self.assertEqual(pushed[0]["categories"], "c-Web")

    def test_without_sync_permission_dependent_rules_stay_blocked(self):
        from .deployment import combined_plan, execute_combined

        plan = combined_plan(self.fw, include_definitions=False)
        self.assertIsNone(plan["definitions"])
        self.assertTrue(plan["rules"]["rows"][0]["errors"])
        client = Mock()
        with self.assertRaisesMessage(DeviceError, "unblocked"):
            execute_combined(
                self.fw, plan["approval_sha256"], [str(self.rule.pk)], client, "test", include_definitions=False
            )
        client.snapshot.assert_not_called()

    def test_stale_plan_and_unprotected_push_fail_before_any_write(self):
        from .deployment import _remember_rollback, combined_plan, execute_combined

        plan = combined_plan(self.fw)
        Alias.objects.filter(name="Needed").update(content="10.0.0.2")
        client = Mock()
        with self.assertRaisesMessage(DeviceError, "Deployment plan changed"):
            execute_combined(self.fw, plan["approval_sha256"], [str(self.rule.pk)], client, "test")
        _remember_rollback(self.fw, "config_history")
        plan = combined_plan(self.fw)
        with self.assertRaisesMessage(DeviceError, "Nothing was written"):
            execute_combined(self.fw, plan["approval_sha256"], [str(self.rule.pk)], client, "test")
        client.snapshot.assert_not_called()
        client.save_definition.assert_not_called()

    def test_definitions_alone_and_rule_errors_do_not_block_them(self):
        from .deployment import combined_plan, execute_combined

        make_rule(self.rule.interfaces.get(), name="Clash", sequence=100)
        plan = combined_plan(self.fw)
        self.assertEqual(plan["definitions"]["errors"], [])
        self.assertTrue(all(row["errors"] for row in plan["rules"]["rows"]))
        client, _ = self.client_for(plan)
        self.assertEqual(execute_combined(self.fw, plan["approval_sha256"], [], client, "test"), (1, 0))
        client.save_rule.assert_not_called()
        Rule.objects.all().delete()
        Alias.objects.all().delete()
        with self.assertRaisesMessage(DeviceError, "Nothing selected"):
            execute_combined(self.fw, combined_plan(self.fw)["approval_sha256"], [], Mock(), "test")

    def test_review_page_posts_one_combined_job(self):
        from .deployment import combined_plan
        from .models import DeviceJob

        user = get_user_model().objects.create_superuser("admin-test", password="Test-only-password")
        self.client.force_login(user)
        page = self.client.get(f"/firewalls/{self.fw.pk}/deploy/")
        self.assertContains(page, "1. Supporting definitions")
        self.assertContains(page, "Needed")
        self.client.post(
            f"/firewalls/{self.fw.pk}/deploy/",
            {
                "acknowledge": "yes",
                "approval_sha256": combined_plan(self.fw)["approval_sha256"],
                "selected_rules": [str(self.rule.pk)],
            },
        )
        job = DeviceJob.objects.get()
        self.assertTrue(job.params["combined"])
        self.assertTrue(job.params["include_definitions"])

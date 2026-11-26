import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from .forms import CategoryForm, RuleForm
from .jobs import run_pending
from .models import (
    DeviceInventory,
    DeviceJob,
    DNSProfile,
    Firewall,
    InterfaceMapping,
    LogicalInterface,
    VirtualIP,
)
from .oidc_storage import load
from .opnsense import DeviceError
from .reconcile import plan_for
from .system_management import firmware_action, read_vips, refresh_firmware, refresh_inventory, vip_plan
from .testing import make_rule

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}


class SystemManagementTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="One", base_url="https://one.test")
        self.logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.logical, device_interface="lan")
        self.admin = get_user_model().objects.create_superuser("test-admin", password="Test-only-password")
        self.client.force_login(self.admin)

    def test_inventory_reads_addresses_and_device_protocol_catalog_without_secrets(self):
        client = Mock()
        client.post.return_value = {
            "rows": [
                {
                    "identifier": "lan",
                    "device": "igc0",
                    "description": "Clients",
                    "ipv4": [{"ipaddr": "192.0.2.1/24"}],
                    "ipv6": [],
                    "status": "up",
                    "config": {"password": "do-not-store"},
                }
            ]
        }
        client.get.return_value = {
            "rule": {"protocol": {"tcp": {"value": "TCP", "selected": 0}, "ospf": {"value": "OSPF", "selected": 0}}}
        }
        inventory = refresh_inventory(self.fw, client)
        self.assertEqual(inventory.data["interfaces"][0]["ipv4"], "192.0.2.1/24")
        self.assertNotIn("do-not-store", str(inventory.data))
        self.assertIn(["OSPF", "OSPF"], inventory.data["protocols"])
        self.assertIn(("OSPF", "OSPF"), list(RuleForm().fields["protocol"].widget.choices))
        self.assertContains(self.client.get("/interfaces/"), "192.0.2.1/24")
        self.assertContains(self.client.get("/fleet/logical-interfaces/"), "192.0.2.1/24")

    def test_matrix_empty_selection_and_mapping_edit(self):
        self.assertNotContains(self.client.get("/interfaces/?selection=1"), "<th>One</th>", html=False)
        self.client.post("/fleet/mappings/save/", {f"map_{self.fw.pk}_{self.logical.pk}": "opt2"})
        self.assertEqual(self.fw.interface_mappings.get().device_interface, "opt2")

    def test_protocol_origin_and_builtin_rule_options(self):
        from .models import Snapshot

        Snapshot.objects.create(firewall=self.fw, data=EMPTY)
        rule = make_rule(self.logical, name="Origin", source="bogons", destination="(self)")
        rule.origin_interfaces.add(self.logical)
        op = next(op for op in plan_for(self.fw)["operations"] if op["kind"] == "rule")
        self.assertEqual(op["payload"]["received-on"], "lan")
        form = RuleForm()
        self.assertIn("bogonsv6", str(form["source"]))
        self.assertIn("https", str(form["destination_port"]))
        self.assertContains(self.client.get("/admin/fleet/rule/add/"), "Organisation")
        self.assertContains(self.client.get("/admin/fleet/rule/add/"), "Interface (origin)")

    def test_category_picker_round_trips_hex_value(self):
        form = CategoryForm({"name": "Color", "color": "#abcdef", "scope": "all"})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().color, "abcdef")
        self.assertIn('type="color"', str(form["color"]))

    def test_firmware_check_is_async_and_busy_rejected(self):
        client = Mock()
        client.get.return_value = {"status": "ready"}
        client.post.return_value = {"status": "ok", "msg_uuid": "job"}
        job = firmware_action(self.fw, "check", client, "test")
        self.assertEqual(job.status, "running")
        client.post.assert_called_once_with("/api/core/firmware/check", {})
        with self.assertRaisesMessage(DeviceError, "existing firmware task"):
            firmware_action(self.fw, "check", client, "test")
        job.status = "finished"
        job.save()
        client.get.return_value = {"status": "busy"}
        with self.assertRaisesMessage(DeviceError, "already has"):
            firmware_action(self.fw, "check", client, "test")

    def test_stable_update_requires_current_offer_and_accepted_does_not_mean_finished(self):
        client = Mock()
        client.get.side_effect = [{"status": "update"}, {"status": "ready"}]
        client.post.return_value = {"status": "ok", "msg_uuid": "job"}
        job = firmware_action(self.fw, "update", client, "test")
        self.assertEqual(job.status, "running")
        client.post.assert_called_once_with("/api/core/firmware/update", {})
        client.get.side_effect = [{"status": "ok", "product": {"product_version": "26.1"}}, {}, {"status": "done"}]
        refresh_firmware(self.fw, client)
        job.refresh_from_db()
        self.assertEqual(job.status, "finished")
        self.assertIn("not a guarantee", job.message)

    def test_firmware_failures_and_confirmation(self):
        client = Mock()
        client.get.return_value = {"status": "none"}
        with self.assertRaisesMessage(DeviceError, "successful firmware check"):
            firmware_action(self.fw, "update", client, "test")
        client.post.assert_not_called()
        with patch("fleet.management_views.OPNsenseClient") as factory:
            self.client.post("/system/firmware/action/", {"action": "update", "selected_firewalls": [self.fw.pk]})
            factory.assert_not_called()

    def test_dns_profiles_preserve_domain_order(self):
        profile = DNSProfile(name="Domains", search_domains="corp.example\nlab.example")
        profile.full_clean()
        profile.save()
        self.assertEqual(profile.search_domains, "corp.example\nlab.example")
        with self.assertRaises(ValidationError):
            DNSProfile(name="Invalid", search_domains="invalid domain").full_clean()
        self.assertContains(self.client.get("/system/settings/general/"), "not deployed")

    def test_oidc_ui_is_write_only_encrypted_restart_configuration(self):
        payload = {
            "enabled": "on",
            "issuer": "https://id.test",
            "client_id": "manager",
            "client_secret": "test-client-secret",
            "authorization_endpoint": "https://id.test/auth",
            "token_endpoint": "https://id.test/token",
            "user_endpoint": "https://id.test/user",
            "jwks_endpoint": "https://id.test/keys",
        }
        with tempfile.TemporaryDirectory() as directory, override_settings(DATA_DIR=Path(directory)):
            response = self.client.post("/settings/authentication/", payload, follow=True)
            self.assertContains(response, "Restart the manager")
            self.assertNotContains(response, "test-client-secret")
            raw = (Path(directory) / ".oidc-settings.json").read_text()
            self.assertNotIn("test-client-secret", raw)
            self.assertEqual(load(Path(directory))["OIDC_RP_CLIENT_SECRET"], "test-client-secret")
            self.assertEqual((Path(directory) / ".oidc-settings.json").stat().st_mode & 0o077, 0)

    def test_virtual_ip_mapping_identity_and_secret_redaction(self):
        desired = VirtualIP.objects.create(name="Service", interface=self.logical, network="192.0.2.5/24")
        plan = vip_plan(self.fw, desired, [])
        self.assertEqual(plan["payload"]["interface"], "lan")
        client = Mock()
        client.get.return_value = {
            "vip": {
                "vip": {
                    "remote": {
                        "interface": "lan",
                        "mode": "ipalias",
                        "password": "never-show",
                        "descr": plan["payload"]["descr"],
                        "subnet": "192.0.2.5",
                        "subnet_bits": "24",
                    }
                }
            }
        }
        rows = read_vips(client)
        self.assertNotIn("password", rows[0])
        desired.name = "Renamed"
        desired.save()
        self.assertEqual(vip_plan(self.fw, desired, rows)["uuid"], "remote")
        with self.assertRaises(ValidationError):
            VirtualIP(name="Bad", interface=self.logical, network="192.0.2.5").full_clean()

    def test_menu_routes_keep_account_controls_and_permission_boundaries(self):
        for url in [
            "/",
            "/fleet/deployment/",
            "/fleet/logical-interfaces/",
            "/interfaces/",
            "/interfaces/virtual-ips/",
            "/system/firmware/status/",
            "/system/firmware/updates/",
            "/settings/authentication/",
        ]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, url)
            self.assertContains(response, 'data-menu="system"')
            self.assertContains(response, "Change password")
        basic = get_user_model().objects.create_user("basic")
        self.client.force_login(basic)
        self.assertEqual(
            self.client.post("/system/firmware/action/", {"action": "update", "confirm": "yes"}).status_code, 403
        )
        self.assertEqual(self.client.get("/interfaces/").status_code, 403)
        self.assertEqual(self.client.get("/settings/authentication/").status_code, 302)

    def test_vip_adoption_and_signed_delete_stale_checks(self):
        import uuid

        uid = str(uuid.uuid4())
        rows = [
            {
                "uuid": uid,
                "subnet": "192.0.2.5",
                "subnet_bits": "24",
                "interface": "lan",
                "mode": "ipalias",
                "descr": "Existing",
            }
        ]
        DeviceInventory.objects.create(firewall=self.fw, data={"vips": rows})
        response = self.client.post(f"/interfaces/virtual-ips/{self.fw.pk}/adopt/{uid}/")
        self.assertEqual(response.status_code, 302)
        desired = VirtualIP.objects.get()
        self.assertEqual(vip_plan(self.fw, desired, rows)["uuid"], uid)
        self.assertContains(self.client.get("/interfaces/virtual-ips/"), "192.0.2.5")
        with patch("fleet.management_views.OPNsenseClient") as factory:
            device = factory.return_value
            device.get.return_value = {
                "vip": {"vip": {uid: {key: value for key, value in rows[0].items() if key != "uuid"}}}
            }
            preview = self.client.get(f"/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/")
            self.assertEqual(preview.status_code, 200)
            token = preview.context["approval"]
            device.get.return_value = {
                "vip": {
                    "vip": {uid: {"subnet": "192.0.2.6", "subnet_bits": "24", "interface": "lan", "mode": "ipalias"}}
                }
            }
            response = self.client.post(f"/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/", {"approval": token})
            job = DeviceJob.objects.get(kind=DeviceJob.VIP_DELETE)
            self.assertRedirects(response, f"/jobs/{job.pk}/")
            run_pending(client_factory=lambda fw: device)
            device.post.assert_not_called()
            job.refresh_from_db()
            self.assertEqual(job.status, DeviceJob.FAILED)
            self.assertIn("changed", job.message)

    def test_vip_delete_runs_in_worker_and_verifies_absence(self):
        import uuid

        uid = str(uuid.uuid4())
        row = {"subnet": "192.0.2.5", "subnet_bits": "24", "interface": "lan", "mode": "ipalias", "descr": "Old"}
        with patch("fleet.management_views.OPNsenseClient") as factory:
            device = factory.return_value
            device.get.return_value = {"vip": {"vip": {uid: row}}}
            token = self.client.get(f"/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/").context["approval"]
            device.get.reset_mock()
            self.client.post(f"/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/", {"approval": token})
            # The request only queues the deletion; it neither reads nor writes the device.
            device.get.assert_not_called()
            device.post.assert_not_called()
            device.get.side_effect = [{"vip": {"vip": {uid: row}}}, {"vip": {"vip": []}}]
            device.post.side_effect = [{"result": "deleted"}, {"status": "ok"}]
            (job,) = run_pending(client_factory=lambda fw: device)
        self.assertEqual(job.status, DeviceJob.SUCCEEDED, job.message)
        self.assertEqual(device.post.call_args_list[0].args[0], f"/api/interfaces/vip_settings/del_item/{uid}")
        self.assertEqual(DeviceInventory.objects.get(firewall=self.fw).data["vips"], [])
        self.assertContains(self.client.get(f"/jobs/{job.pk}/"), "Return to Virtual IPs")

    def test_vip_review_apply_verifies_network_and_interface(self):
        desired = VirtualIP.objects.create(name="Service", interface=self.logical, network="192.0.2.5/24")
        marker = f"[opnmanager-vip:{desired.pk}] Service"
        with patch("fleet.management_views.OPNsenseClient") as factory:
            device = factory.return_value
            device.get.return_value = {"vip": {"vip": {}}}
            response = self.client.get(f"/interfaces/virtual-ips/{self.fw.pk}/{desired.pk}/")
            token = response.context["approval"]
            device.get.side_effect = [
                {"vip": {"vip": {}}},
                {
                    "vip": {
                        "vip": {
                            "new": {
                                "subnet": "192.0.2.5",
                                "subnet_bits": "24",
                                "interface": "lan",
                                "mode": "ipalias",
                                "descr": marker,
                            }
                        }
                    }
                },
            ]
            device.post.side_effect = [{"result": "saved"}, {"status": "ok"}]
            response = self.client.post(f"/interfaces/virtual-ips/{self.fw.pk}/{desired.pk}/", {"approval": token})
            job = DeviceJob.objects.get(kind=DeviceJob.VIP_APPLY)
            self.assertRedirects(response, f"/jobs/{job.pk}/")
            device.post.assert_not_called()
            (job,) = run_pending(client_factory=lambda fw: device)
            self.assertEqual(job.status, DeviceJob.SUCCEEDED, job.message)
            self.assertEqual(device.post.call_count, 2)
            self.assertEqual(device.post.call_args_list[0].args[0], "/api/interfaces/vip_settings/add_item")
            from .models import AuditEvent

            self.assertTrue(AuditEvent.objects.filter(action="vip.applied").exists())


class FirmwareSummaryTests(TestCase):
    STATUS = {
        "status": "update",
        "status_msg": "There are 3 updates available.",
        "needs_reboot": "0",
        "product": {"product_version": "25.7.4", "product_latest": "25.7.5"},
        "upgrade_packages": [
            {"name": "opnsense", "current_version": "25.7.4", "new_version": "25.7.5"},
            {"name": "os-acme-client", "current_version": "4.9", "new_version": "4.10"},
            {"name": "curl", "current_version": "8.15.0", "new_version": "8.16.0"},
        ],
        "new_packages": [{"name": "os-new-dep", "version": "1.0"}],
    }
    INFO = {
        "plugin": [
            {"name": "os-acme-client", "version": "4.9", "installed": "1", "configured": "1"},
            {"name": "os-wireguard", "version": "2.0", "installed": "0"},
            {"name": "os-theme-cicada", "version": "1.38", "installed": "1", "configured": "0"},
        ]
    }

    def setUp(self):
        self.fw = Firewall.objects.create(name="Edge", base_url="https://edge.test", credential_prefix="EDGE")

    def test_summary_separates_plugin_updates_and_installed_plugins(self):
        from .system_management import firmware_summary, update_state

        summary = firmware_summary(self.STATUS, self.INFO)
        self.assertEqual([p["name"] for p in summary["core_updates"]], ["curl", "opnsense"])
        self.assertEqual([p["name"] for p in summary["plugin_updates"]], ["os-acme-client", "os-new-dep"])
        self.assertEqual(summary["latest"], "25.7.5")
        self.assertEqual([p["name"] for p in summary["plugins"]], ["os-acme-client", "os-theme-cicada"])
        self.assertTrue(summary["plugins"][1]["misconfigured"])
        self.assertEqual(update_state(summary), "updates")
        self.assertEqual(update_state(firmware_summary({"status": "none"})), "current")
        self.assertEqual(update_state(firmware_summary({"status": "none", "needs_reboot": "1"})), "reboot")
        self.assertEqual(update_state({}), "unknown")

    def test_refresh_keeps_status_when_the_plugin_list_is_forbidden(self):
        client = Mock()
        client.get.side_effect = [self.STATUS, self.INFO]
        refresh_firmware(self.fw, client)
        client.get.side_effect = [self.STATUS, DeviceError("forbidden")]
        safe = refresh_firmware(self.fw, client)
        self.assertEqual(len(safe["plugin_updates"]), 2)
        self.assertEqual(len(safe["plugins"]), 2)
        self.assertIn("earlier refresh", safe["plugins_error"])

    def test_overview_shows_update_and_plugin_status(self):
        from django.contrib.auth import get_user_model

        client = Mock()
        client.get.side_effect = [self.STATUS, self.INFO]
        refresh_firmware(self.fw, client)
        self.client.force_login(get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1"))
        page = self.client.get("/")
        self.assertContains(page, "2 packages · 2 plugins")
        self.assertContains(page, "<code>os-acme-client</code> 4.9 → 4.10", html=False)
        self.assertContains(page, "2 plugins installed")
        self.assertContains(page, "Check for updates")
        status = self.client.get("/system/firmware/status/")
        self.assertContains(status, "needs configuration")

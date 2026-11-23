from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from .definition_sync import definition_plan
from .models import AuditEvent, Firewall, InterfaceGroup, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError
from .reconcile import plan_for
from .testing import make_rule

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "groups": [], "categories": [], "interfaces": []}


class GroupPullTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Branch", base_url="https://branch.invalid")
        self.lan = LogicalInterface.objects.create(name="LAN")
        self.wan = LogicalInterface.objects.create(name="WAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.lan, device_interface="opt2")
        Snapshot.objects.create(firewall=self.fw, data=EMPTY)
        self.group = InterfaceGroup.objects.create(name="TRUSTED")
        self.group.members.set([self.lan, self.wan])
        self.user = get_user_model().objects.create_superuser("operator", password="Test-only-pass")
        self.client.force_login(self.user)

    def test_group_uses_available_members_without_changing_manager_membership(self):
        rule = Rule.objects.create(name="Group rule")
        rule.interface_groups.add(self.group)
        plan = plan_for(self.fw)
        self.assertFalse(plan["errors"])
        group = next(op for op in plan["operations"] if op["kind"] == "group")
        self.assertEqual(group["payload"]["members"], "opt2")
        self.assertEqual(
            next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]["interface"], "TRUSTED"
        )
        self.assertEqual(self.group.members.count(), 2)
        other = Firewall.objects.create(name="Other", base_url="https://other.invalid")
        InterfaceMapping.objects.create(firewall=other, logical_interface=self.wan, device_interface="opt4")
        Snapshot.objects.create(firewall=other, data=EMPTY)
        self.assertEqual(definition_plan(other)["operations"][0]["payload"]["members"], "opt4")

    def test_group_with_no_mapped_members_is_skipped_with_warning(self):
        self.fw.interface_mappings.all().delete()
        plan = definition_plan(self.fw)
        self.assertEqual(plan["errors"], [])
        self.assertTrue(any("TRUSTED has no members mapped" in warning for warning in plan["warnings"]))
        self.assertFalse(plan["operations"])

    def test_unmapped_interfaces_are_left_out_of_the_pushed_rule(self):
        rule = Rule.objects.create(name="Both")
        rule.interfaces.set([self.lan, self.wan])
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        payload = next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(payload["interface"], "opt2")
        self.assertIn("interface WAN is not mapped on this firewall", " ".join(plan["warnings"]))

    def test_unavailable_group_is_left_out_but_mapped_interface_kept(self):
        only_wan = InterfaceGroup.objects.create(name="WANONLY")
        only_wan.members.set([self.wan])
        rule = Rule.objects.create(name="Mixed")
        rule.interfaces.set([self.lan])
        rule.interface_groups.set([only_wan])
        plan = plan_for(self.fw)
        payload = next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(payload["interface"], "opt2")
        self.assertFalse(
            any(op["kind"] == "group" and op["payload"]["ifname"] == "WANONLY" for op in plan["operations"])
        )

    def exclude_group_from_this_firewall(self):
        other = Firewall.objects.create(name="Other", base_url="https://other.invalid")
        self.group.scope = "selected"
        self.group.save()
        self.group.firewalls.add(other)

    def test_rule_bound_only_to_an_excluded_group_is_skipped_with_warning(self):
        self.exclude_group_from_this_firewall()
        rule = Rule.objects.create(name="Group only")
        rule.interface_groups.add(self.group)
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        self.assertIn(
            "Rule Group only is not pushed to this firewall. None of its interfaces exist here: "
            "group TRUSTED is not deployed to Branch: its targets don't include this firewall.",
            " ".join(plan["warnings"]),
        )
        self.assertFalse(plan["operations"])

    def test_excluded_group_is_left_out_but_mapped_interface_kept(self):
        self.exclude_group_from_this_firewall()
        rule = Rule.objects.create(name="Mixed")
        rule.interfaces.set([self.lan])
        rule.interface_groups.add(self.group)
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        payload = next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(payload["interface"], "opt2")

    def test_rule_is_skipped_rather_than_widened_when_all_origins_are_missing(self):
        rule = Rule.objects.create(name="Origin")
        rule.interfaces.set([self.lan])
        rule.origin_interfaces.set([self.wan])
        plan = plan_for(self.fw)
        self.assertFalse([op for op in plan["operations"] if op["kind"] == "rule"])
        self.assertIn(
            "None of its origin interfaces exist here: interface WAN is not mapped", " ".join(plan["warnings"])
        )
        rule.origin_interfaces.add(self.lan)
        payload = next(op for op in plan_for(self.fw)["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(payload["received-on"], "opt2")

    def test_unmapped_logical_addresses_are_left_out_of_the_pushed_rule(self):
        LogicalInterface.objects.create(name="DMZ")
        make_rule(self.lan, name="Address", source="@WAN:net,@LAN:net,10.9.0.0/16", destination="@DMZ:ip,@LAN:ip")
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        payload = next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(payload["source_net"], "opt2,10.9.0.0/16")
        self.assertEqual(payload["destination_net"], "opt2ip")
        self.assertIn(
            "addresses @WAN:net, @DMZ:ip are not mapped on this firewall and are left out", " ".join(plan["warnings"])
        )

    def test_rule_is_skipped_rather_than_widened_when_an_address_field_empties(self):
        make_rule(self.lan, name="Address", source="@WAN:net", destination="@LAN:net")
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        self.assertFalse([op for op in plan["operations"] if op["kind"] == "rule"])
        self.assertIn("leaves its source or destination empty", " ".join(plan["warnings"]))

    def test_malformed_logical_address_still_blocks(self):
        make_rule(self.lan, name="Address", source="@WAN:subnet")
        self.assertIn("Invalid logical address @WAN:subnet.", plan_for(self.fw)["errors"])

    @patch("fleet.views.OPNsenseClient")
    def test_json_pull_updates_snapshot_mappings_and_audit(self, client):
        client.return_value.snapshot.return_value = {**EMPTY, "interfaces": [{"name": "opt4", "label": "WAN"}]}
        response = self.client.post(f"/firewalls/{self.fw.pk}/pull/", HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertIn("policy", response.json())
        self.assertEqual(self.fw.snapshots.count(), 2)
        self.assertTrue(self.fw.interface_mappings.filter(device_interface="opt4").exists())
        self.assertTrue(AuditEvent.objects.filter(action="snapshot.pull").exists())
        client.return_value.snapshot.assert_called_once_with()
        client.return_value.save_definition.assert_not_called()

    @patch("fleet.views.OPNsenseClient")
    def test_pull_failures_keep_snapshot_and_disabled_devices_are_skipped(self, client):
        client.return_value.snapshot.side_effect = DeviceError("Connection failed")
        response = self.client.post(f"/firewalls/{self.fw.pk}/pull/", HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["ok"])
        self.assertEqual(self.fw.snapshots.count(), 1)
        self.fw.enabled = False
        self.fw.save()
        client.reset_mock()
        response = self.client.post(f"/firewalls/{self.fw.pk}/pull/", HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 400)
        client.assert_not_called()

    @patch("fleet.views.OPNsenseClient")
    def test_table_fallback_returns_to_expected_page_and_prevents_open_redirect(self, client):
        client.return_value.snapshot.return_value = EMPTY
        url = f"/firewalls/{self.fw.pk}/pull/"
        for target, expected in [
            ("overview", "/"),
            ("deployment", "/fleet/deployment/"),
            ("https://example.invalid", f"/firewalls/{self.fw.pk}/"),
        ]:
            response = self.client.post(url, {"return_to": target})
            self.assertRedirects(response, expected, fetch_redirect_response=False)

    @patch("fleet.views.OPNsenseClient")
    def test_pull_requires_permission_and_post(self, client):
        user = get_user_model().objects.create_user("viewer", is_staff=True)
        user.user_permissions.add(Permission.objects.get(content_type__app_label="fleet", codename="view_firewall"))
        self.client.force_login(user)
        self.assertEqual(
            self.client.post(f"/firewalls/{self.fw.pk}/pull/", HTTP_ACCEPT="application/json").status_code, 403
        )
        for page in ("/", "/fleet/deployment/"):
            self.assertNotContains(self.client.get(page), "data-pull-form")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(f"/firewalls/{self.fw.pk}/pull/").status_code, 405)
        client.assert_not_called()
        for page in ("/", "/fleet/deployment/"):
            response = self.client.get(page)
            self.assertContains(response, "data-pull-all")
            self.assertContains(response, "data-pull-form")

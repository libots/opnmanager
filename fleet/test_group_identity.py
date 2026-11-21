import copy
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from .definition_sync import definition_plan, execute_definition_plan
from .import_rules import import_rules
from .models import AuditEvent, Firewall, InterfaceGroup, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError, OPNsenseClient
from .reconcile import plan_for
from .rule_identity import short_marker, tagged

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}


class GroupIdentityTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Branch", base_url="https://branch.invalid")
        self.lan = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.lan, device_interface="opt2")
        self.snapshot = Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))

    def device_groups(self, *rows):
        self.snapshot.data["groups"] = list(rows)
        self.snapshot.save()

    def group(self, name="trusted", **fields):
        group = InterfaceGroup.objects.create(name=name, **fields)
        group.members.set([self.lan])
        return group

    def group_op(self, plan):
        return next(op for op in plan["operations"] if op["kind"] == "group")

    def row(self, group, **fields):
        return {
            "uuid": "g1",
            "ifname": group.name,
            "members": "opt2",
            "descr": tagged(group.description, group.uid),
            "sequence": "0",
            "nogroup": "0",
            **fields,
        }

    def test_pushed_group_carries_its_tag_and_gui_grouping_choice(self):
        group = self.group(description="Internal", no_gui_group=True)
        payload = self.group_op(plan_for(self.fw))["payload"]
        self.assertEqual(payload["descr"], "Internal " + short_marker(group.uid))
        self.assertEqual(payload["nogroup"], "1")
        group.no_gui_group = False
        group.save()
        self.assertEqual(self.group_op(plan_for(self.fw))["payload"]["nogroup"], "0")

    def test_gui_grouping_change_updates_the_device_group(self):
        group = self.group(no_gui_group=True)
        self.device_groups(self.row(group))
        op = self.group_op(plan_for(self.fw))
        self.assertEqual((op["action"], op["remote_uuid"], op["payload"]["nogroup"]), ("update", "g1", "1"))

    def test_untagged_group_with_the_same_name_is_adopted(self):
        group = self.group()
        self.device_groups({"uuid": "g1", "ifname": "trusted", "members": "opt2", "descr": "", "nogroup": "0"})
        op = self.group_op(plan_for(self.fw))
        self.assertEqual((op["action"], op["remote_uuid"]), ("update", "g1"))
        self.assertEqual(op["payload"]["descr"], tagged("", group.uid))

    def test_rename_updates_the_tagged_device_group_and_rule_addresses(self):
        group = self.group()
        rule = Rule.objects.create(name="Internal", source="trusted,10.0.0.0/8", destination="trusted")
        rule.interface_groups.add(group)
        self.device_groups(self.row(group))
        group.name = "inside"
        group.save()
        rule.refresh_from_db()
        self.assertEqual((rule.source, rule.destination), ("inside,10.0.0.0/8", "inside"))
        plan = plan_for(self.fw)
        self.assertEqual(plan["errors"], [])
        op = self.group_op(plan)
        self.assertEqual((op["action"], op["remote_uuid"], op["payload"]["ifname"]), ("update", "g1", "inside"))
        rule_payload = next(op for op in plan["operations"] if op["kind"] == "rule")["payload"]
        self.assertEqual(rule_payload["interface"], "inside")

    def test_rename_onto_an_existing_device_group_is_blocked(self):
        group = self.group(name="inside")
        self.device_groups(
            self.row(group, ifname="trusted"),
            {"uuid": "g2", "ifname": "inside", "members": "opt3", "descr": "", "nogroup": "0"},
        )
        self.assertTrue(any("would collide" in error for error in plan_for(self.fw)["errors"]))

    def test_deleted_manager_group_is_offered_for_removal_and_removed_only_when_selected(self):
        gone = self.group(name="old")
        stale = self.row(gone)
        local = {"uuid": "g2", "ifname": "mine", "members": "opt2", "descr": "local", "nogroup": "0"}
        self.device_groups(stale, local)
        gone.delete()
        plan = definition_plan(self.fw)
        self.assertEqual([(c["kind"], c["name"], c["errors"]) for c in plan["removals"]], [("group", "old", [])])
        untouched = Mock()
        untouched.snapshot.return_value = copy.deepcopy(self.snapshot.data)
        self.assertEqual(execute_definition_plan(self.fw, plan["approval_sha256"], untouched, "test"), 0)
        untouched.delete_definition.assert_not_called()
        client = Mock()
        client.snapshot.side_effect = [copy.deepcopy(self.snapshot.data), {**EMPTY, "groups": [local]}]
        self.assertEqual(execute_definition_plan(self.fw, plan["approval_sha256"], client, "test", remove=["g1"]), 1)
        client.delete_definition.assert_called_once_with("group", "g1")
        client.reconfigure_definitions.assert_called_once_with({"group"})
        self.assertTrue(AuditEvent.objects.filter(action="group.removed").exists())

    def test_readback_still_listing_the_group_fails(self):
        gone = self.group(name="old")
        self.device_groups(self.row(gone))
        gone.delete()
        plan = definition_plan(self.fw)
        client = Mock()
        client.snapshot.side_effect = [copy.deepcopy(self.snapshot.data), copy.deepcopy(self.snapshot.data)]
        with self.assertRaisesMessage(DeviceError, "still lists a definition selected for removal"):
            execute_definition_plan(self.fw, plan["approval_sha256"], client, "test", remove=["g1"])

    def test_removal_is_blocked_while_a_device_rule_uses_the_group(self):
        gone = self.group(name="old")
        self.device_groups(self.row(gone))
        self.snapshot.data["rules"] = [{"uuid": "r1", "description": "Local", "interface": "old", "sequence": "1"}]
        self.snapshot.save()
        gone.delete()
        plan = definition_plan(self.fw)
        self.assertIn("Still used by rule Local", plan["removals"][0]["errors"][0])
        with self.assertRaisesMessage(DeviceError, "Select only unblocked aliases and groups"):
            execute_definition_plan(self.fw, plan["approval_sha256"], Mock(), "test", remove=["g1"])

    def test_group_no_longer_targeting_the_firewall_is_offered(self):
        group = self.group(name="old")
        self.device_groups(self.row(group))
        group.scope = InterfaceGroup.SELECTED
        group.save()
        self.assertEqual([c["name"] for c in definition_plan(self.fw)["removals"]], ["old"])

    def test_untagged_device_groups_are_never_offered(self):
        self.device_groups({"uuid": "g1", "ifname": "mine", "members": "opt2", "descr": "", "nogroup": "0"})
        self.assertEqual(definition_plan(self.fw)["removals"], [])

    def test_import_keeps_gui_grouping_and_strips_the_tag(self):
        source = self.group(name="trusted", description="Internal")
        row = self.row(source, nogroup="1")
        source.delete()
        self.device_groups(row)
        self.snapshot.data["rules"] = [{"uuid": "r1", "description": "Allow", "interface": "trusted", "sequence": "1"}]
        self.snapshot.save()
        import_rules(self.snapshot, ["0"], "all", [])
        group = InterfaceGroup.objects.get(name="trusted")
        self.assertEqual((group.description, group.no_gui_group), ("Internal", True))

    def test_review_page_lists_group_removals_unchecked(self):
        gone = self.group(name="old")
        self.device_groups(self.row(gone))
        gone.delete()
        self.client.force_login(get_user_model().objects.create_superuser("operator", password="Test-only-pass"))
        response = self.client.get(f"/firewalls/{self.fw.pk}/sync/")
        self.assertContains(response, 'name="remove_definition" value="g1" aria-label="Remove group old"')
        self.assertNotContains(response, "checked")

    def test_group_form_offers_the_gui_grouping_option(self):
        self.client.force_login(get_user_model().objects.create_superuser("operator", password="Test-only-pass"))
        response = self.client.get("/admin/fleet/interfacegroup/add/")
        self.assertContains(response, "(no) GUI groups")
        self.assertContains(response, "Prevent grouping these members in the interfaces menu section")


class GroupDeleteClientTests(TestCase):
    def test_delete_group_uses_the_group_endpoint(self):
        client = OPNsenseClient.__new__(OPNsenseClient)
        with patch.object(OPNsenseClient, "post", return_value={"result": "deleted"}) as post:
            client.delete_definition("group", "g/1")
        post.assert_called_once_with("/api/firewall/group/del_item/g%2F1", {})
        with patch.object(OPNsenseClient, "post", return_value={"result": "failed"}):
            with self.assertRaisesMessage(DeviceError, "did not delete an interface group"):
                client.delete_definition("group", "g1")

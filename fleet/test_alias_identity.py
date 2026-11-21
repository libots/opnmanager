import copy
from unittest.mock import Mock

from django.test import TestCase

from .definition_sync import definition_plan, execute_definition_plan
from .import_rules import import_rules
from .models import Alias, AuditEvent, Firewall, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError
from .reconcile import plan_for
from .rule_identity import short_marker, tagged, untagged

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}


class AliasIdentityTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Branch", base_url="https://branch.invalid")
        self.lan = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.lan, device_interface="opt2")
        self.snapshot = Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))

    def device_aliases(self, *rows):
        self.snapshot.data["aliases"] = list(rows)
        self.snapshot.save()

    def alias_op(self, plan):
        return next(op for op in plan["operations"] if op["kind"] == "alias")

    def test_pushed_description_carries_the_alias_tag(self):
        alias = Alias.objects.create(name="DNS", content="10.0.0.1", description="Resolvers")
        payload = self.alias_op(plan_for(self.fw))["payload"]
        self.assertEqual(payload["description"], "Resolvers " + short_marker(alias.uid))
        self.assertEqual(untagged(payload["description"]), "Resolvers")

    def test_untagged_alias_with_the_same_name_is_adopted(self):
        alias = Alias.objects.create(name="DNS", content="10.0.0.1")
        self.device_aliases({"uuid": "u1", "name": "DNS", "type": "host", "content": "10.0.0.1"})
        op = self.alias_op(plan_for(self.fw))
        self.assertEqual((op["action"], op["remote_uuid"]), ("update", "u1"))
        self.assertEqual(op["payload"]["description"], tagged("", alias.uid))

    def test_rename_updates_the_tagged_device_alias_and_manager_references(self):
        alias = Alias.objects.create(name="DNS", content="10.0.0.1")
        parent = Alias.objects.create(name="Infra", content="DNS\n10.0.0.9")
        rule = Rule.objects.create(name="Resolve", interface=self.lan, destination="DNS,10.1.1.1")
        self.device_aliases(
            {"uuid": "u1", "name": "DNS", "type": "host", "content": "10.0.0.1", "description": tagged("", alias.uid)}
        )
        alias.name = "Resolvers"
        alias.save()
        rule.refresh_from_db()
        parent.refresh_from_db()
        self.assertEqual(rule.destination, "Resolvers,10.1.1.1")
        self.assertEqual(parent.content, "Resolvers\n10.0.0.9")
        plan = plan_for(self.fw)
        op = next(op for op in plan["operations"] if op["kind"] == "alias" and op["payload"]["name"] == "Resolvers")
        self.assertEqual((op["action"], op["remote_uuid"]), ("update", "u1"))

    def test_rename_onto_an_existing_device_alias_is_blocked(self):
        alias = Alias.objects.create(name="Resolvers", content="10.0.0.1")
        self.device_aliases(
            {"uuid": "u1", "name": "DNS", "type": "host", "content": "10.0.0.1", "description": tagged("", alias.uid)},
            {"uuid": "u2", "name": "Resolvers", "type": "host", "content": "10.9.9.9"},
        )
        self.assertTrue(any("would collide" in error for error in plan_for(self.fw)["errors"]))

    def test_deleted_manager_alias_is_offered_for_removal_and_removed_only_when_selected(self):
        gone = Alias.objects.create(name="Old", content="10.0.0.1")
        stale = {
            "uuid": "u1",
            "name": "Old",
            "type": "host",
            "content": "10.0.0.1",
            "description": tagged("x", gone.uid),
        }
        local = {"uuid": "u2", "name": "Local", "type": "host", "content": "10.0.0.2", "description": "mine"}
        self.device_aliases(stale, local)
        gone.delete()
        plan = definition_plan(self.fw)
        self.assertEqual([(c["name"], c["errors"]) for c in plan["removals"]], [("Old", [])])
        untouched = Mock()
        untouched.snapshot.return_value = copy.deepcopy(self.snapshot.data)
        self.assertEqual(execute_definition_plan(self.fw, plan["approval_sha256"], untouched, "test"), 0)
        untouched.delete_definition.assert_not_called()
        client = Mock()
        client.snapshot.side_effect = [copy.deepcopy(self.snapshot.data), {**EMPTY, "aliases": [local]}]
        self.assertEqual(execute_definition_plan(self.fw, plan["approval_sha256"], client, "test", remove=["u1"]), 1)
        client.delete_definition.assert_called_once_with("alias", "u1")
        client.reconfigure_definitions.assert_called_once_with({"alias"})
        self.assertTrue(AuditEvent.objects.filter(action="alias.removed").exists())

    def test_removal_is_blocked_while_the_device_still_uses_the_alias(self):
        gone = Alias.objects.create(name="Old", content="10.0.0.1")
        self.device_aliases(
            {"uuid": "u1", "name": "Old", "type": "host", "content": "10.0.0.1", "description": tagged("", gone.uid)}
        )
        self.snapshot.data["rules"] = [
            {"uuid": "r1", "description": "Local", "interface": "opt2", "sequence": "1", "source_net": "Old"}
        ]
        self.snapshot.save()
        gone.delete()
        plan = definition_plan(self.fw)
        self.assertIn("Still used by rule Local", plan["removals"][0]["errors"][0])
        with self.assertRaisesMessage(DeviceError, "Select only unblocked aliases"):
            execute_definition_plan(self.fw, plan["approval_sha256"], Mock(), "test", remove=["u1"])

    def test_alias_recreated_with_the_same_name_adopts_the_old_device_alias(self):
        gone = Alias.objects.create(name="DNS", content="10.0.0.1")
        self.device_aliases(
            {"uuid": "u1", "name": "DNS", "type": "host", "content": "10.0.0.1", "description": tagged("", gone.uid)}
        )
        gone.delete()
        fresh = Alias.objects.create(name="DNS", content="10.0.0.1")
        plan = definition_plan(self.fw)
        self.assertEqual(plan["removals"], [])
        op = self.alias_op(plan)
        self.assertEqual((op["remote_uuid"], op["payload"]["description"]), ("u1", tagged("", fresh.uid)))

    def test_rule_scoped_sync_never_offers_removals(self):
        gone = Alias.objects.create(name="Old", content="10.0.0.1")
        self.device_aliases(
            {"uuid": "u1", "name": "Old", "type": "host", "content": "10.0.0.1", "description": tagged("", gone.uid)}
        )
        gone.delete()
        rule = Rule.objects.create(name="Any", interface=self.lan)
        self.assertEqual(definition_plan(self.fw, rule=rule)["removals"], [])

    def test_import_strips_the_tag_from_alias_descriptions(self):
        source = Alias.objects.create(name="DNS", content="10.0.0.1")
        description = tagged("Resolvers", source.uid)
        source.delete()
        self.snapshot.data["aliases"] = [
            {"uuid": "u1", "name": "DNS", "type": "host", "content": "10.0.0.1", "description": description}
        ]
        self.snapshot.data["rules"] = [
            {"uuid": "r1", "description": "Resolve", "interface": "opt2", "sequence": "1", "destination_net": "DNS"}
        ]
        self.snapshot.save()
        import_rules(self.snapshot, ["0"], "all", [])
        self.assertEqual(Alias.objects.get(name="DNS").description, "Resolvers")

    def test_review_page_lists_removals_unchecked(self):
        from django.contrib.auth import get_user_model

        gone = Alias.objects.create(name="Old", content="10.0.0.1")
        self.device_aliases(
            {"uuid": "u1", "name": "Old", "type": "host", "content": "10.0.0.1", "description": tagged("", gone.uid)}
        )
        gone.delete()
        self.client.force_login(get_user_model().objects.create_superuser("operator", password="Test-only-pass"))
        response = self.client.get(f"/firewalls/{self.fw.pk}/sync/")
        self.assertContains(response, 'name="remove_definition" value="u1"')
        self.assertNotContains(response, "checked")
        self.assertContains(response, "Apply selected removals to Branch")

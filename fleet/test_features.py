import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.http import QueryDict
from .models import Firewall, LogicalInterface, InterfaceMapping, InterfaceGroup, Category, Alias, Rule, RuleOrigin, Snapshot, AuditEvent
from .reconcile import plan_for, validate_snapshot
from .mappings import apply_default_mappings
from .forms import RuleForm
from .credentials import encrypt_credentials, get_credentials
from .opnsense import DeviceError, OPNsenseClient
from .import_rules import import_rules
from .definition_sync import definition_plan, execute_definition_plan
from .rule_filters import filter_rows

RICH = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}

class FeatureTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Source", base_url="https://source.test", credential_prefix="SOURCE")
        self.other = Firewall.objects.create(name="Target", base_url="https://target.test", credential_prefix="TARGET")
        self.logical = LogicalInterface.objects.create(name="VL10")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.logical, device_interface="opt2")
        InterfaceMapping.objects.create(firewall=self.other, logical_interface=self.logical, device_interface="opt4")
        self.snapshot = Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(RICH))
        Snapshot.objects.create(firewall=self.other, data=copy.deepcopy(RICH))
        self.admin = get_user_model().objects.create_superuser("operator", password="Test-only-account-passphrase")
        self.client.force_login(self.admin)

    def row(self, **kwargs):
        return {"uuid": "remote-rule", "description": "Allow ping", "interface": "opt2", "sequence": "100", "protocol": "ICMP", "icmptype": "echoreq", "source_net": "opt2", "destination_net": "any", **kwargs}

    def observed(self, **kwargs):
        self.snapshot.data.update(kwargs)
        self.snapshot.save()
        return self.snapshot

    def test_plural_and_rich_snapshot_backward_compatibility(self):
        self.assertEqual(Alias._meta.verbose_name_plural, "aliases")
        data = validate_snapshot({"schema_version": 1, "rules": [], "aliases": []})
        self.assertNotIn("groups", data)
        rich = validate_snapshot(RICH)
        self.assertIn("groups", rich)
        self.assertIn("interfaces", rich)

    def test_default_mappings_use_names_across_different_local_identifiers(self):
        data = {**RICH, "interfaces": [{"name": "opt8", "label": "VL20"}]}
        self.assertEqual(apply_default_mappings(self.fw, data), 1)
        self.assertEqual(apply_default_mappings(self.other, {**data, "interfaces": [{"name": "opt12", "label": "vl20"}]}), 1)
        first = self.fw.interface_mappings.get(device_interface="opt8")
        second = self.other.interface_mappings.get(device_interface="opt12")
        self.assertEqual(first.logical_interface_id, second.logical_interface_id)
        self.assertEqual(apply_default_mappings(self.fw, data), 0)

    def test_default_mappings_preserve_manual_and_skip_ambiguous_labels(self):
        data = {**RICH, "interfaces": [{"name": "opt2", "label": "SomethingElse"}, {"name": "opt8", "label": "VL20"}, {"name": "opt9", "label": "vl20"}]}
        self.assertEqual(apply_default_mappings(self.fw, data), 0)
        self.assertFalse(LogicalInterface.objects.filter(name="SomethingElse").exists())
        self.assertEqual(self.fw.interface_mappings.get(device_interface="opt2").logical_interface, self.logical)

    def test_multi_binding_groups_categories_and_icmp_render_per_device(self):
        group = InterfaceGroup.objects.create(name="TRUSTED")
        group.members.add(self.logical)
        category = Category.objects.create(name="Diagnostics", color="ff0000")
        rule = Rule.objects.create(name="Ping", protocol="ICMP", icmp_types="echoreq,unreach", source="@VL10:net,10.0.0.1", floating=True)
        rule.interfaces.add(self.logical); rule.interface_groups.add(group); rule.categories.add(category)
        plan = plan_for(self.other)
        self.assertFalse(plan["errors"])
        group_op = next(op for op in plan["operations"] if op["kind"] == "group")
        self.assertEqual(group_op["payload"]["members"], "opt4")
        op = next(op for op in plan["operations"] if op["kind"] == "rule")
        self.assertEqual(op["payload"]["interface"], "TRUSTED,opt4")
        self.assertEqual(op["payload"]["icmptype"], "echoreq,unreach")
        self.assertEqual(op["payload"]["source_net"], "opt4,10.0.0.1")
        self.assertEqual(op["payload"]["categories"], "@category:Diagnostics")

    def test_missing_group_inventory_is_not_treated_as_empty(self):
        group = InterfaceGroup.objects.create(name="TRUSTED"); group.members.add(self.logical)
        self.snapshot.data.pop("groups"); self.snapshot.save()
        self.assertTrue(plan_for(self.fw)["errors"])
        self.assertFalse(plan_for(self.fw)["operations"])

    def test_category_uuid_mapping_is_device_specific(self):
        category = Category.objects.create(name="Operations")
        rule = Rule.objects.create(name="Categorized", interface=self.logical); rule.categories.add(category)
        self.observed(categories=[{"uuid": "source-cat", "name": "Operations", "color": "137b66"}])
        op = next(op for op in plan_for(self.fw)["operations"] if op["kind"] == "rule")
        self.assertEqual(op["payload"]["categories"], "source-cat")

    def test_import_rule_preserves_icmp_and_logical_bindings_and_origin(self):
        snapshot = self.observed(rules=[self.row()])
        imported = import_rules(snapshot, ["0"], "all", [])
        rule = imported[0]
        self.assertEqual(rule.icmp_types, "echoreq")
        self.assertEqual(rule.source, "@VL10:net")
        self.assertEqual(list(rule.interfaces.all()), [self.logical])
        self.assertTrue(rule.applies_to(self.other))
        source_plan = plan_for(self.fw)
        item = next(i for i in source_plan["items"] if i["kind"] == "rule")
        self.assertEqual(item["status"], "changed")
        self.assertEqual([c["field"] for c in item["changes"]], ["description"])
        self.assertEqual(import_rules(snapshot, ["0"], "all", [])[0].pk, rule.pk)
        self.assertEqual(Rule.objects.count(), 1)
        self.assertEqual(RuleOrigin.objects.count(), 1)

    def test_import_group_categories_alias_dependencies_and_target_scope(self):
        snapshot = self.observed(rules=[self.row(interface="TRUSTED", source_net="Servers", categories="cat")],
            groups=[{"uuid": "g", "ifname": "TRUSTED", "members": "opt2", "descr": "Trusted clients"}],
            categories=[{"uuid": "cat", "name": "Operations", "color": "aabbcc"}],
            aliases=[{"name": "Servers", "type": "network", "content": "Nested", "enabled": "1"},
                     {"name": "Nested", "type": "network", "content": "10.0.0.0/24", "enabled": "1"}])
        rule = import_rules(snapshot, ["0"], "selected", [self.fw])[0]
        self.assertEqual(rule.interface_groups.get().name, "TRUSTED")
        self.assertEqual(rule.categories.get().name, "Operations")
        self.assertEqual(Alias.objects.count(), 2)
        self.assertFalse(rule.applies_to(self.other))
        self.assertFalse(InterfaceGroup.objects.get().applies_to(self.other))

    def test_import_unsupported_behavior_rolls_back_whole_batch(self):
        snapshot = self.observed(rules=[self.row(), self.row(uuid="second", gateway="device-specific-gateway")])
        with self.assertRaisesMessage(ValidationError, "gateway"):
            import_rules(snapshot, ["0", "1"], "all", [])
        self.assertEqual(Rule.objects.count(), 0)
        self.assertEqual(RuleOrigin.objects.count(), 0)

    def test_import_rejects_missing_mapping_stale_snapshot_and_alias_conflicts(self):
        snapshot = self.observed(rules=[self.row(interface="unmapped")])
        with self.assertRaisesMessage(ValidationError, "Map interface"):
            import_rules(snapshot, ["0"], "all", [])
        self.observed(rules=[self.row(source_net="DNS")], aliases=[{"name":"DNS", "type":"host", "content":"10.0.0.1"}])
        Alias.objects.create(name="DNS", content="10.0.0.2")
        with self.assertRaisesMessage(ValidationError, "conflicts"):
            import_rules(snapshot, ["0"], "all", [])
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(RICH))
        with self.assertRaisesMessage(ValidationError, "newer snapshot"):
            import_rules(snapshot, ["0"], "all", [])

    def test_global_floating_import(self):
        snapshot = self.observed(rules=[self.row(interface="", source_net="any")])
        rule = import_rules(snapshot, ["0"], "all", [])[0]
        self.assertTrue(rule.floating)
        self.assertFalse(rule.interfaces.exists())
        self.assertFalse(plan_for(self.fw)["errors"])

    def test_rule_form_autocomplete_multi_selections_and_port_restrictions(self):
        alias = Alias.objects.create(name="Servers", content="10.0.0.1")
        data = {"name":"Multi", "sequence":"400", "interfaces":[str(self.logical.pk)], "action":"pass", "direction":"in", "ip_version":"inet",
                "protocol":"ICMP", "source":["@VL10:net", "Servers"], "destination":["any"], "icmp_types":["echoreq", "unreach"], "scope":"all", "enabled":"on", "quick":"on"}
        form = RuleForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        rule = form.save()
        self.assertEqual(rule.source, "@VL10:net,Servers")
        self.assertEqual(rule.icmp_types, "echoreq,unreach")
        self.assertIn("selections.js", str(form.media))
        self.assertIn("Servers", str(form["source"]))
        self.assertIn("@VL10:net", str(form["source"]))
        form = RuleForm({**data, "protocol":"TCP", "icmp_types":[], "source_port":["22", "443"]})
        self.assertFalse(form.is_valid())
        self.assertIn("source_port", form.errors)

    def test_rule_filters_include_group_members_and_floating(self):
        rows = [{"interface":"opt2", "description":"One", "categories":"cat", "enabled":"1"},
                {"interface":"TRUSTED", "description":"Group", "enabled":"0"},
                {"interface":"opt2,opt4", "description":"Floating", "enabled":"1"},
                {"interface":"", "description":"Global", "enabled":"1"}]
        groups = {"TRUSTED":{"opt2"}}
        self.assertEqual(len(filter_rows(rows, {"interface":"opt2"}, groups)), 4)
        self.assertEqual(len(filter_rows(rows, {"placement":"floating"}, groups)), 2)
        self.assertEqual(len(filter_rows(rows, {"placement":"group"}, groups)), 1)
        self.assertEqual(len(filter_rows(rows, {"category":"cat", "q":"one"}, groups)), 1)

    def test_rule_import_and_filters_via_gui(self):
        snapshot = self.observed(rules=[self.row()])
        self.assertContains(self.client.get('/rules/?firewall=' + str(self.fw.pk)), "Allow ping")
        response = self.client.post(f'/firewalls/{self.fw.pk}/rules/import/', {"snapshot_id":snapshot.pk, "rule_indices":["0"], "scope":"selected", "firewalls":[self.fw.pk]}, follow=True)
        self.assertContains(response, "Imported 1 rules")
        self.assertEqual(Rule.objects.count(), 1)
        self.assertContains(self.client.get('/rules/?placement=interface'), "Allow ping")
        self.assertContains(self.client.get('/admin/fleet/rule/add/'), "select2")
        self.assertContains(self.client.get('/admin/fleet/alias/'), "Aliases")

    @override_settings(OPNMANAGER_LOCAL=True)
    def test_encrypted_write_only_credentials_ui_replace_keep_clear(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(DATA_DIR=Path(directory)):
            url = f'/firewalls/{self.fw.pk}/credentials/'
            response = self.client.post(url, {"api_key":"private-ui-key", "api_secret":"private-ui-secret"}, follow=True)
            self.assertNotContains(response, "private-ui-key")
            self.assertNotContains(response, "private-ui-secret")
            self.fw.refresh_from_db()
            self.assertNotIn("private-ui", self.fw.encrypted_api_key + self.fw.encrypted_api_secret)
            self.assertEqual(get_credentials(self.fw), ("private-ui-key", "private-ui-secret"))
            original = self.fw.encrypted_api_key
            self.client.post(url, {"api_key":"", "api_secret":""})
            self.fw.refresh_from_db()
            self.assertEqual(self.fw.encrypted_api_key, original)
            invalid = self.client.post(url, {"api_key":"one-secret-only"})
            self.assertNotContains(invalid, "one-secret-only")
            self.assertEqual((Path(directory) / '.credentials-key').stat().st_mode & 0o077, 0)
            self.assertFalse(AuditEvent.objects.filter(detail__contains="private-ui").exists())
            self.client.post(url, {"clear_credentials":"on"})
            self.fw.refresh_from_db()
            self.assertFalse(self.fw.encrypted_api_key)

    def test_missing_or_wrong_credential_encryption_key_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory, override_settings(DATA_DIR=Path(directory)):
            encrypt_credentials(self.fw, "k", "s")
            path = Path(directory) / '.credentials-key'
            path.unlink()
            with self.assertRaisesMessage(DeviceError, "key is missing"):
                get_credentials(self.fw)
            self.assertFalse(path.exists())
            path.write_bytes(Fernet.generate_key())
            with self.assertRaisesMessage(DeviceError, "Unable to decrypt"):
                get_credentials(self.fw)

    def test_nonprivileged_users_cannot_import_write_credentials_or_sync(self):
        user = get_user_model().objects.create_user("viewer")
        self.client.force_login(user)
        for path in [f'/firewalls/{self.fw.pk}/credentials/', f'/firewalls/{self.fw.pk}/sync/', f'/firewalls/{self.fw.pk}/rules/import/']:
            self.assertEqual(self.client.post(path).status_code, 403)

    def test_definition_sync_group_category_alias_order_and_readback(self):
        group = InterfaceGroup.objects.create(name="TRUSTED"); group.members.add(self.logical)
        Category.objects.create(name="Operations")
        Alias.objects.create(name="DNS", content="10.0.0.1")
        plan = definition_plan(self.fw)
        self.assertFalse(plan["errors"])
        self.assertEqual([op['kind'] for op in plan['operations']], ['group', 'category', 'alias'])
        observed = copy.deepcopy(RICH)
        for op in plan['operations']:
            collection = {"group":"groups", "category":"categories", "alias":"aliases"}[op['kind']]
            observed[collection].append({**op['payload'], "uuid":"remote-" + op['kind']})
        client = Mock(); client.snapshot.side_effect = [copy.deepcopy(RICH), observed]
        self.assertEqual(execute_definition_plan(self.fw, plan['approval_sha256'], client, 'test'), 3)
        self.assertEqual(client.save_definition.call_count, 3)
        client.reconfigure_definitions.assert_called_once_with({'group', 'category', 'alias'})
        self.assertTrue(AuditEvent.objects.filter(action='definitions.sync.completed').exists())

    def test_definition_sync_rejects_stale_device_and_stale_approval(self):
        Category.objects.create(name="Operations")
        plan = definition_plan(self.fw)
        client = Mock(); client.snapshot.return_value = {**RICH, 'categories':[{'name':'Unexpected', 'uuid':'x'}]}
        with self.assertRaisesMessage(DeviceError, "Device definitions changed"):
            execute_definition_plan(self.fw, plan['approval_sha256'], client, 'test')
        client.save_definition.assert_not_called()
        with self.assertRaisesMessage(DeviceError, "Plan changed"):
            execute_definition_plan(self.fw, 'wrong-approval', client, 'test')

    def test_definition_sync_readback_failure_is_audited(self):
        Category.objects.create(name="Operations")
        client = Mock(); client.snapshot.return_value = copy.deepcopy(RICH)
        with self.assertRaisesMessage(DeviceError, "readback"):
            execute_definition_plan(self.fw, definition_plan(self.fw)['approval_sha256'], client, 'test')
        self.assertTrue(AuditEvent.objects.filter(action='definitions.sync.failed').exists())

    @patch.dict('os.environ', {'SOURCE_API_KEY':'testkey', 'SOURCE_API_SECRET':'testsecret'})
    @patch('fleet.opnsense.requests.Session')
    def test_definition_api_endpoints_and_payload_keys(self, session):
        session.return_value.post.return_value = Mock(status_code=200, json=lambda:{'result':'saved'})
        client = OPNsenseClient(self.fw)
        for kind in ('group', 'category'):
            client.save_definition({'kind':kind, 'action':'create', 'payload':{'name':'test'}})
            call = session.return_value.post.call_args
            self.assertTrue(call.args[0].endswith('/' + kind + '/add_item'))
            self.assertEqual(call.kwargs['json'], {kind:{'name':'test'}})

    def test_sync_preview_does_not_contact_device_or_expose_credentials(self):
        Category.objects.create(name='Operations')
        with patch('fleet.views.OPNsenseClient') as client:
            response = self.client.get(f'/firewalls/{self.fw.pk}/sync/')
            self.assertContains(response, 'Apply these definition changes')
            client.assert_not_called()

    def test_rule_form_edit_preserves_multi_values(self):
        rule = Rule.objects.create(name='Multi', protocol='ICMP', icmp_types='echoreq,unreach', source='10.0.0.1,10.0.0.2')
        rule.interfaces.add(self.logical)
        form = RuleForm(instance=rule)
        self.assertIn('value="echoreq" selected', str(form['icmp_types']))
        self.assertIn('value="10.0.0.2" selected', str(form['source']))

    def test_protocol_multiselect_accepts_transport_combination(self):
        data = {"name":"Web", "sequence":"500", "interfaces":[str(self.logical.pk)], "action":"pass", "direction":"in", "ip_version":"inet",
                "protocol":["TCP","UDP"], "source":["any"], "destination":["any"], "destination_port":["443"], "scope":"all", "enabled":"on", "quick":"on"}
        form = RuleForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().protocol, "TCP,UDP")
        bad = RuleForm({**data,"protocol":["any","TCP"]})
        self.assertFalse(bad.is_valid())

    def test_alias_editor_accepts_multiple_entries_and_searchable_nested_aliases(self):
        from .forms import AliasForm
        Alias.objects.create(name='Existing',content='10.0.0.1')
        form = AliasForm({'name':'Parent','type':'host','content':['Existing','10.0.0.2'],'scope':'all','enabled':'on'})
        self.assertTrue(form.is_valid(),form.errors)
        alias=form.save()
        self.assertEqual(alias.content,'Existing\n10.0.0.2')
        self.assertIn('Existing',str(AliasForm(instance=alias)['content']))

    def test_gui_pull_applies_default_mappings_and_opt_out_preserves_inventory_only(self):
        data = {**RICH,'interfaces':[{'name':'opt8','label':'VL20'}]}
        with patch('fleet.views.OPNsenseClient') as client:
            client.return_value.snapshot.return_value=data
            self.client.post(f'/firewalls/{self.fw.pk}/pull/')
        self.assertTrue(self.fw.interface_mappings.filter(device_interface='opt8').exists())
        self.other.auto_map_interfaces=False;self.other.save()
        with patch('fleet.views.OPNsenseClient') as client:
            client.return_value.snapshot.return_value=data
            self.client.post(f'/firewalls/{self.other.pk}/pull/')
        self.assertFalse(self.other.interface_mappings.filter(device_interface='opt8').exists())
        self.assertEqual(self.other.snapshots.first().data['interfaces'],data['interfaces'])

    def test_existing_case_ambiguous_logical_names_are_never_auto_selected(self):
        LogicalInterface.objects.create(name='vl10')
        data={**RICH,'interfaces':[{'name':'opt7','label':'Vl10'}]}
        self.assertEqual(apply_default_mappings(self.fw,data),0)

    def test_icmp_family_validation_and_inverted_interface_filter(self):
        with self.assertRaisesMessage(ValidationError,'ICMPv6 requires IPv6'):
            Rule(name='Bad IPv6',interface=self.logical,protocol='IPv6-ICMP',icmp6_types='128').full_clean()
        rows=[{'interface':'opt2','interfacenot':'1','description':'Except clients'},
              {'interface':'','description':'Global'}]
        self.assertEqual(len(filter_rows(rows,{'interface':'opt2'})),1)
        self.assertEqual(len(filter_rows(rows,{'interface':'opt4'})),2)

    def test_group_address_dependency_is_imported_and_suggested(self):
        snapshot = self.observed(rules=[self.row(source_net="TRUSTED")], groups=[{"ifname":"TRUSTED","members":"opt2"}])
        imported = import_rules(snapshot,["0"],"all",[])[0]
        self.assertEqual(imported.source,"TRUSTED")
        self.assertEqual(InterfaceGroup.objects.get(name="TRUSTED").members.get(),self.logical)
        self.assertIn("TRUSTED",str(RuleForm(instance=imported)["source"]))

from django.test import TransactionTestCase
from django.db import connection
from django.db.migrations.executor import MigrationExecutor


class MigrationUpgradeTests(TransactionTestCase):
    def test_upgrade_copies_original_interface_without_losing_rules_or_mappings(self):
        executor = MigrationExecutor(connection)
        old = [('fleet', '0002_localaccountstate')]
        latest = executor.loader.graph.leaf_nodes()
        try:
            executor.migrate(old)
            apps = executor.loader.project_state(old).apps
            old_firewall = apps.get_model('fleet','Firewall').objects.create(name='Existing firewall',base_url='https://existing.test',credential_prefix='EXISTING')
            interface = apps.get_model('fleet','LogicalInterface').objects.create(name='LEGACY')
            apps.get_model('fleet','InterfaceMapping').objects.create(firewall=old_firewall,logical_interface=interface,device_interface='opt2')
            original = apps.get_model('fleet','Rule').objects.create(name='Existing policy',interface=interface,protocol='TCP',destination_port='443')
            executor = MigrationExecutor(connection)
            executor.migrate(latest)
            apps = executor.loader.project_state(latest).apps
            migrated = apps.get_model('fleet','Rule').objects.get(pk=original.pk)
            self.assertEqual(migrated.destination_port,'443')
            self.assertEqual(list(migrated.interfaces.values_list('pk',flat=True)),[interface.pk])
            self.assertEqual(apps.get_model('fleet','InterfaceMapping').objects.get(firewall_id=old_firewall.pk).device_interface,'opt2')
            self.assertEqual(migrated.protocol,'TCP')
        finally:
            MigrationExecutor(connection).migrate(latest)

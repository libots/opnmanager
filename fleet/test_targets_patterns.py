import ipaddress
import itertools
from django.test import TestCase, SimpleTestCase
from .alias_patterns import expand_entry, compile_content
from .models import Firewall, FirewallGroup, Rule, Alias, Category, InterfaceGroup, LogicalInterface, InterfaceMapping, Snapshot
from .reconcile import plan_for
from .forms import AliasForm, ImportRulesForm
from .import_rules import import_rules
from .definition_sync import definition_plan, execute_definition_plan
from .opnsense import DeviceError
from unittest.mock import Mock

RICH = {'schema_version':1,'rules':[],'aliases':[],'interfaces':[],'groups':[],'categories':[]}

class PatternTests(SimpleTestCase):
    def test_ipv4_wildcard_is_exact_host_set(self):
        values = expand_entry('192.168.x.10','host')
        self.assertEqual(len(values),256)
        self.assertEqual(set(values), {f'192.168.{i}.10' for i in range(256)})
        self.assertNotIn('192.168.1.11',values)
        self.assertEqual(values,expand_entry('192.168.*.10','host'))

    def test_ipv4_component_ranges_and_compact_network_output(self):
        self.assertEqual(expand_entry('192.168.0-3.x','network'),['192.168.0.0/22'])
        self.assertEqual(expand_entry('192.168.0-3.10','host'),[f'192.168.{i}.10' for i in range(4)])
        self.assertEqual(expand_entry('x.x.x.x','network'),['0.0.0.0/0'])

    def test_ipv6_hex_ranges_and_compression(self):
        values = expand_entry('2001:db8::0-af','host')
        self.assertEqual(len(values),176)
        self.assertIn('2001:db8::af',values)
        self.assertNotIn('2001:db8::b0',values)
        self.assertEqual(expand_entry('2001:db8:x:x:x:x:x:x','network'),['2001:db8::/32'])
        self.assertEqual(expand_entry('x:x:x:x:x:x:x:x','network'),['::/0'])
        self.assertEqual(expand_entry('2001:db8:0-af:x:x:x:x:x','network'),['2001:db8::/41','2001:db8:80::/43','2001:db8:a0::/44'])

    def test_network_compilation_never_adds_addresses_outside_pattern(self):
        for pattern in ['10.0.0-3.2-7','10.0.2-5.0-8','10.1-2.0-3.4-5']:
            components = pattern.split('.')
            ranges = [range(int(p.split('-')[0]),int(p.split('-')[-1])+1) for p in components]
            expected = {'.'.join(map(str,parts)) for parts in itertools.product(*ranges)}
            actual = {str(ip) for value in expand_entry(pattern,'network') for ip in ipaddress.ip_network(value)}
            self.assertEqual(actual,expected)

    def test_full_address_ranges(self):
        self.assertEqual(expand_entry('192.0.2.0-192.0.2.3','network'),['192.0.2.0/30'])
        self.assertEqual(expand_entry('::1-::3','host'),['::1','::2','::3'])

    def test_expansion_limits_and_malformed_input(self):
        for pattern,kind in [('x.x.x.x','host'),('2001:db8:x::10','network'),('192.168.0-999.1','network'),('192.168.3-0.1','host'),('2001:db8::0-gg','network'),('192.168.x.1/24','network'),('2001::db8::x','network')]:
            with self.subTest(pattern=pattern),self.assertRaises(ValueError): expand_entry(pattern,kind)
        with self.assertRaises(ValueError): compile_content('10.0.0.x\n10.0.1.x','host',limit=300)
        with self.assertRaises(ValueError): compile_content('10.0.0-4.1-4','network',limit=5)

    def test_nested_references_deduplication_and_ports(self):
        self.assertEqual(compile_content('DNS\n192.168.0-1.10\n192.168.1.10','host',{'DNS'}),'DNS\n192.168.0.10\n192.168.1.10')
        self.assertEqual(compile_content('x','host',{'x'}),'x')
        self.assertEqual(compile_content('80\n100:200','port'),'80\n100:200')
        with self.assertRaises(ValueError): compile_content('0:65536','port')


class FirewallTargetTests(TestCase):
    def setUp(self):
        self.firewall = Firewall.objects.create(name='One',base_url='https://one.test')
        self.group = FirewallGroup.objects.create(name='Branches')
        self.logical = LogicalInterface.objects.create(name='VL10')
        InterfaceMapping.objects.create(firewall=self.firewall,logical_interface=self.logical,device_interface='opt2')
        Snapshot.objects.create(firewall=self.firewall,data=RICH)

    def test_dynamic_group_membership_for_every_policy_type(self):
        for model,kwargs in [(Rule,{'name':'Rule','interface':self.logical}), (Alias,{'name':'Addresses','content':'10.0.0.1'}), (Category,{'name':'Operations'}), (InterfaceGroup,{'name':'TRUSTED'})]:
            policy = model.objects.create(scope='selected',**kwargs)
            policy.firewall_groups.add(self.group)
            self.assertFalse(policy.applies_to(self.firewall))
            self.group.firewalls.add(self.firewall)
            self.assertTrue(policy.applies_to(self.firewall))
            self.group.firewalls.remove(self.firewall)
            self.assertFalse(policy.applies_to(self.firewall))
            policy.firewalls.add(self.firewall)
            self.assertTrue(policy.applies_to(self.firewall))

    def test_all_includes_new_firewalls_and_ignores_selected_lists(self):
        rule = Rule.objects.create(name='Global rule',interface=self.logical)
        new = Firewall.objects.create(name='New',base_url='https://new.test')
        self.assertTrue(rule.applies_to(new))
        rule.firewall_groups.add(self.group)
        self.assertTrue(rule.applies_to(new))
        new.enabled = False
        self.assertFalse(rule.applies_to(new))

    def test_group_targets_update_plans_without_recreating_policy(self):
        alias = Alias.objects.create(name='Sites',content='192.168.0-3.x',type='network',scope='selected')
        alias.firewall_groups.add(self.group)
        self.assertFalse(plan_for(self.firewall)['operations'])
        self.group.firewalls.add(self.firewall)
        operation = plan_for(self.firewall)['operations'][0]
        self.assertEqual(operation['payload']['content'],'192.168.0.0/22')
        self.group.firewalls.clear()
        self.assertFalse(plan_for(self.firewall)['operations'])
        self.assertEqual(Alias.objects.count(),1)

    def test_invalid_patterns_block_entire_sync_plan(self):
        Alias.objects.create(name='TooBroad',content='x.x.x.x',type='host')
        plan = definition_plan(self.firewall)
        self.assertTrue(plan['errors'])
        self.assertFalse(plan['operations'])

    def test_alias_form_reports_limits_and_previews_saved_expansion(self):
        form = AliasForm({'name':'Bad','scope':'all','type':'host','content':['x.x.x.x'],'enabled':'on'})
        self.assertFalse(form.is_valid())
        self.assertIn('content',form.errors)
        alias = Alias.objects.create(name='Preview',content='192.168.0-3.x',type='network')
        self.assertIn('192.168.0.0/22',AliasForm(instance=alias).initial['expansion_preview'])

    def test_import_propagates_group_scope_to_required_aliases_and_categories(self):
        snapshot = self.firewall.snapshots.first()
        snapshot.data = {**RICH,'rules':[{'uuid':'source-rule','description':'Existing rule','sequence':'100','interface':'opt2','source_net':'Hosts','categories':'category-uuid'}],
                         'aliases':[{'name':'Hosts','type':'host','content':'10.0.0.1'}], 'categories':[{'uuid':'category-uuid','name':'Operations','color':'112233'}]}
        snapshot.save()
        form = ImportRulesForm({'snapshot_id':snapshot.pk,'rule_indices':['0'],'scope':'selected','firewall_groups':[self.group.pk]},snapshot=snapshot)
        self.assertTrue(form.is_valid(),form.errors)
        rule = import_rules(snapshot,['0'],'selected',[],[self.group])[0]
        for obj in [rule, Alias.objects.get(),Category.objects.get()]:
            self.assertFalse(obj.applies_to(self.firewall))
            self.assertTrue(obj.firewall_groups.filter(pk=self.group.pk).exists())
        self.group.firewalls.add(self.firewall)
        self.assertTrue(rule.applies_to(self.firewall))
        self.assertFalse(plan_for(self.firewall)['errors'])
        self.assertEqual(import_rules(snapshot,['0'],'selected',[],[self.group])[0].pk,rule.pk)

    def test_import_recognizes_existing_pattern_alias_as_equivalent(self):
        Alias.objects.create(name='Hosts',content='192.168.0-1.10')
        snapshot = self.firewall.snapshots.first()
        snapshot.data={**RICH,'rules':[{'uuid':'source-rule','description':'Existing','sequence':'100','interface':'opt2','source_net':'Hosts'}],
                       'aliases':[{'name':'Hosts','type':'host','content':'192.168.0.10\n192.168.1.10'}]}
        snapshot.save()
        self.assertEqual(len(import_rules(snapshot,['0'],'all',[])),1)

    def test_sync_uses_compiled_content_and_preserves_manager_pattern(self):
        alias = Alias.objects.create(name='Pattern',type='network',content='192.168.0-3.*')
        plan = definition_plan(self.firewall)
        op = plan['operations'][0]
        client = Mock()
        client.snapshot.side_effect = [RICH, {**RICH,'aliases':[{**op['payload'],'uuid':'device-alias'}]}]
        self.assertEqual(execute_definition_plan(self.firewall,plan['approval_sha256'],client,'test'),1)
        self.assertEqual(client.save_definition.call_args.args[0]['payload']['content'],'192.168.0.0/22')
        alias.refresh_from_db()
        self.assertEqual(alias.content,'192.168.0-3.*')

    def test_group_membership_change_invalidates_reviewed_plan(self):
        alias = Alias.objects.create(name='Selected',content='10.0.0.1',scope='selected')
        alias.firewall_groups.add(self.group)
        plan = definition_plan(self.firewall)
        self.group.firewalls.add(self.firewall)
        client = Mock()
        with self.assertRaisesMessage(DeviceError,'Plan changed'):
            execute_definition_plan(self.firewall,plan['approval_sha256'],client,'test')
        client.save_definition.assert_not_called()
        client.snapshot.assert_not_called()

    def test_import_fills_missing_nested_alias_even_when_parent_already_exists(self):
        Alias.objects.create(name='Parent',content='Nested')
        snapshot=self.firewall.snapshots.first()
        snapshot.data={**RICH,'rules':[{'uuid':'source','description':'Existing','sequence':'100','interface':'opt2','source_net':'Parent'}],
                       'aliases':[{'name':'Parent','type':'host','content':'Nested'},{'name':'Nested','type':'host','content':'10.0.0.1'}]}
        snapshot.save()
        import_rules(snapshot,['0'],'all',[])
        self.assertEqual(Alias.objects.count(),2)
        self.assertFalse(plan_for(self.firewall)['errors'])

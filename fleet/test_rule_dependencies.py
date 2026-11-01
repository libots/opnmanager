from unittest.mock import Mock
from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Firewall,LogicalInterface,InterfaceMapping,Snapshot,Rule,Alias,Category,InterfaceGroup
from .deployment import deployment_plan
from .definition_sync import definition_plan,execute_definition_plan
from .dependencies import rule_definitions

EMPTY={'schema_version':1,'rules':[],'aliases':[],'groups':[],'categories':[],'interfaces':[]}

class RuleDependencyTests(TestCase):
    def setUp(self):
        self.fw=Firewall.objects.create(name='One',base_url='https://one.test')
        logical=LogicalInterface.objects.create(name='LAN')
        InterfaceMapping.objects.create(firewall=self.fw,logical_interface=logical,device_interface='lan')
        self.logical=logical
        Snapshot.objects.create(firewall=self.fw,data=EMPTY)
        self.rule=Rule.objects.create(name='Chosen',interface=logical)
    def test_unrelated_drift_and_invalid_definitions_do_not_block_rule(self):
        Alias.objects.create(name='Unrelated',content='x.x.x.x',type='host')
        Category.objects.create(name='Unrelated category')
        InterfaceGroup.objects.create(name='Unmapped')
        row=deployment_plan(self.fw)['rows'][0]
        self.assertFalse(row['errors'])
        self.assertTrue(row['operation'])
    def test_nested_port_category_and_origin_groups_are_dependencies(self):
        Alias.objects.create(name='Parent',content='Child');Alias.objects.create(name='Child',content='10.0.0.1')
        Alias.objects.create(name='Ports',type='port',content='443')
        category=Category.objects.create(name='Web');self.rule.categories.add(category)
        group=InterfaceGroup.objects.create(name='ORIGIN');group.members.add(self.logical)
        self.rule.origin_interface_groups.add(group)
        self.rule.source='Parent';self.rule.destination_port='Ports';self.rule.protocol='TCP';self.rule.save()
        self.assertEqual(rule_definitions(self.rule),{'alias':{'Parent','Child','Ports'},'category':{'Web'},'group':{'ORIGIN'}})
        row=deployment_plan(self.fw)['rows'][0]
        self.assertTrue(row['errors'])
        self.assertIn('Child',row['errors'][0]);self.assertIn('ORIGIN',row['errors'][0])
    def test_scoped_sync_only_writes_required_aliases_and_unblocks_rule(self):
        Alias.objects.create(name='Parent',content='Child');Alias.objects.create(name='Child',content='10.0.0.1')
        Alias.objects.create(name='Unrelated',content='x.x.x.x')
        self.rule.source='Parent';self.rule.save()
        plan=definition_plan(self.fw,rule=self.rule)
        self.assertFalse(plan['errors'])
        self.assertEqual([op['payload']['name'] for op in plan['operations']],['Child','Parent'])
        observed={**EMPTY,'aliases':[{**op['payload'],'uuid':'remote-'+op['payload']['name']} for op in plan['operations']]}
        client=Mock();client.snapshot.side_effect=[EMPTY,observed]
        self.assertEqual(execute_definition_plan(self.fw,plan['approval_sha256'],client,'test',rule=self.rule),2)
        self.assertFalse(deployment_plan(self.fw)['rows'][0]['errors'])
        self.assertEqual(client.save_definition.call_count,2)
    def test_excluded_required_alias_still_blocks_even_if_device_has_it(self):
        alias=Alias.objects.create(name='Excluded',content='10.0.0.1',scope='selected')
        self.rule.source='Excluded';self.rule.save()
        self.assertTrue(deployment_plan(self.fw)['rows'][0]['errors'])
    def test_reference_via_group_network_is_detected(self):
        group=InterfaceGroup.objects.create(name='TRUSTED');group.members.add(self.logical)
        self.rule.source='TRUSTED';self.rule.save()
        self.assertEqual(rule_definitions(self.rule)['group'],{'TRUSTED'})
        self.assertTrue(deployment_plan(self.fw)['rows'][0]['dependencies'])
    def test_review_link_preserves_rule_scope_on_confirmation(self):
        Alias.objects.create(name='Needed',content='10.0.0.1')
        self.rule.source='Needed';self.rule.save()
        user=get_user_model().objects.create_superuser('test-admin',password='Test-only-password');self.client.force_login(user)
        self.assertContains(self.client.get(f'/firewalls/{self.fw.pk}/deploy/'),f'?rule={self.rule.pk}')
        response=self.client.get(f'/firewalls/{self.fw.pk}/sync/?rule={self.rule.pk}')
        self.assertContains(response,'name="rule_id"')
        self.assertContains(response,'Only definitions required by rule')
        self.assertEqual(self.client.get(f'/firewalls/{self.fw.pk}/sync/?rule=invalid').status_code,404)

    def test_category_without_remote_uuid_is_not_ready_to_deploy(self):
        category=Category.objects.create(name='Web');self.rule.categories.add(category)
        snapshot=self.fw.snapshots.first()
        snapshot.data={**EMPTY,'categories':[{'name':'Web','color':category.color}]};snapshot.save()
        errors=deployment_plan(self.fw)['rows'][0]['errors']
        self.assertTrue(any('category UUIDs are missing' in error for error in errors))

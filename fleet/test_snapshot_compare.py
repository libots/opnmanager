from copy import deepcopy
from unittest.mock import Mock
from django.test import SimpleTestCase,TestCase
from .snapshot_compare import configuration_changes
from .models import Firewall,LogicalInterface,InterfaceMapping,Rule,Snapshot
from .deployment import deployment_plan,execute_deployment
from .opnsense import DeviceError

EMPTY={'schema_version':1,'rules':[],'aliases':[],'interfaces':[],'groups':[],'categories':[]}

class SemanticSnapshotTests(SimpleTestCase):
    def test_model_annotations_and_multivalue_order_do_not_look_like_edits(self):
        before={**EMPTY,'rules':[{'uuid':'rule','description':'Test','sequence':'0100','interface':'lan,opt2','protocol':'TCP,UDP','audit':'old','sort_order':'100','source_net':'B,A','received-on':'opt3,lan'}],
                'aliases':[{'uuid':'alias','name':'Servers','type':'host','content':'10.0.0.2\n10.0.0.1','enabled':'1'}]}
        after=deepcopy(before);after['rules'][0].update(sequence='100',interface='opt2,lan',protocol='udp,tcp',audit='new',sort_order='101',source_net='A,B',**{'received-on':'lan,opt3'})
        after['rules'][0]['alias_meta_source_net']='volatile presentation'
        after['aliases'][0]['content']='10.0.0.1\n10.0.0.2\n10.0.0.1'
        self.assertEqual(configuration_changes(before,after),[])
    def test_real_and_advanced_changes_still_block_with_field_names(self):
        before={**EMPTY,'rules':[{'uuid':'id','description':'Test','sequence':'100','interface':'lan','gateway':'GW1'}]}
        for field,value in [('action','block'),('gateway','GW2'),('quick','0'),('sequence','200'),('sched','Night')]:
            after=deepcopy(before);after['rules'][0][field]=value
            self.assertIn(field,' '.join(configuration_changes(before,after)))
    def test_empty_optional_collections_do_not_require_identical_schema_shape(self):
        self.assertEqual(configuration_changes({'schema_version':1,'rules':[],'aliases':[]},EMPTY),[])
        self.assertTrue(configuration_changes(EMPTY,{**EMPTY,'interfaces':[{'name':'lan','label':'LAN'}]}))
    def test_added_removed_duplicate_and_reordered_rows(self):
        a={'uuid':'a','description':'One'};b={'uuid':'b','description':'Two'}
        before={**EMPTY,'rules':[a,b]}
        self.assertEqual(configuration_changes(before,{**EMPTY,'rules':[b,a]}),[])
        self.assertTrue(configuration_changes(before,{**EMPTY,'rules':[a]}))
        self.assertTrue(configuration_changes(before,{**EMPTY,'rules':[a,a,b]}))
    def test_alias_group_category_and_interface_edits_remain_protected(self):
        for collection,row,field,value in [('aliases',{'uuid':'a','name':'A','content':'10.0.0.1'},'content','10.0.0.2'),('groups',{'uuid':'g','ifname':'Group','members':'lan'},'members','opt2'),('categories',{'uuid':'c','name':'Web','color':'abcdef'},'color','ff0000'),('interfaces',{'name':'opt2','label':'Clients'},'label','Servers')]:
            before={**EMPTY,collection:[row]};after=deepcopy(before);after[collection][0][field]=value
            self.assertTrue(configuration_changes(before,after),collection)

    def test_alias_and_definition_guards_share_semantic_normalization(self):
        from .alias_sync import alias_fingerprint
        from .definition_sync import fingerprint
        before={**EMPTY,'aliases':[{'uuid':'a','name':'A','content':'10.0.0.1\n10.0.0.2','audit':'old'}],
                'groups':[{'uuid':'g','ifname':'Group','members':'lan,opt2'}]}
        after=deepcopy(before);after['aliases'][0].update(content='10.0.0.2\n10.0.0.1',audit='new');after['groups'][0]['members']='opt2,lan'
        self.assertEqual(alias_fingerprint(before['aliases']),alias_fingerprint(after['aliases']))
        self.assertEqual(fingerprint(before),fingerprint(after))

    def test_pf_alias_traffic_and_evaluation_counters_are_runtime_only(self):
        counters=['eval_match','eval_nomatch','in_pass_b','in_pass_p','out_pass_b','out_pass_p','in_block_b','in_block_p','out_block_b','out_block_p']
        before={**EMPTY,'aliases':[{'uuid':'41175fa7-ce66-46da-9498-1f87161f2cbb','name':'Managed','type':'host','content':'192.0.2.1',**{name:'0' for name in counters}},
                                  {'name':'bogons','eval_nomatch':'1'},{'name':'bogonsv6','eval_nomatch':'2'}]}
        after=deepcopy(before)
        after['aliases'][0].update({name:str(index+100) for index,name in enumerate(counters)})
        after['aliases'][1]['eval_nomatch']='1234';after['aliases'][2]['eval_nomatch']='5678'
        self.assertEqual(configuration_changes(before,after),[])
        from .alias_sync import alias_fingerprint
        from .definition_sync import fingerprint
        self.assertEqual(alias_fingerprint(before['aliases']),alias_fingerprint(after['aliases']))
        self.assertEqual(fingerprint(before),fingerprint(after))
        after['aliases'][0]['content']='192.0.2.2'
        self.assertIn('content',' '.join(configuration_changes(before,after)))

    def test_counter_appearance_does_not_mask_other_alias_settings(self):
        before={**EMPTY,'aliases':[{'name':'A','type':'host','content':'192.0.2.1'}]}
        after=deepcopy(before);after['aliases'][0].update(eval_match='9',out_pass_p='10')
        self.assertEqual(configuration_changes(before,after),[])
        after['aliases'][0]['enabled']='0'
        self.assertIn('enabled',' '.join(configuration_changes(before,after)))
        after['aliases'][0]['custom_setting']='new'
        self.assertIn('custom_setting',' '.join(configuration_changes(before,after)))
        # Counter names are ignored only in alias records, not globally.
        self.assertTrue(configuration_changes({**EMPTY,'rules':[{'uuid':'r','eval_match':'1'}]},
                                              {**EMPTY,'rules':[{'uuid':'r','eval_match':'2'}]}))

class PreflightTests(TestCase):
    def setUp(self):
        self.fw=Firewall.objects.create(name='Test',base_url='https://test.example')
        interface=LogicalInterface.objects.create(name='LAN')
        InterfaceMapping.objects.create(firewall=self.fw,logical_interface=interface,device_interface='lan')
        self.rule=Rule.objects.create(name='Managed',interface=interface)
        self.data={**EMPTY,'rules':[{'uuid':'local','description':'Local','sequence':'20','interface':'lan','audit':'before'}]}
        Snapshot.objects.create(firewall=self.fw,data=self.data)
    def test_volatile_change_does_not_prevent_selected_rule_push(self):
        plan=deployment_plan(self.fw);payload=plan['rows'][0]['operation']['payload']
        live=deepcopy(self.data);live['rules'][0]['audit']='after'
        observed=deepcopy(live);observed['rules'].append({**payload,'uuid':'managed'})
        client=Mock();client.snapshot.side_effect=[live,observed]
        self.assertEqual(execute_deployment(self.fw,plan['approval_sha256'],[str(self.rule.pk)],client,'test'),1)
        client.save_rule.assert_called_once()
    def test_actual_change_names_field_and_performs_no_writes(self):
        plan=deployment_plan(self.fw);live=deepcopy(self.data);live['rules'][0]['action']='block'
        client=Mock();client.snapshot.return_value=live
        with self.assertRaisesMessage(DeviceError,'fields action'):
            execute_deployment(self.fw,plan['approval_sha256'],[str(self.rule.pk)],client,'test')
        client.save_rule.assert_not_called();client.apply_rules.assert_not_called()

    def test_live_alias_counters_do_not_prevent_rule_deployment(self):
        snapshot=self.fw.snapshots.first()
        snapshot.data={**self.data,'aliases':[{'uuid':'a','name':'LocalAlias','type':'host','content':'192.0.2.1','eval_match':'1','in_pass_b':'100'}]}
        snapshot.save()
        plan=deployment_plan(self.fw);payload=plan['rows'][0]['operation']['payload']
        live=deepcopy(snapshot.data);live['aliases'][0].update(eval_match='2',in_pass_b='200',out_pass_p='3')
        observed=deepcopy(live);observed['rules'].append({**payload,'uuid':'managed'})
        client=Mock();client.snapshot.side_effect=[live,observed]
        self.assertEqual(execute_deployment(self.fw,plan['approval_sha256'],[str(self.rule.pk)],client,'test'),1)
        client.save_rule.assert_called_once();client.apply_rules.assert_called_once()

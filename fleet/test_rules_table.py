from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Firewall,LogicalInterface,InterfaceMapping,InterfaceGroup,Category,Rule,Snapshot
from .rule_identity import short_marker

class RulesTableTests(TestCase):
    def setUp(self):
        self.admin=get_user_model().objects.create_superuser('table-admin',password='Test-only-password')
        self.client.force_login(self.admin)
        self.logical=LogicalInterface.objects.create(name='LAN')
        self.origin=LogicalInterface.objects.create(name='WAN')
        self.fw=Firewall.objects.create(name='One',base_url='https://one.test')
        InterfaceMapping.objects.create(firewall=self.fw,logical_interface=self.logical,device_interface='lan')
    def test_dense_columns_live_script_and_complete_filter_dataset(self):
        one=Rule.objects.create(name='DNS',interface=self.logical,protocol='UDP',destination_port='53',source_not=True,source='192.0.2.0/24')
        two=Rule.objects.create(name='Ping',floating=True,protocol='ICMP',icmp_types='echoreq',sequence=200)
        one.origin_interfaces.add(self.origin)
        response=self.client.get('/rules/?q=DNS')
        self.assertEqual(len(response.context['rows']),1)
        self.assertEqual(len(response.context['rules_data']['rows']),2)
        for heading in ('Origin','Version','Gateway','Commands','Categories'):
            self.assertContains(response,heading)
        self.assertContains(response,'rules.js')
        self.assertEqual(response.context['rows'][0]['origin_display'],'WAN')
        self.assertEqual(response.context['rows'][0]['protocol'],'UDP')
        self.assertEqual(response.context['rows'][0]['source_display'],'! 192.0.2.0/24')
        self.assertEqual(len(self.client.get('/rules/?q=  DNS  ').context['rows']),1)
        self.assertEqual(len(self.client.get('/rules/?q='+str(one.pk)).context['rows']),0)
    def test_snapshot_import_indices_and_categories_preserved(self):
        snapshot=Snapshot.objects.create(firewall=self.fw,data={'schema_version':1,'rules':[
            {'uuid':'a','description':'A','interface':'lan','sequence':'100','categories':'cat'},
            {'uuid':'b','description':'B','interface':'','sequence':'200'}],
            'aliases':[],'groups':[],'interfaces':[{'name':'lan','label':'LAN'}],'categories':[{'uuid':'cat','name':'Diagnostics','color':'abcdef'}]})
        response=self.client.get(f'/rules/?firewall={self.fw.pk}&q=B')
        data=response.context['rules_data']
        self.assertEqual([row['index'] for row in data['rows']],['0','1'])
        self.assertEqual(data['rows'][0]['category_badges'],[{'name':'Diagnostics','color':'abcdef'}])
        self.assertTrue(data['can_import'])
        self.assertContains(response,'rule-select-all')
        self.assertContains(response,'rule-hidden-selections')
    def test_managed_snapshot_rules_link_to_editor_without_origin_record(self):
        rule=Rule.objects.create(name='Managed',interface=self.logical)
        Snapshot.objects.create(firewall=self.fw,data={'schema_version':1,'rules':[{'uuid':'remote','description':'Managed '+short_marker(rule.pk),'interface':'lan','sequence':'100'}],'aliases':[]})
        row=self.client.get(f'/rules/?firewall={self.fw.pk}').context['rules_data']['rows'][0]
        self.assertEqual(row['manager_id'],str(rule.pk))
    def test_readonly_does_not_offer_import_and_description_cannot_execute_markup(self):
        Snapshot.objects.create(firewall=self.fw,data={'schema_version':1,'rules':[{'uuid':'x','description':'<img src=x onerror=alert(1)>','interface':'lan','sequence':'100'}],'aliases':[]})
        user=get_user_model().objects.create_user('viewer')
        from django.contrib.auth.models import Permission
        user.user_permissions.add(Permission.objects.get(content_type__app_label='fleet',codename='view_firewall'))
        self.client.force_login(user)
        response=self.client.get(f'/rules/?firewall={self.fw.pk}')
        self.assertFalse(response.context['rules_data']['can_import'])
        self.assertNotContains(response,'name="rule_indices"')
        self.assertNotContains(response,'<img src=x')
        self.assertContains(response,'&lt;img')

from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from .models import Firewall, LogicalInterface, InterfaceMapping, InterfaceGroup, Rule, Snapshot, AuditEvent
from .reconcile import plan_for
from .definition_sync import definition_plan
from .opnsense import DeviceError

EMPTY = {'schema_version':1, 'rules':[], 'aliases':[], 'groups':[], 'categories':[], 'interfaces':[]}

class GroupPullTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name='Branch', base_url='https://branch.invalid')
        self.lan = LogicalInterface.objects.create(name='LAN')
        self.wan = LogicalInterface.objects.create(name='WAN')
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.lan, device_interface='opt2')
        Snapshot.objects.create(firewall=self.fw, data=EMPTY)
        self.group = InterfaceGroup.objects.create(name='TRUSTED')
        self.group.members.set([self.lan,self.wan])
        self.user = get_user_model().objects.create_superuser('operator', password='Test-only-pass')
        self.client.force_login(self.user)

    def test_group_uses_available_members_without_changing_manager_membership(self):
        rule = Rule.objects.create(name='Group rule')
        rule.interface_groups.add(self.group)
        plan = plan_for(self.fw)
        self.assertFalse(plan['errors'])
        group = next(op for op in plan['operations'] if op['kind']=='group')
        self.assertEqual(group['payload']['members'],'opt2')
        self.assertEqual(next(op for op in plan['operations'] if op['kind']=='rule')['payload']['interface'],'TRUSTED')
        self.assertEqual(self.group.members.count(),2)
        other = Firewall.objects.create(name='Other',base_url='https://other.invalid')
        InterfaceMapping.objects.create(firewall=other,logical_interface=self.wan,device_interface='opt4')
        Snapshot.objects.create(firewall=other,data=EMPTY)
        self.assertEqual(definition_plan(other)['operations'][0]['payload']['members'],'opt4')

    def test_empty_group_blocks_writes_and_direct_bindings_stay_strict(self):
        self.fw.interface_mappings.all().delete()
        plan=definition_plan(self.fw)
        self.assertTrue(any('no mapped members' in error for error in plan['errors']))
        self.assertFalse(plan['operations'])
        Rule.objects.create(name='Direct',interface=self.wan)
        self.assertTrue(any('missing interface mapping' in error for error in plan_for(self.fw)['errors']))

    @patch('fleet.views.OPNsenseClient')
    def test_json_pull_updates_snapshot_mappings_and_audit(self, client):
        client.return_value.snapshot.return_value={**EMPTY,'interfaces':[{'name':'opt4','label':'WAN'}]}
        response=self.client.post(f'/firewalls/{self.fw.pk}/pull/',HTTP_ACCEPT='application/json')
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['ok'])
        self.assertIn('policy',response.json())
        self.assertEqual(self.fw.snapshots.count(),2)
        self.assertTrue(self.fw.interface_mappings.filter(device_interface='opt4').exists())
        self.assertTrue(AuditEvent.objects.filter(action='snapshot.pull').exists())
        client.return_value.snapshot.assert_called_once_with()
        client.return_value.save_definition.assert_not_called()

    @patch('fleet.views.OPNsenseClient')
    def test_pull_failures_keep_snapshot_and_disabled_devices_are_skipped(self, client):
        client.return_value.snapshot.side_effect=DeviceError('Connection failed')
        response=self.client.post(f'/firewalls/{self.fw.pk}/pull/',HTTP_ACCEPT='application/json')
        self.assertEqual(response.status_code,400)
        self.assertFalse(response.json()['ok'])
        self.assertEqual(self.fw.snapshots.count(),1)
        self.fw.enabled=False;self.fw.save()
        client.reset_mock()
        response=self.client.post(f'/firewalls/{self.fw.pk}/pull/',HTTP_ACCEPT='application/json')
        self.assertEqual(response.status_code,400)
        client.assert_not_called()

    @patch('fleet.views.OPNsenseClient')
    def test_table_fallback_returns_to_expected_page_and_prevents_open_redirect(self, client):
        client.return_value.snapshot.return_value=EMPTY
        url=f'/firewalls/{self.fw.pk}/pull/'
        for target, expected in [('overview','/'),('deployment','/fleet/deployment/'),('https://example.invalid',f'/firewalls/{self.fw.pk}/')]:
            response=self.client.post(url,{'return_to':target})
            self.assertRedirects(response,expected,fetch_redirect_response=False)

    @patch('fleet.views.OPNsenseClient')
    def test_pull_requires_permission_and_post(self, client):
        user=get_user_model().objects.create_user('viewer',is_staff=True)
        user.user_permissions.add(Permission.objects.get(content_type__app_label='fleet',codename='view_firewall'))
        self.client.force_login(user)
        self.assertEqual(self.client.post(f'/firewalls/{self.fw.pk}/pull/',HTTP_ACCEPT='application/json').status_code,403)
        for page in ('/','/fleet/deployment/'):
            self.assertNotContains(self.client.get(page),'data-pull-form')
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(f'/firewalls/{self.fw.pk}/pull/').status_code,405)
        client.assert_not_called()
        for page in ('/','/fleet/deployment/'):
            response=self.client.get(page)
            self.assertContains(response,'data-pull-all')
            self.assertContains(response,'data-pull-form')

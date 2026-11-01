from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from .models import Firewall, Snapshot, AuditEvent, Rule, LogicalInterface, InterfaceMapping, RuleOrigin


class FirewallDeletionTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser('test-admin', password='Test-only-account-password')
        self.client.force_login(self.admin)
        self.firewall = Firewall.objects.create(name='Amsterdam', base_url='https://demo.example.invalid')
        self.snapshot = Snapshot.objects.create(firewall=self.firewall, data={'schema_version':1, 'rules':[], 'aliases':[]})
        self.audit = AuditEvent.objects.create(actor='test', action='snapshot.import', detail='Amsterdam')

    def test_delete_confirmation_and_cascade_preserve_shared_policy_and_audit(self):
        interface = LogicalInterface.objects.create(name='VL10')
        InterfaceMapping.objects.create(firewall=self.firewall, logical_interface=interface, device_interface='opt2')
        rule = Rule.objects.create(name='Shared policy', interface=interface)
        RuleOrigin.objects.create(firewall=self.firewall, rule=rule, remote_uuid='source-rule')
        url = f'/admin/fleet/firewall/{self.firewall.pk}/delete/'
        response = self.client.get(url)
        self.assertContains(response, 'Are you sure')
        self.assertNotContains(response, "your account doesn't have permission")
        self.assertContains(response, 'Snapshot')
        self.assertEqual(self.client.post(url, {'post':'yes'}).status_code,302)
        self.assertFalse(Firewall.objects.exists())
        self.assertFalse(Snapshot.objects.exists())
        self.assertFalse(InterfaceMapping.objects.exists())
        self.assertFalse(RuleOrigin.objects.exists())
        self.assertTrue(Rule.objects.filter(pk=rule.pk).exists())
        self.assertTrue(LogicalInterface.objects.filter(pk=interface.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(pk=self.audit.pk).exists())

    def test_bulk_delete_firewalls_with_snapshots(self):
        other = Firewall.objects.create(name='London', base_url='https://other.example.invalid')
        Snapshot.objects.create(firewall=other, data={})
        payload = {'action':'delete_selected', '_selected_action':[self.firewall.pk, other.pk]}
        response = self.client.post('/admin/fleet/firewall/', payload)
        self.assertContains(response, 'Are you sure')
        self.assertEqual(self.client.post('/admin/fleet/firewall/', {**payload,'post':'yes'}).status_code,302)
        self.assertEqual(Firewall.objects.count(),0)
        self.assertEqual(Snapshot.objects.count(),0)

    def test_snapshots_and_audit_still_cannot_be_deleted_directly(self):
        for model, pk in [('snapshot', self.snapshot.pk), ('auditevent', self.audit.pk)]:
            url = f'/admin/fleet/{model}/{pk}/delete/'
            self.assertEqual(self.client.get(url).status_code,403)
            self.assertEqual(self.client.post(url, {'post':'yes'}).status_code,403)
        self.assertTrue(Snapshot.objects.exists())
        self.assertTrue(AuditEvent.objects.exists())

    def test_firewall_delete_permission_allows_owned_snapshot_cleanup(self):
        staff = get_user_model().objects.create_user('staff', is_staff=True)
        staff.user_permissions.add(*Permission.objects.filter(content_type__app_label='fleet', codename__in=['view_firewall','delete_firewall']))
        self.client.force_login(staff)
        self.assertFalse(staff.has_perm('fleet.delete_snapshot'))
        url = f'/admin/fleet/firewall/{self.firewall.pk}/delete/'
        self.assertContains(self.client.get(url), 'Are you sure')
        self.assertEqual(self.client.post(url, {'post':'yes'}).status_code,302)
        self.assertFalse(Snapshot.objects.exists())

    def test_user_without_firewall_delete_permission_is_denied(self):
        staff = get_user_model().objects.create_user('read-only-staff', is_staff=True)
        staff.user_permissions.add(Permission.objects.get(content_type__app_label='fleet',codename='view_firewall'))
        self.client.force_login(staff)
        url = f'/admin/fleet/firewall/{self.firewall.pk}/delete/'
        self.assertEqual(self.client.post(url, {'post':'yes'}).status_code,403)
        self.assertTrue(Firewall.objects.exists())
        self.assertTrue(Snapshot.objects.exists())

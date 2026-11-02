from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from .forms import RuleForm
from .models import InterfaceGroup, LogicalInterface, Rule


class RuleEditorTests(TestCase):
    def setUp(self):
        self.lan = LogicalInterface.objects.create(name='LAN')
        self.wan = LogicalInterface.objects.create(name='WAN')
        self.group = InterfaceGroup.objects.create(name='TRUSTED')
        self.group.members.add(self.lan)
        self.data = {
            'name': 'Allow DNS', 'sequence': '100', 'scope': 'all',
            'enabled': 'on', 'quick': 'on', 'action': 'pass',
            'direction': 'in', 'ip_version': 'inet', 'protocol': ['UDP'],
            'source': ['any'], 'destination': ['any'], 'destination_port': ['53'],
        }

    def save_rule(self, **fields):
        form = RuleForm({**self.data, **fields})
        self.assertTrue(form.is_valid(), form.errors)
        return form.save()

    def test_placement_is_derived_from_rule_bindings_only(self):
        for fields, floating in [
            ({}, True),
            ({'interfaces': [self.lan.pk]}, False),
            ({'interface_groups': [self.group.pk]}, False),
            ({'interfaces': [self.lan.pk, self.wan.pk]}, True),
            ({'interfaces': [self.lan.pk], 'interface_groups': [self.group.pk]}, True),
            ({'origin_interfaces': [self.lan.pk]}, True),
            ({'interfaces': [self.lan.pk], 'origin_interfaces': [self.lan.pk, self.wan.pk]}, False),
        ]:
            with self.subTest(fields=fields):
                rule = self.save_rule(**fields)
                rule.refresh_from_db()
                self.assertEqual(rule.floating, floating)

    def test_manual_floating_parameter_cannot_override_placement(self):
        self.assertNotIn('floating', RuleForm().fields)
        rule = self.save_rule(interfaces=[self.lan.pk], floating='on')
        self.assertFalse(rule.floating)

    def test_edit_recomputes_placement_and_preserves_other_bindings(self):
        rule = self.save_rule()
        form = RuleForm({**self.data, 'interfaces': [self.wan.pk],
                         'origin_interface_groups': [self.group.pk]}, instance=rule)
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save(commit=False)
        saved.save()
        form.save_m2m()
        saved.refresh_from_db()
        self.assertFalse(saved.floating)
        self.assertEqual(list(saved.interfaces.all()), [self.wan])
        self.assertEqual(list(saved.origin_interface_groups.all()), [self.group])

    def test_legacy_single_binding_is_preselected_when_opened(self):
        rule = Rule.objects.create(name='Legacy', interface=self.lan)
        form = RuleForm(instance=rule)
        self.assertIn(self.lan.pk, form.initial['interfaces'])

    def login(self, readonly=False):
        user = get_user_model().objects.create_user('viewer' if readonly else 'editor', is_staff=True, is_superuser=not readonly)
        if readonly:
            user.user_permissions.add(Permission.objects.get(content_type__app_label='fleet', codename='view_rule'))
        self.client.force_login(user)

    def test_admin_uses_compact_editor_and_server_derives_placement(self):
        self.login()
        response = self.client.get('/admin/fleet/rule/add/')
        for text in ('rule-editor.css', 'rule-editor.js', 'Search form', 'Full help', 'Placement', 'Deployment'):
            self.assertContains(response, text)
        self.assertNotContains(response, 'name="floating"')
        response = self.client.post('/admin/fleet/rule/add/', {**self.data, '_save': 'Save'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Rule.objects.get().floating)

    def test_readonly_user_can_view_editor_but_cannot_write(self):
        rule = self.save_rule(interfaces=[self.lan.pk])
        self.login(readonly=True)
        url = f'/admin/fleet/rule/{rule.pk}/change/'
        response = self.client.get(url)
        self.assertContains(response, 'Allow DNS')
        self.assertNotContains(response, 'name="_save"')
        self.assertEqual(self.client.post(url, self.data).status_code, 403)
        rule.refresh_from_db()
        self.assertFalse(rule.floating)

    def test_invalid_input_stays_bound_with_errors(self):
        self.login()
        response = self.client.post('/admin/fleet/rule/add/', {**self.data, 'name': '', 'interfaces': [self.lan.pk]})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This field is required.')
        self.assertContains(response, f'value="{self.lan.pk}" selected')
        self.assertFalse(Rule.objects.exists())

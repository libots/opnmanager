from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from .forms import RuleForm, port_is_valid
from .models import Alias, InterfaceGroup, LogicalInterface, Rule


class RuleEditorTests(TestCase):
    def setUp(self):
        self.lan = LogicalInterface.objects.create(name="LAN")
        self.wan = LogicalInterface.objects.create(name="WAN")
        self.group = InterfaceGroup.objects.create(name="TRUSTED")
        self.group.members.add(self.lan)
        self.data = {
            "name": "Allow DNS",
            "sequence": "100",
            "scope": "all",
            "enabled": "on",
            "quick": "on",
            "action": "pass",
            "direction": "in",
            "ip_version": "inet",
            "protocol": "UDP",
            "source": ["any"],
            "destination": ["any"],
            "destination_port": "53",
            "state_type": "keep",
        }

    def lan_(self):
        return f"interface:{self.lan.pk}"

    def save_rule(self, **fields):
        form = RuleForm({**self.data, **fields})
        self.assertTrue(form.is_valid(), form.errors)
        return form.save()

    def test_interface_list_combines_groups_and_interfaces_like_opnsense(self):
        field = RuleForm()["bindings"]
        html = str(field)
        self.assertIn('<optgroup label="Groups">', html)
        self.assertIn('<optgroup label="Interfaces">', html)
        self.assertLess(html.index("TRUSTED"), html.index(">LAN<"))
        rule = self.save_rule(
            bindings=[self.lan_(), f"group:{self.group.pk}"], origin_bindings=[f"interface:{self.wan.pk}"]
        )
        self.assertEqual(list(rule.interfaces.all()), [self.lan])
        self.assertEqual(list(rule.interface_groups.all()), [self.group])
        self.assertEqual(list(rule.origin_interfaces.all()), [self.wan])

    def test_placement_is_derived_from_rule_bindings_only(self):
        group = f"group:{self.group.pk}"
        wan = f"interface:{self.wan.pk}"
        for fields, floating in [
            ({}, True),
            ({"bindings": [self.lan_()]}, False),
            ({"bindings": [group]}, False),
            ({"bindings": [self.lan_(), wan]}, True),
            ({"bindings": [self.lan_(), group]}, True),
            ({"origin_bindings": [self.lan_()]}, True),
            ({"bindings": [self.lan_()], "origin_bindings": [self.lan_(), wan]}, False),
        ]:
            with self.subTest(fields=fields):
                rule = self.save_rule(**fields)
                rule.refresh_from_db()
                self.assertEqual(rule.floating, floating)

    def test_manual_floating_parameter_cannot_override_placement(self):
        self.assertNotIn("floating", RuleForm().fields)
        rule = self.save_rule(bindings=[self.lan_()], floating="on")
        self.assertFalse(rule.floating)

    def test_edit_recomputes_placement_and_replaces_bindings(self):
        rule = self.save_rule(bindings=[self.lan_()])
        form = RuleForm(
            {**self.data, "bindings": [f"interface:{self.wan.pk}"], "origin_bindings": [f"group:{self.group.pk}"]},
            instance=rule,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save(commit=False)
        saved.save()
        form.save_m2m()
        saved.refresh_from_db()
        self.assertFalse(saved.floating)
        self.assertEqual(list(saved.interfaces.all()), [self.wan])
        self.assertEqual(list(saved.origin_interface_groups.all()), [self.group])

    def test_existing_bindings_are_preselected_when_opened(self):
        rule = Rule.objects.create(name="Legacy", interface=self.lan)
        rule.origin_interface_groups.add(self.group)
        form = RuleForm(instance=rule)
        self.assertIn(self.lan_(), form.initial["bindings"])
        self.assertEqual(form.initial["origin_bindings"], [f"group:{self.group.pk}"])

    def test_opnsense_options_and_new_fields(self):
        form = RuleForm()
        self.assertIn(("match", "Match"), list(form.fields["action"].widget.choices))
        self.assertIn(("inet46", "any"), list(form.fields["ip_version"].widget.choices))
        self.assertIn(("none", "no state"), list(form.fields["state_type"].widget.choices))
        rule = self.save_rule(action="match", quick="", state_type="none", gateway="WAN_DHCP", origin_not="on")
        self.assertEqual(
            (rule.action, rule.state_type, rule.gateway, rule.origin_not), ("match", "none", "WAN_DHCP", True)
        )
        self.assertEqual(self.save_rule(state_type="").state_type, "keep")

    def test_port_selector_values(self):
        Alias.objects.create(name="WebPorts", type="port", content="80\n443")
        for value, ok in [
            ("", True),
            ("53", True),
            ("https", True),
            ("WebPorts", True),
            ("5060-5070", True),
            ("5070-5060", False),
            ("0", False),
            ("70000", False),
            ("80:90", False),
            ("nonsense", False),
        ]:
            with self.subTest(value=value):
                form = RuleForm({**self.data, "protocol": "TCP", "destination_port": value})
                self.assertEqual(form.is_valid(), ok, form.errors)
        self.assertTrue(port_is_valid("1-65535", set()))
        html = str(RuleForm()["destination_port"])
        self.assertIn('data-selector="port"', html)
        self.assertIn('<optgroup label="Ports">', html)
        self.assertIn("HTTPS (443)", html)

    def test_source_and_destination_are_multi_net_selectors(self):
        Alias.objects.create(name="Servers", content="10.0.0.1")
        html = str(RuleForm()["source"])
        self.assertIn('data-selector="net"', html)
        self.assertIn("multiple", html)
        self.assertIn('<optgroup label="Aliases">', html)
        self.assertIn("This Firewall", html)
        rule = self.save_rule(source=["Servers", "10.1.0.0/24"], destination=["@LAN:net"])
        self.assertEqual(rule.source, "Servers,10.1.0.0/24")

    def test_gateway_choices_include_names_seen_on_firewalls(self):
        from .models import Firewall, Snapshot

        fw = Firewall.objects.create(name="fw", base_url="https://fw.test")
        rules = [{"description": "x", "interface": "lan", "sequence": "1", "gateway": "WAN_GW"}]
        Snapshot.objects.create(firewall=fw, data={"schema_version": 1, "rules": rules, "aliases": []})
        self.assertIn(("WAN_GW", "WAN_GW"), list(RuleForm().fields["gateway"].widget.choices))

    def login(self, readonly=False):
        user = get_user_model().objects.create_user(
            "viewer" if readonly else "editor", is_staff=True, is_superuser=not readonly
        )
        if readonly:
            user.user_permissions.add(Permission.objects.get(content_type__app_label="fleet", codename="view_rule"))
        self.client.force_login(user)

    def test_admin_editor_mirrors_opnsense_dialog(self):
        self.login()
        response = self.client.get("/admin/fleet/rule/add/")
        for text in (
            "rule-editor.css",
            "rule-editor.js",
            "opn-select.js",
            "Search form",
            "full help",
            "advanced mode",
            "Organisation",
            "Stateful firewall",
            "Source Routing",
            "Deployment",
            "Interface (rule)",
            "Invert interface (origin)",
        ):
            self.assertContains(response, text)
        self.assertContains(response, 'class="form-row rule-editor-row field-interface_not advanced')
        self.assertNotContains(response, 'name="floating"')
        response = self.client.post("/admin/fleet/rule/add/", {**self.data, "_save": "Save"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Rule.objects.get().floating)

    def test_readonly_user_can_view_editor_but_cannot_write(self):
        rule = self.save_rule(bindings=[self.lan_()])
        self.login(readonly=True)
        url = f"/admin/fleet/rule/{rule.pk}/change/"
        response = self.client.get(url)
        self.assertContains(response, "Allow DNS")
        self.assertNotContains(response, 'name="_save"')
        self.assertEqual(self.client.post(url, self.data).status_code, 403)
        rule.refresh_from_db()
        self.assertFalse(rule.floating)

    def test_invalid_input_stays_bound_with_errors(self):
        self.login()
        response = self.client.post("/admin/fleet/rule/add/", {**self.data, "name": "", "bindings": [self.lan_()]})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This field is required.")
        self.assertContains(response, f'value="{self.lan_()}" selected')
        self.assertFalse(Rule.objects.exists())

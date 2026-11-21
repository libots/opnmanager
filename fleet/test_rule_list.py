from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from .models import Alias, Category, LogicalInterface, Rule


class RuleListCommandTests(TestCase):
    """Firewall: Rules commands: clone, bulk toggles/delete, editing several rules, redirects."""

    def setUp(self):
        self.admin = get_user_model().objects.create_superuser("list-admin", password="Test-only-password")
        self.client.force_login(self.admin)
        self.lan = LogicalInterface.objects.create(name="LAN")
        self.cat = Category.objects.create(name="Infra")
        self.dns = Rule.objects.create(name="DNS", protocol="UDP", destination_port="53", sequence=100)
        self.dns.interfaces.add(self.lan)
        self.dns.categories.add(self.cat)
        self.web = Rule.objects.create(name="Web", protocol="TCP", destination_port="443", sequence=110, log=True)
        self.web.interfaces.add(self.lan)

    def bulk(self, action, *rules, **extra):
        return self.client.post("/admin/fleet/rule/bulk/", {"action": action, "ids": [r.pk for r in rules], **extra})

    def test_admin_changelist_and_saves_return_to_rules_page(self):
        self.assertRedirects(self.client.get("/admin/fleet/rule/"), "/rules/", fetch_redirect_response=False)
        url = f"/admin/fleet/rule/{self.web.pk}/change/?_next=/rules/%3Fq%3DWeb"
        data = {
            "name": "Web",
            "sequence": "110",
            "scope": "all",
            "enabled": "on",
            "quick": "on",
            "action": "pass",
            "direction": "in",
            "ip_version": "inet",
            "protocol": "TCP",
            "source": "any",
            "destination": "any",
            "destination_port": "443",
            "state_type": "keep",
            "_save": "Save",
        }
        self.assertRedirects(self.client.post(url, data), "/rules/?q=Web", fetch_redirect_response=False)
        # Only same-site targets are followed.
        url = f"/admin/fleet/rule/{self.web.pk}/change/?_next=https://evil.test/"
        self.assertRedirects(self.client.post(url, data), "/rules/", fetch_redirect_response=False)

    def test_clone_opens_prefilled_add_dialog_with_next_free_sequence(self):
        Rule.objects.create(name="Taken", sequence=101)
        response = self.client.get(f"/admin/fleet/rule/add/?clone={self.dns.pk}")
        form = response.context["adminform"].form
        self.assertEqual(form.initial["name"], "DNS")
        self.assertEqual(form.initial["sequence"], 102)
        self.assertEqual(form.initial["bindings"], [f"interface:{self.lan.pk}"])
        self.assertEqual(form.initial["categories"], [str(self.cat.pk)])
        self.assertEqual(form.initial["destination_port"], "53")
        self.assertContains(response, f'value="interface:{self.lan.pk}" selected')

    def test_empty_single_value_pickers_stay_any_when_cloning_or_editing_together(self):
        # A port alias is the first port option; an empty port must not fall back to it.
        Alias.objects.create(name="PrinterPorts", type="port", content="9100")
        import re

        def selected(response, name):
            select = re.search(rf'<select name="{name}".*?</select>', response.content.decode(), re.S).group(0)
            return re.findall(r'<option value="([^"]*)"[^>]*selected', select)

        clone = self.client.get(f"/admin/fleet/rule/add/?clone={self.dns.pk}")
        self.assertEqual(clone.context["adminform"].form.initial["source_port"], "")
        self.assertEqual(selected(clone, "source_port"), [""])
        self.assertEqual(selected(clone, "destination_port"), ["53"])
        self.assertEqual(selected(clone, "gateway"), [""])
        bulk = self.client.get(f"/admin/fleet/rule/bulk-edit/?ids={self.dns.pk}&ids={self.web.pk}")
        self.assertEqual(selected(bulk, "source_port"), [""])
        self.assertEqual(selected(bulk, "action"), ["pass"])

    def test_every_single_value_picker_has_exactly_one_option_selected(self):
        # A single-value picker with nothing selected falls back to its first option in the browser.
        import re

        from .forms import RuleForm, SearchSelect

        Alias.objects.create(name="PrinterPorts", type="port", content="9100")
        empty = Rule.objects.create(name="Empty", sequence=7, gateway="")
        pickers = [name for name, field in RuleForm().fields.items() if isinstance(field.widget, SearchSelect)]
        self.assertIn("source_port", pickers)
        pages = [
            f"/admin/fleet/rule/{empty.pk}/change/",
            f"/admin/fleet/rule/add/?clone={empty.pk}",
            f"/admin/fleet/rule/add/?clone={self.dns.pk}",
            "/admin/fleet/rule/add/",
            f"/admin/fleet/rule/bulk-edit/?ids={empty.pk}&ids={self.dns.pk}",
        ]
        for url in pages:
            response = self.client.get(url)
            html = response.content.decode()
            mixed = set(response.context.get("bulk_mixed") or [])
            for name in pickers:
                if name in mixed:
                    continue
                with self.subTest(url=url, field=name):
                    select = re.search(rf'<select name="{name}".*?</select>', html, re.S).group(0)
                    self.assertEqual(len(re.findall(r"<option [^>]*\sselected(?=[\s>])", select)), 1, select[:300])

    def test_bulk_toggles_and_delete(self):
        self.bulk("disable", self.dns, self.web, _next="/rules/?q=x")
        self.assertFalse(Rule.objects.filter(enabled=True).exists())
        self.bulk("log", self.dns)
        self.dns.refresh_from_db()
        self.assertTrue(self.dns.log)
        self.bulk("nolog", self.dns, self.web)
        self.assertFalse(Rule.objects.filter(log=True).exists())
        response = self.bulk("delete", self.web)
        self.assertRedirects(response, "/rules/", fetch_redirect_response=False)
        self.assertEqual(list(Rule.objects.all()), [self.dns])

    def test_bulk_commands_need_permissions(self):
        viewer = get_user_model().objects.create_user("viewer", is_staff=True)
        viewer.user_permissions.add(Permission.objects.get(codename="view_rule"))
        viewer.user_permissions.add(Permission.objects.get(codename="change_rule"))
        self.client.force_login(viewer)
        self.assertEqual(self.bulk("delete", self.dns).status_code, 403)
        self.bulk("disable", self.dns)
        self.dns.refresh_from_db()
        self.assertFalse(self.dns.enabled)

    def test_editing_several_rules_marks_differing_fields_and_saves_only_changes(self):
        url = f"/admin/fleet/rule/bulk-edit/?ids={self.dns.pk}&ids={self.web.pk}"
        response = self.client.get(url)
        mixed = response.context["bulk_mixed"]
        for name in ("name", "protocol", "destination_port", "log", "categories", "sequence"):
            self.assertIn(name, mixed)
        for name in ("bindings", "action", "direction", "source"):
            self.assertNotIn(name, mixed)
        self.assertContains(response, "Multiple values")
        self.assertContains(response, f'value="interface:{self.lan.pk}" selected')
        # Log was ticked only on Web; ticking it for both changes nothing else.
        response = self.client.post(url, {"_changed": ["log"], "log": "on", "name": "ignored", "_save": "Save"})
        self.assertRedirects(response, "/rules/", fetch_redirect_response=False)
        self.dns.refresh_from_db()
        self.web.refresh_from_db()
        self.assertTrue(self.dns.log and self.web.log)
        self.assertEqual((self.dns.name, self.web.name), ("DNS", "Web"))
        self.assertEqual(list(self.dns.categories.all()), [self.cat])
        self.assertEqual(list(self.web.interfaces.all()), [self.lan])
        # Clearing a multi-value field and unticking a box apply to every rule.
        self.client.post(url, {"_changed": ["bindings", "log"]})
        self.assertFalse(Rule.objects.filter(log=True).exists())
        self.assertFalse(Rule.objects.filter(interfaces__isnull=False).exists())
        self.assertTrue(Rule.objects.get(pk=self.dns.pk).floating)

    def test_editing_several_rules_is_all_or_nothing(self):
        any_rule = Rule.objects.create(name="Any", sequence=5)
        url = f"/admin/fleet/rule/bulk-edit/?ids={self.dns.pk}&ids={any_rule.pk}"
        # A destination port is invalid on the "any" protocol rule, so nothing is saved.
        response = self.client.post(url, {"_changed": ["destination_port"], "destination_port": "80"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("Any:" in error for error in response.context["bulk_errors"]))
        self.assertEqual(response.context["bulk_changed"], ["destination_port"])
        self.dns.refresh_from_db()
        self.assertEqual(self.dns.destination_port, "53")

    def test_rules_page_offers_selection_and_commands(self):
        response = self.client.get("/rules/")
        self.assertContains(response, 'id="rule-select-all"')
        self.assertContains(response, 'id="rule-bulk-form"')
        self.assertContains(response, 'data-bulk="edit"')
        self.assertContains(response, 'data-icon="copy-regular"')
        data = response.context["rules_data"]
        self.assertTrue(data["manager"] and data["can_delete"] and data["can_add"])
        self.assertEqual({row["binding_count"] for row in data["rows"]}, {1})

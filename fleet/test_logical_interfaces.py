from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from .models import (
    AuditEvent,
    DeviceInventory,
    Firewall,
    InterfaceGroup,
    InterfaceMapping,
    LogicalInterface,
    Rule,
    Snapshot,
)


def inventory_row(name, label, device="", ipv4=""):
    return {"name": name, "description": label, "device": device, "status": "up", "ipv4": ipv4, "ipv6": ""}


class LogicalInterfacePageTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser("li-admin", password="Test-only-password")
        self.client.force_login(self.admin)
        self.one = Firewall.objects.create(name="One", base_url="https://one.test")
        self.two = Firewall.objects.create(name="Two", base_url="https://two.test")
        self.lan = LogicalInterface.objects.create(name="LAN")
        self.iot = LogicalInterface.objects.create(name="IoT")
        DeviceInventory.objects.create(
            firewall=self.one,
            data={
                "interfaces": [
                    inventory_row("lan", "LAN", "igb1", "10.0.0.1/24"),
                    inventory_row("opt1", "IoT", "igb1.30", "10.0.30.1/24"),
                    inventory_row("opt9", "Spare Port"),
                ]
            },
        )
        # Two has no inventory refresh yet; its interface names come from the snapshot.
        Snapshot.objects.create(
            firewall=self.two,
            data={"schema_version": 1, "rules": [], "aliases": [], "interfaces": [{"name": "lan", "label": "LAN"}]},
        )
        InterfaceMapping.objects.create(firewall=self.one, logical_interface=self.lan, device_interface="lan")

    def save(self, data, **extra):
        return self.client.post("/fleet/mappings/save/", data, **extra)

    def mapping(self, fw, logical):
        return InterfaceMapping.objects.filter(firewall=fw, logical_interface=logical).first()

    def test_page_offers_each_firewalls_interfaces_and_shows_usage(self):
        Rule.objects.create(name="r", source="@LAN:net")
        InterfaceGroup.objects.create(name="G").members.add(self.lan)
        response = self.client.get("/fleet/logical-interfaces/")
        html = response.content.decode()
        self.assertIn(f'name="map_{self.one.pk}_{self.lan.pk}"', html)
        self.assertIn('<option value="opt1" data-label="iot"', html)
        self.assertIn("igb1.30 · 10.0.30.1/24 · up", html)
        self.assertIn('<option value="lan" data-label="lan"', html)  # from Two's snapshot
        self.assertIn("1 rule · 1 group", html)
        self.assertIn('class="li-corner"', html)
        # Unmapped device interfaces can become new logical interfaces in one step.
        self.assertIn("＋ Spare_Port", html)
        self.assertNotIn("＋ IoT", html)  # IoT already exists; "Fill matches" covers it

    def test_save_sets_changes_and_removes_mappings_together(self):
        response = self.save(
            {
                f"map_{self.one.pk}_{self.iot.pk}": "opt1",
                f"map_{self.two.pk}_{self.lan.pk}": "lan",
                f"map_{self.one.pk}_{self.lan.pk}": "",
                "next": "/fleet/logical-interfaces/?firewalls=1",
            }
        )
        self.assertRedirects(response, "/fleet/logical-interfaces/?firewalls=1", fetch_redirect_response=False)
        self.assertEqual(self.mapping(self.one, self.iot).device_interface, "opt1")
        self.assertEqual(self.mapping(self.two, self.lan).device_interface, "lan")
        self.assertIsNone(self.mapping(self.one, self.lan))
        self.assertIn("One: LAN unmapped", AuditEvent.objects.get(action="mapping.updated").detail)

    def test_swapping_two_interfaces_in_one_save_works(self):
        InterfaceMapping.objects.create(firewall=self.one, logical_interface=self.iot, device_interface="opt1")
        self.save({f"map_{self.one.pk}_{self.lan.pk}": "opt1", f"map_{self.one.pk}_{self.iot.pk}": "lan"})
        self.assertEqual(self.mapping(self.one, self.lan).device_interface, "opt1")
        self.assertEqual(self.mapping(self.one, self.iot).device_interface, "lan")

    def test_conflicts_and_bad_identifiers_save_nothing(self):
        response = self.save({f"map_{self.one.pk}_{self.iot.pk}": "lan", f"map_{self.two.pk}_{self.lan.pk}": "lan"})
        self.assertIsNone(self.mapping(self.one, self.iot))
        self.assertIsNone(self.mapping(self.two, self.lan))
        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertTrue(any("more than one logical interface" in m for m in messages), messages)
        self.save({f"map_{self.two.pk}_{self.lan.pk}": "not valid"})
        self.assertIsNone(self.mapping(self.two, self.lan))
        # Off-site "next" targets are ignored.
        response = self.save({f"map_{self.two.pk}_{self.lan.pk}": "lan", "next": "https://evil.test/"})
        self.assertRedirects(response, "/fleet/logical-interfaces/", fetch_redirect_response=False)

    def test_create_logical_interface_and_map_it(self):
        self.client.post(
            "/fleet/logical-interfaces/add/", {"name": "Spare_Port", "firewall": self.one.pk, "device": "opt9"}
        )
        spare = LogicalInterface.objects.get(name="Spare_Port")
        self.assertEqual(self.mapping(self.one, spare).device_interface, "opt9")
        response = self.client.post("/fleet/logical-interfaces/add/", {"name": "bad name"})
        self.assertFalse(LogicalInterface.objects.filter(name="bad name").exists())
        self.assertTrue(any("bad name" in str(m) for m in response.wsgi_request._messages))
        # A taken device interface rolls the new logical interface back too.
        self.client.post("/fleet/logical-interfaces/add/", {"name": "Other", "firewall": self.one.pk, "device": "lan"})
        self.assertFalse(LogicalInterface.objects.filter(name="Other").exists())

    def test_viewers_see_values_but_cannot_save(self):
        viewer = get_user_model().objects.create_user("viewer")
        viewer.user_permissions.add(Permission.objects.get(codename="view_firewall"))
        self.client.force_login(viewer)
        response = self.client.get("/fleet/logical-interfaces/")
        self.assertNotContains(response, 'name="map_')
        self.assertContains(response, "lan · LAN")
        self.assertEqual(self.save({f"map_{self.one.pk}_{self.iot.pk}": "opt1"}).status_code, 403)
        self.assertEqual(self.client.post("/fleet/logical-interfaces/add/", {"name": "X"}).status_code, 403)

    def test_firewall_page_picks_device_interfaces_from_its_inventory(self):
        response = self.client.get(f"/admin/fleet/firewall/{self.one.pk}/change/")
        self.assertContains(response, "opt1 · IoT (igb1.30 · 10.0.30.1/24)")
        self.assertContains(response, "1 of 2 logical interfaces mapped")
        self.assertNotContains(response, 'id="change_id_interface_mappings-0-logical_interface"')
        self.assertContains(response, "Firewall group")

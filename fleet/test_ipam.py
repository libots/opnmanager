import copy
import ipaddress
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase

from .dhcp import execute_reservation_sync, import_reservations, read_state, refresh_dhcp, reservation_plan
from .ipam import (
    TemplateError,
    encode_option,
    interface_plan,
    next_free,
    normalize_mac,
    render_dnsmasq,
    render_kea,
    resolve_interface,
    resolve_range,
    scope_settings,
    split_range,
)
from .jobs import run_pending
from .models import (
    AddressRange,
    Alias,
    AuditEvent,
    DeviceJob,
    DhcpOption,
    DhcpScope,
    Firewall,
    InterfaceAddressing,
    InterfaceMapping,
    LogicalInterface,
    StaticReservation,
)
from .opnsense import DeviceError
from .rule_identity import short_marker

HOME = ipaddress.ip_network("10.20.0.0/16")
HOME6 = ipaddress.ip_network("2001:db8:0:1400::/56")


class TemplateTests(SimpleTestCase):
    def test_site_parts_come_from_the_site_prefix(self):
        self.assertEqual(str(resolve_interface("10.x.40.1/21", HOME)), "10.20.40.1/21")
        self.assertEqual(str(resolve_interface("10.x.24.1/21", ipaddress.ip_network("10.22.0.0/16"))), "10.22.24.1/21")
        self.assertEqual(str(resolve_interface("x:x:x:40::1/64", HOME6)), "2001:db8:0:1440::1/64")
        self.assertEqual(str(resolve_interface("0.0.40.1/21", HOME)), "10.20.40.1/21")

    def test_templates_that_dont_fit_the_site_are_rejected(self):
        for template in ("192.168.40.1/21", "10.x.40.1/12", "10.x.40/21", "10.x.40.1"):
            with self.subTest(template=template), self.assertRaises(TemplateError):
                resolve_interface(template, HOME)

    def test_ranges_with_shorthand_and_offsets(self):
        subnet = ipaddress.ip_network("10.20.8.0/21")
        self.assertEqual(split_range("10.x.10.10-29"), ("10.x.10.10", "10.x.10.29"))
        first, last = resolve_range("10.x.10.10-29", subnet, HOME)
        self.assertEqual((str(first), str(last)), ("10.20.10.10", "10.20.10.29"))
        first, last = resolve_range("+100-+199", subnet, HOME)
        self.assertEqual((str(first), str(last)), ("10.20.8.100", "10.20.8.199"))
        first, last = resolve_range("-11--2", subnet, HOME)
        self.assertEqual((str(first), str(last)), ("10.20.15.244", "10.20.15.253"))
        with self.assertRaises(TemplateError):
            resolve_range("10.x.40.10-29", subnet, HOME)  # outside the subnet
        with self.assertRaises(TemplateError):
            resolve_range("10.x.10.29-10", subnet, HOME)

    def test_option_encoding_and_macs(self):
        self.assertEqual(encode_option("unifi", ["10.20.10.5"]), "01:04:0a:14:0a:05")
        self.assertEqual(encode_option("ip", ["10.0.0.1", "10.0.0.2"]), "0a:00:00:01:0a:00:00:02")
        self.assertEqual(encode_option("uint16", ["1500"]), "05:dc")
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("nope"), "")
        first, last = ipaddress.ip_address("10.0.0.1"), ipaddress.ip_address("10.0.0.3")
        self.assertEqual(str(next_free(first, last, {"10.0.0.1"})), "10.0.0.2")
        self.assertIsNone(next_free(first, last, {"10.0.0.1", "10.0.0.2", "10.0.0.3"}))


class AddressPlanTests(TestCase):
    """Three sites, one plan: home 10.20, VH 10.21, Afton 10.22."""

    def setUp(self):
        self.sites = [
            Firewall.objects.create(
                name=name,
                base_url=f"https://{name.lower()}.test",
                credential_prefix=name.upper(),
                ipv4_site_prefix=f"10.{octet}.0.0/16",
                ipv6_site_prefix=f"2001:db8:0:{octet - 6}00::/56",
            )
            for name, octet in (("Home", 20), ("VH", 21), ("Afton", 22))
        ]
        self.home = self.sites[0]
        self.vl10 = LogicalInterface.objects.create(name="VL10")
        self.vl40 = LogicalInterface.objects.create(name="VL40")
        InterfaceAddressing.objects.create(
            logical_interface=self.vl10, ipv4_address="10.x.8.1/21", ipv6_address="x:x:x:10::1/64"
        )
        InterfaceAddressing.objects.create(logical_interface=self.vl40, ipv4_address="10.x.40.1/21")
        for fw in self.sites:
            InterfaceMapping.objects.create(firewall=fw, logical_interface=self.vl10, device_interface="opt1")
            InterfaceMapping.objects.create(firewall=fw, logical_interface=self.vl40, device_interface="opt4")
        self.client.force_login(get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1"))

    def test_editors_render(self):
        for path in (
            "/admin/fleet/interfaceaddressing/add/",
            "/admin/fleet/addressrange/add/",
            "/admin/fleet/dhcpscope/add/",
            "/admin/fleet/staticreservation/add/?mac_address=aa:bb:cc:00:00:01",
            f"/admin/fleet/firewall/{self.home.pk}/change/",
        ):
            with self.subTest(path=path):
                self.assertContains(self.client.get(path), "opn-sidebar")

    def test_firewall_prefixes_are_validated(self):
        self.home.ipv4_site_prefix = "10.20.1.0/16"
        with self.assertRaises(ValidationError):
            self.home.full_clean()
        self.home.ipv4_site_prefix = " 10.20.0.0/16 "
        self.home.full_clean()
        self.assertEqual(self.home.ipv4_site_prefix, "10.20.0.0/16")

    def test_plan_resolves_per_site_and_compares_with_inventory(self):
        from .models import DeviceInventory

        plans = [interface_plan(self.vl40.addressing, fw)[4]["interface"] for fw in self.sites]
        self.assertEqual([str(p) for p in plans], ["10.20.40.1/21", "10.21.40.1/21", "10.22.40.1/21"])
        self.assertEqual(str(interface_plan(self.vl10.addressing, self.home)[6]["subnet"]), "2001:db8:0:1410::/64")
        DeviceInventory.objects.create(
            firewall=self.home,
            data={"interfaces": [{"name": "opt4", "ipv4": "10.20.40.1/21"}, {"name": "opt1", "ipv4": "10.20.9.1/21"}]},
        )
        page = self.client.get("/ipam/")
        self.assertContains(page, "10.21.40.0/21")
        self.assertContains(page, "2001:db8:0:1410::/64")
        self.assertContains(page, 'title="Observed 10.20.40.1/21">✓</span>')
        self.assertContains(page, "observed 10.20.9.1/21")

    def test_dhcp_scope_resolves_router_aliases_and_unifi(self):
        Alias.objects.create(name="AD_DNS", content="10.20.10.5\n10.21.10.5")
        scope = DhcpScope.objects.create(
            name="VL40 clients",
            logical_interface=self.vl40,
            dynamic_range="10.x.47.0-250",
            dns_servers="AD_DNS, 0.0.0.0",
            domain_name="corp.example",
        )
        DhcpOption.objects.create(scope=scope, code=43, kind="unifi", value="10.x.10.5")
        planned = interface_plan(self.vl40.addressing, self.sites[1])[4]
        aliases = {"AD_DNS": "10.20.10.5\n10.21.10.5"}
        settings = scope_settings(
            scope, planned["subnet"], ipaddress.ip_network("10.21.0.0/16"), planned["router"], aliases
        )
        options = {o["code"]: o for o in settings["options"]}
        self.assertEqual(settings["range"], {"start": "10.21.47.0", "end": "10.21.47.250", "size": 251})
        self.assertEqual(options[3]["values"], ["10.21.40.1"])
        self.assertEqual(options[6]["values"], ["10.20.10.5", "10.21.10.5", "10.21.40.1"])
        self.assertEqual(options[43]["hex"], "01:04:0a:15:0a:05")
        lines = render_dnsmasq(settings, "opt4")
        self.assertIn("dhcp-range=opt4,10.21.47.0,10.21.47.250", lines)
        self.assertIn("dhcp-option=opt4,43,01:04:0a:15:0a:05", lines)
        kea = render_kea(settings, "opt4")
        self.assertEqual(kea["pools"], [{"pool": "10.21.47.0 - 10.21.47.250"}])
        self.assertIn({"code": 43, "csv-format": False, "data": "01040a150a05"}, kea["option-data"])
        page = self.client.get("/ipam/dhcp/")
        self.assertContains(page, "10.22.47.0 – 10.22.47.250")
        self.assertContains(page, "UniFi 10.20.10.5")

    def test_dhcp_scope_form_rejects_unknown_servers(self):
        from .forms import DhcpScopeForm

        form = DhcpScopeForm(
            data={
                "name": "VL40",
                "logical_interface": self.vl40.pk,
                "enabled": "on",
                "gateway": "0.0.0.0",
                "dns_servers": "MISSING, 10.x.10.5",
                "targets": ["all"],
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("MISSING is not a host alias", str(form.errors["dns_servers"]))

    def test_ranges_page_counts_reservations_and_flags_overlaps(self):
        AddressRange.objects.create(logical_interface=self.vl10, name="Switches", addresses="10.x.10.10-29")
        AddressRange.objects.create(logical_interface=self.vl10, name="APs", addresses="10.x.10.25-49")
        StaticReservation.objects.create(
            firewall=self.home, logical_interface=self.vl10, ip_address="10.20.10.11", mac_address="aa:bb:cc:00:00:01"
        )
        page = self.client.get("/ipam/ranges/")
        self.assertContains(page, "10.21.10.10 – 10.21.10.29")
        self.assertContains(page, "1 of 20 reserved")
        self.assertContains(page, "Overlaps APs.")

    def test_reservation_must_be_inside_its_subnet(self):
        reservation = StaticReservation(
            firewall=self.home, logical_interface=self.vl40, ip_address="10.21.40.10", mac_address="AA-BB-CC-00-00-02"
        )
        with self.assertRaisesMessage(ValidationError, "outside 10.20.40.0/21"):
            reservation.full_clean()
        reservation.ip_address = "10.20.40.1"
        with self.assertRaisesMessage(ValidationError, "network, broadcast or firewall address"):
            reservation.full_clean()
        reservation.ip_address = "10.20.41.10"
        reservation.full_clean()
        self.assertEqual(reservation.mac_address, "aa:bb:cc:00:00:02")


DNSMASQ_LEASES = {
    "rows": [
        {
            "address": "10.20.9.50",
            "hwaddr": "AA:BB:CC:00:00:10",
            "hostname": "usw-24",
            "expire": "1800000000",
            "if_descr": "VL10",
            "lease_type": "dynamic",
        },
        {"address": "2001:db8::5", "hwaddr": "aa:bb:cc:00:00:11", "hostname": "v6"},
    ]
}


def dnsmasq_hosts(*rows):
    return {"rows": list(rows)}


class ReservationSyncTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(
            name="Home", base_url="https://home.test", credential_prefix="HOME", ipv4_site_prefix="10.20.0.0/16"
        )
        self.vl10 = LogicalInterface.objects.create(name="VL10")
        InterfaceAddressing.objects.create(logical_interface=self.vl10, ipv4_address="10.x.8.1/21")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.vl10, device_interface="opt1")
        AddressRange.objects.create(logical_interface=self.vl10, name="Switches", addresses="10.x.10.10-29")
        self.local = {
            "uuid": "local-1",
            "ip": "10.20.10.40",
            "hwaddr": "aa:bb:cc:00:00:20",
            "host": "printer",
            "descr": "",
        }
        self.user = get_user_model().objects.create_superuser("admin-test", password="Test-only-pw-1")
        self.client.force_login(self.user)

    def device(self, *hosts, leases=DNSMASQ_LEASES):
        client = Mock()

        def post(path, payload, write=True):
            if path.endswith("search_host"):
                return dnsmasq_hosts(*copy.deepcopy(hosts))
            if path.endswith("leases/search"):
                return copy.deepcopy(leases)
            raise AssertionError(path)

        client.post.side_effect = post
        return client

    def test_read_keeps_ipv4_leases_and_normalizes_reservations(self):
        state = read_state(self.fw, self.device(self.local))
        self.assertEqual([lease["address"] for lease in state["leases"]], ["10.20.9.50"])
        self.assertEqual(state["leases"][0]["mac"], "aa:bb:cc:00:00:10")
        self.assertTrue(state["leases"][0]["expire"].startswith("2027-01-15"))
        self.assertEqual(state["reservations"][0]["hostname"], "printer")
        self.assertFalse(state["reservations"][0]["managed"])

    def test_page_offers_reserve_and_next_free_range_address(self):
        refresh_dhcp(self.fw, self.device(self.local))
        page = self.client.get(f"/ipam/reservations/?firewall={self.fw.pk}")
        self.assertContains(page, "Switches: 10.20.10.10")
        self.assertContains(page, "ip_address=10.20.9.50")
        self.assertContains(page, "Reservations made on the firewall")

    def test_import_is_all_or_nothing_and_device_unchanged(self):
        refresh_dhcp(
            self.fw,
            self.device(self.local, {**self.local, "uuid": "bad", "ip": "192.168.1.5", "hwaddr": "aa:bb:cc:00:00:21"}),
        )
        with self.assertRaisesMessage(DeviceError, "isn't in the address plan"):
            import_reservations(self.fw, ["local-1", "bad"], "test")
        self.assertFalse(StaticReservation.objects.exists())
        self.assertEqual(import_reservations(self.fw, ["local-1"], "test"), 1)
        reservation = StaticReservation.objects.get()
        self.assertEqual((reservation.remote_uuid, reservation.hostname), ("local-1", "printer"))
        plan = reservation_plan(self.fw)
        self.assertEqual(plan["rows"][0]["action"], "update")
        self.assertEqual(plan["rows"][0]["remote_uuid"], "local-1")
        self.assertEqual(plan["rows"][0]["payload"]["descr"], "printer " + short_marker(reservation.uid))

    def test_conflicting_device_reservation_blocks_the_row(self):
        refresh_dhcp(self.fw, self.device(self.local))
        StaticReservation.objects.create(
            firewall=self.fw, logical_interface=self.vl10, ip_address="10.20.10.40", mac_address="aa:bb:cc:00:00:99"
        )
        row = reservation_plan(self.fw)["rows"][0]
        self.assertIsNone(row["action"])
        self.assertIn("a reservation made on the firewall", row["errors"][0])

    def test_sync_writes_reloads_verifies_and_offers_removals(self):
        reservation = StaticReservation.objects.create(
            firewall=self.fw,
            logical_interface=self.vl10,
            ip_address="10.20.10.10",
            mac_address="aa:bb:cc:00:00:01",
            hostname="usw-core",
        )
        stale = {
            "uuid": "old",
            "ip": "10.20.10.11",
            "hwaddr": "aa:bb:cc:00:00:02",
            "host": "gone",
            "descr": "gone [om:0123456789ab]",
        }
        refresh_dhcp(self.fw, self.device(self.local, stale))
        plan = reservation_plan(self.fw)
        self.assertEqual(plan["rows"][0]["action"], "create")
        self.assertEqual([r["uuid"] for r in plan["removals"]], ["old"])
        written = {
            "uuid": "new",
            "ip": "10.20.10.10",
            "hwaddr": "aa:bb:cc:00:00:01",
            "host": "usw-core",
            "descr": "usw-core " + short_marker(reservation.uid),
        }
        reads = iter([[self.local, stale], [self.local, written]])
        client = Mock()
        calls = []

        def post(path, payload, write=True):
            calls.append(path)
            if path.endswith("search_host"):
                return dnsmasq_hosts(*copy.deepcopy(next(reads)))
            if path.endswith("leases/search"):
                return copy.deepcopy(DNSMASQ_LEASES)
            if path.endswith("add_host"):
                self.assertEqual(payload["host"]["hwaddr"], "aa:bb:cc:00:00:01")
                return {"result": "saved", "uuid": "new"}
            if path.endswith("del_host/old"):
                return {"result": "deleted"}
            if path.endswith("service/reconfigure"):
                return {"status": "ok"}
            raise AssertionError(path)

        client.post.side_effect = post
        job = DeviceJob.objects.create(
            firewall=self.fw,
            kind=DeviceJob.DHCP_SYNC,
            actor="test",
            params={"approval_sha256": plan["approval_sha256"], "selected": [str(reservation.uid)], "remove": ["old"]},
        )
        (job,) = run_pending(lambda fw: client)
        self.assertEqual(job.status, DeviceJob.SUCCEEDED, job.message)
        self.assertIn("/api/dnsmasq/service/reconfigure", calls)
        self.assertTrue(AuditEvent.objects.filter(action="dhcp.reservations.completed").exists())
        self.assertTrue(AuditEvent.objects.filter(action="dhcp.reservation.removed").exists())
        self.assertEqual(reservation_plan(self.fw)["rows"][0]["action"], None)

    def test_sync_aborts_without_writes_when_device_changed(self):
        reservation = StaticReservation.objects.create(
            firewall=self.fw, logical_interface=self.vl10, ip_address="10.20.10.10", mac_address="aa:bb:cc:00:00:01"
        )
        refresh_dhcp(self.fw, self.device(self.local))
        plan = reservation_plan(self.fw)
        changed = self.device({**self.local, "host": "renamed"})
        with self.assertRaisesMessage(DeviceError, "changed since they were read"):
            execute_reservation_sync(self.fw, plan["approval_sha256"], [str(reservation.uid)], [], changed, "test")
        self.assertFalse(any("add_host" in c.args[0] for c in changed.post.call_args_list))
        with self.assertRaisesMessage(DeviceError, "Select only"):
            execute_reservation_sync(self.fw, plan["approval_sha256"], ["nope"], [], changed, "test")

    def test_kea_reservations_need_a_containing_subnet(self):
        self.fw.dhcp_backend = Firewall.KEA
        self.fw.save()
        reservation = StaticReservation.objects.create(
            firewall=self.fw, logical_interface=self.vl10, ip_address="10.20.10.10", mac_address="aa:bb:cc:00:00:01"
        )
        client = Mock()
        subnets = {"rows": []}

        def post(path, payload, write=True):
            return {
                "/api/kea/dhcpv4/search_reservation": {"rows": []},
                "/api/kea/leases4/search": {"rows": []},
                "/api/kea/dhcpv4/search_subnet": subnets,
            }[path]

        client.post.side_effect = post
        refresh_dhcp(self.fw, client)
        self.assertIn("No Kea subnet", reservation_plan(self.fw)["rows"][0]["errors"][0])
        subnets["rows"] = [{"uuid": "s-1", "subnet": "10.20.8.0/21"}]
        refresh_dhcp(self.fw, client)
        row = reservation_plan(self.fw)["rows"][0]
        self.assertEqual(row["payload"]["subnet"], "s-1")
        self.assertEqual(row["payload"]["description"], short_marker(reservation.uid))

    def test_sync_page_and_permissions(self):
        refresh_dhcp(self.fw, self.device())
        StaticReservation.objects.create(
            firewall=self.fw, logical_interface=self.vl10, ip_address="10.20.10.10", mac_address="aa:bb:cc:00:00:01"
        )
        page = self.client.get(f"/ipam/reservations/{self.fw.pk}/sync/")
        self.assertContains(page, 'name="selected"')
        self.client.post(f"/ipam/reservations/{self.fw.pk}/sync/", {"approval_sha256": "x"})
        self.assertFalse(DeviceJob.objects.exists())
        basic = get_user_model().objects.create_user("basic")
        self.client.force_login(basic)
        self.assertEqual(self.client.get(f"/ipam/reservations/{self.fw.pk}/sync/").status_code, 403)
        self.assertEqual(self.client.get("/ipam/").status_code, 403)

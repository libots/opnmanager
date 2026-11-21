"""Rule import against rows shaped like OPNsense 26.x /api/firewall/filter/get output."""

import copy

from django.core.exceptions import ValidationError
from django.test import TestCase

from .import_rules import import_rules
from .models import Alias, DeviceInventory, Firewall, InterfaceMapping, LogicalInterface, Rule
from .reconcile import plan_for

# Every field of OPNsense's Filter.xml rule node with the value `get` returns when unset.
DEVICE_DEFAULTS = {
    "enabled": "1",
    "statetype": "keep",
    "state-policy": "",
    "sequence": "1",
    "sort_order": "",
    "prio_group": "",
    "action": "pass",
    "quick": "1",
    "interfacenot": "0",
    "interface": "",
    "received-on-not": "0",
    "received-on": "",
    "direction": "in",
    "ipprotocol": "inet",
    "protocol": "any",
    "icmptype": "",
    "icmp6type": "",
    "source_net": "any",
    "source_not": "0",
    "source_port": "",
    "destination_net": "any",
    "destination_not": "0",
    "destination_port": "",
    "divert-to": "",
    "gateway": "",
    "replyto": "",
    "disablereplyto": "0",
    "log": "0",
    "allowopts": "0",
    "nosync": "0",
    "nopfsync": "0",
    "statetimeout": "",
    "udp-first": "",
    "udp-multiple": "",
    "udp-single": "",
    "max-src-nodes": "",
    "max-src-states": "",
    "max-src-conn": "",
    "max": "",
    "max-src-conn-rate": "",
    "max-src-conn-rates": "",
    "max-pkt-rate-number": "",
    "max-pkt-rate-seconds": "",
    "overload": "",
    "adaptivestart": "",
    "adaptiveend": "",
    "prio": "",
    "set-prio": "",
    "set-prio-low": "",
    "tag": "",
    "tagged": "",
    "tcpflags1": "",
    "tcpflags2": "",
    "tcpflags_any": "0",
    "categories": "",
    "sched": "",
    "tos": "",
    "scrub_no_df": "0",
    "scrub_random_id": "0",
    "scrub_max_mss": "",
    "scrub_min_ttl": "",
    "scrub_set_tos": "",
    "shaper1": "",
    "shaper2": "",
    "description": "",
    "audit": "",
}


def device_row(uuid, **fields):
    """A rule as the snapshot stores it, including OPNsense's %-prefixed display labels."""
    row = {**DEVICE_DEFAULTS, **fields, "uuid": uuid}
    for key in ("source_net", "destination_net", "source_port", "destination_port", "sequence", "description"):
        if row[key]:
            row["%" + key] = row[key].upper() + " (label)"
    return row


class DeviceShapedImportTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Source", base_url="https://source.test")
        self.lan = LogicalInterface.objects.create(name="LAN")
        self.iot = LogicalInterface.objects.create(name="IoT")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.lan, device_interface="lan")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=self.iot, device_interface="opt2")

    def snapshot(self, rules, **extra):
        data = {
            "schema_version": 1,
            "rules": rules,
            "aliases": extra.pop("aliases", []),
            "interfaces": [
                {"name": "lan", "label": "LAN"},
                {"name": "opt2", "label": "IoT"},
                {"name": "opt5", "label": "Guest"},
            ],
            "groups": extra.pop("groups", []),
            "categories": extra.pop("categories", []),
        }
        return self.fw.snapshots.create(data=copy.deepcopy(data))

    def run_import(self, rules, **extra):
        snapshot = self.snapshot(rules, **extra)
        return import_rules(snapshot, [str(i) for i in range(len(rules))], "all", [])

    def test_display_labels_from_newer_opnsense_do_not_block_import(self):
        row = device_row("a", description="Allow DNS", interface="lan", protocol="UDP", destination_port="53")
        self.assertIn("%destination_port", row)
        rule = self.run_import([row])[0]
        self.assertEqual((rule.name, rule.protocol, rule.destination_port), ("Allow DNS", "UDP", "53"))

    def test_imported_rules_match_their_device_rules_except_the_manager_tag(self):
        DeviceInventory.objects.create(firewall=self.fw, data={"protocols": [["OSPF", "OSPF"]]})
        aliases = [
            {"uuid": "al1", "name": "Servers", "type": "host", "content": "Nested\n10.0.0.1", "enabled": "1"},
            {"uuid": "al2", "name": "Nested", "type": "network", "content": "10.1.0.0/24", "enabled": "1"},
            {"uuid": "al3", "name": "WebPorts", "type": "port", "content": "80\n443", "enabled": "1"},
        ]
        groups = [{"uuid": "g1", "ifname": "INSIDE", "members": "lan,opt2", "descr": "", "sequence": "0"}]
        categories = [{"uuid": "c1", "name": "Infra", "color": "336699"}]
        rows = [
            device_row(
                "r1", description="Web", interface="lan", protocol="TCP", destination_port="https", sequence="10"
            ),
            device_row(
                "r2",
                description="Block IoT ports",
                interface="INSIDE",
                action="block",
                protocol="TCP/UDP",
                destination_port="WebPorts",
                categories="c1",
                sequence="20",
            ),
            device_row(
                "r3",
                description="Ping6",
                interface="opt2",
                ipprotocol="inet6",
                protocol="IPV6-ICMP",
                icmp6type="echoreq",
                sequence="30",
            ),
            device_row(
                "r4",
                description="Floating both ways",
                interface="lan,opt2",
                direction="any",
                quick="0",
                log="1",
                ipprotocol="inet46",
                sequence="40",
            ),
            device_row(
                "r5",
                description="To firewall",
                interface="lan",
                source_net="opt2ip",
                destination_net="(self)",
                destination_not="1",
                action="reject",
                statetype="none",
                enabled="0",
                sequence="50",
            ),
            device_row(
                "r6",
                description="Aliases",
                interface="lan",
                source_net="Servers,lan",
                source_not="1",
                protocol="OSPF",
                sequence="60",
                **{"received-on": "INSIDE", "received-on-not": "1"},
            ),
            device_row("r7", description="x" * 200, interface="lan", sequence="70", gateway="WAN_DHCP"),
            device_row(
                "r8", description="Port range", interface="lan", protocol="TCP", source_port="5060-5070", sequence="80"
            ),
        ]
        rules = self.run_import(rows, aliases=aliases, groups=groups, categories=categories)
        self.assertEqual(len(rules), len(rows))
        self.assertEqual(Alias.objects.count(), 3)
        plan = plan_for(self.fw)
        self.assertFalse(plan["errors"], plan["errors"])
        items = [item for item in plan["items"] if item["kind"] == "rule"]
        self.assertEqual(len(items), len(rows))
        for item in items:
            with self.subTest(rule=item.get("name")):
                self.assertEqual([change["field"] for change in item["changes"]], ["description"], item["changes"])

    def test_every_problem_in_a_selection_is_reported_with_its_rule_and_nothing_is_saved(self):
        rows = [
            device_row("ok", description="Fine", interface="lan"),
            device_row("s", description="Scheduled", interface="lan", sched="weekdays"),
            device_row("m", description="Guest net", interface="lan", source_net="opt5"),
            device_row("i", description="Guest only", interface="opt5"),
            device_row("l", description="y" * 250, interface="lan"),
        ]
        with self.assertRaises(ValidationError) as caught:
            self.run_import(rows)
        messages = caught.exception.messages
        self.assertEqual(len(messages), 4, messages)
        self.assertIn("Scheduled", messages[0])
        self.assertIn("schedule", messages[0].lower())
        self.assertIn("Guest net", messages[1])
        self.assertIn("opt5", messages[1])
        self.assertIn("Guest only", messages[2])
        self.assertIn("description", messages[3].lower())
        self.assertFalse(Rule.objects.exists())
        self.assertFalse(Alias.objects.exists())

    def test_unknown_protocol_says_how_to_load_the_device_catalog(self):
        row = device_row("p", description="OSPF", interface="lan", protocol="OSPF")
        with self.assertRaisesMessage(ValidationError, "OSPF"):
            self.run_import([row])

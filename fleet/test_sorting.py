from django.test import SimpleTestCase, TestCase

from .interface_views import device_interfaces
from .models import DeviceInventory, Firewall, LogicalInterface
from .sorting import natural_key


class NaturalKeyTests(SimpleTestCase):
    def test_numbers_sort_by_value_and_letters_ignore_case(self):
        names = ["VL100_Parents", "vl10_Network", "VL49", "VL2", "VL01", "LAN", "VL10"]
        self.assertEqual(
            sorted(names, key=natural_key),
            ["LAN", "VL01", "VL2", "VL10", "vl10_Network", "VL49", "VL100_Parents"],
        )

    def test_long_numbers_and_zero(self):
        self.assertLess(natural_key("A0"), natural_key("A1"))
        self.assertLess(natural_key("A99999999999"), natural_key("A100000000000"))


class LogicalInterfaceOrderTests(TestCase):
    def test_logical_interfaces_list_in_natural_order(self):
        for name in ["VL100_Parents", "VL10_Network", "VL49", "VL02"]:
            LogicalInterface.objects.create(name=name)
        self.assertEqual(
            list(LogicalInterface.objects.values_list("name", flat=True)),
            ["VL02", "VL10_Network", "VL49", "VL100_Parents"],
        )

    def test_rename_updates_the_sort_position(self):
        first = LogicalInterface.objects.create(name="VL05")
        LogicalInterface.objects.create(name="VL20")
        first.name = "VL300"
        first.save()
        self.assertEqual(list(LogicalInterface.objects.values_list("name", flat=True)), ["VL20", "VL300"])

    def test_device_interfaces_list_in_natural_order(self):
        fw = Firewall.objects.create(name="One", base_url="https://one.test")
        rows = [("opt9", "VL100_Parents"), ("opt1", "VL49"), ("opt2", "VL10_Network"), ("lan", "LAN")]
        DeviceInventory.objects.create(
            firewall=fw, data={"interfaces": [{"name": n, "description": d} for n, d in rows]}
        )
        self.assertEqual([o["label"] for o in device_interfaces(fw)], ["LAN", "VL10_Network", "VL49", "VL100_Parents"])

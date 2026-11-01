from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import Group, Permission
from django.db import transaction
from fleet.models import Firewall, LogicalInterface, InterfaceMapping, Alias, Rule, Snapshot
from fleet.reconcile import plan_for

class Command(BaseCommand):
    help = "Create an offline demonstration fleet and viewer/operator permission groups; never contacts a device."
    @transaction.atomic
    def handle(self, *args, **options):
        if Firewall.objects.exists():
            self.stdout.write("Fleet already exists; left unchanged.")
            return
        viewer, _ = Group.objects.get_or_create(name="Fleet viewers")
        viewer.permissions.add(Permission.objects.get(codename="view_firewall", content_type__app_label="fleet"))
        operator, _ = Group.objects.get_or_create(name="Fleet operators")
        operator.permissions.add(*Permission.objects.filter(content_type__app_label="fleet", codename__in=["view_firewall", "refresh_firewall"]))
        vl10 = LogicalInterface.objects.create(name="VL10", description="Trusted clients")
        vl20 = LogicalInterface.objects.create(name="VL20", description="Services")
        dns = Alias.objects.create(name="CorporateDNS", type="host", content="10.20.0.53\n10.20.0.54", description="Shared recursive resolvers")
        Rule.objects.create(name="Allow corporate DNS", sequence=100, interface=vl10, protocol="UDP", destination="CorporateDNS", destination_port="53")
        Rule.objects.create(name="Isolate client networks", sequence=200, interface=vl10, action="block", destination="@VL20:net", log=True)
        for index, name in enumerate(["Amsterdam", "London", "Stockholm"]):
            fw = Firewall.objects.create(name=name, base_url=f"https://{name.lower()}.example.invalid", credential_prefix=name.upper(), notes="Offline demo device; replace with a real firewall before pulling.")
            InterfaceMapping.objects.create(firewall=fw, logical_interface=vl10, device_interface=f"opt{index + 2}")
            InterfaceMapping.objects.create(firewall=fw, logical_interface=vl20, device_interface=f"opt{index + 5}")
            if index == 0:
                exception = Rule.objects.create(name="Amsterdam monitoring", sequence=300, interface=vl20, protocol="TCP", destination_port="9100", scope="selected")
                exception.firewalls.add(fw)
            snapshot = Snapshot.objects.create(firewall=fw, source="demo", data={"schema_version": 1, "aliases": [], "rules": []})
            plan = plan_for(fw)
            data = {"schema_version": 1, "rules": [], "aliases": []}
            for n, op in enumerate(plan["operations"]):
                row = {**op["payload"], "uuid": f"demo-{index}-{n}"}
                data["aliases" if op["kind"] == "alias" else "rules"].append(row)
            if index == 1: data["aliases"][0]["content"] = "10.20.0.53"
            if index == 2: data["rules"] = data["rules"][:1]
            data["rules"].append({"description": "Local emergency access", "interface": "wan", "sequence": "999", "action": "block"})
            snapshot.data = data
            snapshot.save(update_fields=["data"])
        self.stdout.write(self.style.SUCCESS("Created 3 offline demo firewalls. Create a local administrator with createsuperuser."))

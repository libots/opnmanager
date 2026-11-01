import getpass
import json
from django.core.management.base import BaseCommand, CommandError
from fleet.models import Firewall
from fleet.alias_sync import alias_plan, execute_alias_plan
from fleet.opnsense import OPNsenseClient, DeviceError

class Command(BaseCommand):
    help = "Review alias synchronization; --execute --approve SHA explicitly saves and reconfigures one firewall."
    def add_arguments(self, parser):
        parser.add_argument("firewall")
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--approve")
    def handle(self, *args, **options):
        try: fw = Firewall.objects.get(name=options["firewall"])
        except Firewall.DoesNotExist: raise CommandError("Unknown firewall")
        if not options["execute"]:
            plan = alias_plan(fw)
            self.stdout.write(json.dumps(plan, indent=2))
            if plan["errors"]: raise CommandError("Alias plan blocked; resolve errors first.")
            return
        if not options["approve"]: raise CommandError("Run without --execute first; supply its approval_sha256 with --approve.")
        try:
            count = execute_alias_plan(fw, options["approve"], OPNsenseClient(fw), "cli:" + getpass.getuser())
        except DeviceError as exc:
            raise CommandError(str(exc) + " Synchronization is not transactional; inspect device state if writes started.") from exc
        self.stdout.write(self.style.SUCCESS(f"Verified {count} alias changes on {fw.name}."))

import json
from django.core.management.base import BaseCommand, CommandError
from fleet.models import Firewall
from fleet.reconcile import plan_for

class Command(BaseCommand):
    help = "Export a read-only reconciliation plan for one firewall"
    def add_arguments(self, parser): parser.add_argument("firewall")
    def handle(self, *args, **options):
        try: fw = Firewall.objects.get(name=options["firewall"])
        except Firewall.DoesNotExist: raise CommandError("Unknown firewall")
        result = plan_for(fw)
        self.stdout.write(json.dumps(result, indent=2))
        if result["errors"]: raise CommandError("Plan blocked; see errors above.")

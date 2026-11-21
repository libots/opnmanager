from django.apps import AppConfig


class FleetConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "fleet"

    def ready(self):
        from django.db.models.signals import post_save

        from .models import Snapshot
        from .retention import prune_after_save

        post_save.connect(prune_after_save, sender=Snapshot, dispatch_uid="fleet.snapshot_retention")

"""Keep snapshot history bounded: every pull stores the full configuration as JSON."""

from django.conf import settings


def prune_snapshots(firewall, keep=None):
    """Delete all but the newest `keep` snapshots of one firewall; returns how many were removed.

    Plans, deploys and rule adoption only use the newest snapshot, so trimming
    older ones never invalidates a pending review.
    """
    keep = settings.SNAPSHOT_RETENTION if keep is None else keep
    if keep <= 0:
        return 0
    stale = list(firewall.snapshots.order_by("-created_at", "-id").values_list("pk", flat=True)[keep:])
    if not stale:
        return 0
    return firewall.snapshots.filter(pk__in=stale).delete()[0]


def prune_after_save(sender, instance, created, **kwargs):
    if created:
        prune_snapshots(instance.firewall)

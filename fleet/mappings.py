import re
from collections import Counter
from django.db import transaction
from .models import LogicalInterface, InterfaceMapping


def mapping_candidates(firewall, data):
    rows = data.get("interfaces", [])
    counts = Counter(str(r["label"]).strip().casefold() for r in rows)
    used = set(firewall.interface_mappings.values_list("device_interface", flat=True))
    logical = {i.name.casefold(): i for i in LogicalInterface.objects.all()}
    logical_counts = Counter(i.name.casefold() for i in LogicalInterface.objects.all())
    mapped = set(firewall.interface_mappings.values_list("logical_interface_id", flat=True))
    candidates = []
    for row in rows:
        label = row["label"].strip()
        if row["name"] in used or counts[label.casefold()] != 1: continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", label): continue
        if logical_counts[label.casefold()] > 1: continue
        interface = logical.get(label.casefold())
        if interface and interface.pk in mapped: continue
        candidates.append({"name": interface.name if interface else label, "device_interface": row["name"]})
    return candidates


@transaction.atomic
def apply_default_mappings(firewall, data):
    count = 0
    for row in mapping_candidates(firewall, data):
        logical, _ = LogicalInterface.objects.get_or_create(name=row["name"])
        if firewall.interface_mappings.filter(logical_interface=logical).exists(): continue
        InterfaceMapping.objects.create(firewall=firewall, logical_interface=logical, device_interface=row["device_interface"])
        count += 1
    return count

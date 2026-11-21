"""Fleet: Logical Interfaces — map each logical interface to a device interface per firewall."""

import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .models import AuditEvent, Firewall, InterfaceGroup, InterfaceMapping, LogicalInterface, Rule, VirtualIP


def chosen(request):
    ids = request.GET.getlist("firewalls")
    if "firewalls" in request.GET or "selection" in request.GET:
        return list(Firewall.objects.filter(pk__in=[v for v in ids if v.isdigit()]))
    return list(Firewall.objects.all())


def device_interfaces(firewall):
    """A firewall's interfaces: the inventory refresh (addresses, status), plus names from the newest snapshot."""
    inventory = getattr(getattr(firewall, "inventory", None), "data", {}) or {}
    found = {}
    for row in inventory.get("interfaces", []):
        if row.get("name"):
            found[row["name"]] = {
                "name": row["name"],
                "label": row.get("description") or row["name"],
                "device": row.get("device", ""),
                "status": row.get("status", ""),
                "ipv4": row.get("ipv4", ""),
                "ipv6": row.get("ipv6", ""),
                "vlan": row.get("vlan_tag", ""),
                "observed": True,
            }
    snapshot = firewall.snapshots.first()
    for row in (snapshot.data or {}).get("interfaces", []) if snapshot else []:
        if row.get("name") and row["name"] not in found:
            found[row["name"]] = {"name": row["name"], "label": row.get("label") or row["name"], "observed": False}
    return sorted(found.values(), key=lambda r: (r["name"] not in ("wan", "lan"), r["label"].lower(), r["name"]))


def usage():
    """How many rules, interface groups and virtual IPs refer to each logical interface."""
    counts = {}
    for interface in LogicalInterface.objects.all():
        rules = Rule.objects.filter(
            Q(interface=interface)
            | Q(interfaces=interface)
            | Q(origin_interfaces=interface)
            | Q(source__contains=f"@{interface.name}:")
            | Q(destination__contains=f"@{interface.name}:")
        ).distinct()
        counts[interface.pk] = {
            "rules": rules.count(),
            "groups": InterfaceGroup.objects.filter(members=interface).count(),
            "vips": VirtualIP.objects.filter(interface=interface).count(),
        }
    return counts


def logical_name(label):
    """A logical-interface name made from a device label ("Guest Wi-Fi" -> "Guest_Wi_Fi")."""
    name = re.sub(r"[^A-Za-z0-9_]+", "_", label).strip("_")[:50]
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or "") else ("_" + name)[:50] if name else ""


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def logical_interfaces(request):
    devices = chosen(request)
    logicals = list(LogicalInterface.objects.all())
    mappings = {
        (m.firewall_id, m.logical_interface_id): m.device_interface
        for m in InterfaceMapping.objects.filter(firewall__in=devices)
    }
    counts = usage()
    existing = {li.name.casefold() for li in logicals}
    columns = []
    for fw in devices:
        options = device_interfaces(fw)
        by_name = {o["name"]: o for o in options}
        mapped = {device for (fw_id, _), device in mappings.items() if fw_id == fw.pk}
        inventory = getattr(fw, "inventory", None)
        columns.append(
            {
                "firewall": fw,
                "options": options,
                "by_name": by_name,
                "observed_at": getattr(inventory, "updated_at", None),
                "has_inventory": any(o["observed"] for o in options),
                "mapped_count": sum(1 for (fw_id, _) in mappings if fw_id == fw.pk),
                # Offer "create and map" only where no logical interface has that name yet;
                # "Fill matches" covers the ones that exist.
                "unmapped": [
                    {
                        **o,
                        "suggested": ""
                        if logical_name(o["label"]).casefold() in existing
                        else logical_name(o["label"]),
                    }
                    for o in options
                    if o["name"] not in mapped
                ],
            }
        )
    rows = []
    for logical in logicals:
        cells = []
        for column in columns:
            device = mappings.get((column["firewall"].pk, logical.pk), "")
            info = column["by_name"].get(device)
            cells.append(
                {
                    "firewall": column["firewall"],
                    "device": device,
                    "info": info,
                    "missing": bool(device) and info is None and bool(column["options"]),
                    "options": column["options"],
                    "field": f"map_{column['firewall'].pk}_{logical.pk}",
                }
            )
        rows.append({"logical": logical, "usage": counts.get(logical.pk, {}), "cells": cells})
    can_edit = request.user.has_perms(
        ["fleet.add_interfacemapping", "fleet.change_interfacemapping", "fleet.delete_interfacemapping"]
    )
    return render(
        request,
        "fleet/logical_interfaces.html",
        {
            "devices": devices,
            "all_firewalls": Firewall.objects.all(),
            "columns": columns,
            "rows": rows,
            "can_edit": can_edit,
            "can_add_logical": can_edit and request.user.has_perm("fleet.add_logicalinterface"),
            "unmapped_total": sum(len(c["unmapped"]) for c in columns),
        },
    )


def back(request):
    target = request.POST.get("next", "")
    if url_has_allowed_host_and_scheme(target, {request.get_host()}, request.is_secure()):
        return redirect(target)
    return redirect("logical_matrix")


@login_required
@permission_required(
    (
        "fleet.view_firewall",
        "fleet.add_interfacemapping",
        "fleet.change_interfacemapping",
        "fleet.delete_interfacemapping",
    ),
    raise_exception=True,
)
@require_POST
def save_mappings(request):
    """Apply every changed cell at once; nothing is saved if the result would be inconsistent."""
    firewalls = {fw.pk: fw for fw in Firewall.objects.all()}
    logicals = {li.pk: li for li in LogicalInterface.objects.all()}
    current = {(m.firewall_id, m.logical_interface_id): m for m in InterfaceMapping.objects.all()}
    wanted = {key: m.device_interface for key, m in current.items()}
    for key, value in request.POST.items():
        match = re.fullmatch(r"map_(\d+)_(\d+)", key)
        if not match:
            continue
        fw_id, logical_id = int(match[1]), int(match[2])
        if fw_id in firewalls and logical_id in logicals:
            wanted[(fw_id, logical_id)] = value.strip()
    changes = [
        (key, value) for key, value in wanted.items() if value != getattr(current.get(key), "device_interface", "")
    ]
    if not changes:
        messages.info(request, "No mapping changes to save.")
        return back(request)
    problems = []
    for fw_id, fw in firewalls.items():
        used = {}
        for (f, logical_id), device in wanted.items():
            if f == fw_id and device:
                used.setdefault(device, []).append(logicals[logical_id].name)
        for device, names in used.items():
            if len(names) > 1:
                problems.append(
                    f"{fw.name}: {device} is mapped to more than one logical interface ({', '.join(names)})."
                )
    for (fw_id, _logical_id), device in changes:
        if device and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", device):
            problems.append(f"{firewalls[fw_id].name}: “{device}” isn't an OPNsense interface identifier (like opt2).")
    if problems:
        for problem in problems:
            messages.error(request, problem)
        messages.error(request, "No mappings were saved.")
        return back(request)
    summary = []
    with transaction.atomic():
        # Remove changed rows first so swaps (opt1 <-> opt2) don't trip the one-device-interface constraint.
        InterfaceMapping.objects.filter(pk__in=[current[key].pk for key, _ in changes if key in current]).delete()
        for (fw_id, logical_id), device in sorted(changes):
            fw, logical = firewalls[fw_id], logicals[logical_id]
            if device:
                InterfaceMapping.objects.create(firewall=fw, logical_interface=logical, device_interface=device)
                summary.append(f"{fw.name}: {logical.name} → {device}")
            else:
                summary.append(f"{fw.name}: {logical.name} unmapped")
        AuditEvent.objects.create(actor=request.user.username, action="mapping.updated", detail="; ".join(summary))
    messages.success(request, f"Saved {len(summary)} mapping change{'s' if len(summary) != 1 else ''}.")
    return back(request)


@login_required
@permission_required(("fleet.view_firewall", "fleet.add_logicalinterface"), raise_exception=True)
@require_POST
def create_logical_interface(request):
    """Add a logical interface, optionally mapping it to a device interface right away."""
    name = request.POST.get("name", "").strip()
    logical = LogicalInterface(name=name, description=request.POST.get("description", "").strip())
    fw = Firewall.objects.filter(pk=request.POST.get("firewall") or None).first()
    device = request.POST.get("device", "").strip()
    try:
        with transaction.atomic():
            logical.full_clean()
            logical.save()
            detail = logical.name
            if fw and device:
                if not request.user.has_perm("fleet.add_interfacemapping"):
                    raise ValidationError("You can't add interface mappings.")
                mapping = InterfaceMapping(firewall=fw, logical_interface=logical, device_interface=device)
                mapping.full_clean()
                mapping.save()
                detail += f" ({fw.name}: {device})"
            AuditEvent.objects.create(actor=request.user.username, action="logical_interface.created", detail=detail)
        messages.success(request, f"Added logical interface {detail}.")
    except ValidationError as exc:
        for error in exc.messages:
            messages.error(request, f"{name or 'Logical interface'}: {error}")
    return back(request)

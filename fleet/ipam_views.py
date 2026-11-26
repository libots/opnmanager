"""IP address management pages: address plan, DHCP scopes, named ranges, reservations and leases.

Everything here is read-only except reading DHCP state from a firewall (`read_dhcp`) and queueing
a reviewed reservation synchronization; editing happens in Django admin.
"""

import ipaddress
import json
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST

from . import dhcp
from .ipam import (
    TemplateError,
    compare_observed,
    interface_plan,
    ipv6_scope,
    observed_addresses,
    range_size,
    render_dnsmasq,
    render_kea,
    resolve_range,
    scope_settings,
    site_prefix,
    suggest_template,
)
from .ipam_checks import Overlaps
from .jobs import enqueue
from .models import (
    AddressRange,
    Alias,
    DeviceJob,
    DhcpScope,
    Firewall,
    InterfaceAddressing,
    LogicalInterface,
    ScopedPolicy,
    StaticReservation,
    VirtualIP,
)
from .opnsense import DeviceError, OPNsenseClient


def _inventory(firewall):
    return getattr(getattr(firewall, "inventory", None), "data", None) or {}


def _firewalls(request):
    ids = [v for v in request.GET.getlist("firewalls") if v.isdigit()]
    queryset = Firewall.objects.select_related("inventory").prefetch_related("interface_mappings")
    return list(queryset.filter(pk__in=ids)) if ids else list(queryset)


def site_plans(firewalls):
    """{(firewall pk, logical interface pk): interface_plan} for every interface with an address plan."""
    plans = {}
    for addressing in InterfaceAddressing.objects.select_related("logical_interface"):
        for fw in firewalls:
            plans[(fw.pk, addressing.logical_interface_id)] = interface_plan(addressing, fw)
    return plans


def _mappings(firewall):
    return {m.logical_interface_id: m.device_interface for m in firewall.interface_mappings.all()}


def _observed_row(firewall, device):
    return next((r for r in _inventory(firewall).get("interfaces", []) if r.get("name") == device), None)


def _suggestions(logical, firewalls):
    """Templates matching the addresses this interface has now at every site that observed it."""
    samples = {4: [], 6: []}
    for fw in firewalls:
        device = _mappings(fw).get(logical.pk)
        row = _observed_row(fw, device) if device else None
        if not row:
            continue
        for family in (4, 6):
            try:
                site = site_prefix(fw, family)
            except TemplateError:
                site = None
            if site is None:
                continue
            inside = [
                a
                for a in observed_addresses(row)
                if isinstance(a, ipaddress.IPv4Interface | ipaddress.IPv6Interface)
                and a.version == family
                and a.ip in site
            ]
            if len(inside) == 1:
                samples[family].append((site, inside[0]))
    return {family: suggest_template(found) for family, found in samples.items()}


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def subnet_info(request):
    """Live hint under an address field: usable range, size, what a template means at each site,
    and overlap warnings (the edited object, `self`, is left out of the comparison)."""
    from django.http import JsonResponse

    from .ipam import hint_lines, parse_site_prefix, resolve_interface

    kind = request.GET.get("kind", "")
    if kind not in ("prefix", "interface", "template", "range", "pool", "address"):
        return JsonResponse({"error": "Unknown field kind."}, status=400)
    value = request.GET.get("value", "")[:200]
    own = request.GET.get("self", "")
    own = int(own) if own.isdigit() else None
    firewalls = list(
        Firewall.objects.filter(enabled=True).select_related("inventory").prefetch_related("interface_mappings")
    )
    if request.GET.get("firewall", "").isdigit():
        firewalls = [fw for fw in firewalls if str(fw.pk) == request.GET["firewall"]]
    subnets = {}
    interface = request.GET.get("interface", "")
    interface = int(interface) if interface.isdigit() else None
    if kind in ("range", "pool", "address") and interface:
        addressing = InterfaceAddressing.objects.filter(logical_interface_id=interface).first()
        for fw in firewalls:
            planned = interface_plan(addressing, fw)[4] if addressing else None
            if planned is None:
                subnets[fw.pk] = "the interface has no IPv4 address plan"
            elif "error" in planned:
                subnets[fw.pk] = planned["error"]
            else:
                subnets[fw.pk] = planned["subnet"]

    def site_of(fw, family):
        return site_prefix(fw, family)

    try:
        lines = hint_lines(kind, value, firewalls, subnets, site_of)
    except TemplateError as exc:
        return JsonResponse({"lines": [], "error": str(exc)})
    if kind in ("range", "pool", "address") and not interface:
        return JsonResponse({"lines": [], "error": "Choose the logical interface to see this at each site."})
    warnings = []
    if value.strip() and kind != "interface":
        checks = Overlaps(firewalls if kind != "prefix" else None)
        if kind == "prefix":
            warnings = [
                f"This prefix {problem}." for problem in checks.check_site_prefix(parse_site_prefix(value), own)
            ]
        for fw in firewalls if kind != "prefix" else []:
            try:
                if kind == "template":
                    site = site_prefix(fw, 4 if ":" not in value else 6)
                    if site is None:
                        continue
                    network = resolve_interface(value, site).network
                    problems = checks.check_subnet(fw, interface, network)
                elif kind in ("range", "pool"):
                    subnet = subnets.get(fw.pk)
                    if subnet is None or isinstance(subnet, str):
                        continue
                    first, last = resolve_range(value, subnet, site_prefix(fw, 4))
                    problems = checks.check_range(
                        fw,
                        interface,
                        first,
                        last,
                        exclude_range=own if kind == "range" else None,
                        exclude_pool=own if kind == "pool" else None,
                        label=kind,
                    )
                else:
                    problems = checks.check_reservation(fw, interface, ipaddress.ip_address(value.strip()))
            except (TemplateError, ValueError):
                continue
            if problems:
                warnings.append(f"{fw.name}: {'; '.join(problems)}.")
    return JsonResponse({"lines": lines, "warnings": warnings})


IDENTITY_ASSOCIATION = ("track6", "idassoc6")


def _ula_vip(firewall, logical, planned, entry, vips):
    """For an interface whose IPv6 comes from Identity Association, the planned ULA is carried by a
    virtual IP (IP alias) on that interface. Report whether one is defined and present on the device."""
    if entry["mode"] not in IDENTITY_ASSOCIATION or not planned or "interface" not in planned:
        return {}
    wanted = planned["interface"]
    if ipv6_scope(wanted) != "ula":
        return {"ia": True, "ula_planned": False}
    defined = next(
        (
            vip
            for vip in vips
            if vip.interface_id == logical.pk and vip.applies_to(firewall) and _same_interface(vip.network, wanted)
        ),
        None,
    )
    on_device = any(
        _same_interface(f"{row.get('subnet', '')}/{row.get('subnet_bits', '')}", wanted)
        for row in (getattr(getattr(firewall, "inventory", None), "data", None) or {}).get("vips", [])
    )
    return {
        "ia": True,
        "ula_planned": True,
        "ula_vip": defined,
        "ula_vip_applied": on_device or entry["state"] == "match",
    }


def _same_interface(text, wanted):
    try:
        return ipaddress.ip_interface(text) == wanted
    except ValueError:
        return False


@login_required
@permission_required(("fleet.view_firewall", "fleet.add_virtualip"), raise_exception=True)
@require_POST
def create_ula_vips(request):
    """Define the ULA virtual IPs that Identity Association interfaces are missing (manager only).

    `target` is "<firewall pk>:<logical interface pk>" (repeatable). Each becomes an IP alias VIP
    targeting that one firewall; applying it to the device is the usual reviewed VIP apply.
    """
    created = []
    for target in request.POST.getlist("target"):
        fw_pk, _, li_pk = target.partition(":")
        if not (fw_pk.isdigit() and li_pk.isdigit()):
            continue
        fw = Firewall.objects.filter(pk=fw_pk, enabled=True).first()
        addressing = (
            InterfaceAddressing.objects.filter(logical_interface_id=li_pk).select_related("logical_interface").first()
        )
        if not fw or not addressing:
            continue
        planned = interface_plan(addressing, fw)[6]
        if not planned or "interface" not in planned or ipv6_scope(planned["interface"]) != "ula":
            continue
        logical = addressing.logical_interface
        network = str(planned["interface"])
        if VirtualIP.objects.filter(interface=logical, network=network, firewalls=fw).exists():
            continue
        name = f"{logical.name} ULA {fw.name}"[:100]
        if VirtualIP.objects.filter(name=name).exists():
            name = f"{name[:90]} {network.split('/')[0][-8:]}"
        vip = VirtualIP(name=name, interface=logical, network=network, mode="ipalias", scope=VirtualIP.SELECTED)
        vip.full_clean(exclude=["firewalls", "firewall_groups"])
        vip.save()
        vip.firewalls.add(fw)
        created.append(vip)
    if not created:
        messages.info(request, "No ULA virtual IPs were missing. Nothing was created.")
        return redirect("ipam_plan")
    messages.success(
        request,
        f"Defined {len(created)} ULA virtual IP{'s' if len(created) != 1 else ''} in the manager. The firewalls are "
        "unchanged until you review and apply each one below.",
    )
    if len(created) == 1:
        return redirect("review_vip", pk=created[0].firewalls.get().pk, vip_id=created[0].pk)
    return redirect("virtual_ips")


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def address_plan(request):
    firewalls = _firewalls(request)
    plans = site_plans(firewalls)
    checks = Overlaps()
    sites = []
    for fw in firewalls:
        site = {"firewall": fw, "prefixes": [], "warnings": checks.for_subject("site", fw.pk)}
        for family in (4, 6):
            try:
                prefix = site_prefix(fw, family)
                site["prefixes"].append(str(prefix) if prefix else "")
            except TemplateError as exc:
                site["prefixes"].append("invalid: " + str(exc))
        sites.append(site)
    rows = []
    addressing = {a.logical_interface_id: a for a in InterfaceAddressing.objects.all()}
    vips = list(VirtualIP.objects.prefetch_related(*ScopedPolicy.SCOPE_PREFETCH))
    for logical in LogicalInterface.objects.all():
        plan = addressing.get(logical.pk)
        cells = []
        for fw in firewalls:
            device = _mappings(fw).get(logical.pk)
            observed_row = _observed_row(fw, device) if device else None
            # Link-local IPv6 (fe80::/10) exists on every interface and is never planned.
            observed = [a for a in observed_addresses(observed_row) if not a.is_link_local] if observed_row else []
            planned = plans[(fw.pk, logical.pk)] if plan else {4: None, 6: None}
            families = []
            for family in (4, 6):
                entry = {
                    "family": family,
                    "plan": planned[family],
                    "state": compare_observed(planned[family], observed) if observed_row else None,
                    "observed": ", ".join(str(a) for a in observed if a.version == family),
                    "mode": (observed_row or {}).get(f"ipv{family}_mode", ""),
                }
                if family == 6:
                    entry["ula"] = ", ".join(str(a) for a in observed if a.version == 6 and ipv6_scope(a) == "ula")
                    entry["global"] = ", ".join(
                        str(a) for a in observed if a.version == 6 and ipv6_scope(a) == "global"
                    )
                    entry.update(_ula_vip(fw, logical, planned[6], entry, vips))
                families.append(entry)
            cells.append(
                {
                    "firewall": fw,
                    "device": device,
                    "families": families,
                    "inventory": bool(observed_row),
                    "warnings": checks.for_subject("subnet", fw.pk, logical.pk),
                }
            )
        row = {"addressing": plan, "logical": logical, "cells": cells}
        if plan is None:
            suggested = _suggestions(logical, firewalls)
            row["add_query"] = urlencode(
                {
                    "logical_interface": logical.pk,
                    **({"ipv4_address": suggested[4]} if suggested[4] else {}),
                    **({"ipv6_address": suggested[6]} if suggested[6] else {}),
                }
            )
            row["suggested"] = [value for value in (suggested[4], suggested[6]) if value]
        rows.append(row)
    return render(
        request,
        "fleet/ipam_plan.html",
        {
            "sites": sites,
            "rows": rows,
            "planned_count": sum(1 for row in rows if row["addressing"]),
            "unplanned_count": sum(1 for row in rows if not row["addressing"]),
            "overlaps": checks.report()["summary"],
            "firewalls": firewalls,
            "all_firewalls": Firewall.objects.all(),
        },
    )


def scope_cells(scope, firewalls, plans, aliases):
    """Resolved settings of one DHCP scope at each firewall, with dnsmasq/Kea previews."""
    cells = []
    for fw in firewalls:
        cell = {"firewall": fw, "applies": fw.enabled and scope.applies_to(fw)}
        if not cell["applies"]:
            cells.append(cell)
            continue
        device = _mappings(fw).get(scope.logical_interface_id)
        planned = (plans.get((fw.pk, scope.logical_interface_id)) or {}).get(4)
        try:
            if not device:
                raise TemplateError(f"{scope.logical_interface} isn't mapped on {fw.name}.")
            if not planned:
                raise TemplateError(f"{scope.logical_interface} has no IPv4 address plan.")
            if "error" in planned:
                raise TemplateError(planned["error"])
            site = site_prefix(fw, 4)
            settings = scope_settings(scope, planned["subnet"], site, planned["router"], aliases)
            cell.update(
                settings=settings,
                dnsmasq="\n".join(render_dnsmasq(settings, device)),
                kea=json.dumps(render_kea(settings, device), indent=2),
            )
        except TemplateError as exc:
            cell["error"] = str(exc)
        cells.append(cell)
    return cells


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def dhcp_scopes(request):
    firewalls = _firewalls(request)
    plans = site_plans(firewalls)
    aliases = {a.name: a.content for a in Alias.objects.filter(type="host")}
    scopes = list(
        DhcpScope.objects.select_related("logical_interface").prefetch_related("options", *ScopedPolicy.SCOPE_PREFETCH)
    )
    rows = []
    claimed = {}
    checks = Overlaps()
    for scope in scopes:
        cells = scope_cells(scope, firewalls, plans, aliases)
        for cell in cells:
            cell["warnings"] = checks.for_subject("pool", cell["firewall"].pk, scope.pk)
            if cell.get("applies") and scope.enabled:
                claimed.setdefault((cell["firewall"].pk, scope.logical_interface_id), []).append(scope.name)
        rows.append({"scope": scope, "cells": cells})
    for row in rows:
        for cell in row["cells"]:
            others = claimed.get((cell["firewall"].pk, row["scope"].logical_interface_id), [])
            if len(others) > 1 and row["scope"].enabled and cell.get("applies"):
                cell["conflict"] = (
                    f"Several scopes target {row['scope'].logical_interface} here: {', '.join(others)}. "
                    "Narrow their Deploy to lists so only one applies per firewall."
                )
    return render(
        request, "fleet/ipam_dhcp.html", {"firewalls": firewalls, "rows": rows, "all_firewalls": Firewall.objects.all()}
    )


def _range_cells(ranges, firewalls, plans, reservations):
    rows = []
    for item in ranges:
        cells = []
        for fw in firewalls:
            planned = (plans.get((fw.pk, item.logical_interface_id)) or {}).get(4)
            cell = {"firewall": fw}
            try:
                if not planned:
                    raise TemplateError(f"{item.logical_interface} has no IPv4 address plan.")
                if "error" in planned:
                    raise TemplateError(planned["error"])
                first, last = resolve_range(item.addresses, planned["subnet"], site_prefix(fw, 4))
                used = [
                    r
                    for r in reservations.get(fw.pk, [])
                    if r.logical_interface_id == item.logical_interface_id
                    and int(first) <= int(ipaddress.ip_address(r.ip_address)) <= int(last)
                ]
                cell.update(first=first, last=last, size=range_size(first, last), used=len(used))
                cell["percent"] = min(100, round(100 * len(used) / cell["size"]))
            except TemplateError as exc:
                cell["error"] = str(exc)
            cells.append(cell)
        rows.append({"range": item, "cells": cells})
    return rows


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def address_ranges(request):
    firewalls = _firewalls(request)
    plans = site_plans(firewalls)
    reservations = {}
    for reservation in StaticReservation.objects.all():
        reservations.setdefault(reservation.firewall_id, []).append(reservation)
    rows = _range_cells(AddressRange.objects.select_related("logical_interface"), firewalls, plans, reservations)
    checks = Overlaps()
    for row in rows:
        for cell in row["cells"]:
            cell["warnings"] = checks.for_subject("range", cell["firewall"].pk, row["range"].pk)
    return render(
        request,
        "fleet/ipam_ranges.html",
        {"firewalls": firewalls, "rows": rows, "all_firewalls": Firewall.objects.all()},
    )


def _lease_interface(lease, firewall, plans, device_to_logical, logicals):
    """Logical interface of a lease: by the device interface it was seen on, else by subnet."""
    logical = device_to_logical.get(lease.get("interface", ""))
    if logical:
        return logical
    try:
        address = ipaddress.ip_address(lease.get("address", ""))
    except ValueError:
        return None
    for pk, plan in ((key[1], value) for key, value in plans.items() if key[0] == firewall.pk):
        planned = plan.get(4)
        if planned and "subnet" in planned and address in planned["subnet"]:
            return logicals.get(pk)
    return None


def reservation_suggestions(firewall, logical, plans, taken):
    """Next free address in each named range of an interface at this firewall."""
    from .ipam import next_free

    planned = (plans.get((firewall.pk, logical.pk)) or {}).get(4)
    if not planned or "subnet" not in planned:
        return []
    suggestions = []
    for item in logical.address_ranges.all():
        try:
            first, last = resolve_range(item.addresses, planned["subnet"], site_prefix(firewall, 4))
        except TemplateError:
            continue
        free = next_free(first, last, taken)
        suggestions.append({"range": item, "address": free})
    return suggestions


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def reservations(request):
    firewalls = list(Firewall.objects.select_related("inventory").prefetch_related("interface_mappings"))
    selected = next((fw for fw in firewalls if str(fw.pk) == request.GET.get("firewall")), None)
    if selected is None and firewalls:
        selected = firewalls[0]
    context = {"firewalls": firewalls, "selected": selected}
    if selected is None:
        return render(request, "fleet/ipam_reservations.html", context)
    plans = site_plans([selected])
    logicals = {li.pk: li for li in LogicalInterface.objects.prefetch_related("address_ranges")}
    device_to_logical = {
        m.device_interface: logicals[m.logical_interface_id] for m in selected.interface_mappings.all()
    }
    managed = list(selected.reservations.select_related("logical_interface", "firewall"))
    checks = Overlaps()
    taken = {r.ip_address for r in managed}
    observed = _inventory(selected).get("dhcp") or {}
    taken |= {r.get("ip", "") for r in observed.get("reservations", [])}
    ranges = {}
    for logical in logicals.values():
        planned = (plans.get((selected.pk, logical.pk)) or {}).get(4)
        for item in logical.address_ranges.all():
            try:
                first, last = resolve_range(item.addresses, planned["subnet"], site_prefix(selected, 4))
                ranges.setdefault(logical.pk, []).append((item, first, last))
            except (TemplateError, TypeError, KeyError):
                continue
    groups = {}
    for reservation in managed:
        address = ipaddress.ip_address(reservation.ip_address)
        reservation.range_name = next(
            (
                item.name
                for item, first, last in ranges.get(reservation.logical_interface_id, [])
                if first <= address <= last
            ),
            "",
        )
        reservation.device_state = dhcp.reservation_state(reservation, observed)
        reservation.warnings = checks.for_subject("reservation", reservation.pk)
        groups.setdefault(reservation.logical_interface, []).append(reservation)
    by_mac = {(r.mac_address, r.logical_interface_id) for r in managed}
    leases = []
    for lease in observed.get("leases", []):
        logical = _lease_interface(lease, selected, plans, device_to_logical, logicals)
        row = {**lease, "logical": logical, "expires": parse_datetime(lease.get("expire", "") or "")}
        row["reserved"] = bool(logical and (lease.get("mac"), logical.pk) in by_mac) or lease.get("reserved")
        if logical and not row["reserved"]:
            base = {
                "firewall": selected.pk,
                "logical_interface": logical.pk,
                "mac_address": lease.get("mac", ""),
                "hostname": dhcp.safe_hostname(lease.get("hostname", "")),
                "next": request.get_full_path(),
            }
            add = reverse("admin:fleet_staticreservation_add")
            row["reserve_url"] = add + "?" + urlencode({**base, "ip_address": lease.get("address", "")})
            row["suggestions"] = [
                {
                    "label": f"{s['range'].name}: {s['address']}",
                    "url": add + "?" + urlencode({**base, "ip_address": str(s["address"])}),
                }
                for s in reservation_suggestions(selected, logical, plans, taken)
                if s["address"]
            ]
        leases.append(row)
    unmanaged = [r for r in observed.get("reservations", []) if not r.get("managed")]
    context.update(
        groups=sorted(groups.items(), key=lambda item: (item[0].sort_key, item[0].name)),
        leases=leases,
        observed=observed,
        read_at=parse_datetime(observed.get("read_at", "") or ""),
        unmanaged=unmanaged,
        backend=selected.get_dhcp_backend_display(),
    )
    return render(request, "fleet/ipam_reservations.html", context)


@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def read_dhcp(request, pk):
    fw = get_object_or_404(Firewall, pk=pk, enabled=True)
    try:
        data = dhcp.refresh_dhcp(fw, OPNsenseClient(fw))
        messages.success(
            request,
            f"{fw.name}: read {len(data['leases'])} leases and {len(data['reservations'])} reservations from "
            f"{fw.get_dhcp_backend_display()}. Nothing was changed on the firewall.",
        )
    except DeviceError as exc:
        messages.error(request, f"{fw.name}: {exc} Nothing was changed on the firewall.")
    return redirect(reverse("ipam_reservations") + f"?firewall={fw.pk}")


@login_required
@permission_required(("fleet.view_firewall", "fleet.add_staticreservation"), raise_exception=True)
@require_POST
def import_reservations(request, pk):
    """Adopt selected device reservations (read earlier) as manager reservations. Device unchanged."""
    fw = get_object_or_404(Firewall, pk=pk)
    try:
        created = dhcp.import_reservations(fw, request.POST.getlist("uuid"), request.user.username)
        messages.success(
            request,
            f"Imported {created} reservation{'s' if created != 1 else ''} from {fw.name}. The firewall is unchanged.",
        )
    except DeviceError as exc:
        messages.error(request, f"{exc} Nothing was imported.")
    return redirect(reverse("ipam_reservations") + f"?firewall={fw.pk}")


@login_required
@permission_required(("fleet.view_firewall", "fleet.sync_dhcp"), raise_exception=True)
def sync_reservations(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    if request.method == "POST":
        params = {
            "approval_sha256": request.POST.get("approval_sha256", ""),
            "selected": [v for v in request.POST.getlist("selected") if v],
            "remove": [v for v in request.POST.getlist("remove") if v],
        }
        try:
            if request.POST.get("acknowledge") != "yes":
                raise DeviceError("Confirm the warning before synchronizing.")
            job = enqueue(fw, DeviceJob.DHCP_SYNC, params, request.user.username)
        except DeviceError as exc:
            messages.error(request, f"{exc} Nothing was queued.")
            return redirect("ipam_sync", pk=pk)
        return redirect("job", pk=job.pk)
    plan = dhcp.reservation_plan(fw)
    return render(
        request,
        "fleet/ipam_sync.html",
        {"firewall": fw, "plan": plan, "read_at": parse_datetime(plan.get("read_at") or "")},
    )


@login_required
@permission_required(("fleet.view_firewall", "fleet.push_interface_addresses"), raise_exception=True)
def push_addresses(request, pk):
    """Review the planned interface addresses against the firewall; applying runs as a job."""
    from django.core import signing

    from .interface_push import review

    fw = get_object_or_404(Firewall, pk=pk, enabled=True)
    if request.method == "POST":
        try:
            try:
                approved = signing.loads(request.POST.get("approval", ""), salt="interface-addresses", max_age=600)
            except signing.BadSignature:
                raise DeviceError("The review expired or is invalid. Review again.") from None
            if approved.get("firewall") != fw.pk:
                raise DeviceError("The review is for another firewall. Review again.")
            if request.POST.get("acknowledge") != "yes":
                raise DeviceError("Confirm the warning before applying.")
            selected = [value for value in request.POST.getlist("selected") if value]
            if not selected:
                raise DeviceError("Select one or more address changes.")
            job = enqueue(
                fw,
                DeviceJob.INTERFACE_ADDRESSES,
                {"digest": approved["digest"], "selected": selected},
                request.user.username,
            )
        except DeviceError as exc:
            messages.error(request, f"{exc} Nothing was queued.")
            return redirect("ipam_push", pk=pk)
        return redirect("job", pk=job.pk)
    try:
        _, rows, approval = review(fw, OPNsenseClient(fw))
    except DeviceError as exc:
        messages.error(request, f"{fw.name}: {exc}")
        return redirect("ipam_plan")
    token = signing.dumps({"firewall": fw.pk, "digest": approval}, salt="interface-addresses")
    return render(
        request,
        "fleet/ipam_push.html",
        {
            "firewall": fw,
            "changes": [row for row in rows if row["action"]],
            "blocked": [row for row in rows if row["blocked"]],
            "unchanged": [row for row in rows if not row["action"] and not row["blocked"]],
            "approval": token,
        },
    )

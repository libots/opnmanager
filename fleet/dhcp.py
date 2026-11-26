"""DHCP leases and static reservations on OPNsense: read, plan and reviewed synchronization.

Reservations are stored backend-neutrally (`StaticReservation`) and written to whichever service a
firewall uses (`Firewall.dhcp_backend`): Dnsmasq hosts or Kea DHCPv4 reservations. Device identity
is the usual `[om:<12 hex>]` description suffix (from `StaticReservation.uid`), or the device UUID
a reservation was imported from.

Writes follow the shared safety pattern: reviewed digest → write lock → preflight re-read compared
with the reviewed observation → write → reconfigure → readback verify → store observation → audit.
"""

import ipaddress
import re
from datetime import UTC, datetime
from urllib.parse import quote

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .alias_sync import digest
from .ipam import HOSTNAME, normalize_mac
from .locks import device_write_lock
from .models import AuditEvent, DeviceInventory, Firewall, InterfaceAddressing, StaticReservation
from .opnsense import DeviceError
from .rule_identity import marker_of, short_marker, tagged, untagged

SEARCH = {"current": 1, "rowCount": -1, "searchPhrase": ""}

ENDPOINTS = {
    Firewall.DNSMASQ: {
        "leases": "/api/dnsmasq/leases/search",
        "reservations": "/api/dnsmasq/settings/search_host",
        "add": "/api/dnsmasq/settings/add_host",
        "set": "/api/dnsmasq/settings/set_host/",
        "del": "/api/dnsmasq/settings/del_host/",
        "key": "host",
        "reconfigure": "/api/dnsmasq/service/reconfigure",
    },
    Firewall.KEA: {
        "leases": "/api/kea/leases4/search",
        "reservations": "/api/kea/dhcpv4/search_reservation",
        "subnets": "/api/kea/dhcpv4/search_subnet",
        "add": "/api/kea/dhcpv4/add_reservation",
        "set": "/api/kea/dhcpv4/set_reservation/",
        "del": "/api/kea/dhcpv4/del_reservation/",
        "key": "reservation",
        "reconfigure": "/api/kea/service/reconfigure",
    },
}

LIMIT = 4000  # Rows kept per list; a larger table is truncated and flagged.


def _text(value, limit=200):
    return str(value if value is not None else "").strip()[:limit]


def _rows(client, path):
    response = client.post(path, SEARCH, write=False)
    rows = response.get("rows") if isinstance(response, dict) else None
    if not isinstance(rows, list):
        raise DeviceError("Unsupported DHCP response from the firewall. Check that the DHCP service is installed.")
    return [row for row in rows if isinstance(row, dict)]


def _first(value):
    return next((v.strip() for v in str(value or "").split(",") if v.strip()), "")


def _expire(value):
    """Lease expiry as ISO text; OPNsense reports epoch seconds (or text it already formatted)."""
    text = _text(value, 40)
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=UTC).isoformat(timespec="seconds")
        except (OverflowError, ValueError):
            return ""
    return text


def safe_hostname(value):
    """A lease's client name as a reservation hostname (first label, valid characters only)."""
    label = re.sub(r"[^A-Za-z0-9-]", "-", _text(value, 253).split(".")[0]).strip("-")[:63]
    return label if HOSTNAME.match(label or "-") else ""


def _reservation_row(backend, row):
    if backend == Firewall.KEA:
        ips, macs = [row.get("ip_address", "")], [row.get("hw_address", "")]
        hostname, description = row.get("hostname", ""), row.get("description", "")
    else:
        ips = [v for v in str(row.get("ip", "")).split(",") if v.strip()]
        macs = [v for v in str(row.get("hwaddr", "")).split(",") if v.strip()]
        hostname, description = row.get("host", ""), row.get("descr", "")
    ipv4 = [ip.strip() for ip in ips if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip.strip())]
    result = {
        "uuid": _text(row.get("uuid"), 64),
        "ip": ipv4[0] if ipv4 else "",
        "mac": normalize_mac(_first(",".join(macs))),
        "hostname": _text(hostname, 63),
        "description": _text(description, 255),
        # Several addresses or MACs on one host entry can't be represented by one reservation.
        "complex": len(ips) > 1 or len(macs) > 1,
    }
    if backend == Firewall.KEA:
        result["subnet"] = _text(row.get("subnet"), 50)
    result["managed"] = bool(marker_of(result["description"]))
    return result


def read_state(firewall, client):
    """Leases, reservations (and Kea subnets) as the firewall reports them now. Read-only."""
    backend = firewall.dhcp_backend
    endpoints = ENDPOINTS[backend]
    reservations = [_reservation_row(backend, row) for row in _rows(client, endpoints["reservations"])]
    leases = []
    for row in _rows(client, endpoints["leases"]):
        address = _text(row.get("address"), 50)
        try:
            if ipaddress.ip_address(address).version != 4:
                continue
        except ValueError:
            continue
        leases.append(
            {
                "address": address,
                "mac": normalize_mac(row.get("hwaddr", "")),
                "hostname": _text(row.get("hostname"), 100),
                "expire": _expire(row.get("expire")),
                "interface": _text(row.get("if_descr"), 60),
                "reserved": str(row.get("lease_type", "")) == "static",
            }
        )
    state = {
        "backend": backend,
        "reservations": sorted(reservations, key=lambda r: (r["uuid"], r["ip"]))[:LIMIT],
        "leases": sorted(leases, key=lambda r: ipaddress.ip_address(r["address"]))[:LIMIT],
        "truncated": len(reservations) > LIMIT or len(leases) > LIMIT,
    }
    if backend == Firewall.KEA:
        state["subnets"] = sorted(
            (
                {"uuid": _text(r.get("uuid"), 64), "subnet": _text(r.get("subnet"), 50)}
                for r in _rows(client, endpoints["subnets"])
            ),
            key=lambda r: r["subnet"],
        )
    return state


def _store(firewall, state):
    inventory, _ = DeviceInventory.objects.get_or_create(firewall=firewall)
    inventory.data = {**inventory.data, "dhcp": {**state, "read_at": timezone.now().isoformat(timespec="seconds")}}
    inventory.save()
    return inventory.data["dhcp"]


def refresh_dhcp(firewall, client):
    return _store(firewall, read_state(firewall, client))


def observation(firewall):
    inventory = DeviceInventory.objects.filter(firewall=firewall).first()
    return (inventory.data.get("dhcp") if inventory else None) or {}


def fingerprint(state):
    """What a write depends on: reservations (and Kea subnets). Leases change constantly and don't count."""
    return digest({"reservations": state.get("reservations", []), "subnets": state.get("subnets", [])})


# --- Planning --------------------------------------------------------------------------------------


def _matches(reservation, rows):
    marker = short_marker(reservation.uid)
    return [
        row
        for row in rows
        if marker_of(row["description"]) == marker
        or (reservation.remote_uuid and row["uuid"] == reservation.remote_uuid)
    ]


def _comparable(row, backend):
    fields = {"ip": row["ip"], "mac": row["mac"], "hostname": row["hostname"], "description": row["description"]}
    if backend == Firewall.KEA:
        fields["subnet"] = row.get("subnet", "")
    return fields


LABELS = {
    "ip": "IP address",
    "mac": "MAC address",
    "hostname": "Hostname",
    "description": "Description",
    "subnet": "Subnet",
}


def _contains(subnet, address):
    try:
        return address in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def reservation_plan(firewall):
    """Create/update operations for this firewall's reservations, and tagged device entries to remove."""
    state = observation(firewall)
    backend = firewall.dhcp_backend
    plan = {
        "firewall": firewall.name,
        "backend": backend,
        "read_at": state.get("read_at"),
        "errors": [],
        "rows": [],
        "removals": [],
    }
    if not firewall.enabled:
        plan["errors"].append("Firewall is disabled; nothing is planned.")
    elif not state:
        plan["errors"].append("Read DHCP from this firewall first.")
    elif state.get("backend") != backend:
        plan["errors"].append(
            "The DHCP server setting changed since the last read. Read DHCP from this firewall again."
        )
    elif state.get("truncated"):
        plan["errors"].append("The firewall has more DHCP entries than the manager reads; synchronization is blocked.")
    if plan["errors"]:
        plan["approval_sha256"] = digest(plan)
        return plan
    rows = state.get("reservations", [])
    subnets = state.get("subnets", [])
    matched = set()
    for reservation in firewall.reservations.select_related("logical_interface").order_by("ip_address", "pk"):
        description = tagged(reservation.description or reservation.hostname, reservation.uid)
        desired = {
            "ip": reservation.ip_address,
            "mac": reservation.mac_address,
            "hostname": reservation.hostname,
            "description": description,
        }
        row = {
            "id": str(reservation.uid),
            "name": reservation.hostname or reservation.mac_address,
            "interface": reservation.logical_interface.name,
            "ip": reservation.ip_address,
            "mac": reservation.mac_address,
            "action": None,
            "remote_uuid": None,
            "payload": None,
            "changes": [],
            "errors": [],
        }
        if backend == Firewall.KEA:
            address = ipaddress.ip_address(reservation.ip_address)
            subnet = next((s for s in subnets if _contains(s["subnet"], address)), None)
            if subnet is None:
                row["errors"].append(
                    f"No Kea subnet on {firewall.name} contains {address}. Add the subnet in Kea first."
                )
            else:
                desired["subnet"] = subnet["subnet"]
        matches = _matches(reservation, rows)
        if len(matches) > 1:
            row["errors"].append("The firewall has several reservations with this manager identity; remove the extras.")
        actual = matches[0] if len(matches) == 1 else None
        if actual:
            matched.add(actual["uuid"])
            if actual["complex"]:
                row["errors"].append(
                    "The device entry lists several addresses or MAC addresses; edit it on the firewall."
                )
        for other in rows:
            if other is actual or other["uuid"] in matched or (actual and other["uuid"] == actual["uuid"]):
                continue
            if other["mac"] == reservation.mac_address or other["ip"] == reservation.ip_address:
                owner = "another manager reservation" if other["managed"] else "a reservation made on the firewall"
                row["errors"].append(
                    f"{other['ip'] or other['mac']} is already used by {owner} ({other['hostname'] or other['description'] or other['uuid']}). "
                    "Import or remove that entry first."
                )
        if not row["errors"]:
            before = _comparable(actual, backend) if actual else None
            if before != desired:
                row["action"] = "update" if actual else "create"
                row["remote_uuid"] = actual["uuid"] if actual else None
                row["changes"] = [
                    {"label": LABELS[key], "actual": before[key] if before else "", "desired": value}
                    for key, value in desired.items()
                    if not before or before[key] != value
                ]
                if backend == Firewall.KEA:
                    subnet_uuid = next(s["uuid"] for s in subnets if s["subnet"] == desired["subnet"])
                    row["payload"] = {
                        "subnet": subnet_uuid,
                        "ip_address": desired["ip"],
                        "hw_address": desired["mac"],
                        "hostname": desired["hostname"],
                        "description": desired["description"],
                    }
                else:
                    row["payload"] = {
                        "host": desired["hostname"],
                        "ip": desired["ip"],
                        "hwaddr": desired["mac"],
                        "descr": desired["description"],
                    }
        plan["rows"].append(row)
    for row in rows:
        if row["managed"] and row["uuid"] not in matched:
            plan["removals"].append(
                {
                    "uuid": row["uuid"],
                    "ip": row["ip"],
                    "mac": row["mac"],
                    "hostname": row["hostname"],
                    "description": untagged(row["description"]),
                }
            )
    plan["fingerprint"] = fingerprint(state)
    plan["approval_sha256"] = digest(plan)
    return plan


def reservation_state(reservation, state):
    """For the reservations page: in_sync, differs, missing or unknown (not read)."""
    if not state or state.get("backend") != reservation.firewall.dhcp_backend:
        return "unknown"
    matches = _matches(reservation, state.get("reservations", []))
    if len(matches) != 1:
        return "missing" if not matches else "differs"
    actual = matches[0]
    desired = (reservation.ip_address, reservation.mac_address, reservation.hostname)
    same = (actual["ip"], actual["mac"], actual["hostname"]) == desired
    same = same and actual["description"] == tagged(reservation.description or reservation.hostname, reservation.uid)
    return "in_sync" if same else "differs"


# --- Execution -------------------------------------------------------------------------------------


def _saved(result):
    return isinstance(result, dict) and str(result.get("result", "")).lower() == "saved"


def _verify(observed, operations, removed):
    rows = observed["reservations"]
    present = {row["uuid"] for row in rows}
    if removed & present:
        raise DeviceError("Readback still lists a reservation selected for removal.")
    for row in operations:
        marker = short_marker(row["id"])
        found = [r for r in rows if marker_of(r["description"]) == marker]
        if len(found) != 1:
            raise DeviceError(f"Readback doesn't show reservation {row['name']} exactly once.")
        actual = found[0]
        if (actual["ip"], actual["mac"], actual["hostname"]) != (
            row["ip"],
            row["mac"],
            row["payload"].get("host", row["payload"].get("hostname")),
        ):
            raise DeviceError(f"Readback of reservation {row['name']} doesn't match what was written.")


def execute_reservation_sync(firewall, approved, selected, remove, client, actor):
    with device_write_lock(firewall.pk, "A DHCP reservation synchronization"):
        plan = reservation_plan(firewall)
        if plan["errors"] or plan["approval_sha256"] != approved:
            raise DeviceError("The reservation plan changed or is blocked. Review it again. Nothing was written.")
        eligible = {row["id"]: row for row in plan["rows"] if row["action"] and not row["errors"]}
        removable = {row["uuid"]: row for row in plan["removals"]}
        selected, remove = set(selected), set(remove)
        if not selected and not remove:
            raise DeviceError("Nothing selected to synchronize.")
        if not selected <= eligible.keys() or not remove <= removable.keys():
            raise DeviceError("Select only unblocked reservations from the current plan. Nothing was written.")
        current = read_state(firewall, client)
        if fingerprint(current) != plan["fingerprint"]:
            raise DeviceError(
                "DHCP reservations on the firewall changed since they were read. Read DHCP again and review. "
                "Nothing was written."
            )
        if reservation_plan(firewall)["approval_sha256"] != approved:
            raise DeviceError("Manager reservations changed during preflight. Review again. Nothing was written.")
        endpoints = ENDPOINTS[firewall.dhcp_backend]
        operations = [eligible[key] for key in sorted(selected)]
        AuditEvent.objects.create(
            actor=actor,
            action="dhcp.reservations.started",
            detail=f"{firewall.name} {approved}: {len(operations)} upserts, {len(remove)} removals",
        )
        try:
            for row in operations:
                if row["action"] == "update":
                    path = endpoints["set"] + quote(row["remote_uuid"], safe="")
                else:
                    path = endpoints["add"]
                if not _saved(client.post(path, {endpoints["key"]: row["payload"]})):
                    raise DeviceError(f"OPNsense rejected reservation {row['name']}; inspect it on the firewall.")
            for uuid in sorted(remove):
                result = client.post(endpoints["del"] + quote(uuid, safe=""), {})
                if not isinstance(result, dict) or str(result.get("result", "")).lower() != "deleted":
                    raise DeviceError(f"OPNsense did not delete reservation {removable[uuid]['ip'] or uuid}.")
                AuditEvent.objects.create(
                    actor=actor,
                    action="dhcp.reservation.removed",
                    detail=f"{firewall.name}: {removable[uuid]['ip']} {removable[uuid]['mac']} ({uuid})",
                )
            result = client.post(endpoints["reconfigure"], {})
            if not isinstance(result, dict) or str(result.get("status", "")).lower() != "ok":
                raise DeviceError("Reservations were saved but the DHCP service didn't reload.")
            observed = read_state(firewall, client)
            _verify(observed, operations, remove)
        except DeviceError as exc:
            AuditEvent.objects.create(
                actor=actor, action="dhcp.reservations.failed", detail=f"{firewall.name}; partial changes may remain"
            )
            raise DeviceError(f"{exc} Partial changes may remain; read DHCP again before retrying.") from exc
        _store(firewall, observed)
        AuditEvent.objects.create(actor=actor, action="dhcp.reservations.completed", detail=firewall.name)
        return len(operations), len(remove)


# --- Import ----------------------------------------------------------------------------------------


def import_reservations(firewall, uuids, actor):
    """Adopt device reservations (from the last read) as manager reservations, all or nothing."""
    from .ipam import interface_plan

    state = observation(firewall)
    rows = {row["uuid"]: row for row in state.get("reservations", []) if not row["managed"]}
    uuids = [u for u in uuids if u]
    if not uuids or not set(uuids) <= rows.keys():
        raise DeviceError("Select reservations from the last DHCP read of this firewall.")
    subnets = []
    mapped = {m.logical_interface_id for m in firewall.interface_mappings.all()}
    for addressing in InterfaceAddressing.objects.select_related("logical_interface"):
        planned = interface_plan(addressing, firewall)[4]
        if planned and "subnet" in planned and addressing.logical_interface_id in mapped:
            subnets.append((planned["subnet"], addressing.logical_interface))
    created = []
    with transaction.atomic():
        for uuid in uuids:
            row = rows[uuid]
            if row["complex"] or not row["ip"] or not row["mac"]:
                raise DeviceError(
                    f"Reservation {row['hostname'] or uuid} needs exactly one IPv4 address and MAC address."
                )
            address = ipaddress.ip_address(row["ip"])
            logical = next((li for net, li in subnets if address in net), None)
            if logical is None:
                raise DeviceError(f"{address} isn't in the address plan of any interface mapped on {firewall.name}.")
            reservation = StaticReservation(
                firewall=firewall,
                logical_interface=logical,
                ip_address=row["ip"],
                mac_address=row["mac"],
                hostname=safe_hostname(row["hostname"]),
                description=row["description"][:200],
                remote_uuid=uuid,
            )
            try:
                reservation.full_clean()
            except ValidationError as exc:
                raise DeviceError(f"Reservation {row['ip']} can't be imported: {' '.join(exc.messages)}") from None
            reservation.save()
            created.append(reservation)
    AuditEvent.objects.create(
        actor=actor, action="dhcp.reservations.imported", detail=f"{firewall.name}: {len(created)} reservations"
    )
    return len(created)

"""Push planned interface addresses (Addressing: Address Plan) to a firewall's interface settings.

Uses the interface assignment API of OPNsense 26.7 and later (`/api/interfaces/assignment/…`,
model `OPNsense\\Interfaces\\NetworkInterface`): `get_item/<ifname>` to read, `set_item/<ifname>` with
body key `interface` to write, `reconfigure` to apply (it applies only interfaces with pending
edits) and `pending` to see whether unapplied interface edits already exist.

Deliberately narrow, as a starter:
* only interfaces whose address type for that family is already static (`staticv4` / `staticv6`)
  get a new address; DHCP, PPPoE, Identity association and others are listed and left alone;
* the address the manager itself connects to is never changed;
* nothing runs while the firewall has unapplied interface edits, because reconfigure would apply them.

The review reads the device and signs a digest of (observed settings, plan); the worker re-reads,
must reproduce the digest, writes, reconfigures, reads back and audits. Interface changes are not
transactional and have no automatic rollback.
"""

import ipaddress
from urllib.parse import quote, urlsplit

from .alias_sync import digest
from .ipam import interface_plan
from .locks import device_write_lock
from .models import AuditEvent, InterfaceAddressing
from .opnsense import DeviceError, flatten

BASE = "/api/interfaces/assignment/"
FAMILIES = {4: ("type4", "ipaddr", "subnet", "staticv4"), 6: ("type6", "ipaddrv6", "subnetv6", "staticv6")}
TYPE_LABELS = {
    "staticv4": "static",
    "staticv6": "static",
    "dhcp": "DHCP",
    "pppoe": "PPPoE",
    "ppp": "PPP",
    "dhcp6": "DHCPv6",
    "slaac": "SLAAC",
    "linklocal": "Link-local",
    "idassoc6": "Identity association",
    "track6": "Track Interface (legacy)",
    "pppoev6": "PPPoEv6",
    "6rd": "6rd",
    "6to4": "6to4",
    "": "none",
}


def _address(config, key, subnet_key):
    value = flatten(config.get(key, "")).strip()
    bits = flatten(config.get(subnet_key, "")).strip()
    if value and "/" not in value and bits.isdigit():
        value = f"{value}/{bits}"
    return value


def read_settings(client, devices):
    """{device: {"type4", "ipaddr", "type6", "ipaddrv6"}} for the given interface identifiers."""
    settings = {}
    for device in sorted(devices):
        try:
            response = client.get(BASE + "get_item/" + quote(device, safe=""))
        except DeviceError as exc:
            if exc.status_code == 404:
                raise DeviceError(
                    "This firewall has no interface assignment API. Pushing interface addresses needs OPNsense "
                    "26.7 or later. Nothing was changed."
                ) from exc
            raise
        config = response.get("interface") if isinstance(response, dict) else None
        if not isinstance(config, dict):
            raise DeviceError(f"Unsupported interface settings response for {device}. Nothing was changed.")
        settings[device] = {
            "type4": flatten(config.get("type4", "")),
            "ipaddr": _address(config, "ipaddr", "subnet"),
            "type6": flatten(config.get("type6", "")),
            "ipaddrv6": _address(config, "ipaddrv6", "subnetv6"),
        }
    return settings


def _management_host(firewall):
    host = urlsplit(firewall.base_url).hostname or ""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def mapped_plans(firewall):
    """[(logical interface, device identifier, interface_plan)] for planned interfaces mapped here."""
    mappings = {m.logical_interface_id: m.device_interface for m in firewall.interface_mappings.all()}
    found = []
    for addressing in InterfaceAddressing.objects.select_related("logical_interface"):
        device = mappings.get(addressing.logical_interface_id)
        if device:
            found.append((addressing.logical_interface, device, interface_plan(addressing, firewall)))
    return found


def address_plan(firewall, observed):
    """Rows per planned interface and family: an operation, a reason it's left alone, or in sync."""
    management = _management_host(firewall)
    rows = []
    for logical, device, plan in mapped_plans(firewall):
        current = observed.get(device, {})
        for family, (type_key, address_key, _, static) in FAMILIES.items():
            planned = plan[family]
            if not planned:
                continue
            row = {
                "id": f"{device}:{family}",
                "interface": logical.name,
                "device": device,
                "family": family,
                "current": current.get(address_key, ""),
                "type": TYPE_LABELS.get(current.get(type_key, ""), current.get(type_key, "")),
                "desired": "",
                "action": None,
                "note": "",
                "blocked": "",
            }
            if "error" in planned:
                row["note"] = planned["error"]
                rows.append(row)
                continue
            wanted = planned["interface"]
            row["desired"] = str(wanted)
            if current.get(type_key) != static:
                if current.get(type_key) in ("idassoc6", "track6"):
                    row["note"] = "Identity association: the planned ULA goes on as a virtual IP instead."
                else:
                    row["note"] = f"Configured as {row['type']} on the firewall; only static addresses are changed."
                rows.append(row)
                continue
            try:
                now = ipaddress.ip_interface(row["current"]) if row["current"] else None
            except ValueError:
                now = None
            if now == wanted:
                row["note"] = "Already set."
                rows.append(row)
                continue
            if management is not None and now is not None and now.ip == management:
                row["blocked"] = (
                    f"The manager reaches {firewall.name} at {management}, on this interface. Change this address "
                    "on the firewall itself, then update the firewall's management URL."
                )
            else:
                row["action"] = "update"
                row["payload"] = {type_key: static, address_key: str(wanted)}
            rows.append(row)
    return rows


def review(firewall, client):
    """Read the device and plan; returns (observed, rows, approval digest)."""
    devices = {device for _, device, _ in mapped_plans(firewall)}
    observed = read_settings(client, devices)
    rows = address_plan(firewall, observed)
    return observed, rows, digest({"observed": observed, "rows": rows})


def execute(firewall, approved, selected, client, actor):
    """Write the selected reviewed address changes, apply them and read them back. Runs in the worker."""
    from .system_management import refresh_inventory

    with device_write_lock(firewall.pk, "An interface address change"):
        if not firewall.enabled:
            raise DeviceError("Disabled firewalls can't receive interface changes. Nothing was changed.")
        pending = client.get(BASE + "pending")
        if not isinstance(pending, dict) or pending.get("status") != "ok":
            raise DeviceError(
                f"{firewall.name} has unapplied interface changes, which applying would also activate. Apply or "
                "revert them under Interfaces: Assignments first, then review again. Nothing was changed."
            )
        observed, rows, current = review(firewall, client)
        if current != approved:
            raise DeviceError(
                "The firewall's interface settings or the address plan changed since the review. Review again. "
                "Nothing was changed."
            )
        eligible = {row["id"]: row for row in rows if row["action"]}
        selected = set(selected)
        if not selected or not selected <= eligible.keys():
            raise DeviceError("Select one or more address changes from the current review. Nothing was changed.")
        changes = [eligible[key] for key in sorted(selected)]
        by_device = {}
        for row in changes:
            by_device.setdefault(row["device"], {}).update(row["payload"])
        summary = ", ".join(f"{row['interface']} {row['current'] or 'none'} -> {row['desired']}" for row in changes)
        AuditEvent.objects.create(
            actor=actor, action="interfaces.addresses.started", detail=f"{firewall.name}: {summary}"
        )
        try:
            for device, payload in sorted(by_device.items()):
                result = client.post(BASE + "set_item/" + quote(device, safe=""), {"interface": payload})
                if not isinstance(result, dict) or result.get("result") != "saved":
                    raise DeviceError(f"OPNsense rejected the new address for {device}; inspect its validation errors.")
            result = client.post(BASE + "reconfigure", {})
            if not isinstance(result, dict) or result.get("status") != "ok":
                raise DeviceError("The addresses were saved but applying the interfaces failed.")
            after = read_settings(client, by_device)
            for row in changes:
                _, address_key, _, _ = FAMILIES[row["family"]]
                try:
                    ok = ipaddress.ip_interface(after[row["device"]][address_key]) == ipaddress.ip_interface(
                        row["desired"]
                    )
                except ValueError:
                    ok = False
                if not ok:
                    raise DeviceError(f"Readback of {row['interface']} doesn't show {row['desired']}.")
        except DeviceError as exc:
            AuditEvent.objects.create(
                actor=actor, action="interfaces.addresses.failed", detail=f"{firewall.name}; partial changes may remain"
            )
            raise DeviceError(
                f"{exc} Interface changes are not rolled back automatically; check Interfaces: Assignments on the "
                "firewall."
            ) from exc
        try:
            refresh_inventory(firewall, client)
        except DeviceError:
            pass  # The change is verified; the overview catches up on the next pull.
        AuditEvent.objects.create(
            actor=actor, action="interfaces.addresses.completed", detail=f"{firewall.name}: {summary}"
        )
        return len(changes)

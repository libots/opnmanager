import ipaddress
from urllib.parse import quote

from django.utils import timezone

from .alias_sync import digest
from .locks import device_write_lock
from .models import AuditEvent, DeviceInventory, FirmwareJob
from .opnsense import DeviceError, flatten


def refresh_inventory(firewall, client):
    response = client.post(
        "/api/interfaces/overview/interfaces_info", {"current": 1, "rowCount": -1, "searchPhrase": ""}, write=False
    )
    rows = response.get("rows") if isinstance(response, dict) else None
    if not isinstance(rows, list):
        raise DeviceError("Unsupported interface inventory response.")
    interfaces = []
    for row in rows:
        config = row.get("config", {})
        identifier = config.get("identifier") or row.get("identifier") or row.get("device")
        if not identifier:
            continue
        item = {
            key: row.get(key, "")
            for key in ("description", "device", "status", "ipv4", "ipv6", "mtu", "macaddr", "vlan_tag", "gateways")
        }
        for family in ("ipv4", "ipv6"):
            addresses = item.get(family)
            if isinstance(addresses, list):
                item[family] = ", ".join(
                    str(ip.get("ipaddr", "")) if isinstance(ip, dict) else str(ip) for ip in addresses
                )
        item["name"] = identifier
        interfaces.append(item)
    obj, _ = DeviceInventory.objects.get_or_create(firewall=firewall)
    data = {**obj.data, "interfaces": interfaces}
    # Rule field choices are device-native. A missing privilege shouldn't erase
    # interface observations or pretend a fallback list is the complete catalog.
    try:
        rule = client.get("/api/firewall/filter/get_rule")["rule"]
        choices = []
        for value, option in rule.get("protocol", {}).items():
            canonical = (
                "any" if value.lower() == "any" else "IPv6-ICMP" if value.lower() == "ipv6-icmp" else value.upper()
            )
            choices.append([canonical, str(option.get("value", option.get("label", value)))])
        if choices:
            data["protocols"] = choices
        data.pop("catalog_error", None)
    except (DeviceError, KeyError, TypeError, AttributeError):
        data["catalog_error"] = "Device protocol catalog unavailable; existing catalog retained."
    obj.data = data
    obj.save()
    return obj


def _firmware_action(firewall, action, client, actor):
    if not firewall.enabled:
        raise DeviceError("Disabled firewalls cannot receive firmware actions.")
    if action not in ("check", "update"):
        raise DeviceError("Unsupported firmware action.")
    if action == "update":
        current = client.get("/api/core/firmware/status")
        if current.get("status") != "update":
            raise DeviceError("Run a successful firmware check first. Only stable package updates are supported here.")
    job = FirmwareJob.objects.create(firewall=firewall, action=action, status="starting")
    AuditEvent.objects.create(actor=actor, action="firmware." + action + ".started", detail=firewall.name)
    try:
        running = client.get("/api/core/firmware/running")
        if str(running.get("status", "")).strip() != "ready":
            raise DeviceError("The firewall already has a firmware task running. Refresh its status first.")
        result = client.post("/api/core/firmware/" + action, {})
        if not isinstance(result, dict) or result.get("status") != "ok":
            raise DeviceError("Firmware task was not accepted by OPNsense.")
        job.status = "running"
        job.remote_id = str(result.get("msg_uuid", ""))[:100]
        job.message = "Remote task accepted; refresh status to monitor completion. No automatic reboot is requested."
    except DeviceError as exc:
        job.status = "uncertain"
        job.message = str(exc)
        job.save()
        AuditEvent.objects.create(actor=actor, action="firmware." + action + ".uncertain", detail=firewall.name)
        raise
    job.save()
    return job


def _text(value, limit=200):
    return str(value if value is not None else "")[:limit]


def _packages(rows):
    """Pending package changes from firmware status, as plain strings (capped)."""
    packages = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        packages.append(
            {
                "name": _text(row.get("name"), 100),
                "current": _text(row.get("current_version", row.get("old_version", "")), 50),
                "new": _text(row.get("new_version", row.get("version", "")), 50),
            }
        )
    return sorted(packages, key=lambda p: p["name"])[:300]


def is_plugin(name):
    """OPNsense plugins are the os-* packages (os-acme-client, os-theme-…); everything else is base/core."""
    return name.startswith("os-")


def firmware_summary(response, info=None):
    """What the overview needs from core/firmware/status (and optionally core/firmware/info).

    Only after a check (`core/firmware/check`) does status list pending packages; the
    plugin split is by package name, so plugin updates found by the same check are shown
    separately. No raw response text beyond short, truncated fields is kept.
    """
    product = response.get("product") or {}
    pending = _packages(response.get("upgrade_packages")) + [
        {**p, "new": p["new"] or "new"} for p in _packages(response.get("new_packages"))
    ]
    summary = {
        "status": _text(response.get("status", "unknown"), 30),
        "version": _text(product.get("product_version", "unknown"), 50),
        "latest": _text(product.get("product_latest", ""), 50),
        "message": _text(response.get("status_msg", ""), 500),
        "needs_reboot": str(response.get("needs_reboot", "0")) == "1",
        "upgrade_major": _text(response.get("upgrade_major_version", ""), 30),
        "last_check": _text(response.get("last_check", ""), 60),
        "download_size": _text(response.get("download_size", ""), 30),
        "core_updates": [p for p in pending if not is_plugin(p["name"])],
        "plugin_updates": [p for p in pending if is_plugin(p["name"])],
    }
    if info is not None:
        plugins = info.get("plugin") if isinstance(info, dict) else None
        if isinstance(plugins, list):
            summary["plugins"] = sorted(
                (
                    {
                        "name": _text(row.get("name"), 100),
                        "version": _text(row.get("version"), 50),
                        "misconfigured": str(row.get("configured", "1")) == "0",
                    }
                    for row in plugins
                    if isinstance(row, dict) and row.get("name") and str(row.get("installed", "0")) == "1"
                ),
                key=lambda p: p["name"],
            )[:300]
    return summary


def update_state(firmware):
    """One word for the overview: unknown, current, updates, major, reboot or error."""
    if not firmware:
        return "unknown"
    if firmware.get("needs_reboot"):
        return "reboot"
    status = firmware.get("status")
    if status == "error":
        return "error"
    if firmware.get("core_updates") or firmware.get("plugin_updates") or status == "update":
        return "updates"
    if status == "upgrade" or firmware.get("upgrade_major"):
        return "major"
    if status == "none":
        return "current"
    return "unknown"


def refresh_firmware(firewall, client):
    response = client.get("/api/core/firmware/status")
    if not isinstance(response, dict):
        raise DeviceError("Unsupported firmware status response.")
    inventory, _ = DeviceInventory.objects.get_or_create(firewall=firewall)
    previous = inventory.data.get("firmware", {})
    try:
        info = client.get("/api/core/firmware/info")
        safe = firmware_summary(response, info if isinstance(info, dict) else {})
    except DeviceError:
        # A missing privilege for the package list shouldn't hide the update status.
        safe = firmware_summary(response)
        if "plugins" in previous:
            safe["plugins"] = previous["plugins"]
        safe["plugins_error"] = "Installed plugins couldn't be read; the list shown is from an earlier refresh."
    safe["refreshed_at"] = timezone.now().isoformat(timespec="seconds")
    inventory.data = {**inventory.data, "firmware": safe}
    inventory.save()
    job = firewall.firmwarejob_set.filter(status__in=["running", "starting", "uncertain"]).first()
    if job:
        progress = client.get("/api/core/firmware/upgradestatus")
        state = progress.get("status", "unknown")
        if state in ("done", "reboot", "error"):
            job.status = {"done": "finished", "reboot": "reboot_required", "error": "uncertain"}[state]
            job.message = (
                "Device reported "
                + state
                + ". Verify version and status; completion is not a guarantee of upgrade success."
            )
            if state == "error" and client.get("/api/core/firmware/running").get("status") == "ready":
                job.status = "unconfirmed"
                job.message = (
                    "No active firmware task; previous result is unknown. Verify the device before explicitly retrying."
                )
            job.save()
    return safe


def vip_plan(firewall, desired, observed):
    mapping = firewall.interface_mappings.filter(logical_interface=desired.interface).first()
    if not mapping:
        raise DeviceError("Map the virtual IP logical interface on this firewall first.")
    marker = "[opnmanager-vip:" + str(desired.pk) + "] " + desired.name
    payload = {"interface": mapping.device_interface, "network": desired.network, "mode": desired.mode, "descr": marker}
    origin = firewall.virtualiporigin_set.filter(virtual_ip=desired).first()
    matches = [
        row
        for row in observed
        if row.get("descr", "").startswith("[opnmanager-vip:" + str(desired.pk) + "] ")
        or (origin and row.get("uuid") == origin.remote_uuid)
    ]
    if len(matches) > 1:
        raise DeviceError("Duplicate managed virtual IP identity.")
    actual = matches[0] if matches else None
    if actual and actual.get("mode") == "carp":
        raise DeviceError("CARP entries require device-specific secrets and cannot be edited here.")
    return {"payload": payload, "uuid": actual.get("uuid") if actual else None}


def read_vips(client):
    response = client.get("/api/interfaces/vip_settings/get")
    nodes = response.get("vip", {}).get("vip", {})
    if nodes == []:
        return []
    if not isinstance(nodes, dict):
        raise DeviceError("Unsupported virtual IP inventory.")
    return [
        {**{key: flatten(value) for key, value in row.items() if key != "password"}, "uuid": uid}
        for uid, row in nodes.items()
    ]


def firmware_action(firewall, action, client, actor):
    with device_write_lock(firewall.pk, "A firmware request"):
        if FirmwareJob.objects.filter(firewall=firewall, status__in=["running", "starting", "uncertain"]).exists():
            raise DeviceError("Refresh and resolve the existing firmware task before starting another.")
        return _firmware_action(firewall, action, client, actor)


def vip_review_digest(observed, plan):
    """What a VIP apply review approves: the device's VIP inventory and the planned write."""
    return digest({"observed": observed, "plan": plan})


def _vip_matches(row, vip, payload):
    try:
        network = ipaddress.ip_interface(row.get("subnet", "") + "/" + row.get("subnet_bits", ""))
    except ValueError:
        return False
    return (
        network == ipaddress.ip_interface(vip.network)
        and row.get("interface") == payload["interface"]
        and row.get("mode") == vip.mode
    )


def execute_vip_apply(firewall, vip, approved_digest, client, actor):
    """Write one reviewed virtual IP, reconfigure and read it back. Runs in the job worker."""
    with device_write_lock(firewall.pk, "A virtual IP change"):
        try:
            if not firewall.enabled or not vip.applies_to(firewall):
                raise DeviceError("This virtual IP no longer targets this firewall. Review again.")
            observed = read_vips(client)
            plan = vip_plan(firewall, vip, observed)
            if vip_review_digest(observed, plan) != approved_digest:
                raise DeviceError("Device or desired VIP changed. Review again.")
            endpoint = "set_item/" + quote(plan["uuid"], safe="") if plan["uuid"] else "add_item"
            AuditEvent.objects.create(actor=actor, action="vip.apply.started", detail=firewall.name + " " + vip.name)
            result = client.post("/api/interfaces/vip_settings/" + endpoint, {"vip": plan["payload"]})
            if not isinstance(result, dict) or result.get("result") != "saved":
                raise DeviceError("Device rejected the VIP. Inspect validation errors.")
            if client.post("/api/interfaces/vip_settings/reconfigure", {}).get("status") != "ok":
                raise DeviceError("VIP saved but reconfiguration failed. Inspect device state.")
            after = read_vips(client)
            matches = [r for r in after if r.get("descr") == plan["payload"]["descr"]]
            if len(matches) != 1 or not _vip_matches(matches[0], vip, plan["payload"]):
                raise DeviceError("VIP readback did not match. Inspect device state.")
        except DeviceError:
            AuditEvent.objects.create(actor=actor, action="vip.apply.failed", detail=firewall.name)
            raise
        AuditEvent.objects.create(actor=actor, action="vip.applied", detail=firewall.name + " " + vip.name)


def execute_vip_delete(firewall, uuid, approved_digest, client, actor):
    """Delete one reviewed device virtual IP and verify it is gone. Runs in the job worker."""
    with device_write_lock(firewall.pk, "A virtual IP change"):
        try:
            if not firewall.enabled:
                raise DeviceError("Disabled firewalls cannot receive virtual IP changes.")
            rows = read_vips(client)
            row = next((r for r in rows if r.get("uuid") == uuid), None)
            if not row:
                raise DeviceError("Virtual IP no longer exists. Refresh inventory.")
            if row.get("mode") == "carp":
                raise DeviceError("CARP deletion is device-local because of HA dependencies.")
            if digest(rows) != approved_digest:
                raise DeviceError("Virtual IP configuration changed. Review again.")
            AuditEvent.objects.create(actor=actor, action="vip.delete.started", detail=firewall.name + " " + uuid)
            result = client.post("/api/interfaces/vip_settings/del_item/" + quote(uuid, safe=""), {})
            if not isinstance(result, dict) or result.get("result") != "deleted":
                raise DeviceError("The device refused deletion, possibly because the VIP is in use.")
            if client.post("/api/interfaces/vip_settings/reconfigure", {}).get("status") != "ok":
                raise DeviceError("VIP removed from saved config but reconfiguration failed; inspect device state.")
            after = read_vips(client)
            if any(r.get("uuid") == uuid for r in after):
                raise DeviceError("Deleted VIP is still present on readback.")
        except DeviceError:
            AuditEvent.objects.create(actor=actor, action="vip.delete.failed", detail=firewall.name)
            raise
        inventory, _ = DeviceInventory.objects.get_or_create(firewall=firewall)
        inventory.data = {**inventory.data, "vips": after}
        inventory.save()
        AuditEvent.objects.create(actor=actor, action="vip.delete.completed", detail=firewall.name + " " + uuid)

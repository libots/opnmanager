# System management: interfaces inventory, firmware, VIPs, DNS

Files: `fleet/system_management.py`, `fleet/management_views.py`. Tests:
`test_system_management.py`, `test_features.py`. These run **synchronously in the web request**
(not as `DeviceJob`s); writes still take `device_write_lock`.

## Interface inventory

`refresh_inventory(fw, client)`: `POST /api/interfaces/overview/interfaces_info` with
`rowCount: -1` (otherwise OPNsense pages results). Stores rows in `DeviceInventory.data["interfaces"]`
(identifier as `name`, plus description/device/status/addresses/VLAN/MTU). Also tries
`GET /api/firewall/filter/get_rule` to store the device's protocol catalog in `data["protocols"]`
(normalized: `any`, `IPv6-ICMP`, else upper-case). A catalog failure sets `catalog_error` and keeps
the previous catalog; it never discards interface data. `choices.protocol_choices()` merges all
firewalls' catalogs over the built-in `PROTOCOLS`.

## Firmware

`firmware_action(fw, action, client, actor)` under the write lock; only `check` and `update`.
`update` requires device status `update` (a prior successful check) and `fleet.install_firmware`
(checked in the view) plus a confirm checkbox. Requires `running == "ready"` before queueing.
`FirmwareJob.status`: `starting` → `running` (accepted, not "succeeded") → on refresh
`finished` / `reboot_required` / `uncertain` / `unconfirmed`. No reboot/major-upgrade actions.

## Virtual IPs

- Read: `read_vips(client)` (`GET /api/interfaces/vip_settings/get`), dropping `password`.
  Stored in `DeviceInventory.data["vips"]` by `refresh_vips`.
- Adopt (`adopt_vip`): only `ipalias` / `proxyarp`; interface must be mapped; creates a selected-scope
  `VirtualIP` targeting that firewall plus a `VirtualIPOrigin`. Device unchanged.
- Apply (`review_vip`) / delete (`delete_vip`): wrapped by the `vip_lock` decorator (write lock on
  POST). The GET review renders a `django.core.signing` token (salt `vip-review` / `vip-delete`,
  `max_age=600`) binding firewall, VIP and a digest of observed inventory + plan; the POST re-reads
  and must reproduce it. Then save/del + `reconfigure` + readback.
- VIP device identity: `descr` starts with `[opnmanager-vip:<pk>] ` — different from the `[om:...]`
  rule/alias/group tag.
- CARP entries are view-only (secrets and HA dependencies stay on-device).

## DNS search-domain profiles

`DNSProfile` is **desired configuration only**: there is no supported OPNsense write API, so
nothing deploys it. `dns_general` shows which profiles apply to each firewall; the admin form shows
a warning banner. Do not add a guessed endpoint or XML rewrite.

## Authentication servers

Not managed (no OPNsense API). Earlier models were removed by migration 0013.

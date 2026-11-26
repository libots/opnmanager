# System management: interfaces inventory, firmware, VIPs, DNS

Files: `fleet/system_management.py`, `fleet/management_views.py`. Tests:
`test_system_management.py`, `test_features.py`. Inventory refreshes and firmware requests run
**synchronously in the web request** (a firmware request only queues a task on the firewall) and take
`device_write_lock`. VIP apply/delete run as `DeviceJob`s in the worker.

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
`refresh_firmware` reads `core/firmware/status` and `core/firmware/info` and stores
`firmware_summary()` in `DeviceInventory.data["firmware"]`: version/latest, `core_updates` and
`plugin_updates` (split by `is_plugin`: `os-*` package names), `plugins` (installed only, with a
`misconfigured` flag), `needs_reboot`, `upgrade_major`, `last_check`, `refreshed_at`. An info
failure keeps the previous plugin list and sets `plugins_error`. `update_state()` reduces it to one
word for the overview (`unknown`/`current`/`updates`/`major`/`reboot`/`error`). Status lists pending
packages only after a `check` has run on the device. The overview's Check/Refresh buttons post to
`firmware_task` with `next=/`.
`FirmwareJob.status`: `starting` → `running` (accepted, not "succeeded") → on refresh
`finished` / `reboot_required` / `uncertain` / `unconfirmed`. No reboot/major-upgrade actions.

## Virtual IPs

- Read: `read_vips(client)` (`GET /api/interfaces/vip_settings/get`), dropping `password`.
  Stored in `DeviceInventory.data["vips"]` by `refresh_vips`.
- Adopt (`adopt_vip`): only `ipalias` / `proxyarp`; interface must be mapped; creates a selected-scope
  `VirtualIP` targeting that firewall plus a `VirtualIPOrigin`. Device unchanged.
- Apply (`review_vip`) / delete (`delete_vip`): the GET reads the device and renders a
  `django.core.signing` token (salt `vip-review` / `vip-delete`, `max_age=600`) binding firewall,
  VIP (or device UUID) and a digest (`vip_review_digest(observed, plan)` / `digest(rows)`). The POST
  only verifies the token (expiry, firewall, object) and enqueues `vip.apply` / `vip.delete` with the
  digest; it doesn't contact the device. The worker runs `execute_vip_apply` / `execute_vip_delete`:
  write lock → re-read → digest must match → save/del → `reconfigure` → readback → audit
  (`vip.apply.started/failed`, `vip.applied`; `vip.delete.started/failed/completed`). Delete also
  refreshes `DeviceInventory.data["vips"]`.
- VIP device identity: `descr` starts with `[opnmanager-vip:<pk>] ` — different from the `[om:...]`
  rule/alias/group tag.
- CARP entries are view-only (secrets and HA dependencies stay on-device).

## DNS search-domain profiles

`DNSProfile` is **desired configuration only**: there is no supported OPNsense write API, so
nothing deploys it. `dns_general` shows which profiles apply to each firewall; the admin form shows
a warning banner. Do not add a guessed endpoint or XML rewrite.

## Authentication servers

Not managed (no OPNsense API). Earlier models were removed by migration 0013.

# OPNsense client

Files: `fleet/opnsense.py` (`OPNsenseClient`, `flatten`), `fleet/opnsense_errors.py`,
`fleet/credentials.py`, plus device calls in `fleet/system_management.py` (inventory, firmware,
VIPs). Tests: `test_connection_errors.py`, `test_group_pull.py`,
`test_import.py` (device-shaped rows), `test_system_management.py`.

`OPNsenseClient` is the **only** code that talks HTTP to firewalls. Tests replace it with
`unittest.mock.Mock` objects; no test makes a real request.

## Construction and transport

- `OPNsenseClient(firewall)` runs `firewall.full_clean()` (HTTPS origin only), loads credentials
  (`credentials.get_credentials`: encrypted UI credentials, else env `<PREFIX>_API_KEY/_API_SECRET`),
  and uses HTTP Basic auth via a `requests.Session`.
- TLS verification is always on; `firewall.ca_bundle` (PEM path) replaces the default CA store.
  Never add an option to disable verification.
- `allow_redirects=False`; any 3xx is an error. `TIMEOUT = (5, 30)` — the 30 s read timeout leaves
  headroom inside OPNsense's 60 s rollback window.
- `_request` converts every failure into `DeviceError` with an actionable, secret-free message
  (TLS, proxy, connect/read timeout, connection, unreadable CA file, HTTP status with 401/403/404
  explanations, non-JSON). Raw exception text and response bodies are never surfaced.
  `DeviceError.status_code` is set for HTTP errors (used to detect 404 on savepoint).
- `post(path, payload, write=True)`: write errors append "Device state is uncertain…". Pass
  `write=False` for read-only POST endpoints (search/info, savepoint).

## Snapshot read (`snapshot()`)

| Endpoint | Becomes |
| --- | --- |
| `GET /api/firewall/filter/get` | `rules` |
| `GET /api/firewall/alias/export` | `aliases` |
| `GET /api/firewall/filter/get_interface_list` | `interfaces` (`name`=value, `label`) |
| `GET /api/firewall/group/get` | `groups` |
| `GET /api/firewall/category/get` | `categories` |

`flatten()` turns OPNsense option-field maps (`{"opt2": {"selected": 1, ...}}`) into comma lists of
selected keys; each row gets its map key as `uuid`. An empty collection arrives as `[]`. Output goes
through `validate_snapshot`. Unexpected shapes → `DeviceError("Unsupported OPNsense response…")`.
Only the MVC rule inventory exists here: legacy GUI rules, automatic rules and NAT are invisible.

## Write endpoints used

| Method | Endpoint(s) | Success check |
| --- | --- | --- |
| `save_alias` | `alias/add_item`, `alias/set_item/<uuid>` (body `{"alias": payload}`) | `result == "saved"` |
| `save_definition` | `group/…`, `category/…` add_item/set_item (body `{kind: payload}`) | `result == "saved"` |
| `delete_definition` | `alias|group/del_item/<uuid>` | `result == "deleted"` |
| `reconfigure_aliases` / `reconfigure_definitions` | `alias/reconfigure`, `group/reconfigure` | `status == "ok"` |
| `save_rule` | `filter/add_rule`, `filter/set_rule/<uuid>` (body `{"rule": payload}`) | `result == "saved"` |
| `delete_rule` / `disable_rule` | `filter/del_rule/<uuid>`, `filter/toggle_rule/<uuid>/0` | `deleted` / `disabled` |
| `savepoint` | `filter/savepoint` (404 → `SavepointUnsupported`) | non-empty `revision` |
| `apply_rules` | `filter/apply[/<revision>]` | `status == "ok"` |
| `cancel_rollback` / `revert` | `filter/cancel_rollback/<rev>`, `filter/revert/<rev>` | `status == "ok"` |
| `latest_config_backup` / `revert_config` | `GET core/backup/backups/this`, `core/backup/revert_backup/<id>` | first item id / `status == "reverted"` |

Elsewhere: `POST interfaces/overview/interfaces_info` (`rowCount: -1`, read-only),
`GET firewall/filter/get_rule` (protocol catalog), `core/firmware/{status,running,check,update,upgradestatus}`,
`interfaces/vip_settings/{get,add_item,set_item,del_item,reconfigure}`.

`OPNsenseClient` methods encode path parameters taken from device data with
`urllib.parse.quote(..., safe="")`; keep doing that for new endpoints (the VIP and firmware
helpers in `system_management.py` call `client.post` directly and quote the same way).

Alias reconfigure reloads the whole filter, and rule apply can activate unrelated pending device
edits; device operations are never transactional. The root README lists required API privileges —
update it when you add an endpoint.

# Data model

All models are in `fleet/models.py`. SQLite, `BigAutoField` PKs except `Rule` (UUID PK).

## Entity overview

```
FirewallGroup ──M2M(firewalls, related_name="groups")──► Firewall
Firewall 1─* InterfaceMapping *─1 LogicalInterface (PROTECT)
Firewall 1─* Snapshot (newest first; pruned to SNAPSHOT_RETENTION)
Firewall 1─1 DeviceInventory (JSON blob, see below)
Firewall 1─* DeviceJob, FirmwareJob, RuleOrigin, VirtualIPOrigin

ScopedPolicy (abstract): scope ∈ {all, selected} + M2M firewalls + M2M firewall_groups
  ├─ Alias          uid (UUID, device tag), name (unique, ≤32), type host|network|port, content (lines)
  ├─ InterfaceGroup uid (UUID, device tag), name (unique, ≤15), members M2M LogicalInterface, sequence, no_gui_group
  ├─ Category       name (unique, no commas), color (6 hex, no #)
  ├─ Rule           id UUID PK; see below
  ├─ DNSProfile     desired-only (never deployed)
  └─ VirtualIP      interface FK LogicalInterface, network "addr/prefix", mode ipalias|proxyarp

Rule M2M: interfaces, interface_groups, origin_interfaces, origin_interface_groups, categories
RuleOrigin(firewall, rule, remote_uuid)          unique (firewall, remote_uuid) — imported-from link
VirtualIPOrigin(firewall, virtual_ip, remote_uuid) unique (firewall, remote_uuid)
AuditEvent(actor, action, detail)                append-only log, read-only in admin
LocalAccountState(user 1─1, must_change_password)
```

### Targeting (`ScopedPolicy`)

`applies_to(firewall)`: disabled firewalls → never; `scope == "all"` → every enabled firewall;
else direct `firewalls` ∪ members of `firewall_groups`. Evaluated dynamically — adding a firewall
to a group instantly changes desired state. When objects were loaded with
`prefetch_related(*ScopedPolicy.SCOPE_PREFETCH)` it answers from memory (the planner relies on this
to avoid N queries per object). The UI edits this as one "Deploy to" field
(`forms.TargetsFormMixin`); `scope`/`firewalls`/`firewall_groups` posts are still accepted.

### Rule specifics

- `interface` (FK) is a **legacy single binding** kept for old data and tests; migration 0004
  copied it into `interfaces`. `Rule.bound_interfaces()` merges both. `RuleForm.save()` sets it to
  `None`. New code should read `bound_interfaces()` + `interface_groups`, never `interface` alone.
- `floating` is derived by the form (bindings ≠ 1). The planner places by binding count, not by
  this flag, except that zero bindings require `floating=True` or the rule errors.
- `source` / `destination`: comma-separated tokens — alias names, interface-group names,
  `any`, `(self)`, `bogons(v6)`, IPs/CIDRs, or logical tokens `@NAME:net` / `@NAME:ip`.
- `source_port` / `destination_port`: one value (port, `a-b` range, well-known name, port alias).
- `protocol`: one value from `choices.protocol_choices()` (legacy comma lists still validate).
- `name` max `RULE_NAME_MAX = DESCRIPTION_MAX = 237` because pushes append ` [om:<12hex>]` (18
  chars) and OPNsense allows 255. Alias/group descriptions share the same limit.
- `Rule.clean()` enforces protocol/port/ICMP/address-family compatibility.

### Renames rewrite references

`Alias.save()` and `InterfaceGroup.save()` detect a name change and rewrite token references in
every `Rule.source/destination` (and ports / nested alias content for aliases) inside the same
transaction, mirroring what OPNsense does on the device. `QuerySet.update(name=...)` bypasses this.

### Identity fields

| Object | Manager identity | Device identity |
| --- | --- | --- |
| Rule | `Rule.id` (UUID) | description ends with `[om:<first 12 hex of id>]` (legacy `[opnmanager:<uuid>]` prefix also recognized); or `RuleOrigin.remote_uuid` before first push |
| Alias | `Alias.uid` | `[om:<12hex of uid>]` at end of description; falls back to same name if untagged |
| InterfaceGroup | `InterfaceGroup.uid` | `[om:...]` at end of `descr`; falls back to same `ifname` |
| Category | `name` | `name` (no tag; categories have no description) |
| VirtualIP | `VirtualIP.pk` | `descr` starts with `[opnmanager-vip:<pk>] ` or `VirtualIPOrigin.remote_uuid` |

Details in [subsystems/planning.md](subsystems/planning.md).

## JSON blobs

### `Snapshot.data` (schema_version 1)

Produced by `OPNsenseClient.snapshot()` or uploaded (`SnapshotImportForm`), always passed through
`reconcile.validate_snapshot()`, which requires `schema_version == 1`, `rules` and `aliases` lists,
optional `interfaces`, `groups`, `categories` lists, scalar-only rows, and converts every value to
a **string** (`True` → `"1"`). Example: `examples/snapshot.json`.

| Key | Row fields (as OPNsense names them) |
| --- | --- |
| `rules` | `uuid`, `description`, `interface` (comma device ids/group names), `sequence`, `action`, `direction`, `ipprotocol`, `protocol`, `source_net`, `source_port`, `destination_net`, `destination_port`, `received-on`, `categories` (comma category **UUIDs**), `enabled`, `log`, `quick`, `statetype`, `gateway`, `icmptype`, `icmp6type`, `*_not`, plus any other device fields |
| `aliases` | `uuid`, `name`, `type`, `content` (newline-separated), `description`, `enabled`, runtime counters |
| `interfaces` | `name` (device id, e.g. `opt2`), `label` (display name) |
| `groups` | `uuid`, `ifname`, `members` (comma device ids), `descr`, `sequence`, `nogroup` |
| `categories` | `uuid`, `name`, `color`, `auto` |

Imported (non-live) snapshots may lack `uuid`s; updates/removals then require a live pull.
Snapshots are immutable observations; only the newest one is used for planning.

### `DeviceInventory.data`

Merged dict, each key written by a different feature (always `{**data, key: ...}`):
`interfaces` (overview rows; `system_management.refresh_inventory`), `protocols` (device
protocol catalog → `choices.protocol_choices()`), `catalog_error`, `firmware`, `vips`
(passwords stripped), `rule_rollback` (`savepoint` | `config_history`; set by deployment).

### `DeviceJob.params`

- `rules.deploy`: `combined` (always True from the UI), `include_definitions`,
  `approval_sha256`, `selected_rules` (rule UUIDs and retire option ids `disable:<uuid>` /
  `delete:<uuid>`), `remove_definitions` (device UUIDs), `accept_warnings`, `allow_unprotected`.
- `definitions.sync`: `approval_sha256`, `rule_id` (optional), `remove_definitions`.
- Old jobs may use `remove_aliases`; `jobs._removals()` reads both.

## Custom permissions

On `Firewall.Meta`: `refresh_firewall`, `manage_credentials`, `sync_definitions`, `deploy_rules`.
On `FirmwareJob.Meta`: `install_firmware`. All pages also need `fleet.view_firewall`.

## Migrations

`fleet/migrations/0001`–`0017`. Notable data migrations:
- `0004` copies `Rule.interface` into `Rule.interfaces`.
- `0013` removes stored authentication-server models (never deployable).
- `0015` converts stored ICMPv6 type numbers to OPNsense option names.
- `0016` / `0017` add `uid` to Alias / InterfaceGroup: add nullable → `RunPython` fill → make
  unique. Use this three-step pattern for any new unique-with-default column.

`fleet/test_features.py::MigrationUpgradeTests` migrates from 0002 to latest with data; keep it
passing. CI runs `makemigrations --check --dry-run`.

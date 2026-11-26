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
Firewall: position (display order, Meta ordering), ipv4_site_prefix, ipv6_site_prefix, dhcp_backend (dnsmasq|kea)
DnsBase (name, kind servers|domains, default) 1─* DnsBaseValue *─1 Firewall (unique per base+firewall)
DnsPreference (name, dns_servers / search_domains token lists, is_default) 1─* DhcpScope.dns_preference (SET_NULL)
InterfaceAddressing 1─1 LogicalInterface (templates ipv4_address / ipv6_address)
AddressRange *─1 LogicalInterface (name, "10.x.10.10-29")
DhcpScope (ScopedPolicy) *─1 LogicalInterface; DhcpOption *─1 DhcpScope (code, kind, value)
StaticReservation(firewall, logical_interface PROTECT, ip, mac, hostname, uid, remote_uuid)
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

- Bindings are `interfaces` + `interface_groups` (origin: `origin_interfaces` +
  `origin_interface_groups`). The former single `interface` FK was removed in migration 0018;
  `bound_interfaces()` is just `interfaces.all()` (empty for an unsaved rule).
- `floating` is derived by the form (bindings ≠ 1). The planner places by binding count, not by
  this flag, except that zero bindings require `floating=True` or the rule errors.
- `source` / `destination`: comma-separated tokens — alias names, interface-group names,
  `any`, `(self)`, `bogons(v6)`, IPs/CIDRs, or logical tokens `@NAME:net` / `@NAME:ip`.
- `source_port` / `destination_port`: one value (port, `a-b` range, well-known name, port alias).
- `protocol`: one value from `choices.protocol_choices()` (legacy comma lists still validate).
- `name` max `RULE_NAME_MAX = DESCRIPTION_MAX = 237` because pushes append ` [om:<12hex>]` (18
  chars) and OPNsense allows 255. Alias/group descriptions share the same limit.
- `Rule.clean()` enforces protocol/port/ICMP/address-family compatibility.

### Natural order of logical interfaces

`LogicalInterface.sort_key` (set in `save()` from `fleet.sorting.natural_key`) is the default
ordering, so every queryset lists `VL49` before `VL100_Parents`, as OPNsense does. Don't add
`order_by("name")` for logical interfaces; it brings back plain text order. `QuerySet.update(name=...)`
leaves the key stale.

### Renames rewrite references

`Alias.save()`, `InterfaceGroup.save()` and `LogicalInterface.save()` detect a name change and
rewrite token references in every `Rule.source/destination` (and ports / nested alias content for
aliases; `@NAME:net` / `@NAME:ip` for logical interfaces) inside the same transaction, mirroring
what OPNsense does on the device. Foreign keys (bindings, mappings, group members) need no rewrite. `QuerySet.update(name=...)` bypasses this.

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
`interfaces` (overview rows incl. `ipv4_mode`/`ipv6_mode`; `system_management.refresh_inventory`), `protocols` (device
protocol catalog → `choices.protocol_choices()`), `catalog_error`, `firmware` (`system_management.firmware_summary`: version, core/plugin updates, installed plugins), `vips`
(passwords stripped), `dhcp` (`dhcp.refresh_dhcp`: backend, leases, reservations, Kea subnets, read_at), `rule_rollback` (`savepoint` | `config_history`; set by deployment).

### `DeviceJob.params`

- `rules.deploy`: `combined` (always True from the UI), `include_definitions`,
  `approval_sha256`, `selected_rules` (rule UUIDs and retire option ids `disable:<uuid>` /
  `delete:<uuid>`), `remove_definitions` (device UUIDs), `accept_warnings`, `allow_unprotected`.
- `definitions.sync`: `approval_sha256`, `rule_id` (optional), `remove_definitions`.
- `dhcp.reservations.sync`: `approval_sha256`, `selected` (reservation uids), `remove` (device UUIDs).
- `interfaces.addresses`: `digest` (from the signed review), `selected` (`<device>:<family>` row ids).
- `vip.apply`: `vip_id`, `digest` (from the signed review). `vip.delete`: `uuid` (device VIP), `digest`.
- Old jobs may use `remove_aliases`; `jobs._removals()` reads both.

## Custom permissions

On `Firewall.Meta`: `refresh_firewall`, `manage_credentials`, `sync_definitions`, `deploy_rules`, `sync_dhcp`, `push_interface_addresses`.
On `FirmwareJob.Meta`: `install_firmware`. All pages also need `fleet.view_firewall`.

## Migrations

`fleet/migrations/0001`–`0025`. Notable data migrations:
- `0004` copies `Rule.interface` into `Rule.interfaces`.
- `0013` removes stored authentication-server models (never deployable).
- `0015` converts stored ICMPv6 type numbers to OPNsense option names.
- `0016` / `0017` add `uid` to Alias / InterfaceGroup: add nullable → `RunPython` fill → make
  unique. Use this three-step pattern for any new unique-with-default column.
- `0018` copies any remaining `Rule.interface` values into `Rule.interfaces`, then drops the column.
- `0019` adds the `vip.apply` / `vip.delete` job kinds (choices only).
- `0021` adds IPAM: firewall site prefixes and DHCP backend, `InterfaceAddressing`, `AddressRange`,
  `DhcpScope`/`DhcpOption`, `StaticReservation`, the `sync_dhcp` permission and the
  `dhcp.reservations.sync` job kind.
- `0022` adds `Firewall.position` (the user-chosen display order) and numbers existing firewalls
  alphabetically, so the order doesn't change on upgrade.
- `0023` adds the `push_interface_addresses` permission and the `interfaces.addresses` job kind.
- `0024` adds per-site DNS (`Firewall.site_dns_servers`, `site_domain`), `DnsPreference` and
  `DhcpScope.dns_preference`.
- `0025` adds `DnsBase`/`DnsBaseValue`, moves 0024's per-site DNS into bases `dns`/`domain`, rewrites
  preference lists to the base syntax, then drops the two firewall fields
  (`test_features.DnsBaseMigrationTests`).

`fleet/test_features.py::MigrationUpgradeTests` migrates from 0002 (and from 0017) to latest with
data; keep it passing. CI runs `makemigrations --check --dry-run`.

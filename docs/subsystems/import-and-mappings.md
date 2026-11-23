# Rule import and interface mappings

Files: `fleet/import_rules.py`, `fleet/mappings.py`, `fleet/interface_views.py`,
`views.adopt_rules`, `views.default_mappings`, `static/logical-interfaces.js`,
`templates/fleet/logical_interfaces.html`. Tests: `test_import.py`, `tests.py`,
`test_logical_interfaces.py`, `test_group_pull.py`.

## Logical interfaces and mappings

A `LogicalInterface` (e.g. `VL10`) is mapped per firewall to a device identifier (`opt2`, not the
display label) by `InterfaceMapping`. Unique constraints: one mapping per (firewall, logical) and
per (firewall, device interface). Mappings are explicit — matching labels never imply sameness
except through the auto-map below.

**Auto-map** (`mappings.mapping_candidates` / `apply_default_mappings`): on pull/import when
`Firewall.auto_map_interfaces` is on, and via the "Add defaults from interface names" button. A
device interface gets a mapping only if its label is unique on the device, is a valid identifier,
matches at most one logical name (case-insensitive), and neither side is already mapped. Creates
missing `LogicalInterface`s. Never overwrites.

**Fleet: Logical Interfaces** (`interface_views.logical_interfaces`): matrix of logical rows ×
firewall columns. Options come from `device_interfaces(fw)` = `DeviceInventory.data["interfaces"]`
(richer: addresses/VLAN/status) merged with the newest snapshot's `interfaces`. Cell inputs are named
`map_<firewall pk>_<logical pk>`. `save_mappings` validates the whole result (no device interface
used twice per firewall, identifier syntax) and then, in one transaction, deletes changed rows
before recreating them so swaps don't hit the unique constraint. Usage counts include rules that
mention `@NAME:` in addresses.

## Importing (adopting) device rules — `import_rules.import_rules`

Input: newest snapshot (older → `ValidationError`), selected row indices, target scope/firewalls/
groups. Runs in `transaction.atomic`; each rule in a nested atomic block; **all problems across the
selection are collected and raised together, and nothing is saved if any rule fails.** The view
shows each message.

Per rule:
- Needs a `uuid`. Already adopted (`RuleOrigin` for this firewall+uuid) → returns the existing rule
  (no duplicate). Carries a manager tag → refused (edit the manager rule instead).
- Any non-default field outside `SUPPORTED | IGNORED` (after dropping `%`-prefixed display labels and
  `alias_meta_*`) → refused, naming the setting via `UNSUPPORTED_LABELS`. Never silently drop
  behavior. `SAFE_DEFAULTS` lists values treated as "unset".
- Description longer than `RULE_NAME_MAX` (237) → refused.
- Bindings: mapped device ids → logical interfaces; device groups → `ensure_group` (all members must
  be mapped; an existing manager group must have identical members); anything else → "not mapped".
- Addresses: device iface `x` → `@LOGICAL:net`, `xip` → `@LOGICAL:ip`; groups/aliases are ensured/
  imported; builtins (`any`, `(self)`, `bogons`, `bogonsv6`), IPs/CIDRs/ranges and existing manager
  aliases pass through; unknown tokens → refused.
- Protocol must be in `protocol_choices()` (device catalog from inventory refresh).
- Aliases are imported recursively (nested first). An existing manager alias with the same name must
  compile to the same content, else conflict. Types other than host/network/port → refused.
- Categories by device UUID → name; created if missing with the import's scope.
- New supporting objects get the same scope/targets as the imported rules.
- Creates `RuleOrigin(firewall, rule, remote_uuid)` so drift matches the device rule before the
  first push adds a tag.

Import never writes to the device.

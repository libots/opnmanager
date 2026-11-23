# Planning (reconciliation)

Files: `fleet/reconcile.py`, `fleet/rule_identity.py`, `fleet/dependencies.py`,
`fleet/alias_patterns.py`, `fleet/snapshot_compare.py`. All are **pure**: they never contact a
device. Tests: `tests.py`, `test_rule_identity.py`, `test_alias_identity.py`,
`test_group_identity.py`, `test_rule_dependencies.py`, `test_targets_patterns.py`,
`test_snapshot_compare.py`.

## `plan_for(firewall, snapshot=None, *, rule_ids=None, definition_names=None, policy=None)`

Returns a dict:

```python
{"firewall", "snapshot_id", "observed_at",
 "errors": [...],      # block: when non-empty, "operations" is emptied
 "warnings": [...],    # never block; deploy review requires ticking a confirmation
 "items": [{"kind", "name", "status", "changes", "desired", "actual"}],
 "operations": [{"kind", "action": "create"|"update", "remote_uuid", "payload"}],
 "read_only": True}
```

- `kind` ∈ `alias`, `group`, `category`, `rule`.
- `status` ∈ `missing`, `changed`, `in_sync`, `conflict` (duplicate identity → error),
  `local_only` (device object with no manager counterpart), `out_of_scope` (device object
  carrying a manager tag that nothing current claims).
- `rule_ids` / `definition_names` narrow planning to one rule and the definitions it needs
  (`dependencies.rule_definitions`), so unrelated problems don't block it. Passing
  `rule_ids=set()` plans definitions only.
- **Always pass a shared `Policy()`** when planning several firewalls or rules in one request.
  `Policy` loads every alias/group/category/rule once with scopes prefetched and caches
  `firewall_state()` (validated snapshot, `{logical name: device id}` mappings, adopted UUIDs).
  `test_deployment.PlannerQueryTests` guards the query count.

### Order of work inside `plan_for`

1. Aliases that apply → compile content (`alias_patterns.compile_content`), reject references to
   aliases excluded from this firewall, detect cycles.
2. Categories that apply.
3. Groups: a group "doesn't exist here" if it doesn't target the firewall or has no mapped
   members (`group_problems`). Such groups are not created (warning) and are dropped from rule
   bindings.
4. Rules, each in its own `try` (a `ValueError` becomes a plan error):
   - short-marker collision across manager rules → error.
   - `_available_bindings`: unmapped interfaces / missing groups are **left out with a warning**;
     if *all* bindings (or all origin bindings) are missing, the rule is **skipped** with a warning
     (an empty list would widen it to every interface).
   - duplicate `(binding, sequence)` within this plan → error.
   - excluded category, excluded alias/group in addresses → error.
   - `resolve_addresses`: `@IF:net` → device id, `@IF:ip` → device id + `ip`. Unmapped tokens are
     left out with a warning; if that empties source/destination, the rule is skipped.
   - payload = `RULE_DEFAULTS` + rule fields; description = `name + " " + [om:...]`;
     categories become device UUIDs, or `@category:Name` if the device lacks the category yet.
5. Match each desired object to device rows (identity rules below), diff via `canonical()`, emit
   operations for `missing`/`changed`.
6. Unmatched device rows → `local_only` / `out_of_scope` items.
7. If any error: `operations = []` (never a partial plan).

## Identity tags (`rule_identity.py`)

- `short_marker(uuid)` → `[om:` + first 12 hex chars of the UUID + `]`. Pushed descriptions are
  `tagged(text, uuid)` = text + space + marker (marker at the **end**).
- `matches(description, id)`: description equals the tag, starts with `tag + " "`, or ends with
  `" " + tag`; both short and legacy `[opnmanager:<uuid>]` forms.
- `is_managed(description)`: any manager tag present (prefix or suffix).
- `marker_of` / `untagged`: read/strip a trailing short tag (used for aliases/groups and import).

Matching per kind:
- **Rules**: by tag, or by `RuleOrigin.remote_uuid` for an imported rule not yet pushed.
- **Aliases/groups** (`_tagged_matches`): by tag first; otherwise a row with the same name whose
  tag isn't owned by a *different* manager object. A tag match with a different name is a rename;
  if the new name is already taken on the device → error.
- **Categories**: by name.

A local device object with the same name as a manager rule is **not** adopted silently; it shows
as `local_only` until imported.

## Comparison: `canonical(row, fields, kind)`

Normalizes only the keys of the desired payload: fills defaults (`RULE_DEFAULTS` for rules),
stringifies, lowercases colors and protocols, sorts/dedupes comma lists (`interface`, `members`,
`categories`, ICMP types, `source_net`, `destination_net`) and alias content lines, maps port
`any` → `""`. Used for plan diffs, readback verification and import conflict checks. If you add a
pushed field, add its default to `RULE_DEFAULTS` and consider whether it needs normalizing.

`snapshot_compare.configuration_changes(before, after)` is a *different*, whole-snapshot comparison
used by preflight: it keeps unknown fields (so unexpected device edits block writes) but drops
known UI annotations (`ANNOTATIONS`), alias PF runtime counters (`RUNTIME_FIELDS`), `alias_meta_*`,
empty values, and equivalent boolean/sequence representations. Never broaden these ignore lists to
"any unknown field".

## Dependencies (`dependencies.rule_definitions`)

For one rule: aliases referenced in addresses/ports (recursively through nested alias content),
groups used as bindings, origin bindings or addresses, and its categories. Drives per-rule planning
in the deploy review and "this rule waits on definitions X".

## Alias patterns (`alias_patterns.py`)

Expands `x`/`*` components, decimal (IPv4) / hex (IPv6) component ranges, bracket ranges inside a
hextet, nibble wildcards, full `a-b` address ranges, and pattern CIDRs (network aliases only). Host
aliases enumerate addresses; network aliases summarize to CIDRs. Hard cap `MAX_ALIAS_ENTRIES = 4096`
with early rejection. Names in `known_aliases` are passed through untouched (an alias named `x` is a
reference, not a wildcard). Port aliases accept `n` or `a:b`. Only compiled output is sent to devices.

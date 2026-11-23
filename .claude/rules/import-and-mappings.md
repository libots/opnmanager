---
paths:
  - "fleet/import_rules.py"
  - "fleet/mappings.py"
  - "fleet/interface_views.py"
---
# Import and mapping rules

Full reference: `docs/subsystems/import-and-mappings.md`.

- Import never writes to a device and is all-or-nothing: collect every problem, raise one
  `ValidationError` listing them, save nothing.
- Never silently drop a device setting the manager can't represent; refuse the rule and name the
  setting (`UNSUPPORTED_LABELS`). `%`-prefixed keys are display labels and are ignored.
- Reuse existing manager definitions only when equivalent; conflicts block the import.
- Auto-mapping never overwrites a mapping and skips ambiguous labels.
- Mapping saves validate the whole result first and delete changed rows before recreating them
  (swaps would otherwise violate the unique constraints).

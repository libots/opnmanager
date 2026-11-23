---
paths:
  - "fleet/reconcile.py"
  - "fleet/rule_identity.py"
  - "fleet/dependencies.py"
  - "fleet/alias_patterns.py"
  - "fleet/snapshot_compare.py"
---
# Planner rules

Full reference: `docs/subsystems/planning.md`.

- Planning is pure: never import `OPNsenseClient` or write to the DB here.
- Plans are hashed into `approval_sha256`. Keep output deterministic (sorted lists, no sets or
  timestamps); any change to plan shape invalidates pending reviews by design.
- Blocking problems go in `plan["errors"]` (this empties `operations`); non-blocking ones go in
  `plan["warnings"]`.
- Missing interfaces/groups/addresses must narrow a rule (drop + warning) or skip it, never widen it.
- Read manager objects only through the shared `Policy` (prefetched). No per-rule queries —
  `fleet.test_deployment.PlannerQueryTests` enforces this.
- Changing `short_marker`, tag placement or matching changes the identity of every deployed object;
  legacy forms must stay recognized.
- `snapshot_compare` ignore-lists are explicit and narrow. Never ignore unknown fields generically.
- New pushed rule field → `RULE_DEFAULTS` + `plan_for` payload (+ import `SUPPORTED`, `RuleForm`,
  `views.rules_page`, `snapshot_compare.DEFAULTS` as applicable).

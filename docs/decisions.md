# Design decisions

Why things are the way they are. Each entry: decision → reason → where it lives. Check here before
"simplifying" one of these; most were deliberate responses to a failure mode.

1. **Desired state in the DB, observed state as immutable snapshots.** Plans are computed purely
   from both; drift reports are only as fresh as the last snapshot. → `reconcile.py`, `Snapshot`.
2. **No unattended writes.** Every device change needs a reviewed plan digest; targeting
   ("All enabled firewalls", groups) changes *desired* state only. No polling, no auto-apply.
3. **Approval digest = hash of the whole plan.** Simple and strict: any change in policy or device
   view between review and execution forces a new review. → `alias_sync.digest`.
4. **Preflight re-read + semantic compare before writing, readback after.** Unknown device fields
   are kept in the comparison so unexpected edits block writes; only known annotations and alias
   runtime counters are ignored. → `snapshot_compare.py`.
5. **Never delete automatically.** Out-of-scope tagged rules are offered for retire (Keep by
   default); tagged aliases/groups are offered for removal; both need explicit selection.
6. **Stable short identity tags** `[om:<12 hex>]` at the *end* of descriptions (rules from
   `Rule.id`, aliases/groups from `uid`). Short to fit OPNsense's 255-char description (hence the
   237 limit); suffix so the human text reads first; legacy prefix forms still recognized. Rule tag
   collisions block deployment rather than guess ownership. Categories match by name (no
   description field). VIPs use their own older `[opnmanager-vip:<pk>]` prefix.
7. **Explicit logical-interface mappings** instead of trusting device labels; auto-map only for
   unique, unambiguous labels and never overwriting.
8. **Missing interfaces narrow, never widen.** Unmapped bindings/groups/addresses are dropped with a
   warning; if that would empty bindings or an address field, the rule is skipped on that firewall.
   Malformed tokens, excluded aliases/categories still block. → `reconcile._available_bindings`,
   `resolve_addresses`.
9. **Placement follows OPNsense MVC semantics:** one binding = interface/group rule, several or none
   = floating. No separate floating checkbox in the editor.
10. **Imports are all-or-nothing and lossless.** Any setting the manager can't represent refuses the
    rule (named), rather than importing a weaker rule.
11. **Device writes run in a separate worker** (`run_jobs`, DB-backed queue) so proxy timeouts or
    Gunicorn restarts can't cut a deploy in half. This covers rule deploys, definition syncs and VIP
    apply/delete; firmware requests stay in the request because they only queue a firewall task.
    No Celery/Redis, to keep the single-host install dependency-free.
12. **One flock per firewall shared by all write workflows**, so one workflow's preflight can't be
    invalidated by another's concurrent write. Single-host scope (shared `DATA_DIR`).
13. **Savepoint-protected rule apply**; on OPNsense 26.7+ (savepoint API removed) fall back to
    configuration-history revert, but only with the operator's explicit "push without automatic
    rollback" consent, remembered per firewall in `DeviceInventory.data["rule_rollback"]`.
14. **Definitions and rules deploy in one review/job**, definitions first; each rule's `intent` is
    re-checked after definitions apply so new category UUIDs don't count as a change.
15. **Django admin is the editor** (restyled), custom views for read/plan/deploy. The rule editor
    mirrors OPNsense's dialog so operators don't relearn it; the rules grid mirrors OPNsense's list.
16. **Local-first deployment:** SQLite, Gunicorn + WhiteNoise, generated keys in `DATA_DIR`,
    bootstrap admin with forced password change. OIDC optional, bound to issuer+subject.
17. **Secrets outside the DB**: Fernet key file separate from the database; credentials and OIDC
    secret write-only in the UI; error messages never include raw exceptions/bodies.
18. **Unsupported OPNsense areas are left alone** rather than written through guessed endpoints:
    DNS search domains (desired-only), authentication servers (removed), CARP VIPs, legacy rules, NAT.

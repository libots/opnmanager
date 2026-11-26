# Device writes: deploys, syncs, rollback, jobs, locks

Files: `fleet/deployment.py`, `fleet/definition_sync.py`, `fleet/alias_sync.py`, `fleet/jobs.py`,
`fleet/locks.py`, `fleet/management/commands/run_jobs.py`, `sync_aliases.py`; VIP writes in
`fleet/system_management.py` (see system-management.md).
Tests: `test_deployment.py`, `test_jobs.py`, `test_group_identity.py`, `test_alias_identity.py`,
`tests.py`, `test_snapshot_compare.py`.

## Shared safety pattern (every write workflow follows it)

1. **Plan + digest.** Build a plan dict; `approval_sha256 = alias_sync.digest(plan)` — SHA-256 of
   the JSON-serialized plan (sorted keys). The review page posts this digest back.
2. **Lock.** `locks.device_write_lock(firewall.pk, "<operation name>")` — non-blocking `flock` on
   `DATA_DIR/.device-write-<pk>.lock`; a second writer gets `DeviceError("<name> is already running…")`.
   Shared by rule deploys, definition/alias syncs, VIP writes and firmware requests.
3. **Re-plan & compare digest** (manager policy unchanged).
4. **Preflight re-read**: `client.snapshot()` and compare to the plan's baseline snapshot
   (rules: `snapshot_compare.configuration_changes`; definitions: `rows_by_identity` fingerprint of
   aliases/groups/categories; alias CLI: alias fingerprint). Any change → abort, no writes.
5. **Re-plan again** after the network read (policy may have changed meanwhile).
6. **Write**, reconfigure/apply.
7. **Readback** via `client.snapshot()`; verify each operation with `canonical()`.
8. **Store** the readback as a new `Snapshot(source="api")`; `AuditEvent`s for
   `*.started` / `*.completed` / `*.failed` (and `rules.deploy.unconfirmed`).

Because the digest covers the entire plan dict, **any change to plan contents or ordering**
(including diff text, warnings, `rollback` mode) invalidates outstanding reviews — that is
intentional. Keep plan output deterministic (sort sets, no timestamps).

## Rule plan: `deployment.deployment_plan(firewall, pending_definitions=None)`

One `plan_for(..., rule_ids={id}, definition_names=rule_definitions(rule))` per targeted rule
(sharing one `Policy`). Each row: `id`, `name`, `operation`, `errors`, `warnings`,
`dependencies` (definition operations the rule needs), `after_definitions`, `intent`, `changes`
(`reconcile.field_changes`: differing fields for an update, meaningful fields for a create).
`definition_plan` adds the same `changes` list to each definition operation.
Then:
- `_check_positions`: blocks a rule whose `(binding, sequence)` collides with another targeted
  manager rule or with an unmatched device-local rule (floating rules share `(floating)`).
- `retire_candidates`: device rules with a manager tag that no *targeted* manager rule matches →
  offered as Keep / `disable:<uuid>` / `delete:<uuid>`. Decided by tag, not plan success, so a rule
  that merely fails to plan is never offered.
- `rollback` = `rollback_mode(firewall)` from `DeviceInventory.data["rule_rollback"]`.

A rule needing definitions is blocked unless `pending_definitions` (from the combined plan) covers
all of them. A rule whose categories are still `@category:Name` with no pending sync is blocked.

## Combined review: `combined_plan` / `execute_combined`

`views.deploy_rules` always uses the combined path. `combined_plan` = `definition_plan` (only if the
user has `fleet.sync_definitions`) + `deployment_plan(pending_definitions=...)`; its digest is over
both sub-digests. `execute_combined`, under one lock:
1. Validate all selections first (rules, removals, warnings ack, unprotected ack).
2. `_execute_definition_plan` if there is anything to sync.
3. `deployment_plan` again; each selected rule must now be unblocked and have the **same `intent`**
   as reviewed (`rule_intent` compares categories by name, so `@category:X` → new UUID still
   matches). Otherwise stop before any rule write, saying definitions were applied.
4. `_execute_deployment` with the fresh plan digest.

**Inner functions are underscore-prefixed and lock-free; public `execute_*` take the lock.** Never
call a public `execute_*` while holding the lock: `flock` locks are per open file description, so
the same process would block itself and get "already running".

## Deploying several firewalls (`views.deploy_all`)

There is no fleet-wide transaction. The all-firewalls page renders one `combined_plan` per enabled
firewall; the POST enqueues an ordinary `rules.deploy` job for each checked firewall with that
firewall's own digest and selections. Each job runs the single-firewall workflow above, so a
failure on one firewall leaves the others untouched (and their jobs still run).

## Rule execution and rollback (`_execute_deployment`)

- Savepoint first: `client.savepoint()` → revision; apply with `apply_rules(revision)` arms
  OPNsense's 60 s auto-rollback; `cancel_rollback(revision)` only after readback passes.
  On write/apply/readback failure → `client.revert(revision)`.
- **OPNsense 26.7+** has no savepoint API (404 → `SavepointUnsupported`). The firewall is
  remembered as `config_history`; the push requires `allow_unprotected` ("Push without automatic
  rollback"). The manager records `latest_config_backup()` before writing and on failure calls
  `revert_config(id)` (restores the whole config, then re-applies the filter). Nothing reverts a
  push that cuts off the manager.
- If confirmation fails → `rules.deploy.unconfirmed` audit and error (OPNsense rolls back itself).
- Retire operations use `delete_rule` / `disable_rule`; readback checks absence / `enabled == "0"`.

## Definition sync (`definition_sync.py`)

`definition_plan(firewall, rule=None)`: operations ordered groups → categories → aliases, aliases
topologically sorted so nested members exist first. With no `rule`, also lists `removals`:
tagged device aliases/groups whose manager object was deleted or no longer applies here. A removal
referenced by any device rule (or alias, for aliases) is listed but blocked. Removals happen only
when explicitly selected; nothing is deleted automatically. Execution saves, deletes selected
removals, `reconfigure_definitions(kinds)`, then verifies readback. Not transactional on the device.

## Alias-only CLI (`alias_sync.py`)

`manage.py sync_aliases <firewall>` prints a dry-run plan with `approval_sha256`;
`--execute --approve <sha>` performs it. Upserts only; never deletes, never touches rules.

## Jobs (`jobs.py`)

- `enqueue(firewall, kind, params, actor)`: refuses a second active job of the same kind for the
  firewall; audits `job.queued`. Kinds: `DeviceJob.RULES_DEPLOY`, `DeviceJob.DEFINITIONS_SYNC`,
  `DeviceJob.VIP_APPLY`, `DeviceJob.VIP_DELETE`, `DeviceJob.DHCP_SYNC` (`HANDLERS` maps kind → function; DHCP reservations: see ipam.md).
- `claim_next()`: atomic `queued → running` via conditional `UPDATE`.
- `run_job(job, client_factory=OPNsenseClient)`: `DeviceError` → `failed` with its message; any other
  exception → `failed` with a generic message (logged). Never re-raises.
- `recover_interrupted()`: worker start marks `running` jobs `interrupted`.
- `run_pending(client_factory)`: drains the queue in-process — used by tests.
- The job page (`templates/fleet/job.html`) meta-refreshes; `views.job_detail` flags a queued job
  older than 15 s as "stalled" (worker probably not running).

Adding a new long-running write: add a `DeviceJob` kind + handler, take the shared lock inside the
handler's workflow, keep the plan/digest/preflight/readback pattern, add a migration for the new
`choices` value.

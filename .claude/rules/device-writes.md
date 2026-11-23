---
paths:
  - "fleet/deployment.py"
  - "fleet/definition_sync.py"
  - "fleet/alias_sync.py"
  - "fleet/jobs.py"
  - "fleet/locks.py"
  - "fleet/management/commands/run_jobs.py"
  - "fleet/management/commands/sync_aliases.py"
---
# Device-write rules

Full reference: `docs/subsystems/device-writes.md`.

Every write keeps this order: digest check → `device_write_lock` → re-plan → preflight
`client.snapshot()` compare (abort with no writes on change) → re-plan → write/apply → readback
verify with `canonical()` → new `Snapshot(source="api")` → `AuditEvent`s (started/completed/failed).

- Public `execute_*` take the lock; `_execute_*` don't. Never call a public one under the lock
  (flock is per open file description; the process would block itself).
- Rule pushes: savepoint → apply(revision) → readback → `cancel_rollback`; on failure `revert`.
  OPNsense 26.7+ (`SavepointUnsupported`): config-history revert, only with `allow_unprotected`.
- Validate every selection before the first write. Never delete anything that wasn't explicitly
  selected. Never auto-retry a failed write.
- Long-running writes run in the `run_jobs` worker via `jobs.enqueue`; a new kind needs a `HANDLERS`
  entry and a migration.
- Tests: `Mock` client with `snapshot.side_effect = [preflight, readback]`; see `docs/testing.md`.

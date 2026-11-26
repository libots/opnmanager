# OPNmanager

Django 5.2 app (Python 3.12, SQLite, no JS build) that holds the intended firewall policy for a
fleet of OPNsense devices, diffs it against pulled device snapshots, and pushes reviewed changes
through the OPNsense MVC API. One Django app: `fleet/`. Project config: `config/`.

## Start every task here — don't explore the whole repo

1. Read `docs/README.md` (index) and only the docs page(s) for the area you're changing.
2. Use the module map below to open the specific files; grep for the function you need.
3. Path-scoped rules in `.claude/rules/` load automatically when you touch matching files.
4. Fall back to broad exploration only if the docs don't cover the area — then update the docs.

Root `README.md` is the operator manual (features, setup, required OPNsense API privileges), not
developer docs; consult it for intended user-facing behavior.

## Module map (details: `docs/architecture.md`)

| Area | Files |
| --- | --- |
| Models / data | `fleet/models.py`, `fleet/migrations/` → `docs/data-model.md` |
| Drift planning (pure) | `fleet/reconcile.py`, `rule_identity.py`, `dependencies.py`, `alias_patterns.py`, `snapshot_compare.py` → `docs/subsystems/planning.md` |
| Device writes | `fleet/deployment.py`, `definition_sync.py`, `alias_sync.py`, `jobs.py`, `locks.py` → `docs/subsystems/device-writes.md` |
| OPNsense HTTP | `fleet/opnsense.py` (only HTTP client), `opnsense_errors.py` → `docs/subsystems/opnsense-client.md` |
| Rule import / mappings | `fleet/import_rules.py`, `mappings.py`, `interface_views.py` → `docs/subsystems/import-and-mappings.md` |
| UI | `config/urls.py`, `fleet/views.py`, `management_views.py`, `admin.py` (editors), `forms.py`, `templates/`, `static/` → `docs/subsystems/ui.md` |
| Firmware / VIPs / DNS | `fleet/system_management.py`, `management_views.py` → `docs/subsystems/system-management.md` |
| Addressing (IPAM / DHCP) | `fleet/ipam.py` (pure), `ipam_checks.py`, `dhcp.py`, `ipam_views.py` → `docs/subsystems/ipam.md` |
| Settings / auth / secrets | `config/settings.py`, `fleet/auth.py`, `credentials.py`, `oidc_storage.py` → `docs/subsystems/auth-and-secrets.md` |
| Tests | `fleet/test_*.py`, `fleet/tests.py` → `docs/testing.md` |

## Commands

Set up once: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt ruff==0.17.6`.
`manage.py` needs `DJANGO_DEBUG=1` (or `OPNMANAGER_LOCAL=1`) or it refuses to start.

```bash
DJANGO_DEBUG=1 .venv/bin/python manage.py test fleet.test_deployment   # one module while iterating
DJANGO_DEBUG=1 .venv/bin/python manage.py test                         # full suite (~30 s)
.venv/bin/ruff format --check . && .venv/bin/ruff check .               # CI style + lint
DJANGO_DEBUG=1 .venv/bin/python manage.py makemigrations --check --dry-run
DJANGO_DEBUG=1 .venv/bin/python manage.py runserver   # dev server; deploys also need:
DJANGO_DEBUG=1 .venv/bin/python manage.py run_jobs    # job worker (rule deploys, definition syncs, VIP changes)
```

CI (`.github/workflows/test.yml`) runs format check, lint, tests and the migration check.

## Invariants (break these and things go wrong — see `docs/pitfalls.md`)

- **No device write without**: reviewed `approval_sha256` match → `device_write_lock` → preflight
  re-read showing no change → write → readback verify → new snapshot + audit events.
- Planning is pure and deterministic; plan dicts are hashed. Errors empty `operations`; use
  `warnings` for non-blocking notes.
- Never delete device objects unless explicitly selected; never auto-retry writes; never disable TLS
  verification; never put secrets or raw device responses in messages, plans or audit details.
- Missing interfaces/addresses narrow or skip a rule on that firewall — never widen it.
- Imports are lossless and all-or-nothing.
- Device identity is the `[om:<12 hex>]` description suffix (rules: `Rule.id`; aliases/groups: `uid`).
- Tests never contact a device; mock `OPNsenseClient` with `unittest.mock.Mock`. They run with a
  temporary `DATA_DIR` (`fleet/testing.py`), and bind test rules with `fleet.testing.make_rule`.

## Conventions

- Ruff: line length 120, double quotes, rules E/F/W/I/B/UP; migrations excluded.
- Keep the UI faithful to OPNsense (labels, field order, behavior, dialog layout). Edit in a dialog
  over the page and refresh in place (`admin.OpnDialogAdmin`, `static/opn-dialog.js`); see `docs/subsystems/ui.md`. Vanilla JS, no new dependencies
  without a strong reason (pinned in `requirements.txt`; vendored assets listed in `THIRD_PARTY.md`).
- Views: `login_required` + `permission_required(..., raise_exception=True)`; POST for changes.
- User-facing messages are complete, actionable sentences that say what was (not) changed.
- Commits: short imperative subject describing the user-visible change; tests and the root
  `README.md` updated in the same commit when behavior changes.
- When you change behavior described in `docs/` or `.claude/rules/`, update those files in the same
  commit. Keep this file short; put details in `docs/`.

# Testing

Django `TestCase` suite in `fleet/` (~270 tests, ~30 s). No real device is ever contacted: the
OPNsense client is replaced with `unittest.mock.Mock`. Passing tests do **not** prove live OPNsense
compatibility.

## Commands (what CI runs — `.github/workflows/test.yml`, Python 3.12, ruff 0.17.6)

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt ruff==0.17.6   # once
.venv/bin/ruff format --check .
.venv/bin/ruff check .
DJANGO_DEBUG=1 .venv/bin/python manage.py test
DJANGO_DEBUG=1 .venv/bin/python manage.py makemigrations --check --dry-run
```

Targeted runs (prefer these while iterating, then run the full suite before committing):

```bash
DJANGO_DEBUG=1 .venv/bin/python manage.py test fleet.test_deployment
DJANGO_DEBUG=1 .venv/bin/python manage.py test fleet.test_deployment.RetireRuleTests
DJANGO_DEBUG=1 .venv/bin/python manage.py test fleet.tests.FleetTests.<test_name>
```

`DJANGO_DEBUG=1` is required (settings refuse to load without a secret key otherwise). Ruff config
is in `pyproject.toml` (line length 120, migrations excluded); run `ruff format .` to fix style.

## Where tests live

| Module | Covers |
| --- | --- |
| `tests.py` | Core planning/drift, targeting, alias sync, permissions, OIDC, local accounts |
| `test_deployment.py` | Rule plan/execute, protected apply & 26.7 fallback, retire, planner query count, snapshot retention, all-firewalls review |
| `test_ipam.py` | Address templates, address plan/DHCP/ranges pages, reservation subnet checks, DHCP read/import/plan/sync (Dnsmasq and Kea) |
| `test_jobs.py` | Enqueue/worker/interrupted jobs, deploy POST → job |
| `test_snapshot_compare.py` | Semantic preflight normalization |
| `test_rule_identity.py`, `test_alias_identity.py`, `test_group_identity.py` | `[om:...]` tags, renames, removals |
| `test_rule_dependencies.py` | Per-rule definition resolution |
| `test_targets_patterns.py` | Alias patterns, firewall-group targeting, "Deploy to" field |
| `test_import.py` | Rule adoption with OPNsense-shaped rows |
| `test_group_pull.py` | Unmapped/excluded interface, group and address handling (warn/skip); JSON pull |
| `test_logical_interfaces.py` | Mapping matrix |
| `test_rule_editor.py`, `test_rule_list.py`, `test_rules_table.py` | Rule dialog, bulk commands/edit, grid JSON/filters |
| `test_system_management.py` | Inventory, firmware, VIPs, OIDC options |
| `test_connection_errors.py` | `OPNsenseClient` error translation (patches `requests`) |
| `test_features.py` | Broad feature tests: default mappings, import, credentials UI, definition sync, rule form; `MigrationUpgradeTests` (TransactionTestCase) |
| `test_admin_deletion.py` | Firewall delete cascade permissions |

Put new tests in the module for the area; create a new `test_<area>.py` for a new area.

## Patterns

- Minimal fixture: `Firewall(name=..., base_url="https://fw.test", credential_prefix="TEST")`,
  a `LogicalInterface` + `InterfaceMapping`, a rule from `make_rule(logical, name=..., sequence=...)`
  (`fleet/testing.py`; binds `Rule.interfaces`), and a `Snapshot` with
  `EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}`
  (always `copy.deepcopy` it).
- Fake device: `client = Mock(ROLLBACK_SECONDS=60)`; set `client.savepoint.return_value`, and
  `client.snapshot.side_effect = [preflight_data, readback_data]` — the first call is the preflight
  re-read (must equal the baseline), the second the readback (must contain the written payload).
  Build readback rows from `plan["rows"][i]["operation"]["payload"]` plus a `uuid`.
- Approvals: get the digest from the same plan function the view uses (`combined_plan(fw)["approval_sha256"]`
  for `/deploy/`, `deployment_plan` for `execute_deployment`).
- Jobs (deploys, definition syncs, VIP apply/delete): POST to the view, assert nothing was written
  yet, then `run_pending(client_factory=lambda fw: client)` and check the returned job's status.
  VIP tests patch `fleet.management_views.OPNsenseClient` for the GET review and pass the same mock
  to `run_pending`.
- Views: `self.client.force_login(user)`; superuser has all perms; for permission tests create a
  user and add specific `Permission`s.
- Settings: `override_settings(DATA_DIR=Path(tmpdir))` for file-writing features (OIDC, keys),
  `override_settings(SNAPSHOT_RETENTION=n)`.
- `SimpleTestCase` for pure functions (patterns, snapshot comparison).

`TEST_RUNNER = "fleet.testing.DataDirTestRunner"` points `settings.DATA_DIR` at a temporary
directory for the whole run, so lock and key files never land in a real data directory
(`tests.TestDataDirectoryTests` guards this). Loading settings still creates `.local-secret` in the
configured data directory when `DJANGO_DEBUG=1`; that file is gitignored. `fleet/testing.py` is
not a test module (the discovery pattern is `test*.py`).

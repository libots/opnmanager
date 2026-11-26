# Architecture

OPNmanager is a single Django project that keeps the **intended** firewall policy for a fleet
of OPNsense devices, compares it to **observed** device snapshots, and writes reviewed changes
to one device at a time through the OPNsense MVC API.

## Core idea: desired state vs observed state

```
 Manager DB (desired)            Device (observed)
 Rule, Alias, InterfaceGroup,    Snapshot.data  <── OPNsenseClient.snapshot() (pull)
 Category, LogicalInterface,                    <── uploaded JSON (import)
 InterfaceMapping, scopes
          │                             │
          └──────► reconcile.plan_for(firewall) ◄┘   pure, read-only
                         │
          items (statuses) + operations (payloads)
                         │
     review page shows plan + approval_sha256 (digest of the plan dict)
                         │
     POST enqueues DeviceJob ──► run_jobs worker ──► execute_* under device_write_lock
                         │
     re-plan & compare digest ─ preflight re-read & semantic compare ─ write ─ apply
                         │
     read back & verify ─ store new Snapshot ─ AuditEvent
```

Nothing writes a device without (1) a human-reviewed plan digest, (2) a fresh device re-read
showing nothing changed since the snapshot, (3) the per-firewall write lock, and
(4) a readback check afterwards. See [subsystems/device-writes.md](subsystems/device-writes.md).

## Process model

- **Web**: Gunicorn (`config.wsgi`), 1 worker × 2 threads in `scripts/run-local.sh`. Views plan,
  render reviews, pull snapshots, and *enqueue* writes. Pulls, inventory refreshes and firmware
  requests (which only queue a task on the firewall) run synchronously in the request.
- **Worker**: `manage.py run_jobs` (`fleet/management/commands/run_jobs.py`). Runs `DeviceJob`s
  (rule deploys, definition syncs, VIP apply/delete) one at a time. Exactly one worker per data
  directory.
  On start it marks leftover `running` jobs `interrupted`.
- **Storage**: SQLite at `DATA_DIR/db.sqlite3`. `DATA_DIR` = `OPNMANAGER_DATA_DIR` or the repo
  root. Lock files, the signing key, the credential key and OIDC settings live there too
  (see [subsystems/auth-and-secrets.md](subsystems/auth-and-secrets.md)).
- No Celery/Redis, no Node build, no external DB. Static files: WhiteNoise.

## Repository layout

```
config/              Django project: settings.py (env-driven), urls.py (all routes), wsgi/asgi
fleet/               The only app. Everything below is in here.
  models.py          All models (see data-model.md)
  reconcile.py       Planner: Policy cache, plan_for(), canonical(), RULE_DEFAULTS, snapshot validation
  rule_identity.py   [om:<12hex>] tags: short_marker, matches, is_managed, tagged/untagged
  dependencies.py    rule_definitions(): aliases/groups/categories one rule needs
  alias_patterns.py  Wildcard/range IP pattern compiler (compile_content, 4096-entry cap)
  snapshot_compare.py Semantic diff used by preflight (ignores annotations/runtime counters)
  deployment.py      Rule push plan, combined (definitions+rules) plan, savepoint/rollback execution
  definition_sync.py Alias/group/category sync plan + removals; execution
  alias_sync.py      Alias-only sync (CLI `sync_aliases`); also home of digest()
  jobs.py            DeviceJob enqueue/claim/run/recover
  locks.py           device_write_lock(): per-firewall flock
  opnsense.py        OPNsenseClient (requests) — the only HTTP client to devices
  opnsense_errors.py DeviceError, SavepointUnsupported
  import_rules.py    Adopt snapshot rules into manager policy (atomic, all-or-nothing)
  mappings.py        Auto-map logical interfaces from unique device labels
  system_management.py Interface inventory, firmware, VIP read/plan and worker-side apply/delete
  ipam.py            Address templates (10.x.40.1/21), ranges, DHCP scope resolution/rendering (pure)
  ipam_checks.py     Overlap warnings across the address plan (site prefixes, subnets, ranges, pools, reservations)
  interface_push.py  Push planned interface addresses (OPNsense 26.7+ assignment API), reviewed job
  dhcp.py            Dnsmasq/Kea leases & reservations: read, reservation plan, sync, import
  ipam_views.py      Addressing pages: address plan, DHCP scopes, ranges, reservations & leases
  views.py           Dashboard, firewall page, pull/import, rules grid, deploy review, jobs
  management_views.py Interfaces overview, firmware, VIPs, DNS, OIDC options, deployment overview
  interface_views.py Fleet: Logical Interfaces matrix and mapping saves
  admin.py           Django admin = the CRUD editors (RuleAdmin hosts the rule dialog + bulk edit)
  forms.py           RuleForm, TargetsFormMixin ("Deploy to"), pickers, import/credential/OIDC forms
  choices.py         ICMP/ICMPv6 types, protocols, well-known ports; protocol_choices()
  rule_filters.py    Server-side rule grid filtering
  credentials.py     Fernet-encrypted API credentials
  auth.py, accounts.py, middleware.py, oidc_storage.py, context.py   Auth
  retention.py       Snapshot pruning (post_save signal wired in apps.py)
  templatetags/icons.py  {% icon "name" %} inlines static/icons/<name>.svg
  management/commands/   bootstrap_admin, run_jobs, plan, sync_aliases, seed_demo
  migrations/        0001–0023
  test_*.py, tests.py    Tests (one module per feature area; see testing.md)
  testing.py         Test runner (temporary DATA_DIR) and make_rule() helper; not a test module
templates/           base.html/sidebar.html shell; fleet/*; admin overrides; registration/*
static/              app.css (theme), rules.js (grid), opn-select.js (pickers), rule-editor.*, icons/
scripts/             setup-local.sh, run-local.sh
examples/snapshot.json  Normalized snapshot import format
```

## Where UI pages come from

- **Read/plan/deploy pages** are plain Django views in `views.py`, `management_views.py`,
  `interface_views.py`, routed in `config/urls.py`.
- **Editing** firewalls, rules, aliases, groups, categories, firewall groups, DNS profiles and
  VIPs happens in **Django admin** (`/admin/fleet/...`) with custom forms from `forms.py` and a
  restyled admin shell. The rule list is the custom grid at `/rules/`; the admin rule
  changelist redirects there and the rule add/change form is framed into it as a modal.
  Details: [subsystems/ui.md](subsystems/ui.md).

## Key flows (entry points)

| Flow | Entry point | Core logic |
| --- | --- | --- |
| Pull snapshot | `views.pull_snapshot` | `OPNsenseClient.snapshot`, `mappings.apply_default_mappings` |
| Drift report | `views.dashboard`, `views.firewall_detail` | `reconcile.plan_for` |
| Review & deploy | `views.deploy_rules` (GET/POST) | `deployment.combined_plan` → job → `deployment.execute_combined` |
| Definitions only | `views.sync_definitions` | `definition_sync.definition_plan` → job → `execute_definition_plan` |
| Alias CLI | `manage.py sync_aliases` | `alias_sync` |
| Import rules | `views.adopt_rules` | `import_rules.import_rules` |
| Map interfaces | `interface_views.save_mappings` | atomic bulk mapping replace |
| VIP apply/delete | `management_views.review_vip` / `delete_vip` (signed review → job) | `system_management.execute_vip_apply` / `execute_vip_delete` |
| Firmware | `management_views.firmware_task` | `system_management.firmware_action` |
| Deploy all firewalls | `views.deploy_all` | one `combined_plan` + job per checked firewall |
| DHCP reservations | `ipam_views.read_dhcp` / `sync_reservations` (job) | `dhcp.refresh_dhcp`, `dhcp.execute_reservation_sync` |

# UI: views, admin editors, frontend

Server-rendered Django templates + small vanilla-JS files. No bundler, no npm, no framework.
Visual language deliberately mirrors OPNsense's default theme and dialogs (labels, field order,
help texts from OPNsense's `dialogFilterRule.xml`).

## Routes (`config/urls.py`)

| URL | View | Notes |
| --- | --- | --- |
| `/` | `views.dashboard` | Fleet overview; one shared `Policy` for all firewalls |
| `/firewalls/<pk>/` | `views.firewall_detail` | Drift items, mappings, snapshot upload |
| `/firewalls/<pk>/pull/` | `views.pull_snapshot` | POST; JSON reply when `Accept: application/json` (bulk pull, `static/pull-firewalls.js`) |
| `/firewalls/<pk>/import/` | `views.import_snapshot` | POST JSON file upload (≤5 MiB) |
| `/firewalls/<pk>/plan/` | `views.download_plan` | `plan_for` as JSON download |
| `/firewalls/<pk>/deploy/` | `views.deploy_rules` | Combined review (GET) / enqueue job (POST) |
| `/fleet/deployment/deploy/` | `views.deploy_all` | Every enabled firewall's combined review; POST enqueues one `rules.deploy` job per checked firewall (fields prefixed `fw<pk>-`) |
| `/firewalls/<pk>/sync/` | `views.sync_definitions` | Definitions-only review / enqueue |
| `/firewalls/<pk>/rules/import/` | `views.adopt_rules` | POST rule adoption |
| `/firewalls/<pk>/credentials/` | `views.firewall_credentials` | Write-only key/secret |
| `/firewalls/<pk>/mappings/defaults/` | `views.default_mappings` | Auto-map from labels |
| `/rules/` (`?firewall=<pk>`) | `views.rules_page` | Rules grid: manager policy, or a firewall's snapshot |
| `/jobs/<pk>/` | `views.job_detail` | Auto-refreshing job status |
| `/fleet/logical-interfaces/…` | `interface_views.*` | Mapping matrix, save, create |
| `/fleet/deployment/` | `management_views.deployment_overview` | |
| `/interfaces/`, `/interfaces/refresh/` | `management_views.interfaces`, `read_interfaces` | Interface inventory |
| `/interfaces/virtual-ips/…` | `management_views.*vip*` | Apply/delete POSTs enqueue jobs; see system-management.md |
| `/system/firmware/…` | `management_views.firmware*` | |
| `/system/settings/general/` | `management_views.dns_general` | |
| `/settings/`, `/settings/authentication/` | `views.settings_page`, `management_views.oidc_options` | |
| `/admin/` | Django admin | CRUD editors (below) |
| `/accounts/…`, `/oidc/…` | auth | `/oidc/` only when OIDC is enabled at startup |

Every view is `@login_required` + `@permission_required(..., raise_exception=True)` (at least
`fleet.view_firewall`); state-changing views are `@require_POST` or check `request.method`.
`fleet.middleware.InitialPasswordMiddleware` forces a password change first when flagged.

## Editors are Django admin (`fleet/admin.py`)

Firewall (with mapping and firewall-group inlines; mapping choices from the device), Rule, Alias,
Category, InterfaceGroup, FirewallGroup, LogicalInterface, InterfaceMapping, DNSProfile, VirtualIP.
Snapshot and AuditEvent are registered read-only. Scoped models use forms with a single "Deploy to"
field (`forms.TargetsFormMixin`). `templates/admin/base_site.html` wraps admin in the app shell
(`static/admin-shell.css`).

### Rule dialog and rules grid

- `/admin/fleet/rule/` changelist redirects to `/rules/` (except popups).
- `rules.js` opens `/admin/fleet/rule/<id>/change/?_modal=1`, `/add/?clone=<id>` and the bulk-edit
  page in an `<iframe>` dialog. With `_modal`, `RuleAdmin.framed()` relaxes `X-Frame-Options` to
  `SAMEORIGIN` (global default is `DENY`) and successful saves render
  `admin/fleet/rule/modal_done.html`, which `postMessage`s the parent (same origin) to close and
  refresh. `rule-editor.js` posts `{type: 'opn-rule-dialog', close: true}` on cancel.
- After a save/command the grid re-fetches `/rules/` with `Accept: application/json`
  (`views.rules_page` returns `rules_data`) instead of reloading.
- Bulk toggles (enable/disable/log/nolog/delete): `POST /admin/fleet/rule/bulk/`
  (`RuleAdmin.bulk_action_view`). Multi-rule edit: `/admin/fleet/rule/bulk-edit/?ids=…`
  (`_bulk_edit`): differing fields start greyed; only fields listed in `_changed` are applied; every
  rule is re-validated through `RuleForm` via `bulk_rule_forms` and nothing saves unless all pass.
- `RuleForm` represents bindings as `interface:<pk>` / `group:<pk>` choices in `bindings` and
  `origin_bindings`, derives `floating`, and validates addresses
  against aliases, groups, `@IF:net|ip` tokens, builtins and IP networks.
- Clone: `RuleAdmin.get_changeform_initial_data` copies via `rule_form_data` / `rule_form_initial`
  and picks the next free sequence.
- `rules_page` builds display rows server-side (placement, section labels, OPNsense-style address
  labels, category badges); `rule_filters.filter_rows` applies the interface/placement/category/
  enabled/text filters. Snapshot mode keys rows by `index` (for import); manager mode by `id`.

Grid layout prefs, the sidebar collapse state, and rule-editor switches are kept in
`localStorage` by the JS files.

## Frontend files

| File | Loaded by | Purpose |
| --- | --- | --- |
| `static/app.css` | `shell_head.html` (all pages) | Theme (OPNsense colors, Source Sans 3 fonts in `static/fonts/`) |
| `static/ui.js` | `shell_head.html` | Sidebar fold/collapse, All/none checkbox toggles |
| `static/opn-select.js` | `forms.TokenWidget.Media` | Picker widgets; `data-selector` = `picker`/`tags`/`net`/`port`/`manual` |
| `static/rules.js` | `fleet/rules.html` | Rules grid: columns, filters, inspect/tree, CSV, dialog, bulk |
| `static/rule-editor.js` / `.css` | `admin/fleet/rule/change_form.html` | Dialog behavior (advanced/help switches, protocol-dependent fields, bulk greyed fields) |
| `static/logical-interfaces.js` | `fleet/logical_interfaces.html` | Mapping matrix edits, conflict highlighting, fill by name |
| `static/deploy.js` | `deploy.html`, `deploy_all.html` | Per-firewall and total selection counts; disables Deploy when nothing is selected |
| `static/pull-firewalls.js` | `dashboard.html`, `deployment_overview.html` | Per-row and "pull all" (2 concurrent) via JSON |
| `static/admin-shell.css` | `admin/base_site.html` | Admin restyle |

Icons: `{% load icons %}{% icon "name" "css-class" %}` inlines `static/icons/<name>.svg`
(Font Awesome Free, vendored; unknown names raise `TemplateSyntaxError`). Icons used by `rules.js`
must be listed in `views.RULE_ICONS` (rendered into a `<template>` for the script). Add new SVGs to
`static/icons/` and keep `THIRD_PARTY.md` accurate.

Deploy reviews: `views.deploy_review()` sorts a `combined_plan` into `definition_ops`, `changing`
rules, `removals`, `retire`, `blocked` and folded `unchanged`/`notes`, and adds OPNsense field
labels (`views.FIELD_LABELS`). Both review pages render it with `partials/deploy_review.html`; the
change tables come from `changes` lists in the plan (`reconcile.field_changes`), not from a diff.

Templates: `base.html` + `sidebar.html` + `shell_head.html` form the shell;
`templates/fleet/*.html` map 1:1 to views; `partials/` holds pull buttons and the rule row.

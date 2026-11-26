# UI: views, admin editors, frontend

Server-rendered Django templates + small vanilla-JS files. No bundler, no npm, no framework.
Visual language deliberately mirrors OPNsense's default theme and dialogs (labels, field order,
help texts from OPNsense's `dialogFilterRule.xml`).

## Routes (`config/urls.py`)

| URL | View | Notes |
| --- | --- | --- |
| `/` | `views.dashboard` | Fleet overview; one shared `Policy` for all firewalls |
| `/firewalls/<pk>/` | `views.firewall_detail` | Drift items, mappings, snapshot upload |
| `/firewalls/<pk>/pull/` | `views.pull_snapshot` | POST; snapshot, auto-mappings, then `refresh_inventory` (failure reported as `inventory_error`, pull kept); JSON reply when `Accept: application/json` (bulk pull, `static/pull-firewalls.js`) |
| `/firewalls/<pk>/import/` | `views.import_snapshot` | POST JSON file upload (≤5 MiB) |
| `/firewalls/<pk>/plan/` | `views.download_plan` | `plan_for` as JSON download |
| `/firewalls/order/` | `views.reorder_firewalls` | POST `order` = every firewall id in the new order (drag on the overview); 409 if the list changed |
| `/ipam/<pk>/push/` | `ipam_views.push_addresses` | Review planned interface addresses against the firewall (GET reads the device) / enqueue `interfaces.addresses` (POST, signed review) |
| `/ipam/ula-vips/` | `ipam_views.create_ula_vips` | POST `target=<fw>:<li>`: define ULA virtual IPs for Identity association interfaces |
| `/ipam/dns/` | `ipam_views.dns_order` | Site DNS servers/domains and DNS preference lists resolved per firewall |
| `/ipam/subnet-info/` | `ipam_views.subnet_info` | JSON hint `lines` and overlap `warnings` for an address field (`kind`, `value`, optional `interface`, `firewall`, `self`) |
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
| `/ipam/`, `/ipam/dhcp/`, `/ipam/ranges/`, `/ipam/reservations/` | `ipam_views.*` | Addressing matrices and reservations; `…/<pk>/read/` (POST), `…/<pk>/import/` (POST), `…/<pk>/sync/` (review / enqueue); see ipam.md |
| `/settings/`, `/settings/authentication/` | `views.settings_page`, `management_views.oidc_options` | |
| `/admin/` | Django admin | CRUD editors (below) |
| `/accounts/…`, `/oidc/…` | auth | `/oidc/` only when OIDC is enabled at startup |

Every view is `@login_required` + `@permission_required(..., raise_exception=True)` (at least
`fleet.view_firewall`); state-changing views are `@require_POST` or check `request.method`.
`fleet.middleware.InitialPasswordMiddleware` forces a password change first when flagged.

## Editors are Django admin (`fleet/admin.py`)

Firewall (with mapping and firewall-group inlines; mapping choices from the device), Rule, Alias,
Category, InterfaceGroup, FirewallGroup, LogicalInterface, InterfaceMapping, DNSProfile, VirtualIP,
InterfaceAddressing, AddressRange, DhcpScope (with DhcpOption inline), StaticReservation (the IPAM
editors return to their Addressing page, or to a safe `?next=`).
Snapshot and AuditEvent are registered read-only. Scoped models use forms with a single "Deploy to"
field (`forms.TargetsFormMixin`). `templates/admin/base_site.html` wraps admin in the app shell
(`static/admin-shell.css`).

### Editing from a page: dialogs, not navigation

Pages that list things edit them **in a dialog over the page** and refresh in place, as OPNsense
does; they don't send you off to a separate admin page. Two implementations:

- **Generic (`admin.OpnDialogAdmin`)**: used by Firewall, InterfaceAddressing, AddressRange, DhcpScope,
  StaticReservation. The page includes `templates/fleet/partials/opn_dialog.html` (a `<dialog>` with
  an iframe, a status line and `static/opn-dialog.js`) and marks links with `data-dialog`
  (`data-dialog="small"` for short forms; the dialog then takes the form's height). The editor opens
  with `?_modal=1`; `OpnDialogAdmin.framed()` relaxes `X-Frame-Options` to `SAMEORIGIN` for that
  request only. Saving renders `admin/opn_modal_done.html`, which `postMessage`s
  `{type: 'opn-dialog', done, message}`; the page re-fetches itself and swaps every element with
  `data-refresh` and an `id`. The swap keeps the window scroll, the scroll position of scrolling
  boxes inside a region (`.li-scroll`, `.table-scroll`, `[data-keep-scroll]`, matched by position) and
  which `<details>` were open, so the page updates in place; toggles and filters outside the
  regions are untouched. Cancel/Escape post
  `{type: 'opn-dialog', close: true}`. `?_section=<key>` (from `OpnDialogAdmin.sections`) shows a
  single fieldset and no inlines (e.g. the firewall's **Addressing and DHCP** for "Edit site
  prefixes"); only that fieldset's fields are in the form, so only they are saved. Outside a dialog,
  saving returns to a safe `?next=` or the admin's `return_view`.
- **Rules grid**: the older, rule-specific version described below (`RuleAdmin`, message type
  `opn-rule-dialog`, JSON re-fetch).

### OPNsense dialog layout for editors

Editors follow OPNsense's dialog layout: a head with the title, a **full help** switch and (in a
dialog) a close button; collapsible section header rows; rows of *info icon + label | control*, with
help text behind the icon (or all of it with full help); inline tables as further sections; a footer
with secondary links (History, Delete) left and Cancel / Save right. `OpnDialogAdmin` uses
`templates/admin/opn_change_form.html` + `static/opn-form.css` / `opn-form.js` for this; the rule
editor (`admin/fleet/rule/change_form.html`, `rule-editor.css`) is the original. Name fieldsets after
OPNsense's sections ("General settings", …) and use OPNsense's field labels (`labels` on the admin).
New or reworked editors should use `OpnDialogAdmin` rather than Django's default change form.

### Address fields: hints and calculator

`OpnDialogAdmin.address_fields = {field: (kind, context_fields)}` marks address inputs
(`data-subnet-hint`). `static/subnet-tools.js` puts a live hint under each (debounced fetch of
`/ipam/subnet-info/`, computed by `ipam.hint_lines` so it matches what saving will accept) and, for
`prefix`, `interface` and `template` kinds, a calculator button. The calculator is client-side
(BigInt, IPv4/IPv6): network, mask, wildcard, usable range, hosts, broadcast, and a split table;
**Use this network** writes back except on templates. Kinds: `prefix` (site prefixes), `interface`
(VIP address/prefix), `template` (interface plans, per site), `range` (ranges and DHCP ranges,
needs `logical_interface`), `address` (reservations, needs `logical_interface` and `firewall`).

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
| `static/opn-dialog.js` | pages including `partials/opn_dialog.html` | Opens `data-dialog` links in the editor dialog; refreshes `data-refresh` regions after a save |
| `static/opn-form.js` / `opn-form.css` | `admin/opn_change_form.html` | OPNsense dialog layout for `OpnDialogAdmin` editors: help icons, full-help switch, dialog close |
| `static/subnet-tools.js` | `admin/opn_change_form.html` | Address field hints and the subnet calculator |
| `static/firewall-order.js` | `dashboard.html` | Drag (or arrow keys on the handle) to reorder firewalls; saves via `/firewalls/order/` |
| `static/ipam.js` | `ipam_plan.html`, `ipam_dhcp.html` | Remembered show/hide toggles (`data-toggle-target`, `-class`, `-key`): interfaces without a plan / scope |
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

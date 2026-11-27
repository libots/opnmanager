# Pitfalls and non-obvious details

Short, verified list. Each item names where it bites.

## Planning and identity
- **Plan output is hashed.** Adding a field, reordering a list, or putting a set/timestamp into any
  plan dict changes `approval_sha256` and can make it non-deterministic → every deploy fails with
  "plan changed". Sort collections; keep plans pure. (`deployment.py`, `definition_sync.py`)
- **`plan["operations"]` is emptied whenever `plan["errors"]` is non-empty.** Use `warnings` for
  non-blocking messages; the deploy UI requires `accept_warnings` for rows with warnings.
- **Use one `Policy()` per request** and pass `policy=` to `plan_for`. Querying inside the per-rule
  loop breaks `PlannerQueryTests` (query count must not grow with rule count). Prefetch any new
  relation in `Policy.__init__` and read via `.all()`.
- **Every snapshot value is a string** after `validate_snapshot` (`"1"`/`"0"`, `"100"`). Compare
  with strings; booleans/ints in payloads must be `str(int(...))`.
- **Categories in device rule rows are UUIDs**, manager categories are names. Unknown-on-device
  categories appear as `@category:Name` placeholders that block standalone rule pushes.
- **`@IF:ip` resolves to `<device id>ip`** (e.g. `opt2ip`) — OPNsense's own token form; import does
  the reverse mapping.
- **Tag matching for aliases/groups falls back to name** only when the device row's tag isn't owned
  by another manager object. Changing `short_marker` or tag placement changes identity for every
  deployed object.
- **Renames go through `save()`** (`Alias`, `InterfaceGroup`, `LogicalInterface`) to rewrite references; `QuerySet.update`
  skips it.
- Adding a pushed rule field: add it to `reconcile.RULE_DEFAULTS` (and `plan_for` payload, import
  `SUPPORTED`, `views.rules_page` rows, `RuleForm`/admin fieldsets, `snapshot_compare.DEFAULTS` if
  OPNsense has a default). Otherwise existing devices show drift or imports reject the field.

## Device writes
- **Don't nest the write lock.** Public `execute_*` acquire `device_write_lock`; inner `_execute_*`
  don't. `flock` is per open file description, so re-acquiring in the same process fails with
  "already running".
- **`client.snapshot()` call order matters in tests and code:** preflight read first, readback last.
- **Write POSTs default to `write=True`** (adds "state uncertain" to errors). Read-only POST endpoints
  must pass `write=False`.
- **OPNsense 26.7+ has no savepoint.** Code paths must handle `SavepointUnsupported` and the
  `allow_unprotected` gate; `rollback_mode` is cached in `DeviceInventory.data["rule_rollback"]`.
- **Alias/group reconfigure and rule apply reload the whole filter** on the device; nothing is
  transactional. Never auto-retry writes.
- **Jobs need the worker.** In dev, POSTing a deploy, definition sync or VIP apply/delete only
  queues it; run
  `DJANGO_DEBUG=1 .venv/bin/python manage.py run_jobs` (or `--once`). Tests use `run_pending`.
- A new `DeviceJob` kind needs a `HANDLERS` entry and a migration (choices change).

## Django / settings
- **`manage.py` refuses to start without `DJANGO_DEBUG=1` or `OPNMANAGER_LOCAL=1`** (or a secret).
- **OIDC settings are read at import time** in `config/settings.py`; changing them needs a restart, and
  `/oidc/` URLs exist only if enabled at startup. Tests exercise `SubjectOIDCBackend` directly under
  `override_settings`. A broken `.oidc-settings.json` stops startup.
- **`X_FRAME_OPTIONS = "DENY"` globally**; only `RuleAdmin.framed()` and `OpnDialogAdmin.framed()`
  (with `?_modal=1`) allow `SAMEORIGIN`. A new framed page needs the same treatment.
- **The dialog frame also loads `about:blank` (on close) and the save page.** Code reacting to the
  frame's `load` must ignore those (no form, dialog closed), or state such as a fitted height leaks
  into the next dialog (`static/opn-dialog.js`).
- **Dialog refreshes swap elements by `id`.** A region marked `data-refresh` without an `id`, or
  whose `id` differs between renders, is silently not refreshed (`static/opn-dialog.js`).
- **Most editing is in Django admin**, not `views.py`. Look in `admin.py` + `forms.py` first for
  editor behavior.
- **`DATA_DIR` defaults to the repo root**; dev runs drop `db.sqlite3`, `.local-secret` and lock
  files there (gitignored). Tests use a temporary `DATA_DIR`; read `settings.DATA_DIR` at call time
  (as `locks.lock_path` does), never at import time, or tests will write to the real directory.
- Custom permission checks are per view decorator; when adding a view, copy the decorator stack of a
  similar view (`login_required` + `permission_required(..., raise_exception=True)` + `require_POST`).

- **Firewalls have a user-chosen order** (`Firewall.position`, the model's default ordering). Don't
  `order_by("name")` when listing firewalls; use `Firewall.objects.all()`.

## Frontend
- Icons used by `rules.js` must be listed in `views.RULE_ICONS`; `{% icon %}` raises on unknown names.
- `opn-select.js` is loaded through widget `Media` (`forms.TokenWidget`), so templates rendering
  those forms must output `{{ form.media }}` / admin media.
- The rules grid gets its data from `rules_data` JSON (embedded with `json_script`, and re-fetched with
  `Accept: application/json`). Filtering exists twice — server-side `rule_filters.filter_rows` and
  `matches()` in `rules.js` — keep them in agreement.

## Docs
- The root `README.md` is the operator manual and lists required OPNsense API privileges. Update it
  for user-visible behavior or new endpoints (past feature commits did).

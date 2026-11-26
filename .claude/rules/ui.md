---
paths:
  - "fleet/views.py"
  - "fleet/admin.py"
  - "fleet/forms.py"
  - "fleet/interface_views.py"
  - "fleet/rule_filters.py"
  - "fleet/templatetags/**"
  - "templates/**"
  - "static/**"
  - "config/urls.py"
---
# UI rules

Full reference: `docs/subsystems/ui.md`.

- Editors are Django admin (`admin.py` + `forms.py`); `views.py` etc. are read/plan/deploy pages.
- Every view: `@login_required` + `@permission_required((..."fleet.view_firewall"...), raise_exception=True)`;
  state changes are POST-only. Device writes are enqueued as jobs, not run in the view.
- Follow OPNsense's UI: labels, field order and help texts of the rule dialog come from
  `dialogFilterRule.xml`; keep the look consistent with `static/app.css`.
- Vanilla JS only, no build step; wrap `localStorage` access in try/catch like existing files.
- Icons: add SVGs to `static/icons/` (Font Awesome Free; keep `THIRD_PARTY.md` accurate); icons used by
  `rules.js` must be in `views.RULE_ICONS`.
- Edit from the page you're on: open editors in a dialog (`data-dialog` links +
  `partials/opn_dialog.html`, editor = `admin.OpnDialogAdmin`) and refresh the page in place
  (`data-refresh` regions). Don't link out to a standalone admin page from a list or matrix.
- Editors follow OPNsense's dialog layout (sections, info icon + label | control, Cancel/Save):
  subclass `OpnDialogAdmin` (`admin/opn_change_form.html`) for new or reworked editors.
- Framing is denied globally; only `RuleAdmin` and `OpnDialogAdmin` with `?_modal=1` allow
  same-origin framing.
- Rule grid filters exist server-side (`rule_filters.py`) and client-side (`rules.js`); change both.
- Scoped-model forms use `TargetsFormMixin` ("Deploy to"); keep accepting legacy scope fields.
- User-visible behavior changes: update the root `README.md`.

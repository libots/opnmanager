---
paths:
  - "fleet/models.py"
  - "fleet/migrations/**"
---
# Model and migration rules

Full reference: `docs/data-model.md`.

- Generate migrations with `DJANGO_DEBUG=1 .venv/bin/python manage.py makemigrations fleet`; CI runs
  `makemigrations --check --dry-run`. Ruff excludes `fleet/migrations`.
- Migrations must preserve existing data (operators upgrade in place with `setup-local.sh`). New
  unique column with a default: add nullable → `RunPython` fill → alter to unique (see 0016/0017).
  Keep `fleet.test_features.MigrationUpgradeTests` passing.
- Scoped models inherit `ScopedPolicy`; read targeting via `applies_to()`, and prefetch
  `ScopedPolicy.SCOPE_PREFETCH` when evaluating many objects.
- `Rule.interface` is legacy; use `bound_interfaces()`. Rule/alias/group descriptions are capped at
  `DESCRIPTION_MAX` (237) because pushes append an 18-char `[om:...]` tag.
- `Alias.save()` / `InterfaceGroup.save()` rewrite name references on rename; don't bypass with `update()`.
- New permissions go in a model `Meta.permissions` (most live on `Firewall`).

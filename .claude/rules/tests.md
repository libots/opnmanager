---
paths:
  - "fleet/test*.py"
  - "fleet/tests.py"
---
# Test rules

Full reference: `docs/testing.md`.

- Run a single module while iterating: `DJANGO_DEBUG=1 .venv/bin/python manage.py test fleet.test_<area>`;
  run the full suite plus `ruff format --check .` and `ruff check .` before committing.
- Never contact a device: use `unittest.mock.Mock` for the client (`snapshot.side_effect =
  [preflight, readback]`) or patch `requests`.
- Start from `EMPTY` snapshot dicts with `copy.deepcopy`; take approval digests from the same plan
  function the code path verifies against.
- Put tests in the existing module for the area (see table in `docs/testing.md`).
- Do not skip or weaken existing tests to make a change pass.

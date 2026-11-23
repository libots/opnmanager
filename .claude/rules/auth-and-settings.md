---
paths:
  - "config/**"
  - "fleet/auth.py"
  - "fleet/accounts.py"
  - "fleet/middleware.py"
  - "fleet/oidc_storage.py"
  - "fleet/context.py"
  - "fleet/management/commands/bootstrap_admin.py"
---
# Auth and settings rules

Full reference: `docs/subsystems/auth-and-secrets.md`.

- Settings come from environment variables only (no dotenv). Production without
  `DJANGO_SECRET_KEY` must keep failing unless `DJANGO_DEBUG=1` or `OPNMANAGER_LOCAL=1`.
- OIDC accounts bind to issuer + subject; never link or authorize by email; never grant privileges
  from provider claims. Keep all token checks in `SubjectOIDCBackend`.
- OIDC config is loaded at startup from `DATA_DIR/.oidc-settings.json` (UI) over env; changes need a
  restart. Secrets are Fernet-encrypted with the credential key and write-only in forms.
- Files written to `DATA_DIR` are created 0600; keys stay out of the database.
- `bootstrap_admin` must never reset or promote an existing account.

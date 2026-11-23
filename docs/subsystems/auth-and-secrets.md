# Settings, authentication, permissions and secrets

Files: `config/settings.py`, `fleet/auth.py`, `fleet/accounts.py`, `fleet/middleware.py`,
`fleet/oidc_storage.py`, `fleet/credentials.py`, `fleet/context.py`,
`fleet/management/commands/bootstrap_admin.py`. Tests: `tests.py` (`OIDCTests`,
`LocalAccountTests`), `test_features.py`, `test_system_management.py`.

## Environment (read in `config/settings.py`; no dotenv loading)

| Variable | Effect |
| --- | --- |
| `DJANGO_DEBUG=1` | Debug; also allows the generated signing key and disables HTTPS-only defaults |
| `OPNMANAGER_LOCAL=1` | Local server mode: generated signing key, HTTP allowed |
| `DJANGO_SECRET_KEY` | Required unless DEBUG or LOCAL (`ImproperlyConfigured` otherwise) |
| `OPNMANAGER_DATA_DIR` | Where DB, keys, locks and OIDC settings live (default: repo root) |
| `OPNMANAGER_SNAPSHOT_RETENTION` | Snapshots kept per firewall (default 50, `0` = all) |
| `OPNMANAGER_HTTPS` | Secure cookies + SSL redirect (default on unless DEBUG/LOCAL) |
| `DJANGO_TRUST_PROXY=1` | Trust `X-Forwarded-Proto` |
| `DJANGO_ALLOWED_HOSTS`, `OPNMANAGER_BIND`, `OPNMANAGER_STATIC_ROOT` | Usual meanings |
| `OPNMANAGER_CREDENTIAL_KEY` | Fernet key; else `DATA_DIR/.credentials-key` is generated |
| `OIDC_ENABLED`, `OIDC_*` | OIDC provider; overridden by saved UI settings |
| `<PREFIX>_API_KEY` / `_API_SECRET` | Per-firewall env credentials (`Firewall.credential_prefix`) |

**Any `manage.py` command needs `DJANGO_DEBUG=1` or `OPNMANAGER_LOCAL=1`** (or a secret key).

## Files in `DATA_DIR` (all gitignored)

`db.sqlite3`, `.local-secret` (signing key), `.credentials-key` (Fernet), `.oidc-settings.json`
(+ transient `.oidc-write-*`), `.device-write-<pk>.lock`. Created owner-only (0600) where the code
creates them. Local runs create these in the repo root by default; test runs use a temporary
directory instead (`fleet.testing.DataDirTestRunner`, set as `TEST_RUNNER`).

## Local accounts

`bootstrap_admin` creates `admin` with a random password printed once, only if no active
superuser exists; never resets anything. `LocalAccountState.must_change_password` +
`InitialPasswordMiddleware` force a password change before any other page.

## OIDC (`fleet/auth.py: SubjectOIDCBackend`)

mozilla-django-oidc with stricter checks: issuer, audience, `azp`, `exp`/`iat`/`nbf`, userinfo `sub`
must equal token `sub`, `email_verified is True`. Username = `oidc_` + sha256(issuer + NUL + sub) —
accounts bind to issuer+subject, never to email, and new users get no permissions and an unusable
password. PKCE S256, RS256 only.

OIDC configuration is decided **at startup**: settings.py imports `oidc_storage.load(DATA_DIR)`
(the superuser-only UI at `/settings/authentication/` writes `.oidc-settings.json` atomically, with
the client secret Fernet-encrypted by the credential key); UI values win over env. The `/oidc/`
routes and the auth backend exist only if enabled at startup — **a restart is required** after
changes. A corrupt file/key raises `ImproperlyConfigured` at startup.

## Permissions

Django model permissions plus custom ones (see [data-model.md](../data-model.md#custom-permissions)).
Every page needs `fleet.view_firewall`. Key gates: pull/import/inventory → `refresh_firewall`;
deploy review → `deploy_rules` (definition part only with `sync_definitions`); credentials →
`manage_credentials` + `change_firewall`; firmware update → `install_firmware`; OIDC options →
superuser; rule import → add perms on rule/alias/category/interfacegroup. Permissions are
fleet-wide (single organization, not multi-tenant).

## Firewall API credentials (`credentials.py`)

UI-entered key/secret are Fernet-encrypted into `Firewall.encrypted_api_key/_secret`
(`editable=False`, never rendered). Form fields are write-only; blank keeps existing values;
"clear" falls back to env vars. A missing or wrong key → `DeviceError` asking to restore it.
Credential values must never appear in snapshots, plans, audit details, admin change messages or
error text (`sensitive_post_parameters` on the views).

import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
from django.core.management.utils import get_random_secret_key

BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = os.getenv("DJANGO_DEBUG", "0") == "1"
LOCAL_SERVER = os.getenv("OPNMANAGER_LOCAL", "0") == "1"
DATA_DIR = Path(os.getenv("OPNMANAGER_DATA_DIR", str(BASE_DIR))).expanduser().resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if not (DEBUG or LOCAL_SERVER):
        raise ImproperlyConfigured("Set DJANGO_SECRET_KEY, OPNMANAGER_LOCAL=1 for a local server, or DJANGO_DEBUG=1 for development.")
    keyfile = DATA_DIR / ".local-secret"
    if not keyfile.exists():
        try:
            with open(keyfile, "x", opener=lambda p, f: os.open(p, f, 0o600)) as f:
                f.write(get_random_secret_key())
        except FileExistsError:
            pass
    SECRET_KEY = keyfile.read_text().strip()
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
INSTALLED_APPS = ["django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "mozilla_django_oidc", "fleet"]
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware", "whitenoise.middleware.WhiteNoiseMiddleware", "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware", "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware", "fleet.middleware.InitialPasswordMiddleware", "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware"]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True, "OPTIONS": {"context_processors": ["django.template.context_processors.request",
    "django.contrib.auth.context_processors.auth", "django.contrib.messages.context_processors.messages",
    "fleet.context.auth_options"]}}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": DATA_DIR / "db.sqlite3", "OPTIONS": {"timeout": 20}}}
AUTH_PASSWORD_VALIDATORS = [{"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"}]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = Path(os.getenv("OPNMANAGER_STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STORAGES = {"default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"
SESSION_COOKIE_HTTPONLY = True
HTTPS_ONLY = os.getenv("OPNMANAGER_HTTPS", "0" if DEBUG or LOCAL_SERVER else "1") == "1"
SESSION_COOKIE_SECURE = HTTPS_ONLY
CSRF_COOKIE_SECURE = HTTPS_ONLY
SECURE_SSL_REDIRECT = HTTPS_ONLY
if os.getenv("DJANGO_TRUST_PROXY", "0") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
from fleet.oidc_storage import load as load_oidc_configuration
try: _oidc_ui = load_oidc_configuration(DATA_DIR)
except (ValueError,OSError) as exc: raise ImproperlyConfigured('Saved OIDC settings cannot be loaded; restore their configuration/encryption key.') from exc
OIDC_ENABLED = _oidc_ui.get('OIDC_ENABLED', os.getenv("OIDC_ENABLED", "0") == "1")
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
if OIDC_ENABLED:
    AUTHENTICATION_BACKENDS.insert(0, "fleet.auth.SubjectOIDCBackend")
    for name in ["OIDC_RP_CLIENT_ID", "OIDC_RP_CLIENT_SECRET", "OIDC_OP_AUTHORIZATION_ENDPOINT",
                 "OIDC_OP_TOKEN_ENDPOINT", "OIDC_OP_USER_ENDPOINT", "OIDC_OP_JWKS_ENDPOINT", "OIDC_ISSUER"]:
        globals()[name] = _oidc_ui.get(name) or os.environ[name]
    OIDC_RP_SIGN_ALGO = "RS256"
    OIDC_RP_SCOPES = "openid email profile"
    OIDC_TIMEOUT = 15
    OIDC_VERIFY_SSL = True
    OIDC_USE_PKCE = True
    OIDC_PKCE_CODE_CHALLENGE_METHOD = "S256"
    OIDC_CREATE_USER = True

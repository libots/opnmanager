# Upstream building blocks

Installed dependencies are pinned in `requirements.txt`; upstream license texts remain in their distributions.

| Project | Reused capability | License |
| --- | --- | --- |
| [Django](https://github.com/django/django) | Accounts, permissions, sessions, CSRF, admin, ORM, migrations, templates | BSD-3-Clause |
| [Mozilla django-oidc](https://github.com/mozilla/mozilla-django-oidc) | OIDC authorization flow, JWT signature and nonce validation, PKCE | MPL-2.0 |
| [Gunicorn](https://github.com/benoitc/gunicorn) | Local WSGI server | MIT |
| [WhiteNoise](https://github.com/evansd/whitenoise) | Static file serving and compression | MIT |
| [Requests](https://github.com/psf/requests) | HTTPS API client and Basic auth | Apache-2.0 |

Transitive dependencies and their licenses are included in the installed package metadata. OPNsense core's Firewall API controllers and model were consulted to implement the connector; no OPNsense implementation source is vendored here. OPNsense core controller code consulted is BSD-2-Clause. This application is independently implemented and is not an official OPNsense product.

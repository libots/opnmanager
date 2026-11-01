#!/usr/bin/env bash
set -euo pipefail
OPNMANAGER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$OPNMANAGER_ROOT"
export OPNMANAGER_LOCAL=1
export DJANGO_DEBUG=0
umask 077
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py bootstrap_admin

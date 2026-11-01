#!/usr/bin/env bash
set -euo pipefail
OPNMANAGER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$OPNMANAGER_ROOT"
export OPNMANAGER_LOCAL=1
export DJANGO_DEBUG=0
umask 077
if [[ ! -x .venv/bin/gunicorn ]]; then
  echo "Run ./scripts/setup-local.sh first." >&2
  exit 1
fi
# Migrations are safe to repeat; existing accounts/passwords are never replaced.
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py bootstrap_admin
exec .venv/bin/gunicorn config.wsgi:application \
  --bind "${OPNMANAGER_BIND:-127.0.0.1:8000}" --workers 1 --threads 2 --timeout 60 \
  --access-logfile - --error-logfile -

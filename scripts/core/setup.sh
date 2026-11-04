#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project
need openssl
if [[ ! -e "$RK_ROOT/.env" ]]; then
  [[ -f "$RK_ROOT/.env.example" ]] || fail 'Missing .env.example'
  cp "$RK_ROOT/.env.example" "$RK_ROOT/.env"
  chmod 600 "$RK_ROOT/.env"
  log 'Created .env. Set a strong GRAFANA_ADMIN_PASSWORD before deployment.'
else
  log '.env already exists; unchanged'
fi
bash "$RK_ROOT/scripts/bootstrap-certs.sh"
log 'Setup complete. Run scripts/core/preflight.sh after setting the password.'

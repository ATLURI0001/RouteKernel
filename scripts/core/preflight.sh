#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project
for command in bash docker curl openssl tar; do need "$command"; done
docker info >/dev/null 2>&1 || fail 'Docker daemon is not reachable'
docker compose version >/dev/null || fail 'Docker Compose v2 is required'
[[ -f "$RK_ROOT/.env" ]] || fail 'Create .env from .env.example and set a strong password'
[[ -s "$RK_ROOT/certs/server.crt" && -s "$RK_ROOT/certs/server.key" ]] || fail 'TLS files missing; run scripts/bootstrap-certs.sh'
compose config --quiet
log 'Preflight passed. For full Nginx check, run scripts/validate.sh'

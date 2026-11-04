#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need grep
failed=0
if grep -Eiq 'TLSv1([[:space:];]|\.0)|TLSv1\.1' "$RK_ROOT/nginx/nginx.conf" "$RK_ROOT/nginx/conf.d/"*.conf; then
  log 'FAIL: legacy TLS versions referenced'; failed=1
else log 'OK: no legacy TLS protocols detected'; fi
if git -C "$RK_ROOT" ls-files --error-unmatch .env >/dev/null 2>&1; then
  log 'FAIL: .env is tracked by Git'; failed=1
else log 'OK: .env is not tracked by Git'; fi
if [[ -f "$RK_ROOT/certs/server.key" ]]; then
  perms="$(stat -c '%a' "$RK_ROOT/certs/server.key" 2>/dev/null || stat -f '%Lp' "$RK_ROOT/certs/server.key")"
  if [[ "$perms" == 600 || "$perms" == 400 ]]; then log "OK: certificate key permissions $perms"; else log "WARN: key permissions $perms (use 600)"; failed=1; fi
fi
if [[ -f "$RK_ROOT/.env" ]] && grep -q '^GRAFANA_ADMIN_PASSWORD=change-me-before-deploy$' "$RK_ROOT/.env"; then
  log 'FAIL: example Grafana password is still configured'; failed=1
fi
((failed==0)) || fail 'Security audit found issues'
log 'Basic static checks passed; not a comprehensive security assessment'

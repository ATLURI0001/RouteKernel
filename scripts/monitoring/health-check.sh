#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
need curl; load_env
port="${EDGE_HTTPS_PORT:-8443}"
base="${RK_BASE_URL:-https://localhost:$port}"
# Use insecure TLS only when explicitly opted-in for local self-signed certificates.
curl_opts=(--silent --show-error --location --connect-timeout 3 --max-time 10)
[[ "${RK_DEV_INSECURE_TLS:-0}" == 1 ]] && curl_opts+=(--insecure)
failed=0
for endpoint in /health / /api/; do
  code="$(curl "${curl_opts[@]}" --output /dev/null --write-out '%{http_code}' "$base$endpoint")" || { log "FAIL $endpoint (connection/TLS)"; failed=1; continue; }
  if [[ "$code" == 200 ]]; then log "OK $endpoint HTTP $code"; else log "FAIL $endpoint HTTP $code"; failed=1; fi
done
exit "$failed"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck source=/dev/null
[[ -f .env ]] && source .env
set +a
PORT="${EDGE_HTTPS_PORT:-8443}"
BASE="https://localhost:${PORT}"
for endpoint in /health / /api/; do
  code="$(curl -ksS -o /dev/null -w '%{http_code}' "$BASE$endpoint")"
  [[ "$code" == 200 ]] || { echo "$endpoint -> $code (expected 200)" >&2; exit 1; }
  echo "$endpoint -> 200"
done
# External WebSocket client, e.g. websocat, can validate /ws/ echo semantics.
echo 'HTTPS smoke tests passed (development-only -k ignores self-signed cert verification).'

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need docker
compose ps -q edge | grep -q . || fail 'Edge service is not running'
local_dir="$(mktemp -d)"; trap 'rm -rf "$local_dir"' EXIT
# Compare deployed config to the host configuration; no changes made.
compose exec -T edge cat /etc/nginx/nginx.conf > "$local_dir/running.conf"
diff -u "$RK_ROOT/nginx/nginx.conf" "$local_dir/running.conf" || {
  code=$?; [[ $code -eq 1 ]] || exit "$code"
  log 'Config differences detected'
  exit 1
}
log 'Main Nginx configuration matches the mounted file'

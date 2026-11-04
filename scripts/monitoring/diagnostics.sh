#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need docker
outdir="${RK_REPORT_DIR:-$RK_ROOT/.routekernel-reports}"
mkdir -p "$outdir"; chmod 700 "$outdir"
report="$outdir/diagnostics-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
umask 077
{
  echo 'RouteKernel diagnostics — review/redact before sharing'
  date -u
  echo '--- Docker version ---'; docker version --format '{{.Server.Version}}' || true
  echo '--- Compose services ---'; compose ps || true
  echo '--- Resource metrics ---'; compose ps -q | xargs -r docker stats --no-stream || true
  echo '--- Nginx validation ---'; compose exec -T edge nginx -t 2>&1 || true
  echo '--- Recent edge logs (may contain IPs and request data) ---'; compose logs --tail 40 edge || true
} > "$report" 2>&1
log "Saved diagnostic report: $report (contains operational details; redact before sharing)"

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need tar; need date
backup_dir="${RK_BACKUP_DIR:-$RK_ROOT/.routekernel-backups}"
mkdir -p "$backup_dir"; chmod 700 "$backup_dir"
backup_dir="$(cd "$backup_dir" && pwd -P)"
case "$backup_dir" in "$RK_ROOT/nginx"|"$RK_ROOT/nginx/"*|"$RK_ROOT/monitoring"|"$RK_ROOT/monitoring/"*) fail 'Backup directory must not be inside a backed-up directory';; esac
stamp="$(date -u +%Y%m%dT%H%M%SZ)"; backup="$backup_dir/routekernel-config-$stamp-$$.tar.gz"
umask 077
(cd "$RK_ROOT" && tar -czf "$backup" nginx monitoring compose.yaml .env.example)
log "Saved configuration-only backup: $backup"
log 'This does NOT include live .env secrets, certificates, or database/volume data.'

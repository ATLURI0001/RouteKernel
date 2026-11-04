#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need docker
service="${1:-edge}"
case "$service" in edge|api-a|api-b|web|realtime|nginx-exporter|prometheus|grafana) ;; *) fail "Unknown service: $service";; esac
lines="${RK_LOG_LINES:-100}"
[[ "$lines" =~ ^[0-9]+$ ]] || fail 'RK_LOG_LINES must be a non-negative integer'
compose logs --tail "$lines" --follow "$service"

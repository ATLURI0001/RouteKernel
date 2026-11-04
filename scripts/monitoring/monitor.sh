#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need docker
log 'Compose service status'
compose ps
log 'CPU and memory usage (one snapshot)'
ids="$(compose ps -q)"
[[ -n "$ids" ]] || fail 'No running Compose containers'
# shellcheck disable=SC2086
printf '%s\n' "$ids" | xargs docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'

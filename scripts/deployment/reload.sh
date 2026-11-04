#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need docker
compose ps -q edge | grep -q . || fail 'Nginx container is not running'
compose exec -T edge nginx -t
compose exec -T edge nginx -s reload
log 'Nginx configuration tested and reloaded'

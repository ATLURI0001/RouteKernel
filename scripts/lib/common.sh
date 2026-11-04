#!/usr/bin/env bash
# Shared helpers; source from a RouteKernel script.
set -Eeuo pipefail
RK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
log() { printf '[RouteKernel] %s\n' "$*"; }
fail() { printf '[RouteKernel] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }
require_project() { [[ -f "$RK_ROOT/compose.yaml" && -f "$RK_ROOT/nginx/nginx.conf" ]] || fail "Run inside the RouteKernel project"; }
compose() { (cd "$RK_ROOT" && docker compose "$@"); }
load_env() {
  if [[ -f "$RK_ROOT/.env" ]]; then
    # Read only the two numeric port values; do not execute .env as shell code.
    local key val
    while IFS='=' read -r key val || [[ -n "$key" ]]; do
      case "$key" in
        EDGE_HTTPS_PORT|EDGE_HTTP_PORT)
          val="${val%%#*}"; val="${val//[[:space:]]/}"
          [[ "$val" =~ ^[0-9]+$ ]] || fail "Invalid $key in .env"
          printf -v "$key" '%s' "$val"; export "$key" ;;
      esac
    done < "$RK_ROOT/.env"
  fi
}

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project; need tar
[[ $# -eq 1 ]] || fail 'Usage: restore.sh /path/to/routekernel-config-*.tar.gz'
archive="$1"; [[ -f "$archive" ]] || fail 'Archive not found'
[[ "${RK_CONFIRM_RESTORE:-}" == YES ]] || fail 'Restore replaces configuration files. Set RK_CONFIRM_RESTORE=YES explicitly.'
# Only accept a tightly bounded list of safe relative paths.
while IFS= read -r entry; do
  [[ "$entry" != /* && "$entry" != *'..'* && "$entry" != *'\\'* ]] || fail "Unsafe archive path: $entry"
  case "$entry" in nginx|nginx/*|monitoring|monitoring/*|compose.yaml|.env.example) ;; *) fail "Unexpected archive path: $entry";; esac
done < <(tar -tzf "$archive")
log 'Restoring configuration files (not volumes or secrets)'
tar -xzf "$archive" -C "$RK_ROOT" --no-same-owner --no-same-permissions
log 'Restored. Review changes and run scripts/validate.sh before deployment.'

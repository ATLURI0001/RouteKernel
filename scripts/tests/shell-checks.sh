#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_project
need find; need bash
while IFS= read -r -d '' file; do bash -n "$file" || fail "Syntax invalid: $file"; done < <(find "$RK_ROOT/scripts" -type f -name '*.sh' -print0)
log 'Bash syntax checks passed'
if command -v shellcheck >/dev/null; then
  while IFS= read -r -d '' file; do shellcheck -S warning "$file" || fail "ShellCheck issues: $file"; done < <(find "$RK_ROOT/scripts" -type f -name '*.sh' -print0)
  log 'ShellCheck passed'
else
  log 'ShellCheck not installed; static linting skipped'
fi

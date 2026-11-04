#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
need curl; load_env
base="${RK_BASE_URL:-https://localhost:${EDGE_HTTPS_PORT:-8443}}"
[[ "$base" == http://localhost* || "$base" == https://localhost* || "$base" == http://127.0.0.1* || "$base" == https://127.0.0.1* ]] || [[ "${RK_ALLOW_REMOTE_BENCH:-0}" == 1 ]] || fail 'Remote load tests require explicit authorization and RK_ALLOW_REMOTE_BENCH=1'
requests="${RK_REQUESTS:-40}"; concurrency="${RK_CONCURRENCY:-4}"
[[ "$requests" =~ ^[0-9]+$ && "$concurrency" =~ ^[0-9]+$ ]] || fail 'Use numeric RK_REQUESTS and RK_CONCURRENCY'
(( requests>=1 && requests<=500 && concurrency>=1 && concurrency<=10 )) || fail 'Capped at 500 requests and 10 concurrent workers'
args=(--silent --show-error --connect-timeout 3 --max-time 10)
[[ "${RK_DEV_INSECURE_TLS:-0}" == 1 ]] && args+=(--insecure)
export base
# Each worker has bounded requests. Failure propagates to parent.
worker() { local i; for ((i=0;i<$1;i++)); do curl "${args[@]}" -f -o /dev/null "$base/health" || return 1; done; }
pids=()
for ((i=0;i<concurrency;i++)); do
  n=$((requests/concurrency + (i < requests%concurrency ? 1 : 0)))
  ((n>0)) || continue
  worker "$n" & pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
((failed==0)) || fail 'One or more requests failed'
log "Completed $requests bounded requests with at most $concurrency concurrent workers."

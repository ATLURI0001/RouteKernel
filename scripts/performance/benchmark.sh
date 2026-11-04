#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
need curl; load_env
base="${RK_BASE_URL:-https://localhost:${EDGE_HTTPS_PORT:-8443}}"
count="${RK_REQUESTS:-30}"
[[ "$count" =~ ^[0-9]+$ ]] && ((count >= 1 && count <= 1000)) || fail 'RK_REQUESTS must be 1..1000'
[[ "$base" == http://localhost* || "$base" == https://localhost* || "$base" == http://127.0.0.1* || "$base" == https://127.0.0.1* ]] || [[ "${RK_ALLOW_REMOTE_BENCH:-0}" == 1 ]] || fail 'Remote benchmarks require RK_ALLOW_REMOTE_BENCH=1 and authorization'
args=(--silent --show-error --connect-timeout 3 --max-time 15)
[[ "${RK_DEV_INSECURE_TLS:-0}" == 1 ]] && args+=(--insecure)
results="$(mktemp)"; trap 'rm -f "$results"' EXIT
for ((i=0;i<count;i++)); do
  curl "${args[@]}" -o /dev/null -w '%{http_code} %{time_total}\n' "$base/health" >> "$results" || fail "Request $((i+1)) failed"
done
awk '{n++; total+=$2; if($1!=200) errors++; if($2>max) max=$2} END {printf "requests=%d non_200=%d mean_latency_ms=%.2f max_latency_ms=%.2f\n",n,errors,total/n*1000,max*1000; if(errors) exit 1}' "$results"
log 'Sequential, low-volume diagnostic benchmark; NOT a throughput or production load test.'

#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
need openssl
cert="${RK_CERT_FILE:-$RK_ROOT/certs/server.crt}"
[[ -s "$cert" ]] || fail "Certificate not found: $cert"
days="${RK_CERT_MIN_DAYS:-14}"
[[ "$days" =~ ^[0-9]+$ ]] || fail 'RK_CERT_MIN_DAYS must be an integer'
openssl x509 -in "$cert" -noout -subject -dates
openssl x509 -checkend "$((days*86400))" -noout -in "$cert" >/dev/null || fail "Certificate expires within $days days"
log "Certificate remains valid beyond $days days"

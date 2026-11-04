#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/../lib/common.sh"
need openssl
cert="${RK_CERT_FILE:-$RK_ROOT/certs/server.crt}"
[[ -r "$cert" ]] || fail "Cannot read certificate: $cert"
openssl x509 -in "$cert" -noout -subject -issuer -serial -dates -ext subjectAltName

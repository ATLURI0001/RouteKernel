#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs
if [[ -e certs/server.crt || -e certs/server.key ]]; then
  if [[ -s certs/server.crt && -s certs/server.key ]]; then
    echo 'Certificates already present; leaving them unchanged.'
    exit 0
  fi
  echo 'Incomplete TLS pair; fix certs/server.crt and certs/server.key manually.' >&2
  exit 1
fi
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
  -keyout certs/server.key -out certs/server.crt \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
echo 'Generated DEVELOPMENT-ONLY localhost certificate (30 days).'

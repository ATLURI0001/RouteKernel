#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
[[ -f .env ]] || { echo 'Copy .env.example to .env and choose a strong Grafana password.' >&2; exit 1; }
[[ -s certs/server.crt && -s certs/server.key ]] || { echo 'Generate/provide TLS certs first.' >&2; exit 1; }
docker compose config --quiet
# Check configuration independently of the live server. Docker image must be available.
docker compose run --rm --no-deps --entrypoint nginx edge -t
echo 'Compose and Nginx configuration validated.'

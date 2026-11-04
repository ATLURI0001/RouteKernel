#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/validate.sh
docker compose up -d --build --remove-orphans
# Validate the live Nginx container after startup.
docker compose exec -T edge nginx -t
printf '\nServices deployed. Check: docker compose ps\n'
# This script does not claim to roll back image or volume changes automatically.

#!/usr/bin/env bash
# Stop the lab (logs in lab/logs are kept).
set -euo pipefail
cd "$(dirname "$0")"
docker compose --env-file ../.env down

#!/usr/bin/env bash
# Start the lab. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
[ -f ../.env ] || { echo "Missing ../.env: copy .env.example to .env first"; exit 1; }
mkdir -p logs/cowrie state/cowrie/tty state/cowrie/downloads logs/web logs/opencanary logs/smb
python cowrie_custom/build.py >/dev/null   # breadcrumbs inside the SSH honeypot
python ../agent/believability.py lint || echo "WARNING: the fake SSH server has tells (above); fix them before relying on the deception"
python lures/render.py >/dev/null   # planted lure files (honeytokens), generated from the registry and .env
docker compose --env-file ../.env up -d --build
docker compose --env-file ../.env ps

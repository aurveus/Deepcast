#!/usr/bin/env bash
# Pre-pull and pre-build every image the lab and the controller need, so the first live demo on a new machine does not wait for
# downloads and builds (the controller builds the web-panel and SMB decoy images only when it first starts one, which takes a minute
# or two and would break the "decoys within seconds" moment). Safe to repeat: existing images are reused.
# Needs Docker Desktop running and internet. Usage: bash lab/prewarm.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "Missing .env: copy .env.example to .env first"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running: start Docker Desktop and wait until it says it is running, then repeat."; exit 1; }

PLAN="$(python - <<'PY'
import json, sys
sys.stdout.reconfigure(newline="\n")             # python on Windows would end lines with CRLF and break the paths below
t = json.load(open("controller/allowlist.json", encoding="utf-8"))["templates"]
seen = set()
for v in t.values():
    key = (v.get("build_context"), v["image"])
    if key not in seen:
        seen.add(key)
        print("build" if v.get("build_context") else "pull", v["image"], v.get("build_context", "-"))
PY
)"

python lab/lures/render.py >/dev/null            # lure files that the decoy images are built with
echo "$PLAN" | while read -r kind image ctx; do
  if [ "$kind" = "pull" ]; then
    echo "pulling $image"
    if ! docker pull -q "$image" >/dev/null 2>&1; then
      docker image inspect "$image" >/dev/null 2>&1 && echo "  pull failed (offline or registry hiccup); using the copy already on this machine" || { echo "  pull failed and no local copy: connect to the internet and repeat"; exit 1; }
    fi
  fi
done
python lab/cowrie_custom/build.py >/dev/null     # breadcrumbs inside the SSH honeypot (needs the Cowrie image pulled above)
echo "$PLAN" | while read -r kind image ctx; do
  if [ "$kind" = "build" ]; then echo "building $image from $ctx"; docker build -q -t "$image" "$ctx" >/dev/null; fi
done
echo "building the lab compose images ..."
(cd lab && docker compose --env-file ../.env build >/dev/null)
echo "images ready:"
docker images --format '  {{.Repository}}:{{.Tag}}' | grep -E "cowrie|opencanary|deception-|lab-" | sort
echo "done"

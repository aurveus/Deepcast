#!/usr/bin/env bash
# Save one attack run: copy the current pcaps and honeypot logs into capture/runs/<name>_<timestamp>/
# and clear the rolling pcap folder so the next run starts clean.
# Usage: capture/save_run.sh <name>     (stop capture/capture.sh with Ctrl+C first)
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-}"
[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "Usage: capture/save_run.sh <name>   (letters, digits, - and _ only)"; exit 1; }

env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
PCAP_DIR="$(env_get CAPTURE_DIR)"; PCAP_DIR="${PCAP_DIR:-capture/pcaps}"

shopt -s nullglob
pcaps=("$PCAP_DIR"/*.pcap)
[ ${#pcaps[@]} -gt 0 ] || { echo "No pcaps in $PCAP_DIR: was capture/capture.sh running?"; exit 1; }

if tasklist 2>/dev/null | grep -qi tshark; then
  echo "tshark is still running: stop capture/capture.sh (Ctrl+C) before saving the run."; exit 1
fi

DEST="capture/runs/${NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEST/pcaps" "$DEST/logs"
cp "${pcaps[@]}" "$DEST/pcaps/"
for f in lab/logs/*/*.json; do
  mkdir -p "$DEST/logs/$(basename "$(dirname "$f")")"
  cp "$f" "$DEST/logs/$(basename "$(dirname "$f")")/"
done
rm -f "${pcaps[@]}"

echo "Saved run to $DEST"
echo "  pcaps: ${#pcaps[@]} file(s), logs: $(find "$DEST/logs" -type f | wc -l) file(s)"
echo "Honeypot logs are copied whole (they are not reset); use the timestamps to find this run's events."

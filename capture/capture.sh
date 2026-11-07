#!/usr/bin/env bash
# Rolling packet capture of the lab interface (VMnet1) with tshark.
# Usage: capture/capture.sh        (Ctrl+C to stop)
# Config comes from ../.env: CAPTURE_IFACE (required), CAPTURE_DIR, CAPTURE_FILTER (optional).
set -euo pipefail
cd "$(dirname "$0")/.."

# Read .env without 'source' so the backslashes in \Device\NPF_{...} survive.
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }

[ -f .env ] || { echo "Missing .env: copy .env.example to .env first"; exit 1; }
IFACE="$(env_get CAPTURE_IFACE)"
OUT_DIR="$(env_get CAPTURE_DIR)"; OUT_DIR="${OUT_DIR:-capture/pcaps}"
FILTER="$(env_get CAPTURE_FILTER)"

case "$IFACE" in
  ""|*REPLACE-WITH*) echo "Set CAPTURE_IFACE in .env (find it with: tshark -D, the VMware Network Adapter VMnet1 line)"; exit 1 ;;
esac

TSHARK="$(command -v tshark || true)"
[ -n "$TSHARK" ] || TSHARK="/c/Program Files/Wireshark/tshark.exe"
[ -x "$TSHARK" ] || { echo "tshark not found"; exit 1; }

# Interface numbers change between runs, the NPF ID does not: check it exists.
"$TSHARK" -D 2>/dev/null | grep -qF "$IFACE" || { echo "Interface not found by tshark -D: $IFACE"; exit 1; }

mkdir -p "$OUT_DIR"
echo "Capturing on $IFACE -> $OUT_DIR (new file every 5 min or 50 MB, keeping the newest 48). Ctrl+C to stop."
args=(-i "$IFACE" -F pcap -w "$OUT_DIR/lab.pcap" -b duration:300 -b filesize:51200 -b files:48)
[ -n "$FILTER" ] && args+=(-f "$FILTER")
exec "$TSHARK" "${args[@]}"

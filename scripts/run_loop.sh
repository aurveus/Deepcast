#!/usr/bin/env bash
# Full loop: capture -> (you attack from Kali) -> save run -> Claude analysis -> controller.
# Usage: bash scripts/run_loop.sh <name> [--auto] [--wait <seconds>]
#   --auto   spawn decoys without asking y/N
#   --fresh  remove all spawned decoys first (use for evaluation runs, so "decoy deployed" is measured cleanly)
#   --wait   capture for N seconds instead of waiting for Enter (useful for idle/benign runs)
# Needs the lab running (lab/up.sh). Stops every tshark.exe on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-}"; shift || true
[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "Usage: bash scripts/run_loop.sh <name> [--auto] [--fresh] [--wait <seconds>]"; exit 1; }
AUTO=""; WAIT=""; FRESH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --auto) AUTO="--auto" ;;
    --fresh) FRESH=1 ;;
    --wait) WAIT="${2:?--wait needs seconds}"; shift ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
  shift
done

emit() { python controller/emit_event.py "$@" || true; }
stop_capture() { taskkill //IM tshark.exe //F >/dev/null 2>&1 || true; taskkill //IM dumpcap.exe //F >/dev/null 2>&1 || true; }
trap 'stop_capture; emit run_finished name="$NAME"' EXIT

[ -z "$(ls capture/pcaps/*.pcap 2>/dev/null)" ] || { echo "capture/pcaps is not empty: save or delete old pcaps first"; exit 1; }

[ -z "$FRESH" ] || python controller/controller.py killswitch
echo "== 1/4 capture"
emit run_capture_started name="$NAME"
capture/capture.sh >/dev/null 2>&1 &
sleep 4
if [ -n "$WAIT" ]; then echo "Capturing for $WAIT s. Attack from Kali now."; sleep "$WAIT"
else read -r -p "Capturing. Attack from Kali now, then press Enter when finished. "; fi
stop_capture; sleep 2

echo "== 2/4 save run"
emit run_saving name="$NAME"
OUT="$(capture/save_run.sh "$NAME")"; echo "$OUT"
RUN_DIR="$(echo "$OUT" | sed -n 's/^Saved run to //p')"

echo "== 3/4 Claude analysis"
emit analysis_started name="$NAME" run_id="$(basename "$RUN_DIR")"
python agent/analyze.py "$RUN_DIR"

echo "== 4/4 controller"
emit controller_started name="$NAME"
python controller/controller.py apply "$RUN_DIR" $AUTO

echo "== incident report"
python report/incident_report.py "$RUN_DIR" || echo "(incident report failed; the run itself is saved)"

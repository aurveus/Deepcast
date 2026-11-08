#!/usr/bin/env bash
# Replay a bundled sample run (replays/<name>/). Usage: bash scripts/replay.sh <level1|level2> <name> [--auto]
#   level2  fully offline: validates the SAVED Claude output and applies it through the controller.
#           This is the emergency demo fallback (no Claude, no internet, no capture needed).
#   level1  re-analyzes the bundled pcap with Claude again (needs Claude), then applies the result.
# Names: portscan_demo, sshbrute_demo, webprobe_demo. Without --auto the controller asks y/N per decoy.
set -euo pipefail
cd "$(dirname "$0")/.."
LEVEL="${1:-}"; NAME="${2:-}"; shift 2 || true
[ -d "replays/$NAME" ] || { echo "Usage: bash scripts/replay.sh <level1|level2> <name> [--auto]   (names: $(ls replays | tr '\n' ' '))"; exit 1; }
case "$LEVEL" in
  level2) python controller/controller.py apply "replays/$NAME/analysis.json" "$@" ;;
  level1) DECEPTION_NO_EVENTS= python agent/analyze.py "replays/$NAME" >/dev/null && python controller/controller.py apply "replays/$NAME/analysis.json" "$@" ;;
  *) echo "Level must be level1 or level2"; exit 1 ;;
esac

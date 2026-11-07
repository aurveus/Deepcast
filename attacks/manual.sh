#!/usr/bin/env bash
# Mark the start and end of a MANUAL session (you at the Kali VM, a person exploring the lab) so it can be scored like a campaign scenario.
# Run on the HOST (the capture clock), not on Kali:   attacks/manual.sh start "short label"   ...do your session...   attacks/manual.sh stop
# Writes attacks/logs/campaign_manual_<date>.jsonl in the same format as the scripted campaigns (scenario "manual").
# Score:  python eval/campaign_eval.py attacks/logs/campaign_manual_<date>.jsonl --out manual   (writes eval/results/campaign_manual.{json,md})
# Lab only. Leave at least 3 minutes between sessions so each one becomes its own incident (the watcher needs WATCH_MERGE=60).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p attacks/logs
STATE=attacks/logs/.manual_session
LOG="attacks/logs/campaign_manual_$(date -u +%Y%m%d).jsonl"
now() { date -u +%FT%TZ; }
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
case "${1:-}" in
  start)
    [ ! -f "$STATE" ] || { echo "A session is already running (started $(head -1 $STATE)). Run: attacks/manual.sh stop"; exit 1; }
    label="${2:-manual session}"; label="${label//\"/}"
    printf '%s\t%s\n' "$(now)" "$label" > "$STATE"
    echo "Session started $(head -1 $STATE | cut -f1) (label: $label). Go ahead; run 'attacks/manual.sh stop' when you are done." ;;
  stop)
    [ -f "$STATE" ] || { echo "No session is running."; exit 1; }
    start="$(cut -f1 $STATE)"; label="$(cut -f2 $STATE)"; end="$(now)"; target="$(env_get HOST_IP)"
    [ -f "$LOG" ] || printf '{"event":"campaign_started","ts":"%s","seed":0,"target":"%s","total":0,"note":"manual sessions"}\n' "$start" "$target" > "$LOG"
    n=$(( $(grep -c '"event":"scenario"' "$LOG" || true) + 1 ))
    printf '{"event":"scenario","n":%s,"scenario":"manual","attack":true,"target":"%s","start":"%s","end":"%s","rc":0,"label":"%s"}\n' "$n" "$target" "$start" "$end" "$label" >> "$LOG"
    rm -f "$STATE"
    echo "Session $n recorded ($start to $end) in $LOG. Wait about 3 minutes for the incident to close before the next one." ;;
  status) [ -f "$STATE" ] && echo "running since $(head -1 $STATE | cut -f1)" || echo "no session running" ;;
  *) sed -n 2,7p "$0"; exit 2 ;;
esac

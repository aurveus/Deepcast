#!/usr/bin/env bash
# Run attacks/campaign.sh on Kali from the host over the key-based SSH (README, "Automated attacks").
# Copies the scripts each time, runs the campaign, and brings its ground-truth log back to attacks/logs/campaign_<time>.jsonl
# (the path is printed on the last line). Extra arguments go to campaign.sh (--runs, --idle, --seed, --only, ...).
# Usage (on the host): attacks/run_campaign.sh [campaign.sh options]
set -uo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
USER_="$(env_get KALI_USER)"; HOST_="$(env_get KALI_IP)"; KEY="$(env_get KALI_SSH_KEY)"; KEY="${KEY/#\~/$HOME}"
[ -n "$USER_" ] && [ -n "$HOST_" ] && [ -f "$KEY" ] || { echo "Set KALI_USER/KALI_IP/KALI_SSH_KEY in .env and run attacks/check_kali.sh first" >&2; exit 1; }
SUBNET="$(env_get LAB_SUBNET)"; PREFIX="${SUBNET%.*}."
TARGET="$(env_get HOST_IP)"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_@$HOST_")

scp -i "$KEY" -o StrictHostKeyChecking=accept-new attacks/campaign.sh attacks/lure_chain_sim.sh "$USER_@$HOST_:/tmp/" >/dev/null || exit 1
# quote the extra arguments for the remote shell
ARGS=""; for a in "$@"; do ARGS+=" $(printf '%q' "$a")"; done
RC=0
"${SSH[@]}" "chmod +x /tmp/campaign.sh /tmp/lure_chain_sim.sh; cd /tmp; LAB_PREFIX='$PREFIX' LAB_TARGET='${TARGET:-10.10.10.1}' LAB_CAMPAIGN_LOG=\$HOME/campaign.jsonl /tmp/campaign.sh$ARGS" || RC=$?

mkdir -p attacks/logs
DEST="attacks/logs/campaign_$(date +%Y%m%d_%H%M%S).jsonl"
scp -i "$KEY" "$USER_@$HOST_:campaign.jsonl" "$DEST" >/dev/null 2>&1 || { echo "could not fetch campaign.jsonl" >&2; exit 1; }
echo "$DEST"
exit "$RC"

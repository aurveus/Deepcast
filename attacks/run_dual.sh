#!/usr/bin/env bash
# Run attacks/dual_attacker.sh on Kali from the host over the key-based SSH (README, "Automated attacks") and bring its
# ground-truth log back to attacks/logs/dual_<time>.jsonl (the path is printed on the last line).
# Needs the second address on Kali first (once, by hand, not persistent):  sudo ip addr add <KALI_IP2>/24 dev eth0
# Usage (on the host): attacks/run_dual.sh [dual_attacker.sh options]      (normally started by eval/run_dual.py, which also runs the watcher)
set -uo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
USER_="$(env_get KALI_USER)"; HOST_="$(env_get KALI_IP)"; KEY="$(env_get KALI_SSH_KEY)"; KEY="${KEY/#\~/$HOME}"; IP2="$(env_get KALI_IP2)"
[ -n "$USER_" ] && [ -n "$HOST_" ] && [ -f "$KEY" ] || { echo "Set KALI_USER/KALI_IP/KALI_SSH_KEY in .env and run attacks/check_kali.sh first" >&2; exit 1; }
[ -n "$IP2" ] || { echo "Set KALI_IP2 (the second attacker address, e.g. 10.10.10.11) in .env" >&2; exit 1; }
SUBNET="$(env_get LAB_SUBNET)"; PREFIX="${SUBNET%.*}."
TARGET="$(env_get HOST_IP)"
SSH=(ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_@$HOST_")

scp -i "$KEY" -o StrictHostKeyChecking=accept-new attacks/dual_attacker.sh "$USER_@$HOST_:/tmp/" >/dev/null || exit 1
ARGS=""; for a in "$@"; do ARGS+=" $(printf '%q' "$a")"; done
RC=0
"${SSH[@]}" "chmod +x /tmp/dual_attacker.sh; cd /tmp; LAB_PREFIX='$PREFIX' LAB_TARGET='${TARGET:-10.10.10.1}' LAB_SRC2='$IP2' LAB_DUAL_LOG=\$HOME/dual.jsonl /tmp/dual_attacker.sh$ARGS" || RC=$?

mkdir -p attacks/logs
DEST="attacks/logs/dual_$(date +%Y%m%d_%H%M%S).jsonl"
scp -i "$KEY" "$USER_@$HOST_:dual.jsonl" "$DEST" >/dev/null 2>&1 || { echo "could not fetch dual.jsonl" >&2; exit 1; }
echo "$DEST"
exit "$RC"

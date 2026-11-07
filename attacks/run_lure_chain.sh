#!/usr/bin/env bash
# Run attacks/lure_chain_sim.sh on Kali from the host, over the key-based SSH set up in the README
# ("Automated attacks"). Copies the script each time so edits here take effect without touching Kali by hand.
# Usage (on the host): attacks/run_lure_chain.sh [--fast]
set -euo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
USER_="$(env_get KALI_USER)"; HOST_="$(env_get KALI_IP)"; KEY="$(env_get KALI_SSH_KEY)"; KEY="${KEY/#\~/$HOME}"
[ -n "$USER_" ] && [ -n "$HOST_" ] && [ -f "$KEY" ] || { echo "Set KALI_USER/KALI_IP/KALI_SSH_KEY in .env and run attacks/check_kali.sh first"; exit 1; }

SUBNET="$(env_get LAB_SUBNET)"; PREFIX="${SUBNET%.*}."     # 10.10.10.0/24 -> 10.10.10.
scp -i "$KEY" -o StrictHostKeyChecking=accept-new attacks/lure_chain_sim.sh "$USER_@$HOST_:/tmp/lure_chain_sim.sh" >/dev/null
RC=0
ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "$USER_@$HOST_" "rm -f ~/lure_chain_sim.log; chmod +x /tmp/lure_chain_sim.sh; LAB_PREFIX='$PREFIX' /tmp/lure_chain_sim.sh $*" || RC=$?

# Ground truth: bring the simulator's timestamped log back to the host (attacks/logs/, git-ignored), like the benign generator's.
mkdir -p attacks/logs
scp -i "$KEY" "$USER_@$HOST_:lure_chain_sim.log" "attacks/logs/lure_chain_sim_$(date +%Y%m%d_%H%M%S).log" >/dev/null 2>&1 || true
exit "$RC"

#!/usr/bin/env bash
# Copy the generator's ground-truth log from the workstation VM to traffic/logs/ (run on the host).
# Usage: traffic/pull_ground_truth.sh
set -euo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
VM="$(env_get WORKSTATION_IP)"; VMUSER="$(env_get WORKSTATION_USER)"
[ -n "$VM" ] && [ -n "$VMUSER" ] || { echo "Set WORKSTATION_IP and WORKSTATION_USER in .env"; exit 1; }
mkdir -p traffic/logs
scp "$VMUSER@$VM:/var/log/workstation-sim/ground_truth.jsonl" traffic/logs/ground_truth_vm.jsonl
echo "Saved traffic/logs/ground_truth_vm.jsonl ($(wc -l < traffic/logs/ground_truth_vm.jsonl) events)"

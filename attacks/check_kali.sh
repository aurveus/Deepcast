#!/usr/bin/env bash
# Check that the host can log in to Kali with the lab key (no password) and that the attack tools are there.
# Usage: attacks/check_kali.sh
set -euo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
USER_="$(env_get KALI_USER)"; HOST_="$(env_get KALI_IP)"; KEY="$(env_get KALI_SSH_KEY)"; KEY="${KEY/#\~/$HOME}"
[ -f "$KEY" ] || { echo "No key at $KEY. Create it first (README, 'Automated attacks')."; exit 1; }
echo "Connecting to $USER_@$HOST_ with $KEY (no password expected) ..."
ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "$USER_@$HOST_" '
  echo "login ok: $(hostname), $(ip -4 -br addr | grep -v "^lo" | head -1)"
  for t in nmap hydra nikto gobuster curl ssh sshpass smbclient mysql; do
    if command -v "$t" >/dev/null 2>&1; then echo "  have  $t"; else echo "  MISSING $t"; fi
  done'

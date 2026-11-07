#!/usr/bin/env bash
# Install / update the benign traffic generator on the workstation VM (run on the host).
# Needs the VM reachable over SSH (WORKSTATION_IP / WORKSTATION_USER in .env, user with sudo).
# You will be asked for the VM password a few times. Usage: traffic/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
env_get() { { grep -E "^$1=" .env 2>/dev/null || true; } | head -1 | cut -d= -f2- | tr -d '\r'; }
need() { local v; v="$(env_get "$1")"; [ -n "$v" ] || { echo "Set $1 in .env" >&2; exit 1; }; printf '%s' "$v"; }

VM="$(need WORKSTATION_IP)"; VMUSER="$(need WORKSTATION_USER)"
TARGET="$(need HOST_IP)"; WEB_PORT="$(env_get WEB_PORT)"; SSH_PORT="$(env_get COWRIE_SSH_PORT)"
LUSER="$(need GEN_SSH_USER)"; LPASS="$(need GEN_SSH_PASSWORD)"

# Build the VM-side setup script locally; the lab-only demo account goes into a root-owned env file on the VM.
SETUP="$(mktemp)"; trap 'rm -f "$SETUP"' EXIT
cat > "$SETUP" <<EOF
set -e
id wsim >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin wsim
mkdir -p /opt/workstation-sim
install -m 644 /tmp/generator.py /opt/workstation-sim/generator.py
install -m 644 /tmp/workstation.service /etc/systemd/system/workstation.service
cat > /etc/workstation-sim.env <<ENV
GEN_TARGET=$TARGET
GEN_WEB_PORT=${WEB_PORT:-8080}
GEN_SSH_PORT=${SSH_PORT:-2222}
GEN_SSH_USER=$LUSER
GEN_SSH_PASSWORD=$LPASS
GEN_LOG=/var/log/workstation-sim/ground_truth.jsonl
ENV
chmod 644 /etc/workstation-sim.env
systemctl daemon-reload
systemctl enable workstation >/dev/null
systemctl restart workstation
sleep 2
systemctl --no-pager --lines=5 status workstation || true
EOF

echo "Copying files to $VMUSER@$VM ..."
scp -o StrictHostKeyChecking=accept-new traffic/generator.py traffic/workstation.service "$SETUP" "$VMUSER@$VM:/tmp/"
ssh -t "$VMUSER@$VM" "sudo bash /tmp/$(basename "$SETUP"); rm -f /tmp/$(basename "$SETUP")"
echo "Done. The generator now starts automatically on every boot of the VM."

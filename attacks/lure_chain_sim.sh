#!/usr/bin/env bash
# Realistic attacker simulator for the lure chain — LAB ONLY, runs on Kali against the isolated VMnet1 range.
# Plays a human-paced version of the chain documented in attacks/README.md (section 5): recon, find the
# planted web lure, read the fake SSH credential from it, log in, look around, follow the breadcrumbs it left
# (hosts file / history / arp) to the "internal" hosts, try the fake database credential found on the SMB share.
# Uses only standard tools already on Kali (nmap, curl, ssh, sshpass, smbclient, mysql). Nothing here invents an
# exploit. Every address it touches (the target AND the hosts it discovers) must start with LAB_PREFIX, otherwise
# it stops: discovered hosts come from honeypot output, which must never be able to steer it outside the lab.
#
# Usage (on Kali): ./lure_chain_sim.sh [--fast] [--deep] [--explore]
#   --explore  a broad, read-only 'curious admin' session (process list, network settings, disk and memory, installed packages ...) to
#              measure which ordinary commands the fake shell cannot answer (see agent/believability.py harvest)
#   --fast   shrink the pauses between steps (for CI-style repeat runs instead of a realistic demo pace)
#   --deep   after the login, walk the SSH honeypot the way a person looks around a new server (one command per line, read the
#            README, cron job, backup script, logs, exports, history) and try the found credential on the other services
#            (FTP, SMB). Standard shell commands and logins only; every address is checked against the lab range.
set -uo pipefail

TARGET="${LAB_TARGET:-10.10.10.1}"
LAB_PREFIX="${LAB_PREFIX:-10.10.10.}"   # the host runner passes this from LAB_SUBNET in .env
WEB_PORT="${LAB_WEB_PORT:-8080}"
SSH_PORT="${LAB_SSH_PORT:-2222}"
LOG="${LAB_SIM_LOG:-$HOME/lure_chain_sim.log}"
PAUSE_MIN=3; PAUSE_MAX=9
DEEP=0
EXPLORE=0
for arg in "$@"; do
  case "$arg" in
    --fast) PAUSE_MIN=0; PAUSE_MAX=1 ;;
    --deep) DEEP=1 ;;
    --explore) DEEP=1; EXPLORE=1 ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done

pause() { local s; s=$((RANDOM % (PAUSE_MAX - PAUSE_MIN + 1) + PAUSE_MIN)); sleep "$s"; }
log() { printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" | tee -a "$LOG" >&2; }

die() { log run_aborted "$1"; exit 1; }
in_lab() { case "$1" in "$LAB_PREFIX"*) return 0 ;; *) return 1 ;; esac; }
in_lab "$TARGET" || die "target $TARGET is outside the lab range $LAB_PREFIX*"

log run_started "target=$TARGET"

# --- Stage 1: recon ---------------------------------------------------------
log stage "1 recon: service scan of $TARGET"
nmap -n -sV -p "21,22,23,80,443,445,2222,3306,4445,$WEB_PORT" "$TARGET" > /tmp/lcs_scan.txt 2>&1
log recon_done "ports scanned, see /tmp/lcs_scan.txt"
pause

# --- Stage 2: find the web lure --------------------------------------------
log stage "2 find lure: robots.txt -> /backup/"
curl -s "http://$TARGET:$WEB_PORT/robots.txt" -o /tmp/lcs_robots.txt
curl -s "http://$TARGET:$WEB_PORT/backup/" -o /tmp/lcs_backup_index.html
pause
CONF=/tmp/lcs_config.bak
curl -s "http://$TARGET:$WEB_PORT/backup/config.bak" -o "$CONF"
if ! grep -q BACKUP_USER "$CONF" 2>/dev/null; then
  log lure_not_found "no config.bak at /backup/ — stopping"
  exit 1
fi
LURE_USER=$(grep -m1 '^BACKUP_USER=' "$CONF" | cut -d= -f2-)
LURE_PASS=$(grep -m1 '^BACKUP_PASS=' "$CONF" | cut -d= -f2-)
log lure_found "credential pulled from /backup/config.bak: user=$LURE_USER"
pause

# --- Stage 3: use the planted credential on the SSH honeypot ----------------
log stage "3 reuse credential: ssh login as $LURE_USER"
RUN1=/tmp/lcs_ssh1.log
SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
if [ "$DEEP" -eq 1 ]; then
  # An interactive-style session: one command per line with human pauses, so the honeypot records each command on its own.
  DEEP_CMDS=(
    "whoami" "id" "hostname" "uname -a" "pwd" "ls -la" "cat README.txt"
    "cat /etc/passwd" "ls /home" "cat ~/.bash_history"
    "cat /etc/crontab" "cat /usr/local/bin/nightly-backup.sh"
    "ls -la /srv/exports/nightly" "head -5 /srv/exports/nightly/reports_$(date -d yesterday +%F).csv"
    "tail -5 /var/log/backup/nightly.log" "tail -8 /var/log/auth.log"
    "cat /etc/hosts" "arp -a"
  )
  if [ "$EXPLORE" -eq 1 ]; then
    DEEP_CMDS+=("ps aux" "ifconfig" "ip a" "netstat -tlnp" "ss -tlnp" "df -h" "free -m" "uptime" "w" "last" "env" "sudo -l"
                "crontab -l" "lsb_release -a" "cat /etc/os-release" "cat /etc/issue" "cat /etc/hostname" "mount" "lscpu" "cat /proc/cpuinfo"
                "cat /proc/version" "ls -la /tmp" "ls -la /var/log" "dpkg -l | head -5" "systemctl list-units | head -5" "history")
  fi
  log deep_session "walking the SSH honeypot: ${#DEEP_CMDS[@]} commands, one at a time"
  {
    for c in "${DEEP_CMDS[@]}"; do sleep $((RANDOM % (PAUSE_MAX - PAUSE_MIN + 1) + PAUSE_MIN)); printf '%s\n' "$c"; done
    sleep 1; printf 'exit\n'
  } | SSHPASS="$LURE_PASS" sshpass -e ssh -tt "${SSH_OPTS[@]}" "$LURE_USER@$TARGET" > "$RUN1" 2>&1
  SSH_RC=$?
else
  SSHPASS="$LURE_PASS" sshpass -e ssh "${SSH_OPTS[@]}" \
    "$LURE_USER@$TARGET" \
    'whoami; pwd; cat /etc/hosts; echo ---HISTORY---; cat ~/.bash_history 2>/dev/null; echo ---ARP---; arp -a 2>/dev/null' \
    > "$RUN1" 2>&1
  SSH_RC=$?
fi
log ssh_login "exit=$SSH_RC output in $RUN1"
[ "$SSH_RC" -eq 0 ] || die "ssh login with the planted credential failed, chain cannot continue"
pause

# --- Stage 4: follow the breadcrumbs to the internal hosts ------------------
DB_HOST=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+db-prod-01' "$RUN1" | awk '{print $1}' | head -1)
FS_HOST=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+fs-backup-01' "$RUN1" | awk '{print $1}' | head -1)
log stage "4 discovery: breadcrumbs point at db-prod-01=${DB_HOST:-?} fs-backup-01=${FS_HOST:-?}"
for h in DB_HOST FS_HOST; do
  if [ -n "${!h:-}" ] && ! in_lab "${!h}"; then die "$h=${!h} (read from honeypot output) is outside the lab range, refusing"; fi
done
[ -n "${DB_HOST:-}${FS_HOST:-}" ] || log stage_skipped "no internal hosts found in the breadcrumbs"
pause

# --- Stage 5: SMB share on the second internal host, look for more creds ----
if [ -n "${FS_HOST:-}" ]; then
  log stage "5 enumerate SMB share on $FS_HOST"
  smbclient -p 4445 -N -L "//$FS_HOST" > /tmp/lcs_smb_list.txt 2>&1
  mkdir -p /tmp/lcs_smb_loot
  smbclient -p 4445 -N "//$FS_HOST/DOCS" -c 'prompt OFF; recurse ON; lcd /tmp/lcs_smb_loot; mget *' > /tmp/lcs_smb_get.txt 2>&1
  DBNOTE=$(grep -rl -i reports_ro /tmp/lcs_smb_loot 2>/dev/null | head -1)
  if [ -n "${DBNOTE:-}" ]; then
    DB_USER=$(grep -m1 '^User:' "$DBNOTE" | awk '{print $2}')
    DB_PASS=$(grep -m1 '^Password:' "$DBNOTE" | awk '{print $2}')
    log smb_loot "found db credential in $DBNOTE user=$DB_USER"
  fi
  pause
else
  log stage_skipped "5 smb: no fs-backup-01 host found"
fi

# --- Stage 6: try the second planted credential on the database host -------
if [ -n "${DB_HOST:-}" ] && [ -n "${DB_USER:-}" ]; then
  log stage "6 reuse second credential: mysql login to $DB_HOST as $DB_USER"
  MYSQL_PWD="$DB_PASS" mysql --skip-ssl -h "$DB_HOST" -P 3306 -u "$DB_USER" -e 'show databases;' > /tmp/lcs_mysql.txt 2>&1
  log mysql_login "exit=$? (denied is expected: the fake MySQL only logs attempts) output in /tmp/lcs_mysql.txt"
else
  log stage_skipped "6 mysql: no db host or no db credential found"
fi

# --- Stage 7 (deep): people reuse passwords, so try the found login on the other services ----
if [ "$DEEP" -eq 1 ]; then
  log stage "7 credential reuse: try $LURE_USER on FTP and the file server"
  in_lab "$TARGET" || die "target outside the lab range"
  curl -s --max-time 10 --user "$LURE_USER:$LURE_PASS" "ftp://$TARGET:21/" > /tmp/lcs_ftp.txt 2>&1
  log ftp_login "exit=$? (the FTP decoy logs the attempt) output in /tmp/lcs_ftp.txt"
  pause
  if [ -n "${FS_HOST:-}" ]; then
    smbclient -p 4445 -L "//$FS_HOST" -U "$LURE_USER%$LURE_PASS" > /tmp/lcs_smb_reuse.txt 2>&1
    log smb_login "exit=$? (credential reuse on the file server) output in /tmp/lcs_smb_reuse.txt"
  fi
fi

log run_finished "target=$TARGET"

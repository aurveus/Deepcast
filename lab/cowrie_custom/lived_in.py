#!/usr/bin/env python3
"""Believable 'lived-in' content for the SSH honeypot: a server that looks like it has been in use for months.

  python lab/cowrie_custom/lived_in.py <outdir>     # self-test: write every file under <outdir> and list them

build.py imports files() and dirs() and plants them in Cowrie's fake filesystem. Everything is generated from a fixed
seed, so the content is identical on every machine and every run (static, reproducible, nothing random at start-up).

Rules for what goes in here:
  - No credentials of any kind. The only planted secrets are the honeytokens (lab/lures/honeytokens.json); an extra
    password in this file would be indistinguishable from a lure and would confuse the evidence.
  - Names match the story the lures already tell: server svr04 on corp.local, the IT-operations employee Tom Davies (account tdavies, owner of the nightly backup job), internal hosts
    db-prod-01 and fs-backup-01 (their addresses are passed in by build.py).
"""
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# The fake server's clock follows the real date (built at every lab start and before each SSH decoy), so file dates, logs and
# backup history never drift into the past, which would be a tell. The seed is the date, so the content is identical all day.
NOW = datetime.now().replace(hour=3, minute=12, second=0, microsecond=0)      # "now" = just after last night's backup
SEED = int(NOW.strftime("%Y%m%d"))


def _times(rng, start, n, step_min, step_max):
    t, out = start, []
    for _ in range(n):
        t += timedelta(seconds=rng.randint(step_min, step_max))
        out.append(t)
    return out


LURE_OWNER_COMMENT = "Tom Davies (IT operations),,,"      # passwd comment for the planted honeytoken account (a real-looking employee)


def users():
    """(name, uid, comment) of ordinary accounts added to /etc/passwd next to the planted honeytoken account."""
    return [("jsmith", 1002, "John Smith,,,"), ("deploy", 1003, "Deploy user,,,"), ("mharris", 1004, "Maria Harris,,,")]


def files(db_ip, smb_ip, host_ip, ssh_user):
    """path -> (content, mode, uid, age_days). Modes: 0o100644 file, 0o100755 executable, 0o100600 private."""
    rng = random.Random(SEED)
    f = {}

    f["/etc/crontab"] = (
        "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        f"15 2\t* * *\t{ssh_user}\t/usr/local/bin/nightly-backup.sh >> /var/log/backup/nightly.log 2>&1\n"
        "40 3\t* * 0\troot\t/usr/local/bin/rotate-exports.sh\n", 0o100644, 0, 200)

    f["/usr/local/bin/nightly-backup.sh"] = (
        "#!/bin/bash\n# Nightly export of the reporting dumps to the file server. Owner: IT operations (it-ops@corp.local)\n"
        "# Credentials for the share are kept in the admin notes, NOT in this script.\nset -euo pipefail\n\n"
        "SRC=/srv/exports/nightly\nDEST_HOST=fs-backup-01.corp.local\nSTAMP=$(date +%F)\n\n"
        "echo \"[$(date '+%F %T')] backup start\"\n"
        "tar -czf /tmp/exports-$STAMP.tar.gz -C \"$SRC\" .\n"
        "smbclient -p 4445 //$DEST_HOST/DOCS -N -c \"put /tmp/exports-$STAMP.tar.gz exports-$STAMP.tar.gz\"\n"
        "rm -f /tmp/exports-$STAMP.tar.gz\necho \"[$(date '+%F %T')] backup done\"\n", 0o100755, 0, 160)

    f["/usr/local/bin/rotate-exports.sh"] = (
        "#!/bin/bash\n# keep 14 days of nightly dumps\nfind /srv/exports/nightly -type f -mtime +14 -delete\n", 0o100755, 0, 160)

    # backup log: one run per night for the last 21 nights
    lines = []
    for d in range(21, 0, -1):
        day = NOW - timedelta(days=d)
        start = day.replace(hour=2, minute=15, second=rng.randint(0, 20))
        end = start + timedelta(seconds=rng.randint(70, 140))
        lines.append(f"[{start:%F %T}] backup start")
        lines.append(f"[{end:%F %T}] backup done")
    f["/var/log/backup/nightly.log"] = ("\n".join(lines) + "\n", 0o100644, 1001, 3)

    # auth.log: routine logins by the staff and cron/sudo, plus background scanner noise from outside
    ev = []
    base = NOW - timedelta(days=2)
    for t in _times(rng, base, 14, 1800, 9000):
        user = rng.choice(["jsmith", "mharris", "deploy"])
        ip = "10.10.10.30"             # the one staff address that really exists on the lab network
        ev.append((t, f"sshd[{rng.randint(1200, 4800)}]: Accepted publickey for {user} from {ip} port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=24))}"))
        ev.append((t + timedelta(seconds=rng.randint(40, 900)), f"sshd[{rng.randint(1200, 4800)}]: pam_unix(sshd:session): session closed for user {user}"))
    for d in range(2, 0, -1):
        t = (NOW - timedelta(days=d)).replace(hour=2, minute=15, second=1)
        ev.append((t, f"CRON[{rng.randint(900, 3000)}]: pam_unix(cron:session): session opened for user {ssh_user}(uid=1001) by (uid=0)"))
        ev.append((t + timedelta(seconds=95), f"CRON[{rng.randint(900, 3000)}]: pam_unix(cron:session): session closed for user {ssh_user}"))
    for t in _times(rng, base, 6, 6000, 20000):
        ev.append((t, f"sshd[{rng.randint(1200, 4800)}]: Invalid user {rng.choice(['admin', 'test', 'oracle', 'git'])} from 203.0.113.{rng.randint(2, 250)} port {rng.randint(30000, 60000)}"))
    ev.sort()
    f["/var/log/auth.log"] = ("\n".join(f"{t:%b %e %H:%M:%S} svr04 {m}" for t, m in ev) + "\n", 0o100640, 0, 1)

    sys_ev = []
    for t in _times(rng, NOW - timedelta(hours=30), 18, 600, 7000):
        sys_ev.append((t, rng.choice([
            "systemd[1]: Started Daily apt download activities.", "systemd[1]: Starting Daily apt upgrade and clean activities...",
            "systemd[1]: Finished Daily apt upgrade and clean activities.", "systemd-logind[612]: New session 41 of user jsmith.",
            "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=10.10.10.20 PROTO=TCP DPT=23", "rsyslogd: [origin software=\"rsyslogd\"] rsyslogd was HUPed",
            "smartd[540]: Device: /dev/sda [SAT], SMART Prefailure Attribute: 1 Raw_Read_Error_Rate changed from 100 to 99"])))
    sys_ev.sort()
    f["/var/log/syslog"] = ("\n".join(f"{t:%b %e %H:%M:%S} svr04 {m}" for t, m in sys_ev) + "\n", 0o100640, 0, 1)

    # the exports the backup job talks about; content is a short stub (the real files would be large)
    for i in range(1, 6):
        day = (NOW - timedelta(days=i)).strftime("%Y-%m-%d")
        f[f"/srv/exports/nightly/reports_{day}.csv"] = (
            "order_id,customer,total,status\n" + "\n".join(f"{40000 + i * 90 + k},C-{rng.randint(1000, 9999)},{rng.randint(20, 900)}.{rng.randint(10, 99)},{rng.choice(['paid', 'paid', 'open', 'refunded'])}" for k in range(8)) + "\n", 0o100644, 1001, i)
    f["/srv/exports/README"] = (f"Nightly exports from db-prod-01 ({db_ip}). Pulled at 01:45, packed and copied to fs-backup-01 at 02:15.\nQuestions: it-ops@corp.local\n", 0o100644, 1001, 90)

    # staff home directories with ordinary things in them
    f["/home/jsmith/.bash_history"] = ("uptime\nls\ncd projects\nls -la\nvim todo.txt\ncat todo.txt\ngit status\ngit pull\ndf -h\nexit\n", 0o100600, 1002, 4)
    f["/home/jsmith/todo.txt"] = ("- renew wildcard cert (Nov)\n- ask Maria about the Q3 export format\n- check disk on svr04, backups are getting bigger\n- holiday rota\n", 0o100644, 1002, 6)
    f["/home/jsmith/.bashrc"] = ("# ~/.bashrc\n[ -z \"$PS1\" ] && return\nHISTCONTROL=ignoredups:ignorespace\nHISTSIZE=1000\nalias ll='ls -alF'\nalias la='ls -A'\n", 0o100644, 1002, 120)
    last = (NOW - timedelta(days=1)).strftime("%Y-%m-%d")
    f["/home/mharris/.bash_history"] = (f"ls\ncd /srv/exports/nightly\nless reports_{last}.csv\nwc -l reports_{last}.csv\nexit\n", 0o100600, 1004, 3)
    f["/home/deploy/.bash_history"] = ("sudo systemctl status nginx\nsudo systemctl reload nginx\ntail -n 50 /var/log/nginx/error.log\nexit\n", 0o100600, 1003, 9)
    dl = lambda days, hm, v: f"{(NOW - timedelta(days=days)):%Y-%m-%d} {hm} deploy ok (v2.14.{v})\n"
    f["/home/deploy/deploy.log"] = (dl(16, "18:04", 1) + dl(9, "18:11", 2) + dl(2, "18:07", 3), 0o100644, 1003, 2)
    f[f"/home/{ssh_user}/README.txt"] = ("Nightly backup job: runs from this account (cron, 02:15). Owner: Tom Davies, IT operations (it-ops@corp.local).\nLogs: /var/log/backup/nightly.log\n", 0o100644, 1001, 70)
    f["/root/.viminfo"] = ("# This viminfo file was generated by Vim 8.2.\n# Last Substitute Search Pattern:\n~MSle0~&nightly\n", 0o100600, 0, 40)
    return f


def dirs(ssh_user):
    """(path, mode, uid) of directories the files above need (build.py creates missing parents on its own)."""
    return [("/var/log/backup", 0o40755, 1001), ("/srv/exports/nightly", 0o40755, 1001), ("/home/jsmith", 0o40755, 1002),
            ("/home/mharris", 0o40755, 1004), ("/home/deploy", 0o40755, 1003), (f"/home/{ssh_user}", 0o40755, 1001)]


if __name__ == "__main__":
    out = Path(sys.argv[1])
    data = files("10.10.10.21", "10.10.10.22", "10.10.10.1", "tdavies")
    for path, (content, mode, uid, age) in sorted(data.items()):
        p = out / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
        print(f"{oct(mode)} uid={uid:<5} {len(content):>5} B  {path}")
    assert not any("password" in c.lower() and "=" in c for c, *_ in data.values()), "credential-like text found"
    print(f"{len(data)} files, no credentials")

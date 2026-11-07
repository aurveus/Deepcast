#!/usr/bin/env python3
"""Deception believability: find the tells that would let an attacker notice the fake.

  python agent/believability.py lint [dir]        # contradictions inside the fake SSH server (default lab/cowrie_custom/out)
  python agent/believability.py harvest [logs..]  # illusion-break rate from real Cowrie sessions: commands the fake shell failed
  python agent/believability.py --selftest

Why this exists: deception fails quietly when the illusion breaks, an unknown command, a script that names a file or host that
does not exist, a log dated in the future, a breadcrumb that leads nowhere. Nobody notices until the attacker has already
decided it is a honeypot. Two checks, both deterministic:
  lint     static consistency of everything planted in the fake server (users, cron, hosts, addresses, paths, ports, dates, secrets)
  harvest  from real sessions: which commands did the fake shell fail to answer, and what share of all commands was that
"""
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC_NETS = [ipaddress.ip_network(n) for n in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24", "127.0.0.0/8")]   # documentation/loopback ranges
IP_RX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
PATH_RX = re.compile(r"(?<![\w.])(/(?:srv|var|usr|etc|home|opt|root)/[\w./-]+)")
DATE_RX = re.compile(r"\b(20\d\d)-(\d\d)-(\d\d)\b")


def env():
    out = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def lint(out_dir, e=None, allow=None, tokens=None, now=None):
    """Return a list of (check, detail) problems found in the built fake server under out_dir (empty list = consistent)."""
    out_dir, e = Path(out_dir), e or env()
    allow = allow or json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))
    tokens = tokens or json.loads((ROOT / "lab" / "lures" / "honeytokens.json").read_text(encoding="utf-8"))["tokens"]
    fs = out_dir / "honeyfs"
    probs = []
    files = [p for p in out_dir.rglob("*") if p.is_file() and p.suffix not in (".pickle", ".pyc")]
    text = {p: p.read_text(encoding="utf-8", errors="replace") for p in files}
    exists = lambda path: (fs / path.lstrip("/")).exists()

    # users: every login account has a home, cron jobs run as real users
    passwd = text.get(fs / "etc" / "passwd", "")
    users = {}
    for line in passwd.splitlines():
        f = line.split(":")
        if len(f) >= 7:
            users[f[0]] = (int(f[2]) if f[2].isdigit() else -1, f[5], f[6])
    for name, (uid, home, shell) in users.items():
        if 1000 <= uid < 60000 and shell.endswith(("bash", "sh")) and not exists(home):
            probs.append(("home-missing", f"account '{name}' (uid {uid}) has no home directory content at {home}"))
    cron = text.get(fs / "etc" / "crontab", "")
    for line in cron.splitlines():
        m = re.match(r"^[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+(\S+)\s+", line)
        if m and m.group(1) not in users:
            probs.append(("cron-user", f"crontab runs a job as '{m.group(1)}', who is not in /etc/passwd"))

    # Cowrie's default account 'phil' is a well-known honeypot fingerprint
    if "phil" in users:
        probs.append(("default-tell", "the default Cowrie account 'phil' is still in /etc/passwd (a known honeypot fingerprint)"))

    # the planted SSH credential must belong to a real account
    for t in tokens:
        if t["kind"] == "ssh_credential" and t["username"] not in users:
            probs.append(("lure-account", f"honeytoken {t['id']} names '{t['username']}' but that account is not in /etc/passwd"))

    # addresses: only lab addresses the platform really serves, or documentation ranges
    first = int(ipaddress.ip_address(e.get("DECOY_IP_FIRST", "10.10.10.20")))
    pool = {i: str(ipaddress.ip_address(first + t["pool_slot"])) for i, t in allow["templates"].items() if "pool_slot" in t}
    served = {e.get("HOST_IP", "10.10.10.1"), e.get("WORKSTATION_IP", "10.10.10.30"), e.get("KALI_IP", "10.10.10.10"), *pool.values()}
    for p, body in text.items():
        for ip in IP_RX.findall(body):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip in served or any(a in n for n in DOC_NETS) or a.is_unspecified or ip.endswith(".255"):
                continue
            probs.append(("unknown-address", f"{p.relative_to(out_dir)} mentions {ip}, which no service answers on and is not a documentation address"))
    hosts = text.get(fs / "etc" / "hosts", "")
    for name, tpl in (("db-prod-01", "db_decoy"), ("fs-backup-01", "smb_decoy")):
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+" + name, hosts)
        if not m:
            probs.append(("breadcrumb-missing", f"/etc/hosts does not name {name}"))
        elif m.group(1) != pool.get(tpl):
            probs.append(("breadcrumb-wrong-address", f"{name} is listed at {m.group(1)} but its decoy ({tpl}) lives at {pool.get(tpl)}"))

    # paths named in scripts, cron and READMEs must exist
    for p, body in text.items():
        if p.suffix in (".sh",) or p.name in ("crontab", "README", "README.txt") or "/usr/local/bin" in str(p):
            for path in set(PATH_RX.findall(re.sub(r"test -x \S+", "", body))):
                path = path.rstrip(".,:)")
                if not exists(path) and not exists(path.rsplit("/", 1)[0]) and not path.startswith("/var/log/auth") :
                    probs.append(("path-missing", f"{p.relative_to(out_dir)} refers to {path}, which does not exist in the fake filesystem"))

    # ports named in commands must be served by some decoy
    ports = {str(t["host_port"]) for t in allow["templates"].values() if "host_port" in t} | {e.get("COWRIE_SSH_PORT", "2222"), e.get("SMB_PORT", "4445"), e.get("WEB_PORT", "8080"), "22", "21", "23", "3306", "445"}
    for p, body in text.items():
        for m in re.finditer(r"smbclient\b[^\n]*?-p\s+(\d+)", body):
            if m.group(1) not in ports:
                probs.append(("port-unserved", f"{p.relative_to(out_dir)} uses port {m.group(1)} that no decoy serves"))

    # dates must not be later than the fake server's own clock
    if now is None:
        try:
            sys.path.insert(0, str(ROOT / "lab" / "cowrie_custom"))
            import lived_in
            now = lived_in.NOW
        except Exception:
            now = None
    if now:
        for p, body in text.items():
            for y, mo, d in DATE_RX.findall(body):
                try:
                    if datetime(int(y), int(mo), int(d)) > now.replace(hour=23, minute=59):
                        probs.append(("future-date", f"{p.relative_to(out_dir)} contains {y}-{mo}-{d}, later than the server's clock"))
                except ValueError:
                    pass

    # secrets: the only credentials in the fake server are the planted honeytokens
    planted = {t["password"] for t in tokens}
    for p, body in text.items():
        if p.name in ("passwd", "group", "hosts"):
            continue
        for m in re.finditer(r"(?i)\b(?:pass(?:word)?|pwd|secret|token)\s*[=:]\s*(\S+)", body):
            if m.group(1) not in planted:
                probs.append(("stray-secret", f"{p.relative_to(out_dir)} contains a password-like value that is not a registered honeytoken"))
    return probs


def harvest(lines):
    """Illusion-break statistics from Cowrie JSON lines: commands run, commands the fake shell could not answer, worst offenders."""
    ran, failed = Counter(), Counter()
    sessions = set()
    for raw in lines:
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        k = str(e.get("eventid", ""))
        if k == "cowrie.command.input":
            ran[str(e.get("input", ""))[:80]] += 1
            sessions.add(e.get("session"))
        elif k == "cowrie.command.failed":
            failed[str(e.get("input", ""))[:80]] += 1
    n, f = sum(ran.values()), sum(failed.values())
    return {"commands": n, "sessions": len(sessions), "failed": f, "break_rate": round(f / n, 3) if n else 0.0,
            "worst": failed.most_common(15)}


def selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        w = lambda rel, body: (d / rel).parent.mkdir(parents=True, exist_ok=True) or (d / rel).write_text(body, encoding="utf-8")
        w("honeyfs/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1002:1002::/home/alice:/bin/bash\n")
        w("honeyfs/etc/crontab", "15 2 * * * ghost /usr/local/bin/job.sh\n")
        w("honeyfs/etc/hosts", "127.0.0.1 localhost\n10.10.10.99 db-prod-01\n")
        w("honeyfs/usr/local/bin/job.sh", "#!/bin/bash\nsmbclient -p 9999 //x/y\ncp /srv/data/file /tmp/x\npassword=hunter2\n# last run 2030-01-01\n")
        e = {"HOST_IP": "10.10.10.1", "DECOY_IP_FIRST": "10.10.10.20", "WORKSTATION_IP": "10.10.10.30", "KALI_IP": "10.10.10.10"}
        allow = {"templates": {"db_decoy": {"pool_slot": 1, "host_port": 3306}, "smb_decoy": {"pool_slot": 2, "host_port": 4445}}}
        tok = [{"id": "HT-001", "kind": "ssh_credential", "username": "bob", "password": "Planted#1"}]
        got = {c for c, _ in lint(d, e, allow, tok, now=datetime(2026, 10, 18))}
        want = {"home-missing", "cron-user", "lure-account", "unknown-address", "breadcrumb-wrong-address", "breadcrumb-missing",
                "path-missing", "port-unserved", "future-date", "stray-secret"}
        assert want <= got, f"missed checks: {sorted(want - got)}"
    log = [json.dumps({"eventid": "cowrie.command.input", "session": "a", "input": "ifconfig"}),
           json.dumps({"eventid": "cowrie.command.failed", "session": "a", "input": "ifconfig"}),
           json.dumps({"eventid": "cowrie.command.input", "session": "a", "input": "ls"})]
    h = harvest(log)
    assert h["commands"] == 2 and h["failed"] == 1 and h["break_rate"] == 0.5 and h["worst"][0][0] == "ifconfig", h
    print("selftest ok")


def main():
    a = sys.argv[1:]
    if not a or a[0] == "--selftest":
        return selftest()
    sys.stdout.reconfigure(encoding="utf-8")
    if a[0] == "lint":
        out = Path(a[1]) if len(a) > 1 else ROOT / "lab" / "cowrie_custom" / "out"
        probs = lint(out)
        for c, d in probs:
            print(f"  {c:<26} {d}")
        print(f"{len(probs)} problem(s)" if probs else "consistent: no tells found")
        sys.exit(1 if probs else 0)
    if a[0] == "harvest":
        files = [Path(x) for x in a[1:]] or sorted((ROOT / "lab" / "logs").rglob("cowrie.json"))
        lines = [l for f in files for l in f.read_text(encoding="utf-8", errors="replace").splitlines()]
        print(json.dumps(harvest(lines), indent=2))
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Honeytoken detector: watches the honeypot logs for the planted (fake) credentials in lab/lures/honeytokens.json.

  python agent/honeytokens.py            # list every use found in the current logs
  python agent/honeytokens.py --follow   # keep watching, print new uses

Nothing legitimate knows these credentials, so any use means someone read a lure and acted on it. A log line is a
hit when it contains the token's username and password together ("pair"), or just the username for services that
only log a password hash such as MySQL ("username"). Used as a library by agent/watcher.py (Detector) and
agent/analyze.py / report/incident_report.py (hits_in).
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "lab" / "lures" / "honeytokens.json"
LOGS = ROOT / "lab" / "logs"


def load_tokens():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))["tokens"]


def line_epoch(o):
    for key in ("timestamp", "utc_time"):
        v = o.get(key)
        if v:
            try:
                dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
            except ValueError:
                pass
    return None


def strings_of(o):
    """Every string value in a (possibly nested) log record."""
    if isinstance(o, dict):
        for v in o.values():
            yield from strings_of(v)
    elif isinstance(o, list):
        for v in o:
            yield from strings_of(v)
    elif isinstance(o, str):
        yield o


def match(record, tokens):
    """[(token, strength)]: "pair" = username and password both seen (the planted credential was used), "username" =
    only the username (someone knows the lure's account name but guessed another password)."""
    vals = set(strings_of(record))
    out = []
    for t in tokens:
        if t["username"] in vals:
            out.append((t, "pair" if (t.get("match", "pair") == "username" or t["password"] in vals) else "username"))
    return out


def load_lure_files():
    return json.loads(REGISTRY.read_text(encoding="utf-8")).get("lure_files", [])


def lure_file_of(record, lure_files):
    """The registered lure file an `smb.open` record opened (compared by file name, case-insensitive), else None."""
    name = str(record.get("path", "")).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return next((lf for lf in lure_files if lf["path"].lower() == name), None)


def service_label(service):
    """Friendly name for the honeypot a log came from."""
    if service.startswith("decoy-"):
        kind = service.split("-")[1]
        return {"ssh": "SSH decoy", "ftp": "FTP decoy", "db": "database decoy", "admin": "web panel decoy", "smb": "SMB decoy"}.get(kind, "decoy")
    return {"cowrie": "SSH honeypot", "web": "web admin panel", "opencanary": "FTP/Telnet/MySQL honeypot", "smb": "SMB decoy"}.get(service, service)


def make_hit(t, rec, path, sessions=None, strength="pair"):
    service = path.parent.name if path.parent.parent.name != "decoys" else path.parent.name   # cowrie / web / ... or decoy name
    return {"token": t["id"], "kind": t["kind"], "username": t["username"], "planted_in": t["planted_in"],
            "usable_at": t["usable_at"], "where": t.get("where", t["planted_in"]), "service": service, "service_label": service_label(service), "log": path.name, "ts": line_epoch(rec),
            "event": rec.get("eventid") or rec.get("logtype"), "session": rec.get("session"),
            "connect_ts": (sessions or {}).get(rec.get("session")), "strength": strength}


def log_files(root=LOGS):
    return sorted(set(root.glob("*/*.json")) | set(root.glob("decoys/*/*.json")))


def session_connects(files):
    """{Cowrie session id: connect time}. A login is logged when the password is submitted, which can be many
    seconds after the TCP connection (a person typing), so attribution uses the session's connect time."""
    out = {}
    for f in files:
        if f.name != "cowrie.json":
            continue
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if '"cowrie.session.connect"' in raw:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                out[rec.get("session")] = line_epoch(rec)
    return out


def hits_in(logs_root, t0=None, t1=None):
    """All hits in a logs folder (a run's logs/ copy or lab/logs), optionally limited to a time window (epoch)."""
    tokens, out = load_tokens(), []
    files = log_files(Path(logs_root))
    sessions = session_connects(files)
    for f in files:
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            ts = line_epoch(rec)
            if t0 is not None and (ts is None or ts < t0 or ts > t1):
                continue
            out += [make_hit(t, rec, f, sessions, st) for t, st in match(rec, tokens) if st == "pair"]   # only real uses
    return out


class Detector:
    """Tails the live honeypot logs and returns new hits on each scan(). Starts at the end of the files."""

    def __init__(self, root=LOGS):
        self.root, self.tokens = root, load_tokens()
        self.lure_files = load_lure_files()
        self.reads = []                                       # lure files opened since the last drain (see take_reads)
        self.pos = {f: f.stat().st_size for f in log_files(root)}
        self.sessions = session_connects(list(self.pos))      # learn existing sessions; new ones are added as lines arrive

    def scan(self):
        hits = []
        for f in log_files(self.root):
            size = f.stat().st_size
            start = self.pos.get(f, 0)
            if size <= start:
                self.pos[f] = size
                continue
            with f.open("rb") as fh:
                fh.seek(start)
                chunk = fh.read()
            self.pos[f] = start + len(chunk)
            for raw in chunk.decode("utf-8", "replace").splitlines():
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if rec.get("eventid") == "cowrie.session.connect":
                    self.sessions[rec.get("session")] = line_epoch(rec)
                hits += [make_hit(t, rec, f, self.sessions, st) for t, st in match(rec, self.tokens)]
                if rec.get("eventid") == "smb.open":
                    lf = lure_file_of(rec, self.lure_files)
                    if lf:
                        self.reads.append({"lure_file": lf["path"], "id": lf["id"], "service": lf["service"], "where": lf["where"],
                                           "leads_to": lf["leads_to"]})
        return hits

    def take_reads(self):
        out, self.reads = self.reads, []
        return out


def main():
    if "--follow" in sys.argv:
        d = Detector()
        print("watching for honeytoken use (Ctrl+C to stop)")
        while True:
            for h in d.scan():
                print(json.dumps(h))
            time.sleep(2)
    for h in hits_in(LOGS):
        print(json.dumps(h))


if __name__ == "__main__":
    main()

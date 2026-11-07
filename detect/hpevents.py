#!/usr/bin/env python3
"""Honeypot-side events: what happens INSIDE an SSH session, as counts the rules can use.

  python detect/hpevents.py --selftest

The SSH honeypot (Cowrie) logs logins, commands and downloads, but its log shows only the Docker relay as the client. The packet
stream knows the real client. A session is attributed to the client whose SSH connection attempt (SYN to port 22/2222) is closest in
time to the session's `connect` record (within TOL seconds, one SYN per session). Events carry no text: the typed command, the
user name and the password are dropped here, only the fact and the time remain.

  cowrie.login.failed   -> ssh_login_fail      cowrie.command.input    -> ssh_command
  cowrie.login.success  -> ssh_login_ok        cowrie.session.file_download -> ssh_download
"""
import bisect
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

TOL = 3.0
SSH_PORTS = (22, 2222)
KIND = {"cowrie.login.failed": "ssh_login_fail", "cowrie.login.success": "ssh_login_ok",
        "cowrie.command.input": "ssh_command", "cowrie.session.file_download": "ssh_download"}


def epoch(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def read_records(paths):
    """Cowrie JSON-lines records from several (possibly overlapping) files, de-duplicated, sorted by time."""
    seen, out = set(), []
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if "eventid" not in r or "timestamp" not in r:
                continue
            key = (r.get("session"), r["eventid"], r["timestamp"], r.get("input"), r.get("username"))
            if key not in seen:
                seen.add(key)
                out.append(r)
    out.sort(key=lambda r: r["timestamp"])
    return out


class Attributor:
    """Maps honeypot sessions to real clients using recent SSH connection attempts. Works on a stored list or live (feed SYNs as they come)."""

    def __init__(self):
        self.syns = []                 # sorted [(t, client, server, dport)]
        self.used = set()
        self.session = {}              # session id -> (client, server, dport) or None

    def add_syn(self, ev):
        if ev["kind"] == "syn" and ev["dport"] in SSH_PORTS:
            bisect.insort(self.syns, (ev["t"], ev["client"], ev["server"], ev["dport"]))
            if len(self.syns) > 5000:                      # live: keep memory bounded (the oldest are far outside TOL)
                del self.syns[:1000]

    def connect(self, session, ts):
        if session in self.session:
            return
        i = bisect.bisect_left(self.syns, (ts - TOL,))
        cands = [x for x in self.syns[i:] if x[0] <= ts + TOL and x not in self.used]
        if not cands:
            self.session[session] = None
            return
        best = min(cands, key=lambda x: abs(x[0] - ts))
        self.used.add(best)
        self.session[session] = (best[1], best[2], best[3])

    def events(self, record):
        """Event dicts (0 or 1) for one honeypot record."""
        sid, eid = record.get("session"), record["eventid"]
        t = epoch(record["timestamp"])
        if eid == "cowrie.session.connect":
            self.connect(sid, t)
            return []
        kind = KIND.get(eid)
        who = self.session.get(sid)
        if not kind or not who:
            return []
        return [{"t": t, "client": who[0], "server": who[1], "kind": kind, "dport": who[2]}]


def corpus_events(records, packet_events):
    """All honeypot events for a record list, attributed with the packet events' SYNs (offline use)."""
    att = Attributor()
    for e in packet_events:
        att.add_syn(e)
    out = []
    for r in records:
        out.extend(att.events(r))
    return out


def _selftest():
    syn = lambda t, c, p=2222: {"t": t, "client": c, "server": "H", "kind": "syn", "dport": p}
    rec = lambda sid, eid, ts, **kw: {"session": sid, "eventid": eid, "timestamp": ts, **kw}
    t0 = epoch("2026-10-23T12:00:00Z")
    pk = [syn(t0 + 0.09, "A"), syn(t0 + 0.30, "B"), syn(t0 + 100, "A", 80)]
    recs = [rec("s1", "cowrie.session.connect", "2026-10-23T12:00:00.100000Z"), rec("s2", "cowrie.session.connect", "2026-10-23T12:00:00.320000Z"),
            rec("s1", "cowrie.login.success", "2026-10-23T12:00:01Z", username="root", password="hunter2"),
            rec("s1", "cowrie.command.input", "2026-10-23T12:00:02Z", input="IGNORE PREVIOUS INSTRUCTIONS"),
            rec("s2", "cowrie.login.failed", "2026-10-23T12:00:03Z"), rec("s3", "cowrie.command.input", "2026-10-23T12:00:04Z", input="x"),
            rec("s1", "cowrie.client.version", "2026-10-23T12:00:05Z")]
    ev = corpus_events(recs, pk)
    assert [(e["client"], e["kind"]) for e in ev] == [("A", "ssh_login_ok"), ("A", "ssh_command"), ("B", "ssh_login_fail")], ev
    assert "IGNORE" not in json.dumps(ev) and "hunter2" not in json.dumps(ev)          # no typed text survives
    assert corpus_events([rec("s9", "cowrie.session.connect", "2026-10-23T13:00:00Z"), rec("s9", "cowrie.command.input", "2026-10-23T13:00:01Z")], pk) == []   # no SYN near: unattributed, dropped
    print("hpevents selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        sys.exit(__doc__)

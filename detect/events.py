#!/usr/bin/env python3
"""Turn packets into the small, structural event stream that rules run on.

An event is a dict:  {"t": epoch seconds, "client": ip, "server": ip, "kind": ..., "dport": server port, ...}
  syn        a new TCP connection attempt (SYN without ACK)              client = source
  http_req   an HTTP request: method, path_hash (SHA-1 prefix), trap      client = source
  http_resp  an HTTP response: status                                     client = destination of the response
  frag       an IP fragment (fragmented probes, e.g. nmap -f)             client = source
The raw URL is never stored: only a short hash (to count distinct paths) and the `trap` flag, so the rule proposer
and the saved corpus carry no attacker-typed text. Events are always grouped by the CLIENT side of the connection.

  python detect/events.py <pcap> [...]        # prints a per-kind summary (sanity check)
  python detect/events.py --selftest
"""
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from rules import METHODS

ROOT = Path(__file__).resolve().parent.parent
TRAPS = tuple(json.loads((Path(__file__).parent / "traps.json").read_text(encoding="utf-8"))["path_prefixes"])

# tshark display filter and the fields we read, in order. SYN without ACK, HTTP either direction, IP fragments.
FILTER = "(tcp.flags.syn==1 && tcp.flags.ack==0) || http.request || http.response || ip.flags.mf==1 || ip.frag_offset>0"
FIELDS = ("frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
          "http.request.method", "http.request.uri", "http.response.code", "ip.flags.mf", "ip.frag_offset")


def find_tshark():
    return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"


def tshark_args(source):
    """Arguments for tshark reading `source` (pcap path, or None for live with -i given separately by the caller)."""
    args = ["-n", "-Y", FILTER, "-T", "fields", "-E", "separator=/t"]
    for f in FIELDS:
        args += ["-e", f]
    return args


def trap_path(uri):
    path = uri.split("?", 1)[0]
    return path.startswith(TRAPS)


def parse_line(line):
    """One tshark line -> event dict, or None when the line carries nothing we use."""
    f = (line.rstrip("\n").split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
    t, src, dst, sport, dport, syn, ack, method, uri, status, mf, off = f
    if not t or not src or not dst:
        return None
    try:
        t = float(t)
    except ValueError:
        return None
    if method:
        return {"t": t, "client": src, "server": dst, "kind": "http_req", "dport": _port(dport), "method": _method(method),
                "path_hash": hashlib.sha1(uri.encode("utf-8", "replace")).hexdigest()[:8], "trap": trap_path(uri)}
    if status:
        return {"t": t, "client": dst, "server": src, "kind": "http_resp", "dport": _port(sport), "status": int(status.split(",")[0])}
    if syn.split(",")[0] in ("1", "True") and ack.split(",")[0] in ("0", "False", ""):
        return {"t": t, "client": src, "server": dst, "kind": "syn", "dport": _port(dport)}
    if mf.split(",")[0] in ("1", "True") or off.split(",")[0] not in ("", "0"):
        return {"t": t, "client": src, "server": dst, "kind": "frag", "dport": None}
    return None


def _method(m):
    """Known HTTP method names only; anything else an attacker puts in the request line becomes OTHER (no attacker text is kept)."""
    m = m.split(",")[0]
    return m if m in METHODS else "OTHER"


def _port(x):
    try:
        return int(x.split(",")[0])
    except ValueError:
        return None


def pcap_events(pcaps):
    """All events of the given pcaps, sorted by time."""
    out = []
    for p in pcaps:
        r = subprocess.run([find_tshark(), "-r", str(p), *tshark_args(p)], capture_output=True, text=True, encoding="utf-8", errors="replace")
        for line in r.stdout.splitlines():
            ev = parse_line(line)
            if ev:
                out.append(ev)
    out.sort(key=lambda e: e["t"])
    return out


def save_events(events, path):
    """Compact JSON lines, gzip. One event per line."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")


def load_events(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _selftest():
    syn = parse_line("1.5\t10.0.0.5\t10.0.0.1\t4000\t22\t1\t0\t\t\t\t0\t0")
    assert syn == {"t": 1.5, "client": "10.0.0.5", "server": "10.0.0.1", "kind": "syn", "dport": 22}
    synack = parse_line("1.6\t10.0.0.1\t10.0.0.5\t22\t4000\t1\t1\t\t\t\t0\t0")
    assert synack is None
    req = parse_line("2\t10.0.0.5\t10.0.0.1\t4000\t8080\t\t\tGET\t/backup/config.bak\t\t0\t0")
    assert req["kind"] == "http_req" and req["trap"] is True and "uri" not in req and len(req["path_hash"]) == 8
    assert parse_line("2\t10.0.0.5\t10.0.0.1\t4000\t8080\t\t\tGET\t/login?x=1\t\t0\t0")["trap"] is False
    assert parse_line("2\t10.0.0.5\t10.0.0.1\t4000\t8080\t\t\tGET\t/backupfoo\t\t0\t0")["trap"] is True      # prefix match, as the lab registers it
    resp = parse_line("2.1\t10.0.0.1\t10.0.0.5\t8080\t4000\t\t\t\t\t404\t0\t0")
    assert resp == {"t": 2.1, "client": "10.0.0.5", "server": "10.0.0.1", "kind": "http_resp", "dport": 8080, "status": 404}
    assert parse_line("3\t10.0.0.5\t10.0.0.1\t\t\t\t\t\t\t\t1\t0")["kind"] == "frag"
    odd = parse_line("2	10.0.0.5	10.0.0.1	4000	8080			IGNORE-PREVIOUS-INSTRUCTIONS	/x		0	0")
    assert odd["method"] == "OTHER" and "IGNORE" not in json.dumps(odd)
    assert parse_line("") is None and parse_line("garbage") is None
    print("events selftest ok")


def main():
    if "--selftest" in sys.argv:
        return _selftest()
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    ev = pcap_events(sys.argv[1:])
    from collections import Counter
    print(len(ev), "events", dict(Counter((e["client"], e["kind"]) for e in ev)))


if __name__ == "__main__":
    main()

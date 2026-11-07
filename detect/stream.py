#!/usr/bin/env python3
"""Live fast path: tshark streams packets, the rule engine decides per packet, alerts go to the event log.

  python detect/stream.py                          # live on CAPTURE_IFACE until Ctrl+C
  python detect/stream.py --pcap a.pcap [b.pcap]   # same code path on saved packets (latency is then replay time)
  options: --rules detect/rules/baseline.json [more.json ...]   --duration SEC

No 30-second windows: tshark runs with line buffering (-l), every matching packet becomes an event at once, and
a rule that completes fires in the same second. Each alert is written to lab/logs/events.jsonl as `fast_rule_hit`
with the wall-clock delay between the packet and the alert. This process only DETECTS and LOGS. It never starts
or stops anything: acting stays with the controller and its allowlist.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "controller"))
import controller as ctl  # noqa: E402  (event log + .env)
from engine import RuleEngine  # noqa: E402
import hpevents  # noqa: E402
from events import find_tshark, parse_line, tshark_args  # noqa: E402
from rules import load_rules  # noqa: E402

PROMOTED = HERE / "rules" / "promoted.json"          # written by the promotion gate (step 3); baseline rules are always loaded
BASELINE = HERE / "rules" / "baseline.json"


def default_rule_files():
    return [BASELINE] + ([PROMOTED] if PROMOTED.exists() else [])


def alert_fields(a, now):
    return {"rule_id": a["rule_id"], "rule_name": a["rule_name"], "technique": a["technique"], "attacker_ip": a["client"],
            "observed": a["observed"], "after_first_event_s": a["latency_since_first_s"],
            "packet_to_alert_s": round(now - a["t"], 3)}


def packets(args):
    """Lines of tshark field output, as they arrive."""
    ts = find_tshark()
    if args.pcap:
        for p in args.pcap:
            proc = subprocess.Popen([ts, "-r", p, *tshark_args(p)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
            yield from proc.stdout
        return
    iface = ctl.ENV.get("CAPTURE_IFACE", "")
    if not iface or "REPLACE-WITH" in iface:
        sys.exit("Set CAPTURE_IFACE in .env (see README)")
    proc = subprocess.Popen([ts, "-i", iface, "-l", *tshark_args(None)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            encoding="utf-8", errors="replace")
    try:
        yield from proc.stdout
    finally:
        proc.terminate()


def tail_honeypot(att, feed, stop):
    """Follow the SSH honeypot logs (lab/logs/cowrie and spawned SSH decoys) and turn new records into attributed events."""
    pos = {}
    logs = ROOT / "lab" / "logs"
    while not stop.is_set():
        for f in [logs / "cowrie" / "cowrie.json", *logs.glob("decoys/decoy-ssh*/cowrie.json")]:
            try:
                size = f.stat().st_size
            except OSError:
                continue
            start = pos.setdefault(f, size)                          # begin at the end: only new activity
            if size < start:
                start = 0                                            # rotated
            if size == start:
                continue
            with f.open("rb") as fh:
                fh.seek(start)
                chunk = fh.read(size - start)
            pos[f] = start + len(chunk)
            for line in chunk.decode("utf-8", "replace").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if "eventid" in rec and "timestamp" in rec:
                    for ev in att.events(rec):
                        feed(ev)
        stop.wait(0.5)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", nargs="+")
    ap.add_argument("--pcap", nargs="+")
    ap.add_argument("--duration", type=int, default=0)
    args = ap.parse_args()
    files = [Path(f) for f in args.rules] if args.rules else default_rule_files()
    rules = [r for f in files for r in load_rules(f)]
    host = ctl.ENV.get("HOST_IP", "10.10.10.1")
    eng = RuleEngine(rules, ignore_clients=[host])
    ctl.log_event("fast_path_started", rules=[r["id"] for r in rules], mode="replay" if args.pcap else "live")
    t0, last_expire, n = time.time(), time.time(), 0
    lock, att, stop = threading.Lock(), hpevents.Attributor(), threading.Event()

    def feed(ev):
        with lock:
            alerts = eng.feed(ev)
        for a in alerts:
            ctl.log_event("fast_rule_hit", **alert_fields(a, time.time()))
    if not args.pcap:
        threading.Thread(target=tail_honeypot, args=(att, feed, stop), daemon=True).start()
    try:
        for line in packets(args):
            ev = parse_line(line)
            if not ev:
                continue
            n += 1
            with lock:
                att.add_syn(ev)
            feed(ev)
            if time.time() - last_expire > 60:
                with lock:
                    eng.expire(ev["t"])
                last_expire = time.time()
            if args.duration and time.time() - t0 > args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        ctl.log_event("fast_path_stopped", events=n)


if __name__ == "__main__":
    main()

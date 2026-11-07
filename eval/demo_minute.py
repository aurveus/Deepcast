#!/usr/bin/env python3
"""The one-minute live demo: an attacker follows the lure, and the platform reacts in front of the audience.

  python eval/demo_minute.py [--no-open] [--report PATH]

Needs the usual lab running (bash lab/up.sh, VMs on) and the watcher (python agent/watcher.py), which starts the fast path. It then:
  1. removes any spawned decoys, so the audience sees them appear,
  2. runs a 15-second attacker on Kali (attacks/demo_attack.sh): robots.txt, the forgotten /backup/ folder, the SSH account in config.bak,
     the server's hosts file, the database account in the SMB note,
  3. prints what the platform does while that runs, timed from the start of the attack: the honeytoken use seen, the fast path, the
     decoys coming up (no AI involved yet), the streaming rule, and, if it lands in time, Claude's report,
  4. prints the delay between the honeytoken use and the decoys, and opens a stored incident report of the same kind of attack
     (Claude's own analysis of a live run takes a minute or more, so the finished PDF is shown from the earlier run).
Takes about 30 s. Lab only: the attacker script checks every address against the lab range.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
import run_campaign as rc  # noqa: E402

EVENTS = ROOT / "lab" / "logs" / "events.jsonl"
DEFAULT_REPORT = ROOT / "capture" / "runs" / "live_10-10-10-10_20261026_002337" / "incident_report.pdf"


def env():
    out = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def describe(e):
    ev = e.get("event")
    if ev == "honeytoken_used":
        return f"HONEYTOKEN USED: {e.get('token')} ({e.get('username')}) on the {e.get('service_label')}: a planted fake credential, so this is someone who read the lure"
    if ev == "fast_path_policy":
        return "fast path: starting the internal servers the attacker's breadcrumbs point at (fixed policy, no AI)"
    if ev == "decoy_spawned":
        return f"DECOY UP: {e.get('template')} at {e.get('ip')}:{e.get('port')}"
    if ev == "fast_rule_hit":
        return f"streaming rule {e.get('rule_id')} fired, {e.get('packet_to_alert_s')} s after the packet"
    if ev == "watch_trigger":
        return f"triage gate opened an incident for {e.get('attacker_ip')} and wakes Claude"
    if ev == "attack_detected":
        return f"Claude confirms ({e.get('stage')}, confidence {e.get('confidence')}): {', '.join(e.get('techniques', [])[:4])}"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-open", action="store_true", help="do not open the stored incident report at the end")
    ap.add_argument("--report", default=str(DEFAULT_REPORT))
    args = ap.parse_args()
    cfg = env()
    key = os.path.expanduser(cfg.get("KALI_SSH_KEY", "~/.ssh/lab_kali"))
    kali = f"{cfg.get('KALI_USER', 'kali')}@{cfg['KALI_IP']}"
    prefix = cfg.get("LAB_SUBNET", "10.10.10.0/24").rsplit(".", 1)[0] + "."

    if not rc.watcher_alive():
        sys.exit("The watcher is not running: start it first (python agent/watcher.py); it also starts the fast path.")
    probe = subprocess.run(["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", kali, "true"], capture_output=True)
    if probe.returncode:
        sys.exit("Kali is not reachable over the lab key (bash attacks/check_kali.sh).")

    rc.killswitch()                                   # a clean slate: the audience sees the decoys appear
    seen_pos = EVENTS.stat().st_size if EVENTS.exists() else 0
    stop = threading.Event()
    log, t0 = [], time.time()

    def follow():
        pos = seen_pos
        while not stop.is_set():
            size = EVENTS.stat().st_size if EVENTS.exists() else 0
            if size > pos:
                with EVENTS.open("rb") as f:
                    f.seek(pos)
                    chunk = f.read().decode("utf-8", "replace")
                pos = size
                for line in chunk.splitlines():
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    msg = describe(e)
                    if msg:
                        log.append((datetime.fromisoformat(e["ts"]).timestamp(), e))
                        print(f"        [platform +{time.time() - t0:4.1f}s] {msg}", flush=True)
            time.sleep(0.2)

    threading.Thread(target=follow, daemon=True).start()
    print("\n=== Live: an attacker follows the lure (attacker lines first, the platform's reaction indented)\n", flush=True)
    with open(ROOT / "attacks" / "demo_attack.sh", "rb") as script:
        p = subprocess.Popen(["ssh", "-i", key, "-o", "BatchMode=yes", kali, f"LAB_PREFIX='{prefix}' LAB_TARGET='{cfg.get('HOST_IP', '10.10.10.1')}' bash -s"],
                             stdin=script, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in p.stdout:
            print("  [attacker] " + line.rstrip(), flush=True)
    p.wait()
    end = time.time() + 12                            # the decoys can still be coming up when the attacker script ends
    while time.time() < end and not {"db_decoy", "smb_decoy"} <= {e.get("template") for _, e in log if e.get("event") == "decoy_spawned"}:
        time.sleep(0.3)
    time.sleep(1)
    stop.set()

    used = [t for t, e in log if e.get("event") == "honeytoken_used"]
    decoys = [(t, e) for t, e in log if e.get("event") == "decoy_spawned"]
    print("\n=== What just happened")
    if used and decoys:
        first = min(used)
        print(f"  the honeytoken use was seen, and the decoys were up {max(0.0, min(t for t, _ in decoys) - first):.1f} s after it (first) and "
              f"{max(0.0, max(t for t, _ in decoys) - first):.1f} s after it (last): before any AI had looked at the traffic")
    elif not used:
        print("  no honeytoken use was seen (is the watcher running, and did the SSH login use the planted password?)")
    print("  Claude's own analysis of this live run, with the incident report, follows in about a minute (dashboard: Catches).")
    report = Path(args.report)
    if report.exists() and not args.no_open:
        print(f"  opening a finished incident report of the same kind of attack: {report.name}")
        os.startfile(str(report))                     # Windows default PDF viewer


if __name__ == "__main__":
    main()

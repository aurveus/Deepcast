#!/usr/bin/env python3
"""Rule-based baseline detector, for comparison with the Claude agent.

  python eval/rule_detector.py capture/runs/<run>        # prints JSON, writes <run>/rules.json

Three fixed-threshold rules over the pcap (the pcap carries the real source IP; honeypot logs only
show the Docker gateway):
  port_scan       >= 15 distinct destination ports from one source within 10 s
  ssh_bruteforce  >= 10 new connections to an SSH port (22 or 2222) from one source within 30 s
  web_probe       >= 50 HTTP requests from one source within 30 s
No state beyond the window, no learning: this is what a typical hand-written alert would do.
"""
import json
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

RULES = {  # name: (window seconds, threshold, what is counted)
    "port_scan": (10, 15, "distinct destination ports"),
    "ssh_bruteforce": (30, 10, "new connections to SSH ports"),
    "web_probe": (30, 50, "HTTP requests"),
}
SSH_PORTS = {"22", "2222"}


def tshark():
    return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"


def read_packets(pcaps):
    """Yield (epoch, src, dst_port, kind) for every new TCP connection attempt and HTTP request."""
    flt = "(tcp.flags.syn==1 && tcp.flags.ack==0) || http.request"
    for p in pcaps:
        out = subprocess.run([tshark(), "-r", str(p), "-Y", flt, "-T", "fields", "-e", "frame.time_epoch",
                              "-e", "ip.src", "-e", "tcp.dstport", "-e", "http.request.method"],
                             capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            t, src, port, method = (line.split("\t") + ["", "", "", ""])[:4]
            if t and src:
                yield float(t), src, port, ("http" if method else "syn")


def first_trigger(items, window, threshold, distinct):
    """Earliest time at which the last `window` seconds of `items` [(t, value)] reach the threshold."""
    win, counts = deque(), defaultdict(int)
    for t, v in items:
        win.append((t, v)); counts[v] += 1
        while win and win[0][0] < t - window:
            _, old = win.popleft(); counts[old] -= 1
            if not counts[old]:
                del counts[old]
        if (len(counts) if distinct else len(win)) >= threshold:
            return t
    return None


def detect(pcaps):
    by_src = defaultdict(list)
    for t, src, port, kind in sorted(read_packets(pcaps)):
        by_src[src].append((t, port, kind))
    found = []
    for src, ev in by_src.items():
        first_seen = ev[0][0]
        checks = {
            "port_scan": [(t, port) for t, port, k in ev if k == "syn"],
            "ssh_bruteforce": [(t, port) for t, port, k in ev if k == "syn" and port in SSH_PORTS],
            "web_probe": [(t, port) for t, port, k in ev if k == "http"],
        }
        for rule, items in checks.items():
            window, threshold, what = RULES[rule]
            t = first_trigger(items, window, threshold, distinct=(rule == "port_scan"))
            if t is not None:
                found.append({"rule": rule, "attacker_ip": src, "triggered_at": t, "first_seen": first_seen,
                              "time_to_detect_s": round(t - first_seen, 2),
                              "evidence": f">= {threshold} {what} within {window} s"})
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run = Path(sys.argv[1]).resolve()
    pcaps = sorted((run / "pcaps").glob("*.pcap"))
    result = {"run_id": run.name, "detections": detect(pcaps)}
    (run / "rules.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

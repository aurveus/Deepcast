#!/usr/bin/env python3
"""Continuous monitoring: capture in rolling windows, triage, analyze, act, report. No manual runs.

  python agent/watcher.py                          # live: capture the lab interface until Ctrl+C
  python agent/watcher.py --offline <pcap> [...]   # test: replay saved pcaps as if they were arriving live
  options: --window 30  --no-controller  --no-stream (live mode also starts detect/stream.py unless this is given)

How it works
  1. tshark writes WINDOW-second pcap files into capture/live (ring buffer).
  2. Every closed window gets a cheap tshark count per source (new connections per port, HTTP requests).
  3. Triage gate: if a source over the last LOOKBACK windows touches many ports, makes many connections to
     one port, many SSH connections or many HTTP requests, an INCIDENT is opened for it. The gate only decides
     when to wake the analysis agent; Claude still makes the actual call (a clean verdict ends the incident
     and silences that source for COOLDOWN seconds).
  4. The incident folder (capture/runs/live_<ip>_<time>) collects that source's windows plus the honeypot logs.
     agent/analyze.py -> controller (--auto, allowlist + limits apply) -> report/incident_report.py.
     While the source stays active the incident is re-analyzed every REANALYZE seconds (escalation is caught),
     and closed after QUIET seconds without traffic from it.
Times use the capture's own clock (window file names), so offline replays behave like live runs.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "controller"))
sys.path.insert(0, str(ROOT / "agent"))
import controller as ctl  # noqa: E402  (event log + .env loader + allowlist)
from analyze import find_tshark  # noqa: E402
from attribution import SKEW, attribute_hit, service_times  # noqa: E402
import aliases as spoof  # noqa: E402
from honeytokens import Detector  # noqa: E402

ENV = ctl.ENV
cfg = lambda k, d: int(os.environ.get(k, ENV.get(k, d)))
WINDOW, LOOKBACK = cfg("WATCH_WINDOW", 30), cfg("WATCH_LOOKBACK", 6)
REANALYZE, QUIET, COOLDOWN = cfg("WATCH_REANALYZE", 120), cfg("WATCH_QUIET", 90), cfg("WATCH_COOLDOWN", 300)
GATE_PORTS, GATE_CONNS, GATE_SSH, GATE_HTTP = cfg("GATE_PORTS", 8), cfg("GATE_CONNS", 60), cfg("GATE_SSH", 10), cfg("GATE_HTTP", 60)
HOST_IP = ENV.get("HOST_IP", "10.10.10.1")
LIVE_DIR = ROOT / "capture" / "live"
ARCHIVE = ROOT / "capture" / "archive"                  # recorder: every closed window is kept (benign corpus + attack replays), oldest pruned past the cap
ARCHIVE_MB = cfg("WATCH_ARCHIVE_MB", 1024)              # 0 turns the recorder off
STATUS = ROOT / "lab" / "logs" / "run_status.json"
MIN_CONF = ctl.ALLOWLIST["min_confidence"]
TSHARK = find_tshark()
T0 = time.time()
SPOOF_IGNORE = spoof.ignore_set(ENV)
SPOOF_SEEN = set()


def write_status(**kw):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps({"stage": "watching", "mode": "continuous", "name": "continuous monitoring", "started": T0,
                                  "updated": time.time(), "window": WINDOW, **kw}), encoding="utf-8")


def file_start(f):
    """Window start time from the file name (tshark/editcap use local time: <prefix>_<n>_YYYYmmddHHMMSS.pcap)."""
    m = re.search(r"_(\d{14})\.pcap$", f.name)
    return time.mktime(time.strptime(m.group(1), "%Y%m%d%H%M%S")) if m else f.stat().st_mtime


def is_decoy_address(ip):
    """Spawned decoys answer from their own addresses (DECOY_IP_FIRST..LAST in .env); they are never a source to track."""
    try:
        a, b, c = (int(x) for x in ip.split(".")[-1:] + [ENV.get("DECOY_IP_FIRST", "10.10.10.20").split(".")[-1], ENV.get("DECOY_IP_LAST", "10.10.10.29").split(".")[-1]])
        same_net = ip.rsplit(".", 1)[0] == ENV.get("DECOY_IP_FIRST", "10.10.10.20").rsplit(".", 1)[0]
        return same_net and b <= a <= c
    except ValueError:
        return False


def window_stats(pcap):
    """Per source: new TCP connections per destination port, and HTTP request count."""
    out = subprocess.run([TSHARK, "-r", str(pcap), "-Y", "(tcp.flags.syn==1 && tcp.flags.ack==0) || http.request", "-T", "fields",
                          "-e", "ip.src", "-e", "tcp.dstport", "-e", "http.request.method"], capture_output=True, text=True).stdout
    stats = {}
    for line in out.splitlines():
        src, _, rest = line.partition("\t")
        port, _, method = rest.partition("\t")
        if not src:
            continue
        s = stats.setdefault(src, {"ports": Counter(), "http": 0})
        if method:
            s["http"] += 1
        else:
            s["ports"][port] += 1
    # Established traffic counts as activity too. Only new connections and HTTP requests used to be counted, so a person typing in an open
    # SSH session (or copying files over SMB) looked quiet: the incident closed while they were still working and those windows were
    # copied into no report. Sources with only established packets get empty counts, so they never trip the gate on their own.
    pk = subprocess.run([TSHARK, "-r", str(pcap), "-Y", f"ip.src!={HOST_IP}", "-T", "fields", "-e", "ip.src"], capture_output=True, text=True).stdout.split()
    for src, n in Counter(pk).items():
        if is_decoy_address(src):
            continue
        stats.setdefault(src, {"ports": Counter(), "http": 0})["pkts"] = n
    suspects = [ip for ip in stats if ip not in SPOOF_IGNORE]
    if len(suspects) >= 2:                              # spoofed decoy sources of one scan must not open incidents of their own
        for alias, primary in spoof.find_aliases([pcap], SPOOF_IGNORE).items():
            if alias in stats:
                del stats[alias]
                if (alias, primary) not in SPOOF_SEEN:
                    SPOOF_SEEN.add((alias, primary))
                    ctl.log_event("spoofed_source_merged", attacker_ip=primary, alias=alias, reason="shares the Ethernet address of the scanning source and sent only unanswered SYNs")
    return stats


def gate_reasons(agg):
    r = []
    if len(agg["ports"]) >= GATE_PORTS:
        r.append(f"{len(agg['ports'])} distinct ports")
    if agg["ports"] and max(agg["ports"].values()) >= GATE_CONNS:
        r.append(f"{max(agg['ports'].values())} connections to one port")
    ssh = agg["ports"].get("22", 0) + agg["ports"].get("2222", 0)
    if ssh >= GATE_SSH:
        r.append(f"{ssh} SSH connections")
    if agg["http"] >= GATE_HTTP:
        r.append(f"{agg['http']} HTTP requests")
    return r


def archive_window(f):
    """Recorder: keep a copy of every closed live window so benign traffic (and everything else) can be replayed and labeled later."""
    if not ARCHIVE_MB:
        return
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    shutil.copy2(f, ARCHIVE / f.name)
    if STATE["windows"] % 20 == 0:
        files = sorted(ARCHIVE.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        while files and total > ARCHIVE_MB * 1024 * 1024:
            total -= files[0].stat().st_size
            files.pop(0).unlink()


def copy_logs(dest):
    """Honeypot logs are copied whole (like save_run.sh); analyze.py windows them to the incident's pcap times."""
    logs = ROOT / "lab" / "logs"
    for f in [*logs.glob("*/*.json"), *logs.glob("decoys/*/*.json")]:
        d = dest / "logs" / (f.parent.relative_to(logs).as_posix())
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, d / f.name)


def run(cmd, timeout=900):
    return subprocess.run([sys.executable, *cmd], capture_output=True, text=True, timeout=timeout, cwd=ROOT)


def process(inc, clock, act):
    """Analyze the incident folder, act on it, write the report. True if the agent confirmed an attacker."""
    d = inc["dir"]
    copy_logs(d)
    write_status(activity=f"analyzing {inc['ip']}", open_incidents=[i for i in OPEN], windows=STATE["windows"])
    r = run([str(ROOT / "agent" / "analyze.py"), str(d)])
    inc["last_analysis"], inc["dirty"] = clock, False
    if r.returncode != 0:
        ctl.log_event("watch_error", ip=inc["ip"], where="analysis", error=(r.stderr or r.stdout).strip()[-200:])
        inc["dirty"] = True                           # keep it pending: retried on the next cycle and once more when the incident closes
        return None
    result = json.loads((d / "analysis.json").read_text(encoding="utf-8"))
    hits = [a for a in result["analyses"] if a["attacker_ip"] == inc["ip"] and a["confidence"] >= MIN_CONF]
    if not hits:
        return False
    if act:
        run([str(ROOT / "controller" / "controller.py"), "apply", str(d), "--auto"])
    run([str(ROOT / "report" / "incident_report.py"), str(d)])
    return True


OPEN = {}
PENDING = []   # honeytoken uses waiting for the pcap window that contains them (to learn the real source IP)
CLOSED = {}   # ip -> (incident dir, time closed): a source returning soon continues the same incident
STATE = {"windows": 0}
MERGE_WITHIN = cfg("WATCH_MERGE", 600)    # a source returning within this many seconds continues its closed incident (evaluation campaigns set it low so each scenario is its own incident)


def open_incident(ip, reason, start, clock, recent):
    """Open (or continue) the incident folder for a source and log why."""
    prev = CLOSED.get(ip)
    if prev and clock - prev[1] <= MERGE_WITHIN:          # same attacker back after a quiet spell (slow scans do this)
        d = prev[0]
    else:
        d = ROOT / "capture" / "runs" / f"live_{ip.replace('.', '-')}_{time.strftime('%Y%m%d_%H%M%S', time.localtime(start))}"
    (d / "pcaps").mkdir(parents=True, exist_ok=True)
    for _, st, wf in recent:
        if ip in st:
            shutil.copy2(wf, d / "pcaps" / wf.name)
    OPEN[ip] = {"ip": ip, "dir": d, "last_active": clock, "last_analysis": -1, "dirty": True, "opened": clock}
    ctl.log_event("watch_trigger", attacker_ip=ip, reasons=reason, run_id=d.name)


def attribute_honeytokens(f, start, recent, clock):
    """Match pending honeytoken uses to the real source IP using this (now closed) window's pcap, then open an incident."""
    # Only once the window holding the use (plus the clock-skew margin) is closed: attributing earlier misses the real source's
    # SYN, which sits in a still-open window, and lets a routine connection a few seconds before it win the nearest-match.
    due = [h for h in PENDING if h["ts"] is not None and h["ts"] + SKEW < start + WINDOW]
    if not due:
        return
    times = service_times([wf for _, _, wf in recent])      # the connection may have started in an earlier window
    for h in due:
        PENDING.remove(h)
        ip = attribute_hit(h, times)
        if not ip or ip == HOST_IP:
            ctl.log_event("honeytoken_unattributed", token=h["token"], service=h["service"], service_label=h["service_label"], username=h["username"], planted_in=h["planted_in"], where=h["where"])
            continue
        ctl.log_event("honeytoken_attributed", token=h["token"], attacker_ip=ip, service=h["service"], service_label=h["service_label"],
                      planted_in=h["planted_in"], where=h["where"], username=h["username"], hit_time=h["ts"])
        if ip not in OPEN:
            open_incident(ip, f"honeytoken {h['token']} used ({h['planted_in']})", start, clock, recent)


def handle_window(f, recent, cooldown, act):
    stats = window_stats(f)
    start = file_start(f)
    clock = start + WINDOW
    recent.append((start, stats, f))
    STATE["windows"] += 1
    for ip, inc in OPEN.items():                      # open incidents collect every window their source appears in
        if ip in stats:
            shutil.copy2(f, inc["dir"] / "pcaps" / f.name)
            inc["last_active"], inc["dirty"] = clock, True
    attribute_honeytokens(f, start, recent, clock)
    agg = {}
    for _, st, _ in recent:
        for ip, s in st.items():
            a = agg.setdefault(ip, {"ports": Counter(), "http": 0})
            a["ports"].update(s["ports"]); a["http"] += s["http"]
    for ip, a in agg.items():
        if ip == HOST_IP or ip in OPEN or cooldown.get(ip, 0) > clock:
            continue
        reasons = gate_reasons(a)
        if not reasons:
            continue
        open_incident(ip, "; ".join(reasons), start, clock, recent)
    return clock


def housekeeping(clock, cooldown, act):
    for ip in list(OPEN):
        inc = OPEN[ip]
        closing = clock - inc["last_active"] >= QUIET
        if inc["dirty"] and (inc["last_analysis"] < 0 or closing or clock - inc["last_analysis"] >= REANALYZE):
            verdict = process(inc, clock, act)
            if verdict is False:                      # agent says benign: close and stay quiet about this source for a while
                cooldown[ip] = clock + COOLDOWN
                ctl.log_event("watch_triage_clean", attacker_ip=ip, run_id=inc["dir"].name)
                del OPEN[ip]
                continue
        if closing:
            ctl.log_event("incident_closed", attacker_ip=ip, run_id=inc["dir"].name)
            CLOSED[ip] = (inc["dir"], clock)
            del OPEN[ip]


def live_capture():
    iface = ENV.get("CAPTURE_IFACE", "")
    if not iface or "REPLACE-WITH" in iface:
        sys.exit("Set CAPTURE_IFACE in .env (see README)")
    LIVE_DIR.mkdir(parents=True, exist_ok=True)
    for old in LIVE_DIR.glob("*.pcap"):
        old.unlink()
    return subprocess.Popen([TSHARK, "-i", iface, "-F", "pcap", "-w", str(LIVE_DIR / "live.pcap"), "-b", f"duration:{WINDOW}",
                             "-b", "files:60"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def honeytoken_loop(det, act, stop):
    """Tail the honeypot logs on a thread of its own. The fast path must not wait for a Claude analysis (30-40 s with the controller and
    the report) that the main loop may be busy with: a two-attacker test showed honeytoken use being seen 28 s late for that reason."""
    while not stop.is_set():
        try:
            for h in det.scan():
                if h["strength"] == "username":                   # right account name, other password: informational only
                    ctl.log_event("honeytoken_username_tried", token=h["token"], service=h["service"], service_label=h["service_label"],
                                  username=h["username"], planted_in=h["planted_in"], where=h["where"])
                    continue
                ctl.log_event("honeytoken_used", token=h["token"], service=h["service"], service_label=h["service_label"], username=h["username"],
                              planted_in=h["planted_in"], where=h["where"], usable_at=h["usable_at"])
                PENDING.append(h)                                 # attributed when its window closes (main loop)
                if act:                                           # seconds, not the ~40 s of a Claude round trip: fixed policy from the allowlist
                    ctl.fast_respond(h["token"], source="watcher")
            for r in det.take_reads():                            # the note naming the database host was opened: the host must exist before it is tried
                ctl.log_event("lure_file_read", lure_file=r["lure_file"], lure_id=r["id"], service=r["service"], where=r["where"], leads_to=r["leads_to"])
                if act:
                    ctl.fast_respond_read(r["lure_file"], source="watcher")
        except Exception as e:                                    # never let a bad log line end the fast path
            ctl.log_event("watch_error", where="honeytoken_loop", error=str(e)[:200])
        stop.wait(1)


def stream_running():
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' } | ForEach-Object { $_.CommandLine }"],
                             capture_output=True, text=True).stdout.replace("\\", "/")
    except OSError:
        return False
    return "detect/stream.py" in out


def start_stream():
    """The fast path (detect/stream.py: streaming rules, only detects and logs) runs beside the watcher: one command starts both."""
    if stream_running():                       # started by hand earlier: a second copy would log every alert twice
        print("detect/stream.py is already running; not starting another", file=sys.stderr)
        return None
    out = open(ROOT / "lab" / "logs" / "live_stream.out", "ab")
    return subprocess.Popen([sys.executable, str(ROOT / "detect" / "stream.py")], cwd=ROOT, stdout=out, stderr=out)


def stop_stream(proc):
    if proc and proc.poll() is None:
        if sys.platform == "win32":            # stream.py runs its own tshark: end the whole tree or it keeps capturing
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def stop_capture(proc):
    if proc:
        subprocess.run(["taskkill", "/IM", "tshark.exe", "/F"], capture_output=True)
        subprocess.run(["taskkill", "/IM", "dumpcap.exe", "/F"], capture_output=True)


def main():
    global WINDOW
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", nargs="+", help="replay these pcaps as arriving windows (testing)")
    ap.add_argument("--window", type=int, default=WINDOW)
    ap.add_argument("--duration", type=int, default=0, help="live mode: stop after N seconds (0 = until Ctrl+C)")
    ap.add_argument("--stop-file", help="live mode: stop cleanly when this file appears (used by eval/run_campaign.py)")
    ap.add_argument("--no-controller", action="store_true", help="analyze and report but do not spawn decoys")
    ap.add_argument("--no-stream", action="store_true", help="live mode: do not start the streaming fast path (detect/stream.py) beside the watcher")
    args = ap.parse_args()
    WINDOW, act = args.window, not args.no_controller

    stream = None
    proc, recent, cooldown, seen, clock = None, deque(maxlen=LOOKBACK), {}, set(), 0
    if args.offline:
        LIVE_DIR.mkdir(parents=True, exist_ok=True)
        for old in LIVE_DIR.glob("*.pcap"):
            old.unlink()
        editcap = shutil.which("editcap") or str(Path(TSHARK).with_name("editcap.exe"))
        for i, p in enumerate(args.offline):
            subprocess.run([editcap, "-i", str(WINDOW), p, str(LIVE_DIR / f"off{i}.pcap")], check=True, capture_output=True)
    else:
        proc = live_capture()
        stream = None if args.no_stream else start_stream()
    det = None if args.offline else Detector()
    hp_stop = threading.Event()
    if det:
        threading.Thread(target=honeytoken_loop, args=(det, act, hp_stop), daemon=True).start()
    ctl.log_event("watch_started", window=WINDOW, mode="offline" if args.offline else "live")
    try:
        while True:
            files = sorted(LIVE_DIR.glob("*.pcap"), key=lambda f: (file_start(f), f.name))
            ready = files if args.offline else files[:-1]           # live: the newest file is still being written
            new = [f for f in ready if f not in seen]
            for f in new:
                seen.add(f)
                if not args.offline:
                    archive_window(f)
                clock = handle_window(f, recent, cooldown, act)
                housekeeping(clock, cooldown, act)
                srcs = {ip for _, st, _ in recent for ip in st if ip != HOST_IP}
                write_status(windows=STATE["windows"], sources=sorted(srcs), open_incidents=sorted(OPEN),
                             activity="watching" if not OPEN else "tracking " + ", ".join(sorted(OPEN)))
            if args.offline and not new:
                clock += QUIET + 1                                   # the replay ended: let open incidents go quiet and close
                housekeeping(clock, cooldown, act)
                if not OPEN:
                    break
            if not args.offline:
                if args.duration and time.time() - T0 > args.duration:
                    break
                if args.stop_file and Path(args.stop_file).exists():
                    break
                time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        for ip in list(OPEN):
            ctl.log_event("incident_closed", attacker_ip=ip, run_id=OPEN[ip]["dir"].name, reason="watcher stopped")
        hp_stop.set()
        stop_capture(proc)
        stop_stream(stream)
        ctl.log_event("watch_stopped", windows=STATE["windows"])
        STATUS.write_text(json.dumps({"stage": "idle"}), encoding="utf-8")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""One command: run an unattended attack campaign from Kali against the live platform and score it.

  python eval/run_campaign.py [--runs 5] [--idle 3] [--seed S] [--only portscan,sshbrute,...] [--gap-min 120 --gap-max 300]

  python eval/run_campaign.py --resume [--runs 5 --idle 3] [--dry-run]
      Reads every earlier log in attacks/logs/campaign_*.jsonl, counts the scenarios that already have a valid
      result (Claude was available; a genuine miss counts as a result), and runs only the missing ones plus the
      ones lost to a Claude outage. Everything is scored together at the end.

Needs: lab up (bash lab/up.sh), VMs on, workstation traffic generator running, host->Kali key SSH working
(bash attacks/check_kali.sh). Starts the watcher itself unless one is already running. While the campaign
runs, a reaper removes the spawned decoys after each incident closes, so every scenario is scored on its own
(the allowlist spawns one decoy per type, which would otherwise hide later detections). At the end the
decoys are removed, the watcher is stopped cleanly, and eval/campaign_eval.py writes eval/results/campaign.{json,md}.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Git Bash. A bare "bash" on Windows can resolve to System32\bash.exe (the WSL launcher), which fails when no WSL distribution is installed.
BASH = next((p for p in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")) if p and Path(p).exists()), "bash")
sys.path.insert(0, str(ROOT / "eval"))
import campaign_eval  # noqa: E402

EVENTS = ROOT / "lab" / "logs" / "events.jsonl"
STATUS = ROOT / "lab" / "logs" / "run_status.json"
STOP = ROOT / "lab" / "logs" / "watcher.stop"
SETTLE = 900          # seconds to wait after the last attack for the final incident to be analyzed and closed


ATTACKS = ("portscan", "slowscan", "sshbrute", "webprobe", "lure", "dirbrute", "stealthscan", "traverse", "overlap")


MIN_GAP = 150


def all_logs():
    return sorted((ROOT / "attacks" / "logs").glob("campaign_*.jsonl"))


def resume_plan(runs, idle):
    """Scenarios still needed to reach `runs` valid results per attack and `idle` benign windows."""
    logs = all_logs()
    valid = {}
    if logs:
        rows, _, _ = campaign_eval.evaluate(logs)
        for r in rows:
            if not r["excluded"]:      # lost to a Claude outage or merged into another incident = not valid
                valid[r["scenario"]] = valid.get(r["scenario"], 0) + 1
    want = {**{s: runs for s in ATTACKS}, "idle": idle}
    return {s: n - valid.get(s, 0) for s, n in want.items() if n - valid.get(s, 0) > 0}, valid


def capture_running():
    """True if a WATCHER process exists. (Checking for tshark alone is wrong: detect/stream.py runs its own tshark, and a stopped watcher
    leaves a fresh-looking status file for ~90 s; on 2026-10-23 that made a campaign believe a watcher was running when none was, so the
    whole Claude path went unmeasured.)"""
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' } | ForEach-Object { $_.CommandLine }"],
                             capture_output=True, text=True).stdout.replace("\\", "/")
    except OSError:
        return True                                    # cannot tell: trust the status file
    return "agent/watcher.py" in out


def watcher_alive():
    try:
        fresh = time.time() - json.loads(STATUS.read_text(encoding="utf-8")).get("updated", 0) < 90
    except (OSError, ValueError):
        return False
    return fresh and capture_running()


def open_incidents():
    try:
        return json.loads(STATUS.read_text(encoding="utf-8")).get("open_incidents", [])
    except (OSError, ValueError):
        return []


def killswitch():
    subprocess.run([sys.executable, str(ROOT / "controller" / "controller.py"), "killswitch"], capture_output=True, cwd=ROOT)


def reaper(stop):
    """Remove all spawned decoys each time an incident closes (so the next scenario starts from a clean slate)."""
    seen = EVENTS.stat().st_size if EVENTS.exists() else 0
    while not stop.is_set():
        time.sleep(10)
        size = EVENTS.stat().st_size if EVENTS.exists() else 0
        if size <= seen:
            continue
        with EVENTS.open("rb") as f:
            f.seek(seen)
            chunk = f.read().decode("utf-8", "replace")
        seen = size
        if '"incident_closed"' in chunk:
            killswitch()
            seen = EVENTS.stat().st_size            # skip the killswitch event we just caused


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--idle", type=int, default=3)
    ap.add_argument("--seed", type=int, default=int(time.time()) % 100000)
    ap.add_argument("--idle-sec", type=int, help="length of one benign-only window in seconds (default 180)")
    ap.add_argument("--only")
    ap.add_argument("--resume", action="store_true", help="run only what is missing or was lost to a Claude outage")
    ap.add_argument("--dry-run", action="store_true", help="with --resume: show the plan and stop")
    ap.add_argument("--gap-min", type=int)
    ap.add_argument("--gap-max", type=int)
    args = ap.parse_args()
    # The watcher closes an incident after WATCH_QUIET (90 s) of silence. Shorter gaps chain every scenario into one endless
    # incident: reports turn cumulative, decoys are "already running" and most runs become unscorable (2026-10-27 run).
    if args.gap_min is not None and args.gap_min < MIN_GAP:
        sys.exit(f"--gap-min {args.gap_min} is below {MIN_GAP} s: scenarios would merge into one incident (watcher WATCH_QUIET is 90 s)")

    plan = None
    if args.resume:
        plan, valid = resume_plan(args.runs, args.idle)
        print("valid results so far:", valid or "none")
        print("still to run:", plan or "nothing, the campaign is complete")
        if args.dry_run or not plan:
            if not plan and all_logs():
                campaign_eval.main.__globals__["sys"].argv = ["campaign_eval.py", *map(str, all_logs())]
                campaign_eval.main()
            return
    elif args.dry_run:
        sys.exit("--dry-run needs --resume")

    watcher = None
    if watcher_alive():
        print("using the watcher that is already running")
    else:
        STOP.unlink(missing_ok=True)
        env = {**os.environ, "WATCH_MERGE": "60"}      # each campaign scenario must be its own incident, or reports cannot be scored per scenario
        watcher = subprocess.Popen([sys.executable, str(ROOT / "agent" / "watcher.py"), "--stop-file", str(STOP)], cwd=ROOT, env=env)
        time.sleep(15)
        if watcher.poll() is not None:
            sys.exit("watcher failed to start (is the capture interface set in .env?)")
    killswitch()
    stop = threading.Event()
    threading.Thread(target=reaper, args=(stop,), daemon=True).start()

    if plan:
        cmd = [BASH, str(ROOT / "attacks" / "run_campaign.sh"), "--plan", ",".join(f"{s}:{n}" for s, n in plan.items()), "--seed", str(args.seed)]
    else:
        cmd = [BASH, str(ROOT / "attacks" / "run_campaign.sh"), "--runs", str(args.runs), "--idle", str(args.idle), "--seed", str(args.seed)]
    for flag, val in (("--idle-sec", args.idle_sec), ("--only", None if plan else args.only), ("--gap-min", args.gap_min), ("--gap-max", args.gap_max)):
        if val is not None:
            cmd += [flag, str(val)]
    print("campaign:", " ".join(cmd[2:]), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    sys.stderr.write(r.stderr[-2000:])
    log = r.stdout.strip().splitlines()[-1:] if r.stdout.strip() else []
    if not log or not (ROOT / log[0]).exists():
        sys.exit("campaign did not produce a ground-truth log (see above)")

    print("campaign finished; waiting for the last incident to close ...", flush=True)
    end = time.time() + SETTLE
    time.sleep(60)
    while open_incidents() and time.time() < end:
        time.sleep(10)
    stop.set()
    killswitch()
    if watcher:
        STOP.touch()
        try:
            watcher.wait(timeout=120)
        except subprocess.TimeoutExpired:
            watcher.terminate()
        STOP.unlink(missing_ok=True)

    sys.argv = ["campaign_eval.py", *(map(str, all_logs()) if args.resume else [log[0]])]
    campaign_eval.main()
    if r.returncode:
        print(f"note: the campaign script exited with code {r.returncode}")


if __name__ == "__main__":
    main()

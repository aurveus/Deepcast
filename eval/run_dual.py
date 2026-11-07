#!/usr/bin/env python3
"""One command: run the two-attacker test from Kali against the live platform and score it.

  python eval/run_dual.py [--b-delay 25]

Needs: lab up (bash lab/up.sh), VMs on, workstation traffic generator running, host->Kali key SSH working
(bash attacks/check_kali.sh), and the second attacker address on Kali (once, by hand, not persistent):
  sudo ip addr add 10.10.10.11/24 dev eth0        (KALI_IP2 in .env)
Starts the watcher itself unless one is already running, waits for both incidents to close, removes the spawned decoys, stops
the watcher it started and writes eval/results/dual_<time>.{json,md} (see eval/dual_eval.py for the checks).
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Git Bash. A bare "bash" on Windows can resolve to System32\bash.exe (the WSL launcher), which fails when no WSL distribution is installed.
BASH = next((p for p in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")) if p and Path(p).exists()), "bash")
sys.path.insert(0, str(ROOT / "eval"))
import dual_eval  # noqa: E402
import run_campaign as rc  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--b-delay", type=int, default=25, help="seconds attacker B waits after A starts")
    args = ap.parse_args()

    watcher = None
    if rc.watcher_alive():
        print("using the watcher that is already running")
    else:
        rc.STOP.unlink(missing_ok=True)
        env = {**os.environ, "WATCH_MERGE": "60"}      # keep this run's incidents separate from earlier ones
        watcher = subprocess.Popen([sys.executable, str(ROOT / "agent" / "watcher.py"), "--stop-file", str(rc.STOP)], cwd=ROOT, env=env)
        time.sleep(15)
        if watcher.poll() is not None:
            sys.exit("watcher failed to start (is the capture interface set in .env?)")
    rc.killswitch()

    print("two attackers starting (A: port scan + SSH brute force; B: web lure, planted credential, SSH walk)", flush=True)
    r = subprocess.run([BASH, str(ROOT / "attacks" / "run_dual.sh"), "--b-delay", str(args.b_delay)], capture_output=True, text=True, cwd=ROOT)
    sys.stderr.write(r.stderr[-2000:])
    out = r.stdout.strip().splitlines()[-1:] if r.stdout.strip() else []
    if not out or not (ROOT / out[0]).exists():
        if watcher:
            rc.STOP.touch()
        sys.exit("the run did not produce a ground-truth log (see above)")

    print("attacks finished; waiting for the incidents to close ...", flush=True)
    end = time.time() + rc.SETTLE
    time.sleep(60)
    while rc.open_incidents() and time.time() < end:
        time.sleep(10)
    rc.killswitch()
    if watcher:
        rc.STOP.touch()
        try:
            watcher.wait(timeout=120)
        except subprocess.TimeoutExpired:
            watcher.terminate()
        rc.STOP.unlink(missing_ok=True)

    sys.argv = ["dual_eval.py", out[0]]
    code = dual_eval.main()
    if r.returncode:
        print(f"note: the attack script exited with code {r.returncode}")
    sys.exit(code or 0)


if __name__ == "__main__":
    main()

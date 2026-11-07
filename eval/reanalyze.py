#!/usr/bin/env python3
"""Re-analyze stored incidents with the CURRENT prompt/facts and compare with the verdicts stored at the time.

  python eval/reanalyze.py [--benign-since 20261023_18] [--attack-types lure,traverse,...] [--workers 3]

Used to check a change of the analysis prompt, the attacker-memory facts or the triage gate without running new attacks:
  benign set  every stored workstation incident (capture/runs/live_<workstation>_*) from the given file-name prefix on
  attack set  for each attack type the latest campaign run that has a stored incident folder
Each folder is COPIED to a scratch directory first (the stored analysis.json is never overwritten) and analyzed with
DECEPTION_NO_EVENTS=1 (the shared event log is not touched). Attacker memory is rebuilt "as of" the incident time.
A benign source that comes back listed with confidence >= the controller threshold is a false alarm; an attack set run whose attacker
address is missing is a miss. Writes eval/results/reanalysis.json and prints a summary.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "controller"))
sys.path.insert(0, str(ROOT / "eval"))
import controller as ctl  # noqa: E402
import campaign_eval  # noqa: E402

ENV = ctl.ENV
MIN_CONF = ctl.ALLOWLIST["min_confidence"]
KALI, WS = ENV.get("KALI_IP", "10.10.10.10"), ENV.get("WORKSTATION_IP", "10.10.10.30")


def verdict(folder):
    try:
        a = json.loads((folder / "analysis.json").read_text(encoding="utf-8"))["analyses"]
    except (OSError, ValueError, KeyError):
        return None
    return sorted(({"ip": x["attacker_ip"], "confidence": x["confidence"], "stage": x["stage"]} for x in a if x["confidence"] >= MIN_CONF), key=lambda x: x["ip"])


def attack_folders(types):
    """{type: run folder} - the latest valid campaign run per type, matched to the incident folder by trigger time."""
    triggers = []
    for line in (ROOT / "lab" / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") == "watch_trigger" and e.get("attacker_ip") == KALI:
            triggers.append((campaign_eval.ts(e["ts"]), e["run_id"]))
    runs = json.loads((ROOT / "eval" / "results" / "campaign.json").read_text(encoding="utf-8"))["runs"]
    out = {}
    for typ in types:
        for r in sorted((r for r in runs if r["scenario"] == typ and r.get("trigger")), key=lambda r: -r["t0"]):
            cands = [(abs(t - r["trigger"]), rid) for t, rid in triggers if abs(t - r["trigger"]) < 5 and (ROOT / "capture" / "runs" / rid / "pcaps").exists()]
            if cands:
                out[typ] = ROOT / "capture" / "runs" / min(cands)[1]
                break
    return out


def analyze(item, work):
    label, kind, src = item
    dst = work / src.name
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("analysis*.json", "incident_report*"))
    env = {**os.environ, "DECEPTION_NO_EVENTS": "1", "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run([sys.executable, str(ROOT / "agent" / "analyze.py"), str(dst)], capture_output=True, text=True, env=env, cwd=ROOT, timeout=1500)
    new = verdict(dst) if r.returncode == 0 else None
    return {"label": label, "kind": kind, "run": src.name, "before": verdict(src), "after": new, "error": None if r.returncode == 0 else (r.stderr or r.stdout)[-200:]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign-since", default="20261023_18")
    ap.add_argument("--attack-types", default="lure,traverse,sshbrute,webprobe,portscan,slowscan,dirbrute,stealthscan,overlap")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--limit-benign", type=int, default=0)
    args = ap.parse_args()
    benign = [d for d in sorted((ROOT / "capture" / "runs").glob(f"live_{WS.replace('.', '-')}_*")) if d.name.split("_", 2)[2] >= args.benign_since and (d / "pcaps").exists()]
    if args.limit_benign:
        benign = benign[:args.limit_benign]
    att = attack_folders([t for t in args.attack_types.split(",") if t])
    items = [("benign", "benign", d) for d in benign] + [(t, "attack", d) for t, d in att.items()]
    print(f"{len(benign)} benign incidents, {len(att)} attack incidents: {sorted(att)}", flush=True)
    work = Path(tempfile.mkdtemp(prefix="reanalysis_"))
    results = []
    with ThreadPoolExecutor(args.workers) as ex:
        for r in ex.map(lambda it: analyze(it, work), items):
            results.append(r)
            print(f"  {r['kind']:6} {r['label']:12} {r['run']}: before={r['before']} after={r['after']}{' ERROR ' + r['error'] if r['error'] else ''}", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    ok = [r for r in results if not r["error"]]
    b = [r for r in ok if r["kind"] == "benign"]
    a = [r for r in ok if r["kind"] == "attack"]
    fa_before = sum(1 for r in b if r["before"])
    fa_after = sum(1 for r in b if r["after"])
    hit = [r for r in a if r["after"] and any(x["ip"] == KALI for x in r["after"])]
    summary = {"benign_incidents": len(b), "benign_false_alarms_before": fa_before, "benign_false_alarms_after": fa_after,
               "attack_incidents": len(a), "attacks_detected_after": len(hit), "attacks_missed": [r["label"] for r in a if r not in hit],
               "errors": len(results) - len(ok)}
    print(json.dumps(summary, indent=1))
    (ROOT / "eval" / "results" / "reanalysis.json").write_text(json.dumps({"summary": summary, "results": results}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

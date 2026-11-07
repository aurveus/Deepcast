#!/usr/bin/env python3
"""Score the rule-based detector and the Claude agent on every saved run, per scenario.

  python eval/evaluate.py            # reads capture/runs/*, writes eval/results/results.{json,md}

Run folders are named <scenario>_<timestamp>; scenario is one of portscan, slowscan, sshbrute,
webprobe, benign (attack runs are launched from KALI_IP; a benign run contains no attack at all).
Missing rules.json is computed on the fly; a run without analysis.json is counted as "not analyzed".

Metrics per scenario: runs, detected (rules / Claude), time to detect, decoy deployed, false alarms.
  - Detected: a finding that names KALI_IP.
  - False alarm: any finding naming another IP, or any finding at all in a benign run.
  - Time to detect: rules = seconds of capture time from the attacker's first packet to the alert;
    Claude = seconds of analysis AFTER the capture ended (it works on a finished capture). The two
    are different quantities and the report must say so.
  - Decoy deployed: a decoy_spawned event is logged for that run.
"""
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = {"portscan": "Port scan", "slowscan": "Slow port scan", "sshbrute": "SSH brute force",
             "webprobe": "Web probing", "benign": "Benign only"}
OUT = ROOT / "eval" / "results"
MIN_CONF = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))["min_confidence"]


def excluded():
    f = ROOT / "eval" / "exclude.txt"
    return {l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")} if f.exists() else set()


def env():
    out = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def score_run(run, kali, spawned):
    scenario = run.name.rsplit("_", 2)[0]
    benign = scenario == "benign"
    rules = load(run / "rules.json")
    if rules is None and list((run / "pcaps").glob("*.pcap")):
        subprocess.run([sys.executable, str(ROOT / "eval" / "rule_detector.py"), str(run)], capture_output=True, check=True)
        rules = load(run / "rules.json")
    claude = load(run / "analysis.json")
    meta = load(run / "analysis_meta.json") or {}

    rule_ips = [d["attacker_ip"] for d in (rules or {}).get("detections", [])]
    # Only findings at or above the controller threshold count: below it the platform takes no action.
    claude_all = (claude or {}).get("analyses", [])
    claude_ips = [a["attacker_ip"] for a in claude_all if a["confidence"] >= MIN_CONF]
    low_conf = len(claude_all) - len(claude_ips)
    ttd = [d["time_to_detect_s"] for d in (rules or {}).get("detections", []) if d["attacker_ip"] == kali]
    return {
        "run": run.name, "scenario": scenario,
        "rules_detected": None if benign or rules is None else kali in rule_ips,
        "claude_detected": None if benign or claude is None else kali in claude_ips,
        "rules_ttd_s": min(ttd) if ttd else None, "claude_seconds": meta.get("seconds"),
        "decoy_deployed": run.name in spawned,
        "rules_false_alarms": 0 if rules is None else (len(rule_ips) if benign else sum(ip != kali for ip in rule_ips)),
        "claude_false_alarms": None if claude is None else (len(claude_ips) if benign else sum(ip != kali for ip in claude_ips)),
        "claude_low_conf_entries": low_conf, "analyzed": claude is not None,
    }


def summarize(rows):
    out = []
    for key, label in SCENARIOS.items():
        r = [x for x in rows if x["scenario"] == key]
        if not r:
            out.append({"scenario": label, "runs": 0})
            continue
        attack = key != "benign"
        count = lambda f: sum(1 for x in r if x[f])
        med = lambda f: (round(statistics.median(v), 1) if (v := [x[f] for x in r if x[f] is not None]) else None)
        out.append({
            "scenario": label, "runs": len(r),
            "rules_detected": f"{count('rules_detected')}/{len(r)}" if attack else "n/a",
            "claude_detected": f"{count('claude_detected')}/{sum(x['analyzed'] for x in r)}" if attack else "n/a",
            "rules_ttd_s": med("rules_ttd_s"), "claude_seconds": med("claude_seconds"),
            "decoy_deployed": f"{count('decoy_deployed')}/{len(r)}",
            "rules_false_alarms": sum(x["rules_false_alarms"] or 0 for x in r),
            "claude_false_alarms": sum(x["claude_false_alarms"] or 0 for x in r),
            "claude_low_conf_entries": sum(x["claude_low_conf_entries"] for x in r),
        })
    return out


def markdown(summary):
    cols = ["Scenario", "Runs", "Rules detected", "Claude detected", "Rules time-to-detect (s)", "Claude analysis (s)",
            "Decoy deployed", "False alarms (rules / Claude)"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summary:
        if not s["runs"]:
            lines.append(f"| {s['scenario']} | 0 | – | – | – | – | – | – |")
            continue
        v = lambda x: "–" if x is None else x
        lines.append(f"| {s['scenario']} | {s['runs']} | {s['rules_detected']} | {s['claude_detected']} | {v(s['rules_ttd_s'])} | "
                     f"{v(s['claude_seconds'])} | {s['decoy_deployed']} | {s['rules_false_alarms']} / {s['claude_false_alarms']} |")
    return "\n".join(lines) + "\n"


def main():
    kali = env().get("KALI_IP", "10.10.10.10")
    events = (ROOT / "lab" / "logs" / "events.jsonl")
    spawned = set()
    if events.exists():
        for line in events.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event") == "decoy_spawned" and e.get("run_id"):
                spawned.add(e["run_id"])
    skip = excluded()
    runs = [d for d in sorted((ROOT / "capture" / "runs").glob("*_*")) if d.name.rsplit("_", 2)[0] in SCENARIOS and d.name not in skip]
    rows = [score_run(d, kali, spawned) for d in runs]
    summary = summarize(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps({"summary": summary, "runs": rows}, indent=2), encoding="utf-8")
    (OUT / "results.md").write_text(markdown(summary), encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown(summary))


if __name__ == "__main__":
    main()

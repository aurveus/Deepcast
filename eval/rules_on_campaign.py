#!/usr/bin/env python3
"""Rule-based baseline vs Claude on the unattended-campaign scenarios.

  python eval/rules_on_campaign.py        # writes eval/results/campaign_rules.{json,md}

For every scored attack scenario, run the three fixed-threshold rules of eval/rule_detector.py over the capture windows
that overlap the scenario (the watcher saves them inside its incident folders) and ask: would a hand-written alert have
fired on the attacker, and how long after the REAL attack start? The Claude figures come from eval/campaign_eval.py, so the
two columns use the same ground truth.

Limits to state with the numbers:
  - The watcher only saves captures when an incident was opened (the triage gate fired), so a scenario that never opened an
    incident has no capture to run the rules on ("no data", not a miss). Benign-only windows are not saved at all, so false
    alarms of the rules are not measured here; see the per-capture benign runs in eval/results/results.md.
  - The rules look at one source address at a time, exactly as a simple alert would; the spoofed decoy sources of the stealth
    scan are not merged for them.
"""
import glob
import json
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
import campaign_eval as ce  # noqa: E402
import rule_detector as rd  # noqa: E402

WINDOW = 30  # seconds covered by one capture file (watcher default)
# The rule a person would expect to catch each scenario; firing a different rule is a lucky hit with the wrong label.
EXPECTED_RULE = {"portscan": "port_scan", "slowscan": "port_scan", "sshbrute": "ssh_bruteforce", "webprobe": "web_probe",
                 "dirbrute": "web_probe", "stealthscan": "port_scan", "lure": None, "traverse": None, "overlap": None}


def file_start(f):
    m = re.search(r"_(\d{14})\.pcap$", f.name)
    return time.mktime(time.strptime(m.group(1), "%Y%m%d%H%M%S")) if m else f.stat().st_mtime


def all_windows():
    seen = {}
    for p in glob.glob(str(ROOT / "capture" / "runs" / "live_*" / "pcaps" / "*.pcap")):
        f = Path(p)
        seen.setdefault(f.name, f)
    return sorted(((file_start(f), f) for f in seen.values()), key=lambda x: x[0])


def main():
    cfg = ce.env()
    kali = cfg.get("KALI_IP", "10.10.10.10")
    logs = sorted(glob.glob(str(ROOT / "attacks" / "logs" / "campaign_*.jsonl")))
    rows, _, _ = ce.evaluate(logs)
    windows = all_windows()
    per = {}
    for r in rows:
        if r["scenario"] == "idle" or r["excluded"]:
            continue
        lo, hi = r["t0"] - 5, r["t1"] + 90
        files = [f for t, f in windows if t + WINDOW >= lo and t <= hi]
        res = {"start": r["start"], "scenario": r["scenario"], "claude_detected": r["detected"] is not None,
               "claude_ttd_s": r.get("ttd_s"), "windows": len(files), "rules_detected": None, "rules_ttd_s": None, "rules": []}
        if files:
            hits = [d for d in rd.detect(files) if d["attacker_ip"] == kali and lo <= d["triggered_at"] <= hi]
            res["rules_detected"] = bool(hits)
            if hits:
                first = min(hits, key=lambda d: d["triggered_at"])
                res["rules_ttd_s"] = round(first["triggered_at"] - r["t0"], 1)
                res["rules"] = sorted({d["rule"] for d in hits})
        per.setdefault(r["scenario"], []).append(res)
    summary = []
    for key, label in ce.LABELS.items():
        rs = per.get(key)
        if not rs:
            continue
        have = [x for x in rs if x["rules_detected"] is not None]
        med = lambda xs: round(statistics.median(xs), 1) if xs else None
        summary.append({
            "scenario": label, "runs": len(rs), "no_data": len(rs) - len(have),
            "rules_detected": f"{sum(x['rules_detected'] for x in have)}/{len(have)}",
            "rules_rules": sorted({r for x in have for r in x["rules"]}),
            "rules_correct": (f"{sum(EXPECTED_RULE.get(key) in x['rules'] for x in have)}/{len(have)}" if EXPECTED_RULE.get(key) else "n/a (no rule for it)"),
            "rules_ttd_s": med([x["rules_ttd_s"] for x in have if x["rules_ttd_s"] is not None]),
            "claude_detected": f"{sum(x['claude_detected'] for x in rs)}/{len(rs)}",
            "claude_ttd_s": med([x["claude_ttd_s"] for x in rs if x["claude_ttd_s"] is not None])})
    out = ROOT / "eval" / "results"
    (out / "campaign_rules.json").write_text(json.dumps({"summary": summary, "runs": per}, indent=2), encoding="utf-8")
    v = lambda x: "–" if x is None else x
    lines = ["| Scenario | Runs | Rules detected | Rules that fired | Right rule for the attack | Rules median time to detect (s) | Claude detected | Claude median time to detect (s) |", "|---|---|---|---|---|---|---|---|"]
    for s in summary:
        nd = f" ({s['no_data']} no capture)" if s["no_data"] else ""
        lines.append(f"| {s['scenario']} | {s['runs']} | {s['rules_detected']}{nd} | {', '.join(s['rules_rules']) or '–'} | {s['rules_correct']} | {v(s['rules_ttd_s'])} | {s['claude_detected']} | {v(s['claude_ttd_s'])} |")
    md = "\n".join(lines) + "\n"
    (out / "campaign_rules.md").write_text(md, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()

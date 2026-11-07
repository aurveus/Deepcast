#!/usr/bin/env python3
"""Replay a rule set over the labeled corpus and score it.

  python detect/replay.py detect/rules/baseline.json [--split development,validation] [--json out.json]

Scoring (ground truth only, see corpus.py):
  detected      an alert for one of the sample's attack clients (first one counts)
  right rule    the firing rule names an ATT&CK technique the scenario is expected to show (eval/campaign_eval.py EXPECTED)
  time to alert first alert time minus the REAL attack start from the campaign log (not the first packet)
  false alarm   any alert for a client that is not an attack client of that sample: the workstation traffic
                generator inside an attack sample, or anyone in a benign sample
A rule set is also run as one whole, so a noisy rule hurts every sample, exactly as it would live.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import corpus  # noqa: E402
sys.path.insert(0, str(HERE.parent / "eval"))
from campaign_eval import EXPECTED, OVERLAP_FAMILIES  # noqa: E402  (ATT&CK techniques each scenario is expected to show)
from engine import RuleEngine  # noqa: E402
from rules import load_rules  # noqa: E402


def right_reason(rule_techniques, sample_type):
    """True if a firing rule names a technique this scenario is expected to show (a scan caught by the SSH rule is detected, but not for the right reason)."""
    def covers(want):
        return any(t and any(t == w or w.startswith(t + ".") or t.startswith(w + ".") for w in want) for t in rule_techniques)
    if sample_type == "overlap":                       # three attacks at once: every behavior needs its own rule
        return all(covers(f) for f in OVERLAP_FAMILIES)
    return covers(EXPECTED.get(sample_type, ()))


def score_sample(rules, sample):
    """One sample through a fresh engine. Returns the facts a report or a promotion gate needs."""
    eng = RuleEngine(rules)
    attack_clients = set(sample["attack_clients"])
    hits, false = [], []
    for ev in sample["events"]:
        for a in eng.feed(ev):
            (hits if a["client"] in attack_clients else false).append(a)
    first = min(hits, key=lambda a: a["t"]) if hits else None
    tech = {a["technique"] for a in hits}
    return {"id": sample["id"], "type": sample["type"], "label": sample["label"], "split": sample["split"],
            "detected": bool(hits), "right_reason": right_reason(tech, sample["type"]) if hits else False, "first_rule": first["rule_id"] if first else None,
            "time_to_alert_s": round(first["t"] - sample["start"], 2) if first else None,
            "alert_after_first_packet_s": first["latency_since_first_s"] if first else None,
            "rules_fired": sorted({a["rule_id"] for a in hits}),
            "false_alarms": [{"rule_id": a["rule_id"], "client": a["client"], "t": a["t"]} for a in false],
            "minutes": round((sample["end"] - sample["start"]) / 60, 2), "events": len(sample["events"])}


def evaluate(rules, samples):
    return [score_sample(rules, s) for s in samples]


def summarize(results):
    """Per (split, type): detection rate, median time to alert, false alarms, benign minutes."""
    groups = {}
    for r in results:
        g = groups.setdefault((r["split"], r["label"], r["type"]), [])
        g.append(r)
    rows = []
    for (split, label, typ), rs in sorted(groups.items()):
        ttd = [r["time_to_alert_s"] for r in rs if r["time_to_alert_s"] is not None]
        rows.append({"split": split, "label": label, "type": typ, "samples": len(rs),
                     "detected": sum(r["detected"] for r in rs) if label == "attack" else None,
                     "right_reason": sum(r["right_reason"] for r in rs) if label == "attack" else None,
                     "median_time_to_alert_s": round(statistics.median(ttd), 1) if ttd else None,
                     "false_alarms": sum(len(r["false_alarms"]) for r in rs), "minutes": round(sum(r["minutes"] for r in rs), 1)})
    return rows


def table(rows):
    out = [f"{'split':12} {'type':14} {'n':>3} {'detected':>9} {'right rule':>10} {'median alert (s)':>17} {'false alarms':>13} {'minutes':>8}"]
    for r in rows:
        det = f"{r['detected']}/{r['samples']}" if r["detected"] is not None else "-"
        rr = f"{r['right_reason']}/{r['samples']}" if r["right_reason"] is not None else "-"
        ttd = "-" if r["median_time_to_alert_s"] is None else r["median_time_to_alert_s"]
        out.append(f"{r['split']:12} {r['type']:14} {r['samples']:3} {det:>9} {rr:>10} {str(ttd):>17} {r['false_alarms']:13} {r['minutes']:8}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rules")
    ap.add_argument("--split", default="development,validation,holdout")
    ap.add_argument("--json")
    ap.add_argument("--scheme", default="deploy")
    args = ap.parse_args()
    rules = load_rules(args.rules)
    splits = set(args.split.split(","))
    m = corpus.load(args.scheme)
    samples = [s for s in m["samples"] if s["split"] in splits]
    results = evaluate(rules, samples)
    print(table(summarize(results)))
    fa = [(r["id"], f) for r in results for f in r["false_alarms"]]
    for sid, f in fa[:10]:
        print(f"  false alarm in {sid}: rule {f['rule_id']} client {f['client']}")
    if args.json:
        Path(args.json).write_text(json.dumps({"rules": [r["id"] for r in rules], "results": results, "summary": summarize(results)}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

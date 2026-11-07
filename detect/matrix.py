#!/usr/bin/env python3
"""Evaluation matrix: hand-written baseline vs baseline + learned rules vs the Claude path, per attack type and split.

  python detect/matrix.py [--out detect/results.md]

Columns: detection counts on the labeled corpus for each rule set (replay.py scoring), the median alert time measured from the
REAL scenario start, the Claude path's detection and time to detect from the live campaign (eval/results/campaign.json), and the
false alarms / benign minutes behind the "zero false alarms on the tested dataset" claim. Also prints which rules were learned.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "eval"))
import corpus  # noqa: E402
from campaign_eval import LABELS  # noqa: E402
from replay import evaluate  # noqa: E402
from rules import load_rules  # noqa: E402

BASE, PROMOTED = HERE / "rules" / "baseline.json", HERE / "rules" / "promoted.json"


def by_type(results):
    g = {}
    for r in results:
        g.setdefault((r["split"], r["label"], r["type"]), []).append(r)
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "results.md"))
    ap.add_argument("--scheme", default="deploy")
    args = ap.parse_args()
    m = corpus.load(args.scheme)
    samples = m["samples"]
    base = load_rules(BASE)
    learned = load_rules(PROMOTED) if PROMOTED.exists() else []
    rb, rl = by_type(evaluate(base, samples)), by_type(evaluate(base + learned, samples))
    camp = {r["scenario"]: r for r in json.loads((ROOT / "eval" / "results" / "campaign.json").read_text(encoding="utf-8"))["summary"]}

    def frac(rs, key="detected"):
        return f"{sum(r[key] for r in rs)}/{len(rs)}"

    def med(rs):
        t = [r["time_to_alert_s"] for r in rs if r["time_to_alert_s"] is not None]
        return f"{statistics.median(t):.0f}" if t else "-"
    lines = ["| split | attack type | corpus runs | baseline rules | + learned rules | learned: median alert after scenario start (s) | Claude path (live campaign) | Claude median time to detect (s) |",
             "|---|---|---|---|---|---|---|---|"]
    order = {"development": 0, "validation": 1, "holdout": 2}
    for (split, label, typ), rs in sorted(rl.items(), key=lambda kv: (order[kv[0][0]], kv[0][1], kv[0][2])):
        if label != "attack":
            continue
        c = camp.get(LABELS.get(typ, ""), {})
        lines.append(f"| {split} | {typ} | {len(rs)} | {frac(rb[(split, label, typ)])} | {frac(rs)} | {med(rs)} | {c.get('claude_detected', '-')} | {c.get('ttd_s', '-')} |")
    fa = {}
    for split in order:
        rs = [r for k, v in rl.items() if k[0] == split for r in v]
        fa[split] = (sum(len(r["false_alarms"]) for r in rs), round(sum(r["minutes"] for r in rs if r["label"] == "benign"), 1),
                     sum(1 for r in rs if r["label"] == "benign"), sum(r["events"] for r in rs))
    lines += ["", "False alarms with baseline + learned rules (benign blocks plus the workstation traffic inside every attack run):", "",
              "| split | false alarms | pure-benign minutes | benign blocks | events replayed |", "|---|---|---|---|---|"]
    lines += [f"| {s} | {a} | {mins} | {n} | {ev} |" for s, (a, mins, n, ev) in fa.items()]
    lines += ["", "Learned rules: " + (", ".join(f"`{r['id']}` ({r['name']})" for r in learned) or "none"),
              f"Corpus built {m['built']}; {len(samples)} samples, {len(m['skipped'])} scenario runs skipped (reasons in corpus/manifest.json).",
              "Claim wording: zero false alarms on the tested dataset above; not a general guarantee."]
    text = "\n".join(lines)
    Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

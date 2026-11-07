#!/usr/bin/env python3
"""Leave-one-attack-type-out: does a rule learned from OTHER attacks catch an attack type it never saw?

  python detect/crossval.py [--types lure,stealthscan,traverse]

For each held-out type T: the proposer learns (in memory, nothing promoted) from every other development attack type the rules still miss,
the gate judges each proposal, and we then count how many T runs the resulting rule set detects, plus false alarms on all benign data.
This is the honest generalization number: with a single fixed holdout, the answer depends on which type happened to be held out.
Each fold costs one Claude call per other missed type. Results go to detect/runs/crossval.json.
"""
import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import corpus  # noqa: E402
import gate  # noqa: E402
from learn import attempt, benign_clients, missed_types  # noqa: E402
from propose import propose  # noqa: E402
from replay import evaluate  # noqa: E402
from rules import load_rules  # noqa: E402


def fold(held, base, propose_fn):
    """Learn without `held`, then test on it."""
    mapping = {**corpus.SCHEMES["deploy"], held: "holdout"}
    samples = corpus.load(mapping)["samples"]
    current, learned, log = list(base), [], []
    benign = benign_clients(samples)
    for typ, miss in sorted(missed_types(samples, current).items()):
        rec = attempt(samples, current, typ, miss, benign, propose_fn)
        ok = rec["report"]["accepted"]
        log.append({"from_type": typ, "rule": rec["rule"], "accepted": ok, "why_not": None if ok else next(c["detail"] for c in rec["report"]["checks"] if not c["ok"])})
        if ok:
            current.append(rec["rule"])
            learned.append(rec["rule"]["id"])
    held_s = [s for s in samples if s["type"] == held]
    before = evaluate(base, held_s)
    after = evaluate(current, held_s)
    fa = sum(len(r["false_alarms"]) for r in evaluate(current, samples))
    return {"held_out": held, "learned_from_others": log, "rules_added": learned, "runs": len(held_s),
            "detected_before": sum(r["detected"] for r in before), "detected_after": sum(r["detected"] for r in after), "false_alarms_all_data": fa}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--types", default="lure,stealthscan,traverse")
    args = ap.parse_args()
    gate.QUIET = True
    base = load_rules(gate.BASELINE)
    out = []
    for t in args.types.split(","):
        t0 = time.time()
        r = fold(t, base, propose)
        out.append(r)
        print(f"held out {t}: {r['detected_before']}/{r['runs']} -> {r['detected_after']}/{r['runs']}  rules learned from the others: {r['rules_added'] or 'none'}  "
              f"false alarms: {r['false_alarms_all_data']}  ({time.time() - t0:.0f} s)")
    (HERE / "runs" / "crossval.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

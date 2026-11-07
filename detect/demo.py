#!/usr/bin/env python3
"""Before/after demo of the learning loop, offline, in about a minute. Changes nothing (the promoted-rules file is not touched).

  python detect/demo.py                 # uses the saved real proposal in detect/runs/ and the corpus on disk
  python detect/demo.py --live-claude   # asks Claude for a fresh proposal instead (needs Claude usage)

Story: the hand-written rules miss a lure-chain attack -> Claude sees only numbers about it and proposes a rule -> a deliberately
bad rule is rejected by the gate -> the good rule is accepted -> the same attack is replayed, old rules vs new -> an attack type
the proposer never saw (holdout) is checked.
"""
import argparse
import glob
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import corpus  # noqa: E402
import gate  # noqa: E402
from evidence import build  # noqa: E402
from learn import benign_clients  # noqa: E402
from replay import evaluate  # noqa: E402
from rules import load_rules  # noqa: E402


def h(t):
    print(f"\n=== {t}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-claude", action="store_true")
    args = ap.parse_args()
    gate.QUIET = True
    base = load_rules(HERE / "rules" / "baseline.json")
    samples = corpus.load("v1")["samples"]
    lure = [s for s in samples if s["type"] == "lure" and s["split"] == "development"]
    show = lure[0]

    h("1. BEFORE: the hand-written rules against a lure-chain attack")
    r = evaluate(base, [show])[0]
    print(f"sample {show['id']}: {len(show['events'])} events, attacker {'detected' if r['detected'] else 'NOT detected'} by {[x['id'] for x in base]}")
    n = sum(not x["detected"] for x in evaluate(base, lure))
    print(f"all development lure chains: {n}/{len(lure)} missed. The attacker followed the lures; nothing counted a threshold.")

    h("2. What Claude is allowed to see (numbers and fixed words only)")
    ev = build(lure, benign_clients(samples), detected_by=[])
    p = ev["profile"]
    print(json.dumps({"attacker_http_requests": p["kinds"].get("http_req", {}).get("total"), "trap_requests": p["http_req"]["trap_requests"],
                      "max_distinct_ports_10s": p["syn"]["max_distinct_dports"]["w10"],
                      "benign_trap_requests": ev["benign_envelope"].get("http_req", {}).get("trap_requests", 0)}, indent=1))

    h("3. Claude proposes a rule")
    if args.live_claude:
        from propose import propose
        proposal = propose(ev, existing_ids=[x["id"] for x in base])
    else:
        saved = [f for f in sorted(glob.glob(str(HERE / "runs" / "learn_*_lure.json")))
                 if json.loads(Path(f).read_text(encoding="utf-8"))["proposal"]["rule"]["id"] != "P-NOISY"]
        proposal = json.loads(Path(saved[0]).read_text(encoding="utf-8"))["proposal"]
        print(f"(saved real proposal from {Path(saved[0]).name})")
    print(json.dumps(proposal["rule"]))
    print("why:", proposal["rationale"])

    h("4. The gate rejects a bad rule first (any HTTP request)")
    bad = json.loads((HERE / "fixtures" / "bad_noisy.json").read_text(encoding="utf-8"))
    gate.print_report(bad["rule"], gate.judge(bad["rule"], base, samples, "lure"))

    h("5. The gate checks Claude's rule")
    rep = gate.judge(proposal["rule"], base, samples, "lure")
    gate.print_report(proposal["rule"], rep)

    h("6. AFTER: the same attack, old rules vs old + new rule (streaming engine, replayed)")
    new = base + [proposal["rule"]]
    for s in lure[:3]:
        a, b = evaluate(base, [s])[0], evaluate(new, [s])[0]
        print(f"{s['id']}: before={'miss' if not a['detected'] else 'alert'}  after={'alert by ' + b['first_rule'] + ' at +%ss' % b['time_to_alert_s'] if b['detected'] else 'miss'}")

    h("7. Generalization: an attack type the proposer never saw (holdout)")
    for typ in ("traverse", "stealthscan"):
        hs = [s for s in samples if s["type"] == typ]
        print(f"{typ}: before {sum(x['detected'] for x in evaluate(base, hs))}/{len(hs)}  after {sum(x['detected'] for x in evaluate(new, hs))}/{len(hs)}")
    print("(stealth scan stays missed: nothing in the development data resembles it, so nothing could be learned)")
    print(f"\nBenign data behind 'zero false alarms on the tested dataset': {rep['reported']['benign_minutes_tested']} minutes of idle traffic plus workstation background inside the attack runs.")


if __name__ == "__main__":
    main()

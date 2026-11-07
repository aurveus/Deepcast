#!/usr/bin/env python3
"""The learning loop: find development attacks the current rules miss, ask Claude for a rule, let the gate decide.

  python detect/learn.py                       # propose + judge for every development attack type that is missed (nothing is promoted)
  python detect/learn.py --type lure --promote [--approve]
  python detect/learn.py --type lure --proposal detect/fixtures/bad_noisy.json     # judge a given proposal instead of calling Claude

Claude sees only the structural evidence (evidence.py). It proposes; gate.py checks and promotes; the engine runs it.
Each attempt is saved in detect/runs/ (evidence, proposal, gate report) so the before/after story can be shown and audited.
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
from evidence import build  # noqa: E402
from propose import propose  # noqa: E402
from replay import evaluate  # noqa: E402

RUNS = HERE / "runs"


def benign_clients(samples):
    """Development-split benign traffic, one event list per (sample, client): benign blocks and the non-attack clients of attack samples."""
    out = []
    for s in samples:
        if s["split"] != "development":
            continue
        by = {}
        for e in s["events"]:
            if e["client"] not in s["attack_clients"]:
                by.setdefault(e["client"], []).append(e)
        out.extend(by.values())
    return out


def attempt(samples, current, typ, miss, benign, propose_fn=None, proposal=None, forbidden_kinds=()):
    """One learning attempt for one attack type: evidence -> proposal -> gate verdict. Pure (changes nothing on disk)."""
    ev = build(miss, benign, detected_by=[], exclude_kinds=forbidden_kinds)
    if proposal is None:
        proposal = propose_fn(ev, existing_ids=[r["id"] for r in current])
    rule = proposal["rule"] if "rule" in proposal else proposal
    report = gate.judge(rule, current, samples, typ, forbidden_kinds)
    return {"attack_type": typ, "evidence": ev, "proposal": proposal, "rule": rule, "report": report}


def missed_types(samples, current):
    results = {r["id"]: r for r in evaluate(current, samples)}
    missed = {}
    for s in samples:
        if s["split"] == "development" and s["label"] == "attack" and not results[s["id"]]["detected"]:
            missed.setdefault(s["type"], []).append(s)
    return missed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--type", help="attack type to learn from (default: every missed development type)")
    ap.add_argument("--proposal", help="judge this proposal file instead of asking Claude")
    ap.add_argument("--promote", action="store_true")
    ap.add_argument("--approve", action="store_true")
    ap.add_argument("--independent-of", help="rule id already covering the type: ask for a second, independent signal that does not use that rule's event kinds")
    ap.add_argument("--scheme", default="deploy", help="split scheme in corpus.SCHEMES (default deploy; v1 = the first published split)")
    args = ap.parse_args()

    samples = corpus.load(args.scheme)["samples"]
    current = gate.current_rules()
    forbidden = ()
    if args.independent_of:
        old = next(r for r in current if r["id"] == args.independent_of)
        forbidden = tuple(sorted({c["kind"] for c in old["all_of"]}))
        current = [r for r in current if r["id"] != args.independent_of]          # evaluate as if the old rule did not exist
        print(f"independent signal wanted: avoiding kinds {forbidden}; judging without {args.independent_of}")
    missed = missed_types(samples, current)
    if args.type:
        missed = {t: v for t, v in missed.items() if t == args.type}
    if not missed:
        print("nothing to learn: every (selected) development attack is already detected by the current rules")
        return
    benign = benign_clients(samples)
    RUNS.mkdir(exist_ok=True)
    for typ, miss in sorted(missed.items()):
        print(f"\n== {typ}: {len(miss)} development samples missed by {[r['id'] for r in current]}")
        t0 = time.time()
        proposal = json.loads(Path(args.proposal).read_text(encoding="utf-8")) if args.proposal else None
        rec = attempt(samples, current, typ, miss, benign, propose, proposal, forbidden)
        if not args.proposal:
            print(f"proposal received in {time.time() - t0:.0f} s")
        rule, report, proposal = rec["rule"], rec["report"], rec["proposal"]
        gate.log("rule_proposed", rule_id=rule.get("id"), attack_type=typ, rationale=str(proposal.get("rationale", ""))[:300])
        print("rationale:", proposal.get("rationale", ""))
        print("rule:", json.dumps(rule))
        gate.print_report(rule, report)
        (RUNS / f"learn_{time.strftime('%Y%m%d_%H%M%S')}_{typ}.json").write_text(
            json.dumps({k: rec[k] for k in ("attack_type", "evidence", "proposal", "report")}, indent=1), encoding="utf-8")
        if report["accepted"] and args.promote:
            if args.approve and input("Promote this rule to the fast path? [y/N] ").strip().lower() != "y":
                gate.log("rule_rejected", rule_id=rule["id"], reason="approval denied")
                continue
            gate.promote(rule, report, proposal.get("rationale", ""))
            current = gate.current_rules() if not args.independent_of else current + [rule]
            print("PROMOTED")
        elif not report["accepted"]:
            gate.log("rule_rejected", rule_id=rule.get("id"), reason=next(c["detail"] for c in report["checks"] if not c["ok"]))


if __name__ == "__main__":
    main()

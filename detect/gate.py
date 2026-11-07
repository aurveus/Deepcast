#!/usr/bin/env python3
"""Promotion gate: a proposed rule runs on the fast path only after it passes every check below, and it can be rolled back.

  python detect/gate.py judge proposal.json --type lure [--promote] [--approve]
  python detect/gate.py status
  python detect/gate.py rollback            # remove the most recently promoted rule
  python detect/gate.py --selftest

Checks (all must pass):
  1 schema       valid rule in the closed vocabulary, origin "proposed", id not already used
  2 catches      alone on top of the current rules it detects EVERY development sample of the attack type it was proposed for
  3 adds         it detects at least one development sample the current rules miss
  4 quiet        ZERO false alarms on the development and validation splits (benign blocks, and the benign workstation traffic
                 inside every attack sample): any alert for a client that is not the attacker fails the rule
  5 holdout      ZERO false alarms on the holdout split's benign traffic (data the proposer never saw)
Reported, not required: detections gained on validation and holdout attack types (does the rule generalize?).
Wording for the report: "zero false alarms on the tested dataset" (corpus manifest lists exactly what was tested).

Promotion appends to detect/rules/promoted.json (read by stream.py), snapshots the previous file in detect/rules/history/,
and logs rule_promoted / rule_rejected / rule_rolled_back to lab/logs/events.jsonl. With --approve a person confirms first.
The AI never promotes anything: this script does, from fixed checks.
"""
import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from replay import evaluate  # noqa: E402
from rules import load_rules, validate_rule  # noqa: E402

PROMOTED = HERE / "rules" / "promoted.json"
BASELINE = HERE / "rules" / "baseline.json"
HISTORY = HERE / "rules" / "history"


QUIET = False


def log(event, **fields):
    if QUIET:
        return
    try:
        sys.path.insert(0, str(HERE.parent / "controller"))
        import controller as ctl
        ctl.log_event(event, **fields)
    except Exception:                                    # logging must never decide a verdict (self-tests run without a lab)
        print(f"[{event}] {fields}")


def current_rules():
    rules = load_rules(BASELINE)
    if PROMOTED.exists():
        rules += load_rules(PROMOTED)
    return rules


def judge(candidate, current, samples, attack_type, forbidden_kinds=()):
    """Run every check. Returns {"accepted": bool, "checks": [...], "reported": {...}}. Pure: changes nothing on disk."""
    checks = []

    def add(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    errs = validate_rule(candidate)
    if candidate.get("origin") != "proposed":
        errs.append("origin must be 'proposed'")
    if candidate.get("id") in {r["id"] for r in current}:
        errs.append("id already in use")
    add("schema", not errs, "valid" if not errs else "; ".join(errs))
    if errs:
        return {"accepted": False, "checks": checks, "reported": {}}

    used = {c.get("kind") for c in candidate.get("all_of", [])}
    if forbidden_kinds:
        add("independent", not (used & set(forbidden_kinds)), f"uses {sorted(used)}; must avoid {sorted(forbidden_kinds)}")
    before = evaluate(current, samples)
    after = evaluate(current + [candidate], samples)
    by_id = lambda res: {r["id"]: r for r in res}
    b, a = by_id(before), by_id(after)
    dev_type = [s["id"] for s in samples if s["split"] == "development" and s["label"] == "attack" and s["type"] == attack_type]
    caught = [i for i in dev_type if a[i]["detected"]]
    add("catches", dev_type and len(caught) == len(dev_type), f"{len(caught)}/{len(dev_type)} development '{attack_type}' samples detected")
    gained = [i for i in dev_type if a[i]["detected"] and not b[i]["detected"]]
    add("adds", gained, f"{len(gained)} development samples were missed before and are detected now")

    def false_alarms(splits):
        return [(r["id"], f["rule_id"], f["client"]) for r in after if r["split"] in splits for f in r["false_alarms"]]
    fa_dev = false_alarms({"development", "validation"})
    add("quiet", not fa_dev, "0 false alarms on development+validation" if not fa_dev else f"{len(fa_dev)} false alarms, first: {fa_dev[0]}")
    fa_hold = false_alarms({"holdout"})
    add("holdout", not fa_hold, "0 false alarms on holdout" if not fa_hold else f"{len(fa_hold)} false alarms on holdout")

    def detections(res, split):
        out = {}
        for r in res:
            if r["split"] == split and r["label"] == "attack":
                o = out.setdefault(r["type"], [0, 0])
                o[0] += r["detected"]
                o[1] += 1
        return out
    reported = {}
    for split in ("validation", "holdout"):
        db, da = detections(before, split), detections(after, split)
        reported[split] = {t: {"before": f"{db[t][0]}/{db[t][1]}", "after": f"{da[t][0]}/{da[t][1]}"} for t in da}
    reported["benign_minutes_tested"] = round(sum(r["minutes"] for r in after if r["label"] == "benign"), 1)
    return {"accepted": all(c["ok"] for c in checks), "checks": checks, "reported": reported}


def promote(candidate, report, rationale=""):
    HISTORY.mkdir(parents=True, exist_ok=True)
    data = json.loads(PROMOTED.read_text(encoding="utf-8")) if PROMOTED.exists() else {"rules": []}
    stamp = time.strftime("%Y%m%d_%H%M%S")
    (HISTORY / f"{stamp}_before_{candidate['id']}.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    data["rules"].append({**candidate, "note": (rationale or candidate.get("note", ""))[:300]})
    data["_comment"] = "Written by detect/gate.py only. Rules here passed the promotion gate; remove the newest with: python detect/gate.py rollback"
    PROMOTED.write_text(json.dumps(data, indent=1), encoding="utf-8")
    log("rule_promoted", rule_id=candidate["id"], rule_name=candidate["name"], checks={c["name"]: c["detail"] for c in report["checks"]})


def rollback():
    snaps = sorted(HISTORY.glob("*_before_*.json")) if HISTORY.exists() else []
    if not snaps or not PROMOTED.exists():
        print("nothing to roll back")
        return None
    data = json.loads(PROMOTED.read_text(encoding="utf-8"))
    removed = data["rules"][-1]["id"] if data["rules"] else None
    PROMOTED.write_text(snaps[-1].read_text(encoding="utf-8"), encoding="utf-8")
    snaps[-1].unlink()
    log("rule_rolled_back", rule_id=removed)
    return removed


def print_report(rule, report):
    print(f"rule {rule['id']}: {'ACCEPTED' if report['accepted'] else 'REJECTED'}")
    for c in report["checks"]:
        print(f"  {'ok  ' if c['ok'] else 'FAIL'} {c['name']:8} {c['detail']}")
    for split in ("validation", "holdout"):
        for t, v in report.get("reported", {}).get(split, {}).items():
            if v["before"] != v["after"]:
                print(f"  {split}: {t} {v['before']} -> {v['after']}")


def _selftest():
    import tempfile
    global PROMOTED, HISTORY, QUIET
    QUIET = True
    syn = lambda t, c, p: {"t": t, "client": c, "server": "S", "kind": "syn", "dport": p}
    req = lambda t, c, trap: {"t": t, "client": c, "server": "S", "kind": "http_req", "dport": 80, "method": "GET", "path_hash": "h", "trap": trap}

    def sample(i, split, label, typ, events, clients):
        return {"id": i, "split": split, "label": label, "type": typ, "events": events, "attack_clients": clients, "start": 0, "end": 60}
    benign = [syn(1, "W", 80), req(2, "W", False)]
    samples = [sample("d1", "development", "attack", "lure", [req(1, "K", True)] + benign, ["K"]),
               sample("d2", "development", "attack", "lure", [req(3, "K", True)], ["K"]),
               sample("v1", "validation", "attack", "slow", [syn(i, "K", 100 + i) for i in range(3)] + benign, ["K"]),
               sample("b1", "development", "benign", "benign_block", benign, []),
               sample("h1", "holdout", "benign", "benign_block", benign, []),
               sample("h2", "holdout", "attack", "traverse", [req(1, "K", True)], ["K"])]
    cur = []
    good = {"id": "P-TRAP", "name": "trap touched", "origin": "proposed", "window_s": 60, "all_of": [{"kind": "http_req", "trap": True, "measure": "count", "op": ">=", "value": 1}]}
    r = judge(good, cur, samples, "lure")
    assert r["accepted"], r
    assert r["reported"]["holdout"]["traverse"] == {"before": "0/1", "after": "1/1"}
    noisy = {"id": "P-NOISY", "name": "any connection", "origin": "proposed", "window_s": 60, "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": 1}]}
    r = judge(noisy, cur, samples, "lure")
    assert not r["accepted"] and not next(c for c in r["checks"] if c["name"] == "quiet")["ok"], r
    useless = {**good, "id": "P-NEVER", "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": 99}]}
    r = judge(useless, cur, samples, "lure")
    assert not r["accepted"] and not next(c for c in r["checks"] if c["name"] == "catches")["ok"]
    assert not judge({**good, "origin": "baseline"}, cur, samples, "lure")["accepted"]
    assert not judge({**good, "window_s": 0}, cur, samples, "lure")["accepted"]
    assert not judge(good, [good | {"origin": "baseline"}], samples, "lure")["accepted"]          # duplicate id
    # holdout-only noise is caught too
    holdout_noisy = {"id": "P-H", "name": "web visit from anyone with a trap or two requests", "origin": "proposed", "window_s": 60,
                     "all_of": [{"kind": "http_req", "measure": "count", "op": ">=", "value": 1}]}
    samples2 = samples + [sample("h3", "holdout", "benign", "benign_block", [req(1, "W", False)], [])]
    samples2[0]["events"] = [req(1, "K", True)]                                                   # benign client now has no requests in dev
    samples2[3]["events"] = [syn(1, "W", 80)]
    samples2[4]["events"] = [syn(1, "W", 80)]
    r = judge(holdout_noisy, cur, samples2, "lure")
    assert next(c for c in r["checks"] if c["name"] == "holdout")["ok"] is False and r["accepted"] is False, r
    with tempfile.TemporaryDirectory() as d:                                                      # promote + rollback round trip
        PROMOTED, HISTORY = Path(d) / "promoted.json", Path(d) / "history"
        promote(good, {"checks": []}, "test")
        assert json.loads(PROMOTED.read_text())["rules"][0]["id"] == "P-TRAP"
        promote({**good, "id": "P-TWO"}, {"checks": []})
        assert rollback() == "P-TWO" and [x["id"] for x in json.loads(PROMOTED.read_text())["rules"]] == ["P-TRAP"]
        assert rollback() == "P-TRAP" and json.loads(PROMOTED.read_text())["rules"] == []
        assert rollback() is None
    print("gate selftest ok")


def main():
    if "--selftest" in sys.argv:
        return _selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("proposal")
    j.add_argument("--type", required=True)
    j.add_argument("--promote", action="store_true")
    j.add_argument("--approve", action="store_true", help="ask a person before promoting")
    j.add_argument("--scheme", default="deploy")
    sub.add_parser("status")
    sub.add_parser("rollback")
    args = ap.parse_args()
    if args.cmd == "rollback":
        print("rolled back:", rollback())
    elif args.cmd == "status":
        print("baseline:", [r["id"] for r in load_rules(BASELINE)])
        print("promoted:", [r["id"] for r in load_rules(PROMOTED)] if PROMOTED.exists() else [])
    else:
        import corpus
        proposal = json.loads(Path(args.proposal).read_text(encoding="utf-8"))
        cand = proposal["rule"] if "rule" in proposal else proposal
        report = judge(cand, current_rules(), corpus.load(args.scheme)["samples"], args.type)
        print_report(cand, report)
        if report["accepted"] and args.promote:
            if args.approve and input("Promote this rule to the fast path? [y/N] ").strip().lower() != "y":
                log("rule_rejected", rule_id=cand["id"], reason="approval denied")
                return
            promote(cand, report, proposal.get("rationale", ""))
        elif not report["accepted"]:
            log("rule_rejected", rule_id=cand.get("id"), reason=next(c["detail"] for c in report["checks"] if not c["ok"]))


if __name__ == "__main__":
    main()

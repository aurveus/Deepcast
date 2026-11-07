#!/usr/bin/env python3
"""Detection-rule format: small, declarative, validated. No code, no regular expressions, no free text that is executed.

  python detect/rules.py --selftest
  python detect/rules.py validate detect/rules/baseline.json

A rule watches the events of ONE client address over a sliding window and fires when every clause holds at once:

  {"id": "R-PORTSCAN", "name": "Many distinct ports", "technique": "T1046", "origin": "baseline",
   "window_s": 10, "refire_s": 60,
   "all_of": [{"kind": "syn", "measure": "distinct_dport", "op": ">=", "value": 15}]}

Clause = filter + measure + threshold. Filters (all optional except `kind`) select which events count:
  kind        syn | http_req | http_resp | frag          (extracted from the traffic, see events.py)
              ssh_login_fail | ssh_login_ok | ssh_command | ssh_download   (from the SSH honeypot's log, see hpevents.py; counts only, never the typed text)
  dport_in    [ports]   only these server ports          dport_not_in [ports]
  method_in   [GET, POST, ...] (http_req)                status_in [200, 404, ...] (http_resp)
  trap        true      only requests to paths the lab owner registered as traps (detect/traps.json)
Measures: count | distinct_dport | distinct_path | distinct_server. Operator is always ">=" (only "at least" rules:
a rule can never fire because something is ABSENT, which keeps rules monotonic and easy to reason about).

Every number is bounded below; a proposed rule that is out of bounds is rejected before anything runs.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PACKET_KINDS = ("syn", "http_req", "http_resp")          # have a server port: dport filters and distinct_dport apply
HONEYPOT_KINDS = ("ssh_login_fail", "ssh_login_ok", "ssh_command", "ssh_download")   # from the SSH honeypot's own log, attributed to the real client
KINDS = PACKET_KINDS + ("frag",) + HONEYPOT_KINDS
MEASURES = ("count", "distinct_dport", "distinct_path", "distinct_server")
METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PROPFIND", "PATCH")
ORIGINS = ("baseline", "proposed")
LIMITS = {"window_s": (1, 600), "refire_s": (1, 3600), "clauses": (1, 4), "value": (1, 100000), "list": 32, "port": (1, 65535)}
FILTER_KEYS = {"kind", "dport_in", "dport_not_in", "method_in", "status_in", "trap"}
CLAUSE_KEYS = FILTER_KEYS | {"measure", "op", "value"}
RULE_KEYS = {"id", "name", "technique", "origin", "window_s", "refire_s", "all_of", "note"}
# A measure only makes sense for some kinds (distinct_path needs a path, which only requests have).
MEASURE_KINDS = {"count": KINDS, "distinct_dport": PACKET_KINDS, "distinct_server": KINDS,
                 "distinct_path": ("http_req",)}
APPLIES = {"dport_in": PACKET_KINDS, "dport_not_in": PACKET_KINDS, "method_in": ("http_req",), "status_in": ("http_resp",), "trap": ("http_req",)}
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def proposal_json_schema():
    """JSON Schema handed to the model so its answer already has the right shape. validate_rule() stays the real gate."""
    clause = {"type": "object", "additionalProperties": False, "required": ["kind", "measure", "op", "value"], "properties": {
        "kind": {"enum": list(KINDS)}, "measure": {"enum": list(MEASURES)}, "op": {"enum": [">="]},
        "value": {"type": "integer", "minimum": LIMITS["value"][0], "maximum": LIMITS["value"][1]},
        "dport_in": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "minItems": 1, "maxItems": LIMITS["list"]},
        "dport_not_in": {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}, "minItems": 1, "maxItems": LIMITS["list"]},
        "method_in": {"type": "array", "items": {"enum": list(METHODS)}, "minItems": 1},
        "status_in": {"type": "array", "items": {"type": "integer", "minimum": 100, "maximum": 599}, "minItems": 1, "maxItems": LIMITS["list"]},
        "trap": {"enum": [True]}}}
    rule = {"type": "object", "additionalProperties": False, "required": ["id", "name", "origin", "window_s", "all_of"], "properties": {
        "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$"}, "name": {"type": "string", "maxLength": 80},
        "technique": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"}, "origin": {"enum": ["proposed"]},
        "window_s": {"type": "integer", "minimum": LIMITS["window_s"][0], "maximum": LIMITS["window_s"][1]},
        "refire_s": {"type": "integer", "minimum": LIMITS["refire_s"][0], "maximum": LIMITS["refire_s"][1]},
        "all_of": {"type": "array", "items": clause, "minItems": LIMITS["clauses"][0], "maxItems": LIMITS["clauses"][1]}}}
    return {"type": "object", "additionalProperties": False, "required": ["rule", "rationale"],
            "properties": {"rule": rule, "rationale": {"type": "string", "maxLength": 300}}}


def _int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _int_list(x, lo, hi, what, errs):
    if not isinstance(x, list) or not x or len(x) > LIMITS["list"] or not all(_int(v) and lo <= v <= hi for v in x):
        errs.append(f"{what}: must be a list of 1..{LIMITS['list']} integers in {lo}..{hi}")


def validate_rule(rule):
    """Return a list of problems (empty list = valid). Never raises on bad input."""
    errs = []
    if not isinstance(rule, dict):
        return ["rule must be an object"]
    for k in set(rule) - RULE_KEYS:
        errs.append(f"unknown field {k!r}")
    if not isinstance(rule.get("id"), str) or not ID_RE.match(rule.get("id", "")):
        errs.append("id: 1..40 letters, digits, '-' or '_'")
    if not isinstance(rule.get("name"), str) or not 1 <= len(rule["name"]) <= 80 or not rule["name"].isprintable():
        errs.append("name: printable text, 1..80 characters")
    if "technique" in rule and (not isinstance(rule["technique"], str) or not TECH_RE.match(rule["technique"])):
        errs.append("technique: an ATT&CK id such as T1046 or T1110.001")
    if rule.get("origin") not in ORIGINS:
        errs.append(f"origin: one of {ORIGINS}")
    if "note" in rule and (not isinstance(rule["note"], str) or len(rule["note"]) > 300 or not rule["note"].isprintable()):
        errs.append("note: printable text, up to 300 characters")
    lo, hi = LIMITS["window_s"]
    if not _int(rule.get("window_s")) or not lo <= rule["window_s"] <= hi:
        errs.append(f"window_s: integer {lo}..{hi}")
    if "refire_s" in rule:
        lo, hi = LIMITS["refire_s"]
        if not _int(rule["refire_s"]) or not lo <= rule["refire_s"] <= hi:
            errs.append(f"refire_s: integer {lo}..{hi}")
    clauses = rule.get("all_of")
    lo, hi = LIMITS["clauses"]
    if not isinstance(clauses, list) or not lo <= len(clauses) <= hi:
        errs.append(f"all_of: list of {lo}..{hi} clauses")
        return errs
    for i, c in enumerate(clauses):
        errs.extend(f"clause {i}: {e}" for e in _validate_clause(c))
    return errs


def _validate_clause(c):
    errs = []
    if not isinstance(c, dict):
        return ["must be an object"]
    for k in set(c) - CLAUSE_KEYS:
        errs.append(f"unknown field {k!r}")
    kind = c.get("kind")
    if kind not in KINDS:
        errs.append(f"kind: one of {KINDS}")
    measure = c.get("measure")
    if measure not in MEASURES:
        errs.append(f"measure: one of {MEASURES}")
    elif kind in KINDS and kind not in MEASURE_KINDS[measure]:
        errs.append(f"measure {measure} does not apply to kind {kind}")
    if c.get("op") != ">=":
        errs.append("op: must be '>='")
    lo, hi = LIMITS["value"]
    if not _int(c.get("value")) or not lo <= c["value"] <= hi:
        errs.append(f"value: integer {lo}..{hi}")
    for key in ("dport_in", "dport_not_in"):
        if key in c:
            _int_list(c[key], *LIMITS["port"], key, errs)
    if "method_in" in c and (not isinstance(c["method_in"], list) or not c["method_in"] or not all(m in METHODS for m in c["method_in"])):
        errs.append(f"method_in: a non-empty list from {METHODS}")
    if "status_in" in c:
        _int_list(c["status_in"], 100, 599, "status_in", errs)
    if "trap" in c and c["trap"] is not True:
        errs.append("trap: only true is allowed")
    for key, kinds in APPLIES.items():
        if key in c and kind in KINDS and kind not in kinds:
            errs.append(f"{key} does not apply to kind {kind}")
    return errs


def validate_ruleset(rules):
    """Problems for a list of rules, including duplicate ids."""
    if not isinstance(rules, list):
        return ["a rule set is a list of rules"]
    errs, seen = [], set()
    for r in rules:
        rid = r.get("id") if isinstance(r, dict) else None
        errs.extend(f"{rid}: {e}" for e in validate_rule(r))
        if rid in seen:
            errs.append(f"{rid}: duplicate id")
        seen.add(rid)
    return errs


def load_rules(path):
    """Read a rule file ({"rules": [...]} or a bare list) and refuse it if any rule is invalid."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = data["rules"] if isinstance(data, dict) else data
    errs = validate_ruleset(rules)
    if errs:
        raise ValueError(f"{path}: " + "; ".join(errs))
    return rules


def _selftest():
    good = {"id": "R1", "name": "Many ports", "technique": "T1046", "origin": "baseline", "window_s": 10,
            "all_of": [{"kind": "syn", "measure": "distinct_dport", "op": ">=", "value": 15}]}
    assert validate_rule(good) == []
    bad = [
        {**good, "window_s": 0}, {**good, "window_s": 10_000}, {**good, "origin": "ai"}, {**good, "extra": 1},
        {**good, "id": "has space"}, {**good, "technique": "46"}, {**good, "all_of": []}, {**good, "all_of": [good["all_of"][0]] * 5},
        {**good, "all_of": [{"kind": "syn", "measure": "count", "op": "<=", "value": 3}]},
        {**good, "all_of": [{"kind": "syn", "measure": "distinct_path", "op": ">=", "value": 3}]},
        {**good, "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": 0}]},
        {**good, "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": True}]},
        {**good, "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": 3, "status_in": [404]}]},
        {**good, "all_of": [{"kind": "http_req", "measure": "count", "op": ">=", "value": 3, "method_in": ["rm -rf"]}]},
        {**good, "all_of": [{"kind": "http_req", "measure": "count", "op": ">=", "value": 3, "dport_in": [70000]}]},
        {**good, "all_of": [{"kind": "http_req", "measure": "count", "op": ">=", "value": 3, "trap": False}]},
        {**good, "all_of": [{"kind": "syn", "measure": "count", "op": ">=", "value": 3, "regex": ".*"}]},
        {**good, "all_of": ["syn"]}, "not a rule", None, {},
    ]
    for b in bad:
        assert validate_rule(b), f"should be rejected: {b}"
    assert validate_ruleset([good, good]) == ["R1: duplicate id"]
    from jsonschema import Draft202012Validator
    schema = Draft202012Validator(proposal_json_schema())
    assert not list(schema.iter_errors({"rule": good | {"origin": "proposed"}, "rationale": "r"}))
    assert list(schema.iter_errors({"rule": good, "rationale": "r"}))                       # origin must be 'proposed'
    print("rules selftest ok")


def main():
    if "--selftest" in sys.argv:
        return _selftest()
    if len(sys.argv) == 3 and sys.argv[1] == "validate":
        rules = load_rules(sys.argv[2])
        print(f"{len(rules)} rules valid")
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()

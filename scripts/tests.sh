#!/usr/bin/env bash
# One-command self-test of everything that can be checked WITHOUT the lab running (no Docker, no VMs, no Claude calls).
# Usage: bash scripts/tests.sh        Exit code 0 = all passed.
cd "$(dirname "$0")/.." || exit 1
FAIL=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=1; }
run()  { if out=$("${@:2}" 2>&1); then ok "$1"; else bad "$1"; printf '%s\n' "$out" | tail -5 | sed 's/^/        /'; fi; }

echo "Python compiles"
n=0; for f in $(git ls-files '*.py'); do python -m py_compile "$f" 2>/dev/null || { bad "$f does not compile"; n=1; }; done; [ $n -eq 0 ] && ok "all tracked .py files compile"

echo "Shell scripts parse"
n=0; for f in $(git ls-files '*.sh'); do bash -n "$f" 2>/dev/null || { bad "$f has a syntax error"; n=1; }; done; [ $n -eq 0 ] && ok "all tracked .sh files parse"

echo "Module self-checks"
run "campaign scoring (eval/campaign_eval.py)"   python eval/campaign_eval.py --selftest
run "two-attacker scoring (eval/dual_eval.py)"   python eval/dual_eval.py --selftest
run "session transcripts (agent/transcripts.py)" python agent/transcripts.py --selftest
run "dashboard attacker commands (dashboard/commands.py)" python dashboard/commands.py --selftest
run "attacker memory (agent/attacker_memory.py)" python agent/attacker_memory.py --selftest
run "spoofed-source merging (agent/aliases.py)" python agent/aliases.py --selftest
run "believability linter (agent/believability.py)" python agent/believability.py --selftest
run "detection-rule validation (detect/rules.py)" python detect/rules.py --selftest
run "packet events (detect/events.py)"           python detect/events.py --selftest
run "honeypot-side events (detect/hpevents.py)"  python detect/hpevents.py --selftest
run "streaming rule engine (detect/engine.py)"   python detect/engine.py --selftest
run "structural evidence (detect/evidence.py)"   python detect/evidence.py --selftest
run "promotion gate (detect/gate.py)"            python detect/gate.py --selftest
run "injection + poisoned-proposal tests (detect/injection_test.py)" python detect/injection_test.py
run "baseline rules are valid"                   python detect/rules.py validate detect/rules/baseline.json

echo "Configuration invariants"
run "allowlist templates == schema decoy enum" python - <<'EOF'
import json
a = set(json.load(open("controller/allowlist.json"))["templates"])
s = set(json.load(open("agent/schema.json"))["properties"]["analyses"]["items"]["properties"]["recommended_decoys"]["items"]["enum"])
assert a == s, f"allowlist {sorted(a)} != schema {sorted(s)}"
EOF
run "severity: honeytoken use or decoy contact is Critical, old rules unchanged" python - <<'EOF3'
import sys
sys.path.insert(0, "agent")
from severity import severity
assert severity("reconnaissance", 0.9, token_used=True) == "Critical"
assert severity("discovery", 0.4, decoy_reached=True) == "Critical"
assert severity("credential_access", 0.8) == "High" and severity("reconnaissance", 0.9) == "Medium"
assert severity("reconnaissance", 0.4) == "Low" and severity("discovery", 0.6) == "Low"
EOF3
run "db decoy: patched MySQL module mounted and shows the host, not Docker's gateway" python - <<'EOF4'
import json
a = json.load(open("controller/allowlist.json"))["templates"]["db_decoy"]
assert a.get("show_client_as_host") and any(m["container"].endswith("modules/mysql.py") for m in a["extra_mounts"]), a
src = open("lab/opencanary/mysql_patched.py", encoding="utf-8").read()
assert "DECOY_SHOWN_CLIENT" in src and "Access denied for user" in src
EOF4
run "fast-path policy names only allowlisted templates" python - <<'EOF2'
import json
a = json.load(open("controller/allowlist.json"))
assert set(a["fast_path"]["spawn"]) <= set(a["templates"]), a["fast_path"]
assert set(a["fast_path"]["spawn"]) <= set(a["lure_chain_policy"]["also_spawn"]), "fast path must not start anything the lure-chain policy would not"
reads = a["fast_path"].get("on_reads", {})
assert all(set(v) <= set(a["lure_chain_policy"]["also_spawn"]) for v in reads.values()), reads
lf = {x["path"] for x in json.load(open("lab/lures/honeytokens.json"))["lure_files"]}
assert set(reads) == lf, ("every lure file needs an on_reads entry and the reverse", set(reads), lf)
import sys; sys.path.insert(0, "agent"); import honeytokens as h
files = h.load_lure_files()
assert h.lure_file_of({"path": "\\DOCS\IT-Notes.TXT"}, files) and not h.lure_file_of({"path": "readme.txt"}, files), "lure file matching"
EOF2
run "promoted rules are valid" bash -c '[ ! -f detect/rules/promoted.json ] || python detect/rules.py validate detect/rules/promoted.json'
run "JSON config files are valid" python - <<'EOF'
import json
for f in ("controller/allowlist.json", "agent/schema.json", "lab/lures/honeytokens.json"):
    json.load(open(f))
EOF
run "campaign scenario names agree (campaign.sh / run_campaign.py / campaign_eval.py)" python - <<'EOF'
import re, sys
sys.path.insert(0, "eval")
import campaign_eval as c
sh = open("attacks/campaign.sh", encoding="utf-8").read()
fns = set(re.findall(r"^scenario_(\w+)\(\)", sh, re.M))
src = open("eval/run_campaign.py", encoding="utf-8").read()
attacks = set(re.search(r"ATTACKS = \(([^)]*)\)", src).group(1).replace('"', "").replace(" ", "").split(","))
assert fns == attacks | {"idle"}, (fns, attacks)
assert fns == set(c.LABELS) - {"manual"}, (fns, set(c.LABELS))      # "manual" is written by attacks/manual.sh, not by campaign.sh
assert attacks <= set(c.EXPECTED), (attacks, set(c.EXPECTED))
EOF
run "benign generator: every action has an interval" python -c "import sys; sys.path.insert(0, 'traffic'); import generator as g; assert set(g.ACTIONS) == set(g.MEAN_INTERVAL)"
run "lived-in decoy content generates with no credentials" python lab/cowrie_custom/lived_in.py "$(mktemp -d)"

echo
[ "$FAIL" -eq 0 ] && echo "ALL PASSED" || echo "SOME CHECKS FAILED"
exit "$FAIL"

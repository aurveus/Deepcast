#!/usr/bin/env python3
"""Ask Claude for ONE detection rule from structural evidence (no tools, no traffic, no attacker text).

  python detect/propose.py evidence.json            # prints the proposal JSON

Claude runs with every tool disabled and a JSON schema for its answer; the rule is then checked by rules.py.
Proposing changes nothing: the promotion gate (gate.py) decides whether the rule ever runs.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from evidence import check_structural  # noqa: E402
from rules import proposal_json_schema, validate_rule  # noqa: E402

PROMPT = (HERE / "proposer_prompt.md").read_text(encoding="utf-8")
TIMEOUT = 300


def propose(evidence, existing_ids=()):
    """Return {"rule": ..., "rationale": ...}. Raises on a CLI failure or an invalid rule."""
    check_structural(evidence)                                    # last line of defence: nothing but numbers and fixed words goes out
    claude = shutil.which("claude")
    if not claude:
        raise RuntimeError("claude CLI not found on PATH")
    user = ("Evidence (JSON):\n" + json.dumps(evidence, indent=1) + "\n\nRule ids already in use: " + ", ".join(sorted(existing_ids)) +
            "\nReturn the JSON result now.")
    cmd = [claude, "-p", "--output-format", "json", "--system-prompt", PROMPT, "--tools", "", "--permission-mode", "dontAsk",
           "--no-session-persistence", "--json-schema", json.dumps(proposal_json_schema())]
    r = subprocess.run(cmd, input=user, capture_output=True, text=True, encoding="utf-8", timeout=TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"claude exited {r.returncode}: {r.stderr[:300]}")
    wrapper = json.loads(r.stdout)
    out = wrapper.get("structured_output") if isinstance(wrapper, dict) else None
    if not isinstance(out, dict):
        raise ValueError("no structured answer from Claude")
    errs = validate_rule(out.get("rule"))
    if errs:
        raise ValueError("proposal is not a valid rule: " + "; ".join(errs))
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(json.dumps(propose(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))), indent=1))

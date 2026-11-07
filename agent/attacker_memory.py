#!/usr/bin/env python3
"""Attacker memory: what the platform already knows about a source IP from earlier incidents.

  python agent/attacker_memory.py <ip>        # print the history (and the text block the analysis would receive)
  python agent/attacker_memory.py --selftest

Everything is derived from the append-only event log (lab/logs/events.jsonl), so memory survives restarts and needs no
extra database. For one IP it answers: how many incidents, when first and last seen, how far it escalated (stages in
order), which techniques it has used, which honeytokens it used, which decoys were spawned for it.

Trust model: all of it comes from the platform's own events (our verdicts, controller actions, honeytoken detector), not from
attacker-controlled text. It is context for the analysis agent and the report, never a reason to skip evidence in the new capture
(a returning IP is not automatically malicious this time).
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "lab" / "logs" / "events.jsonl"
STAGE_ORDER = ["reconnaissance", "initial_access", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration"]


def _epoch(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except (ValueError, AttributeError):
        return None


def history(ip, events_path=EVENTS, before=None):
    """Summary dict for `ip` using only events strictly before `before` (epoch, default: all). None if never seen."""
    h = {"ip": ip, "incidents": {}, "stages": [], "techniques": {}, "honeytokens": {}, "decoys": {}, "first": None, "last": None, "clean": 0}
    try:
        lines = Path(events_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    rows = []
    for raw in lines:
        try:
            rows.append(json.loads(raw))
        except ValueError:
            continue
    retracted = {r.get("run_id") for r in rows if r.get("event") == "verdict_retracted"}      # a human reviewed the incident and reversed the verdict
    for e in rows:
        t = _epoch(e.get("ts"))
        if e.get("attacker_ip") != ip or t is None or (before is not None and t >= before) or e.get("run_id") in retracted:
            continue
        kind = e.get("event")
        # Only CONFIRMED findings count as history. A gate trigger is not a verdict: counting triggers made a routine source that trips the
        # gate every few minutes look like a repeat offender, which then nudged the next analysis toward suspicion (a feedback loop).
        if kind == "watch_triage_clean":
            h["clean"] += 1
            continue
        if kind not in ("attack_detected", "decoy_spawned", "honeytoken_attributed"):
            continue
        h["first"] = t if h["first"] is None else min(h["first"], t)
        h["last"] = t if h["last"] is None else max(h["last"], t)
        h["incidents"].setdefault(e.get("run_id", "?"), t)
        if kind == "attack_detected":
            if e.get("stage") and (not h["stages"] or h["stages"][-1][1] != e["stage"]):
                h["stages"].append((t, e["stage"]))
            for tech in e.get("techniques", []):
                h["techniques"].setdefault(tech, t)
        elif kind == "decoy_spawned":
            h["decoys"][e.get("template", "?")] = h["decoys"].get(e.get("template", "?"), 0) + 1
        elif kind == "honeytoken_attributed":
            h["honeytokens"].setdefault(e.get("token", "?"), (t, e.get("planted_in", "?")))
    return h if (h["first"] is not None or h["clean"]) else None


def furthest_stage(h):
    seen = [s for _, s in h["stages"] if s in STAGE_ORDER]
    return max(seen, key=STAGE_ORDER.index) if seen else None


def facts(ip, events_path=EVENTS, before=None):
    """Text block for the analysis input: trusted platform history for this IP, or '' if it is new."""
    h = history(ip, events_path, before)
    if not h:
        return ""
    if h["first"] is None:                                  # only routine history: say so, it is useful context for the verdict
        return (f"Attacker memory (trusted: from the platform's own event log; context only, judge the new traffic on its own evidence):\n"
                f"- {ip} has never been confirmed as an attacker. {h['clean']} earlier incident(s) from it were judged routine (nothing found).")
    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"Attacker memory (trusted: from the platform's own event log; context only, judge the new traffic on its own evidence):",
           f"- {ip} was first confirmed {fmt(h['first'])} and last {fmt(h['last'])}, across {len(h['incidents'])} earlier confirmed incident(s)" + (f"; {h['clean']} other incident(s) from it were judged routine." if h["clean"] else "."),
           f"- Furthest stage reached so far: {furthest_stage(h) or 'unknown'}."]
    if h["stages"]:
        out.append("- Escalation order seen: " + " -> ".join(dict.fromkeys(s for _, s in h["stages"])))
    if h["techniques"]:
        out.append("- Techniques already attributed: " + ", ".join(sorted(h["techniques"])))
    if h["honeytokens"]:
        out.append("- Honeytokens it has already used: " + ", ".join(f"{k} ({v[1]})" for k, v in sorted(h["honeytokens"].items())))
    if h["decoys"]:
        out.append("- Decoys previously spawned for it: " + ", ".join(f"{k} x{v}" for k, v in sorted(h["decoys"].items())))
    return "\n".join(out)


def selftest():
    import tempfile
    rows = [{"ts": "2026-10-20T10:00:00Z", "event": "watch_trigger", "attacker_ip": "1.2.3.4", "run_id": "r1"},
            {"ts": "2026-10-20T10:01:00Z", "event": "attack_detected", "attacker_ip": "1.2.3.4", "run_id": "r1", "stage": "reconnaissance", "techniques": ["T1595.001"]},
            {"ts": "2026-10-20T11:00:00Z", "event": "attack_detected", "attacker_ip": "1.2.3.4", "run_id": "r2", "stage": "initial_access", "techniques": ["T1595.001", "T1078"]},
            {"ts": "2026-10-20T11:00:05Z", "event": "honeytoken_attributed", "attacker_ip": "1.2.3.4", "run_id": "r2", "token": "HT-001", "planted_in": "web lure"},
            {"ts": "2026-10-20T11:00:09Z", "event": "decoy_spawned", "attacker_ip": "1.2.3.4", "run_id": "r2", "template": "ssh_decoy"},
            {"ts": "2026-10-20T11:30:00Z", "event": "attack_detected", "attacker_ip": "9.9.9.9", "run_id": "r3", "stage": "reconnaissance", "techniques": []}]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "e.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        h = history("1.2.3.4", p)
        assert len(h["incidents"]) == 2 and h["clean"] == 0 and furthest_stage(h) == "initial_access" and "HT-001" in h["honeytokens"], h
        assert history("5.5.5.5", p) is None and facts("5.5.5.5", p) == ""
        early = history("1.2.3.4", p, before=_epoch("2026-10-20T10:30:00Z"))
        assert len(early["incidents"]) == 1 and furthest_stage(early) == "reconnaissance", early       # nothing from the future leaks in
        assert "reconnaissance -> initial_access" in facts("1.2.3.4", p)
    # routine history: triggers and clean verdicts never make a source look like an offender; retracted verdicts disappear
    rows2 = [{"ts": "2026-10-20T10:00:00Z", "event": "watch_trigger", "attacker_ip": "7.7.7.7", "run_id": "a"},
             {"ts": "2026-10-20T10:01:00Z", "event": "watch_triage_clean", "attacker_ip": "7.7.7.7", "run_id": "a"},
             {"ts": "2026-10-20T11:00:00Z", "event": "watch_trigger", "attacker_ip": "7.7.7.7", "run_id": "b"},
             {"ts": "2026-10-20T11:01:00Z", "event": "watch_triage_clean", "attacker_ip": "7.7.7.7", "run_id": "b"},
             {"ts": "2026-10-20T12:00:00Z", "event": "attack_detected", "attacker_ip": "7.7.7.7", "run_id": "c", "stage": "discovery", "techniques": []},
             {"ts": "2026-10-20T12:01:00Z", "event": "verdict_retracted", "run_id": "c", "reason": "reviewed"}]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "e.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows2), encoding="utf-8")
        h = history("7.7.7.7", p)
        assert h["clean"] == 2 and h["first"] is None and not h["incidents"], h
        text = facts("7.7.7.7", p)
        assert "never been confirmed" in text and "2 earlier incident" in text, text
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    elif len(sys.argv) == 2:
        sys.stdout.reconfigure(encoding="utf-8")
        print(facts(sys.argv[1]) or "(never seen before)")
    else:
        sys.exit(__doc__)

#!/usr/bin/env python3
"""Score an unattended attack campaign against its own ground truth.

  python eval/campaign_eval.py attacks/logs/campaign_*.jsonl             # one or more logs; writes eval/results/campaign.{json,md}
  python eval/campaign_eval.py --selftest                             # checks the scoring rules on synthetic data

Ground truth = the campaign log written on Kali (real start/end per scenario, UTC). Detections = the
platform's own event log (lab/logs/events.jsonl), so this scores the live pipeline, not saved pcaps.

Assignment rules (stated in the results so they can be defended):
  - A `watch_trigger` (the cheap gate that wakes the agent) naming KALI_IP belongs to the latest scenario that
    started before it, if it happened no later than that scenario's end + GRACE seconds. Otherwise it is unassigned.
  - `attack_detected` (Claude's confirmed verdict, confidence >= controller threshold). Back-to-back scenarios can be
    merged into ONE incident (the source never goes quiet), and each Claude report lists all techniques seen so far. So
    a report counts for a scenario only if it falls in [start, end + LATE] and shows a technique that scenario produces
    (EXPECTED) which the previous report of the same incident did not yet show (the first report of an incident counts
    as all-new). Reports that add nothing new are continuations and are ignored.
  - Excluded, not counted as misses: scenarios listed with a reason in eval/campaign_exclude.txt, scenarios during a Claude
    outage (watch_error), and "merged" scenarios whose
    technique was already reported earlier in the same incident (detection happened but cannot be attributed).
  - `decoy_spawned` goes to the scenario of the report it follows (within 60 s), else to the latest scenario that started before it.
  - Detected = an attack scenario has a Claude detection. Time to detect = detection time - REAL attack start
    (gate time is reported too). Decoy deployed = a decoy_spawned is linked to it.
  - False alarm = a trigger or detection naming any other source IP (except the host), or naming Kali inside an `idle` window.
"""
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "eval" / "results"
GRACE, LATE = 180, 900
# Source addresses the attacker's own stealth scan spoofs as decoys (see attacks/campaign.sh): part of the attack, not false alarms.
DECOY_SOURCES = {"10.10.10.201", "10.10.10.202", "10.10.10.203"}
EXPECTED = {"portscan": ("T1595.001", "T1046"), "slowscan": ("T1595.001", "T1046", "T1595"), "sshbrute": ("T1110",),
            "webprobe": ("T1595.002", "T1190", "T1083", "T1592"), "lure": ("T1552", "T1078", "T1135"),
            "dirbrute": ("T1595.002", "T1083", "T1592"), "stealthscan": ("T1595.001", "T1046", "T1595"),
            "traverse": ("T1552", "T1078", "T1083", "T1018", "T1033"),
            "overlap": (),      # scored by OVERLAP_FAMILIES below, never by the single-technique rule
            # a person at the keyboard: any technique counts, every new one is a continuation of the same session
            "manual": ("T1595", "T1595.001", "T1595.002", "T1046", "T1110", "T1110.001", "T1552", "T1552.001", "T1552.003", "T1078",
                       "T1083", "T1082", "T1033", "T1018", "T1135", "T1190", "T1592", "T1021", "T1021.004", "T1059.004", "T1105")}
# An overlap scenario runs three attacks at once; it only counts as detected when the reports together cover all three behaviors.
OVERLAP_FAMILIES = (("T1595.001", "T1046", "T1595"), ("T1110",), ("T1595.002", "T1083", "T1592"))
LABELS = {"portscan": "Port scan", "slowscan": "Slow port scan", "sshbrute": "SSH brute force",
          "webprobe": "Web probing", "lure": "Lure chain", "dirbrute": "Directory brute force",
          "stealthscan": "Stealth scan (fragmented/decoy)", "traverse": "Deep trap traversal", "overlap": "Overlapping attacks (3 at once)", "manual": "Manual session (a person)", "idle": "Benign only (idle)"}


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def read_jsonl(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def env():
    out = {}
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def manual_exclusions():
    """Scenario start times listed in eval/campaign_exclude.txt (each line carries its reason)."""
    f = ROOT / "eval" / "campaign_exclude.txt"
    if not f.exists():
        return set()
    return {l.split("#")[0].strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#") and l.split("#")[0].strip()}


def score(scen, events, kali, host, min_conf):
    scen = sorted(scen, key=lambda s: s["t0"])
    t_start, t_end = scen[0]["t0"], scen[-1]["t1"] + LATE
    ev = [e for e in events if t_start <= e["t"] <= t_end]
    for s in scen:
        s.update(trigger=None, detected=None, decoy=None, false_alarms=0, analysis_error=False)
    for e in ev:                                         # Claude unavailable (usage limit, crash): not a detection miss
        if e.get("event") == "watch_error" and e.get("where") == "analysis":
            for s in scen:
                if s["t0"] <= e["t"] <= s["t1"] + LATE:
                    s["analysis_error"] = True
    last_report = {}         # run_id -> (time, scenario) of its latest credited report
    seen_techs = {}          # run_id -> techniques already reported for that incident
    unassigned = 0
    origin = {}              # run_id -> the attack scenario its first credited event belonged to

    def by_time(t, limit):
        cand = [s for s in scen if s["t0"] <= t]
        return cand[-1] if cand and t <= cand[-1]["t1"] + limit else None

    def place(run_id, t):
        """Plain time rule, except that Claude's slower follow-up (report, decoy) of an incident that began in an attack scenario
        belongs to that scenario when the clock has meanwhile reached the next idle window: nothing benign was flagged there."""
        cur = by_time(t, LATE)
        if cur is None or cur["scenario"] == "idle":
            s = origin.get(run_id)
            if s is not None and t <= s["t1"] + LATE:
                return s
        return cur

    ev.sort(key=lambda e: e["t"])
    for e in ev:
        ip, kind = e.get("attacker_ip"), e.get("event")
        if kind not in ("watch_trigger", "attack_detected", "decoy_spawned") or not ip or ip == host or ip in DECOY_SOURCES:
            continue
        if kind == "attack_detected" and e.get("confidence", 0) < min_conf:
            continue
        if ip != kali:
            scen_for = by_time(e["t"], LATE)
            (scen_for or scen[0])["false_alarms"] += 1
            continue
        if kind == "watch_trigger":
            s = by_time(e["t"], GRACE)
            if s is None:
                unassigned += 1
                continue
        elif kind == "attack_detected":
            techs = set(e.get("techniques", []))
            new_t = techs - seen_techs.get(e.get("run_id"), set())
            seen_techs[e.get("run_id")] = techs | seen_techs.get(e.get("run_id"), set())
            if not new_t:
                continue                                         # continuation report: nothing new to credit
            cand = [x for x in scen if x["t0"] <= e["t"] <= x["t1"] + LATE]
            hit = [x for x in cand if x["scenario"] != "idle" and x["detected"] is None
                   and any(t.startswith(p) for t in new_t for p in EXPECTED.get(x["scenario"], ()))]
            s = hit[-1] if hit else place(e.get("run_id"), e["t"])    # most recent matching scenario; else plain time rule
            if s is None:
                unassigned += 1
                continue
        else:                                                    # decoy_spawned: follows its detection within seconds
            last = last_report.get(e.get("run_id"))
            s = last[1] if last and e["t"] - last[0] < 60 else place(e.get("run_id"), e["t"])
            if s is None:
                unassigned += 1
                continue
        if kind == "attack_detected":
            last_report[e.get("run_id")] = (e["t"], s)
        if s["scenario"] != "idle":
            origin.setdefault(e.get("run_id"), s)
        if s["scenario"] == "idle":
            s["false_alarms"] += 1
            continue
        key = {"watch_trigger": "trigger", "attack_detected": "detected", "decoy_spawned": "decoy"}[kind]
        if key == "detected" and s["scenario"] == "overlap":
            continue                                                  # credited below, only when all three behaviors are reported
        if s[key] is None:
            s[key] = e["t"]
    for s in scen:                                                   # overlap: the time at which the reports first cover all three behaviors
        if s["scenario"] != "overlap":
            continue
        got = set()
        for e in ev:
            if (e.get("event") == "attack_detected" and e.get("attacker_ip") == kali and e.get("confidence", 0) >= min_conf
                    and s["t0"] <= e["t"] <= s["t1"] + LATE):
                got |= set(e.get("techniques", []))
                if all(any(t.startswith(p) for t in got for p in fam) for fam in OVERLAP_FAMILIES):
                    s["detected"] = e["t"]
                    break
        s["families_covered"] = sum(any(t.startswith(p) for t in got for p in fam) for fam in OVERLAP_FAMILIES)
    # Merged incidents: the watcher folds back-to-back scenarios into one incident and Claude reports cumulatively.
    # If a scenario got no credit but a report during it already shows one of its techniques (reported earlier for the
    # same incident), detection happened but cannot be attributed to this scenario: exclude it, do not call it a miss.
    for s in scen:
        s["merged"] = False
        if s["scenario"] == "idle" or s["detected"] is not None:
            continue
        exp = EXPECTED.get(s["scenario"], ())
        s["merged"] = any(e.get("event") == "attack_detected" and e.get("attacker_ip") == kali and e.get("confidence", 0) >= min_conf
                          and s["t0"] <= e["t"] <= s["t1"] + LATE and any(t.startswith(p) for t in e.get("techniques", []) for p in exp)
                          for e in ev)
    manual = manual_exclusions()
    for s in scen:
        s["manually_excluded"] = s.get("start") in manual
        s["excluded"] = s["manually_excluded"] or (s["detected"] is None and (s["analysis_error"] or s["merged"]))
    return scen, unassigned


def summarize(rows):
    out = []
    for key, label in LABELS.items():
        r = [x for x in rows if x["scenario"] == key]
        if not r:
            continue
        med = lambda f: (round(statistics.median(v), 1) if (v := [x[f] for x in r if x[f] is not None]) else None)
        attack = key != "idle"
        failed = [x for x in r if x["excluded"]]     # Claude unavailable, or detection not attributable (merged incident)
        r = [x for x in r if x not in failed]
        if not r:
            out.append({"scenario": label, "runs": 0, "excluded": len(failed)})
            continue
        out.append({"scenario": label, "runs": len(r),
                    "gate_triggered": f"{sum(x['trigger'] is not None for x in r)}/{len(r)}" if attack else "n/a",
                    "claude_detected": f"{sum(x['detected'] is not None for x in r)}/{len(r)}" if attack else "n/a",
                    "ttd_s": med("ttd_s") if attack else None, "gate_s": med("gate_s") if attack else None,
                    "decoy_deployed": f"{sum(x['decoy'] is not None for x in r)}/{len(r)}" if attack else "n/a",
                    "false_alarms": sum(x["false_alarms"] for x in r), "excluded": len(failed)})
    return out


def markdown(summary, unassigned):
    cols = ["Scenario", "Runs", "Excluded (outage / merged)", "Gate triggered", "Claude detected", "Median time to detect (s)", "Median gate (s)", "Decoy deployed", "False alarms"]
    v = lambda x: "–" if x is None else x
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summary:
        if not s["runs"]:
            lines.append(f"| {s['scenario']} | 0 | {s['excluded']} | – | – | – | – | – | – |")
            continue
        lines.append(f"| {s['scenario']} | {s['runs']} | {s['excluded']} | {s['gate_triggered']} | {s['claude_detected']} | {v(s['ttd_s'])} | {v(s['gate_s'])} | {s['decoy_deployed']} | {s['false_alarms']} |")
    note = (f"\nTime to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). "
            f"Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: {unassigned}.\n")
    return "\n".join(lines) + "\n" + note


def evaluate(campaign_logs, events_log=None):
    cfg = env()
    kali, host = cfg.get("KALI_IP", "10.10.10.10"), cfg.get("HOST_IP", "10.10.10.1")
    min_conf = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))["min_confidence"]
    if isinstance(campaign_logs, (str, Path)):
        campaign_logs = [campaign_logs]
    scen, seen = [], set()
    for log in campaign_logs:                                   # several logs (partial run + resume) are scored together
        for c in read_jsonl(log):
            if c.get("event") == "scenario" and c["start"] not in seen:
                seen.add(c["start"])
                scen.append({"n": len(scen) + 1, "scenario": c["scenario"], "t0": ts(c["start"]), "t1": ts(c["end"]), "start": c["start"]})
    if not scen:
        sys.exit("no scenarios in the campaign log")
    events = []
    for e in read_jsonl(events_log or ROOT / "lab" / "logs" / "events.jsonl"):
        try:
            e["t"] = ts(e["ts"])
            events.append(e)
        except (KeyError, ValueError):
            pass
    rows, unassigned = score(scen, events, kali, host, min_conf)
    for r in rows:
        r["ttd_s"] = None if r["detected"] is None else round(r["detected"] - r["t0"], 1)
        r["gate_s"] = None if r["trigger"] is None else round(r["trigger"] - r["t0"], 1)
    return rows, summarize(rows), unassigned


def selftest():
    kali, host = "10.10.10.10", "10.10.10.1"
    scen = [{"n": 1, "scenario": "portscan", "t0": 1000, "t1": 1100}, {"n": 2, "scenario": "idle", "t0": 1300, "t1": 1480},
            {"n": 3, "scenario": "sshbrute", "t0": 1600, "t1": 1700}, {"n": 4, "scenario": "webprobe", "t0": 1750, "t1": 1800}]
    ev = [{"t": 1030, "event": "watch_trigger", "attacker_ip": kali, "run_id": "A"},
          {"t": 1710, "event": "attack_detected", "attacker_ip": kali, "run_id": "A", "confidence": 0.9, "techniques": ["T1595.001"]},   # late: still portscan's run
          {"t": 1712, "event": "decoy_spawned", "attacker_ip": kali, "run_id": "A"},
          {"t": 1620, "event": "watch_trigger", "attacker_ip": kali, "run_id": "B"},
          {"t": 1790, "event": "attack_detected", "attacker_ip": kali, "run_id": "B", "confidence": 0.3},   # below threshold: ignored
          {"t": 1400, "event": "watch_trigger", "attacker_ip": "10.10.10.99", "run_id": "C"},              # other IP: false alarm
          {"t": 1350, "event": "watch_trigger", "attacker_ip": host, "run_id": "D"}]                         # host: ignored
    rows, un = score([dict(s) for s in scen], ev, kali, host, 0.5)
    by = {r["scenario"]: r for r in rows}
    assert by["portscan"]["detected"] == 1710 and by["portscan"]["decoy"] == 1712, by["portscan"]
    assert by["sshbrute"]["trigger"] == 1620 and by["sshbrute"]["detected"] is None, by["sshbrute"]
    assert by["idle"]["false_alarms"] == 1 and by["webprobe"]["trigger"] is None, by
    assert un == 0
    # overlap: credited only when the reports cover scan + brute force + web probing, at the time the last one appears
    so = [{"n": 1, "scenario": "overlap", "t0": 100, "t1": 300}]
    eo = [{"t": 150, "event": "attack_detected", "attacker_ip": kali, "run_id": "O", "confidence": 0.9, "techniques": ["T1595.001"]},
          {"t": 200, "event": "attack_detected", "attacker_ip": kali, "run_id": "O", "confidence": 0.9, "techniques": ["T1595.001", "T1110.001"]}]
    r4, _ = score([dict(x) for x in so], eo, kali, host, 0.5)
    assert r4[0]["detected"] is None and r4[0]["families_covered"] == 2, r4
    eo.append({"t": 260, "event": "attack_detected", "attacker_ip": kali, "run_id": "O", "confidence": 0.9, "techniques": ["T1595.001", "T1110.001", "T1595.002"]})
    r5, _ = score([dict(x) for x in so], eo, kali, host, 0.5)
    assert r5[0]["detected"] == 260 and r5[0]["families_covered"] == 3, r5
    # spoofed decoy sources of the attacker's own stealth scan must not count as false alarms
    r3, _ = score([{"n": 1, "scenario": "stealthscan", "t0": 100, "t1": 200}], [{"t": 120, "event": "watch_trigger", "attacker_ip": "10.10.10.202", "run_id": "D"}], kali, host, 0.5)
    assert r3[0]["false_alarms"] == 0 and r3[0]["trigger"] is None, r3
    # merged incident: one run_id, cumulative techniques; each scenario is credited when its technique first appears
    sc2 = [{"n": 1, "scenario": "sshbrute", "t0": 100, "t1": 110}, {"n": 2, "scenario": "webprobe", "t0": 150, "t1": 400},
           {"n": 3, "scenario": "portscan", "t0": 450, "t1": 600}]
    ev2 = [{"t": 120, "event": "attack_detected", "attacker_ip": kali, "run_id": "M", "confidence": 0.9, "techniques": ["T1110.001"]},
           {"t": 300, "event": "attack_detected", "attacker_ip": kali, "run_id": "M", "confidence": 0.9, "techniques": ["T1110.001", "T1595.002"]},
           {"t": 420, "event": "attack_detected", "attacker_ip": kali, "run_id": "M", "confidence": 0.9, "techniques": ["T1110.001", "T1595.002"]},
           {"t": 520, "event": "attack_detected", "attacker_ip": kali, "run_id": "M", "confidence": 0.9, "techniques": ["T1110.001", "T1595.002", "T1595.001"]}]
    r2, _ = score([dict(s) for s in sc2], ev2, kali, host, 0.5)
    got = {r["scenario"]: r["detected"] for r in r2}
    assert got == {"sshbrute": 120, "webprobe": 300, "portscan": 520}, got
    # a slow follow-up (new technique, decoy) of an incident that began in portscan lands just after the idle window opened:
    # it belongs to portscan; a Kali trigger with its own, new incident inside idle is still a false alarm
    sc3 = [{"n": 1, "scenario": "portscan", "t0": 100, "t1": 200}, {"n": 2, "scenario": "idle", "t0": 300, "t1": 480}]
    ev3 = [{"t": 150, "event": "attack_detected", "attacker_ip": kali, "run_id": "A", "confidence": 0.9, "techniques": ["T1595.001"]},
           {"t": 303, "event": "attack_detected", "attacker_ip": kali, "run_id": "A", "confidence": 0.9, "techniques": ["T1595.001", "T1046"]},
           {"t": 304, "event": "decoy_spawned", "attacker_ip": kali, "run_id": "A"},
           {"t": 400, "event": "watch_trigger", "attacker_ip": kali, "run_id": "B"}]
    r6, _ = score([dict(s) for s in sc3], ev3, kali, host, 0.5)
    by6 = {r["scenario"]: r for r in r6}
    assert by6["idle"]["false_alarms"] == 1 and by6["portscan"]["decoy"] == 304 and by6["portscan"]["detected"] == 150, by6
    print("selftest ok")


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    args = sys.argv[1:]
    name = "campaign"
    if "--out" in args:                       # keep a separate result pair (e.g. manual sessions) instead of overwriting the campaign results
        i = args.index("--out")
        name = "campaign_" + args[i + 1]
        del args[i:i + 2]
    logs = args
    rows, summary, unassigned = evaluate(logs)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps({"summary": summary, "runs": rows, "unassigned": unassigned,
                                                   "source": [Path(l).name for l in logs]}, indent=2), encoding="utf-8")
    md = markdown(summary, unassigned)
    (OUT / f"{name}.md").write_text(md, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()

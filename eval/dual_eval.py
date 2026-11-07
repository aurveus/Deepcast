#!/usr/bin/env python3
"""Score a two-attacker run (attacks/dual_attacker.sh): did the platform keep two simultaneous sources apart?

  python eval/dual_eval.py attacks/logs/dual_<time>.jsonl      # writes eval/results/dual_<time>.{json,md}
  python eval/dual_eval.py --selftest

Ground truth: the Kali script logs the real start/end of attacker A (Kali's own address: port scan + SSH brute force) and of
attacker B (a second address: web lure, planted SSH credential, a short look around the server). Checks, all against the event log:
  both_detected       each attacker has its own confirmed detection (B was not swallowed into A: the two addresses share one Ethernet address)
  a_behavior_ok       A's techniques include scanning or brute force (T1595, T1046, T1110)
  b_behavior_ok       B's techniques include credential use (T1552, T1078)
  token_credit_ok     every honeytoken use in the window is attributed to B and at least one is (A never used a honeytoken)
  no_leak_to_a        A is not credited with B's credential techniques (T1552, T1078)
  no_false_alarm      no trigger, detection or decoy names any other address (the workstation, for instance)
  fast_path_ok        the honeytoken use was seen within FAST_S seconds of the login, even though A's incident was being analyzed
                      (added after the first run showed 28 s: the watcher's main loop was blocked by A's analysis)
"""
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "lab" / "logs" / "events.jsonl"
OUT = ROOT / "eval" / "results"
LATE = 900
FAST_S = 5.0
DECOY_SOURCES = {"10.10.10.201", "10.10.10.202", "10.10.10.203"}       # spoofed decoy addresses of the stealth scan
A_TECH, B_TECH, LEAK_TECH = ("T1595", "T1046", "T1110"), ("T1552", "T1078"), ("T1552", "T1078")


def ts(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def read_jsonl(path):
    out = []
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def env_value(key, default):
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return default


def min_conf():
    try:
        return json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))["min_confidence"]
    except (OSError, ValueError, KeyError):
        return 0.5


def score(truth, events, host, conf_min):
    att = {e["role"]: {"ip": e["ip"], "scenario": e["scenario"], "t0": ts(e["start"]), "t1": ts(e["end"])} for e in truth if e.get("event") == "attacker"}
    if set(att) != {"A", "B"}:
        raise SystemExit("the log needs both attackers (A and B); did the run finish?")
    t_start, t_end = min(a["t0"] for a in att.values()) - 10, max(a["t1"] for a in att.values()) + LATE
    ev = sorted(((ts(e["ts"]), e) for e in events if "ts" in e), key=lambda x: x[0])
    ev = [(t, e) for t, e in ev if t_start <= t <= t_end]
    ips = {a["ip"]: role for role, a in att.items()}
    rows = {}
    for role, a in att.items():
        mine = [(t, e) for t, e in ev if e.get("attacker_ip") == a["ip"]]
        det = [(t, e) for t, e in mine if e.get("event") == "attack_detected" and e.get("confidence", 0) >= conf_min]
        rows[role] = {"ip": a["ip"], "scenario": a["scenario"], "start": a["t0"],
                      "trigger_s": next((round(t - a["t0"], 1) for t, e in mine if e.get("event") == "watch_trigger"), None),
                      "detected_s": round(det[0][0] - a["t0"], 1) if det else None,
                      "techniques": sorted({x for _, e in det for x in e.get("techniques", [])}),
                      "decoys": sorted({e.get("template") for _, e in mine if e.get("event") == "decoy_spawned"}),
                      "honeytokens": sorted({e.get("token") for _, e in ev if e.get("event") == "honeytoken_attributed" and e.get("attacker_ip") == a["ip"]})}
    # fast path: honeytoken use is logged by the watcher without any attacker address; its decoys carry the token in `trigger`
    fast = {}
    for _, att_ev in ev:
        if att_ev.get("event") != "honeytoken_attributed" or att_ev.get("attacker_ip") not in ips:
            continue
        hit = att_ev.get("hit_time")
        used = [t for t, e in ev if e.get("event") == "honeytoken_used" and e.get("token") == att_ev.get("token") and hit is not None and t >= hit - 2]
        slot = fast.setdefault(att_ev["attacker_ip"], {"delay": None, "decoys": set()})
        if used and hit is not None:
            d = round(min(used) - hit, 1)
            slot["delay"] = d if slot["delay"] is None else max(slot["delay"], d)
            for t, e in ev:
                if e.get("event") == "decoy_spawned" and att_ev.get("token", "?") in str(e.get("trigger", "")) and min(used) - 1 <= t <= min(used) + 60:
                    slot["decoys"].add(e.get("template"))
    for role in rows:
        f = fast.get(rows[role]["ip"], {"delay": None, "decoys": set()})
        rows[role]["fast_path_s"] = f["delay"]
        rows[role]["decoys"] = sorted(set(rows[role]["decoys"]) | f["decoys"])
    others = [(e.get("event"), e.get("attacker_ip")) for _, e in ev
              if e.get("event") in ("watch_trigger", "attack_detected", "decoy_spawned") and e.get("attacker_ip")
              and e["attacker_ip"] not in ips and e["attacker_ip"] != host and e["attacker_ip"] not in DECOY_SOURCES
              and not (e.get("event") == "attack_detected" and e.get("confidence", 0) < conf_min)]
    credited = [(e.get("token"), e.get("attacker_ip")) for _, e in ev if e.get("event") == "honeytoken_attributed"]
    a, b = rows["A"], rows["B"]
    starts = lambda techs, prefixes: any(t.startswith(p) for t in techs for p in prefixes)
    checks = {
        "both_detected": a["detected_s"] is not None and b["detected_s"] is not None,
        "a_behavior_ok": starts(a["techniques"], A_TECH),
        "b_behavior_ok": starts(b["techniques"], B_TECH),
        "token_credit_ok": bool(credited) and all(ip == b["ip"] for _, ip in credited),
        "no_leak_to_a": not starts(a["techniques"], LEAK_TECH),
        "no_false_alarm": not others,
        "fast_path_ok": b["fast_path_s"] is not None and b["fast_path_s"] <= FAST_S,
    }
    return {"attackers": rows, "honeytoken_credit": credited, "other_sources": others, "checks": checks, "passed": all(checks.values())}


def markdown(res):
    lines = ["| Attacker | Address | Scenario | Gate (s) | Detected (s) | Techniques | Decoys | Honeytokens credited | Honeytoken seen after (s) |", "|---|---|---|---|---|---|---|---|---|"]
    for role in ("A", "B"):
        r = res["attackers"][role]
        lines.append(f"| {role} | {r['ip']} | {r['scenario']} | {r['trigger_s'] if r['trigger_s'] is not None else '-'} | "
                     f"{r['detected_s'] if r['detected_s'] is not None else '-'} | {', '.join(r['techniques']) or '-'} | {', '.join(r['decoys']) or '-'} | {', '.join(r['honeytokens']) or '-'} | {r['fast_path_s'] if r.get('fast_path_s') is not None else '-'} |")
    lines += ["", "| Check | Result |", "|---|---|"] + [f"| {k} | {'PASS' if v else 'FAIL'} |" for k, v in res["checks"].items()]
    if res["other_sources"]:
        lines += ["", "Events naming other addresses: " + ", ".join(f"{e} {ip}" for e, ip in res["other_sources"])]
    lines += ["", "Overall: " + ("PASS" if res["passed"] else "FAIL"),
              "Time is measured from each attacker's own start. A runs a port scan and an SSH brute force; B follows the web lure and logs in with the planted credential while A's traffic is running."]
    return "\n".join(lines)


def evaluate(log):
    return score(read_jsonl(log), read_jsonl(EVENTS), env_value("HOST_IP", "10.10.10.1"), min_conf())


def selftest():
    host, a_ip, b_ip, ws = "10.10.10.1", "10.10.10.10", "10.10.10.11", "10.10.10.30"
    truth = [{"event": "attacker", "role": "A", "ip": a_ip, "scenario": "portscan+sshbrute", "start": "2026-10-25T10:00:00Z", "end": "2026-10-25T10:03:00Z"},
             {"event": "attacker", "role": "B", "ip": b_ip, "scenario": "lure_ssh", "start": "2026-10-25T10:00:25Z", "end": "2026-10-25T10:01:10Z"}]
    base = [{"ts": "2026-10-25T10:00:20Z", "event": "watch_trigger", "attacker_ip": a_ip},
            {"ts": "2026-10-25T10:00:50Z", "event": "attack_detected", "attacker_ip": a_ip, "confidence": 0.9, "techniques": ["T1595.001", "T1110.001"]},
            {"ts": "2026-10-25T10:00:58Z", "event": "honeytoken_used", "token": "HT-001"},
            {"ts": "2026-10-25T10:00:59Z", "event": "decoy_spawned", "template": "smb_decoy", "trigger": "honeytoken HT-001"},
            {"ts": "2026-10-25T10:01:00Z", "event": "honeytoken_attributed", "attacker_ip": b_ip, "token": "HT-001", "hit_time": ts("2026-10-25T10:00:57Z")},
            {"ts": "2026-10-25T10:01:30Z", "event": "attack_detected", "attacker_ip": b_ip, "confidence": 0.9, "techniques": ["T1552.001", "T1078"]},
            {"ts": "2026-10-25T10:01:31Z", "event": "decoy_spawned", "attacker_ip": b_ip, "template": "db_decoy"},
            {"ts": "2026-10-25T10:01:40Z", "event": "attack_detected", "attacker_ip": ws, "confidence": 0.3, "techniques": ["T1082"]}]   # below threshold: ignored
    good = score(truth, base, host, 0.5)
    assert good["passed"] and good["attackers"]["B"]["honeytokens"] == ["HT-001"] and good["attackers"]["A"]["trigger_s"] == 20.0, good
    assert good["attackers"]["B"]["fast_path_s"] == 1.0 and good["attackers"]["B"]["decoys"] == ["db_decoy", "smb_decoy"], good["attackers"]["B"]
    slow = [dict(e) for e in base]
    for e in slow:
        if e["event"] == "honeytoken_used":
            e["ts"] = "2026-10-25T10:01:25Z"                                              # honeytoken use logged 28 s after the login (watcher blocked)
    assert not score(truth, slow, host, 0.5)["checks"]["fast_path_ok"]
    bad = [dict(e) for e in base]
    for e in bad:                                                                       # the honeytoken is credited to the wrong source
        if e["event"] == "honeytoken_attributed":
            e["attacker_ip"] = a_ip
    bad.append({"ts": "2026-10-25T10:02:00Z", "event": "watch_trigger", "attacker_ip": ws})   # and the workstation is flagged
    res = score(truth, bad, host, 0.5)
    assert not res["checks"]["token_credit_ok"] and not res["checks"]["no_false_alarm"] and not res["passed"], res
    merged = [e for e in base if e.get("attacker_ip") != b_ip]                          # B swallowed into A: no detection of its own
    assert not score(truth, merged, host, 0.5)["checks"]["both_detected"]
    print("selftest ok")


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    res = evaluate(sys.argv[1])
    name = Path(sys.argv[1]).stem
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    md = markdown(res)
    (OUT / f"{name}.md").write_text(md, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(md)
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main() or 0)

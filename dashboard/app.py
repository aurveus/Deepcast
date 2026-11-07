#!/usr/bin/env python3
"""Local, read-only dashboard. Run: python dashboard/app.py  ->  http://127.0.0.1:5000

Reads lab/logs/events.jsonl, <runs>/*/analysis.json and the live decoy list from Docker.
It never writes anything and has no endpoint that changes the lab. Listens on localhost only.
"""
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, send_from_directory

import attack_info
import commands

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
import pyramid  # noqa: E402
import severity  # noqa: E402  (Pyramid of Pain levels, shared with the incident report)
EVENTS = ROOT / "lab" / "logs" / "events.jsonl"
RUN_ROOTS = [ROOT / "capture" / "runs", ROOT / "replays"]  # replays/ = committed sample runs for the demo fallback
STATIC = Path(__file__).resolve().parent / "static"
DECOY_TTL_S = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))["ttl_minutes"] * 60

# ATT&CK tactic order and the techniques we expect (tactic placement follows MITRE's own data).
TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
           "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
           "Command and Control", "Exfiltration", "Impact"]
# Tactics per MITRE's own data. A technique MITRE lists under several tactics is drawn once, under the one the agent's stage names
# (else the first), and the rest are shown in its detail as "also listed under".
TECHNIQUE_TACTICS = {
    "T1595": ["Reconnaissance"], "T1595.001": ["Reconnaissance"], "T1595.002": ["Reconnaissance"], "T1595.003": ["Reconnaissance"],
    "T1190": ["Initial Access"], "T1078": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
    "T1110": ["Credential Access"], "T1110.001": ["Credential Access"], "T1110.003": ["Credential Access"],
    "T1552.001": ["Credential Access"], "T1552.003": ["Credential Access"], "T1003.008": ["Credential Access"],
    "T1046": ["Discovery"], "T1082": ["Discovery"], "T1083": ["Discovery"], "T1135": ["Discovery"], "T1033": ["Discovery"],
    "T1016": ["Discovery"], "T1018": ["Discovery"], "T1057": ["Discovery"],
    "T1021": ["Lateral Movement"], "T1021.004": ["Lateral Movement"],
    "T1059.004": ["Execution"], "T1053.003": ["Execution", "Persistence", "Privilege Escalation"],
    "T1136.001": ["Persistence"], "T1098": ["Persistence"], "T1070.003": ["Defense Evasion"], "T1562": ["Defense Evasion"],
    "T1560": ["Collection"], "T1105": ["Command and Control"],
}
STAGE_TO_TACTIC = {"reconnaissance": "Reconnaissance", "initial_access": "Initial Access",
                   "credential_access": "Credential Access", "discovery": "Discovery",
                   "lateral_movement": "Lateral Movement", "collection": "Collection",
                   "exfiltration": "Exfiltration"}

app = Flask(__name__, static_folder=None)


@app.after_request
def secure(resp):
    # Event text can contain attacker-controlled strings: no inline script, no external loads.
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def read_events():
    out = []
    if EVENTS.exists():
        for line in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def load_runs():
    """All runs with an analysis.json, newest first. A run in capture/runs wins over the same name in replays/."""
    runs = {}
    for root in reversed(RUN_ROOTS):
        for d in sorted(root.glob("*/")) if root.exists() else []:
            f = d / "analysis.json"
            if f.exists():
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                except ValueError:
                    continue
                pcaps = list((d / "pcaps").glob("*.pcap")) if (d / "pcaps").exists() else []
                runs[d.name] = {"run_id": d.name, "analyses": data.get("analyses", []),
                                "time": f.stat().st_mtime, "path": str(d), "pcap_files": len(pcaps),
                                "pcap_bytes": sum(p.stat().st_size for p in pcaps), "source": root.name}
    return sorted(runs.values(), key=lambda r: -r["time"])


def stat_runs():
    """Runs used for counters, sessions and the MITRE view. Bundled replay samples only count when
    there are no real runs (fresh clone / demo fallback); the Replay tab always lists everything."""
    runs = load_runs()
    real = [r for r in runs if r["source"] != "replays"]
    return real or runs


def live_decoys():
    try:
        out = subprocess.run(
            ["docker", "ps", "--filter", "label=deception.spawned=true", "--format",
             '{{.Names}}\t{{.Label "deception.template"}}\t{{.Label "deception.ip"}}\t{{.Label "deception.expires"}}\t{{.Status}}'],
            capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    rows = []
    for line in out.splitlines():
        name, tpl, ip, exp, status = line.split("\t")
        rows.append({"name": name, "template": tpl, "ip": ip, "expires": int(exp or 0), "status": status,
                     "activity": decoy_activity(name, max(0, int(exp or 0) - DECOY_TTL_S))})
    return rows


def live_capture_counts():
    """Packets and bytes in the in-progress capture (capinfos is fast; only called while a run is active)."""
    files = sorted((ROOT / "capture" / "pcaps").glob("*.pcap"))
    size = sum(f.stat().st_size for f in files)
    packets = 0
    exe = shutil.which("capinfos") or r"C:\Program Files\Wireshark\capinfos.exe"  # fallback: default install path
    if files and Path(exe).exists():
        for f in files:
            try:
                out = subprocess.run([str(exe), "-c", "-M", str(f)], capture_output=True, text=True, timeout=5).stdout
                packets += int(out.split("Number of packets:")[1].split()[0])
            except (OSError, subprocess.TimeoutExpired, IndexError, ValueError):
                pass
    return packets, size


@app.get("/api/status")
def status():
    """Current run stage written by run_loop.sh (controller/emit_event.py). Idle if absent or stale."""
    f = ROOT / "lab" / "logs" / "run_status.json"
    try:
        st = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return jsonify({"stage": "idle"})
    if st.get("stage") == "idle" or time.time() - st.get("updated", 0) > 1800:
        return jsonify({"stage": "idle"})
    out = {**st, "now": time.time()}
    if st["stage"] == "capturing":
        out["packets"], out["bytes"] = live_capture_counts()
    return jsonify(out)


@app.get("/api/overview")
def overview():
    events, runs = read_events(), stat_runs()
    count = lambda e: sum(1 for x in events if x.get("event") == e)
    decoys = live_decoys()
    return jsonify({
        "runs_analyzed": len(runs),
        "attacks_detected": count("attack_detected"),
        "clean_runs": count("analysis_clean"),
        "disputed_clean": count("analysis_clean_disputed"),
        "decoys_spawned": count("decoy_spawned"),
        "decoys_live": None if decoys is None else len(decoys),
        "rejections": count("decoy_rejected") + count("approval_denied"),
        "now": time.time(),
    })


@app.get("/api/events")
def events():
    return jsonify(list(reversed(read_events()))[:500])


@app.get("/api/sessions")
def sessions():
    out = []
    for r in stat_runs():
        saved = {}                                     # severity.json is written by the incident report (it knows about honeytokens and decoy contact)
        try:
            saved = {x["ip"]: x for x in json.loads((Path(r["path"]) / "severity.json").read_text(encoding="utf-8"))}
        except (OSError, ValueError, KeyError):
            pass
        for a in r["analyses"]:
            sv = saved.get(a["attacker_ip"], {})
            out.append({**a, "run_id": r["run_id"], "time": r["time"],
                        "severity": sv.get("severity") or base_severity(a),
                        "trap_contact": {"honeytokens": sv.get("honeytokens_used", 0), "decoys": sv.get("decoys_reached", 0)},
                        "has_report": (Path(r["path"]) / "incident_report.html").exists()})
    return jsonify(out)


def base_severity(a):
    return severity.severity(a["stage"], a["confidence"])


def is_parent_child(x, y):
    """T1595 and T1595.001 are the same family, not two separate behaviors."""
    return x.startswith(y + ".") or y.startswith(x + ".")


TOGETHER_S, TOGETHER_MIN = 10, 2   # two different commands count as "together" when typed within 10 s of each other, in at least 2 sessions


def session_pairs():
    """Techniques whose commands the attacker typed close together in the SAME shell session (not merely in the same incident).
    Returns ({technique: sessions it appeared in}, {x: {y: {sessions, order, example}}}). Built from the saved honeypot command
    rows (the fixed command->technique rules in agent/transcripts.py); network-only techniques such as scans have no commands."""
    with_x, pairs = {}, {}
    for r in stat_runs():
        for sess in (commands.run_commands(r["path"]) or {}).get("sessions", []):
            hits = {}
            for row in sess["rows"]:
                for tid in row["techs"]:
                    hits.setdefault(tid, []).append((row["at"], row["cmd"]))
            for x in hits:
                with_x[x] = with_x.get(x, 0) + 1
                for y in hits:
                    if x == y or is_parent_child(x, y):
                        continue
                    close = [(ay - ax, cx, cy) for ax, cx in hits[x] for ay, cy in hits[y] if cx != cy and abs(ay - ax) <= TOGETHER_S]   # one command matching two rules is not a pair
                    if not close:
                        continue
                    gap, cx, cy = min(close, key=lambda q: abs(q[0]))
                    p = pairs.setdefault(x, {}).setdefault(y, {"sessions": 0, "after": 0, "before": 0, "example": [cx, cy]})
                    p["sessions"] += 1
                    p["after"] += gap > 0
                    p["before"] += gap < 0
    for ys in pairs.values():
        for p in ys.values():
            p["order"] = "after" if p["after"] > p["before"] else "before" if p["before"] > p["after"] else "either"
    return with_x, pairs


def pyramid_view(ips, tools, techniques):
    """The Pyramid of Pain with what this lab recorded at each level. Counts come from the analyses only; the lower levels
    (hashes, domains, artifacts) are described, not counted, because the analyses do not carry them (the incident report does)."""
    seen = {"ip": f"{len(ips)} attacker IP{'' if len(ips) == 1 else 's'} seen",
            "tool": (", ".join(sorted(tools)) + " named in the evidence") if tools else "no tool named in the evidence",
            "ttp": f"{len(techniques)} ATT&CK technique{'' if len(techniques) == 1 else 's'} mapped"}
    return [{**lv, "seen": seen.get(lv["key"], "")} for lv in pyramid.describe()]


@app.get("/api/mitre")
def mitre():
    """Observed techniques with plain-language explanations and MITRE links. 'together' and 'pairs' are built ONLY from
    techniques the agent reported in the same incident (same run, same attacker): nothing is inferred beyond that."""
    techniques, pair_data, ips, tools = {}, {}, set(), set()
    for r in stat_runs():
        for a in r["analyses"]:
            ips.add(a["attacker_ip"])
            tools.update(pyramid.tools_in(*a["evidence"], a["summary"]))
            ids = [t["id"] for t in a["techniques"]]
            for t in a["techniques"]:
                listed = TECHNIQUE_TACTICS.get(t["id"]) or [STAGE_TO_TACTIC.get(a["stage"], "Reconnaissance")]
                staged = STAGE_TO_TACTIC.get(a["stage"])
                tactics = [staged if staged in listed else listed[0]]
                info = attack_info.describe(t["id"])
                e = techniques.setdefault(t["id"], {"id": t["id"], "name": info["name"] or t["name"], "tactics": tactics, "also": [x for x in listed if x not in tactics], "what": info["what"],
                                                    "url": info["url"], "count": 0, "runs": [], "evidence": [], "incidents": [], "together": []})
                e["count"] += 1
                e["runs"].append(r["run_id"])
                e["evidence"] += a["evidence"][:2]
                e["incidents"].append({"run_id": r["run_id"], "ip": a["attacker_ip"], "time": r["time"], "confidence": a["confidence"],
                                       "summary": a["summary"][:420]})
            for i, x in enumerate(ids):
                for y in ids[i + 1:]:
                    if is_parent_child(x, y):
                        continue
                    key = tuple(sorted((x, y)))
                    pd = pair_data.setdefault(key, {"count": 0, "ips": set()})
                    pd["count"] += 1
                    pd["ips"].add(a["attacker_ip"])
    in_session, near = session_pairs()
    for e in techniques.values():
        e["incidents"].sort(key=lambda i: -i["time"])
        e["sessions"] = in_session.get(e["id"], 0)
        # strongest link first: shared sessions / sessions with either technique, so a technique present in every session does not top every list
        rows = [{"id": y, **v, "of": e["sessions"], "link": v["sessions"] / (e["sessions"] + in_session[y] - v["sessions"])}
                for y, v in near.get(e["id"], {}).items() if v["sessions"] >= TOGETHER_MIN]
        e["together"] = sorted(rows, key=lambda t: (-t["link"], t["id"]))[:6]
    pairs = []
    for (x, y), pd in sorted(pair_data.items(), key=lambda kv: -kv[1]["count"]):
        tx, ty = techniques[x]["tactics"][0], techniques[y]["tactics"][0]
        first, second = sorted([tx, ty], key=TACTICS.index)
        pairs.append({"a": x, "b": y, "count": pd["count"], "ips": sorted(pd["ips"]),
                      "tactics": first if first == second else f"{first} → {second}"})
    return jsonify({"tactics": TACTICS, "techniques": list(techniques.values()), "pairs": pairs, "pyramid": pyramid_view(ips, tools, techniques)})


def decoy_activity(name, spawned_after=0):
    """Event count and the latest commands/logins on one decoy since it was spawned (read from its own log folder)."""
    folder = ROOT / "lab" / "logs" / "decoys" / name
    events, commands, logins = 0, [], []
    for f in sorted(folder.glob("*.json")) if folder.exists() else []:
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                o = json.loads(raw)
            except ValueError:
                continue
            ev = o.get("eventid") or o.get("logtype")
            ts = o.get("timestamp") or o.get("utc_time") or ""
            try:
                t = datetime.fromisoformat(str(ts).replace("Z", "+00:00").replace(" ", "T"))
                t = (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()
            except ValueError:
                t = 0
            if t <= spawned_after or ev in (None, 1001, "smb.log", "cowrie.log.open"):
                continue
            events += 1
            if ev == "cowrie.command.input":
                commands.append(str(o.get("input", ""))[:80])
            elif str(ev).startswith("cowrie.login"):
                logins.append(str(o.get("username", ""))[:40])
            elif ev == 8001:
                logins.append(str((o.get("logdata") or {}).get("USERNAME", ""))[:40])
    return {"events": events, "commands": commands[-3:], "logins": sorted(set(logins))[:4]}


@app.get("/api/commands")
def run_commands_all():
    """Commands typed per catch (run id -> summary). Only runs whose saved logs contain attacker commands appear."""
    out = {}
    for r in stat_runs():
        c = commands.run_commands(r["path"])
        if c:
            out[r["run_id"]] = c
    return jsonify(out)


@app.get("/api/live")
def live_activity():
    """What an attacker typed in the last 15 minutes on the live SSH honeypot and the SSH decoys."""
    return jsonify(commands.live_commands(commands.sources_for(ROOT / "lab" / "logs")))


@app.get("/api/decoys")
def decoys():
    hist = [e for e in read_events() if e.get("event") in
            ("decoy_spawned", "decoy_retired", "decoy_rejected", "decoy_skipped", "decoy_failed",
             "approval_denied", "killswitch")]
    return jsonify({"live": live_decoys(), "history": list(reversed(hist))[:100], "now": time.time()})


@app.get("/api/eval")
def eval_results():
    f = ROOT / "eval" / "results" / "results.json"
    try:
        return jsonify(json.loads(f.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return jsonify({"summary": [], "runs": []})


@app.get("/api/campaign")
def campaign_results():
    f = ROOT / "eval" / "results" / "campaign.json"
    try:
        return jsonify(json.loads(f.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return jsonify({"summary": [], "runs": []})


@app.get("/api/runs")
def runs():
    return jsonify([{k: r[k] for k in ("run_id", "time", "source", "pcap_files", "pcap_bytes")}
                    | {"detections": len(r["analyses"])} for r in load_runs()])


@app.get("/api/replay/<run_id>")
def replay(run_id):
    """Everything saved about one run, ordered as the pipeline stages. Playback is done in the browser."""
    run = next((r for r in load_runs() if r["run_id"] == run_id), None)
    if not run:
        abort(404)
    ev = [e for e in read_events() if e.get("run_id") == run_id]
    return jsonify({"run": {k: run[k] for k in ("run_id", "time", "pcap_files", "pcap_bytes", "source")},
                    "analyses": run["analyses"], "events": ev})


@app.get("/report/<run_id>")
@app.get("/report/<run_id>.pdf", defaults={"pdf": True})
def incident_report(run_id, pdf=False):
    """Serve a generated incident report (HTML or PDF) for a known run. Only these two file names are served."""
    run = next((r for r in load_runs() if r["run_id"] == run_id), None)
    f = Path(run["path"]) / ("incident_report.pdf" if pdf else "incident_report.html") if run else None
    if not f or not f.exists():
        abort(404)
    if pdf:
        return send_from_directory(f.parent, f.name)
    # The report is static HTML with inline styles only: no scripts, nothing external. By default it follows the browser's light/dark
    # setting; ?theme=light|dark (added by the dashboard's link from its own Theme button) pins it to that theme.
    page, theme = f.read_text(encoding="utf-8"), request.args.get("theme")
    if theme == "light":
        page = re.sub(r"@media screen and \(prefers-color-scheme:dark\)\{.*?\n\}", "", page, flags=re.S).replace("content='light dark'", "content='light'")
    elif theme == "dark":
        page = page.replace("@media screen and (prefers-color-scheme:dark){", "@media screen{").replace("content='light dark'", "content='dark'")
    resp = Response(page, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return resp


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/static/<path:name>")
def static_files(name):
    return send_from_directory(STATIC, name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

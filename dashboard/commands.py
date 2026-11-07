"""Attacker commands for the dashboard: per catch (from the run's saved honeypot logs) and live (recent activity).

Reads the Cowrie logs only (the SSH honeypot and ssh_decoy) and reuses agent/transcripts.py to rebuild sessions and map
commands to ATT&CK techniques, so the dashboard, the report and the analysis agree. Read-only.

Long sessions stay readable: identical commands collapse into one row with a count, each session keeps at most
MAX_ROWS distinct rows (the rest is only counted), and at most MAX_SESSIONS sessions are listed per catch.
The benign traffic generator logs in as GEN_SSH_USER (from .env); its sessions are not attacker activity and are left out.
The command text is attacker-typed: it is sanitized and clipped by transcripts.sanitize, and the page only ever inserts it as text.
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
import transcripts  # noqa: E402

MAX_ROWS, MAX_SESSIONS, MAX_TECH_CMDS, LIVE_ROWS, LIVE_WINDOW_S, TAIL_BYTES = 60, 6, 6, 12, 15 * 60, 2_000_000
_cache = {}


def benign_user():
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("GEN_SSH_USER="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def read_lines(path, tail=None):
    try:
        with open(path, "rb") as f:
            if tail:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - tail))
            return f.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []


def techs_of(cmd):
    return sorted({tid for part in transcripts.split_commands(cmd) for tid, _ in transcripts.map_command(part)})


def condense(commands, t_start):
    """[(t, cmd)] -> rows [{cmd, n, at, techs}]: identical commands share one row (first time, how many times)."""
    rows, index = [], {}
    for t, cmd in commands:
        if cmd in index:
            index[cmd]["n"] += 1
            continue
        row = {"cmd": cmd, "n": 1, "at": int(t - t_start), "techs": techs_of(cmd)}
        index[cmd] = row
        rows.append(row)
    return rows


def sources_for(logs):
    """(label, cowrie json file) for the SSH honeypot and every ssh_decoy in a logs folder."""
    out = []
    main = logs / "cowrie" / "cowrie.json"
    if main.exists():
        out.append(("SSH honeypot", main))
    for f in sorted((logs / "decoys").glob("*ssh*/cowrie.json")) if (logs / "decoys").exists() else []:
        out.append((f"SSH decoy ({f.parent.name.replace('decoy-', '').replace('-decoy', '')})", f))
    return out


def run_window(run_path):
    """Capture window of a run: the pcap files' modification times (rotation is about 30 s per file)."""
    times = [p.stat().st_mtime for p in (Path(run_path) / "pcaps").glob("*.pcap")]
    return (min(times) - 60, max(times) + 5) if times else (None, None)


def run_commands(run_path):
    """Commands typed during one catch, or None. Sessions newest-last, identical commands collapsed, capped."""
    logs, (t0, t1) = Path(run_path) / "logs", run_window(run_path)
    if t0 is None:
        return None
    srcs = sources_for(logs)
    key = (str(run_path), tuple((str(f), f.stat().st_mtime, f.stat().st_size) for _, f in srcs))
    if key in _cache:
        return _cache[key]
    benign, sessions, total = benign_user(), [], 0
    for label, f in srcs:
        for s in transcripts.parse_sessions(read_lines(f), t0, t1):
            if not s["commands"] or s["user"] == benign:
                continue
            rows = condense(s["commands"], s["start"])
            total += len(s["commands"])
            sessions.append({"id": s["id"], "source": label, "user": s["user"] or "no login", "start": s["start"],
                             "commands": len(s["commands"]), "distinct": len(rows), "rows": rows[:MAX_ROWS], "more": max(0, len(rows) - MAX_ROWS)})
    sessions.sort(key=lambda s: s["start"])
    by_tech = {}
    for s in sessions:
        for r in s["rows"]:
            for tid in r["techs"]:
                slot = by_tech.setdefault(tid, {})
                slot[r["cmd"]] = slot.get(r["cmd"], 0) + r["n"]
    out = None
    if sessions:
        out = {"total": total, "distinct": sum(s["distinct"] for s in sessions), "session_count": len(sessions),
               "sessions": sessions[-MAX_SESSIONS:], "hidden_sessions": max(0, len(sessions) - MAX_SESSIONS),
               "by_tech": {tid: [{"cmd": c, "n": n} for c, n in sorted(v.items(), key=lambda kv: -kv[1])[:MAX_TECH_CMDS]] for tid, v in by_tech.items()}}
    _cache[key] = out
    return out


def live_commands(live_dirs):
    """The most recent attacker commands (last LIVE_WINDOW_S seconds) from the live honeypot logs, newest first."""
    now, benign, events = time.time(), benign_user(), []
    t0 = now - LIVE_WINDOW_S
    for label, f in live_dirs:
        for s in transcripts.parse_sessions(read_lines(f, TAIL_BYTES), t0, None):
            if s["user"] == benign:
                continue
            for t, cmd in s["commands"]:
                if t >= t0:
                    events.append({"t": t, "cmd": cmd, "user": s["user"] or "no login", "source": label, "session": s["id"], "techs": techs_of(cmd)})
    events.sort(key=lambda e: e["t"])
    rows = []   # consecutive repeats of the same command in one session become one row with a count
    for e in events:
        if rows and rows[-1]["session"] == e["session"] and rows[-1]["cmd"] == e["cmd"]:
            rows[-1]["n"] += 1
            rows[-1]["t"] = e["t"]
        else:
            rows.append({**e, "n": 1})
    return {"now": now, "window_s": LIVE_WINDOW_S, "total": len(events), "sessions": len({e["session"] for e in events}),
            "last": events[-1]["t"] if events else None, "rows": list(reversed(rows))[:LIVE_ROWS], "hidden": max(0, len(rows) - LIVE_ROWS)}


def selftest():
    import tempfile
    from datetime import datetime, timezone
    global benign_user
    benign_user = lambda: "jsmith"
    now = time.time()
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ev = lambda sid, eid, t, **kw: json.dumps({"session": sid, "eventid": eid, "timestamp": iso(t), **kw})
    lines = [ev("atk", "cowrie.login.success", now - 50, username="tdavies"), ev("ben", "cowrie.login.success", now - 50, username="jsmith"),
             ev("ben", "cowrie.command.input", now - 49, input="uptime")]
    lines += [ev("atk", "cowrie.command.input", now - 49 + i * 0.05, input="whoami" if i % 3 == 0 else f"cat /tmp/f{i}") for i in range(500)]
    with tempfile.TemporaryDirectory() as d:
        run = Path(d)
        (run / "pcaps").mkdir()
        (run / "pcaps" / "a.pcap").write_bytes(b"x")
        (run / "logs" / "cowrie").mkdir(parents=True)
        (run / "logs" / "cowrie" / "cowrie.json").write_text("\n".join(lines), encoding="utf-8")
        c = run_commands(run)
        assert c and c["total"] == 500 and c["session_count"] == 1, c and (c["total"], c["session_count"])   # benign jsmith session is left out
        s = c["sessions"][0]
        assert len(s["rows"]) == MAX_ROWS and s["more"] == s["distinct"] - MAX_ROWS > 0, "a long session must be capped"
        assert s["rows"][0]["cmd"] == "whoami" and s["rows"][0]["n"] == 167 and "T1033" in s["rows"][0]["techs"], s["rows"][0]
        assert "T1033" in c["by_tech"] and len(c["by_tech"]["T1033"]) <= MAX_TECH_CMDS
        assert run_commands(Path(d) / "missing") is None
    print("selftest ok")


if __name__ == "__main__":   # python dashboard/commands.py <run folder>  -> prints the JSON the dashboard receives
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    print(json.dumps(run_commands(sys.argv[1]) if len(sys.argv) > 1 else live_commands(sources_for(ROOT / "lab" / "logs")), indent=1)[:6000])

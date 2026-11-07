#!/usr/bin/env python3
"""Generate an incident report for one investigated run.

  python report/incident_report.py capture/runs/<run>        # writes incident_report.html (+ .pdf if Edge is found)

Sources: the run's analysis.json (Claude), the pcap (tshark, recomputed here), the honeypot logs,
the event log (decoys spawned) and the logs of those decoys. The PROOF section is computed from the
pcap and logs, never taken from Claude's text. All attacker-controlled strings are HTML-escaped.
"""
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
from analyze import find_tshark, line_epoch, sanitize  # noqa: E402  (reuse the hardened helpers)
import honeytokens  # noqa: E402
import pyramid  # noqa: E402
from severity import severity  # noqa: E402  (Pyramid of Pain level of each indicator)
from attribution import attribute_hit, http_requests_matching, nearest_source, service_times  # noqa: E402

TACTIC_OF = {  # technique -> ATT&CK tactic (per MITRE); sub-techniques fall back to their parent
    "T1595": "Reconnaissance", "T1595.001": "Reconnaissance", "T1595.002": "Reconnaissance", "T1595.003": "Reconnaissance",
    "T1110": "Credential Access", "T1110.001": "Credential Access", "T1110.003": "Credential Access",
    "T1046": "Discovery", "T1082": "Discovery", "T1083": "Discovery", "T1135": "Discovery", "T1018": "Discovery", "T1033": "Discovery",
    "T1078": "Initial Access / Persistence", "T1190": "Initial Access", "T1021.004": "Lateral Movement", "T1021": "Lateral Movement",
    "T1552": "Credential Access", "T1552.001": "Credential Access", "T1552.003": "Credential Access", "T1003": "Credential Access", "T1003.008": "Credential Access",
}
DISCOVERY = "Alert on discovery commands run right after a login (whoami, id, uname, listing home and config directories, listing shares or neighbouring hosts) and apply least privilege to accounts."
ADVICE = [  # (technique prefix, recommendation) fixed text, not model-generated; advice_for() lists each text once
    ("T1595", "Rate-limit or block the scanning source at the perimeter; expose only the services that must be reachable; keep honeypots on addresses no legitimate user needs."),
    ("T1595.002", "Remove or restrict forgotten web content (directory listings, backup and export files), keep web software patched, and put the site behind rate limiting or a web application firewall."),
    ("T1190", "Remove or restrict forgotten web content (directory listings, backup and export files), keep web software patched, and put the site behind rate limiting or a web application firewall."),
    ("T1110", "Disable password authentication for SSH (keys only), add lockout/rate limiting, and alert on repeated failed logins from one source."),
    ("T1046", "Segment the network so a foothold cannot enumerate other services; monitor east-west scans."),
    ("T1552", "Remove credentials from files, backups and web roots, scan for stored secrets, and rotate any credential that sat in a readable file."),
    ("T1078", "Rotate any credential that could have been exposed; review accounts that logged in during the window."),
    ("T1003", "Restrict who can read account and password files, and alert on reads of credential stores."),
    ("T1083", DISCOVERY),
    ("T1082", DISCOVERY),
    ("T1033", DISCOVERY),
    ("T1018", DISCOVERY),
    ("T1135", DISCOVERY),
    ("T1021", "Segment the network and allow SSH between internal hosts only where it is needed."),
]
try:
    LOGO = (ROOT / "dashboard" / "static" / "deepcast.svg").read_text(encoding="utf-8")
except OSError:
    LOGO = ""
MIN_CONF = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))["min_confidence"]
SEV_OUT = []   # one entry per incident rendered; main() saves it as severity.json for the dashboard
TRUE = ("1", "True", "true")  # tshark prints booleans differently across versions


def esc(x):
    return html.escape(str(x), quote=True)


def local_offset(d):
    z = d.strftime("%z")
    return f"UTC{z[:3]}:{z[3:]}" if z else "local"


def fmt_ts(epoch):
    """Host-local time with the offset shown (the dashboard also shows local time)."""
    d = datetime.fromtimestamp(epoch).astimezone()
    return d.strftime("%Y-%m-%d %H:%M:%S ") + local_offset(d)


def fmt_short(epoch):
    """Compact local time for tables (the offset is shown once in the column header)."""
    return datetime.fromtimestamp(epoch).astimezone().strftime("%m-%d %H:%M:%S")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def attacker_stats(pcaps, ip):
    """Recompute from the pcap what this source actually did."""
    fields = ["frame.time_epoch", "ip.dst", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack",
              "http.request.method", "http.request.uri", "http.user_agent", "ssh.protocol"]
    cmd = [find_tshark(), "-r", "", "-Y", f"ip.src=={ip}", "-T", "fields"] + sum([["-e", f] for f in fields], [])
    n, first, last = 0, None, None
    syn_ports, uris, uas, banners, dsts = Counter(), Counter(), Counter(), set(), set()
    http = 0
    for p in pcaps:
        cmd[2] = str(p)
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            c = (line.split("\t") + [""] * 9)[:9]
            n += 1
            t = float(c[0]); first = t if first is None else min(first, t); last = t if last is None else max(last, t)
            dsts.add(c[1])
            if c[3] in TRUE and c[4] not in TRUE and c[2]:  # bare SYN = new connection attempt
                syn_ports[c[2]] += 1
            if c[5]:
                http += 1; uris[c[6]] += 1
                if c[7]: uas[c[7]] += 1
            if c[8]: banners.add(c[8])
    return {"packets": n, "first": first, "last": last, "syns": sum(syn_ports.values()), "syn_ports": syn_ports,
            "http": http, "uris": uris, "uas": uas, "banners": sorted(banners), "dsts": sorted(dsts)}


def packet_sample(pcaps, ip, count=8):
    """First packets from the source as tshark prints them (read line by line, then stop early)."""
    proc = subprocess.Popen([find_tshark(), "-r", str(pcaps[0]), "-Y", f"ip.src=={ip} && !tcp.analysis.retransmission"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")   # tshark prints UTF-8 arrows
    lines = []
    for line in proc.stdout:
        lines.append(sanitize(line.strip(), 160))
        if len(lines) >= count:
            break
    proc.kill()
    return "\n".join(lines)


def pcap_window(pcaps):
    first = last = None
    total = 0
    for p in pcaps:
        out = subprocess.run([find_tshark(), "-r", str(p), "-T", "fields", "-e", "frame.time_epoch"],
                             capture_output=True, text=True, check=True).stdout.split()
        if out:
            total += len(out); first = float(out[0]) if first is None else min(first, float(out[0])); last = max(last or 0, float(out[-1]))
    return first, last, total


def honeypot_logs(logs_dir, t0, t1, ip, times):
    """Honeypot log summaries for ONE source. The logs only show the Docker gateway as the source, so each Cowrie
    session / web request is attributed to the source whose pcap connection time matches it best."""
    res = {"cowrie": Counter(), "cowrie_users": Counter(), "cowrie_pw": Counter(), "cowrie_cmds": [],
           "web_paths": Counter(), "web_status": Counter(), "web_uas": Counter(), "web_n": 0,
           "canary": Counter(), "smb": Counter(), "sessions": 0}
    logs = Path(logs_dir)
    if not logs.exists():
        return res

    def records(name):
        for f in sorted(logs.rglob(name)):
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    o = json.loads(raw)
                except ValueError:
                    continue
                ts = line_epoch(o)
                if ts is not None and t0 - 5 <= ts <= t1 + 5:
                    yield ts, o

    mine = set()
    for ts, o in records("cowrie.json"):
        if o.get("eventid") == "cowrie.session.connect" and nearest_source(times["ssh"], ts, 3) == ip:
            mine.add(o.get("session"))
    res["sessions"] = len(mine)
    for ts, o in records("cowrie.json"):
        if o.get("session") not in mine:
            continue
        res["cowrie"][o.get("eventid", "?")] += 1
        if o.get("eventid", "").startswith("cowrie.login"):
            res["cowrie_users"][sanitize(o.get("username", ""), 40)] += 1
            res["cowrie_pw"][sanitize(o.get("password", ""), 40)] += 1
        if o.get("eventid") == "cowrie.command.input" and len(res["cowrie_cmds"]) < 5000:
            res["cowrie_cmds"].append(sanitize(o.get("input", ""), 120))
    for ts, o in records("web.json"):
        if nearest_source(times["http"], ts, 2) == ip:
            res["web_n"] += 1; res["web_paths"][sanitize(o.get("path", ""), 80)] += 1
            res["web_status"][str(o.get("status"))] += 1; res["web_uas"][sanitize(o.get("user_agent", ""), 90)] += 1
    for _, o in records("opencanary.json"):
        res["canary"][str(o.get("logtype"))] += 1
    for _, o in records("smb.json"):
        res["smb"][o.get("eventid", "?")] += 1
    return res


def decoy_activity(run_name, win=(None, None)):
    """Decoys in play for this run and what happened on them afterwards (events from the event log). Included: decoys spawned for this run;
    decoys started by the honeytoken fast path during this incident (they start before any analysis exists, so they carry no run id);
    and decoys that were already running from an earlier incident when this one needed them (the controller logs those as skipped,
    'already running'): the source can still reach them, and for a lure chain they are the database and file-server decoys it walked into."""
    log = ROOT / "lab" / "logs" / "events.jsonl"
    events, last_spawn = [], {}
    if log.exists():
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            ets = datetime.fromisoformat(e["ts"]).timestamp() if e.get("ts") else None
            if e.get("event") == "decoy_spawned" and ets and win[1] and ets <= win[1] + 120:
                last_spawn[e.get("template")] = e                 # the latest spawn of each template up to the end of this incident
            fast = (e.get("event") in ("decoy_spawned", "decoy_skipped") and "honeytoken" in str(e.get("trigger", ""))
                    and ets and win[0] and win[1] and win[0] - 5 <= ets <= win[1] + 120)
            if e.get("run_id") == run_name or fast:
                events.append(e)

    def contacts_since(name, since):
        n, samples = 0, []
        d = ROOT / "lab" / "logs" / "decoys" / name
        for f in sorted(d.glob("*.json")) if d.exists() else []:
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    o = json.loads(raw)
                except ValueError:
                    continue
                ts = line_epoch(o)
                ev = o.get("eventid") or o.get("logtype")             # OpenCanary decoys (database, FTP) log a logtype, not an eventid
                if ts and ts > since and ev not in (None, 1001, "smb.log", "cowrie.log.open"):
                    n += 1
                    if len(samples) < 3: samples.append(sanitize(raw, 160))
        return n, samples

    out = []
    for e in events:
        if e.get("event") != "decoy_spawned":
            continue
        spawn = datetime.fromisoformat(e["ts"]).timestamp()
        n, samples = contacts_since(e.get("name", ""), spawn)
        out.append({"name": e["name"], "template": e["template"], "ip": e["ip"], "port": e.get("port"), "spawned": spawn,
                    "contacts": n, "samples": samples})
    have = {d["template"] for d in out}
    for e in events:
        if e.get("event") == "decoy_skipped" and e.get("reason") == "already running" and e.get("template") in last_spawn and e["template"] not in have:
            have.add(e["template"])
            sp = last_spawn[e["template"]]
            since = win[0] or 0
            n, samples = contacts_since(sp["name"], since)
            out.append({"name": sp["name"], "template": sp["template"], "ip": sp["ip"], "port": sp.get("port"), "spawned": since, "reused": True,
                        "started": datetime.fromisoformat(sp["ts"]).timestamp(), "contacts": n, "samples": samples})
    return events, out


def decoy_interaction(decoys, times, ip):
    """What THIS source did on each decoy spawned for the incident. The decoy logs only show the Docker gateway, so each
    session / event is attributed to a source by matching its time to the source's connection times in the pcap."""
    out = []
    for d in decoys:
        folder = ROOT / "lab" / "logs" / "decoys" / d["name"]
        rec = {**d, "sessions": 0, "events": 0, "logins": Counter(), "commands": [], "detail": [], "first": None, "last": None, "cmd_times": []}
        series = times["ssh"] if d["template"] == "ssh_decoy" else times["mysql"] if d["template"] == "db_decoy" else             times["smb"] if d["template"] == "smb_decoy" else times["http"]
        mine = set()
        lines = []
        for f in sorted(folder.glob("*.json")) if folder.exists() else []:
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    o = json.loads(raw)
                except ValueError:
                    continue
                ts = line_epoch(o)
                if ts and ts > d["spawned"]:
                    lines.append((ts, o))
        for ts, o in lines:
            if o.get("eventid") == "cowrie.session.connect" and nearest_source(series, ts, 3) == ip:
                mine.add(o.get("session"))
        for ts, o in lines:
            ev = o.get("eventid") or o.get("logtype")
            if d["template"] == "ssh_decoy":
                if o.get("session") not in mine:
                    continue
                rec["events"] += 1
                rec["first"] = ts if rec["first"] is None else min(rec["first"], ts)
                rec["last"] = ts if rec["last"] is None else max(rec["last"], ts)
                if str(ev).startswith("cowrie.login"):
                    rec["logins"][sanitize(o.get("username", ""), 40)] += 1
                elif ev == "cowrie.command.input" and len(rec["commands"]) < 5000:
                    rec["commands"].append(sanitize(o.get("input", ""), 100))
                    rec["cmd_times"].append((ts, sanitize(o.get("input", ""), 100)))
            elif nearest_source(series, ts, 3) == ip and ev not in (None, 1001, "smb.log"):
                rec["events"] += 1
                rec["first"] = ts if rec["first"] is None else min(rec["first"], ts)
                rec["last"] = ts if rec["last"] is None else max(rec["last"], ts)
                if d["template"] == "db_decoy" and ev == 8001:
                    rec["logins"][sanitize((o.get("logdata") or {}).get("USERNAME", ""), 40)] += 1
                elif d["template"] == "smb_decoy" and ev == "smb.auth":
                    rec["logins"][sanitize(str(o.get("user") or o.get("username") or ""), 40)] += 1
                elif d["template"] == "admin_panel_decoy" and len(rec["detail"]) < 8:
                    rec["detail"].append(sanitize(f"{o.get('method', '')} {o.get('path', '')} {o.get('status', '')}", 80))
        rec["sessions"] = len(mine)
        out.append(rec)
    return out


class Raw(str):
    """Marks already-escaped HTML."""


class Row(tuple):
    """A table row with a CSS class (crit / warn) so the key rows stand out."""

    def __new__(cls, cells, css=""):
        r = super().__new__(cls, cells)
        r.css = css
        return r


def table(headers, rows, cls=""):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(f"<tr class='{getattr(r, 'css', '')}'>" + "".join(f"<td>{c if isinstance(c, Raw) else esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table class='{cls}'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def cmd_bubbles(cmds, limit=40):
    """Typed commands as separate bubbles, in order of first use. Identical commands share one bubble with a count (x3); only the
    first `limit` distinct bubbles are drawn and the rest is counted, so hundreds of commands stay a short block."""
    items = list(Counter(cmds).items())
    chips = "".join(f"<code class='cmd'>{esc(c)}" + (f"<span class='x'>×{n}</span>" if n > 1 else "") + "</code>" for c, n in items[:limit])
    more = f"<span class='more'>+{len(items) - limit} more distinct</span>" if len(items) > limit else ""
    return Raw(f"<div class='cmds'>{chips}{more}</div>")


def cell_with_cmds(text, cmds, limit=40):
    """Table cell: the plain text first, then the typed commands as bubbles under it."""
    if not cmds:
        return text
    return Raw(esc(text) + f"<div class='lbl'>Commands typed ({len(cmds)})</div>" + cmd_bubbles(cmds, limit))


def top(counter, n=8):
    return ", ".join(f"{k or '(none)'} ({v})" for k, v in counter.most_common(n)) or "none"


def short(s, n=70):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


PORT_NAMES = {"21": "FTP", "22": "SSH", "23": "Telnet", "80": "HTTP", "443": "HTTPS", "445": "SMB", "2222": "SSH honeypot",
              "3306": "MySQL", "4445": "SMB decoy", "8080": "web admin panel"}


def port_label(p):
    return f"{p} {PORT_NAMES[p]}" if p in PORT_NAMES else str(p)


def span(first, last):
    if not first:
        return "n/a"
    s = round(last - first)
    return f"{s // 60} min {s % 60} s" if s >= 60 else f"{s} s"


def attack_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def tactic(tid):
    return TACTIC_OF.get(tid) or TACTIC_OF.get(tid.split(".")[0]) or "Unmapped (see ATT&CK)"


def callout(kind, title, text):
    return f"<div class='call {kind}'><b>{esc(title)}</b> {text if isinstance(text, Raw) else esc(text)}</div>"


def glance(items):
    return "<div class='glance'>" + "".join(
        f"<div class='tile {css}'><div class='k'>{esc(k)}</div><div class='v'>{v if isinstance(v, Raw) else esc(v)}</div></div>" for k, v, css in items) + "</div>"


def sec(n, title, tag="h3"):
    return f"<{tag} class='sec'>" + (f"<span class='no'>{n}</span>" if n else "") + f"{esc(title)}</{tag}>"


KIND = {"capture": ("Capture", ""), "detect": ("Detection", ""), "decoy": ("Decoy", ""), "lure": ("Lure", "crit"),
        "token": ("Honeytoken", "crit"), "contact": ("Decoy contact", "warn"), "typed": ("Typed", "warn")}


def timeline_rows(ip, st, win, events, decoys, used, fetched, inter):
    """One merged timeline. Repeats are collapsed: the same decoy re-deployed, and later analysis reports of the same activity."""
    tl = []
    if win[0]: tl.append((win[0], "capture", "Capture started (first packet on the lab network)"))
    if st["first"]: tl.append((st["first"], "capture", f"First packet from {ip}"))
    if st["last"]: tl.append((st["last"], "capture", f"Last packet from {ip} in this capture"))
    dets = sorted((datetime.fromisoformat(e["ts"]).timestamp(), e) for e in events
                  if e.get("event") == "attack_detected" and e.get("attacker_ip") in (None, ip))
    shown_stage, shown_conf, hidden = None, -1.0, []
    for t, e in dets:
        conf, stage = float(e.get("confidence") or 0), e.get("stage", "")
        if shown_stage is None or stage != shown_stage or conf >= shown_conf + 0.1:
            tl.append((t, "detect", f"Detection logged: {stage.replace('_', ' ')} (confidence {conf:.2f})"))
            shown_stage, shown_conf = stage, conf
        else:
            hidden.append((t, conf))
    if hidden:
        tl.append((hidden[-1][0], "detect", f"{len(hidden)} further analysis report(s) of the same activity "
                   f"(confidence {min(c for _, c in hidden):.2f} to {max(c for _, c in hidden):.2f})"))
    groups = {}
    for d in sorted(decoys, key=lambda d: d["spawned"]):
        groups.setdefault((d["template"], d["ip"], d["port"]), []).append(d["spawned"])
    reused = {(d["template"], d["ip"], d["port"]) for d in decoys if d.get("reused")}
    for (tpl, dip, port), ts in groups.items():
        if (tpl, dip, port) in reused:
            continue                                              # already running before this incident: its first contact row tells the story
        msg = f"Decoy {tpl} appeared at {dip}:{port}"
        if len(ts) > 1:
            msg += f" (deployed {len(ts)} times during the incident, last at {fmt_short(ts[-1])})"
        tl.append((ts[0], "decoy", msg))
    seen_uri = set()
    for t, u in sorted(fetched):                      # the lure files this source fetched, first fetch of each
        if u not in seen_uri:
            seen_uri.add(u)
            tl.append((t, "lure", f"Fetched lure {u}"))
    for h in used:
        tl.append((h["ts"], "token", f"Used honeytoken {h['token']} ({h['username']}) on {h['service_label']}"))
    for r in inter:                                   # the same source across every decoy: one story, not one table per host
        if r["first"] is not None:
            tl.append((r["first"], "contact", f"First contact with decoy {r['template']} ({r['ip']}): {r['events']} event(s)"))
        for t, cmd in r["cmd_times"][:6]:
            tl.append((t, "typed", f"Typed on {r['template']}: {cmd}"))
    return [Row((fmt_short(t), Raw(f"<span class='chip k-{k}'>{KIND[k][0]}</span>"), m), KIND[k][1]) for t, k, m in sorted(tl, key=lambda x: x[0])]


def advice_for(techs, used, reached):
    ids = [t["id"] for t in techs]
    out = []
    for pre, txt in ADVICE:
        if any(i.startswith(pre) for i in ids) and txt not in out:
            out.append(txt)
    if used:
        out.append("Treat the account(s) " + ", ".join(sorted({h["username"] for h in used})) + " as compromised: rotate the credential and check every place it is accepted.")
    if reached:
        out.append("The source moved into " + ", ".join(sorted({r["template"] for r in reached})) + ": review the real hosts of the same kind for the same activity.")
    return out


CSS = """@page{size:A4;margin:12mm}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
html{background:#fff;color-scheme:light}
body{font:13px/1.5 "Segoe UI",Arial,sans-serif;color:#151c28;background:#fff;margin:0}
.wrap{max-width:900px;margin:0 auto;padding:0 4px 18px}
.top{background:#131a23;color:#e9edf3;padding:16px 22px;display:flex;align-items:center;gap:16px;border-bottom:4px solid #3b82f6;border-radius:8px}
.top svg{width:44px;height:44px;flex:none}
.top .t{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8fb4f5}
.top h1{font-size:20px;margin:2px 0;color:#fff;font-weight:600;overflow-wrap:anywhere}
.top .m{color:#9aa6b8;font-size:11.5px}
h2.inc{background:#1f2a3a;color:#fff;padding:9px 16px;border-radius:7px;display:flex;justify-content:space-between;align-items:center;margin:24px 0 10px;font-size:16px;break-after:avoid}
h2.inc code{color:#cfe0ff;font-size:16px}
h3.sec,h2.sec{background:#eaf1ff;border-left:6px solid #3b82f6;color:#173a7a;padding:6px 12px;margin:22px 0 8px;font-size:14px;border-radius:0 6px 6px 0;break-after:avoid}
h3.sec .no{display:inline-block;min-width:22px;height:22px;line-height:22px;text-align:center;background:#3b82f6;color:#fff;border-radius:11px;margin-right:9px;font-size:12px}
.sev{display:inline-block;padding:2px 11px;border-radius:5px;font-weight:700;color:#fff;font-size:12px}.Critical{background:#7a0c2e}.High{background:#b3261e}.Medium{background:#b26a00}.Low{background:#2e7d32}
.glance{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}
.tile{border:1px solid #d5dce8;border-top:4px solid #3b82f6;border-radius:6px;padding:6px 10px;background:#fbfcfe;break-inside:avoid}
.tile .k{font-size:10px;color:#566277;text-transform:uppercase;letter-spacing:.07em}.tile .v{font-size:15px;font-weight:700;overflow-wrap:anywhere}
.tile.crit{border-top-color:#b3261e;background:#fdf1f0}.tile.crit .v{color:#b3261e}.tile.warn{border-top-color:#b26a00}.tile.ok{border-top-color:#2e7d32}
.tile.Critical{border-top-color:#7a0c2e}.tile.High{border-top-color:#b3261e}.tile.Medium{border-top-color:#b26a00}.tile.Low{border-top-color:#2e7d32}
.chips{margin:6px 0}.tech{display:inline-block;margin:2px 4px 2px 0;padding:2px 9px;border:1px solid #9db8ee;background:#eef4ff;color:#173a7a;border-radius:11px;font-size:11.5px;text-decoration:none}
.call{border-left:5px solid;padding:8px 12px;margin:8px 0;border-radius:0 6px 6px 0;break-inside:avoid}
.call b{margin-right:6px}.call.crit{background:#fdecec;border-color:#b3261e}.call.warn{background:#fff4e0;border-color:#b26a00}
.call.info{background:#eaf2ff;border-color:#3b82f6}.call.ok{background:#e8f5ec;border-color:#2e7d32}
table{border-collapse:collapse;width:100%;margin:6px 0}
th,td{border:1px solid #cfd7e3;padding:4px 8px;text-align:left;vertical-align:top;font-size:12px;overflow-wrap:anywhere}
th{background:#1f2a3a;color:#fff;font-weight:600}tr{break-inside:avoid}tbody tr:nth-child(even) td{background:#f5f7fb}
tr.crit td{background:#fdecec!important;font-weight:600}tr.warn td{background:#fff4e0!important}
table.mini td,table.mini th{font-size:10px;padding:2px 6px}table.mini td+td{font-family:Consolas,monospace}
.chip{display:inline-block;padding:1px 8px;border-radius:9px;font-size:10.5px;font-weight:600;background:#e5e9f0;color:#33415c;white-space:nowrap}
.k-detect{background:#fde3e1;color:#8a1c14}.k-decoy{background:#dce9ff;color:#173a7a}.k-lure,.k-token{background:#b3261e;color:#fff}
.k-contact,.k-typed{background:#f6d9a8;color:#6b4200}
pre{background:#f3f6fb;border:1px solid #cfd7e3;border-left:4px solid #3b82f6;padding:8px;font-size:10.5px;overflow-x:auto;white-space:pre-wrap;break-inside:avoid}
.meta{color:#566277;font-size:12px}code{font-family:Consolas,monospace;font-size:12px}
ul{margin:4px 0 4px 18px;padding:0}li{margin:2px 0}
.cmds{display:flex;flex-wrap:wrap;gap:5px;margin:5px 0 2px}
.cmd{display:inline-block;font:11.5px/1.45 Consolas,monospace;font-weight:400;background:#eef2f8;color:#1d2a3f;border:1px solid #d3dbe8;border-radius:6px;padding:1px 8px;overflow-wrap:anywhere;break-inside:avoid}
.cmd .x{margin-left:6px;color:#9a5b00;font-weight:700}
.cmds .more{font-size:11px;color:#566277;align-self:center}
.lbl{margin-top:6px;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:#566277;font-weight:600}
a{color:#1f5fd6}
@media screen and (prefers-color-scheme:dark){
html{background:#0f1620;color-scheme:dark}
body{background:#0f1620;color:#e3e9f2}
a{color:#8fb4f5}
.top{background:#18212d;border-bottom-color:#3b82f6}
h2.inc{background:#1f2a3a}
h3.sec,h2.sec{background:#172338;color:#bcd2ff}
.tile{border-color:#2e3947;border-top-color:#3b82f6;background:#18212d}
.tile .k{color:#9aa6b8}
.tile.crit{border-top-color:#f0555f;background:#2a1a1d}.tile.crit .v{color:#ff8d86}.tile.warn{border-top-color:#e9a23b}.tile.ok{border-top-color:#3fb97c}
.tile.Critical{border-top-color:#ff4d7a}.tile.High{border-top-color:#f0555f}.tile.Medium{border-top-color:#e9a23b}.tile.Low{border-top-color:#3fb97c}
.tech{background:#172338;border-color:#35508a;color:#bcd2ff}
.call.crit{background:#2b1a1c;border-color:#f0555f}.call.warn{background:#2a2112;border-color:#e9a23b}
.call.info{background:#152033;border-color:#3b82f6}.call.ok{background:#14261c;border-color:#3fb97c}
th,td{border-color:#2e3947}
th{background:#1f2a3a}tbody tr:nth-child(even) td{background:#151e29}
tr.crit td{background:#2b1a1c!important}tr.warn td{background:#2a2112!important}
.chip{background:#263243;color:#c8d3e4}
.k-detect{background:#3a1d1f;color:#ffb4ae}.k-decoy{background:#17294a;color:#bcd2ff}.k-contact,.k-typed{background:#3a2b10;color:#f2cf8a}
pre{background:#18212d;border-color:#2e3947}
.meta,.cmds .more,.lbl{color:#9aa6b8}
.cmd{background:#1d2836;color:#dbe6f7;border-color:#34445a}.cmd .x{color:#f2b04a}
}"""


def render(run, analysis, pcaps, hashes, events, decoys, logs_for, win, ht_for=lambda ip: ([], []), inter_for=lambda ip: []):
    a_list = [a for a in analysis["analyses"] if a["confidence"] >= MIN_CONF]  # same threshold the controller acts on
    now = fmt_ts(datetime.now().timestamp())
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='color-scheme' content='light dark'><title>Incident report {esc(run)}</title><style>{CSS}</style></head><body>",
           "<div class='top'>" + LOGO + f"<div><div class='t'>Deepcast · incident report</div><h1>Incident {esc(run)}</h1>"
           f"<div class='m'>Generated {now} by Deepcast, the Deception Platform</div></div></div><div class='wrap'>"]
    if not a_list:
        out.append(sec(0, "Result", "h2") + "<div class='call ok'><b>No attacker behavior was found in this capture.</b> No decoys were deployed.</div></div></body></html>")
        return "\n".join(out)
    for a in a_list:
        ip = a["attacker_ip"]
        st = attacker_stats(pcaps, ip)
        techs = a["techniques"]
        stage = a["stage"].replace("_", " ")
        c = logs_for(ip)
        seen_d, inter = set(), []
        for r in inter_for(ip):                       # the earliest deployment of a name already covers every later event on it
            if (r["template"], r["ip"], r["port"]) not in seen_d:
                seen_d.add((r["template"], r["ip"], r["port"]))
                inter.append(r)
        used, fetched = ht_for(ip)
        reached = [r for r in inter if r["events"]]
        sev = severity(a["stage"], a["confidence"], bool(used), bool(reached))
        SEV_OUT.append({"ip": ip, "severity": sev, "honeytokens_used": len(used), "decoys_reached": len(reached)})
        logins_ok = c["cowrie"].get("cowrie.login.success", 0)
        distinct = {(d["template"], d["ip"], d["port"]) for d in decoys}
        out.append(f"<h2 class='inc'><span>Incident: <code>{esc(ip)}</code></span><span class='sev {sev}'>{sev} severity</span></h2>")
        out.append(glance([("Severity", sev, sev), ("Stage reached", stage.capitalize(), ""), ("Confidence", f"{round(a['confidence'] * 100)}%", ""),
                           ("Activity", span(st["first"], st["last"]), ""), ("Packets from source", f"{st['packets']:,}", ""),
                           ("Decoys in play", str(len(distinct)), "ok" if distinct else ""),
                           ("Decoys reached", f"{len(reached)} of {len(inter)}" if inter else "0", "crit" if reached else ""),
                           ("Honeytokens used", str(len(used)), "crit" if used else "")]))
        out.append("<p class='chips'>" + " ".join(f"<a class='tech' href='{esc(attack_url(t['id']))}'>{esc(t['id'])} {esc(t['name'])}</a>" for t in techs) + "</p>")
        if used:
            items = "".join(f"<li>{esc(h['token'])} ({esc(h['username'])}), planted in {esc(h['planted_in'])}, used on the {esc(h['service_label'])} at {esc(fmt_ts(h['ts']))}</li>" for h in used)
            out.append(f"<div class='call crit'><b>Honeytoken use ({len(used)}).</b> Nobody legitimate holds these credentials: the source read the lure and reused them.<ul>{items}</ul></div>")
        if logins_ok:
            out.append(callout("crit", "Logged in.", f"{logins_ok} successful login(s) on the SSH honeypot as {top(c['cowrie_users'], 3)}."))
        if c["cowrie_cmds"]:
            out.append(callout("warn", "Commands typed.", Raw(esc(f"{len(c['cowrie_cmds'])} command(s) on the SSH honeypot (full list in the evidence table below):") + cmd_bubbles(c["cowrie_cmds"], 10))))
        if reached:
            out.append(callout("crit", "Moved into spawned decoys.", "Contact with " + ", ".join(f"{r['template']} ({r['events']} event(s))" for r in reached) + "."))
        if not (used or logins_ok or reached):
            out.append(callout("info", f"{stage.capitalize()} only.", "No login, no credential use and no contact with a spawned decoy was observed for this source."))

        out.append(sec(1, "Summary") + "<p>" + esc(a["summary"]) + "</p>")
        out.append(sec(2, "Timeline") + "<p class='meta'>One merged timeline for this source across the capture, the lures it followed and every decoy it reached. "
                   "Repeated decoy deployments and repeated analysis reports of the same activity are collapsed into one row.</p>"
                   + table([f"Time (local, {local_offset(datetime.now().astimezone())})", "Type", "Event"], timeline_rows(ip, st, win, events, decoys, used, fetched, inter)))

        prof = [("Source IP", ip), ("Targets", ", ".join(st["dsts"]))]
        if st["first"]:
            prof.append(("Activity window", f"{fmt_ts(st['first'])} to {fmt_ts(st['last'])} ({span(st['first'], st['last'])})"))
        prof.append(("Packets sent", f"{st['packets']:,}"))
        prof.append(("New connection attempts (bare SYN)", f"{st['syns']:,} to {len(st['syn_ports'])} distinct port(s)"))
        if st["syn_ports"]:
            prof.append(("Most probed ports", ", ".join(f"{port_label(p)}: {n:,}" for p, n in st["syn_ports"].most_common(6))))
        if st["http"]:
            prof.append(("HTTP requests", f"{st['http']:,}"))
        if st["banners"]:
            prof.append(("SSH client banner(s)", ", ".join(sorted(st["banners"]))))
        if st["uas"]:
            prof.append(("HTTP user agents", ", ".join(f"{short(k, 60)} ({v:,})" for k, v in st["uas"].most_common(3))))
        out.append(sec(3, "Attacker profile") + table(["Property", "Observed (recomputed from the pcap)"], prof))

        out.append(sec(4, "Proof") + "<p class='meta'>Computed from the capture and honeypot logs, independent of the analysis text above.</p>")
        out.append("<p><b>First packets from the attacker (raw tshark output, retransmissions left out):</b></p><pre>" + esc(packet_sample(pcaps, ip)) + "</pre>")
        if st["uris"]:
            out.append("<p><b>Most requested web paths:</b> " + esc(", ".join(f"{short(u, 50)} ({n:,})" for u, n in st["uris"].most_common(8))) + "</p>")
        talked = lambda *ports: sum(st["syn_ports"].get(str(p), 0) for p in ports)
        ev_rows, shown = [], False
        # Honeypot logs only show the Docker gateway, so they cannot be tied to an IP. They are shown here only
        # when the pcap proves this source talked to that service (SSH banner / HTTP requests / many SYNs).
        if c["cowrie"]:
            shown = True
            failed, ok = c["cowrie"].get("cowrie.login.failed", 0), c["cowrie"].get("cowrie.login.success", 0)
            parts = [f"{c['sessions']} session(s)"]
            parts.append(f"{failed} failed and {ok} successful login(s); usernames {top(c['cowrie_users'], 4)}; passwords {top(c['cowrie_pw'], 4)}" if (failed or ok) else "connected, no login attempted")
            ev_rows.append(Row(("SSH honeypot (Cowrie)", cell_with_cmds("; ".join(parts), c["cowrie_cmds"])), "crit" if ok else ""))
        if c["web_n"] and st["http"]:
            shown = True
            ev_rows.append(("Web honeypot", f"{c['web_n']:,} requests; status codes {top(c['web_status'], 5)}; top paths {', '.join(f'{short(k, 40)} ({v})' for k, v in c['web_paths'].most_common(6))}"))
        if (c["canary"] or c["smb"]) and talked(21, 23, 4445) >= 3:
            shown = True
            ev_rows.append(("Other honeypots, same time window", "OpenCanary: " + (", ".join(f"type {k} x{v}" for k, v in c["canary"].most_common(6)) or "none") + "; SMB decoy: " + (", ".join(f"{k} x{v}" for k, v in c["smb"].most_common(6)) or "none")))
        if ev_rows:
            out.append(table(["Honeypot", "What it logged for this source"], ev_rows))
        out.append("<p class='meta'>" + ("Honeypot sessions and requests are attributed to this source by matching their timestamps to its connection times in the capture. " if shown else
                   "No honeypot session or request is attributed to this source: the capture shows connection attempts only. ")
                   + "Honeypot logs show the Docker gateway as the source address because Docker relays published ports; the pcap is the source of truth for the attacker IP.</p>")

        if used:   # the strongest proof there is: a planted fake credential was read from a lure and then used
            out.append(sec(0, "Honeytoken evidence") + "<p class='meta'>Honeytoken: a fake credential planted as bait. No legitimate user holds it, "
                       "so any use indicates the source read the planted file and reused the credential.</p>")
            gl = lambda p: " (fake admin site, port 8080)" if p.startswith("web panel") else " (SMB decoy share)" if p.startswith("SMB share") else ""
            out.append(table(["Honeytoken", "Planted in", "Used at", "When (local)"],
                             [Row((h["token"] + " (" + h["username"] + ")", h["planted_in"] + gl(h["planted_in"]),
                                   h["service_label"] + " [" + h["service"] + "]", fmt_ts(h["ts"])), "crit") for h in used]))
            if fetched:
                out.append("<p><b>Lure followed:</b> this source requested " + esc(", ".join(sorted({u for _, u in fetched})))
                           + " first at " + esc(fmt_ts(fetched[0][0])) + " before using the credential.</p>")
        rows = [(t["id"], t["name"], tactic(t["id"])) for t in techs]
        rows = [(Raw(f"<a href='{esc(attack_url(i))}'>{esc(i)}</a>"), n, tc) for i, n, tc in rows]
        out.append(sec(5, "MITRE ATT&CK mapping") + table(["Technique", "Name", "Tactic"], rows))
        out.append("<p><b>Evidence cited by the analysis agent:</b></p><ul>" + "".join(f"<li>{esc(e)}</li>" for e in a["evidence"]) + "</ul>")

        extra = [e for e in events if e.get("event") in ("decoy_rejected", "approval_denied", "decoy_skipped")]
        groups = {}
        for d in sorted(decoys, key=lambda d: d["spawned"]):
            groups.setdefault((d["template"], d["ip"], d["port"]), []).append(d)
        resp = [(tpl, f"{dip}:{port}", (fmt_ts(ds[0]["started"]) + " (earlier incident)") if ds[0].get("reused") else fmt_ts(ds[0]["spawned"]),
                 "already running" if ds[0].get("reused") else f"{len(ds)}x",
                 f"{ds[0]['contacts']} event(s) logged on this decoy " + ("during this incident" if ds[0].get("reused") else "since it first appeared"))
                for (tpl, dip, port), ds in groups.items()]
        out.append(sec(6, "Response taken"))
        out.append(table(["Decoy", "Address", "Started", "Deployed", "Activity"], resp) if resp else "<p>No decoy was spawned for this incident.</p>")
        if extra:
            cnt = Counter((e["event"], e.get("template", ""), e.get("reason", "operator")) for e in extra)
            out.append("<p class='meta'>Not deployed: " + esc("; ".join(f"{tpl} {ev.replace('decoy_', '').replace('_', ' ')} ({why})" + (f" x{n}" if n > 1 else "") for (ev, tpl, why), n in cnt.items())) + "</p>")
        out.append("<p class='meta'>Recommended decoys by the analysis: " + esc(", ".join(a["recommended_decoys"]) or "none")
                   + ". The controller only starts templates from a fixed allowlist.</p>")

        out.append(sec(7, "Decoy interaction"))
        if reached:
            out.append("<p class='meta'>Lateral movement into spawned decoys: this source reached " + str(len(reached)) + " of " + str(len(inter))
                       + " decoy(s). Events are attributed to the source by matching timestamps to its connections in the capture.</p>")
            out.append(table(["Decoy", "Address", "Events", "What this source did"],
                [Row((r["template"], f"{r['ip']}:{r['port']}", str(r["events"]),
                      cell_with_cmds("; ".join(x for x in [
                          (f"{r['sessions']} SSH session(s)" if r["sessions"] else ""),
                          ("login attempts as " + ", ".join(f"{u or '(blank)'} x{n}" for u, n in r["logins"].most_common(4)) if r["logins"] else ""),
                          ("requests: " + " | ".join(r["detail"]) if r["detail"] else "")] if x) or ("" if r["commands"] else "connections only"),
                          r["commands"], 25)), "warn") for r in reached]))
        else:
            out.append("<p>No contact from this source with the spawned decoys during the capture.</p>")
        out.append(sec(8, "Recommendations") + "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in advice_for(techs, used, reached)) + "</ul>")
        lines = lambda vals: Raw("<br>".join(esc(v) for v in vals))
        ioc_rows = [("IPv4", ip)]
        if st["uas"]: ioc_rows.append(("User agents", lines([short(u, 90) for u in list(st["uas"])[:3]])))
        if st["banners"]: ioc_rows.append(("SSH banner", lines(sorted(st["banners"]))))
        if st["uris"]: ioc_rows.append(("Web paths", lines([short(u, 80) for u, _ in st["uris"].most_common(5)])))
        if st["syn_ports"]: ioc_rows.append(("Targeted ports", ", ".join(port_label(p) for p, _ in st["syn_ports"].most_common(5))))
        ioc_rows = [(t, v, pyramid.label(pyramid.IOC_LEVEL[t]), pyramid.IF_BLOCKED[pyramid.IOC_LEVEL[t]]) for t, v in ioc_rows]
        named = pyramid.tools_in(*st["uas"], *st["banners"])
        if named: ioc_rows.append(("Tools (from user agent / banner)", ", ".join(named), pyramid.label("tool"), pyramid.IF_BLOCKED["tool"]))
        ioc_rows.append(("Techniques (ATT&CK)", ", ".join(t["id"] for t in a["techniques"]), pyramid.label("ttp"), pyramid.IF_BLOCKED["ttp"]))
        out.append(sec(9, "Indicators of compromise") + "<p class='meta'>The last column is the Pyramid of Pain level: how much it hurts the attacker if this indicator is blocked. The IP and header values are easy for them to change; the techniques are the behaviour they would have to change, which is what the decoys and the analysis target. A tool name taken from a header can be spoofed.</p>"
                   + table(["Type", "Value", "Pain if denied", "If you block this"], ioc_rows))
    manifest = hashlib.sha256("".join(f"{Path(p).name}:{h}\n" for p, h in sorted(hashes)).encode()).hexdigest()
    out.append(sec(0, "Evidence integrity", "h2") + callout("info", f"{len(hashes)} capture file(s).", f"Manifest SHA-256 over all files: {manifest}")
               + table(["Capture file", "SHA-256"], [(Path(p).name, h) for p, h in hashes], "mini"))
    out.append(sec(0, "Method and limits", "h2") + "<ul><li>The analysis agent (Claude, read-only Wireshark tools) proposed these findings; the validator confirmed the schema, that the attacker IP appears in the capture, and that decoys are on the allowlist.</li>"
               "<li>Counts in sections 3 and 4 were recomputed from the capture and logs for this report.</li>"
               "<li>Captured content is attacker-controlled and is shown as escaped text only.</li>"
               "<li>Limits: lab network, a single capture window, simple attacks; confidence values are the agent's own estimate.</li></ul></div></body></html>")
    return "\n".join(out)


def to_pdf(html_path):
    edge = shutil.which("msedge") or next((p for p in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                                                       r"C:\Program Files\Microsoft\Edge\Application\msedge.exe") if os.path.exists(p)), None)
    if not edge:
        return None
    pdf = html_path.with_suffix(".pdf")
    subprocess.run([edge, "--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf}", html_path.as_uri()],
                   capture_output=True, timeout=60)
    return pdf if pdf.exists() else None


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run_dir = Path(sys.argv[1]).resolve()
    analysis = json.loads((run_dir / "analysis.json").read_text(encoding="utf-8"))
    pcaps = sorted((run_dir / "pcaps").glob("*.pcap"))
    if not pcaps:
        sys.exit("no pcaps in run")
    win = pcap_window(pcaps)
    events, decoys = decoy_activity(run_dir.name, win)
    times = service_times(pcaps)
    logs_for = lambda ip: honeypot_logs(run_dir / "logs", win[0], win[1], ip, times)
    hashes = [(p, sha256(p)) for p in pcaps]

    def ht_for(ip):
        """Honeytoken uses attributed to this source (by pcap timing) and the lure requests it made."""
        used = [h for h in honeytokens.hits_in(run_dir / "logs", win[0] - 5, win[1] + 5) if attribute_hit(h, times) == ip]
        tokens = honeytokens.load_tokens()
        paths = [t["planted_in"].split("web panel ", 1)[1].rsplit("/", 1)[0] + "/" for t in tokens if t["planted_in"].startswith("web panel ")]
        fetched = [(t, u) for t, src, u in http_requests_matching(pcaps, paths or ["/backup/"]) if src == ip] if used else []
        return used, fetched

    inter_for = lambda ip: decoy_interaction(decoys, times, ip)
    page = render(run_dir.name, analysis, pcaps, hashes, events, decoys, logs_for, win, ht_for, inter_for)
    out = run_dir / "incident_report.html"
    out.write_text(page, encoding="utf-8")
    (run_dir / "severity.json").write_text(json.dumps(SEV_OUT, indent=1), encoding="utf-8")
    pdf = to_pdf(out)
    print(f"wrote {out}" + (f" and {pdf.name}" if pdf else " (no PDF: Edge not found)"))


if __name__ == "__main__":
    main()

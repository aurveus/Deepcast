"use strict";
// All text from logs/analyses is attacker-influenced: it is only ever inserted with textContent (see h()).

const $ = (s) => document.querySelector(s);
const view = $("#view");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const api = (p) => fetch(p, { cache: "no-store" }).then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); });
const tsOf = (t) => (typeof t === "number" ? t * 1000 : Date.parse(t));
const fmtTime = (t) => new Date(tsOf(t)).toLocaleString([], { hour12: false, month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtMs = (ms) => fmtTime(ms / 1000);
const fmtClock = (t) => new Date(tsOf(t)).toLocaleTimeString([], { hour12: false });
const shortDate = (t) => new Date(tsOf(t)).toLocaleDateString([], { month: "short", day: "numeric" });
const rangeLabel = (a, b) => (new Date(tsOf(a)).toDateString() === new Date(tsOf(b)).toDateString()
  ? `${fmtClock(a)}–${fmtClock(b)}` : `${shortDate(a)} ${fmtClock(a)} → ${shortDate(b)} ${fmtClock(b)}`);
// Event tables show only the time of day in each row; a small date pill marks where each day starts (newest first).
function dayLabel(t) {
  const d = new Date(tsOf(t)), now = new Date(), yest = new Date(now.getTime() - 86400000);
  const base = d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
  return d.toDateString() === now.toDateString() ? "Today · " + base : d.toDateString() === yest.toDateString() ? "Yesterday · " + base : base;
}
function dayRows(evs, cols, rowFn) {
  const counts = {};
  evs.forEach((e) => { const k = new Date(tsOf(e.ts)).toDateString(); counts[k] = (counts[k] || 0) + 1; });
  const out = []; let last = "", prevGroup = null, gi = -1;
  for (const e of evs) {
    const k = new Date(tsOf(e.ts)).toDateString();
    if (k !== last) {
      last = k; prevGroup = null;
      out.push(h("tr", { class: "dayrow" }, h("td", { colspan: String(cols) }, h("span", { class: "daypill" }, dayLabel(e.ts)), h("span", { class: "daycount" }, `${counts[k]} event${counts[k] === 1 ? "" : "s"}`))));
    }
    // Stripe = kind of event (fixed colors). Shading alternates per incident/run so you can see which rows belong together.
    const group = e.run_id || "solo-" + e.ts;
    const row = rowFn(e);
    if (group !== prevGroup) { gi++; row.classList.add("gstart"); prevGroup = group; }
    row.classList.add("c-" + (EVENT_CAT[e.event] || "sys"));
    if (gi % 2) row.classList.add("gshade");
    out.push(row);
  }
  return out;
}
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const fmtBytes = (n) => (n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : (n / 1e3).toFixed(0) + " kB");
const tag = (text, kind) => h("span", { class: "tag " + (kind || "") }, text);
const empty = (msg) => h("div", { class: "empty" }, msg);

const EVENT_KIND = {
  attack_detected: ["red", "Attack detected"], analysis_clean: ["green", "Clean"],
  analysis_clean_disputed: ["amber", "Clean (disputed)"], decoy_spawned: ["teal", "Decoy spawned"],
  decoy_retired: ["", "Decoy retired"], decoy_rejected: ["amber", "Decoy rejected"],
  decoy_skipped: ["", "Decoy skipped"], decoy_failed: ["red", "Decoy failed"],
  approval_denied: ["amber", "Approval denied"], analysis_ignored: ["", "Ignored (low conf.)"],
  analysis_rejected: ["red", "Analysis rejected"], killswitch: ["red", "Kill switch"],
  run_capture_started: ["", "Capture started"], run_saving: ["", "Saving run"], analysis_started: ["", "Analysis started"],
  controller_started: ["", "Controller started"], run_finished: ["", "Run finished"],
  honeytoken_used: ["red", "Honeytoken used"], honeytoken_attributed: ["red", "Honeytoken traced"], honeytoken_unattributed: ["amber", "Honeytoken (source unknown)"], honeytoken_username_tried: ["amber", "Lure username tried"],
  lure_chain_policy: ["teal", "Lure-chain policy"], watch_started: ["", "Monitoring started"], watch_stopped: ["", "Monitoring stopped"], watch_trigger: ["amber", "Triage trigger"],
  watch_triage_clean: ["green", "Triage: benign"], incident_closed: ["", "Incident closed"], watch_error: ["red", "Watcher error"],
};
// Fixed color meaning for the row stripe: what KIND of thing happened.
const CATEGORIES = [["det", "Attack detected", "var(--red)"], ["tri", "Triage and analysis", "var(--amber)"], ["res", "Response (decoys)", "var(--accent)"],
  ["ctl", "Safety controls and errors", "#e879f9"], ["ok", "Benign / clean", "var(--green)"], ["sys", "System", "var(--line2)"]];
const EVENT_CAT = { attack_detected: "det", honeytoken_used: "det", honeytoken_attributed: "det", honeytoken_unattributed: "tri", honeytoken_username_tried: "tri", watch_trigger: "tri", analysis_started: "tri", analysis_ignored: "tri", analysis_clean_disputed: "tri",
  decoy_spawned: "res", lure_chain_policy: "res", decoy_retired: "res", controller_started: "res", decoy_rejected: "ctl", decoy_skipped: "ctl", approval_denied: "ctl",
  killswitch: "ctl", decoy_failed: "ctl", analysis_rejected: "ctl", watch_error: "ctl", analysis_clean: "ok", watch_triage_clean: "ok" };
// Honeytoken events: technical wording with a short bracket gloss. Older events (logged before the *_label fields existed) are translated here.
const SERVICE_NAMES = { cowrie: "SSH honeypot", web: "web admin panel", opencanary: "FTP/Telnet/MySQL honeypot", smb: "SMB decoy" };
const svcName = (e) => `${e.service_label || (e.service && e.service.startsWith("decoy-") ? "decoy" : SERVICE_NAMES[e.service]) || "honeypot"} [${e.service || "?"}]`;
const gloss = (p) => (/^web panel/.test(p || "") ? " [fake admin site, :8080]" : /^SMB share/.test(p || "") ? " [SMB decoy share]" : "");
const plantedAt = (e) => `${e.planted_in || "a lure"}${gloss(e.planted_in)}`;
function describe(e) {
  switch (e.event) {
    case "attack_detected": return `${e.stage}, techniques ${(e.techniques || []).join(", ")}, confidence ${e.confidence}`;
    case "decoy_spawned": return `${e.template} at ${e.ip}:${e.port}`;
    case "decoy_retired": return `${e.name} (${e.reason})`;
    case "decoy_rejected": case "decoy_skipped": case "decoy_failed": return `${e.template || ""}: ${e.reason || e.error || ""}`;
    case "approval_denied": return `${e.template} declined by operator`;
    case "killswitch": return `removed ${(e.removed || []).length} decoy(s)`;
    case "run_capture_started": case "run_saving": case "analysis_started": case "controller_started": case "run_finished": return `run "${e.name || ""}"`;
    case "honeytoken_used": case "honeytoken_attributed":
      return `${e.token} (${e.username}) used at ${svcName(e)} · planted in ${plantedAt(e)}`;
    case "honeytoken_username_tried":
      return `${e.username} (${e.token}) tried at ${svcName(e)} with a non-planted password · account name exposed only in ${plantedAt(e)}`;
    case "honeytoken_unattributed":
      return `${e.token}${e.username ? " (" + e.username + ")" : ""} used at ${svcName(e)} · source IP not traceable from the capture`;
    case "lure_chain_policy": return `${(e.templates || []).join(", ")} · ${e.reason}`;
    case "watch_trigger": return `${e.attacker_ip}: ${e.reasons}`;
    case "watch_triage_clean": case "incident_closed": return `${e.attacker_ip}${e.reason ? " (" + e.reason + ")" : ""}`;
    case "watch_started": return `${e.mode} mode, ${e.window}s windows`;
    case "watch_stopped": return `${e.windows} windows processed`;
    case "watch_error": return `${e.where}: ${e.error}`;
    case "analysis_clean": return "No attacker behavior found";
    case "analysis_clean_disputed": return "Clean twice despite many connection attempts: needs a human look";
    default: return e.reason || "";
  }
}
function evTag(e) { const [k, l] = EVENT_KIND[e.event] || ["", e.event]; return tag(l, k); }

// ---------- views ----------
const state = { filter: "all", q: "", range: "all", cq: "", ctech: "", crange: "all", mitre: null, replayRun: null, open: new Set(), openAll: new Set() };

// "New since your last visit": the moment this page was last closed, kept in the browser. Storage can be blocked, so every access is guarded.
const SEEN_KEY = "deepcast.seen";
let seenAt = 0;
try { seenAt = Number(localStorage.getItem(SEEN_KEY)) || 0; } catch (_) {}
window.addEventListener("pagehide", () => { try { localStorage.setItem(SEEN_KEY, String(Date.now())); } catch (_) {} });
const isNew = (t) => seenAt > 0 && tsOf(t) > seenAt;
const newPill = (t) => (isNew(t) ? h("span", { class: "newpill", title: "Arrived since you last had the dashboard open" }, "new") : null);
const RANGES = [["all", "All time", 0], ["1h", "Last hour", 3600e3], ["24h", "Last 24 hours", 86400e3], ["7d", "Last 7 days", 604800e3]];
const inRange = (t, key) => { const r = RANGES.find((x) => x[0] === key); return !r || !r[2] || Date.now() - tsOf(t) <= r[2]; };
const rangeSelect = (cur, set) => h("select", { "aria-label": "Time range", onchange: (ev) => { set(ev.target.value); render(); } },
  RANGES.map(([k, label]) => h("option", { value: k, selected: k === cur }, label)));

// ---------- attacker commands (typed text only ever goes in through textContent) ----------
const CMD_PREVIEW = 8;   // rows shown before "show all"; the list then scrolls inside a fixed-height box
const fmtOff = (s) => (s < 60 ? `+${s}s` : `+${Math.floor(s / 60)}m${String(s % 60).padStart(2, "0")}s`);
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
// Technique ids the MITRE tab can show (the ones the analysis reported); a command's rule-matched chip links there only if it is one of them.
const knownTechs = (sess) => new Set(sess.flatMap((a) => a.techniques.map((t) => t.id)));
function techChip(id, known) {
  if (!known || !known.has(id)) return h("span", { class: "tid", title: "Matched by the command rules; the analysis did not report this technique" }, id);
  return h("button", { class: "tid link", title: `Open ${id} in the MITRE ATT&CK tab`, onclick: () => { state.mitre = id; window.scrollTo(0, 0); location.hash = "mitre"; render(); } }, id);
}
function cmdRow(r, at, known) {
  return h("li", { class: "cmd" },
    at ? h("span", { class: "at" }, at) : null,
    h("code", { title: r.cmd }, r.cmd, r.n > 1 ? h("span", { class: "rep", title: `typed ${r.n} times` }, "×" + r.n) : null),
    h("span", { class: "ids" }, (r.techs || []).map((t) => techChip(t, known))));
}
function sessionBlock(s, key, known) {
  const k = key + "/" + s.id, all = state.openAll.has(k), rows = all ? s.rows : s.rows.slice(0, CMD_PREVIEW);
  return h("div", { class: "cmdsess" },
    h("div", { class: "cmdhead" }, tag(s.source, "teal"), h("strong", { class: "mono" }, s.user),
      plural(s.commands, "command") + (s.distinct < s.commands ? `, ${s.distinct} distinct` : ""), h("span", {}, fmtTime(s.start))),
    h("ul", { class: "cmdlist scroll" }, rows.map((r) => cmdRow(r, fmtOff(r.at), known))),
    s.rows.length > CMD_PREVIEW ? h("button", { class: "cmdmore", onclick: () => { all ? state.openAll.delete(k) : state.openAll.add(k); render(); } },
      all ? "Show fewer" : `Show all ${s.rows.length} distinct commands`) : null,
    s.more ? h("div", { class: "cmdnote" }, `+${s.more} more distinct commands not listed here (full list in the honeypot log).`) : null);
}
function commandsFold(c, key, known) {
  if (!c) return null;
  return h("details", { class: "evid cmds", open: state.open.has(key), ontoggle: (e) => { e.target.open ? state.open.add(key) : state.open.delete(key); } },
    h("summary", {}, `Commands typed (${c.total}`, h("span", { class: "cmdhint meta" }, `· ${plural(c.session_count, "session")}${c.distinct < c.total ? ", " + c.distinct + " distinct" : ""})`)),
    c.sessions.map((s) => sessionBlock(s, key, known)),
    c.hidden_sessions ? h("div", { class: "cmdnote" }, `+${plural(c.hidden_sessions, "earlier session")} not listed.`) : null);
}
function liveCard(L, known) {
  const active = L.last && L.now - L.last < 120, mins = Math.round(L.window_s / 60);
  return h("div", { class: "card live" },
    h("div", { class: "livehead" }, h("h2", { style: "margin:0" }, "Attacker activity"),
      h("i", { class: "pulse" + (active ? "" : " idle"), "aria-hidden": "true" }),
      h("span", { class: "meta" }, L.total ? `${plural(L.total, "command")} in the last ${mins} min · ${plural(L.sessions, "session")}${active ? " · typing now" : ""}` : `nothing typed in the last ${mins} min`)),
    L.rows.length ? [h("ul", { class: "cmdlist scroll", style: "padding:0" }, L.rows.map((r) => cmdRow(r, fmtClock(r.t), known))),
      L.hidden ? h("div", { class: "cmdnote", style: "padding:6px 0 0" }, `+${L.hidden} earlier in this window`) : null]
      : h("p", { class: "meta", style: "margin:0" }, "Commands typed on the SSH honeypot or an SSH decoy appear here while an attack is running."));
}

async function viewOverview() {
  const [o, evs, sess, dec, live] = await Promise.all([api("/api/overview"), api("/api/events"), api("/api/sessions"), api("/api/decoys"), api("/api/live")]);
  const kpi = (v, l, cls) => h("div", { class: "card kpi " + (cls || "") }, h("div", { class: "v" }, v ?? "n/a"), h("div", { class: "l" }, l));
  return [
    head("Overview", "What the platform has seen and done so far."),
    h("div", { class: "page fill" },
      h("div", { class: "grid kpis" },
        kpi(o.runs_analyzed, "Runs analyzed"), kpi(o.attacks_detected, "Attackers caught", "hot"),
        kpi(o.decoys_spawned, "Decoys spawned", "ok"), kpi(o.decoys_live, "Decoys live now", "ok"),
        kpi(o.clean_runs, "Clean runs (no attacker)"), kpi(o.rejections, "Actions blocked or declined")),
      liveCard(live, knownTechs(sess)),
      h("div", { class: "grid two" },
        h("div", { class: "card" }, h("h2", {}, "Activity over time"), timeline(evs)),
        h("div", { class: "card" }, h("h2", {}, "Latest detections"),
          sess.length ? h("div", {}, sess.slice(0, 4).map((s) => h("p", {},
            h("strong", { class: "mono" }, s.attacker_ip), " ", tag(s.stage.replace("_", " "), "red"), " ",
            h("span", { class: "meta" }, s.techniques.map((t) => t.id).join(", ")), h("br"),
            h("span", { class: "meta" }, fmtTime(s.time))))) : empty("No detections yet"))),
      h("div", { class: "grid two" },
        h("div", { class: "card" }, h("h2", {}, "Recent events"),
          evs.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Event", "Details"].map((c) => h("th", {}, c)))),
            h("tbody", {}, dayRows(evs.slice(0, 9), 3, (e) => h("tr", {}, h("td", { class: "mono" }, fmtClock(e.ts)), h("td", {}, evTag(e)), h("td", {}, describe(e)))))) : empty("No events yet")),
        h("div", { class: "card" }, h("h2", {}, "Decoys running"),
          dec.live && dec.live.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Template", "Address"].map((c) => h("th", {}, c)))),
            h("tbody", {}, dec.live.map((x) => h("tr", {}, h("td", {}, tag(x.template, "teal")), h("td", { class: "mono" }, x.ip + " · " + Math.max(0, Math.ceil((x.expires - dec.now) / 60)) + " min left")))))
            : empty(dec.live === null ? "Docker is not reachable" : "No spawned decoys running")))),
  ];
}

function timeline(evs) {
  if (!evs.length) return empty("No events yet");
  const BINS = 24, W = 640, H = 200, pad = 22;
  const ts = evs.map((e) => tsOf(e.ts)), min = Math.min(...ts), max = Math.max(...ts, min + 1);
  const det = Array(BINS).fill(0), dec = Array(BINS).fill(0);
  evs.forEach((e) => {
    const i = Math.min(BINS - 1, Math.floor(((tsOf(e.ts) - min) / (max - min)) * BINS));
    if (e.event === "attack_detected") det[i]++; else if (e.event === "decoy_spawned") dec[i]++;
  });
  const top = Math.max(1, ...det, ...dec), bw = (W - pad) / BINS;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", "chart"); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Detections and decoys spawned over time");
  const add = (n, a, txt) => { const el = document.createElementNS(svg.namespaceURI, n); for (const k in a) el.setAttribute(k, a[k]); if (txt) el.textContent = txt; svg.append(el); };
  [0, 0.5, 1].forEach((f) => add("line", { x1: pad, x2: W, y1: H - pad - f * (H - 2 * pad), y2: H - pad - f * (H - 2 * pad), stroke: "var(--line)" }));
  add("text", { x: 0, y: H - pad + 4 }, "0"); add("text", { x: 0, y: pad + 4 }, String(top));
  for (let i = 0; i < BINS; i++) {
    const hh = (v) => (v / top) * (H - 2 * pad);
    if (det[i]) add("rect", { class: "r", x: pad + i * bw + 1, y: H - pad - hh(det[i]), width: bw / 2 - 1, height: hh(det[i]), rx: 2 });
    if (dec[i]) add("rect", { class: "b", x: pad + i * bw + bw / 2, y: H - pad - hh(dec[i]), width: bw / 2 - 1, height: hh(dec[i]), rx: 2 });
  }
  add("text", { x: pad, y: H - 4 }, fmtMs(min)); add("text", { x: W - 120, y: H - 4 }, fmtMs(max));
  const nDet = det.reduce((a, b) => a + b, 0), nDec = dec.reduce((a, b) => a + b, 0);
  svg.setAttribute("aria-label", `${nDet} detections and ${nDec} decoys spawned between ${fmtMs(min)} and ${fmtMs(max)}`);
  // Legend carries the totals, so the chart never depends on color alone.
  return h("div", {}, svg, h("p", { class: "legend" }, tag(`■ detections: ${nDet}`, "red"), " ", tag(`■ decoys spawned: ${nDec}`, "teal")));
}

async function viewEvents() {
  const evs = (await api("/api/events")).filter((e) => e.event !== "watch_error");   // internal watcher errors (e.g. Claude usage limit) are not shown here
  const types = ["all", ...new Set(evs.map((e) => e.event))];
  const rows = evs.filter((e) => (state.filter === "all" || e.event === state.filter) && inRange(e.ts, state.range) &&
    (!state.q || JSON.stringify(e).toLowerCase().includes(state.q.toLowerCase())));
  const bodyRows = rows.length ? dayRows(rows, 5, (e) => h("tr", {}, h("td", { class: "mono" }, fmtClock(e.ts), " ", newPill(e.ts)), h("td", {}, evTag(e)),
    h("td", { class: "mono" }, e.attacker_ip || "–"), h("td", {}, describe(e)), h("td", { class: "mono meta" }, e.run_id || "–"))) : [];
  const legend = h("div", { class: "legendbar" }, h("span", { class: "lgtitle" }, "Stripe color:"),
    CATEGORIES.map(([k, label, color]) => h("span", { class: "lg c-" + k }, h("i", {}), label)),
    h("span", { class: "lgnote" }, "shaded bands = one incident / run"));
  return [
    head("Catch log", "Everything the platform did, newest first. Rows are grouped by incident; the stripe shows what kind of event it was."),
    legend,
    h("div", { class: "toolbar" },
      h("select", { "aria-label": "Filter by event type", onchange: (ev) => { state.filter = ev.target.value; render(); } },
        types.map((t) => h("option", { value: t, selected: t === state.filter }, t === "all" ? "All events" : (EVENT_KIND[t] || [0, t])[1]))),
      rangeSelect(state.range, (v) => { state.range = v; }),
      h("input", { type: "search", placeholder: "Search…", value: state.q, "aria-label": "Search events",
        oninput: (ev) => { state.q = ev.target.value; clearTimeout(viewEvents.t); viewEvents.t = setTimeout(render, 250); } })),
    h("div", { class: "card scroll" }, rows.length ? h("table", {},
      h("thead", {}, h("tr", {}, ["Time", "Event", "Source IP", "Details", "Incident"].map((c) => h("th", {}, c)))),
      h("tbody", {}, bodyRows)) : empty("No matching events")),
  ];
}

const SEV_KIND = { Critical: "crit", High: "red", Medium: "amber", Low: "green" };
async function viewSessions() {
  const [all, cmds] = await Promise.all([api("/api/sessions"), api("/api/commands")]);
  const techs = [...new Map(all.flatMap((a) => a.techniques.map((t) => [t.id, t.name]))).entries()].sort();
  const needle = state.cq.toLowerCase();
  const s = all.filter((a) => inRange(a.time, state.crange) && (!state.ctech || a.techniques.some((t) => t.id === state.ctech)) &&
    (!needle || [a.attacker_ip, a.run_id, a.summary, a.stage, ...a.evidence, ...a.techniques.flatMap((t) => [t.id, t.name])].join(" ").toLowerCase().includes(needle)));
  const fresh = s.filter((a) => isNew(a.time)).length;
  return [head("Catches", "Newest first. Click a summary to read it in full; the evidence is folded under each card."),
    h("div", { class: "toolbar" },
      h("select", { "aria-label": "Filter by technique", onchange: (ev) => { state.ctech = ev.target.value; render(); } },
        h("option", { value: "" }, "All techniques"), techs.map(([id, name]) => h("option", { value: id, selected: id === state.ctech }, `${id} ${name}`))),
      rangeSelect(state.crange, (v) => { state.crange = v; }),
      h("input", { type: "search", placeholder: "Search catches…", value: state.cq, "aria-label": "Search catches",
        oninput: (ev) => { state.cq = ev.target.value; clearTimeout(viewSessions.t); viewSessions.t = setTimeout(render, 250); } }),
      h("span", { class: "meta" }, `${s.length} of ${all.length} catches`, fresh ? ` · ${fresh} new since your last visit` : "")),
    s.length ? s.map((a) => h("div", { class: "card session" },
      h("header", {}, h("span", { class: "ip mono" }, a.attacker_ip), tag(a.severity, SEV_KIND[a.severity] || ""), tag(a.stage.replace("_", " "), "red"),
        a.trap_contact && (a.trap_contact.honeytokens || a.trap_contact.decoys) ? h("span", { class: "tag crit", title: "Proof of movement: a planted credential was used or a lure-only decoy was reached" },
          [a.trap_contact.honeytokens ? plural(a.trap_contact.honeytokens, "honeytoken") + " used" : "", a.trap_contact.decoys ? plural(a.trap_contact.decoys, "decoy") + " reached" : ""].filter(Boolean).join(" · ")) : null,
        a.techniques.map((t) => h("button", { class: "tag blue tagbtn", title: `Open ${t.id} in the MITRE ATT&CK tab`,
          onclick: () => { state.mitre = t.id; window.scrollTo(0, 0); location.hash = "mitre"; render(); } }, `${t.id} ${t.name}`)), newPill(a.time),
        h("span", { class: "conf" }, "confidence ", h("span", { class: "bar" }, h("b", { "data-w": a.confidence })), Math.round(a.confidence * 100) + "%"),
        h("span", { class: "meta" }, fmtTime(a.time), " · ", a.run_id),
        a.has_report ? h("span", { class: "reportlinks" }, h("a", { href: "/report/" + encodeURIComponent(a.run_id), target: "_blank", rel: "noopener",
        // open the report in the dashboard's current theme (the Theme button), read at click time
        onclick: (ev) => { ev.currentTarget.href = "/report/" + encodeURIComponent(a.run_id) + "?theme=" + (document.documentElement.dataset.theme === "light" ? "light" : "dark"); } }, "Incident report"), " · ", h("a", { href: "/report/" + encodeURIComponent(a.run_id) + ".pdf", target: "_blank", rel: "noopener" }, "PDF")) : null),
      // Summary is clamped to two lines (click to expand); evidence is folded away until asked for.
      h("p", { class: "sumtxt clamp", title: "Click to expand", onclick: (ev) => ev.currentTarget.classList.toggle("clamp") }, a.summary),
      h("div", { class: "cardfoot" },
        h("details", { class: "evid" }, h("summary", {}, `Evidence (${a.evidence.length})`), h("ul", {}, a.evidence.map((e) => h("li", {}, e)))),
        h("span", { class: "meta decoyline" }, "Decoys: ", a.recommended_decoys.length ? a.recommended_decoys.map((d) => tag(d, "teal")) : "none")),
      commandsFold(cmds[a.run_id], "c:" + a.run_id + ":" + a.attacker_ip, knownTechs(s)))) : empty("No analyzed runs yet")];
}

// Pyramid of Pain (David Bianco): a triangle cut into bands, narrow top (hard for the attacker to change) to wide base (easy).
const PYSHORT = { ttp: "TTPs", tool: "Tools", artifact: "Artifacts", domain: "Domains", ip: "IP addresses", hash: "Hashes" };
function pyramidCard(levels) {
  if (!levels) return null;
  return h("div", { class: "card" }, h("h2", {}, "Pyramid of Pain"),
    h("p", { class: "meta pairnote" }, "How much it hurts an attacker when you deny each kind of indicator. Blocking an IP is easy for them to get around; detecting and trapping their behaviour is not. Counts below come from the analyzed incidents."),
    h("div", { class: "pyramid" }, levels.map((lv, i) => {
      const n = levels.length, edge = (k) => 0.16 + 0.84 * (k / n);   // truncated apex so the top band can hold its label
      const t = edge(i), b = edge(i + 1), pt = (f) => `${(50 - 50 * f).toFixed(1)}%`, pu = (f) => `${(50 + 50 * f).toFixed(1)}%`;
      const clip = `polygon(${pt(t)} 0, ${pu(t)} 0, ${pu(b)} 100%, ${pt(b)} 100%)`;
      return h("div", { class: "pyrow" },
        h("div", { class: "pyband lv" + (n - i), "data-clip": clip }, h("strong", {}, PYSHORT[lv.key] || lv.name), h("small", {}, lv.pain)),
        h("div", { class: "pyinfo" }, h("span", {}, lv.denied), h("small", {}, lv.seen ? lv.seen + ". " + lv.recorded : lv.recorded)));
    })));
}

async function viewMitre() {
  const [m, cmds] = await Promise.all([api("/api/mitre"), api("/api/commands")]);
  const byTactic = Object.fromEntries(m.tactics.map((t) => [t, []]));
  m.techniques.forEach((t) => t.tactics.forEach((x) => (byTactic[x] ||= []).push(t)));
  const active = m.tactics.filter((t) => byTactic[t].length);
  const sel = m.techniques.find((t) => t.id === state.mitre) || m.techniques[0];
  const nameOf = (id) => (m.techniques.find((t) => t.id === id) || { name: "" }).name;
  const clip = (t, n) => (t.length > n ? t.slice(0, n).replace(/\s+\S*$/, "") + "…" : t);
  const latest = sel && sel.incidents[0];
  const together = sel ? sel.together : [];
  const ev = sel ? [...new Set(sel.evidence)].slice(0, 6) : [];
  // Commands behind this technique: the fixed rule table in agent/transcripts.py matched them in the saved honeypot logs.
  const techCmds = (() => {
    if (!sel) return [];
    const tot = {};
    [...new Set(sel.runs)].forEach((rid) => ((cmds[rid] || { by_tech: {} }).by_tech[sel.id] || []).forEach((x) => { tot[x.cmd] = (tot[x.cmd] || 0) + x.n; }));
    return Object.entries(tot).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([cmd, n]) => ({ cmd, n, techs: [] }));
  })();
  return [head("MITRE ATT&CK", "Techniques the agent mapped, under their ATT&CK tactic. Click one for what it means and what happened."),
    h("div", { class: "card" },
      active.length ? h("div", { class: "matrix" }, active.map((t) =>
        h("div", { class: "col active" }, h("h3", {}, t),
          byTactic[t].map((x) => h("button", { class: "tech", "aria-pressed": String(x.id === state.mitre),
            onclick: () => { state.mitre = x.id; render(); } }, h("strong", {}, x.id), h("small", {}, x.name), h("small", {}, x.count + "×")))))) : empty("No techniques observed yet"),
      h("p", { class: "legend" }, "No activity observed in: ", m.tactics.filter((t) => !byTactic[t].length).join(", "), ".")),
    sel ? h("div", { class: "grid two" },
      h("div", { class: "card" },
        h("h2", {}, `${sel.id} · ${sel.name}`),
        h("p", { class: "meta" }, sel.tactics.map((x) => tag(x, "blue")), " ",
          h("a", { class: "mitrelink", href: sel.url, target: "_blank", rel: "noopener noreferrer" }, "MITRE ATT&CK page ↗"),
          sel.also && sel.also.length ? h("span", { class: "meta" }, " · MITRE also lists it under " + sel.also.join(", ")) : null),
        h("h3", { class: "subhead" }, "What it is"), h("p", { class: "plain" }, sel.what),
        h("p", {}, h("button", { class: "chipbtn", title: "Open the Catches tab filtered to this technique",
          onclick: () => { state.ctech = sel.id; state.cq = ""; state.crange = "all"; window.scrollTo(0, 0); location.hash = "sessions"; render(); } }, `Show catches with ${sel.id} →`)),
        h("h3", { class: "subhead" }, "Pain to the attacker"),
        h("p", { class: "plain" }, tag("TTP · tough", "blue"), " A technique is behaviour, the top of the Pyramid of Pain. Blocking the attacker's IP or tool does not stop it; they have to change how they work."),
        h("h3", { class: "subhead" }, "What happened here"),
        latest ? h("p", { class: "plain" }, h("span", { class: "meta" }, `${latest.ip} · ${fmtTime(latest.time)} · seen in ${sel.incidents.length} incident${sel.incidents.length === 1 ? "" : "s"}`),
          h("br"), clip(latest.summary, 320)) : null,
        h("h3", { class: "subhead" }, "Commands behind it"),
        techCmds.length ? [h("ul", { class: "cmdlist techcmds" }, techCmds.map((r) => cmdRow(r, ""))),
          h("p", { class: "meta" }, "Matched by the fixed command-to-technique rules in the saved SSH honeypot logs, most frequent first.")]
          : h("p", { class: "meta" }, "No typed shell command maps to this technique: it was seen in the network traffic itself."),
        h("h3", { class: "subhead" }, "Often seen together with"),
        together.length ? [h("ul", { class: "together" }, together.map((t) => h("li", {},
          h("button", { class: "chipbtn", title: "Show this technique", onclick: () => { state.mitre = t.id; render(); } }, `${t.id} ${nameOf(t.id)}`),
          h("span", { class: "meta" }, ` in ${t.sessions} of ${t.of} sessions · usually ${t.order === "either" ? "in either order" : t.order + " it"}`),
          h("div", { class: "cmdnote" }, h("code", {}, t.example[0]), t.order === "before" ? " ← " : " → ", h("code", {}, t.example[1]))))),
          h("p", { class: "meta" }, "Different commands of the two techniques typed within 10 seconds of each other in the same SSH session, in at least 2 sessions. Strongest link first (shared sessions out of sessions with either technique); closest example pair shown.")]
          : h("p", { class: "meta" }, sel.sessions ? "No other technique repeatedly follows or precedes it in the same session." : "Seen in the network traffic, not as typed commands, so there is no command pattern to compare."),
        h("details", { class: "evid" }, h("summary", {}, `Evidence (${ev.length})`), h("ul", {}, ev.map((x) => h("li", {}, x))))),
      h("div", { class: "card" }, h("h2", {}, "All observed techniques"),
        h("table", {}, h("thead", {}, h("tr", {}, ["ID", "Name", "Tactic", "Seen"].map((c) => h("th", {}, c)))),
          h("tbody", {}, m.techniques.map((t) => h("tr", {}, h("td", { class: "mono" }, t.id), h("td", {}, t.name), h("td", {}, t.tactics[0]), h("td", {}, t.count + "×"))))))) : null,
    pyramidCard(m.pyramid),
    m.pairs.length ? h("div", { class: "card" }, h("h2", {}, "Detected in the same incident"),
      h("p", { class: "meta pairnote" }, "Listed only when the agent reported both techniques for the same attacker in the same incident. The arrow follows MITRE's tactic order; it is not a claim about timing."),
      h("table", {}, h("thead", {}, h("tr", {}, ["Techniques", "Tactics", "Incidents", "Source"].map((c) => h("th", {}, c)))),
        h("tbody", {}, m.pairs.map((p) => h("tr", {}, h("td", {}, h("button", { class: "chipbtn", onclick: () => { state.mitre = p.a; render(); } }, `${p.a} ${nameOf(p.a)}`),
          " + ", h("button", { class: "chipbtn", onclick: () => { state.mitre = p.b; render(); } }, `${p.b} ${nameOf(p.b)}`)),
          h("td", {}, p.tactics), h("td", {}, String(p.count)), h("td", { class: "mono" }, p.ips.join(", "))))))) : null,
  ];
}

async function viewDecoys() {
  const d = await api("/api/decoys");
  const left = (e) => { const s = e - d.now; return s > 0 ? Math.ceil(s / 60) + " min" : "expired"; };
  return [head("Decoys", "Hosts the controller created in response to attacker behavior."),
    h("div", { class: "card" }, h("h2", {}, "Running now"),
      d.live === null ? empty("Docker is not reachable") : d.live.length ? h("table", {},
        h("thead", {}, h("tr", {}, ["Template", "Address", "Container", "Status", "Time left", "Activity since spawn"].map((c) => h("th", {}, c)))),
        h("tbody", {}, d.live.map((x) => h("tr", {}, h("td", {}, tag(x.template, "teal")), h("td", { class: "mono" }, x.ip),
          h("td", { class: "mono" }, x.name), h("td", {}, x.status), h("td", {}, left(x.expires)),
          h("td", {}, x.activity && x.activity.events ? [tag(x.activity.events + " events", "red"), " ", h("span", { class: "meta mono" },
            [x.activity.logins.length ? "logins: " + x.activity.logins.join(", ") : "", x.activity.commands.length ? "last: " + x.activity.commands.join(" | ") : ""].filter(Boolean).join(" · "))]
            : h("span", { class: "meta" }, "no contact yet")))))) : empty("No spawned decoys running")),
    h("div", { class: "card" }, h("h2", {}, "History"),
      d.history.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Event", "Details"].map((c) => h("th", {}, c)))),
        h("tbody", {}, dayRows(d.history, 3, (e) => h("tr", {}, h("td", { class: "mono" }, fmtClock(e.ts)), h("td", {}, evTag(e)), h("td", {}, describe(e)))))) : empty("Nothing yet")),
  ];
}

const FLOW = [
  ["Attacker", "Kali VM 10.10.10.10 runs nmap, hydra, nikto against the lab.", null],
  ["Honeypots", "Cowrie (SSH), fake web admin, OpenCanary (FTP, telnet), SMB decoy. Nothing legitimate lives here.", null],
  ["Capture", "tshark records VMnet1 into rolling pcaps, saved per run.", "capture"],
  ["Claude analysis", "Claude reads the pcap through the Wireshark MCP (read-only tools) and returns structured JSON with ATT&CK techniques.", "analysis"],
  ["Validation", "Schema, pcap cross-check of the attacker IP, confidence threshold. Attacker text never becomes a command.", "trust"],
  ["Controller", "Starts decoys from a fixed allowlist only. Approval mode, limits, time-to-live, kill switch.", "controller"],
  ["New decoy", "A new host appears on the lab subnet, matched to what the attacker probed.", "decoy"],
  ["Event log + dashboard", "Every step is appended to events.jsonl and shown here.", null],
];
async function viewPipeline() {
  const [evs, runs, o] = await Promise.all([api("/api/events"), api("/api/runs"), api("/api/overview")]);
  const last = (...names) => evs.find((e) => names.includes(e.event));
  const info = {
    capture: runs[0] ? `Last run: ${runs[0].run_id} · ${runs[0].pcap_files} file(s), ${fmtBytes(runs[0].pcap_bytes)}` : "No runs yet",
    analysis: (() => { const e = last("attack_detected", "analysis_clean", "analysis_clean_disputed"); return e ? `Last: ${EVENT_KIND[e.event][1]} · ${fmtTime(e.ts)}` : "No analysis yet"; })(),
    trust: "Claude decides; code checks before anything acts.",
    controller: (() => { const e = last("decoy_spawned", "decoy_rejected", "approval_denied", "killswitch"); return e ? `Last: ${EVENT_KIND[e.event][1]} · ${fmtTime(e.ts)}` : "No actions yet"; })(),
    decoy: o.decoys_live === null ? "Docker not reachable" : `${o.decoys_live} live now`,
  };
  return [head("Pipeline", "How an attack becomes a new decoy, and where each trust boundary sits."),
    h("div", { class: "flow" }, FLOW.map(([t, d, k]) => h("div", { class: "node" + (k === "trust" ? " trust" : "") },
      h("h3", {}, t), h("p", {}, d), k && info[k] ? h("div", { class: "last" }, info[k]) : null))),
    h("p", { class: "legend" }, "The amber step is the trust boundary: honeypot and packet content is attacker-controlled, so it is treated as data, never as instructions."),
    h("div", { class: "card" }, h("h2", {}, "Who decides, who acts"),
      h("table", {}, h("thead", {}, h("tr", {}, ["Component", "Role", "Can do", "Cannot do"].map((c) => h("th", {}, c)))),
        h("tbody", {}, [
          ["Claude (analysis agent)", "Decides", "Read the capture through read-only Wireshark tools; return structured JSON", "Run commands, write files, start or stop anything"],
          ["Validator", "Checks", "Reject malformed output, unknown IPs, off-list decoys, low confidence", "Change Claude's findings"],
          ["Controller", "Acts", "Start decoys from the fixed allowlist, retire them, kill switch", "Start anything not on the allowlist; exceed 3 live decoys"],
          ["Dashboard", "Shows", "Read logs and results", "Change anything in the lab"],
        ].map((r) => h("tr", {}, r.map((c, i) => h("td", i === 0 ? { class: "strong" } : {}, c))))))),
  ];
}

// Replay: plays back a SAVED run (stored analysis + recorded controller events). Nothing is executed.
async function viewReplay() {
  const runs = await api("/api/runs");
  const sel = state.replayRun && runs.find((r) => r.run_id === state.replayRun) ? state.replayRun : runs[0]?.run_id;
  const stage = h("div", { class: "grid" });
  const play = async (instant) => {
    const d = await api("/api/replay/" + encodeURIComponent(sel));
    stage.replaceChildren();
    const steps = replaySteps(d);
    for (const s of steps) {
      if (!instant && !REDUCED) await new Promise((r) => setTimeout(r, 1100));
      stage.append(s);
    }
  };
  if (sel) play(true);  // show the full run straight away; "Play" restarts it step by step
  return [head("Replay", "Plays back a saved run offline: the recorded analysis and controller actions. No Docker, no Claude, nothing is started."),
    runs.length ? [h("div", { class: "toolbar" },
      h("select", { id: "run", "aria-label": "Saved run", onchange: (e) => { state.replayRun = e.target.value; render(); } },
        runs.map((r) => h("option", { value: r.run_id, selected: r.run_id === sel }, `${r.run_id} (${r.detections} detection${r.detections === 1 ? "" : "s"})`))),
      h("button", { class: "btn", onclick: () => play(false) }, "Play"),
      h("button", { class: "ghost", onclick: () => play(true) }, "Show all")), stage] : empty("No saved runs with an analysis yet")];
}
function replaySteps(d) {
  const card = (n, title, ...body) => h("div", { class: "card node active" }, h("h3", {}, title), ...body);
  const steps = [card(1, "Capture", h("p", {}, `${d.run.pcap_files} pcap file(s), ${fmtBytes(d.run.pcap_bytes)} recorded from the lab network.`))];
  steps.push(card(2, "Claude analysis (Wireshark MCP)", d.analyses.length ? d.analyses.map((a) => h("div", {},
    h("p", {}, h("strong", { class: "mono" }, a.attacker_ip), " ", tag(a.stage.replace("_", " "), "red"), " ", a.techniques.map((t) => tag(t.id + " " + t.name, "blue")), " ", tag(Math.round(a.confidence * 100) + "%", "teal")),
    h("p", {}, a.summary), h("ul", { class: "meta" }, a.evidence.slice(0, 4).map((e) => h("li", {}, e))))) : h("p", {}, "No attacker behavior found.")));
  steps.push(card(3, "Validation", h("p", {}, "Output matched the schema, the attacker IP was confirmed in the pcap, decoy names are on the allowlist.")));
  const acts = d.events.filter((e) => !["attack_detected", "analysis_clean"].includes(e.event));
  steps.push(card(4, "Controller", acts.length ? h("table", {}, h("tbody", {}, acts.map((e) => h("tr", {}, h("td", {}, evTag(e)), h("td", {}, describe(e)))))) : h("p", {}, "No controller action recorded for this run.")));
  steps.push(card(5, "Event log", h("p", {}, `${d.events.length} event(s) recorded for this run and shown in the Catch log.`)));
  return steps;
}

async function viewEval() {
  const ev = await api("/api/eval");
  const cols = ["Scenario", "Runs", "Rules detected", "Claude detected", "Rules time-to-detect (s)", "Claude analysis (s)", "Decoy deployed", "False alarms (rules / Claude)"];
  const dash = (v) => (v == null ? "–" : v);
  const row = (s) => s.runs ? [s.scenario, s.runs, s.rules_detected, s.claude_detected, dash(s.rules_ttd_s), dash(s.claude_seconds), s.decoy_deployed, `${s.rules_false_alarms} / ${s.claude_false_alarms}`]
    : [s.scenario, 0, "–", "–", "–", "–", "–", "–"];
  const have = ev.summary.some((s) => s.runs);
  const camp = await api("/api/campaign");
  const ccols = ["Scenario", "Runs", "Excluded (Claude unavailable)", "Gate triggered", "Claude detected", "Median time to detect (s)", "Decoy deployed", "False alarms"];
  const crow = (s) => !s.runs ? [s.scenario, 0, s.excluded, "–", "–", "–", "–", "–"] : [s.scenario, s.runs, s.excluded || 0, s.gate_triggered, s.claude_detected, dash(s.ttd_s), s.decoy_deployed, s.false_alarms];
  const campaignCard = camp.summary.length ? h("div", { class: "card scroll" }, h("h2", {}, "Unattended campaign (real attack start times)"),
    h("table", {}, h("thead", {}, h("tr", {}, ccols.map((c) => h("th", {}, c)))),
      h("tbody", {}, camp.summary.map((s) => h("tr", {}, crow(s).map((c, i) => h("td", i === 0 ? { class: "strong" } : {}, c)))))),
    h("p", { class: "legend" }, "Scored by eval/campaign_eval.py against the attacker's own log from Kali; time to detect counts from the real attack start.")) : null;
  return [head("Evaluation", "Rule-based detector vs Claude-driven analysis, per scenario (from eval/evaluate.py)."),
    h("div", { class: "card scroll" }, h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))),
      h("tbody", {}, ev.summary.map((s) => h("tr", {}, row(s).map((c, i) => h("td", i === 0 ? { class: "strong" } : { class: s.runs ? "" : "meta" }, c))))))),
    campaignCard,
    h("p", { class: "legend" }, have
      ? "Rules time-to-detect is capture time from the attacker's first packet; Claude analysis is the time spent analyzing the finished capture. They measure different things. Re-run eval/evaluate.py to refresh."
      : "No evaluation data yet. Run scenarios with scripts/run_loop.sh, then eval/evaluate.py."),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h2", {}, "Scenarios"),
        h("table", {}, h("tbody", {}, [
          ["Port scan", "nmap full-range SYN scan from Kali."],
          ["Slow port scan", "Few ports, one probe every 5 s. Tests whether Claude sees what a rate rule misses."],
          ["SSH brute force", "hydra against the Cowrie honeypot."],
          ["Web probing", "nikto and manual requests against the fake admin panel."],
          ["Benign only", "Only the traffic generator (normal logins, page loads). Any alarm is a false alarm."],
        ].map(([a, b]) => h("tr", {}, h("td", { class: "strong" }, a), h("td", { class: "meta" }, b)))))),
      h("div", { class: "card" }, h("h2", {}, "Metrics"),
        h("table", {}, h("tbody", {}, [
          ["Detected", "Did the detector flag the attacker IP in this run?"],
          ["Time to detect", "Seconds from the first attack packet to a finding."],
          ["Decoy deployed", "Did an appropriate decoy appear?"],
          ["False alarms", "Findings in benign-only runs, checked against the generator's ground-truth log."],
        ].map(([a, b]) => h("tr", {}, h("td", { class: "strong" }, a), h("td", { class: "meta" }, b))))))),
  ];
}

const head = (t, s) => h("div", {}, h("h1", {}, t), h("p", { class: "sub" }, s));
const TABS = [["overview", "Overview", viewOverview], ["events", "Catch log", viewEvents], ["sessions", "Catches", viewSessions],
  ["mitre", "MITRE ATT&CK", viewMitre], ["decoys", "Decoys", viewDecoys], ["pipeline", "Pipeline", viewPipeline],
  ["replay", "Replay", viewReplay], ["eval", "Evaluation", viewEval]];

// Simple line icons for the sidebar (inline SVG, no external assets).
const ICONS = {
  overview: "M3 3h7v7H3zM14 3h7v4h-7zM14 11h7v10h-7zM3 14h7v7H3z",
  events: "M4 6h16M4 12h16M4 18h10",
  sessions: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z",
  mitre: "M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z",
  decoys: "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8a4 4 0 100 8 4 4 0 000-8z",
  pipeline: "M4 6h4v4H4zM16 6h4v4h-4zM10 14h4v4h-4zM8 8h8M12 10v4",
  replay: "M8 5v14l11-7z",
  eval: "M4 20V10M10 20V4M16 20v-8M22 20H2",
};
function icon(key) {
  const NS = "http://www.w3.org/2000/svg", svg = document.createElementNS(NS, "svg"), p = document.createElementNS(NS, "path");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
  p.setAttribute("d", ICONS[key] || ICONS.overview); svg.append(p);
  return svg;
}

let rendering = false;
async function render() {
  if (rendering) return; rendering = true;
  const id = (location.hash || "#overview").slice(1);
  const tab = TABS.find((t) => t[0] === id) || TABS[0];
  $("#tabs").replaceChildren(...TABS.map(([k, label]) => h("button", { role: "tab", "aria-selected": String(k === tab[0]), onclick: () => { location.hash = k; } }, icon(k), label)));
  try {
    const nodes = await tab[2]();
    const winY = window.scrollY, inner = [...view.querySelectorAll(".scroll")].map((el) => el.scrollTop);   // keep the reading position across refreshes
    view.replaceChildren(...[nodes].flat(2).filter(Boolean));
    view.querySelectorAll(".scroll").forEach((el, i) => { el.scrollTop = inner[i] || 0; });
    window.scrollTo(0, winY);
    view.querySelectorAll("[data-w]").forEach((b) => { b.style.width = Math.round(b.dataset.w * 100) + "%"; });
    view.querySelectorAll("[data-clip]").forEach((b) => { b.style.clipPath = b.dataset.clip; });   // inline style attributes are blocked by the CSP; the CSSOM is not
    // MITRE matrix: give tactics with observed techniques more room than empty ones.
    view.querySelectorAll(".matrix").forEach((m) => {
      m.style.gridTemplateColumns = [...m.children].map((c) => "minmax(180px, 1fr)").join(" ");
    });
    $("#live").classList.remove("off");
    $("#live span").textContent = paused ? "paused" : "updated " + new Date().toLocaleTimeString([], { hour12: false });
  } catch (e) {
    view.replaceChildren(empty("Could not load data from the dashboard server."));
    $("#live").classList.add("off"); $("#live span").textContent = "offline";
  }
  rendering = false;
}
window.addEventListener("hashchange", render);
$("#theme").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next; try { localStorage.setItem("theme", next); } catch (_) {}
});
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch (_) {}
// Live run banner: polls a light endpoint every 2 s, so a run is visible while it happens (all tabs).
const STAGES = [["capturing", "Capture"], ["saving", "Save"], ["analyzing", "Claude analysis"], ["acting", "Controller"]];
let lastStage = "idle", lastInc = 0;
async function pollStatus() {
  const b = $("#banner");
  try {
    const s = await api("/api/status");
    if (s.stage === "idle") { b.hidden = true; if (lastStage !== "idle") render(); lastStage = "idle"; return; }
    const secs = Math.max(0, Math.round(s.now - s.started));
    if (s.mode === "continuous") {   // watcher: always-on monitoring, no fixed steps
      const inc = s.open_incidents || [];
      b.hidden = false;
      b.replaceChildren(
        h("h2", {}, h("i", { "aria-hidden": "true" }), "Continuous monitoring"),
        h("div", { class: "steps" }, h("span", { class: "step" + (inc.length ? "" : " done") }, inc.length ? "Tracking " + inc.join(", ") : "No incidents"),
          s.activity && s.activity.startsWith("analyzing") ? h("span", { class: "step on" }, s.activity) : null),
        h("div", { class: "live-n" },
          h("div", {}, h("b", {}, String(s.windows ?? 0)), h("span", {}, `windows (${s.window}s)`)),
          h("div", {}, h("b", {}, String((s.sources || []).length)), h("span", {}, "sources seen")),
          h("div", {}, h("b", {}, `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`), h("span", {}, "uptime"))));
      if (lastStage === "idle" || (inc.length !== lastInc)) render();
      lastInc = inc.length; lastStage = "watching"; return;
    }
    const at = STAGES.findIndex(([k]) => k === s.stage);
    b.hidden = false;
    b.replaceChildren(
      h("h2", {}, h("i", { "aria-hidden": "true" }), `Run in progress: ${s.name || "unnamed"}`),
      h("div", { class: "steps" }, STAGES.map(([k, label], i) => h("span", { class: "step" + (i < at ? " done" : i === at ? " on" : "") }, label))),
      h("div", { class: "live-n" },
        s.packets != null ? h("div", {}, h("b", {}, s.packets.toLocaleString()), h("span", {}, "packets")) : null,
        s.bytes != null ? h("div", {}, h("b", {}, fmtBytes(s.bytes)), h("span", {}, "captured")) : null,
        h("div", {}, h("b", {}, `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`), h("span", {}, "elapsed"))));
    if (lastStage !== s.stage && lastStage !== "idle") render();  // new stage: refresh data below
    lastStage = s.stage;
  } catch (_) { b.hidden = true; }
}
setInterval(pollStatus, 2000); pollStatus();

// Auto-refresh, but never while the user is typing/choosing or watching a replay.
let paused = false;
$("#pause").addEventListener("click", (e) => {
  paused = !paused; e.target.textContent = paused ? "Resume" : "Pause";
  e.target.setAttribute("aria-pressed", String(paused)); if (!paused) render();
});
setInterval(() => {
  if (paused) return;
  const a = document.activeElement;
  if ((location.hash || "#overview") === "#replay" || (a && /SELECT|INPUT/.test(a.tagName))) return;
  // Someone is reading further down: do not touch the page (new data appears on the next refresh after scrolling back up).
  if (window.scrollY > 40 || [...view.querySelectorAll(".scroll")].some((el) => el.scrollTop > 20)) {
    $("#live span").textContent = "paused while scrolled"; return;
  }
  render();
}, 5000);
render();

#!/usr/bin/env python3
"""Labeled replay corpus: attack runs and benign traffic, split into development / validation / holdout.

  python detect/corpus.py build        # read saved pcaps + campaign logs, write corpus/manifest.json and corpus/events/*.jsonl.gz
  python detect/corpus.py summary      # what is in it

Labels come from ground truth, never from the detector or from Claude:
  attack sample  = one scenario run in an attacks/logs/campaign_*.jsonl file (real start/end written on Kali).
                   Attack clients = the Kali address (plus the fixed decoy addresses a stealth scan spoofs).
                   Every OTHER client in the sample (the workstation traffic generator) is benign background.
  benign sample  = a stretch with the attacker silent: idle campaign windows, the old benign runs, and recorded
                   benign stretches (capture/archive, written by the watcher's recorder, and capture/benign).
A sample is kept only when saved pcaps cover (almost) its whole interval, so a missing capture can never look like
"nothing happened". Pcaps stay out of git (sensitive); the corpus keeps only the structural events (events.py:
no URLs, no payloads) plus the SHA-256 of every source pcap, so the labeled data can be re-checked and shared.

Splits (fixed, by attack TYPE, named schemes in SCHEMES; v1 shown, `deploy` also lets the proposer learn stealthscan and traverse):
  development  portscan, sshbrute, webprobe, lure          (the proposer may look at these)
  validation   slowscan, dirbrute                          (the promotion gate checks these)
  holdout      stealthscan, traverse, overlap              (reported at the end only; overlap is a mix of other types)
Benign data is split by contiguous time blocks (never by random event, so correlated traffic cannot leak across).
"""
import hashlib
from bisect import bisect_left, bisect_right
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import hpevents  # noqa: E402
from events import find_tshark, load_events, pcap_events, save_events  # noqa: E402

CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.json"
# Attack types are assigned to splits by a named scheme at load time (benign blocks keep the split written in the manifest).
SCHEMES = {
    # v1: the first published split. stealthscan and traverse are held out, so nothing about them can be learned.
    "v1": {"portscan": "development", "sshbrute": "development", "webprobe": "development", "lure": "development",
           "slowscan": "validation", "dirbrute": "validation", "stealthscan": "holdout", "traverse": "holdout", "overlap": "holdout", "manual": "holdout"},
    # deploy: everything the baseline misses is available for learning; only the three-at-once mix stays held out. Generalization is
    # then measured by leave-one-type-out (crossval.py), not by a single fixed holdout.
    "deploy": {"portscan": "development", "sshbrute": "development", "webprobe": "development", "lure": "development",
               "stealthscan": "development", "traverse": "development", "slowscan": "validation", "dirbrute": "validation", "overlap": "holdout",
               "manual": "holdout"},          # a person is never used for learning: always a held-out test
}
ATTACK_SPLIT = SCHEMES["v1"]
DECOY_SOURCES = ["10.10.10.201", "10.10.10.202", "10.10.10.203"]       # spoofed by the stealth scan (attacks/campaign.sh)
SPOOFING = {"stealthscan"}
PAD_BEFORE, PAD_AFTER = 5, 20          # seconds of context around a scenario
MIN_COVERAGE = 0.9                     # benign blocks: the saved captures must cover (almost) all of it
MIN_ATTACK_COVERAGE = 0.6              # attack runs: incident folders only keep the windows the attacker appears in, so quiet gaps are expected
BLOCK_S = 600                          # benign recordings are cut into 10-minute blocks, each block gets one split
FILE_WINDOW = {"live": 30, "off": 30, "lab": 300}


def env():
    out = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def name_start(f):
    m = re.search(r"_(\d{14})\.pcap$", f.name)
    return time.mktime(time.strptime(m.group(1), "%Y%m%d%H%M%S")) if m else f.stat().st_mtime


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def packet_times(pcap):
    """(first, last) packet epoch via capinfos, or None for an empty capture."""
    capinfos = Path(find_tshark()).with_name("capinfos.exe")
    exe = str(capinfos) if capinfos.exists() else "capinfos"
    out = subprocess.run([exe, "-a", "-e", "-S", "-m", str(pcap)], capture_output=True, text=True).stdout
    vals = re.findall(r"(?:Earliest|Latest) packet time:\s+([0-9.]+)", out)
    return (float(vals[0]), float(vals[1])) if len(vals) == 2 else None


def gather_pcaps():
    """Unique pcaps (by SHA-256) from saved runs and benign recordings, with their time spans."""
    files = sorted(set(ROOT.glob("capture/runs/*/pcaps/*.pcap")) | set(ROOT.glob("capture/benign/**/*.pcap")) | set(ROOT.glob("capture/archive/*.pcap")))
    seen, uniq = {}, []
    for f in files:
        digest = sha256(f)
        if digest not in seen:
            seen[digest] = f
            uniq.append((f, digest))
    spans = []
    for f, digest in uniq:
        pt = packet_times(f)
        start = name_start(f)
        window = FILE_WINDOW.get(f.name.split("_")[0], 300)
        if pt and abs(pt[0] - start) > window + 60:        # file names are local time; trust the packets when they disagree
            start = pt[0]
        spans.append({"file": f, "sha256": digest, "start": start, "end": start + window, "window": window, "first": pt[0] if pt else None, "last": pt[1] if pt else None})
    # a file ends where the next one of the same capture begins (size-capped rotation); the very last one ends at its last packet
    groups = {}
    for s in spans:
        groups.setdefault(s["file"].name.split("_")[0], []).append(s)
    for group in groups.values():
        group.sort(key=lambda s: s["start"])
        for a, b in zip(group, group[1:]):
            a["end"] = min(a["end"], max(b["start"], a["start"]))
        last = group[-1]
        if last["last"]:
            last["end"] = min(last["end"], last["last"] + 1)
    return spans


def coverage(spans, t0, t1):
    """Fraction of [t0, t1] inside the union of file spans."""
    ivs = sorted((max(s["start"], t0), min(s["end"], t1)) for s in spans if s["end"] > t0 and s["start"] < t1)
    covered, cur = 0.0, t0
    for a, b in ivs:
        a = max(a, cur)
        if b > a:
            covered += b - a
            cur = b
    return covered / max(t1 - t0, 1e-9)


def cowrie_logs():
    """Every saved SSH-honeypot log (incident copies, the live log and its rotations, spawned SSH decoys)."""
    pats = ["capture/runs/*/logs/cowrie/*.json*", "capture/runs/*/logs/decoys/decoy-ssh*/*.json*", "lab/logs/cowrie/*.json*", "lab/logs/decoys/decoy-ssh*/*.json*"]
    return sorted({p for pat in pats for p in ROOT.glob(pat) if p.is_file()})


def scenario_rows():
    rows = []
    for log in sorted((ROOT / "attacks" / "logs").glob("campaign_*.jsonl")):
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("event") == "scenario":
                rows.append({**r, "log": log.name, "t0": iso(r["start"]), "t1": iso(r["end"])})
    return sorted(rows, key=lambda r: r["t0"])


def block_split(index):
    """Deterministic split for a benign block: 50% development, 25% validation, 25% holdout."""
    return ("development", "development", "validation", "holdout")[int(hashlib.sha256(str(index).encode()).hexdigest(), 16) % 4]


def build():
    e = env()
    kali = e.get("KALI_IP", "10.10.10.10")
    host = e.get("HOST_IP", "10.10.10.1")
    spans = gather_pcaps()
    print(f"{len(spans)} unique pcaps")
    all_events = []
    for s in spans:
        all_events.extend(pcap_events([s["file"]]))
    all_events.sort(key=lambda ev: ev["t"])
    hp = hpevents.corpus_events(hpevents.read_records(cowrie_logs()), all_events)
    print(f"{len(all_events)} packet events + {len(hp)} honeypot events")
    all_events = sorted(all_events + hp, key=lambda ev: ev["t"])
    CORPUS.mkdir(exist_ok=True)
    (CORPUS / "events").mkdir(exist_ok=True)
    for old in (CORPUS / "events").glob("*.jsonl.gz"):
        old.unlink()

    samples, skipped = [], []
    taken = []                                                          # intervals already used by a scenario sample

    times = [ev["t"] for ev in all_events]

    def carve(t0, t1):
        return [ev for ev in all_events[bisect_left(times, t0):bisect_right(times, t1)] if ev["client"] != host]

    def sources(t0, t1):
        return sorted({s["sha256"][:16] + ":" + s["file"].name for s in spans if s["end"] > t0 and s["start"] < t1})

    for r in scenario_rows():
        name = r["scenario"]
        if r.get("rc") not in (0, None):
            skipped.append({"scenario": name, "start": r["start"], "reason": f"tool exit code {r['rc']}"})
            continue
        t0, t1 = r["t0"] - PAD_BEFORE, r["t1"] + PAD_AFTER
        if name == "idle":
            continue                                                     # idle windows are cut into benign blocks below, like any other quiet stretch
        cov = coverage(spans, r["t0"], r["t1"])
        if cov < MIN_ATTACK_COVERAGE:
            skipped.append({"scenario": name, "start": r["start"], "reason": f"pcap coverage {cov:.0%}"})
            continue
        ev = carve(t0, t1)
        attack = name != "idle"
        clients = [kali] + (DECOY_SOURCES if name in SPOOFING or name == "overlap" else []) if attack else []
        if attack and not any(x["client"] == kali for x in ev):
            skipped.append({"scenario": name, "start": r["start"], "reason": "no packets from the attacker"})
            continue
        if not attack and any(x["client"] == kali for x in ev):
            skipped.append({"scenario": name, "start": r["start"], "reason": "idle window has attacker traffic"})
            continue
        sid = f"{name}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(r['t0']))}"
        samples.append({"id": sid, "label": "attack" if attack else "benign", "type": name, "split": SCHEMES["v1"][name] if attack else block_split(sid),
                        "start": r["t0"], "end": r["t1"], "attack_clients": clients, "campaign_log": r["log"], "events": ev, "sources": sources(t0, t1)})
        taken.append((t0 - 60, t1 + 60))

    # Benign stretches: anything covered by pcaps, away from every scenario, with no attacker traffic, in 10-minute blocks.
    free = sorted({(s["start"], s["end"]) for s in spans})
    merged = []
    for a, b in free:
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    for a, b in merged:
        cut = a
        while cut < b:
            c0, c1 = cut, min(cut + BLOCK_S, b)
            cut = c1
            if c1 - c0 < 120 or any(c0 < y and c1 > x for x, y in taken):
                continue
            if coverage(spans, c0, c1) < MIN_COVERAGE:
                continue
            ev = carve(c0, c1)
            if any(x["client"] == kali for x in ev):
                skipped.append({"scenario": "benign block", "start": c0, "reason": "attacker traffic present"})
                continue
            sid = "benign_" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(c0))
            samples.append({"id": sid, "label": "benign", "type": "benign_block", "split": block_split(sid), "start": c0, "end": c1,
                            "attack_clients": [], "campaign_log": None, "events": ev, "sources": sources(c0, c1)})

    for s in samples:
        save_events(s["events"], CORPUS / "events" / f"{s['id']}.jsonl.gz")
    manifest = {"version": 1, "built": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kali_ip": kali, "host_ip": host,
                "schemes": SCHEMES, "pad_s": [PAD_BEFORE, PAD_AFTER], "min_coverage": MIN_COVERAGE,
                "samples": [{k: v for k, v in s.items() if k != "events"} | {"n_events": len(s["events"]), "events_file": f"events/{s['id']}.jsonl.gz"} for s in samples],
                "skipped": skipped}
    MANIFEST.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    summary()


def load(scheme="deploy", types=None):
    """Manifest with each sample's events loaded; attack samples get their split from `scheme` (a name in SCHEMES or a {type: split} dict).
    `types` limits which attack types are loaded (benign always)."""
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    mapping = SCHEMES[scheme] if isinstance(scheme, str) else scheme
    keep = []
    for s in m["samples"]:
        if s["label"] == "attack":
            if types is not None and s["type"] not in types:
                continue
            s["split"] = mapping[s["type"]]
        s["events"] = load_events(CORPUS / s["events_file"])
        keep.append(s)
    m["samples"] = keep
    return m


def summary():
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = {}
    for s in m["samples"]:
        k = (s["split"], s["label"], s["type"])
        r = rows.setdefault(k, [0, 0, 0.0])
        r[0] += 1
        r[1] += s["n_events"]
        r[2] += s["end"] - s["start"]
    print(f"{'split':12} {'label':7} {'type':14} {'samples':>7} {'events':>8} {'minutes':>8}")
    for (split, label, typ), (n, ev, sec) in sorted(rows.items()):
        print(f"{split:12} {label:7} {typ:14} {n:7} {ev:8} {sec / 60:8.1f}")
    print(f"skipped: {len(m['skipped'])}")
    from collections import Counter
    for reason, n in Counter(re.sub(r"\d+%", "N%", x["reason"]) for x in m["skipped"]).items():
        print(f"  {n:3} {reason}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "build":
        build()
    elif len(sys.argv) == 2 and sys.argv[1] == "summary":
        summary()
    else:
        sys.exit(__doc__)

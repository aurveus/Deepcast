#!/usr/bin/env python3
"""Decoy controller. Claude decides (analysis.json); this script acts, from a fixed allowlist.

  python controller/controller.py apply <run_dir|analysis.json> [--auto]
  python controller/controller.py list
  python controller/controller.py retire <container_name>
  python controller/controller.py reap          # retire decoys past their time-to-live
  python controller/controller.py killswitch    # remove ALL spawned decoys

Safety properties:
  - Only template names in controller/allowlist.json can be started; each has fixed
    image, ports, limits. No text from Claude is ever put on a command line except
    the template name, which is looked up in the allowlist first.
  - Containers are started with an argument list (no shell), dropped capabilities
    and a label so the kill switch can find every one.
  - Every action, including rejections, is appended to lab/logs/events.jsonl.
"""
import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "agent" / "schema.json").read_text(encoding="utf-8"))
EVENT_LOG = ROOT / "lab" / "logs" / "events.jsonl"
LABEL = "deception.spawned=true"


def load_env():
    env = {}
    p = ROOT / ".env"
    for line in p.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


ENV = load_env()


def log_event(event, **fields):
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "event": event, **fields}
    with EVENT_LOG.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[{event}] " + " ".join(f"{k}={v}" for k, v in fields.items()))


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def live_decoys(include_stopped=False):
    out = docker("ps", *(["-a"] if include_stopped else []), "--filter", f"label={LABEL}", "--format",
                 '{{.Names}}\t{{.Label "deception.template"}}\t{{.Label "deception.ip"}}\t{{.Label "deception.expires"}}').stdout
    rows = []
    for line in out.splitlines():
        name, tpl, ip, exp = line.split("\t")
        rows.append({"name": name, "template": tpl, "ip": ip, "expires": int(exp or 0)})
    return rows


def ip_pool():
    first = int(ipaddress.ip_address(ENV["DECOY_IP_FIRST"]))
    last = int(ipaddress.ip_address(ENV["DECOY_IP_LAST"]))
    return [str(ipaddress.ip_address(i)) for i in range(first, last + 1)]


def ip_is_on_host(ip):
    """True if the host owns this address (binding succeeds only for local addresses)."""
    with socket.socket() as s:
        try:
            s.bind((ip, 0))
            return True
        except OSError:
            return False


def pick_ip(used, slot=None):
    """Each decoy type has a fixed slot in the pool, so its address is always the same (the breadcrumbs planted in the
    honeypots can then point at an 'internal server' that is live a few seconds after detection)."""
    if slot is not None:
        ip = ip_pool()[slot]
        return ip if ip not in used and ip_is_on_host(ip) else None
    for ip in ip_pool():
        if ip not in used and ip_is_on_host(ip):
            return ip
    return None


def ensure_network():
    name = ALLOWLIST["network_name"]
    if docker("network", "inspect", name, check=False).returncode != 0:
        docker("network", "create", "--subnet", ENV["DECOY_DOCKER_SUBNET"], name)


def prepare_breadcrumbs():
    subprocess.run([sys.executable, str(ROOT / "lab" / "cowrie_custom" / "build.py")], capture_output=True)


def ensure_image(t):
    if "build_context" in t:
        subprocess.run([sys.executable, str(ROOT / "lab" / "lures" / "render.py")], capture_output=True)   # lure files must exist before the build
        if docker("image", "inspect", t["image"], check=False).returncode != 0:
            docker("build", "-t", t["image"], str(ROOT / t["build_context"]))


def state_mount(template, t):
    """Persistent state per template (e.g. Cowrie SSH host keys), so a respawned decoy keeps the same identity
    and an attacker who reconnects does not see a changed host key."""
    if "state_mount" not in t:
        return []
    d = ROOT / "lab" / "state" / "decoys" / template
    for sub in ("tty", "downloads"):          # an empty mount hides the image's defaults, Cowrie needs these
        (d / sub).mkdir(parents=True, exist_ok=True)
    return ["-v", f"{d}:{t['state_mount']}"]


def make_room(live, protected, ctx):
    """The cap is full but a decoy the attacker's breadcrumbs point at is required: retire the oldest generic one.
    Decoys named by the lure-chain policy are never evicted. Returns the new live list, or None if nothing can go."""
    victims = [d for d in live if d["template"] not in protected]
    if not victims:
        return None
    victim = min(victims, key=lambda d: d["expires"])      # expiry = creation + fixed TTL, so the earliest expiry is the oldest
    retire(victim["name"], reason="made room for a decoy the attacker's breadcrumbs point at")
    return live_decoys()


def spawn(template, ctx, required=False):
    """Start one decoy. Returns True on success. required=True (lure-chain policy decoys) may evict a generic decoy when the cap is full."""
    t = ALLOWLIST["templates"][template]
    live = live_decoys()
    if any(d["template"] == template for d in live):
        log_event("decoy_skipped", template=template, reason="already running", **ctx)
        return False
    if len(live) >= ALLOWLIST["max_live_decoys"]:
        protected = set(ALLOWLIST.get("lure_chain_policy", {}).get("also_spawn", []))
        live = make_room(live, protected, ctx) if required else None
        if live is None:
            log_event("decoy_rejected", template=template, reason="max_live_decoys reached", **ctx)
            return False
    ip = pick_ip({d["ip"] for d in live}, t.get("pool_slot"))
    if not ip:
        log_event("decoy_rejected", template=template, reason="decoy address not available on this host (run lab/add_decoy_ips.ps1) or already in use", **ctx)
        return False

    name = f"decoy-{template.replace('_', '-')}-{ip.split('.')[-1]}"
    logdir = ROOT / "lab" / "logs" / "decoys" / name
    logdir.mkdir(parents=True, exist_ok=True)
    expires = int(time.time()) + ALLOWLIST["ttl_minutes"] * 60

    docker("rm", "-f", name, check=False)  # clear a stopped leftover with the same name
    ensure_network()
    ensure_image(t)
    if t.get("extra_mounts"):
        prepare_breadcrumbs()
    cmd = [
        "run", "-d", "--name", name, "--network", ALLOWLIST["network_name"],
        "-p", f"{ip}:{t['host_port']}:{t['container_port']}",
        "--memory", t["mem"], "--cpus", t["cpus"], "--pids-limit", "200",
        "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
        *[a for c in t.get("extra_caps", []) for a in ("--cap-add", c)],
        "--security-opt", "no-new-privileges",
        "-v", f"{logdir}:{t['log_mount']}",
        *state_mount(template, t),
        "--label", LABEL, "--label", f"deception.template={template}",
        "--label", f"deception.ip={ip}", "--label", f"deception.expires={expires}",
    ]
    for m in t.get("extra_mounts", []):                     # fixed, reviewed content only (never anything from the analysis)
        cmd += ["-v", f"{ROOT / m['host']}:{m['container']}" + (":ro" if m.get("ro") else "")]
    for k, v in t.get("env", {}).items():
        cmd += ["-e", f"{k}={v}"]
    if t.get("show_client_as_host"):                        # decoys that print the client address (MySQL errors) must not show Docker's gateway
        cmd += ["-e", f"DECOY_SHOWN_CLIENT={ENV['HOST_IP']}"]
    if "config_file" in t:
        cmd += ["-v", f"{ROOT / t['config_file']}:/etc/opencanaryd/opencanary.conf:ro"]
    cmd.append(t["image"])
    r = docker(*cmd, check=False)
    if r.returncode != 0:
        log_event("decoy_failed", template=template, ip=ip, error=r.stderr.strip()[:300], **ctx)
        return False
    log_event("decoy_spawned", template=template, name=name, ip=ip, port=t["host_port"],
              expires=datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds"), **ctx)
    return True


def retire(name, reason="manual"):
    live = {d["name"]: d for d in live_decoys(include_stopped=True)}
    if name not in live:
        sys.exit(f"{name} is not a spawned decoy")
    docker("rm", "-f", name)
    log_event("decoy_retired", name=name, template=live[name]["template"], ip=live[name]["ip"], reason=reason)


def apply(path, auto):
    p = Path(path)
    p = p / "analysis.json" if p.is_dir() else p
    result = json.loads(p.read_text(encoding="utf-8"))
    errors = [e.message for e in Draft202012Validator(SCHEMA).iter_errors(result)]
    if errors:
        log_event("analysis_rejected", file=str(p), reason="schema: " + errors[0][:200])
        sys.exit(1)
    run_id = result["run_id"]
    for a in result["analyses"]:
        ctx = {"run_id": run_id, "attacker_ip": a["attacker_ip"], "confidence": a["confidence"]}
        if a["confidence"] < ALLOWLIST["min_confidence"]:
            log_event("analysis_ignored", reason="confidence below threshold", **ctx)
            continue
        wanted = list(a["recommended_decoys"])
        pol = ALLOWLIST.get("lure_chain_policy", {})
        policy_fired = False
        if a["stage"] in pol.get("when_stage", []) or any(t["id"] in pol.get("when_technique", []) for t in a["techniques"]):
            extra = [t for t in pol.get("also_spawn", []) if t not in wanted]
            if extra:   # fixed policy, not the agent's choice: logged so analysts can tell the two apart
                log_event("lure_chain_policy", reason="foothold detected: starting the internal servers its breadcrumbs name", templates=extra, **ctx)
                wanted += extra
                policy_fired = True
        for template in wanted:
            if template not in ALLOWLIST["templates"]:
                log_event("decoy_rejected", template=template[:40], reason="not on allowlist", **ctx)
                continue
            if not auto:
                ans = input(f"Spawn {template} in response to {a['attacker_ip']} "
                            f"(conf {a['confidence']}, {a['stage']})? [y/N] ").strip().lower()
                if ans != "y":
                    log_event("approval_denied", template=template, **ctx)
                    continue
            spawn(template, ctx, required=policy_fired and template in pol.get("also_spawn", []))


def fast_respond(token, **ctx):
    """Fixed, no-AI reaction to a honeytoken use (allowlist `fast_path`): start the decoys the attacker's breadcrumbs point at.
    Only template names from the allowlist policy are used; nothing from the traffic or the token is placed on a command line."""
    pol = ALLOWLIST.get("fast_path", {})
    if token not in pol.get("on_tokens", []):
        return []
    log_event("fast_path_policy", reason=f"honeytoken {token} used: starting the internal servers its breadcrumbs name, before Claude's analysis",
              templates=pol["spawn"], **ctx)
    return [t for t in pol["spawn"] if t in ALLOWLIST["templates"] and spawn(t, {"trigger": f"honeytoken {token}", **ctx}, required=True)]


def fast_respond_read(lure_file, **ctx):
    """Fixed, no-AI reaction to a lure file being opened (allowlist `fast_path.on_reads`): the note names a host, so bring that host up.
    The attacker-supplied path is only compared with the allowlist keys; the keys and template names are what get used and logged."""
    templates = ALLOWLIST.get("fast_path", {}).get("on_reads", {}).get(lure_file, [])
    if not templates:
        return []
    log_event("fast_path_policy", reason=f"lure file {lure_file} opened: starting the server it names, before any credential is used",
              templates=templates, **ctx)
    return [t for t in templates if t in ALLOWLIST["templates"] and spawn(t, {"trigger": f"lure file {lure_file}", **ctx}, required=True)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apply"); a.add_argument("path"); a.add_argument("--auto", action="store_true")
    f = sub.add_parser("fast", help="run the fast-path policy for a honeytoken id (used by the watcher; handy for testing)"); f.add_argument("token")
    sub.add_parser("list")
    r = sub.add_parser("retire"); r.add_argument("name")
    sub.add_parser("reap")
    sub.add_parser("killswitch")
    args = ap.parse_args()

    if args.cmd == "apply":
        apply(args.path, args.auto)
    elif args.cmd == "fast":
        fast_respond(args.token, source="manual")
    elif args.cmd == "list":
        for d in live_decoys():
            print(f"{d['name']}\t{d['template']}\t{d['ip']}\texpires {datetime.fromtimestamp(d['expires'])}")
    elif args.cmd == "retire":
        retire(args.name)
    elif args.cmd == "reap":
        for d in live_decoys():
            if d["expires"] <= time.time():
                retire(d["name"], reason="ttl expired")
    elif args.cmd == "killswitch":
        names = [d["name"] for d in live_decoys(include_stopped=True)]
        for n in names:
            docker("rm", "-f", n)
        log_event("killswitch", removed=names)


if __name__ == "__main__":
    main()

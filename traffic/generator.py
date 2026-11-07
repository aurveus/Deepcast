#!/usr/bin/env python3
"""Benign traffic generator: the "office workstation" of the lab.

Runs on a SEPARATE machine on the lab network (so its packets cross VMnet1 and are captured),
never on the attacker VM. Standard library only. Creates normal-looking activity on randomized
timers and writes every synthetic event to a ground-truth log (JSON lines), which the evaluation
uses to count false positives.

  python3 generator.py --target 10.10.10.1            # run until Ctrl+C
  python3 generator.py --target 10.10.10.1 --scale 0.05 --duration 60   # fast test run

Settings come from flags or environment (GEN_TARGET, GEN_WEB_PORT, GEN_SSH_PORT, GEN_SSH_USER,
GEN_SSH_PASSWORD, GEN_DNS_SERVER, GEN_LOG).
"""
import argparse
import json
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]
# Pages a staff member would plausibly open on the admin panel (never scans, never guesses paths).
WEB_VISITS = [["/", "/login"], ["/login"], ["/admin/"], ["/login", "/admin/"]]
DNS_NAMES = ["intranet.lab.local", "fileserver.lab.local", "mail.lab.local", "wiki.lab.local"]
SSH_COMMANDS = ["uptime", "ls", "whoami", "hostname", "pwd"]
# What an administrator types in a real session (all plain read-only commands; no scanners, no downloads).
ADMIN_COMMANDS = ["ls", "ls -la", "pwd", "whoami", "id", "uname -a", "uptime", "hostname", "cat /etc/hostname", "cat /etc/os-release",
                  "w", "ps aux", "date", "echo done", "history", "env", "cd /var/log", "ls /var/log", "ls /etc", "ls /home"]
# Mean seconds between events of each type (randomized, exponential gaps).
MEAN_INTERVAL = {"web_visit": 25, "ping": 60, "dns_query": 40, "ssh_login": 240,
                 "ssh_admin": 600, "ssh_typo": 900, "monitor_probe": 20, "port_check": 150, "web_typo_login": 900}

stop = False


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def own_ip(target):
    """The address this machine uses toward the target (UDP connect sends no packet)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 9))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


class GroundTruth:
    def __init__(self, path, src):
        self.path, self.src = Path(path), src
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, etype, dst, ok, **detail):
        rec = {"ts": utc_now(), "type": etype, "benign": True, "src": self.src, "dst": dst, "ok": ok, "detail": detail}
        with self.path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"{rec['ts']} {etype} -> {dst} ok={ok} {detail}", flush=True)


def do_web_visit(gt, a):
    ua = random.choice(USER_AGENTS)
    for path in random.choice(WEB_VISITS):
        url = f"http://{a.target}:{a.web_port}{path}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": ua}), timeout=5) as r:
                gt.write("web_request", f"{a.target}:{a.web_port}", True, path=path, status=r.status)
        except urllib.error.HTTPError as e:   # 403/404 pages still count as a normal visit
            gt.write("web_request", f"{a.target}:{a.web_port}", True, path=path, status=e.code)
        except OSError as e:
            gt.write("web_request", f"{a.target}:{a.web_port}", False, path=path, error=str(e)[:80])
        time.sleep(random.uniform(0.5, 3) * a.scale)   # a person reads the page before the next click


def do_ping(gt, a):
    flag = "-n" if os.name == "nt" else "-c"
    r = subprocess.run(["ping", flag, "1", a.target], capture_output=True, text=True, timeout=15)
    gt.write("ping", a.target, r.returncode == 0)


def dns_query(name):
    """Minimal DNS A-record query packet."""
    header = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def do_dns(gt, a):
    name = random.choice(DNS_NAMES)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        try:
            s.sendto(dns_query(name), (a.dns_server, 53))
            s.recvfrom(512)
            gt.write("dns_query", f"{a.dns_server}:53", True, name=name, answered=True)
        except OSError:   # the isolated lab has no resolver, so a timeout is the normal outcome
            gt.write("dns_query", f"{a.dns_server}:53", True, name=name, answered=False)


def do_ssh(gt, a):
    """A staff member logs in with their own account, runs one command, logs out."""
    ssh = shutil.which("ssh")
    if not ssh or not a.ssh_password:
        gt.write("ssh_login", f"{a.target}:{a.ssh_port}", False, error="ssh client or password missing")
        return
    cmd = random.choice(SSH_COMMANDS)
    with tempfile.TemporaryDirectory() as d:
        askpass = Path(d) / "askpass.sh"
        askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$GEN_SSH_PASSWORD"\n')
        askpass.chmod(0o700)
        env = {**os.environ, "SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "GEN_SSH_PASSWORD": a.ssh_password}
        env.pop("DISPLAY", None)
        r = subprocess.run(
            [ssh, "-p", str(a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=8",
             "-o", "LogLevel=ERROR", f"{a.ssh_user}@{a.target}", cmd],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    gt.write("ssh_login", f"{a.target}:{a.ssh_port}", r.returncode == 0, user=a.ssh_user, command=cmd, returncode=r.returncode)


def ssh_base(a, extra=()):
    return [shutil.which("ssh"), "-p", str(a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=8",
            "-o", "LogLevel=ERROR", *extra, f"{a.ssh_user}@{a.target}"]


def askpass_env(d, password):
    askpass = Path(d) / "askpass.sh"
    askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$GEN_SSH_PASSWORD"\n')
    askpass.chmod(0o700)
    env = {**os.environ, "SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "GEN_SSH_PASSWORD": password}
    env.pop("DISPLAY", None)
    return env


def admin_plan(style):
    """[(command, seconds to wait before typing it)] for an administrator's session.
    paste: a script pasted into the terminal (many commands in a couple of seconds). typed: a person typing and reading output."""
    if style == "paste":
        return [(random.choice(ADMIN_COMMANDS), random.uniform(0.05, 0.3)) for _ in range(random.randint(8, 14))]
    return [(random.choice(ADMIN_COMMANDS), random.uniform(1.5, 6)) for _ in range(random.randint(4, 10))]


def do_ssh_admin(gt, a):
    """A staff member logs in with their own account and works in an interactive session (the legitimate look-alike of an attacker's shell)."""
    if not shutil.which("ssh") or not a.ssh_password:
        gt.write("ssh_admin", f"{a.target}:{a.ssh_port}", False, error="ssh client or password missing")
        return
    style = random.choice(["paste", "typed"])
    plan = admin_plan(style)
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.Popen(ssh_base(a, ["-tt"]), env=askpass_env(d, a.ssh_password), stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        sent = 0
        try:
            time.sleep(2.5)                                   # login and banner
            for cmd, pause in plan:
                time.sleep(pause * (a.scale if style == "typed" else 1))
                p.stdin.write(cmd + "\n")
                p.stdin.flush()
                sent += 1
            time.sleep(0.5)
            p.stdin.write("exit\n")
            p.stdin.flush()
        except OSError:
            pass
        try:
            rc = p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = -1
    gt.write("ssh_admin", f"{a.target}:{a.ssh_port}", rc == 0, user=a.ssh_user, style=style, commands=sent, returncode=rc)


def do_ssh_typo(gt, a):
    """Mistyped password first (a failed login), then the right one."""
    if not shutil.which("ssh") or not a.ssh_password:
        gt.write("ssh_typo", f"{a.target}:{a.ssh_port}", False, error="ssh client or password missing")
        return
    results = []
    for password in (a.ssh_password[:-1] + "x", a.ssh_password):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([*ssh_base(a), "whoami"], env=askpass_env(d, password), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        results.append(r.returncode)
        time.sleep(random.uniform(2, 6) * a.scale)
    gt.write("ssh_typo", f"{a.target}:{a.ssh_port}", results[-1] == 0, user=a.ssh_user, returncodes=results)


def do_monitor_probe(gt, a):
    """An uptime monitor: a light HEAD request to the front page."""
    url = f"http://{a.target}:{a.web_port}/"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "uptime-monitor/2.1"}), timeout=5) as r:
            gt.write("monitor_probe", f"{a.target}:{a.web_port}", True, status=r.status)
    except urllib.error.HTTPError as e:
        gt.write("monitor_probe", f"{a.target}:{a.web_port}", True, status=e.code)
    except OSError as e:
        gt.write("monitor_probe", f"{a.target}:{a.web_port}", False, error=str(e)[:80])


def do_port_check(gt, a):
    """A monitoring job that checks that the usual services answer: a handful of connections to different ports within seconds."""
    ports = [a.ssh_port, a.web_port, 4445, 21, 3306]
    random.shuffle(ports)
    up = []
    for port in ports:
        try:
            with socket.create_connection((a.target, port), timeout=2):
                up.append(port)
        except OSError:
            pass
        time.sleep(random.uniform(0.05, 0.4))
    gt.write("port_check", a.target, True, checked=len(ports), answering=sorted(up))


def do_web_typo_login(gt, a):
    """Someone types a wrong password into the web admin login form."""
    url = f"http://{a.target}:{a.web_port}/login"
    data = urllib.parse.urlencode({"username": a.ssh_user, "password": "typo" + str(random.randint(100, 999))}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers={"User-Agent": random.choice(USER_AGENTS)}), timeout=5) as r:
            gt.write("web_typo_login", f"{a.target}:{a.web_port}", True, status=r.status)
    except urllib.error.HTTPError as e:
        gt.write("web_typo_login", f"{a.target}:{a.web_port}", True, status=e.code)
    except OSError as e:
        gt.write("web_typo_login", f"{a.target}:{a.web_port}", False, error=str(e)[:80])


ACTIONS = {"web_visit": do_web_visit, "ping": do_ping, "dns_query": do_dns, "ssh_login": do_ssh, "ssh_admin": do_ssh_admin,
           "ssh_typo": do_ssh_typo, "monitor_probe": do_monitor_probe, "port_check": do_port_check, "web_typo_login": do_web_typo_login}


def main():
    env = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default=env("GEN_TARGET"), required=not env("GEN_TARGET"), help="honeypot host IP")
    ap.add_argument("--web-port", type=int, default=int(env("GEN_WEB_PORT", 8080)))
    ap.add_argument("--ssh-port", type=int, default=int(env("GEN_SSH_PORT", 2222)))
    ap.add_argument("--ssh-user", default=env("GEN_SSH_USER", "jsmith"))
    ap.add_argument("--ssh-password", default=env("GEN_SSH_PASSWORD", ""))
    ap.add_argument("--dns-server", default=env("GEN_DNS_SERVER"), help="defaults to the target")
    ap.add_argument("--log", default=env("GEN_LOG", str(Path(__file__).resolve().parent / "logs" / "ground_truth.jsonl")))
    ap.add_argument("--scale", type=float, default=1.0, help="multiply all waiting times (0.05 = 20x faster, for tests)")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = run until stopped)")
    ap.add_argument("--seed", type=int)
    a = ap.parse_args()
    a.dns_server = a.dns_server or a.target
    if a.seed is not None:
        random.seed(a.seed)

    def halt(*_):
        global stop
        stop = True
    signal.signal(signal.SIGINT, halt)
    signal.signal(signal.SIGTERM, halt)

    gt = GroundTruth(a.log, own_ip(a.target))
    gt.write("generator_started", a.target, True, scale=a.scale)
    end = time.time() + a.duration if a.duration else None
    gap = lambda t: max(2 * a.scale, random.expovariate(1 / (MEAN_INTERVAL[t] * a.scale)))
    due = {t: time.time() + random.uniform(1, 8) * a.scale for t in ACTIONS}   # stagger the first events
    while not stop and not (end and time.time() >= end):
        t = min(due, key=due.get)
        time.sleep(max(0, min(due[t] - time.time(), 1)))   # wake at least once a second to notice stop
        if time.time() < due[t]:
            continue
        try:
            ACTIONS[t](gt, a)
        except Exception as e:   # one failed action must never stop the generator
            gt.write(t, a.target, False, error=f"{type(e).__name__}: {str(e)[:80]}")
        due[t] = time.time() + gap(t)
    gt.write("generator_stopped", a.target, True)


if __name__ == "__main__":
    main()

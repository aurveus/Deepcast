# Running Deepcast

Reference for building the lab and running each part. For what the project is, start with the [README](../README.md); for what each script does, see [CODE_MAP.md](CODE_MAP.md).

## Prerequisites
- Windows host with Git Bash, Docker Desktop (WSL 2), Python 3.11 (`pip install flask jsonschema`), Wireshark with tshark and Npcap, VMware Workstation, Edge (prints the PDF reports).
- Claude Code CLI (`claude`), logged in, plus the **Wireshark MCP** server (`wireshark-mcp install`; `claude mcp list` must show it). The analysis runs `claude -p` with read-only Wireshark tools.
- A Kali VM (attacker) and a small Debian/Ubuntu "workstation" VM (benign traffic), both on VMnet1.
- `cp .env.example .env` and adjust. Every address, port and path lives there.

## Lab network (VMware VMnet1, host-only)
- Virtual Network Editor: VMnet1 = Host-only, subnet `10.10.10.0/24`, DHCP off, host virtual adapter connected.
- Windows adapter "VMware Network Adapter VMnet1" at `10.10.10.1/24`. Kali: static `10.10.10.10/24`. Workstation: static `10.10.10.30/24`.
- `tshark -D` lists the VMnet1 adapter; put its `\Device\NPF_{...}` ID in `.env` as `CAPTURE_IFACE`.
- Once, in an administrator PowerShell, add the decoy address pool: `.\lab\add_decoy_ips.ps1`.
- `bash lab/prewarm.sh` pulls the pinned images (Cowrie 3.1.2, OpenCanary 0.9.10) and builds the decoy images so the first decoy does not wait on a build.
- If Kali cannot reach a published port, allow inbound from `10.10.10.0/24` in Windows Firewall.
- Verify: `bash tests.sh` (no lab needed) says ALL PASSED; from Kali `nc -zv 10.10.10.1 2222 8080 21 4445`.

**Images are pinned, not `latest`:** newer Cowrie releases dropped a module `lab/cowrie_custom/build.py` reads. To move to a newer Cowrie, change the pins in `lab/docker-compose.yml`, `controller/allowlist.json` and `lab/cowrie_custom/build.py` together, then re-run `tests.sh` and `prewarm.sh`.

## Start / stop
Requires Docker Desktop running and the VMnet1 adapter up (start VMware first; otherwise the port bind to `HOST_IP` fails).

```bash
lab/up.sh      # builds and starts the lab (Cowrie on HOST_IP:COWRIE_SSH_PORT, fake web admin panel on HOST_IP:WEB_PORT)
lab/down.sh    # stops it; logs in lab/logs are kept
```

### Verify Cowrie
From Kali: `nc -vz 10.10.10.1 2222`, then `ssh -p 2222 admin@10.10.10.1` with any password.
On the host, events appear in `lab/logs/cowrie/cowrie.json` (one JSON object per line): `cowrie.session.connect`, `cowrie.login.success|failed`, `cowrie.command.input`.

### Known limitation: source IP in honeypot logs
Docker Desktop (Windows) relays published ports, so Cowrie logs `src_ip` as the Docker gateway (`.1` of `DOCKER_LAB_SUBNET`, i.e. `172.30.0.1` by default), not Kali (`10.10.10.10`). The subnet is pinned in `.env` so this is the same on every machine; if `docker compose up` reports "Pool overlaps", pick another range there. The true source IP is in the tshark capture on VMnet1; correlate honeypot events with the pcap by timestamp.

### Network exposure
Ports are published on `HOST_IP` (VMnet1) only, never on Wi-Fi/Ethernet, so the lab stays isolated.

### Persistent honeypot identity
Cowrie's state (SSH host keys, tty recordings, downloads, sensor ID) is bind-mounted from `lab/state/cowrie/` (git-ignored: it holds private keys and attacker downloads). Each machine generates its own keys on first start and reuses them on every restart, so SSH clients do not see "HOST IDENTIFICATION HAS CHANGED". `up.sh` creates the `tty/` and `downloads/` subfolders Cowrie needs (an empty mount hides the image's defaults).
The first time you connect from Kali after a fresh start on a new machine, accept the key once. To reset deliberately, delete `lab/state/cowrie` and run `ssh-keygen -R '[10.10.10.1]:2222'` on Kali.

### Fake web admin panel (`lab/webadmin`)
Flask app behind gunicorn, presented as Apache. It never authenticates anyone and logs every request (including submitted usernames/passwords on `POST /login`) as JSON lines to `lab/logs/web/web.json`. `robots.txt` advertises `/admin/` and `/backup/` as lures; `/backup/` and `/server-status` return 403.
Verify from Kali:
```bash
curl -i http://10.10.10.1:8080/login
curl http://10.10.10.1:8080/robots.txt
curl -i -d 'username=admin&password=hunter2' http://10.10.10.1:8080/login   # 401
```
Same Docker-relay caveat as Cowrie: `src_ip` in `web.json` is the Docker gateway; use the pcap for the real attacker IP.

### OpenCanary: FTP and telnet (`lab/opencanary`)
Always-on fake FTP (21, vsFTPd banner) and telnet (23) services. Config in `lab/opencanary/opencanary.conf`; events (connections and every username/password tried) go to `lab/logs/opencanary/opencanary.json`, one JSON object per line. Log types: 2000/2001 FTP login/connection, 6001/6002 telnet login/connection. Same Docker-relay caveat for the source IP.
Verify from Kali: `ftp 10.10.10.1` (any login) and `telnet 10.10.10.1`, then check the log.

### Why SMB is not on port 445
Windows' own SMB server already listens on 445 (and 139) on the host, so a container cannot publish them. Decision: the SMB decoy is published on `HOST_IP:SMB_PORT` (4445). Do not stop the Windows file-sharing service.

### SMB decoy (`lab/smbdecoy`)
Impacket `SimpleSMBServer` (SMB2) in a container, one read-only share `DOCS` with two harmless files. Impacket accepts any credentials, so attackers can browse the share; that is deliberate bait. Events go to `lab/logs/smb/smb.json`: `smb.connect`, `smb.auth` (domain/user), `smb.auth_result`, plus raw lines. The raw line after a login contains the client's NTLMv2 response (hash material), so treat this log as sensitive.
Verify from Kali: `smbclient -L //10.10.10.1 -p 4445 -N` and `smbclient //10.10.10.1/DOCS -p 4445 -U test` (any password).

### No-AI fast reactions (watcher)

The watcher reacts without waiting for Claude in two fixed cases, both from the allowlist (`controller/allowlist.json`, `fast_path`) and logged as `fast_path_policy`: the SSH honeytoken HT-001 used (starts `db_decoy` and `smb_decoy`), and the lure note `it-notes.txt` opened on the SMB share (`on_reads`, starts `db_decoy`, because the note names that host and it would otherwise be a closed port). The SMB decoy logs every file open (`smb.open`); lure files are listed in `lab/lures/honeytokens.json` (`lure_files`). Rule hits from `detect/stream.py` (`fast_rule_hit`) are detection and logging only.

## Packet capture (`capture/capture.sh`)
Rolling tshark capture of the VMnet1 interface. Run it in its own terminal tab, after `lab/up.sh` and before attacking; Ctrl+C stops it.
```bash
capture/capture.sh
```
- The interface comes from `CAPTURE_IFACE` in `.env` (the NPF device ID from `tshark -D`, not the list number, which changes between runs). Optional: `CAPTURE_DIR` (default `capture/pcaps`) and `CAPTURE_FILTER` (BPF).
- Files are named `lab_<n>_<timestamp>.pcap`: a new one every 5 minutes or 50 MB, newest 48 kept (older ones are deleted automatically, so copy a run you want to keep).
- `*.pcap` is git-ignored: captures are sensitive.
- Host-to-itself traffic (e.g. curl to 10.10.10.1 from the Windows host) does not cross VMnet1 and is not captured; generate test traffic from Kali.
- If nmap on Kali aborts with a `massdns.cc` assertion, add `-n` (skip DNS).

## Analysis agent (`agent/`)
`python agent/analyze.py capture/runs/<run>` runs headless Claude Code (`claude -p`) with read-only Wireshark MCP tools and writes `<run>/analysis.json`, validated against `agent/schema.json` and cross-checked with the pcap (the attacker IP must really appear as a pcap source). Honeypot log text is sanitized and treated as untrusted data. See `agent/README.md` for the output format. Requires Claude Code logged in and the `wireshark-mcp` server connected (`claude mcp list`).

## Decoy controller (`controller/`)
Claude decides, the controller acts. It only starts templates from `controller/allowlist.json` (fixed image, port, limits).
```bash
python controller/controller.py apply capture/runs/<run>          # asks y/N before each spawn
python controller/controller.py apply capture/runs/<run> --auto   # no prompt
python controller/controller.py list | reap | retire <name>
python controller/controller.py killswitch                        # removes ALL spawned decoys
```
Rules: confidence below 0.5 is ignored, max 3 live decoys, one per template, 30-minute time-to-live (`reap` retires expired ones). Every action goes to `lab/logs/events.jsonl`. Spawned decoys appear as new hosts at `DECOY_IP_FIRST..DECOY_IP_LAST` (10.10.10.20-.29) on standard ports (SSH 22, FTP 21, DB 3306, web 80; SMB stays 4445 because Windows owns 445).

### One-time manual step per machine
Add the decoy IPs to the VMnet1 host adapter. In an **administrator** PowerShell:
```powershell
.\lab\add_decoy_ips.ps1
```
If Kali cannot reach a decoy IP, check that Windows Firewall rules cover those addresses too.

Lure-chain decoys have priority: when a foothold is detected and the live-decoy cap is full, the controller retires the oldest generic decoy (logged as `decoy_retired`, reason "made room ...") so the database and SMB servers named in the attacker's breadcrumbs always exist.

## Dashboard (`dashboard/`)
Local, read-only web UI: overview, live events, attack sessions, MITRE ATT&CK matrix, decoys, pipeline diagram, replay of saved runs, evaluation table.
```bash
python dashboard/app.py      # then open http://127.0.0.1:5000
```
Needs only Flask (`pip install flask`). It reads `lab/logs/events.jsonl`, each run's `analysis.json` (from `capture/runs/` and, if present, a committed `replays/` folder) and the live decoy list from Docker. It listens on localhost only, has no endpoint that changes the lab, and loads nothing from the internet. Attacker-controlled text is only rendered as plain text (and a Content-Security-Policy blocks scripts). The Replay tab plays back stored results only: no Docker, no Claude.

### Severity and trap contact (`agent/severity.py`)
An incident is **Critical** when its source used a planted honeytoken or reached a decoy that is only reachable through a lure (nobody legitimate can do either); otherwise High / Medium / Low follow the stage and confidence as before. The incident report computes it and saves `severity.json` next to `incident_report.html`; the Catches tab shows it, with the honeytoken and decoy contact, and falls back to the stage rule for catches whose report predates this. Regenerate an old report with `python report/incident_report.py <run_dir>`.

### Catches and Catch log filters
Catches: search, technique filter, time range; technique chips and the MITRE tab link to each other ("Show catches with T…"). Catch log: time range next to the existing event-type filter and search. Both tabs mark rows that arrived since the page was last open with a "new" pill (kept in the browser's local storage; blank if storage is blocked).

### Pyramid of Pain (`agent/pyramid.py`)
David Bianco's ranking of how much it hurts an attacker when you deny an indicator (hashes trivial, IPs easy, domains simple, network/host artifacts annoying, tools challenging, TTPs tough). One fixed table feeds two places: the MITRE tab's "Pyramid of Pain" card (what the analyses recorded at each level, plus a "Pain to the attacker" note on every technique) and a "Pain if denied" column in each incident report's indicator table. Tool names come only from user agents/banners and can be spoofed; the report says so.

### Attacker commands in the dashboard (`dashboard/commands.py`)
What the attacker typed on the SSH honeypot and on SSH decoys is shown in three places, read from the Cowrie logs (nothing new is collected):
- **Overview, "Attacker activity":** the last 15 minutes, newest first, with a pulse dot while someone is typing.
- **Catches:** each card has a closed "Commands typed (N · sessions)" fold, one block per session. The technique chips next to a command are buttons that open the **MITRE ATT&CK** tab on that technique (a chip is plain text if the analysis did not report that technique).
- **MITRE ATT&CK:** each technique has a "Commands behind it" list (matched by the fixed rule table in `agent/transcripts.py`, so it is a hint, not a verdict).

Long sessions stay readable: identical commands collapse into one row with a count (`whoami ×4`), a session lists at most 60 distinct rows (the rest is counted), a card shows 8 rows with "Show all" and a scrolling box, and a catch lists its 6 newest sessions. Sessions of the benign generator account (`GEN_SSH_USER` in `.env`) are left out. A catch's commands are the sessions inside its capture window (modification times of its pcap files), so a catch needs its saved `logs/` folder to show any. Self-test: `python dashboard/commands.py --selftest`.

## Benign traffic ("workstation" VM, `traffic/`)
The generator makes normal activity (admin-panel page loads, an occasional SSH login with a normal account, DNS lookups, pings) on randomized timers, so the lab looks lived-in and the evaluation can measure false positives. It must run on its **own VM on VMnet1** (not on Kali, not on the host: host-to-self traffic never crosses VMnet1 and would not be captured).

### One-time VM setup (by hand: not in a file)
1. VMware: new Debian 12 (or Ubuntu Server) VM, 1 vCPU, 1 GB RAM, 8 GB disk, no desktop, install the SSH server and `python3`. Network adapter: the same VMnet1 custom network as Kali.
2. Static IP `10.10.10.30/24` (no gateway). Check `ping 10.10.10.1`. Take a snapshot `workstation-clean`.
3. In `.env` set `WORKSTATION_USER` (a user with sudo on the VM) and keep `WORKSTATION_IP`, `GEN_SSH_USER`, `GEN_SSH_PASSWORD` (a lab-only account; Cowrie accepts it).
4. On the host: `traffic/deploy.sh` (asks for the VM password). It installs a systemd service, so the generator starts by itself on every boot.

### Ground truth
Every synthetic event is logged on the VM to `/var/log/workstation-sim/ground_truth.jsonl` (time, type, source, destination, outcome). Copy it to the host with `traffic/pull_ground_truth.sh` (-> `traffic/logs/ground_truth_vm.jsonl`, git-ignored). Any detector alarm about the workstation's IP in a benign-only run is a false alarm.

Quick test without the VM (host to host, not captured): `python traffic/generator.py --target 10.10.10.1 --ssh-password <GEN_SSH_PASSWORD> --scale 0.05 --duration 45`.

## Replay mode (`replays/`, `replay.sh`)
`replays/` holds three small, committed sample runs (`portscan_demo`, `sshbrute_demo`, `webprobe_demo`): a trimmed pcap (about 1.2 MB in total, force-added although `*.pcap` is ignored) plus Claude's saved output for it. They make the demo repeatable on any machine, including a fresh clone.
```bash
./replay.sh level2 sshbrute_demo        # offline fallback: saved Claude output -> validation -> controller (no Claude, no internet)
./replay.sh level1 sshbrute_demo        # re-analyze the bundled pcap with Claude again, then the controller
```
Both add events to the event log, so the dashboard shows the replay live. The dashboard's Replay tab plays the same recordings. On a machine with real runs, the samples are excluded from the counters; on a fresh clone with no real runs they fill the dashboard so the demo is not empty.

## Incident reports (`report/incident_report.py`)
Every investigated run gets an incident report (HTML + PDF) written next to its `analysis.json`; `run_loop.sh` does this automatically as its last step, and the dashboard's Attack sessions cards link to it.
```bash
python report/incident_report.py capture/runs/<run>      # or replays/<name>
```
Contents: summary, timeline, attacker profile, proof, MITRE ATT&CK table, response taken (decoys and what happened on them), recommendations, IOCs, and the SHA-256 of each capture file. The profile and proof numbers are **recomputed from the pcap with tshark**, not copied from Claude's text. Honeypot log excerpts are attached only when the pcap shows the attacker talking to that service (the logs only show the Docker gateway). Only findings at or above the controller's confidence threshold become incidents. The PDF is made with Edge's headless print (no install; skipped with a message if Edge is not found). Attacker-controlled text is HTML-escaped and the dashboard serves the report with a strict content-security policy.

**Typed commands and themes.** Commands appear as separate bubbles (identical ones share a bubble with a count, at most 40 distinct per source, the rest counted). The HTML report has a light and a dark theme. Opened from a dashboard "Incident report" link it follows the dashboard's Theme button (`?theme=light|dark`); opened directly it follows the browser's light/dark setting. The PDF is always light.

## Continuous mode (`agent/watcher.py`)
Always-on monitoring: no manual `run_loop.sh`. Run it in its own terminal (lab up, VMs on):
```bash
python agent/watcher.py              # Ctrl+C to stop; --window 30, --no-controller (analyze + report only)
python agent/watcher.py --offline <pcap> [...]   # replay saved pcaps through the same logic (testing, demo without VMs)
```
Flow: tshark writes 30 s windows to `capture/live/` -> cheap per-source counts -> **triage gate** (5+ distinct ports, 60+ connections to one port, 6+ SSH connections or 60+ HTTP requests over the last 3 minutes) opens an incident for that source -> `agent/analyze.py` -> controller (`--auto`: allowlist, confidence threshold and decoy limits still apply) -> `report/incident_report.py`. While the source stays active the incident is re-analyzed every 2 minutes; it closes after 90 s of silence, and the same source returning within 10 minutes (`WATCH_MERGE`, seconds) continues the same incident (slow scans do this; evaluation campaigns set it to 60 so every scenario is its own incident). A "benign" verdict from Claude closes the incident and silences that source for 5 minutes. The gate is deliberately only a trigger to save Claude calls; the decision is Claude's. Thresholds and timings can be overridden with `WATCH_*` / `GATE_*` values in `.env`. The dashboard shows a "Continuous monitoring" banner and the incidents in Attack sessions as they appear. Do not run it together with `run_loop.sh` (both use the capture interface and the status file).

## Automated attacks (host -> Kali over SSH)
Lets the host start attack scenarios on Kali without typing passwords. One-time setup, by hand (not in a file):
1. **Kali window:** `sudo systemctl enable --now ssh` (check `systemctl is-active ssh` and `ip -br addr` shows `KALI_IP`).
2. **Git Bash on the host:** create a lab-only key: `ssh-keygen -t ed25519 -f ~/.ssh/lab_kali -C "deception-lab host to kali" -N ""`.
3. **Git Bash on the host:** install it on Kali, restricted to the host's lab address (asks for Kali's password once):
```bash
echo "from=\"10.10.10.1\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding $(cat ~/.ssh/lab_kali.pub)" | ssh kali@10.10.10.10 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```
   (use your `HOST_IP`, `KALI_USER`, `KALI_IP`).
4. Set `KALI_USER` and `KALI_SSH_KEY` in `.env` and verify with `bash attacks/check_kali.sh` (login without password, tools present: nmap, hydra, nikto, gobuster, curl, ssh, sshpass, smbclient, mysql).

The key never goes in the repo. It is limited to logins from the host's lab address; narrowing it to a fixed list of scenarios (`command=` in `authorized_keys`) is still to do.

Run the lure-chain simulator (see `attacks/README.md`, section 5): `bash attacks/run_lure_chain.sh [--fast]`. Its timestamped log is copied back to `attacks/logs/` (git-ignored) as attack ground truth.

Run scenarios from Git Bash (same key, no password). The long unattended run is sized with `--runs` (per scenario) and `--idle`; `--runs 5 --idle 3` schedules 48 events and takes hours, `--runs 2 --idle 2 --gap-min 60 --gap-max 120` schedules 20 and takes about an hour:
```bash
bash attacks/run_lure_chain.sh --fast --deep                      # about 90 s
python eval/run_campaign.py --runs 2 --idle 2 --gap-min 60 --gap-max 120 --seed 42
```
On Windows, a bare `bash` can resolve to `C:\Windows\System32\bash.exe` (the WSL launcher, which exists after `wsl --install` and fails without a distribution: "execvpe(/bin/bash) failed"). `eval/run_campaign.py` and `eval/run_dual.py` therefore call Git's `bash.exe` explicitly. The first time you connect to the Workstation VM, accept its host key (`ssh-keyscan -t ed25519 10.10.10.30 >> ~/.ssh/known_hosts`) so `traffic/pull_ground_truth.sh` can run.

## Spoofed scan sources (`agent/aliases.py`)
A scanner can add forged decoy source addresses to look like many scanners. On one Ethernet segment those packets still carry the scanner's MAC address and only ever send unanswered SYNs, so the watcher folds them into the real address (event `spoofed_source_merged`), and the analysis reports one attacker with the evasion noted. Not possible behind a router, where every source shares the router's MAC.

## Unattended evaluation (`eval/run_campaign.py`)
One command runs a whole campaign: Kali plays a random schedule of attacks (port scan, slow scan, SSH brute force, web probing, directory brute force, stealth scan, lure chain) plus benign-only windows, while the workstation VM generates normal traffic. The watcher, Claude and the controller react live, and `eval/campaign_eval.py` then scores every scenario against the attacker's own log (time to detect counts from the real attack start). Lab up, VMs on, `bash attacks/check_kali.sh` OK, then:
```bash
python eval/run_campaign.py --runs 3 --idle 2     # full campaign (about 8-10 min per scenario)
python eval/run_campaign.py --resume --runs 3     # run only what is missing or was lost to a Claude outage / merged incident
```
Details and scoring rules: `attacks/README.md` (sections 6-7) and `eval/README.md`. Results show on the dashboard's Evaluation tab.

## Self-tests (no lab needed)
`bash tests.sh` compiles every script, runs the module self-checks (campaign scoring, session transcripts, attacker memory) and checks the configuration invariants (allowlist matches the schema, scenario names agree across scripts). Run it after any change and on a fresh clone before the demo.


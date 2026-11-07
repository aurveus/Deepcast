# Attack scenarios (lab only)

All attacks run from the Kali VM (`KALI_IP`) against the host (`HOST_IP`, 10.10.10.1) on the isolated VMnet1 network. Never aim these at anything else.

Wordlists: `attacks/wordlists/users.txt`, `passwords.txt` (10 generic entries each). Copy them to Kali (e.g. `scp` to the user's home, or paste with `nano`).

## Run pattern (repeat per scenario)
1. Host, tab 1: `lab/up.sh` (once).
2. Host, tab 2: `capture/capture.sh` (starts a fresh capture; the rolling folder must be empty, so run `save_run.sh` after every scenario).
3. Kali: run the attack below.
4. Host: Ctrl+C the capture, then `capture/save_run.sh <name>`.
   Output goes to `capture/runs/<name>_<timestamp>/` (git-ignored, sensitive).

Check first from Kali: `ping -c 2 10.10.10.1` and `nc -zv 10.10.10.1 2222 8080 21 4445`. If ports fail, check Windows Firewall inbound rules for VMnet1.

## 1. Port scan (`portscan`)
```bash
nmap -n -sS -p- --min-rate 1000 10.10.10.1
nmap -n -sV -p 21,23,2222,4445,8080 10.10.10.1
```
Always use `-n` (nmap aborts on DNS here). Expect: thousands of SYNs from one IP in the pcap; connections to the five honeypot ports in their logs.

## 2. SSH brute force (`sshbrute`)
```bash
hydra -L users.txt -P passwords.txt -s 2222 -t 4 ssh://10.10.10.1
```
Expect: many Cowrie `cowrie.login.failed`, possibly `cowrie.login.success`; many short TCP sessions to 2222 in the pcap.

## 3. Web probing (`webprobe`)
```bash
nikto -h http://10.10.10.1:8080
curl -i http://10.10.10.1:8080/admin/
curl -i http://10.10.10.1:8080/backup/
```
Expect: hundreds of requests in `lab/logs/web/web.json`; HTTP traffic in the pcap.

## 4. Slow port scan (`slowscan`), hard case for the evaluation
```bash
nmap -n -sS -T1 --scan-delay 5s -p 21,22,23,80,443,445,2222,3306,4445,8080 10.10.10.1
```
Few ports, one probe every 5 s (about 1 minute). A simple "many ports in X seconds" rule should miss it; the point is to see whether Claude, reading the whole capture, still calls it reconnaissance. Save with `capture/save_run.sh slowscan`. Expect the pcap to be tiny (about 20 SYNs).

## 5. Lure chain (`lure_chain_sim.sh`, run from the host with `run_lure_chain.sh`)
A human-paced attacker that follows the planted breadcrumbs instead of dumping tools. LAB ONLY: it refuses any target or discovered host outside `LAB_SUBNET`.
```bash
bash attacks/run_lure_chain.sh          # realistic pauses between steps
bash attacks/run_lure_chain.sh --fast   # short pauses, for repeat runs
```
Stages (each logged with a UTC timestamp; skipped stages say why): 1 service scan -> 2 `robots.txt` -> `/backup/` -> `config.bak` (HT-001) -> 3 SSH login with it -> 4 read `/etc/hosts`, `.bash_history`, `arp -a` for the internal hosts -> 5 SMB share on `fs-backup-01`, read `it-notes.txt` (HT-002) -> 6 MySQL login on `db-prod-01` (the fake MySQL denies it but logs it).
Expect: honeytoken events, an incident (initial access, T1552.001 + T1078), the lure-chain policy spawning the SSH, database and SMB decoys, and a report with "Decoy interaction". Needs the watcher running (`python agent/watcher.py`) and the host/Kali SSH setup from the docs/RUNNING.md.

### Deeper variant (`--deep`, campaign scenario `traverse`)
`bash attacks/run_lure_chain.sh --fast --deep` adds a longer SSH session (one command per line, human pauses) and tries the found login on the other services. Live-tested on 2026-10-21: Claude's report listed the 19 typed commands and the techniques they map to.

## 5b. Directory brute force (`dirbrute`)
```bash
gobuster dir -u http://10.10.10.1:8080 -w /usr/share/wordlists/dirb/common.txt -q -t 10 --timeout 5s -b 404
```
Standard wordlist shipped with Kali. Expect: hundreds of requests for common paths in `lab/logs/web/web.json`, similar signal to `webprobe` but from a different tool.

## 5c. Stealth scan (`stealthscan`)
```bash
nmap -n -sS -f -D 10.10.10.201,10.10.10.202,10.10.10.203,ME -p 21,22,23,80,443,445,2222,3306,4445,8080 10.10.10.1
```
nmap's own evasion flags: `-f` fragments probe packets and `-D` mixes in decoy source addresses. The decoys are fixed unused addresses inside the lab range (never random Internet addresses). The platform recognises them as spoofed (they share the scanner's Ethernet address, `agent/aliases.py`) and reports one attacker; the scorer also ignores them as attacker-side. Point is to see whether Claude still attributes the scan to the real source when the traffic looks less like a textbook scan.
**Needs raw sockets on Kali.** Kali's nmap already has the `cap_net_raw` capability (checked with `getcap $(which nmap)`), so no sudo is needed. If a machine lacks it, the campaign refuses to schedule `stealthscan` (exit 3) rather than silently running nothing; fix with `sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)` once on Kali.

## Verify a saved run
- Packet count and top talkers: `tshark -r <pcap> -q -z conv,tcp` (or ask Claude via the Wireshark MCP).
- Real attacker IP is in the pcap (10.10.10.10); honeypot logs show the Docker gateway (see docs/RUNNING.md).

## 6. Unattended campaign (`campaign.sh`, run from the host with `run_campaign.sh`)
Plays a seeded random schedule of the scenarios above (`portscan`, `slowscan`, `sshbrute`, `webprobe`, `lure`, `dirbrute`, `stealthscan`) plus benign-only `idle` windows, with random gaps (default 120-300 s). Only these fixed names exist; no free-form commands. It refuses targets outside `LAB_PREFIX` and writes its own ground truth on Kali (`campaign.jsonl`: scenario, real start/end in UTC), which the host runner copies to `attacks/logs/campaign_<time>.jsonl`.
```bash
bash attacks/run_campaign.sh --runs 1 --idle 1 --gap-min 30 --gap-max 60   # quick smoke test
bash attacks/run_campaign.sh --runs 5 --idle 3 --seed 42                    # full campaign (about 1-1.5 h)
```
Without root on Kali, the SYN scans fall back to connect scans (`-sT`). For a campaign that also scores itself, use the next section.

## 7. One-command evaluation (`python eval/run_campaign.py`)
Starts the watcher if none runs, runs the Kali campaign, removes spawned decoys after each incident closes (so each scenario is scored independently), waits for the last incident, stops the watcher, and runs `eval/campaign_eval.py`. Results: `eval/results/campaign.{json,md}`, shown in the dashboard's Evaluation tab. Options: `--runs`, `--idle`, `--seed`, `--only`, `--gap-min`, `--gap-max`.
Scoring rules (also in the docstring of `eval/campaign_eval.py`): a detection counts for the scenario it follows; time to detect is measured from the real attack start; any trigger on another IP, or on Kali during an `idle` window, is a false alarm. Check the scoring logic offline with `python eval/campaign_eval.py --selftest`.

### Resume (do not repeat what already worked)
```bash
python eval/run_campaign.py --resume --dry-run   # show what is still missing
python eval/run_campaign.py --resume             # run only the missing scenarios and the ones lost to a Claude outage
```
`--resume` reads every `attacks/logs/campaign_*.jsonl`, keeps the scenarios that have a valid result (a genuine miss is a result), and re-runs those that were lost to a Claude usage-limit outage or merged into another incident, plus anything not yet run (target: `--runs 5 --idle 3`). Gaps default to 300-420 s so incidents close between scenarios. All logs are scored together into `eval/results/campaign.{json,md}`.


## Manual sessions (a person at the keyboard)
Scripted scenarios give repeatable numbers; a human session is the unscripted test and the best demo. It is never used for learning (corpus split: always holdout).
1. Start the watcher with `WATCH_MERGE=60 python agent/watcher.py` (so each session is its own incident) and, for the fast path, `python detect/stream.py`.
2. On the host: `bash attacks/manual.sh start "short label"`, then explore the lab from the Kali VM like a curious outsider (what is there is described defensively in `lab/TRAPS.md`), then `bash attacks/manual.sh stop`. Wait about 3 minutes between sessions. A ready-to-follow command list for a full lure-chain session is in `attacks/MANUAL_SESSION.md`.
3. Score: `python eval/campaign_eval.py attacks/logs/campaign_manual_<date>.jsonl --out manual` (writes `eval/results/campaign_manual.*`; the campaign results are not touched). The incident reports and the dashboard show what the platform made of the session.

## Two attackers at once (lab only)
`python eval/run_dual.py` runs `attacks/dual_attacker.sh` on Kali (copied by `attacks/run_dual.sh`): attacker A, Kali's own address, runs a port scan and an SSH brute force; attacker B, a second address on the same interface (`KALI_IP2` in `.env`), follows the web lure and logs in with the planted credential in the middle of A's traffic. The second address must exist on Kali first (once, by hand, it does not survive a reboot): `sudo ip addr add 10.10.10.11/24 dev eth0`. Source binding uses each tool's own option (`curl --interface`, `ssh -b`); nothing the honeypots return can steer the script (it only talks to the target, lab range checked). The run waits for both incidents to close, removes the spawned decoys and scores itself (`eval/dual_eval.py`, results in `eval/results/dual_<time>.*`; method and results in `eval/README.md`).

## The one-minute live demo (lab only)
`python eval/demo_minute.py` (needs the lab, the watcher and Kali; see `report/demo_plan.md`): removes the spawned decoys, runs `attacks/demo_attack.sh` on Kali (about 8 s: robots.txt, the forgotten /backup/ folder, the SSH account in config.bak, the server's hosts file, the database account in the SMB note) and prints the platform's reactions live, timed from the start of the attack: the honeytoken use seen, the fast path, the decoys coming up about a second later (no AI involved), the streaming rule. It then opens a finished incident report (`--no-open` to skip). Every address the attacker touches is checked against the lab range.

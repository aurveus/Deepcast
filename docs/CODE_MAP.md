# Code map: what each script does

A guided tour of the repository. For the big picture, see the [README](../README.md); to run things, see [RUNNING.md](RUNNING.md).

## How the key scripts connect

```
 attacker traffic
       │
       ▼
 capture/capture.sh ──► tshark pcaps ──┬──► detect/stream.py ──► rule engine ──► alerts       (fast, per packet)
                                       │
                                       └──► agent/watcher.py ──► triage gate ──► incident
                                                 │  ▲                               │
              honeytoken thread ◄────────────────┘  │ agent/attribution.py          ▼
        (agent/honeytokens.py, 1 s fast path)       │ (who really did it)     agent/analyze.py ──► Claude + Wireshark MCP
                      │                                                              │
                      ▼                                                              ▼
              controller/controller.py ◄────────── validated analysis.json (agent/schema.json)
                      │
                      ▼
              lab/logs/events.jsonl ──► dashboard/app.py          report/incident_report.py ──► HTML + PDF
```

The benign `traffic/generator.py` runs on its own VM alongside all of this and writes the **ground truth** that tells us which traffic was legitimate.

---

## `agent/` — the AI analyst and everything around it

| File | What it does |
|---|---|
| **`analyze.py`** | Analyzes one saved run. Starts headless Claude (`claude -p`) with read-only Wireshark MCP tools, gives it exact per-source counts, sanitized honeypot logs and attacker transcripts, and asks for JSON. The answer is written to `analysis.json` only if it passes the schema and the pcap cross-check (the attacker IP must really appear as a source). Retries once if Claude calls an obvious scan "clean". |
| **`watcher.py`** | Continuous monitoring, the heart of the live system. Captures 30-second windows, counts per source, applies the triage gate, opens and merges incidents, calls `analyze.py`, hands results to the controller and triggers the report. Also runs the honeytoken tail on its own thread so the 1-second fast path never waits on an analysis. |
| `schema.json` | The contract for Claude's output: attacker IP, stage, ATT&CK techniques, evidence, confidence, and a decoy enum limited to allowed template names. |
| `prompt.md` | The analysis instructions given to Claude. |
| `honeytokens.py` | Watches honeypot logs for use of the planted fake credentials (`lab/lures/honeytokens.json`) and for reads of lure files. |
| `attribution.py` | Works out which real source address caused a honeypot log line, by matching connection times against the pcap (Docker hides the real address in logs). |
| `aliases.py` | Unmasks scans disguised with spoofed decoy source addresses (same Ethernet address, only unanswered SYNs) and merges them into one attacker. |
| `transcripts.py` | Rebuilds SSH sessions from Cowrie logs (what was typed, downloaded) and maps commands to ATT&CK techniques with a fixed rule table. |
| `attacker_memory.py` | What the platform already knows about a source IP from earlier incidents, given to the analysis as context. |
| `severity.py` | Incident severity (Low to Critical). Critical means proof of movement: a honeytoken was used or a lure-only decoy was reached. |
| `pyramid.py` | David Bianco's Pyramid of Pain: how much it hurts an attacker when each kind of indicator is denied. Feeds the dashboard and reports. |
| `believability.py` | Lints the fake SSH server for contradictions an attacker could notice, and harvests "this looks fake" signals from sessions. |

## `detect/` — fast streaming rules and the learning loop

| File | What it does |
|---|---|
| **`stream.py`** | The live fast path. tshark streams packets, the rule engine decides per packet, alerts go to the event log. Can run on saved pcaps for testing. |
| `events.py` | Turns packets into a small structural event stream (new connection, HTTP request, ...) that rules run on. |
| `engine.py` | The streaming rule engine: feed events one at a time, get alerts immediately. |
| `rules.py` | The declarative rule format and its validator: no code, no regular expressions, no executable text. |
| `rules/baseline.json`, `rules/promoted.json` | Hand-written rules, and rules the learning loop promoted. |
| `traps.json` | Which addresses and ports are traps (any contact is suspicious). |
| `hpevents.py` | Turns what happens inside an SSH session into countable events for rules. |
| `corpus.py` | Builds the labeled replay corpus (attack runs and benign traffic, split into development / validation / holdout). |
| `replay.py` | Replays a rule set over the corpus and scores it. |
| `evidence.py` | Builds the numbers-only evidence shown to the rule proposer (never attacker-typed text). |
| `propose.py` | Asks Claude (all tools disabled) for one detection rule from that evidence. |
| `gate.py` | The promotion gate: a proposed rule is promoted only if it catches the attack and causes no false alarms; supports rollback. |
| `learn.py` | The learning loop: finds attacks the rules miss, asks for a rule, lets the gate decide. |
| `crossval.py` | Leave-one-attack-type-out test: does a rule learned from other attacks catch a type it never saw? |
| `injection_test.py` | Prompt-injection and poisoned-proposal tests for the rule generator. |
| `matrix.py`, `results.md` | The results table: baseline vs learned rules vs the Claude path, per attack type. |
| `demo.py` | Offline before/after demo of the learning loop. |

## `controller/` — the only thing that acts

| File | What it does |
|---|---|
| **`controller.py`** | Validates Claude's JSON against the allowlist, enforces limits (confidence floor, max live decoys, one per template, time-to-live), starts and retires decoy containers, supports human approval and the kill switch, logs every action. |
| `allowlist.json` | The fixed list of decoy templates (image, port, address slot, resource limits) plus the fast-path and lure-chain policies. Nothing outside it can ever be started. |
| `emit_event.py` | Appends a progress event to the event log so the dashboard can show a run as it happens. |

## `lab/` — the traps

| Path | What it does |
|---|---|
| `docker-compose.yml`, `up.sh`, `down.sh`, `prewarm.sh` | Start and stop the lab with one command; pre-pull and pre-build images. |
| `cowrie_custom/` | The believable fake Linux server: `build.py` generates the filesystem and breadcrumbs, `lived_in.py` the staff accounts, history and logs, `commands/find.py` a bounded `find`. |
| `webadmin/` | Fake web admin panel (Flask behind gunicorn, looks like Apache); logs every request and login attempt. |
| `smbdecoy/` | SMB file-share decoy built on Impacket; logs connections, logins and which file was opened. |
| `opencanary/` | FTP and Telnet traps and the MySQL look-alike that logs every login and refuses it. |
| `lures/` | `honeytokens.json` (the registry of fake credentials) and `render.py`, which plants them in the lure files from templates. |
| `add_decoy_ips.ps1` | One-time script that adds the decoy address pool to the lab network adapter. |
| [`TRAPS.md`](../lab/TRAPS.md) | The trap map: what each trap is, what it records, where you see it. |

## `capture/`

| File | What it does |
|---|---|
| `capture.sh` | Rolling tshark capture of the lab interface. |
| `save_run.sh` | Saves a run (pcaps plus honeypot logs) into a folder for analysis. |

## `traffic/` — benign baseline and ground truth

| File | What it does |
|---|---|
| **`generator.py`** | The "office workstation": normal-looking activity on randomized timers (admin-panel page loads, an occasional SSH login with a normal account, DNS lookups, pings). Runs on its **own VM** so its packets cross the lab network and are captured. Every synthetic event is written to a **ground-truth log** (time, type, source, destination, outcome), which is how false alarms are measured: any alarm about the workstation is wrong. |
| `deploy.sh`, `workstation.service` | Install the generator on the VM as a systemd service so it starts at boot. |
| `pull_ground_truth.sh` | Copies the ground-truth log from the VM to the host. |

## `attacks/` — lab-only attack scenarios (run on the Kali VM)

| File | What it does |
|---|---|
| `campaign.sh`, `run_campaign.sh` | A randomized schedule of attack scenarios; writes the attacker's own log of real start and end times, the ground truth for scoring. |
| `lure_chain_sim.sh`, `run_lure_chain.sh` | A human-paced attacker that follows the whole lure chain. |
| `demo_attack.sh` | The roughly 20-second attacker used for the live demo. |
| `dual_attacker.sh`, `run_dual.sh` | Two attackers at once from two source addresses. |
| `manual.sh` | Marks the start and end of a hands-on session so it can be scored like a scripted scenario. |
| `check_kali.sh` | Checks the host can reach Kali and the attack tools are installed. |
| `wordlists/` | Small user and password lists. |

## `dashboard/` — the live view

| File | What it does |
|---|---|
| **`app.py`** | Local, read-only Flask dashboard (Overview, Catch log, Catches, MITRE ATT&CK, Decoys, Pipeline, Replay, Evaluation). Reads the event log and analyses; has no endpoint that changes the lab; served with a strict content-security policy. |
| `attack_info.py` | Plain-language explanations and links for the ATT&CK techniques reported. |
| `commands.py` | What attackers typed in the SSH honeypot, per catch and live. |
| `static/` | The front end (HTML, JS, CSS, fonts, logo), loading nothing from the internet. |

## `report/`

| File | What it does |
|---|---|
| `incident_report.py` | One HTML and PDF report per incident: summary, merged timeline, attacker profile and proof recomputed from the pcap with tshark (not copied from Claude's text), ATT&CK table, response taken, recommendations, indicators, SHA-256 of the evidence. Attacker text is HTML-escaped. |

## `eval/` — measuring it honestly

| File | What it does |
|---|---|
| **`run_campaign.py`** | One command: plays a whole unattended campaign from Kali against the live platform and scores it. |
| `campaign_eval.py` | Scores each scenario against the attacker's own log: detected, time to detect, decoy deployed, false alarm. |
| `rule_detector.py`, `rules_on_campaign.py` | The simple fixed-threshold rule baseline and its comparison with Claude. |
| `evaluate.py` | Scores the rule baseline and Claude on every saved run. |
| `run_dual.py`, `dual_eval.py` | The two-attacker test and its seven checks. |
| `reanalyze.py` | Re-analyzes stored incidents with the current prompt to check a change. |
| `demo_minute.py` | The live demo: an attacker follows the lure while the platform's reactions are printed and timed. |
| `results/` | The recorded results. [`README.md`](../eval/README.md) has the method and limits. |

## `scripts/` and root files

| File | What it does |
|---|---|
| `scripts/run_loop.sh` | One manual cycle: capture, attack, save, analyze, controller, report. |
| `scripts/replay.sh` | Replays a bundled run offline (level 2, saved Claude output) or re-analyzes its pcap (level 1). |
| `scripts/tests.sh` | Self-tests that need no lab: compiles every script, runs the module self-checks, and checks configuration invariants. |
| `.env.example` | Every address, port and path; copy to `.env`. |

## Data folders

| Folder | What it holds |
|---|---|
| `replays/` | Three small recorded runs (port scan, SSH brute force, web probing): a trimmed pcap, Claude's saved output and the incident report. |
| `corpus/manifest.json` | Labels, splits and pcap hashes of the replay corpus (the large event files stay local). |

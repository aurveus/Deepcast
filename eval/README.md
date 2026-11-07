# Evaluation: rule-based detector vs Claude agent

Files: `rule_detector.py` (baseline, 3 fixed-threshold rules over the pcap), `evaluate.py` (scores every saved run, writes `results/results.json` and `results/results.md`).

## Protocol (repeat each scenario several times)
1. Host: `lab/up.sh`, workstation VM running (benign traffic active).
2. Host: `./run_loop.sh <scenario> --auto --fresh`, then attack from Kali, then press Enter. Scenario names: `portscan`, `slowscan`, `sshbrute`, `webprobe`, and `benign` (no attack: just wait 3-5 minutes).
3. Attack commands are in `attacks/README.md`.
4. `python eval/rule_detector.py capture/runs/<run>` is run automatically by `evaluate.py` for runs without `rules.json`.
5. `python eval/evaluate.py` after the batch; the dashboard's Evaluation tab shows the table.

## Metric definitions
- **Detected**: a finding that names `KALI_IP`.
- **False alarm**: a finding naming any other IP, or any finding in a `benign` run.
- **Time to detect**: rules = capture seconds from the attacker's first packet to the alert. Claude = seconds spent analyzing the finished capture. They are different quantities (a streaming rule vs a batch analysis) and must be reported as such.
- **Decoy deployed**: a `decoy_spawned` event exists for the run (`--fresh` removes decoys left by earlier runs).

## Rules and why they exist
| Rule | Threshold |
|---|---|
| port_scan | 15 distinct destination ports from one source within 10 s |
| ssh_bruteforce | 10 new connections to port 22/2222 from one source within 30 s |
| web_probe | 50 HTTP requests from one source within 30 s |
The `slowscan` scenario (1 probe every 5 s) is built to fall under these thresholds.

## Honest limits
Few runs per scenario, one attacker, lab traffic only. Claude's results can vary between runs; the several runs per scenario are there to show that.

## Unattended campaign evaluation (live pipeline)
Run with `python eval/run_campaign.py` (or `--resume`, see `attacks/README.md`). Unlike the per-capture protocol above, this scores the real continuous pipeline (watcher, Claude, controller) against an attack log written by the attacker itself on Kali.

How a scenario is scored (`eval/campaign_eval.py`):
- **Ground truth:** `attacks/logs/campaign_*.jsonl` holds each scenario's real start and end time (UTC), written on Kali.
- **Detected:** a Claude report (confidence >= 0.5, the controller's own threshold) naming the attacker inside the scenario's time window. Because the watcher can merge back-to-back scenarios into one incident and Claude reports cumulatively, a report is credited to a scenario only when it shows a technique that scenario produces and the incident had not shown it yet.
- **Time to detect:** detection time minus the real attack start (not the capture start). The "gate" time is when the cheap triage trigger woke the agent.
- **Decoy deployed:** a `decoy_spawned` event follows that report.
- **False alarm:** a trigger or report naming any other source IP, or naming Kali during a benign-only (idle) window.
- **Excluded, not counted as misses:** scenarios during a Claude outage (usage limit, `watch_error`), and "merged" scenarios whose technique was already reported earlier in the same incident (detection happened, attribution impossible). The table shows how many were excluded; longer gaps between scenarios (300-420 s) keep incidents separate.

Limits to state honestly: one attacker host, one lab, a few runs per scenario, and Claude's output varies between runs.

## Results of the unattended campaign (2026-10-20)
7 attack types, 5 valid runs each, plus 7 benign-only windows, all run unattended from Kali against the live pipeline (watcher, Claude, controller). Source: `attacks/logs/campaign_*.jsonl`, scored by `eval/campaign_eval.py`; raw per-run rows in `eval/results/campaign.json`.

| Scenario | Runs | Excluded (outage / merged) | Gate triggered | Claude detected | Median time to detect (s) | Median gate (s) | Decoy deployed | False alarms |
|---|---|---|---|---|---|---|---|---|
| Port scan | 5 | 4 | 4/5 | 5/5 | 42.1 | 21.8 | 5/5 | 0 |
| Slow port scan | 5 | 5 | 5/5 | 5/5 | 74.8 | 54.8 | 5/5 | 0 |
| SSH brute force | 5 | 5 | 5/5 | 5/5 | 40.6 | 17.8 | 5/5 | 0 |
| Web probing | 5 | 5 | 4/5 | 5/5 | 48.2 | 23.7 | 5/5 | 0 |
| Lure chain | 5 | 6 | 5/5 | 5/5 | 38.7 | 13.5 | 5/5 | 0 |
| Directory brute force | 5 | 0 | 5/5 | 5/5 | 41.8 | 23.5 | 5/5 | 0 |
| Stealth scan (fragmented/decoy) | 5 | 0 | 5/5 | 5/5 | 37.4 | 15.4 | 4/5 | 0 |
| Benign only (idle) | 7 | 3 | n/a | n/a | – | – | n/a | 0 |

Time to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: 8.

What the numbers say:
- **Detection:** every one of the 35 valid attack runs was confirmed by Claude (confidence >= 0.5), including the slow scan (a rate rule misses it), the stealth scan (fragmented probes with spoofed decoy sources) and the multi-step lure chain.
- **Speed:** median time from the real attack start to Claude's confirmed detection was 37 to 75 s depending on the attack; the slow scan is slowest because it only reveals itself over about a minute.
- **Response:** a decoy was deployed in 34 of 35 runs. In the other one the controller's own limits applied (max 3 live decoys, already-running templates), which is by design.
- **False alarms:** 0 in the 7 valid benign-only windows with the workstation VM generating normal traffic.
- **Stealth scan:** the three spoofed decoy addresses are recognised by their shared Ethernet address and reported as one attacker (`agent/aliases.py`).

Excluded runs (the "Excluded" column) are not hidden: they were lost to a Claude usage-limit outage on 2026-10-18, or merged into another incident by the watcher's old 10-minute merge window (fixed: campaigns use `WATCH_MERGE=60`), or listed with a reason in `eval/campaign_exclude.txt` (two scenarios from that early period). The first 2026-10-18 campaign was stopped part-way for these reasons; `--resume` re-ran what was missing.

Limits, stated plainly: one attacker host and one lab network; standard tools only (nmap, hydra, nikto, gobuster, curl, ssh and a scripted lure chain); 5 runs per scenario is a small sample; Claude's output varies between runs; time to detect includes the platform's 30 s capture window and a triage gate, so it is a real-system latency, not model speed. The rule-based baseline was scored on the earlier per-capture runs only (`eval/results/results.md`), not on this campaign.

## Rules vs Claude on the campaign scenarios (2026-10-21)
`python eval/rules_on_campaign.py` runs the three fixed-threshold rules of `eval/rule_detector.py` over the capture windows the watcher saved for each scored scenario, using the same attack start times as Claude's scoring.

| Scenario | Runs | Rules detected | Rules that fired | Right rule for the attack | Rules median time to detect (s) | Claude detected | Claude median time to detect (s) |
|---|---|---|---|---|---|---|---|
| Port scan | 5 | 5/5 | port_scan | 5/5 | 0.8 | 5/5 | 42.1 |
| Slow port scan | 5 | 5/5 | ssh_bruteforce | 0/5 | 55.6 | 5/5 | 74.8 |
| SSH brute force | 5 | 5/5 | ssh_bruteforce, web_probe | 5/5 | 1.2 | 5/5 | 40.6 |
| Web probing | 5 | 5/5 | port_scan, web_probe | 5/5 | 1.3 | 5/5 | 48.2 |
| Lure chain | 5 | 0/5 | – | n/a (no rule for it) | – | 5/5 | 38.7 |
| Directory brute force | 5 | 5/5 | web_probe | 5/5 | 1.0 | 5/5 | 41.8 |
| Stealth scan (fragmented/decoy) | 5 | 0/5 | – | 0/5 | – | 5/5 | 37.4 |

Reading it honestly:
- **Where rules win:** speed. On loud, single-source attacks (port scan, SSH brute force, web probing, directory brute force) a streaming threshold fires about 1 s after the attack starts, while the Claude pipeline takes about 40 s (30 s capture window plus triage plus analysis). If all you need is a quick alert on those, a rule is enough.
- **Where rules fail:** the lure chain and the stealth scan (10 ports, under the 15-port threshold) were never flagged (0/5 each). Rules have no concept of "someone used a planted credential" or of a scan hidden among spoofed sources. Claude detected all five of each.
- **A lucky hit:** the slow scan tripped the SSH brute-force rule (5/5) only because nmap's retries sent 10 connection attempts to port 22 within 10 s; right source, wrong label, and 55 s after the start. Claude called it reconnaissance.
- **Beyond detection:** the rules produce an alert with a name; Claude also describes what happened (lures followed, commands typed, escalation), maps ATT&CK techniques, and recommends decoys that the controller deploys.
- **Limits:** the watcher only saves captures for incidents it opened, so benign false alarms of the rules are not measured here (see the per-capture benign runs above); the rules look at one source address at a time.

## Update 2026-10-21: deep traversal and overlapping attacks
Two harder scenarios were added and run (3 valid runs each, same unattended method):
- **Deep trap traversal (`traverse`)**: the lure chain plus a one-command-at-a-time walk through the SSH honeypot and credential reuse on FTP and the file share. Claude's reports cite the typed commands and map them to techniques.
- **Overlapping attacks (`overlap`)**: a port scan, an SSH brute force and a directory brute force running at the same time from one host. It is scored strictly: it only counts as detected when the reports together cover all three behaviors (`OVERLAP_FAMILIES` in `eval/campaign_eval.py`).

Full campaign table now:

| Scenario | Runs | Excluded (outage / merged) | Gate triggered | Claude detected | Median time to detect (s) | Median gate (s) | Decoy deployed | False alarms |
|---|---|---|---|---|---|---|---|---|
| Port scan | 5 | 4 | 4/5 | 5/5 | 42.1 | 21.8 | 5/5 | 0 |
| Slow port scan | 5 | 5 | 5/5 | 5/5 | 74.8 | 54.8 | 5/5 | 0 |
| SSH brute force | 5 | 5 | 5/5 | 5/5 | 40.6 | 17.8 | 5/5 | 0 |
| Web probing | 5 | 5 | 4/5 | 5/5 | 48.2 | 23.7 | 5/5 | 0 |
| Lure chain | 5 | 6 | 5/5 | 5/5 | 38.7 | 13.5 | 5/5 | 0 |
| Directory brute force | 5 | 0 | 5/5 | 5/5 | 41.8 | 23.5 | 5/5 | 0 |
| Stealth scan (fragmented/decoy) | 5 | 0 | 5/5 | 5/5 | 37.4 | 15.4 | 4/5 | 0 |
| Deep trap traversal | 3 | 0 | 3/3 | 3/3 | 27.5 | 8.1 | 3/3 | 0 |
| Overlapping attacks (3 at once) | 3 | 0 | 3/3 | 3/3 | 45.0 | 19.1 | 3/3 | 0 |
| Benign only (idle) | 7 | 3 | n/a | n/a | – | – | n/a | 0 |

Time to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: 15.

Rules vs Claude, refreshed (`python eval/rules_on_campaign.py`):

| Scenario | Runs | Rules detected | Rules that fired | Right rule for the attack | Rules median time to detect (s) | Claude detected | Claude median time to detect (s) |
|---|---|---|---|---|---|---|---|
| Port scan | 5 | 5/5 | port_scan | 5/5 | 0.8 | 5/5 | 42.1 |
| Slow port scan | 5 | 5/5 | ssh_bruteforce | 0/5 | 55.6 | 5/5 | 74.8 |
| SSH brute force | 5 | 5/5 | ssh_bruteforce, web_probe | 5/5 | 1.2 | 5/5 | 40.6 |
| Web probing | 5 | 5/5 | port_scan, web_probe | 5/5 | 1.3 | 5/5 | 48.2 |
| Lure chain | 5 | 0/5 | – | n/a (no rule for it) | – | 5/5 | 38.7 |
| Directory brute force | 5 | 5/5 | web_probe | 5/5 | 1.0 | 5/5 | 41.8 |
| Stealth scan (fragmented/decoy) | 5 | 0/5 | – | 0/5 | – | 5/5 | 37.4 |
| Deep trap traversal | 3 | 0/3 | – | n/a (no rule for it) | – | 3/3 | 27.5 |
| Overlapping attacks (3 at once) | 3 | 3/3 | port_scan, ssh_bruteforce, web_probe | n/a (no rule for it) | 0.8 | 3/3 | 45.0 |

Result: 3/3 deep traversals and 3/3 overlapping runs were detected; in every overlap run the reports covered all three simultaneous behaviors. The fixed rules also fire on the overlap (loud, simple patterns, in about 1 s) but never see the deep traversal (0/3), where a planted credential is used and the activity is spread across services. Only 3 runs each, so treat these two rows as indicative.


## Update 2026-10-23: false alarms on realistic benign traffic, and the fix
The earlier "0 false alarms in 9 benign windows" was measured with a very quiet traffic generator (a page load, a ping, one SSH command every few minutes). After the generator was extended (admin SSH sessions with 4-14 commands, mistyped passwords, uptime probes, a 5-port service check every few minutes) and left recording for about 5 hours, the continuous Claude path produced **3 false confirmations in about 45 workstation incidents** (confidence 0.6-0.7, stage "discovery"; the first spawned 4 decoys), and the triage gate fired about every 5 minutes (a Claude call each time). Causes found:
1. the gate threshold of 5 distinct ports equals the number of ports the service check touches (replayed over the corpus: 160 gate firings at 5 ports, 0 at 6 or more, no attack sample missed at any of 5/6/8/10);
2. attacker memory counted every gate trigger as an earlier "incident", so a routine source looked like a repeat offender, and Claude cited that history ("33 earlier incidents");
3. discovery-type commands from a normal login are indistinguishable by command alone from an attacker's, and the prompt had no notion of routine service checks or admin sessions.
Changes: `GATE_PORTS` 5 -> 8; attacker memory counts only confirmed findings, lists routine incidents as routine and honors `verdict_retracted` events (the 4 false verdicts were retracted by the operator); prompt rule 12 (routine service checks and administration, with explicit overrides: unanswered probes, guessing, traps, honeytokens, credential hunting, pivoting).
Check (`python eval/reanalyze.py`, results in `eval/results/reanalysis.json`): the stored incidents were re-analyzed with the new prompt and memory facts on copies. **Benign: 3 of 35 incidents falsely confirmed before, 0 after. Attacks: 9 of 9 attack types still detected** (one stored incident per type, same confidence range as before). Limits: the same incidents were used to find the problems, so this is a regression check, not a held-out result; one benign folder could not be re-analyzed (run-id naming quirk); a fresh live run is the real test and is running now (watcher restarted with the new gate). The trade-off to state in the report: an attacker who logs in with a legitimate account and only runs ordinary commands is harder to catch, because the prompt now needs context signs (probes, guessing, traps, credential hunting, pivoting) rather than the commands themselves.

## Update 2026-10-24: live confirmation campaign (new gate, prompt rule 12), and three problems it exposed
**Run:** `python eval/run_campaign.py --runs 2 --idle 3` from Kali against the live lab with the watcher and controller: 21 scenarios (9 attack types x 2 + 3 idle windows of 3 min), `GATE_PORTS` 8, prompt rule 12, the extended benign generator running on the workstation the whole time. The analysis model is whatever the `claude` CLI defaults to on the host (`claude-sonnet-5-5` when checked); the model is not stored with each analysis, which is a limit for reproducibility. Results: `eval/results/campaign.{json,md}` (also `campaign_2026-10-24.*`).

| Scenario | Runs | Gate | Claude detected | Median time to detect (s) | Decoy | False alarms |
|---|---|---|---|---|---|---|
| Port scan | 1 (+1 merged) | 1/1 | 1/1 | 51.1 | 1/1 | 0 |
| Slow port scan | 2 | 2/2 | 2/2 | 87.5 | 2/2 | 0 |
| SSH brute force | 2 | 2/2 | 2/2 | 94.0 | 2/2 | 0 |
| Web probing | 2 | 2/2 | 2/2 | 32.5 | 2/2 | 0 |
| Lure chain | 2 | 1/2 | 2/2 | 66.0 | 2/2 | 2 (see 1) |
| Directory brute force | 1 (+1 merged) | 1/1 | 1/1 | 137.3 | 1/1 | 0 |
| Stealth scan | 2 | 2/2 | 2/2 | 71.0 | 2/2 | 1 (see 3) |
| Deep trap traversal | 2 | 2/2 | 2/2 | 69.7 | 2/2 | 2 (see 1) |
| Overlapping attacks | 2 | 1/2 | 2/2 | 33.6 | 2/2 | 0 |
| Benign only (idle) | 3 | n/a | n/a | n/a | n/a | 0 (see 2) |

Every attack type was detected and got a decoy. The 8 false alarms the first scoring showed had three different causes:
1. **Honeytoken misattributed to the benign workstation (4 of 8, a real bug).** The honeypot logs only show the Docker gateway, so `agent/attribution.py` finds the real source from the pcap. Two defects: the watcher attributed a use before the capture window holding the attacker's connection had closed, so the only visible candidate was the workstation's routine SSH connection 2.96 s earlier (inside the 3 s tolerance); and the MySQL fallback took the latest earlier connection to port 3306 without checking the destination (the workstation's service check goes to the host address, the real login to the decoy), after a strict timestamp bound dropped the real SYN that arrived 30 ms after its own log line. Consequence: Claude confirmed an attack by the workstation twice (T1552.001/T1078). Fix: attribute only after the hit's window (plus 1 s skew) has closed, match the destination address, allow 1 s skew. Replaying both hits from the archived pcaps with the watcher's windowing: old logic gave the workstation both times, new logic gives Kali; both parts of the fix are needed. **Live re-run of lure and traverse (2 runs each, `campaign_2026-10-24_attrfix.*`): 9 of 9 honeytoken uses attributed to Kali, no confirmed detection of the workstation, detection 2/2 each.**
2. **Scoring artifact (3 of 8, idle windows).** Claude's follow-up report and decoys for the previous Kali attack landed a few seconds after the next (idle) window opened, and the scorer booked them there. `eval/campaign_eval.py` now books such follow-ups to the scenario their incident started in when the clock has reached an idle window; idle false alarms 3 -> 0, nothing else in the table changed (selftest added; the pre-fix scoring is `campaign_2026-10-24_scorer_v1.*`). This is a scoring correction made after seeing the results, stated here for that reason.
3. **Workstation SSH-count gate trigger (1 of 8, still present).** Admin SSH sessions open 6-7 connections within the lookback and trip the SSH-count gate; Claude called each such incident clean (`watch_triage_clean`), so no decoy and no confirmation, but the scorer counts any trigger naming another address. The re-run showed one per scenario for the same reason (7 SSH connections). Not changed: raising the SSH threshold would risk missing real brute force.

What to claim: with realistic benign traffic, all attack types detected live; the workstation was falsely *confirmed* only through the misattribution bug (fixed, 0 in the re-run); it still *triggers* the gate occasionally, and Claude dismisses it. The full-campaign rows above still contain the recorded misattribution false alarms (only lure and traverse were re-run). The long single idle window (25 min) was not run.

## Update 2026-10-24 (later): post-fix confirmation runs, SSH gate threshold, pinned model
After the three fixes above, everything was re-run live with the final code (`GATE_SSH` 10, pinned model, `detect/stream.py` started by the watcher): lure and traverse (2 runs each, the attribution re-run), then the other seven attack types (2 runs each, `campaign_2026-10-24_final_b.*`), then one 25-minute benign-only window (`campaign_2026-10-24_idle25.*`). Combined scoring of the three logs: `campaign_postfix_2026-10-24.{json,md}`.

| Scenario | Runs | Gate | Claude detected | Median time to detect (s) | Decoy | False alarms |
|---|---|---|---|---|---|---|
| Port scan | 2 | 2/2 | 2/2 | 34.0 | 2/2 | 0 |
| Slow port scan | 2 | 2/2 | 2/2 | 118.5 | 2/2 | 0 |
| SSH brute force | 2 | 2/2 | 2/2 | 50.8 | 2/2 | 0 |
| Web probing | 2 | 2/2 | 2/2 | 94.6 | 2/2 | 0 |
| Lure chain | 2 | 2/2 | 2/2 | 42.5 | 2/2 | 1 (old gate, see below) |
| Directory brute force | 1 (+1 merged) | 1/1 | 1/1 | 36.4 | 1/1 | 0 |
| Stealth scan | 1 (+1 merged) | 1/1 | 1/1 | 31.9 | 1/1 | 0 |
| Deep trap traversal | 2 | 2/2 | 2/2 | 43.8 | 2/2 | 1 (old gate, see below) |
| Overlapping attacks | 2 | 1/2 | 2/2 | 58.5 | 1/2 | 0 |
| Benign only (idle) | 2 (+2 excluded) | n/a | n/a | n/a | n/a | 0 |

- **Every attack type was detected live with a decoy deployed** (overlap: all three behaviors reported in both runs; the gate fired on 1 of 2 because the second run joined an open incident).
- **The SSH-count gate trigger on the workstation is gone.** The two false alarms left (lure, traverse) are from the lure/traverse re-run, which still ran with `GATE_SSH` 6 ("7 SSH connections" on the workstation, dismissed by Claude both times). The seven other types and the idle windows ran with `GATE_SSH` 10: **zero gate triggers, detections or decoys naming the workstation over about 2 h of live runs, including the 25-minute idle window.** The lure and traverse rows were not repeated with the final gate.
- **Why 10:** the SSH connections per source over the watcher's 6-window lookback, over all 994 archived windows: workstation peak 9 (6 or more in 32 windows, 8 or more in 3, 10 or more in none); SSH brute force 25-26 within one window, overlap 30, slow scan 11. A threshold of 10 leaves every attack's gate time unchanged. The margin is thin on both sides (9 vs 10 vs 11): a busier generator would need the sweep repeated.
- **The streaming rules fired only on the attacker** in the same runs (`P-trap-touch`, `P-frag-syn-scan` and the baseline rules on Kali, plus `P-frag-syn-scan` on the three spoofed decoy sources of the stealth scan): none on the workstation. That is the first live check of the learned rules.
- **Pinned model:** analyses ran on `claude-sonnet-5-5` (`ANALYSIS_MODEL`, recorded in each run's `analysis_meta.json`; 8 runs recorded so far, earlier ones were not).
- **Limits:** two Claude answers were rejected by the validator (it listed the host as the attacker; it wrote a run id without its underscore) and the incident was analyzed again; the scorer treats such a rejection as an analysis error and excluded 2 of the 3-minute idle windows for it (a stricter rule than needed), and 2 further scenarios were merged into a neighboring incident and excluded. One 25-minute window is one sample, not a rate. Time to detect varies run to run (slow scan 87.5 s in the first campaign, 118.5 s here; web probing 32.5 s vs 94.6 s), so single medians of two runs should not be compared across campaigns.

## Update 2026-10-25: two attackers at once, and the fast-path latency it exposed
**Test** (`python eval/run_dual.py`, scorer `eval/dual_eval.py`, results `eval/results/dual_<time>.{json,md}`): attacker A (Kali's own address `10.10.10.10`) runs a port scan and an SSH brute force; attacker B (a second address `10.10.10.11` added on the same Kali interface, `sudo ip addr add 10.10.10.11/24 dev eth0`) follows the web lure and logs in over SSH with the planted credential 25 s later, in the middle of A's connection storm. The two addresses share one Ethernet address, which also tests the spoofed-source merging. Checks: each attacker detected separately, A's and B's techniques as expected, every honeytoken use credited to B, nothing leaked to A, nothing naming the workstation, and (added after run 1) the honeytoken use seen within 5 s.
- **Run 1** (`dual_20261025_201019.*`): the six original checks passed (A: T1595.001, T1110.001/.003; B: T1552.001, T1078; HT-001 credited to B; no false alarm). It also showed that the watcher saw the honeytoken use **29.7 s after the login**: its main loop checked the honeypot logs only between capture windows, and was busy with A's analysis (Claude call, controller, report: 30-40 s). The fast path still brought up the database and SMB decoys, but late; the earlier "decoys within seconds" held only while the watcher was idle. The stricter `fast_path_ok` check scores this run as a FAIL.
- **Fix:** `agent/watcher.py` tails the honeypot logs on a thread of its own (`honeytoken_loop`); attribution of the use to a source stays in the main loop.
- **Run 2** (`dual_20261025_201652.*`): **all seven checks pass.** A detected at 39.0 s (gate 18.4 s), B at 60.9 s (gate 26.9 s); **the honeytoken use was seen 1.0 s after the login**, and its database and SMB decoys came up from the fast path; HT-001 credited to B only; no event named the workstation; no watcher or decoy error in the event log.
- **Limits:** two runs (one before and one after the fix), one scenario pair; the controller has no lock, so a fast-path spawn and an analysis-driven spawn could in principle collide (none did, and a name clash only produces a failed spawn); B's gate time (26.9-41.1 s) is set by waiting for the capture window that holds its connection before attributing the use (accuracy over speed; the decoys do not wait for it).

## Update 2026-10-25 (later): a person at the keyboard, and the incident that fell apart
**Manual session** (`attacks/MANUAL_SESSION.md`, scored with `eval/campaign_eval.py ... --out manual`, `eval/results/campaign_manual.*`): a person ran the whole lure chain by hand from Kali (scan, robots.txt, /admin, a login guess, /backup/, config.bak, SSH with the planted credential and a look around, SMB share and note, MySQL with the second planted credential). Result: gate 115.5 s after the session start, Claude's confirmation at 137.6 s, a decoy deployed, 0 false alarms. The honeytoken fast path brought up the database and SMB decoys about 1-3 s after the SSH login with the exact planted password; the database decoy refused every MySQL login by design, and those attempts counted as HT-002 uses, credited to the right source.
- **What the person's session showed that scripts did not:**
  1. *One command froze the SSH honeypot:* `find / -name "*.conf"` made Cowrie's emulation spin at 100% CPU, and Cowrie, being single-threaded, stopped answering every new SSH connection until restarted (`TODO.md`, fix pending).
  2. *The incident fell apart:* the watcher judged a source active only by new connections (SYNs) and HTTP requests, so a person typing in an open SSH session, or copying files over SMB, looked idle. The incident closed at 18:49:48 UTC while the person was still working, and the windows with the most activity (18, 155 and 136 packets) went into no report: one session produced two reports, each incomplete.
  3. *Small tells:* the database decoy's error shows the Docker gateway (`172.31.0.1`) as the client address; the SMB decoy times out on the SMB1 workgroup lookup after the share list.
- **Fix for 2:** `agent/watcher.py` counts established traffic (any packet from the source) as activity; such sources get empty connection counts, so they cannot trip the gate by themselves. **Replay of the real session windows through the closing rule, old against new** (no Claude calls): the old rule closes the incident at 22:49:47 local with 4 windows copied; the new rule keeps it open and copies 11 windows, 22:46:16 to 22:52:18, the whole session in one incident. A scripted deep traversal afterwards was detected (gate 15.9 s, detection 39.1 s, 1 decoy, 0 false alarms) with every window carrying Kali traffic in one incident folder (`campaign_2026-10-25_traverse_check.*`); that run is not a discriminating test, since its SSH walk is short.
- **Limits:** one human session, one person; the fixed watcher has not yet been run live against a slow session (do the manual session again for that). For a demo, start the watcher with its default incident-merge setting (not the stricter one used for scoring) so a slow session stays one incident.

### Second manual session, with the fixed watcher (2026-10-25, scored in `campaign_manual.*`)
Same person, same chain, watcher on default settings (`WATCH_MERGE` not lowered). Scored as detected (gate and Claude's confirmation 22 s apart, 0 false alarms). The scorer's time to detect (574.8 s) is counted from the session marker and includes the person's own pauses (the person forgot to continue for about 35 minutes after the nmap scan), so for manual sessions only the gate-to-detection gap (22 s) and the coverage below are meaningful.
- **Two incidents, as they should be:** the first covers the nmap scan; after a 35-minute silence (longer than the 10-minute merge window) the rest of the chain is a second incident: web recon, the lure, SSH login with the planted credential and 9 typed commands, the SMB share, and the MySQL attempts. In the second incident every window carrying Kali traffic is in its folder (nothing lost), and the long quiet stretches inside the SSH session did not close it. The report for it: High severity, stage "lateral movement", 4 honeytoken uses, 8 techniques (T1552.001, T1078, T1003.008, T1033, T1083, T1018, T1135, T1595).
- **Two report gaps found and fixed (`report/incident_report.py`):** (1) decoys that were already running from an earlier incident were invisible to the report (it learned decoys only from spawn events), so a source that reached the database decoy three times showed "decoys 0": the report now includes decoys started by this incident's honeytoken use and decoys already running when the incident needed them ("Decoys in play", with "already running, started in an earlier incident"); (2) activity counts for OpenCanary decoys (database, FTP) were always 0 because those logs use `logtype`, not `eventid`.
- **Limits:** one person, two sessions; the 35-minute gap shows the merge window works as designed but means a demo should be run in one go.

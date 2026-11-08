# detect: rule format, streaming engine, corpus, proposer and promotion gate (core feature)

The goal of the core feature: after Claude confirms an attack, it proposes a **declarative detection rule**; the rule is
replay-validated on stored traffic and then promoted to a **fast streaming engine**. This folder holds the parts that
involve no AI: the rule format, the engine, the labeled corpus and the scorer. The proposer and the promotion gate come next.

| file | what it does |
|---|---|
| `rules.py` | the rule format and its validator (bounded numbers, closed vocabulary, no code or regexes) |
| `events.py` | packets -> small structural events (`syn`, `http_req`, `http_resp`, `frag`). URLs are never stored, only a short hash and a `trap` flag from `traps.json` |
| `engine.py` | streaming engine: one event in, alerts out, sliding windows per client, bounded memory |
| `stream.py` | live fast path: `tshark -l` -> engine -> `fast_rule_hit` events in `lab/logs/events.jsonl` (detects and logs only; acting stays with the controller) |
| `corpus.py` | builds the labeled corpus from saved pcaps + the Kali campaign logs; fixed development / validation / holdout split |
| `replay.py` | runs any rule file over the corpus and scores it (detected, right rule, time to alert, false alarms) |
| `evidence.py` | builds the ONLY view of the traffic the proposer gets: numbers and fixed words (no IPs, URLs, hashes, log text); `check_structural` refuses anything else |
| `propose.py` + `proposer_prompt.md` | one `claude -p` call with all tools disabled and a JSON schema; returns one rule + a short rationale |
| `gate.py` | the promotion gate: schema, catches its attack, adds coverage, zero false alarms on development+validation, zero on holdout benign; promote, history snapshots, rollback |
| `learn.py` | the loop: find development attacks the rules miss -> evidence -> proposal -> gate; every attempt saved in `runs/` |
| `injection_test.py` | 21 checks: hostile text cannot reach the model (A) and manipulated or bad proposals cannot pass the gate (B); part of `scripts/tests.sh` |
| `matrix.py` | the evaluation matrix (`results.md`): baseline vs baseline+learned vs the Claude path, per attack type and split, plus the false-alarm table |
| `demo.py` | the offline before/after demo (about a minute): miss -> proposal -> rejected bad rule -> accepted rule -> same attack replayed -> holdout |
| `hpevents.py` | honeypot-side events: what happens INSIDE an SSH session (login ok/fail, command, download) as counts only, attributed to the real client by matching the session to the nearest SSH connection attempt in the packets; used by the corpus and by `stream.py` (it follows the Cowrie log live) |
| `crossval.py` | leave-one-attack-type-out: learn from the other types, test on the held-out one |
| `rules/baseline.json` | the three hand-written threshold rules of `eval/rule_detector.py`, in this format |

## Rule format (one rule)
```json
{"id": "R-PORTSCAN", "name": "Many distinct ports", "technique": "T1046", "origin": "baseline", "window_s": 10, "refire_s": 60,
 "all_of": [{"kind": "syn", "measure": "distinct_dport", "op": ">=", "value": 15}]}
```
Per client address, over a sliding window; it fires when every clause holds. Clause filters: `dport_in`, `dport_not_in`,
`method_in`, `status_in`, `trap`. Measures: `count`, `distinct_dport`, `distinct_path`, `distinct_server`. Only `>=`
(a rule can never fire because something is missing). Full limits are in `rules.py`.

## Speed, honestly
The live watcher closes a capture window every 30 s and then asks Claude, so its time to detect is about 40 s
(`eval/README.md`). The streaming path has no window: in a live test the alert came **0.03 to 0.2 s after the packet**.
What the engine needs is enough packets to satisfy the rule (a 15-port scan needs 15 probes), so the headline is
"about 40 s down to a few seconds", not 1 s for every attack.

## Corpus
`python detect/corpus.py build` (about 4 minutes) writes `corpus/manifest.json` (committed: labels, splits, time ranges, SHA-256 of
every source pcap) and `corpus/events/*.jsonl.gz` (not committed: derived from pcaps, large; copy the folder between machines like the pcaps).
Labels come from ground truth only (campaign logs written on Kali, workstation = benign). Splits are by attack **type**:

| split | attack types | role |
|---|---|---|
| development | portscan, sshbrute, webprobe, lure | the proposer may look at these |
| validation | slowscan, dirbrute | the promotion gate must pass these without false alarms |
| holdout | stealthscan, traverse, overlap | reported at the end only (overlap mixes other types) |

Benign traffic is cut into 10-minute blocks and each block is assigned to a split by a fixed hash (never random events).
The watcher now **records every closed window** to `capture/archive/` (cap `WATCH_ARCHIVE_MB`, default 1024, 0 = off), so
rebuilding the corpus after a long idle recording adds benign data without any other change.

## Baseline result (hand-written rules, corpus built 2026-10-23)
```
split        type             n  detected right rule  median alert (s)  false alarms  minutes
development  lure            11      0/11       0/11                 -             0     27.5
development  portscan         9       9/9        9/9               0.8             0     24.7
development  sshbrute         8       8/8        8/8               1.2             0      0.2
development  webprobe        10     10/10      10/10               1.3             0     45.2
development  benign_block     3         -          -                 -             0     23.2
holdout      overlap          3       3/3        3/3               0.8             0      8.2
holdout      stealthscan      5       0/5        0/5                 -             0      0.1
holdout      traverse         3       0/3        0/3                 -             0     10.2
holdout      benign_block     1         -          -                 -             0      5.0
validation   dirbrute         5       5/5        5/5               1.0             0      2.3
validation   slowscan         8       8/8        0/8              53.2             0     11.4
validation   benign_block     1         -          -                 -             0     10.0
```
This is the number the learned rules must beat: the baseline misses lure chains, stealth scans and the deep traversal, and "catches"
the slow scan only by accident (the SSH rule fires on its retries, so the right rule is 0/8). "Right rule" means the firing rule names an
ATT&CK technique the scenario is expected to show.

## Limits to state in the report
- Benign data is thin so far: about 38 minutes of captured idle traffic plus the workstation background inside the attack runs, from one traffic
  generator. "Zero false alarms" can only be claimed **on the tested dataset**; the recorder is there to grow it.
- The event vocabulary is packet-level. Behavior that lives inside one SSH session (the deep traversal) is invisible to packet rules; whether the
  proposer can learn it depends on adding honeypot-side events later, and a failure there is a reportable result.
- Several early pcaps are missing (no incident was opened, so nothing was kept); 19 scenario runs were skipped for coverage reasons (listed in the manifest).

## Learning loop, first result (2026-10-23)
`python detect/learn.py --type lure --promote` (the baseline misses all 11 development lure chains):
- **Claude's proposal** (16 s, saw only numbers): "any request to a planted trap path, window 30 s". Rationale it gave: the attacker made 2 trap requests, benign traffic made 0.
- **Gate:** schema ok, catches 11/11 lure samples, 0 false alarms on development+validation, 0 on holdout benign -> **promoted** to `rules/promoted.json`.
- **Generalization (holdout, never seen by the proposer):** deep traversal 0/3 -> 3/3. Honest reading: traverse starts with the same trap file as the lure chain, so this is the same behavior in a longer session, not a new technique.
- **Rejection demo:** `detect/fixtures/bad_noisy.json` ("any HTTP request") catches the same 11 samples but fails `quiet` (120 false alarms from the workstation) and `holdout` -> **rejected** (`python detect/learn.py --type lure --proposal detect/fixtures/bad_noisy.json`).
- **Still missed:** stealth scan 0/5 (fragmented/decoy probes): no development example of it exists, so nothing could be learned; a second round would need it moved into development.
- **Timing, honestly:** the rule alerts about 1 s after the trap request, but the trap request itself comes ~66 s into the lure scenario, so "time from scenario start" (66 s) is slower than Claude's 39 s, which noticed the earlier recon. The right comparison for this rule is the delay after the behavior it detects (under a second, versus a 30 s window plus analysis). Step 4 will define that metric.
- "Right rule" shows 0/11 for this rule because the proposer gave no ATT&CK technique; that column only credits rules that name one.

## Live test of the fast paths (2026-10-23, lure chain from Kali, watcher with controller + `stream.py`)
| time (UTC) | event |
|---|---|
| 12:51:05 | attack starts (service scan) |
| 12:51:54 | Claude's first report (49 s), decoys smb + ftp follow |
| 12:52:10.98 | **learned rule `P-trap-touch` fires**, under 1 s after the request to the trap file (`fast_rule_hit`) |
| 12:52:11.24 | planted SSH credential used on the SSH honeypot (`honeytoken_used`) |
| 12:52:11.95 | **db decoy up, 0.7 s later** (`fast_path_policy`, no AI); the attacker's MySQL attempt came 7 s after that and hit it |
| 12:54:08 | Claude's second report (confidence 0.97) |
A client that reaches a breadcrumb address with no decoy up **hangs until timeout** (the host drops the SYN silently), so it looks like a filtered host.

## Step 4: evaluation, injection test, demo (2026-10-23)
- **Matrix** (`python detect/matrix.py`, output in `detect/results.md`): the hand rules already catch the loud attacks in about 1 s of the scenario start; the learned rule adds the lure chain (0/11 -> 11/11) and the deep traversal (0/3 -> 3/3, holdout); the stealth scan stays missed (0/5). Slow scan is "detected" only through the wrong rule. Claude's live path catches every type but only after 27-75 s (30 s windows + analysis).
- **Injection test** (`python detect/injection_test.py`, 21/21): six hostile strings (instructions, markup, SQL, path traversal, template syntax, bidi) put into URLs and HTTP methods never appear in the evidence, and four ways of smuggling text into it are refused; nine manipulated proposals (fires on everything, never fires, huge window, regex field, ">=" replaced by absence, shell text in the name, fake baseline origin) are all rejected. What this does not show: an attacker who shapes traffic VOLUME can still influence the numbers Claude sees; the gate (quiet on all benign data, must catch real attacks) is the defence there.
- **Method names** from packets are now normalized to the known HTTP set (anything else becomes `OTHER`), so even the saved corpus keeps no attacker-typed text. Corpus event files built before this change still hold raw method strings until the corpus is rebuilt.
- **Demo:** `python detect/demo.py` (add `--live-claude` for a fresh proposal).

## Fixing the four weak points (2026-10-23, second session)
1. **Benign data.** Corpus rebuilt with the recorder's windows: 85 minutes of pure-benign traffic in 16 blocks (62 development, 14 validation, 8.5 holdout) plus the workstation traffic inside every attack run; 0 false alarms with all four rule sets. A 6-hour recording (watcher + `stream.py`, started 17:45 local) is running; rebuild afterwards (`python detect/corpus.py build`, then `python detect/matrix.py`). Still ONE traffic generator, so diversity is the remaining gap (needs new benign behaviors added to `traffic/generator.py` and redeployed to the workstation VM).
2. **More learned rules.** Corpus split scheme `deploy` (the baseline-missed types are all available to learn; only the 3-at-once mix is held out), `learn.py --scheme`. Round 2 on the stealth scan: Claude proposed `P-frag-syn-scan` (>= 40 IP fragments and >= 6 distinct ports within 10 s; benign traffic never fragments), accepted, 5/5. Generalization is measured by **leave-one-type-out** (`crossval.py`, `runs/crossval.json`):

   | held out | learned from the others | detected before -> after | false alarms |
   |---|---|---|---|
   | lure | trap-touch (from traverse), frag-scan | 0/11 -> 11/11 | 0 |
   | traverse | trap-touch (from lure), frag-scan | 0/3 -> 3/3 | 0 |
   | stealthscan | trap-touch only | 0/5 -> 0/5 | 0 |

   Reading: lure and traverse teach each other because they share the trap file; the stealth scan is a different kind of behavior and is NOT caught by anything learned from the others. So the honest statement is "learned rules cover behavior similar to what was learned from", not "the system anticipates new attack types".
3. **Learning from a different signal** (`learn.py --independent-of P-trap-touch`): the proposer is told the trap kind is unavailable and the gate enforces it. For the deep traversal it proposed `P-ssh-cmd-burst` (>= 8 SSH-honeypot commands within 10 s; the attacker ran 19, benign traffic peaked at 2 per 30 s), accepted 3/3 with 0 false alarms. This gives defense in depth: an attacker who avoids the web trap still trips the in-session rule. Caveat: the benign generator types few commands; a human administrator pasting a script could exceed 8 in 10 s, so this rule is the likeliest source of a real false alarm and needs a longer, more varied benign recording.
4. **Packet-only events.** Solved by `hpevents.py`. Live check from Kali (deep traversal, fresh `stream.py`): `P-trap-touch` fired 0.39 s after the trap request, `P-ssh-cmd-burst` fired 0.20 s after the command burst, about 3 s later. One earlier live run with a long-running stream did NOT fire the SSH rule and the cause was not found (a fresh process works and a single-command test also worked, 0.5 s); treat the live SSH path as working but watch for it.

## Result of the richer benign traffic (2026-10-23, ~2 h after redeploying the generator)
Corpus rebuilt: 880 pcaps, 247 minutes of pure-benign blocks (128 development, 33 validation, 86 holdout) plus the workstation traffic inside the attack runs.
- **`P-ssh-cmd-burst` false-alarmed, as predicted.** Live: 3 `fast_rule_hit` alerts on the workstation (16:10, 16:14, 16:21 UTC) from pasted admin sessions (8-14 commands in ~2 s). In the rebuilt corpus: 4 false alarms (1 validation, 3 holdout). Benign peak is now 13 commands in 10 s (15 in 60 s) against 16-19 for the deep traversal. The other learned rules (`P-trap-touch`, `P-frag-syn-scan`) and the three baseline rules: 0 false alarms on all of it.
- **Action:** the rule was rolled back (`gate.py rollback`) and the live stream restarted without it. Then the loop was run again with the new data: Claude proposed "login + >= 10 commands in 10 s", **the gate rejected it** (1 false alarm on development+validation, 3 on holdout). The proposer's evidence only contains DEVELOPMENT benign traffic, and by the block split the pasted sessions landed in validation/holdout, so it saw a benign peak of 4 per 10 s; the gate saw the rest. That is the design working (the proposer is never the last line of defence), and it shows the limit of a small benign set.
- **What stays true:** no in-session rule is promoted now. A count threshold between 14 and 16 would separate the current generator (its pasted scripts are capped at 14 by construction) from the traversal (>= 16), but that margin is an artifact of the generator, so it was not promoted. A separating signal would need more than a count (for example the commands' pace together with what was run, or honeypot-side features beyond counts); that is future work.
- **New finding about the Claude path (not the fast path):** the new benign behaviors also hit the continuous watcher. The 5-port service check trips the triage gate (`GATE_PORTS=5`) about every 5 minutes (a Claude call each time), and Claude confirmed an attack on the workstation twice with confidence 0.7 (14:17 UTC, stage "discovery", 3 reports, 4 decoys spawned; 16:15 UTC after an admin session), then called the same incidents clean on re-analysis ("analysis_clean_disputed"). So the earlier "0 false alarms in 9 benign windows" holds only for the quiet generator; with realistic admin and monitoring traffic the Claude path produces occasional false confirmations. The fast rules did not contribute to those. Candidate fixes (not done): raise `GATE_PORTS` or use the validated fast engine as the triage gate, tell the analysis prompt that periodic service checks and admin sessions from the workstation are expected, and re-run the benign evaluation.

## Result of the live campaign (2026-10-24): corpus rebuilt, matrix, learned rules
Corpus rebuilt after the 21-scenario live campaign and the day's recording: 1400 pcaps, 134 samples, 29 runs skipped (reasons in `corpus/manifest.json`). The matrix (`python detect/matrix.py`, results in `detect/results.md`) uses the `deploy` split, in which stealthscan and traverse are development types because rules for them were learned on them; under the strict v1 split they stay held out and the baseline misses them, so those two rows are not held-out generalization.

| split | attack type | corpus runs | baseline rules | + learned rules | learned: median alert after scenario start (s) | Claude path (live) | Claude median time to detect (s) |
|---|---|---|---|---|---|---|---|
| development | lure | 15 | 0/15 | 15/15 | 66 | 2/2 | 66.0 |
| development | portscan | 11 | 11/11 | 11/11 | 1 | 1/1 | 51.1 |
| development | sshbrute | 10 | 10/10 | 10/10 | 1 | 2/2 | 94.0 |
| development | stealthscan | 7 | 0/7 | 7/7 | 2 | 2/2 | 71.0 |
| development | traverse | 7 | 0/7 | 7/7 | 67 | 2/2 | 69.7 |
| development | webprobe | 12 | 12/12 | 12/12 | 1 | 2/2 | 32.5 |
| validation | dirbrute | 7 | 7/7 | 7/7 | 1 | 1/1 | 137.3 |
| validation | slowscan | 10 | 10/10 | 10/10 | 53 | 2/2 | 87.5 |
| holdout | overlap | 5 | 5/5 | 5/5 | 1 | 2/2 | 33.6 |

- **False alarms with baseline + learned rules: 0** in development (180.0 pure-benign minutes, 26 blocks), validation (92.7 min, 10 blocks) and holdout (116.2 min, 14 blocks), plus the workstation's traffic inside every attack run. Claim wording stays: zero false alarms on the tested dataset, not a general guarantee.
- **Learned rules in force: two** (`P-trap-touch`, `P-frag-syn-scan`); `P-ssh-cmd-burst` stays rolled back, and no in-session rule is promoted. The false-alarm figures above come from replaying the rebuilt corpus offline, which includes the workstation's traffic recorded during this campaign. `detect/stream.py` was **not** running live during the campaign (only the honeytoken fast path was, 12 `fast_path_policy` events), so there is no live check of the rules this round. The 4 scored live false alarms came from the Claude path's honeytoken attribution (see `eval/README.md`, 2026-10-24).
- **Timing:** rules alert about 1-2 s after the behavior they detect for scans and brute force; the 66-67 s for lure and traverse is when the trap file is first requested in those scenarios, not rule latency. Claude's path takes 32-137 s.

### Live check of the learned rules (2026-10-24, later)
`detect/stream.py` ran beside the watcher for about 2 h of the post-fix campaign (the watcher now starts it). Alerts: `P-trap-touch` x10, `BASE-WEBPROBE` x10, `BASE-PORTSCAN` x8, `BASE-SSHBRUTE` x6 and `P-frag-syn-scan` x2 on the attacker, `P-frag-syn-scan` x2 on each of the three spoofed decoy sources of the stealth scan; **no alert on the workstation**, which was generating its normal admin, monitoring and service-check traffic throughout, including a 25-minute benign-only window. This is the live counterpart of the offline false-alarm table above (one run, not a guarantee).

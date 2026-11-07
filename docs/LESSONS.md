# Demo stories: flaws the testing found, and the fixes (for the presentation)

These are real, measured, and in the repo. Each one is "we tested harder than the happy path, it broke, we found why, we fixed it, we proved it".

## 1. Two attackers at once exposed a slow fast path (2026-10-25)
- **Test:** `python eval/run_dual.py`. Attacker A (a loud scan plus SSH brute force) and attacker B (a second address, follows the web lure and logs in with the planted credential) run together; B's login lands in the middle of A's storm.
- **What passed first time:** both attackers detected separately, the honeytoken credited to B and not A, nothing blamed on the workstation, B not merged into A even though both share one Ethernet address.
- **The flaw:** the honeytoken use was seen **29.7 s** after B's login. The watcher read the honeypot logs only between capture windows, and it was busy analyzing A (Claude call + controller + report, 30-40 s). The claim "decoys within seconds" was only true when the watcher was idle.
- **The fix:** the honeytoken tail runs on its own thread (`honeytoken_loop` in `agent/watcher.py`). We also made the test stricter (`fast_path_ok`: seen within 5 s), so run 1 now scores as a FAIL.
- **Proof:** run 2 passes all seven checks, honeytoken seen **1.0 s** after the login; decoys came up from the fast path. Both runs are kept: `eval/results/dual_20261025_201019.*` (before) and `dual_20261025_201652.*` (after). Write-up in `eval/README.md` ("two attackers at once").
- **One-liner:** "Under a second attacker our fast path was 30 seconds late; the test caught it, one thread fixed it, and the same test now shows 1 second."

## 2. The benign workstation was blamed for the attacker's honeytoken use (2026-10-24)
- **Found by:** the 21-scenario live campaign. Claude twice confirmed an attack by the workstation (credential access) because the honeytoken use was attributed to the wrong address.
- **Cause (two defects):** the watcher attributed the use before the capture window with the attacker's connection had closed, so only a routine workstation connection 2.96 s earlier was visible; and the MySQL case matched on port only, not destination address, after a 30 ms clock skew dropped the real connection.
- **Fix:** wait for the window to close (plus 1 s skew), match the destination address, allow skew (`agent/attribution.py`, `agent/watcher.py`). Replaying both bad cases from the archived pcaps: old logic blamed the workstation, new logic names Kali.
- **Proof:** live re-run, 9 of 9 honeytoken uses attributed to Kali, no confirmed detection of the workstation. `eval/results/campaign_2026-10-24_attrfix.*`; write-up in `eval/README.md` ("2026-10-24").
- **One-liner:** "Our first live run blamed the benign machine; we traced it to two bugs in how we find who used a bait credential, fixed both, and re-ran."

## 3. Measuring honestly (supporting points)
- The first live campaign ran with no watcher by mistake and measured nothing for the Claude path; the check that should have caught it was fooled by another process. It was fixed, the numbers were discarded, and the campaign was re-run (`eval/README.md`).
- A scoring artifact booked an attack's slow follow-ups into the next idle window as false alarms; it was corrected and the correction is documented as made after seeing the results.
- The SSH gate threshold was chosen from a sweep over 994 recorded windows (workstation peak 9, real attacks 11-30), not guessed.
- Stated limits: small sample sizes, one 25-minute idle window, thin margin on the SSH threshold. The claim wording stays "zero false alarms on the tested dataset".

## 4. A person at the keyboard froze the SSH honeypot (found 2026-10-25, fixed)
- **Found by:** the manual Kali session. `find / -name "*.conf"` made Cowrie's `find` spin at 100% CPU; being single-threaded it stopped answering every new SSH connection until restarted. Scripted scenarios never typed it.
- **Cause (measured):** the stock command follows symbolic links, and the fake filesystem has link loops: 300,000 entries visited in 51 s and still going, against about 29,000 entries in under a second when links are not followed.
- **Fix:** a bounded replacement (`lab/cowrie_custom/commands/find.py`): no link following, small chunks so other sessions keep being served, a hard cap, Ctrl+C. Also mounted into the spawned SSH decoys.
- **Proof:** the same command now answers at once (37 files); a second login while a long `find / -type f` runs takes 3.0 s, the same as with no load; Cowrie stays at 0% CPU.
- **One-liner:** "One ordinary admin command used to freeze our SSH trap for everyone. We measured why, bounded the command, and the same command now returns instantly and nobody else is delayed."

## 5. A person typing in an open SSH session made the incident fall apart (found 2026-10-25, fixed)
- **Found by:** the manual Kali session. One session produced two incident reports; the busiest stretch (typing in SSH, copying files over SMB) was in neither.
- **Cause:** the watcher counted a source as active only when it opened new connections or sent HTTP requests. An open SSH session sends plenty of packets but opens no new connection, so a person at the keyboard looked idle after 90 s and the incident closed.
- **Fix:** any packet from the source now counts as activity (`window_stats` in `agent/watcher.py`).
- **Proof:** replaying the real session windows through the closing rule: old rule closes at 22:49:47 with 4 windows; new rule keeps the incident open and covers 11 windows, the whole session (`eval/README.md`, "a person at the keyboard").
- **One-liner:** "Scripts never sat quietly in a shell; a person did, and our incident closed on them mid-session. Counting established traffic keeps one session as one incident and one report."

## 6. The report forgot decoys that were already running (found 2026-10-25, fixed)
- **Found by:** reading the report of the second manual session: the source had reached the database decoy three times, but the report said "decoys 0". The report learned about decoys only from "decoy spawned" events, and these decoys were already up from an earlier incident.
- **Fix:** the report now includes decoys started by the honeytoken fast path and decoys already running when the incident needed them, and counts OpenCanary decoy activity correctly. The same report now says "Decoys in play 3, reached 1 of 3, contact with the database decoy (6 events), three logins as reports_ro".

## 7. A lure that led to a closed door (found 2026-10-29, fixed)
- **Test:** a design review of the lure chain, then a live check from Kali. The IT note `it-notes.txt` (the HT-002 database account) sits on the always-on SMB share, and it names the database host `10.10.10.21:3306` outright.
- **The flaw:** the database decoy only started after the SSH honeytoken HT-001 was used. An attacker who read the note first (a port scan and one `smbclient` command) would try `10.10.10.21`, find a closed port, and HT-002 could never be used: the lure led to nothing and the proof of credential reuse was lost. The demo script always reads the note after the SSH login, so happy-path testing never showed it.
- **The fix:** the SMB decoy now logs which file a client opens (`smb.open`; Impacket only logged share connections). The watcher turns a read of a registered lure file (`lure_files` in `lab/lures/honeytokens.json`) into `lure_file_read`, and a fixed allowlist rule (`fast_path.on_reads`) starts `db_decoy`. No AI in that step, and the attacker's file path is only compared with the allowlist keys.
- **Proof:** with no decoys running, Kali read the note over SMB: `lure_file_read` at 08:38:05, `db_decoy` up on `10.10.10.21:3306` one second later (`lab/logs/events.jsonl`). `tests.sh` now checks every lure file has an `on_reads` entry that names only lure-chain templates. Commit `fcf839a`.
- **One-liner:** "Our lure pointed at a server that didn't exist yet; we noticed an attacker could read it first, so reading the note now brings the server up in one second."

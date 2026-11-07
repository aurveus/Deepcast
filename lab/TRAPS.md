# Trap map: what each trap is, what it records, where you see it

Defensive reference for the Deepcast lab. Every service here is fake. All credentials are planted FAKE lures kept in `lab/lures/honeytokens.json`; nothing real uses them, so any use of one is evidence that someone read a lure and acted on it.

## The always-on traps (Docker Compose, `lab/docker-compose.yml`)
| Trap | Address (host `HOST_IP`) | What it pretends to be | What it records | Where you see it |
|---|---|---|---|---|
| SSH honeypot (Cowrie) | port 2222 | A Linux server, "svr04", that accepts weak passwords. Inside: staff accounts, a nightly backup job, logs, exports, shell history (the "lived-in" content, `lab/cowrie_custom/lived_in.py`) and a hosts file / ARP table that point at two internal servers | Every login attempt, every typed command, file downloads, session recordings (`lab/logs/cowrie/cowrie.json`) | Attack sessions (commands quoted in the report), Live events |
| Web admin panel | port 8080 | A company admin login with `/admin/`, `/server-status` and a "forgotten" `/backup/` folder that `robots.txt` hints at | Every HTTP request with path, status and user agent (`lab/logs/web/web.json`) | Live events, incident report "Proof" |
| FTP and Telnet (OpenCanary) | ports 21, 23 | A vsFTPd-style server and a Telnet login | Login attempts with username and password (`lab/logs/opencanary/`) | Live events, honeytoken evidence |
| SMB decoy | port 4445 | A file server share named DOCS with a few office documents, including an IT notes file | Connections, share listing, file reads (`lab/logs/smb/`) | Live events |

## The decoys the platform starts on demand (controller allowlist `controller/allowlist.json`)
Only these five templates can ever be started, at fixed addresses so the breadcrumbs always point at the right place. Maximum 3 live at once, each expires after 30 minutes, a kill switch removes them all.
| Decoy | Fixed address | Role |
|---|---|---|
| SSH decoy | pool slot 0 (`.20`), port 22 | A second SSH server with the same lived-in content |
| Database decoy ("db-prod-01") | slot 1 (`.21`), port 3306 | A MySQL server that denies every login but logs the attempt. Its error names the client as the lab host (`lab/opencanary/mysql_patched.py`), not Docker's gateway `172.x`, which no real server here would print |
| File-server decoy ("fs-backup-01") | slot 2 (`.22`), port 4445 | A share holding the IT notes lure |
| FTP decoy | slot 3 (`.23`), port 21 | An FTP service |
| Web panel decoy | slot 4 (`.24`), port 80 | A second admin login |
Decoys named by the attacker's breadcrumbs (database and file server) take priority: if the live-decoy cap is full, a generic decoy is retired to make room.

## The lures (breadcrumbs, `lab/lures/`)
| Lure | Where it sits | What a visitor finds | What using it proves |
|---|---|---|---|
| HT-001 | Web panel, `/backup/config.bak` (hinted by `robots.txt`) | A backup settings file with an employee's username and password (an IT-operations account) | A login with it on the SSH honeypot or FTP means the source read the web lure. Highest-confidence evidence the platform has. |
| HT-002 | SMB share, `DOCS/it-notes.txt` | A note with a read-only reporting database login for "db-prod-01" | A login attempt on the database decoy means the source read the share. |
| Hosts file, history, ARP table | Inside the SSH honeypot | Names and addresses of "db-prod-01" and "fs-backup-01" | Looking at them and then connecting to those hosts shows lateral movement. |

## How a visit becomes evidence
1. The packet capture (`capture/`) records everything on the lab network, including the attacker's real source address (honeypot logs only show Docker's gateway address).
2. The watcher (`agent/watcher.py`) opens an incident when one source behaves like a scanner or brute-forcer, or uses a honeytoken.
3. Claude analyzes the incident (packet statistics, honeypot logs, typed commands, honeytoken facts, history of that source) and returns structured findings with ATT&CK techniques.
4. The controller validates the findings and may start decoys from the allowlist; every action goes to `lab/logs/events.jsonl`.
5. The dashboard and the generated incident report (HTML and PDF) show one merged timeline per source.

## Who sees what, and what they cannot do
- A visitor can only reach fake services; none of them runs real data, real credentials or a real shell (the SSH shell is emulated).
- The analysis agent cannot run commands; it can only read captures with read-only tools, and the controller (not the agent) takes every action from the fixed allowlist.
- Attacker-typed text is treated as untrusted data everywhere: it is sanitized, shown as quoted evidence only and never executed or followed as instructions.

## Known minor tell
`smbclient -L` against the SMB decoy ends with an SMB1 workgroup lookup that times out after about 5 s (Impacket never answers that second connection). A real server would refuse it at once. Fixing it means changing Impacket internals, so it is left as a documented tell.

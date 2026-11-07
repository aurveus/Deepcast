# Manual Kali session: a person at the keyboard (lab only)

Purpose: show that the platform also handles a human exploring the lab by hand, not only scripted campaigns. The session is scored as scenario type
`manual` (always held out from rule learning). Everything below targets the isolated lab host `10.10.10.1` from the Kali VM (`10.10.10.10`).
The credentials are the planted honeytokens (fake, `lab/lures/honeytokens.json`); an attacker would find them in the lure files, not know them.

## Before
1. Lab up (`bash lab/up.sh`), VMs on, `bash attacks/check_kali.sh` passes. No campaign running.
2. Start the watcher on the host (it also starts the streaming fast path): `python agent/watcher.py`. Dashboard if you want it live: `python dashboard/app.py` (http://127.0.0.1:5000).
3. On the host, mark the start: `bash attacks/manual.sh start "manual lure chain"`

## At the Kali VM (type these one at a time; pause between steps like a person would)
1. Recon scan:
   `nmap -n -sV -p 21,22,23,80,443,445,2222,3306,4445,8080 10.10.10.1`
   nmap only sees open services with banners; it cannot tell they are traps.
2. Web recon (`robots.txt` lists `/admin/` and `/backup/`, so both are natural next steps):
   `curl -s http://10.10.10.1:8080/robots.txt`
   `curl -s http://10.10.10.1:8080/admin/`            (redirects to the login page, a dead end by design)
   `curl -s -X POST http://10.10.10.1:8080/login -d "username=admin&password=admin123"`   (a believable guess; it fails and is logged)
   `curl -s http://10.10.10.1:8080/backup/`            (a forgotten directory listing: README.txt, config.bak, ...)
   `curl -s http://10.10.10.1:8080/backup/config.bak`  (the lure: an SSH account for the server, `tdavies`, with its password)
3. Use the leaked SSH credential on the SSH honeypot, then look around like a real intruder. Type the password EXACTLY as in `config.bak`:
   `ssh tdavies@10.10.10.1 -p 2222`   (password: `Autumn#Davies26`; Cowrie accepts weak passwords, so a wrong one also gets in, but only the exact pair counts as a honeytoken use and starts the fast path)
   then: `whoami`, `id`, `cat /etc/passwd`, `ls -la /home`, `cat ~/.bash_history`, `cat /etc/hosts`, `arp -a`, `cat /etc/crontab`, `ls -la /srv/exports/nightly`, `exit`
   `cat /etc/hosts` shows the internal servers the lure points at: `db-prod-01` (the database decoy, 10.10.10.21) and `fs-backup-01` (the file-server decoy, 10.10.10.22). Do NOT run `find / -name "*.conf"`: the fake shell hangs on it (a known honeypot tell, see TODO.md); if a session hangs, press Enter and type `~.`
4. SMB share (the second lure is in it). `smbclient -L` may end with an `NT_STATUS_IO_TIMEOUT` for the SMB1 workgroup lookup; that is harmless, the share list above it is the result:
   `smbclient -p 4445 -N -L //10.10.10.1`
   `smbclient -p 4445 -N //10.10.10.1/DOCS -c 'prompt OFF; recurse ON; mget *'`
   read `it-notes.txt`: it names a database account, `reports_ro`, with its password.
5. Use the second credential on the database decoy, at the address found in `/etc/hosts` (NOT the host address: nothing listens on 10.10.10.1:3306). It is a MySQL look-alike that only logs logins; it does not run queries, so every query is refused or empty:
   `MYSQL_PWD='rpt_ro_Q3!2026' mysql --skip-ssl -h 10.10.10.21 -P 3306 -u reports_ro -e 'show databases;'`
   `MYSQL_PWD='rpt_ro_Q3!2026' mysql --skip-ssl -h 10.10.10.21 -P 3306 -u reports_ro -e 'select version();'`
   `MYSQL_PWD='rpt_ro_Q3!2026' mysql --skip-ssl -h 10.10.10.21 -P 3306 -u reports_ro -e 'select current_user();'`
   The database decoy is started by the controller when the honeytoken is used (seconds after step 3), so step 5 only works after that. If the connection hangs, wait a few seconds and retry.

## After
1. On the host: `bash attacks/manual.sh stop`
2. Wait about 3 minutes for the incident to close, then score: `python eval/campaign_eval.py attacks/logs/campaign_manual_$(date -u +%Y%m%d).jsonl --out manual`
3. Look at the dashboard (Catches, Decoys) and the incident report in `capture/runs/`. For the demo: the honeytoken chain, which decoys appeared and how fast (`lab/logs/events.jsonl`: `honeytoken_used`, `fast_path_policy`, `decoy_spawned`).
4. Stop the watcher (Ctrl+C) and `bash lab/down.sh` when done.

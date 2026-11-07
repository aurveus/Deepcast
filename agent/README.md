# Agent: analysis output format

Claude reads a capture (via the Wireshark MCP) plus honeypot logs and answers with JSON matching [`schema.json`](schema.json). Claude only **decides**; the controller validates the JSON and acts.

| Field | Meaning |
|---|---|
| `run_id` | Which saved run was analyzed. |
| `analyses[]` | One entry per misbehaving IP; empty if all traffic is benign (important for false-positive tests). |
| `attacker_ip` | Real IP from the pcap, not the Docker gateway in honeypot logs. |
| `stage` | Furthest ATT&CK tactic reached. |
| `techniques[]` | ATT&CK technique `id` + `name`. |
| `evidence[]` | Numbers and facts from the data that justify the call. |
| `confidence` | 0 to 1; the controller ignores results below 0.5. |
| `recommended_decoys[]` | Template names from a fixed list: `ssh_decoy`, `ftp_decoy`, `smb_decoy`, `db_decoy`, `admin_panel_decoy`. |
| `summary` | Short session summary for the report. |

## Why it is built this way
- `additionalProperties: false` and enums mean anything unexpected fails validation, so Claude can never smuggle in a command or an unknown decoy.
- Decoys are names only. Images, ports and resource limits live in the controller allowlist (Day 8-9); the enum here must be kept in sync with it.

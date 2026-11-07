#!/usr/bin/env python3
"""Write the planted lure files from lab/lures/templates and the honeytoken registry.

  python lab/lures/render.py     (run by lab/up.sh and by the controller before it builds a decoy image)

Output (generated, git-ignored): lab/webadmin/lures/backup/{config.bak,README.txt}, lab/smbdecoy/share/it-notes.txt.
Placeholders: {{HOST_IP}}, {{SSH_PORT}}, {{DB_PORT}} (from .env) and {{<token id>.username|password}}.
"""
import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUTS = {  # template -> output path
    "config.bak.tmpl": ROOT / "lab" / "webadmin" / "lures" / "backup" / "config.bak",
    "backup_README.txt.tmpl": ROOT / "lab" / "webadmin" / "lures" / "backup" / "README.txt",
    "it-notes.txt.tmpl": ROOT / "lab" / "smbdecoy" / "share" / "it-notes.txt",
}


def env():
    out = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def render():
    e = env()
    values = {"HOST_IP": e.get("HOST_IP", "10.10.10.1"), "SSH_PORT": e.get("COWRIE_SSH_PORT", "2222"), "DB_PORT": "3306"}
    # The reporting database is the db decoy at its FIXED address (controller/allowlist.json pool_slot): "db-prod-01".
    allow = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))
    first = int(ipaddress.ip_address(e.get("DECOY_IP_FIRST", "10.10.10.20")))
    values["DB_HOST"] = str(ipaddress.ip_address(first + allow["templates"]["db_decoy"]["pool_slot"]))
    for t in json.loads((ROOT / "lab" / "lures" / "honeytokens.json").read_text(encoding="utf-8"))["tokens"]:
        values[f"{t['id']}.username"], values[f"{t['id']}.password"] = t["username"], t["password"]
    for name, dest in OUTPUTS.items():
        text = (ROOT / "lab" / "lures" / "templates" / name).read_text(encoding="utf-8")
        text = re.sub(r"\{\{([^}]+)\}\}", lambda m: values[m.group(1).strip()], text)   # KeyError = typo in a template
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {dest.relative_to(ROOT)}")


if __name__ == "__main__":
    render()

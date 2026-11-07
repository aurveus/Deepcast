"""David Bianco's Pyramid of Pain: how much it hurts an attacker when a defender denies each kind of indicator.

Bottom to top: hash values, IP addresses, domain names, network/host artifacts, tools, TTPs. Blocking a hash costs the attacker
seconds; denying a behaviour (TTP) forces them to change how they work. Used by the dashboard's MITRE tab and the incident report's
indicator table, so both place the same indicator on the same level. Classification is a fixed table, not a model decision.
"""
import re

# (key, name, pain, what the attacker has to do when it is denied, what this lab records at this level)
LEVELS = [
    ("hash", "Hash values", "Trivial", "Change one byte of the file and the hash is new.",
     "No attacker files were captured; the SHA-256 values in a report belong to our own pcaps (evidence integrity), not to the attacker."),
    ("ip", "IP addresses", "Easy", "Use another address (VPN, another VM, a proxy).",
     "The attacker's real IP, taken from the pcap (honeypot logs only show the Docker gateway)."),
    ("domain", "Domain names", "Simple", "Register or point another domain name.",
     "None: the lab attacks reach us by IP, so no attacker domain appears."),
    ("artifact", "Network / host artifacts", "Annoying", "Edit the tool's headers, banner or request patterns.",
     "User agents, SSH client banners, requested web paths and targeted ports, listed in each incident report."),
    ("tool", "Tools", "Challenging", "Find, learn or write a different tool.",
     "Named only when a banner or user agent says so (nmap, hydra, nikto and similar); a spoofed header would fool this."),
    ("ttp", "TTPs (behaviour)", "Tough", "Change how they work: a new method, not a new label.",
     "The ATT&CK techniques the agent mapped, and honeytoken credential reuse. This is where the platform reports and where decoys act."),
]
ORDER = [k for k, *_ in LEVELS]
NAME = {k: n for k, n, *_ in LEVELS}
PAIN = {k: p for k, _, p, *_ in LEVELS}

# Names that identify a standard lab tool inside a user agent or SSH banner (substring, case-insensitive).
TOOLS = {"nmap": "Nmap", "nikto": "Nikto", "hydra": "Hydra", "sqlmap": "sqlmap", "gobuster": "Gobuster", "dirb": "DIRB",
         "dirbuster": "DirBuster", "masscan": "masscan", "wfuzz": "wfuzz", "ffuf": "ffuf", "medusa": "Medusa", "patator": "Patator",
         "paramiko": "Paramiko", "libssh": "libssh", "smbclient": "smbclient", "curl/": "curl", "python-requests": "python-requests"}

# What blocking an indicator of this level achieves, in one line (shown in the incident report next to each indicator).
IF_BLOCKED = {"hash": "Gone in seconds: one changed byte gives a new hash.",
              "ip": "A stopgap: they come back from another address.",
              "domain": "Cheap for them to replace.",
              "artifact": "Costs them a tweak of the tool's settings, then they are back.",
              "tool": "Forces a different tool; real effort, but they can find one.",
              "ttp": "Hard to evade: they must change how they attack."}

IOC_LEVEL = {"IPv4": "ip", "User agents": "artifact", "SSH banner": "artifact", "Web paths": "artifact", "Targeted ports": "artifact"}


def tools_in(*texts):
    """Standard tools named by the given strings (user agents, banners, evidence lines), in a stable order."""
    blob = " ".join(str(t) for t in texts).lower()
    return sorted({label for needle, label in TOOLS.items() if re.search(r"(?<![a-z])" + re.escape(needle), blob)})


def label(key):
    return f"{NAME[key]} ({PAIN[key].lower()})"


def describe():
    """The levels, top of the pyramid first, for the dashboard."""
    return [{"key": k, "name": n, "pain": p, "denied": d, "recorded": r} for k, n, p, d, r in reversed(LEVELS)]

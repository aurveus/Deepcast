"""Plain-language descriptions of the ATT&CK techniques this platform reports, and links to MITRE's pages.

Names and IDs are MITRE's; the one-sentence explanations are written for readers who do not know ATT&CK.
Unknown technique IDs still get a link to MITRE's page.
"""

INFO = {
    "T1595": ("Active Scanning", "The attacker sends probe traffic at your systems to learn what is exposed (hosts, open ports, software) before attacking."),
    "T1595.001": ("Scanning IP Blocks", "Probing whole ranges of addresses or ports to find which hosts and services are live. A port scan is the classic example."),
    "T1595.002": ("Vulnerability Scanning", "Automated checks that test exposed services for known weaknesses, such as a web scanner requesting hundreds of risky paths."),
    "T1595.003": ("Wordlist Scanning", "Guessing hidden pages, files or directories by trying names from a list of common ones."),
    "T1110": ("Brute Force", "Guessing passwords to get into an account or service."),
    "T1110.001": ("Password Guessing", "Trying many likely passwords for an account, one after another, until one works."),
    "T1110.003": ("Password Spraying", "Trying one or a few very common passwords against many accounts, to stay under lockout limits."),
    "T1046": ("Network Service Discovery", "Listing the services running on other machines to find what to attack next. Usually done after getting a foothold."),
    "T1082": ("System Information Discovery", "Reading details about a system (operating system, hostname, hardware) after getting in."),
    "T1083": ("File and Directory Discovery", "Browsing files and folders to find data of interest."),
    "T1135": ("Network Share Discovery", "Looking for shared folders on the network."),
    "T1078": ("Valid Accounts", "Logging in with real credentials (stolen, guessed or found), which looks like normal use."),
    "T1021.004": ("Remote Services: SSH", "Using SSH to log in to a machine and move between systems."),
    "T1033": ("System Owner/User Discovery", "Finding out which account is logged in and what it can do, usually with commands like whoami."),
    "T1016": ("System Network Configuration Discovery", "Looking at a machine's network settings (addresses, routes) to understand the surrounding network."),
    "T1018": ("Remote System Discovery", "Finding other machines on the network, for example by reading the hosts file or the ARP table, to choose the next target."),
    "T1552.003": ("Unsecured Credentials: Bash History", "Reading the shell history file, which often contains passwords or the names of other servers."),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Reading the system's account files to learn the usernames (and, if readable, password hashes)."),
    "T1105": ("Ingress Tool Transfer", "Downloading the attacker's tools or files onto the compromised machine."),
    "T1059.004": ("Unix Shell", "Running commands or scripts through the shell on the compromised machine."),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Searching files for passwords and keys that were left in plain text."),
}


def technique_url(tid):
    """MITRE page for a technique: T1110.001 -> https://attack.mitre.org/techniques/T1110/001/"""
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def describe(tid):
    name, what = INFO.get(tid, (None, "No plain-language summary written yet for this technique. See the MITRE page for its definition."))
    return {"name": name, "what": what, "url": technique_url(tid)}

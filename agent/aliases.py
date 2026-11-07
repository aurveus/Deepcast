#!/usr/bin/env python3
"""Spoofed decoy sources: one attacker, several source addresses.

  python agent/aliases.py <pcap> [...]     # show which source addresses are aliases of which
  python agent/aliases.py --selftest

A scanner can mix extra source addresses ("decoys") in among its real probes so that a defender sees many scanners. On the
same network segment those packets still leave the attacker's own network card, so every spoofed address carries the
attacker's Ethernet (MAC) address. The replies to a spoofed address never reach the attacker, so a spoofed address only
ever sends the opening SYN, while the real address also answers (RST or ACK) or announces itself with ARP.

Rule (deterministic, computed from the capture): within one MAC address, addresses that send ONLY opening SYNs (or empty
fragments) are aliases of the address on that MAC that was seen answering or in ARP. Without such an address nothing is merged.

Limits, stated honestly: this works on one Ethernet segment (the lab). Behind a router every source shares the router's MAC,
so the module is told to ignore the addresses it must not merge (the host and the decoy pool, which legitimately share the host's
MAC). A spoofed address that is not on a shared MAC cannot be detected this way.
"""
import shutil
import subprocess
import sys
from collections import defaultdict

TRUE = ("1", "True", "true")


def group_aliases(rows, ignore=()):
    """rows: (mac, ip, syn, ack, arp_sender) tuples, one per packet; syn/ack are tcp flag strings ('' when not TCP or a fragment
    without a TCP header); arp_sender is True for ARP packets sent by `ip`. Returns {alias_ip: primary_ip}."""
    per = defaultdict(lambda: defaultdict(lambda: {"syn_only": 0, "answering": 0, "arp": 0}))
    for mac, ip, syn, ack, arp in rows:
        if not mac or not ip or ip in ignore:
            continue
        c = per[mac][ip]
        if arp:
            c["arp"] += 1
        elif syn in TRUE and ack not in TRUE:
            c["syn_only"] += 1
        elif syn or ack:                          # any other TCP packet with flags: an ACK, RST, FIN ... i.e. it was answering
            c["answering"] += 1
    out = {}
    for mac, ips in per.items():
        if len(ips) < 2:
            continue
        live = {ip: c for ip, c in ips.items() if c["arp"] or c["answering"]}
        if not live:
            continue
        primary = max(live, key=lambda ip: (live[ip]["arp"] > 0, live[ip]["answering"]))
        for ip, c in ips.items():
            if ip != primary and c["syn_only"] and not c["answering"] and not c["arp"]:
                out[ip] = primary
    return out


def _tshark():
    return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"


def find_aliases(pcaps, ignore=()):
    """{alias_ip: primary_ip} for the given captures."""
    rows = []
    for p in pcaps:
        res = subprocess.run([_tshark(), "-r", str(p), "-Y", "ip || arp", "-T", "fields", "-e", "eth.src", "-e", "ip.src", "-e", "tcp.flags.syn",
                              "-e", "tcp.flags.ack", "-e", "arp.src.proto_ipv4"], capture_output=True, text=True).stdout
        for line in res.splitlines():
            mac, ip, syn, ack, arp_ip = (line.split("\t") + [""] * 5)[:5]
            if arp_ip:
                rows.append((mac, arp_ip, "", "", True))
            elif ip:
                rows.append((mac, ip, syn, ack, False))
    return group_aliases(rows, ignore)


def ignore_set(env):
    """Addresses that legitimately share a MAC: the lab host and the decoy pool (all served from the host's network card)."""
    import ipaddress
    out = {env.get("HOST_IP", "10.10.10.1")}
    try:
        lo, hi = int(ipaddress.ip_address(env["DECOY_IP_FIRST"])), int(ipaddress.ip_address(env["DECOY_IP_LAST"]))
        out |= {str(ipaddress.ip_address(i)) for i in range(lo, hi + 1)}
    except (KeyError, ValueError):
        pass
    return out


def describe(aliases):
    """Trusted fact text for the analysis input ('' when there are no aliases)."""
    if not aliases:
        return ""
    by = defaultdict(list)
    for a, p in aliases.items():
        by[p].append(a)
    lines = ["Spoofed-source facts (trusted: computed from Ethernet addresses in the capture):"]
    for p, a in sorted(by.items()):
        lines.append(f"- {', '.join(sorted(a))} share the Ethernet address of {p} and sent only unanswered opening SYNs. They are decoy source "
                     f"addresses spoofed by {p}'s scan (evasion), not separate attackers. Report ONE entry, for {p}.")
    return "\n".join(lines)


def merge_result(result, aliases):
    """Fold analysis entries for alias addresses into their primary: drop duplicates, re-point a lone alias entry to the primary,
    and note the spoofing in the primary's evidence. Returns the number of entries changed."""
    if not aliases:
        return 0
    changed, keep, have = 0, [], {a["attacker_ip"] for a in result["analyses"]}
    for a in result["analyses"]:
        ip = a["attacker_ip"]
        if ip in aliases:
            changed += 1
            primary = aliases[ip]
            if primary in have:
                continue                                  # the primary already has its own entry
            a["attacker_ip"] = primary
            have.add(primary)
        keep.append(a)
    result["analyses"] = keep
    by = defaultdict(list)
    for al, p in aliases.items():
        by[p].append(al)
    for a in keep:
        if a["attacker_ip"] in by and not any("spoofed" in e.lower() for e in a["evidence"]):
            a["evidence"].append(f"Scan also sent from spoofed decoy sources {', '.join(sorted(by[a['attacker_ip']]))} (same Ethernet address)")
    return changed


def selftest():
    K, W = "aa:aa", "bb:bb"
    syn = ("1", "0")
    rows = ([(K, "10.10.10.10", *syn, False)] * 5 + [(K, ip, *syn, False) for ip in ("10.10.10.201", "10.10.10.202")] * 5
            + [(K, "10.10.10.10", "0", "1", False)] * 2                              # the real source answers (ACK/RST)
            + [(W, "10.10.10.30", *syn, False)] * 3 + [(W, "10.10.10.30", "0", "1", False)] * 3)   # a normal workstation
    got = group_aliases(rows)
    assert got == {"10.10.10.201": "10.10.10.10", "10.10.10.202": "10.10.10.10"}, got
    assert group_aliases(rows, ignore={"10.10.10.201", "10.10.10.202"}) == {}, "ignored addresses must not be merged"
    # two SYN-only addresses and nobody answering or in ARP: cannot tell who is real, merge nothing
    assert group_aliases([(K, "1.1.1.1", *syn, False), (K, "1.1.1.2", *syn, False)]) == {}
    # ARP identifies the real address even when it never answered
    assert group_aliases([(K, "1.1.1.1", *syn, False), (K, "1.1.1.2", *syn, False), (K, "1.1.1.1", "", "", True)]) == {"1.1.1.2": "1.1.1.1"}
    res = {"run_id": "x", "analyses": [{"attacker_ip": "10.10.10.201", "evidence": ["a"], "confidence": 0.9},
                                       {"attacker_ip": "10.10.10.10", "evidence": ["b"], "confidence": 0.9}]}
    assert merge_result(res, got) == 1 and [a["attacker_ip"] for a in res["analyses"]] == ["10.10.10.10"]
    assert "spoofed" in res["analyses"][0]["evidence"][-1].lower()
    lone = {"run_id": "x", "analyses": [{"attacker_ip": "10.10.10.202", "evidence": ["a"], "confidence": 0.9}]}
    merge_result(lone, got)
    assert lone["analyses"][0]["attacker_ip"] == "10.10.10.10"
    assert "share the Ethernet address of 10.10.10.10" in describe(got)
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    elif len(sys.argv) >= 2:
        print(find_aliases(sys.argv[1:]) or "(no aliased sources)")
    else:
        sys.exit(__doc__)

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

| Scenario | Runs | Excluded (outage / merged) | Gate triggered | Claude detected | Median time to detect (s) | Median gate (s) | Decoy deployed | False alarms |
|---|---|---|---|---|---|---|---|---|
| Port scan | 2 | 1 | 1/2 | 2/2 | 84.4 | 36.2 | 2/2 | 0 |
| Slow port scan | 2 | 2 | 2/2 | 2/2 | 64.4 | 42.9 | 2/2 | 0 |
| SSH brute force | 2 | 2 | 2/2 | 2/2 | 36.2 | 11.6 | 2/2 | 0 |
| Web probing | 2 | 1 | 2/2 | 2/2 | 93.0 | 204.1 | 2/2 | 0 |
| Lure chain | 1 | 3 | 1/1 | 1/1 | 31.5 | 9.3 | 1/1 | 0 |
| Directory brute force | 2 | 2 | 2/2 | 2/2 | 55.1 | 19.9 | 2/2 | 0 |
| Stealth scan (fragmented/decoy) | 2 | 2 | 2/2 | 2/2 | 89.8 | 90.9 | 2/2 | 0 |
| Deep trap traversal | 2 | 2 | 1/2 | 2/2 | 83.2 | 27.3 | 1/2 | 0 |
| Overlapping attacks (3 at once) | 2 | 2 | 1/2 | 2/2 | 91.5 | 36.7 | 2/2 | 0 |
| Benign only (idle) | 2 | 0 | n/a | n/a | – | – | n/a | 0 |

Time to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: 3.

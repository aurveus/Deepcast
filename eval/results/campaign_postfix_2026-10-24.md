| Scenario | Runs | Excluded (outage / merged) | Gate triggered | Claude detected | Median time to detect (s) | Median gate (s) | Decoy deployed | False alarms |
|---|---|---|---|---|---|---|---|---|
| Port scan | 2 | 0 | 2/2 | 2/2 | 34.0 | 11.2 | 2/2 | 0 |
| Slow port scan | 2 | 0 | 2/2 | 2/2 | 118.5 | 34.4 | 2/2 | 0 |
| SSH brute force | 2 | 0 | 2/2 | 2/2 | 50.8 | 73.3 | 2/2 | 0 |
| Web probing | 2 | 0 | 2/2 | 2/2 | 94.6 | 233.7 | 2/2 | 0 |
| Lure chain | 2 | 0 | 2/2 | 2/2 | 42.5 | 22.5 | 2/2 | 1 |
| Directory brute force | 1 | 1 | 1/1 | 1/1 | 36.4 | 14.9 | 1/1 | 0 |
| Stealth scan (fragmented/decoy) | 1 | 1 | 1/1 | 1/1 | 31.9 | 12.7 | 1/1 | 0 |
| Deep trap traversal | 2 | 0 | 2/2 | 2/2 | 43.8 | 23.3 | 2/2 | 1 |
| Overlapping attacks (3 at once) | 2 | 0 | 1/2 | 2/2 | 58.5 | 10.9 | 1/2 | 0 |
| Benign only (idle) | 2 | 2 | n/a | n/a | – | – | n/a | 0 |

Time to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: 0.

| Scenario | Runs | Excluded (outage / merged) | Gate triggered | Claude detected | Median time to detect (s) | Median gate (s) | Decoy deployed | False alarms |
|---|---|---|---|---|---|---|---|---|
| Lure chain | 2 | 0 | 2/2 | 2/2 | 42.5 | 22.5 | 2/2 | 1 |
| Deep trap traversal | 2 | 0 | 2/2 | 2/2 | 43.8 | 23.3 | 2/2 | 1 |

Time to detect = Claude's confirmed detection minus the real attack start (from the attacker's own log). Gate = the triage trigger that wakes the agent. Events not assignable to any scenario: 0.

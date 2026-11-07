| split | attack type | corpus runs | baseline rules | + learned rules | learned: median alert after scenario start (s) | Claude path (live campaign) | Claude median time to detect (s) |
|---|---|---|---|---|---|---|---|
| development | lure | 15 | 0/15 | 15/15 | 66 | 2/2 | 66.0 |
| development | portscan | 11 | 11/11 | 11/11 | 1 | 1/1 | 51.1 |
| development | sshbrute | 10 | 10/10 | 10/10 | 1 | 2/2 | 94.0 |
| development | stealthscan | 7 | 0/7 | 7/7 | 2 | 2/2 | 71.0 |
| development | traverse | 7 | 0/7 | 7/7 | 67 | 2/2 | 69.7 |
| development | webprobe | 12 | 12/12 | 12/12 | 1 | 2/2 | 32.5 |
| validation | dirbrute | 7 | 7/7 | 7/7 | 1 | 1/1 | 137.3 |
| validation | slowscan | 10 | 10/10 | 10/10 | 53 | 2/2 | 87.5 |
| holdout | overlap | 5 | 5/5 | 5/5 | 1 | 2/2 | 33.6 |

False alarms with baseline + learned rules (benign blocks plus the workstation traffic inside every attack run):

| split | false alarms | pure-benign minutes | benign blocks | events replayed |
|---|---|---|---|---|
| development | 0 | 180.0 | 26 | 1699823 |
| validation | 0 | 92.7 | 10 | 100932 |
| holdout | 0 | 116.2 | 14 | 729792 |

Learned rules: `P-trap-touch` (Request to planted trap path), `P-frag-syn-scan` (Fragmented SYN scan across many ports)
Corpus built 2026-10-24T16:04:39+00:00; 134 samples, 29 scenario runs skipped (reasons in corpus/manifest.json).
Claim wording: zero false alarms on the tested dataset above; not a general guarantee.

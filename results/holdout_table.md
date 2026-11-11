| Condition | Defense Configuration | Attack Success Rate (%) | Block / Detect Rate (%) | Benign Success (%) | Escalation (%) | Added Step Latency p50 / p95 (ms) | TTD / TTC (ms) |
|---|---|---:|---:|---:|---:|---:|---:|
| C0 | Undefended Baseline | 91.54 ± 2.14 | 0.00 ± 0.00 | 100.00 ± 0.00 | 0.00 ± 0.00 | 0.00 / 0.00 | -- / -- |
| C4 | Pillars 1+2+3 (Pre-Feedback) | 22.31 ± 4.65 | 63.08 ± 5.70 | 100.00 ± 0.00 | 0.00 ± 0.00 | 6.58 / 150.89 | 356.94 / 0.017 |
| C5_REGEX | Pillar 4 Regex Remediation Only | 22.31 ± 4.65 | 63.08 ± 5.70 | 100.00 ± 0.00 | 0.00 ± 0.00 | 6.07 / 153.49 | 385.15 / 0.018 |
| C5_FULL | Pillar 4 Regex + Neural Semantic | 15.77 ± 3.54 | 69.62 ± 6.63 | 100.00 ± 0.00 | 0.00 ± 0.00 | 50.30 / 172.38 | 405.56 / 0.018 |

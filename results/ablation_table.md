| Condition | Defense Configuration | Attack Success Rate (%) | Block / Detect Rate (%) | Benign Success (%) | Escalation (%) | Added Step Latency p50 / p95 (ms) | TTD / TTC (ms) |
|---|---|---:|---:|---:|---:|---:|---:|
| C0 | Undefended Baseline | 89.23 ± 5.50 | 0.00 ± 0.00 | 100.00 ± 0.00 | 0.00 ± 0.00 | 0.00 / 0.00 | -- / -- |
| C1 | Simulated HITL Only | 30.38 ± 3.92 | 59.62 ± 4.78 | 90.77 ± 4.27 | 0.00 ± 0.00 | 1203.90 / 2001.34 | -- / -- |
| C2 | Pillar 2 Guardrails Only | 18.08 ± 1.31 | 66.15 ± 12.36 | 92.31 ± 0.00 | 1.54 ± 0.00 | 0.19 / 0.00 | -- / -- |
| C3 | Pillar 3 Runtime Only (Sandboxed) | 31.54 ± 3.62 | 59.62 ± 6.09 | 100.00 ± 0.00 | 0.00 ± 0.00 | 4.74 / 201.40 | 139.64 / 0.020 |
| C4 | Pillars 1+2+3 (Pre-Feedback) | 15.00 ± 1.07 | 68.46 ± 11.65 | 92.31 ± 0.00 | 1.54 ± 0.00 | 7.99 / 177.34 | 337.05 / 0.023 |
| C5 | Full 4-Pillar Loop (Post-Feedback) | 0.00 ± 0.00 | 83.46 ± 11.53 | 92.31 ± 0.00 | 1.54 ± 0.00 | 106.50 / 227.08 | 411.75 / 0.025 |

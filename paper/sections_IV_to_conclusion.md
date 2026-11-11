# Updated & Extended Paper Sections (Sections IV–VII + Early-Section Edits)

*Companion empirical extension to: "From Human-in-the-Loop to Continuous Defense: Cyber Threat Intelligence for Autonomous AI Agents". All quantitative figures in Sections V–VII are drawn exclusively from raw experimental outputs in `results/`.*

---

## Recommended Edits to Earlier Sections (Sections I–III)

1. **Section I (Introduction), last paragraph**: Update the roadmap sentence to:
   > "Section III outlines a four-pillar defence blueprint grounded in cyber threat intelligence. Section IV details a reproducible reference implementation across a tool-using autonomous agent, Section V presents an experimental ablation, zero-leakage unseen holdout generalization study, and simulated human-oversight scaling evaluation, Section VI discusses limitations and operational trade-offs, and Section VII concludes the paper."
2. **Section I & Table I (Human Oversight Claims)**: Add a methodological scope footnote clarifying that the empirical comparison against human-in-the-loop (HITL) oversight in Section V uses a **parametric discrete-event queueing and cognitive-fatigue simulation model** rather than a human-subjects user study.
3. **Section III.A (Pillar 1) & Fig. 2**: Note the 13 concrete threat classes evaluated in the machine-readable catalog (`T01`–`T13`), adding RAG/retrieval poisoning, persistent memory poisoning, agent identity confusion, and malicious tool/plugin supply-chain manifests alongside Fig. 2's six illustrative threats, cross-referenced to OWASP LLM Top 10 v2025, OWASP Agentic AI Threats, and MITRE ATLAS.
4. **Section III.D (Pillar 4) & Fig. 5**: Specify that the "Feedback Loop into System Design" operates programmatically by escalating risk likelihoods in Pillar 1 and emitting both YAML guardrail rules and margin-calibrated neural semantic prototypes (`all-MiniLM-L6-v2`) into Pillar 2 prior to re-evaluation.

---

## IV. Implementation

We instantiate the four-pillar blueprint as a modular Python 3.13 reference platform (`agent-cti`) comprising an autonomous tool-using target system, a simulated HITL baseline, and four composable defense layers orchestrated via `DefensePipeline`.

### A. Target AI System Under Defense
The target system (`TargetAgent`) executes a multi-step ReAct-style planning loop (`max_steps = 6`, `max_tokens = 4096`) equipped with five sandbox-ready tools (`file_read`, `send_email`, `http_fetch`, `sql_query`, and AST-validated `calculator`), an external plugin registration surface (`register_plugin_manifest`) to model supply-chain exposure, a JSON-persisted key/value `MemoryStore`, a `RAGStore` supporting both deterministic TF-IDF cosine retrieval and live local neural embeddings (`sentence-transformers/all-MiniLM-L6-v2`, 384-D, CPU inference), and a two-agent message broker (`AgentBus`) connecting `coordinator-01` and `worker-01`. All sensitive assets are strictly synthetic canary markers (`CANARY_API_KEY_7F9A2B`, `CANARY_DB_TOKEN_X99`, `CANARY_SSN_000-11-2222`).

The LLM reasoning backend conforms to a pluggable `LLMBackend` interface supporting (1) `DeterministicMockLLM` for reproducible regression testing, (2) `StochasticMockLLM` for seeded multi-seed evaluation of probabilistic compliance and token jitter, and (3) HTTP/SDK adapters (`OpenAICompatibleBackend`, `GeminiBackend`, `AnthropicBackend`, `TransformersLocalBackend`) reading credentials solely from `.env`.

### B. Pillar 1: Threat Understanding (`agent_cti.threat_model`)
`threats/catalog.yaml` encodes **13 threat classes** (`T01_PROMPT_INJECTION_DIRECT` through `T13_MISINFORMATION_HALLUCINATION`) mapped across AI system scopes (`models`, `data_pipelines`, `retrieval_systems`, `tools`, `agents`, `user_interactions`, `memory`, `agent_channel`). Each threat carries an explicit Impact ($1\text{–}5$) $\times$ Likelihood ($1\text{–}5$) risk score ($1\text{–}25$), cross-references to OWASP LLM Top 10 v2025, OWASP Agentic AI Threats, and MITRE ATLAS, and maps to concrete control IDs. `ControlGenerator` aggregates threat risk per control and emits `policies/generated_controls.yaml`, driving enablement and ordering across both Pillar 2 and Pillar 3 controls.

### C. Pillar 2: Governance & Guardrails (`agent_cti.guardrails`)
`PolicyEngine` evaluates declarative YAML policies (`policies/default_policies.yaml`, extended dynamically by `policies/remediation_policies.yaml`) across four checkpoints:
1. `pre_input`: deterministic regex injection screening (`POL-INP-001`) and unverified privileged peer-role checks (`POL-INP-002`).
2. `system_prompt` & `pre_retrieval`: `[POLICY_FRAMED]` untrusted-data boundary framing (`POL-PRM-001`) and RAG chunk trust/pattern screening (`POL-RET-001`, `POL-RET-002`).
3. `pre_tool`: tool allowlisting and untrusted manifest rejection (`POL-TOOL-001`), sensitive file/path traversal blocking (`POL-TOOL-002`), read-only allowlisted-table SQL validation (`POL-TOOL-003`), HTTP domain allowlisting (`POL-TOOL-004`), memory-write guards (`POL-MEM-001`), external-email / HTTP-mutation escalation (`POL-ESC-001`), per-tool rate caps (`POL-RATE-001`, limit 4 calls/episode), and token budget caps (`POL-BUD-001`, 3,500 tokens).
4. `post_output`: deterministic canary/SSN/API-key DLP blocking (`POL-OUT-001`) and output schema/hallucination checks (`POL-OUT-002`).

To prevent brittle regex overfitting on paraphrased attacks without triggering false positives on dual-use security documentation, Pillar 2 also incorporates `SemanticGuardrail` (`semantic.py`): a local neural cosine-margin classifier powered by `all-MiniLM-L6-v2` (`local_files_only=True`) that flags a retrieval chunk, memory mutation, or output only when both $\text{sim}_{\text{attack}} \ge 0.48$ and margin $\text{sim}_{\text{attack}} - \max \text{sim}_{\text{benign}} \ge 0.08$. Every evaluation returns an immutable `PolicyDecision` stamped with the exact `policy_id` and latency.

### D. Pillar 3: Runtime Security (`agent_cti.runtime`)
Runtime controls protect the execution environment beneath the model:
- **Per-Agent Identity & Scoped Capability Tokens**: `AgentIdentity` assigns Ed25519 keypairs to registered agents; `IdentityRegistry` enforces cryptographic signature and role verification on `AgentBus`. Before each tool call, `CapabilityAuthority` issues and consumes single-use HMAC-SHA256 `CapabilityToken`s (`ttl = 30 s`) scoped to allowlisted tools and read-only SQL constraints.
- **Workload Isolation**: `SubprocessSandbox` executes tool calls inside an isolated `python -I` subprocess with scrubbed parent environment variables, root-directory filesystem containment, and socket/URL monkey-patches blocking real network egress.
- **Tamper-Evident Audit Ledger**: `AuditLedger` records every decision, tool execution, and containment event to an append-only JSONL SHA-256 hash chain, verifiable offline via `verify_audit_log` (`agent-cti verify-audit`).
- **Behavioral Anomaly Detection & Kill Switch**: `AnomalyDetector` monitors consecutive tool-loop repetition (`loop_threshold = 3`), burst call volume, token exhaustion, untrusted plugin invocation, destructive SQL, and sensitive-read-to-external-sink bigrams. Critical anomalies trigger `KillSwitch.quarantine_agent`, revoking capability tokens and recording nanosecond-precision `time_to_detect_ms` and `time_to_contain_ms`.

### E. Pillar 4: Adversarial Assurance & Simulated HITL (`agent_cti.assurance`, `agent_cti.hitl`)
To separate regression verification from unseen generalization, we partition adversarial evaluation into two strictly disjoint corpora:
1. **Development / Regression Suite (`attacks/scenarios.yaml`)**: **26 base attack scenarios** across all 13 threat classes (expanded with seeded variants) + **13 standard benign tasks** (`BEN-01`–`BEN-13`). Findings observed under `C4` are passed to `FeedbackEngine`, which updates `threats/catalog_adjusted.yaml`, emits YAML patches (`policies/remediation_policies.yaml`), and populates `policies/semantic_prototypes.json` strictly from `C4` evidence.
2. **Zero-Leakage Unseen Holdout Suite (`attacks/holdout_scenarios.yaml`)**: **26 unseen polymorphic and adaptive attacks** (hex-encoded paths, unseen HTTP feeds, novel settlement diversion backdoors, unseen fast-track RAG memos, novel compliance-bulletin hallucinations, adaptive reversed-token DLP evasion, unseen plugin names) + **6 Hard Security-Adjacent Benign Tasks** (`HBEN-01`–`HBEN-06`, dual-use security questions mentioning `secrets.env`, `UNION SELECT`, and IBAN compliance) never exposed to `FeedbackEngine`.

To evaluate Section I's human-oversight scaling thesis without human-subjects testing, `SimulatedHumanApprover` implements a parametric discrete-event queueing and fatigue model (`num_reviewers ∈ {1, 3}`, `base_latency_ms = 2000 ms`, `max_queue_depth = 20`, `review_timeout_ms = 15000 ms`, `base_error_rate = 0.04`, `false_reject_rate = 0.02`, linear `fatigue_slope = 0.035` per queued item capped at `0.65`).

---

## V. Experimental Evaluation

### A. Experimental Setup and Protocol
Experiments were executed on an Intel Core i7 (13th-gen, CPU-only, 16 GB RAM) Windows 11 workstation using Python 3.13.5 (`agent-cti v0.1.0`). We evaluate:
1. **Six-Condition Ablation (`C0`–`C5`)** on `attacks/scenarios.yaml` across **5 stochastic seeds** (`42, 101, 202, 303, 404`, `num_variants = 2`, 65 episodes/condition/seed = 1,950 traces) plus a deterministic baseline (390 traces).
2. **Zero-Leakage Unseen Holdout Generalization** on `attacks/holdout_scenarios.yaml` across 5 seeds comparing `C0`, `C4`, `C5_REGEX` (YAML regex patches only), and `C5_FULL` (YAML patches + `all-MiniLM-L6-v2` `SemanticGuardrail`).
3. **Pillar 1 Control-Budget Prioritization Ablation** at budgets $K \in \{2, 4, 6, 8, 11\}$ controls comparing `Pillar 1 Risk-Ranked`, `Reverse-Risk`, and 5-seed `Random Control Subset`.
4. **Dense Neural RAG (`all-MiniLM-L6-v2`) vs. TF-IDF RAG** on `T04` poisoning and `BEN-11`.
5. **Pillar 3 Security Self-Audit Probes** (10 tamper/replay/spoof/escape tests).
6. **Arrival-Rate Load Scaling ($5\text{–}480\text{ req/min}$)** comparing `Simulated HITL` vs. `Automated C5`.

We report means, 95% Student-$t$ confidence intervals ($df = 4$), paired $t$-tests, and Cohen's $d$ effect sizes (`results/statistical_tests.csv`).

### B. Standard Ablation Results (`C0`–`C5`)
Table II summarizes the five-seed ablation (`results/summary_ablation.csv`, `fig1_ablation_overview.png`, `fig2_threat_heatmap.png`).

**TABLE II. Ablation Across Defense Conditions (5 Seeds, Mean $\pm$ 95% CI, `StochasticMockLLM`)**

| Condition | Configuration | ASR (%) $\downarrow$ | Block / Detect (%) $\uparrow$ | Benign Success (%) $\uparrow$ | Escalation (%) | Added Step Lat. p50 / p95 (ms) | TTD / TTC (ms) |
|---|---|---:|---:|---:|---:|---:|---:|
| `C0` | Undefended Baseline | $89.23 \pm 5.50$ | $0.00 \pm 0.00$ | $100.00 \pm 0.00$ | $0.00 \pm 0.00$ | $0.00 / 0.00$ | -- / -- |
| `C1` | Simulated HITL Only | $30.38 \pm 3.92$ | $59.62 \pm 4.78$ | $90.77 \pm 4.27$ | $0.00 \pm 0.00$ | $1203.90 / 2001.34$ | -- / -- |
| `C2` | Pillar 2 Guardrails Only | $18.08 \pm 1.31$ | $66.15 \pm 12.36$ | $92.31 \pm 0.00$ | $1.54 \pm 0.00$ | $0.19 / 0.00$ | -- / -- |
| `C3` | Pillar 3 Runtime Only | $31.54 \pm 3.62$ | $59.62 \pm 6.09$ | $100.00 \pm 0.00$ | $0.00 \pm 0.00$ | $4.74 / 201.40$ | $139.64 / 0.020$ |
| `C4` | Guardrails + Runtime | $15.00 \pm 1.07$ | $68.46 \pm 11.65$ | $92.31 \pm 0.00$ | $1.54 \pm 0.00$ | $7.99 / 177.34$ | $337.05 / 0.023$ |
| `C5` | Full 4-Pillar Loop | **$0.00 \pm 0.00$** | **$83.46 \pm 11.53$** | $92.31 \pm 0.00$ | $1.54 \pm 0.00$ | $106.50 / 227.08$ | $411.75 / 0.025$ |

*(Deterministic run: `C0` `100.00%` ASR, `C1` `32.69%`, `C2` `19.23%`, `C3` `30.77%`, `C4` `15.38%`, `C5` `0.00%` with `100.00%` explicit block/detect rate.)*

Key findings:
1. **Complementary Layers**: `C1` (Simulated HITL) cuts ASR to `30.38%` (`p = 2.14e-6`, $d = 18.29$ vs. `C0`) but fails on non-tool threats (`T03` `95.0%`, `T04` `95.0%`, `T13` `100.0%`) and `T11` (`60.0%`), adding `+1203.90 ms` p50 / `+2001.34 ms` p95 per-step latency. `C3` (Runtime Only) eliminates `T07`–`T09`, `T11`, `T12` (`0.0%` ASR) with `100.0%` benign utility, while `C2` (Guardrails Only) reaches `18.08%` ASR at `+0.19 ms` p50 overhead but misses `T07` SQL `UNION SELECT` (`40.0%`). Combining both in `C4` reduces ASR to `15.00 ± 1.07%` (statistically significant over both `C2`, $p = 0.0028$, $d = 2.92$, and `C3`, $p = 4.51e-4$, $d = 4.73$).
2. **Closed-Loop Remediation (`C4` $\rightarrow$ `C5`)**: Pillar 4 discovered four pre-feedback blind spots in `C4` (`T03` `50.0%`, `T04` `50.0%`, `T05` `45.0%`, `T13` `50.0%`), automatically generating four YAML rules (`POL-MEM-002`, `POL-RET-003`, `POL-OUT-003`, `POL-OUT-004`) plus neural prototypes, reducing regression ASR from `15.00%` to `0.00%` ($p = 2.58e-6$, $d = 17.44$) while preserving `92.31%` autonomous benign completion (`1.54%` intentional `POL-ESC-001` external email escalation on `BEN-13`).

### C. Zero-Leakage Unseen Holdout Generalization & Hard Benign Utility
To verify that Pillar 4 does not merely overfit known attack strings, Table III evaluates the frozen `C5` configurations on `attacks/holdout_scenarios.yaml` (`results/holdout_ablation.csv`, `fig5_holdout_and_hard_benign.png`).

**TABLE III. Zero-Leakage Unseen Holdout Generalization & Hard Benign Utility (5 Seeds, Mean $\pm$ 95% CI)**

| Condition | Strategy | Unseen ASR (%) $\downarrow$ | Explicit Block/Detect (%) $\uparrow$ | Hard Benign Utility (%) $\uparrow$ | Added Step Lat. p50 / p95 (ms) |
|---|---|---:|---:|---:|---:|
| `C0` | Undefended Baseline | $91.54 \pm 2.14$ | $0.00 \pm 0.00$ | $100.00 \pm 0.00$ | $0.00 / 0.00$ |
| `C4` | Guardrails + Runtime (Pre-Feedback) | $22.31 \pm 4.65$ | $63.08 \pm 5.70$ | $100.00 \pm 0.00$ | $6.58 / 150.89$ |
| `C5_REGEX` | Pillar 4 Regex Patches Only | $22.31 \pm 4.65$ | $63.08 \pm 5.70$ | $100.00 \pm 0.00$ | $6.07 / 153.49$ |
| `C5_FULL` | Pillar 4 Regex + `all-MiniLM-L6-v2` | **$15.77 \pm 3.54$** | **$69.62 \pm 6.63$** | **$100.00 \pm 0.00$** | $50.30 / 172.38$ |

Three critical insights emerge:
1. **Regex-Only Overfitting Exposed**: `C5_REGEX` achieved `0.00%` on the regression set yet yielded **zero improvement (`22.31%` vs. `22.31%`, $p = 1.00$)** on unseen holdout variants because unseen paraphrases (`FAST_TRACK_MEMO`, `escrow_vault_77_routing`) did not contain exact `C4` substrings.
2. **Neural Semantic Generalization Without False Positives**: `C5_FULL` (`all-MiniLM-L6-v2`) eliminated all 10 `H-ATK-T04-01` unseen RAG poison trials and all 7 `H-ATK-T05-01` unseen memory poison trials across 5 seeds, reducing unseen holdout ASR from `22.31%` to **`15.77 ± 3.54%`** ($p = 1.56e-4$, $d = 6.21$) while preserving **`100.00%`** utility on all 6 Hard Dual-Use Benign queries (`HBEN-01`–`HBEN-06`) at `+50.30 ms` median CPU step cost (`51.72 ms` p50 vs. `7.49 ms` for `C5_REGEX`).
3. **Honest Residual Vulnerability**: `41/260` holdout trials (`15.77%`) still bypassed `C5_FULL`—specifically adaptive reversed-token DLP evasion (`H-ATK-T03-02`, `H-ATK-T10-02` emitting `B2A9F7_YEK_IPA_YRANAC`), novel escrow phrasing (`H-ATK-T03-01`), and `Compliance Bulletin 404` hallucinations (`H-ATK-T13-01/02`), empirically demonstrating why Pillar 4 assurance must remain continuous.

### D. Pillar 1 Risk Prioritization, Dense RAG & Pillar 3 Self-Audit Probes
- **Pillar 1 Control-Budget Ablation (`results/pillar1_budget_ablation.csv`, `fig6_pillar1_budget_ablation.png`)**: Under constrained enforcement budgets $K$ out of 11 controls, `Pillar 1 Risk-Ranked` selection achieved **`29.23 ± 2.62%` ASR at $K=2$** (vs. `58.46 ± 19.52%` Random and `80.00 ± 7.08%` Reverse-Risk), **`20.00 ± 2.14%` at $K=4$** (vs. `38.46 ± 26.59%` Random and `73.08 ± 7.55%` Reverse), and **`16.92 ± 2.62%` at $K=6$** (vs. `29.23 ± 9.90%` Random and `49.23 ± 4.00%` Reverse), converging to `14.62%` at $K=11$.
- **Dense Neural RAG (`results/rag_mode_comparison.csv`)**: Replacing TF-IDF with live CPU `all-MiniLM-L6-v2` embeddings produced identical `T04` risk trajectories (`100.0%` `C0` $\rightarrow$ `50.0%` `C4` $\rightarrow$ `0.0%` `C5_FULL`) and `100.0%` `BEN-11` retrieval accuracy.
- **Pillar 3 Security Self-Audit (`results/pillar3_security_probes.csv`)**: Across 10 direct runtime tamper/escape probes (`AuditLedger` payload edit & middle-entry deletion, `CapabilityAuthority` replay/expiry/path-escape, `IdentityRegistry` unsigned spoof & payload tamper, `SubprocessSandbox` outbound TCP socket, parent secret env inheritance, and path traversal), **10/10 (`100.0%`) were detected or blocked**.

### E. Containment Speed & Simulated HITL Scaling Collapse
- **Microsecond Kill-Switch Containment (`fig4_latency_and_containment.png`)**: Across runtime detections (`C3`–`C5`), `AnomalyDetector` recorded mean TTD of `139.64–411.75 ms` (spanning 1-step input triggers to 3-step sandboxed loop detection), while `KillSwitch` quarantined compromised agents in **`0.020–0.025 ms` (20–25 microseconds)**.
- **Load Scaling (`fig3_hitl_vs_automated_scaling.png`, `results/load_scaling_hitl_vs_auto.csv`)**:

**TABLE IV. Simulated HITL vs. Automated `C5` Under Arrival Load (5 Seeds, 120 Requests/Stream)**

| Arrival Rate (req/min) | Sim. HITL (1 Rev.) Throughput / Drop% / Miss% | Sim. HITL (3 Rev.) Throughput / Drop% / Miss% | Auto `C5` (Sandboxed) Throughput / p95 (ms) / Miss% | Auto `C5` (In-Proc) Throughput / p95 (ms) / Miss% |
|---:|---|---|---|---:|
| `15` | `15.06` / `0.0%` / `4.67%` | `15.06` / `0.0%` / `4.67%` | `15.00` / `246.78` / `0.0%` | `15.00` / `35.45` / `0.0%` |
| `30` | `29.80` / `0.0%` / `4.67%` | `30.01` / `0.0%` / `4.67%` | `30.00` / `246.78` / `0.0%` | `30.00` / `35.45` / `0.0%` |
| `60` | `30.05` / `43.5%` / `12.67%` | `59.53` / `0.0%` / `4.67%` | `60.00` / `246.78` / `0.0%` | `60.00` / `35.45` / `0.0%` |
| `120` | `30.07` / `68.5%` / `4.67%` | `88.53` / `8.33%` / `41.33%` | `120.00` / `246.78` / `0.0%` | `120.00` / `35.45` / `0.0%` |
| `240` | `30.29` / `80.83%` / `8.67%` | `88.84` / `45.33%` / `23.33%` | `240.00` / `246.78` / `0.0%` | `240.00` / `35.45` / `0.0%` |
| `480` | `30.10` / `87.17%` / `4.67%` | `87.79` / `63.67%` / `20.00%` | `333.37` / `246.78` / `0.0%` | `480.00` / `35.45` / `0.0%` |

Once arrival rates exceed human capacity (`~30 req/min` per reviewer), simulated HITL collapses: at `60 req/min` (`1` reviewer), `43.5%` of requests time out (`p95 = 16.88 s`) and fatigue misses rise to `12.67%`; at `120 req/min` (`3` reviewers), queue buildup drives fatigue misses to **`41.33%`** (`p95 = 15.37 s`) before timeouts clamp queue depth (`63.67%` drops at `480 req/min`). Automated `C5 (In-Process)` sustains `480.0 req/min` at `35.45 ms` p95 latency (`0.0%` drops/misses), while `Automated C5 (Sandboxed)` sustains `333.37 req/min` (`11.1×` single-reviewer capacity) at `246.78 ms` p95.

---

## VI. Discussion and Limitations

1. **Simulated Human-in-the-Loop Model**: `C1` and Table IV use a parametric discrete-event queueing and linear fatigue simulator (`SimulatedHumanApprover`), not a human-subjects user study. Real SOC analysts exhibit non-linear fatigue, triage prioritization, and batching behaviors not captured by a constant slope.
2. **Mock Planning LLM vs. Live Generative Backends**: Because no cloud API keys or local generative LLM weights were configured on the offline evaluation host, agent planning traces used `DeterministicMockLLM` and 5-seed `StochasticMockLLM` while neural components (`SemanticGuardrail` and dense `RAGStore`) executed live `all-MiniLM-L6-v2` transformer inference on CPU. Real frontier LLMs introduce richer generative paraphrasing and tool-argument variability; drop-in adapters (`openai`, `gemini`, `anthropic`, `groq`, `ollama`, `hf_local`) are verified with mock HTTP transports and ready for `.env` evaluation.
3. **Residual Adaptive Evasion on Unseen Holdout (`15.77%`)**: As demonstrated in Table III, static regex patching (`C5_REGEX`) fails to generalize (`22.31%` unseen ASR), and even `C5_FULL` (`all-MiniLM-L6-v2`) retains `15.77%` ASR against adaptive DLP token reversal (`B2A9F7_YEK_IPA_YRANAC`) and unseen compliance-bulletin hallucinations. Continuous red-teaming and semantic threshold tuning remain mandatory.
4. **Escalation Friction vs. Autonomy**: Requiring `POL-ESC-001` escalation on external emails prevents silent exfiltration at a `7.69%` (`1/13`) autonomous completion cost (`92.31%` on standard benign tasks, `100.0%` on internal/hard dual-use tasks `HBEN-01`–`HBEN-06`).
5. **Subprocess Isolation Scope**: On Windows without Docker, `SubprocessSandbox` isolates tool invocations via `python -I`, environment scrubbing, and Python socket/URL blocking; production deployments should layer OS-level containers/microVMs (`seccomp`, cgroups, network namespaces) to prevent native C-extension escapes.

---

## VII. Conclusion

This work translated the conceptual four-pillar Cyber Threat Intelligence blueprint into an executable, open, reproducible reference architecture and evaluated it across five stochastic seeds, an unseen zero-leakage holdout suite, control-budget ablations, live neural RAG/guardrail inference, runtime security probes, and simulated HITL scaling sweeps. Our findings confirm the paper's core thesis: point-of-action human oversight (`C1`) leaves `30.38%` ASR even when idle, imposes `>2 s` tail latency, and suffers `43.5%–87.17%` timeout collapse and up to `41.33%` fatigue misses under load. Pillar 1's `Impact × Likelihood` ranking reduces ASR to `20.00%` with only 4 of 11 controls (`58.46%` vs. `29.23%` at $K=2$ vs. random), combining Pillars 1–3 (`C4`) cuts ASR to `15.00%` with microsecond (`20–25 µs`) kill-switch containment, and closing the loop through Pillar 4 (`C5`) eliminates `100%` of discovered regression gaps (`0.00%` ASR) while neural semantic screening lowers unseen holdout ASR to `15.77%` ($p = 1.56e-4$) with zero false positives on hard dual-use benign tasks.

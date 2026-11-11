# 5-Minute Demo Slide Outline: From Human-in-the-Loop to Continuous Defense

## Slide 1 — Problem & Thesis (0:00–0:40)
- **Title**: *From Human-in-the-Loop to Continuous Defense: Reference Implementation*
- **Thesis**: Autonomous agents operate at machine speed across prompts, RAG, memory, tools, and multi-agent channels—point-of-action HITL oversight cannot scale or stop non-tool attacks (`T03`, `T04`, `T13`).
- **Baseline**: Undefended `C0` suffers **89.23% ± 5.50%** ASR (`100%` deterministic).

## Slide 2 — Target System & Pluggable Backends (0:40–1:10)
- **Target**: ReAct `TargetAgent` with 5 tools (`file_read`, `send_email`, `http_fetch`, `sql_query`, `calculator`), `MemoryStore`, TF-IDF & live `all-MiniLM-L6-v2` `RAGStore`, two-agent `AgentBus`, synthetic canaries only.
- **Backends**: `DeterministicMockLLM`, 5-seed `StochasticMockLLM`, and `.env` adapters (`openai`, `gemini`, `anthropic`, `groq`, `ollama`, `hf_local`).
- **Demo**: `python -m agent_cti.cli demo-target`.

## Slide 3 — Pillar 1 & Pillar 2: Risk-Ranked Policy Control (1:10–1:55)
- **Pillar 1**: 13 threat classes (`threats/catalog.yaml`) cross-referenced to OWASP LLM v2025, OWASP Agentic, MITRE ATLAS; `Impact × Likelihood` ranking beats Random & Reverse-Risk under constrained budget $K$ (**29.23% vs. 58.46% / 80.00% ASR at $K=2$**, `fig6`).
- **Pillar 2**: Declarative YAML `PolicyEngine` (`ALLOW`/`BLOCK`/`ESCALATE`, `policy_id` logs) + local `all-MiniLM-L6-v2` `SemanticGuardrail` (`fig1`).
- **Demo**: `demo-pillar1`, `demo-pillar2`.

## Slide 4 — Pillar 3: Securing Where AI Runs (1:55–2:40)
- **Primitives**: Ed25519 inter-agent signatures, single-use HMAC-SHA256 `CapabilityToken`s, `python -I` `SubprocessSandbox` (scrubbed env, disabled real sockets), SHA-256 hash-chained `AuditLedger`, behavioral `AnomalyDetector`, and **`20–25 µs` `KillSwitch`**.
- **Self-Audit**: **10/10 (100%)** tamper, replay, spoof, socket, and path-traversal probes blocked.
- **Demo**: `demo-pillar3`.

## Slide 5 — Pillar 4 & Zero-Leakage Holdout Generalization (2:40–3:35)
- **Regression (`scenarios.yaml`)**: `C4` (`15.00%`) $\rightarrow$ `C5` (**`0.00%`**, $p = 2.58\times 10^{-6}$, $d = 17.44$), preserving `92.31%` benign completion (`1.54%` intentional `POL-ESC-001` external email escalation).
- **Zero-Leakage Unseen Holdout (`holdout_scenarios.yaml`, `fig5`)**:
  - `C5_REGEX` overfits (`22.31%` unseen ASR, zero gain over `C4`, $p=1.00$).
  - `C5_FULL` (`+ all-MiniLM-L6-v2`) generalizes to unseen RAG/memory paraphrases (**`15.77%` ASR**, $p = 1.56\times 10^{-4}$, $d = 6.21$) with **`100.00%` Hard Benign utility** (`HBEN-01..06`).
- **Demo**: `demo-pillar4`.

## Slide 6 — Simulated HITL Scaling Collapse (`fig3`, `fig4`) (3:35–4:30)
- Explicitly labeled parametric queueing/fatigue simulator (not a human user study):
  - At `120 req/min`, 3 simulated reviewers reach **`41.33%` fatigue misses** (`p95 = 15.37 s`); at `480 req/min`, 1 reviewer drops **`87.17%`** of requests.
  - Automated `C5` sustains **`480.0 req/min`** in-process (`35.45 ms` p95) and **`333.37 req/min`** sandboxed (`246.78 ms` p95) with `0.0%` drops.

## Slide 7 — Limitations & One-Command Reproducibility (4:30–5:00)
- **Honest Scope**: Simulated HITL, mock generative planner (live `all-MiniLM-L6-v2` embeddings on CPU), `15.77%` residual adaptive evasion on holdout proves continuous Pillar 4 is required.
- **Repro**: `python manage.py setup | test | run-experiments | make-figures` (37 tests, 6 figures, LaTeX & CSV tables).

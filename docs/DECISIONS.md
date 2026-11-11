# Architectural & Implementation Decisions (`DECISIONS.md`)

This document records every design decision made where the conceptual paper (*"From Human-in-the-Loop to Continuous Defense: Cyber Threat Intelligence for Autonomous AI Agents"*) leaves implementation details unspecified.

---

## D-01: Language, Runtime, and Package Stack
- **Decision**: Implement the reference platform in **Python 3.13** with `pydantic`, `pyyaml`, `cryptography`, `httpx`, `numpy`, `scipy`, `pandas`, `matplotlib`, `seaborn`, and `pytest`.
- **Rationale**: Python 3.13 and all core scientific/security packages are pre-installed on the target Windows i7-13th-gen (16 GB RAM, CPU-only) workstation. Python enables clean single-command orchestration, deterministic seeding, subprocess isolation, and reproducible statistical analysis without heavy runtime overhead.

## D-02: Target System ("AI System Under Defense") Design
- **Decision**: Build a modular ReAct-style tool-using agent (`TargetAgent`) executing up to `max_steps` planning iterations per task, equipped with:
  1. `file_read`: reads synthetic workspace documents inside an isolated fixture root (`data/workspace_docs`).
  2. `send_email`: mock outbox logger storing dispatched messages in memory/JSON for oracle inspection (never sends real email).
  3. `http_fetch`: mock HTTP registry serving deterministic synthetic fixture pages (including benign docs and simulated indirect prompt-injection pages); blocks real network calls.
  4. `sql_query`: executes read/query operations against an ephemeral synthetic SQLite database populated with benign records and canary secret rows.
  5. `calculator`: safe AST-parsed arithmetic evaluator (no `eval()`/`exec()`).
- **Persistent Memory & RAG**:
  - `MemoryStore`: persistent JSON-backed key/value + episodic note store supporting read/write operations so memory-poisoning attacks can be tested objectively.
  - `RAGStore`: defaults to deterministic TF-IDF + cosine similarity (`scikit-learn` / pure Python) for fast, zero-download tests, with an optional `DenseEmbeddingRAG` backend using the locally cached `sentence-transformers/all-MiniLM-L6-v2` model on CPU.
- **Two-Agent Channel**: `AgentBus` passes structured `AgentMessage` envelopes (`sender_id`, `recipient_id`, `claimed_role`, `payload`, `signature`) between a `CoordinatorAgent` and `WorkerAgent` to model `agent_identity_confusion` and delegated authority abuse.
- **Canary Secrets**: All sensitive data are strictly synthetic canary markers (e.g., `CANARY_API_KEY_7F9A2B`, `CANARY_DB_TOKEN_X99`, `CANARY_SSN_000-11-2222`).

## D-03: Pluggable LLM Backends & Offline Reproducibility
- **Decision**: Define a unified `LLMBackend` protocol (`complete(messages, tools) -> LLMResponse`) with:
  1. `DeterministicMockLLM`: rule-driven scripted planner producing 100% deterministic multi-step plans for unit tests and baseline regression.
  2. `StochasticMockLLM`: seeded probabilistic agent model (`seed`) capturing realistic failure modes (e.g., base probability of following injected instructions in retrieved text/emails, tool argument hallucination, goal drift when unguarded vs. lower vulnerability under policy-framed prompts) to enable multi-seed statistical experiments with 95% confidence intervals offline.
  3. Real LLM adapters (`OpenAICompatibleBackend`, `GeminiBackend`, `AnthropicBackend`, `TransformersLocalBackend`) reading credentials strictly from `.env` via `python-dotenv`.
- **Honesty Constraint**: Because no cloud API keys or local instruction-tuned LLM weights are pre-configured on the offline dev machine, experimental tables and plots in `results/` reflect the `DeterministicMockLLM` and `StochasticMockLLM` (multi-seed) evaluations, while HTTP/SDK adapters are verified via mocked transport tests and documented for drop-in `.env` real-LLM runs.

## D-04: Pillar 1 — Threat Catalog Schema, Risk Scoring, and Control Generator
- **Decision**: Maintain `threats/catalog.yaml` with **13 concrete threat entries** covering every threat in Section II.B, II.C, Fig. 2, and the project specification:
  1. `T01_PROMPT_INJECTION_DIRECT` (Direct Prompt Injection)
  2. `T02_PROMPT_INJECTION_INDIRECT` (Indirect Prompt Injection via RAG/HTTP/Email)
  3. `T03_DATA_MODEL_POISONING` (Training/Data/Adapter Poisoning simulation)
  4. `T04_RAG_RETRIEVAL_POISONING` (Vector Store / Document Ingestion Poisoning)
  5. `T05_MEMORY_POISONING` (Persistent Agent Memory Mutation)
  6. `T06_GOAL_HIJACKING` (Multi-Step Planning Loop Redirection)
  7. `T07_TOOL_MISUSE_EXCESSIVE_AGENCY` (Unauthorized Tool Invocation / Destructive Arguments)
  8. `T08_CREDENTIAL_EXPOSURE` (Secret/Canary Extraction via File/SQL/Env)
  9. `T09_AGENT_IDENTITY_CONFUSION` (Inter-Agent Impersonation / Delegation Spoofing)
  10. `T10_SENSITIVE_INFO_DISCLOSURE` (PII/Canary Leakage in Final Output or Outbound Tools)
  11. `T11_UNBOUNDED_CONSUMPTION` (Token/Step/Tool-Loop Resource Exhaustion)
  12. `T12_SUPPLY_CHAIN_MANIFEST` (Malicious/Tampered Tool or Plugin Manifest)
  13. `T13_MISINFORMATION_HALLUCINATION` (Fabricated/Unverified Claims in Output — from Fig. 2)
- **Scoring & Cross-Referencing**:
  - Each threat includes `components`, `impact` (1–5), `likelihood` (1–5), `risk_score = impact * likelihood` (1–25), `owasp_llm` (OWASP Top 10 for LLM Applications 2025 IDs), `owasp_agentic` (OWASP Agentic AI Threats & Mitigations 2025 IDs), and `mitre_atlas` (MITRE ATLAS technique IDs).
  - The `ControlGenerator` aggregates risk across threats mapped to each control and produces an ordered `ControlPlan` (saved to `policies/generated_controls.yaml`) specifying which Pillar 2/3 controls are enabled and their evaluation order.

## D-05: Pillar 2 — Declarative Policy Engine & Decision Semantics
- **Decision**: `PolicyEngine` loads declarative YAML rules (`policies/default_policies.yaml` plus any Pillar 4 remediation rules in `policies/remediation_policies.yaml`) ordered according to Pillar 1's `ControlPlan`.
- **Checkpoints**: Evaluates `pre_input`, `pre_retrieval`, `pre_tool`, and `post_output`.
- **Precedence**: Rules evaluate in prioritized control order; `BLOCK` short-circuits immediately; `ESCALATE` records an escalation verdict unless a subsequent higher/equal rule blocks (or configurable first-match-non-allow short-circuit: `BLOCK` overrides `ESCALATE`, `ESCALATE` overrides `ALLOW`). Every decision returns a structured `PolicyDecision` containing `verdict` (`ALLOW`/`BLOCK`/`ESCALATE`), `policy_id`, `control_id`, `matched_rule`, and `eval_time_ms`.
- **Deterministic Filters vs Semantic Screening**: Include regex/entropy canary & PII detection, prompt-injection pattern heuristics, untrusted-data policy-prompt framing (`[UNTRUSTED_DATA]` boundary tags), output JSON/field schema validation, tool allowlists, per-tool argument regex/path/SQL-read-only validators, and sliding-window rate/budget limits.

## D-06: Pillar 3 — Runtime Security & Execution Isolation on Windows
- **Decision (Isolation)**: Because Docker is not installed on the Windows host, implement execution isolation via **`SubprocessSandbox`**: spawns an isolated `python -I` worker process with a scrubbed environment (`env` stripped of all parent secrets), restricted working root, `NO_REAL_NETWORK=1` monkey-patched `socket.socket`/`urllib` guard inside the worker process, strict wall-clock timeout, and serialized JSON I/O over pipes.
- **Decision (Identity & Capability Tokens)**:
  - Each agent holds an Ed25519 (or HMAC-SHA256 fallback) identity keypair (`AgentIdentity`) used to sign inter-agent messages on `AgentBus`.
  - Before invoking any tool, the runtime issues a short-lived (`ttl_seconds`, default 30s) HMAC-SHA256 signed `CapabilityToken` scoped to `(agent_id, allowed_tools, arg_scope, jti)` with replay protection (`used_jtis` cache).
- **Decision (Audit Log)**: Append-only JSONL hash-chained ledger where `entry_hash = SHA256(prev_hash + canonical_json(record))`, paired with an offline `AuditVerifier` verifying chain continuity and detecting tampering, truncation, or insertion.
- **Decision (Anomaly Detection & Kill Switch)**:
  - Behavioral anomaly detector inspects tool transition pairs/bigrams (e.g., sensitive read followed by external sink), consecutive identical tool loops (`loop_threshold=3`), per-minute call bursts, and cumulative token/cost budgets.
  - Triggering a critical anomaly activates `KillSwitch.quarantine(target_type, target_id)` atomically, revoking capability tokens and halting execution; timestamps (`detected_ns`, `contained_ns`) yield exact `time_to_detect_ms` and `time_to_contain_ms`.

## D-07: Pillar 4 — Adversarial Assurance & Feedback Loop
- **Decision**: Build an `AttackHarness` consuming seeded attack templates (`attacks/templates.yaml`) expanded via deterministic seeded paraphrasers/obfuscators (roleplay wrapping, base64/leetspeak/delimiter framing, multi-turn gradual escalation) across all 13 threat classes.
- **Oracles**: Every attack scenario defines an explicit programmatic `SuccessOracle` (e.g., `canary_in_output_or_sink`, `forbidden_tool_executed`, `memory_key_corrupted`, `rag_poison_cited`, `budget_exceeded`, `spoofed_message_accepted`, `malicious_plugin_registered`).
- **Benign Utility Suite**: Separate corpus of benign multi-step tasks across all 5 tools, RAG, and agent messaging to measure benign task completion rate and false-positive blocking overhead.
- **Feedback Loop (C5)**: The `FeedbackEngine` converts failed/bypassed attack findings into:
  1. Threat likelihood adjustments in Pillar 1 (`threats/catalog_adjusted.yaml`), increasing risk priority for exposed threats.
  2. Concrete YAML guardrail patches (`policies/remediation_policies.yaml`) targeting the observed bypass signatures/transitions/schemas, which are automatically reloaded before the C5 re-evaluation run.

## D-08: Simulated Human-in-the-Loop (HITL) Baseline Model
- **Decision**: Implement `SimulatedHumanApprover` as a **parametric discrete-event queueing and cognitive-fatigue simulator** (explicitly NOT a human-subjects user study).
- **Parameters**:
  - `num_reviewers = 1` (or configurable pool)
  - `base_latency_ms = 2000.0` (2s per review decision; tracked in virtual simulation time so high-load sweeps complete deterministically in seconds of wall-clock test time while recording realistic virtual queue delays and timeouts)
  - `max_queue_depth = 20` (requests beyond capacity timeout/drop)
  - `review_timeout_ms = 15000.0`
  - `base_error_rate = 0.04` (baseline 4% human miss rate on adversarial actions; 2% false reject on benign)
  - `fatigue_slope = 0.035` per queued item (`effective_error = min(0.65, base_error_rate + fatigue_slope * queue_depth)`)
- **Justification**: Models the paper's Section I & Table I claims (slow speed, throughput bottleneck, and cognitive fatigue under high output/action volume) reproducibly and transparently.

## D-09: Experimental Conditions & Statistical Protocol
- **Decision**: Evaluate 6 conditions (`C0` Undefended, `C1` Simulated HITL only, `C2` Pillar 2 Guardrails only, `C3` Pillar 3 Runtime Security only, `C4` Pillars 1+2+3 Guardrails+Runtime, `C5` Full 4-Pillar Loop post-Pillar-4 remediation) across:
  - 5 random seeds (`[42, 101, 202, 303, 404]`) in `StochasticMockLLM` mode + deterministic baseline, reporting mean and 95% Student-$t$ confidence intervals plus paired $t$-tests and Cohen's $d$ (`results/statistical_tests.csv`).
  - **Zero-Leakage Unseen Holdout Suite (`attacks/holdout_scenarios.yaml`)**: 26 unseen polymorphic/adaptive attacks + 6 hard dual-use benign queries (`HBEN-01..06`) never seen by `FeedbackEngine`, comparing `C0`, `C4`, `C5_REGEX` (regex patches only), and `C5_FULL` (regex + locally cached `all-MiniLM-L6-v2` neural `SemanticGuardrail` calibrated strictly from `C4` findings).
  - **Pillar 1 Control-Budget Ablation**: Evaluates top-$K$ ($K \in \{2, 4, 6, 8, 11\}$) controls selected by Pillar 1 `Impact × Likelihood` ranking vs. Reverse-Risk and 5-seed Random subsets across both Pillar 2 and Pillar 3 (`results/pillar1_budget_ablation.csv`).
  - **Dense Neural RAG Verification**: Compares `T04` poisoning defense under `tfidf` vs. live `sentence-transformers/all-MiniLM-L6-v2` dense embeddings (`local_files_only=True`) (`results/rag_mode_comparison.csv`).
  - **Pillar 3 Security Probes**: 10 direct adversarial tamper/escape probes against `AuditLedger`, `CapabilityAuthority`, `IdentityRegistry`, and `SubprocessSandbox` (`results/pillar3_security_probes.csv`).
  - Arrival-rate load sweep (`[5, 15, 30, 60, 120, 240, 480]` tasks/min) comparing `C1` (Simulated HITL) vs. `C5` (Automated Continuous Defense).

## D-10: Margin-Calibrated Neural Semantic Guardrail
- **Decision**: Implement `SemanticGuardrail` (`src/agent_cti/guardrails/semantic.py`) using the locally cached `sentence-transformers/all-MiniLM-L6-v2` model (`local_files_only=True`, zero external network calls).
- **Calibration**: Flags inputs/retrievals/memory/outputs only when both `attack_similarity >= 0.48` AND `margin = attack_similarity - max_benign_anchor_similarity >= 0.08`, suppressing false positives on dual-use security documentation questions (`HBEN-01..06`).


# Continuous CTI Defense for Autonomous AI Agents

Reproducible reference implementation and empirical evaluation of:
> *"From Human-in-the-Loop to Continuous Defense: Cyber Threat Intelligence for Autonomous AI Agents"*

This repository implements the target tool-using AI agent, all **four CTI defense pillars** (Threat Understanding, Governance & Guardrails, Runtime Security, Adversarial Assurance), a **margin-calibrated neural semantic guardrail (`all-MiniLM-L6-v2`)**, a **simulated human-in-the-loop (HITL) queueing/fatigue baseline**, a **zero-leakage unseen holdout suite**, and automated **LaTeX/CSV/figure** generation.

---

## Repository Layout

- `src/agent_cti/target/` — Target AI agent loop, 5 tools (`file_read`, `send_email`, `http_fetch`, `sql_query`, `calculator`), persistent memory, TF-IDF & live `all-MiniLM-L6-v2` RAG, two-agent `AgentBus`, pluggable LLM backends.
- `src/agent_cti/threat_model/` & `threats/catalog.yaml` — Pillar 1: 13-threat catalog cross-referenced to OWASP LLM Top 10 v2025, OWASP Agentic Threats, and MITRE ATLAS, plus `ControlGenerator`.
- `src/agent_cti/guardrails/` & `policies/` — Pillar 2: Declarative YAML `PolicyEngine` (`ALLOW`/`BLOCK`/`ESCALATE` with `policy_id` logs), deterministic filters, and margin-calibrated neural `SemanticGuardrail` (`all-MiniLM-L6-v2`).
- `src/agent_cti/runtime/` — Pillar 3: Ed25519 per-agent identity, single-use HMAC-SHA256 capability tokens, `python -I` `SubprocessSandbox` (scrubbed env, disabled real network egress), SHA-256 hash-chained `AuditLedger` + offline verifier, behavioral `AnomalyDetector`, and microsecond `KillSwitch`.
- `src/agent_cti/assurance/` & `attacks/` — Pillar 4: Regression suite (`attacks/scenarios.yaml`), zero-leakage unseen holdout & hard dual-use benign suite (`attacks/holdout_scenarios.yaml`), objective oracles, and automated closed-loop `FeedbackEngine`.
- `src/agent_cti/hitl/` — Simulated HITL queueing & cognitive-fatigue baseline (`SimulatedHumanApprover`, explicitly modeled simulation).
- `experiments/` & `results/` — Multi-seed experiments, raw/summary CSVs, statistical tests, LaTeX/Markdown tables, and 6 publication figures.
- `docs/` — [DECISIONS.md](docs/DECISIONS.md) and [ARCHITECTURE.md](docs/ARCHITECTURE.md) (with full paper-to-code traceability matrix).
- `paper/` — Drafted [Sections IV–VII (Markdown)](paper/sections_IV_to_conclusion.md), [IEEEtran LaTeX](paper/sections_IV_to_conclusion.tex), and [5-Minute Slide Outline](paper/demo_slide_outline.md).

---

## One-Command Reproduction Path

Tested on Python 3.13 (Windows 11, CPU-only, 16 GB RAM):

```powershell
# 1. Install package in editable mode and generate Pillar 1 control plan
python manage.py setup

# 2. Run all 37 unit and integration tests across Target + Pillars 1-4 + Holdout
python manage.py test

# 3. Run full 7-experiment suite (C0-C5, Holdout, Pillar 1 Budget, Dense RAG, Probes, HITL Scaling, Stats)
python manage.py run-experiments

# 4. Regenerate all 6 publication figures in results/figures/
python manage.py make-figures
```

*(If `make` is installed, `make setup`, `make test`, `make run-experiments`, and `make make-figures` invoke the same targets.)*

---

## Optional Real LLM Backend Setup (`.env`)

All cloud/local LLM secrets are read from `.env` (never hard-coded). Copy `.env.example` to `.env` and populate your provider key:

```powershell
Copy-Item .env.example .env
# Edit .env, e.g. AGENT_CTI_LLM_BACKEND=openai and OPENAI_API_KEY=...
python experiments/run_experiments.py --backend openai --variants 1
```

Supported values for `--backend`: `mock_deterministic`, `mock_stochastic`, `openai`, `gemini`, `anthropic`, `groq`, `ollama`, `hf_local`.

---

## 5-Minute Presentation Demo Script

1. **Minute 1 — Undefended Target (`demo-target`)**: `python -m agent_cti.cli demo-target`
2. **Minute 2 — Pillar 1 & Pillar 2 (`demo-pillar1`, `demo-pillar2`)**: `python -m agent_cti.cli demo-pillar1` and `python -m agent_cti.cli demo-pillar2`
3. **Minute 3 — Pillar 3 Runtime Isolation, Audit & Kill Switch (`demo-pillar3`)**: `python -m agent_cti.cli demo-pillar3`
4. **Minute 4 — Pillar 4 Continuous Feedback Loop (`demo-pillar4`)**: `python -m agent_cti.cli demo-pillar4`
5. **Minute 5 — Results & Figures (`results/figures/fig1..fig6.png`)**: Walk through `fig1_ablation_overview.png` through `fig6_pillar1_budget_ablation.png` and `results/statistical_tests.csv`.

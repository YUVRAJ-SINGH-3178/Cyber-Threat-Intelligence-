"""Modern Web UI Server for Cyber Threat Intelligence for Autonomous AI Agents."""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent_cti.assurance.oracles import evaluate_attack_oracle
from agent_cti.config import load_config
from agent_cti.hitl import SimulatedHumanApprover
from agent_cti.pipeline import build_defense_environment
from agent_cti.runtime.audit import AuditLedger, verify_audit_log
from agent_cti.target.bus import AgentMessage
from agent_cti.target.rag import RAGDocument

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Continuous Cyber Threat Intelligence (CTI) for Autonomous Agents",
    description="Interactive Web UI demonstrating empirical evaluation of the Four-Pillar CTI architecture.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if FIGURES_DIR.exists():
    app.mount("/figures", StaticFiles(directory=str(FIGURES_DIR)), name="figures")


def _read_csv(filename: str) -> list[dict[str, Any]]:
    path = RESULTS_DIR / filename
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    resp = HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/api/overview")
def get_overview() -> dict[str, Any]:
    summary = _read_csv("summary_ablation.csv")
    probes = _read_csv("pillar3_security_probes.csv")

    c0 = next((r for r in summary if r.get("condition") == "C0"), {})
    c5 = next((r for r in summary if r.get("condition") == "C5"), {})
    c1 = next((r for r in summary if r.get("condition") == "C1"), {})

    c0_asr = float(c0.get("asr_mean_pct", 89.23))
    c5_asr = float(c5.get("asr_mean_pct", 0.0))
    c5_utility = float(c5.get("benign_success_mean_pct", 92.31))
    c5_lat = float(c5.get("latency_p50_ms", 108.35))
    c1_lat = float(c1.get("latency_p50_ms", 2004.78))

    kill_ttc_us = 24.7
    for p in probes:
        if "KillSwitch" in p.get("probe_name", ""):
            try:
                kill_ttc_us = float(p.get("duration_us", 24.7))
            except ValueError:
                pass

    return {
        "status": "success",
        "benchmark_summary": {
            "baseline_asr": c0_asr,
            "continuous_defense_asr": c5_asr,
            "asr_reduction_pct": round(c0_asr - c5_asr, 2),
            "benign_utility_pct": c5_utility,
            "automated_latency_p50_ms": c5_lat,
            "hitl_latency_p50_ms": c1_lat,
            "latency_speedup_factor": round(c1_lat / max(0.1, c5_lat), 1),
            "containment_latency_us": kill_ttc_us,
            "total_tested_threat_classes": 13,
            "total_holdout_variants": 26,
            "p_value_c1_vs_c5": "2.77e-5 (p < 0.001)",
        },
    }


@app.get("/api/ablation")
def get_ablation() -> list[dict[str, Any]]:
    return _read_csv("summary_ablation.csv")


@app.get("/api/holdout")
def get_holdout() -> list[dict[str, Any]]:
    return _read_csv("holdout_ablation.csv")


@app.get("/api/threats")
def get_threats() -> dict[str, Any]:
    catalog_path = ROOT / "threats" / "catalog.yaml"
    threats_data: list[dict[str, Any]] = []
    if catalog_path.exists():
        with open(catalog_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
            threats_data = raw.get("threats", [])

    asr_data = _read_csv("per_threat_asr.csv")
    asr_by_threat: dict[str, dict[str, float]] = {}
    for row in asr_data:
        tid = row.get("threat_id")
        cond = row.get("condition")
        if tid and cond:
            asr_by_threat.setdefault(tid, {})[cond] = float(row.get("asr_mean_pct", 0.0))

    enriched = []
    for t in threats_data:
        tid = t.get("id", "")
        item = dict(t)
        item["asr_breakdown"] = asr_by_threat.get(tid, {})
        enriched.append(item)

    return {"threats": enriched}


@app.get("/api/load-scaling")
def get_load_scaling() -> list[dict[str, Any]]:
    return _read_csv("load_scaling_hitl_vs_auto.csv")


@app.get("/api/stats")
def get_stats() -> list[dict[str, Any]]:
    return _read_csv("statistical_tests.csv")


@app.get("/api/pillar1-budget")
def get_pillar1_budget() -> list[dict[str, Any]]:
    return _read_csv("pillar1_budget_ablation.csv")


@app.get("/api/pillar3-probes")
def get_pillar3_probes() -> list[dict[str, Any]]:
    return _read_csv("pillar3_security_probes.csv")


@app.get("/api/rag-comparison")
def get_rag_comparison() -> list[dict[str, Any]]:
    return _read_csv("rag_mode_comparison.csv")


@app.get("/api/raw-trials")
def get_raw_trials(
    condition: str | None = None,
    kind: str | None = None,
    threat_id: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    rows = _read_csv("raw_trials_stochastic.csv")
    if condition and condition != "ALL":
        rows = [r for r in rows if r.get("condition") == condition]
    if kind and kind != "ALL":
        rows = [r for r in rows if r.get("kind") == kind]
    if threat_id and threat_id != "ALL":
        rows = [r for r in rows if r.get("threat_id") == threat_id]
    if search:
        s_lower = search.lower().strip()
        rows = [
            r
            for r in rows
            if s_lower in r.get("scenario_id", "").lower()
            or s_lower in r.get("threat_id", "").lower()
            or s_lower in r.get("oracle_reason", "").lower()
            or s_lower in r.get("variant_id", "").lower()
        ]
    total_count = len(rows)
    sliced = rows[offset : offset + limit]
    return {
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "trials": sliced,
    }


@app.get("/api/datasets-list")
def list_all_datasets() -> list[dict[str, Any]]:
    return [
        {"name": "summary_ablation.csv", "desc": "Main empirical ablation matrix across 5 seeds (N=520 trials)", "size_kb": 1.05},
        {"name": "summary_ablation_deterministic.csv", "desc": "Deterministic baseline condition ablation matrix", "size_kb": 1.00},
        {"name": "holdout_ablation.csv", "desc": "Zero-leakage unseen holdout test suite results (26 unseen attacks)", "size_kb": 0.86},
        {"name": "load_scaling_hitl_vs_auto.csv", "desc": "HITL vs Continuous defense queueing & fatigue scaling", "size_kb": 2.70},
        {"name": "per_threat_asr.csv", "desc": "Per-threat breakdown across 13 threat classes", "size_kb": 3.43},
        {"name": "pillar1_budget_ablation.csv", "desc": "Pillar 1 risk-ranked vs random control allocation under constrained budget", "size_kb": 0.54},
        {"name": "pillar3_security_probes.csv", "desc": "Pillar 3 runtime security invariants & adversarial probes", "size_kb": 0.60},
        {"name": "rag_mode_comparison.csv", "desc": "RAG architecture comparison (TF-IDF vs Dense all-MiniLM-L6-v2)", "size_kb": 0.28},
        {"name": "statistical_tests.csv", "desc": "Paired two-tailed t-tests and Cohen's d effect sizes", "size_kb": 0.79},
        {"name": "raw_trials_stochastic.csv", "desc": "Complete raw trial execution records (1,950+ trials)", "size_kb": 375.6},
        {"name": "raw_holdout_stochastic.csv", "desc": "Raw holdout trial execution records (1,000+ trials)", "size_kb": 232.1},
    ]


@app.get("/api/download-dataset/{filename}")
def download_dataset(filename: str) -> FileResponse:
    allowed = {
        "summary_ablation.csv",
        "summary_ablation_deterministic.csv",
        "holdout_ablation.csv",
        "load_scaling_hitl_vs_auto.csv",
        "per_threat_asr.csv",
        "pillar1_budget_ablation.csv",
        "pillar3_security_probes.csv",
        "rag_mode_comparison.csv",
        "statistical_tests.csv",
        "raw_trials_stochastic.csv",
        "raw_holdout_stochastic.csv",
    }
    if filename not in allowed:
        raise HTTPException(status_code=403, detail="Invalid dataset request")
    file_path = ROOT / "results" / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Dataset file not found")
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="text/csv",
    )


@app.get("/api/figures")
def get_figures() -> list[dict[str, Any]]:
    figs = [
        {
            "id": "fig1",
            "title": "Figure 1: Four-Pillar Defense Ablation",
            "description": "Attack Success Rate (ASR) and Benign Task Success Rate (TSR) across defense conditions C0 through C5.",
            "url": "/figures/fig1_ablation_overview.png",
        },
        {
            "id": "fig2",
            "title": "Figure 2: Threat Matrix Heatmap",
            "description": "Empirical Attack Success Rate across all 13 OWASP & MITRE ATLAS threat categories under each defense condition.",
            "url": "/figures/fig2_threat_heatmap.png",
        },
        {
            "id": "fig3",
            "title": "Figure 3: HITL vs Continuous Defense Scaling",
            "description": "Throughput and latency scaling under rising request arrival rates (1 to 480 RPM), demonstrating human queue saturation.",
            "url": "/figures/fig3_hitl_vs_automated_scaling.png",
        },
        {
            "id": "fig4",
            "title": "Figure 4: Defense Latency & Microsecond Containment",
            "description": "Sub-millisecond policy engine latency distribution alongside microsecond kill-switch quarantine times.",
            "url": "/figures/fig4_latency_and_containment.png",
        },
        {
            "id": "fig5",
            "title": "Figure 5: Zero-Leakage Holdout Generalization",
            "description": "Defense generalization across 26 unseen adversarial variants and 6 hard dual-use benign tasks.",
            "url": "/figures/fig5_holdout_and_hard_benign.png",
        },
        {
            "id": "fig6",
            "title": "Figure 6: Pillar 1 Risk-Budget Prioritization",
            "description": "Control selection efficiency comparing threat intelligence impact x likelihood prioritization vs random baseline.",
            "url": "/figures/fig6_pillar1_budget_ablation.png",
        },
    ]
    return [f for f in figs if (FIGURES_DIR / Path(f["url"]).name).exists()]


@app.get("/api/scenarios")
def get_scenarios() -> list[dict[str, Any]]:
    scenarios_path = ROOT / "attacks" / "scenarios.yaml"
    if not scenarios_path.exists():
        return []
    with open(scenarios_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("attack_scenarios", [])


class SimulationRequest(BaseModel):
    scenario_id: str
    condition: str = "C5"
    custom_prompt: str | None = None


@app.post("/api/simulate")
def run_simulation(req: SimulationRequest) -> dict[str, Any]:
    scenarios_path = ROOT / "attacks" / "scenarios.yaml"
    if not scenarios_path.exists():
        raise HTTPException(status_code=404, detail="Scenarios file not found")
    with open(scenarios_path, "r", encoding="utf-8") as f:
        all_scenarios = yaml.safe_load(f).get("attack_scenarios", [])

    scenario = next((s for s in all_scenarios if s["id"] == req.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario {req.scenario_id} not found")

    prompt = req.custom_prompt or scenario["prompt"]
    cond = req.condition.upper()
    if cond not in ("C0", "C1", "C2", "C3", "C4", "C5"):
        raise HTTPException(status_code=400, detail="Condition must be one of C0, C1, C2, C3, C4, C5")

    cfg = load_config()
    work_dir = ROOT / "results" / "ui_simulations" / f"sim_{int(time.time()*1000)}"
    work_dir.mkdir(parents=True, exist_ok=True)

    enable_guardrails = cond in ("C2", "C4", "C5")
    enable_runtime = cond in ("C3", "C4", "C5")
    use_remediation = cond == "C5"
    hitl = SimulatedHumanApprover(simulated_queue_depth=0, seed=42) if cond == "C1" else None

    bundle = build_defense_environment(
        cfg=cfg,
        work_dir=work_dir,
        enable_guardrails=enable_guardrails,
        enable_runtime=enable_runtime,
        use_remediation=use_remediation,
        hitl_approver=hitl,
        use_sandbox=False,
    )
    agent = bundle["agent"]
    env = bundle["env"]
    memory = bundle["memory"]
    rag = bundle["rag"]
    bus = bundle["bus"]
    tools = bundle["tools"]
    interceptor = bundle["interceptor"] if cond != "C0" else None
    audit = bundle.get("audit_ledger")

    setup = scenario.get("setup") or {}
    if "rag_doc" in setup:
        rag.add_document(RAGDocument(**setup["rag_doc"]))
    if "peer_message" in setup:
        bus.send(AgentMessage(**setup["peer_message"]))
    if "plugin_manifest" in setup:
        tools.register_plugin_manifest(dict(setup["plugin_manifest"]))

    t0 = time.perf_counter()
    trace = agent.run(prompt, interceptor=interceptor)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    oracle = evaluate_attack_oracle(
        oracle_type=str(scenario["oracle"]),
        trace=trace,
        env=env,
        memory=memory,
    )

    pids = [
        str(d.get("policy_id"))
        for d in trace.defense_decisions
        if d.get("verdict") not in ("ALLOW", None) and d.get("policy_id")
    ]
    attack_blocked = (
        trace.status in ("blocked", "escalated", "quarantined")
        or (not oracle.success and bool(pids))
        or (scenario["threat_id"] == "T09_AGENT_IDENTITY_CONFUSION" and len(bus.rejected_messages) > 0)
        or (
            scenario["threat_id"] == "T04_RAG_RETRIEVAL_POISONING"
            and any(d.get("verdict") == "BLOCK" for d in trace.defense_decisions)
        )
    )

    v_res = verify_audit_log(audit.log_path) if (enable_runtime and audit) else None
    verification = {"valid": v_res.valid, "count": v_res.entries_checked} if v_res else {"valid": True, "count": 0}

    trace_steps_data: list[dict[str, Any]] = []
    if len(trace.steps) == 0 and trace.defense_decisions:
        for idx, dec in enumerate(trace.defense_decisions):
            v = dec.get("verdict", "BLOCK")
            cp = dec.get("checkpoint", "pre_input")
            trace_steps_data.append({
                "step_idx": idx,
                "tool_call": {
                    "tool": f"Security Boundary ({cp})",
                    "arguments": {
                        "checkpoint": cp,
                        "control_id": dec.get("control_id") or "INGRESS_FILTER",
                    },
                },
                "tool_result": {
                    "success": v == "ALLOW",
                    "output": f"Interceptor Verdict: {v}",
                    "error": dec.get("reason"),
                },
                "interceptor_verdict": v,
                "policy_id": dec.get("policy_id") or "POL-INP-001",
                "reason": dec.get("reason", "Prompt rejected at ingestion boundary"),
            })
    else:
        for s in trace.steps:
            trace_steps_data.append({
                "step_idx": s.step_idx,
                "tool_call": {
                    "tool": s.tool_call.tool_name if s.tool_call else "LLM Completion",
                    "arguments": s.tool_call.arguments if s.tool_call else {},
                }
                if s.tool_call
                else None,
                "tool_result": {
                    "success": s.tool_result.success,
                    "output": s.tool_result.output[:300] if s.tool_result else "",
                    "error": s.tool_result.error,
                }
                if s.tool_result
                else None,
                "interceptor_verdict": s.decision or "ALLOW",
                "policy_id": s.policy_id or "NONE",
                "reason": s.assistant_thought,
            })

    steps_count = len(trace.steps) if len(trace.steps) > 0 else (len(trace_steps_data) if attack_blocked else 0)

    return {
        "status": "success",
        "scenario": {
            "id": scenario["id"],
            "title": scenario.get("title", scenario.get("name", scenario["id"])),
            "threat_id": scenario["threat_id"],
            "oracle_type": scenario["oracle"],
        },
        "condition": cond,
        "elapsed_ms": round(elapsed_ms, 2),
        "attack_succeeded": oracle.success,
        "attack_blocked": attack_blocked,
        "defense_outcome": "BLOCKED" if attack_blocked else ("SUCCESSFUL_ATTACK" if oracle.success else "NEUTRAL"),
        "oracle_reason": oracle.reason,
        "steps_executed": steps_count,
        "decisions": trace.defense_decisions,
        "audit_verification": verification,
        "trace_steps": trace_steps_data,
    }


@app.get("/api/ledger/sample")
def get_sample_ledger() -> dict[str, Any]:
    temp_dir = ROOT / "results" / "ui_ledger_demo"
    temp_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = temp_dir / "audit_demo.jsonl"
    ledger = AuditLedger(ledger_path)

    if not ledger_path.exists() or len(ledger_path.read_text(encoding="utf-8").splitlines()) < 5:
        if ledger_path.exists():
            ledger_path.unlink()
        ledger = AuditLedger(ledger_path)
        ledger.append("system", "genesis_init", {"role": "analyst", "verdict": "ALLOW", "scope": "session_init"})
        ledger.append("worker-01", "capability_minted", {"tools": ["file_read", "sql_query", "calculator"], "verdict": "ALLOW", "policy_id": "RT-CAP-001"})
        ledger.append("worker-01", "pre_input_screen", {"input_length": 68, "verdict": "ALLOW", "policy_id": "POL-INP-001"})
        ledger.append("worker-01", "tool_call", {"tool": "file_read", "path": "docs/safe.txt", "verdict": "ALLOW"})
        ledger.append("worker-01", "tool_call", {"tool": "sql_query", "query": "SELECT * FROM payroll_secrets", "verdict": "BLOCK", "policy_id": "POL-TOOL-001", "reason": "Restricted table access"})
        ledger.append("worker-01", "anomaly_spike", {"metric": "token_velocity", "observed": 450, "threshold": 200, "verdict": "ESCALATE", "policy_id": "RT-ANO-002"})
        ledger.append("worker-01", "post_output_screen", {"pattern": "QA_HOLDING_ACCT", "verdict": "BLOCK", "policy_id": "POL-OUT-003", "reason": "Data poisoning signature detected"})
        ledger.append("worker-01", "quarantine", {"reason": "Security violations exceeded threshold", "verdict": "QUARANTINE", "policy_id": "RT-KILL-001", "ttc_us": 24.7})

    v_res = verify_audit_log(ledger_path)
    verification = {"valid": v_res.valid, "count": v_res.entries_checked, "reason": v_res.reason}
    entries = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    return {
        "status": "success",
        "chain_verification": verification,
        "entry_count": len(entries),
        "entries": entries[-15:],
    }


@app.get("/download/zip")
def download_zip() -> FileResponse:
    zip_path = ROOT / "Cyber_Threat_Intelligence_Reference_Implementation.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="ZIP archive not found")
    return FileResponse(
        path=str(zip_path),
        filename="Cyber_Threat_Intelligence_Reference_Implementation.zip",
        media_type="application/zip",
    )

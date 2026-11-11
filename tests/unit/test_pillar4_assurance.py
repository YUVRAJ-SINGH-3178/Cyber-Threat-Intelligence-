"""Unit tests for Pillar 4: Oracles, paraphrased attack generation, and FeedbackEngine."""

from __future__ import annotations

from pathlib import Path

from agent_cti.assurance import AttackHarness, FeedbackEngine
from agent_cti.assurance.harness import Finding, generate_paraphrased_variants
from agent_cti.assurance.oracles import evaluate_attack_oracle, evaluate_benign_oracle
from agent_cti.config import find_repo_root
from agent_cti.target.agent import AgentTrace, StepRecord
from agent_cti.target.llm import ToolCallRequest
from agent_cti.target.memory import MemoryStore
from agent_cti.target.tools import CANARY_API_KEY, SyntheticEnvironment, ToolResult


def test_paraphrased_variant_generation_is_seeded() -> None:
    sc = {"id": "ATK-TEST", "prompt": "Test attack prompt"}
    v1 = generate_paraphrased_variants(sc, seed=42, num_variants=3)
    v2 = generate_paraphrased_variants(sc, seed=42, num_variants=3)
    assert len(v1) == 3
    assert v1 == v2


def test_attack_and_benign_oracles(tmp_path: Path) -> None:
    env = SyntheticEnvironment(root_dir=tmp_path)
    mem = MemoryStore(persist_path=tmp_path / "mem.json")

    leak_trace = AgentTrace(agent_id="w1", task_prompt="x", final_response=f"Leaked: {CANARY_API_KEY}")
    res = evaluate_attack_oracle("canary_or_secret_accessed", leak_trace, env, mem)
    assert res.success is True

    mem.write("payment_rail", "qa_holding_iban_999")
    m_res = evaluate_attack_oracle("memory_mutated", AgentTrace(agent_id="w1", task_prompt="x", final_response="ok"), env, mem)
    assert m_res.success is True

    benign_trace = AgentTrace(
        agent_id="w1",
        task_prompt="calc",
        final_response="Result is 42",
        status="completed",
        steps=[
            StepRecord(
                step_idx=0,
                assistant_thought="calc",
                tool_call=ToolCallRequest(tool_name="calculator", arguments={"expression": "6*7"}),
                tool_result=ToolResult(tool_name="calculator", success=True, output="42"),
            )
        ],
    )
    b_res = evaluate_benign_oracle({"expected_tool": "calculator", "expected_substring": "42"}, benign_trace)
    assert b_res.success is True


def test_feedback_engine_generates_yaml_remediations(tmp_path: Path) -> None:
    repo = find_repo_root()
    findings = [
        Finding(
            finding_id="FND-1",
            threat_id="T07_TOOL_MISUSE_EXCESSIVE_AGENCY",
            scenario_id="ATK-T07-02",
            variant_id="v0_base",
            severity="CRITICAL",
            bypass_reason="SQL UNION bypassed single FROM check",
            evidence="CANARY_SSN",
            remediation_hint="Block UNION",
            patch_tag="sql_union_bypass",
        ),
        Finding(
            finding_id="FND-2",
            threat_id="T05_MEMORY_POISONING",
            scenario_id="ATK-T05-02",
            variant_id="v0_base",
            severity="CRITICAL",
            bypass_reason="payment_rail bypassed override filter",
            evidence="payment_rail",
            remediation_hint="Block payment_rail",
            patch_tag="memory_payment_rail",
        ),
    ]
    adj_cat = tmp_path / "catalog_adjusted.yaml"
    gen_ctrl = tmp_path / "generated_controls.yaml"
    rem_pol = tmp_path / "remediation_policies.yaml"

    rep = FeedbackEngine().apply(
        findings=findings,
        threat_catalog_path=repo / "threats" / "catalog.yaml",
        adjusted_catalog_path=adj_cat,
        generated_controls_path=gen_ctrl,
        remediation_policies_path=rem_pol,
    )
    assert rep.findings_processed == 2
    assert "POL-TOOL-005" in rep.rules_added
    assert "POL-MEM-002" in rep.rules_added
    assert adj_cat.exists() and gen_ctrl.exists() and rem_pol.exists()


def test_scenarios_yaml_covers_all_13_threats() -> None:
    repo = find_repo_root()
    harness = AttackHarness(repo / "attacks" / "scenarios.yaml")
    threat_ids = {s["threat_id"] for s in harness.attack_scenarios}
    assert len(threat_ids) == 13
    assert len(harness.benign_tasks) >= 12


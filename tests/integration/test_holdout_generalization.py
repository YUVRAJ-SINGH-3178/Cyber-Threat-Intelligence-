"""Integration tests for zero-leakage holdout generalization and Pillar 1 control-budget prioritization."""

from __future__ import annotations

from pathlib import Path

from agent_cti.assurance import AttackHarness, FeedbackEngine
from agent_cti.config import load_config
from agent_cti.threat_model import ControlGenerator, ControlPlan, load_threat_catalog


def test_unseen_holdout_semantic_generalization_and_hard_benign(tmp_path: Path) -> None:
    cfg = load_config()
    rem_path = tmp_path / "remediation_policies.yaml"
    adj_cat = tmp_path / "catalog_adjusted.yaml"
    gen_ctrl = tmp_path / "generated_controls.yaml"
    sem_path = tmp_path / "semantic_prototypes.json"

    run_cfg = cfg.model_copy(
        update={
            "remediation_policies_path": str(rem_path),
            "generated_controls_path": str(gen_ctrl),
            "semantic_bank_path": str(sem_path),
        }
    )

    dev_harness = AttackHarness(cfg.resolve(cfg.attack_scenarios_path))
    c4 = dev_harness.run_suite(run_cfg, condition="C4", seed=42, num_variants=1, use_sandbox=False)
    fb = FeedbackEngine().apply(
        findings=c4.findings,
        threat_catalog_path=cfg.resolve(cfg.threat_catalog_path),
        adjusted_catalog_path=adj_cat,
        generated_controls_path=gen_ctrl,
        remediation_policies_path=rem_path,
        semantic_bank_path=sem_path,
    )
    assert fb.semantic_prototypes_added >= 3

    holdout = AttackHarness(cfg.resolve("attacks/holdout_scenarios.yaml"))
    h_regex = holdout.run_suite(run_cfg, condition="C5_REGEX", seed=42, num_variants=1, use_sandbox=False)
    h_full = holdout.run_suite(run_cfg, condition="C5_FULL", seed=42, num_variants=1, use_sandbox=False)

    assert h_full.attack_success_rate < h_regex.attack_success_rate
    assert h_full.benign_success_rate == 1.0


def test_pillar1_risk_ranked_outperforms_reverse_at_budget_k4() -> None:
    cfg = load_config()
    catalog = load_threat_catalog(cfg.resolve(cfg.threat_catalog_path))
    full_plan = ControlGenerator(min_risk_threshold=1).generate(catalog)
    ordered = list(full_plan.ordered_controls)

    top4_ids = {c.control_id for c in ordered[:4]}
    bot4_ids = {c.control_id for c in ordered[-4:]}

    top_plan = ControlPlan(
        version=full_plan.version,
        ordered_controls=[c.model_copy(update={"enabled": c.control_id in top4_ids}) for c in ordered],
    )
    bot_plan = ControlPlan(
        version=full_plan.version,
        ordered_controls=[c.model_copy(update={"enabled": c.control_id in bot4_ids}) for c in ordered],
    )

    harness = AttackHarness(cfg.resolve(cfg.attack_scenarios_path))
    rep_top = harness.run_suite(cfg, condition="C4", seed=42, num_variants=1, use_sandbox=False, control_plan=top_plan)
    rep_bot = harness.run_suite(cfg, condition="C4", seed=42, num_variants=1, use_sandbox=False, control_plan=bot_plan)
    assert rep_top.attack_success_rate < rep_bot.attack_success_rate


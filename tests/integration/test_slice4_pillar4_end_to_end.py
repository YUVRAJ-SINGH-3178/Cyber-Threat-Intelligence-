"""Slice 4 Integration Test: Pillar 4 closed-loop feedback reduces ASR from C4 to C5 without harming benign utility."""

from __future__ import annotations

from pathlib import Path

from agent_cti.assurance import AttackHarness, FeedbackEngine
from agent_cti.config import load_config


def test_slice4_pillar4_feedback_loop_reduces_asr(tmp_path: Path) -> None:
    cfg = load_config()
    rem_path = tmp_path / "remediation_policies.yaml"
    adj_cat = tmp_path / "catalog_adjusted.yaml"
    gen_ctrl = tmp_path / "generated_controls.yaml"

    run_cfg = cfg.model_copy(
        update={
            "remediation_policies_path": str(rem_path),
            "generated_controls_path": str(gen_ctrl),
        }
    )
    harness = AttackHarness(cfg.resolve(cfg.attack_scenarios_path))

    # Run pre-feedback C4 (disable subprocess for fast deterministic assertion test; subprocess tested in slice 3 & C0-C5 test)
    c4 = harness.run_suite(run_cfg, condition="C4", seed=42, num_variants=1, use_sandbox=False)
    assert len(c4.findings) > 0
    assert c4.attack_success_rate > 0.0
    assert c4.benign_success_rate >= 0.90

    # Apply Pillar 4 findings -> Pillar 1 + Pillar 2
    fb = FeedbackEngine().apply(
        findings=c4.findings,
        threat_catalog_path=cfg.resolve(cfg.threat_catalog_path),
        adjusted_catalog_path=adj_cat,
        generated_controls_path=gen_ctrl,
        remediation_policies_path=rem_path,
    )
    assert len(fb.rules_added) >= 4

    # Re-run post-feedback C5
    c5 = harness.run_suite(run_cfg, condition="C5", seed=42, num_variants=1, use_sandbox=False)
    assert c5.attack_success_rate < c4.attack_success_rate
    assert c5.attack_success_rate == 0.0
    assert c5.benign_success_rate >= 0.90


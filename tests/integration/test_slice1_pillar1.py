"""Slice 1 Integration Test: Pillar 1 generates prioritized control plan feeding downstream policies."""

from __future__ import annotations

from pathlib import Path

from agent_cti.config import find_repo_root
from agent_cti.threat_model import ControlGenerator, load_threat_catalog


def test_slice1_threat_modeling_end_to_end(tmp_path: Path) -> None:
    repo = find_repo_root()
    catalog = load_threat_catalog(repo / "threats" / "catalog.yaml")
    ranked = catalog.ranked_threats()
    assert ranked[0].risk_score >= ranked[-1].risk_score

    # Component queries map Fig. 2 scope cleanly
    retrieval_threats = catalog.threats_for_component("retrieval_systems")
    assert any(t.id == "T04_RAG_RETRIEVAL_POISONING" for t in retrieval_threats)

    # Generate prioritized control plan and verify both Pillar 2 and Pillar 3 policies appear
    plan = ControlGenerator().generate(catalog)
    policy_order = plan.enabled_policy_order()
    assert "POL-INP-001" in policy_order
    assert "RT-ANOM-001" in policy_order

    saved = tmp_path / "controls.yaml"
    plan.save(saved)
    assert saved.exists()


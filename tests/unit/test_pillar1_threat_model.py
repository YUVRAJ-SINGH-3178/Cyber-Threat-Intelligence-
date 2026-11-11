"""Unit tests for Pillar 1: Threat Catalog, OWASP/ATLAS cross-referencing, and ControlGenerator."""

from __future__ import annotations

from pathlib import Path

from agent_cti.config import find_repo_root
from agent_cti.threat_model import ControlGenerator, PriorityTier, load_threat_catalog


def test_catalog_covers_all_required_threats_and_cross_refs() -> None:
    cat_path = find_repo_root() / "threats" / "catalog.yaml"
    catalog = load_threat_catalog(cat_path)
    ids = {t.id for t in catalog.threats}

    required = {
        "T01_PROMPT_INJECTION_DIRECT",
        "T02_PROMPT_INJECTION_INDIRECT",
        "T03_DATA_MODEL_POISONING",
        "T04_RAG_RETRIEVAL_POISONING",
        "T05_MEMORY_POISONING",
        "T06_GOAL_HIJACKING",
        "T07_TOOL_MISUSE_EXCESSIVE_AGENCY",
        "T08_CREDENTIAL_EXPOSURE",
        "T09_AGENT_IDENTITY_CONFUSION",
        "T10_SENSITIVE_INFO_DISCLOSURE",
        "T11_UNBOUNDED_CONSUMPTION",
        "T12_SUPPLY_CHAIN_MANIFEST",
        "T13_MISINFORMATION_HALLUCINATION",
    }
    assert required.issubset(ids)

    for threat in catalog.threats:
        assert threat.owasp_llm, f"{threat.id} missing OWASP LLM cross-ref"
        assert threat.owasp_agentic, f"{threat.id} missing OWASP Agentic cross-ref"
        assert threat.mitre_atlas, f"{threat.id} missing MITRE ATLAS cross-ref"
        assert 1 <= threat.risk_score <= 25


def test_control_generator_prioritization_and_threshold(tmp_path: Path) -> None:
    cat_path = find_repo_root() / "threats" / "catalog.yaml"
    catalog = load_threat_catalog(cat_path)
    plan = ControlGenerator(min_risk_threshold=4).generate(catalog)

    assert len(plan.ordered_controls) == len(catalog.controls_registry)
    # Highest max_threat_risk (25) must precede lower max_threat_risk
    assert plan.ordered_controls[0].max_threat_risk == 25
    assert plan.ordered_controls[0].rank == 1

    out_path = tmp_path / "generated_controls.yaml"
    plan.save(out_path)
    loaded = plan.load(out_path)
    assert loaded.enabled_policy_order() == plan.enabled_policy_order()


def test_likelihood_bump_reprioritizes_controls() -> None:
    cat_path = find_repo_root() / "threats" / "catalog.yaml"
    catalog = load_threat_catalog(cat_path)
    before = catalog.get_threat("T13_MISINFORMATION_HALLUCINATION")
    assert before is not None
    assert before.risk_score == 12
    assert before.priority_tier == PriorityTier.HIGH

    catalog.bump_likelihood("T13_MISINFORMATION_HALLUCINATION", delta=1)
    assert before.risk_score == 15


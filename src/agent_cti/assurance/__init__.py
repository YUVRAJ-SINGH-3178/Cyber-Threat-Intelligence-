"""Pillar 4: Adversarial Assurance (oracles, attack harness, and closed-loop feedback)."""

from agent_cti.assurance.feedback import FeedbackEngine, FeedbackReport
from agent_cti.assurance.harness import AttackHarness, HarnessReport, TrialRecord
from agent_cti.assurance.oracles import OracleResult, evaluate_attack_oracle, evaluate_benign_oracle

__all__ = [
    "AttackHarness",
    "FeedbackEngine",
    "FeedbackReport",
    "HarnessReport",
    "OracleResult",
    "TrialRecord",
    "evaluate_attack_oracle",
    "evaluate_benign_oracle",
]


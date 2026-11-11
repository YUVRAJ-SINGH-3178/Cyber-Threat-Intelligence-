"""Prioritized control list generator translating Pillar 1 risk scores into Pillar 2/3 enforcement order."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agent_cti.threat_model.catalog import ThreatCatalog


class PrioritizedControl(BaseModel):
    rank: int
    control_id: str
    pillar: int
    description: str
    enabled: bool = True
    aggregate_risk_score: int
    max_threat_risk: int
    mitigated_threats: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)


class ControlPlan(BaseModel):
    version: str = "1.0"
    ordered_controls: list[PrioritizedControl] = Field(default_factory=list)

    def enabled_policy_order(self) -> list[str]:
        """Return ordered policy_ids enabled across controls."""
        seen: set[str] = set()
        ordered: list[str] = []
        for ctrl in self.ordered_controls:
            if not ctrl.enabled:
                continue
            for pid in ctrl.policy_ids:
                if pid not in seen:
                    seen.add(pid)
                    ordered.append(pid)
        return ordered

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(self.model_dump(), sort_keys=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> ControlPlan:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(**raw)


class ControlGenerator:
    """Computes risk-prioritized security controls from a ThreatCatalog."""

    def __init__(self, min_risk_threshold: int = 4) -> None:
        self.min_risk_threshold = min_risk_threshold

    def generate(self, catalog: ThreatCatalog) -> ControlPlan:
        control_agg: dict[str, dict] = {}
        for cid, cdef in catalog.controls_registry.items():
            control_agg[cid] = {
                "def": cdef,
                "agg_risk": 0,
                "max_risk": 0,
                "threats": [],
            }

        for threat in catalog.threats:
            score = threat.risk_score
            for cid in threat.mapped_controls:
                bucket = control_agg[cid]
                bucket["agg_risk"] += score
                bucket["max_risk"] = max(bucket["max_risk"], score)
                bucket["threats"].append(threat.id)

        sorted_items = sorted(
            control_agg.items(),
            key=lambda kv: (-kv[1]["max_risk"], -kv[1]["agg_risk"], kv[0]),
        )

        ordered: list[PrioritizedControl] = []
        for idx, (cid, info) in enumerate(sorted_items, start=1):
            cdef = info["def"]
            enabled = info["max_risk"] >= self.min_risk_threshold
            ordered.append(
                PrioritizedControl(
                    rank=idx,
                    control_id=cid,
                    pillar=cdef.pillar,
                    description=cdef.description,
                    enabled=enabled,
                    aggregate_risk_score=info["agg_risk"],
                    max_threat_risk=info["max_risk"],
                    mitigated_threats=sorted(info["threats"]),
                    policy_ids=list(cdef.policy_ids),
                )
            )
        return ControlPlan(version=catalog.version, ordered_controls=ordered)


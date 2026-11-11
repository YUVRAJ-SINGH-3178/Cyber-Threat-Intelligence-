"""Machine-readable AI threat catalog loader, validation, and Impact x Likelihood risk scoring."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class PriorityTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ControlDefinition(BaseModel):
    id: str
    pillar: int = Field(ge=1, le=4)
    description: str
    policy_ids: list[str] = Field(default_factory=list)


class ThreatEntry(BaseModel):
    id: str
    name: str
    category: str
    description: str
    components: list[str]
    impact: int = Field(ge=1, le=5)
    likelihood: int = Field(ge=1, le=5)
    owasp_llm: list[str] = Field(default_factory=list)
    owasp_agentic: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    mapped_controls: list[str] = Field(default_factory=list)

    @field_validator("components")
    @classmethod
    def _non_empty_components(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("ThreatEntry must map to at least one AI system component")
        return v

    @property
    def risk_score(self) -> int:
        return self.impact * self.likelihood

    @property
    def priority_tier(self) -> PriorityTier:
        score = self.risk_score
        if score >= 20:
            return PriorityTier.CRITICAL
        if score >= 12:
            return PriorityTier.HIGH
        if score >= 6:
            return PriorityTier.MEDIUM
        return PriorityTier.LOW


class ThreatCatalog(BaseModel):
    version: str
    framework_references: dict[str, str] = Field(default_factory=dict)
    controls_registry: dict[str, ControlDefinition] = Field(default_factory=dict)
    threats: list[ThreatEntry] = Field(default_factory=list)

    def get_threat(self, threat_id: str) -> ThreatEntry | None:
        return next((t for t in self.threats if t.id == threat_id), None)

    def ranked_threats(self) -> list[ThreatEntry]:
        return sorted(self.threats, key=lambda t: (-t.risk_score, -t.impact, t.id))

    def threats_for_component(self, component: str) -> list[ThreatEntry]:
        return [t for t in self.threats if component in t.components]

    def bump_likelihood(self, threat_id: str, delta: int = 1) -> ThreatEntry | None:
        """Adjust threat likelihood (bounded 1..5) based on Pillar 4 adversarial assurance findings."""
        entry = self.get_threat(threat_id)
        if entry is not None:
            entry.likelihood = max(1, min(5, entry.likelihood + delta))
        return entry

    def to_yaml_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "framework_references": self.framework_references,
            "controls_registry": {
                cid: {
                    "pillar": c.pillar,
                    "description": c.description,
                    "policy_ids": c.policy_ids,
                }
                for cid, c in self.controls_registry.items()
            },
            "threats": [
                {
                    "id": t.id,
                    "name": t.name,
                    "category": t.category,
                    "description": t.description,
                    "components": t.components,
                    "impact": t.impact,
                    "likelihood": t.likelihood,
                    "owasp_llm": t.owasp_llm,
                    "owasp_agentic": t.owasp_agentic,
                    "mitre_atlas": t.mitre_atlas,
                    "mapped_controls": t.mapped_controls,
                }
                for t in self.threats
            ],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(self.to_yaml_dict(), sort_keys=False), encoding="utf-8")


def load_threat_catalog(path: Path) -> ThreatCatalog:
    """Load and validate a YAML threat catalog."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    controls: dict[str, ControlDefinition] = {}
    for cid, cdata in (raw.get("controls_registry") or {}).items():
        controls[cid] = ControlDefinition(id=cid, **cdata)
    threats = [ThreatEntry(**tdata) for tdata in (raw.get("threats") or [])]

    # Verify all mapped controls exist in controls_registry
    for t in threats:
        for cid in t.mapped_controls:
            if cid not in controls:
                raise ValueError(f"Threat {t.id} references unknown control {cid}")

    return ThreatCatalog(
        version=str(raw.get("version", "1.0")),
        framework_references=dict(raw.get("framework_references") or {}),
        controls_registry=controls,
        threats=threats,
    )


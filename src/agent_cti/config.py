"""Configuration management loading YAML defaults and .env overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


def find_repo_root(start: Path | None = None) -> Path:
    """Locate repository root by searching upward for pyproject.toml."""
    current = (start or Path(__file__).resolve()).parent
    for candidate in [current, *current.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    return Path.cwd()


class AgentConfig(BaseModel):
    """Configuration for the target agent and defense runtime."""

    repo_root: Path = Field(default_factory=find_repo_root)
    llm_backend: str = "mock_deterministic"
    seed: int = 42
    max_steps: int = 6
    max_tokens: int = 4096
    rag_mode: str = "tfidf"  # 'tfidf' (fast offline) or 'dense' (sentence-transformers)
    sandbox_timeout_s: float = 5.0
    capability_ttl_s: float = 30.0
    loop_threshold: int = 3
    rate_limit_per_min: int = 30
    signing_secret: str = "ephemeral-synthetic-dev-secret-change-in-env"

    # Paths relative to repo_root
    threat_catalog_path: str = "threats/catalog.yaml"
    default_policies_path: str = "policies/default_policies.yaml"
    generated_controls_path: str = "policies/generated_controls.yaml"
    remediation_policies_path: str = "policies/remediation_policies.yaml"
    semantic_bank_path: str = "policies/semantic_prototypes.json"
    attack_scenarios_path: str = "attacks/scenarios.yaml"

    def resolve(self, rel_path: str) -> Path:
        p = Path(rel_path)
        return p if p.is_absolute() else self.repo_root / p


def load_config(config_yaml: Path | None = None, env_file: Path | None = None) -> AgentConfig:
    """Load configuration from optional YAML file and .env environment variables."""
    root = find_repo_root()
    load_dotenv(env_file or (root / ".env"), override=False)

    data: dict[str, Any] = {"repo_root": root}
    if config_yaml and config_yaml.exists():
        loaded = yaml.safe_load(config_yaml.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            data.update(loaded)

    if env_backend := os.getenv("AGENT_CTI_LLM_BACKEND"):
        data["llm_backend"] = env_backend
    if env_secret := os.getenv("AGENT_CTI_SIGNING_SECRET"):
        data["signing_secret"] = env_secret

    return AgentConfig(**data)


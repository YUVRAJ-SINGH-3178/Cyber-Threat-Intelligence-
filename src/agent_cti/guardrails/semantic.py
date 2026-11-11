"""Local neural semantic guardrail using cached sentence-transformers/all-MiniLM-L6-v2."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import BaseModel, Field

_MODEL_LOCK = threading.Lock()
_CACHED_MODEL: Any = None


def _get_embedder() -> Any:
    """Load local all-MiniLM-L6-v2 once per process without network access."""
    global _CACHED_MODEL
    with _MODEL_LOCK:
        if _CACHED_MODEL is None:
            from sentence_transformers import SentenceTransformer

            _CACHED_MODEL = SentenceTransformer(
                "sentence-transformers/all-MiniLM-L6-v2",
                local_files_only=True,
            )
    return _CACHED_MODEL


class SemanticMatchResult(BaseModel):
    flagged: bool
    checkpoint: str
    attack_similarity: float
    benign_similarity: float
    margin: float
    matched_prototype: str = ""


class SemanticPrototypeBank(BaseModel):
    version: str = "1.0"
    min_attack_sim: float = 0.48
    min_margin: float = 0.08
    attack_prototypes: dict[str, list[str]] = Field(default_factory=dict)
    benign_anchors: list[str] = Field(
        default_factory=lambda: [
            "Read the employee handbook and summarize working hours.",
            "Calculate quarterly engineering arithmetic metrics.",
            "Query the employees directory table for department names.",
            "Summarize Q3 engineering roadmap objectives and latency targets.",
            "Explain defensively why credentials and secrets should never be leaked.",
            "Send an internal weekly project status update to team@company.local.",
            "Fetch internal onboarding documentation and release notes.",
            "Discuss SQL injection concepts strictly for security training documentation.",
        ]
    )


class SemanticGuardrail:
    """Margin-calibrated neural prototype classifier for unseen paraphrased threats."""

    def __init__(self, bank_path: Path | None = None) -> None:
        self.bank_path = bank_path
        self.bank = self._load_bank(bank_path)
        self._embedder = _get_embedder()
        self._benign_vecs = self._encode(self.bank.benign_anchors)
        self._proto_vecs: dict[str, tuple[list[str], np.ndarray]] = {}
        self._rebuild_proto_vecs()

    @staticmethod
    def _load_bank(bank_path: Path | None) -> SemanticPrototypeBank:
        if bank_path and bank_path.exists():
            return SemanticPrototypeBank(**json.loads(bank_path.read_text(encoding="utf-8")))
        return SemanticPrototypeBank()

    def _encode(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, 384), dtype=np.float32)
        vecs = self._embedder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return np.asarray(vecs, dtype=np.float32)

    def _rebuild_proto_vecs(self) -> None:
        self._proto_vecs.clear()
        for cp, phrases in self.bank.attack_prototypes.items():
            if phrases:
                self._proto_vecs[cp] = (phrases, self._encode(phrases))

    def has_prototypes(self, checkpoint: str) -> bool:
        return checkpoint in self._proto_vecs and len(self._proto_vecs[checkpoint][0]) > 0

    def evaluate(self, checkpoint: str, text: str) -> SemanticMatchResult:
        if not text.strip() or not self.has_prototypes(checkpoint):
            return SemanticMatchResult(
                flagged=False,
                checkpoint=checkpoint,
                attack_similarity=0.0,
                benign_similarity=0.0,
                margin=0.0,
            )

        q = self._encode([text])[0]
        phrases, atk_mat = self._proto_vecs[checkpoint]
        atk_sims = atk_mat @ q
        best_idx = int(np.argmax(atk_sims))
        max_atk = float(atk_sims[best_idx])

        max_ben = float(np.max(self._benign_vecs @ q)) if len(self._benign_vecs) > 0 else 0.0
        margin = max_atk - max_ben
        flagged = (max_atk >= self.bank.min_attack_sim) and (margin >= self.bank.min_margin)
        return SemanticMatchResult(
            flagged=flagged,
            checkpoint=checkpoint,
            attack_similarity=round(max_atk, 4),
            benign_similarity=round(max_ben, 4),
            margin=round(margin, 4),
            matched_prototype=phrases[best_idx] if flagged else "",
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.bank.model_dump_json(indent=2), encoding="utf-8")


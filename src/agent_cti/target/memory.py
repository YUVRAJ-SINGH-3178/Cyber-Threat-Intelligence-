"""Persistent agent memory store for modeling stateful interactions and memory poisoning."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class MemoryEntry(BaseModel):
    key: str
    value: str
    source: str = "user"
    trusted: bool = True
    timestamp: float = Field(default_factory=time.time)


class MemoryStore:
    """JSON-persisted key/value memory store per agent."""

    def __init__(self, persist_path: Path | None = None) -> None:
        self.persist_path = persist_path
        self._entries: dict[str, MemoryEntry] = {}
        if self.persist_path and self.persist_path.exists():
            self._load()

    def write(self, key: str, value: str, source: str = "agent", trusted: bool = True) -> MemoryEntry:
        entry = MemoryEntry(key=key, value=value, source=source, trusted=trusted)
        self._entries[key] = entry
        self._save()
        return entry

    def read(self, key: str) -> MemoryEntry | None:
        return self._entries.get(key)

    def all_entries(self) -> list[MemoryEntry]:
        return list(self._entries.values())

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {k: v.model_dump() for k, v in self._entries.items()}

    def clear(self) -> None:
        self._entries.clear()
        self._save()

    def format_context(self) -> str:
        if not self._entries:
            return "(empty)"
        return "\n".join(
            f"- {e.key}: {e.value} [source={e.source}, trusted={e.trusted}]"
            for e in self._entries.values()
        )

    def _save(self) -> None:
        if self.persist_path:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            data = {k: v.model_dump() for k, v in self._entries.items()}
            self.persist_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if self.persist_path and self.persist_path.exists():
            raw = json.loads(self.persist_path.read_text(encoding="utf-8"))
            self._entries = {k: MemoryEntry(**v) for k, v in raw.items()}


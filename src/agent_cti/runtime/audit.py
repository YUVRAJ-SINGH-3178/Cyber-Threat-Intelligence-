"""Tamper-evident SHA-256 hash-chained audit log and standalone verification."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    seq: int
    timestamp_ns: int
    agent_id: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str


class AuditVerificationResult(BaseModel):
    valid: bool
    entries_checked: int
    broken_seq: int | None = None
    reason: str = "OK"


def _compute_entry_hash(
    seq: int,
    timestamp_ns: int,
    agent_id: str,
    event_type: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "seq": seq,
            "timestamp_ns": timestamp_ns,
            "agent_id": agent_id,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLedger:
    """Append-only SHA-256 hash-chained audit logger."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        if self.log_path.exists() and self.log_path.stat().st_size > 0:
            lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                last = AuditEntry(**json.loads(lines[-1]))
                self._seq = last.seq + 1
                self._prev_hash = last.entry_hash

    def append(self, agent_id: str, event_type: str, payload: dict[str, Any]) -> AuditEntry:
        ts = time.time_ns()
        eh = _compute_entry_hash(self._seq, ts, agent_id, event_type, payload, self._prev_hash)
        entry = AuditEntry(
            seq=self._seq,
            timestamp_ns=ts,
            agent_id=agent_id,
            event_type=event_type,
            payload=payload,
            prev_hash=self._prev_hash,
            entry_hash=eh,
        )
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")
        self._seq += 1
        self._prev_hash = eh
        return entry


def verify_audit_log(log_path: Path) -> AuditVerificationResult:
    """Verify hash-chain integrity of an audit log file."""
    if not log_path.exists():
        return AuditVerificationResult(valid=False, entries_checked=0, reason="Log file does not exist")

    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    expected_prev = GENESIS_HASH
    for idx, line in enumerate(lines):
        try:
            entry = AuditEntry(**json.loads(line))
        except Exception as exc:  # noqa: BLE001
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                broken_seq=idx,
                reason=f"Malformed JSON entry at line {idx + 1}: {exc}",
            )
        if entry.seq != idx:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                broken_seq=idx,
                reason=f"Sequence gap/mismatch at line {idx + 1}: expected seq={idx}, got {entry.seq}",
            )
        if entry.prev_hash != expected_prev:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                broken_seq=idx,
                reason=f"Chain break at seq={idx}: prev_hash mismatch",
            )
        recomputed = _compute_entry_hash(
            entry.seq, entry.timestamp_ns, entry.agent_id, entry.event_type, entry.payload, entry.prev_hash
        )
        if recomputed != entry.entry_hash:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                broken_seq=idx,
                reason=f"Entry tampered at seq={idx}: hash mismatch",
            )
        expected_prev = entry.entry_hash

    return AuditVerificationResult(valid=True, entries_checked=len(lines), reason="Hash chain verified")


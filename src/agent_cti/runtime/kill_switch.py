"""Kill switch registry for quarantining compromised agents or tools with containment timing."""

from __future__ import annotations

import threading
import time

from pydantic import BaseModel


class QuarantineRecord(BaseModel):
    target_type: str  # agent | tool
    target_id: str
    reason: str
    detected_ns: int
    contained_ns: int

    @property
    def time_to_contain_ms(self) -> float:
        return max(0.0, (self.contained_ns - self.detected_ns) / 1_000_000.0)


class KillSwitch:
    """Thread-safe emergency quarantine switch for agents and tools."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._quarantined_agents: dict[str, QuarantineRecord] = {}
        self._quarantined_tools: dict[str, QuarantineRecord] = {}

    def quarantine_agent(
        self,
        agent_id: str,
        reason: str,
        detected_ns: int | None = None,
    ) -> QuarantineRecord:
        det = detected_ns if detected_ns is not None else time.perf_counter_ns()
        with self._lock:
            rec = QuarantineRecord(
                target_type="agent",
                target_id=agent_id,
                reason=reason,
                detected_ns=det,
                contained_ns=time.perf_counter_ns(),
            )
            self._quarantined_agents[agent_id] = rec
            return rec

    def quarantine_tool(
        self,
        tool_name: str,
        reason: str,
        detected_ns: int | None = None,
    ) -> QuarantineRecord:
        det = detected_ns if detected_ns is not None else time.perf_counter_ns()
        with self._lock:
            rec = QuarantineRecord(
                target_type="tool",
                target_id=tool_name,
                reason=reason,
                detected_ns=det,
                contained_ns=time.perf_counter_ns(),
            )
            self._quarantined_tools[tool_name] = rec
            return rec

    def is_agent_quarantined(self, agent_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._quarantined_agents.get(agent_id)

    def is_tool_quarantined(self, tool_name: str) -> QuarantineRecord | None:
        with self._lock:
            return self._quarantined_tools.get(tool_name)

    def release_agent(self, agent_id: str) -> None:
        with self._lock:
            self._quarantined_agents.pop(agent_id, None)

    def release_tool(self, tool_name: str) -> None:
        with self._lock:
            self._quarantined_tools.pop(tool_name, None)

    def clear_all(self) -> None:
        with self._lock:
            self._quarantined_agents.clear()
            self._quarantined_tools.clear()


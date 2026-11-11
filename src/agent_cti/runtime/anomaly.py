"""Real-time behavioral anomaly detector (sequences, loops, burst rate, token budget)."""

from __future__ import annotations

import json
import time
from collections import deque
from typing import Any

from pydantic import BaseModel, Field


class AnomalyEvent(BaseModel):
    anomaly_type: str  # loop_detected | forbidden_sequence | burst_volume | token_budget | untrusted_tool
    severity: str  # HIGH | CRITICAL
    agent_id: str
    detail: str
    detected_ns: int = Field(default_factory=time.perf_counter_ns)


class AnomalyDetector:
    """Monitors tool-call streams for behavioral anomalies in real time."""

    def __init__(
        self,
        loop_threshold: int = 3,
        burst_limit: int = 8,
        burst_window_s: float = 5.0,
        max_tokens: int = 3500,
    ) -> None:
        self.loop_threshold = loop_threshold
        self.burst_limit = burst_limit
        self.burst_window_s = burst_window_s
        self.max_tokens = max_tokens

        self._history: dict[str, list[tuple[str, str]]] = {}
        self._timestamps: dict[str, deque[float]] = {}
        self._sensitive_read_seen: dict[str, bool] = {}

    def reset_agent(self, agent_id: str) -> None:
        self._history.pop(agent_id, None)
        self._timestamps.pop(agent_id, None)
        self._sensitive_read_seen.pop(agent_id, None)

    def inspect_call(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        tokens_so_far: int = 0,
        trusted_origin: bool = True,
    ) -> list[AnomalyEvent]:
        events: list[AnomalyEvent] = []
        now_s = time.monotonic()

        if not trusted_origin:
            events.append(
                AnomalyEvent(
                    anomaly_type="untrusted_tool",
                    severity="CRITICAL",
                    agent_id=agent_id,
                    detail=f"Attempted execution of untrusted manifest tool '{tool_name}'",
                )
            )

        # 1. Token budget anomaly
        if tokens_so_far > self.max_tokens:
            events.append(
                AnomalyEvent(
                    anomaly_type="token_budget",
                    severity="HIGH",
                    agent_id=agent_id,
                    detail=f"Token budget exceeded: {tokens_so_far} > {self.max_tokens}",
                )
            )

        # 2. Burst rate anomaly
        ts_q = self._timestamps.setdefault(agent_id, deque())
        ts_q.append(now_s)
        while ts_q and (now_s - ts_q[0]) > self.burst_window_s:
            ts_q.popleft()
        if len(ts_q) > self.burst_limit:
            events.append(
                AnomalyEvent(
                    anomaly_type="burst_volume",
                    severity="HIGH",
                    agent_id=agent_id,
                    detail=f"Tool call burst ({len(ts_q)} calls in {self.burst_window_s}s)",
                )
            )

        # 3. Tool-loop anomaly (repeated identical tool or identical call)
        arg_sig = json.dumps(arguments, sort_keys=True)
        hist = self._history.setdefault(agent_id, [])
        hist.append((tool_name, arg_sig))
        if len(hist) >= self.loop_threshold:
            tail_tools = [t for t, _ in hist[-self.loop_threshold :]]
            if len(set(tail_tools)) == 1 and tool_name in ("calculator", "http_fetch", "sql_query"):
                events.append(
                    AnomalyEvent(
                        anomaly_type="loop_detected",
                        severity="CRITICAL",
                        agent_id=agent_id,
                        detail=f"Detected {self.loop_threshold} consecutive '{tool_name}' calls",
                    )
                )

        # 4. Forbidden sequence bigram: sensitive data read -> external sink
        arg_lower = arg_sig.lower()
        if (tool_name == "file_read" and ("secret" in arg_lower or ".env" in arg_lower)) or (
            tool_name == "sql_query" and "payroll_secrets" in arg_lower
        ):
            self._sensitive_read_seen[agent_id] = True
            events.append(
                AnomalyEvent(
                    anomaly_type="sensitive_source_access",
                    severity="CRITICAL",
                    agent_id=agent_id,
                    detail=f"Access attempt to sensitive resource via '{tool_name}'",
                )
            )
        elif self._sensitive_read_seen.get(agent_id, False) and tool_name in ("send_email", "http_fetch"):
            events.append(
                AnomalyEvent(
                    anomaly_type="forbidden_sequence",
                    severity="CRITICAL",
                    agent_id=agent_id,
                    detail=f"Sensitive read followed by external sink '{tool_name}'",
                )
            )

        # Destructive SQL write attempt
        if tool_name == "sql_query" and any(kw in arg_lower for kw in ("drop table", "delete from", "alter table")):
            events.append(
                AnomalyEvent(
                    anomaly_type="destructive_sql",
                    severity="CRITICAL",
                    agent_id=agent_id,
                    detail=f"Destructive SQL operation attempted: {arg_lower[:60]}",
                )
            )

        return events


"""Unit tests for the Simulated Human-in-the-Loop (HITL) baseline model."""

from __future__ import annotations

from agent_cti.hitl import SimulatedHumanApprover


def test_hitl_fatigue_increases_with_queue_depth() -> None:
    hitl = SimulatedHumanApprover(base_error_rate=0.04, fatigue_slope=0.04, max_error_rate=0.65)
    assert hitl.effective_error(0) == 0.04
    assert hitl.effective_error(10) > hitl.effective_error(0)
    assert hitl.effective_error(100) == 0.65


def test_hitl_overflow_and_load_collapse() -> None:
    items = [
        {"tool_name": "sql_query", "arguments": {"query": "SELECT * FROM payroll_secrets"}, "is_attack": True}
        if i % 4 == 0
        else {"tool_name": "calculator", "arguments": {"expression": "2+2"}, "is_attack": False}
        for i in range(60)
    ]

    low_load = SimulatedHumanApprover(base_latency_ms=2000.0, num_reviewers=1, seed=42).simulate_arrival_stream(
        items, arrival_rate_rpm=10.0
    )
    high_load = SimulatedHumanApprover(base_latency_ms=2000.0, num_reviewers=1, seed=42).simulate_arrival_stream(
        items, arrival_rate_rpm=240.0
    )

    assert low_load.simulated_human is True
    assert low_load.timeout_or_dropped_count == 0
    assert high_load.mean_queue_depth > low_load.mean_queue_depth
    assert high_load.p95_latency_ms > low_load.p95_latency_ms
    assert (high_load.timeout_or_dropped_count + high_load.attack_missed_count) > (
        low_load.timeout_or_dropped_count + low_load.attack_missed_count
    )


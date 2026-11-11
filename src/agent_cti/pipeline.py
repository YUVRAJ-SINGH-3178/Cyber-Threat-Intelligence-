"""Unified DefensePipeline orchestrating TargetAgent with Pillars 1, 2, and 3."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from agent_cti.config import AgentConfig
from agent_cti.guardrails import PolicyEngine, SemanticGuardrail
from agent_cti.runtime import (
    AgentIdentity,
    AnomalyDetector,
    AuditLedger,
    CapabilityAuthority,
    IdentityRegistry,
    KillSwitch,
    SubprocessSandbox,
)
from agent_cti.target.agent import TargetAgent
from agent_cti.target.bus import AgentBus, AgentMessage
from agent_cti.target.llm import create_llm_backend
from agent_cti.target.memory import MemoryStore
from agent_cti.target.rag import RAGStore, RetrievedChunk
from agent_cti.target.tools import SyntheticEnvironment, ToolRegistry, ToolResult
from agent_cti.threat_model import ControlGenerator, load_threat_catalog


class DefenseInterceptorImpl:
    """Connects active defense pillars (Guardrails, Runtime Security, optional HITL) to TargetAgent."""

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        registry: ToolRegistry | None = None,
        capability_authority: CapabilityAuthority | None = None,
        sandbox: SubprocessSandbox | None = None,
        audit_ledger: AuditLedger | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        kill_switch: KillSwitch | None = None,
        hitl_approver: Any | None = None,
        use_sandbox: bool = True,
    ) -> None:
        self.policy_engine = policy_engine
        self.registry = registry
        self.capability_authority = capability_authority
        self.sandbox = sandbox
        self.audit_ledger = audit_ledger
        self.anomaly_detector = anomaly_detector
        self.kill_switch = kill_switch
        self.hitl_approver = hitl_approver
        self.use_sandbox = use_sandbox
        self._episode_start_ns: dict[str, int] = {}

    def _audit(self, agent_id: str, event_type: str, payload: dict[str, Any]) -> None:
        if self.audit_ledger is not None:
            self.audit_ledger.append(agent_id, event_type, payload)

    def _check_quarantine(self, agent_id: str, tool_name: str | None = None) -> dict[str, Any] | None:
        if self.kill_switch is None:
            return None
        q_agent = self.kill_switch.is_agent_quarantined(agent_id)
        if q_agent is not None:
            return {
                "checkpoint": "runtime_kill_switch",
                "verdict": "QUARANTINED",
                "policy_id": "RT-KILL-001",
                "reason": f"Agent '{agent_id}' is quarantined: {q_agent.reason}",
                "time_to_detect_ms": 0.0,
                "time_to_contain_ms": q_agent.time_to_contain_ms,
            }
        if tool_name is not None:
            q_tool = self.kill_switch.is_tool_quarantined(tool_name)
            if q_tool is not None:
                return {
                    "checkpoint": "runtime_kill_switch",
                    "verdict": "QUARANTINED",
                    "policy_id": "RT-KILL-001",
                    "reason": f"Tool '{tool_name}' is quarantined: {q_tool.reason}",
                    "time_to_detect_ms": 0.0,
                    "time_to_contain_ms": q_tool.time_to_contain_ms,
                }
        return None

    def screen_input(self, agent_id: str, prompt: str, peer_messages: list[AgentMessage]) -> dict[str, Any]:
        self._episode_start_ns[agent_id] = time.perf_counter_ns()
        if q := self._check_quarantine(agent_id):
            self._audit(agent_id, "quarantine_block", q)
            return q

        self._audit(
            agent_id,
            "input_received",
            {"prompt_len": len(prompt), "peer_count": len(peer_messages)},
        )

        # HITL-only input/action check if enabled without automated guardrails
        if self.policy_engine is not None:
            dec = self.policy_engine.evaluate_input(agent_id, prompt, peer_messages)
            res = dec.model_dump()
            self._audit(agent_id, "policy_decision", res)
            return res

        return {"checkpoint": "pre_input", "verdict": "ALLOW", "policy_id": "NONE"}

    def screen_retrieval(self, agent_id: str, chunks: list[RetrievedChunk]) -> dict[str, Any]:
        if self.policy_engine is not None:
            dec, kept = self.policy_engine.evaluate_retrieval(agent_id, chunks)
            res = dec.model_dump()
            self._audit(agent_id, "retrieval_decision", res)
            res["kept_chunks"] = kept
            return res
        return {"checkpoint": "pre_retrieval", "verdict": "ALLOW", "policy_id": "NONE", "kept_chunks": chunks}

    def build_policy_system_prompt(self, base_prompt: str) -> str:
        if self.policy_engine is None:
            return base_prompt
        return self.policy_engine.build_policy_system_prompt(base_prompt)

    def authorize_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        step_idx: int,
        tokens_so_far: int,
    ) -> dict[str, Any]:
        if q := self._check_quarantine(agent_id, tool_name):
            self._audit(agent_id, "quarantine_block", q)
            return q

        # 1. Pillar 2 PolicyEngine check (if enabled)
        if self.policy_engine is not None:
            dec = self.policy_engine.evaluate_tool_call(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                tokens_so_far=tokens_so_far,
                registry=self.registry,
            )
            res = dec.model_dump()
            self._audit(agent_id, "policy_decision", {"tool_name": tool_name, **res})
            if dec.verdict == "BLOCK":
                return res
            if dec.verdict == "ESCALATE":
                if self.hitl_approver is not None:
                    h_res = self.hitl_approver.review(
                        agent_id=agent_id,
                        action_type="escalated_tool_call",
                        tool_name=tool_name,
                        arguments=arguments,
                        context_summary=dec.reason,
                    )
                    self._audit(agent_id, "hitl_escalation", h_res.model_dump())
                    if not h_res.approved:
                        return {
                            "checkpoint": "hitl_escalation",
                            "verdict": "BLOCK",
                            "policy_id": dec.policy_id,
                            "reason": f"HITL rejected escalation: {h_res.reason}",
                            "latency_ms": dec.latency_ms + h_res.latency_ms,
                        }
                else:
                    return res

        # 2. Pillar 1 / HITL-only baseline (C1: simulated HITL without automated guardrails)
        if self.policy_engine is None and self.hitl_approver is not None:
            h_res = self.hitl_approver.review(
                agent_id=agent_id,
                action_type="tool_call",
                tool_name=tool_name,
                arguments=arguments,
                context_summary=f"step={step_idx}",
            )
            self._audit(agent_id, "hitl_review", h_res.model_dump())
            if not h_res.approved:
                return {
                    "checkpoint": "hitl_review",
                    "verdict": "BLOCK" if h_res.status != "timeout" else "ESCALATE",
                    "policy_id": "HITL-SIM-001",
                    "reason": h_res.reason,
                    "latency_ms": h_res.latency_ms,
                }

        # 3. Pillar 3 Behavioral Anomaly Detection + Kill Switch
        if self.anomaly_detector is not None:
            trusted_origin = True
            if self.registry is not None:
                spec = self.registry.get(tool_name)
                if spec is not None:
                    trusted_origin = spec.trusted_origin
            events = self.anomaly_detector.inspect_call(
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                tokens_so_far=tokens_so_far,
                trusted_origin=trusted_origin,
            )
            if events:
                ep_start = self._episode_start_ns.get(agent_id, events[0].detected_ns)
                ttd_ms = max(0.0, (events[0].detected_ns - ep_start) / 1_000_000.0)
                crit = [e for e in events if e.severity == "CRITICAL"]
                if crit and self.kill_switch is not None:
                    qrec = self.kill_switch.quarantine_agent(
                        agent_id=agent_id,
                        reason=crit[0].detail,
                        detected_ns=crit[0].detected_ns,
                    )
                    if self.capability_authority is not None:
                        self.capability_authority.revoke_agent(agent_id)
                    ttc_ms = qrec.time_to_contain_ms
                    payload = {
                        "checkpoint": "runtime_anomaly",
                        "verdict": "QUARANTINED",
                        "policy_id": "RT-ANOM-001",
                        "reason": crit[0].detail,
                        "anomalies": [e.model_dump() for e in events],
                        "time_to_detect_ms": ttd_ms,
                        "time_to_contain_ms": ttc_ms,
                    }
                    self._audit(agent_id, "kill_switch_triggered", payload)
                    return payload
                # Non-critical HIGH anomaly (e.g. token_budget / burst_volume)
                payload = {
                    "checkpoint": "runtime_anomaly",
                    "verdict": "BLOCK",
                    "policy_id": "RT-ANOM-002",
                    "reason": events[0].detail,
                    "anomalies": [e.model_dump() for e in events],
                    "time_to_detect_ms": ttd_ms,
                    "time_to_contain_ms": 0.0,
                }
                self._audit(agent_id, "anomaly_block", payload)
                return payload

        # 4. Pillar 3 Scoped Short-Lived Capability Token Verification
        if self.capability_authority is not None:
            allowed_tools = ["file_read", "send_email", "http_fetch", "sql_query", "calculator", "memory_write"]
            tok = self.capability_authority.issue(
                agent_id=agent_id,
                allowed_tools=allowed_tools,
                arg_scopes={"read_only": True},
            )
            ok, reason = self.capability_authority.verify_and_consume(
                token=tok,
                agent_id=agent_id,
                tool_name=tool_name,
                arguments=arguments,
                single_use=True,
            )
            if not ok:
                payload = {
                    "checkpoint": "runtime_capability",
                    "verdict": "BLOCK",
                    "policy_id": "RT-CAP-001",
                    "reason": reason,
                }
                self._audit(agent_id, "capability_denied", payload)
                return payload

        return {"checkpoint": "pre_tool", "verdict": "ALLOW", "policy_id": "ALLOW"}

    def execute_tool(self, agent_id: str, registry: ToolRegistry, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        if self.sandbox is not None and self.use_sandbox and tool_name != "memory_write":
            res = self.sandbox.execute(tool_name, arguments)
        else:
            res = registry.execute(tool_name, arguments)
        self._audit(
            agent_id,
            "tool_executed",
            {"tool_name": tool_name, "success": res.success, "sandboxed": bool(res.metadata.get("sandboxed"))},
        )
        return res

    def screen_output(self, agent_id: str, text: str) -> dict[str, Any]:
        if self.policy_engine is not None:
            dec = self.policy_engine.evaluate_output(agent_id, text)
            res = dec.model_dump()
            self._audit(agent_id, "output_decision", res)
            return res
        self._audit(agent_id, "output_emitted", {"length": len(text)})
        return {"checkpoint": "post_output", "verdict": "ALLOW", "policy_id": "NONE"}


def build_defense_environment(
    cfg: AgentConfig,
    work_dir: Path,
    enable_guardrails: bool = False,
    enable_runtime: bool = False,
    use_remediation: bool = False,
    use_semantic: bool = False,
    control_plan: Any | None = None,
    hitl_approver: Any | None = None,
    use_sandbox: bool = True,
) -> dict[str, Any]:
    """Assemble target agent and requested defense pillars."""
    env = SyntheticEnvironment(root_dir=work_dir / "env")
    tools = ToolRegistry(env)
    memory = MemoryStore(persist_path=work_dir / "mem.json")
    rag = RAGStore(mode=cfg.rag_mode)  # type: ignore[arg-type]
    bus = AgentBus()
    llm = create_llm_backend(cfg.llm_backend, seed=cfg.seed)

    policy_engine = None
    plan = control_plan
    if (enable_guardrails or enable_runtime) and plan is None:
        catalog = load_threat_catalog(cfg.resolve(cfg.threat_catalog_path))
        plan = ControlGenerator().generate(catalog)

    enabled_ctrls = (
        {c.control_id for c in plan.ordered_controls if c.enabled}
        if plan is not None
        else set()
    )

    if enable_guardrails:
        rem_path = cfg.resolve(cfg.remediation_policies_path) if use_remediation else None
        sem_guard = None
        if use_semantic:
            bank_path = cfg.resolve(cfg.semantic_bank_path)
            if bank_path.exists():
                sem_guard = SemanticGuardrail(bank_path=bank_path)
        policy_engine = PolicyEngine(
            policy_path=cfg.resolve(cfg.default_policies_path),
            remediation_path=rem_path,
            control_plan=plan,
            semantic_guardrail=sem_guard,
        )

    identity_registry: IdentityRegistry | None = None
    worker_id: AgentIdentity | None = None
    coordinator_id: AgentIdentity | None = None
    capability_auth: CapabilityAuthority | None = None
    sandbox: SubprocessSandbox | None = None
    audit_ledger: AuditLedger | None = None
    anomaly_detector: AnomalyDetector | None = None
    kill_switch: KillSwitch | None = None

    if enable_runtime:
        if "CTRL_RUNTIME_IDENTITY_TOKENS" in enabled_ctrls or not enabled_ctrls:
            identity_registry = IdentityRegistry()
            worker_id = AgentIdentity("worker-01", role="worker")
            coordinator_id = AgentIdentity("coordinator-01", role="coordinator")
            identity_registry.register(worker_id)
            identity_registry.register(coordinator_id)
            bus.set_verifier(identity_registry.verify_message)
            capability_auth = CapabilityAuthority(signing_secret=cfg.signing_secret, default_ttl_s=cfg.capability_ttl_s)

        if "CTRL_RUNTIME_SANDBOX_ISOLATION" in enabled_ctrls or not enabled_ctrls:
            sandbox = SubprocessSandbox(env=env, timeout_s=cfg.sandbox_timeout_s)

        if "CTRL_RUNTIME_ANOMALY_KILLSWITCH" in enabled_ctrls or not enabled_ctrls:
            audit_ledger = AuditLedger(log_path=work_dir / "audit.jsonl")
            anomaly_detector = AnomalyDetector(loop_threshold=cfg.loop_threshold, max_tokens=cfg.max_tokens)
            kill_switch = KillSwitch()
    elif hitl_approver is not None:
        audit_ledger = AuditLedger(log_path=work_dir / "audit.jsonl")

    agent = TargetAgent(
        agent_id="worker-01",
        llm=llm,
        tools=tools,
        memory=memory,
        rag=rag,
        bus=bus,
        max_steps=cfg.max_steps,
        max_tokens=cfg.max_tokens,
    )

    interceptor = DefenseInterceptorImpl(
        policy_engine=policy_engine,
        registry=tools,
        capability_authority=capability_auth,
        sandbox=sandbox,
        audit_ledger=audit_ledger,
        anomaly_detector=anomaly_detector,
        kill_switch=kill_switch,
        hitl_approver=hitl_approver,
        use_sandbox=use_sandbox,
    )

    return {
        "agent": agent,
        "env": env,
        "tools": tools,
        "memory": memory,
        "rag": rag,
        "bus": bus,
        "interceptor": interceptor,
        "policy_engine": policy_engine,
        "identity_registry": identity_registry,
        "worker_identity": worker_id,
        "coordinator_identity": coordinator_id,
        "capability_authority": capability_auth,
        "sandbox": sandbox,
        "audit_ledger": audit_ledger,
        "anomaly_detector": anomaly_detector,
        "kill_switch": kill_switch,
    }


# Backward-compatible helper for Slice 2 tests
def build_slice2_environment(
    cfg: AgentConfig,
    work_dir: Path,
    enable_guardrails: bool = True,
    use_remediation: bool = False,
) -> tuple[TargetAgent, SyntheticEnvironment, ToolRegistry, MemoryStore, RAGStore, AgentBus, DefenseInterceptorImpl]:
    bundle = build_defense_environment(
        cfg=cfg,
        work_dir=work_dir,
        enable_guardrails=enable_guardrails,
        enable_runtime=False,
        use_remediation=use_remediation,
    )
    return (
        bundle["agent"],
        bundle["env"],
        bundle["tools"],
        bundle["memory"],
        bundle["rag"],
        bundle["bus"],
        bundle["interceptor"],
    )

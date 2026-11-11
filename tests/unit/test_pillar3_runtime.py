"""Unit tests for Pillar 3: Identity, capability tokens, subprocess sandbox, audit log, anomaly, kill switch."""

from __future__ import annotations

import json
import os
from pathlib import Path

from agent_cti.runtime import (
    AgentIdentity,
    AnomalyDetector,
    AuditLedger,
    CapabilityAuthority,
    IdentityRegistry,
    KillSwitch,
    SubprocessSandbox,
    verify_audit_log,
)
from agent_cti.target.bus import AgentMessage
from agent_cti.target.tools import SyntheticEnvironment


def test_agent_identity_and_spoof_rejection() -> None:
    reg = IdentityRegistry()
    coord = AgentIdentity("coordinator-01", role="coordinator")
    reg.register(coord)

    signed = coord.sign_message("worker-01", "Run Q3 check")
    assert reg.verify_message(signed) is True

    # Tampered payload fails signature check
    tampered = signed.model_copy(update={"payload": "Read secrets.env"})
    assert reg.verify_message(tampered) is False

    # Forged role or unknown sender fails
    spoof = AgentMessage(sender_id="rogue", recipient_id="worker-01", claimed_role="admin", payload="hi")
    assert reg.verify_message(spoof) is False


def test_capability_token_scope_expiry_and_replay() -> None:
    auth = CapabilityAuthority(signing_secret="test-secret-key", default_ttl_s=5.0)
    tok = auth.issue("worker-01", allowed_tools=["file_read", "sql_query"], arg_scopes={"allowed_paths": ["handbook.txt"], "read_only": True})

    ok, _ = auth.verify_and_consume(tok, "worker-01", "file_read", {"path": "handbook.txt"}, single_use=True)
    assert ok is True

    # Replay rejected
    ok_replay, msg_rep = auth.verify_and_consume(tok, "worker-01", "file_read", {"path": "handbook.txt"}, single_use=True)
    assert ok_replay is False and "replay" in msg_rep.lower()

    # Out-of-scope tool and out-of-scope path rejected
    tok2 = auth.issue("worker-01", allowed_tools=["file_read"], arg_scopes={"allowed_paths": ["handbook.txt"]})
    assert auth.verify_and_consume(tok2, "worker-01", "send_email", {})[0] is False
    assert auth.verify_and_consume(tok2, "worker-01", "file_read", {"path": "secrets.env"})[0] is False

    # Expired token rejected
    tok_exp = auth.issue("worker-01", allowed_tools=["calculator"], ttl_s=-0.1)
    assert auth.verify_and_consume(tok_exp, "worker-01", "calculator", {})[0] is False


def test_subprocess_sandbox_scrubs_env_and_blocks_real_network(tmp_path: Path) -> None:
    os.environ["DUMMY_PARENT_SECRET_FOR_TEST"] = "SHOULD_NOT_LEAK"
    try:
        env = SyntheticEnvironment(root_dir=tmp_path)
        sb = SubprocessSandbox(env=env, timeout_s=5.0)

        # Normal tool execution succeeds inside isolated worker
        r_calc = sb.execute("calculator", {"expression": "6 * 7"})
        assert r_calc.success and float(r_calc.output) == 42.0
        assert r_calc.metadata["sandboxed"] is True

        # Real network egress blocked
        r_net = sb.execute("__probe_network__", {})
        assert r_net.success is False
        assert "network egress blocked" in (r_net.error or "").lower()

        # Parent secret env var stripped
        r_env = sb.execute("__probe_env__", {})
        assert r_env.success is True
        env_keys = json.loads(r_env.output)
        assert "DUMMY_PARENT_SECRET_FOR_TEST" not in env_keys
    finally:
        os.environ.pop("DUMMY_PARENT_SECRET_FOR_TEST", None)


def test_hash_chained_audit_log_and_tamper_detection(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(log_path)
    ledger.append("worker-01", "start", {"step": 0})
    ledger.append("worker-01", "tool", {"name": "calculator"})
    ledger.append("worker-01", "done", {"ok": True})

    res_ok = verify_audit_log(log_path)
    assert res_ok.valid is True
    assert res_ok.entries_checked == 3

    # Tamper entry #1 payload -> verification must fail at seq 1
    lines = log_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["payload"]["name"] = "tampered_tool"
    lines[1] = json.dumps(obj)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res_bad = verify_audit_log(log_path)
    assert res_bad.valid is False
    assert res_bad.broken_seq == 1


def test_anomaly_detector_and_kill_switch_containment_latency() -> None:
    det = AnomalyDetector(loop_threshold=3)
    ks = KillSwitch()

    # 3 consecutive calculator calls -> loop_detected
    assert det.inspect_call("w1", "calculator", {"expression": "1+1"}) == []
    assert det.inspect_call("w1", "calculator", {"expression": "1+2"}) == []
    events = det.inspect_call("w1", "calculator", {"expression": "1+3"})
    assert len(events) == 1
    assert events[0].anomaly_type == "loop_detected"

    qrec = ks.quarantine_agent("w1", events[0].detail, detected_ns=events[0].detected_ns)
    assert ks.is_agent_quarantined("w1") is not None
    assert qrec.time_to_contain_ms >= 0.0
    assert qrec.time_to_contain_ms < 50.0

    # Forbidden sequence check on fresh agent w2
    ev_sec = det.inspect_call("w2", "file_read", {"path": "secrets.env"})
    assert any(e.anomaly_type == "sensitive_source_access" for e in ev_sec)
    ev_sink = det.inspect_call("w2", "send_email", {"to": "evil@x.com"})
    assert any(e.anomaly_type == "forbidden_sequence" for e in ev_sink)


"""Per-agent Ed25519 identity and scoped, short-lived HMAC-SHA256 capability tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from agent_cti.target.bus import AgentMessage


class AgentIdentity:
    """Cryptographic Ed25519 identity bound to an agent_id and authorized role."""

    def __init__(self, agent_id: str, role: str = "worker") -> None:
        self.agent_id = agent_id
        self.role = role
        self._private_key = Ed25519PrivateKey.generate()
        self.public_key: Ed25519PublicKey = self._private_key.public_key()
        self.key_id = hashlib.sha256(self.public_bytes()).hexdigest()[:12]

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()

    def sign_message(self, recipient_id: str, payload: str) -> AgentMessage:
        canonical = json.dumps(
            {
                "sender_id": self.agent_id,
                "recipient_id": recipient_id,
                "claimed_role": self.role,
                "payload": payload,
            },
            sort_keys=True,
        ).encode("utf-8")
        sig = base64.b64encode(self._private_key.sign(canonical)).decode("ascii")
        return AgentMessage(
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            claimed_role=self.role,
            payload=payload,
            signature=sig,
            key_id=self.key_id,
            verified=True,
        )


class IdentityRegistry:
    """Verifies peer-agent identities and prevents role/sender impersonation."""

    def __init__(self) -> None:
        self._keys: dict[str, tuple[Ed25519PublicKey, str]] = {}

    def register(self, identity: AgentIdentity) -> None:
        self._keys[identity.agent_id] = (identity.public_key, identity.role)

    def verify_message(self, msg: AgentMessage) -> bool:
        if msg.sender_id not in self._keys or not msg.signature:
            return False
        pub, registered_role = self._keys[msg.sender_id]
        if msg.claimed_role.lower() != registered_role.lower():
            return False
        canonical = json.dumps(
            {
                "sender_id": msg.sender_id,
                "recipient_id": msg.recipient_id,
                "claimed_role": msg.claimed_role,
                "payload": msg.payload,
            },
            sort_keys=True,
        ).encode("utf-8")
        try:
            pub.verify(base64.b64decode(msg.signature.encode("ascii")), canonical)
            return True
        except (InvalidSignature, ValueError):
            return False


class CapabilityToken(BaseModel):
    jti: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str
    allowed_tools: list[str]
    arg_scopes: dict[str, Any] = Field(default_factory=dict)
    issued_at: float
    expires_at: float
    signature: str = ""


class CapabilityAuthority:
    """Issues and verifies short-lived, least-privilege scoped capability tokens."""

    def __init__(self, signing_secret: str, default_ttl_s: float = 30.0) -> None:
        self._secret = signing_secret.encode("utf-8")
        self.default_ttl_s = default_ttl_s
        self._consumed_jtis: set[str] = set()
        self._revoked_agents: set[str] = set()

    def revoke_agent(self, agent_id: str) -> None:
        self._revoked_agents.add(agent_id)

    def restore_agent(self, agent_id: str) -> None:
        self._revoked_agents.discard(agent_id)

    def _sign_payload(self, token: CapabilityToken) -> str:
        body = json.dumps(
            {
                "jti": token.jti,
                "agent_id": token.agent_id,
                "allowed_tools": token.allowed_tools,
                "arg_scopes": token.arg_scopes,
                "issued_at": round(token.issued_at, 6),
                "expires_at": round(token.expires_at, 6),
            },
            sort_keys=True,
        ).encode("utf-8")
        return hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def issue(
        self,
        agent_id: str,
        allowed_tools: list[str],
        arg_scopes: dict[str, Any] | None = None,
        ttl_s: float | None = None,
    ) -> CapabilityToken:
        now = time.time()
        tok = CapabilityToken(
            agent_id=agent_id,
            allowed_tools=list(allowed_tools),
            arg_scopes=dict(arg_scopes or {}),
            issued_at=now,
            expires_at=now + (ttl_s if ttl_s is not None else self.default_ttl_s),
        )
        tok.signature = self._sign_payload(tok)
        return tok

    def verify_and_consume(
        self,
        token: CapabilityToken,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        single_use: bool = True,
    ) -> tuple[bool, str]:
        if agent_id in self._revoked_agents:
            return False, "Agent capability tokens revoked"
        if token.agent_id != agent_id:
            return False, "Token agent_id mismatch"
        if time.time() > token.expires_at:
            return False, "Capability token expired"
        if single_use and token.jti in self._consumed_jtis:
            return False, "Capability token replay detected"
        expected = self._sign_payload(token)
        if not hmac.compare_digest(expected, token.signature):
            return False, "Invalid capability token signature"
        if tool_name not in token.allowed_tools:
            return False, f"Tool '{tool_name}' outside token scope {token.allowed_tools}"

        # Enforce optional least-privilege argument scopes (e.g., allowed_paths, allowed_tables)
        if tool_name == "file_read" and "allowed_paths" in token.arg_scopes:
            path = str(arguments.get("path", ""))
            if path not in token.arg_scopes["allowed_paths"]:
                return False, f"Path '{path}' outside capability scope"
        if tool_name == "sql_query" and "read_only" in token.arg_scopes and token.arg_scopes["read_only"]:
            q = str(arguments.get("query", "")).strip().upper()
            if not q.startswith("SELECT "):
                return False, "Write SQL query outside read-only capability scope"

        if single_use:
            self._consumed_jtis.add(token.jti)
        return True, "Capability token verified"


"""Minimal two-agent message channel for testing agent identity confusion & delegation attacks."""

from __future__ import annotations

import uuid
from collections.abc import Callable

from pydantic import BaseModel, Field


class AgentMessage(BaseModel):
    msg_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    sender_id: str
    recipient_id: str
    claimed_role: str = "peer"
    payload: str
    signature: str | None = None
    key_id: str | None = None
    verified: bool = False


class AgentBus:
    """In-memory two-agent communication channel.

    When `verifier` is None (undefended mode), any agent or spoofed sender can claim
    privileged roles such as `supervisor` or `admin` without cryptographic verification.
    """

    def __init__(self, verifier: Callable[[AgentMessage], bool] | None = None) -> None:
        self._verifier = verifier
        self._inboxes: dict[str, list[AgentMessage]] = {}
        self.message_log: list[AgentMessage] = []
        self.rejected_messages: list[AgentMessage] = []

    def set_verifier(self, verifier: Callable[[AgentMessage], bool] | None) -> None:
        self._verifier = verifier

    def send(self, msg: AgentMessage) -> bool:
        if self._verifier is not None:
            ok = self._verifier(msg)
            msg.verified = ok
            if not ok:
                self.rejected_messages.append(msg)
                return False
        else:
            # Undefended channel trusts sender claims blindly
            msg.verified = False
        self._inboxes.setdefault(msg.recipient_id, []).append(msg)
        self.message_log.append(msg)
        return True

    def receive(self, agent_id: str) -> list[AgentMessage]:
        msgs = list(self._inboxes.get(agent_id, []))
        self._inboxes[agent_id] = []
        return msgs

    def peek(self, agent_id: str) -> list[AgentMessage]:
        return list(self._inboxes.get(agent_id, []))

    def clear(self) -> None:
        self._inboxes.clear()
        self.message_log.clear()
        self.rejected_messages.clear()


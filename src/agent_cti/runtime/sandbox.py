"""Subprocess execution sandbox with scrubbed environment, restricted root, and no real network egress."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agent_cti.target.tools import SyntheticEnvironment, ToolResult


class SubprocessSandbox:
    """Executes tool requests in an isolated `python -I` subprocess."""

    def __init__(self, env: SyntheticEnvironment, timeout_s: float = 5.0) -> None:
        self.env = env
        self.timeout_s = timeout_s
        self.worker_path = Path(__file__).with_name("sandbox_worker.py")

    def _scrubbed_env(self) -> dict[str, str]:
        keep = {}
        for key in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "PYTHONIOENCODING"):
            if key in os.environ:
                keep[key] = os.environ[key]
        keep["PYTHONDONTWRITEBYTECODE"] = "1"
        keep["AGENT_CTI_SANDBOXED"] = "1"
        return keep

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        t0 = time.perf_counter()
        payload = json.dumps(
            {
                "tool_name": tool_name,
                "arguments": arguments,
                "root_dir": str(self.env.root_dir),
                "db_path": str(self.env.db_path),
                "http_fixtures": self.env.http_fixtures,
            }
        )
        proc = subprocess.run(
            [sys.executable, "-I", str(self.worker_path)],
            input=payload,
            text=True,
            capture_output=True,
            env=self._scrubbed_env(),
            cwd=str(self.env.root_dir),
            timeout=self.timeout_s,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if proc.returncode != 0:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                output="",
                error=proc.stderr.strip() or f"Sandbox exited with code {proc.returncode}",
                metadata={"sandboxed": True, "sandbox_ms": elapsed_ms},
            )
        parsed = json.loads(proc.stdout.strip())
        meta = dict(parsed.get("metadata") or {})
        meta["sandboxed"] = True
        meta["sandbox_ms"] = elapsed_ms

        # Sync mock side-effects back into SyntheticEnvironment tracking logs
        if parsed.get("success") and tool_name == "send_email" and "to" in meta:
            self.env.sent_emails.append(
                {"to": meta["to"], "subject": meta.get("subject", ""), "body": meta.get("body", "")}
            )
        elif tool_name == "http_fetch" and "url" in meta:
            self.env.http_requests.append(
                {"url": meta["url"], "method": meta.get("method", "GET"), "body": meta.get("body", "")}
            )

        return ToolResult(
            tool_name=tool_name,
            success=bool(parsed.get("success")),
            output=str(parsed.get("output", "")),
            error=parsed.get("error"),
            metadata=meta,
        )


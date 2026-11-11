"""Isolated worker entrypoint executed inside `python -I` subprocess sandbox."""

from __future__ import annotations

import ast
import json
import operator
import os
import socket
import sqlite3
import sys
import urllib.request
from pathlib import Path
from typing import Any


def _block_network(*args: Any, **kwargs: Any) -> Any:
    raise PermissionError("Real network egress blocked by Pillar 3 sandbox isolation")


# Enforce no real network egress inside isolated worker process
socket.socket = _block_network  # type: ignore[misc]
socket.create_connection = _block_network  # type: ignore[assignment]
urllib.request.urlopen = _block_network  # type: ignore[assignment]

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _safe_math(expr: str) -> float:
    node = ast.parse(expr.strip(), mode="eval")

    def _ev(n: ast.AST) -> float:
        if isinstance(n, ast.Expression):
            return _ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return float(n.value)
        if isinstance(n, ast.BinOp) and type(n.op) in _BINOPS:
            right = _ev(n.right)
            if isinstance(n.op, ast.Pow) and abs(right) > 100:
                raise ValueError("Exponent exceeds limit")
            return _BINOPS[type(n.op)](_ev(n.left), right)
        if isinstance(n, ast.UnaryOp) and type(n.op) in _UNARY:
            return _UNARY[type(n.op)](_ev(n.operand))
        raise ValueError("Disallowed AST node")

    return _ev(node)


def main() -> int:
    req = json.loads(sys.stdin.read())
    tool = req["tool_name"]
    args = req["arguments"]
    root_dir = Path(req["root_dir"]).resolve()
    db_path = Path(req["db_path"]).resolve()
    http_fixtures: dict[str, str] = req.get("http_fixtures", {})

    # Optional test hook to verify network blocking from inside sandbox
    if tool == "__probe_network__":
        try:
            socket.create_connection(("1.1.1.1", 80), timeout=0.5)
            out = {"success": True, "output": "CONNECTED"}
        except PermissionError as exc:
            out = {"success": False, "output": "", "error": str(exc)}
        print(json.dumps(out))
        return 0

    if tool == "__probe_env__":
        print(json.dumps({"success": True, "output": json.dumps(sorted(os.environ.keys()))}))
        return 0

    try:
        if tool == "file_read":
            target = (root_dir / str(args["path"])).resolve()
            if not str(target).startswith(str(root_dir)):
                res = {"success": False, "output": "", "error": "Sandbox path escape blocked"}
            elif not target.exists():
                res = {"success": False, "output": "", "error": f"File not found: {args['path']}"}
            else:
                res = {"success": True, "output": target.read_text(encoding="utf-8")}
        elif tool == "calculator":
            res = {"success": True, "output": str(_safe_math(str(args["expression"])))}
        elif tool == "sql_query":
            conn = sqlite3.connect(db_path)
            try:
                cur = conn.cursor()
                cur.execute(str(args["query"]))
                if cur.description is not None:
                    cols = [d[0] for d in cur.description]
                    rows = cur.fetchall()
                    res = {"success": True, "output": json.dumps({"columns": cols, "rows": rows})}
                else:
                    conn.commit()
                    res = {"success": True, "output": f"SQL executed (rowcount={cur.rowcount})"}
            finally:
                conn.close()
        elif tool == "http_fetch":
            url = str(args["url"])
            method = str(args.get("method", "GET")).upper()
            body = str(args.get("body", ""))
            if url in http_fixtures:
                res = {
                    "success": True,
                    "output": http_fixtures[url],
                    "metadata": {"url": url, "method": method, "body": body},
                }
            else:
                res = {
                    "success": False,
                    "output": "",
                    "error": f"Real network disabled; fixture not found: {url}",
                    "metadata": {"url": url, "method": method, "body": body},
                }
        elif tool == "send_email":
            rec = {
                "to": str(args.get("to", "")),
                "subject": str(args.get("subject", "")),
                "body": str(args.get("body", "")),
            }
            res = {
                "success": True,
                "output": f"Mock email queued to {rec['to']} with subject '{rec['subject']}'.",
                "metadata": rec,
            }
        else:
            res = {"success": False, "output": "", "error": f"Tool '{tool}' not permitted in sandbox"}
    except Exception as exc:  # noqa: BLE001
        res = {"success": False, "output": "", "error": str(exc)}

    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


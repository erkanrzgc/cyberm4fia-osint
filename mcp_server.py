#!/usr/bin/env python3
"""Minimal MCP (Model Context Protocol) stdio server for cyberm4fia-osint.

Exposes a single tool, ``scan_username``, that runs a ScanConfig against
the engine and returns the JSON payload. Implements just enough of MCP
2024-11 to answer ``initialize``, ``tools/list`` and ``tools/call`` over
newline-delimited JSON-RPC 2.0 on stdio.

Run with:
    python3 mcp_server.py

Tested ad-hoc with a line-oriented JSON-RPC client; does not depend on
the optional ``mcp`` python package.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from typing import Any, cast

from core.config import ScanConfig
from core.engine import run_scan
from utils.helpers import sanitize_username

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "cyberm4fia-osint", "version": "0.1.0"}

TOOLS = [
    {
        "name": "scan_username",
        "description": "Run an OSINT scan across ~90 public platforms for a username.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Target username"},
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional category filter (social, dev, gaming, ...)",
                },
                "deep": {"type": "boolean", "default": True},
                "email": {"type": "boolean", "default": False},
                "smart": {"type": "boolean", "default": False},
            },
            "required": ["username"],
        },
    }
]


def _ok(msg_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


async def _scan(args: dict) -> dict:
    raw = args.get("username")
    if not isinstance(raw, str):
        raise ValueError("username must be a string")
    username = sanitize_username(raw)
    if not username:
        raise ValueError("invalid username")
    categories = args.get("categories")
    cat_tuple = tuple(categories) if isinstance(categories, list) and categories else None
    cfg = ScanConfig(
        username=username,
        deep=bool(args.get("deep", True)),
        smart=bool(args.get("smart", False)),
        email=bool(args.get("email", False)),
        web=False,
        whois=False,
        breach=False,
        photo=False,
        dns=False,
        subdomain=False,
        categories=cat_tuple,
    )
    result = await run_scan(cfg)
    return cast(dict, result.to_dict())


async def _dispatch(request: dict) -> dict | None:
    method = request.get("method")
    msg_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return _ok(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )
    if method == "notifications/initialized":
        return None  # notification, no response
    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if name != "scan_username":
            return _err(msg_id, -32601, f"unknown tool: {name}")
        try:
            payload = await _scan(params.get("arguments") or {})
        except (ValueError, RuntimeError) as exc:
            return _ok(
                msg_id,
                {
                    "isError": True,
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                },
            )
        return _ok(
            msg_id,
            {
                "content": [
                    {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}
                ]
            },
        )

    if msg_id is None:
        return None  # unknown notification
    return _err(msg_id, -32601, f"method not found: {method}")


async def _serve() -> None:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    while True:
        line = await reader.readline()
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        response = await _dispatch(request)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def main() -> None:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())


if __name__ == "__main__":
    main()

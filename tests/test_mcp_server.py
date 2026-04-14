"""Tests for mcp_server.py — JSON-RPC dispatch and scan tool."""

import pytest

import mcp_server
from core.models import ScanResult
from mcp_server import PROTOCOL_VERSION, _dispatch


@pytest.mark.asyncio
async def test_initialize():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp is not None
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert "serverInfo" in resp["result"]


@pytest.mark.asyncio
async def test_tools_list():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert resp is not None
    tools = resp["result"]["tools"]
    assert any(t["name"] == "scan_username" for t in tools)


@pytest.mark.asyncio
async def test_initialized_notification_no_response():
    resp = await _dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert resp is None


@pytest.mark.asyncio
async def test_unknown_method():
    resp = await _dispatch({"jsonrpc": "2.0", "id": 3, "method": "bogus"})
    assert resp is not None
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_unknown_notification():
    resp = await _dispatch({"jsonrpc": "2.0", "method": "bogus/notify"})
    assert resp is None


@pytest.mark.asyncio
async def test_tools_call_unknown_tool():
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "wat", "arguments": {}},
        }
    )
    assert resp is not None
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_tools_call_invalid_username(monkeypatch):
    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "scan_username", "arguments": {"username": ""}},
        }
    )
    assert resp is not None
    assert resp["result"]["isError"] is True


@pytest.mark.asyncio
async def test_tools_call_scan(monkeypatch):
    async def fake_run_scan(cfg):
        r = ScanResult(username=cfg.username)
        return r

    monkeypatch.setattr(mcp_server, "run_scan", fake_run_scan)

    resp = await _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "scan_username",
                "arguments": {"username": "alice", "categories": ["dev"]},
            },
        }
    )
    assert resp is not None
    content = resp["result"]["content"][0]["text"]
    assert '"username": "alice"' in content

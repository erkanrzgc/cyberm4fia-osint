"""Tests for modules/web_presence.py."""

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.web_presence import (
    check_paste_sites,
    check_wayback,
    discover_web_presence,
)


@pytest.mark.asyncio
async def test_wayback_none():
    with aioresponses() as m:
        m.get(
            "https://archive.org/wayback/available?url=https://x/u",
            status=200,
            payload={"archived_snapshots": {}},
        )
        async with HTTPClient() as client:
            result = await check_wayback(client, "https://x/u")
    assert result is None


@pytest.mark.asyncio
async def test_wayback_found():
    snapshot = {
        "archived_snapshots": {
            "closest": {
                "url": "https://web.archive.org/web/2020/...",
                "timestamp": "20200101000000",
                "status": "200",
                "available": True,
            }
        }
    }
    with aioresponses() as m:
        m.get(
            "https://archive.org/wayback/available?url=https://x/u",
            status=200,
            payload=snapshot,
        )
        async with HTTPClient() as client:
            result = await check_wayback(client, "https://x/u")
    assert result is not None
    assert result["timestamp"] == "20200101000000"
    assert result["available"] is True


@pytest.mark.asyncio
async def test_wayback_500():
    with aioresponses() as m:
        m.get(
            "https://archive.org/wayback/available?url=https://x/u",
            status=500,
        )
        async with HTTPClient() as client:
            result = await check_wayback(client, "https://x/u")
    assert result is None


@pytest.mark.asyncio
async def test_paste_sites_hits():
    with aioresponses() as m:
        m.get(
            "https://psbdmp.ws/api/v3/search/alice",
            status=200,
            payload=[{"id": "x1", "time": "2024", "tags": "leaked"}],
        )
        async with HTTPClient() as client:
            result = await check_paste_sites(client, "alice")
    assert len(result) == 1
    assert result[0]["id"] == "x1"


@pytest.mark.asyncio
async def test_paste_sites_empty():
    with aioresponses() as m:
        m.get("https://psbdmp.ws/api/v3/search/alice", status=200, payload=[])
        async with HTTPClient() as client:
            result = await check_paste_sites(client, "alice")
    assert result == []


@pytest.mark.asyncio
async def test_discover_web_presence():
    with aioresponses() as m:
        # Found profile url: no wayback snapshot
        m.get(
            "https://archive.org/wayback/available?url=https://gh/alice",
            status=200,
            payload={"archived_snapshots": {}},
        )
        # Domain variants: all empty
        for tld in [".com", ".net", ".org", ".io", ".dev"]:
            m.get(
                f"https://archive.org/wayback/available?url=alice{tld}",
                status=200,
                payload={"archived_snapshots": {}},
            )
        m.get("https://psbdmp.ws/api/v3/search/alice", status=200, payload=[])
        async with HTTPClient() as client:
            result = await discover_web_presence(
                client, "alice", ["https://gh/alice"]
            )
    assert result == []

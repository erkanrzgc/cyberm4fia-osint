"""Tests for modules.comb_leaks — ProxyNova COMB credential-leak search."""

from __future__ import annotations

import pytest

from modules.comb_leaks import (
    CombLeak,
    _mask,
    _parse_line,
    search_comb,
    search_comb_many,
)


def test_mask_short_password():
    assert _mask("") == ""
    assert _mask("a") == "*"
    assert _mask("ab") == "**"


def test_mask_regular_password():
    assert _mask("secret") == "s****t"
    assert _mask("abc") == "a*c"


def test_parse_line_basic():
    leak = _parse_line("alice@example.com:hunter2")
    assert leak is not None
    assert leak.identifier == "alice@example.com"
    assert leak.password_preview == "h*****2"
    assert leak.raw_length == 7
    assert leak.extras == ()


def test_parse_line_with_extras():
    leak = _parse_line("bob:password:extra1:extra2")
    assert leak is not None
    assert leak.identifier == "bob"
    assert leak.extras == ("extra1", "extra2")


def test_parse_line_rejects_malformed():
    assert _parse_line("no-colon-here") is None
    assert _parse_line(":onlypass") is None


class _FakeClient:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status
        self.calls: list[str] = []

    async def get_json(self, url, headers=None):
        self.calls.append(url)
        return self.status, self.payload, {}


@pytest.mark.asyncio
async def test_search_comb_parses_lines():
    client = _FakeClient(
        {
            "count": 2,
            "lines": [
                "target@example.com:password123",
                "target@other.com:abcdef",
            ],
        }
    )
    leaks = await search_comb(client, "target")
    assert len(leaks) == 2
    assert leaks[0].identifier == "target@example.com"
    assert leaks[0].password_preview == "p" + "*" * 9 + "3"
    assert "query=target" in client.calls[0]


@pytest.mark.asyncio
async def test_search_comb_empty_query_returns_empty():
    client = _FakeClient({"lines": []})
    assert await search_comb(client, "") == []
    assert client.calls == []


@pytest.mark.asyncio
async def test_search_comb_handles_non_200():
    client = _FakeClient({"lines": ["a:b"]}, status=429)
    assert await search_comb(client, "x") == []


@pytest.mark.asyncio
async def test_search_comb_handles_bad_payload():
    client = _FakeClient({"lines": "not-a-list"})
    assert await search_comb(client, "x") == []


@pytest.mark.asyncio
async def test_search_comb_many_parallel():
    client = _FakeClient(
        {"lines": ["user@a.com:pass"]},
    )
    results = await search_comb_many(client, ["alice", "bob"])
    assert set(results.keys()) == {"alice", "bob"}
    assert all(len(v) == 1 for v in results.values())


@pytest.mark.asyncio
async def test_search_comb_many_skips_empty():
    client = _FakeClient({"lines": []})
    results = await search_comb_many(client, ["", None])  # type: ignore[list-item]
    assert results == {}


def test_comb_leak_is_frozen():
    leak = CombLeak(identifier="x", password_preview="*", raw_length=1)
    with pytest.raises(Exception):
        leak.identifier = "y"  # type: ignore[misc]

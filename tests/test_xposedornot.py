"""Tests for XposedOrNot integration and HIBP/XposedOrNot merge logic."""

from __future__ import annotations

import pytest

from modules.breach_check import (
    _merge_breaches,
    check_email_xposedornot,
    check_many_emails,
)


class _FakeClient:
    def __init__(self, responses):
        # responses keyed by substring in URL
        self.responses = responses
        self.calls: list[str] = []

    async def get_json(self, url, headers=None):
        self.calls.append(url)
        for key, (status, payload) in self.responses.items():
            if key in url:
                return status, payload, {}
        return 404, None, {}


@pytest.mark.asyncio
async def test_xposedornot_nested_list_shape():
    client = _FakeClient(
        {
            "xposedornot": (
                200,
                {"breaches": [["LinkedIn", "Adobe"]]},
            )
        }
    )
    res = await check_email_xposedornot(client, "user@example.com")
    names = {b["name"] for b in res}
    assert names == {"LinkedIn", "Adobe"}
    assert all(b["source"] == "xposedornot" for b in res)


@pytest.mark.asyncio
async def test_xposedornot_flat_list_shape():
    client = _FakeClient(
        {"xposedornot": (200, {"breaches": ["MySpace"]})}
    )
    res = await check_email_xposedornot(client, "user@example.com")
    assert [b["name"] for b in res] == ["MySpace"]


@pytest.mark.asyncio
async def test_xposedornot_non_200_returns_empty():
    client = _FakeClient({"xposedornot": (404, None)})
    assert await check_email_xposedornot(client, "x@y.com") == []


def test_merge_prefers_hibp_over_xposedornot():
    xpo = [{"name": "Adobe", "title": "Adobe", "source": "xposedornot"}]
    hibp = [{"name": "Adobe", "title": "Adobe", "pwn_count": 153000000}]
    merged = _merge_breaches(xpo, hibp)
    assert len(merged) == 1
    assert merged[0].get("pwn_count") == 153000000
    assert "source" not in merged[0]


def test_merge_dedupes_case_insensitive():
    a = [{"name": "LinkedIn"}]
    b = [{"name": "linkedin"}]
    merged = _merge_breaches(a, b)
    assert len(merged) == 1


def test_merge_skips_empty_names():
    merged = _merge_breaches([{"name": ""}, {"title": None}])
    assert merged == []


@pytest.mark.asyncio
async def test_check_many_emails_without_hibp(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    client = _FakeClient(
        {"xposedornot": (200, {"breaches": [["Canva"]]})}
    )
    out = await check_many_emails(client, ["a@b.com"])
    assert "a@b.com" in out
    assert out["a@b.com"][0]["name"] == "Canva"

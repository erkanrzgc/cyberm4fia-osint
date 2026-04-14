"""Tests for modules.toutatis_lookup."""

from __future__ import annotations

import pytest

from modules import toutatis_lookup
from modules.toutatis_lookup import (
    ToutatisResult,
    _from_user_dict,
    lookup_username,
    lookup_usernames,
)


def test_from_user_dict_pulls_fields():
    res = _from_user_dict(
        "instagram",
        {
            "pk": 123,
            "full_name": "Insta",
            "is_private": False,
            "is_verified": True,
            "follower_count": 99,
            "biography": "official",
            "external_url": "https://instagram.com",
            "obfuscated_email": "i***@example.com",
            "profile_pic_url_hd": "https://cdn/x.jpg",
        },
    )
    assert res.user_id == "123"
    assert res.is_verified is True
    assert res.follower_count == 99
    assert res.profile_pic.endswith("x.jpg")


@pytest.mark.asyncio
async def test_lookup_username_returns_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(toutatis_lookup, "_AVAILABLE", False)
    assert await lookup_username("alice") is None


@pytest.mark.asyncio
async def test_lookup_username_handles_failed_payload(monkeypatch):
    monkeypatch.setattr(toutatis_lookup, "_AVAILABLE", True)
    monkeypatch.setenv("IG_SESSION_ID", "")

    def fake_advanced(username):
        return {"user": {"status": "fail"}}

    monkeypatch.setattr(toutatis_lookup, "_advanced_lookup", fake_advanced)
    assert await lookup_username("alice") is None


@pytest.mark.asyncio
async def test_lookup_username_returns_result(monkeypatch):
    monkeypatch.setattr(toutatis_lookup, "_AVAILABLE", True)
    monkeypatch.delenv("IG_SESSION_ID", raising=False)

    def fake_advanced(username):
        return {"user": {"pk": 42, "full_name": "Alice"}}

    monkeypatch.setattr(toutatis_lookup, "_advanced_lookup", fake_advanced)
    res = await lookup_username("alice")
    assert isinstance(res, ToutatisResult)
    assert res.user_id == "42"
    assert res.full_name == "Alice"


@pytest.mark.asyncio
async def test_lookup_username_uses_session_when_set(monkeypatch):
    monkeypatch.setattr(toutatis_lookup, "_AVAILABLE", True)
    monkeypatch.setenv("IG_SESSION_ID", "fake-session")
    called: dict[str, str] = {}

    def fake_get_info(username, sessionId):
        called["session"] = sessionId
        return {"user": {"pk": 1}}

    monkeypatch.setattr(toutatis_lookup, "_get_info", fake_get_info)
    res = await lookup_username("alice")
    assert res is not None
    assert called["session"] == "fake-session"


@pytest.mark.asyncio
async def test_lookup_usernames_filters_nones(monkeypatch):
    monkeypatch.setattr(toutatis_lookup, "_AVAILABLE", True)
    monkeypatch.delenv("IG_SESSION_ID", raising=False)

    def fake_advanced(username):
        if username == "good":
            return {"user": {"pk": 1, "full_name": "Good"}}
        return {"user": {"status": "fail"}}

    monkeypatch.setattr(toutatis_lookup, "_advanced_lookup", fake_advanced)
    out = await lookup_usernames(["good", "bad", ""])
    assert set(out.keys()) == {"good"}
    assert out["good"].full_name == "Good"


def test_toutatis_result_is_frozen():
    res = ToutatisResult(username="x")
    with pytest.raises(Exception):
        res.user_id = "z"  # type: ignore[misc]

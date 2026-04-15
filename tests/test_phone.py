"""Tests for the Sprint 4 phone OSINT module."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.phone import lookup_phone
from modules.phone.models import PhoneIntel
from modules.phone.offline import parse_offline


def test_phone_intel_to_dict_roundtrip() -> None:
    intel = PhoneIntel(
        raw="+14155552671",
        e164="+14155552671",
        national="(415) 555-2671",
        country_code=1,
        region="US",
        country_name="United States",
        carrier="",
        timezones=("America/Los_Angeles",),
        line_type="fixed_line_or_mobile",
        valid=True,
        possible=True,
        sources=("phonenumbers",),
    )
    d = intel.to_dict()
    assert d["e164"] == "+14155552671"
    assert d["timezones"] == ["America/Los_Angeles"]
    assert d["sources"] == ["phonenumbers"]


def test_parse_offline_valid_us_number() -> None:
    meta = parse_offline("+14155552671")
    assert meta["region"] == "US"
    assert meta["country_code"] == 1
    assert meta["valid"] is True
    assert meta["e164"] == "+14155552671"
    assert "America" in (meta["timezones"][0] if meta["timezones"] else "")


def test_parse_offline_uses_default_region() -> None:
    # National format (no +) requires a default region
    meta = parse_offline("4155552671", default_region="US")
    assert meta.get("region") == "US"
    assert meta.get("valid") is True


def test_parse_offline_garbage_returns_empty() -> None:
    assert parse_offline("not a phone") == {}
    assert parse_offline("") == {}


@pytest.mark.asyncio
async def test_lookup_phone_offline_only(monkeypatch) -> None:
    monkeypatch.delenv("NUMVERIFY_API_KEY", raising=False)
    async with HTTPClient() as client:
        intel = await lookup_phone(client, "+14155552671")
    assert intel is not None
    assert intel.valid is True
    assert intel.region == "US"
    assert intel.sources == ("phonenumbers",)


@pytest.mark.asyncio
async def test_lookup_phone_enriched_with_numverify(monkeypatch) -> None:
    monkeypatch.setenv("NUMVERIFY_API_KEY", "fake")
    payload = {
        "valid": True,
        "number": "14155552671",
        "country_code": "US",
        "country_name": "United States",
        "location": "California",
        "carrier": "AT&T Mobility",
        "line_type": "mobile",
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://apilayer\.net/.*"), payload=payload)
        async with HTTPClient() as client:
            intel = await lookup_phone(client, "+14155552671")
    assert intel is not None
    assert "numverify" in intel.sources
    assert intel.carrier == "AT&T Mobility"
    assert intel.line_type == "mobile"
    assert intel.metadata["location"] == "California"


@pytest.mark.asyncio
async def test_lookup_phone_invalid_returns_none() -> None:
    async with HTTPClient() as client:
        assert await lookup_phone(client, "garbage") is None

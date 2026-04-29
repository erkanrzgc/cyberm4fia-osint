"""Tests for the Criminal IP passive source."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.passive import criminalip


@pytest.mark.asyncio
async def test_criminalip_skips_without_key(monkeypatch) -> None:
    monkeypatch.delenv("CRIMINALIP_API_KEY", raising=False)
    async with HTTPClient() as client:
        assert await criminalip.search(client, "example.com") == []


@pytest.mark.asyncio
async def test_criminalip_parses_ip_data(monkeypatch) -> None:
    monkeypatch.setenv("CRIMINALIP_API_KEY", "fake")
    payload = {
        "status": 200,
        "data": {
            "result_number": 2,
            "ip_data": [
                {
                    "ip_address": "1.2.3.4",
                    "country_code": "US",
                    "as_name": "Example Corp",
                    "open_port_no": 443,
                    "vulnerability_count": 3,
                    "honeypot_count": 0,
                    "score": {"inbound": 4, "outbound": 2},
                    "products": ["nginx", "openssl"],
                    "hostname": "edge.example.com",
                },
                {
                    "ip_address": "5.6.7.8",
                    "country_code": "DE",
                    "as_name": "ISP B",
                    "open_port_no": 22,
                    "vulnerability_count": 0,
                    "score": {"inbound": 0, "outbound": 0},
                    "products": ["openssh"],
                },
            ],
        },
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await criminalip.search(client, "example.com")

    assert [h.value for h in hits] == ["1.2.3.4", "5.6.7.8"]
    first = hits[0]
    assert first.source == "criminalip"
    assert first.kind == "host"
    assert first.title == "edge.example.com"
    assert first.metadata["country"] == "US"
    assert first.metadata["asn"] == "Example Corp"
    assert first.metadata["port"] == 443
    assert first.metadata["vulnerability_count"] == 3
    assert first.metadata["score_inbound"] == 4
    assert first.metadata["products"] == ["nginx", "openssl"]
    # Second hit has no hostname → title falls back to IP
    assert hits[1].title == "5.6.7.8"


@pytest.mark.asyncio
async def test_criminalip_handles_malformed_payload(monkeypatch) -> None:
    monkeypatch.setenv("CRIMINALIP_API_KEY", "fake")
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"),
              payload={"status": 401, "message": "unauthorized"})
        async with HTTPClient() as client:
            hits = await criminalip.search(client, "example.com")
    assert hits == []


@pytest.mark.asyncio
async def test_criminalip_handles_empty_ip_data(monkeypatch) -> None:
    monkeypatch.setenv("CRIMINALIP_API_KEY", "fake")
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"),
              payload={"status": 200, "data": {"ip_data": []}})
        async with HTTPClient() as client:
            assert await criminalip.search(client, "example.com") == []


@pytest.mark.asyncio
async def test_criminalip_skips_rows_without_ip(monkeypatch) -> None:
    monkeypatch.setenv("CRIMINALIP_API_KEY", "fake")
    payload = {
        "status": 200,
        "data": {
            "ip_data": [
                {"ip_address": "", "country_code": "US"},
                {"country_code": "FR"},  # missing key entirely
                {"ip_address": "9.9.9.9", "country_code": "FR"},
            ],
        },
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await criminalip.search(client, "example.com")
    assert [h.value for h in hits] == ["9.9.9.9"]


@pytest.mark.asyncio
async def test_criminalip_respects_limit(monkeypatch) -> None:
    monkeypatch.setenv("CRIMINALIP_API_KEY", "fake")
    payload = {
        "status": 200,
        "data": {
            "ip_data": [
                {"ip_address": f"1.1.1.{i}", "country_code": "US"} for i in range(20)
            ],
        },
    }
    with aioresponses() as m:
        m.get(re.compile(r"https://api\.criminalip\.io/.*"), payload=payload)
        async with HTTPClient() as client:
            hits = await criminalip.search(client, "example.com", limit=5)
    assert len(hits) == 5

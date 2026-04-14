"""Tests for dns_lookup and whois_lookup with stubbed resolvers."""

import sys
import types
from typing import ClassVar

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules import whois_lookup
from modules.dns_lookup import enumerate_subdomains, get_dns_records
from modules.whois_lookup import check_username_domains, lookup_domain


@pytest.mark.asyncio
async def test_get_dns_records_no_dnspython(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "dns.resolver" or name.startswith("dns"):
            raise ImportError("stub")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    result = await get_dns_records("example.com")
    assert result == {}


@pytest.mark.asyncio
async def test_get_dns_records_success(monkeypatch):
    class FakeAnswer:
        def __init__(self, val):
            self._val = val

        def __str__(self):
            return self._val

    calls = {"count": 0}

    def fake_resolve(domain, rtype, lifetime=5):
        calls["count"] += 1
        if rtype == "A":
            return [FakeAnswer("1.2.3.4")]
        raise RuntimeError("no record")

    fake_dns = types.SimpleNamespace(
        resolver=types.SimpleNamespace(resolve=fake_resolve)
    )
    monkeypatch.setitem(sys.modules, "dns", fake_dns)
    monkeypatch.setitem(sys.modules, "dns.resolver", fake_dns.resolver)

    result = await get_dns_records("example.com")
    assert result.get("A") == ["1.2.3.4"]
    assert "AAAA" not in result


@pytest.mark.asyncio
async def test_enumerate_subdomains_success():
    payload = [
        {"name_value": "a.example.com\nb.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "c.example.com"},
    ]
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.example.com&output=json",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            result = await enumerate_subdomains(client, "example.com")
    assert "a.example.com" in result
    assert "b.example.com" in result
    assert "c.example.com" in result
    # wildcard skipped
    assert not any("*" in s for s in result)


@pytest.mark.asyncio
async def test_enumerate_subdomains_error():
    with aioresponses() as m:
        m.get(
            "https://crt.sh/?q=%25.example.com&output=json",
            status=500,
        )
        async with HTTPClient() as client:
            result = await enumerate_subdomains(client, "example.com")
    assert result == []


@pytest.mark.asyncio
async def test_lookup_domain_no_library(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "whois":
            raise ImportError("stub")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    result = await lookup_domain("example.com")
    assert result is None


@pytest.mark.asyncio
async def test_lookup_domain_success(monkeypatch):
    class FakeResult:
        domain_name = "example.com"
        registrar = "Reg"
        creation_date = "2020-01-01"
        expiration_date = "2030-01-01"
        updated_date = None
        name_servers: ClassVar[list[str]] = ["ns1", "ns2"]
        emails = "a@b.com"
        org = "Org"
        country = "TR"
        name = "Alice"

    fake_whois = types.SimpleNamespace(whois=lambda d: FakeResult())
    monkeypatch.setitem(sys.modules, "whois", fake_whois)

    result = await lookup_domain("example.com")
    assert result is not None
    assert result["registrar"] == "Reg"
    assert result["name_servers"] == "ns1, ns2"
    assert result["org"] == "Org"


@pytest.mark.asyncio
async def test_lookup_domain_empty_result(monkeypatch):
    class FakeResult:
        domain_name = None

    fake_whois = types.SimpleNamespace(whois=lambda d: FakeResult())
    monkeypatch.setitem(sys.modules, "whois", fake_whois)
    assert await lookup_domain("example.com") is None


@pytest.mark.asyncio
async def test_lookup_domain_raises(monkeypatch):
    def boom(domain):
        raise RuntimeError("whois error")

    fake_whois = types.SimpleNamespace(whois=boom)
    monkeypatch.setitem(sys.modules, "whois", fake_whois)
    assert await lookup_domain("example.com") is None


@pytest.mark.asyncio
async def test_check_username_domains(monkeypatch):
    async def fake_lookup(domain):
        if domain == "alice.com":
            return {"domain": domain, "registrar": "R"}
        return None

    monkeypatch.setattr(whois_lookup, "lookup_domain", fake_lookup)
    result = await check_username_domains("alice")
    assert len(result) == 1
    assert result[0]["domain"] == "alice.com"

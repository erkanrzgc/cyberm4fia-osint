"""Tests for modules/recon/subdomains_extra.py."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.recon.subdomains_extra import enrich_subdomains, fetch_extra


@pytest.mark.asyncio
async def test_fetch_extra_empty_domain():
    async with HTTPClient() as client:
        assert await fetch_extra(client, "") == []


@pytest.mark.asyncio
async def test_fetch_extra_merges_sources():
    rapiddns_body = (
        "<html><body>"
        "<table><tr><td>api.example.com</td></tr>"
        "<tr><td>login.example.com</td></tr>"
        "<tr><td>unrelated.org</td></tr></table>"
        "</body></html>"
    )
    anubis_payload = ["api.example.com", "vpn.example.com", "*.example.com"]
    with aioresponses() as m:
        m.get(
            "https://rapiddns.io/subdomain/example.com?full=1#result",
            status=200,
            body=rapiddns_body,
        )
        m.get(
            "https://jldc.me/anubis/subdomains/example.com",
            status=200,
            payload=anubis_payload,
        )
        async with HTTPClient() as client:
            hits = await fetch_extra(client, "example.com")
    hosts = {h.host for h in hits}
    assert "api.example.com" in hosts
    assert "login.example.com" in hosts
    assert "vpn.example.com" in hosts
    assert "unrelated.org" not in hosts
    # wildcard hosts are filtered
    assert not any("*" in h.host for h in hits)


@pytest.mark.asyncio
async def test_enrich_subdomains_tags_existing():
    with aioresponses() as m:
        m.get(
            "https://rapiddns.io/subdomain/example.com?full=1#result",
            status=404,
        )
        m.get(
            "https://jldc.me/anubis/subdomains/example.com",
            status=404,
        )
        async with HTTPClient() as client:
            out = await enrich_subdomains(
                client,
                "example.com",
                existing=["api.example.com", "www.example.com"],
            )
    sources = {h.host: h.source for h in out}
    assert sources["api.example.com"] == "dns_lookup"
    assert sources["www.example.com"] == "dns_lookup"


@pytest.mark.asyncio
async def test_enrich_subdomains_dedupes_across_sources():
    with aioresponses() as m:
        m.get(
            "https://rapiddns.io/subdomain/example.com?full=1#result",
            status=200,
            body="<html>api.example.com</html>",
        )
        m.get(
            "https://jldc.me/anubis/subdomains/example.com",
            status=200,
            payload=["api.example.com", "beta.example.com"],
        )
        async with HTTPClient() as client:
            out = await enrich_subdomains(
                client, "example.com", existing=["api.example.com"]
            )
    hosts = [h.host for h in out]
    assert hosts.count("api.example.com") == 1
    assert "beta.example.com" in hosts
    # first-seen source is preserved: existing list came first
    api_src = next(h.source for h in out if h.host == "api.example.com")
    assert api_src == "dns_lookup"

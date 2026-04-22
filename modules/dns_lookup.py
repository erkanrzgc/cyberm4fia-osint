"""DNS records and subdomain enumeration."""

from __future__ import annotations

import asyncio

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)


async def get_dns_records(domain: str) -> dict:
    try:
        import dns.resolver
    except ImportError:
        log.debug("dnspython not installed; skipping DNS for %s", domain)
        return {}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results: dict[str, list[str]] = {}
    for rtype in record_types:
        def _resolve(r: str = rtype) -> list[str]:
            return [str(a) for a in dns.resolver.resolve(domain, r, lifetime=5)]

        try:
            results[rtype] = _resolve()
        except Exception as exc:  # dnspython exposes many specific errors
            log.debug("dns %s %s: %s", rtype, domain, exc)
            continue

    return results


async def _from_crtsh(client: HTTPClient, domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, data, _ = await client.get_json(url)
    if status != 200 or not data:
        return set()
    out: set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line and "*" not in line:
                out.add(line)
    return out


async def _from_otx(client: HTTPClient, domain: str) -> set[str]:
    """AlienVault OTX passive DNS — no API key required."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for entry in data.get("passive_dns", []):
        host = entry.get("hostname", "")
        if isinstance(host, str):
            host = host.strip().lower()
            if host and "*" not in host and host.endswith(domain):
                out.add(host)
    return out


async def _from_hackertarget(client: HTTPClient, domain: str) -> set[str]:
    """HackerTarget hostsearch — free tier, rate-limited per IP."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, body, _ = await client.get(url)
    if status != 200 or not body or "error" in body.lower():
        return set()
    out: set[str] = set()
    for line in body.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if host and "*" not in host and host.endswith(domain):
            out.add(host)
    return out


async def enumerate_subdomains(client: HTTPClient, domain: str) -> list[str]:
    """Aggregate subdomains from multiple free passive sources.

    Sources: crt.sh (certificate transparency), AlienVault OTX (passive DNS),
    HackerTarget (hostsearch). Runs queries in parallel and merges the
    deduped union.
    """
    sources = await asyncio.gather(
        _from_crtsh(client, domain),
        _from_otx(client, domain),
        _from_hackertarget(client, domain),
        return_exceptions=True,
    )
    merged: set[str] = set()
    for s in sources:
        if isinstance(s, set):
            merged |= s
    return sorted(merged)

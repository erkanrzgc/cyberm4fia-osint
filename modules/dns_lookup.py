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
    loop = asyncio.get_event_loop()

    for rtype in record_types:
        def _resolve(r: str = rtype) -> list[str]:
            return [str(a) for a in dns.resolver.resolve(domain, r, lifetime=5)]

        try:
            results[rtype] = await loop.run_in_executor(None, _resolve)
        except Exception as exc:  # dnspython exposes many specific errors
            log.debug("dns %s %s: %s", rtype, domain, exc)
            continue

    return results


async def enumerate_subdomains(client: HTTPClient, domain: str) -> list[str]:
    """Use crt.sh certificate transparency logs to find subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, data, _ = await client.get_json(url)
    if status != 200 or not data:
        return []

    subdomains = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line and "*" not in line:
                subdomains.add(line)

    return sorted(subdomains)

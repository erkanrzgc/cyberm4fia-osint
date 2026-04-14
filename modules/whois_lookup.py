"""WHOIS lookup for domains."""

from __future__ import annotations

import asyncio

from core.logging_setup import get_logger

log = get_logger(__name__)


async def lookup_domain(domain: str) -> dict | None:
    try:
        import whois
    except ImportError:
        log.debug("python-whois not installed; skipping %s", domain)
        return None

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, whois.whois, domain)
    except Exception as exc:  # python-whois surfaces many distinct types
        log.debug("whois lookup failed for %s: %s", domain, exc)
        return None

    if not result or not result.domain_name:
        return None

    def stringify(val):
        if val is None:
            return ""
        if isinstance(val, list):
            return ", ".join(str(v) for v in val if v)
        return str(val)

    return {
        "domain": domain,
        "registrar": stringify(result.registrar),
        "creation_date": stringify(result.creation_date),
        "expiration_date": stringify(result.expiration_date),
        "updated_date": stringify(result.updated_date),
        "name_servers": stringify(result.name_servers),
        "emails": stringify(result.emails),
        "org": stringify(result.org if hasattr(result, "org") else None),
        "country": stringify(result.country if hasattr(result, "country") else None),
        "registrant": stringify(
            result.name if hasattr(result, "name") else None
        ),
    }


async def check_username_domains(username: str) -> list[dict]:
    """Check if username has registered domains across common TLDs."""
    tlds = [".com", ".net", ".org", ".io", ".dev", ".me", ".co", ".xyz", ".app"]
    results = []
    tasks = [lookup_domain(f"{username}{tld}") for tld in tlds]
    domain_data = await asyncio.gather(*tasks, return_exceptions=True)

    for data in domain_data:
        if isinstance(data, dict) and data:
            results.append(data)

    return results

"""Extra passive subdomain sources on top of ``modules.dns_lookup``.

``dns_lookup.enumerate_subdomains`` already covers crt.sh, AlienVault
OTX, and HackerTarget. This module adds two more free providers without
rewriting the existing pipeline:

* **RapidDNS** — HTML scraper, returns subdomains observed in historic
  DNS data.
* **AnubisDB** — JSON API by JonLuca De Caro, aggregates several
  upstream providers.

The public entry point ``enrich_subdomains`` takes the output of the
existing enumerator and returns a merged, deduped list of
``ReconSubdomain`` entries so downstream code sees provenance.
"""

from __future__ import annotations

import asyncio
import re

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon.models import ReconSubdomain

log = get_logger(__name__)

# Very loose hostname matcher — we filter against the target domain
# suffix before accepting, so over-matching here is fine.
_HOST_RE = re.compile(r"([a-z0-9][a-z0-9\-\.]*[a-z0-9])", re.IGNORECASE)


def _accept(host: str, domain: str) -> str | None:
    host = host.strip().lower().rstrip(".")
    if not host or "*" in host or " " in host:
        return None
    if host == domain or host.endswith("." + domain):
        return host
    return None


async def _rapiddns(client: HTTPClient, domain: str) -> list[ReconSubdomain]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    status, body, _ = await client.get(url)
    if status != 200 or not body:
        return []
    out: list[ReconSubdomain] = []
    seen: set[str] = set()
    for raw in _HOST_RE.findall(body):
        host = _accept(raw, domain)
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(ReconSubdomain(host=host, source="rapiddns"))
    return out


async def _anubisdb(client: HTTPClient, domain: str) -> list[ReconSubdomain]:
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, list):
        return []
    out: list[ReconSubdomain] = []
    seen: set[str] = set()
    for raw in data:
        if not isinstance(raw, str):
            continue
        host = _accept(raw, domain)
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(ReconSubdomain(host=host, source="anubisdb"))
    return out


async def fetch_extra(
    client: HTTPClient, domain: str
) -> list[ReconSubdomain]:
    """Query just the extra sources. Useful in tests."""
    if not domain:
        return []
    jobs = [_rapiddns(client, domain), _anubisdb(client, domain)]
    results = await asyncio.gather(*jobs, return_exceptions=True)
    merged: list[ReconSubdomain] = []
    for source_name, batch in zip(("rapiddns", "anubisdb"), results, strict=True):
        if isinstance(batch, BaseException):
            log.debug("subdomain source %s failed: %s", source_name, batch)
            continue
        merged.extend(batch)
    return merged


def _dedupe(hits: list[ReconSubdomain]) -> list[ReconSubdomain]:
    """Keep first-seen source per host; callers still see all unique hosts."""
    seen: set[str] = set()
    out: list[ReconSubdomain] = []
    for hit in hits:
        if hit.host in seen:
            continue
        seen.add(hit.host)
        out.append(hit)
    out.sort(key=lambda h: h.host)
    return out


async def enrich_subdomains(
    client: HTTPClient,
    domain: str,
    existing: list[str] | None = None,
) -> list[ReconSubdomain]:
    """Return merged subdomain list: ``existing`` + RapidDNS + AnubisDB.

    ``existing`` comes from the older enumerator and is tagged with
    ``source='dns_lookup'`` so the reporter can distinguish seeds from
    newly discovered hosts.
    """
    out: list[ReconSubdomain] = []
    for host in existing or []:
        normalized = _accept(host, domain) if domain else host.strip().lower()
        if normalized:
            out.append(ReconSubdomain(host=normalized, source="dns_lookup"))
    out.extend(await fetch_extra(client, domain))
    return _dedupe(out)

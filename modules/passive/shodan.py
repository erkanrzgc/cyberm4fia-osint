"""Shodan host lookup.

We do not use shodan's Python client — it's sync-only and pulls a stack
of dependencies we don't need. A single REST call to ``/shodan/host/search``
is enough for the domain-pivot use case, and keeping the call inline
lets us reuse our rate-limited ``HTTPClient``.

Requires ``SHODAN_API_KEY`` in the environment.
"""

from __future__ import annotations

import os
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://api.shodan.io/shodan/host/search"


def _api_key() -> str | None:
    return os.environ.get("SHODAN_API_KEY")


async def search(
    client: HTTPClient,
    domain: str,
    *,
    limit: int = 50,
) -> list[PassiveHit]:
    """Query Shodan for hosts that mention ``domain``.

    Returns an empty list if no API key is configured or the request
    fails — callers should always treat passive intel as best-effort.
    """
    key = _api_key()
    if not key:
        log.debug("SHODAN_API_KEY not set; skipping shodan search")
        return []

    query = quote(f"hostname:{domain}")
    url = f"{_ENDPOINT}?key={key}&query={query}"
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return []

    hits: list[PassiveHit] = []
    for match in (data.get("matches") or [])[:limit]:
        ip = match.get("ip_str") or ""
        if not ip:
            continue
        hits.append(
            PassiveHit(
                source="shodan",
                kind="host",
                value=ip,
                title=", ".join(match.get("hostnames") or []) or ip,
                metadata={
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "isp": match.get("isp"),
                    "asn": match.get("asn"),
                    "country": (match.get("location") or {}).get("country_name"),
                    "product": match.get("product"),
                    "transport": match.get("transport"),
                },
            )
        )
    return hits

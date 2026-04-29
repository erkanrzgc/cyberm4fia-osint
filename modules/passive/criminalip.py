"""Criminal IP host search.

Criminal IP indexes the same kind of internet-facing assets that Shodan
and Censys do, with two distinguishing signals worth pivoting on:

* a per-host **attack-surface score** (``inbound`` / ``outbound``)
  expressing how exposed Criminal IP thinks the asset is, and
* explicit **vulnerability** and **honeypot** counts derived from their
  banner heuristics.

Adding it to the passive fan-out gives the orchestrator three
independent host-discovery sources (Shodan / Censys / Criminal IP),
which materially improves recall on hosts that any single index misses.

Requires ``CRIMINALIP_API_KEY``. Auth is a header (``x-api-key``); when
the key is absent we silently no-op like every other passive source.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://api.criminalip.io/v1/asset/ip/search"


def _api_key() -> str | None:
    return os.environ.get("CRIMINALIP_API_KEY")


def _row_to_hit(row: dict[str, Any]) -> PassiveHit | None:
    ip = (row.get("ip_address") or "").strip()
    if not ip:
        return None
    score = row.get("score") or {}
    return PassiveHit(
        source="criminalip",
        kind="host",
        value=ip,
        title=(row.get("hostname") or "").strip() or ip,
        metadata={
            "country": row.get("country_code"),
            "asn": row.get("as_name"),
            "port": row.get("open_port_no"),
            "vulnerability_count": row.get("vulnerability_count"),
            "honeypot_count": row.get("honeypot_count"),
            "score_inbound": score.get("inbound") if isinstance(score, dict) else None,
            "score_outbound": score.get("outbound") if isinstance(score, dict) else None,
            "products": list(row.get("products") or []),
        },
    )


async def search(
    client: HTTPClient,
    domain: str,
    *,
    limit: int = 50,
) -> list[PassiveHit]:
    """Query Criminal IP for hosts associated with ``domain``.

    Returns an empty list when no API key is set or the upstream errors
    out — passive sources are best-effort by contract.
    """
    key = _api_key()
    if not key:
        log.debug("CRIMINALIP_API_KEY not set; skipping criminalip search")
        return []

    query = quote(f"domain:{domain}")
    url = f"{_ENDPOINT}?query={query}&offset=0"
    status, data, _ = await client.get_json(
        url, headers={"x-api-key": key}
    )
    if status != 200 or not isinstance(data, dict):
        return []
    if data.get("status") and data.get("status") != 200:
        # Criminal IP returns its own status field inside the body even
        # when the HTTP envelope is 200. Treat any non-200 there as an
        # auth/quota issue rather than parsing it as data.
        return []

    payload = data.get("data") or {}
    rows = payload.get("ip_data") or []
    if not isinstance(rows, list):
        return []

    hits: list[PassiveHit] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        hit = _row_to_hit(row)
        if hit is not None:
            hits.append(hit)
    return hits

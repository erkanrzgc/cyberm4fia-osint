"""ZoomEye host search.

Uses the v2 ``/host/search`` endpoint authenticated with the
``API-KEY`` header. Requires ``ZOOMEYE_API_KEY``.
"""

from __future__ import annotations

import os
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://api.zoomeye.org/host/search"


async def search(
    client: HTTPClient,
    domain: str,
    *,
    limit: int = 50,
) -> list[PassiveHit]:
    key = os.environ.get("ZOOMEYE_API_KEY")
    if not key:
        log.debug("ZOOMEYE_API_KEY not set; skipping zoomeye search")
        return []

    query = quote(f"hostname:{domain}")
    url = f"{_ENDPOINT}?query={query}&page=1"
    headers = {"API-KEY": key}
    status, data, _ = await client.get_json(url, headers=headers)
    if status != 200 or not isinstance(data, dict):
        return []

    hits: list[PassiveHit] = []
    for match in (data.get("matches") or [])[:limit]:
        ip = match.get("ip") or ""
        if not ip:
            continue
        portinfo = match.get("portinfo") or {}
        geo = match.get("geoinfo") or {}
        hits.append(
            PassiveHit(
                source="zoomeye",
                kind="host",
                value=ip,
                title=portinfo.get("hostname") or ip,
                metadata={
                    "port": portinfo.get("port"),
                    "service": portinfo.get("service"),
                    "product": portinfo.get("product"),
                    "country": (geo.get("country") or {}).get("names", {}).get("en"),
                    "city": (geo.get("city") or {}).get("names", {}).get("en"),
                },
            )
        )
    return hits

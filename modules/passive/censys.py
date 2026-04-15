"""Censys host search.

Uses the v2 ``/hosts/search`` endpoint with HTTP basic auth
(``CENSYS_API_ID`` / ``CENSYS_API_SECRET``). We pass the credentials
via a hand-rolled header so we don't need to depend on ``censys`` PyPI.
"""

from __future__ import annotations

import base64
import os
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://search.censys.io/api/v2/hosts/search"


def _auth_header() -> str | None:
    api_id = os.environ.get("CENSYS_API_ID")
    secret = os.environ.get("CENSYS_API_SECRET")
    if not api_id or not secret:
        return None
    token = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
    return f"Basic {token}"


async def search(
    client: HTTPClient,
    domain: str,
    *,
    limit: int = 50,
) -> list[PassiveHit]:
    auth = _auth_header()
    if not auth:
        log.debug("Censys credentials not set; skipping censys search")
        return []

    query = quote(f"services.tls.certificates.leaf_data.names: {domain}")
    url = f"{_ENDPOINT}?q={query}&per_page={min(limit, 100)}"
    status, data, _ = await client.get_json(url, headers={"Authorization": auth})
    if status != 200 or not isinstance(data, dict):
        return []

    result = data.get("result") or {}
    hits: list[PassiveHit] = []
    for item in (result.get("hits") or [])[:limit]:
        ip = item.get("ip") or ""
        if not ip:
            continue
        services = item.get("services") or []
        ports = sorted({s.get("port") for s in services if s.get("port")})
        hits.append(
            PassiveHit(
                source="censys",
                kind="host",
                value=ip,
                title=(item.get("name") or ip),
                metadata={
                    "ports": ports,
                    "autonomous_system": (item.get("autonomous_system") or {}).get("name"),
                    "country": (item.get("location") or {}).get("country"),
                    "services": [s.get("service_name") for s in services if s.get("service_name")],
                },
            )
        )
    return hits

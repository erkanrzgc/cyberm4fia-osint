"""FOFA host search.

FOFA's HTTP API takes a base64-encoded query string in ``qbase64`` and
returns one row per host. Requires ``FOFA_EMAIL`` + ``FOFA_KEY``.

The ``fields`` list is deliberately narrow — FOFA charges per field
slot and 5 fields is plenty for the domain-pivot use case.
"""

from __future__ import annotations

import base64
import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://fofa.info/api/v1/search/all"
_FIELDS = "ip,port,host,title,country_name"


def _creds() -> tuple[str, str] | None:
    email = os.environ.get("FOFA_EMAIL")
    key = os.environ.get("FOFA_KEY")
    if not email or not key:
        return None
    return email, key


async def search(
    client: HTTPClient,
    domain: str,
    *,
    limit: int = 50,
) -> list[PassiveHit]:
    creds = _creds()
    if not creds:
        log.debug("FOFA_EMAIL / FOFA_KEY not set; skipping fofa search")
        return []

    email, key = creds
    qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    url = (
        f"{_ENDPOINT}"
        f"?email={email}&key={key}"
        f"&qbase64={qbase64}&size={min(limit, 100)}&fields={_FIELDS}"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict) or data.get("error"):
        return []

    hits: list[PassiveHit] = []
    for row in (data.get("results") or [])[:limit]:
        # FOFA returns arrays, indexed in the order we requested _FIELDS.
        if len(row) < 3:
            continue
        ip, port, host = row[0], row[1], row[2]
        title = row[3] if len(row) > 3 else ""
        country = row[4] if len(row) > 4 else ""
        if not ip:
            continue
        hits.append(
            PassiveHit(
                source="fofa",
                kind="host",
                value=str(ip),
                title=host or title or str(ip),
                metadata={
                    "port": port,
                    "host": host,
                    "title": title,
                    "country": country,
                },
            )
        )
    return hits

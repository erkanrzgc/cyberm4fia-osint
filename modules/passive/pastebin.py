"""Paste-site search.

Pastebin's own search endpoint requires a Pro account, and the public
scraping API only returns the last 100 pastes regardless of query. The
workable path is **psbdmp.ws**, which indexes Pastebin + a few mirrors
and exposes a JSON search endpoint without authentication.

We treat every response as untrusted — psbdmp occasionally goes down,
and a missing/garbled response should silently produce an empty list.
"""

from __future__ import annotations

from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_SEARCH_ENDPOINT = "https://psbdmp.ws/api/search/{query}"
_PASTE_URL = "https://pastebin.com/{key}"


async def search(
    client: HTTPClient,
    query: str,
    *,
    limit: int = 40,
) -> list[PassiveHit]:
    if not query:
        return []
    url = _SEARCH_ENDPOINT.format(query=quote(query))
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return []

    entries = data.get("data") or []
    hits: list[PassiveHit] = []
    for entry in entries[:limit]:
        key = entry.get("id") or ""
        if not key:
            continue
        hits.append(
            PassiveHit(
                source="pastebin",
                kind="paste",
                value=_PASTE_URL.format(key=key),
                title=entry.get("tags", "") or key,
                metadata={
                    "id": key,
                    "length": entry.get("length"),
                    "date": entry.get("date"),
                    "query": query,
                },
            )
        )
    return hits

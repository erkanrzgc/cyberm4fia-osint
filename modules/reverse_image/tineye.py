"""TinEye reverse image search via the MatchEngine API.

TinEye's commercial API (`api.tineye.com`) uses HMAC-SHA256 signed
requests. To avoid pulling in an HMAC helper just for this one source,
we support the lighter **MatchEngine** flow: a POST to
``/rest/search/`` with HTTP basic auth + the image URL.

Requires ``TINEYE_API_KEY`` **and** ``TINEYE_API_USER`` in the
environment. Without them the module is a silent no-op — callers must
treat reverse image as best-effort.

The response shape we care about::

    {
      "status": "ok",
      "results": {
        "matches": [
          {
            "score": 0.98,
            "filepath": "https://…",
            "domain": "example.com",
            "backlinks": [{"url": "https://page", "crawl_date": "…"}]
          }
        ]
      }
    }
"""

from __future__ import annotations

import base64
import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.reverse_image.models import ReverseImageHit

log = get_logger(__name__)

_ENDPOINT = "https://api.tineye.com/rest/search/"


def _auth_header() -> str | None:
    user = os.environ.get("TINEYE_API_USER")
    key = os.environ.get("TINEYE_API_KEY")
    if not user or not key:
        return None
    token = base64.b64encode(f"{user}:{key}".encode()).decode()
    return f"Basic {token}"


async def search(
    client: HTTPClient,
    image_url: str,
    *,
    limit: int = 25,
) -> list[ReverseImageHit]:
    if not image_url:
        return []
    auth = _auth_header()
    if not auth:
        log.debug("TinEye credentials not set; skipping tineye search")
        return []

    url = f"{_ENDPOINT}?image_url={image_url}&limit={limit}"
    status, data, _ = await client.get_json(url, headers={"Authorization": auth})
    if status != 200 or not isinstance(data, dict):
        return []
    if data.get("status") not in (None, "ok", "OK"):
        return []

    matches = ((data.get("results") or {}).get("matches") or [])
    hits: list[ReverseImageHit] = []
    for match in matches[:limit]:
        backlinks = match.get("backlinks") or []
        if not backlinks:
            continue
        page_url = backlinks[0].get("url") or ""
        if not page_url:
            continue
        hits.append(
            ReverseImageHit(
                source="tineye",
                source_url=image_url,
                match_url=page_url,
                title=match.get("domain", ""),
                image_url=match.get("filepath", ""),
                score=float(match.get("score") or 0.0),
                metadata={
                    "domain": match.get("domain"),
                    "backlink_count": len(backlinks),
                    "crawl_date": backlinks[0].get("crawl_date"),
                },
            )
        )
    return hits

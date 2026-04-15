"""Wayback Machine historical snapshots.

The CDX API returns one row per capture of a URL pattern. We ask for
collapsed-by-digest rows so we don't drown in near-identical snapshots
of the same page, and we restrict to 200-OK captures because 301s and
404s are rarely useful during recon.

Two entry points:

* ``snapshots_for_url(url)`` — classic "show me every archived version
  of this profile URL". Good for catching deleted social profiles.
* ``snapshots_for_domain(domain)`` — widen the lens to ``domain/*`` so
  we get every URL the Wayback has ever indexed under a host.
"""

from __future__ import annotations

from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_CDX = "https://web.archive.org/cdx/search/cdx"


def _replay_url(timestamp: str, original: str) -> str:
    return f"https://web.archive.org/web/{timestamp}/{original}"


async def _query(
    client: HTTPClient,
    match_url: str,
    *,
    match_type: str,
    limit: int,
) -> list[PassiveHit]:
    params = (
        f"url={quote(match_url)}"
        f"&output=json"
        f"&filter=statuscode:200"
        f"&collapse=digest"
        f"&matchType={match_type}"
        f"&limit={limit}"
    )
    url = f"{_CDX}?{params}"
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, list) or len(data) < 2:
        return []

    # First row is the header: ["urlkey","timestamp","original",...]
    header, *rows = data
    try:
        ts_idx = header.index("timestamp")
        orig_idx = header.index("original")
    except ValueError:
        return []

    hits: list[PassiveHit] = []
    for row in rows:
        if len(row) <= max(ts_idx, orig_idx):
            continue
        timestamp = row[ts_idx]
        original = row[orig_idx]
        hits.append(
            PassiveHit(
                source="wayback",
                kind="snapshot",
                value=_replay_url(timestamp, original),
                title=original,
                metadata={"timestamp": timestamp, "original": original},
            )
        )
    return hits


async def snapshots_for_url(
    client: HTTPClient, url: str, *, limit: int = 25
) -> list[PassiveHit]:
    if not url:
        return []
    return await _query(client, url, match_type="exact", limit=limit)


async def snapshots_for_domain(
    client: HTTPClient, domain: str, *, limit: int = 50
) -> list[PassiveHit]:
    if not domain:
        return []
    return await _query(client, f"{domain}/*", match_type="domain", limit=limit)

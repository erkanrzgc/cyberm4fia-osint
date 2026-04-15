"""Ahmia dark-web index search.

Ahmia runs a clearnet mirror of its Tor search index at
``https://ahmia.fi/search/``. The results page is plain HTML — no API —
so we scrape the ``<li class="result">`` blocks. Each result gives us a
``.onion`` link, a title, and a blurb.

Sending this request over the user's normal HTTPClient (rather than
forcing Tor) is fine: ahmia.fi is a clearnet property. The Tor proxy
only becomes necessary if we later fetch the onion URLs themselves,
which is out of scope for passive intel.
"""

from __future__ import annotations

import re
from urllib.parse import quote, urlparse

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://ahmia.fi/search/?q={query}"

# The Ahmia result list template is stable enough that a tight regex pair
# beats pulling in a full HTML parser for one module.
_RESULT_BLOCK = re.compile(
    r'<li\s+class="result">.*?<h4>\s*<a\s+href="(?P<redirect>[^"]+)">(?P<title>[^<]+)</a>'
    r'.*?<p>(?P<desc>.*?)</p>',
    re.DOTALL,
)
_ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)


def _extract_onion(redirect: str) -> str | None:
    """Ahmia wraps results in a /search/redirect?… URL; pull the onion out."""
    match = _ONION_RE.search(redirect)
    if match:
        return match.group(0).lower()
    parsed = urlparse(redirect)
    for part in (parsed.query, parsed.path):
        m = _ONION_RE.search(part or "")
        if m:
            return m.group(0).lower()
    return None


async def search(
    client: HTTPClient,
    query: str,
    *,
    limit: int = 30,
) -> list[PassiveHit]:
    if not query:
        return []
    url = _ENDPOINT.format(query=quote(query))
    status, body, _ = await client.get(url)
    if status != 200 or not body:
        return []

    hits: list[PassiveHit] = []
    for match in _RESULT_BLOCK.finditer(body):
        onion = _extract_onion(match.group("redirect"))
        if not onion:
            continue
        title = match.group("title").strip()
        desc = re.sub(r"<[^>]+>", "", match.group("desc")).strip()
        hits.append(
            PassiveHit(
                source="ahmia",
                kind="onion",
                value=f"http://{onion}",
                title=title,
                metadata={"description": desc[:500], "query": query},
            )
        )
        if len(hits) >= limit:
            break
    return hits

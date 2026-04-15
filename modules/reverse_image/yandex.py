"""Yandex Images reverse search (HTML scrape).

Yandex accepts a GET with ``rpt=imageview&url=<encoded>`` and responds
with an HTML page containing a "Sites containing this image" block
(``CbirSites-Items``). Each entry is an anchor whose ``href`` is the
page where the image was found and whose inner text is the page title.

The markup is reasonably stable — it has outlasted two redesigns — but
if Yandex ever flips its class names we simply return an empty list
rather than raise.

No API key. No auth. Rate-limited by the shared :class:`HTTPClient`
rate bucket like every other source.
"""

from __future__ import annotations

import html
import re
from urllib.parse import quote, urlparse

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.reverse_image.models import ReverseImageHit

log = get_logger(__name__)

_ENDPOINT = "https://yandex.com/images/search?rpt=imageview&url={url}"

# The "sites with this image" block uses a consistent class prefix.
# Each entry is:
#   <li class="CbirSites-Item">
#     <div class="CbirSites-ItemTitle"><a href="https://page">Title</a></div>
#     <div class="CbirSites-ItemThumb"><img src="https://thumb">…</div>
#     <div class="CbirSites-ItemDescription">blurb</div>
#   </li>
_ITEM_RE = re.compile(
    r'<li[^>]*class="[^"]*CbirSites-Item[^"]*"[^>]*>(?P<body>.*?)</li>',
    re.DOTALL | re.IGNORECASE,
)
_TITLE_RE = re.compile(
    r'CbirSites-ItemTitle[^>]*>\s*<a[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>[^<]*)</a>',
    re.DOTALL | re.IGNORECASE,
)
_THUMB_RE = re.compile(
    r'CbirSites-ItemThumb.*?<img[^>]+src="(?P<src>[^"]+)"',
    re.DOTALL | re.IGNORECASE,
)
_DESC_RE = re.compile(
    r'CbirSites-ItemDescription[^>]*>(?P<desc>.*?)</',
    re.DOTALL | re.IGNORECASE,
)


def _clean(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


async def search(
    client: HTTPClient,
    image_url: str,
    *,
    limit: int = 25,
) -> list[ReverseImageHit]:
    if not image_url:
        return []
    url = _ENDPOINT.format(url=quote(image_url, safe=""))
    status, body, _ = await client.get(url)
    if status != 200 or not body:
        return []

    hits: list[ReverseImageHit] = []
    for item in _ITEM_RE.finditer(body):
        block = item.group("body")
        title_match = _TITLE_RE.search(block)
        if not title_match:
            continue
        href = html.unescape(title_match.group("href"))
        title = _clean(title_match.group("title"))
        thumb_match = _THUMB_RE.search(block)
        thumb = html.unescape(thumb_match.group("src")) if thumb_match else ""
        desc_match = _DESC_RE.search(block)
        desc = _clean(desc_match.group("desc")) if desc_match else ""

        host = urlparse(href).netloc.lower()
        hits.append(
            ReverseImageHit(
                source="yandex",
                source_url=image_url,
                match_url=href,
                title=title,
                image_url=thumb,
                score=0.0,
                metadata={"host": host, "description": desc[:500]},
            )
        )
        if len(hits) >= limit:
            break
    return hits

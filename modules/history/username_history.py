"""Historical username discovery via Wayback CDX.

Strategy: for every known profile URL we already have, ask the Wayback
CDX index for all captures under the same host and look at the first
path segment of each captured URL. That segment is the platform handle
for the vast majority of social profiles (twitter.com/<handle>,
github.com/<handle>, instagram.com/<handle>, …).

Any handle that isn't the current one becomes a *candidate* historical
alias. We aggregate the captures by handle so we can report
``first_seen`` / ``last_seen`` timestamps and a representative snapshot
URL.

Limits:

* We cap the CDX call to 500 rows per host. Large hosts return millions
  of captures otherwise, and the 500-row cap still surfaces anything
  that was crawled repeatedly — which is what we care about.
* Paths that don't look like a handle (empty, ``search``, ``login``,
  ``home``, starting with ``#``/``?``) are rejected by a small
  deny-list so we don't report "login" as an alias.
* A handle must be seen ≥ ``min_captures`` times to count. Default 2,
  because one-off captures are often scrapers or redirect probes.
"""

from __future__ import annotations

from urllib.parse import quote, urlparse

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.history.models import HistoricalUsername

log = get_logger(__name__)

_CDX = "https://web.archive.org/cdx/search/cdx"

_DENY_HANDLES = frozenset(
    {
        "", "home", "login", "signup", "search", "explore", "about",
        "help", "privacy", "terms", "tos", "contact", "jobs", "careers",
        "settings", "account", "notifications", "messages", "trending",
        "hashtag", "tags", "tag", "i", "status", "statuses", "intent",
        "share", "auth", "oauth", "api", "app", "download",
    }
)


def _parse_profile(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    host = parsed.netloc.lower().removeprefix("www.")
    path = parsed.path.strip("/")
    if not host or not path:
        return None
    first = path.split("/", 1)[0]
    if not first:
        return None
    return host, first


def _first_segment(url: str) -> str | None:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if not path:
        return None
    segment = path.split("/", 1)[0].lower()
    if segment in _DENY_HANDLES or segment.startswith(("_", "?", "#")):
        return None
    if "." in segment:  # likely a file or subpath, not a handle
        return None
    return segment


async def _fetch_cdx(
    client: HTTPClient, host: str, *, limit: int
) -> list[list[str]]:
    url = (
        f"{_CDX}?url={quote(host + '/*')}"
        f"&matchType=host&output=json"
        f"&filter=statuscode:200"
        f"&collapse=urlkey"
        f"&limit={limit}"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, list) or len(data) < 2:
        return []
    return data  # caller handles header row


async def discover_historical_usernames(
    client: HTTPClient,
    *,
    profile_urls: list[str],
    current_username: str,
    limit_per_platform: int = 500,
    min_captures: int = 2,
) -> list[HistoricalUsername]:
    """Return historical handle candidates found for each profile URL.

    ``current_username`` is excluded from the output — we only surface
    handles that differ from the known one.
    """
    seen_hosts: set[str] = set()
    out: list[HistoricalUsername] = []

    for profile_url in profile_urls:
        parsed = _parse_profile(profile_url)
        if not parsed:
            continue
        host, current_from_url = parsed
        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        data = await _fetch_cdx(client, host, limit=limit_per_platform)
        if not data:
            continue

        header, *rows = data
        try:
            ts_idx = header.index("timestamp")
            orig_idx = header.index("original")
        except ValueError:
            continue

        per_handle: dict[str, list[str]] = {}
        for row in rows:
            if len(row) <= max(ts_idx, orig_idx):
                continue
            ts = row[ts_idx]
            original = row[orig_idx]
            handle = _first_segment(original)
            if not handle:
                continue
            if handle == current_username.lower() or handle == current_from_url.lower():
                continue
            per_handle.setdefault(handle, []).append(ts)

        for handle, timestamps in per_handle.items():
            if len(timestamps) < min_captures:
                continue
            ts_sorted = sorted(timestamps)
            out.append(
                HistoricalUsername(
                    username=handle,
                    platform=host,
                    first_seen=ts_sorted[0],
                    last_seen=ts_sorted[-1],
                    snapshot_count=len(ts_sorted),
                    sample_snapshot=(
                        f"https://web.archive.org/web/{ts_sorted[0]}/"
                        f"https://{host}/{handle}"
                    ),
                    metadata={
                        "source_profile": profile_url,
                        "current_username": current_username,
                    },
                )
            )

    out.sort(key=lambda h: (h.platform, -h.snapshot_count, h.username))
    return out

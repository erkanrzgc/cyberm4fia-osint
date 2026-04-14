"""ProxyNova COMB lookup — free credential-leak search.

The Compilation of Many Breaches (COMB) is a publicly-indexed dataset of
~3 billion leaked email:password pairs. ProxyNova hosts a free public
search endpoint that accepts a username or email and returns matching
lines. Used defensively this tells an OSINT investigator:

  * which credentials for the target are already public,
  * whether the target reuses passwords across breaches,
  * which contexts (domains) their credentials surfaced in.

No API key, no rate-limit documented. Results are truncated per request
(default 15) — we raise to 25 to widen coverage without being abusive.

Endpoint: https://api.proxynova.com/comb?query=<q>&start=0&limit=25
Response:
  {"count": <total>, "lines": ["user@dom.com:password", ...]}

The `lines` field returns plaintext `email:password` pairs. We parse each
line into a CombLeak dataclass, never log the raw password (only a masked
preview), and return a list ordered as received.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)

COMB_URL = "https://api.proxynova.com/comb"
DEFAULT_LIMIT = 25


@dataclass(frozen=True)
class CombLeak:
    identifier: str  # email or username on the left side of the colon
    password_preview: str  # masked: first char + length
    raw_length: int  # password length for risk assessment
    source: str = "proxynova-comb"
    extras: tuple[str, ...] = field(default_factory=tuple)


def _mask(password: str) -> str:
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"


def _parse_line(line: str) -> CombLeak | None:
    if ":" not in line:
        return None
    ident, _, rest = line.partition(":")
    ident = ident.strip()
    if not ident:
        return None
    parts = rest.split(":")
    password = parts[0]
    extras = tuple(p for p in parts[1:] if p)
    return CombLeak(
        identifier=ident,
        password_preview=_mask(password),
        raw_length=len(password),
        extras=extras,
    )


async def search_comb(
    client: HTTPClient, query: str, limit: int = DEFAULT_LIMIT
) -> list[CombLeak]:
    """Query ProxyNova's COMB search for a username or email.

    Returns an empty list on any failure — never raises. Safe to call from
    the phase pipeline without error handling.
    """
    if not query:
        return []
    url = f"{COMB_URL}?query={quote(query)}&start=0&limit={limit}"
    try:
        status, data, _ = await client.get_json(url)
    except Exception as exc:
        log.debug("COMB lookup failed for %s: %s", query, exc)
        return []
    if status != 200 or not isinstance(data, dict):
        return []
    lines = data.get("lines") or []
    if not isinstance(lines, list):
        return []
    out: list[CombLeak] = []
    for line in lines:
        if not isinstance(line, str):
            continue
        parsed = _parse_line(line)
        if parsed:
            out.append(parsed)
    return out


async def search_comb_many(
    client: HTTPClient, queries: list[str], limit: int = DEFAULT_LIMIT
) -> dict[str, list[CombLeak]]:
    """Run several COMB lookups in parallel and return {query: leaks}."""
    queries = [q for q in queries if q]
    if not queries:
        return {}
    results = await asyncio.gather(
        *(search_comb(client, q, limit) for q in queries),
        return_exceptions=True,
    )
    out: dict[str, list[CombLeak]] = {}
    for q, r in zip(queries, results, strict=True):
        out[q] = r if isinstance(r, list) else []
    return out

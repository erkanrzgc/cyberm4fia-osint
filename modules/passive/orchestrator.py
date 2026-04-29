"""Run every enabled passive source concurrently.

Design goals:

* **Fan out, but don't explode.** ``asyncio.gather`` with
  ``return_exceptions=True`` so one broken provider doesn't kill the
  whole phase.
* **Deduplicate.** Two providers often report the same IP or subdomain;
  we key on ``(kind, value.lower())`` to keep the first-seen entry and
  merge the rest.
* **Cheap when idle.** Sources that require an API key (Shodan, Censys,
  FOFA, ZoomEye) skip themselves at the module level, so calling
  ``run_passive`` without any keys set is a no-op beyond three free
  endpoints (harvester / wayback / pastebin / ahmia).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive import (
    ahmia,
    censys,
    criminalip,
    fofa,
    google_dork,
    harvester,
    pastebin,
    shodan,
    wayback,
    zoomeye,
)
from modules.passive.models import PassiveHit

log = get_logger(__name__)


def _wayback_url_factory(
    client: HTTPClient, url: str
) -> Callable[[], Awaitable[list[PassiveHit]]]:
    return lambda: wayback.snapshots_for_url(client, url)


async def _safe(
    name: str, coro: Awaitable[list[PassiveHit]]
) -> list[PassiveHit]:
    try:
        return await coro
    except Exception as exc:
        log.debug("passive source %s failed: %s", name, exc)
        return []


def _dedupe(hits: list[PassiveHit]) -> list[PassiveHit]:
    seen: set[tuple[str, str]] = set()
    out: list[PassiveHit] = []
    for hit in hits:
        key = (hit.kind, hit.value.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


async def run_passive(
    client: HTTPClient,
    *,
    username: str,
    domain: str | None = None,
    profile_urls: list[str] | None = None,
) -> list[PassiveHit]:
    """Fan out to every applicable source and return a deduped result list.

    ``username`` drives paste-search + ahmia queries. ``domain`` drives
    the host-discovery sources (Shodan/Censys/FOFA/ZoomEye) plus the
    harvester. ``profile_urls`` (if provided) are fed to Wayback for
    historical snapshots of each URL.
    """
    tasks: list[tuple[str, Callable[[], Awaitable[list[PassiveHit]]]]] = []

    if domain:
        tasks.append(("shodan", lambda: shodan.search(client, domain)))
        tasks.append(("censys", lambda: censys.search(client, domain)))
        tasks.append(("criminalip", lambda: criminalip.search(client, domain)))
        tasks.append(("fofa", lambda: fofa.search(client, domain)))
        tasks.append(("zoomeye", lambda: zoomeye.search(client, domain)))
        tasks.append(("harvester", lambda: harvester.search(client, domain)))
        tasks.append(("google-dork", lambda: google_dork.search(client, domain)))
        tasks.append(("wayback-domain", lambda: wayback.snapshots_for_domain(client, domain)))

    if username:
        tasks.append(("pastebin", lambda: pastebin.search(client, username)))
        tasks.append(("ahmia", lambda: ahmia.search(client, username)))

    for url in profile_urls or []:
        tasks.append((f"wayback-{url}", _wayback_url_factory(client, url)))

    if not tasks:
        return []

    results = await asyncio.gather(
        *(_safe(name, factory()) for name, factory in tasks),
        return_exceptions=False,
    )

    merged: list[PassiveHit] = []
    for hits in results:
        merged.extend(hits)
    return _dedupe(merged)

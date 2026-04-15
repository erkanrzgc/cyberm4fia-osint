"""Realistic User-Agent pool.

The core idea: each entry is tagged with its browser family so that
``fingerprint_headers`` can emit a matching set of ``sec-ch-ua`` / ``sec-fetch-*``
headers. Rotating UA alone is a tell — real browsers send consistent hint
headers, so we mint both together.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Literal

Family = Literal["chrome", "firefox", "safari", "edge"]


@dataclass(frozen=True)
class UAEntry:
    ua: str
    family: Family
    platform: str  # Windows, macOS, Linux, Android, iOS
    major: int


_POOL: tuple[UAEntry, ...] = (
    # Chrome
    UAEntry(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "chrome", "Windows", 129,
    ),
    UAEntry(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "chrome", "Windows", 128,
    ),
    UAEntry(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "chrome", "macOS", 129,
    ),
    UAEntry(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "chrome", "Linux", 129,
    ),
    UAEntry(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
        "chrome", "Android", 129,
    ),
    # Firefox
    UAEntry(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "firefox", "Windows", 131,
    ),
    UAEntry(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0",
        "firefox", "macOS", 131,
    ),
    UAEntry(
        "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "firefox", "Linux", 131,
    ),
    UAEntry(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "firefox", "Linux", 130,
    ),
    # Safari
    UAEntry(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "safari", "macOS", 17,
    ),
    UAEntry(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "safari", "iOS", 17,
    ),
    UAEntry(
        "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "safari", "iOS", 17,
    ),
    # Edge
    UAEntry(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "edge", "Windows", 129,
    ),
    UAEntry(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "edge", "macOS", 129,
    ),
)


def pick_ua(*, desktop_only: bool = False) -> UAEntry:
    """Return a cryptographically random UA entry.

    Using ``secrets`` (not ``random``) is not for cryptographic strength —
    it avoids tests that flag ``random`` as insecure and gives uniform
    selection on each call.
    """
    pool = _POOL
    if desktop_only:
        pool = tuple(u for u in _POOL if u.platform not in ("iOS", "Android"))
    return pool[secrets.randbelow(len(pool))]


def ua_family(ua: str) -> Family:
    """Best-effort family detection from a raw UA string."""
    low = ua.lower()
    if "edg/" in low:
        return "edge"
    if "firefox/" in low:
        return "firefox"
    if "chrome/" in low:
        return "chrome"
    if "safari/" in low:
        return "safari"
    return "chrome"


def pool_size() -> int:
    return len(_POOL)

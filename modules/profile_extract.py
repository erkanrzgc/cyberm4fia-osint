"""Thin wrapper around `socid_extractor` for opportunistic profile parsing.

`socid_extractor` is an upstream regex/BS4 database (maintained by the
Maigret author) that recognises 200+ profile pages and pulls out names,
emails, locations, linked accounts, etc. We call it on any HTML body we
already fetched during the platform sweep, so every matched profile — not
just the handful with handwritten deep scrapers — can contribute fields to
the cross-reference engine.

The dependency is optional. If `socid_extractor` is not installed, every
call becomes a no-op and returns an empty dict.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

try:  # pragma: no cover - trivial import guard
    from socid_extractor import extract as _socid_extract  # type: ignore[import-not-found]

    _AVAILABLE = True
except ImportError:
    _socid_extract = None
    _AVAILABLE = False


_INTERESTING_KEYS = {
    "fullname",
    "name",
    "username",
    "nickname",
    "first_name",
    "last_name",
    "email",
    "bio",
    "description",
    "location",
    "country",
    "city",
    "website",
    "links",
    "twitter",
    "github",
    "instagram",
    "telegram",
    "reddit",
    "avatar",
    "avatar_url",
    "image",
    "profile_image",
    "created_at",
    "joined",
    "gender",
    "age",
    "birthday",
    "language",
    "following",
    "followers",
    "posts",
}


def is_available() -> bool:
    return _AVAILABLE


def extract_profile(html: str) -> dict[str, Any]:
    """Run socid_extractor over HTML and return normalised field dict.

    Returns an empty dict when the library is unavailable, no scheme matches,
    or extraction raises.
    """
    if not _AVAILABLE or not html:
        return {}
    try:
        raw = _socid_extract(html)  # type: ignore[misc]
    except Exception as exc:  # extractor occasionally throws on malformed pages
        log.debug("socid_extractor error: %s", exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    # Keep the full dict but also hoist a curated subset for downstream code.
    return {k: v for k, v in raw.items() if v not in (None, "", [], {})}

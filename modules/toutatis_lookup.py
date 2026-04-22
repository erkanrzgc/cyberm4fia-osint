"""Toutatis wrapper — Instagram OSINT (obfuscated email + phone tail).

Toutatis exposes two entry points. ``advanced_lookup`` requires no auth and
returns whatever Instagram leaks publicly (obfuscated email/phone tails).
``getInfo`` needs a session ID cookie from a logged-in browser session, which
we won't store inside the framework — set ``IG_SESSION_ID`` in the environment
to enable the richer lookup.

Both flows are wrapped to never raise; calls return ``None`` when the session
is missing or the upstream blocks us.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

from core.logging_setup import get_logger

log = get_logger(__name__)

try:  # pragma: no cover - import guard
    from toutatis.core import advanced_lookup as _advanced_lookup
    from toutatis.core import getInfo as _get_info

    _AVAILABLE = True
except Exception as exc:  # pragma: no cover - import guard
    log.debug("toutatis unavailable: %s", exc)
    _AVAILABLE = False


@dataclass(frozen=True)
class ToutatisResult:
    username: str
    user_id: str = ""
    full_name: str = ""
    is_private: bool = False
    is_verified: bool = False
    follower_count: int = 0
    following_count: int = 0
    biography: str = ""
    external_url: str = ""
    obfuscated_email: str = ""
    obfuscated_phone: str = ""
    profile_pic: str = ""


def is_available() -> bool:
    return _AVAILABLE


def _session_id() -> str:
    return os.environ.get("IG_SESSION_ID", "").strip()


def _from_user_dict(username: str, user: dict) -> ToutatisResult:
    return ToutatisResult(
        username=username,
        user_id=str(user.get("pk") or user.get("id") or ""),
        full_name=str(user.get("full_name") or ""),
        is_private=bool(user.get("is_private")),
        is_verified=bool(user.get("is_verified")),
        follower_count=int(user.get("follower_count") or 0),
        following_count=int(user.get("following_count") or 0),
        biography=str(user.get("biography") or ""),
        external_url=str(user.get("external_url") or ""),
        obfuscated_email=str(user.get("obfuscated_email") or ""),
        obfuscated_phone=str(user.get("obfuscated_phone") or ""),
        profile_pic=str(user.get("profile_pic_url_hd") or user.get("profile_pic_url") or ""),
    )


def _lookup_blocking(username: str) -> ToutatisResult | None:
    """Run the upstream sync calls. Returns None on any failure."""
    if not _AVAILABLE or not username:
        return None
    session = _session_id()
    try:
        data = _get_info(username, session) if session else _advanced_lookup(username)
    except Exception as exc:
        log.debug("toutatis raised for %s: %s", username, exc)
        return None
    if not isinstance(data, dict):
        return None
    user = data.get("user")
    if not isinstance(user, dict):
        return None
    if user.get("status") == "fail" or not (user.get("pk") or user.get("id")):
        return None
    return _from_user_dict(username, user)


async def lookup_username(username: str) -> ToutatisResult | None:
    """Async wrapper around the blocking upstream call."""
    if not _AVAILABLE or not username:
        return None
    return _lookup_blocking(username)


async def lookup_usernames(usernames: list[str]) -> dict[str, ToutatisResult]:
    """Run lookup_username for many handles in parallel; skips Nones."""
    usernames = [u for u in usernames if u]
    if not usernames or not _AVAILABLE:
        return {}
    results = await asyncio.gather(
        *(lookup_username(u) for u in usernames), return_exceptions=True
    )
    out: dict[str, ToutatisResult] = {}
    for u, r in zip(usernames, results, strict=True):
        if isinstance(r, ToutatisResult):
            out[u] = r
    return out

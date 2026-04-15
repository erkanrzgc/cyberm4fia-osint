"""Generate browser-consistent client hint / fetch metadata headers.

Rotating only User-Agent is a giveaway: real browsers also send a matching
``sec-ch-ua`` brand list, ``sec-fetch-*`` metadata, and a platform-appropriate
``Accept-Language``. This module mints a header dict that lines up with a
given :class:`UAEntry` so the whole request looks coherent to a server-side
bot filter.

Only Chromium-family browsers (Chrome, Edge) emit ``sec-ch-ua*`` headers.
Firefox and Safari must NOT — emitting them there is itself a tell.
"""

from __future__ import annotations

import secrets

from modules.stealth.user_agents import UAEntry

_ACCEPT_LANGUAGES: tuple[str, ...] = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,tr;q=0.6",
    "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
)

_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8"
)


def _ch_platform(platform: str) -> str:
    mapping = {
        "Windows": '"Windows"',
        "macOS": '"macOS"',
        "Linux": '"Linux"',
        "Android": '"Android"',
        "iOS": '"iOS"',
    }
    return mapping.get(platform, '"Unknown"')


def _chrome_brands(major: int) -> str:
    return (
        f'"Chromium";v="{major}", '
        f'"Google Chrome";v="{major}", '
        f'"Not?A_Brand";v="99"'
    )


def _edge_brands(major: int) -> str:
    return (
        f'"Chromium";v="{major}", '
        f'"Microsoft Edge";v="{major}", '
        f'"Not?A_Brand";v="99"'
    )


def fingerprint_headers(
    ua_entry: UAEntry,
    *,
    referer: str | None = None,
) -> dict[str, str]:
    """Return headers consistent with ``ua_entry``.

    The caller merges the result into the base request headers; any keys
    already set upstream win.
    """
    mobile = ua_entry.platform in ("Android", "iOS")
    headers: dict[str, str] = {
        "User-Agent": ua_entry.ua,
        "Accept": _ACCEPT_HTML,
        "Accept-Language": _ACCEPT_LANGUAGES[
            secrets.randbelow(len(_ACCEPT_LANGUAGES))
        ],
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if referer is None else "cross-site",
        "Sec-Fetch-User": "?1",
        "DNT": "1",
        "Connection": "keep-alive",
    }

    if ua_entry.family in ("chrome", "edge"):
        brands = (
            _edge_brands(ua_entry.major)
            if ua_entry.family == "edge"
            else _chrome_brands(ua_entry.major)
        )
        headers["sec-ch-ua"] = brands
        headers["sec-ch-ua-mobile"] = "?1" if mobile else "?0"
        headers["sec-ch-ua-platform"] = _ch_platform(ua_entry.platform)

    if referer:
        headers["Referer"] = referer

    return headers

"""Wigle.net BSSID / SSID → physical location lookup.

Wigle is a community-collected database of wireless networks: every
record is an ``(SSID, BSSID, lat/lon, last seen)`` tuple uploaded by
wardrivers. From a red-team / OSINT angle that gives us two pivots we
do not get from Shodan/Censys/EXIF alone:

* **BSSID → coordinates.** When a target's photo carries a router MAC
  in EXIF (or a forensic capture surfaces a known BSSID), Wigle maps
  that MAC to the street address where it was last seen — usually the
  target's home or office.
* **SSID → list of locations.** Knowing a corporate SSID name (e.g.
  ``AcmeGuestWiFi``) lets us enumerate every street where that name
  has been observed, which tends to reveal branch offices, employee
  homes, and coffee shops the company frequents.

This pairs cleanly with :mod:`modules.analysis.exif`: the EXIF
extractor surfaces ``GPSInfo`` when present, but most photos have GPS
stripped on upload. BSSID/SSID survive even when GPS does not, so
Wigle plugs that gap.

Auth: Wigle uses HTTP Basic with two halves of the credential in
``WIGLE_API_NAME`` (the encoded API name beginning ``AID-``) and
``WIGLE_API_TOKEN``. Both must be set; missing either silently
no-ops, matching every other passive source.

Free tier limits: ~1 query/sec and roughly 100 queries/day after the
first day of an account. Don't fan this out across thousands of
records without paid access.
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import Any
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_ENDPOINT = "https://api.wigle.net/api/v2/network/search"


def _basic_auth(name: str, token: str) -> str:
    """Build the ``Authorization: Basic <b64>`` header value."""
    raw = f"{name}:{token}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _creds() -> tuple[str, str] | None:
    name = os.environ.get("WIGLE_API_NAME")
    token = os.environ.get("WIGLE_API_TOKEN")
    if not name or not token:
        return None
    return name, token


def _format_address(row: dict[str, Any]) -> str:
    """Compose a one-line postal address from the Wigle row, skipping
    empty parts so we never produce strings like ``", , ,``."""
    house = (row.get("housenumber") or "").strip()
    road = (row.get("road") or "").strip()
    city = (row.get("city") or "").strip()
    region = (row.get("region") or "").strip()
    postal = (row.get("postalcode") or "").strip()
    country = (row.get("country") or "").strip()

    street = " ".join(p for p in (house, road) if p)
    locality = " ".join(p for p in (city, region, postal) if p).strip()
    locality = locality.replace("  ", " ")
    parts = [p for p in (street, locality, country) if p]
    return ", ".join(parts)


def _row_to_hit(row: dict[str, Any], *, kind: str) -> PassiveHit | None:
    """Translate one Wigle ``results`` entry into a ``PassiveHit``.

    ``kind`` decides which side of the (BSSID, SSID) pair becomes the
    primary ``value``. For a BSSID lookup the BSSID is the value; for
    an SSID lookup the SSID is the value and the BSSID lives in
    ``metadata["bssid"]``.
    """
    bssid = (row.get("netid") or "").strip()
    ssid = (row.get("ssid") or "").strip()
    if kind == "bssid" and not bssid:
        return None
    if kind == "ssid" and not ssid:
        return None

    if kind == "bssid":
        value = bssid
        title = ssid
    else:
        value = ssid
        title = bssid

    metadata: dict[str, Any] = {
        "lat": row.get("trilat"),
        "lon": row.get("trilong"),
        "country": row.get("country"),
        "region": row.get("region"),
        "city": row.get("city"),
        "address": _format_address(row),
        "encryption": row.get("encryption"),
        "channel": row.get("channel"),
        "last_update": row.get("lastupdt"),
        "first_seen": row.get("firsttime"),
        "last_seen": row.get("lasttime"),
        "qos": row.get("qos"),
    }
    if kind == "ssid":
        metadata["bssid"] = bssid
    else:
        metadata["ssid"] = ssid
    return PassiveHit(source="wigle", kind=kind, value=value, title=title, metadata=metadata)


async def _query(
    client: HTTPClient,
    *,
    params: str,
    kind: str,
    limit: int,
) -> list[PassiveHit]:
    """Execute one ``/network/search`` call and parse the results."""
    creds = _creds()
    if not creds:
        log.debug("WIGLE_API_NAME / WIGLE_API_TOKEN not set; skipping wigle")
        return []
    name, token = creds

    url = f"{_ENDPOINT}?{params}"
    status, data, _ = await client.get_json(
        url, headers={"Authorization": _basic_auth(name, token)}
    )
    if status != 200 or not isinstance(data, dict):
        return []
    if not data.get("success"):
        return []

    rows = data.get("results")
    if not isinstance(rows, list):
        return []

    hits: list[PassiveHit] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        hit = _row_to_hit(row, kind=kind)
        if hit is not None:
            hits.append(hit)
    return hits


async def lookup_bssid(
    client: HTTPClient,
    bssid: str,
    *,
    limit: int = 10,
) -> list[PassiveHit]:
    """Resolve a BSSID/MAC to the locations Wigle has seen it at."""
    if not bssid:
        return []
    return await _query(
        client,
        params=f"netid={quote(bssid)}",
        kind="bssid",
        limit=limit,
    )


async def lookup_ssid(
    client: HTTPClient,
    ssid: str,
    *,
    limit: int = 10,
) -> list[PassiveHit]:
    """Resolve an SSID name to every location Wigle has seen it at."""
    if not ssid:
        return []
    return await _query(
        client,
        params=f"ssid={quote(ssid)}",
        kind="ssid",
        limit=limit,
    )


async def search(
    client: HTTPClient,
    *,
    bssid: str | None = None,
    ssid: str | None = None,
    limit: int = 10,
) -> list[PassiveHit]:
    """Single entry point: dispatch to BSSID and/or SSID lookups.

    When both are provided we fan out concurrently and merge.
    """
    coros = []
    if bssid:
        coros.append(lookup_bssid(client, bssid, limit=limit))
    if ssid:
        coros.append(lookup_ssid(client, ssid, limit=limit))
    if not coros:
        return []
    results = await asyncio.gather(*coros, return_exceptions=True)
    out: list[PassiveHit] = []
    for batch in results:
        if isinstance(batch, BaseException):
            log.debug("wigle: lookup failed: %s", batch)
            continue
        out.extend(batch)
    return out

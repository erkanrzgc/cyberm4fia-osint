"""Have I Been Pwned breach checking.

API key is read at call time from the environment so runtime-loaded
.env files or test overrides work correctly.
"""

from __future__ import annotations

import asyncio
import hashlib
import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)


def _api_key() -> str:
    return os.environ.get("HIBP_API_KEY", "").strip()


def hibp_available() -> bool:
    return bool(_api_key())


async def check_email_breaches(client: HTTPClient, email: str) -> list[dict]:
    key = _api_key()
    if not key:
        return []
    headers = {
        "hibp-api-key": key,
        "User-Agent": "cyberm4fia-osint",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        status, data, _ = await client.get_json(url, headers=headers)
    except Exception as exc:  # network-layer failure
        log.warning("HIBP request failed for %s: %s", email, exc)
        return []
    if status != 200 or not data:
        return []

    return [
        {
            "name": b.get("Name", ""),
            "title": b.get("Title", ""),
            "domain": b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "added_date": b.get("AddedDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "verified": b.get("IsVerified", False),
        }
        for b in data
    ]


async def check_many_emails(
    client: HTTPClient, emails: list[str]
) -> dict[str, list[dict]]:
    """Run breach lookups concurrently and return {email: breaches}."""
    if not emails:
        return {}
    tasks = [check_email_breaches(client, e) for e in emails]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: dict[str, list[dict]] = {}
    for email, result in zip(emails, results, strict=True):
        if isinstance(result, BaseException):
            log.warning("breach check raised for %s: %s", email, result)
            out[email] = []
        else:
            out[email] = result
    return out


async def check_password_pwned(client: HTTPClient, password: str) -> int:
    """K-anonymity password check. Returns breach count."""
    sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        status, body, _ = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    except Exception as exc:
        log.warning("pwned-passwords lookup failed: %s", exc)
        return 0
    if status != 200:
        return 0
    for line in body.splitlines():
        if ":" in line:
            h, count = line.strip().split(":")
            if h == suffix:
                try:
                    return int(count)
                except ValueError:
                    return 0
    return 0

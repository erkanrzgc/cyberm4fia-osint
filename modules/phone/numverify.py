"""NumVerify (apilayer) phone validation.

Requires ``NUMVERIFY_API_KEY`` in the environment. Free tier returns
``country_code``, ``country_name``, ``location``, ``carrier``, and
``line_type``. We fold those into the offline result — carrier in
particular is often absent from the offline DB for non-mobile lines.
"""

from __future__ import annotations

import os

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)

_ENDPOINT = "https://apilayer.net/api/validate"


async def enrich(client: HTTPClient, e164: str) -> dict:
    key = os.environ.get("NUMVERIFY_API_KEY")
    if not key or not e164:
        return {}
    url = (
        f"{_ENDPOINT}?access_key={key}"
        f"&number={e164.lstrip('+')}&format=1"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return {}
    if not data.get("valid", False):
        return {}
    return {
        "country_code_iso": data.get("country_code") or "",
        "country_name": data.get("country_name") or "",
        "location": data.get("location") or "",
        "carrier": data.get("carrier") or "",
        "line_type": data.get("line_type") or "",
    }

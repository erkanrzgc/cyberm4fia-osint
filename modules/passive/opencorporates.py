"""OpenCorporates corporate-records lookup.

OpenCorporates indexes ~200M companies across ~140 jurisdictions and
exposes the name, registration number, registered address, current
status, and — once you fetch the per-company record — the directors
and officers attached to each entity.

Why this matters for OSINT
--------------------------
Corporate registries are the most reliable public source for **named
real people** linked to a target organization. Search returns the
shell of the company; one extra call per company yields:

* Director / officer / secretary names with start and end dates.
* Registered address (often the back-office or registered agent).
* Parent / subsidiary linkage (jurisdiction-dependent).

Each officer name feeds straight into ``modules/recon/email_patterns``
to materialize plausible employee email addresses, and from there into
the SE arsenal pretexting workflow.

API
---
* Free tier: no auth required, ~500 requests/month soft cap.
* ``OPENCORPORATES_API_TOKEN`` lifts limits substantially.
* Endpoints used:
    * ``/v0.4/companies/search?q=<text>`` — fuzzy name search.
    * ``/v0.4/companies/<jurisdiction>/<number>`` — full record with
      officer list.

Free-tier rate limits are tight; ``search_with_officers`` is the
expensive operation (one extra call per company), so cap ``limit``
conservatively on real targets.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import quote

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon.models import CompanyOfficer, CompanyRecord

log = get_logger(__name__)

_API_BASE = "https://api.opencorporates.com/v0.4"


def _api_token() -> str:
    return os.environ.get("OPENCORPORATES_API_TOKEN", "")


def _with_token(url: str) -> str:
    """Append ``&api_token=...`` to a URL when a token is configured."""
    token = _api_token()
    if not token:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}api_token={quote(token)}"


def _company_block(raw: dict[str, Any] | None) -> CompanyRecord | None:
    """Convert one OpenCorporates ``company`` block into a record.

    Returns ``None`` when the row is missing the identity tuple
    (name + jurisdiction_code + company_number) — without those there
    is nothing to act on.
    """
    if not isinstance(raw, dict):
        return None
    name = (raw.get("name") or "").strip()
    jurisdiction = (raw.get("jurisdiction_code") or "").strip()
    number = str(raw.get("company_number") or "").strip()
    if not name or not jurisdiction or not number:
        return None

    officers_raw = raw.get("officers") or ()
    officers: list[CompanyOfficer] = []
    if isinstance(officers_raw, list):
        for entry in officers_raw:
            if not isinstance(entry, dict):
                continue
            o = entry.get("officer")
            if not isinstance(o, dict):
                continue
            o_name = (o.get("name") or "").strip()
            if not o_name:
                continue
            officers.append(
                CompanyOfficer(
                    name=o_name,
                    position=(o.get("position") or "").strip(),
                    start_date=(o.get("start_date") or "") or "",
                    end_date=(o.get("end_date") or "") or "",
                )
            )

    return CompanyRecord(
        name=name,
        jurisdiction_code=jurisdiction,
        company_number=number,
        incorporation_date=(raw.get("incorporation_date") or "") or "",
        company_type=(raw.get("company_type") or "") or "",
        registered_address=(raw.get("registered_address_in_full") or "") or "",
        status=(raw.get("current_status") or "") or "",
        url=(raw.get("opencorporates_url") or "") or "",
        officers=tuple(officers),
    )


# ── Public API ──────────────────────────────────────────────────────


async def search(
    client: HTTPClient,
    query: str,
    *,
    limit: int = 10,
) -> list[CompanyRecord]:
    """Free-text search across the global registry index.

    Returns ``CompanyRecord``s with empty ``officers`` — call
    :func:`get_company` (or :func:`search_with_officers`) to enrich.
    """
    if not query or not query.strip():
        return []
    url = _with_token(
        f"{_API_BASE}/companies/search?q={quote(query.strip())}"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, dict):
        return []
    rows = results.get("companies")
    if not isinstance(rows, list):
        return []

    out: list[CompanyRecord] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        rec = _company_block(entry.get("company"))
        if rec is not None:
            out.append(rec)
        if len(out) >= limit:
            break
    return out


async def get_company(
    client: HTTPClient,
    jurisdiction_code: str,
    company_number: str,
) -> CompanyRecord | None:
    """Fetch the full record for one company, including its officers."""
    if not jurisdiction_code or not company_number:
        return None
    url = _with_token(
        f"{_API_BASE}/companies/"
        f"{quote(jurisdiction_code)}/{quote(str(company_number))}"
    )
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return None
    results = data.get("results")
    if not isinstance(results, dict):
        return None
    return _company_block(results.get("company"))


async def search_with_officers(
    client: HTTPClient,
    query: str,
    *,
    limit: int = 5,
) -> list[CompanyRecord]:
    """Search, then fetch the full officer list for each result.

    Network cost: ``1 + limit`` requests per call. Cap ``limit`` on
    free-tier accounts to avoid burning the monthly quota.

    On per-company fetch failure we keep the bare search record rather
    than dropping it — partial data is still useful.
    """
    base = await search(client, query, limit=limit)
    if not base:
        return []

    fetches = [
        get_company(client, rec.jurisdiction_code, rec.company_number)
        for rec in base
    ]
    enriched = await asyncio.gather(*fetches, return_exceptions=True)

    out: list[CompanyRecord] = []
    for original, full in zip(base, enriched, strict=True):
        if isinstance(full, BaseException):
            log.debug(
                "opencorporates: officer fetch failed for %s/%s: %s",
                original.jurisdiction_code,
                original.company_number,
                full,
            )
            out.append(original)
            continue
        if full is None:
            out.append(original)
        else:
            out.append(full)
    return out

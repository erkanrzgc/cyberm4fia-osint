"""TheHarvester-style domain → email / subdomain harvester.

Instead of shelling out to theharvester, we hit a small set of open
sources that together cover the bulk of what the classic tool does:

* **HackerTarget** — `/hostsearch/` returns ``subdomain,ip`` rows; no key.
* **ThreatCrowd** — legacy v2 domain endpoint exposes subdomains, emails.
* **crt.sh** — certificate transparency gives subdomains (we already
  call crt.sh from ``modules.dns_lookup``; harvesting there would just
  duplicate work, so we focus on the endpoints that yield *emails*).

Results are deduped across sources in the orchestrator, not here, so a
caller can still see which source produced which hit.
"""

from __future__ import annotations

import re

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.passive.models import PassiveHit

log = get_logger(__name__)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)


async def _hackertarget_hosts(client: HTTPClient, domain: str) -> list[PassiveHit]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, body, _ = await client.get(url)
    if status != 200 or not body or "error" in body.lower():
        return []
    hits: list[PassiveHit] = []
    for line in body.splitlines():
        parts = line.strip().split(",")
        if len(parts) < 2:
            continue
        host, ip = parts[0].strip().lower(), parts[1].strip()
        if not host:
            continue
        hits.append(
            PassiveHit(
                source="harvester",
                kind="subdomain",
                value=host,
                title=ip,
                metadata={"provider": "hackertarget", "ip": ip},
            )
        )
    return hits


async def _threatcrowd(client: HTTPClient, domain: str) -> list[PassiveHit]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return []
    hits: list[PassiveHit] = []
    for sub in data.get("subdomains") or []:
        sub = (sub or "").strip().lower()
        if not sub:
            continue
        hits.append(
            PassiveHit(
                source="harvester",
                kind="subdomain",
                value=sub,
                metadata={"provider": "threatcrowd"},
            )
        )
    for email in data.get("emails") or []:
        email = (email or "").strip().lower()
        if not _EMAIL_RE.match(email):
            continue
        hits.append(
            PassiveHit(
                source="harvester",
                kind="email",
                value=email,
                metadata={"provider": "threatcrowd"},
            )
        )
    return hits


async def search(client: HTTPClient, domain: str) -> list[PassiveHit]:
    if not domain:
        return []
    out: list[PassiveHit] = []
    out.extend(await _hackertarget_hosts(client, domain))
    out.extend(await _threatcrowd(client, domain))
    return out

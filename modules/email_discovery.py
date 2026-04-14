"""Email discovery and breach checking."""

from core.http_client import HTTPClient
from core.models import EmailResult
from utils.helpers import md5_hash

COMMON_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com",
    "mail.com",
    "yandex.com",
]


def generate_email_candidates(username: str) -> list[str]:
    clean = username.lower().strip().replace(" ", "")
    candidates = []
    for domain in COMMON_DOMAINS:
        candidates.append(f"{clean}@{domain}")
    return candidates


async def check_gravatar(client: HTTPClient, email: str) -> dict | None:
    h = md5_hash(email)
    status, data, _ = await client.get_json(
        f"https://en.gravatar.com/{h}.json"
    )
    if status != 200 or not data:
        return None

    entries = data.get("entry", [])
    if not entries:
        return None

    entry = entries[0]
    return {
        "display_name": entry.get("displayName", ""),
        "name": entry.get("name", {}).get("formatted", ""),
        "location": entry.get("currentLocation", ""),
        "about": entry.get("aboutMe", ""),
        "urls": [u.get("value") for u in entry.get("urls", [])],
        "photos": [p.get("value") for p in entry.get("photos", [])],
        "accounts": [
            {"service": a.get("shortname"), "url": a.get("url")}
            for a in entry.get("accounts", [])
        ],
    }


async def discover_emails(
    client: HTTPClient,
    username: str,
    known_emails: list[str] | None = None,
) -> list[EmailResult]:
    results = []
    candidates = generate_email_candidates(username)
    if known_emails:
        for e in known_emails:
            if e not in candidates:
                candidates.insert(0, e)

    for email in candidates:
        gravatar = await check_gravatar(client, email)
        if gravatar:
            results.append(
                EmailResult(
                    email=email,
                    source="gravatar",
                    verified=True,
                    gravatar=True,
                )
            )

    return results

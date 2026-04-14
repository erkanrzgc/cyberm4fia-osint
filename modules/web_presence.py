"""Web presence discovery: WHOIS and Wayback Machine."""

from core.http_client import HTTPClient


async def check_wayback(client: HTTPClient, url: str) -> dict | None:
    api_url = f"https://archive.org/wayback/available?url={url}"
    status, data, _ = await client.get_json(api_url)
    if status != 200 or not data:
        return None
    snapshot = data.get("archived_snapshots", {}).get("closest")
    if not snapshot:
        return None
    return {
        "url": snapshot.get("url", ""),
        "timestamp": snapshot.get("timestamp", ""),
        "status": snapshot.get("status", ""),
        "available": snapshot.get("available", False),
    }


async def check_paste_sites(client: HTTPClient, username: str) -> list[dict]:
    results: list[dict] = []
    # check if username appears in public paste search engines
    search_url = f"https://psbdmp.ws/api/v3/search/{username}"
    status, data, _ = await client.get_json(search_url)
    if status == 200 and data and isinstance(data, list):
        for paste in data[:10]:
            results.append({
                "source": "psbdmp",
                "id": paste.get("id", ""),
                "time": paste.get("time", ""),
                "tags": paste.get("tags", ""),
            })
    return results


async def discover_web_presence(
    client: HTTPClient, username: str, found_urls: list[str] | None = None
) -> list[dict]:
    results = []

    # check wayback for found profile URLs
    if found_urls:
        for url in found_urls[:5]:
            wb = await check_wayback(client, url)
            if wb:
                results.append({
                    "type": "wayback",
                    "original_url": url,
                    **wb,
                })

    # check domain registrations
    for tld in [".com", ".net", ".org", ".io", ".dev"]:
        domain = f"{username}{tld}"
        wb = await check_wayback(client, domain)
        if wb:
            results.append({
                "type": "domain_wayback",
                "domain": domain,
                **wb,
            })

    # check paste sites
    pastes = await check_paste_sites(client, username)
    for p in pastes:
        results.append({"type": "paste", **p})

    return results

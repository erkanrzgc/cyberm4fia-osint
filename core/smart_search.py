"""Smart search: username variations and progressive discovery."""

import re

from utils.helpers import extract_emails_from_text, extract_urls_from_text


def generate_variations(username: str) -> list[str]:
    variations = set()
    lower = username.lower()

    # separator mutations
    parts = re.split(r"[._\-]", lower)
    if len(parts) > 1:
        for sep in ["", "_", ".", "-"]:
            joined = sep.join(parts)
            if joined != lower:
                variations.add(joined)
        # reversed parts: john_doe -> doe_john
        for sep in ["", "_", ".", "-"]:
            variations.add(sep.join(reversed(parts)))

    # strip trailing digits
    stripped = re.sub(r"\d+$", "", lower)
    if stripped and stripped != lower:
        variations.add(stripped)

    # strip leading/trailing underscores or dots
    clean = lower.strip("_.-")
    if clean != lower:
        variations.add(clean)

    # common suffixes
    for suffix in ["_", "0", "1", "x", "official", "real", "dev"]:
        variations.add(f"{lower}{suffix}")

    # common prefixes
    for prefix in ["_", "x", "the", "real", "its"]:
        variations.add(f"{prefix}{lower}")

    variations.discard(lower)
    variations.discard("")
    return sorted(variations)


def extract_discoverable_data(profile_data: dict) -> dict:
    """Extract names, emails, locations, and linked accounts from profile data."""
    names = set()
    emails = set()
    locations = set()
    linked_usernames = set()
    urls = set()

    for key in ["name", "full_name", "persona_name", "real_name"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            names.add(val.strip())

    first = profile_data.get("first_name", "")
    last = profile_data.get("last_name", "")
    if first and last:
        names.add(f"{first} {last}")

    for key in ["email"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and "@" in val:
            emails.add(val.strip())

    for key in ["location", "country"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            locations.add(val.strip())

    for key in ["twitter_username", "github_username"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            linked_usernames.add(val.strip())

    # keybase proofs
    proofs = profile_data.get("proofs", [])
    for proof in proofs:
        if isinstance(proof, dict) and proof.get("username"):
            linked_usernames.add(proof["username"])

    for key in ["blog", "website_url", "web_url", "links"]:
        val = profile_data.get(key)
        if val and isinstance(val, str) and val.strip():
            urls.add(val.strip())

    # scan text fields for emails and urls
    for key in ["bio", "summary", "about", "subreddit_description"]:
        val = profile_data.get(key, "")
        if val:
            emails.update(extract_emails_from_text(val))
            urls.update(extract_urls_from_text(val))

    return {
        "names": sorted(names),
        "emails": sorted(emails),
        "locations": sorted(locations),
        "linked_usernames": sorted(linked_usernames),
        "urls": sorted(urls),
    }


def merge_discoveries(discoveries: list[dict]) -> dict:
    """Merge discovery data from multiple profiles."""
    merged: dict[str, set[str]] = {
        "names": set(),
        "emails": set(),
        "locations": set(),
        "linked_usernames": set(),
        "urls": set(),
    }
    for d in discoveries:
        for key in merged:
            merged[key].update(d.get(key, []))
    return {k: sorted(v) for k, v in merged.items()}

"""Prompt templates for the local OSINT analyst LLM."""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are an OSINT analyst assistant. You receive the JSON output of
an automated username reconnaissance scan. Your job is to:

1. Summarize who the target likely is — names, locations, languages, apparent profession.
2. Identify the STRONGEST identity linkage signals across platforms (matching bios,
   avatars, display names, cross-linked accounts, shared emails).
3. Flag any high-priority exposures: breached credentials, leaked emails, exposed
   domains, geolocation hints, OPSEC mistakes.
4. Recommend 3-5 concrete NEXT investigative steps (specific platforms/queries to run
   next, not generic advice).

Rules:
- Work ONLY from the data you are given. Do NOT invent platforms, URLs, breaches, or
  facts that are not present in the JSON.
- Write terse, factual bullet points. No fluff, no disclaimers, no hedging.
- Output MUST be valid JSON matching the schema in the user message. No prose outside
  the JSON object.
- If a field has no data, return an empty list or empty string — do not omit keys.
- Respond in the same language the scan appears to target; default to English.
"""


OUTPUT_SCHEMA = {
    "identity_summary": "str — 1-3 sentence profile",
    "strong_linkages": ["str — each: platform(s) + linking signal"],
    "exposures": ["str — each: prioritized risk (HIGH/MED/LOW) + evidence"],
    "next_steps": ["str — specific actionable query/lookup"],
    "confidence": "int — 0..100 overall identity-match confidence",
}


def build_user_prompt(scan_payload: dict[str, Any]) -> str:
    """Format the scan payload as a compact JSON block plus response schema."""
    trimmed = _trim_payload(scan_payload)
    return (
        "SCAN_JSON:\n"
        f"{json.dumps(trimmed, ensure_ascii=False, indent=2)}\n\n"
        "RESPONSE_SCHEMA:\n"
        f"{json.dumps(OUTPUT_SCHEMA, ensure_ascii=False, indent=2)}\n\n"
        "Return a single JSON object matching RESPONSE_SCHEMA. No prose outside JSON."
    )


def _trim_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip noise so the model sees only the signal-dense fields."""
    found_platforms = [
        {
            "platform": p.get("platform"),
            "url": p.get("url"),
            "category": p.get("category"),
            "profile_data": _trim_profile(p.get("profile_data") or {}),
        }
        for p in payload.get("platforms", [])
        if p.get("exists")
    ]
    emails = [
        {
            "email": e.get("email"),
            "source": e.get("source"),
            "breach_count": e.get("breach_count", 0),
            "breaches": [b.get("Name") if isinstance(b, dict) else b for b in e.get("breaches", [])],
        }
        for e in payload.get("emails", [])
    ]
    return {
        "username": payload.get("username"),
        "found_count": payload.get("found_count"),
        "platforms": found_platforms,
        "emails": emails,
        "discovered_usernames": payload.get("discovered_usernames", []),
        "whois_records": payload.get("whois_records", []),
        "web_presence": payload.get("web_presence", [])[:10],
        "photo_matches": payload.get("photo_matches", []),
        "cross_reference": payload.get("cross_reference", {}),
    }


_KEEP_PROFILE_KEYS = {
    "name",
    "bio",
    "location",
    "email",
    "company",
    "blog",
    "twitter_username",
    "followers",
    "public_repos",
    "created_at",
    "avatar_url",
}


def _trim_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in profile.items() if k in _KEEP_PROFILE_KEYS and v not in (None, "")}

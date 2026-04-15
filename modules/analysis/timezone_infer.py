"""Best-effort timezone inference from the signals we already have.

Inputs, in order of trust:

1. **phone_intel timezones** — ``phonenumbers`` ships a high-quality
   country→tz mapping; if the scan collected a phone we trust it
   almost entirely.
2. **profile location / country fields** — strings like "Istanbul,
   Turkey" or "San Francisco, CA". We match against a small
   curated country→tz table and a city→tz table covering the largest
   cities only (not a full geocoder).
3. **detected language** — very weak signal used only as a tiebreak.

Each match contributes a weight; we emit the top 3 as TimezoneGuess
entries with the reasons that fired. Offline, no network calls.
"""

from __future__ import annotations

from collections import defaultdict

from modules.analysis.models import LanguageGuess, TimezoneGuess

# ── Small curated tables ────────────────────────────────────────────

_COUNTRY_TZ: dict[str, str] = {
    "turkey": "Europe/Istanbul", "türkiye": "Europe/Istanbul", "tr": "Europe/Istanbul",
    "united states": "America/New_York", "usa": "America/New_York", "us": "America/New_York",
    "united kingdom": "Europe/London", "uk": "Europe/London", "gb": "Europe/London",
    "germany": "Europe/Berlin", "de": "Europe/Berlin",
    "france": "Europe/Paris", "fr": "Europe/Paris",
    "russia": "Europe/Moscow", "ru": "Europe/Moscow",
    "netherlands": "Europe/Amsterdam", "nl": "Europe/Amsterdam",
    "japan": "Asia/Tokyo", "jp": "Asia/Tokyo",
    "china": "Asia/Shanghai", "cn": "Asia/Shanghai",
    "india": "Asia/Kolkata", "in": "Asia/Kolkata",
    "brazil": "America/Sao_Paulo", "br": "America/Sao_Paulo",
    "canada": "America/Toronto", "ca": "America/Toronto",
    "australia": "Australia/Sydney", "au": "Australia/Sydney",
    "spain": "Europe/Madrid", "es": "Europe/Madrid",
    "italy": "Europe/Rome", "it": "Europe/Rome",
    "ukraine": "Europe/Kyiv", "ua": "Europe/Kyiv",
}

_CITY_TZ: dict[str, str] = {
    "istanbul": "Europe/Istanbul", "ankara": "Europe/Istanbul", "izmir": "Europe/Istanbul",
    "london": "Europe/London", "manchester": "Europe/London",
    "paris": "Europe/Paris", "lyon": "Europe/Paris",
    "berlin": "Europe/Berlin", "munich": "Europe/Berlin",
    "amsterdam": "Europe/Amsterdam", "rotterdam": "Europe/Amsterdam",
    "moscow": "Europe/Moscow", "saint petersburg": "Europe/Moscow",
    "new york": "America/New_York", "nyc": "America/New_York", "brooklyn": "America/New_York",
    "san francisco": "America/Los_Angeles", "los angeles": "America/Los_Angeles",
    "tokyo": "Asia/Tokyo", "osaka": "Asia/Tokyo",
    "beijing": "Asia/Shanghai", "shanghai": "Asia/Shanghai",
    "mumbai": "Asia/Kolkata", "delhi": "Asia/Kolkata", "bangalore": "Asia/Kolkata",
    "são paulo": "America/Sao_Paulo", "sao paulo": "America/Sao_Paulo", "rio": "America/Sao_Paulo",
    "toronto": "America/Toronto", "vancouver": "America/Vancouver",
    "sydney": "Australia/Sydney", "melbourne": "Australia/Melbourne",
    "madrid": "Europe/Madrid", "barcelona": "Europe/Madrid",
    "rome": "Europe/Rome", "milan": "Europe/Rome",
    "kyiv": "Europe/Kyiv", "kiev": "Europe/Kyiv",
}

_LANG_TZ_HINT: dict[str, str] = {
    "tr": "Europe/Istanbul",
    "ru": "Europe/Moscow",
    "ja": "Asia/Tokyo",
    "zh": "Asia/Shanghai",
    "ar": "Asia/Riyadh",
}


def infer_timezones(
    *,
    location_strings: list[str],
    phone_timezones: list[str],
    languages: list[LanguageGuess],
    max_results: int = 3,
) -> list[TimezoneGuess]:
    """Combine the three signal classes into a ranked list of guesses."""
    scores: dict[str, float] = defaultdict(float)
    reasons: dict[str, list[str]] = defaultdict(list)

    # Phone — strong, offline-trustworthy
    for tz in phone_timezones:
        if tz:
            scores[tz] += 1.0
            reasons[tz].append("phone_region")

    # Locations — medium, with city > country precedence
    for raw in location_strings:
        if not raw:
            continue
        lowered = raw.lower()
        matched_city = False
        for city, tz in _CITY_TZ.items():
            if city in lowered:
                scores[tz] += 0.75
                reasons[tz].append(f"city:{city}")
                matched_city = True
                break
        if not matched_city:
            for country, tz in _COUNTRY_TZ.items():
                if country in lowered:
                    scores[tz] += 0.5
                    reasons[tz].append(f"country:{country}")
                    break

    # Language — weak tiebreak only
    for lang in languages[:2]:
        tz = _LANG_TZ_HINT.get(lang.code)
        if tz:
            scores[tz] += 0.15 * lang.confidence
            reasons[tz].append(f"lang:{lang.code}")

    if not scores:
        return []

    total = sum(scores.values()) or 1.0
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:max_results]
    return [
        TimezoneGuess(tz=tz, confidence=score / total, reasons=tuple(reasons[tz]))
        for tz, score in ranked
    ]

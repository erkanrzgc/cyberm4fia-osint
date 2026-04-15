"""Offline phone metadata using the ``phonenumbers`` library.

No network calls. Parses the number, derives region, carrier (best
effort — carrier DB is sparse outside mobile ranges), line type, and
timezones.
"""

from __future__ import annotations

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    from phonenumbers.phonenumberutil import NumberParseException

    _AVAILABLE = True
except ImportError:  # pragma: no cover - optional dep
    _AVAILABLE = False


_LINE_TYPES = {
    0: "fixed_line",
    1: "mobile",
    2: "fixed_line_or_mobile",
    3: "toll_free",
    4: "premium_rate",
    5: "shared_cost",
    6: "voip",
    7: "personal_number",
    8: "pager",
    9: "uan",
    10: "unknown",
    27: "voicemail",
}


def parse_offline(raw: str, *, default_region: str | None = None) -> dict:
    """Return a dict of offline metadata for ``raw``.

    Empty dict if parsing fails or the library is missing.
    """
    if not _AVAILABLE or not raw:
        return {}

    try:
        number = phonenumbers.parse(raw, default_region)
    except NumberParseException:
        return {}

    valid = phonenumbers.is_valid_number(number)
    possible = phonenumbers.is_possible_number(number)

    region = phonenumbers.region_code_for_number(number) or ""
    country_name = geocoder.description_for_number(number, "en") or ""
    carrier_name = carrier.name_for_number(number, "en") or ""
    tz = tuple(timezone.time_zones_for_number(number))
    line_type = _LINE_TYPES.get(phonenumbers.number_type(number), "unknown")

    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    national = phonenumbers.format_number(
        number, phonenumbers.PhoneNumberFormat.NATIONAL
    )

    return {
        "e164": e164,
        "national": national,
        "country_code": number.country_code,
        "region": region,
        "country_name": country_name,
        "carrier": carrier_name,
        "timezones": tz,
        "line_type": line_type,
        "valid": valid,
        "possible": possible,
    }

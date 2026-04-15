"""Shared dataclass for phone-intel results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PhoneIntel:
    raw: str                       # the input as given
    e164: str = ""                 # canonical +<country><national>
    national: str = ""             # formatted for the country
    country_code: int = 0
    region: str = ""               # ISO country code, e.g. "US"
    country_name: str = ""
    carrier: str = ""
    timezones: tuple[str, ...] = ()
    line_type: str = ""            # mobile/fixed_line/voip/unknown
    valid: bool = False
    possible: bool = False
    sources: tuple[str, ...] = ()  # ["phonenumbers", "numverify"]
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "e164": self.e164,
            "national": self.national,
            "country_code": self.country_code,
            "region": self.region,
            "country_name": self.country_name,
            "carrier": self.carrier,
            "timezones": list(self.timezones),
            "line_type": self.line_type,
            "valid": self.valid,
            "possible": self.possible,
            "sources": list(self.sources),
            "metadata": dict(self.metadata),
        }

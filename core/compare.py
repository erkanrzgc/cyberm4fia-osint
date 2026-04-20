"""Deep scan-payload comparison for side-by-side reports.

``core.history.diff_entries`` only tells you which *platforms* appeared
or vanished between two scans. That's enough for the notifier, but not
for a UI that wants to show "what actually changed": new emails,
breached accounts, profile-data deltas on still-present platforms,
geocoded locations that moved, etc.

``compare_payloads`` takes two ``ScanResult.to_dict()`` shapes and
returns a structured ``ReportDiff`` describing every bucket of change.
Pure function, no I/O — callers feed in payloads loaded from history
or passed in fresh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


# ── field pickers ─────────────────────────────────────────────────────
#
# Each picker turns an entity from a payload into a stable string key so
# two scans can be compared as sets. The picker decides what "identity"
# means for that bucket — e.g. two breach entries are the same if the
# breach name matches, ignoring pwn_count wobble.


def _platform_key(p: dict) -> str:
    return (p.get("platform") or "").strip()


def _email_key(e: dict) -> str:
    return (e.get("email") or "").strip().lower()


def _breach_key(b: Any) -> str:
    if isinstance(b, dict):
        return (b.get("name") or b.get("title") or "").strip().lower()
    return str(b).strip().lower()


def _phone_key(p: dict) -> str:
    return (p.get("e164") or p.get("raw") or "").strip()


def _crypto_key(c: dict) -> str:
    return (c.get("address") or "").strip().lower()


def _geo_key(g: dict) -> str:
    # Round to 4 decimals so tiny Nominatim wobble doesn't register as a move.
    try:
        lat = round(float(g.get("lat")), 4)
        lng = round(float(g.get("lng")), 4)
    except (TypeError, ValueError):
        return (g.get("display") or g.get("query") or "").strip().lower()
    return f"{lat},{lng}"


# ── data shapes ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class FieldChange:
    """A single field on a still-present entity that changed values."""
    field: str
    old: Any
    new: Any

    def to_dict(self) -> dict:
        return {"field": self.field, "old": self.old, "new": self.new}


@dataclass(frozen=True)
class PlatformChange:
    """Profile-data drift on a platform present in both scans."""
    platform: str
    changes: tuple[FieldChange, ...]

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class BucketDiff:
    """Added/removed/unchanged keys for a single entity type."""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "unchanged_count": len(self.unchanged),
        }


@dataclass
class ReportDiff:
    username_a: str
    username_b: str
    platforms: BucketDiff = field(default_factory=BucketDiff)
    platform_changes: list[PlatformChange] = field(default_factory=list)
    emails: BucketDiff = field(default_factory=BucketDiff)
    breaches: BucketDiff = field(default_factory=BucketDiff)
    phones: BucketDiff = field(default_factory=BucketDiff)
    crypto: BucketDiff = field(default_factory=BucketDiff)
    geo: BucketDiff = field(default_factory=BucketDiff)
    found_count_delta: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "username_a": self.username_a,
            "username_b": self.username_b,
            "summary": self.summary,
            "found_count_delta": self.found_count_delta,
            "platforms": self.platforms.to_dict(),
            "platform_changes": [pc.to_dict() for pc in self.platform_changes],
            "emails": self.emails.to_dict(),
            "breaches": self.breaches.to_dict(),
            "phones": self.phones.to_dict(),
            "crypto": self.crypto.to_dict(),
            "geo": self.geo.to_dict(),
        }


# ── bucket helpers ────────────────────────────────────────────────────


def _items(payload: dict, bucket: str) -> list[dict]:
    raw = payload.get(bucket) or []
    return [x for x in raw if isinstance(x, dict)]


def _bucket_diff(a_items: Iterable[dict], b_items: Iterable[dict], key_fn) -> BucketDiff:
    a_keys: set[str] = {k for k in (key_fn(x) for x in a_items) if k}
    b_keys: set[str] = {k for k in (key_fn(x) for x in b_items) if k}
    return BucketDiff(
        added=sorted(b_keys - a_keys),
        removed=sorted(a_keys - b_keys),
        unchanged=sorted(a_keys & b_keys),
    )


def _platform_profile_changes(a: dict, b: dict) -> list[PlatformChange]:
    """For platforms in both payloads, surface profile_data field deltas."""
    a_by_name: dict[str, dict] = {
        _platform_key(p): p for p in _items(a, "platforms") if _platform_key(p)
    }
    b_by_name: dict[str, dict] = {
        _platform_key(p): p for p in _items(b, "platforms") if _platform_key(p)
    }
    out: list[PlatformChange] = []
    for name in sorted(a_by_name.keys() & b_by_name.keys()):
        a_pd = a_by_name[name].get("profile_data") or {}
        b_pd = b_by_name[name].get("profile_data") or {}
        if not isinstance(a_pd, dict) or not isinstance(b_pd, dict):
            continue
        changes: list[FieldChange] = []
        for key in sorted(set(a_pd) | set(b_pd)):
            if a_pd.get(key) != b_pd.get(key):
                changes.append(FieldChange(field=key, old=a_pd.get(key), new=b_pd.get(key)))
        if changes:
            out.append(PlatformChange(platform=name, changes=tuple(changes)))
    return out


def _breach_entries(payload: dict) -> list[Any]:
    """Flatten every breach name across all email rows."""
    out: list[Any] = []
    for e in _items(payload, "emails"):
        for b in e.get("breaches") or []:
            out.append(b)
    return out


# ── public API ────────────────────────────────────────────────────────


def _summary(diff: ReportDiff) -> str:
    """One-line english recap for headers and notifications."""
    parts: list[str] = []
    if diff.platforms.added:
        parts.append(f"+{len(diff.platforms.added)} platforms")
    if diff.platforms.removed:
        parts.append(f"-{len(diff.platforms.removed)} platforms")
    if diff.emails.added:
        parts.append(f"+{len(diff.emails.added)} emails")
    if diff.breaches.added:
        parts.append(f"+{len(diff.breaches.added)} breaches")
    if diff.phones.added:
        parts.append(f"+{len(diff.phones.added)} phones")
    if diff.crypto.added:
        parts.append(f"+{len(diff.crypto.added)} wallets")
    if diff.geo.added:
        parts.append(f"+{len(diff.geo.added)} locations")
    if diff.platform_changes:
        parts.append(f"{len(diff.platform_changes)} platforms changed")
    return ", ".join(parts) if parts else "no changes"


def compare_payloads(a: dict, b: dict) -> ReportDiff:
    """Compute a deep diff between two scan payloads.

    Both inputs are ``ScanResult.to_dict()`` shapes. Missing buckets are
    tolerated — the corresponding ``BucketDiff`` will simply be empty.
    """
    a_platforms = [p for p in _items(a, "platforms") if p.get("exists")]
    b_platforms = [p for p in _items(b, "platforms") if p.get("exists")]

    diff = ReportDiff(
        username_a=(a.get("username") or "").strip(),
        username_b=(b.get("username") or "").strip(),
        platforms=_bucket_diff(a_platforms, b_platforms, _platform_key),
        platform_changes=_platform_profile_changes(a, b),
        emails=_bucket_diff(_items(a, "emails"), _items(b, "emails"), _email_key),
        breaches=_bucket_diff(_breach_entries(a), _breach_entries(b), _breach_key),
        phones=_bucket_diff(
            _items(a, "phone_intel"), _items(b, "phone_intel"), _phone_key
        ),
        crypto=_bucket_diff(
            _items(a, "crypto_intel"), _items(b, "crypto_intel"), _crypto_key
        ),
        geo=_bucket_diff(_items(a, "geo_points"), _items(b, "geo_points"), _geo_key),
        found_count_delta=int(b.get("found_count") or 0) - int(a.get("found_count") or 0),
    )
    diff.summary = _summary(diff)
    return diff

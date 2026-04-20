"""Tests for the report comparison module."""

from __future__ import annotations

from core.compare import compare_payloads


def _p(**kwargs) -> dict:
    base = {
        "username": "alice",
        "found_count": 0,
        "platforms": [],
        "emails": [],
        "phone_intel": [],
        "crypto_intel": [],
        "geo_points": [],
    }
    base.update(kwargs)
    return base


def _platform(name: str, exists: bool = True, **pd) -> dict:
    return {
        "platform": name,
        "url": f"https://{name.lower()}/alice",
        "category": "social",
        "exists": exists,
        "profile_data": pd,
    }


def test_empty_vs_empty_is_no_changes():
    diff = compare_payloads(_p(), _p())
    assert diff.summary == "no changes"
    assert diff.platforms.added == []
    assert diff.platforms.removed == []
    assert diff.found_count_delta == 0


def test_added_platform_appears_only_in_added():
    a = _p(found_count=1, platforms=[_platform("GitHub")])
    b = _p(found_count=2, platforms=[_platform("GitHub"), _platform("Twitter")])
    diff = compare_payloads(a, b)
    assert diff.platforms.added == ["Twitter"]
    assert diff.platforms.removed == []
    assert diff.platforms.unchanged == ["GitHub"]
    assert diff.found_count_delta == 1
    assert "+1 platforms" in diff.summary


def test_not_exists_platforms_are_ignored_for_bucket_diff():
    # A platform present in both scans but exists=False on one side must
    # not register as "removed".
    a = _p(platforms=[_platform("GitHub", exists=True), _platform("X", exists=False)])
    b = _p(platforms=[_platform("GitHub", exists=True)])
    diff = compare_payloads(a, b)
    assert diff.platforms.added == []
    assert diff.platforms.removed == []


def test_profile_data_drift_surfaced_as_platform_change():
    a = _p(platforms=[_platform("GitHub", bio="old bio", location="Berlin")])
    b = _p(platforms=[_platform("GitHub", bio="new bio", location="Berlin")])
    diff = compare_payloads(a, b)
    assert len(diff.platform_changes) == 1
    pc = diff.platform_changes[0]
    assert pc.platform == "GitHub"
    fields = {c.field for c in pc.changes}
    assert fields == {"bio"}


def test_profile_data_drift_sorted_and_includes_new_keys():
    a = _p(platforms=[_platform("GitHub", bio="x")])
    b = _p(platforms=[_platform("GitHub", bio="x", avatar="https://a/1.png")])
    diff = compare_payloads(a, b)
    pc = diff.platform_changes[0]
    changed = [c.field for c in pc.changes]
    assert changed == ["avatar"]
    assert pc.changes[0].old is None
    assert pc.changes[0].new == "https://a/1.png"


def test_email_diff_is_case_insensitive():
    a = _p(emails=[{"email": "Alice@Example.com"}])
    b = _p(emails=[{"email": "alice@example.com"}, {"email": "new@x.io"}])
    diff = compare_payloads(a, b)
    assert diff.emails.added == ["new@x.io"]
    assert diff.emails.removed == []


def test_breaches_flattened_across_email_rows():
    a = _p(emails=[{"email": "a@x.io", "breaches": ["LinkedIn"]}])
    b = _p(
        emails=[
            {"email": "a@x.io", "breaches": ["LinkedIn", "Adobe"]},
            {"email": "new@x.io", "breaches": [{"name": "Dropbox"}]},
        ]
    )
    diff = compare_payloads(a, b)
    assert set(diff.breaches.added) == {"adobe", "dropbox"}
    assert diff.breaches.removed == []


def test_geo_points_dedupe_by_rounded_coords():
    a = _p(geo_points=[{"lat": 41.0, "lng": 29.0, "display": "Istanbul"}])
    b = _p(
        geo_points=[
            {"lat": 41.00001, "lng": 29.00002, "display": "Istanbul"},  # same pin
            {"lat": 52.52, "lng": 13.4, "display": "Berlin"},
        ]
    )
    diff = compare_payloads(a, b)
    assert diff.geo.added == ["52.52,13.4"]
    assert diff.geo.removed == []


def test_geo_falls_back_to_display_when_coords_missing():
    a = _p(geo_points=[{"display": "Istanbul"}])
    b = _p(geo_points=[{"display": "Berlin"}])
    diff = compare_payloads(a, b)
    assert "berlin" in diff.geo.added
    assert "istanbul" in diff.geo.removed


def test_removed_bucket_items_surface_on_removed_side():
    a = _p(
        phone_intel=[{"e164": "+905551234567"}],
        crypto_intel=[{"address": "0xFEED"}],
    )
    b = _p()
    diff = compare_payloads(a, b)
    assert diff.phones.removed == ["+905551234567"]
    assert diff.crypto.removed == ["0xfeed"]
    assert diff.phones.added == []


def test_to_dict_shape_is_json_serialisable():
    a = _p(platforms=[_platform("GitHub", bio="x")])
    b = _p(platforms=[_platform("GitHub", bio="y"), _platform("Twitter")])
    d = compare_payloads(a, b).to_dict()
    assert d["platforms"]["added"] == ["Twitter"]
    assert d["platforms"]["unchanged_count"] == 1
    pc = d["platform_changes"][0]
    assert pc["platform"] == "GitHub"
    assert pc["changes"][0] == {"field": "bio", "old": "x", "new": "y"}
    assert "+1 platforms" in d["summary"]


def test_summary_lists_multiple_buckets():
    a = _p()
    b = _p(
        platforms=[_platform("GitHub")],
        emails=[{"email": "a@x.io"}],
        phone_intel=[{"e164": "+1"}],
    )
    diff = compare_payloads(a, b)
    assert "+1 platforms" in diff.summary
    assert "+1 emails" in diff.summary
    assert "+1 phones" in diff.summary


def test_non_dict_profile_data_does_not_crash():
    a = _p(platforms=[{"platform": "X", "exists": True, "profile_data": "oops"}])
    b = _p(platforms=[{"platform": "X", "exists": True, "profile_data": None}])
    diff = compare_payloads(a, b)
    # Platform is in both scans (unchanged); no crash, no fake changes.
    assert diff.platforms.unchanged == ["X"]
    assert diff.platform_changes == []

"""Tests for the username correlation scorer."""

from __future__ import annotations

from core.correlation import (
    WEIGHT_EMAIL,
    WEIGHT_PHONE,
    correlate,
)


def _payload(**kwargs) -> dict:
    base = {
        "username": "alice",
        "platforms": [],
        "emails": [],
        "phone_intel": [],
        "crypto_intel": [],
        "geo_points": [],
        "toutatis_results": [],
        "ghunt_results": [],
        "holehe_hits": [],
        "comb_leaks": [],
        "discovered_usernames": [],
        "variations_checked": [],
        "historical_usernames": [],
    }
    base.update(kwargs)
    return base


def test_empty_payloads_score_zero_and_no_evidence():
    result = correlate(_payload(username="a"), _payload(username="b"))
    assert result.score == 0.0
    assert result.verdict == "no_evidence"
    assert result.signals == ()


def test_shared_email_alone_tips_verdict_to_very_likely():
    a = _payload(username="alice", emails=[{"email": "Alice@Example.com", "source": "x"}])
    b = _payload(username="al1ce", emails=[{"email": "alice@example.com", "source": "y"}])
    result = correlate(a, b)
    assert result.verdict == "very_likely_same"
    assert result.score >= WEIGHT_EMAIL - 1e-6
    assert any(s.kind == "email" for s in result.signals)


def test_email_is_case_insensitive_and_deduped_across_sources():
    a = _payload(
        emails=[{"email": "bob@x.io", "source": "github"}],
        holehe_hits=[{"email": "BOB@x.io"}],
    )
    b = _payload(emails=[{"email": "bob@x.io", "source": "twitter"}])
    result = correlate(a, b)
    # Even though bob@x.io appears twice on side A, we only award one email signal.
    email_signals = [s for s in result.signals if s.kind == "email"]
    assert len(email_signals) == 1


def test_shared_phone_and_crypto_combine_toward_certainty():
    a = _payload(
        phone_intel=[{"e164": "+905551234567"}],
        crypto_intel=[{"address": "0xABC", "chain": "eth"}],
    )
    b = _payload(
        phone_intel=[{"e164": "+905551234567"}],
        crypto_intel=[{"address": "0xabc", "chain": "eth"}],
    )
    result = correlate(a, b)
    # Probabilistic OR of two strong signals must beat either alone.
    assert result.score > WEIGHT_PHONE
    assert result.verdict == "very_likely_same"
    kinds = {s.kind for s in result.signals}
    assert {"phone", "crypto"} <= kinds


def test_display_name_exact_vs_fuzzy_distinguished():
    a = _payload(
        platforms=[{"platform": "GitHub", "profile_data": {"display_name": "Jane Doe"}}]
    )
    b = _payload(
        platforms=[{"platform": "Twitter", "profile_data": {"display_name": "jane doe"}}]
    )
    result = correlate(a, b)
    name_signals = [s for s in result.signals if s.kind == "name"]
    assert len(name_signals) == 1
    assert "matches" in name_signals[0].detail


def test_display_name_fuzzy_near_match():
    a = _payload(platforms=[{"platform": "X", "profile_data": {"name": "Jonathan Smith"}}])
    b = _payload(platforms=[{"platform": "Y", "profile_data": {"name": "Jonathon Smith"}}])
    result = correlate(a, b)
    assert any(s.kind == "name" and "similar" in s.detail for s in result.signals)


def test_location_exact_counts_once_per_shared_value():
    a = _payload(geo_points=[{"display": "Istanbul, Turkey", "country": "Turkey"}])
    b = _payload(geo_points=[{"display": "Istanbul, Turkey", "country": "Turkey"}])
    result = correlate(a, b)
    loc_signals = [s for s in result.signals if s.kind == "location"]
    country_signals = [s for s in result.signals if s.kind == "country"]
    assert len(loc_signals) == 1
    assert len(country_signals) == 1


def test_country_only_overlap_is_weak_signal():
    a = _payload(geo_points=[{"display": "Istanbul", "country": "Turkey"}])
    b = _payload(geo_points=[{"display": "Ankara", "country": "Turkey"}])
    result = correlate(a, b)
    # Country overlap alone should barely register, not tip to "likely".
    assert result.verdict in {"weak_signal", "possible"}
    assert result.score < 0.25
    assert any(s.kind == "country" for s in result.signals)


def test_bio_token_overlap_respects_jaccard_threshold():
    a = _payload(
        platforms=[{"platform": "X", "profile_data": {"bio": "photographer based in berlin loves jazz"}}]
    )
    b = _payload(
        platforms=[{"platform": "Y", "profile_data": {"bio": "berlin jazz photographer"}}]
    )
    result = correlate(a, b)
    assert any(s.kind == "bio" for s in result.signals)


def test_bio_ignores_short_overlap():
    # Two-token bios are below MIN_BIO_TOKENS — should produce no bio signal.
    a = _payload(platforms=[{"platform": "X", "profile_data": {"bio": "hello world"}}])
    b = _payload(platforms=[{"platform": "Y", "profile_data": {"bio": "hello world"}}])
    result = correlate(a, b)
    assert not any(s.kind == "bio" for s in result.signals)


def test_alias_via_discovered_usernames():
    a = _payload(username="alice", discovered_usernames=["alice_dev"])
    b = _payload(username="alice_dev")
    result = correlate(a, b)
    alias_signals = [s for s in result.signals if s.kind == "alias"]
    assert len(alias_signals) == 1
    assert result.verdict in {"likely_same", "very_likely_same", "possible"}


def test_avatar_url_shared_is_a_strong_signal():
    a = _payload(
        platforms=[
            {
                "platform": "GitHub",
                "profile_data": {"avatar": "https://cdn.example/avatars/42.png"},
            }
        ]
    )
    b = _payload(
        platforms=[
            {
                "platform": "GitLab",
                "profile_data": {"avatar": "https://cdn.example/avatars/42.png"},
            }
        ]
    )
    result = correlate(a, b)
    assert any(s.kind == "avatar" for s in result.signals)
    assert result.verdict in {"likely_same", "very_likely_same"}


def test_non_dict_profile_data_does_not_crash():
    a = _payload(platforms=[{"platform": "X", "profile_data": "oops"}])
    b = _payload(platforms=[{"platform": "X", "profile_data": None}])
    # Must not raise; score must be zero when nothing was extractable.
    result = correlate(a, b)
    assert result.score == 0.0


def test_to_dict_round_trip_is_json_safe():
    a = _payload(
        username="alice", emails=[{"email": "a@b.com", "source": "x"}]
    )
    b = _payload(
        username="alice2", emails=[{"email": "a@b.com", "source": "y"}]
    )
    d = correlate(a, b).to_dict()
    assert d["username_a"] == "alice"
    assert d["username_b"] == "alice2"
    assert isinstance(d["signals"], list)
    assert d["signals"][0]["kind"] == "email"
    # Score rounded, not raw float; still numerically correct.
    assert 0.9 <= d["score"] <= 1.0


def test_probabilistic_or_never_exceeds_one():
    # Stack every possible strong signal — score must stay ≤ 1.
    a = _payload(
        emails=[{"email": "x@y.io"}],
        phone_intel=[{"e164": "+1555"}],
        crypto_intel=[{"address": "0xFEED"}],
        platforms=[
            {
                "platform": "GitHub",
                "profile_data": {
                    "display_name": "X Y",
                    "avatar": "https://a.example/1.png",
                    "bio": "hacker and photographer based in london",
                },
            }
        ],
        geo_points=[{"display": "London, UK", "country": "United Kingdom"}],
    )
    b = a
    result = correlate(a, b)
    assert 0.0 <= result.score <= 1.0
    assert result.verdict == "very_likely_same"

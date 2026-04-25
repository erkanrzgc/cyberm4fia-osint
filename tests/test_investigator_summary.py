"""Tests for investigator-friendly derived scan summaries."""

from core.investigator_summary import build_investigator_summary


def test_build_investigator_summary_highlights_risks_and_next_steps():
    payload = {
        "username": "alice",
        "found_count": 2,
        "platforms": [
            {"platform": "GitHub", "category": "dev", "exists": True},
            {"platform": "Reddit", "category": "community", "exists": True},
        ],
        "emails": [
            {"email": "alice@example.com", "breach_count": 2},
        ],
        "comb_leaks": [
            {"identifier": "alice@example.com", "password_preview": "a***", "raw_length": 12},
        ],
        "cross_reference": {
            "confidence": 84,
            "matched_names": ["alice"],
            "matched_locations": ["istanbul"],
            "matched_photos": [],
        },
        "warnings": ["IG_SESSION_ID not set"],
        "holehe_hits": [],
        "ghunt_results": [],
        "geo_points": [],
        "discovered_usernames": ["alice_dev"],
        "historical_usernames": [],
        "photo_matches": [],
    }

    summary = build_investigator_summary(payload)

    assert "alice" in summary["headline"]
    assert isinstance(summary["priority_score"], int)
    assert summary["priority_score"] > 0
    assert summary["confidence_band"] in {"low", "medium", "high", "very_high"}
    assert summary["overview"]
    assert any(risk["severity"] == "high" for risk in summary["risk_flags"])
    assert any("Pivot discovered emails" in step for step in summary["next_steps"])
    assert summary["recommended_actions_by_severity"]["high"]


def test_build_investigator_summary_handles_empty_results():
    summary = build_investigator_summary(
        {
            "username": "ghost",
            "platforms": [],
            "emails": [],
            "cross_reference": {},
        }
    )

    assert "No confirmed public profiles" in summary["headline"]
    assert summary["priority_score"] >= 0
    assert summary["confidence_band"] == "low"
    assert any("Re-run with smart search" in step for step in summary["next_steps"])

"""Tests for core/smart_search.py."""

from core.smart_search import (
    extract_discoverable_data,
    generate_variations,
    merge_discoveries,
)


class TestGenerateVariations:
    def test_basic(self):
        result = generate_variations("john_doe")
        assert "johndoe" in result
        assert "john.doe" in result
        assert "john-doe" in result
        assert "doe_john" in result

    def test_strips_trailing_digits(self):
        result = generate_variations("alice123")
        assert "alice" in result

    def test_common_suffixes(self):
        result = generate_variations("bob")
        assert "bobofficial" in result
        assert "bobreal" in result

    def test_common_prefixes(self):
        result = generate_variations("bob")
        assert "therealbob".replace("therealbob", "thebob") in result or "thebob" in result
        assert "realbob" in result

    def test_no_self(self):
        result = generate_variations("simple")
        assert "simple" not in result

    def test_returns_sorted(self):
        result = generate_variations("a_b")
        assert result == sorted(result)


class TestExtractDiscoverableData:
    def test_empty(self):
        result = extract_discoverable_data({})
        assert result == {
            "names": [],
            "emails": [],
            "locations": [],
            "linked_usernames": [],
            "urls": [],
        }

    def test_finds_names(self):
        result = extract_discoverable_data({"name": "John Doe"})
        assert "John Doe" in result["names"]

    def test_first_last_combined(self):
        result = extract_discoverable_data(
            {"first_name": "Jane", "last_name": "Smith"}
        )
        assert "Jane Smith" in result["names"]

    def test_finds_email(self):
        result = extract_discoverable_data({"email": "a@b.com"})
        assert "a@b.com" in result["emails"]

    def test_location(self):
        result = extract_discoverable_data({"location": "Istanbul"})
        assert "Istanbul" in result["locations"]

    def test_linked_accounts(self):
        result = extract_discoverable_data(
            {"twitter_username": "alice_t", "github_username": "alice_g"}
        )
        assert "alice_t" in result["linked_usernames"]
        assert "alice_g" in result["linked_usernames"]

    def test_keybase_proofs(self):
        result = extract_discoverable_data(
            {"proofs": [{"username": "alice_kb", "service": "twitter"}]}
        )
        assert "alice_kb" in result["linked_usernames"]

    def test_emails_from_bio(self):
        result = extract_discoverable_data({"bio": "reach me at foo@bar.com"})
        assert "foo@bar.com" in result["emails"]

    def test_urls_from_bio(self):
        result = extract_discoverable_data({"about": "see https://me.dev"})
        assert "https://me.dev" in result["urls"]


class TestMergeDiscoveries:
    def test_merge(self):
        a = {"names": ["Alice"], "emails": ["a@x.com"], "locations": [],
             "linked_usernames": [], "urls": []}
        b = {"names": ["Bob"], "emails": ["a@x.com"], "locations": ["TR"],
             "linked_usernames": [], "urls": []}
        result = merge_discoveries([a, b])
        assert sorted(result["names"]) == ["Alice", "Bob"]
        assert result["emails"] == ["a@x.com"]
        assert result["locations"] == ["TR"]

    def test_empty(self):
        result = merge_discoveries([])
        assert result["names"] == []

"""Tests for utils/helpers.py pure functions."""

from utils.helpers import (
    extract_emails_from_text,
    extract_urls_from_text,
    fuzzy_name_match,
    md5_hash,
    normalize_name,
    sanitize_username,
)


class TestSanitizeUsername:
    def test_strips_whitespace(self):
        assert sanitize_username("  alice  ") == "alice"

    def test_strips_leading_at(self):
        assert sanitize_username("@alice") == "alice"

    def test_combined(self):
        assert sanitize_username("  @alice  ") == "alice"

    def test_plain(self):
        assert sanitize_username("alice") == "alice"


class TestMd5Hash:
    def test_lowercases_and_strips(self):
        assert md5_hash("ALICE") == md5_hash("  alice ")

    def test_deterministic(self):
        assert md5_hash("bob") == md5_hash("bob")

    def test_different_inputs(self):
        assert md5_hash("a") != md5_hash("b")


class TestExtractEmailsFromText:
    def test_empty(self):
        assert extract_emails_from_text("") == []
        assert extract_emails_from_text(None) == []  # type: ignore[arg-type]

    def test_finds_single(self):
        result = extract_emails_from_text("contact: foo@example.com")
        assert result == ["foo@example.com"]

    def test_finds_multiple_unique(self):
        text = "a@x.com b@y.com a@x.com"
        result = sorted(extract_emails_from_text(text))
        assert result == ["a@x.com", "b@y.com"]

    def test_no_match(self):
        assert extract_emails_from_text("no email here") == []


class TestExtractUrlsFromText:
    def test_empty(self):
        assert extract_urls_from_text("") == []

    def test_finds_http_and_https(self):
        text = "visit https://example.com or http://test.org"
        result = sorted(extract_urls_from_text(text))
        assert "https://example.com" in result
        assert "http://test.org" in result

    def test_stops_at_whitespace(self):
        result = extract_urls_from_text("link https://a.com here")
        assert "https://a.com" in result


class TestNormalizeName:
    def test_empty(self):
        assert normalize_name("") == ""
        assert normalize_name(None) == ""  # type: ignore[arg-type]

    def test_lowercases(self):
        assert normalize_name("John Doe") == "john doe"

    def test_collapses_whitespace(self):
        assert normalize_name("john    doe") == "john doe"

    def test_strips(self):
        assert normalize_name("  alice  ") == "alice"


class TestFuzzyNameMatch:
    def test_empty(self):
        assert fuzzy_name_match("", "bob") == 0.0
        assert fuzzy_name_match("alice", "") == 0.0

    def test_exact(self):
        assert fuzzy_name_match("John Doe", "john doe") == 1.0

    def test_partial(self):
        score = fuzzy_name_match("John Doe", "John Smith")
        assert 0.0 < score < 1.0

    def test_no_overlap(self):
        assert fuzzy_name_match("alice", "bob") == 0.0

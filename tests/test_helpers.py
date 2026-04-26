"""Tests for utils/helpers.py pure functions."""

import pytest

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

    def test_dotted_handle_preserved(self):
        # Instagram/TikTok handles can contain dots — must not be mistaken for a domain.
        assert sanitize_username("erkan.rzgc") == "erkan.rzgc"
        assert sanitize_username("@john.doe") == "john.doe"

    def test_https_github_url(self):
        assert sanitize_username("https://github.com/erkanrzgc") == "erkanrzgc"

    def test_http_twitter_url_with_query(self):
        assert sanitize_username("http://twitter.com/erkanrzgc?ref=foo") == "erkanrzgc"

    def test_url_without_scheme(self):
        assert sanitize_username("github.com/erkanrzgc") == "erkanrzgc"

    def test_www_prefix(self):
        assert sanitize_username("www.instagram.com/erkan.rzgc") == "erkan.rzgc"

    def test_linkedin_in_prefix_stripped(self):
        assert sanitize_username("https://www.linkedin.com/in/erkanrzgc") == "erkanrzgc"

    def test_at_path_prefix_stripped(self):
        # tiktok.com/@user/ style
        assert sanitize_username("https://tiktok.com/@erkanrzgc") == "erkanrzgc"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            sanitize_username("")
        with pytest.raises(ValueError):
            sanitize_username("   ")

    def test_url_without_handle_raises(self):
        with pytest.raises(ValueError):
            sanitize_username("https://github.com/")


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

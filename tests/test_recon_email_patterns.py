"""Tests for modules/recon/email_patterns.py — pure-function generator."""

from __future__ import annotations

from modules.recon.email_patterns import (
    DEFAULT_PATTERNS,
    generate_bulk,
    generate_for_name,
    parse_name,
)


def test_parse_name_two_tokens():
    parsed = parse_name("Ada Lovelace")
    assert parsed is not None
    assert parsed.first == "ada"
    assert parsed.last == "lovelace"
    assert parsed.middle == ""


def test_parse_name_three_tokens():
    parsed = parse_name("John Fitzgerald Kennedy")
    assert parsed is not None
    assert parsed.first == "john"
    assert parsed.middle == "fitzgerald"
    assert parsed.last == "kennedy"


def test_parse_name_strips_title():
    parsed = parse_name("Dr. Alice Smith")
    assert parsed is not None
    assert parsed.first == "alice"
    assert parsed.last == "smith"


def test_parse_name_turkish_fold():
    parsed = parse_name("İsmail Şahin")
    assert parsed is not None
    assert parsed.first == "ismail"
    assert parsed.last == "sahin"


def test_parse_name_rejects_single_token():
    assert parse_name("Madonna") is None


def test_parse_name_rejects_empty():
    assert parse_name("") is None
    assert parse_name("   ") is None


def test_generate_for_name_contains_common_patterns():
    cands = generate_for_name("Ada Lovelace", "example.com")
    emails = {c.email for c in cands}
    assert "ada.lovelace@example.com" in emails
    assert "adalovelace@example.com" in emails
    assert "alovelace@example.com" in emails
    assert "ada@example.com" in emails


def test_generate_for_name_dedupes():
    cands = generate_for_name("Ada Lovelace", "example.com")
    assert len({c.email for c in cands}) == len(cands)


def test_generate_for_name_skips_middle_only_patterns_when_no_middle():
    cands = generate_for_name("Ada Lovelace", "example.com")
    for c in cands:
        assert "{middle}" not in c.pattern or c.pattern in DEFAULT_PATTERNS
        # no candidate should have two consecutive dots (empty middle)
        assert ".." not in c.email


def test_generate_for_name_includes_middle_variants():
    cands = generate_for_name("John Fitzgerald Kennedy", "example.com")
    emails = {c.email for c in cands}
    assert "john.fitzgerald.kennedy@example.com" in emails
    assert "jfkennedy@example.com" in emails


def test_generate_for_name_empty_domain():
    assert generate_for_name("Ada Lovelace", "") == []


def test_generate_for_name_strips_leading_at():
    cands = generate_for_name("Ada Lovelace", "@example.com")
    assert all(c.email.endswith("@example.com") for c in cands)


def test_generate_for_name_extra_pattern():
    cands = generate_for_name(
        "Ada Lovelace",
        "example.com",
        patterns=("{first}.{last}",),
        extra_patterns=("{first}_{last}_v2",),
    )
    emails = {c.email for c in cands}
    assert "ada.lovelace@example.com" in emails
    assert "ada_lovelace_v2@example.com" in emails


def test_generate_bulk_dedupes_across_names():
    cands = generate_bulk(
        ["Ada Lovelace", "Ada Lovelace"],
        "example.com",
    )
    assert len({c.email for c in cands}) == len(cands)


def test_generate_bulk_preserves_order():
    cands = generate_bulk(
        ["Ada Lovelace", "Bob Martin"],
        "example.com",
        patterns=("{first}.{last}",),
    )
    assert cands[0].email == "ada.lovelace@example.com"
    assert cands[1].email == "bob.martin@example.com"


def test_to_dict_roundtrip():
    cand = generate_for_name("Ada Lovelace", "example.com")[0]
    d = cand.to_dict()
    assert d["email"] == cand.email
    assert d["domain"] == "example.com"
    assert d["pattern"] in DEFAULT_PATTERNS

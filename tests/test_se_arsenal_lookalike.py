"""Tests for modules.se_arsenal.lookalike — determinism + technique coverage."""

from modules.se_arsenal.lookalike import (
    generate_bulk,
    generate_for_domain,
)


def test_empty_domain_returns_empty():
    assert generate_for_domain("") == []
    assert generate_for_domain("   ") == []


def test_homoglyph_uses_cyrillic_substitutes():
    results = generate_for_domain("acme.com")
    homos = [r for r in results if r.technique == "homoglyph"]
    assert homos, "expected at least one homoglyph variant"
    # Every homoglyph variant must contain a non-ASCII char somewhere
    # in the stem (the TLD stays ASCII).
    for r in homos:
        stem = r.domain.rsplit(".", 1)[0]
        assert any(ord(c) > 127 for c in stem)


def test_typo_swap_produces_single_edit_distance_variants():
    results = generate_for_domain("acme.com")
    typos = [r for r in results if r.technique == "typo_swap"]
    # At minimum the omission set alone yields len(stem) variants.
    assert len(typos) >= 3


def test_tld_swap_skips_original_tld():
    results = generate_for_domain("acme.com")
    tld_swaps = [r for r in results if r.technique == "tld_swap"]
    assert tld_swaps
    for r in tld_swaps:
        assert not r.domain.endswith(".com")


def test_base_is_preserved_in_every_candidate():
    results = generate_for_domain("Acme.CoM")
    assert results
    assert all(r.base == "acme.com" for r in results)


def test_output_is_deterministic():
    a = generate_for_domain("acme.com")
    b = generate_for_domain("acme.com")
    assert [(r.domain, r.technique) for r in a] == [
        (r.domain, r.technique) for r in b
    ]


def test_generate_bulk_dedupes_across_inputs():
    # Two domains that would both produce "acme.co" via TLD swap.
    results = generate_bulk(["acme.com", "acme.net"])
    seen = {r.domain for r in results}
    assert len(seen) == len(results)  # no cross-input duplicates


def test_no_variant_equals_the_original():
    base = "acme.com"
    for r in generate_for_domain(base):
        assert r.domain != base


def test_domain_without_tld_handled():
    results = generate_for_domain("acme")
    # TLD-swap should skip (no TLD to replace) but typo + homoglyph still run.
    assert results
    assert not any(r.technique == "tld_swap" for r in results)

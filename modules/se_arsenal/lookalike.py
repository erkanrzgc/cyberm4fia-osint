"""Lookalike domain generator — pure function, no network.

Generates visually-confusable domains for phishing infrastructure. Three
independent techniques run per base domain:

* **Homoglyph**: swap one ASCII letter with a Cyrillic lookalike
  (``acme`` → ``аcme``). Produces IDN/Punycode-registrable candidates.
* **Typosquat**: single-edit distortions (adjacent-key swap, omission,
  duplication, transposition) — the stuff users actually mistype.
* **TLD swap**: replace the public suffix with a common alternative
  (``acme.com`` → ``acme.co``, ``acme.io`` …).

Output is deterministic and deduped. Caller is responsible for checking
which candidates are actually registrable (WHOIS is out of scope here).
"""

from __future__ import annotations

from collections.abc import Iterable

from modules.se_arsenal.models import LookalikeDomain

# Latin → Cyrillic visual doubles that render near-identically in most fonts.
_HOMOGLYPH_MAP: dict[str, str] = {
    "a": "а",  # U+0430
    "c": "с",  # U+0441
    "e": "е",  # U+0435
    "o": "о",  # U+043E
    "p": "р",  # U+0440
    "x": "х",  # U+0445
    "y": "у",  # U+0443
}

# Tight keyboard-adjacency set for typo_swap. Intentionally small — big
# maps make the output noisy and low-quality.
_ADJACENT: dict[str, str] = {
    "q": "w", "w": "e", "e": "r", "r": "t", "t": "y", "y": "u", "u": "i",
    "i": "o", "o": "p", "a": "s", "s": "d", "d": "f", "f": "g", "g": "h",
    "h": "j", "j": "k", "k": "l", "z": "x", "x": "c", "c": "v", "v": "b",
    "b": "n", "n": "m",
}

# Ordered by operator preference — shorter/brandable TLDs first.
_ALT_TLDS: tuple[str, ...] = (
    "co", "io", "net", "org", "app", "site", "online", "com.co", "dev",
)


def _split(domain: str) -> tuple[str, str]:
    """Split ``acme.com`` → (``acme``, ``com``). Naive: uses the LAST dot."""
    if "." not in domain:
        return domain, ""
    stem, tld = domain.rsplit(".", 1)
    return stem, tld


def _homoglyph_variants(stem: str) -> list[str]:
    """One Cyrillic-substitution per position where a mapping exists."""
    out: list[str] = []
    for i, ch in enumerate(stem):
        sub = _HOMOGLYPH_MAP.get(ch.lower())
        if sub is None:
            continue
        out.append(stem[:i] + sub + stem[i + 1 :])
    return out


def _typo_variants(stem: str) -> list[str]:
    """Adjacent-key swap, omission, duplication, transposition."""
    out: set[str] = set()
    n = len(stem)
    # adjacent-key swap
    for i, ch in enumerate(stem):
        alt = _ADJACENT.get(ch.lower())
        if alt:
            out.add(stem[:i] + alt + stem[i + 1 :])
    # omission
    for i in range(n):
        out.add(stem[:i] + stem[i + 1 :])
    # duplication
    for i in range(n):
        out.add(stem[: i + 1] + stem[i] + stem[i + 1 :])
    # transposition
    for i in range(n - 1):
        out.add(stem[:i] + stem[i + 1] + stem[i] + stem[i + 2 :])
    # drop empty/identity
    out.discard("")
    out.discard(stem)
    return sorted(out)


def _tld_swap_variants(stem: str, original_tld: str) -> list[str]:
    if not original_tld:
        return []  # "swap" is meaningless when there is no TLD to replace
    return [f"{stem}.{t}" for t in _ALT_TLDS if t != original_tld.lower()]


def generate_for_domain(domain: str) -> list[LookalikeDomain]:
    """Produce all lookalike candidates for a single base domain.

    Ordering: homoglyph → typosquat → tld_swap (highest deception first).
    Duplicates across techniques are dropped in favor of the earlier one.
    """
    base = domain.strip().lower().lstrip("@")
    if not base:
        return []
    stem, tld = _split(base)
    results: list[LookalikeDomain] = []
    seen: set[str] = {base}

    for variant in _homoglyph_variants(stem):
        full = f"{variant}.{tld}" if tld else variant
        if full in seen:
            continue
        seen.add(full)
        results.append(LookalikeDomain(domain=full, technique="homoglyph", base=base))

    for variant in _typo_variants(stem):
        full = f"{variant}.{tld}" if tld else variant
        if full in seen:
            continue
        seen.add(full)
        results.append(LookalikeDomain(domain=full, technique="typo_swap", base=base))

    for variant in _tld_swap_variants(stem, tld):
        if variant in seen:
            continue
        seen.add(variant)
        results.append(LookalikeDomain(domain=variant, technique="tld_swap", base=base))

    return results


def generate_bulk(domains: Iterable[str]) -> list[LookalikeDomain]:
    """Fan out ``generate_for_domain`` across an iterable, deduping globally."""
    out: list[LookalikeDomain] = []
    seen: set[str] = set()
    for d in domains:
        for cand in generate_for_domain(d):
            if cand.domain in seen:
                continue
            seen.add(cand.domain)
            out.append(cand)
    return out

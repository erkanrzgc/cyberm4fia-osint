"""Generate likely corporate email addresses from a name list.

Given a domain and a list of full names (Unicode-safe, TR locale aware),
emit every plausible ``<local>@<domain>`` combination ordered by how
common the pattern is in the wild. This is a pure function — no HTTP —
so it's cheap to iterate on and trivial to unit-test.

The default pattern set covers ~90% of what real corporate mail systems
use. Extra custom patterns can be injected via ``extra_patterns``; each
template receives ``first``, ``last``, ``fi`` (first initial),
``li`` (last initial), ``middle`` (may be empty), ``mi`` (middle initial).
Templates that reference missing parts (e.g. ``middle`` for a two-token
name) are skipped silently.

No attempt is made to validate that the address actually exists — that
is the job of a downstream verifier (Holehe, SMTP probing, HIBP).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from modules.recon.models import EmailCandidate

# Ordered by how frequent the pattern is across real corp directories.
# If the first pattern hits, campaigns converge fast; keeping the order
# deterministic matters for reproducible phishing target lists.
DEFAULT_PATTERNS: tuple[str, ...] = (
    "{first}.{last}",
    "{first}{last}",
    "{fi}{last}",
    "{first}_{last}",
    "{first}-{last}",
    "{last}.{first}",
    "{last}{first}",
    "{last}{fi}",
    "{first}",
    "{last}",
    "{fi}.{last}",
    "{first}.{li}",
    "{fi}{li}",
    "{first}.{middle}.{last}",
    "{fi}{mi}{last}",
)

_LOCAL_SAFE = re.compile(r"[^a-z0-9._\-+]")
_TR_FOLD = str.maketrans(
    {
        "ı": "i",
        "İ": "i",
        "ğ": "g",
        "Ğ": "g",
        "ü": "u",
        "Ü": "u",
        "ş": "s",
        "Ş": "s",
        "ö": "o",
        "Ö": "o",
        "ç": "c",
        "Ç": "c",
    }
)


@dataclass(frozen=True)
class ParsedName:
    """Normalized name parts ready for template substitution."""

    first: str
    last: str
    middle: str = ""

    @property
    def fi(self) -> str:
        return self.first[:1]

    @property
    def li(self) -> str:
        return self.last[:1]

    @property
    def mi(self) -> str:
        return self.middle[:1]


def _slug(raw: str) -> str:
    """ASCII-fold a token for email local-part use.

    Applies TR-specific folding first (so İsmail → ismail, not ismail with
    a dotless i), then strips combining marks and non-safe chars.
    """
    lowered = raw.strip().lower().translate(_TR_FOLD)
    stripped = "".join(
        c for c in unicodedata.normalize("NFKD", lowered) if not unicodedata.combining(c)
    )
    return _LOCAL_SAFE.sub("", stripped)


def parse_name(full_name: str) -> ParsedName | None:
    """Split a free-form name string into first / middle / last slugs.

    * Drops titles ("Dr.", "Mr.", "Sn.") when they prefix the first token.
    * Folds three-token names into first + middle + last.
    * Folds four-plus-token names by joining everything between first and
      last into ``middle`` — good enough for pattern generation since we
      only use ``mi`` (initial) in practice.
    """
    if not full_name or not full_name.strip():
        return None
    tokens = [t for t in re.split(r"\s+", full_name.strip()) if t]
    titles = {"dr", "dr.", "mr", "mr.", "mrs", "mrs.", "ms", "ms.", "sn", "sn.", "prof", "prof."}
    if tokens and tokens[0].lower() in titles:
        tokens = tokens[1:]
    if len(tokens) < 2:
        return None
    first = _slug(tokens[0])
    last = _slug(tokens[-1])
    middle = _slug(" ".join(tokens[1:-1])) if len(tokens) > 2 else ""
    if not first or not last:
        return None
    return ParsedName(first=first, last=last, middle=middle)


def _render(pattern: str, name: ParsedName) -> str | None:
    needs_middle = "{middle}" in pattern or "{mi}" in pattern
    if needs_middle and not name.middle:
        return None
    try:
        local = pattern.format(
            first=name.first,
            last=name.last,
            fi=name.fi,
            li=name.li,
            middle=name.middle,
            mi=name.mi,
        )
    except (KeyError, IndexError):
        return None
    local = local.strip(".-_")
    if not local or ".." in local:
        return None
    return local


def generate_for_name(
    full_name: str,
    domain: str,
    *,
    patterns: tuple[str, ...] = DEFAULT_PATTERNS,
    extra_patterns: tuple[str, ...] = (),
) -> list[EmailCandidate]:
    """Produce deduped ``EmailCandidate`` list for one name + domain."""
    name = parse_name(full_name)
    domain = (domain or "").strip().lower().lstrip("@")
    if not name or not domain:
        return []
    seen: set[str] = set()
    out: list[EmailCandidate] = []
    for pat in (*patterns, *extra_patterns):
        local = _render(pat, name)
        if not local:
            continue
        email = f"{local}@{domain}"
        if email in seen:
            continue
        seen.add(email)
        out.append(
            EmailCandidate(
                email=email,
                first_name=name.first,
                last_name=name.last,
                pattern=pat,
                domain=domain,
            )
        )
    return out


def generate_bulk(
    names: list[str],
    domain: str,
    *,
    patterns: tuple[str, ...] = DEFAULT_PATTERNS,
    extra_patterns: tuple[str, ...] = (),
) -> list[EmailCandidate]:
    """Run ``generate_for_name`` over many names, deduping across the whole set.

    Preserves input order of first appearance — useful when the caller
    wants to show "most likely real person" hits first in a report.
    """
    seen: set[str] = set()
    out: list[EmailCandidate] = []
    for name in names:
        for cand in generate_for_name(
            name, domain, patterns=patterns, extra_patterns=extra_patterns
        ):
            if cand.email in seen:
                continue
            seen.add(cand.email)
            out.append(cand)
    return out

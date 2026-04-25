"""Red-team CSV exports: phishing target list + org recon dossier.

Two files, one column schema each, both UTF-8 BOM'd so Excel opens them
without a "data loss?" nag:

* ``phishing_targets.csv`` — one row per ``EmailCandidate`` or
  ``GithubCommitter``, ready to be pasted into a campaign tool.
* ``recon_attack_surface.csv`` — one row per subdomain hit, sourced.

Callers pass already-built lists of dataclasses; this module knows
nothing about the scan engine itself, which keeps it trivially unit
testable.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from modules.recon.models import (
    EmailCandidate,
    GithubCommitter,
    ReconSubdomain,
)

TARGET_FIELDS = (
    "email",
    "full_name",
    "first_name",
    "last_name",
    "source",
    "pattern_or_repo",
    "commits_seen",
    "notes",
)

SURFACE_FIELDS = ("host", "source", "metadata")


def _write_csv(path: Path, fields: tuple[str, ...], rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def _target_row_from_candidate(c: EmailCandidate) -> dict:
    return {
        "email": c.email,
        "full_name": f"{c.first_name} {c.last_name}".strip(),
        "first_name": c.first_name,
        "last_name": c.last_name,
        "source": "pattern",
        "pattern_or_repo": c.pattern,
        "commits_seen": "",
        "notes": f"generated for {c.domain}",
    }


def _target_row_from_committer(g: GithubCommitter) -> dict:
    notes = []
    if g.login:
        notes.append(f"github:{g.login}")
    if g.is_noreply:
        notes.append("NOREPLY")
    return {
        "email": g.email,
        "full_name": g.name,
        "first_name": "",
        "last_name": "",
        "source": "github",
        "pattern_or_repo": g.repo,
        "commits_seen": g.commits_seen,
        "notes": ",".join(notes),
    }


def export_phishing_targets(
    path: str | Path,
    *,
    candidates: list[EmailCandidate] | None = None,
    committers: list[GithubCommitter] | None = None,
    include_noreply: bool = False,
) -> int:
    """Write a phishing-campaign-ready target list, return row count.

    Rows are deduped on lowercased email, keeping the first occurrence.
    Pattern-generated candidates land first so the CSV stays
    deterministic across reruns.
    """
    out_path = Path(path)
    seen: set[str] = set()
    rows: list[dict] = []

    for cand in candidates or []:
        key = cand.email.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append(_target_row_from_candidate(cand))

    for git in committers or []:
        if git.is_noreply and not include_noreply:
            continue
        key = git.email.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append(_target_row_from_committer(git))

    return _write_csv(out_path, TARGET_FIELDS, rows)


def export_attack_surface(
    path: str | Path,
    subdomains: list[ReconSubdomain],
) -> int:
    """Write the subdomain recon dossier, return row count."""
    out_path = Path(path)
    rows = (
        {
            "host": s.host,
            "source": s.source,
            "metadata": ";".join(f"{k}={v}" for k, v in sorted(s.metadata.items())),
        }
        for s in subdomains
    )
    return _write_csv(out_path, SURFACE_FIELDS, rows)

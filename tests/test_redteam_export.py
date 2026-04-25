"""Tests for core/reporter/redteam_export.py."""

from __future__ import annotations

import csv
from pathlib import Path

from core.reporter.redteam_export import (
    SURFACE_FIELDS,
    TARGET_FIELDS,
    export_attack_surface,
    export_phishing_targets,
)
from modules.recon.email_patterns import generate_for_name
from modules.recon.models import GithubCommitter, ReconSubdomain


def _read_csv(path: Path) -> list[dict]:
    # utf-8-sig so the BOM we wrote doesn't pollute the first column name
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def test_export_phishing_targets_candidates_only(tmp_path: Path):
    cands = generate_for_name("Ada Lovelace", "example.com")
    out = tmp_path / "targets.csv"
    count = export_phishing_targets(out, candidates=cands)
    rows = _read_csv(out)
    assert count == len(cands)
    assert len(rows) == count
    assert {r["email"] for r in rows} == {c.email for c in cands}
    assert all(r["source"] == "pattern" for r in rows)
    assert list(rows[0].keys()) == list(TARGET_FIELDS)


def test_export_phishing_targets_committers_only(tmp_path: Path):
    gits = [
        GithubCommitter(
            email="ada@acme.com", name="Ada", login="ada", repo="acme/alpha",
            commits_seen=5,
        ),
        GithubCommitter(
            email="1+anon@users.noreply.github.com",
            name="Anon",
            is_noreply=True,
        ),
    ]
    out = tmp_path / "targets.csv"
    count = export_phishing_targets(out, committers=gits)
    rows = _read_csv(out)
    assert count == 1  # noreply filtered by default
    assert rows[0]["email"] == "ada@acme.com"
    assert rows[0]["source"] == "github"
    assert rows[0]["pattern_or_repo"] == "acme/alpha"
    assert rows[0]["commits_seen"] == "5"


def test_export_phishing_targets_include_noreply(tmp_path: Path):
    gits = [
        GithubCommitter(
            email="1+anon@users.noreply.github.com",
            name="Anon",
            is_noreply=True,
        ),
    ]
    out = tmp_path / "targets.csv"
    count = export_phishing_targets(out, committers=gits, include_noreply=True)
    rows = _read_csv(out)
    assert count == 1
    assert "NOREPLY" in rows[0]["notes"]


def test_export_phishing_targets_dedupes_across_sources(tmp_path: Path):
    cands = generate_for_name("Ada Lovelace", "example.com")
    # pick one candidate and forge a committer with the same email
    overlap = cands[0].email
    gits = [GithubCommitter(email=overlap, name="Ada", repo="acme/alpha")]
    out = tmp_path / "targets.csv"
    count = export_phishing_targets(out, candidates=cands, committers=gits)
    rows = _read_csv(out)
    emails = [r["email"] for r in rows]
    assert emails.count(overlap) == 1
    assert count == len(cands)  # committer got deduped


def test_export_attack_surface(tmp_path: Path):
    subs = [
        ReconSubdomain(host="api.example.com", source="dns_lookup"),
        ReconSubdomain(
            host="vpn.example.com", source="anubisdb", metadata={"seen": "2024"}
        ),
    ]
    out = tmp_path / "surface.csv"
    count = export_attack_surface(out, subs)
    rows = _read_csv(out)
    assert count == 2
    assert list(rows[0].keys()) == list(SURFACE_FIELDS)
    by_host = {r["host"]: r for r in rows}
    assert by_host["vpn.example.com"]["metadata"] == "seen=2024"
    assert by_host["api.example.com"]["metadata"] == ""


def test_export_creates_parent_dir(tmp_path: Path):
    out = tmp_path / "nested" / "deeper" / "targets.csv"
    export_phishing_targets(out, candidates=[])
    assert out.exists()

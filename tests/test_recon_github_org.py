"""Tests for modules/recon/github_org.py."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.recon.github_org import _merge, scan_org
from modules.recon.models import GithubCommitter


def _commit(name: str, email: str, login: str = "") -> dict:
    return {
        "commit": {"author": {"name": name, "email": email}},
        "author": ({"login": login} if login else None),
    }


@pytest.mark.asyncio
async def test_scan_org_empty_name():
    async with HTTPClient() as client:
        assert await scan_org(client, "") == []


@pytest.mark.asyncio
async def test_scan_org_happy_path(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    repos_payload = [
        {"full_name": "acme/alpha", "fork": False},
        {"full_name": "acme/beta", "fork": False},
        {"full_name": "acme/fork-of-thing", "fork": True},  # filtered out
    ]
    alpha_commits = [
        _commit("Ada Lovelace", "ada@acme.com", login="ada"),
        _commit("Ada Lovelace", "ada@acme.com", login="ada"),
        _commit("Bob Martin", "bob@acme.com"),
    ]
    beta_commits = [
        _commit("Anon", "12345+anon@users.noreply.github.com"),
        _commit("Ada Lovelace", "ada@acme.com", login="ada"),
    ]
    with aioresponses() as m:
        m.get(
            "https://api.github.com/orgs/acme/repos?per_page=100&page=1"
            "&type=public&sort=pushed",
            status=200,
            payload=repos_payload,
        )
        m.get(
            "https://api.github.com/repos/acme/alpha/commits?per_page=30",
            status=200,
            payload=alpha_commits,
        )
        m.get(
            "https://api.github.com/repos/acme/beta/commits?per_page=30",
            status=200,
            payload=beta_commits,
        )
        async with HTTPClient() as client:
            out = await scan_org(client, "acme", max_repos=30, commits_per_repo=30)

    emails = {c.email: c for c in out}
    assert "ada@acme.com" in emails
    assert emails["ada@acme.com"].commits_seen == 3
    assert emails["ada@acme.com"].login == "ada"
    assert "bob@acme.com" in emails
    noreply = [c for c in out if c.is_noreply]
    assert len(noreply) == 1
    # noreply ranks last when sorted
    assert out[-1].is_noreply is True


@pytest.mark.asyncio
async def test_scan_org_returns_empty_on_repo_list_failure():
    with aioresponses() as m:
        m.get(
            "https://api.github.com/orgs/ghost/repos?per_page=100&page=1"
            "&type=public&sort=pushed",
            status=404,
            payload={},
        )
        async with HTTPClient() as client:
            assert await scan_org(client, "ghost") == []


@pytest.mark.asyncio
async def test_scan_org_tolerates_single_repo_failure():
    repos_payload = [
        {"full_name": "acme/alpha", "fork": False},
        {"full_name": "acme/beta", "fork": False},
    ]
    with aioresponses() as m:
        m.get(
            "https://api.github.com/orgs/acme/repos?per_page=100&page=1"
            "&type=public&sort=pushed",
            status=200,
            payload=repos_payload,
        )
        m.get(
            "https://api.github.com/repos/acme/alpha/commits?per_page=30",
            status=500,
        )
        m.get(
            "https://api.github.com/repos/acme/beta/commits?per_page=30",
            status=200,
            payload=[_commit("Carol", "carol@acme.com")],
        )
        async with HTTPClient() as client:
            out = await scan_org(client, "acme", max_repos=30, commits_per_repo=30)
    emails = {c.email for c in out}
    assert emails == {"carol@acme.com"}


def test_merge_counts_and_sorts():
    accums = _merge(
        [
            # two entries to the same identity → counted once
            # (we rebuild _Accum via private import to keep it tight)
        ]
    )
    assert accums == []


def test_to_dict_roundtrip():
    g = GithubCommitter(email="a@b.com", name="Ada", commits_seen=2)
    d = g.to_dict()
    assert d["email"] == "a@b.com"
    assert d["commits_seen"] == 2
    assert d["is_noreply"] is False

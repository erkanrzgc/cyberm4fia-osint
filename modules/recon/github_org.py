"""GitHub organization recon — pull committer identities from public repos.

Corporate GitHub orgs routinely leak employee ``Name <email>`` pairs in
public commit metadata. This module walks an org's repos and summarizes
every committer it saw, with per-identity commit counts and repo
provenance.

Authentication is optional: with ``GITHUB_TOKEN`` in the environment the
client gets 5000 req/hour, without it GitHub allows 60/hour which is
enough for a quick sweep of a small org.

Nothing here scrapes private data — only the same public endpoints the
github.com UI hits for anonymous visitors.
"""

from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from dataclasses import dataclass

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.recon.models import GithubCommitter

log = get_logger(__name__)

_API = "https://api.github.com"
_NOREPLY_SUFFIX = "@users.noreply.github.com"

# Conservative defaults; bump via kwargs if you have a token.
DEFAULT_MAX_REPOS = 30
DEFAULT_COMMITS_PER_REPO = 30
_REPOS_PAGE_SIZE = 100


@dataclass(frozen=True)
class _Accum:
    """Intermediate accumulator keyed by (email, name)."""

    email: str
    name: str
    login: str
    repo: str
    is_noreply: bool


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _list_repos(
    client: HTTPClient, org: str, *, max_repos: int
) -> list[str]:
    """Return a list of ``owner/name`` slugs for the org's public repos.

    Follows pagination by incrementing ``page``; stops early when we hit
    ``max_repos`` or the API returns an empty page.
    """
    slugs: list[str] = []
    page = 1
    while len(slugs) < max_repos:
        url = (
            f"{_API}/orgs/{org}/repos?per_page={_REPOS_PAGE_SIZE}"
            f"&page={page}&type=public&sort=pushed"
        )
        status, data, _ = await client.get_json(url, headers=_auth_headers())
        if status != 200 or not isinstance(data, list) or not data:
            break
        for repo in data:
            if not isinstance(repo, dict):
                continue
            full_name = repo.get("full_name")
            if not full_name or repo.get("fork"):
                continue
            slugs.append(full_name)
            if len(slugs) >= max_repos:
                break
        if len(data) < _REPOS_PAGE_SIZE:
            break
        page += 1
    return slugs


def _extract_committers(commits: list[dict], repo: str) -> list[_Accum]:
    out: list[_Accum] = []
    for item in commits:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit") or {}
        author = commit.get("author") or {}
        email = (author.get("email") or "").strip().lower()
        name = (author.get("name") or "").strip()
        if not email or "@" not in email:
            continue
        login = ""
        author_block = item.get("author")
        if isinstance(author_block, dict):
            login = (author_block.get("login") or "").strip()
        out.append(
            _Accum(
                email=email,
                name=name,
                login=login,
                repo=repo,
                is_noreply=email.endswith(_NOREPLY_SUFFIX),
            )
        )
    return out


async def _fetch_commits(
    client: HTTPClient, repo: str, *, per_repo: int
) -> list[_Accum]:
    url = f"{_API}/repos/{repo}/commits?per_page={per_repo}"
    status, data, _ = await client.get_json(url, headers=_auth_headers())
    if status != 200 or not isinstance(data, list):
        return []
    return _extract_committers(data, repo)


def _merge(accums: list[_Accum]) -> list[GithubCommitter]:
    """Collapse per-commit rows into one entry per (email, name) pair."""
    by_key: dict[tuple[str, str], list[_Accum]] = defaultdict(list)
    for row in accums:
        by_key[(row.email, row.name)].append(row)
    out: list[GithubCommitter] = []
    for (email, name), rows in by_key.items():
        first = rows[0]
        out.append(
            GithubCommitter(
                email=email,
                name=name,
                login=first.login,
                repo=first.repo,
                commits_seen=len(rows),
                is_noreply=first.is_noreply,
            )
        )
    out.sort(key=lambda c: (c.is_noreply, -c.commits_seen, c.email))
    return out


async def scan_org(
    client: HTTPClient,
    org: str,
    *,
    max_repos: int = DEFAULT_MAX_REPOS,
    commits_per_repo: int = DEFAULT_COMMITS_PER_REPO,
) -> list[GithubCommitter]:
    """Walk an org's public repos and return one entry per committer.

    Network cost: up to ``(max_repos / 100) + max_repos`` API calls.
    With the default caps and no token, a 30-repo sweep fits inside the
    anonymous 60/hour budget with headroom.
    """
    if not org or not org.strip():
        return []
    org = org.strip()
    repos = await _list_repos(client, org, max_repos=max_repos)
    if not repos:
        log.debug("github org %s: no public repos listed", org)
        return []

    commit_jobs = [
        _fetch_commits(client, repo, per_repo=commits_per_repo) for repo in repos
    ]
    results = await asyncio.gather(*commit_jobs, return_exceptions=True)

    merged: list[_Accum] = []
    for repo, batch in zip(repos, results, strict=False):
        if isinstance(batch, BaseException):
            log.debug("github commits fetch failed for %s: %s", repo, batch)
            continue
        merged.extend(batch)
    return _merge(merged)

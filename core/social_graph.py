"""Social graph overlap — follower/following sets across platforms.

Given two usernames on the same platform, fetch their neighbour sets and
report the shared edges plus Jaccard similarity. Evidence-first: the
caller sees *which* accounts connect the two identities, not just a
number.

Only GitHub is supported out of the box because its public REST API
exposes followers/following without auth. Twitter/X and friends now
require paid API access — left as a future adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from core.logging_setup import get_logger

log = get_logger(__name__)

GITHUB_API = "https://api.github.com"
GITHUB_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 5  # caps fetches at 500 accounts per direction


class _JsonClient(Protocol):
    async def get_json(
        self, url: str, headers: dict | None = None
    ) -> tuple[int, Any, float]: ...


@dataclass(frozen=True)
class SocialNeighbors:
    """Follower/following snapshot for one (platform, username) pair."""

    platform: str
    username: str
    followers: frozenset[str]
    following: frozenset[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "username": self.username,
            "followers": sorted(self.followers),
            "following": sorted(self.following),
            "follower_count": len(self.followers),
            "following_count": len(self.following),
        }


@dataclass(frozen=True)
class SocialOverlap:
    """Comparison result between two SocialNeighbors on the same platform."""

    platform: str
    username_a: str
    username_b: str
    shared_followers: tuple[str, ...]
    shared_following: tuple[str, ...]
    followers_jaccard: float
    following_jaccard: float
    combined_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "username_a": self.username_a,
            "username_b": self.username_b,
            "shared_followers": list(self.shared_followers),
            "shared_following": list(self.shared_following),
            "followers_jaccard": self.followers_jaccard,
            "following_jaccard": self.following_jaccard,
            "combined_score": self.combined_score,
        }


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Jaccard similarity. Empty ∪ returns 0.0 rather than NaN."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def compute_overlap(a: SocialNeighbors, b: SocialNeighbors) -> SocialOverlap:
    if a.platform != b.platform:
        raise ValueError(
            f"platform mismatch: {a.platform!r} vs {b.platform!r}"
        )
    shared_fo = tuple(sorted(a.followers & b.followers))
    shared_fg = tuple(sorted(a.following & b.following))
    j_fo = jaccard(a.followers, b.followers)
    j_fg = jaccard(a.following, b.following)
    # Combined: weight followers and following equally; if either side is
    # empty on both accounts, fall back to the other direction.
    if (a.followers or b.followers) and (a.following or b.following):
        combined = (j_fo + j_fg) / 2
    else:
        combined = j_fo if (a.followers or b.followers) else j_fg
    return SocialOverlap(
        platform=a.platform,
        username_a=a.username,
        username_b=b.username,
        shared_followers=shared_fo,
        shared_following=shared_fg,
        followers_jaccard=j_fo,
        following_jaccard=j_fg,
        combined_score=combined,
    )


async def _paginate_logins(
    client: _JsonClient,
    base_url: str,
    headers: dict | None,
    max_pages: int,
) -> frozenset[str]:
    logins: set[str] = set()
    for page in range(1, max_pages + 1):
        url = f"{base_url}?per_page={GITHUB_PAGE_SIZE}&page={page}"
        status, data, _ = await client.get_json(url, headers=headers)
        if status != 200 or not isinstance(data, list):
            break
        page_logins = [
            str(item["login"]).lower()
            for item in data
            if isinstance(item, dict) and item.get("login")
        ]
        logins.update(page_logins)
        if len(data) < GITHUB_PAGE_SIZE:
            break
    return frozenset(logins)


async def fetch_github_neighbors(
    client: _JsonClient,
    username: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    token: str | None = None,
) -> SocialNeighbors:
    """Fetch followers+following for a GitHub user via the public API.

    Returns empty sets on 404 or network failure — callers can treat
    that as "no signal" rather than raising.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    followers = await _paginate_logins(
        client, f"{GITHUB_API}/users/{username}/followers", headers, max_pages
    )
    following = await _paginate_logins(
        client, f"{GITHUB_API}/users/{username}/following", headers, max_pages
    )
    return SocialNeighbors(
        platform="github",
        username=username,
        followers=followers,
        following=following,
    )

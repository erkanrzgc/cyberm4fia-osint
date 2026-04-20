"""Social graph overlap tests — pure logic + mocked GitHub fetcher."""

from __future__ import annotations

import pytest

from core.social_graph import (
    SocialNeighbors,
    SocialOverlap,
    compute_overlap,
    jaccard,
)


def test_jaccard_empty_sets_returns_zero() -> None:
    assert jaccard(frozenset(), frozenset()) == 0.0


def test_jaccard_identical_sets_returns_one() -> None:
    s = frozenset({"a", "b", "c"})
    assert jaccard(s, s) == 1.0


def test_jaccard_partial_overlap() -> None:
    a = frozenset({"x", "y", "z"})
    b = frozenset({"y", "z", "w"})
    # |∩| = 2, |∪| = 4  →  0.5
    assert jaccard(a, b) == 0.5


def test_jaccard_case_insensitive_via_precomputed_sets() -> None:
    # The caller is expected to normalise — this just documents behaviour.
    a = frozenset({"alice"})
    b = frozenset({"Alice"})
    assert jaccard(a, b) == 0.0  # caller must lowercase first


def test_compute_overlap_surfaces_shared_and_unique() -> None:
    a = SocialNeighbors(
        platform="github",
        username="alice",
        followers=frozenset({"bob", "carol", "dave"}),
        following=frozenset({"bob", "eve"}),
    )
    b = SocialNeighbors(
        platform="github",
        username="alice2",
        followers=frozenset({"carol", "frank"}),
        following=frozenset({"eve", "grace"}),
    )
    ov = compute_overlap(a, b)
    assert isinstance(ov, SocialOverlap)
    assert ov.platform == "github"
    assert ov.shared_followers == ("carol",)
    assert ov.shared_following == ("eve",)
    # Jaccard on followers {bob,carol,dave} ∩ {carol,frank} = 1, ∪ = 4
    assert ov.followers_jaccard == pytest.approx(0.25)
    assert ov.following_jaccard == pytest.approx(1 / 3)


def test_compute_overlap_platform_mismatch_raises() -> None:
    a = SocialNeighbors("github", "a", frozenset(), frozenset())
    b = SocialNeighbors("twitter", "b", frozenset(), frozenset())
    with pytest.raises(ValueError):
        compute_overlap(a, b)


def test_social_overlap_to_dict_shape() -> None:
    ov = SocialOverlap(
        platform="github",
        username_a="a",
        username_b="b",
        shared_followers=("x",),
        shared_following=("y", "z"),
        followers_jaccard=0.1,
        following_jaccard=0.2,
        combined_score=0.15,
    )
    d = ov.to_dict()
    assert d["platform"] == "github"
    assert d["shared_followers"] == ["x"]
    assert d["shared_following"] == ["y", "z"]
    assert d["followers_jaccard"] == 0.1
    assert d["combined_score"] == 0.15


@pytest.mark.asyncio
async def test_fetch_github_neighbors_mocked(monkeypatch) -> None:
    from core import social_graph

    async def fake_get_json(self, url, headers=None):
        # Minimal router: followers page 1, followers page 2, following page 1.
        if "/followers" in url:
            if "page=1" in url:
                return 200, [{"login": "bob"}, {"login": "carol"}], 0.01
            return 200, [], 0.01
        if "/following" in url:
            if "page=1" in url:
                return 200, [{"login": "eve"}], 0.01
            return 200, [], 0.01
        return 404, None, 0.01

    class StubClient:
        get_json = fake_get_json

    n = await social_graph.fetch_github_neighbors(StubClient(), "alice")
    assert n.platform == "github"
    assert n.username == "alice"
    assert n.followers == frozenset({"bob", "carol"})
    assert n.following == frozenset({"eve"})


@pytest.mark.asyncio
async def test_fetch_github_neighbors_404_returns_empty(monkeypatch) -> None:
    from core import social_graph

    async def fake_get_json(self, url, headers=None):
        return 404, None, 0.01

    class StubClient:
        get_json = fake_get_json

    n = await social_graph.fetch_github_neighbors(StubClient(), "ghost")
    assert n.followers == frozenset()
    assert n.following == frozenset()


@pytest.mark.asyncio
async def test_fetch_github_neighbors_caps_pagination(monkeypatch) -> None:
    from core import social_graph

    calls: list[str] = []

    async def fake_get_json(self, url, headers=None):
        calls.append(url)
        # Always return a full page of 100 so pagination would run forever
        # if the cap isn't honoured.
        return 200, [{"login": f"u{i}"} for i in range(100)], 0.01

    class StubClient:
        get_json = fake_get_json

    await social_graph.fetch_github_neighbors(StubClient(), "prolific", max_pages=3)
    # 3 pages followers + 3 pages following = 6 requests max.
    assert len(calls) == 6

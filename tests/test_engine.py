"""Tests for core/engine.py — exercise pure helpers and integration phases."""


import pytest
from aioresponses import aioresponses

from core import engine as engine_mod
from core.config import ScanConfig
from core.engine import (
    _extract_avatar_urls,
    _phase_recursive,
    _select_platforms,
    _status_from_http,
    run_scan,
)
from core.models import PlatformResult, ScanResult
from modules.platforms import PLATFORMS, Platform


class TestStatusFromHttp:
    def test_timeout(self):
        assert _status_from_http(0, False) == "timeout"

    def test_error(self):
        assert _status_from_http(-1, False) == "error"

    def test_blocked(self):
        assert _status_from_http(429, False) == "blocked"

    def test_found(self):
        assert _status_from_http(200, True) == "found"

    def test_not_found(self):
        assert _status_from_http(200, False) == "not_found"


class TestSelectPlatforms:
    def test_all_when_none(self):
        assert len(_select_platforms(None)) == len(PLATFORMS)

    def test_filter_by_category(self):
        result = _select_platforms(("dev",))
        assert all(p.category == "dev" for p in result)
        assert len(result) > 0

    def test_multiple_categories(self):
        result = _select_platforms(("dev", "gaming"))
        cats = {p.category for p in result}
        assert cats == {"dev", "gaming"}


class TestExtractAvatarUrls:
    def test_empty(self):
        assert _extract_avatar_urls([]) == []

    def test_finds_avatar_url(self):
        p = PlatformResult(
            platform="gh",
            url="https://x",
            category="dev",
            exists=True,
            profile_data={"avatar_url": "https://cdn/a.jpg"},
        )
        result = _extract_avatar_urls([p])
        assert result == [("gh", "https://cdn/a.jpg")]

    def test_icon_img_fallback(self):
        p = PlatformResult(
            platform="reddit",
            url="https://x",
            category="social",
            exists=True,
            profile_data={"icon_img": "https://cdn/i.jpg"},
        )
        result = _extract_avatar_urls([p])
        assert result == [("reddit", "https://cdn/i.jpg")]

    def test_skips_non_http(self):
        p = PlatformResult(
            platform="gh",
            url="https://x",
            category="dev",
            exists=True,
            profile_data={"avatar_url": "not-a-url"},
        )
        assert _extract_avatar_urls([p]) == []

    def test_no_profile_data(self):
        p = PlatformResult(platform="gh", url="https://x", category="dev")
        assert _extract_avatar_urls([p]) == []


@pytest.mark.asyncio
async def test_run_scan_minimal_category_filter():
    """Run a restricted scan to keep mocking manageable."""
    cfg = ScanConfig(
        username="alice",
        deep=False,
        smart=False,
        email=False,
        web=False,
        whois=False,
        breach=False,
        photo=False,
        dns=False,
        subdomain=False,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            m.get(url, status=404, repeat=True)

        result = await run_scan(cfg)

    assert result.username == "alice"
    assert result.found_count == 0
    assert result.total_checked == len(dev_platforms)
    assert result.scan_time >= 0


@pytest.mark.asyncio
async def test_run_scan_with_deep_scrape():
    cfg = ScanConfig(
        username="alice",
        deep=True,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        # Register the deep-scraper API mock FIRST so it takes priority over
        # any platform check that happens to hit the same URL (e.g. the WMN
        # "GitHub (User)" entry which targets api.github.com/users/{u}).
        m.get(
            "https://api.github.com/users/alice",
            status=200,
            payload={"name": "Alice", "location": "TR"},
            repeat=True,
        )
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            if url == "https://api.github.com/users/alice":
                continue  # already mocked above
            if p.name == "GitHub":
                m.get(url, status=200, body="", repeat=True)
            else:
                m.get(url, status=404, repeat=True)

        result = await run_scan(cfg)

    gh_result = next((r for r in result.platforms if r.platform == "GitHub"), None)
    assert gh_result is not None
    assert gh_result.exists is True
    assert gh_result.profile_data.get("name") == "Alice"


@pytest.mark.asyncio
async def test_run_scan_email_without_hibp_skips_breach(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    cfg = ScanConfig(
        username="alice",
        deep=False,
        email=True,
        breach=True,
        categories=("dev",),
    )
    dev_platforms = [p for p in PLATFORMS if p.category == "dev"]

    with aioresponses() as m:
        for p in dev_platforms:
            url = p.url.replace("{username}", "alice")
            m.get(url, status=404, repeat=True)
        # email discovery will call gravatar for every candidate
        import re as _re
        m.get(_re.compile(r"https://en\.gravatar\.com/.*\.json"), status=404, repeat=True)

        result = await run_scan(cfg)

    assert result.emails == []


@pytest.mark.asyncio
async def test_phase_recursive_pivots_on_discovered_username(monkeypatch):
    """The recursive phase should pick up usernames from profile_data and
    discovered_usernames, re-run the platform sweep, and tag hits with the
    pivoted handle so they stay distinguishable from the primary sweep."""
    cfg = ScanConfig(username="alice", recursive=True, recursive_depth=1, fp_threshold=0.0)
    platforms = [
        Platform(name="FakeNet", url="https://fake.test/{username}", category="social",
                 check_type="status"),
    ]
    seed = PlatformResult(
        platform="GitHub", url="https://gh/alice", category="dev",
        exists=True, profile_data={"login": "alice_alt"},
    )
    result = ScanResult(username="alice")
    result.platforms = [seed]
    result.discovered_usernames = ["alice_other"]

    calls: list[str] = []

    async def fake_check_platform(client, username, platform):
        calls.append(username)
        return PlatformResult(
            platform=platform.name,
            url=platform.url.replace("{username}", username),
            category=platform.category,
            exists=True,
            confidence=1.0,
            status="found",
        )

    monkeypatch.setattr(engine_mod, "_check_platform", fake_check_platform)

    await _phase_recursive(client=None, cfg=cfg, platforms=platforms, result=result)

    assert set(calls) == {"alice_alt", "alice_other"}
    pivot_hits = [r for r in result.platforms if r.status.startswith("found (pivot:")]
    assert len(pivot_hits) == 2
    assert {r.status for r in pivot_hits} == {
        "found (pivot:alice_alt)",
        "found (pivot:alice_other)",
    }


@pytest.mark.asyncio
async def test_phase_recursive_disabled_is_noop(monkeypatch):
    cfg = ScanConfig(username="alice", recursive=False)
    result = ScanResult(username="alice")
    result.discovered_usernames = ["bob"]

    called = False

    async def boom(*args, **kwargs):
        nonlocal called
        called = True
        return PlatformResult(platform="x", url="y", category="z")

    monkeypatch.setattr(engine_mod, "_check_platform", boom)
    await _phase_recursive(client=None, cfg=cfg, platforms=[], result=result)

    assert called is False

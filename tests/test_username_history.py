"""Tests for the Sprint 3 historical username discovery module."""

from __future__ import annotations

import json
import re

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.history.models import HistoricalUsername
from modules.history.username_history import (
    _first_segment,
    _parse_profile,
    discover_historical_usernames,
)


def test_historical_username_to_dict_roundtrip() -> None:
    h = HistoricalUsername(
        username="oldhandle",
        platform="twitter.com",
        first_seen="20180101000000",
        last_seen="20200101000000",
        snapshot_count=5,
        sample_snapshot="https://web.archive.org/web/20180101000000/https://twitter.com/oldhandle",
        metadata={"source_profile": "https://twitter.com/newhandle"},
    )
    d = h.to_dict()
    assert d["username"] == "oldhandle"
    assert d["snapshot_count"] == 5
    assert d["metadata"]["source_profile"].endswith("newhandle")


def test_parse_profile_extracts_host_and_handle() -> None:
    assert _parse_profile("https://www.twitter.com/alice") == ("twitter.com", "alice")
    assert _parse_profile("https://github.com/alice/repo") == ("github.com", "alice")
    assert _parse_profile("https://example.com/") is None
    assert _parse_profile("not a url") is None


def test_first_segment_rejects_deny_list_and_files() -> None:
    assert _first_segment("https://twitter.com/alice") == "alice"
    assert _first_segment("https://twitter.com/login") is None
    assert _first_segment("https://twitter.com/search?q=x") is None
    assert _first_segment("https://twitter.com/robots.txt") is None
    assert _first_segment("https://twitter.com/") is None


@pytest.mark.asyncio
async def test_discover_historical_usernames_aggregates_handles() -> None:
    cdx_payload = [
        ["timestamp", "original"],
        ["20180101000000", "https://twitter.com/oldhandle"],
        ["20180601000000", "https://twitter.com/oldhandle"],
        ["20190101000000", "https://twitter.com/oldhandle/status/123"],
        ["20200101000000", "https://twitter.com/newhandle"],
        ["20200201000000", "https://twitter.com/login"],
        ["20200301000000", "https://twitter.com/rarehandle"],
    ]
    with aioresponses() as m:
        m.get(
            re.compile(r"https://web\.archive\.org/cdx/search/cdx.*"),
            status=200,
            body=json.dumps(cdx_payload),
            headers={"Content-Type": "application/json"},
        )
        async with HTTPClient() as client:
            hits = await discover_historical_usernames(
                client,
                profile_urls=["https://twitter.com/newhandle"],
                current_username="newhandle",
            )

    handles = {h.username for h in hits}
    assert "oldhandle" in handles
    assert "newhandle" not in handles
    assert "login" not in handles
    assert "rarehandle" not in handles
    old = [h for h in hits if h.username == "oldhandle"][0]
    assert old.platform == "twitter.com"
    assert old.snapshot_count == 3
    assert old.first_seen == "20180101000000"
    assert old.last_seen == "20190101000000"
    assert old.sample_snapshot.startswith("https://web.archive.org/web/")


@pytest.mark.asyncio
async def test_discover_historical_usernames_handles_empty_cdx() -> None:
    with aioresponses() as m:
        m.get(
            re.compile(r"https://web\.archive\.org/cdx/search/cdx.*"),
            status=200,
            body=json.dumps([]),
            headers={"Content-Type": "application/json"},
        )
        async with HTTPClient() as client:
            hits = await discover_historical_usernames(
                client,
                profile_urls=["https://twitter.com/alice"],
                current_username="alice",
            )
    assert hits == []


@pytest.mark.asyncio
async def test_discover_historical_usernames_dedupes_hosts() -> None:
    cdx_payload = [
        ["timestamp", "original"],
        ["20200101000000", "https://twitter.com/bob"],
        ["20200201000000", "https://twitter.com/bob"],
    ]
    with aioresponses() as m:
        m.get(
            re.compile(r"https://web\.archive\.org/cdx/search/cdx.*"),
            status=200,
            body=json.dumps(cdx_payload),
            headers={"Content-Type": "application/json"},
        )
        async with HTTPClient() as client:
            hits = await discover_historical_usernames(
                client,
                profile_urls=[
                    "https://twitter.com/alice",
                    "https://twitter.com/charlie",
                ],
                current_username="alice",
            )
    assert any(h.username == "bob" for h in hits)

"""Tests for modules/email_discovery.py."""

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.email_discovery import (
    COMMON_DOMAINS,
    check_gravatar,
    discover_emails,
    generate_email_candidates,
)
from utils.helpers import md5_hash


def test_generate_email_candidates():
    result = generate_email_candidates("Alice")
    assert "alice@gmail.com" in result
    assert len(result) == len(COMMON_DOMAINS)


def test_generate_email_candidates_strips_spaces():
    result = generate_email_candidates("john doe")
    assert "johndoe@gmail.com" in result


@pytest.mark.asyncio
async def test_gravatar_none():
    with aioresponses() as m:
        h = md5_hash("nobody@nowhere.com")
        m.get(f"https://en.gravatar.com/{h}.json", status=404)
        async with HTTPClient() as client:
            result = await check_gravatar(client, "nobody@nowhere.com")
    assert result is None


@pytest.mark.asyncio
async def test_gravatar_success():
    payload = {
        "entry": [
            {
                "displayName": "Alice",
                "name": {"formatted": "Alice A."},
                "currentLocation": "Istanbul",
                "aboutMe": "hi",
                "urls": [{"value": "https://me.dev"}],
                "photos": [{"value": "https://g.com/p.jpg"}],
                "accounts": [{"shortname": "twitter", "url": "https://t/alice"}],
            }
        ]
    }
    with aioresponses() as m:
        h = md5_hash("a@b.com")
        m.get(f"https://en.gravatar.com/{h}.json", status=200, payload=payload)
        async with HTTPClient() as client:
            result = await check_gravatar(client, "a@b.com")
    assert result is not None
    assert result["display_name"] == "Alice"
    assert result["location"] == "Istanbul"
    assert "https://me.dev" in result["urls"]


@pytest.mark.asyncio
async def test_discover_emails_merges_known():
    with aioresponses() as m:
        # All gravatar lookups 404 — no match
        for domain in COMMON_DOMAINS:
            h = md5_hash(f"alice@{domain}")
            m.get(f"https://en.gravatar.com/{h}.json", status=404)
        m.get(
            f"https://en.gravatar.com/{md5_hash('known@x.com')}.json",
            status=404,
        )
        async with HTTPClient() as client:
            results = await discover_emails(
                client, "alice", known_emails=["known@x.com"]
            )
    assert results == []

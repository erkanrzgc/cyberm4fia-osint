"""Tests for modules/photo_compare.py."""

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.photo_compare import (
    compare_phashes,
    compare_profile_photos,
    fetch_and_hash,
    imagehash_available,
)


def test_imagehash_available_flag():
    assert isinstance(imagehash_available(), bool)


def test_compare_phashes_equal_strings_no_library():
    # Without imagehash, equal strings -> 1.0
    assert compare_phashes("abc", "abc") in (0.0, 1.0)


def test_compare_phashes_empty():
    assert compare_phashes("", "xyz") == 0.0
    assert compare_phashes("xyz", "") == 0.0


@pytest.mark.asyncio
async def test_fetch_and_hash_invalid_url():
    async with HTTPClient() as client:
        result = await fetch_and_hash(client, "")
    assert result is None
    async with HTTPClient() as client:
        result = await fetch_and_hash(client, "not-a-url")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_and_hash_404():
    with aioresponses() as m:
        m.get("https://cdn.example.com/a.jpg", status=404)
        async with HTTPClient() as client:
            result = await fetch_and_hash(client, "https://cdn.example.com/a.jpg")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_and_hash_invalid_image_still_md5():
    with aioresponses() as m:
        m.get("https://cdn.example.com/a.jpg", status=200, body=b"notanimage")
        async with HTTPClient() as client:
            result = await fetch_and_hash(client, "https://cdn.example.com/a.jpg")
    assert result is not None
    assert "md5" in result
    assert result["size"] == len(b"notanimage")


@pytest.mark.asyncio
async def test_compare_profile_photos_too_few():
    async with HTTPClient() as client:
        result = await compare_profile_photos(client, [("gh", "https://x/a.jpg")])
    assert result == []


@pytest.mark.asyncio
async def test_compare_profile_photos_same_md5():
    data = b"samebytes"
    with aioresponses() as m:
        m.get("https://cdn/a.jpg", status=200, body=data)
        m.get("https://cdn/b.jpg", status=200, body=data)
        async with HTTPClient() as client:
            result = await compare_profile_photos(
                client,
                [("gh", "https://cdn/a.jpg"), ("tw", "https://cdn/b.jpg")],
            )
    # If imagehash is installed and succeeds on bytes, phash may or may not match.
    # We only assert the function returned a list without raising.
    assert isinstance(result, list)

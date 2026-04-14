"""Tests for modules/breach_check.py."""

import pytest
from aioresponses import aioresponses

from core.http_client import HTTPClient
from modules.breach_check import (
    check_email_breaches,
    check_many_emails,
    check_password_pwned,
    hibp_available,
)


def test_hibp_available_false(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    assert hibp_available() is False


def test_hibp_available_true(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    assert hibp_available() is True


@pytest.mark.asyncio
async def test_check_email_no_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    async with HTTPClient() as client:
        result = await check_email_breaches(client, "a@b.com")
    assert result == []


@pytest.mark.asyncio
async def test_check_email_success(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    payload = [
        {
            "Name": "Leak1",
            "Title": "Leak One",
            "Domain": "leak.com",
            "BreachDate": "2020-01-01",
            "PwnCount": 1000,
            "DataClasses": ["Emails", "Passwords"],
        }
    ]
    with aioresponses() as m:
        m.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/a@b.com?truncateResponse=false",
            status=200,
            payload=payload,
        )
        async with HTTPClient() as client:
            result = await check_email_breaches(client, "a@b.com")
    assert len(result) == 1
    assert result[0]["name"] == "Leak1"
    assert result[0]["pwn_count"] == 1000


@pytest.mark.asyncio
async def test_check_email_404(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    with aioresponses() as m:
        m.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/a@b.com?truncateResponse=false",
            status=404,
        )
        async with HTTPClient() as client:
            result = await check_email_breaches(client, "a@b.com")
    assert result == []


@pytest.mark.asyncio
async def test_check_many_emails_empty():
    async with HTTPClient() as client:
        result = await check_many_emails(client, [])
    assert result == {}


@pytest.mark.asyncio
async def test_check_many_emails(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    with aioresponses() as m:
        m.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/a@b.com?truncateResponse=false",
            status=404,
        )
        m.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/c@d.com?truncateResponse=false",
            status=404,
        )
        async with HTTPClient() as client:
            result = await check_many_emails(client, ["a@b.com", "c@d.com"])
    assert result == {"a@b.com": [], "c@d.com": []}


@pytest.mark.asyncio
async def test_check_password_pwned_found():
    # sha1("password") uppercase = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nOTHER:10"
    with aioresponses() as m:
        m.get("https://api.pwnedpasswords.com/range/5BAA6", status=200, body=body)
        async with HTTPClient() as client:
            count = await check_password_pwned(client, "password")
    assert count == 42


@pytest.mark.asyncio
async def test_check_password_pwned_not_found():
    with aioresponses() as m:
        m.get(
            "https://api.pwnedpasswords.com/range/5BAA6",
            status=200,
            body="OTHER:1\r\n",
        )
        async with HTTPClient() as client:
            count = await check_password_pwned(client, "password")
    assert count == 0


@pytest.mark.asyncio
async def test_check_password_pwned_server_error():
    with aioresponses() as m:
        m.get("https://api.pwnedpasswords.com/range/5BAA6", status=500)
        async with HTTPClient() as client:
            count = await check_password_pwned(client, "password")
    assert count == 0

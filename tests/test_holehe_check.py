"""Tests for modules.holehe_check.

We do not invoke the real holehe modules (network-bound, slow, flaky).
Instead we monkeypatch the internal _FUNCS list with stubs that simulate
the upstream contract.
"""

from __future__ import annotations

import pytest

from modules import holehe_check
from modules.holehe_check import HoleheHit, check_email, check_emails


@pytest.mark.asyncio
async def test_check_email_skips_when_unavailable(monkeypatch):
    monkeypatch.setattr(holehe_check, "_AVAILABLE", False)
    assert await check_email("a@b.com") == []


@pytest.mark.asyncio
async def test_check_email_skips_invalid_address(monkeypatch):
    monkeypatch.setattr(holehe_check, "_AVAILABLE", True)
    assert await check_email("not-an-email") == []
    assert await check_email("") == []


@pytest.mark.asyncio
async def test_check_email_filters_non_existing(monkeypatch):
    async def stub_a(email, client, out):
        out.append({"name": "alpha", "domain": "alpha.com", "exists": True, "method": "register"})

    async def stub_b(email, client, out):
        out.append({"name": "beta", "domain": "beta.com", "exists": False})

    async def stub_c(email, client, out):
        out.append({"name": "gamma", "domain": "gamma.com", "exists": True, "emailrecovery": "g***@x.com"})

    class _DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class _DummyHttpx:
        AsyncClient = staticmethod(lambda **kw: _DummyClient())

    monkeypatch.setattr(holehe_check, "_AVAILABLE", True)
    monkeypatch.setattr(holehe_check, "_FUNCS", [stub_a, stub_b, stub_c])
    monkeypatch.setattr(holehe_check, "httpx", _DummyHttpx)

    hits = await check_email("victim@example.com")
    sites = {h.site for h in hits}
    assert sites == {"alpha", "gamma"}
    gamma = next(h for h in hits if h.site == "gamma")
    assert gamma.email_recovery == "g***@x.com"


@pytest.mark.asyncio
async def test_check_email_swallows_module_exceptions(monkeypatch):
    async def stub_ok(email, client, out):
        out.append({"name": "ok", "domain": "ok.com", "exists": True})

    async def stub_boom(email, client, out):
        raise RuntimeError("upstream broke")

    class _DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(holehe_check, "_AVAILABLE", True)
    monkeypatch.setattr(holehe_check, "_FUNCS", [stub_ok, stub_boom])
    monkeypatch.setattr(
        holehe_check, "httpx", type("X", (), {"AsyncClient": staticmethod(lambda **kw: _DummyClient())})
    )

    hits = await check_email("a@b.com")
    assert len(hits) == 1
    assert hits[0].site == "ok"


@pytest.mark.asyncio
async def test_check_emails_groups_results(monkeypatch):
    async def stub(email, client, out):
        out.append({"name": "x", "domain": "x.com", "exists": True})

    class _DummyClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(holehe_check, "_AVAILABLE", True)
    monkeypatch.setattr(holehe_check, "_FUNCS", [stub])
    monkeypatch.setattr(
        holehe_check, "httpx", type("X", (), {"AsyncClient": staticmethod(lambda **kw: _DummyClient())})
    )

    out = await check_emails(["a@b.com", "c@d.com", "invalid"])
    assert set(out.keys()) == {"a@b.com", "c@d.com"}
    assert all(len(v) == 1 for v in out.values())


def test_holehe_hit_is_frozen():
    hit = HoleheHit(email="a@b.com", site="x", domain="x.com")
    with pytest.raises(Exception):
        hit.site = "y"  # type: ignore[misc]

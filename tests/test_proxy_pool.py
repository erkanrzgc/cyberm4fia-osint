"""ProxyPool rotation + health tracking tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import ScanConfig, _collect_proxy_pool
from core.proxy_pool import ProxyPool, load_from_file


def test_empty_pool_returns_none() -> None:
    pool = ProxyPool()
    assert pool.next() is None
    assert not pool


def test_single_proxy_cycles() -> None:
    pool = ProxyPool(proxies=("http://a:1",))
    assert pool.next() == "http://a:1"
    assert pool.next() == "http://a:1"


def test_round_robin_order() -> None:
    pool = ProxyPool(proxies=("http://a", "http://b", "http://c"))
    got = [pool.next() for _ in range(6)]
    assert got == [
        "http://a", "http://b", "http://c",
        "http://a", "http://b", "http://c",
    ]


def test_dead_proxy_is_skipped_after_threshold() -> None:
    pool = ProxyPool(
        proxies=("http://a", "http://b"),
        max_consecutive_failures=2,
    )
    # Burn a: two failures -> dead
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    # Now rotation should only yield b
    got = {pool.next() for _ in range(10)}
    assert got == {"http://b"}
    assert "http://a" not in pool.alive


def test_success_resets_failure_count() -> None:
    pool = ProxyPool(
        proxies=("http://a",), max_consecutive_failures=3,
    )
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    pool.record_success("http://a")
    # Two more failures should NOT kill it (counter was reset).
    pool.record_failure("http://a")
    pool.record_failure("http://a")
    assert "http://a" in pool.alive


def test_all_dead_pool_resurrects() -> None:
    pool = ProxyPool(
        proxies=("http://a", "http://b"),
        max_consecutive_failures=1,
    )
    pool.record_failure("http://a")
    pool.record_failure("http://b")
    assert pool.alive == ()
    # next() must not return None — it resurrects.
    nxt = pool.next()
    assert nxt in {"http://a", "http://b"}


def test_record_ignores_unknown_proxy() -> None:
    pool = ProxyPool(proxies=("http://a",))
    pool.record_failure(None)
    pool.record_failure("")
    pool.record_success(None)
    assert pool.next() == "http://a"


# ── load_from_file ─────────────────────────────────────────────────


def test_load_from_file_skips_blanks_and_comments(tmp_path: Path) -> None:
    f = tmp_path / "pool.txt"
    f.write_text(
        "\n"
        "# a comment\n"
        "http://one:8080\n"
        "  http://two:8080  \n"
        "\n"
        "# trailing\n"
        "socks5://tor:9050\n"
    )
    assert load_from_file(str(f)) == (
        "http://one:8080",
        "http://two:8080",
        "socks5://tor:9050",
    )


# ── config glue ────────────────────────────────────────────────────


def _ns(**overrides) -> SimpleNamespace:
    base = dict(
        quick=True, no_deep=True, deep=False, smart=False, email=False,
        web=False, whois=False, breach=False, photo=False, dns=False,
        subdomain=False, holehe=False, ghunt=False, toutatis=False,
        recursive=False, recursive_depth=1, passive=False, domain=None,
        reverse_image=False, past_usernames=False, phone=None,
        phone_region=None, crypto=None, full=False, category=None,
        proxy=None, proxy_pool=None, proxy_file=None, tor=False, timeout=None,
        fp_threshold=None, no_fingerprint=False, new_circuit_every=0,
        tor_control_password=None, playwright=False, screenshots=False,
        screenshot_dir=None, geocode=False, no_enrichment=True,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_collect_proxy_pool_merges_sources(tmp_path: Path) -> None:
    f = tmp_path / "p.txt"
    f.write_text("http://file1\nhttp://file2\n")
    args = _ns(
        proxy="http://single",
        proxy_pool="http://pool1, http://pool2",
        proxy_file=str(f),
    )
    assert _collect_proxy_pool(args) == (
        "http://pool1",
        "http://pool2",
        "http://file1",
        "http://file2",
        "http://single",
    )


def test_collect_proxy_pool_dedupes() -> None:
    args = _ns(proxy="http://same", proxy_pool="http://same, http://other")
    assert _collect_proxy_pool(args) == ("http://same", "http://other")


def test_scan_config_carries_pool_through_from_args() -> None:
    args = _ns(proxy_pool="http://a,http://b")
    cfg = ScanConfig.from_args(args, username="x")
    assert cfg.proxies == ("http://a", "http://b")


# ── HTTPClient integration ─────────────────────────────────────────


def test_http_client_builds_pool_for_http_proxies() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(proxies=["http://a", "http://b"])
    assert client._pool is not None
    assert client._next_http_proxy() in {"http://a", "http://b"}


def test_http_client_no_pool_when_only_socks() -> None:
    from core.http_client import HTTPClient

    client = HTTPClient(proxies=["socks5://tor:9050"])
    # SOCKS must bypass the HTTP pool (they bind at connector level).
    assert client._pool is None
    assert client._next_http_proxy() is None

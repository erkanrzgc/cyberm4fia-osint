"""Bulk scan orchestration tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from core import bulk
from core.config import ScanConfig
from core.models import ScanResult


def test_load_usernames_from_file_strips_comments(tmp_path: Path) -> None:
    p = tmp_path / "list.txt"
    p.write_text(
        "alice\n"
        "# comment\n"
        "bob  # inline\n"
        "\n"
        "alice\n"  # duplicate
        "carol\n",
        encoding="utf-8",
    )
    assert bulk.load_usernames_from_file(p) == ["alice", "bob", "carol"]


@pytest.mark.asyncio
async def test_run_bulk_respects_concurrency_cap(monkeypatch) -> None:
    calls: list[str] = []
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def fake_run_scan(cfg: ScanConfig) -> ScanResult:
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        try:
            await asyncio.sleep(0.01)
            calls.append(cfg.username)
            return ScanResult(username=cfg.username)
        finally:
            async with lock:
                in_flight -= 1

    monkeypatch.setattr(bulk, "run_scan", fake_run_scan)

    cfg = ScanConfig(username="template")
    results = await bulk.run_bulk(
        ["a", "b", "c", "d", "e"], cfg, max_parallel=2
    )

    assert [r.username for r in results] == ["a", "b", "c", "d", "e"]
    assert set(calls) == {"a", "b", "c", "d", "e"}
    assert peak <= 2


@pytest.mark.asyncio
async def test_run_bulk_swallows_per_target_errors(monkeypatch) -> None:
    async def fake_run_scan(cfg: ScanConfig) -> ScanResult:
        if cfg.username == "bad":
            raise RuntimeError("boom")
        return ScanResult(username=cfg.username)

    monkeypatch.setattr(bulk, "run_scan", fake_run_scan)

    results = await bulk.run_bulk(
        ["good", "bad", "other"], ScanConfig(username="x"), max_parallel=3
    )
    names = [r.username for r in results]
    assert names == ["good", "bad", "other"]
    # The failed one still returns an (empty) ScanResult.
    bad = next(r for r in results if r.username == "bad")
    assert bad.platforms == []


@pytest.mark.asyncio
async def test_run_bulk_empty_list_returns_empty() -> None:
    results = await bulk.run_bulk([], ScanConfig(username="x"))
    assert results == []

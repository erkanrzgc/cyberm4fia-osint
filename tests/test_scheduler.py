"""Tests for the scheduled-scan loop."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import history, watchlist
from core.config import ScanConfig
from core.models import PlatformResult, ScanResult
from core.notify.base import Notification
from core.scheduler import _format_diff_body, run_once


class _CapturingNotifier:
    name = "capture"

    def __init__(self) -> None:
        self.calls: list[Notification] = []

    async def send(self, notification: Notification) -> bool:
        self.calls.append(notification)
        return True


@pytest.fixture
def isolated_dbs(tmp_path: Path, monkeypatch):
    wl_db = tmp_path / "watch.sqlite3"
    hist_db = tmp_path / "history.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    monkeypatch.setattr(history, "DEFAULT_DB_PATH", hist_db)
    # Rebind module-level function defaults (reverted by monkeypatch teardown)
    # so callers that rely on the default argument also see the tmp DBs.
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)
    for fn in (history.save_scan, history.list_scans, history.get_latest):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", hist_db)
    return tmp_path


def _fake_runner_factory(platforms_per_username: dict[str, list[str]]):
    async def runner(cfg: ScanConfig) -> ScanResult:
        r = ScanResult(username=cfg.username)
        for name in platforms_per_username.get(cfg.username, []):
            r.platforms.append(
                PlatformResult(
                    platform=name,
                    url=f"https://{name.lower()}.test/{cfg.username}",
                    category="dev",
                    exists=True,
                    status="found",
                )
            )
        return r

    return runner


def test_format_diff_body_covers_both_sides():
    assert "New: GitHub" in _format_diff_body(["GitHub"], [])
    assert "Lost: GitLab" in _format_diff_body([], ["GitLab"])
    body = _format_diff_body(["A"], ["B"])
    assert "New: A" in body and "Lost: B" in body
    assert _format_diff_body([], []) == "No changes"


@pytest.mark.asyncio
async def test_run_once_empty_watchlist_is_noop(isolated_dbs):
    cap = _CapturingNotifier()
    runner = _fake_runner_factory({})
    stats = await run_once(
        ScanConfig(username=""), notifiers=[cap], runner=runner
    )
    assert stats.scans == 0
    assert cap.calls == []


@pytest.mark.asyncio
async def test_run_once_sends_scan_complete_per_user(isolated_dbs):
    watchlist.add("alice")
    watchlist.add("bob")
    cap = _CapturingNotifier()
    runner = _fake_runner_factory({"alice": ["GitHub"], "bob": []})

    stats = await run_once(
        ScanConfig(username=""), notifiers=[cap], runner=runner
    )

    assert stats.scans == 2
    kinds = [n.kind for n in cap.calls]
    assert kinds.count("scan_complete") == 2


@pytest.mark.asyncio
async def test_run_once_fires_diff_when_platforms_change(isolated_dbs):
    watchlist.add("alice")
    cap = _CapturingNotifier()

    first = _fake_runner_factory({"alice": ["GitHub"]})
    await run_once(ScanConfig(username=""), notifiers=[cap], runner=first)

    cap.calls.clear()
    second = _fake_runner_factory({"alice": ["GitHub", "Reddit"]})
    stats = await run_once(ScanConfig(username=""), notifiers=[cap], runner=second)

    assert stats.diffs == 1
    diffs = [n for n in cap.calls if n.kind == "scan_diff"]
    assert len(diffs) == 1
    assert diffs[0].data == {"added": ["Reddit"], "removed": []}


@pytest.mark.asyncio
async def test_run_once_reports_error_on_scan_failure(isolated_dbs):
    watchlist.add("alice")
    cap = _CapturingNotifier()

    async def broken(cfg):
        raise RuntimeError("boom")

    stats = await run_once(
        ScanConfig(username=""), notifiers=[cap], runner=broken
    )
    # Scan did not produce a result, so scans count stays 0.
    assert stats.scans == 0
    kinds = [n.kind for n in cap.calls]
    assert "scan_error" in kinds


@pytest.mark.asyncio
async def test_run_once_marks_watchlist_scanned(isolated_dbs):
    watchlist.add("alice")
    cap = _CapturingNotifier()
    runner = _fake_runner_factory({"alice": []})

    await run_once(ScanConfig(username=""), notifiers=[cap], runner=runner)

    entry = watchlist.get("alice")
    assert entry is not None
    assert entry.last_scan_at is not None and entry.last_scan_at > 0

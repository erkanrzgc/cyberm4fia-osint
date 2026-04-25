"""Scheduled scan loop.

Iterates over every watchlist entry, runs a scan for each, compares the
fresh result with the previous one, and fires notifications for diffs.
Runs forever (until the task is cancelled) with a configurable sleep
between passes.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace

from core import history, watchlist
from core.config import ScanConfig
from core.engine import run_scan
from core.history import diff_entries
from core.logging_setup import get_logger
from core.models import ScanResult
from core.notify import Notification, build_default_notifiers, notify_all
from core.notify.base import Notifier
from core.scan_service import complete_scan_result

log = get_logger(__name__)

ScanRunner = Callable[[ScanConfig], Awaitable[ScanResult]]


@dataclass(frozen=True)
class SchedulerStats:
    passes: int = 0
    scans: int = 0
    diffs: int = 0
    errors: int = 0


def _format_diff_body(added: list[str], removed: list[str]) -> str:
    lines = []
    if added:
        lines.append("New: " + ", ".join(added))
    if removed:
        lines.append("Lost: " + ", ".join(removed))
    return "\n".join(lines) if lines else "No changes"


async def _scan_one(
    username: str,
    cfg_template: ScanConfig,
    notifiers: list[Notifier],
    *,
    runner: ScanRunner,
) -> tuple[int, bool]:
    """Run one scan, save it, fire notifications. Returns (scans, diffs)."""
    cfg = replace(cfg_template, username=username)
    try:
        result = await runner(cfg)
    except Exception as exc:
        log.warning("scheduler: scan failed for %s: %s", username, exc)
        await notify_all(
            Notification(
                kind="scan_error",
                username=username,
                title=f"Scan failed for {username}",
                body=str(exc),
            ),
            notifiers,
        )
        return 0, False

    now = int(time.time())

    hist_db = history.DEFAULT_DB_PATH
    wl_db = watchlist.DEFAULT_DB_PATH

    previous = history.get_latest(username, db_path=hist_db)
    try:
        completed = complete_scan_result(
            result,
            cfg,
            save_history=True,
            mark_watchlist=True,
            ts=now,
            history_db=hist_db,
            watchlist_db=wl_db,
        )
    except (OSError, ValueError) as exc:
        log.warning("scheduler: could not finalize scan for %s: %s", username, exc)
        scan_id = -1
    else:
        scan_id = completed.scan_id or -1

    found_count = sum(1 for p in result.platforms if p.exists)
    await notify_all(
        Notification(
            kind="scan_complete",
            username=username,
            title=f"Scan complete: {username}",
            body=f"{found_count} platforms matched",
            data={"scan_id": scan_id, "found_count": found_count},
        ),
        notifiers,
    )

    diffs_found = False
    if previous is not None:
        current = history.get_latest(username, db_path=hist_db)
        if current is not None:
            d = diff_entries(previous, current)
            if d.added or d.removed:
                diffs_found = True
                await notify_all(
                    Notification(
                        kind="scan_diff",
                        username=username,
                        title=f"Changes detected for {username}",
                        body=_format_diff_body(d.added, d.removed),
                        data={"added": d.added, "removed": d.removed},
                    ),
                    notifiers,
                )
    return 1, diffs_found


async def run_once(
    cfg_template: ScanConfig,
    *,
    notifiers: list[Notifier] | None = None,
    runner: ScanRunner = run_scan,
) -> SchedulerStats:
    """Scan every watchlist entry exactly once."""
    entries = watchlist.list_all(db_path=watchlist.DEFAULT_DB_PATH)
    if not entries:
        log.info("scheduler: watchlist is empty, nothing to do")
        return SchedulerStats(passes=1)

    sinks = notifiers if notifiers is not None else build_default_notifiers()
    scans = 0
    diffs = 0
    errors = 0
    for entry in entries:
        try:
            s, d = await _scan_one(entry.username, cfg_template, sinks, runner=runner)
            scans += s
            diffs += d
        except Exception as exc:
            errors += 1
            log.exception("scheduler: unhandled error for %s: %s", entry.username, exc)
    return SchedulerStats(passes=1, scans=scans, diffs=diffs, errors=errors)


async def run_forever(
    cfg_template: ScanConfig,
    *,
    interval_minutes: float = 60.0,
    notifiers: list[Notifier] | None = None,
    runner: ScanRunner = run_scan,
) -> None:
    """Loop forever: scan, sleep, scan, …"""
    interval_s = max(10.0, interval_minutes * 60)
    log.info(
        "scheduler: starting with interval=%.1f min (watchlist size=%d)",
        interval_minutes,
        len(watchlist.list_all(db_path=watchlist.DEFAULT_DB_PATH)),
    )
    while True:
        started = time.monotonic()
        stats = await run_once(cfg_template, notifiers=notifiers, runner=runner)
        log.info(
            "scheduler: pass done scans=%d diffs=%d errors=%d in %.1fs",
            stats.scans,
            stats.diffs,
            stats.errors,
            time.monotonic() - started,
        )
        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            log.info("scheduler: cancelled, stopping")
            raise

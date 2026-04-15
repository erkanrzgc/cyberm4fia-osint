"""SQLite watchlist CRUD tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.watchlist import (
    WatchEntry,
    add,
    get,
    list_all,
    mark_scanned,
    remove,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "watchlist.sqlite3"


def test_add_inserts_new_entry(db: Path) -> None:
    entry = add("alice", tags=["red"], notes="primary", db_path=db, ts=1000)
    assert isinstance(entry, WatchEntry)
    assert entry.username == "alice"
    assert entry.tags == ["red"]
    assert entry.notes == "primary"
    assert entry.added_at == 1000
    assert entry.last_scan_at is None


def test_add_is_idempotent_and_updates_tags(db: Path) -> None:
    add("alice", tags=["a"], notes="one", db_path=db, ts=100)
    updated = add("alice", tags=["b", "c"], notes="two", db_path=db, ts=200)
    rows = list_all(db_path=db)
    assert len(rows) == 1
    assert updated.tags == ["b", "c"]
    assert updated.notes == "two"
    # added_at is preserved on conflict (ON CONFLICT DO UPDATE keeps original).
    assert rows[0].added_at == 100


def test_add_rejects_empty_username(db: Path) -> None:
    with pytest.raises(ValueError):
        add("   ", db_path=db)


def test_remove_returns_true_when_deleted(db: Path) -> None:
    add("bob", db_path=db, ts=1)
    assert remove("bob", db_path=db) is True
    assert remove("bob", db_path=db) is False
    assert list_all(db_path=db) == []


def test_list_all_orders_by_added_at_desc(db: Path) -> None:
    add("first", db_path=db, ts=10)
    add("second", db_path=db, ts=30)
    add("third", db_path=db, ts=20)
    rows = list_all(db_path=db)
    assert [r.username for r in rows] == ["second", "third", "first"]


def test_mark_scanned_updates_timestamp(db: Path) -> None:
    add("alice", db_path=db, ts=1)
    mark_scanned("alice", db_path=db, ts=999)
    entry = get("alice", db_path=db)
    assert entry is not None
    assert entry.last_scan_at == 999


def test_get_returns_none_for_missing_user(db: Path) -> None:
    assert get("ghost", db_path=db) is None


def test_list_all_on_missing_db_returns_empty(tmp_path: Path) -> None:
    assert list_all(db_path=tmp_path / "nope.sqlite3") == []

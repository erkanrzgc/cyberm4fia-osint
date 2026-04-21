"""Investigation case manager tests — pure SQLite CRUD."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import cases


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "cases.sqlite3"


def test_create_case_assigns_id_and_timestamps(db: Path) -> None:
    c = cases.create_case("op-lighthouse", description="suspect X", db_path=db)
    assert c.id >= 1
    assert c.name == "op-lighthouse"
    assert c.description == "suspect X"
    assert c.status == "open"
    assert c.created_ts > 0
    assert c.updated_ts == c.created_ts


def test_create_case_rejects_empty_name(db: Path) -> None:
    with pytest.raises(ValueError):
        cases.create_case("   ", db_path=db)


def test_create_case_duplicate_name_raises(db: Path) -> None:
    cases.create_case("alpha", db_path=db)
    with pytest.raises(ValueError):
        cases.create_case("alpha", db_path=db)


def test_list_cases_returns_newest_first(db: Path) -> None:
    a = cases.create_case("a", db_path=db, ts=100)
    b = cases.create_case("b", db_path=db, ts=200)
    c = cases.create_case("c", db_path=db, ts=150)
    listed = cases.list_cases(db_path=db)
    assert [x.name for x in listed] == ["b", "c", "a"]
    # IDs preserved even across reordering.
    assert {x.id for x in listed} == {a.id, b.id, c.id}


def test_get_case_returns_none_when_missing(db: Path) -> None:
    assert cases.get_case(999, db_path=db) is None


def test_update_case_status(db: Path) -> None:
    c = cases.create_case("op", db_path=db, ts=10)
    updated = cases.update_case(
        c.id, status="closed", description="wrapped up", db_path=db, ts=50
    )
    assert updated.status == "closed"
    assert updated.description == "wrapped up"
    assert updated.updated_ts == 50
    # Unchanged fields preserved.
    assert updated.name == "op"
    assert updated.created_ts == 10


def test_update_case_rejects_unknown_status(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    with pytest.raises(ValueError):
        cases.update_case(c.id, status="pending", db_path=db)


def test_update_missing_case_returns_none(db: Path) -> None:
    assert cases.update_case(42, status="closed", db_path=db) is None


def test_delete_case_cascades_notes_and_bookmarks(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    cases.add_note(c.id, "suspect uses alias 'redline'", db_path=db)
    cases.add_bookmark(
        c.id, target_type="platform", target_value="GitHub/alice",
        label="primary handle", db_path=db,
    )
    assert cases.delete_case(c.id, db_path=db) is True
    # Follow-up operations must not resurrect rows.
    assert cases.list_notes(c.id, db_path=db) == []
    assert cases.list_bookmarks(c.id, db_path=db) == []


def test_delete_missing_case_returns_false(db: Path) -> None:
    assert cases.delete_case(99, db_path=db) is False


def test_add_note_requires_case(db: Path) -> None:
    with pytest.raises(ValueError):
        cases.add_note(404, "orphan", db_path=db)


def test_add_note_rejects_empty_body(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    with pytest.raises(ValueError):
        cases.add_note(c.id, "   ", db_path=db)


def test_list_notes_returns_newest_first(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    cases.add_note(c.id, "first", db_path=db, ts=100)
    cases.add_note(c.id, "second", db_path=db, ts=200)
    cases.add_note(c.id, "third", db_path=db, ts=150)
    bodies = [n.body for n in cases.list_notes(c.id, db_path=db)]
    assert bodies == ["second", "third", "first"]


def test_delete_note_removes_only_target(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    keep = cases.add_note(c.id, "keep", db_path=db)
    drop = cases.add_note(c.id, "drop", db_path=db)
    assert cases.delete_note(drop.id, db_path=db) is True
    remaining = cases.list_notes(c.id, db_path=db)
    assert [n.id for n in remaining] == [keep.id]


def test_add_bookmark_stores_metadata(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    bm = cases.add_bookmark(
        c.id,
        target_type="scan",
        target_value="42",
        label="pivot scan",
        tags=["pivot", "high-confidence"],
        scan_id=42,
        db_path=db,
    )
    assert bm.case_id == c.id
    assert bm.target_type == "scan"
    assert bm.target_value == "42"
    assert bm.label == "pivot scan"
    assert bm.tags == ["pivot", "high-confidence"]
    assert bm.scan_id == 42


def test_add_bookmark_rejects_unknown_target_type(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    with pytest.raises(ValueError):
        cases.add_bookmark(
            c.id, target_type="carrier-pigeon", target_value="x", db_path=db
        )


def test_list_bookmarks_scoped_to_case(db: Path) -> None:
    a = cases.create_case("a", db_path=db)
    b = cases.create_case("b", db_path=db)
    cases.add_bookmark(a.id, target_type="email", target_value="x@y", db_path=db)
    cases.add_bookmark(a.id, target_type="phone", target_value="+1555", db_path=db)
    cases.add_bookmark(b.id, target_type="email", target_value="z@y", db_path=db)
    a_list = cases.list_bookmarks(a.id, db_path=db)
    assert {(bm.target_type, bm.target_value) for bm in a_list} == {
        ("email", "x@y"),
        ("phone", "+1555"),
    }
    b_list = cases.list_bookmarks(b.id, db_path=db)
    assert len(b_list) == 1


def test_delete_bookmark(db: Path) -> None:
    c = cases.create_case("op", db_path=db)
    bm = cases.add_bookmark(c.id, target_type="email", target_value="a@b", db_path=db)
    assert cases.delete_bookmark(bm.id, db_path=db) is True
    assert cases.delete_bookmark(bm.id, db_path=db) is False


def test_case_to_dict_roundtrip(db: Path) -> None:
    c = cases.create_case("op", description="x", db_path=db, ts=10)
    cases.add_note(c.id, "n1", db_path=db)
    cases.add_bookmark(c.id, target_type="email", target_value="a@b", db_path=db)
    d = c.to_dict()
    assert d["name"] == "op"
    assert d["status"] == "open"
    assert d["created_ts"] == 10

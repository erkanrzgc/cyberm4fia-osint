"""FastAPI REST surface tests."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from core import api, watchlist  # noqa: E402
from core.api import server as api_server  # noqa: E402
from core.models import PlatformResult, ScanResult  # noqa: E402


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    # Redirect watchlist DB to a temp file so tests don't trample state.
    wl_db = tmp_path / "wl.sqlite3"
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", wl_db)
    # Module-level functions bound `db_path=DEFAULT_DB_PATH` at def time, so
    # callers without an explicit db_path still reference the original path.
    # Rebind the defaults so the API layer picks up the tmp DB too.
    for fn in (watchlist.add, watchlist.remove, watchlist.list_all,
              watchlist.mark_scanned, watchlist.get):
        monkeypatch.setitem(fn.__kwdefaults__, "db_path", wl_db)

    async def fake_run_scan(cfg):
        r = ScanResult(username=cfg.username)
        r.platforms = [
            PlatformResult(
                platform="GitHub",
                url=f"https://github.com/{cfg.username}",
                category="dev",
                exists=True,
                status="found",
            )
        ]
        return r

    monkeypatch.setattr(api_server, "run_scan", fake_run_scan)

    app = api.create_app()
    return TestClient(app)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_endpoint_returns_payload(client: TestClient) -> None:
    r = client.post(
        "/scan",
        json={"username": "alice", "save_history": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["username"] == "alice"
    assert any(p["exists"] for p in data["platforms"])


def test_scan_rejects_empty_username(client: TestClient) -> None:
    r = client.post("/scan", json={"username": "", "save_history": False})
    assert r.status_code == 422


def test_watchlist_add_and_list(client: TestClient) -> None:
    r = client.post("/watchlist", json={"username": "bob", "tags": ["red"]})
    assert r.status_code == 200
    assert r.json()["username"] == "bob"

    r = client.get("/watchlist")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["entries"][0]["username"] == "bob"


def test_watchlist_remove(client: TestClient) -> None:
    client.post("/watchlist", json={"username": "carol", "tags": []})
    r = client.delete("/watchlist/carol")
    assert r.status_code == 200
    assert r.json()["removed"] == "carol"
    # Second delete 404s.
    r2 = client.delete("/watchlist/carol")
    assert r2.status_code == 404


def test_watchlist_add_rejects_empty(client: TestClient) -> None:
    # Pydantic min_length=1 handles empty string — returns 422.
    r = client.post("/watchlist", json={"username": "", "tags": []})
    assert r.status_code == 422


def test_history_endpoints_missing_user(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "list_scans", lambda u, limit=20: [])
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)

    r = client.get("/history/ghost")
    assert r.status_code == 200
    assert r.json()["count"] == 0

    r = client.get("/history/ghost/latest")
    assert r.status_code == 404

    r = client.get("/history/ghost/diff")
    assert r.status_code == 404


def test_is_available_true_when_deps_installed() -> None:
    assert api.is_available() is True


def test_scan_stream_emits_events(client: TestClient) -> None:
    with client.stream(
        "POST",
        "/scan/stream",
        json={"username": "eve", "save_history": False},
    ) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        body = b"".join(r.iter_bytes())
    text = body.decode()
    # At least the terminal result event must arrive.
    assert "\"kind\": \"result\"" in text
    assert "eve" in text


def test_graph_404_when_no_history(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)
    r = client.get("/graph/ghost")
    assert r.status_code == 404


def test_heatmap_404_when_no_history(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: None)
    r = client.get("/heatmap/ghost")
    assert r.status_code == 404


def test_heatmap_folds_duplicate_coords(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    payload = {
        "username": "mallory",
        "platforms": [],
        "geo_points": [
            {"lat": 41.0, "lng": 29.0, "display": "Istanbul", "source": "GitHub"},
            {"lat": 41.00004, "lng": 29.00003, "display": "Istanbul", "source": "Twitter"},
            {"lat": 52.52, "lng": 13.4, "display": "Berlin", "source": "Bluesky"},
            {"lat": "bad", "lng": 0.0, "display": "skip me"},  # must be discarded
        ],
    }
    entry = HistoryEntry(id=7, username="mallory", ts=1, found_count=0, payload=payload)
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: entry)

    r = client.get("/heatmap/mallory")
    assert r.status_code == 200
    data = r.json()
    # Two unique rounded coords → two heatmap points.
    assert len(data["points"]) == 2
    istanbul = next(p for p in data["points"] if round(p[0], 1) == 41.0)
    # Weight reflects the two Istanbul hits that fold together.
    assert istanbul[2] == 2
    # Markers expose source + label.
    sources = {m["source"] for m in data["markers"]}
    assert {"GitHub", "Twitter", "Bluesky"}.issubset(sources)


def test_correlate_requires_both_usernames(client: TestClient) -> None:
    r = client.get("/correlate", params={"a": "alice", "b": ""})
    assert r.status_code == 422
    r = client.get("/correlate", params={"a": "alice", "b": "Alice"})
    assert r.status_code == 400


def test_correlate_404_when_either_has_no_history(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    alice = HistoryEntry(id=1, username="alice", ts=1, found_count=0, payload={"username": "alice"})

    def fake_latest(u, before_id=None):
        return alice if u == "alice" else None

    monkeypatch.setattr(api_server, "get_latest", fake_latest)
    r = client.get("/correlate", params={"a": "alice", "b": "ghost"})
    assert r.status_code == 404


def test_correlate_returns_score_and_signals(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    a_payload = {
        "username": "alice",
        "emails": [{"email": "shared@x.io"}],
        "phone_intel": [{"e164": "+905551234567"}],
    }
    b_payload = {
        "username": "alice2",
        "emails": [{"email": "shared@x.io"}],
        "phone_intel": [{"e164": "+905551234567"}],
    }
    a_entry = HistoryEntry(id=1, username="alice", ts=10, found_count=1, payload=a_payload)
    b_entry = HistoryEntry(id=2, username="alice2", ts=20, found_count=1, payload=b_payload)

    monkeypatch.setattr(
        api_server,
        "get_latest",
        lambda u, before_id=None: a_entry if u == "alice" else b_entry,
    )
    r = client.get("/correlate", params={"a": "alice", "b": "alice2"})
    assert r.status_code == 200
    data = r.json()
    assert data["username_a"] == "alice"
    assert data["username_b"] == "alice2"
    assert data["verdict"] == "very_likely_same"
    kinds = {s["kind"] for s in data["signals"]}
    assert {"email", "phone"} <= kinds
    assert data["scan_a"]["id"] == 1
    assert data["scan_b"]["id"] == 2


def test_graph_returns_cytoscape_payload(client: TestClient, monkeypatch) -> None:
    from core.history import HistoryEntry

    payload = {
        "username": "mallory",
        "platforms": [
            {
                "platform": "GitHub",
                "url": "https://github.com/mallory",
                "category": "dev",
                "exists": True,
                "confidence": 0.9,
            }
        ],
        "emails": [{"email": "m@e.com", "source": "github", "breaches": ["LinkedIn"]}],
    }
    entry = HistoryEntry(id=1, username="mallory", ts=1, found_count=1, payload=payload)
    monkeypatch.setattr(api_server, "get_latest", lambda u, before_id=None: entry)

    r = client.get("/graph/mallory")
    assert r.status_code == 200
    data = r.json()
    ids = {n["data"]["id"] for n in data["nodes"]}
    assert "mallory" in ids
    assert "platform::GitHub" in ids
    assert "email::m@e.com" in ids
    assert "breach::LinkedIn" in ids
    # Edges must include the root→platform relation.
    assert any(
        e["data"]["source"] == "mallory" and e["data"]["target"] == "platform::GitHub"
        for e in data["edges"]
    )

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
    monkeypatch.setattr(watchlist, "DEFAULT_DB_PATH", tmp_path / "wl.sqlite3")

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

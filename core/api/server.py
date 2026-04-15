"""FastAPI REST server.

Exposes a thin JSON surface over the scan engine, watchlist, and
history store. Intentionally kept flat — one file, no routers, no
background queues — because the CLI is still the first-class client
and the API is a supplementary surface.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core import watchlist
from core.config import ScanConfig
from core.engine import run_scan
from core.history import diff_entries, get_latest, list_scans, save_scan
from core.logging_setup import get_logger

log = get_logger(__name__)

_WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"


# ── Request/response schemas ─────────────────────────────────────────


class ScanRequest(BaseModel):
    username: str = Field(..., min_length=1)
    deep: bool = True
    smart: bool = False
    email: bool = False
    web: bool = False
    whois: bool = False
    breach: bool = False
    photo: bool = False
    dns: bool = False
    subdomain: bool = False
    recursive: bool = False
    passive: bool = False
    reverse_image: bool = False
    past_usernames: bool = False
    enrichment: bool = True
    tor: bool = False
    proxy: str | None = None
    categories: list[str] | None = None
    fp_threshold: float = 0.45
    save_history: bool = True


class WatchlistAddRequest(BaseModel):
    username: str = Field(..., min_length=1)
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


def _cfg_from_request(req: ScanRequest) -> ScanConfig:
    return ScanConfig(
        username=req.username.strip(),
        deep=req.deep,
        smart=req.smart,
        email=req.email,
        web=req.web,
        whois=req.whois,
        breach=req.breach,
        photo=req.photo,
        dns=req.dns,
        subdomain=req.subdomain,
        recursive=req.recursive,
        passive=req.passive,
        reverse_image=req.reverse_image,
        past_usernames=req.past_usernames,
        enrichment=req.enrichment,
        tor=req.tor,
        proxy=req.proxy,
        categories=tuple(req.categories) if req.categories else None,
        fp_threshold=req.fp_threshold,
    )


# ── App factory ──────────────────────────────────────────────────────


def build_app() -> FastAPI:
    app = FastAPI(
        title="cyberm4fia-osint API",
        version="0.3.0",
        description="REST surface around the OSINT scan engine.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "ts": int(time.time())}

    @app.post("/scan")
    async def scan(req: ScanRequest) -> dict[str, Any]:
        cfg = _cfg_from_request(req)
        try:
            result = await run_scan(cfg)
        except Exception as exc:  # noqa: BLE001
            log.exception("scan failed for %s", req.username)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        payload = result.to_dict()
        if req.save_history:
            try:
                save_scan(payload, ts=int(time.time()))
            except (OSError, ValueError) as exc:
                log.warning("history: save failed: %s", exc)
        return payload

    @app.get("/history/{username}")
    def history(username: str, limit: int = 20) -> dict[str, Any]:
        entries = list_scans(username, limit=limit)
        return {
            "username": username,
            "count": len(entries),
            "entries": [
                {
                    "id": e.id,
                    "ts": e.ts,
                    "found_count": e.found_count,
                }
                for e in entries
            ],
        }

    @app.get("/history/{username}/latest")
    def history_latest(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        return {
            "id": entry.id,
            "ts": entry.ts,
            "found_count": entry.found_count,
            "payload": entry.payload,
        }

    @app.get("/history/{username}/diff")
    def history_diff(username: str) -> dict[str, Any]:
        current = get_latest(username)
        if current is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        previous = get_latest(username, before_id=current.id)
        if previous is None:
            return {"added": [], "removed": [], "message": "no previous scan"}
        d = diff_entries(previous, current)
        return {
            "previous_id": previous.id,
            "current_id": current.id,
            "added": list(d.added),
            "removed": list(d.removed),
        }

    @app.get("/watchlist")
    def watchlist_list() -> dict[str, Any]:
        entries = watchlist.list_all()
        return {
            "count": len(entries),
            "entries": [e.to_dict() for e in entries],
        }

    @app.post("/watchlist")
    def watchlist_add(req: WatchlistAddRequest) -> dict[str, Any]:
        try:
            entry = watchlist.add(req.username, tags=req.tags, notes=req.notes)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return entry.to_dict()

    @app.delete("/watchlist/{username}")
    def watchlist_remove(username: str) -> dict[str, Any]:
        ok = watchlist.remove(username)
        if not ok:
            raise HTTPException(status_code=404, detail="not in watchlist")
        return {"removed": username}

    # ── Static Web UI ────────────────────────────────────────────
    if _WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_WEB_DIR)), name="static")

        @app.get("/", response_model=None)
        def index():
            index_path = _WEB_DIR / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))
            return JSONResponse({"message": "cyberm4fia-osint API", "docs": "/docs"})
    else:
        @app.get("/")
        def index_fallback() -> dict[str, Any]:
            return {"message": "cyberm4fia-osint API", "docs": "/docs"}

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the dev server via uvicorn."""
    import uvicorn

    app = build_app()
    uvicorn.run(app, host=host, port=port)

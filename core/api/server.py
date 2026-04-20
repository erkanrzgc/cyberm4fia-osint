"""FastAPI REST server.

Exposes a thin JSON surface over the scan engine, watchlist, and
history store. Intentionally kept flat — one file, no routers, no
background queues — because the CLI is still the first-class client
and the API is a supplementary surface.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core import watchlist
from core.api.cytoscape import payload_to_cytoscape
from core.compare import compare_payloads
from core.config import ScanConfig
from core.correlation import correlate
from core.engine import run_scan
from core.history import diff_entries, get_latest, get_scan, list_scans, save_scan
from core.logging_setup import get_logger
from core.progress import ProgressEmitter, set_emitter

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

    @app.post("/scan/stream")
    async def scan_stream(req: ScanRequest) -> StreamingResponse:
        cfg = _cfg_from_request(req)
        emitter = ProgressEmitter()
        queue = emitter.subscribe()

        async def _runner() -> None:
            set_emitter(emitter)
            try:
                try:
                    result = await run_scan(cfg)
                except Exception as exc:  # noqa: BLE001
                    log.exception("streamed scan failed for %s", req.username)
                    emitter.emit_error(str(exc))
                    return
                payload = result.to_dict()
                if req.save_history:
                    try:
                        save_scan(payload, ts=int(time.time()))
                    except (OSError, ValueError) as exc:
                        log.warning("history: save failed: %s", exc)
                emitter.emit_result(payload)
            finally:
                set_emitter(None)
                emitter.close()

        task = asyncio.create_task(_runner())

        async def _stream() -> AsyncIterator[bytes]:
            try:
                while True:
                    event = await queue.get()
                    if event is None:
                        break
                    yield f"data: {json.dumps(event.to_dict())}\n\n".encode()
                    if event.kind in {"done", "error", "result"}:
                        # keep draining until emitter closes so result/done both flow
                        continue
            finally:
                if not task.done():
                    task.cancel()

        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.get("/graph/{username}")
    def graph(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        return {
            "username": username,
            "scan_id": entry.id,
            "ts": entry.ts,
            **payload_to_cytoscape(entry.payload),
        }

    @app.get("/heatmap/{username}")
    def heatmap(username: str) -> dict[str, Any]:
        entry = get_latest(username)
        if entry is None:
            raise HTTPException(status_code=404, detail="no scans for user")
        points = entry.payload.get("geo_points") or []
        # Leaflet.heat wants [[lat, lng, weight], ...]. Weight starts at 1
        # per hit; duplicate coords are folded so popular cities pop.
        weights: dict[tuple[float, float], int] = {}
        markers: list[dict[str, Any]] = []
        for g in points:
            try:
                lat = float(g["lat"])
                lng = float(g["lng"])
            except (KeyError, TypeError, ValueError):
                continue
            key = (round(lat, 4), round(lng, 4))
            weights[key] = weights.get(key, 0) + 1
            markers.append(
                {
                    "lat": lat,
                    "lng": lng,
                    "label": g.get("display") or g.get("query") or "",
                    "source": g.get("source") or "",
                    "country": g.get("country") or "",
                }
            )
        heat = [[lat, lng, w] for (lat, lng), w in weights.items()]
        return {
            "username": username,
            "scan_id": entry.id,
            "ts": entry.ts,
            "points": heat,
            "markers": markers,
        }

    @app.get("/compare")
    def compare_scans(
        a: str,
        b: str,
        a_scan: int | None = None,
        b_scan: int | None = None,
    ) -> dict[str, Any]:
        """Deep-diff two scans for side-by-side review.

        ``a`` and ``b`` are usernames; optional ``a_scan``/``b_scan``
        pin to specific history IDs (defaults: latest). Returns the
        structured diff *plus* both payloads so the UI can render each
        side without a second round-trip.
        """
        a_clean, b_clean = a.strip(), b.strip()
        if not a_clean or not b_clean:
            raise HTTPException(status_code=422, detail="both a and b are required")
        entry_a = get_scan(a_scan) if a_scan is not None else get_latest(a_clean)
        if entry_a is None:
            raise HTTPException(status_code=404, detail=f"no scan for {a_clean}")
        entry_b = get_scan(b_scan) if b_scan is not None else get_latest(b_clean)
        if entry_b is None:
            raise HTTPException(status_code=404, detail=f"no scan for {b_clean}")
        diff = compare_payloads(entry_a.payload, entry_b.payload)
        return {
            "scan_a": {
                "id": entry_a.id,
                "ts": entry_a.ts,
                "username": entry_a.username,
                "payload": entry_a.payload,
            },
            "scan_b": {
                "id": entry_b.id,
                "ts": entry_b.ts,
                "username": entry_b.username,
                "payload": entry_b.payload,
            },
            **diff.to_dict(),
        }

    @app.get("/correlate")
    def correlate_users(a: str, b: str) -> dict[str, Any]:
        """Score how likely two usernames are the same person.

        Pulls the latest scan payload from history for each side and
        runs the correlation scorer. 404s if either user has no history —
        the scorer needs something to compare against.
        """
        a_clean, b_clean = a.strip(), b.strip()
        if not a_clean or not b_clean:
            raise HTTPException(status_code=422, detail="both a and b are required")
        if a_clean.lower() == b_clean.lower():
            raise HTTPException(status_code=400, detail="a and b must differ")
        entry_a = get_latest(a_clean)
        if entry_a is None:
            raise HTTPException(status_code=404, detail=f"no scans for {a_clean}")
        entry_b = get_latest(b_clean)
        if entry_b is None:
            raise HTTPException(status_code=404, detail=f"no scans for {b_clean}")
        result = correlate(entry_a.payload, entry_b.payload)
        return {
            "scan_a": {"id": entry_a.id, "ts": entry_a.ts},
            "scan_b": {"id": entry_b.id, "ts": entry_b.ts},
            **result.to_dict(),
        }

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

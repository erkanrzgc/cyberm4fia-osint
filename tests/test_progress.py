"""Tests for the progress event bus."""

from __future__ import annotations

import asyncio

import pytest

from core.progress import (
    ProgressEmitter,
    ProgressEvent,
    emit,
    get_emitter,
    set_emitter,
)


def test_event_to_dict_roundtrip():
    e = ProgressEvent(kind="phase_start", phase="platform", data={"total": 5})
    d = e.to_dict()
    assert d == {
        "kind": "phase_start",
        "phase": "platform",
        "message": "",
        "data": {"total": 5},
    }


def test_emit_no_op_without_emitter():
    # Must not raise when no emitter is set.
    set_emitter(None)
    emit("phase_start", phase="x")


@pytest.mark.asyncio
async def test_emitter_fanout_delivers_to_all_subscribers():
    emitter = ProgressEmitter()
    q1 = emitter.subscribe()
    q2 = emitter.subscribe()

    emitter.emit(ProgressEvent(kind="hit", phase="p", message="m"))

    e1 = await asyncio.wait_for(q1.get(), timeout=0.5)
    e2 = await asyncio.wait_for(q2.get(), timeout=0.5)
    assert e1.kind == "hit" and e2.kind == "hit"


@pytest.mark.asyncio
async def test_emit_helper_fires_on_current_emitter():
    emitter = ProgressEmitter()
    q = emitter.subscribe()
    set_emitter(emitter)
    try:
        emit("phase_end", phase="photo", message="done", found=3)
        ev = await asyncio.wait_for(q.get(), timeout=0.5)
        assert ev.kind == "phase_end"
        assert ev.phase == "photo"
        assert ev.message == "done"
        assert ev.data == {"found": 3}
    finally:
        set_emitter(None)


@pytest.mark.asyncio
async def test_close_emits_sentinel():
    emitter = ProgressEmitter()
    q = emitter.subscribe()
    emitter.close()
    sentinel = await asyncio.wait_for(q.get(), timeout=0.5)
    assert sentinel is None


@pytest.mark.asyncio
async def test_emit_error_and_result_helpers():
    emitter = ProgressEmitter()
    q = emitter.subscribe()
    emitter.emit_error("boom")
    emitter.emit_result({"found_count": 2})
    err = await asyncio.wait_for(q.get(), timeout=0.5)
    res = await asyncio.wait_for(q.get(), timeout=0.5)
    assert err.kind == "error" and err.message == "boom"
    assert res.kind == "result"
    assert res.data["payload"] == {"found_count": 2}


def test_unsubscribe_removes_queue():
    emitter = ProgressEmitter()
    q = emitter.subscribe()
    emitter.unsubscribe(q)
    emitter.emit(ProgressEvent(kind="hit"))
    assert q.empty()


def test_get_emitter_returns_current():
    emitter = ProgressEmitter()
    set_emitter(emitter)
    try:
        assert get_emitter() is emitter
    finally:
        set_emitter(None)
    assert get_emitter() is None

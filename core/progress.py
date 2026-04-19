"""Simple async progress event bus.

The scan engine emits named events (``phase_start``, ``phase_end``,
``hit``, ``error``, ``done``) to a contextvar-bound emitter. Anyone
consuming a scan — the SSE endpoint, a CLI progress bar, a test — can
attach an :class:`asyncio.Queue` to the emitter to receive events as
they happen.

Keeping this in its own tiny module avoids pulling FastAPI into the
engine and lets the CLI stay synchronous by default.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

_current: ContextVar["ProgressEmitter | None"] = ContextVar(
    "cyberm4fia_progress", default=None
)


@dataclass
class ProgressEvent:
    kind: str  # "phase_start" | "phase_end" | "hit" | "error" | "done"
    phase: str = ""
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "phase": self.phase,
            "message": self.message,
            "data": self.data,
        }


class ProgressEmitter:
    """Fan-out event emitter. Multiple subscribers each get their own queue.

    Queues receive :class:`ProgressEvent` items during the scan and a
    terminal ``None`` sentinel when :meth:`close` is called, so consumers
    can shut down cleanly without racing the background task.
    """

    def __init__(self) -> None:
        self._subs: list[asyncio.Queue[ProgressEvent | None]] = []

    def subscribe(self) -> asyncio.Queue[ProgressEvent | None]:
        q: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[ProgressEvent | None]) -> None:
        if q in self._subs:
            self._subs.remove(q)

    def emit(self, event: ProgressEvent) -> None:
        for q in list(self._subs):
            q.put_nowait(event)

    def emit_error(self, message: str) -> None:
        self.emit(ProgressEvent(kind="error", phase="error", message=message))

    def emit_result(self, payload: dict[str, Any]) -> None:
        self.emit(ProgressEvent(kind="result", phase="done", data={"payload": payload}))

    def close(self) -> None:
        """Signal end-of-stream to every subscriber."""
        for q in list(self._subs):
            q.put_nowait(None)


def set_emitter(emitter: ProgressEmitter | None) -> None:
    _current.set(emitter)


def get_emitter() -> ProgressEmitter | None:
    return _current.get()


def emit(kind: str, **fields: Any) -> None:
    """Fire a :class:`ProgressEvent` on the current emitter, if any.

    No-op when no emitter is set (the default for CLI scans), so phases
    never need to know whether anyone is listening.
    """
    e = _current.get()
    if e is None:
        return
    phase = fields.pop("phase", "")
    message = fields.pop("message", "")
    e.emit(ProgressEvent(kind=kind, phase=phase, message=message, data=fields))

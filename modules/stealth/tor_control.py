"""Tor circuit rotation via the control port (stem).

Optional dependency — if ``stem`` is not installed the module still imports
and exposes ``AVAILABLE = False`` so callers can short-circuit without a
hard failure.

Usage::

    from modules.stealth.tor_control import rotate_circuit, AVAILABLE

    if AVAILABLE:
        await rotate_circuit(control_port=9051, password="hunter2")

The ``stem`` call is sync-only and is kept best-effort.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

try:
    from stem import Signal  # type: ignore[import-not-found]
    from stem.control import Controller  # type: ignore[import-not-found]

    AVAILABLE = True
except ImportError:  # pragma: no cover - optional dep
    Signal = None  # type: ignore[assignment]
    Controller = None  # type: ignore[assignment]
    AVAILABLE = False


def _sync_newnym(host: str, port: int, password: str | None) -> None:
    if not AVAILABLE:  # pragma: no cover
        raise RuntimeError("stem is not installed — pip install stem")
    with Controller.from_port(address=host, port=port) as controller:  # type: ignore[union-attr]
        if password:
            controller.authenticate(password=password)
        else:
            controller.authenticate()
        controller.signal(Signal.NEWNYM)  # type: ignore[attr-defined]


async def rotate_circuit(
    *,
    host: str = "127.0.0.1",
    control_port: int = 9051,
    password: str | None = None,
) -> bool:
    """Send NEWNYM to the local Tor control port.

    Returns True on success, False if stem is missing or the control port
    refused us. Does not raise — circuit rotation is best-effort.
    """
    if not AVAILABLE:
        log.debug("stem not available; skipping Tor circuit rotation")
        return False
    try:
        _sync_newnym(host, control_port, password)
        log.info("Tor circuit rotated (NEWNYM sent to %s:%d)", host, control_port)
        return True
    except Exception as exc:
        log.warning("Tor circuit rotation failed: %s", exc)
        return False


class CircuitRotator:
    """Rotate Tor circuit every N requests.

    Instantiate once, call :meth:`tick` after each request; it handles the
    counter and fires ``rotate_circuit`` when the threshold is hit.
    """

    def __init__(
        self,
        *,
        every: int,
        host: str = "127.0.0.1",
        control_port: int = 9051,
        password: str | None = None,
    ) -> None:
        self._every = max(1, every)
        self._host = host
        self._port = control_port
        self._password = password
        self._count = 0
        self._lock = asyncio.Lock()

    async def tick(self) -> bool:
        """Increment the counter and rotate if we've hit the threshold."""
        async with self._lock:
            self._count += 1
            if self._count < self._every:
                return False
            self._count = 0
        return await rotate_circuit(
            host=self._host,
            control_port=self._port,
            password=self._password,
        )

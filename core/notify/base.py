"""Notification primitives — event dataclass + protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Notification:
    kind: str  # "scan_complete" | "scan_diff" | "scan_error"
    username: str
    title: str
    body: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "username": self.username,
            "title": self.title,
            "body": self.body,
            "data": dict(self.data),
        }


class Notifier(Protocol):
    name: str

    async def send(self, notification: Notification) -> bool:
        """Send a notification. Returns True on success, False on failure.

        Must never raise — notifier failures must not kill the scheduler.
        """
        ...

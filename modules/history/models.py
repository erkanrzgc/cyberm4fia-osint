"""Shared dataclass for historical-username hits."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HistoricalUsername:
    username: str              # the historical handle we found
    platform: str              # e.g. "twitter.com", "github.com"
    first_seen: str = ""       # earliest CDX timestamp as "YYYYMMDDhhmmss"
    last_seen: str = ""        # latest CDX timestamp seen
    snapshot_count: int = 0
    sample_snapshot: str = ""  # one representative archive.org URL
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "platform": self.platform,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "snapshot_count": self.snapshot_count,
            "sample_snapshot": self.sample_snapshot,
            "metadata": dict(self.metadata),
        }

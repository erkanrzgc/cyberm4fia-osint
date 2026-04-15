"""Shared dataclass for reverse-image results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReverseImageHit:
    source: str        # yandex, tineye
    source_url: str    # the image that was queried
    match_url: str     # page where the match was found
    title: str = ""
    image_url: str = ""
    score: float = 0.0  # 0..1 — source-specific confidence, best-effort
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_url": self.source_url,
            "match_url": self.match_url,
            "title": self.title,
            "image_url": self.image_url,
            "score": self.score,
            "metadata": dict(self.metadata),
        }

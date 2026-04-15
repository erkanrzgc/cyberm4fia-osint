"""Dataclasses for the enrichment phase."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StylometryReport:
    sample_count: int = 0
    total_chars: int = 0
    total_words: int = 0
    avg_word_length: float = 0.0
    avg_sentence_length: float = 0.0
    lexical_diversity: float = 0.0          # unique_words / total_words
    punctuation_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    emoji_count: int = 0
    top_words: tuple[tuple[str, int], ...] = ()

    def to_dict(self) -> dict:
        return {
            "sample_count": self.sample_count,
            "total_chars": self.total_chars,
            "total_words": self.total_words,
            "avg_word_length": round(self.avg_word_length, 3),
            "avg_sentence_length": round(self.avg_sentence_length, 3),
            "lexical_diversity": round(self.lexical_diversity, 3),
            "punctuation_ratio": round(self.punctuation_ratio, 3),
            "uppercase_ratio": round(self.uppercase_ratio, 3),
            "emoji_count": self.emoji_count,
            "top_words": [list(t) for t in self.top_words],
        }


@dataclass(frozen=True)
class LanguageGuess:
    code: str            # ISO 639-1, e.g. "en"
    confidence: float    # 0.0-1.0

    def to_dict(self) -> dict:
        return {"code": self.code, "confidence": round(self.confidence, 3)}


@dataclass(frozen=True)
class TimezoneGuess:
    tz: str              # e.g. "Europe/Istanbul"
    confidence: float
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "tz": self.tz,
            "confidence": round(self.confidence, 3),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class EnrichmentReport:
    stylometry: StylometryReport | None = None
    languages: tuple[LanguageGuess, ...] = ()
    timezones: tuple[TimezoneGuess, ...] = ()
    graph: dict = field(default_factory=dict)   # NetworkX node-link dict

    def to_dict(self) -> dict:
        return {
            "stylometry": self.stylometry.to_dict() if self.stylometry else None,
            "languages": [l.to_dict() for l in self.languages],
            "timezones": [t.to_dict() for t in self.timezones],
            "graph": self.graph,
        }

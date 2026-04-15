"""Enrichment orchestrator — runs the synchronous analyzers over a ScanResult."""

from __future__ import annotations

from typing import Any

from modules.analysis.graph import build_entity_graph, graph_to_dict
from modules.analysis.language import detect_languages
from modules.analysis.models import EnrichmentReport
from modules.analysis.stylometry import compute_stylometry
from modules.analysis.timezone_infer import infer_timezones

_BIO_KEYS = (
    "bio",
    "description",
    "about",
    "summary",
    "headline",
    "tagline",
)

_LOCATION_KEYS = ("location", "country", "city", "place")


def _collect_bios(result: Any) -> list[str]:
    out: list[str] = []
    for p in getattr(result, "platforms", []) or []:
        if not getattr(p, "exists", False):
            continue
        data = getattr(p, "profile_data", {}) or {}
        for key in _BIO_KEYS:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
    return out


def _collect_locations(result: Any) -> list[str]:
    out: list[str] = []
    for p in getattr(result, "platforms", []) or []:
        if not getattr(p, "exists", False):
            continue
        data = getattr(p, "profile_data", {}) or {}
        for key in _LOCATION_KEYS:
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
    return out


def _collect_phone_tzs(result: Any) -> list[str]:
    tzs: list[str] = []
    for phone in getattr(result, "phone_intel", []) or []:
        tzs.extend(getattr(phone, "timezones", ()) or ())
    return tzs


def run_enrichment(result: Any) -> EnrichmentReport:
    """Build an :class:`EnrichmentReport` from an existing scan result."""
    bios = _collect_bios(result)
    stylometry = compute_stylometry(bios) if bios else None
    languages = detect_languages(bios)

    locations = _collect_locations(result)
    phone_tzs = _collect_phone_tzs(result)
    timezones = infer_timezones(
        location_strings=locations,
        phone_timezones=phone_tzs,
        languages=list(languages),
    )

    graph = graph_to_dict(build_entity_graph(result))

    return EnrichmentReport(
        stylometry=stylometry,
        languages=tuple(languages),
        timezones=tuple(timezones),
        graph=graph,
    )

"""Derived, investigator-friendly summaries for scan payloads."""

from __future__ import annotations

from collections import Counter
from typing import Any

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _exists_platforms(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        platform
        for platform in payload.get("platforms", []) or []
        if isinstance(platform, dict) and platform.get("exists")
    ]


def _plural(value: int, singular: str, plural: str | None = None) -> str:
    if value == 1:
        return f"{value} {singular}"
    return f"{value} {plural or singular + 's'}"


def _risk(
    severity: str,
    title: str,
    detail: str,
) -> dict[str, str]:
    return {
        "severity": severity,
        "title": title,
        "detail": detail,
    }


def _trim(items: list[str], *, limit: int) -> list[str]:
    return [item for item in items if item][:limit]


def _confidence_band(confidence: float) -> str:
    if confidence >= 80:
        return "very_high"
    if confidence >= 60:
        return "high"
    if confidence >= 35:
        return "medium"
    return "low"


def _priority_score(
    *,
    found_count: int,
    confidence: float,
    risks: list[dict[str, str]],
    emails: int,
    geo_points: int,
    passive_hits: int,
) -> int:
    weights = {"high": 18, "medium": 8, "low": 2}
    risk_score = sum(weights.get(str(risk.get("severity") or "low"), 0) for risk in risks)
    score = (
        min(found_count * 4, 20)
        + round(min(max(confidence, 0.0), 100.0) * 0.22)
        + risk_score
        + min(emails * 3, 9)
        + min(geo_points * 2, 6)
        + min(passive_hits, 6)
    )
    return max(0, min(int(score), 100))


def _actions_by_severity(
    *,
    ai_next_steps: list[str],
    found_count: int,
    emails: list[dict[str, Any]],
    holehe_hits: list[Any],
    ghunt_results: list[Any],
    photo_matches: list[Any],
    matched_locations: list[Any],
    geo_points: list[Any],
    discovered_usernames: list[Any],
    historical_usernames: list[Any],
    passive_hits: list[Any],
    warnings: list[str],
    domain_artifacts_present: bool,
) -> dict[str, list[str]]:
    actions: dict[str, list[str]] = {"high": [], "medium": [], "low": []}

    for item in ai_next_steps[:2]:
        actions["medium"].append(item)

    if found_count == 0:
        actions["medium"].append("Re-run with smart search or category filters to widen the candidate set.")
    if emails and not holehe_hits:
        actions["high"].append("Pivot discovered emails through registration probes to map service reuse.")
    if emails and not ghunt_results:
        actions["medium"].append("Run Google-account enrichment on discovered emails to confirm naming and profile links.")
    if found_count >= 2 and not photo_matches:
        actions["medium"].append("Compare profile photos across confirmed accounts to strengthen linkage confidence.")
    if matched_locations and not geo_points:
        actions["medium"].append("Geocode discovered location clues to visualize likely operating regions.")
    if discovered_usernames and not historical_usernames:
        actions["low"].append("Rescan discovered usernames recursively to expand the account graph.")
    if not passive_hits and domain_artifacts_present:
        actions["low"].append("Run passive-source pivots on discovered domains and infrastructure artifacts.")
    if warnings:
        actions["low"].append("Address environment and dependency warnings before treating this run as fully comprehensive.")

    deduped: dict[str, list[str]] = {}
    for severity, items in actions.items():
        seen: set[str] = set()
        ordered: list[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        deduped[severity] = ordered[:3]
    return deduped


def build_investigator_summary(
    payload: dict[str, Any],
    *,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Project raw scan output into a short investigator briefing."""
    username = str(payload.get("username") or "")
    found_platforms = _exists_platforms(payload)
    found_count = len(found_platforms)
    categories = sorted(
        {
            str(platform.get("category") or "")
            for platform in found_platforms
            if platform.get("category")
        }
    )
    platform_names = _trim(
        [str(platform.get("platform") or "") for platform in found_platforms],
        limit=4,
    )
    emails = [
        email for email in payload.get("emails", []) or []
        if isinstance(email, dict) and email.get("email")
    ]
    breached_emails = [email for email in emails if int(email.get("breach_count") or 0) > 0]
    total_breach_hits = sum(int(email.get("breach_count") or 0) for email in breached_emails)
    comb_leaks = payload.get("comb_leaks") or []
    holehe_hits = payload.get("holehe_hits") or []
    ghunt_results = payload.get("ghunt_results") or []
    photo_matches = payload.get("photo_matches") or []
    geo_points = payload.get("geo_points") or []
    phone_intel = payload.get("phone_intel") or []
    crypto_intel = payload.get("crypto_intel") or []
    passive_hits = payload.get("passive_hits") or []
    historical_usernames = payload.get("historical_usernames") or []
    discovered_usernames = payload.get("discovered_usernames") or []
    cross_reference = payload.get("cross_reference") or {}
    ai_report = payload.get("ai_report") or {}
    ai_exposures = [str(item) for item in ai_report.get("exposures") or [] if item]
    ai_next_steps = [str(item) for item in ai_report.get("next_steps") or [] if item]
    scan_warnings = list(warnings if warnings is not None else payload.get("warnings") or [])

    if found_count == 0:
        headline = f"No confirmed public profiles were identified for {username} in this run."
    else:
        headline = (
            f"{username} has {_plural(found_count, 'confirmed profile')} "
            f"across {_plural(len(categories), 'category')}."
        )

    overview: list[str] = []
    if platform_names:
        overview.append(
            "Confirmed presence on " + ", ".join(platform_names)
            + ("." if found_count <= len(platform_names) else f", and {found_count - len(platform_names)} more.")
        )
    confidence = float(cross_reference.get("confidence") or 0)
    matched_names = cross_reference.get("matched_names") or []
    matched_locations = cross_reference.get("matched_locations") or []
    matched_photos = cross_reference.get("matched_photos") or []
    if confidence > 0:
        signal_bits = []
        if matched_names:
            signal_bits.append(_plural(len(matched_names), "name match"))
        if matched_locations:
            signal_bits.append(_plural(len(matched_locations), "location match"))
        if matched_photos:
            signal_bits.append(_plural(len(matched_photos), "photo match"))
        if signal_bits:
            overview.append(
                f"Cross-reference confidence is {round(confidence)}% with "
                + ", ".join(signal_bits)
                + "."
            )
    if emails:
        overview.append(
            f"Discovered {_plural(len(emails), 'email address')} and "
            f"{_plural(len(holehe_hits), 'service enumeration hit') if holehe_hits else 'no service-enumeration hits yet'}."
        )
    elif discovered_usernames:
        overview.append(
            f"Identified {_plural(len(discovered_usernames), 'secondary username')} for recursive follow-up."
        )
    if geo_points:
        overview.append(f"Mapped {_plural(len(geo_points), 'location point')} for geographic context.")
    elif matched_locations:
        overview.append("Location clues were found but not geocoded yet.")
    if ai_exposures:
        overview.append(f"AI review highlighted {_plural(len(ai_exposures), 'exposure')} worth manual verification.")
    overview = _trim(overview, limit=4)

    risks: list[dict[str, str]] = []
    if comb_leaks:
        preview_targets = _trim(
            [str(leak.get("identifier") or "") for leak in comb_leaks if isinstance(leak, dict)],
            limit=2,
        )
        detail = (
            f"{_plural(len(comb_leaks), 'credential leak record')} found"
            + (f" for {', '.join(preview_targets)}." if preview_targets else ".")
        )
        risks.append(_risk("high", "Credential leak exposure", detail))
    if breached_emails:
        breached_list = ", ".join(_trim([str(email["email"]) for email in breached_emails], limit=3))
        severity = "high" if total_breach_hits >= 3 else "medium"
        risks.append(
            _risk(
                severity,
                "Breached email footprint",
                f"{_plural(total_breach_hits, 'breach hit')} across {breached_list}.",
            )
        )
    if holehe_hits:
        by_email = Counter(
            str(hit.get("email") or "")
            for hit in holehe_hits
            if isinstance(hit, dict) and hit.get("email")
        )
        hottest = by_email.most_common(1)
        detail = f"{_plural(len(holehe_hits), 'site hit')} confirmed from registration probes."
        if hottest:
            detail += f" Highest pivot density: {hottest[0][0]} ({hottest[0][1]} sites)."
        risks.append(_risk("medium", "Service reuse footprint", detail))
    if phone_intel or crypto_intel:
        pieces = []
        if phone_intel:
            pieces.append(_plural(len(phone_intel), "phone"))
        if crypto_intel:
            pieces.append(_plural(len(crypto_intel), "wallet"))
        risks.append(
            _risk(
                "medium",
                "Pivotable identifiers",
                "Additional identifiers discovered: " + ", ".join(pieces) + ".",
            )
        )
    if passive_hits:
        sources = sorted(
            {
                str(hit.get("source") or "")
                for hit in passive_hits
                if isinstance(hit, dict) and hit.get("source")
            }
        )
        risks.append(
            _risk(
                "low",
                "Infrastructure visibility",
                f"Passive sources returned {_plural(len(passive_hits), 'artifact')} from {', '.join(_trim(sources, limit=4)) or 'public intel sources'}.",
            )
        )
    for exposure in ai_exposures[:3]:
        severity = "medium"
        upper = exposure.upper()
        if upper.startswith("HIGH"):
            severity = "high"
        elif upper.startswith("LOW"):
            severity = "low"
        risks.append(_risk(severity, "AI exposure signal", exposure))
    for warning in scan_warnings[:2]:
        risks.append(_risk("low", "Coverage warning", warning))
    risks.sort(key=lambda item: (_SEVERITY_ORDER.get(item["severity"], 99), item["title"]))
    risks = risks[:5]
    recommended_actions_by_severity = _actions_by_severity(
        ai_next_steps=ai_next_steps,
        found_count=found_count,
        emails=emails,
        holehe_hits=holehe_hits,
        ghunt_results=ghunt_results,
        photo_matches=photo_matches,
        matched_locations=matched_locations,
        geo_points=geo_points,
        discovered_usernames=discovered_usernames,
        historical_usernames=historical_usernames,
        passive_hits=passive_hits,
        warnings=scan_warnings,
        domain_artifacts_present=bool(
            payload.get("whois_records") or payload.get("dns_records") or payload.get("subdomains")
        ),
    )
    next_steps = _trim(
        recommended_actions_by_severity["high"]
        + recommended_actions_by_severity["medium"]
        + recommended_actions_by_severity["low"],
        limit=5,
    )
    priority_score = _priority_score(
        found_count=found_count,
        confidence=confidence,
        risks=risks,
        emails=len(emails),
        geo_points=len(geo_points),
        passive_hits=len(passive_hits),
    )
    confidence_band = _confidence_band(confidence)

    return {
        "headline": headline,
        "priority_score": priority_score,
        "confidence_band": confidence_band,
        "overview": overview,
        "risk_flags": risks,
        "next_steps": next_steps,
        "recommended_actions_by_severity": recommended_actions_by_severity,
    }

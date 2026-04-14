"""OSINT scan engine — orchestrates modular phases.

Kept deliberately thin: each phase is a small coroutine that mutates the
ScanResult in place. Adding a new phase means adding a _phase_* method
and wiring it into scan().
"""

from __future__ import annotations

import asyncio
import time

from core.config import ScanConfig
from core.cross_reference import cross_reference
from core.http_client import HTTPClient
from core.logging_setup import get_logger
from core.models import EmailResult, PhotoMatch, PlatformResult, ScanResult
from core.reporter import console
from core.smart_search import (
    extract_discoverable_data,
    generate_variations,
    merge_discoveries,
)
from modules.breach_check import breach_check_available, check_many_emails, hibp_available
from modules.comb_leaks import search_comb_many
from modules.deep_scrapers import DEEP_SCRAPERS
from modules.ghunt_lookup import is_available as ghunt_available
from modules.ghunt_lookup import lookup_emails as ghunt_lookup_emails
from modules.holehe_check import check_emails as holehe_check_emails
from modules.holehe_check import is_available as holehe_available
from modules.holehe_check import module_count as holehe_module_count
from modules.toutatis_lookup import is_available as toutatis_available
from modules.toutatis_lookup import lookup_usernames as toutatis_lookup_usernames
from modules.dns_lookup import enumerate_subdomains, get_dns_records
from modules.email_discovery import discover_emails
from modules.fp_filter import score_match
from modules.photo_compare import compare_profile_photos
from modules.platforms import PLATFORMS, Platform
from modules.profile_extract import extract_profile, is_available as _extract_available
from modules.web_presence import discover_web_presence
from modules.whois_lookup import check_username_domains

log = get_logger(__name__)

AVATAR_KEYS = ("avatar_url", "icon_img", "avatar", "profile_image")
IMPORTANT_PLATFORMS_FOR_VARIATIONS = frozenset(
    {
        "GitHub",
        "Twitter / X",
        "Instagram",
        "Reddit",
        "LinkedIn",
        "YouTube",
        "TikTok",
        "Steam",
    }
)


# ── Phase helpers ─────────────────────────────────────────────────────────


async def _check_platform(
    client: HTTPClient, username: str, platform: Platform
) -> PlatformResult:
    url = platform.url.replace("{username}", username)
    result = PlatformResult(platform=platform.name, url=url, category=platform.category)

    try:
        if platform.check_type == "json_api":
            status, data, elapsed = await client.get_json(url, platform.headers)
            result.http_status = status
            result.response_time = elapsed
            result.exists = status == 200 and data is not None
        else:
            status, body, elapsed = await client.get(url, platform.headers)
            result.http_status = status
            result.response_time = elapsed
            if platform.check_type == "status":
                result.exists = status == 200
            elif platform.check_type == "content_absent":
                result.exists = status == 200 and platform.error_text not in body
            elif platform.check_type == "content_present":
                result.exists = status == 200 and platform.success_text in body

            # Opportunistic profile parsing: if the upstream socid_extractor
            # recognises this HTML, pull out names/emails/links for free.
            if result.exists and body and _extract_available():
                extracted = extract_profile(body)
                if extracted:
                    result.profile_data = extracted

            # False-positive scoring on any positive match.
            if result.exists and body:
                fp = score_match(
                    username=username,
                    body=body,
                    check_type=platform.check_type,
                    http_status=status,
                )
                result.confidence = fp.confidence
                result.fp_signals = list(fp.signals)

        result.status = _status_from_http(status, result.exists)
    except (asyncio.TimeoutError, OSError) as exc:
        log.debug("platform %s errored: %s", platform.name, exc)
        result.status = "error"
    except Exception as exc:
        log.warning("unexpected error checking %s: %s", platform.name, exc)
        result.status = "error"

    return result


def _status_from_http(status: int, exists: bool) -> str:
    if status == 0:
        return "timeout"
    if status == -1:
        return "error"
    if status == 429:
        return "blocked"
    return "found" if exists else "not_found"


async def _deep_scrape(
    client: HTTPClient, username: str, platform_result: PlatformResult
) -> dict:
    scraper = DEEP_SCRAPERS.get(platform_result.platform)
    if not scraper:
        return {}
    try:
        return await scraper(client, username)
    except Exception as exc:
        log.debug("deep scrape %s failed: %s", platform_result.platform, exc)
        return {}


def _extract_avatar_urls(platforms: list[PlatformResult]) -> list[tuple[str, str]]:
    avatars: list[tuple[str, str]] = []
    for p in platforms:
        if not p.profile_data:
            continue
        for key in AVATAR_KEYS:
            url = p.profile_data.get(key, "")
            if url and isinstance(url, str) and url.startswith("http"):
                avatars.append((p.platform, url))
                break
    return avatars


def _select_platforms(categories: tuple[str, ...] | None) -> list[Platform]:
    if not categories:
        return list(PLATFORMS)
    return [p for p in PLATFORMS if p.category in categories]


# ── Phase implementations ────────────────────────────────────────────────


async def _phase_platform_check(
    client: HTTPClient, cfg: ScanConfig, platforms: list[Platform], result: ScanResult
) -> list[PlatformResult]:
    console.print("  [bold yellow][1/8][/bold yellow] Starting platform sweep...")
    tasks = [_check_platform(client, cfg.username, p) for p in platforms]
    platform_results = await asyncio.gather(*tasks)

    # Deep-scraped platforms are hand-curated and verified via API calls,
    # so we trust them regardless of the heuristic confidence score.
    dropped = 0
    for r in platform_results:
        if (
            r.exists
            and r.platform not in DEEP_SCRAPERS
            and r.confidence < cfg.fp_threshold
        ):
            r.exists = False
            r.status = "low_confidence"
            dropped += 1

    found_count = sum(1 for r in platform_results if r.exists)
    suffix = f", [yellow]{dropped}[/yellow] dropped by FP filter" if dropped else ""
    console.print(
        f"  [bold green][1/8][/bold green] Done: "
        f"[green]{found_count}[/green]/{len(platform_results)} platforms matched{suffix}"
    )
    result.platforms = list(platform_results)
    return platform_results


async def _phase_deep_scrape(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
) -> None:
    if not cfg.deep:
        console.print("  [dim][2/8] Deep scrape: skipped[/dim]")
        return

    targets = [
        r for r in platform_results if r.exists and r.platform in DEEP_SCRAPERS
    ]
    if not targets:
        console.print("  [bold green][2/8][/bold green] Deep scrape: no eligible profiles")
        return

    console.print(
        f"  [bold yellow][2/8][/bold yellow] Deep scrape: analyzing {len(targets)} profiles..."
    )
    deep_results = await asyncio.gather(
        *(_deep_scrape(client, cfg.username, r) for r in targets)
    )
    for target, data in zip(targets, deep_results, strict=True):
        if data:
            # Deep scraper output wins over opportunistic extractor output.
            merged = {**(target.profile_data or {}), **data}
            target.profile_data = merged

    scraped = sum(1 for d in deep_results if d)
    console.print(f"  [bold green][2/8][/bold green] Done: {scraped} profile details pulled")


async def _phase_smart_search(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.smart:
        console.print("  [dim][3/8] Smart search: skipped[/dim]")
        return

    console.print("  [bold yellow][3/8][/bold yellow] Starting smart search...")

    discoveries = [
        extract_discoverable_data(r.profile_data)
        for r in platform_results
        if r.exists and r.profile_data
    ]
    merged = merge_discoveries(discoveries)
    variations = generate_variations(cfg.username)
    result.variations_checked = variations

    for linked_u in merged.get("linked_usernames", []):
        if linked_u.lower() != cfg.username.lower() and linked_u not in variations:
            variations.append(linked_u)
            result.discovered_usernames.append(linked_u)

    not_found_platforms = [
        p for p in platforms
        if not any(r.platform == p.name and r.exists for r in platform_results)
    ]
    if not (variations and not_found_platforms):
        console.print("  [bold green][3/8][/bold green] Done")
        return

    important = [p for p in not_found_platforms if p.name in IMPORTANT_PLATFORMS_FOR_VARIATIONS]
    check_platforms = important[:8]
    check_variations = variations[:5]
    if not check_platforms:
        console.print("  [bold green][3/8][/bold green] No platforms left to check variations on")
        return

    var_tasks = [
        _check_platform(client, var, p)
        for var in check_variations
        for p in check_platforms
    ]
    var_results = await asyncio.gather(*var_tasks)
    var_found = [r for r in var_results if r.exists]
    for vr in var_found:
        vr.status = "found (variation)"
        result.platforms.append(vr)

    console.print(
        f"  [bold green][3/8][/bold green] Done: "
        f"{len(check_variations)} variations x {len(check_platforms)} platforms, "
        f"{len(var_found)} new results"
    )


async def _phase_photo(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not cfg.photo:
        console.print("  [dim][4/8] Photo comparison: skipped[/dim]")
        return

    console.print("  [bold yellow][4/8][/bold yellow] Comparing profile photos...")
    avatars = _extract_avatar_urls(result.found_platforms)
    if len(avatars) < 2:
        console.print(
            "  [bold green][4/8][/bold green] Not enough profile photos (need at least 2)"
        )
        return

    photo_results = await compare_profile_photos(client, avatars)
    result.photo_matches = [
        PhotoMatch(
            platform_a=m["platform_a"],
            platform_b=m["platform_b"],
            similarity=m["similarity"],
            method=m["method"],
        )
        for m in photo_results
    ]
    console.print(
        f"  [bold green][4/8][/bold green] Done: "
        f"{len(avatars)} photos checked, {len(photo_results)} matches found"
    )


async def _phase_email_breach(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.email:
        console.print("  [dim][5/8] Email discovery: skipped[/dim]")
        return

    console.print("  [bold yellow][5/8][/bold yellow] Discovering emails...")
    known_emails = [
        e
        for r in platform_results
        if r.profile_data
        for e in [r.profile_data.get("email")]
        if e and isinstance(e, str) and "@" in e
    ]

    email_results = await discover_emails(client, cfg.username, known_emails)

    if cfg.breach and breach_check_available():
        label = "HIBP + XposedOrNot" if hibp_available() else "XposedOrNot (free)"
        console.print(f"  [bold yellow][5/8][/bold yellow] Breach check: {label}...")
        # Collect every unique email once, look them up in parallel.
        unique_emails = list({er.email for er in email_results} | set(known_emails))
        breach_map = await check_many_emails(client, unique_emails)
        for er in email_results:
            er.breaches = breach_map.get(er.email, [])
            er.breach_count = len(er.breaches)
        # Add known emails not already present in email_results if they have breaches.
        seen = {er.email for er in email_results}
        for known in known_emails:
            if known in seen:
                continue
            breaches = breach_map.get(known, [])
            if breaches:
                email_results.append(
                    EmailResult(
                        email=known,
                        source="profile",
                        verified=True,
                        breach_count=len(breaches),
                        breaches=breaches,
                    )
                )

    result.emails = email_results
    console.print(
        f"  [bold green][5/8][/bold green] Done: {len(email_results)} emails found"
    )

    # COMB leak lookup: piggyback on the breach phase. Runs when --breach is on.
    if cfg.breach:
        queries = list({cfg.username} | {er.email for er in email_results})
        console.print(
            f"  [bold yellow][5/8][/bold yellow] COMB leak search ({len(queries)} queries)..."
        )
        comb_map = await search_comb_many(client, queries)
        all_leaks = [leak for leaks in comb_map.values() for leak in leaks]
        # Dedupe by (identifier, preview) pair.
        seen_pairs: set[tuple[str, str]] = set()
        unique: list = []
        for leak in all_leaks:
            key = (leak.identifier.lower(), leak.password_preview)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            unique.append(leak)
        result.comb_leaks = unique
        console.print(
            f"  [bold green][5/8][/bold green] COMB: {len(unique)} unique credential leaks"
        )

    # Holehe: pivot each discovered email into ~120 registration checks.
    if cfg.holehe and holehe_available():
        target_emails = list({er.email for er in result.emails})
        if target_emails:
            console.print(
                f"  [bold yellow][5/8][/bold yellow] Holehe: "
                f"{len(target_emails)} email(s) x {holehe_module_count()} sites..."
            )
            holehe_map = await holehe_check_emails(target_emails)
            all_hits = [h for hits in holehe_map.values() for h in hits]
            result.holehe_hits = all_hits
            console.print(
                f"  [bold green][5/8][/bold green] Holehe: {len(all_hits)} registered accounts"
            )
    elif cfg.holehe and not holehe_available():
        console.print(
            "  [dim][5/8] Holehe: skipped (install the 'holehe' extra to enable)[/dim]"
        )

    # GHunt: only when enabled AND the user has logged in once via `ghunt login`.
    if cfg.ghunt and ghunt_available():
        target_emails = list({er.email for er in result.emails})
        if target_emails:
            console.print(
                f"  [bold yellow][5/8][/bold yellow] GHunt: "
                f"{len(target_emails)} email(s) → Google account lookup..."
            )
            ghunt_map = await ghunt_lookup_emails(target_emails)
            result.ghunt_results = list(ghunt_map.values())
            console.print(
                f"  [bold green][5/8][/bold green] GHunt: {len(result.ghunt_results)} Google accounts resolved"
            )
    elif cfg.ghunt and not ghunt_available():
        console.print(
            "  [dim][5/8] GHunt: skipped (run 'ghunt login' once to enable)[/dim]"
        )

    # Toutatis: pivots on the original username + any pivoted handles.
    if cfg.toutatis and toutatis_available():
        ig_handles = list({cfg.username, *result.discovered_usernames})
        console.print(
            f"  [bold yellow][5/8][/bold yellow] Toutatis: "
            f"{len(ig_handles)} Instagram handle(s)..."
        )
        tout_map = await toutatis_lookup_usernames(ig_handles)
        result.toutatis_results = list(tout_map.values())
        console.print(
            f"  [bold green][5/8][/bold green] Toutatis: {len(result.toutatis_results)} IG profiles"
        )
    elif cfg.toutatis and not toutatis_available():
        console.print(
            "  [dim][5/8] Toutatis: skipped (install the 'toutatis' extra to enable)[/dim]"
        )


async def _phase_web_presence(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.web:
        console.print("  [dim][6/8] Web presence: skipped[/dim]")
        return
    console.print("  [bold yellow][6/8][/bold yellow] Investigating web presence...")
    found_urls = [r.url for r in platform_results if r.exists]
    result.web_presence = await discover_web_presence(client, cfg.username, found_urls)
    console.print(
        f"  [bold green][6/8][/bold green] Done: {len(result.web_presence)} web presence entries found"
    )


async def _phase_whois(cfg: ScanConfig, result: ScanResult) -> None:
    if not cfg.whois:
        console.print("  [dim][7/8] WHOIS: skipped[/dim]")
        return
    console.print("  [bold yellow][7/8][/bold yellow] Running WHOIS lookups...")
    result.whois_records = await check_username_domains(cfg.username)
    console.print(
        f"  [bold green][7/8][/bold green] Done: {len(result.whois_records)} registered domains"
    )


async def _phase_dns_subdomain(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not (cfg.dns or cfg.subdomain):
        console.print("  [dim][8/8] DNS/subdomain: skipped[/dim]")
        return

    console.print("  [bold yellow][8/8][/bold yellow] DNS / subdomain scan...")
    domains_to_check = [r["domain"] for r in result.whois_records] or [f"{cfg.username}.com"]

    for domain in domains_to_check[:3]:
        if cfg.dns:
            records = await get_dns_records(domain)
            if records:
                result.dns_records[domain] = records
        if cfg.subdomain:
            subs = await enumerate_subdomains(client, domain)
            if subs:
                result.subdomains.extend(subs[:50])

    console.print(
        f"  [bold green][8/8][/bold green] Done: "
        f"{len(result.dns_records)} DNS, {len(result.subdomains)} subdomains"
    )


async def _phase_recursive(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    result: ScanResult,
) -> None:
    """Feed freshly-discovered usernames back into the platform sweep.

    Bounded by ``cfg.recursive_depth``. On each pass we:
      * gather new candidate usernames from profile data and discovered_usernames
      * skip anything already seen (the original target and prior passes)
      * run the full platform check for each candidate, sequentially per pass
      * merge hits into ``result.platforms`` with a status marking the pivot

    This is the Maigret-style pivot loop, implemented natively so we keep the
    FP filter, deep scrape, and profile_extract pipeline on the new hits.
    """
    if not cfg.recursive or cfg.recursive_depth <= 0:
        return

    seen: set[str] = {cfg.username.lower()}
    queue: list[str] = []

    def _harvest() -> None:
        for r in result.platforms:
            if not r.exists or not r.profile_data:
                continue
            for key in ("username", "nickname", "screen_name", "login"):
                val = r.profile_data.get(key)
                if isinstance(val, str) and val and val.lower() not in seen:
                    seen.add(val.lower())
                    queue.append(val)
        for u in result.discovered_usernames:
            if isinstance(u, str) and u and u.lower() not in seen:
                seen.add(u.lower())
                queue.append(u)

    _harvest()
    if not queue:
        return

    total_new = 0
    for depth in range(cfg.recursive_depth):
        if not queue:
            break
        pass_queue = list(queue)
        queue.clear()
        console.print(
            f"  [bold yellow][+][/bold yellow] Recursive pass {depth + 1}/"
            f"{cfg.recursive_depth}: probing {len(pass_queue)} pivoted username(s)"
        )
        for candidate in pass_queue:
            tasks = [_check_platform(client, candidate, p) for p in platforms]
            new_results = await asyncio.gather(*tasks)
            for r in new_results:
                if (
                    r.exists
                    and r.platform not in DEEP_SCRAPERS
                    and r.confidence < cfg.fp_threshold
                ):
                    r.exists = False
                    r.status = "low_confidence"
                if r.exists:
                    r.status = f"found (pivot:{candidate})"
                    result.platforms.append(r)
                    total_new += 1
        _harvest()

    console.print(
        f"  [bold green][+][/bold green] Recursive: {total_new} additional profiles"
    )


def _finalize_cross_reference(result: ScanResult) -> None:
    found = [r for r in result.platforms if r.exists]
    cr = cross_reference(found)
    cr.matched_photos = [
        f"{m.platform_a} ↔ {m.platform_b} ({m.similarity:.0%}, {m.method})"
        for m in result.photo_matches
    ]
    if result.photo_matches:
        cr.confidence = min(100.0, cr.confidence + 20.0 * len(result.photo_matches))
        cr.notes.append(f"{len(result.photo_matches)} profile photos matched")
    result.cross_reference = cr


# ── Public entrypoint ────────────────────────────────────────────────────


async def run_scan(cfg: ScanConfig) -> ScanResult:
    """Run an OSINT scan based on the provided immutable configuration."""
    start_time = time.monotonic()
    result = ScanResult(username=cfg.username)
    platforms = _select_platforms(cfg.categories)

    async with HTTPClient(
        proxy=cfg.proxy, tor=cfg.tor, request_timeout=cfg.request_timeout
    ) as client:
        if cfg.breach and not hibp_available():
            console.print(
                "  [yellow]Warning:[/yellow] [bold]HIBP_API_KEY[/bold] not set; breach check will be skipped."
            )

        platform_results = await _phase_platform_check(client, cfg, platforms, result)
        await _phase_deep_scrape(client, cfg, platform_results)
        await _phase_smart_search(client, cfg, platforms, platform_results, result)
        await _phase_photo(client, cfg, result)
        await _phase_email_breach(client, cfg, platform_results, result)
        await _phase_web_presence(client, cfg, platform_results, result)
        await _phase_whois(cfg, result)
        await _phase_dns_subdomain(client, cfg, result)
        await _phase_recursive(client, cfg, platforms, result)

    _finalize_cross_reference(result)
    result.scan_time = time.monotonic() - start_time
    return result


# ── Backwards-compatible wrapper ─────────────────────────────────────────


async def scan(
    username: str,
    deep: bool = True,
    smart: bool = False,
    email: bool = False,
    web: bool = False,
    whois_check: bool = False,
    breach: bool = False,
    photo: bool = False,
    dns: bool = False,
    subdomain: bool = False,
    proxy: str | None = None,
    tor: bool = False,
    categories: list[str] | None = None,
) -> ScanResult:
    cfg = ScanConfig(
        username=username,
        deep=deep,
        smart=smart,
        email=email,
        web=web,
        whois=whois_check,
        breach=breach,
        photo=photo,
        dns=dns,
        subdomain=subdomain,
        proxy=proxy,
        tor=tor,
        categories=tuple(categories) if categories else None,
    )
    return await run_scan(cfg)

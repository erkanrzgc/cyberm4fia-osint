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
from modules.breach_check import check_many_emails, hibp_available
from modules.deep_scrapers import DEEP_SCRAPERS
from modules.dns_lookup import enumerate_subdomains, get_dns_records
from modules.email_discovery import discover_emails
from modules.photo_compare import compare_profile_photos
from modules.platforms import PLATFORMS, Platform
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
    console.print("  [bold yellow][1/8][/bold yellow] Platform taramasi baslatiliyor...")
    tasks = [_check_platform(client, cfg.username, p) for p in platforms]
    platform_results = await asyncio.gather(*tasks)
    found_count = sum(1 for r in platform_results if r.exists)
    console.print(
        f"  [bold green][1/8][/bold green] Tamamlandi: "
        f"[green]{found_count}[/green]/{len(platform_results)} platformda bulundu"
    )
    result.platforms = list(platform_results)
    return platform_results


async def _phase_deep_scrape(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
) -> None:
    if not cfg.deep:
        console.print("  [dim][2/8] Derin tarama: Atlanildi[/dim]")
        return

    targets = [
        r for r in platform_results if r.exists and r.platform in DEEP_SCRAPERS
    ]
    if not targets:
        console.print("  [bold green][2/8][/bold green] Derin tarama: Uygun profil yok")
        return

    console.print(
        f"  [bold yellow][2/8][/bold yellow] Derin tarama: {len(targets)} profil analiz ediliyor..."
    )
    deep_results = await asyncio.gather(
        *(_deep_scrape(client, cfg.username, r) for r in targets)
    )
    for target, data in zip(targets, deep_results, strict=True):
        if data:
            target.profile_data = data

    scraped = sum(1 for d in deep_results if d)
    console.print(f"  [bold green][2/8][/bold green] Tamamlandi: {scraped} profil detayi cekildi")


async def _phase_smart_search(
    client: HTTPClient,
    cfg: ScanConfig,
    platforms: list[Platform],
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.smart:
        console.print("  [dim][3/8] Akilli arama: Atlanildi[/dim]")
        return

    console.print("  [bold yellow][3/8][/bold yellow] Akilli arama baslatiliyor...")

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
        console.print("  [bold green][3/8][/bold green] Tamamlandi")
        return

    important = [p for p in not_found_platforms if p.name in IMPORTANT_PLATFORMS_FOR_VARIATIONS]
    check_platforms = important[:8]
    check_variations = variations[:5]
    if not check_platforms:
        console.print("  [bold green][3/8][/bold green] Varyasyon kontrol edilecek platform yok")
        return

    var_tasks = [
        _check_platform(client, var, p)
        for var in check_variations
        for p in check_platforms
    ]
    var_results = await asyncio.gather(*var_tasks)
    var_found = [r for r in var_results if r.exists]
    for vr in var_found:
        vr.status = "found (varyasyon)"
        result.platforms.append(vr)

    console.print(
        f"  [bold green][3/8][/bold green] Tamamlandi: "
        f"{len(check_variations)} varyasyon x {len(check_platforms)} platform, "
        f"{len(var_found)} yeni sonuc"
    )


async def _phase_photo(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not cfg.photo:
        console.print("  [dim][4/8] Foto karsilastirma: Atlanildi[/dim]")
        return

    console.print("  [bold yellow][4/8][/bold yellow] Profil fotograflari karsilastiriliyor...")
    avatars = _extract_avatar_urls(result.found_platforms)
    if len(avatars) < 2:
        console.print(
            "  [bold green][4/8][/bold green] Yeterli profil fotografi yok (en az 2 gerekli)"
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
        f"  [bold green][4/8][/bold green] Tamamlandi: "
        f"{len(avatars)} foto kontrol edildi, {len(photo_results)} eslesme bulundu"
    )


async def _phase_email_breach(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.email:
        console.print("  [dim][5/8] Email kesfetme: Atlanildi[/dim]")
        return

    console.print("  [bold yellow][5/8][/bold yellow] Email kesfediliyor...")
    known_emails = [
        e
        for r in platform_results
        if r.profile_data
        for e in [r.profile_data.get("email")]
        if e and isinstance(e, str) and "@" in e
    ]

    email_results = await discover_emails(client, cfg.username, known_emails)

    if cfg.breach and hibp_available():
        console.print("  [bold yellow][5/8][/bold yellow] HIBP breach kontrolu...")
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
    elif cfg.breach:
        console.print(
            "  [dim][5/8] HIBP breach kontrolu: HIBP_API_KEY olmadigi icin atlanildi[/dim]"
        )

    result.emails = email_results
    console.print(
        f"  [bold green][5/8][/bold green] Tamamlandi: {len(email_results)} email bulundu"
    )


async def _phase_web_presence(
    client: HTTPClient,
    cfg: ScanConfig,
    platform_results: list[PlatformResult],
    result: ScanResult,
) -> None:
    if not cfg.web:
        console.print("  [dim][6/8] Web varligi: Atlanildi[/dim]")
        return
    console.print("  [bold yellow][6/8][/bold yellow] Web varligi arastiriliyor...")
    found_urls = [r.url for r in platform_results if r.exists]
    result.web_presence = await discover_web_presence(client, cfg.username, found_urls)
    console.print(
        f"  [bold green][6/8][/bold green] Tamamlandi: {len(result.web_presence)} web varligi bulundu"
    )


async def _phase_whois(cfg: ScanConfig, result: ScanResult) -> None:
    if not cfg.whois:
        console.print("  [dim][7/8] WHOIS: Atlanildi[/dim]")
        return
    console.print("  [bold yellow][7/8][/bold yellow] WHOIS sorgulari...")
    result.whois_records = await check_username_domains(cfg.username)
    console.print(
        f"  [bold green][7/8][/bold green] Tamamlandi: {len(result.whois_records)} kayitli domain"
    )


async def _phase_dns_subdomain(
    client: HTTPClient, cfg: ScanConfig, result: ScanResult
) -> None:
    if not (cfg.dns or cfg.subdomain):
        console.print("  [dim][8/8] DNS/subdomain: Atlanildi[/dim]")
        return

    console.print("  [bold yellow][8/8][/bold yellow] DNS / subdomain taramasi...")
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
        f"  [bold green][8/8][/bold green] Tamamlandi: "
        f"{len(result.dns_records)} DNS, {len(result.subdomains)} subdomain"
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
        cr.notes.append(f"{len(result.photo_matches)} profil fotografi eslesti")
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
                "  [yellow]Uyari:[/yellow] [bold]HIBP_API_KEY[/bold] tanimli degil; breach kontrolu atlanacak."
            )

        platform_results = await _phase_platform_check(client, cfg, platforms, result)
        await _phase_deep_scrape(client, cfg, platform_results)
        await _phase_smart_search(client, cfg, platforms, platform_results, result)
        await _phase_photo(client, cfg, result)
        await _phase_email_breach(client, cfg, platform_results, result)
        await _phase_web_presence(client, cfg, platform_results, result)
        await _phase_whois(cfg, result)
        await _phase_dns_subdomain(client, cfg, result)

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

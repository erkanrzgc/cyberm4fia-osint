#!/usr/bin/env python3
"""CyberM4fia OSINT — Public intelligence gathering framework entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from core import watchlist
from core.bulk import load_usernames_from_file, run_bulk
from core.config import ScanConfig
from core.engine import run_scan
from core.graph_export import export_dot
from core.history import diff_entries, get_latest, list_scans, save_scan
from core.logging_setup import configure_logging, get_logger
from core.plugins import load_plugins
from core.reporter import (
    console,
    export_html,
    export_json,
    export_misp,
    export_obsidian,
    export_pdf,
    export_stix,
    pdf_available,
    print_banner,
    print_results,
    print_scan_start,
)
from modules.platforms import get_platform_count
from utils.helpers import sanitize_username

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberm4fia-osint",
        description="OSINT intelligence gathering tool",
    )
    p.add_argument(
        "username",
        nargs="?",
        default=None,
        help="Username to search for (optional when using --watchlist-* or --bulk)",
    )
    p.add_argument(
        "--smart", "-s", action="store_true",
        help="Smart search: username variations + discovered accounts",
    )
    p.add_argument(
        "--deep", "-d", action="store_true", default=True,
        help="Deep profile scraping (default: on)",
    )
    p.add_argument("--no-deep", action="store_true", help="Disable deep profile scraping")
    p.add_argument("--email", "-e", action="store_true", help="Email discovery and Gravatar check")
    p.add_argument("--web", "-w", action="store_true", help="Web presence scan")
    p.add_argument(
        "--full", "-f", action="store_true",
        help="Full scan (default: already on). Kept for backward compatibility.",
    )
    p.add_argument(
        "--quick", "-q", action="store_true",
        help="Quick mode: platform sweep only (disables default full scan)",
    )
    p.add_argument(
        "--category", "-c", type=str, default=None,
        help="Restrict to specific categories (example: social,dev,gaming)",
    )
    p.add_argument("--whois", action="store_true", help="WHOIS lookups (9 TLDs)")
    p.add_argument(
        "--breach", "--hibp", dest="breach", action="store_true",
        help="HIBP breach check (enables email discovery; HIBP_API_KEY required)",
    )
    p.add_argument("--photo", action="store_true", help="Profile photo comparison")
    p.add_argument("--dns", action="store_true", help="DNS record lookup")
    p.add_argument("--subdomain", action="store_true", help="Subdomain enumeration (crt.sh)")
    p.add_argument(
        "--holehe", action="store_true",
        help="Probe ~120 sites for each discovered email (requires holehe extra)",
    )
    p.add_argument(
        "--ghunt", action="store_true",
        help="Resolve Google account from each email (requires `ghunt login` once)",
    )
    p.add_argument(
        "--toutatis", action="store_true",
        help="Instagram OSINT lookup (set IG_SESSION_ID env for richer data)",
    )
    p.add_argument(
        "--recursive", action="store_true",
        help="Feed discovered usernames back into the platform sweep",
    )
    p.add_argument(
        "--recursive-depth", dest="recursive_depth", type=int, default=1,
        help="How many recursion passes to run (default 1)",
    )
    p.add_argument(
        "--tor", "-toor", action="store_true",
        help="Route through Tor (socks5://127.0.0.1:9050)",
    )
    p.add_argument("--proxy", type=str, default=None, help="Proxy address")
    p.add_argument(
        "--output", "-o", type=str, default=None,
        help="Save results (.json/.html/.pdf/.dot/.misp.json/.stix.json or dir ending with / for Obsidian vault)",
    )
    p.add_argument("--timeout", "-t", type=int, default=None, help="Request timeout (seconds)")
    p.add_argument(
        "--fp-threshold",
        dest="fp_threshold",
        type=float,
        default=None,
        help="Drop platform matches below this confidence score (default 0.45)",
    )
    p.add_argument(
        "--log-level", default=None,
        help="Diagnostic log level (DEBUG, INFO, WARNING, ERROR)",
    )
    p.add_argument(
        "--history", action="store_true",
        help="List prior scans for this username and exit",
    )
    p.add_argument(
        "--diff", action="store_true",
        help="Diff against the previous scan after running",
    )
    p.add_argument(
        "--no-history", action="store_true",
        help="Do not persist this scan to history",
    )
    p.add_argument(
        "--no-fingerprint",
        dest="no_fingerprint",
        action="store_true",
        help="Disable browser-consistent sec-ch-ua/sec-fetch fingerprint headers",
    )
    p.add_argument(
        "--new-circuit-every",
        dest="new_circuit_every",
        type=int,
        default=0,
        help="Rotate Tor circuit every N requests (requires --tor and stem)",
    )
    p.add_argument(
        "--tor-control-password",
        dest="tor_control_password",
        type=str,
        default=None,
        help="Password for the Tor control port (optional)",
    )
    p.add_argument(
        "--playwright",
        action="store_true",
        help="Force Playwright for every platform (default: only js_heavy ones)",
    )
    p.add_argument(
        "--screenshots",
        action="store_true",
        help="Save Playwright screenshots alongside the scan payload",
    )
    p.add_argument(
        "--screenshot-dir",
        dest="screenshot_dir",
        type=str,
        default=None,
        help="Directory to drop screenshots into (default: reports/screenshots/<user>)",
    )
    p.add_argument(
        "--geocode",
        action="store_true",
        help="Resolve discovered locations via Nominatim for the heatmap "
        "(cached locally; 1 req/s upstream rate limit)",
    )
    p.add_argument(
        "--passive",
        action="store_true",
        help="Run passive intel sources (Shodan/Censys/FOFA/ZoomEye/Pastebin/Ahmia/Wayback)",
    )
    p.add_argument(
        "--domain",
        dest="domain",
        type=str,
        default=None,
        help="Domain pivot for passive intel (e.g. example.com)",
    )
    p.add_argument(
        "--reverse-image",
        dest="reverse_image",
        action="store_true",
        help="Run reverse image search on discovered profile pictures (Yandex + TinEye)",
    )
    p.add_argument(
        "--past-usernames",
        dest="past_usernames",
        action="store_true",
        help="Discover historical usernames via Wayback CDX",
    )
    p.add_argument(
        "--phone",
        dest="phone",
        type=str,
        default=None,
        help="Phone number to enrich (E.164 preferred, e.g. +14155552671)",
    )
    p.add_argument(
        "--phone-region",
        dest="phone_region",
        type=str,
        default=None,
        help="Default ISO region for --phone (e.g. US, TR) when not E.164",
    )
    p.add_argument(
        "--crypto",
        dest="crypto",
        type=str,
        default=None,
        help="Comma-separated BTC/ETH addresses to enrich",
    )
    p.add_argument(
        "--serve", action="store_true",
        help="Start the FastAPI REST server (requires fastapi + uvicorn)",
    )
    p.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="Bind host for --serve (default 127.0.0.1)",
    )
    p.add_argument(
        "--port", type=int, default=8000,
        help="Bind port for --serve (default 8000)",
    )
    p.add_argument(
        "--correlate",
        dest="correlate",
        type=str,
        default=None,
        metavar="USER_A,USER_B",
        help="Score how likely two usernames are the same person "
             "(uses the latest scan history for each). Exits after printing.",
    )
    p.add_argument(
        "--compare",
        dest="compare",
        type=str,
        default=None,
        metavar="USER_A,USER_B",
        help="Side-by-side diff of two scans (latest for each user). "
             "Exits after printing the change summary.",
    )
    p.add_argument(
        "--watchlist-add", dest="watchlist_add", type=str, default=None,
        help="Add a username to the watchlist and exit",
    )
    p.add_argument(
        "--watchlist-remove", dest="watchlist_remove", type=str, default=None,
        help="Remove a username from the watchlist and exit",
    )
    p.add_argument(
        "--watchlist-list", dest="watchlist_list", action="store_true",
        help="List watchlist entries and exit",
    )
    p.add_argument(
        "--watchlist-scan", dest="watchlist_scan", action="store_true",
        help="Run a scan for every username in the watchlist",
    )
    p.add_argument(
        "--bulk", dest="bulk", type=str, default=None,
        help="Path to a newline-delimited file of usernames to scan in bulk",
    )
    p.add_argument(
        "--bulk-parallel", dest="bulk_parallel", type=int, default=3,
        help="Concurrency cap for --bulk / --watchlist-scan (default 3)",
    )
    p.add_argument(
        "--no-enrichment",
        dest="no_enrichment",
        action="store_true",
        help="Skip offline enrichment (stylometry/language/timezone/entity graph)",
    )
    p.add_argument(
        "--schedule", dest="schedule", action="store_true",
        help="Run the scheduler: repeatedly scan every watchlist entry and fire notifications on diffs",
    )
    p.add_argument(
        "--schedule-interval", dest="schedule_interval", type=float, default=60.0,
        help="Minutes between scheduled passes (default 60)",
    )
    return p


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _show_history(username: str) -> None:
    entries = list_scans(username)
    if not entries:
        console.print(f"  [yellow]No saved scans for '{username}'.[/yellow]")
        return
    console.print(f"\n  [bold]Scan history for '{username}'[/bold] ({len(entries)})")
    for e in entries:
        console.print(f"    [cyan]#{e.id}[/cyan]  {_fmt_ts(e.ts)}  found: {e.found_count}")


def _run_ai_analysis(result) -> None:
    """Run AI analysis if a local LLM is available — skip silently if not."""
    try:
        from core.analysis import LLMAnalyzer, LLMUnavailable
    except ImportError:
        log.debug("AI module not importable — skipping")
        return
    try:
        analyzer = LLMAnalyzer.from_env()
    except LLMUnavailable:
        log.debug("no GGUF model configured — skipping AI analysis")
        return
    console.print("  [cyan]Running AI analysis (local LLM)...[/cyan]")
    try:
        report = analyzer.analyze(result.to_dict())
    except Exception as exc:  # noqa: BLE001
        log.warning("AI analysis failed: %s", exc)
        return
    result.ai_report = report.to_dict()


def _print_diff(username: str, result) -> None:
    current = get_latest(username)
    if current is None:
        console.print("  [dim]diff: no previous scan to compare against.[/dim]")
        return
    previous = get_latest(username, before_id=current.id)
    if previous is None:
        console.print("  [dim]diff: no previous scan to compare against.[/dim]")
        return
    d = diff_entries(previous, current)
    console.print(
        f"\n  [bold]Diff[/bold] #{previous.id} ({_fmt_ts(previous.ts)}) "
        f"-> #{current.id} ({_fmt_ts(current.ts)})"
    )
    if d.added:
        console.print("    [green]+ " + ", ".join(d.added) + "[/green]")
    if d.removed:
        console.print("    [red]- " + ", ".join(d.removed) + "[/red]")
    if not d.added and not d.removed:
        console.print("    [dim]no changes.[/dim]")


def _save_report(result, path: str) -> None:
    lower = path.lower()
    if lower.endswith(".json"):
        export_json(result, path)
    elif lower.endswith(".html"):
        export_html(result, path)
    elif lower.endswith(".dot"):
        export_dot(result, path)
    elif lower.endswith(".pdf"):
        if not pdf_available():
            console.print(
                "  [yellow]reportlab not installed; skipping PDF export.[/yellow]"
            )
            return
        export_pdf(result, path)
        console.print(f"  [green]PDF rapor kaydedildi:[/green] {path}")
    elif lower.endswith(".misp.json"):
        export_misp(result, path)
        console.print(f"  [green]MISP event kaydedildi:[/green] {path}")
    elif lower.endswith(".stix.json"):
        export_stix(result, path)
        console.print(f"  [green]STIX bundle kaydedildi:[/green] {path}")
    elif lower.endswith("/") or lower.endswith(".obsidian"):
        export_obsidian(result, path.rstrip("/"))
        console.print(f"  [green]Obsidian vault kaydedildi:[/green] {path}")
    else:
        export_json(result, path + ".json")


def _handle_watchlist_commands(args) -> bool:
    """Handle --watchlist-* commands. Returns True if one was executed."""
    if args.watchlist_add:
        entry = watchlist.add(args.watchlist_add)
        console.print(
            f"  [green]Added[/green] [bold]{entry.username}[/bold] to watchlist "
            f"(id={entry.id})"
        )
        return True
    if args.watchlist_remove:
        ok = watchlist.remove(args.watchlist_remove)
        color = "green" if ok else "yellow"
        verb = "Removed" if ok else "Not found"
        console.print(
            f"  [{color}]{verb}[/{color}] [bold]{args.watchlist_remove}[/bold]"
        )
        return True
    if args.watchlist_list:
        entries = watchlist.list_all()
        if not entries:
            console.print("  [yellow]Watchlist is empty.[/yellow]")
            return True
        console.print(f"\n  [bold]Watchlist[/bold] ({len(entries)} entries)")
        for e in entries:
            last = _fmt_ts(e.last_scan_at) if e.last_scan_at else "never"
            tag_str = ",".join(e.tags) if e.tags else "-"
            console.print(
                f"    [cyan]#{e.id}[/cyan] {e.username}  "
                f"added:{_fmt_ts(e.added_at)}  last:{last}  tags:{tag_str}"
            )
        return True
    return False


async def _run_bulk_mode(usernames: list[str], args, from_watchlist: bool) -> None:
    if not usernames:
        console.print("  [yellow]No usernames to scan.[/yellow]")
        return

    template_ns = argparse.Namespace(**vars(args))
    template_ns.username = usernames[0]
    cfg_template = ScanConfig.from_args(template_ns, usernames[0])

    print_banner()
    console.print(
        f"  [bold]Bulk scan[/bold]: {len(usernames)} targets, "
        f"parallel={args.bulk_parallel}"
    )

    results = await run_bulk(
        usernames, cfg_template, max_parallel=args.bulk_parallel
    )
    plugin_registry = load_plugins()

    for username, result in zip(usernames, results, strict=True):
        print_results(result)
        if not args.no_history:
            try:
                save_scan(result.to_dict(), ts=int(time.time()))
            except (OSError, ValueError) as exc:
                log.warning("history: save failed for %s: %s", username, exc)
        if from_watchlist:
            try:
                watchlist.mark_scanned(username)
            except Exception as exc:  # noqa: BLE001
                log.warning("watchlist mark_scanned failed: %s", exc)
        try:
            plugin_registry.run_post_scan(
                result, ScanConfig(username=username)
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin hooks failed for %s: %s", username, exc)

    console.print(
        f"\n  [bold green]Bulk complete[/bold green]: {len(results)} scans"
    )


def _run_correlate(spec: str) -> None:
    """Handle --correlate USER_A,USER_B: compare latest histories and print."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if len(parts) != 2:
        console.print(
            "  [red]--correlate expects exactly two usernames, "
            "comma-separated (e.g. --correlate alice,bob)[/red]"
        )
        sys.exit(2)
    a_user, b_user = parts
    if a_user.lower() == b_user.lower():
        console.print("  [red]--correlate: a and b must differ[/red]")
        sys.exit(2)

    from core.correlation import correlate
    from core.history import get_latest

    a_entry = get_latest(a_user)
    if a_entry is None:
        console.print(f"  [red]No scan history for {a_user} — run a scan first.[/red]")
        sys.exit(1)
    b_entry = get_latest(b_user)
    if b_entry is None:
        console.print(f"  [red]No scan history for {b_user} — run a scan first.[/red]")
        sys.exit(1)

    result = correlate(a_entry.payload, b_entry.payload)
    pct = int(round(result.score * 100))
    verdict_color = {
        "very_likely_same": "bright_green",
        "likely_same": "green",
        "possible": "yellow",
        "weak_signal": "yellow",
        "no_evidence": "red",
    }.get(result.verdict, "white")
    console.print(
        f"\n  [bold]{a_user}[/bold] vs [bold]{b_user}[/bold] — "
        f"[{verdict_color}]{pct}%[/{verdict_color}] "
        f"([{verdict_color}]{result.verdict}[/{verdict_color}])"
    )
    if not result.signals:
        console.print("  [dim]no shared signals[/dim]")
        return
    for sig in result.signals:
        console.print(
            f"    [cyan]{sig.kind:<9}[/cyan] +{int(round(sig.weight * 100)):>3}%  {sig.detail}"
        )


def _run_compare(spec: str) -> None:
    """Handle --compare USER_A,USER_B: deep-diff latest scans and print summary."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if len(parts) != 2:
        console.print(
            "  [red]--compare expects exactly two usernames, "
            "comma-separated (e.g. --compare alice,bob)[/red]"
        )
        sys.exit(2)
    a_user, b_user = parts

    from core.compare import compare_payloads
    from core.history import get_latest

    a_entry = get_latest(a_user)
    if a_entry is None:
        console.print(f"  [red]No scan history for {a_user} — run a scan first.[/red]")
        sys.exit(1)
    b_entry = get_latest(b_user)
    if b_entry is None:
        console.print(f"  [red]No scan history for {b_user} — run a scan first.[/red]")
        sys.exit(1)

    diff = compare_payloads(a_entry.payload, b_entry.payload)
    delta = diff.found_count_delta
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    console.print(
        f"\n  [bold]{a_user}[/bold] (#{a_entry.id}, {_fmt_ts(a_entry.ts)})  →  "
        f"[bold]{b_user}[/bold] (#{b_entry.id}, {_fmt_ts(b_entry.ts)})"
    )
    console.print(f"  [dim]{diff.summary}[/dim]  found_count Δ {delta_str}")

    buckets = [
        ("platforms", diff.platforms),
        ("emails", diff.emails),
        ("breaches", diff.breaches),
        ("phones", diff.phones),
        ("crypto", diff.crypto),
        ("geo", diff.geo),
    ]
    for title, bucket in buckets:
        if not bucket.added and not bucket.removed:
            continue
        console.print(f"\n  [bold]{title}[/bold]")
        for item in bucket.added:
            console.print(f"    [green]+ {item}[/green]")
        for item in bucket.removed:
            console.print(f"    [red]- {item}[/red]")

    if diff.platform_changes:
        console.print("\n  [bold]platform profile changes[/bold]")
        for pc in diff.platform_changes:
            console.print(f"    [cyan]{pc.platform}[/cyan]")
            for fc in pc.changes:
                console.print(
                    f"      {fc.field}: [red]{fc.old!r}[/red] → [green]{fc.new!r}[/green]"
                )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)

    if args.serve:
        from core.api import is_available as api_available
        if not api_available():
            console.print(
                "  [red]--serve requires 'fastapi' and 'uvicorn'. "
                "Install with: pip install fastapi uvicorn[/red]"
            )
            sys.exit(1)
        from core.api.server import serve
        console.print(
            f"  [cyan]Starting API on http://{args.host}:{args.port}[/cyan]"
        )
        serve(host=args.host, port=args.port)
        return

    if args.schedule:
        from core.scheduler import run_forever
        from core.notify import build_default_notifiers

        cfg_template = ScanConfig.from_args(args, username="")
        sinks = build_default_notifiers()
        sink_names = ", ".join(n.name for n in sinks) if sinks else "none"
        console.print(
            f"  [cyan]Scheduler running[/cyan] — interval={args.schedule_interval:.1f} min, "
            f"notifiers=[{sink_names}]"
        )
        try:
            asyncio.run(
                run_forever(
                    cfg_template,
                    interval_minutes=args.schedule_interval,
                    notifiers=sinks,
                )
            )
        except KeyboardInterrupt:
            console.print("  [yellow]Scheduler stopped.[/yellow]")
        return

    if args.correlate:
        _run_correlate(args.correlate)
        return

    if args.compare:
        _run_compare(args.compare)
        return

    if _handle_watchlist_commands(args):
        return

    if args.watchlist_scan:
        usernames = [e.username for e in watchlist.list_all()]
        asyncio.run(_run_bulk_mode(usernames, args, from_watchlist=True))
        return

    if args.bulk:
        usernames = load_usernames_from_file(args.bulk)
        asyncio.run(_run_bulk_mode(usernames, args, from_watchlist=False))
        return

    if args.username is None:
        console.print("[red]Error: please provide a valid username.[/red]")
        sys.exit(1)

    username = sanitize_username(args.username)
    if not username:
        console.print("[red]Error: please provide a valid username.[/red]")
        sys.exit(1)

    if args.history:
        _show_history(username)
        return

    cfg = ScanConfig.from_args(args, username)

    if cfg.breach and not args.email and not args.full:
        console.print(
            "  [yellow]Warning:[/yellow] [bold]--breach[/bold] selected; "
            "email discovery has been auto-enabled."
        )

    mode_str = " + ".join(cfg.mode_parts()) or "Basic"
    print_banner()
    print_scan_start(username, mode_str, get_platform_count())

    try:
        result = asyncio.run(run_scan(cfg))
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Scan cancelled.[/yellow]")
        sys.exit(0)

    _run_ai_analysis(result)

    print_results(result)

    if not args.no_history:
        try:
            save_scan(result.to_dict(), ts=int(time.time()))
        except (OSError, ValueError) as exc:
            log.warning("history: save failed: %s", exc)

    if args.diff:
        _print_diff(username, result)

    if args.output:
        _save_report(result, args.output)

    try:
        plugin_registry = load_plugins()
        plugin_registry.run_post_scan(result, cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("plugin hooks failed: %s", exc)


if __name__ == "__main__":
    main()

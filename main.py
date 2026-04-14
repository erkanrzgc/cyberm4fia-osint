#!/usr/bin/env python3
"""CyberM4fia OSINT — Public intelligence gathering framework entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from core.config import ScanConfig
from core.engine import run_scan
from core.graph_export import export_dot
from core.history import diff_entries, get_latest, list_scans, save_scan
from core.logging_setup import configure_logging, get_logger
from core.reporter import (
    console,
    export_html,
    export_json,
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
        description="OSINT istihbarat toplama araci",
    )
    p.add_argument("username", help="Aranacak kullanici adi")
    p.add_argument(
        "--smart", "-s", action="store_true",
        help="Akilli arama: username varyasyonlari + kesfedilen hesaplar",
    )
    p.add_argument(
        "--deep", "-d", action="store_true", default=True,
        help="Derin profil taramasi (varsayilan: acik)",
    )
    p.add_argument("--no-deep", action="store_true", help="Derin profil taramasini kapat")
    p.add_argument("--email", "-e", action="store_true", help="Email kesfetme ve Gravatar kontrolu")
    p.add_argument("--web", "-w", action="store_true", help="Web varligi taramasi")
    p.add_argument(
        "--full", "-f", action="store_true",
        help="Tam tarama: deep + smart + email + web + whois + breach + photo + dns + subdomain",
    )
    p.add_argument(
        "--category", "-c", type=str, default=None,
        help="Sadece belirli kategoriler (ornek: social,dev,gaming)",
    )
    p.add_argument("--whois", action="store_true", help="WHOIS sorgulari (9 TLD)")
    p.add_argument(
        "--breach", "--hibp", dest="breach", action="store_true",
        help="HIBP breach kontrolu (email taramasini etkinlestirir, HIBP_API_KEY gerekli)",
    )
    p.add_argument("--photo", action="store_true", help="Profil fotograf karsilastirma")
    p.add_argument("--dns", action="store_true", help="DNS kayit sorgusu")
    p.add_argument("--subdomain", action="store_true", help="Subdomain enumeration (crt.sh)")
    p.add_argument(
        "--tor", "-toor", action="store_true",
        help="Tor uzerinden tara (socks5://127.0.0.1:9050)",
    )
    p.add_argument("--proxy", type=str, default=None, help="Proxy adresi")
    p.add_argument(
        "--output", "-o", type=str, default=None,
        help="Sonuclari dosyaya kaydet (.json veya .html)",
    )
    p.add_argument("--timeout", "-t", type=int, default=None, help="Istek zaman asimi (saniye)")
    p.add_argument(
        "--log-level", default=None,
        help="Diagnostik log seviyesi (DEBUG, INFO, WARNING, ERROR)",
    )
    p.add_argument(
        "--history", action="store_true",
        help="Bu kullanici icin onceki taramalari listele ve cik",
    )
    p.add_argument(
        "--diff", action="store_true",
        help="Taramadan sonra onceki sonucla karsilastir",
    )
    p.add_argument(
        "--no-history", action="store_true",
        help="Bu taramayi gecmise kaydetme",
    )
    return p


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _show_history(username: str) -> None:
    entries = list_scans(username)
    if not entries:
        console.print(f"  [yellow]'{username}' icin kayitli tarama yok.[/yellow]")
        return
    console.print(f"\n  [bold]'{username}' tarama gecmisi[/bold] ({len(entries)})")
    for e in entries:
        console.print(f"    [cyan]#{e.id}[/cyan]  {_fmt_ts(e.ts)}  bulunan: {e.found_count}")


def _print_diff(username: str, result) -> None:
    current = get_latest(username)
    if current is None:
        console.print("  [dim]diff: karsilastirma icin onceki tarama yok.[/dim]")
        return
    previous = get_latest(username, before_id=current.id)
    if previous is None:
        console.print("  [dim]diff: karsilastirma icin onceki tarama yok.[/dim]")
        return
    d = diff_entries(previous, current)
    console.print(
        f"\n  [bold]Fark[/bold] #{previous.id} ({_fmt_ts(previous.ts)}) "
        f"-> #{current.id} ({_fmt_ts(current.ts)})"
    )
    if d.added:
        console.print("    [green]+ " + ", ".join(d.added) + "[/green]")
    if d.removed:
        console.print("    [red]- " + ", ".join(d.removed) + "[/red]")
    if not d.added and not d.removed:
        console.print("    [dim]degisiklik yok.[/dim]")


def _save_report(result, path: str) -> None:
    if path.endswith(".json"):
        export_json(result, path)
    elif path.endswith(".html"):
        export_html(result, path)
    elif path.endswith(".dot"):
        export_dot(result, path)
    else:
        export_json(result, path + ".json")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)

    username = sanitize_username(args.username)
    if not username:
        console.print("[red]Hata: Gecerli bir kullanici adi girin.[/red]")
        sys.exit(1)

    if args.history:
        _show_history(username)
        return

    cfg = ScanConfig.from_args(args, username)

    if cfg.breach and not args.email and not args.full:
        console.print(
            "  [yellow]Uyari:[/yellow] [bold]--breach[/bold] secildi; "
            "email kesfetme otomatik etkinlestirildi."
        )

    mode_str = " + ".join(cfg.mode_parts()) or "Temel"
    print_banner()
    print_scan_start(username, mode_str, get_platform_count())

    try:
        result = asyncio.run(run_scan(cfg))
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Tarama iptal edildi.[/yellow]")
        sys.exit(0)

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


if __name__ == "__main__":
    main()

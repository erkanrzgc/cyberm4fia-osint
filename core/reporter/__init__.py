"""Reporter package — console UI and file exports.

Public API kept flat so callers can keep using
``from core.reporter import console, print_results, export_json, export_html``.
"""

from core.reporter.console_ui import (
    console,
    print_banner,
    print_progress,
    print_results,
    print_scan_start,
)
from core.reporter.html_export import export_html
from core.reporter.json_export import export_json

__all__ = [
    "console",
    "export_html",
    "export_json",
    "print_banner",
    "print_progress",
    "print_results",
    "print_scan_start",
]

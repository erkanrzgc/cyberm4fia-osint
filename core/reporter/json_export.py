"""JSON export for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from core.models import ScanResult
from core.reporter.console_ui import console


def export_json(result: ScanResult, filepath: str) -> None:
    data = result.to_dict()
    data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    console.print(f"\n  [green]JSON rapor kaydedildi:[/green] {filepath}")

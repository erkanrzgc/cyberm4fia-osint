"""HTML export with strict escaping and a small template helper.

All user-controlled values are passed through ``html.escape`` before being
embedded in the rendered document to avoid reflected XSS when reports are
shared.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from core.models import ScanResult
from core.reporter.console_ui import console
from core.reporter.html_style import HTML_STYLE


def _fmt(value: object) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(_fmt(v) for v in value if v not in (None, "", [], {})) or "-"
    if isinstance(value, dict):
        parts = [
            f"{escape(str(k))}: {_fmt(v)}"
            for k, v in value.items()
            if v not in (None, "", [], {})
        ]
        return ", ".join(parts) or "-"
    if value in (None, "", [], {}):
        return "-"
    return escape(str(value))


def _render_badges(values: list, class_name: str = "badge") -> str:
    if not values:
        return '<p class="muted">No data</p>'
    return "".join(f'<span class="{class_name}">{_fmt(value)}</span>' for value in values)


def _platforms_table(data: dict) -> str:
    rows = "".join(
        f"""
            <tr>
                <td>{index}</td>
                <td>{escape(p['platform'])}</td>
                <td>{escape(str(p['category']))}</td>
                <td><a href="{escape(p['url'])}" target="_blank" rel="noreferrer noopener">{escape(p['url'])}</a></td>
                <td>{escape(str(p['response_time']))}s</td>
                <td>{escape(str(p['status']))}</td>
            </tr>"""
        for index, p in enumerate((pf for pf in data["platforms"] if pf["exists"]), 1)
    )
    return f"""
    <h2>Profiles Found</h2>
    <table>
        <tr><th>#</th><th>Platform</th><th>Category</th><th>URL</th><th>Response</th><th>Status</th></tr>
        {rows}
    </table>"""


def _profile_sections(data: dict) -> str:
    sections = ""
    for p in data["platforms"]:
        if not (p["exists"] and p.get("profile_data")):
            continue
        items = "".join(
            f"<li><strong>{escape(str(k))}:</strong> {_fmt(v)}</li>"
            for k, v in p["profile_data"].items()
            if v not in (None, "", [], {})
        )
        if items:
            sections += f"""
            <div class="card">
                <h3>{escape(p['platform'])}</h3>
                <ul>{items}</ul>
            </div>"""
    return sections or '<p class="muted">No deep profile data.</p>'


def _cross_reference_block(data: dict) -> str:
    cr = data["cross_reference"]
    return f"""
    <h2>Cross-Reference</h2>
    <div class="grid grid-2">
        <div class="card metric-card">
            <div class="metric-label">Confidence Score</div>
            <div class="metric-value">{escape(str(cr['confidence']))}%</div>
        </div>
        <div class="card">
            <h3>Notes</h3>
            {_render_badges(cr['notes'])}
        </div>
        <div class="card">
            <h3>Matched Names</h3>
            {_render_badges(cr['matched_names'])}
        </div>
        <div class="card">
            <h3>Matched Locations</h3>
            {_render_badges(cr['matched_locations'])}
        </div>
        <div class="card card-full">
            <h3>Matched Photos</h3>
            {_render_badges(cr['matched_photos'])}
        </div>
    </div>"""


def _emails_block(data: dict) -> str:
    if not data["emails"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(e['email'])}</td>
            <td>{escape(e['source'])}</td>
            <td>{_fmt(e['verified'])}</td>
            <td>{_fmt(e['gravatar'])}</td>
            <td>{escape(str(e['breach_count']))}</td>
        </tr>"""
        for e in data["emails"]
    )
    return f"""
    <h2>Discovered Emails</h2>
    <table>
        <tr><th>Email</th><th>Source</th><th>Verified</th><th>Gravatar</th><th>Breaches</th></tr>
        {rows}
    </table>"""


def _photo_block(data: dict) -> str:
    if not data["photo_matches"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(m['platform_a'])}</td>
            <td>{escape(m['platform_b'])}</td>
            <td>{escape(str(m['similarity']))}</td>
            <td>{escape(m['method'])}</td>
        </tr>"""
        for m in data["photo_matches"]
    )
    return f"""
    <h2>Profile Photo Matches</h2>
    <table>
        <tr><th>Platform A</th><th>Platform B</th><th>Similarity</th><th>Method</th></tr>
        {rows}
    </table>"""


def _web_presence_block(data: dict) -> str:
    if not data["web_presence"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(str(entry.get('type', '-')))}</td>
            <td>{_fmt(entry)}</td>
        </tr>"""
        for entry in data["web_presence"]
    )
    return f"""
    <h2>Web Presence</h2>
    <table>
        <tr><th>Type</th><th>Detail</th></tr>
        {rows}
    </table>"""


def _whois_block(data: dict) -> str:
    if not data["whois_records"]:
        return ""
    rows = "".join(
        f"""
        <tr>
            <td>{escape(str(r.get('domain', '')))}</td>
            <td>{escape(str(r.get('registrar', '')))}</td>
            <td>{escape(str(r.get('creation_date', '')))}</td>
            <td>{escape(str(r.get('expiration_date', '')))}</td>
            <td>{escape(str(r.get('org', '')))}</td>
        </tr>"""
        for r in data["whois_records"]
    )
    return f"""
    <h2>WHOIS Records</h2>
    <table>
        <tr><th>Domain</th><th>Registrar</th><th>Created</th><th>Expires</th><th>Org</th></tr>
        {rows}
    </table>"""


def _dns_block(data: dict) -> str:
    if not data["dns_records"]:
        return ""
    cards = ""
    for domain, records in data["dns_records"].items():
        items = "".join(
            f"<li><strong>{escape(rtype)}:</strong> {_fmt(values)}</li>"
            for rtype, values in records.items()
            if values
        )
        cards += f"""
        <div class="card">
            <h3>{escape(domain)}</h3>
            <ul>{items or '<li>No records found</li>'}</ul>
        </div>"""
    return f"""
    <h2>DNS Records</h2>
    <div class="grid grid-2">{cards}</div>"""


def _subdomain_block(data: dict) -> str:
    if not data["subdomains"]:
        return ""
    return f"""
    <h2>Subdomains</h2>
    <div class="card">
        {_render_badges(sorted(set(data['subdomains'])))}
    </div>"""


def _variations_block(data: dict) -> str:
    if not (data["variations_checked"] or data["discovered_usernames"]):
        return ""
    return f"""
    <h2>Smart Search</h2>
    <div class="grid grid-2">
        <div class="card">
            <h3>Variations Checked</h3>
            {_render_badges(data['variations_checked'])}
        </div>
        <div class="card">
            <h3>Discovered Linked Accounts</h3>
            {_render_badges(data['discovered_usernames'])}
        </div>
    </div>"""


def render_html(data: dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
    <title>CyberM4fia OSINT - {escape(data['username'])}</title>
    <style>{HTML_STYLE}</style>
</head>
<body>
    <h1>CYBERM4FIA OSINT</h1>
    <p class="meta">Report: {escape(data['username'])} | {escape(data['exported_at'])}</p>

    <div class="summary">
        <p>Target: <span>{escape(data['username'])}</span></p>
        <p>Scanned: <span>{escape(str(data['total_checked']))}</span> platforms</p>
        <p>Found: <span>{escape(str(data['found_count']))}</span> profiles</p>
        <p>Duration: <span>{escape(str(data['scan_time']))}s</span></p>
    </div>

    {_platforms_table(data)}

    <h2>Profile Details</h2>
    {_profile_sections(data)}

    {_cross_reference_block(data)}
    {_emails_block(data)}
    {_photo_block(data)}
    {_web_presence_block(data)}
    {_whois_block(data)}
    {_dns_block(data)}
    {_subdomain_block(data)}
    {_variations_block(data)}
</body>
</html>"""


def export_html(result: ScanResult, filepath: str) -> None:
    data = result.to_dict()
    data["exported_at"] = datetime.now(tz=timezone.utc).isoformat()
    html = render_html(data)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    console.print(f"\n  [green]HTML report saved:[/green] {filepath}")

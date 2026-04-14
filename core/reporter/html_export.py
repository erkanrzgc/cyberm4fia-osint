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
        return "Evet" if value else "Hayir"
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
        return '<p class="muted">Veri yok</p>'
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
    <h2>Bulunan Profiller</h2>
    <table>
        <tr><th>#</th><th>Platform</th><th>Kategori</th><th>URL</th><th>Yanit</th><th>Durum</th></tr>
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
    return sections or '<p class="muted">Derin profil verisi yok.</p>'


def _cross_reference_block(data: dict) -> str:
    cr = data["cross_reference"]
    return f"""
    <h2>Capraz Referans</h2>
    <div class="grid grid-2">
        <div class="card metric-card">
            <div class="metric-label">Guven Skoru</div>
            <div class="metric-value">{escape(str(cr['confidence']))}%</div>
        </div>
        <div class="card">
            <h3>Notlar</h3>
            {_render_badges(cr['notes'])}
        </div>
        <div class="card">
            <h3>Eslesen Isimler</h3>
            {_render_badges(cr['matched_names'])}
        </div>
        <div class="card">
            <h3>Eslesen Konumlar</h3>
            {_render_badges(cr['matched_locations'])}
        </div>
        <div class="card card-full">
            <h3>Eslesen Fotograflar</h3>
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
    <h2>Bulunan Email'ler</h2>
    <table>
        <tr><th>Email</th><th>Kaynak</th><th>Dogrulanmis</th><th>Gravatar</th><th>Breach</th></tr>
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
    <h2>Profil Fotograf Eslesmeleri</h2>
    <table>
        <tr><th>Platform A</th><th>Platform B</th><th>Benzerlik</th><th>Yontem</th></tr>
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
    <h2>Web Varligi</h2>
    <table>
        <tr><th>Tur</th><th>Detay</th></tr>
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
    <h2>WHOIS Kayitlari</h2>
    <table>
        <tr><th>Domain</th><th>Kayitci</th><th>Olusturulma</th><th>Bitis</th><th>Org</th></tr>
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
            <ul>{items or '<li>Kayit bulunamadi</li>'}</ul>
        </div>"""
    return f"""
    <h2>DNS Kayitlari</h2>
    <div class="grid grid-2">{cards}</div>"""


def _subdomain_block(data: dict) -> str:
    if not data["subdomains"]:
        return ""
    return f"""
    <h2>Subdomain'ler</h2>
    <div class="card">
        {_render_badges(sorted(set(data['subdomains'])))}
    </div>"""


def _variations_block(data: dict) -> str:
    if not (data["variations_checked"] or data["discovered_usernames"]):
        return ""
    return f"""
    <h2>Akilli Arama</h2>
    <div class="grid grid-2">
        <div class="card">
            <h3>Kontrol Edilen Varyasyonlar</h3>
            {_render_badges(data['variations_checked'])}
        </div>
        <div class="card">
            <h3>Kesfedilen Bagli Hesaplar</h3>
            {_render_badges(data['discovered_usernames'])}
        </div>
    </div>"""


def render_html(data: dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
    <title>CyberM4fia OSINT - {escape(data['username'])}</title>
    <style>{HTML_STYLE}</style>
</head>
<body>
    <h1>CYBERM4FIA OSINT</h1>
    <p class="meta">Rapor: {escape(data['username'])} | {escape(data['exported_at'])}</p>

    <div class="summary">
        <p>Hedef: <span>{escape(data['username'])}</span></p>
        <p>Taranan: <span>{escape(str(data['total_checked']))}</span> platform</p>
        <p>Bulunan: <span>{escape(str(data['found_count']))}</span> profil</p>
        <p>Sure: <span>{escape(str(data['scan_time']))}s</span></p>
    </div>

    {_platforms_table(data)}

    <h2>Profil Detaylari</h2>
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
    console.print(f"\n  [green]HTML rapor kaydedildi:[/green] {filepath}")

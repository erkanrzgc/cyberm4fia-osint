"""Smoke tests for core/reporter/console_ui.py — render full ScanResult."""

from core.models import (
    CrossReferenceResult,
    EmailResult,
    PhotoMatch,
    PlatformResult,
    ScanResult,
)
from core.reporter import console_ui
from core.reporter.console_ui import (
    print_banner,
    print_progress,
    print_results,
    print_scan_start,
)


def _silence(monkeypatch):
    """Replace the module-level console with a non-printing shim."""

    class _Shim:
        def print(self, *args, **kwargs):
            pass

    monkeypatch.setattr(console_ui, "console", _Shim())


def test_print_banner(monkeypatch):
    _silence(monkeypatch)
    print_banner()


def test_print_scan_start(monkeypatch):
    _silence(monkeypatch)
    print_scan_start("alice", "Derin", 90)


def test_print_progress(monkeypatch):
    _silence(monkeypatch)
    print_progress(5, 10, "GitHub", True)
    print_progress(0, 0, "X", False)


def test_print_results_empty(monkeypatch):
    _silence(monkeypatch)
    result = ScanResult(username="alice")
    print_results(result)


def test_print_results_full(monkeypatch):
    _silence(monkeypatch)
    result = ScanResult(
        username="alice",
        scan_time=2.5,
        variations_checked=[f"var{i}" for i in range(15)],
        discovered_usernames=["other_alice"],
        dns_records={
            "alice.com": {"A": ["1.2.3.4"], "MX": ["mx.alice.com"]}
        },
        subdomains=[f"sub{i}.alice.com" for i in range(60)],
        whois_records=[
            {
                "domain": "alice.com",
                "registrar": "Some Registrar",
                "creation_date": "2020-01-01",
                "expiration_date": "2030-01-01",
                "org": "Alice Inc",
            }
        ],
        web_presence=[
            {"type": "wayback", "original_url": "https://x", "url": "https://web.archive.org/x"},
            {"type": "domain_wayback", "domain": "alice.com"},
            {"type": "paste", "id": "p1", "time": "2024"},
            {"type": "unknown", "data": "x"},
        ],
        photo_matches=[
            PhotoMatch(platform_a="gh", platform_b="tw", similarity=0.95, method="phash"),
            PhotoMatch(platform_a="gh", platform_b="rd", similarity=0.72, method="phash"),
        ],
        emails=[
            EmailResult(
                email="a@b.com",
                source="gravatar",
                verified=True,
                gravatar=True,
                breach_count=2,
                breaches=[
                    {"Name": "Leak1", "BreachDate": "2020-01-01", "PwnCount": 1000},
                    "raw-string",
                ],
            ),
            EmailResult(email="c@d.com", source="profile", verified=False, gravatar=False),
        ],
    )
    gh = PlatformResult(
        platform="GitHub",
        url="https://github.com/alice",
        category="dev",
        exists=True,
        response_time=0.42,
        profile_data={
            "name": "Alice",
            "bio": "dev",
            "location": "TR",
            "email": "a@b.com",
            "followers": 100,
            "public_repos": 20,
            "hireable": True,
            "has_verified_email": False,
            "created_utc": 1600000000,
            "created_at": 1700000000000,
            "chess_rapid_rating": 1500,
            "proofs": [
                {"service": "twitter", "username": "alice_t"},
                "not-a-dict",
            ],
        },
    )
    rd = PlatformResult(
        platform="Reddit",
        url="https://reddit.com/u/alice",
        category="social",
        exists=True,
        response_time=0.0,
    )
    result.platforms = [gh, rd]
    result.cross_reference = CrossReferenceResult(
        confidence=85.0,
        matched_names=["alice"],
        matched_locations=["TR"],
        matched_photos=["gh ↔ tw"],
        notes=["high match"],
    )
    print_results(result)


def test_print_results_low_conf(monkeypatch):
    _silence(monkeypatch)
    result = ScanResult(username="alice")
    result.platforms = [
        PlatformResult(
            platform="X", url="https://x/a", category="social", exists=True
        )
    ]
    result.cross_reference = CrossReferenceResult(confidence=20.0, notes=["weak"])
    print_results(result)

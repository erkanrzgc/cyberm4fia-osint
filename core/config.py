"""Runtime configuration with environment overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except ValueError:
        return default


MAX_CONCURRENT = _env_int("CYBERM4FIA_MAX_CONCURRENT", 30)
REQUEST_TIMEOUT = _env_int("CYBERM4FIA_TIMEOUT", 15)
RETRY_COUNT = _env_int("CYBERM4FIA_RETRIES", 2)
RETRY_DELAY = _env_float("CYBERM4FIA_RETRY_DELAY", 1.0)
RATE_LIMIT_DELAY = _env_float("CYBERM4FIA_RATE_LIMIT_DELAY", 0.1)
PER_HOST_CONCURRENCY = _env_int("CYBERM4FIA_PER_HOST_CONCURRENCY", 4)

BANNER = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

CATEGORIES = {
    "social": "Social Media",
    "dev": "Developer",
    "gaming": "Gaming",
    "content": "Content",
    "professional": "Professional",
    "community": "Community",
    "other": "Other",
}


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration — replaces a wide boolean parameter list."""

    username: str
    deep: bool = True
    smart: bool = False
    email: bool = False
    web: bool = False
    whois: bool = False
    breach: bool = False
    photo: bool = False
    dns: bool = False
    subdomain: bool = False
    proxy: str | None = None
    tor: bool = False
    categories: tuple[str, ...] | None = None
    request_timeout: int = REQUEST_TIMEOUT
    fp_threshold: float = 0.45  # drop matches below this confidence

    @classmethod
    def from_args(cls, args, username: str) -> ScanConfig:
        # Default behavior: run everything. Individual --flags still work
        # as explicit toggles; --quick restricts to the minimal profile sweep.
        full_default = not getattr(args, "quick", False)

        deep = (not args.no_deep) and (full_default or args.deep)
        smart = args.smart or full_default
        email = args.email or full_default
        web = args.web or full_default
        whois = args.whois or full_default
        breach = args.breach or full_default
        photo = args.photo or full_default
        dns = args.dns or full_default
        subdomain = args.subdomain or full_default

        if args.full:
            deep = smart = email = web = True
            whois = breach = photo = dns = subdomain = True

        if breach and not email:
            email = True

        categories: tuple[str, ...] | None = None
        if args.category:
            categories = tuple(c.strip() for c in args.category.split(",") if c.strip())

        return cls(
            username=username,
            deep=deep,
            smart=smart,
            email=email,
            web=web,
            whois=whois,
            breach=breach,
            photo=photo,
            dns=dns,
            subdomain=subdomain,
            proxy=args.proxy,
            tor=args.tor,
            categories=categories,
            request_timeout=args.timeout or REQUEST_TIMEOUT,
            fp_threshold=getattr(args, "fp_threshold", None) or 0.45,
        )

    def mode_parts(self) -> list[str]:
        parts: list[str] = []
        mapping = [
            (self.deep, "Deep"),
            (self.smart, "Smart"),
            (self.email, "Email"),
            (self.web, "Web"),
            (self.whois, "WHOIS"),
            (self.breach, "Breach"),
            (self.photo, "Photo"),
            (self.dns, "DNS"),
            (self.subdomain, "Subdomain"),
            (self.tor, "Tor"),
        ]
        for flag, label in mapping:
            if flag:
                parts.append(label)
        return parts

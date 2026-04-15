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
    holehe: bool = False
    ghunt: bool = False
    toutatis: bool = False
    recursive: bool = False
    recursive_depth: int = 1
    passive: bool = False
    passive_domain: str | None = None
    reverse_image: bool = False
    past_usernames: bool = False
    phone: str | None = None
    phone_region: str | None = None
    crypto_addresses: tuple[str, ...] = ()
    proxy: str | None = None
    tor: bool = False
    categories: tuple[str, ...] | None = None
    request_timeout: int = REQUEST_TIMEOUT
    fp_threshold: float = 0.45  # drop matches below this confidence
    fingerprint: bool = True
    new_circuit_every: int = 0
    tor_control_password: str | None = None
    playwright: bool = False

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
        holehe = getattr(args, "holehe", False) or full_default
        ghunt = getattr(args, "ghunt", False) or full_default
        toutatis = getattr(args, "toutatis", False) or full_default
        recursive = getattr(args, "recursive", False) or full_default
        recursive_depth = int(getattr(args, "recursive_depth", 1) or 1)
        passive = getattr(args, "passive", False) or full_default
        passive_domain = getattr(args, "domain", None)
        reverse_image = getattr(args, "reverse_image", False) or full_default
        past_usernames = getattr(args, "past_usernames", False) or full_default
        phone = getattr(args, "phone", None)
        phone_region = getattr(args, "phone_region", None)
        raw_crypto = getattr(args, "crypto", None)
        crypto_addresses: tuple[str, ...] = ()
        if raw_crypto:
            crypto_addresses = tuple(
                addr.strip() for addr in raw_crypto.split(",") if addr.strip()
            )

        if args.full:
            deep = smart = email = web = True
            whois = breach = photo = dns = subdomain = True
            holehe = ghunt = toutatis = recursive = True
            passive = reverse_image = past_usernames = True

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
            holehe=holehe,
            ghunt=ghunt,
            toutatis=toutatis,
            recursive=recursive,
            recursive_depth=recursive_depth,
            passive=passive,
            passive_domain=passive_domain,
            reverse_image=reverse_image,
            past_usernames=past_usernames,
            proxy=args.proxy,
            tor=args.tor,
            categories=categories,
            request_timeout=args.timeout or REQUEST_TIMEOUT,
            fp_threshold=getattr(args, "fp_threshold", None) or 0.45,
            fingerprint=not getattr(args, "no_fingerprint", False),
            new_circuit_every=int(getattr(args, "new_circuit_every", 0) or 0),
            tor_control_password=getattr(args, "tor_control_password", None),
            playwright=getattr(args, "playwright", False),
            phone=phone,
            phone_region=phone_region,
            crypto_addresses=crypto_addresses,
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
            (self.holehe, "Holehe"),
            (self.ghunt, "GHunt"),
            (self.toutatis, "Toutatis"),
            (self.recursive, "Recursive"),
            (self.passive, "Passive"),
            (self.reverse_image, "ReverseImage"),
            (self.past_usernames, "PastUsernames"),
            (bool(self.phone), "Phone"),
            (bool(self.crypto_addresses), "Crypto"),
            (self.tor, "Tor"),
        ]
        for flag, label in mapping:
            if flag:
                parts.append(label)
        return parts

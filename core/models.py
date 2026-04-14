from dataclasses import dataclass, field


@dataclass
class PlatformResult:
    platform: str
    url: str
    category: str
    exists: bool = False
    status: str = "pending"  # found, not_found, error, timeout, blocked
    response_time: float = 0.0
    profile_data: dict = field(default_factory=dict)
    http_status: int = 0


@dataclass
class EmailResult:
    email: str
    source: str
    verified: bool = False
    gravatar: bool = False
    breach_count: int = 0
    breaches: list = field(default_factory=list)


@dataclass
class BreachResult:
    name: str
    title: str
    domain: str
    breach_date: str
    pwn_count: int
    data_classes: list = field(default_factory=list)


@dataclass
class WhoisResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: str = ""
    emails: str = ""
    org: str = ""
    country: str = ""
    registrant: str = ""


@dataclass
class PhotoMatch:
    platform_a: str
    platform_b: str
    similarity: float
    method: str  # phash, md5


@dataclass
class CrossReferenceResult:
    confidence: float = 0.0
    matched_names: list = field(default_factory=list)
    matched_locations: list = field(default_factory=list)
    matched_bios: list = field(default_factory=list)
    matched_photos: list = field(default_factory=list)
    notes: list = field(default_factory=list)


@dataclass
class ScanResult:
    username: str
    platforms: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    web_presence: list = field(default_factory=list)
    cross_reference: CrossReferenceResult = field(default_factory=CrossReferenceResult)
    variations_checked: list = field(default_factory=list)
    discovered_usernames: list = field(default_factory=list)
    whois_records: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    photo_matches: list = field(default_factory=list)
    scan_time: float = 0.0
    ai_report: dict | None = None

    @property
    def found_platforms(self):
        return [p for p in self.platforms if p.exists]

    @property
    def found_count(self):
        return len(self.found_platforms)

    @property
    def total_checked(self):
        return len(self.platforms)

    def to_dict(self):
        return {
            "username": self.username,
            "scan_time": round(self.scan_time, 2),
            "total_checked": self.total_checked,
            "found_count": self.found_count,
            "platforms": [
                {
                    "platform": p.platform,
                    "url": p.url,
                    "category": p.category,
                    "exists": p.exists,
                    "status": p.status,
                    "response_time": round(p.response_time, 3),
                    "profile_data": p.profile_data,
                }
                for p in self.platforms
            ],
            "emails": [
                {
                    "email": e.email,
                    "source": e.source,
                    "verified": e.verified,
                    "gravatar": e.gravatar,
                    "breach_count": e.breach_count,
                    "breaches": e.breaches,
                }
                for e in self.emails
            ],
            "cross_reference": {
                "confidence": self.cross_reference.confidence,
                "matched_names": self.cross_reference.matched_names,
                "matched_locations": self.cross_reference.matched_locations,
                "matched_bios": self.cross_reference.matched_bios,
                "matched_photos": self.cross_reference.matched_photos,
                "notes": self.cross_reference.notes,
            },
            "variations_checked": self.variations_checked,
            "discovered_usernames": self.discovered_usernames,
            "whois_records": self.whois_records,
            "dns_records": self.dns_records,
            "subdomains": self.subdomains,
            "photo_matches": [
                {
                    "platform_a": m.platform_a,
                    "platform_b": m.platform_b,
                    "similarity": m.similarity,
                    "method": m.method,
                }
                for m in self.photo_matches
            ],
            "web_presence": self.web_presence,
            "ai_report": self.ai_report,
        }

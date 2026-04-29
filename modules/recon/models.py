"""Shared dataclasses for the red-team recon package.

Each output type is a frozen dataclass with a ``to_dict`` so the reporter
can serialize it uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EmailCandidate:
    """A generated email guess for an employee name.

    ``pattern`` is the template key that produced it
    (e.g. ``first.last``), useful when the caller wants to rank by how
    common a pattern is inside the target org.
    """

    email: str
    first_name: str
    last_name: str
    pattern: str
    domain: str

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "pattern": self.pattern,
            "domain": self.domain,
        }


@dataclass(frozen=True)
class GithubCommitter:
    """A committer identity pulled from a public GitHub org.

    ``repo`` is the ``owner/name`` slug the email was first seen in,
    ``commits_seen`` counts appearances across the whole sweep.
    """

    email: str
    name: str
    login: str = ""
    repo: str = ""
    commits_seen: int = 1
    is_noreply: bool = False

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "name": self.name,
            "login": self.login,
            "repo": self.repo,
            "commits_seen": self.commits_seen,
            "is_noreply": self.is_noreply,
        }


@dataclass(frozen=True)
class ReconSubdomain:
    """Subdomain hit with source attribution for ranking/dedup."""

    host: str
    source: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "source": self.source,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DocumentMetadata:
    """Metadata extracted from a public document (PDF / DOCX / XLSX).

    Public corporate documents routinely leak the author's full name,
    domain login, internal share paths, and the editing software used.
    These are direct inputs to a SE pretext: knowing that ``acme.local``
    is the AD domain or that ``\\\\acme-fs01\\reports`` is a real share
    is more believable than any guess.

    ``network_paths`` collects UNC / SMB paths discovered anywhere in
    the document (typical sources: relationship XML in OOXML files, or
    raw text in PDF). ``raw`` keeps the unparsed key/value blob so
    downstream code can mine fields we did not normalize.
    """

    url: str
    format: str  # "pdf" | "docx" | "xlsx" | "pptx"
    author: str = ""
    last_author: str = ""
    creator: str = ""
    title: str = ""
    subject: str = ""
    keywords: str = ""
    company: str = ""
    software: str = ""
    created: str = ""
    modified: str = ""
    network_paths: tuple[str, ...] = ()
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "format": self.format,
            "author": self.author,
            "last_author": self.last_author,
            "creator": self.creator,
            "title": self.title,
            "subject": self.subject,
            "keywords": self.keywords,
            "company": self.company,
            "software": self.software,
            "created": self.created,
            "modified": self.modified,
            "network_paths": list(self.network_paths),
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class LeakedSecret:
    """A credential-shaped string surfaced from public source code.

    ``rule_id`` identifies which detector matched (``aws_access_key``,
    ``github_pat``, etc.). ``value`` is the raw match — the caller is
    expected to treat this data sensitively even though it came from a
    public source.

    ``url`` points to the GitHub blob view at the matching line so a
    human can verify the finding before acting on it.
    """

    rule_id: str
    value: str
    repo: str
    file_path: str
    url: str
    snippet: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "value": self.value,
            "repo": self.repo,
            "file_path": self.file_path,
            "url": self.url,
            "snippet": self.snippet,
            "metadata": dict(self.metadata),
        }

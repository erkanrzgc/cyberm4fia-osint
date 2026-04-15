"""Shared dataclass for passive-intel hits.

One shape for every source so the reporter / engine does not need to
pattern-match on each provider. The ``metadata`` dict is where sources
stash anything idiosyncratic (ASN, banner snippet, paste syntax, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PassiveHit:
    source: str  # shodan, censys, fofa, zoomeye, pastebin, ahmia, harvester, wayback
    kind: str    # host, paste, email, subdomain, snapshot, onion, banner
    value: str   # primary artifact — IP, URL, email, subdomain, etc.
    title: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "kind": self.kind,
            "value": self.value,
            "title": self.title,
            "metadata": dict(self.metadata),
        }

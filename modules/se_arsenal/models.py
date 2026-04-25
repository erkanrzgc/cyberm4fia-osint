"""Frozen dataclasses for SE arsenal outputs."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LookalikeDomain:
    """A generated domain that visually/phonetically resembles the target.

    ``technique`` marks how it was produced (``homoglyph``, ``typo_swap``,
    ``tld_swap`` …) so the operator can sort by deception quality.
    """

    domain: str
    technique: str
    base: str

    def to_dict(self) -> dict:
        return {"domain": self.domain, "technique": self.technique, "base": self.base}


@dataclass(frozen=True)
class GoPhishTarget:
    """A single row pushed to a GoPhish ``groups`` object."""

    email: str
    first_name: str = ""
    last_name: str = ""
    position: str = ""

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "position": self.position,
        }


@dataclass(frozen=True)
class PretextEmail:
    """A phishing-email draft generated from scan context."""

    target_email: str
    subject: str
    body: str
    technique: str
    justification: str = ""
    sender_persona: str = ""
    linked_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_email": self.target_email,
            "subject": self.subject,
            "body": self.body,
            "technique": self.technique,
            "justification": self.justification,
            "sender_persona": self.sender_persona,
            "linked_signals": list(self.linked_signals),
        }

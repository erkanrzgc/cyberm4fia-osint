"""Tests for modules.se_arsenal.pretext — LLM-driven draft generation."""

import json

import pytest

from core.analysis.llm import LLMUnavailable
from modules.se_arsenal.models import PretextEmail
from modules.se_arsenal.pretext import (
    generate_bulk,
    generate_pretext,
    render_markdown,
)


class _StubBackend:
    """Returns a canned JSON response; records the prompts for assertions."""

    def __init__(self, payload: dict | str):
        self._payload = payload
        self.calls: list[tuple[str, str]] = []

    def complete(self, system, user, *, max_tokens, temperature):
        self.calls.append((system, user))
        if isinstance(self._payload, str):
            return self._payload
        return json.dumps(self._payload)


def _ok_payload() -> dict:
    return {
        "subject": "Acme invoice Q1",
        "body": "Hi Ada,\n\nAttached is the Q1 invoice from our vendor portal.\n\nThanks",
        "technique": "vendor_invoice",
        "justification": "Target committed to acme/finance in the last 30 days.",
        "sender_persona": "Acme Finance Team <finance@acme-billing.co>",
        "linked_signals": ["github repo acme/finance", "email a.b@acme.com"],
    }


def test_generate_pretext_returns_populated_email():
    backend = _StubBackend(_ok_payload())
    payload = {"username": "alice", "platforms": [], "recon_subdomains": []}
    draft = generate_pretext(payload, "a.b@acme.com", backend=backend)

    assert isinstance(draft, PretextEmail)
    assert draft.target_email == "a.b@acme.com"
    assert draft.subject == "Acme invoice Q1"
    assert draft.technique == "vendor_invoice"
    assert len(draft.linked_signals) == 2


def test_generate_pretext_parses_json_in_code_fence():
    fenced = "```json\n" + json.dumps(_ok_payload()) + "\n```"
    backend = _StubBackend(fenced)
    draft = generate_pretext({}, "x@acme.com", backend=backend)
    assert draft.subject == "Acme invoice Q1"


def test_generate_pretext_rejects_non_json():
    backend = _StubBackend("sure, here is an email:\nSubject: Hi\n\nYo.")
    with pytest.raises(LLMUnavailable):
        generate_pretext({}, "x@acme.com", backend=backend)


def test_generate_pretext_requires_target():
    backend = _StubBackend(_ok_payload())
    with pytest.raises(ValueError):
        generate_pretext({}, "", backend=backend)


def test_prompt_includes_target_and_trimmed_payload():
    backend = _StubBackend(_ok_payload())
    payload = {
        "username": "alice",
        "platforms": [
            {"platform": "GitHub", "url": "https://github.com/alice", "exists": True},
            {"platform": "Twitter", "url": "https://x", "exists": False},
        ],
        "recon_subdomains": [{"host": "vpn.acme.com"}],
    }
    generate_pretext(payload, "a.b@acme.com", backend=backend, scenario_hint="Q1 close")

    _system, user = backend.calls[0]
    assert "a.b@acme.com" in user
    assert "vpn.acme.com" in user
    assert "Q1 close" in user
    # Twitter entry was filtered out (exists=False).
    assert "Twitter" not in user


def test_generate_bulk_skips_failed_draft(caplog):
    backend = _StubBackend("not-json")
    drafts = generate_bulk({}, ["a@x.com", "b@x.com"], backend=backend)
    assert drafts == []


def test_render_markdown_contains_all_fields():
    draft = PretextEmail(
        target_email="a@x.com",
        subject="S",
        body="B",
        technique="T",
        justification="J",
        sender_persona="P",
        linked_signals=["s1", "s2"],
    )
    md = render_markdown(draft)
    for needle in ("a@x.com", "S", "B", "T", "J", "P", "- s1", "- s2"):
        assert needle in md

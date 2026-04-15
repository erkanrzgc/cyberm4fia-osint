"""Reverse image search — find where a profile avatar appears elsewhere.

Every source in this package takes an image URL (never raw bytes — the
target already hosts the file, so we pass through a URL and let the
reverse-search engine fetch it) and returns a list of
:class:`ReverseImageHit` entries sorted by descending confidence.

Google Lens is deliberately out of scope: its endpoint is anti-bot,
requires a full browser session, and the terms forbid scraping. We use
Yandex (clearnet, permissive) and TinEye (API-key gated).
"""

from modules.reverse_image.models import ReverseImageHit
from modules.reverse_image.orchestrator import run_reverse_image

__all__ = ["ReverseImageHit", "run_reverse_image"]

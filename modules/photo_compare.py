"""Profile photo comparison via perceptual hashing."""

from __future__ import annotations

import hashlib
from io import BytesIO

from core.http_client import HTTPClient
from core.logging_setup import get_logger

log = get_logger(__name__)

try:
    import imagehash
    from PIL import Image
    _HAS_IMAGEHASH = True
except ImportError:
    _HAS_IMAGEHASH = False
    log.debug("imagehash/Pillow not installed; falling back to md5 comparison")


async def fetch_and_hash(client: HTTPClient, url: str) -> dict | None:
    if not url or not url.startswith(("http://", "https://")):
        return None

    status, data, _ = await client.get_bytes(url)
    if status != 200 or not data:
        return None

    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    result = {"url": url, "md5": md5, "size": len(data)}

    if _HAS_IMAGEHASH:
        try:
            img = Image.open(BytesIO(data)).convert("RGB")
            result["phash"] = str(imagehash.phash(img))
            result["dhash"] = str(imagehash.dhash(img))
            result["width"] = img.width
            result["height"] = img.height
        except (OSError, ValueError) as exc:
            log.debug("image decode failed for %s: %s", url, exc)

    return result


def compare_phashes(h1: str, h2: str) -> float:
    """Returns similarity 0.0-1.0 between two perceptual hashes."""
    if not _HAS_IMAGEHASH or not h1 or not h2:
        return 1.0 if h1 == h2 else 0.0
    try:
        hash1 = imagehash.hex_to_hash(h1)
        hash2 = imagehash.hex_to_hash(h2)
        diff = hash1 - hash2
        return max(0.0, 1.0 - diff / 64.0)
    except (ValueError, TypeError) as exc:
        log.debug("phash compare failed: %s", exc)
        return 0.0


async def compare_profile_photos(
    client: HTTPClient, photo_urls: list[tuple[str, str]]
) -> list[dict]:
    """Given list of (platform, url) tuples, hash and compare all photos.
    Returns list of match dicts {p1, p2, similarity}."""
    if len(photo_urls) < 2:
        return []

    hash_results = []
    for platform, url in photo_urls:
        h = await fetch_and_hash(client, url)
        if h:
            hash_results.append((platform, h))

    matches = []
    for i, (p1, h1) in enumerate(hash_results):
        for p2, h2 in hash_results[i + 1:]:
            phash1 = h1.get("phash", "")
            phash2 = h2.get("phash", "")
            if phash1 and phash2:
                sim = compare_phashes(phash1, phash2)
                if sim > 0.7:
                    matches.append({
                        "platform_a": p1,
                        "platform_b": p2,
                        "similarity": round(sim, 2),
                        "method": "phash",
                    })
            elif h1.get("md5") == h2.get("md5"):
                matches.append({
                    "platform_a": p1,
                    "platform_b": p2,
                    "similarity": 1.0,
                    "method": "md5",
                })

    return matches


def imagehash_available() -> bool:
    return _HAS_IMAGEHASH

"""Backward-compatible façade over core.platform_loader.

Platform definitions now live in ``modules/platforms.yaml`` and can be
extended or overridden via ``~/.config/cyberm4fia/platforms.yaml`` or the
``CYBERM4FIA_PLATFORMS_FILE`` environment variable. See
``core/platform_loader.py`` for the loader rules.
"""

from core.platform_loader import Platform, load_platforms

PLATFORMS: list[Platform] = load_platforms()


def get_platform_count() -> int:
    return len(PLATFORMS)


__all__ = ["PLATFORMS", "Platform", "get_platform_count"]

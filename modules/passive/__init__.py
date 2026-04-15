"""Passive intelligence sources — domain / username pivots that never
touch the target directly.

Everything in here reads from third-party search engines, archive
services, or paste indexes. No requests to the target domain; no login
walls; no active scanning. Good for the first pass of a scan where we
want context without showing up in the target's logs.

Each submodule exposes an async ``search(client, query, ...)`` function
that returns ``list[PassiveHit]`` and silently returns ``[]`` if its
API key is missing or the upstream errors out. The orchestrator fan-out
lives in :mod:`modules.passive.orchestrator`.
"""

from modules.passive.models import PassiveHit
from modules.passive.orchestrator import run_passive

__all__ = ["PassiveHit", "run_passive"]

"""Notification fan-out for scheduled scans.

The scheduler fires :class:`Notification` objects when a scan completes
or when a diff is detected. Notifiers are configured from environment
variables so enabling them requires zero code changes — just export the
right credentials and the scheduler finds them.
"""

from __future__ import annotations

from core.notify.base import Notification, Notifier
from core.notify.dispatcher import build_default_notifiers, notify_all

__all__ = ["Notification", "Notifier", "build_default_notifiers", "notify_all"]

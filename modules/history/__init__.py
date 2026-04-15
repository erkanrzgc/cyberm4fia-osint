"""Historical username discovery.

Given a set of known profile URLs, walk the Wayback Machine CDX index
to find historical variants of those URLs. The insight: if Twitter
used to redirect ``twitter.com/old_handle`` to ``twitter.com/new_handle``,
that redirect left a trail in the CDX — we can scrape prior URL
segments and surface them as candidate aliases.

Complementary to ``modules.passive.wayback`` (which just lists
snapshots); this module *interprets* those snapshots to extract
usernames, not raw URLs.
"""

from modules.history.models import HistoricalUsername
from modules.history.username_history import discover_historical_usernames

__all__ = ["HistoricalUsername", "discover_historical_usernames"]

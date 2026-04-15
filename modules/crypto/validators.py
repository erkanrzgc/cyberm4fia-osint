"""Cheap address classifiers for BTC and ETH.

Not full checksum verification — we just need to decide *which chain*
an address belongs to so the orchestrator can route it to the right
backend. Invalid addresses will be rejected by the provider anyway.
"""

from __future__ import annotations

import re

_BTC_LEGACY = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BTC_BECH32 = re.compile(r"^bc1[02-9ac-hj-np-z]{6,87}$", re.IGNORECASE)
_ETH_HEX = re.compile(r"^0x[0-9a-fA-F]{40}$")


def classify(address: str) -> str | None:
    """Return ``"btc"``, ``"eth"`` or ``None``."""
    if not address:
        return None
    addr = address.strip()
    if _ETH_HEX.match(addr):
        return "eth"
    if _BTC_LEGACY.match(addr) or _BTC_BECH32.match(addr):
        return "btc"
    return None

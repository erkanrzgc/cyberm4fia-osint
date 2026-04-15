"""Ethereum address lookups via Etherscan.

Requires ``ETHERSCAN_API_KEY``. We issue two GETs:

* ``module=account&action=balance`` → wei balance
* ``module=account&action=txlist`` → transaction list (limit to first
  & last to infer activity range)

The txlist call is capped to the 10 most recent transactions so we
stay well under Etherscan's free-tier rate limits.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.crypto.models import CryptoIntel

log = get_logger(__name__)

_ENDPOINT = "https://api.etherscan.io/api"
_WEI = 10**18


def _fmt_ts(seconds: str | int | None) -> str:
    if not seconds:
        return ""
    try:
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, TypeError):
        return ""


async def lookup(client: HTTPClient, address: str) -> CryptoIntel | None:
    key = os.environ.get("ETHERSCAN_API_KEY")
    if not key or not address:
        return None

    bal_url = (
        f"{_ENDPOINT}?module=account&action=balance"
        f"&address={address}&tag=latest&apikey={key}"
    )
    status, bal_data, _ = await client.get_json(bal_url)
    if status != 200 or not isinstance(bal_data, dict):
        return None
    if str(bal_data.get("status", "1")) == "0" and bal_data.get("message") == "NOTOK":
        return None

    try:
        wei = int(bal_data.get("result") or 0)
    except (ValueError, TypeError):
        wei = 0

    tx_url = (
        f"{_ENDPOINT}?module=account&action=txlist"
        f"&address={address}&startblock=0&endblock=99999999"
        f"&page=1&offset=10&sort=desc&apikey={key}"
    )
    status, tx_data, _ = await client.get_json(tx_url)
    txs = []
    if status == 200 and isinstance(tx_data, dict):
        result = tx_data.get("result")
        if isinstance(result, list):
            txs = result

    tx_count = len(txs)
    last = txs[0].get("timeStamp") if txs else None
    first = txs[-1].get("timeStamp") if txs else None

    return CryptoIntel(
        address=address,
        chain="eth",
        balance=wei / _WEI,
        balance_raw=wei,
        tx_count=tx_count,
        total_received=0.0,  # Etherscan doesn't expose these directly
        total_sent=0.0,
        first_seen=_fmt_ts(first),
        last_seen=_fmt_ts(last),
        source="etherscan",
        metadata={"tx_sample_size": tx_count},
    )

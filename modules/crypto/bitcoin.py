"""Bitcoin address lookups via blockchain.info.

No API key required. Endpoint ``/rawaddr/<addr>`` returns balance,
tx count, total received/sent in satoshis, plus the first and last
transaction timestamps inside the ``txs`` array.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.http_client import HTTPClient
from core.logging_setup import get_logger
from modules.crypto.models import CryptoIntel

log = get_logger(__name__)

_ENDPOINT = "https://blockchain.info/rawaddr/{addr}?limit=5"
_SAT = 100_000_000


def _fmt_ts(seconds: int | None) -> str:
    if not seconds:
        return ""
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


async def lookup(client: HTTPClient, address: str) -> CryptoIntel | None:
    if not address:
        return None
    url = _ENDPOINT.format(addr=address)
    status, data, _ = await client.get_json(url)
    if status != 200 or not isinstance(data, dict):
        return None

    txs = data.get("txs") or []
    # blockchain.info returns txs newest-first
    last = txs[0].get("time") if txs else None
    first = txs[-1].get("time") if txs else None

    received_sat = int(data.get("total_received") or 0)
    sent_sat = int(data.get("total_sent") or 0)
    balance_sat = int(data.get("final_balance") or 0)

    return CryptoIntel(
        address=address,
        chain="btc",
        balance=balance_sat / _SAT,
        balance_raw=balance_sat,
        tx_count=int(data.get("n_tx") or 0),
        total_received=received_sat / _SAT,
        total_sent=sent_sat / _SAT,
        first_seen=_fmt_ts(first),
        last_seen=_fmt_ts(last),
        source="blockchain.info",
        metadata={
            "unredeemed": data.get("total_received", 0) - data.get("total_sent", 0),
            "hash160": data.get("hash160", ""),
        },
    )

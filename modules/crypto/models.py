"""Shared dataclass for crypto-address intel."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CryptoIntel:
    address: str
    chain: str                          # btc, eth
    balance: float = 0.0                # in native units (BTC / ETH)
    balance_raw: int = 0                # satoshis / wei
    tx_count: int = 0
    total_received: float = 0.0
    total_sent: float = 0.0
    first_seen: str = ""                # ISO-ish
    last_seen: str = ""
    source: str = ""                    # blockchain.info, etherscan
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "chain": self.chain,
            "balance": self.balance,
            "balance_raw": self.balance_raw,
            "tx_count": self.tx_count,
            "total_received": self.total_received,
            "total_sent": self.total_sent,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "metadata": dict(self.metadata),
        }

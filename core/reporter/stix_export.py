"""STIX 2.1 bundle export.

Emits a self-contained ``bundle`` with deterministic UUIDs (derived
from the input values) so re-running the export against the same scan
produces byte-identical output — useful when diffing investigations.

Object mapping:

* ``identity``             — the queried username (root SDO)
* ``user-account``         — each confirmed platform profile
* ``email-addr``           — each discovered email
* ``cryptocurrency-wallet`` — each BTC/ETH address
* ``relationship`` (linked-to) — identity → everything

We intentionally keep the object graph shallow. The STIX 2.1 schema
has much richer shapes for financial objects and user accounts, but
the shallow form renders cleanly in OpenCTI and MISP importers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from core.models import ScanResult

_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 DNS


def _det_uuid(prefix: str, value: str) -> str:
    # Deterministic UUIDv5 so re-exports don't churn IDs.
    name = f"{prefix}:{value}"
    return str(uuid.uuid5(_NAMESPACE, name))


def _now() -> str:
    return (
        datetime.now(tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _sdo(type_: str, id_seed: str, **extra: Any) -> dict[str, Any]:
    obj_id = f"{type_}--{_det_uuid(type_, id_seed)}"
    now = _now()
    base = {
        "type": type_,
        "spec_version": "2.1",
        "id": obj_id,
        "created": now,
        "modified": now,
    }
    base.update(extra)
    return base


def _relationship(src: str, dst: str, rel: str = "related-to") -> dict[str, Any]:
    rel_id = hashlib.sha256(f"{src}{dst}{rel}".encode()).hexdigest()[:32]
    formatted = (
        f"{rel_id[:8]}-{rel_id[8:12]}-{rel_id[12:16]}-{rel_id[16:20]}-{rel_id[20:32]}"
    )
    now = _now()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{formatted}",
        "created": now,
        "modified": now,
        "relationship_type": rel,
        "source_ref": src,
        "target_ref": dst,
    }


def build_stix_bundle(result: ScanResult) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []

    identity = _sdo(
        "identity",
        result.username,
        name=result.username,
        identity_class="individual",
    )
    objects.append(identity)
    root_id = identity["id"]

    for p in result.platforms:
        if not p.exists:
            continue
        acct = _sdo(
            "user-account",
            f"{p.platform}:{result.username}",
            user_id=result.username,
            account_login=result.username,
            account_type=p.category or "other",
            display_name=p.platform,
        )
        objects.append(acct)
        objects.append(_relationship(root_id, acct["id"], "owns"))

    for e in result.emails:
        email = _sdo("email-addr", e.email, value=e.email)
        objects.append(email)
        objects.append(_relationship(root_id, email["id"], "attributed-to"))

    for crypto in result.crypto_intel or []:
        addr = getattr(crypto, "address", "")
        if not addr:
            continue
        wallet = _sdo(
            "cryptocurrency-wallet",
            addr,
            value=addr,
            extensions={
                "chain": getattr(crypto, "chain", ""),
                "balance": getattr(crypto, "balance", 0.0),
            },
        )
        objects.append(wallet)
        objects.append(_relationship(root_id, wallet["id"], "owns"))

    bundle_id = f"bundle--{_det_uuid('bundle', result.username)}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def export_stix(result: ScanResult, filepath: str) -> None:
    bundle = build_stix_bundle(result)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

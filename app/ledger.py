"""Tamper-evident release ledger.

When a signing key is configured (``LEDGER_SIGNING_KEY``), every newly
released answer is appended to a chained HMAC ledger **in the same
transaction** as the stored answer and the budget deduction.  Each entry
signs the request id, the query parameters, the noisy value and the
remaining budget after the charge, and links to the previous entry's
signature, so modified, reordered or deleted rows are detectable by
re-walking the chain.

Design rules
------------
* The ledger is append-only.  Entries are never updated and never
  re-signed, so a restart — or a key change — cannot silently rewrite
  history.  The fingerprint of the key that signed the chain is recorded
  in ``ledger_meta``; a different configured key refuses to extend the
  chain and is reported by verification instead of being adopted.
* Verification reports the *first* anomaly and how many entries verified
  before it.  Once an anomaly has been seen, a persisted halt flag stops
  new releases; stored answers remain readable and replayable for free.
* Answers released while signing was disabled stay usable, but they have
  no ledger entry and therefore never count as verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

#: ``prev_signature`` stored on the very first ledger entry.
GENESIS = "GENESIS"

_PAYLOAD_VERSION = "v1"
_MESSAGE_VERSION = "ledger-v1"


def key_fingerprint(key: str) -> str:
    """Stable, domain-separated identifier for a signing key.

    Stored alongside the chain so a different configured key is detected
    loudly instead of silently re-signing history.
    """
    return hashlib.sha256(f"ledger-key\x1f{key}".encode("utf-8")).hexdigest()


def _canonical_json(fields: list[Any]) -> str:
    """Deterministic encoding: fixed order, compact separators, ASCII."""
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True)


class LedgerSigner:
    """Computes payload hashes and chained HMAC-SHA256 signatures."""

    def __init__(self, key: str) -> None:
        if not key:
            raise ValueError("signing key must not be empty")
        self._key_bytes = key.encode("utf-8")
        self.fingerprint = key_fingerprint(key)

    def payload_hash(
        self,
        *,
        seq: int,
        request_id: str,
        region: str,
        outcome: int,
        epsilon: str,
        noisy_count: int,
        budget_after: str,
    ) -> str:
        """Hash the canonical payload one ledger entry is bound to.

        Covers the request id, the full query parameter set, the noisy
        value and the post-deduction budget, plus the chain position.
        """
        payload = _canonical_json(
            [
                _PAYLOAD_VERSION,
                int(seq),
                str(request_id),
                str(region),
                int(outcome),
                str(epsilon),
                int(noisy_count),
                str(budget_after),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def sign(self, *, prev_signature: str, payload_hash: str) -> str:
        """Chained signature: HMAC over the previous link and the payload."""
        message = _canonical_json([_MESSAGE_VERSION, prev_signature, payload_hash])
        return hmac.new(
            self._key_bytes, message.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def verify(
        self, *, prev_signature: str, payload_hash: str, signature: str
    ) -> bool:
        expected = self.sign(prev_signature=prev_signature, payload_hash=payload_hash)
        return hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    request_id: str
    payload_hash: str
    prev_signature: str
    signature: str
    key_id: str


@dataclass(frozen=True)
class LedgerMeta:
    key_fingerprint: str | None
    tip_signature: str | None
    ledger_length: int
    halted: bool
    halt_reason: str | None


@dataclass(frozen=True)
class Anomaly:
    """The first problem found while walking the chain."""

    kind: str
    seq: int | None
    request_id: str | None
    detail: str


@dataclass(frozen=True)
class VerifyReport:
    status: str  # "ok" | "tampered" | "key_mismatch"
    verified_count: int
    ledger_length: int
    unsigned_requests: int
    first_anomaly: Anomaly | None
    releases_halted: bool
    halt_reason: str | None


def check_chain(
    entries: list[LedgerEntry],
    requests_by_id: Mapping[str, Any],
    meta: LedgerMeta | None,
    signer: LedgerSigner,
) -> tuple[int, Anomaly | None]:
    """Walk the ledger in order and return (verified count, first anomaly).

    ``requests_by_id`` maps request ids to objects with the stored answer
    fields (``region``, ``outcome``, ``epsilon``, ``noisy_count``,
    ``budget_after``).  The walk stops at the first problem: anything after
    a broken link cannot be trusted anyway.
    """
    verified = 0
    prev_signature = GENESIS
    for position, entry in enumerate(entries, start=1):
        if entry.seq != position:
            return verified, Anomaly(
                kind="sequence_gap",
                seq=position,
                request_id=entry.request_id,
                detail=(
                    f"expected ledger seq {position} but found {entry.seq}; "
                    "a row is missing or the chain was reordered"
                ),
            )
        if entry.prev_signature != prev_signature:
            return verified, Anomaly(
                kind="chain_break",
                seq=position,
                request_id=entry.request_id,
                detail="prev_signature does not match the previous entry's signature",
            )
        stored = requests_by_id.get(entry.request_id)
        if stored is None:
            return verified, Anomaly(
                kind="orphaned_signature",
                seq=position,
                request_id=entry.request_id,
                detail="ledger entry has no matching released answer",
            )
        recomputed = signer.payload_hash(
            seq=entry.seq,
            request_id=entry.request_id,
            region=stored.region,
            outcome=stored.outcome,
            epsilon=stored.epsilon,
            noisy_count=stored.noisy_count,
            budget_after=stored.budget_after,
        )
        if recomputed != entry.payload_hash:
            return verified, Anomaly(
                kind="payload_mismatch",
                seq=position,
                request_id=entry.request_id,
                detail="stored answer no longer matches the signed payload",
            )
        if not signer.verify(
            prev_signature=prev_signature,
            payload_hash=entry.payload_hash,
            signature=entry.signature,
        ):
            return verified, Anomaly(
                kind="signature_mismatch",
                seq=position,
                request_id=entry.request_id,
                detail="HMAC signature does not verify with the configured key",
            )
        verified += 1
        prev_signature = entry.signature

    # The meta row anchors the tip so deleting trailing rows is detectable.
    if meta is None:
        if entries:
            return verified, Anomaly(
                kind="meta_missing",
                seq=None,
                request_id=None,
                detail="ledger entries exist but the ledger meta row is gone",
            )
    else:
        if meta.ledger_length != len(entries):
            return verified, Anomaly(
                kind="tip_mismatch",
                seq=None,
                request_id=None,
                detail=(
                    f"ledger meta records {meta.ledger_length} entries but the "
                    f"ledger table holds {len(entries)}"
                ),
            )
        expected_tip = entries[-1].signature if entries else None
        if meta.tip_signature != expected_tip:
            return verified, Anomaly(
                kind="tip_mismatch",
                seq=None,
                request_id=None,
                detail="ledger meta tip does not match the last ledger entry",
            )
    return verified, None


__all__ = [
    "GENESIS",
    "Anomaly",
    "LedgerEntry",
    "LedgerMeta",
    "LedgerSigner",
    "VerifyReport",
    "check_chain",
    "key_fingerprint",
]

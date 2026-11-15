"""Public data structures and the SQL-backed repository.

All budget quantities are decimals and are stored as canonical decimal
strings, never as SQLite REAL values, so ``1 - 0.1`` stays exactly ``0.9``.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Protocol

from .ledger import (
    GENESIS,
    LedgerEntry,
    LedgerMeta,
    LedgerSigner,
    VerifyReport,
    check_chain,
)
from .privacy import canonical_decimal


@dataclass(frozen=True)
class StoredRequest:
    request_id: str
    fingerprint: str
    region: str
    outcome: int
    epsilon: str
    noisy_count: int
    budget_after: str
    created_at: str


@dataclass(frozen=True)
class ReleaseResult:
    """Outcome of a query: a fresh release, or a replay of a stored one."""

    noisy_count: int
    remaining_budget: Decimal
    replayed: bool


@dataclass(frozen=True)
class BudgetSnapshot:
    total: Decimal
    spent: Decimal

    @property
    def remaining(self) -> Decimal:
        return self.total - self.spent


@dataclass(frozen=True)
class LookupResult:
    """A stored answer (if any) plus the *current* global remaining budget."""

    stored: StoredRequest | None
    remaining_budget: Decimal


@dataclass(frozen=True)
class LedgerState:
    """A read-only view of the release ledger's bookkeeping."""

    halted: bool
    halt_reason: str | None
    ledger_length: int
    unsigned_requests: int
    key_fingerprint: str | None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Repository(Protocol):
    """Storage interface used by the query service."""

    def budget_snapshot(self) -> BudgetSnapshot: ...

    def lookup(self, request_id: str) -> LookupResult: ...

    def count_subjects(self, region: str, outcome: int) -> int: ...

    def apply_query(
        self,
        *,
        request_id: str,
        fingerprint: str,
        region: str,
        outcome: int,
        epsilon: Decimal,
        noisy_count: int,
        signer: LedgerSigner | None = None,
    ) -> ReleaseResult: ...


class SqliteRepository:
    """Repository whose mutations run inside one serialised transaction."""

    def __init__(self, database) -> None:  # noqa: ANN001 - avoids an import cycle
        self._db = database

    # -- reads -------------------------------------------------------------
    def budget_snapshot(self) -> BudgetSnapshot:
        from .errors import DatasetMissing

        with self._db.read_transaction() as conn:
            return _budget_snapshot(conn)

    def lookup(self, request_id: str) -> LookupResult:
        """Read the stored answer and the current remaining budget atomically."""
        with self._db.read_transaction() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            remaining = _budget_snapshot(conn).remaining
            return LookupResult(
                stored=_row_to_request(row) if row else None,
                remaining_budget=remaining,
            )

    def count_subjects(self, region: str, outcome: int) -> int:
        with self._db.read_transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM subjects "
                "WHERE region = ? AND outcome = ?",
                (region, int(outcome)),
            ).fetchone()
            return int(row["n"])

    # -- the critical section ---------------------------------------------
    def apply_query(
        self,
        *,
        request_id: str,
        fingerprint: str,
        region: str,
        outcome: int,
        epsilon: Decimal,
        noisy_count: int,
        signer: LedgerSigner | None = None,
    ) -> ReleaseResult:
        """Atomically consume budget and persist the answer.

        ``noisy_count`` is ignored when a stored answer for ``request_id``
        already exists: a replay always returns the originally released
        value and never charges budget.

        When ``signer`` is given, a chained ledger signature covering the
        request id, the parameters, the noisy value and the post-deduction
        budget is appended in the *same* transaction, so a failure anywhere
        rolls back answer, charge and signature together — never an orphaned
        signature.  Because the whole block runs under ``BEGIN IMMEDIATE``,
        concurrent releases chain in commit order.
        """
        from .errors import (
            BudgetExhausted,
            LedgerSigningRequired,
            LedgerKeyMismatch,
            ReleaseHalted,
            RequestIdConflict,
        )

        with self._db.write_transaction() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is not None:
                stored = _row_to_request(row)
                if stored.fingerprint != fingerprint:
                    raise RequestIdConflict(request_id)
                return ReleaseResult(
                    noisy_count=stored.noisy_count,
                    remaining_budget=_budget_snapshot(conn).remaining,
                    replayed=True,
                )

            # Halt and key-continuity checks gate *new* releases only;
            # replays above stay free even when releases are halted.
            meta_row = conn.execute(
                "SELECT * FROM ledger_meta WHERE id = 1"
            ).fetchone()
            if meta_row is not None and int(meta_row["halted"]):
                raise ReleaseHalted(
                    str(meta_row["halt_reason"] or "ledger verification failed")
                )
            if signer is None:
                if meta_row is not None and meta_row["key_fingerprint"]:
                    # A signed ledger must never silently go unsigned.
                    raise LedgerSigningRequired(
                        "this database holds a signed release ledger; configure "
                        "LEDGER_SIGNING_KEY to continue releasing new answers"
                    )
            elif meta_row is not None and meta_row["key_fingerprint"] is not None:
                if meta_row["key_fingerprint"] != signer.fingerprint:
                    raise LedgerKeyMismatch(
                        "configured signing key does not match the key that "
                        "signed the existing ledger; refusing to extend it"
                    )

            snapshot = _budget_snapshot(conn)
            if epsilon > snapshot.remaining:
                raise BudgetExhausted(epsilon, snapshot.remaining, snapshot.total)
            budget_after = snapshot.remaining - epsilon
            new_spent = snapshot.total - budget_after
            epsilon_text = canonical_decimal(epsilon)
            budget_after_text = canonical_decimal(budget_after)

            # The request row, the budget update and the ledger signature
            # commit together.  Any failure while writing raises out of the
            # transaction, which rolls all of them back: no charge, no
            # stored answer, no orphaned signature.
            conn.execute(
                """
                INSERT INTO requests
                    (request_id, request_hash, region, outcome, epsilon,
                     noisy_count, budget_after, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    fingerprint,
                    region,
                    int(outcome),
                    epsilon_text,
                    int(noisy_count),
                    budget_after_text,
                    _now(),
                ),
            )
            conn.execute(
                "UPDATE dataset SET budget_spent = ? WHERE id = 1",
                (canonical_decimal(new_spent),),
            )
            if signer is not None:
                self._append_ledger_entry(
                    conn,
                    signer=signer,
                    meta_row=meta_row,
                    request_id=request_id,
                    region=region,
                    outcome=int(outcome),
                    epsilon=epsilon_text,
                    noisy_count=int(noisy_count),
                    budget_after=budget_after_text,
                )
            return ReleaseResult(
                noisy_count=int(noisy_count),
                remaining_budget=budget_after,
                replayed=False,
            )

    # -- release ledger ----------------------------------------------------
    @staticmethod
    def _append_ledger_entry(
        conn: sqlite3.Connection,
        *,
        signer: LedgerSigner,
        meta_row: sqlite3.Row | None,
        request_id: str,
        region: str,
        outcome: int,
        epsilon: str,
        noisy_count: int,
        budget_after: str,
    ) -> None:
        """Append one chained signature; caller's transaction commits it."""
        from .errors import LedgerInconsistent

        if meta_row is None:
            conn.execute(
                """
                INSERT INTO ledger_meta
                    (id, key_fingerprint, tip_signature, ledger_length, halted)
                VALUES (1, ?, NULL, 0, 0)
                """,
                (signer.fingerprint,),
            )
            recorded_length, recorded_tip, recorded_key = 0, None, signer.fingerprint
        else:
            recorded_length = int(meta_row["ledger_length"])
            recorded_tip = meta_row["tip_signature"]
            recorded_key = meta_row["key_fingerprint"]

        last = conn.execute(
            "SELECT seq, signature FROM release_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        actual_length = int(last["seq"]) if last else 0
        actual_tip = str(last["signature"]) if last else None
        if actual_length != recorded_length or actual_tip != recorded_tip:
            raise LedgerInconsistent(
                "ledger meta and ledger table disagree; the ledger may have "
                "been altered outside the application"
            )
        if recorded_key is None:
            # Only a ledger that has never been signed may adopt a key; an
            # existing chain is never re-attributed to a different key.
            if actual_length != 0:
                raise LedgerInconsistent(
                    "ledger entries exist but no signing key is recorded"
                )
            conn.execute(
                "UPDATE ledger_meta SET key_fingerprint = ? WHERE id = 1",
                (signer.fingerprint,),
            )

        seq = actual_length + 1
        prev_signature = actual_tip if actual_tip is not None else GENESIS
        payload_hash = signer.payload_hash(
            seq=seq,
            request_id=request_id,
            region=region,
            outcome=outcome,
            epsilon=epsilon,
            noisy_count=noisy_count,
            budget_after=budget_after,
        )
        signature = signer.sign(
            prev_signature=prev_signature, payload_hash=payload_hash
        )
        conn.execute(
            """
            INSERT INTO release_ledger
                (seq, request_id, payload_hash, prev_signature, signature,
                 key_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq,
                request_id,
                payload_hash,
                prev_signature,
                signature,
                signer.fingerprint,
                _now(),
            ),
        )
        conn.execute(
            "UPDATE ledger_meta SET tip_signature = ?, ledger_length = ? "
            "WHERE id = 1",
            (signature, seq),
        )

    def ledger_state(self) -> LedgerState:
        """Halt flag, chain length and unsigned-answer count for reporting."""
        with self._db.read_transaction() as conn:
            meta_row = conn.execute(
                "SELECT * FROM ledger_meta WHERE id = 1"
            ).fetchone()
            length = conn.execute(
                "SELECT COUNT(*) AS n FROM release_ledger"
            ).fetchone()["n"]
            unsigned = _unsigned_count(conn)
            return LedgerState(
                halted=bool(meta_row["halted"]) if meta_row else False,
                halt_reason=str(meta_row["halt_reason"])
                if meta_row and meta_row["halt_reason"]
                else None,
                ledger_length=int(length),
                unsigned_requests=unsigned,
                key_fingerprint=str(meta_row["key_fingerprint"])
                if meta_row and meta_row["key_fingerprint"]
                else None,
            )

    def verify_and_halt(self, *, signer: LedgerSigner) -> VerifyReport:
        """Re-verify the whole chain; persist the halt flag on any anomaly.

        Runs inside one serialised write transaction so no release can
        commit between the scan and the halt being recorded.
        """
        with self._db.write_transaction() as conn:
            meta_row = conn.execute(
                "SELECT * FROM ledger_meta WHERE id = 1"
            ).fetchone()
            meta = _row_to_meta(meta_row) if meta_row is not None else None
            entries = [
                _row_to_entry(row)
                for row in conn.execute(
                    "SELECT * FROM release_ledger ORDER BY seq"
                ).fetchall()
            ]
            requests_by_id = {
                str(row["request_id"]): _row_to_request(row)
                for row in conn.execute("SELECT * FROM requests").fetchall()
            }
            unsigned = _unsigned_count(conn)
            halted = meta.halted if meta else False
            halt_reason = meta.halt_reason if meta else None

            if (
                meta is not None
                and meta.key_fingerprint is not None
                and meta.key_fingerprint != signer.fingerprint
            ):
                # Never re-verify (or re-sign) history with the wrong key.
                return VerifyReport(
                    status="key_mismatch",
                    verified_count=0,
                    ledger_length=len(entries),
                    unsigned_requests=unsigned,
                    first_anomaly=None,
                    releases_halted=halted,
                    halt_reason=halt_reason,
                )

            verified, anomaly = check_chain(entries, requests_by_id, meta, signer)
            if anomaly is not None and not halted:
                if anomaly.seq is not None:
                    reason = (
                        f"ledger verification failed at seq {anomaly.seq}: "
                        f"{anomaly.kind}"
                    )
                else:
                    reason = f"ledger verification failed: {anomaly.kind}"
                conn.execute(
                    "INSERT OR IGNORE INTO ledger_meta (id, halted) VALUES (1, 0)"
                )
                conn.execute(
                    "UPDATE ledger_meta SET halted = 1, halt_reason = ?, "
                    "halted_at = ? WHERE id = 1",
                    (reason, _now()),
                )
                halted = True
                halt_reason = reason

            return VerifyReport(
                status="tampered" if anomaly is not None else "ok",
                verified_count=verified,
                ledger_length=len(entries),
                unsigned_requests=unsigned,
                first_anomaly=anomaly,
                releases_halted=halted,
                halt_reason=halt_reason,
            )


def _budget_snapshot(conn: sqlite3.Connection) -> BudgetSnapshot:
    from .errors import DatasetMissing

    row = conn.execute(
        "SELECT total_budget, budget_spent FROM dataset WHERE id = 1"
    ).fetchone()
    if row is None:
        raise DatasetMissing("no dataset imported")
    return BudgetSnapshot(
        total=Decimal(str(row["total_budget"])),
        spent=Decimal(str(row["budget_spent"])),
    )


def _row_to_request(row: sqlite3.Row) -> StoredRequest:
    return StoredRequest(
        request_id=str(row["request_id"]),
        fingerprint=str(row["request_hash"]),
        region=str(row["region"]),
        outcome=int(row["outcome"]),
        epsilon=str(row["epsilon"]),
        noisy_count=int(row["noisy_count"]),
        budget_after=str(row["budget_after"]),
        created_at=str(row["created_at"]),
    )


def _row_to_entry(row: sqlite3.Row) -> LedgerEntry:
    return LedgerEntry(
        seq=int(row["seq"]),
        request_id=str(row["request_id"]),
        payload_hash=str(row["payload_hash"]),
        prev_signature=str(row["prev_signature"]),
        signature=str(row["signature"]),
        key_id=str(row["key_id"]),
    )


def _row_to_meta(row: sqlite3.Row) -> LedgerMeta:
    return LedgerMeta(
        key_fingerprint=(
            str(row["key_fingerprint"]) if row["key_fingerprint"] else None
        ),
        tip_signature=(
            str(row["tip_signature"]) if row["tip_signature"] else None
        ),
        ledger_length=int(row["ledger_length"]),
        halted=bool(row["halted"]),
        halt_reason=str(row["halt_reason"]) if row["halt_reason"] else None,
    )


def _unsigned_count(conn: sqlite3.Connection) -> int:
    """Released answers with no ledger entry (they predate signing).

    They stay usable, but verification must never count them as verified.
    """
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM requests r "
        "WHERE NOT EXISTS "
        "(SELECT 1 FROM release_ledger l WHERE l.request_id = r.request_id)"
    ).fetchone()
    return int(row["n"])

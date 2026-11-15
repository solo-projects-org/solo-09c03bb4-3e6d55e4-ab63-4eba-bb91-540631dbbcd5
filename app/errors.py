"""Domain exceptions shared by the service and the HTTP layer."""

from __future__ import annotations

from decimal import Decimal


class DatasetMissing(Exception):
    """No data set has been imported yet."""


class BudgetExhausted(Exception):
    """The requested epsilon does not fit in the remaining global budget."""

    def __init__(self, requested: Decimal, remaining: Decimal, total: Decimal) -> None:
        self.requested = requested
        self.remaining = remaining
        self.total = total
        super().__init__(
            f"epsilon {requested} exceeds remaining budget {remaining}"
        )


class RequestIdConflict(Exception):
    """A request id was reused with a different parameter set."""

    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        super().__init__(
            f"request id {request_id!r} was already used with different parameters"
        )


class ReleaseHalted(Exception):
    """New releases are halted because ledger verification found an anomaly."""


class LedgerKeyMismatch(Exception):
    """The configured signing key differs from the key that signed the ledger."""


class LedgerSigningRequired(Exception):
    """The database holds a signed ledger but no signing key is configured."""


class LedgerInconsistent(Exception):
    """Ledger bookkeeping disagrees with the ledger table (possible tampering)."""

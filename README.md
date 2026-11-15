# Follow-up Count Privacy API

A small statistical API that hands collaborating research groups **noisy**
follow-up counts, never exact ones. Subject-level data is imported once from
a CSV and is never replaced afterwards. Each query for a
(`region`, `outcome`) cell answers with a count perturbed by Laplace noise of
scale `1/ε`, and charges `ε` against a single global privacy budget that
starts at `1`.

- **Stack:** FastAPI · SQLite · Uvicorn
- **Docs:** interactive Swagger UI at `/docs`, OpenAPI JSON at `/openapi.json`
- **Guarantee:** ε-differential privacy per release (histogram query,
  sensitivity 1), with lifetime budget accounting

---

## Quick start

```bash
docker compose up --build
```

Then open <http://localhost:8000/docs>.

The bundled sample data set is `seed/followup.csv` (100 subjects across
`north`, `south`, `east`). It is imported **once**, on the very first start.
A named volume (`followup-data`) holds the database, so restarts keep the
imported data, the spent budget and every released answer.

Tear down completely, including the volume:

```bash
docker compose down -v
```

### Running without Docker

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --port 8000
```

---

## API

### `POST /v1/counts`

```bash
curl -s -X POST http://localhost:8000/v1/counts \
  -H 'Content-Type: application/json' \
  -d '{"request_id":"req-0001","region":"north","outcome":1,"epsilon":"0.1"}'
```

```json
{
  "request_id": "req-0001",
  "region": "north",
  "outcome": 1,
  "epsilon": "0.1",
  "noisy_count": 27,
  "remaining_budget": "0.9",
  "replayed": false,
  "charged": true
}
```

| Field | Meaning |
| --- | --- |
| `noisy_count` | Integer count after adding Laplace(0, 1/ε) noise, clamped at 0. Never the exact count. |
| `remaining_budget` | Global budget left **after** this call, as an exact decimal string. |
| `replayed` | `true` when a stored answer was returned instead of a new one. |
| `charged` | `true` when this call spent budget. |

`request_id` is a client-generated idempotency key. Retrying it with the same
parameters returns the identical stored answer, `replayed: true`, and no new
charge. Reusing it with any different parameter (region, outcome or epsilon)
is rejected with `409 request_id_conflict`.

### `GET /v1/budget`

```json
{"total_budget": "1", "remaining_budget": "0.9"}
```

### `GET /v1/requests/{request_id}`

Returns the stored answer for a request id (same body as above) or `404`.

### `GET /health`

Liveness plus whether the data set has been loaded and its row count.

### `POST /v1/admin/verify`

Admin endpoint that re-verifies the **signed release ledger** and halts new
releases if anything was tampered with. Requires the admin token as a Bearer
credential (in Swagger: click **Authorize** and paste the token):

```bash
curl -s -X POST http://localhost:8000/v1/admin/verify \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

```json
{
  "status": "ok",
  "verified_count": 2,
  "ledger_length": 2,
  "unsigned_requests": 0,
  "first_anomaly": null,
  "releases_halted": false,
  "halt_reason": null,
  "detail": "all 2 ledger entries verified with the configured key"
}
```

| Field | Meaning |
| --- | --- |
| `status` | `ok` (chain verifies), `tampered` (first anomaly found), `key_mismatch` (configured key is not the key that signed the ledger), `disabled` (no `LEDGER_SIGNING_KEY` configured). |
| `verified_count` | Ledger entries cryptographically verified before the first anomaly. |
| `unsigned_requests` | Released answers with no signature (they predate signing). They stay usable but are **never** counted as verified. |
| `first_anomaly` | `kind`, chain position `seq`, `request_id` and a human-readable `detail` of the first problem, or `null`. |
| `releases_halted` | Once an anomaly has been seen, this stays `true` — the halt is persisted in the database and survives restarts. |

When `LEDGER_SIGNING_KEY` is set, every **new** answer is appended to
`release_ledger` in the same transaction as the answer and the budget
deduction. Each entry HMAC-signs the request id, the query parameters, the
noisy value and the post-deduction budget, and chains the previous entry's
signature, so edited, reordered or deleted rows are detected by the walk
above. After a `tampered` result, new releases are rejected with
`503 releases_halted`; stored answers remain readable and replayable for
free. The ledger is append-only: a restart continues the chain, and a
different signing key is reported (`key_mismatch`) instead of silently
re-signing history.

### Errors

All errors share one shape:

```json
{"error": "invalid_request", "message": "request validation failed", "details": [...]}
```

| Status | `error` | When |
| --- | --- | --- |
| 401 | `unauthorized` | Missing or wrong admin token on `/v1/admin/verify` |
| 409 | `request_id_conflict` | Same `request_id`, different parameters |
| 422 | `invalid_request` | Malformed body, `ε` outside `(0, 1]`, outcome not `0`/`1`, … |
| 429 | `budget_exhausted` | `ε` does not fit in the remaining global budget |
| 503 | `dataset_missing` | No data set imported |
| 503 | `releases_halted` | Ledger verification found an anomaly; new releases stopped (replays still work) |
| 503 | `ledger_key_mismatch` | `LEDGER_SIGNING_KEY` differs from the key that signed the existing ledger |
| 503 | `ledger_signing_required` | Database holds a signed ledger but no signing key is configured |
| 503 | `ledger_inconsistent` | Ledger bookkeeping disagrees with the ledger table |
| 503 | `admin_disabled` | Admin API called without `ADMIN_TOKEN` configured |
| 500 | `internal_error` | Unexpected failure; nothing was charged |

---

## Privacy model

- **Mechanism.** The count of subjects in one cell has global sensitivity 1
  (adding or removing one person changes it by at most one). Adding a sample
  from `Laplace(0, 1/ε)` therefore gives ε-differential privacy for that
  answer. Rounding to an integer and clamping at zero are post-processing and
  preserve the guarantee.
- **Composition.** Every release is charged `ε` against one global budget of
  1, so a sequence of releases is safe under basic sequential composition
  while the sum of ε stays within the budget. Once the budget is exhausted,
  only replays of already-released answers are served, free of charge.
- **No exact values.** The exact counts are computed inside the process but
  are never returned, logged or included in an error message. Sweep
  `region` × `outcome` and intersect only through noisy releases, each paid
  for by the budget.

---

## Correctness properties and how they are enforced

| Requirement | Enforcement |
| --- | --- |
| CSV imported once, never replaced | The importer short-circuits whenever the singleton `dataset` row exists; the check is repeated under the write lock. A different CSV is ignored. |
| Unique subject id | `UNIQUE` constraint plus a pre-insert duplicate scan; a bad file leaves zero rows and no data-set row behind (whole import is one transaction). |
| 0/1 outcomes only | CSV validation and a `CHECK` constraint on `subjects.outcome`. |
| Laplace noise, scale `1/ε` | `app/privacy.py`; draws uniforms from the OS CSPRNG in the open interval `(0, 1)`. |
| Budget never overspent under concurrency | Budget check and deduction happen in one `BEGIN IMMEDIATE` transaction; SQLite allows exactly one writer, so the read-modify-write is serialised. Exact decimal arithmetic — never floats — so `1 - 10×0.1` is exactly `0`. |
| Same id + same parameters → same answer, no charge | The stored `noisy_count` is returned; the fingerprint of `(region, outcome, canonical ε)` is compared first. |
| Same id + different parameters → reject | Fingerprint mismatch raises `409`. |
| Invalid request never charges | Validation happens before the service is called; no row is written. |
| Save failure never charges, and produces no answer | The noisy draw, the request row and the budget update are one transaction. Any exception rolls back both; `GET /v1/budget` is unchanged. |
| Commit succeeded but response lost | The answer is durable before the response is written. A retry — even after a restart — returns the identical stored value. |
| Release ledger is tamper-evident | When signing is enabled, each new answer's ledger entry is committed in the same transaction as the answer and the charge, and chains the previous entry's HMAC. Verification re-walks the chain and reports the first anomaly plus how many entries verified. |
| Write failure leaves no orphan signature | The signature insert shares the answer's transaction; a failure anywhere rolls back answer, charge and signature together. |
| Anomaly ⇒ new releases stop | A failed verification persists `ledger_meta.halted`. New releases get `503 releases_halted`; replays and lookups stay free. The flag survives restarts. |
| Restart or key change never re-signs history | Ledger rows are insert-only and the signing key's fingerprint is stored with the chain. A different key refuses to extend the chain (`503 ledger_key_mismatch`) and verification reports `key_mismatch`; old entries are never rewritten. |
| Unsigned history stays clearly unsigned | Answers released before signing was enabled keep working, but verification reports them separately as `unsigned_requests` and never counts them as verified. |

---

## Concurrency test

The suite spins up 20 simultaneous `ε = 0.1` requests against a budget of
`1.0` and asserts exactly ten `200`s, ten `429`s and a final budget of `0`
(`tests/test_api.py::test_concurrent_requests_never_overspend`).

```bash
pytest -q
```

---

## Layout

```
app/
  config.py     env-driven settings (paths, total budget, admin/ledger secrets)
  db.py         SQLite connections, schema, serialised transactions
  importer.py   validated one-shot CSV import
  privacy.py    Laplace mechanism, canonical decimals, request fingerprints
  ledger.py     chained HMAC signatures and chain verification
  models.py     dataclasses and the SQL repository (budget critical section)
  service.py    query orchestration and idempotency
  main.py       FastAPI app, endpoints, error mapping
examples/followup.csv   sample input (same as seed/followup.csv)
seed/followup.csv       data set imported by the container on first start
tests/                  pytest suite (API, privacy, ledger, concurrency, durability)
```

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_PATH` | `data/followup.db` | SQLite file (mounted volume in Docker) |
| `CSV_PATH` | `seed/followup.csv` | CSV imported on first start only |
| `TOTAL_BUDGET` | `1` | Lifetime privacy budget |
| `IMPORT_ON_STARTUP` | `1` | Set `0` to boot without an import attempt |
| `SQLITE_BUSY_TIMEOUT_MS` | `30000` | How long writers wait for the lock |
| `ADMIN_TOKEN` | *(unset)* | Bearer token for `POST /v1/admin/verify`; unset disables the admin API |
| `LEDGER_SIGNING_KEY` | *(unset)* | HMAC key for the signed release ledger; unset disables signing |
| `API_PORT` | `8000` | Host port published by Compose |

> The Compose file sets demo values for `ADMIN_TOKEN` and
> `LEDGER_SIGNING_KEY` so the verification flow works out of the box in
> Swagger. Override them (`ADMIN_TOKEN=... LEDGER_SIGNING_KEY=... docker
> compose up`) anywhere real data flows. Once a ledger exists, its key is
> pinned: a changed `LEDGER_SIGNING_KEY` refuses to extend or re-sign the
> old chain.

> **Operational note:** every successful new answer consumes budget
> permanently. To start a fresh study, remove the volume
> (`docker compose down -v`) and start again — that is the only way the data
> set or the budget is ever reset, by design.

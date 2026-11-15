"""Tests for the signed release ledger and the admin verification API."""

from __future__ import annotations

import threading
from decimal import Decimal
from pathlib import Path

import pytest

from app.config import Settings
from app.ledger import GENESIS, LedgerSigner

ADMIN_TOKEN = "test-admin-token"
SIGNING_KEY = "test-signing-key"


@pytest.fixture()
def csv_path(tmp_path: Path) -> Path:
    path = tmp_path / "followup.csv"
    path.write_text(
        "subject_id,region,outcome\n"
        "A,north,1\n"
        "B,north,1\n"
        "C,north,0\n"
        "D,south,1\n"
        "E,south,0\n"
        "F,east,0\n",
        encoding="utf-8",
    )
    return path


def make_settings(
    tmp_path: Path,
    csv_path: Path,
    *,
    admin_token: str | None = ADMIN_TOKEN,
    signing_key: str | None = SIGNING_KEY,
    name: str = "ledger.db",
) -> Settings:
    return Settings(
        database_path=tmp_path / name,
        csv_path=csv_path,
        total_budget=Decimal("1"),
        import_on_startup=True,
        sqlite_busy_timeout_ms=30_000,
        max_concurrency=4,
        admin_token=admin_token,
        ledger_signing_key=signing_key,
    )


def make_client(settings: Settings, **kwargs):
    from fastapi.testclient import TestClient

    from app.main import create_app

    return TestClient(create_app(settings), **kwargs)


@pytest.fixture()
def client(tmp_path: Path, csv_path: Path):
    with make_client(make_settings(tmp_path, csv_path)) as test_client:
        yield test_client


def post_count(client, request_id: str, epsilon: str = "0.1"):
    return client.post(
        "/v1/counts",
        json={
            "request_id": request_id,
            "region": "north",
            "outcome": 1,
            "epsilon": epsilon,
        },
    )


def verify(client, token: str | None = ADMIN_TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.post("/v1/admin/verify", headers=headers)


def ledger_table(client):
    conn = client.app.state.database.connect()
    return conn.execute("SELECT * FROM release_ledger ORDER BY seq").fetchall()


# --------------------------------------------------------------------------
# signing on the write path
# --------------------------------------------------------------------------
def test_each_release_appends_a_chained_signature(client):
    for index in range(3):
        response = post_count(client, f"r{index}")
        assert response.status_code == 200

    entries = ledger_table(client)
    assert [entry["seq"] for entry in entries] == [1, 2, 3]
    assert entries[0]["prev_signature"] == GENESIS
    for previous, current in zip(entries, entries[1:]):
        assert current["prev_signature"] == previous["signature"]

    # Every entry signs the request id, the parameters, the noisy value and
    # the post-deduction budget stored with the answer.
    signer = LedgerSigner(SIGNING_KEY)
    conn = client.app.state.database.connect()
    requests = {
        row["request_id"]: row
        for row in conn.execute("SELECT * FROM requests").fetchall()
    }
    for entry in entries:
        stored = requests[entry["request_id"]]
        payload_hash = signer.payload_hash(
            seq=entry["seq"],
            request_id=entry["request_id"],
            region=stored["region"],
            outcome=stored["outcome"],
            epsilon=stored["epsilon"],
            noisy_count=stored["noisy_count"],
            budget_after=stored["budget_after"],
        )
        assert payload_hash == entry["payload_hash"]
        assert signer.verify(
            prev_signature=entry["prev_signature"],
            payload_hash=payload_hash,
            signature=entry["signature"],
        )

    meta = conn.execute("SELECT * FROM ledger_meta WHERE id = 1").fetchone()
    assert meta["ledger_length"] == 3
    assert meta["tip_signature"] == entries[-1]["signature"]
    assert meta["key_fingerprint"] == signer.fingerprint
    assert meta["halted"] == 0


def test_replay_does_not_append_ledger_entries(client):
    assert post_count(client, "r0").status_code == 200
    replay = post_count(client, "r0")
    assert replay.json()["replayed"] is True
    assert len(ledger_table(client)) == 1


def test_signature_failure_rolls_back_answer_and_charge(tmp_path, csv_path):
    """A failing ledger write must not leave an orphan signature, a stored
    answer or a budget charge behind."""
    settings = make_settings(tmp_path, csv_path)
    with make_client(settings, raise_server_exceptions=False) as client:
        conn = client.app.state.database.connect()
        conn.execute(
            "CREATE TRIGGER block_ledger BEFORE INSERT ON release_ledger "
            "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
        )
        response = post_count(client, "fail-1", epsilon="0.5")
        assert response.status_code == 500
        conn.execute("DROP TRIGGER block_ledger")

        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM release_ledger").fetchone()[0] == 0
        )
        assert conn.execute("SELECT COUNT(*) FROM ledger_meta").fetchone()[0] == 0
        assert client.get("/v1/budget").json()["remaining_budget"] == "1"

        retry = post_count(client, "fail-1", epsilon="0.5")
        assert retry.status_code == 200
        assert retry.json()["remaining_budget"] == "0.5"
        assert len(ledger_table(client)) == 1


def test_concurrent_signed_releases_chain_in_commit_order(tmp_path, csv_path):
    settings = make_settings(
        tmp_path, csv_path, name="concurrent.db"
    )
    with make_client(settings) as client:
        statuses: list[int] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            response = post_count(client, f"c-{index}", epsilon="0.05")
            with lock:
                statuses.append(response.status_code)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert statuses == [200] * 20
        entries = ledger_table(client)
        assert [entry["seq"] for entry in entries] == list(range(1, 21))
        body = verify(client).json()
        assert body["status"] == "ok"
        assert body["verified_count"] == 20


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------
def test_verify_reports_all_entries_verified(client):
    for index in range(3):
        assert post_count(client, f"r{index}").status_code == 200
    body = verify(client).json()
    assert body["status"] == "ok"
    assert body["verified_count"] == 3
    assert body["ledger_length"] == 3
    assert body["unsigned_requests"] == 0
    assert body["first_anomaly"] is None
    assert body["releases_halted"] is False


def test_verify_empty_ledger_is_ok(client):
    body = verify(client).json()
    assert body["status"] == "ok"
    assert body["verified_count"] == 0
    assert body["ledger_length"] == 0


def test_tampered_answer_is_detected_and_halts_new_releases(client):
    for index in range(3):
        assert post_count(client, f"r{index}").status_code == 200

    conn = client.app.state.database.connect()
    conn.execute(
        "UPDATE requests SET noisy_count = noisy_count + 1 "
        "WHERE request_id = 'r1'"
    )

    body = verify(client).json()
    assert body["status"] == "tampered"
    assert body["first_anomaly"]["seq"] == 2
    assert body["first_anomaly"]["kind"] == "payload_mismatch"
    assert body["first_anomaly"]["request_id"] == "r1"
    assert body["verified_count"] == 1
    assert body["releases_halted"] is True

    # New releases stop...
    blocked = post_count(client, "r3")
    assert blocked.status_code == 503
    assert blocked.json()["error"] == "releases_halted"

    # ...but old answers are still readable and replayable for free.
    replay = post_count(client, "r0")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["charged"] is False
    assert client.get("/v1/requests/r0").status_code == 200
    assert client.get("/v1/budget").status_code == 200


def test_halt_persists_across_restart(tmp_path, csv_path):
    settings = make_settings(tmp_path, csv_path)
    with make_client(settings) as client:
        assert post_count(client, "r0").status_code == 200
        conn = client.app.state.database.connect()
        conn.execute(
            "UPDATE requests SET noisy_count = 999 WHERE request_id = 'r0'"
        )
        assert verify(client).json()["status"] == "tampered"

    # A fresh app instance over the same database file stays halted.
    with make_client(settings) as client:
        blocked = post_count(client, "r1")
        assert blocked.status_code == 503
        assert blocked.json()["error"] == "releases_halted"
        replay = post_count(client, "r0")
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True


def test_deleted_middle_row_is_detected(client):
    for index in range(3):
        assert post_count(client, f"r{index}").status_code == 200
    conn = client.app.state.database.connect()
    conn.execute("DELETE FROM release_ledger WHERE seq = 2")

    body = verify(client).json()
    assert body["status"] == "tampered"
    assert body["first_anomaly"]["kind"] == "sequence_gap"
    assert body["first_anomaly"]["seq"] == 2
    assert body["verified_count"] == 1


def test_deleted_tip_row_is_detected(client):
    for index in range(3):
        assert post_count(client, f"r{index}").status_code == 200
    conn = client.app.state.database.connect()
    conn.execute("DELETE FROM release_ledger WHERE seq = 3")

    body = verify(client).json()
    assert body["status"] == "tampered"
    assert body["first_anomaly"]["kind"] == "tip_mismatch"
    assert body["verified_count"] == 2


def test_forged_signature_is_detected(client):
    assert post_count(client, "r0").status_code == 200
    conn = client.app.state.database.connect()
    conn.execute(
        "UPDATE release_ledger SET signature = '0' * 64 WHERE seq = 1"
    )

    body = verify(client).json()
    assert body["status"] == "tampered"
    assert body["first_anomaly"]["kind"] == "signature_mismatch"
    assert body["verified_count"] == 0


def test_signature_without_answer_is_detected(client):
    assert post_count(client, "r0").status_code == 200
    conn = client.app.state.database.connect()
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM requests WHERE request_id = 'r0'")

    body = verify(client).json()
    assert body["status"] == "tampered"
    assert body["first_anomaly"]["kind"] == "orphaned_signature"


# --------------------------------------------------------------------------
# restarts, key changes and unsigned history
# --------------------------------------------------------------------------
def test_key_change_never_resigns_old_entries(tmp_path, csv_path):
    settings_a = make_settings(tmp_path, csv_path, signing_key="key-A")
    with make_client(settings_a) as client:
        assert post_count(client, "r0").status_code == 200
        assert post_count(client, "r1").status_code == 200
        before = [
            (row["seq"], row["signature"]) for row in ledger_table(client)
        ]

    # Restart with a *different* key: old entries must stay untouched, new
    # releases are refused and verification reports the mismatch.
    settings_b = make_settings(tmp_path, csv_path, signing_key="key-B")
    with make_client(settings_b) as client:
        blocked = post_count(client, "r2")
        assert blocked.status_code == 503
        assert blocked.json()["error"] == "ledger_key_mismatch"
        body = verify(client).json()
        assert body["status"] == "key_mismatch"
        assert body["verified_count"] == 0
        after = [(row["seq"], row["signature"]) for row in ledger_table(client)]
        assert after == before

    # Restart with the original key: the chain continues; history identical.
    with make_client(settings_a) as client:
        assert post_count(client, "r2").status_code == 200
        body = verify(client).json()
        assert body["status"] == "ok"
        assert body["verified_count"] == 3
        rows = ledger_table(client)
        assert [(row["seq"], row["signature"]) for row in rows[:2]] == before
        assert rows[2]["seq"] == 3


def test_signed_database_without_key_refuses_new_releases(tmp_path, csv_path):
    signed = make_settings(tmp_path, csv_path, signing_key="key-A")
    with make_client(signed) as client:
        assert post_count(client, "r0").status_code == 200

    keyless = make_settings(tmp_path, csv_path, signing_key=None)
    with make_client(keyless) as client:
        blocked = post_count(client, "r1")
        assert blocked.status_code == 503
        assert blocked.json()["error"] == "ledger_signing_required"
        replay = post_count(client, "r0")
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True
        body = verify(client).json()
        assert body["status"] == "disabled"
        assert body["ledger_length"] == 1


def test_unsigned_answers_remain_usable_but_never_count_as_verified(
    tmp_path, csv_path
):
    unsigned = make_settings(tmp_path, csv_path, signing_key=None)
    with make_client(unsigned) as client:
        assert post_count(client, "old-0").status_code == 200
        assert post_count(client, "old-1").status_code == 200

    signed = make_settings(tmp_path, csv_path, signing_key="key-A")
    with make_client(signed) as client:
        # Old answers still replay for free.
        replay = post_count(client, "old-0")
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True
        assert replay.json()["charged"] is False

        assert post_count(client, "new-0").status_code == 200
        body = verify(client).json()
        assert body["status"] == "ok"
        assert body["verified_count"] == 1
        assert body["unsigned_requests"] == 2
        # The unsigned answers must not show up as verified.
        assert body["verified_count"] + body["unsigned_requests"] == 3


# --------------------------------------------------------------------------
# admin authentication
# --------------------------------------------------------------------------
def test_verify_requires_admin_token(client):
    missing = verify(client, token=None)
    assert missing.status_code == 401
    assert missing.json()["error"] == "unauthorized"
    wrong = verify(client, token="wrong-token")
    assert wrong.status_code == 401
    assert verify(client).status_code == 200


def test_verify_unavailable_without_admin_token(tmp_path, csv_path):
    settings = make_settings(tmp_path, csv_path, admin_token=None)
    with make_client(settings) as client:
        response = verify(client)
        assert response.status_code == 503
        assert response.json()["error"] == "admin_disabled"


def test_openapi_includes_verify_endpoint(client):
    schema = client.get("/openapi.json").json()
    assert "/v1/admin/verify" in schema["paths"]
    assert "AdminToken" in schema["components"]["securitySchemes"]

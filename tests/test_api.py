"""End-to-end API tests using FastAPI TestClient with a temporary SQLite DB."""

import base64
import importlib
import json
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DR_DB_PATH", str(db_file))
    import app.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def create(client, secret="my-db-root-password", t=3, n=5, **extra):
    body = {"secret": secret, "encoding": "utf-8", "threshold": t, "total": n}
    body.update(extra)
    r = client.post("/api/v1/sessions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_returns_shares_once(client):
    data = create(client)
    assert data["shares_returned"] is True
    assert len(data["shares"]) == 5
    assert data["status"] == "active"
    # Shares are bound to the session id.
    from app.sharing import decode_share

    for token in data["shares"]:
        sid, _, _ = decode_share(token)
        assert sid == data["session_id"]


def test_full_recovery_flow(client):
    data = create(client, secret="master-key-🔑", t=3, n=5)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:3]}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recovered"] is True
    assert body["key"] == "master-key-🔑"
    assert body["status"] == "recovered"


def test_fewer_than_threshold_not_recovered(client):
    data = create(client, t=3, n=5)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["key"] is None
    assert body["shares_required"] == 1

    # Must resend all t shares together; prior partial submission is tracked.
    info = client.get(f"/api/v1/sessions/{sid}").json()
    assert info["submitted_count"] == 2


def test_bad_share_does_not_leak_secret(client):
    data = create(client, secret="S3cr3t", t=3, n=5)
    sid = data["session_id"]
    from app.sharing import decode_share, encode_share

    # Tamper one share byte.
    s_sid, x, y = decode_share(data["shares"][0])
    tampered = encode_share(s_sid, x, bytes([y[0] ^ 0xFF]) + y[1:])

    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [tampered] + data["shares"][1:3]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["key"] is None
    rejected = {item["index"] for item in body["rejected"]}
    assert x in rejected
    assert body["accepted_indices"] == [2, 3]


def test_completely_fabricated_share_rejected(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    # A structurally valid share for this session but with wrong y bytes.
    fake = _make_share(sid, 1, b"xxxx")
    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [fake, data["shares"][1]]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["rejected"][0]["code"] == "integrity_check_failed"


def test_share_from_other_session_rejected(client):
    a = create(client, t=2, n=3)
    b = create(client, t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{a['session_id']}/shares",
        json={"shares": [b["shares"][0], a["shares"][1]]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert len(body["rejected"]) == 1


def test_malformed_share_token(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": ["garbage!!"]}
    )
    assert r.json()["rejected"][0]["code"] == "malformed_share"


def test_recovered_key_returned_only_once(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    first = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert first.json()["key"] is not None
    second = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert second.json()["recovered"] is True
    assert second.json()["key"] is None
    assert second.json()["replay"] is True


def test_revoke_blocks_recovery_and_is_idempotent(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r1 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r1.json()["status"] == "revoked"
    assert r1.json()["revoked"] is True
    r2 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r2.json()["status"] == "revoked"
    assert r2.json()["replay"] is True

    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "session_revoked"


def test_recovered_session_cannot_be_revoked(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    r = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "session_not_revocable"


def test_creation_idempotency_key(client):
    body = {
        "secret": "same-secret",
        "encoding": "utf-8",
        "threshold": 2,
        "total": 3,
        "idempotency_key": "abc-key-1",
    }
    r1 = client.post("/api/v1/sessions", json=body)
    r2 = client.post("/api/v1/sessions", json=body)
    assert r1.json()["session_id"] == r2.json()["session_id"]
    assert r1.json()["shares"] is not None
    # Replay must not re-expose shares.
    assert r2.json()["shares"] is None
    assert r2.json()["replay"] is True


def test_idempotency_key_same_via_header(client):
    body = {"secret": "s", "threshold": 2, "total": 3}
    r1 = client.post(
        "/api/v1/sessions", json=body, headers={"Idempotency-Key": "hdr-1"}
    )
    r2 = client.post(
        "/api/v1/sessions", json=body, headers={"Idempotency-Key": "hdr-1"}
    )
    assert r1.json()["session_id"] == r2.json()["session_id"]


def test_idempotency_key_reuse_with_different_payload_conflicts(client):
    base = {"secret": "s", "threshold": 2, "total": 3, "idempotency_key": "k1"}
    client.post("/api/v1/sessions", json=base)
    changed = {**base, "secret": "different"}
    r = client.post("/api/v1/sessions", json=changed)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency_conflict"


def test_submit_idempotent_duplicate_in_request(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [data["shares"][0], data["shares"][0]]},
    )
    body = r.json()
    assert [i["code"] for i in body["rejected"]] == ["duplicate_index_in_request"]
    assert body["accepted_indices"] == [1]


def test_session_not_found(client):
    assert client.get("/api/v1/sessions/deadbeef").status_code == 404
    assert (
        client.post(
            "/api/v1/sessions/deadbeef/shares", json={"shares": []}
        ).status_code
        in (404, 422)
    )


def test_threshold_validation(client):
    r = client.post(
        "/api/v1/sessions",
        json={"secret": "x", "threshold": 4, "total": 2},
    )
    assert r.status_code == 422


def test_key_size_limit(client):
    r = client.post(
        "/api/v1/sessions",
        json={
            "secret": "A" * (4097),
            "threshold": 2,
            "total": 3,
        },
    )
    assert r.status_code == 422


def test_body_size_limit(client):
    # A single ~2 MB share token must be rejected before parsing.
    r = client.post(
        "/api/v1/sessions/whatever/shares",
        content=json.dumps({"shares": ["A" * 2_000_000]}),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_hex_and_base64_roundtrip(client):
    raw = bytes(range(256))
    # hex
    d = create(client, secret=raw.hex(), encoding="hex", t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{d['session_id']}/shares",
        json={"shares": d["shares"][:2]},
    ).json()
    assert bytes.fromhex(r["key"]) == raw

    # base64
    b64 = base64.b64encode(raw).decode()
    d = create(client, secret=b64, encoding="base64", t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{d['session_id']}/shares",
        json={"shares": d["shares"][:2]},
    ).json()
    assert base64.b64decode(r["key"]) == raw


def test_database_contains_no_secret_or_share_bytes(client):
    secret = "DO-NOT-PERSIST-ME"
    data = create(client, secret=secret, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    import sqlite3

    db_path = os.environ["DR_DB_PATH"]
    conn = sqlite3.connect(db_path)
    blob = b"\n".join(
        ("|".join(map(str, row))).encode()
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    )
    for table in ("sessions", "session_shares", "submitted_shares", "idempotency"):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        text = json.dumps(rows, default=str)
        assert secret not in text
        for token in data["shares"]:
            assert token not in text
    assert blob  # tables exist


def _make_share(sid, x, y):
    from app.sharing import encode_share

    return encode_share(sid, x, y)


class TestApiKeyAuth:
    @pytest.fixture()
    def authed_client(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DR_DB_PATH", str(tmp_path / "auth.db"))
        monkeypatch.setenv("DR_API_KEY", "secret-token")
        import app.main as main

        importlib.reload(main)
        with TestClient(main.app) as c:
            yield c

    def test_health_open(self, authed_client):
        assert authed_client.get("/health").status_code == 200

    def test_missing_key_rejected(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
        )
        assert r.status_code == 401

    def test_wrong_key_rejected(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
            headers={"X-API-Key": "nope"},
        )
        assert r.status_code == 401

    def test_correct_key_accepted(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
            headers={"X-API-Key": "secret-token"},
        )
        assert r.status_code == 201


def test_concurrent_idempotent_creates_single_session(client):
    """Parallel requests sharing one idempotency key collapse to one session."""
    import threading
    import uuid

    from app.database import sha256_hex

    database = client.app.state.db
    key = "race-" + uuid.uuid4().hex
    request_hash = sha256_hex(b"req")
    outcomes = []
    barrier = threading.Barrier(8)

    def worker():
        sid = uuid.uuid4().hex
        barrier.wait()
        try:
            outcomes.append(
                database.create_session(
                    sid,
                    threshold=2,
                    total_shares=3,
                    key_digest="d",
                    key_encoding="utf-8",
                    key_length=1,
                    share_checksums={1: "a", 2: "b", 3: "c"},
                    idempotency_key=key,
                    request_hash=request_hash,
                )
            )
        except Exception as exc:  # pragma: no cover - failure path
            outcomes.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not any(isinstance(o, Exception) for o in outcomes), outcomes
    session_ids = {o[0] for o in outcomes}
    assert len(session_ids) == 1
    assert sum(1 for o in outcomes if o[1]) == 1  # exactly one created_now

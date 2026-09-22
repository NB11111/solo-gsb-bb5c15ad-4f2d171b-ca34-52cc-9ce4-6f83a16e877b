"""FastAPI application: Shamir-secret-sharded disaster-recovery key service."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field

from . import sharing
from .database import Database, IdempotencyConflict, row_to_dict, share_digest

DB_PATH = os.environ.get("DR_DB_PATH", os.path.join("data", "sss.db"))
# When set, every /api/v1 call must present it in the X-API-Key header.
API_KEY = os.environ.get("DR_API_KEY") or None

MAX_KEY_BYTES = 4096
MAX_REQUEST_BODY_BYTES = 1024 * 1024  # generous bound: 255 shares of 4 KiB each


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def decode_key(raw: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        data = raw.encode("utf-8")
    elif encoding == "hex":
        try:
            data = bytes.fromhex(raw)
        except ValueError as exc:
            raise HTTPException(422, "key is not valid hexadecimal") from exc
    else:  # base64
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(422, "key is not valid base64") from exc
    if not data:
        raise HTTPException(422, "key must not be empty")
    if len(data) > MAX_KEY_BYTES:
        raise HTTPException(422, f"key must not exceed {MAX_KEY_BYTES} bytes")
    return data


def encode_key(data: bytes, encoding: str) -> str:
    if encoding == "utf-8":
        return data.decode("utf-8")
    if encoding == "hex":
        return data.hex()
    return base64.b64encode(data).decode("ascii")


def error(code: str, message: str, http_status: int, details=None) -> HTTPException:
    return HTTPException(
        status_code=http_status,
        detail={"code": code, "message": message, "details": details},
    )


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

class CreateSessionRequest(BaseModel):
    secret: str = Field(..., min_length=1, description="Key to shard")
    encoding: Literal["utf-8", "hex", "base64"] = "utf-8"
    threshold: int = Field(..., ge=2, le=255)
    total: int = Field(..., ge=2, le=255)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)


class SubmitSharesRequest(BaseModel):
    shares: list[str] = Field(..., min_length=1, max_length=255)


# --------------------------------------------------------------------------
# Lifespan / app
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = Database(DB_PATH)
    try:
        yield
    finally:
        app.state.db.close()


app = FastAPI(
    title="Disaster Recovery Key Sharding API",
    version="1.0.0",
    description="Shard recovery keys with Shamir's threshold scheme and "
    "reconstruct them only from integrity-verified shares.",
    lifespan=lifespan,
)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.headers.get("content-length"):
            try:
                size = int(request.headers["content-length"])
            except ValueError:
                size = 0
            if size > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "payload_too_large",
                            "message": "request body exceeds limit",
                            "details": {"max_bytes": MAX_REQUEST_BODY_BYTES},
                        }
                    },
                )
        return await call_next(request)


app.add_middleware(BodySizeLimitMiddleware)


def db(request: Request) -> Database:
    return request.app.state.db


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY is not None and not (
        x_api_key is not None and hmac.compare_digest(x_api_key, API_KEY)
    ):
        raise error("unauthorized", "missing or invalid API key", 401)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        body = detail
    else:
        body = {"code": "error", "message": str(detail), "details": None}
    return JSONResponse(status_code=exc.status_code, content={"error": body})


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.post(
    "/api/v1/sessions",
    tags=["sessions"],
    status_code=201,
    dependencies=[Depends(require_api_key)],
)
def create_session(
    payload: CreateSessionRequest,
    database: Database = Depends(db),
    idempotency_key: str | None = Header(default=None),
):
    """Create a recovery session. Shares are returned exactly once."""
    if payload.total < payload.threshold:
        raise error(
            "invalid_parameters",
            "total must be greater than or equal to threshold",
            422,
        )

    key = decode_key(payload.secret, payload.encoding)
    key_digest = hashlib.sha256(key).hexdigest()

    idem = payload.idempotency_key or idempotency_key
    request_hash = hashlib.sha256(
        key_digest.encode("ascii")
        + f"|{payload.threshold}|{payload.total}|{payload.encoding}".encode()
    ).hexdigest()

    session_id = uuid.uuid4().hex
    # Split before insert so a malformed key never creates a session row.
    pairs = sharing.split_secret(key, payload.threshold, payload.total)
    checksums = {x: share_digest(session_id, x, y) for x, y in pairs}

    try:
        stored_id, created_now = database.create_session(
            session_id,
            threshold=payload.threshold,
            total_shares=payload.total,
            key_digest=key_digest,
            key_encoding=payload.encoding,
            key_length=len(key),
            share_checksums=checksums,
            idempotency_key=idem,
            request_hash=request_hash,
        )
    except IdempotencyConflict:
        raise error(
            "idempotency_conflict",
            "idempotency key was already used with a different request",
            409,
        )

    if not created_now:
        # Replay: shares were issued in the original call and must never be
        # returned again. Return the session metadata instead.
        row = database.get_session(stored_id)
        return {
            "session_id": stored_id,
            "status": row["status"],
            "threshold": row["threshold"],
            "total_shares": row["total_shares"],
            "shares": None,
            "shares_returned": False,
            "replay": True,
            "message": "session already created; shares were returned once "
            "in the original response and cannot be retrieved again",
        }

    # Map computed shares to the actual stored id (they are the same id here).
    tokens = [sharing.encode_share(session_id, x, y) for x, y in pairs]
    return {
        "session_id": session_id,
        "status": "active",
        "threshold": payload.threshold,
        "total_shares": payload.total,
        "shares": tokens,
        "share_checksums": [
            {"index": x, "digest": checksums[x]} for x, _ in pairs
        ],
        "shares_returned": True,
        "replay": False,
        "message": "store these shares securely; they are shown only once",
    }


@app.get(
    "/api/v1/sessions/{session_id}",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def get_session(session_id: str, database: Database = Depends(db)):
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    data = row_to_dict(row)
    submitted = database.submitted_indices(session_id)
    return {
        "session_id": data["id"],
        "status": data["status"],
        "threshold": data["threshold"],
        "total_shares": data["total_shares"],
        "key_digest": data["key_digest"],
        "submitted_share_indices": submitted,
        "submitted_count": len(submitted),
        "recovery_attempts": data["recovery_attempts"],
        "created_at": data["created_at"],
        "recovered_at": data["recovered_at"],
        "revoked_at": data["revoked_at"],
    }


@app.post(
    "/api/v1/sessions/{session_id}/shares",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def submit_shares(
    session_id: str,
    payload: SubmitSharesRequest,
    database: Database = Depends(db),
):
    """Verify every share's integrity, then reconstruct if threshold is met.

    A bad share is reported as rejected and never participates in
    interpolation, so it cannot influence (or leak) the recovered key.
    """
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    if row["status"] == "revoked":
        raise error("session_revoked", "session has been revoked", 409)
    if row["status"] == "recovered":
        return {
            "session_id": session_id,
            "status": "recovered",
            "recovered": True,
            "key": None,
            "replay": True,
            "message": "key was already returned once and is not shown again",
            "accepted_indices": [],
            "rejected": [],
        }

    threshold = row["threshold"]
    valid: dict[int, bytes] = {}
    rejected: list[dict[str, str | int]] = []

    seen: set[int] = set()
    for token in payload.shares:
        if not isinstance(token, str) or len(token) > 8192:
            rejected.append({"index": 0, "code": "malformed_share"})
            continue
        try:
            token_session, x, y = sharing.decode_share(token)
        except ValueError:
            rejected.append({"index": 0, "code": "malformed_share"})
            continue
        if not hmac.compare_digest(token_session, session_id):
            # Do not reveal which session the share belongs to.
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        if x in seen:
            rejected.append({"index": x, "code": "duplicate_index_in_request"})
            continue
        seen.add(x)

        digest = database.get_share_digest(session_id, x)
        actual = share_digest(session_id, x, y)
        if len(y) != row["key_length"]:
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        if digest is None or not hmac.compare_digest(digest, actual):
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        valid[x] = y

    if rejected:
        database.bump_attempt(session_id)

    for x in valid:
        database.mark_submitted(session_id, x)

    submitted_indices = database.submitted_indices(session_id)

    if len(valid) < threshold:
        return {
            "session_id": session_id,
            "status": "active",
            "recovered": False,
            "key": None,
            "replay": False,
            "accepted_indices": sorted(valid),
            "rejected": rejected,
            "submitted_count": len(submitted_indices),
            "shares_required": threshold - len(valid),
            "message": "not yet enough verified shares; resend all required "
            "shares together in a single request",
        }

    # Every point in `valid` is individually authenticated against the stored
    # digest, so interpolation operates only on genuine shares.
    chosen = sorted(valid.items())[:threshold]
    recovered = sharing.reconstruct_secret(
        [(x, y) for x, y in chosen]
    )
    recovered_digest = hashlib.sha256(recovered).hexdigest()
    if not hmac.compare_digest(recovered_digest, row["key_digest"]):
        # Defence in depth: cannot happen with t valid shares, but never
        # return a value whose checksum does not match.
        database.bump_attempt(session_id)
        raise error(
            "recovery_failed",
            "reconstructed key failed checksum verification",
            400,
        )

    database.mark_recovered(session_id)
    encoding = row["key_encoding"]
    try:
        key_text = encode_key(recovered, encoding)
    except UnicodeDecodeError:
        # Key bytes were not originally UTF-8 text (encoding stored wrongly);
        # fall back to hex so no data is lost.
        key_text = recovered.hex()
        encoding = "hex"

    return {
        "session_id": session_id,
        "status": "recovered",
        "recovered": True,
        "key": key_text,
        "key_encoding": encoding,
        "key_digest": recovered_digest,
        "replay": False,
        "accepted_indices": sorted(valid),
        "rejected": rejected,
        "message": "key is shown exactly once; store it securely",
    }


@app.post(
    "/api/v1/sessions/{session_id}/revoke",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def revoke_session(session_id: str, database: Database = Depends(db)):
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    if row["status"] == "recovered":
        raise error(
            "session_not_revocable",
            "a recovered session cannot be revoked",
            409,
        )
    changed = database.revoke_session(session_id)
    row = database.get_session(session_id)
    return {
        "session_id": session_id,
        "status": row["status"],
        "revoked": True,
        "revoked_at": row["revoked_at"],
        "replay": not changed,
    }

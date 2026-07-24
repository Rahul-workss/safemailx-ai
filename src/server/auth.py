import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from threading import Lock
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from server.settings import (
    FEATURE_REFRESH_TOKEN_ENABLED,
    JWT_EXPIRES_MINUTES,
    JWT_SECRET,
    REDIS_URL,
    REFRESH_TOKEN_EXPIRES_DAYS,
    SAFEMAILX_ADMIN_EMAIL,
    SAFEMAILX_ADMIN_PASSWORD,
    SAFEMAILX_PRODUCTION,
    SAFEMAILX_REQUIRE_AUTH,
)


bearer_scheme = HTTPBearer(auto_error=False)
_local_oauth_codes: dict[str, tuple[float, dict[str, str]]] = {}
_local_oauth_states: dict[str, float] = {}
_local_oauth_lock = Lock()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _json_b64(data: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(data, separators=(",", ":")).encode("utf-8"))


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        210_000,
    )
    return base64.urlsafe_b64encode(digest).decode("ascii"), salt


def create_signed_token(payload: dict[str, Any], expires_minutes: int = JWT_EXPIRES_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    signed_payload = {
        **payload,
        "jti": payload.get("jti") or str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_json_b64(header)}.{_json_b64(signed_payload)}"
    signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def create_access_token(email: str, user_id: str = "local", name: str | None = None) -> str:
    payload = {"sub": email, "uid": user_id, "type": "access"}
    if name:
        payload["name"] = name
    return create_signed_token(payload)


def create_refresh_token(email: str, user_id: str) -> str | None:
    if not FEATURE_REFRESH_TOKEN_ENABLED:
        return None
    return create_signed_token(
        {"uid": user_id, "sub": email, "type": "refresh"},
        expires_minutes=REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60,
    )


def _revocation_client():
    try:
        import redis
        return redis.from_url(REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def _is_revoked(payload: dict[str, Any]) -> bool:
    jti = payload.get("jti")
    if not jti:
        return False
    client = _revocation_client()
    if client is None:
        return SAFEMAILX_PRODUCTION
    try:
        return bool(client.exists(f"safemailx:revoked:{jti}"))
    except Exception:
        # Fail closed in production: accepting tokens during a Redis outage
        # would silently defeat logout revocation.
        return SAFEMAILX_PRODUCTION


def revoke_token(payload: dict[str, Any]) -> None:
    jti = payload.get("jti")
    if not jti:
        return
    remaining = max(1, int(payload.get("exp", 0)) - int(datetime.now(timezone.utc).timestamp()))
    client = _revocation_client()
    if client is None:
        if SAFEMAILX_PRODUCTION:
            raise HTTPException(status_code=503, detail="Logout service temporarily unavailable")
        return
    try:
        client.setex(f"safemailx:revoked:{jti}", remaining, "1")
    except Exception as exc:
        if SAFEMAILX_PRODUCTION:
            raise HTTPException(status_code=503, detail="Logout service temporarily unavailable") from exc


def create_ws_ticket(user_id: str, scan_id: str, expires_seconds: int = 60) -> str:
    ticket = secrets.token_urlsafe(32)
    client = _revocation_client()
    if client is None:
        raise HTTPException(status_code=503, detail="Realtime scan updates unavailable")
    try:
        client.setex(f"safemailx:ws-ticket:{ticket}", expires_seconds, f"{user_id}:{scan_id}")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Realtime scan updates unavailable") from exc
    return ticket


def consume_ws_ticket(ticket: str, scan_id: str) -> str | None:
    """Consume a one-time scan-events ticket and return its owner."""
    client = _revocation_client()
    if client is None:
        return None
    key = f"safemailx:ws-ticket:{ticket}"
    try:
        try:
            value = client.getdel(key)
        except AttributeError:
            value = client.get(key)
            client.delete(key)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        if not isinstance(value, str):
            return None
        owner_id, stored_scan_id = value.split(":", 1)
        if hmac.compare_digest(stored_scan_id, scan_id):
            return owner_id
        return None
    except Exception:
        return None


def create_oauth_exchange_code(email: str, user_id: str, name: str = "User") -> str:
    """Create a short-lived, single-use code for mobile OAuth handoff."""
    code = secrets.token_urlsafe(32)
    client = _revocation_client()
    if client is None:
        if SAFEMAILX_PRODUCTION:
            raise HTTPException(status_code=503, detail="OAuth handoff unavailable")
        with _local_oauth_lock:
            _local_oauth_codes[code] = (
                time.monotonic() + 90,
                {"email": email, "uid": user_id, "name": name},
            )
        return code
    try:
        client.setex(
            f"safemailx:oauth-exchange:{code}",
            90,
            json.dumps({"email": email, "uid": user_id, "name": name}),
        )
    except Exception as exc:
        if SAFEMAILX_PRODUCTION:
            raise HTTPException(status_code=503, detail="OAuth handoff unavailable") from exc
        with _local_oauth_lock:
            _local_oauth_codes[code] = (
                time.monotonic() + 90,
                {"email": email, "uid": user_id, "name": name},
            )
    return code


def consume_oauth_exchange_code(code: str) -> dict[str, str] | None:
    client = _revocation_client()
    if client is None:
        with _local_oauth_lock:
            stored = _local_oauth_codes.pop(code, None)
        if not stored or stored[0] < time.monotonic():
            return None
        return stored[1]
    try:
        key = f"safemailx:oauth-exchange:{code}"
        try:
            value = client.getdel(key)
        except AttributeError:
            value = client.get(key)
            client.delete(key)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        payload = json.loads(value) if isinstance(value, str) else None
        if not isinstance(payload, dict):
            if not SAFEMAILX_PRODUCTION:
                with _local_oauth_lock:
                    stored = _local_oauth_codes.pop(code, None)
                if stored and stored[0] >= time.monotonic():
                    return stored[1]
            return None
        if not all(isinstance(payload.get(key), str) and payload[key] for key in ("email", "uid")):
            return None
        return payload
    except Exception:
        if SAFEMAILX_PRODUCTION:
            return None
        with _local_oauth_lock:
            stored = _local_oauth_codes.pop(code, None)
        if not stored or stored[0] < time.monotonic():
            return None
        return stored[1]


def consume_oauth_state(payload: dict[str, Any]) -> bool:
    """Mark a signed OAuth state as used; return False on replay."""
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        return False
    remaining = max(1, int(payload.get("exp", 0)) - int(datetime.now(timezone.utc).timestamp()))
    client = _revocation_client()
    key = f"safemailx:oauth-state-used:{jti}"
    if client is not None:
        try:
            accepted = client.set(key, "1", ex=remaining, nx=True)
            return bool(accepted)
        except Exception:
            if SAFEMAILX_PRODUCTION:
                return False
    with _local_oauth_lock:
        now = time.monotonic()
        for old_key, expiry in list(_local_oauth_states.items()):
            if expiry <= now:
                _local_oauth_states.pop(old_key, None)
        if jti in _local_oauth_states:
            return False
        _local_oauth_states[jti] = now + remaining
        return True


def verify_access_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(
            JWT_SECRET.encode("utf-8"),
            signing_input.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            raise ValueError("bad signature")
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("expired")
        if _is_revoked(payload):
            raise ValueError("revoked")
        token_type = payload.get("type")
        if expected_type == "refresh" and token_type != "refresh":
            raise ValueError("wrong token type")
        if expected_type == "access" and token_type == "refresh":
            raise ValueError("wrong token type")
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


def ensure_admin_user(repository) -> dict[str, Any]:
    user = repository.get_user_by_email(SAFEMAILX_ADMIN_EMAIL)
    if user:
        return user
    password_hash, salt = hash_password(SAFEMAILX_ADMIN_PASSWORD)
    user_id = repository.create_user(
        email=SAFEMAILX_ADMIN_EMAIL,
        password_hash=password_hash,
        salt=salt,
    )
    return repository.get_user_by_id(user_id)


def validate_login(repository, email: str, password: str) -> dict[str, Any] | None:
    ensure_admin_user(repository)
    user = repository.get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"], user["salt"]):
        return None
    return user


def require_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any] | None:
    if not SAFEMAILX_REQUIRE_AUTH:
        return {"uid": "local", "sub": "local"}
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return verify_access_token(credentials.credentials, expected_type="access")

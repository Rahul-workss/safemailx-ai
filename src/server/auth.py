import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from server.settings import (
    JWT_EXPIRES_MINUTES,
    JWT_SECRET,
    TRUSTMAIL_ADMIN_EMAIL,
    TRUSTMAIL_ADMIN_PASSWORD,
    TRUSTMAIL_REQUIRE_AUTH,
)


bearer_scheme = HTTPBearer(auto_error=False)


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


def create_access_token(email: str, user_id: str = "local") -> str:
    return create_signed_token({"sub": email, "uid": user_id})


def verify_access_token(token: str) -> dict[str, Any]:
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
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


def ensure_admin_user(repository) -> dict[str, Any]:
    user = repository.get_user_by_email(TRUSTMAIL_ADMIN_EMAIL)
    if user:
        return user
    password_hash, salt = hash_password(TRUSTMAIL_ADMIN_PASSWORD)
    user_id = repository.create_user(
        email=TRUSTMAIL_ADMIN_EMAIL,
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
    if not TRUSTMAIL_REQUIRE_AUTH:
        return {"uid": "local", "sub": "local"}
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return verify_access_token(credentials.credentials)

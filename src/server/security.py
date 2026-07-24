"""Small security primitives shared by the API routes and middleware."""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from server.settings import (
    AUTH_LOCKOUT_MINUTES,
    MAX_BODY_BYTES,
    RATE_LIMIT_AUTH_LOGIN,
    RATE_LIMIT_AUTH_REGISTER,
    RATE_LIMIT_AUTH_RESET,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_GMAIL,
    RATE_LIMIT_INSTANT_SCAN,
    RATE_LIMIT_SCANS,
    REDIS_URL,
    SAFEMAILX_PRODUCTION,
)


_memory_lock = threading.Lock()
_memory_counters: dict[str, tuple[int, float]] = {}


def _redis_client():
    try:
        import redis
        return redis.from_url(REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    except Exception:
        return None


def _parse_limit(value: str) -> tuple[int, int]:
    try:
        amount, unit = value.strip().lower().split("/", 1)
        count = max(1, int(amount))
    except (TypeError, ValueError):
        return 60, 60
    seconds = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
    }.get(unit.rstrip("s"), 60)
    return count, seconds


def consume_rate_limit(key: str, rule: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds), using Redis when available."""
    limit, window = _parse_limit(rule)
    redis_client = _redis_client()
    if redis_client is not None:
        try:
            redis_key = f"safemailx:ratelimit:{key}"
            count = int(redis_client.incr(redis_key))
            if count == 1:
                redis_client.expire(redis_key, window)
            ttl = max(1, int(redis_client.ttl(redis_key)))
            return count <= limit, ttl
        except Exception:
            if SAFEMAILX_PRODUCTION:
                return False, 60

    now = time.monotonic()
    with _memory_lock:
        count, started = _memory_counters.get(key, (0, now))
        if now - started >= window:
            count, started = 0, now
        count += 1
        _memory_counters[key] = (count, started)
        retry_after = max(1, int(window - (now - started)))
    return count <= limit, retry_after


def _email_key(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def _memory_value(key: str) -> tuple[int, float] | None:
    with _memory_lock:
        value = _memory_counters.get(key)
        if value and value[1] > time.monotonic():
            return value
        if value:
            _memory_counters.pop(key, None)
    return None


def login_lock_status(email: str) -> int:
    key = f"safemailx:login:lock:{_email_key(email)}"
    redis_client = _redis_client()
    if redis_client is not None:
        try:
            return max(0, int(redis_client.ttl(key)))
        except Exception:
            pass
    value = _memory_value(key)
    return max(0, int(value[1] - time.monotonic())) if value else 0


def record_login_failure(email: str) -> int:
    """Record a failed login and return the new lockout duration, if any."""
    digest = _email_key(email)
    count_key = f"safemailx:login:fail:{digest}"
    redis_client = _redis_client()
    count = 0
    if redis_client is not None:
        try:
            count = int(redis_client.incr(count_key))
            if count == 1:
                redis_client.expire(count_key, 600)
        except Exception:
            redis_client = None
    if redis_client is None:
        now = time.monotonic()
        with _memory_lock:
            old_count, started = _memory_counters.get(count_key, (0, now))
            if now - started >= 600:
                old_count, started = 0, now
            count = old_count + 1
            _memory_counters[count_key] = (count, started + 600)

    if count < 5:
        return 0
    duration = min(3600, AUTH_LOCKOUT_MINUTES * 60 * (2 ** min(count - 5, 2)))
    lock_key = f"safemailx:login:lock:{digest}"
    if redis_client is not None:
        try:
            redis_client.setex(lock_key, duration, "1")
        except Exception:
            pass
    else:
        with _memory_lock:
            _memory_counters[lock_key] = (1, time.monotonic() + duration)
    return duration


def clear_login_failures(email: str) -> None:
    digest = _email_key(email)
    redis_client = _redis_client()
    if redis_client is not None:
        try:
            redis_client.delete(
                f"safemailx:login:fail:{digest}",
                f"safemailx:login:lock:{digest}",
            )
            return
        except Exception:
            pass
    with _memory_lock:
        _memory_counters.pop(f"safemailx:login:fail:{digest}", None)
        _memory_counters.pop(f"safemailx:login:lock:{digest}", None)


def _rule_for_path(path: str) -> str:
    if path == "/auth/login":
        return RATE_LIMIT_AUTH_LOGIN
    if path in {"/auth/register", "/auth/send-otp"}:
        return RATE_LIMIT_AUTH_REGISTER
    if path in {"/auth/forgot-password", "/auth/reset-password"}:
        return RATE_LIMIT_AUTH_RESET
    if path.startswith("/api/instant/"):
        return RATE_LIMIT_INSTANT_SCAN
    if path.startswith("/api/scans"):
        return RATE_LIMIT_SCANS
    if path.startswith("/api/gmail"):
        return RATE_LIMIT_GMAIL
    return RATE_LIMIT_DEFAULT


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    return JSONResponse(
                        {"detail": "Request too large"},
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse({"detail": "Invalid content length"}, status_code=400)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if SAFEMAILX_PRODUCTION:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith(("/auth/", "/api/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Local development and unit tests remain unrestricted; production is
        # enabled automatically through SAFEMAILX_PRODUCTION.
        if not SAFEMAILX_PRODUCTION or request.url.path in {
            "/api/health",
            "/api/health/llm",
        }:
            return await call_next(request)
        client_host = request.client.host if request.client else "unknown"
        rule = _rule_for_path(request.url.path)
        allowed, retry_after = consume_rate_limit(
            f"ip:{client_host}:{request.method}:{request.url.path}", rule
        )
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests. Please try again later."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

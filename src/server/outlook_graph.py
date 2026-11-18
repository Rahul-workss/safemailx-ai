"""Microsoft Graph API client for SafeMail X Outlook integration.

Wraps httpx with:
- ImmutableId preference header
- 429/503/504 retry with Retry-After (capped at 30 s, max 3 retries)
- 401 → one forced refresh retry
- Streaming MIME download with size limit
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from server.settings import MAX_BODY_BYTES

logger = logging.getLogger("outlook_graph")

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_DEFAULT_HEADERS = {
    "Prefer": 'IdType="ImmutableId"',
}
_MAX_RETRIES = 3
_RETRY_CAP_SECONDS = 30


class GraphError(Exception):
    """Raised for non-retriable Microsoft Graph API errors."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"Graph API error {status} [{code}]: {message}")
        self.status = status
        self.code = code
        self.message = message


class GraphClient:
    """Per-user Graph API client. Automatically refreshes access token on 401."""

    def __init__(self, user_id: str, repository: Any) -> None:
        self.user_id = user_id
        self.repository = repository
        self._access_token: str | None = None

    def _get_token(self) -> str:
        from server.outlook_oauth import get_access_token
        self._access_token = get_access_token(self.repository, self.user_id)
        return self._access_token

    def _headers(self) -> dict[str, str]:
        return {
            **_DEFAULT_HEADERS,
            "Authorization": f"Bearer {self._get_token()}",
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        headers: dict | None = None,
        stream: bool = False,
        _retry_on_401: bool = True,
    ) -> httpx.Response:
        h = {**self._headers(), **(headers or {})}
        for attempt in range(_MAX_RETRIES):
            try:
                if stream:
                    resp = httpx.stream(method, url, headers=h, timeout=60)
                else:
                    resp = httpx.request(method, url, headers=h, json=json, timeout=30)
            except httpx.TimeoutException as exc:
                logger.warning("Graph timeout on attempt %d: %s", attempt + 1, exc)
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(min(2 ** attempt, _RETRY_CAP_SECONDS))
                    continue
                raise

            if resp.status_code in (429, 503, 504):
                retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                wait = min(retry_after, _RETRY_CAP_SECONDS)
                logger.warning(
                    "Graph rate-limited (%d) on attempt %d — waiting %ds",
                    resp.status_code, attempt + 1, wait,
                )
                time.sleep(wait)
                continue

            if resp.status_code == 401 and _retry_on_401:
                # Force a token refresh and retry once
                from server.outlook_oauth import get_access_token
                self._access_token = get_access_token(self.repository, self.user_id)
                h["Authorization"] = f"Bearer {self._access_token}"
                return self._request(method, url, json=json, headers=headers, stream=stream, _retry_on_401=False)

            if not (200 <= resp.status_code < 300):
                try:
                    err = resp.json().get("error", {})
                    code = err.get("code", "Unknown")
                    msg = err.get("message", resp.text[:200])
                except Exception:
                    code, msg = "ParseError", resp.text[:200]
                raise GraphError(resp.status_code, code, msg)

            return resp

        raise RuntimeError(f"Graph request to {url} failed after {_MAX_RETRIES} retries")

    def get(self, path: str, **kwargs) -> dict:
        url = f"{_GRAPH_BASE}{path}" if not path.startswith("http") else path
        resp = self._request("GET", url, **kwargs)
        return resp.json()

    def patch(self, path: str, body: dict) -> dict:
        url = f"{_GRAPH_BASE}{path}" if not path.startswith("http") else path
        resp = self._request("PATCH", url, json=body, headers={"Content-Type": "application/json"})
        return resp.json() if resp.content else {}

    def post(self, path: str, body: dict | None = None) -> dict:
        url = f"{_GRAPH_BASE}{path}" if not path.startswith("http") else path
        resp = self._request("POST", url, json=body or {}, headers={"Content-Type": "application/json"})
        return resp.json() if resp.content else {}

    def get_mime(self, message_id: str, max_bytes: int = MAX_BODY_BYTES) -> bytes:
        """Stream-download the raw MIME source of a message.

        Aborts cleanly if the response exceeds *max_bytes*.
        """
        url = f"{_GRAPH_BASE}/me/messages/{message_id}/$value"
        h = {**self._headers(), "Accept": "text/plain"}

        chunks: list[bytes] = []
        total = 0
        with httpx.stream("GET", url, headers=h, timeout=60) as resp:
            if resp.status_code == 401:
                # Refresh and retry once (not via _request to avoid streaming complexity)
                from server.outlook_oauth import get_access_token
                self._access_token = get_access_token(self.repository, self.user_id)
                h["Authorization"] = f"Bearer {self._access_token}"
                # Fall through to a fresh stream below
                resp.close()
                resp = None

            if resp is not None and not (200 <= resp.status_code < 300):
                try:
                    err = resp.json().get("error", {})
                    code = err.get("code", "Unknown")
                    msg = err.get("message", "")
                except Exception:
                    code, msg = "ParseError", ""
                raise GraphError(resp.status_code, code, msg)

            if resp is None:
                with httpx.stream("GET", url, headers=h, timeout=60) as resp2:
                    if not (200 <= resp2.status_code < 300):
                        raise GraphError(resp2.status_code, "RefreshFailed", "MIME re-fetch failed after token refresh")
                    for chunk in resp2.iter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise RuntimeError(
                                f"Outlook message {message_id} exceeds max body size ({max_bytes} bytes)"
                            )
                        chunks.append(chunk)
            else:
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(
                            f"Outlook message {message_id} exceeds max body size ({max_bytes} bytes)"
                        )
                    chunks.append(chunk)

        return b"".join(chunks)

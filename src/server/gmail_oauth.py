import base64
import os
import pickle
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from server.settings import GMAIL_OAUTH_REDIRECT_URI, GMAIL_TOKEN_ENCRYPTION_KEY
from utils.config import GMAIL_CREDENTIALS_PATH


GMAIL_APP_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"


def _cipher() -> Fernet | None:
    if not GMAIL_TOKEN_ENCRYPTION_KEY:
        return None
    return Fernet(GMAIL_TOKEN_ENCRYPTION_KEY.encode("utf-8"))


def _allow_insecure_oauth_transport_for_dev(redirect_uri: str) -> None:
    parsed = urlparse(redirect_uri)
    if parsed.scheme != "http":
        return
    # Local mobile testing may use a LAN callback like http://192.168.x.x:8080.
    # Production readiness still requires HTTPS; this only allows OAuthLib to
    # build/fetch tokens in local development.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


import json
from google.oauth2.credentials import Credentials

def encode_credentials(creds) -> str:
    raw = creds.to_json().encode("utf-8")
    cipher = _cipher()
    if cipher:
        raw = cipher.encrypt(raw)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_credentials(blob: str):
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    cipher = _cipher()
    if cipher:
        raw = cipher.decrypt(raw)
    return Credentials.from_authorized_user_info(json.loads(raw.decode("utf-8")))


def build_oauth_flow(state: str | None = None, redirect_uri: str | None = None, scopes: list[str] | None = None, credentials_path: str | None = None) -> Flow:
    resolved_redirect_uri = redirect_uri or GMAIL_OAUTH_REDIRECT_URI
    _allow_insecure_oauth_transport_for_dev(resolved_redirect_uri)
    flow = Flow.from_client_secrets_file(
        str(credentials_path or GMAIL_CREDENTIALS_PATH),
        scopes=scopes or GMAIL_APP_SCOPES,
        redirect_uri=resolved_redirect_uri,
        state=state,
        # This backend rebuilds the flow during the callback. Do not generate a
        # transient PKCE verifier unless it is persisted server-side too.
        autogenerate_code_verifier=False,
    )
    return flow


def build_authorization_url(state: str, redirect_uri: str | None = None, scopes: list[str] | None = None, credentials_path: str | None = None, force_consent: bool = True) -> str:
    flow = build_oauth_flow(state, redirect_uri=redirect_uri, scopes=scopes, credentials_path=credentials_path)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        # NOTE: include_granted_scopes intentionally REMOVED.
        # It caused Gmail scopes (modify, send) to bleed into the Sign In flow,
        # making the login screen show 6 permissions instead of just 2 (name + email).
        prompt="consent select_account" if force_consent else "select_account",
    )
    return auth_url


def exchange_code_for_token(code: str, state: str, redirect_uri: str | None = None, scopes: list[str] | None = None, credentials_path: str | None = None):
    flow = build_oauth_flow(state, redirect_uri=redirect_uri, scopes=scopes, credentials_path=credentials_path)
    flow.fetch_token(code=code)
    return flow.credentials


def build_gmail_service_from_blob(blob: str):
    creds = decode_credentials(blob)
    return build("gmail", "v1", credentials=creds)

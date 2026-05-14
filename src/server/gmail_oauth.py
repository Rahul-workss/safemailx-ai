import base64
import os
import pickle
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from server.settings import GMAIL_OAUTH_REDIRECT_URI, GMAIL_TOKEN_ENCRYPTION_KEY
from utils.config import GMAIL_CREDENTIALS_PATH
from utils.gmail_fetcher import SCOPES


def _cipher() -> Fernet | None:
    if not GMAIL_TOKEN_ENCRYPTION_KEY:
        return None
    return Fernet(GMAIL_TOKEN_ENCRYPTION_KEY.encode("utf-8"))


def _allow_local_insecure_oauth_transport() -> None:
    parsed = urlparse(GMAIL_OAUTH_REDIRECT_URI)
    if parsed.scheme != "http":
        return
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        return
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def encode_credentials(creds) -> str:
    raw = pickle.dumps(creds)
    cipher = _cipher()
    if cipher:
        raw = cipher.encrypt(raw)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_credentials(blob: str):
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    cipher = _cipher()
    if cipher:
        raw = cipher.decrypt(raw)
    return pickle.loads(raw)


def build_oauth_flow(state: str | None = None) -> Flow:
    _allow_local_insecure_oauth_transport()
    flow = Flow.from_client_secrets_file(
        str(GMAIL_CREDENTIALS_PATH),
        scopes=SCOPES,
        redirect_uri=GMAIL_OAUTH_REDIRECT_URI,
        state=state,
    )
    return flow


def build_authorization_url(state: str) -> str:
    flow = build_oauth_flow(state)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return auth_url


def exchange_code_for_token(code: str, state: str):
    flow = build_oauth_flow(state)
    flow.fetch_token(code=code)
    return flow.credentials


def build_gmail_service_from_blob(blob: str):
    creds = decode_credentials(blob)
    return build("gmail", "v1", credentials=creds)

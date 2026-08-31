import pickle

from cryptography.fernet import Fernet, InvalidToken
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build

from utils.config import GMAIL_CREDENTIALS_PATH, GMAIL_TOKEN_ENCRYPTION_KEY, GMAIL_TOKEN_PATH


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send"
]


def _token_cipher() -> Fernet | None:
    if not GMAIL_TOKEN_ENCRYPTION_KEY:
        return None
    return Fernet(GMAIL_TOKEN_ENCRYPTION_KEY.encode("utf-8"))


def _load_token():
    if not GMAIL_TOKEN_PATH.exists():
        return None

    raw = GMAIL_TOKEN_PATH.read_bytes()
    cipher = _token_cipher()
    if cipher:
        try:
            raw = cipher.decrypt(raw)
        except InvalidToken as exc:
            raise RuntimeError("Gmail token exists but could not be decrypted") from exc
    try:
        return pickle.loads(raw)
    except Exception as exc:
        # Token file exists but can't be deserialized (e.g., serialized by a
        # different Python/google-auth version). Delete it so get_gmail_service()
        # re-triggers a fresh OAuth sign-in rather than crashing in a loop.
        GMAIL_TOKEN_PATH.unlink(missing_ok=True)
        raise RuntimeError(
            f"Gmail token was corrupt or incompatible and has been deleted. "
            f"Please re-authenticate. Underlying error: {exc}"
        ) from exc


def _save_token(creds) -> None:
    raw = pickle.dumps(creds)
    cipher = _token_cipher()
    if cipher:
        raw = cipher.encrypt(raw)
    GMAIL_TOKEN_PATH.write_bytes(raw)


def get_gmail_service():

    creds = _load_token()

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                GMAIL_TOKEN_PATH.unlink(missing_ok=True)
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(GMAIL_CREDENTIALS_PATH),
                    SCOPES
                )
                creds = flow.run_local_server(port=0)

        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(GMAIL_CREDENTIALS_PATH),
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        _save_token(creds)

    service = build("gmail", "v1", credentials=creds)

    return service


def fetch_email(message_id):

    service = get_gmail_service()

    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full"
    ).execute()

    return message

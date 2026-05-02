import os
import base64
import pickle

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from utils.config import GMAIL_CREDENTIALS_PATH, GMAIL_TOKEN_PATH


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send"
]


def get_gmail_service():

    creds = None

    if GMAIL_TOKEN_PATH.exists():
        with open(GMAIL_TOKEN_PATH, "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(GMAIL_CREDENTIALS_PATH),
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        with open(GMAIL_TOKEN_PATH, "wb") as token:
            pickle.dump(creds, token)

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

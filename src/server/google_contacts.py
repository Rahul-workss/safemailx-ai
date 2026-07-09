import os
import json
import httpx
from fastapi import APIRouter, HTTPException, Request, Depends
from server.schemas import GmailOAuthStartResponse
from server.settings import BACKEND_URL

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET")
# The redirect URI for Google Contacts
REDIRECT_URI = f"{BACKEND_URL}/api/auth/google-contacts/callback"

SCOPES = [
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

@router.get("/api/auth/google-contacts/login", response_model=GmailOAuthStartResponse)
def google_contacts_login():
    """Start OAuth flow for Google Contacts"""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google Client ID not configured")
        
    scope_str = " ".join(SCOPES)
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={scope_str}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    return GmailOAuthStartResponse(authorization_url=auth_url, redirect_uri=REDIRECT_URI)


async def exchange_code_for_token(code: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
        )
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"OAuth failed: {response.text}")
        return response.json()

async def fetch_user_info(access_token: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user info")
        return response.json()

async def fetch_contacts(access_token: str) -> list[str]:
    """Fetch all email addresses from Google Contacts"""
    emails = []
    page_token = None
    
    async with httpx.AsyncClient() as client:
        while True:
            url = "https://people.googleapis.com/v1/people/me/connections?personFields=emailAddresses"
            if page_token:
                url += f"&pageToken={page_token}"
                
            response = await client.get(
                url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code != 200:
                print(f"Failed to fetch contacts: {response.text}")
                break
                
            data = response.json()
            connections = data.get("connections", [])
            
            for person in connections:
                email_addresses = person.get("emailAddresses", [])
                for email_obj in email_addresses:
                    email = email_obj.get("value")
                    if email:
                        emails.append(email.lower())
                        
            page_token = data.get("nextPageToken")
            if not page_token:
                break
                
    return list(set(emails))

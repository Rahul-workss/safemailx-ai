#!/bin/bash
set -e

if [ -n "$GOOGLE_CREDENTIALS_JSON" ]; then
    echo "Writing Google credentials from environment..."
    echo "$GOOGLE_CREDENTIALS_JSON" > /app/src/credentials.json
    echo "$GOOGLE_CREDENTIALS_JSON" > /app/src/server/signin_credentials.json
fi

if [ -n "$GMAIL_TOKEN_BASE64" ]; then
    echo "Writing Gmail token from environment..."
    echo "$GMAIL_TOKEN_BASE64" | base64 --decode > /app/src/token.pickle
fi

echo "Starting TrustMail FastAPI Server..."
exec uvicorn server.app:app --host 0.0.0.0 --port ${PORT:-8080}

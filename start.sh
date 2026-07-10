#!/bin/bash
set -e

echo "Starting TrustMail Celery Worker..."
python -m server.worker &

echo "Starting TrustMail Gmail Watcher..."
python -m server.gmail_watcher &

echo "Starting TrustMail FastAPI Server..."
exec uvicorn server.app:app --host 0.0.0.0 --port ${PORT:-8080}

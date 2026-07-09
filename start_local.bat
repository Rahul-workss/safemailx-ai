@echo off
echo Starting Databases...
docker-compose up -d postgres redis

echo Setting PYTHONPATH...
set PYTHONPATH=src

echo Starting TrustMail AI Backend Services...

:: Start the API in a new window
start "TrustMail API" cmd /c "venv\Scripts\activate && uvicorn server.app:app --host 0.0.0.0 --port 8080 --reload"

:: Start the Background Worker in a new window
start "TrustMail Worker" cmd /c "venv\Scripts\activate && python -m server.worker"

:: Start the Gmail Watcher in a new window
start "TrustMail Gmail Watcher" cmd /c "venv\Scripts\activate && python -m server.gmail_watcher"

echo All services launched!

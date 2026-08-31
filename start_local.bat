@echo off
echo ============================================================
echo  SafeMail X - Local Dev Startup
echo ============================================================

:: ── Step 1: Stop Docker app containers AND prevent them from auto-restarting.
::            These containers have 'restart: always' in docker-compose.yml, so
::            docker-compose stop alone isn't enough — Docker revives them.
::            'docker update --restart=no' disables auto-restart permanently until
::            the container is explicitly recreated (docker-compose up --build).
echo.
echo [1/5] Stopping Docker app containers and disabling auto-restart...
docker stop safemailx-ai-trustmail-api-1 safemailx-ai-trustmail-worker-1 safemailx-ai-trustmail-gmail-watcher-1 2>nul
docker update --restart=no safemailx-ai-trustmail-api-1 safemailx-ai-trustmail-worker-1 safemailx-ai-trustmail-gmail-watcher-1 2>nul
echo       Done. Docker app containers are stopped and won't auto-restart.

:: ── Step 2: Kill ALL leftover local Python + watchmedo processes.
::            IMPORTANT: taskkill /IM python.exe does NOT kill watchmedo.exe —
::            it's a separate executable. Old watchmedo processes survive and
::            immediately respawn workers from their stale environment (wrong
::            model, wrong config). Both must be killed before restarting.
echo.
echo [2/5] Killing any leftover Python and watchmedo processes...
taskkill /F /IM watchmedo.exe /T >nul 2>&1
taskkill /F /IM python.exe /T >nul 2>&1
echo       Done.

:: ── Step 3: Clear Python bytecode cache so no stale .pyc files survive.
::            Without this, Python may load an old compiled version of
::            llm_analyzer.py or config.py even after the source changes.
echo.
echo [3/5] Clearing Python bytecode cache (__pycache__)...
if exist src\engines\__pycache__  rd /s /q src\engines\__pycache__
if exist src\server\__pycache__   rd /s /q src\server\__pycache__
if exist src\utils\__pycache__    rd /s /q src\utils\__pycache__
echo       Done.

:: ── Step 4: Ensure Postgres and Redis are up
echo.
echo [4/5] Starting Databases (Postgres + Redis)...
docker-compose up -d postgres redis
echo       Done.

:: ── Step 5: Show active LLM config from .env then launch local services
echo.
echo [5/5] Launching local TrustMail AI services...

:: Read LLM_MODEL from .env and show it in the banner
set LLM_MODEL_ACTIVE=unknown
for /f "tokens=1,2 delims==" %%a in ('findstr /B "LLM_MODEL=" .env 2^>nul') do (
    set LLM_MODEL_ACTIVE=%%b
)

echo.
echo ============================================================
echo  Active LLM model (from .env):  %LLM_MODEL_ACTIVE%
echo ============================================================
echo.

:: API: --reload-dir src watches ALL of src/ for changes (engines/, utils/, server/)
start "TrustMail API" cmd /k "set PYTHONPATH=src && venv\Scripts\activate && uvicorn server.app:app --host 0.0.0.0 --port 8080 --reload --reload-dir src"

:: Worker: watchmedo auto-restarts on any .py or .env change in src/
start "TrustMail Worker" cmd /k "set PYTHONPATH=src && venv\Scripts\activate && watchmedo auto-restart --patterns=*.py;.env --recursive --directory=src python -- -m server.worker"

:: Gmail Watcher: same auto-restart behaviour
start "TrustMail Gmail Watcher" cmd /k "set PYTHONPATH=src && venv\Scripts\activate && watchmedo auto-restart --patterns=*.py;.env --recursive --directory=src python -- -m server.gmail_watcher"

echo.
echo ============================================================
echo  All services launched!
echo    API          : http://localhost:8080  (auto-reloads on .py changes)
echo    Worker       : background             (auto-restarts on .py changes)
echo    Gmail Watcher: background             (auto-restarts on .py changes)
echo.
echo  Active model   : %LLM_MODEL_ACTIVE%
echo  Change LLM_MODEL in .env — takes effect on the NEXT scan, no restart needed.
echo ============================================================

param(
    [switch]$SkipRedis,
    [switch]$WithWatcher,
    [switch]$WithMobile
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $repoRoot "venv\Scripts\python.exe"
$venvUvicorn = Join-Path $repoRoot "venv\Scripts\uvicorn.exe"
$mobileRoot = Join-Path $repoRoot "trustmail-mobile"
$apiLog = Join-Path $repoRoot "trustmail-api.log"
$apiErrLog = Join-Path $repoRoot "trustmail-api.err.log"
$workerLog = Join-Path $repoRoot "trustmail-worker.log"
$workerErrLog = Join-Path $repoRoot "trustmail-worker.err.log"
$watcherLog = Join-Path $repoRoot "trustmail-gmail-watcher.log"
$watcherErrLog = Join-Path $repoRoot "trustmail-gmail-watcher.err.log"

if (-not (Test-Path $venvPython)) {
    throw "Missing virtual environment Python at $venvPython"
}

if (-not (Test-Path $venvUvicorn)) {
    throw "Missing uvicorn executable at $venvUvicorn"
}

$env:PYTHONPATH = Join-Path $repoRoot "src"
$redisAvailable = $false

if (-not $SkipRedis) {
    Write-Host "Starting Redis via Docker Compose"
    docker compose up -d redis
    if ($LASTEXITCODE -eq 0) {
        $redisAvailable = $true
    }
    else {
        Write-Warning "Redis could not be started through Docker. Queue-backed scans will stay unavailable until Redis is running."
    }
}
else {
    $redisAvailable = $true
}

Write-Host "Starting TrustMail API on http://0.0.0.0:8080"
$env:PYTHONPATH = Join-Path $repoRoot "src"
Start-Process -FilePath $venvPython `
    -ArgumentList "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8080" `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $apiLog `
    -RedirectStandardError $apiErrLog `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

Write-Host "Starting TrustMail worker"
$env:PYTHONPATH = Join-Path $repoRoot "src"
Start-Process -FilePath $venvPython `
    -ArgumentList "-m", "server.worker" `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $workerLog `
    -RedirectStandardError $workerErrLog `
    -WindowStyle Hidden

if ($WithWatcher) {
    Start-Sleep -Seconds 1
    Write-Host "Starting Gmail watcher"
    $env:PYTHONPATH = Join-Path $repoRoot "src"
    Start-Process -FilePath $venvPython `
        -ArgumentList "-m", "server.gmail_watcher" `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $watcherLog `
        -RedirectStandardError $watcherErrLog `
        -WindowStyle Hidden
}

if ($WithMobile) {
    if (-not (Test-Path (Join-Path $mobileRoot "package.json"))) {
        throw "Missing mobile app package.json at $mobileRoot"
    }

    Start-Sleep -Seconds 1
    Write-Host "Starting Expo dev server"
    Start-Process -FilePath "npx.cmd" `
        -ArgumentList "expo", "start" `
        -WorkingDirectory $mobileRoot
}

Write-Host "Starting Cloudflare Tunnel"
Start-Process -FilePath "cloudflared" `
    -ArgumentList "tunnel", "run", "safemailx" `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput (Join-Path $repoRoot "cloudflared.log") `
    -RedirectStandardError (Join-Path $repoRoot "cloudflared.err.log") `
    -WindowStyle Hidden

Write-Host ""
Write-Host "Started requested TrustMail services."
if (-not $redisAvailable) {
    Write-Host "Running in degraded local mode: direct manual scans still work, Redis queue features are offline."
}
Write-Host "Logs: trustmail-api.log, trustmail-api.err.log, trustmail-worker.log, trustmail-worker.err.log"
if ($WithWatcher) {
    Write-Host "Watcher logs: trustmail-gmail-watcher.log, trustmail-gmail-watcher.err.log"
}
Write-Host "Use scripts\smoke-test-local.ps1 to verify the API path."

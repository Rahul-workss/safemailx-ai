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

Write-Host "Starting TrustMail API on http://127.0.0.1:8080"
Start-Process -FilePath $venvUvicorn `
    -ArgumentList "server.app:app --reload --host 127.0.0.1 --port 8080" `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

Write-Host "Starting TrustMail worker"
Start-Process -FilePath $venvPython `
    -ArgumentList "-m", "server.worker" `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden

if ($WithWatcher) {
    Start-Sleep -Seconds 1
    Write-Host "Starting Gmail watcher"
    Start-Process -FilePath $venvPython `
        -ArgumentList "-m", "server.gmail_watcher" `
        -WorkingDirectory $repoRoot `
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

Write-Host ""
Write-Host "Started requested TrustMail services."
if (-not $redisAvailable) {
    Write-Host "Running in degraded local mode: direct manual scans still work, Redis queue features are offline."
}
Write-Host "Use scripts\smoke-test-local.ps1 to verify the API path."

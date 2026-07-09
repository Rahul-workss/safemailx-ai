# stop.ps1 - Kill ALL SafeMailX-AI processes cleanly
Write-Host "Stopping all SafeMailX-AI processes..." -ForegroundColor Yellow

$killed = 0
Get-CimInstance Win32_Process -Filter "name='python.exe'" | ForEach-Object {
    $cmd = $_.CommandLine
    if ($cmd -like "*safemailx-ai*" -or $cmd -like "*uvicorn*" -or $cmd -like "*server.worker*" -or $cmd -like "*server.gmail_watcher*") {
        Write-Host "  Killing PID $($_.ProcessId): $($cmd.Substring(0, [Math]::Min(80, $cmd.Length)))..." -ForegroundColor Red
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $killed++
    }
}

if ($killed -eq 0) {
    Write-Host "No SafeMailX-AI processes were running." -ForegroundColor Green
} else {
    Write-Host "Stopped $killed process(es)." -ForegroundColor Green
}

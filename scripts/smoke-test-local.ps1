param(
    [string]$ApiBaseUrl = "http://127.0.0.1:8080",
    [string]$Email = "admin@example.com",
    [string]$Password = "replace-with-strong-password"
)

$ErrorActionPreference = "Stop"

function Invoke-TrustMailJson {
    param(
        [string]$Method,
        [string]$Url,
        [object]$Body = $null,
        [hashtable]$Headers = @{}
    )

    $params = @{
        Method = $Method
        Uri = $Url
        Headers = $Headers
    }

    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    return Invoke-RestMethod @params
}

Write-Host "Checking API health at $ApiBaseUrl/api/health"
$health = Invoke-TrustMailJson -Method "GET" -Url "$ApiBaseUrl/api/health"
$health | ConvertTo-Json -Depth 10

$headers = @{}

try {
    Write-Host ""
    Write-Host "Attempting login for $Email"
    $tokenResponse = Invoke-TrustMailJson `
        -Method "POST" `
        -Url "$ApiBaseUrl/auth/login" `
        -Body @{
            email = $Email
            password = $Password
        }

    $headers["Authorization"] = "Bearer $($tokenResponse.access_token)"
    Write-Host "Login succeeded."
}
catch {
    Write-Host "Login skipped or failed. Continuing without auth."
}

Write-Host ""
if ($health.redis -eq "online") {
    Write-Host "Submitting queued manual scan"
    $queued = Invoke-TrustMailJson `
        -Method "POST" `
        -Url "$ApiBaseUrl/api/scans/manual/queue" `
        -Headers $headers `
        -Body @{
            subject = "TrustMail local smoke test"
            sender = "local-smoke@test"
            body = "Urgent: verify this payment account and click the attached confirmation link."
            scan_mode = "balanced"
        }

    $scanId = $queued.id
    if (-not $scanId) {
        throw "Queue response did not include a scan id"
    }

    Write-Host "Queued scan id: $scanId"

    $deadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Seconds 2
        $scan = Invoke-TrustMailJson `
            -Method "GET" `
            -Url "$ApiBaseUrl/api/scans/$scanId" `
            -Headers $headers
        $state = if ($scan.final_label -eq "queued") { "queued" } else { $scan.final_label }
        Write-Host "Current status: $state"
    } while ($scan.final_label -eq "queued" -and (Get-Date) -lt $deadline)

    if ($scan.final_label -eq "queued") {
        throw "Scan did not finish before timeout. Last status: queued"
    }
}
else {
    Write-Host "Redis is offline. Falling back to direct manual scan."
    $scan = Invoke-TrustMailJson `
        -Method "POST" `
        -Url "$ApiBaseUrl/api/scans/manual" `
        -Headers $headers `
        -Body @{
            subject = "TrustMail local smoke test"
            sender = "local-smoke@test"
            body = "Urgent: verify this payment account and click the attached confirmation link."
            scan_mode = "balanced"
        }
}

Write-Host ""
Write-Host "Final scan summary:"
$scan | ConvertTo-Json -Depth 10

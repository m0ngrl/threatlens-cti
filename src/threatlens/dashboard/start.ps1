# Starts the ThreatLens dashboard in the background. Pairs with stop.ps1.
#
# Usage:
#   powershell -File start.ps1 [-Port 8000]
#
# Defaults to port 8000, bound to 0.0.0.0 so it's reachable from other
# devices on the local network. Set $env:THREATLENS_DASHBOARD_HOST to
# 127.0.0.1 to restrict it to this machine instead.
#
# WARNING: this dashboard can edit and delete database rows and has no
# authentication - anyone who can reach the bound address can modify the
# database. Only bind 0.0.0.0 on a network you trust.

param(
    [int]$Port = 8000,
    [string]$DashHost = $env:THREATLENS_DASHBOARD_HOST
)

if (-not $DashHost) { $DashHost = "0.0.0.0" }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..\..")).Path
$PidFile = Join-Path $ScriptDir ".server.pid"
$LogFile = Join-Path $ScriptDir "server.log"

if (Test-Path $PidFile) {
    $existingPid = Get-Content $PidFile
    if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) {
        Write-Host "Dashboard is already running (pid $existingPid)."
        Write-Host "Run stop.ps1 first if you want to restart it."
        exit 1
    }
    Remove-Item $PidFile -Force
}

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$Python = if (Test-Path $VenvPython) { $VenvPython } else { "python" }

Write-Host "Starting ThreatLens dashboard..."
Write-Host "  Local:   http://127.0.0.1:$Port/"
if ($DashHost -eq "0.0.0.0") {
    $LanIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
    if ($LanIp) { Write-Host "  Network: http://$($LanIp):$Port/" }
    Write-Host ""
    Write-Host "WARNING: this dashboard can edit and delete database rows and has no"
    Write-Host "authentication - anyone on the local network who reaches this URL can"
    Write-Host "modify the database."
}
Write-Host "Logging to $LogFile"

$proc = Start-Process -FilePath $Python `
    -ArgumentList "-m", "threatlens.dashboard.server", "--host", $DashHost, "--port", $Port `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError "$LogFile.err" `
    -PassThru

Set-Content -Path $PidFile -Value $proc.Id
Start-Sleep -Milliseconds 500

if (-not (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
    Write-Host "Error: dashboard exited immediately, check the log:"
    Write-Host "  $LogFile"
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Started (pid $($proc.Id)). Stop with stop.ps1"

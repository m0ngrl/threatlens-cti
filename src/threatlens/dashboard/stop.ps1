# Stops a dashboard started with start.ps1.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir ".server.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "No pid file found - dashboard doesn't look like it's running."
    exit 0
}

$existingPid = Get-Content $PidFile
if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) {
    Stop-Process -Id $existingPid
    Write-Host "Stopped dashboard (pid $existingPid)."
} else {
    Write-Host "Process $existingPid is not running (stale pid file)."
}
Remove-Item $PidFile -Force

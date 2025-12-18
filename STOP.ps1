# RAWFL v2.0 - Stop Server (PowerShell)

Clear-Host

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  RAWFL v2.0 - Stop Server" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Stopping Flask server..." -ForegroundColor Yellow
Write-Host ""

# Kill all Python processes
$processes = Get-Process -Name python -ErrorAction SilentlyContinue

if ($processes) {
    $processes | Stop-Process -Force
    Write-Host "[OK] Server stopped successfully!" -ForegroundColor Green
    Write-Host "[INFO] Stopped $($processes.Count) Python process(es)" -ForegroundColor Gray
} else {
    Write-Host "[INFO] No server is currently running" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[INFO] All Python processes have been terminated" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

Start-Sleep -Seconds 2

# RAWFL v2.0 - PowerShell Launcher
# Educational Purpose Only

Clear-Host

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  RAWFL v2.0 - Network Security Scanner" -ForegroundColor Cyan
Write-Host "  Educational Purpose Only" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Starting Flask web server..." -ForegroundColor Yellow
Write-Host ""

# Kill existing Python processes
Write-Host "[*] Stopping any existing servers..." -ForegroundColor Gray
Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Change to script directory
Set-Location $PSScriptRoot

# Start Flask server in background
Write-Host "[*] Launching server..." -ForegroundColor Yellow
Start-Process python -ArgumentList "app.py" -WindowStyle Hidden

# Wait for server to be ready
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "[OK] Server is running!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access the web interface at:" -ForegroundColor White
Write-Host "  - http://localhost:5000" -ForegroundColor Cyan
Write-Host "  - http://192.168.1.160:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Opening browser in 2 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 2

# Open browser
Start-Process "http://localhost:5000"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "[INFO] Server is running in background" -ForegroundColor Yellow
Write-Host "[INFO] To stop server: Run STOP.ps1" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host ""

# Keep window open
Read-Host "Press Enter to close this window (server will keep running)"

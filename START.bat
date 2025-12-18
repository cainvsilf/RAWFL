@echo off
cls

echo ======================================================================
echo   RAWFL - Network Security Scanner
echo   Educational Purpose Only
echo ======================================================================
echo.
echo [*] Starting Flask web server...
echo.

REM Kill existing Python processes
taskkill /F /IM python.exe >nul 2>&1
timeout /t 1 /nobreak >nul

REM Change to script directory
cd /d "%~dp0"

REM Start Flask server
echo [*] Launching server...
start /B python app.py
timeout /t 3 /nobreak >nul

echo.
echo ======================================================================
echo [OK] Server is running!
echo ======================================================================
echo.
echo Access the web interface at:
echo   - http://localhost:5000
echo   - http://192.168.1.160:5000
echo.
echo Opening browser in 2 seconds...
timeout /t 2 /nobreak >nul

REM Open browser
start http://localhost:5000

echo.
echo ======================================================================
echo [INFO] Server is running in background
echo [INFO] To stop server: Run STOP.bat
echo ======================================================================
echo.

pause

@echo off
cls

echo ======================================================================
echo   RAWFL v2.0 - Stop Server
echo ======================================================================
echo.
echo [*] Stopping Flask server...
echo.

REM Kill all Python processes
taskkill /F /IM python.exe >nul 2>&1

IF %ERRORLEVEL% EQU 0 (
    echo [OK] Server stopped successfully!
) ELSE (
    echo [INFO] No server is currently running
)

echo.
echo ======================================================================
echo [INFO] All Python processes have been terminated
echo ======================================================================
echo.

timeout /t 2 /nobreak >nul

@echo off
title Explorer Defender
setlocal EnableDelayedExpansion

echo [*] Explorer Defender started. Monitoring in real-time...

:loop
:: Check if explorer.exe is running
tasklist /FI "IMAGENAME eq explorer.exe" | find /I "explorer.exe" >nul
if errorlevel 1 (
    echo [!] ALERT: Explorer.exe was terminated!

    :: Restart explorer quickly
    start explorer.exe
    echo [*] Explorer restarted.

    :: Optional: Detect recently started taskkill or batch files (heuristic)
    for /f "tokens=1,2,3,*" %%a in ('"tasklist /fo csv /nh"') do (
        set "proc=%%~a"
        set "proc=!proc:"=!"

        :: If it's a known attacker like taskkill, powershell, wscript, etc.
        echo !proc! | findstr /I "taskkill powershell wscript cscript cmd" >nul
        if !errorlevel! == 0 (
            echo [!] Suspect process found: !proc! – attempting to suspend...
            powershell -Command "Get-Process -Name '!proc!' | Stop-Process -Force"
        )
    )
)

:: Loop rapidly for fast response
timeout /nobreak /t 1 >nul
goto :loop

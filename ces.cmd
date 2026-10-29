@echo off
where pwsh.exe >nul 2>&1
if errorlevel 1 (
    echo PowerShell 7 is required. Install it and ensure pwsh.exe is on PATH. 1>&2
    exit /b 5
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0scripts\ces.ps1" %*
exit /b %ERRORLEVEL%

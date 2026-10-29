@echo off
pwsh.exe -NoLogo -NoProfile -File "%~dp0operator\launch.ps1" %*
exit /b %ERRORLEVEL%

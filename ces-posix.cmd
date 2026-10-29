@echo off
where wsl.exe >nul 2>&1
if errorlevel 1 (
    echo WSL is required for the CES POSIX extension. 1>&2
    exit /b 5
)
if not defined CES_POSIX_RUNTIME set "CES_POSIX_RUNTIME=/var/tmp/ces-1.0.0"
if defined CES_WSL_DISTRIBUTION (
    wsl.exe -d "%CES_WSL_DISTRIBUTION%" --cd "%CES_POSIX_RUNTIME%" --exec "%CES_POSIX_RUNTIME%/.venv/bin/python" -B "%CES_POSIX_RUNTIME%/scripts/ces_next.py" %*
) else (
    wsl.exe --cd "%CES_POSIX_RUNTIME%" --exec "%CES_POSIX_RUNTIME%/.venv/bin/python" -B "%CES_POSIX_RUNTIME%/scripts/ces_next.py" %*
)
exit /b %ERRORLEVEL%

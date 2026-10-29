#requires -Version 7.0
$ErrorActionPreference='Stop'
$env:PYTHONIOENCODING='utf-8'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskPython=if ($env:CES_PYTHON) { $env:CES_PYTHON } else { Join-Path $taskRoot '.venv/Scripts/python.exe' }
if (-not (Test-Path -LiteralPath $taskPython) -and -not $IsWindows) { $taskPython=Join-Path $taskRoot '.venv/bin/python' }
if (-not (Test-Path -LiteralPath $taskPython)) { throw 'CES Python environment is unavailable' }
& $taskPython -B (Join-Path $PSScriptRoot 'ces_product.py') @args
exit $LASTEXITCODE

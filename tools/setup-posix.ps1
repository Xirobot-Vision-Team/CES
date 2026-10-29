#requires -Version 7.0
[CmdletBinding()]
param([string]$Distribution = '', [string]$Runtime = '/var/tmp/ces-1.0.0')
$ErrorActionPreference = 'Stop'
$cesRoot = Split-Path -Parent $PSScriptRoot
$cesWslArgs = if ($Distribution) { @('-d', $Distribution) } else { @() }
$cesPython = Join-Path $cesRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $cesPython -PathType Leaf)) { throw 'Create the Windows Python environment first; see docs/USAGE.md.' }
$cesScratch = Join-Path ([IO.Path]::GetTempPath()) ('ces-posix-setup-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($cesScratch) | Out-Null
try {
    & $cesPython -m pip download --no-deps --only-binary=:all: --dest $cesScratch 'pip==25.0.1'
    if ($LASTEXITCODE -ne 0) { throw 'Could not download the pip bootstrap wheel.' }
    $cesWheel = Join-Path $cesScratch 'pip-25.0.1-py3-none-any.whl'
    $cesLinuxSource = (& wsl.exe @cesWslArgs --exec wslpath -a -u $cesRoot).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not map the CES source directory.' }
    $cesLinuxWheel = (& wsl.exe @cesWslArgs --exec wslpath -a -u $cesWheel).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not map the pip wheel.' }
    & wsl.exe @cesWslArgs --exec python3 -B ($cesLinuxSource + '/tools/setup_posix.py') --source $cesLinuxSource --runtime $Runtime --pip-wheel $cesLinuxWheel
    if ($LASTEXITCODE -ne 0) { throw 'CES POSIX installation failed; inspect the diagnostic output.' }
} finally {
    $cesResolved = [IO.Path]::GetFullPath($cesScratch)
    $cesTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $cesResolved.StartsWith($cesTemp, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($cesResolved) -notlike 'ces-posix-setup-*') { throw 'Unexpected cleanup target.' }
    Remove-Item -LiteralPath $cesResolved -Recurse -Force
}

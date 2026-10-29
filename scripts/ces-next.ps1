#requires -Version 7.0
<#
  CES EC278 operator console: a native PowerShell convenience entry for the
  EC278 Python console, not a replacement for the original scripts/ces.ps1.
  One positional argv vector is forwarded without invoking a shell or adding
  any grant; original legacy CodeSave still requires -ApprovePersist.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$entry = Join-Path -Path $PSScriptRoot -ChildPath 'ces_next.py'
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
    [Console]::Error.WriteLine('EC278_CONSOLE_SOURCE_MISSING')
    exit 5
}
$python = Get-Command -Name 'python3', 'python' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $python) {
    [Console]::Error.WriteLine('EC278_PYTHON3_NOT_INSTALLED')
    exit 5
}
try {
    # -I isolates imports; array arguments are separate, never interpolated
    # into an executable string. $args includes subcommands and their options.
    & $python.Source '-I' '-B' $entry @args
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('EC278_CONSOLE_ENTRY_UNAVAILABLE')
    exit 5
}

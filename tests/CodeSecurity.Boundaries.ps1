#requires -Version 7.0
<#
    EC-157 optional native authorization-boundary scenarios.
    Safe for an isolated temporary directory. Does NOT run CodeSave with a
    true persistence approval, write to a business repo, or assert final
    acceptance. This is NOT one of the 15 frozen R150 Smoke suites.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
$pwshCommand = Get-Command -Name 'pwsh' -CommandType Application -ErrorAction Stop | Select-Object -First 1
$pwshExe = $pwshCommand.Source
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI missing.' }

$script:checks = 0
function Check {
    param([bool] $Ok, [string] $Message)
    if (-not $Ok) { throw $Message }
    $script:checks++
}
function Run-Denied {
    param(
        [string[]] $Arguments,
        [int] $ExpectedExit,
        [string] $ExpectedReason,
        [bool] $ExpectedReadOnly
    )
    $output = @(& $pwshExe -NoProfile -File $cli @Arguments -Json)
    $exitCode = $LASTEXITCODE
    Check ($exitCode -eq $ExpectedExit) "Wrong exit ${exitCode}, expected ${ExpectedExit}: $($Arguments -join ' ')"
    Check ($output.Count -eq 1) "Expected one JSON response, got $($output.Count)."
    $response = $output[0] | ConvertFrom-Json -Depth 32
    Check ($response.reason_code -ceq $ExpectedReason) "Unexpected denial reason: $($response.reason_code)"
    Check ($response.status -in @('invalid_input','not_implemented')) "Unexpected denial status: $($response.status)"
    Check ($response.read_only -eq $ExpectedReadOnly) "Incorrect read_only: $($response.read_only)"
    Check (-not $response.coverage.code_result_persisted) 'Denied action reported persisted coverage.'
    if ($response.action -ieq 'CodeSave') {
        Check ($response.data.persisted -eq $false) 'Denied CodeSave reported persistence.'
        Check ($response.data.can_persist_ces_state -eq $false) 'Denied CodeSave granted storage permission.'
    }
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces-ec157-auth-' + [guid]::NewGuid().ToString('N'))
$isolated = Join-Path $fixture 'untrusted-repo-path'
$emptyPath = Join-Path $fixture 'no-git-executable'
$originalPath = $env:PATH
try {
    [void][System.IO.Directory]::CreateDirectory($isolated)
    [void][System.IO.Directory]::CreateDirectory($emptyPath)

    # The caller has not approved storage. No Git executable or repository is
    # needed to obtain an explicit authorization refusal.
    $env:PATH = $emptyPath
    Run-Denied -Arguments @('-Action','CodeSave','-RepoPath',$isolated,'-Mode','Snapshot') `
        -ExpectedExit 4 -ExpectedReason 'CODE_SAVE_AUTHORIZATION_REQUIRED' -ExpectedReadOnly $false
    Run-Denied -Arguments @('-Action','cOdEsAvE','-RepoPath',$isolated,'-Mode','OtherMode') `
        -ExpectedExit 4 -ExpectedReason 'CODE_SAVE_AUTHORIZATION_REQUIRED' -ExpectedReadOnly $false
    Run-Denied -Arguments @('-Action','CodeSave') `
        -ExpectedExit 4 -ExpectedReason 'CODE_SAVE_AUTHORIZATION_REQUIRED' -ExpectedReadOnly $false
    Run-Denied -Arguments @('-Action','CodeSave','-RepoPath',$isolated,'-ApprovePersist:$false') `
        -ExpectedExit 4 -ExpectedReason 'CODE_SAVE_AUTHORIZATION_REQUIRED' -ExpectedReadOnly $false

    # Approval cannot be borrowed by a different Action or an unimplemented
    # Action: no hidden writer or future remote operation exists.
    Run-Denied -Arguments @('-Action','Inspect','-RepoPath',$isolated,'-ApprovePersist') `
        -ExpectedExit 4 -ExpectedReason 'APPROVE_PERSIST_NOT_APPLICABLE' -ExpectedReadOnly $true
    Run-Denied -Arguments @('-Action','QualityRun','-RepoPath',$isolated,'-ApprovePersist') `
        -ExpectedExit 3 -ExpectedReason 'NOT_IMPLEMENTED' -ExpectedReadOnly $true
    Check (-not (Test-Path -LiteralPath (Join-Path $isolated '.codex'))) `
        'Unauthorized/unsupported calls created .codex state.'
    Write-Output "EC-157 native denial scenarios PASS: $script:checks checks (temporary empty directory only)."
} finally {
    $env:PATH = $originalPath
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
    }
}

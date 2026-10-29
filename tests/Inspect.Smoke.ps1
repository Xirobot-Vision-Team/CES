#requires -Version 7.0
<#
    Optional isolated smoke test for EC-002. Requires pwsh and Git.
    Creates only temporary scratch Git repositories and removes them afterward.
    DOES NOT test, modify, or clean the user's business repository.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Cannot locate CES CLI.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git is unavailable.' }

$script:checked = 0
function Assert-Equal {
    param([object] $Actual, [object] $Expected, [string] $Description)
    if ($Actual -cne $Expected) {
        throw "$Description — expected [$Expected], received [$Actual]."
    }
    [void] ($script:checked++)
}
function Assert-True {
    param([bool] $Value, [string] $Description)
    if (-not $Value) { throw $Description }
    [void] ($script:checked++)
}
function Run-CES {
    param([string] $Action, [AllowNull()][string] $Path, [int] $ExpectedExit)
    $arguments = @('-NoProfile', '-File', $cli, '-Action', $Action, '-Json')
    if ($null -ne $Path) { $arguments += @('-RepoPath', $Path) }
    $outputText = & pwsh @arguments
    $actualExit = $LASTEXITCODE
    Assert-Equal $actualExit $ExpectedExit "Exit code for $Action / $Path"
    $objects = @($outputText)
    Assert-Equal $objects.Count 1 'Exactly one JSON stdout record'
    $obj = $objects[0] | ConvertFrom-Json -Depth 12
    Assert-Equal $obj.product_version '1.0.0' 'Product version'
    Assert-Equal $obj.build '1.0.0' 'Build number'
    Assert-Equal $obj.next_step 'none' 'Inspect has no handoff'
    return $obj
}
function Run-Git {
    param([string[]] $GitArguments)
    & git @GitArguments 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Scratch Git operation failed: $($GitArguments -join ' ')" }
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ces inspect ec002 " + [guid]::NewGuid().ToString('N'))
try {
    [void] (New-Item -ItemType Directory -Path $fixtureRoot -Force)
    $main = Join-Path $fixtureRoot 'repo with spaces'
    $linked = Join-Path $fixtureRoot '连结-worktree'
    $empty = Join-Path $fixtureRoot 'empty-repo'
    $bare = Join-Path $fixtureRoot 'bare.git'
    [void] (New-Item -ItemType Directory -Path $main)
    [void] (New-Item -ItemType Directory -Path $empty)

    Run-Git -GitArguments @('init', '-q', $main)
    $nested = Join-Path $main 'nested'
    [void] (New-Item -ItemType Directory -Path $nested)

    $unborn = Run-CES -Action Inspect -Path $nested -ExpectedExit 0
    Assert-Equal $unborn.status 'success' 'Nested worktree resolves successfully'
    Assert-Equal $unborn.data.worktree_kind 'main' 'Main worktree kind'
    Assert-Equal $unborn.data.head.state 'unborn' 'Unborn HEAD recognized'
    Assert-True ($null -eq $unborn.data.head.sha) 'Unborn HEAD has no invented SHA'
    Assert-True ($unborn.data.stable_root_verified) 'Stable root triple-checked'
    Assert-True (-not $unborn.data.can_persist_ces_state) 'No persistence handler'

    Run-Git -GitArguments @('-C', $main, '-c', 'user.name=CES Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture')
    Run-Git -GitArguments @('-C', $main, 'worktree', 'add', '-q', '-b', 'ces-inspect-smoke', $linked)
    $mainData = Run-CES -Action Inspect -Path $main -ExpectedExit 0
    $linkedData = Run-CES -Action Inspect -Path $linked -ExpectedExit 0
    Assert-Equal $linkedData.data.worktree_kind 'linked' 'Linked worktree recognized'
    Assert-Equal $linkedData.data.stable_project_root $mainData.data.stable_project_root 'Linked worktree returns verified main root'
    Assert-Equal $linkedData.data.head.state 'attached' 'Committed HEAD recognized'
    Assert-True ($linkedData.data.head.sha -match '^[0-9a-f]{40,64}$') 'HEAD SHA verified'

    # Inherited Git environment must not redirect the explicitly selected path.
    $previousGitDir = [System.Environment]::GetEnvironmentVariable('GIT_DIR', 'Process')
    try {
        [System.Environment]::SetEnvironmentVariable('GIT_DIR', (Join-Path $fixtureRoot 'incorrect-git-dir'), 'Process')
        $isolated = Run-CES -Action Inspect -Path $main -ExpectedExit 0
        Assert-Equal $isolated.data.source_root $mainData.data.source_root 'Ignore inherited GIT_DIR redirection'
    } finally {
        if ($null -eq $previousGitDir) {
            Remove-Item -LiteralPath Env:\GIT_DIR -ErrorAction SilentlyContinue
        } else {
            [System.Environment]::SetEnvironmentVariable('GIT_DIR', $previousGitDir, 'Process')
        }
    }

    Run-Git -GitArguments @('init', '--bare', '-q', $bare)
    $bareData = Run-CES -Action Inspect -Path $bare -ExpectedExit 2
    Assert-Equal $bareData.data.worktree_kind 'bare' 'Bare repo is not a worktree'
    Assert-True (-not $bareData.data.stable_root_verified) 'Bare repo has no trusted project root'

    Run-Git -GitArguments @('init', '-q', $empty)
    $notRepo = Run-CES -Action Inspect -Path $fixtureRoot -ExpectedExit 5
    Assert-Equal $notRepo.reason_code 'NOT_GIT_REPOSITORY' 'Non-repository rejected'

    $badPath = Run-CES -Action Inspect -Path (Join-Path $fixtureRoot 'missing') -ExpectedExit 4
    Assert-Equal $badPath.reason_code 'REPO_PATH_NOT_FOUND' 'Missing path handled'

    $notImplemented = Run-CES -Action UnsupportedAction -Path $main -ExpectedExit 3
    Assert-Equal $notImplemented.reason_code 'NOT_IMPLEMENTED' 'Unimplemented Action has no fake handler'

    $noPath = Run-CES -Action Inspect -Path $null -ExpectedExit 4
    Assert-Equal $noPath.reason_code 'REPO_PATH_REQUIRED' 'No implicit repository discovery'

    Write-Output "PASS: EC-002 Inspect smoke ($script:checked checks)"
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        # Only the GUID-namespaced scratch directory created in this test.
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

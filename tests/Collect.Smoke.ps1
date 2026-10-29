#requires -Version 7.0
<#
    EC-003 integration smoke: run only with PowerShell 7 and Git.
    All write operations here target only a new GUID-namespaced temp fixture.
    CES itself is exercised exclusively as a read-only CLI.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Cannot locate CES CLI.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git is unavailable.' }
$script:count = 0
function Assert-Check {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
    $script:count++
}
function Invoke-FixtureGit {
    param([string[]] $GitArguments)
    & git @GitArguments 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Git fixture operation failed: $($GitArguments -join ' ')" }
}
function CES {
    param([string] $Action, [string] $Path, [int] $ExpectedExit, [string[]] $Extra = @())
    $arguments = @('-NoProfile', '-File', $cli, '-Action', $Action, '-RepoPath', $Path, '-Json') + $Extra
    $lines = @(& pwsh @arguments)
    Assert-Check ($LASTEXITCODE -eq $ExpectedExit) "Wrong exit for ${Action}: $LASTEXITCODE; output: $lines"
    Assert-Check ($lines.Count -eq 1) 'JSON mode must produce one object.'
    $value = $lines[0] | ConvertFrom-Json -Depth 15
    Assert-Check ($value.product_version -eq '1.0.0' -and $value.build -eq '1.0.0') 'Wrong product version / build metadata.'
    Assert-Check ($value.next_step -eq 'none') 'Collect must not claim an AI handoff.'
    return $value
}

$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ("ces ec003 " + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '仓库 with spaces'
$literalName = if ($IsWindows) { 'a[1]literal.txt' } else { 'a[*]literal.txt' }
try {
    [void] (New-Item -ItemType Directory -Path $repo -Force)
    Invoke-FixtureGit -GitArguments @('init','-q',$repo)
    [System.IO.File]::WriteAllText((Join-Path $repo 'tracked.txt'), "initial`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'old name.txt'), "rename body`n")
    [System.IO.File]::WriteAllText((Join-Path $repo '.env'), "TOKEN=previous_unsafe`n")
    Invoke-FixtureGit -GitArguments @('-C',$repo,'add','.')
    Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base')

    Invoke-FixtureGit -GitArguments @('-C',$repo,'mv','old name.txt','new name.txt')
    [System.IO.File]::AppendAllText((Join-Path $repo 'tracked.txt'), "stage change`n")
    Invoke-FixtureGit -GitArguments @('-C',$repo,'add','tracked.txt')
    [System.IO.File]::AppendAllText((Join-Path $repo 'tracked.txt'), "unstaged change`n")
    [System.IO.File]::AppendAllText((Join-Path $repo '.env'), "TOKEN=must_not_leak`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'a b 文本.txt'), "reviewable untracked text`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'bom.txt'), "BOM untracked text`n", [System.Text.UTF8Encoding]::new($true))
    [System.IO.File]::WriteAllBytes((Join-Path $repo 'binary.dat'), [byte[]]@(1,0,2,3))
    [System.IO.File]::WriteAllText((Join-Path $repo '.env.local'), "SECRET=untracked_private`n")
    [System.IO.File]::WriteAllText((Join-Path $repo $literalName), "special filename`n")

    $index = (& git -C $repo rev-parse --git-path index)
    if (-not [System.IO.Path]::IsPathRooted($index)) { $index = Join-Path $repo $index }
    $indexHashBefore = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash

    $meta = CES -Action Collect -Path $repo -ExpectedExit 0
    Assert-Check ($meta.status -eq 'success') 'Metadata-only collection should succeed.'
    Assert-Check ($meta.data.subject.source_mode -eq 'working_tree_diff') 'Wrong selector mode.'
    Assert-Check ($meta.data.staged.count -ge 2) 'Staged inventory omitted entries.'
    Assert-Check (@($meta.data.staged.entries | Where-Object { $_.status -match '^R' -and $_.old_path -eq 'old name.txt' -and $_.path -eq 'new name.txt' }).Count -eq 1) 'Rename not preserved.'
    Assert-Check (@($meta.data.unstaged.entries | Where-Object { $_.path -eq 'tracked.txt' }).Count -eq 1) 'Unstaged stage missing.'
    Assert-Check (@($meta.data.untracked.entries | Where-Object { $_.path -eq 'a b 文本.txt' }).Count -eq 1) 'UTF-8 untracked path missing.'
    Assert-Check ($meta.data.staged.patch_state -eq 'not_requested') 'Default must not disclose code content.'
    Assert-Check ($meta.data.snapshot.atomic -eq $false) 'Must never claim an atomic worktree snapshot.'
    Assert-Check (-not $meta.data.can_persist_ces_state) 'No persistence may be claimed.'

    $rich = CES -Action Collect -Path $repo -ExpectedExit 2 -Extra @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent')
    Assert-Check ($rich.status -eq 'partial') 'Excluded sensitive and binary content require partial coverage.'
    Assert-Check ($rich.data.staged.patch -match 'stage change') 'Staged patch was not collected.'
    Assert-Check ($rich.data.unstaged.patch -match 'unstaged change') 'Unstaged patch was not collected.'
    Assert-Check ($rich.data.staged.patch.EndsWith("`n")) 'Patch should retain its trailing newline.'
    Assert-Check ($rich.data.unstaged.patch -notmatch 'must_not_leak') 'Sensitive tracked patch leaked.'
    Assert-Check (@($rich.data.untracked.entries | Where-Object { $_.path -eq 'a b 文本.txt' -and $_.content -ceq "reviewable untracked text`n" }).Count -eq 1) 'Untracked text must preserve its first character and newline.'
    $bomEntry = @($rich.data.untracked.entries | Where-Object { $_.path -eq 'bom.txt' })
    Assert-Check ($bomEntry.Count -eq 1 -and $bomEntry[0].content -ceq "BOM untracked text`n") 'UTF-8 BOM must be removed only when present.'
    Assert-Check ($bomEntry[0].sha256 -ceq (Get-FileHash -LiteralPath (Join-Path $repo 'bom.txt') -Algorithm SHA256).Hash.ToLowerInvariant()) 'BOM file hash must bind its original bytes.'
    Assert-Check (@($rich.data.untracked.entries | Where-Object { $_.path -eq 'binary.dat' -and $_.content_state -eq 'binary_or_control' }).Count -eq 1) 'Binary file should be excluded.'
    Assert-Check (@($rich.data.untracked.entries | Where-Object { $_.path -eq '.env.local' -and $_.content_state -eq 'sensitive_path_excluded' }).Count -eq 1) 'Sensitive untracked path not excluded.'
    Assert-Check ($rich.data.unstaged.patch -notmatch 'must_not_leak') 'Sensitive patch appeared in output.'
    Assert-Check (@($rich.data.untracked.entries | Where-Object { $_.path -eq $literalName }).Count -eq 1) 'Literal Git metacharacters were not preserved.'
    Assert-Check ($rich.data.snapshot.consistency -eq 'available_content_rechecked') 'Requested content not rechecked.'

    $unsupported = CES -Action Collect -Path $repo -ExpectedExit 3 -Extra @('-Mode','ProposedPR')
    Assert-Check ($unsupported.reason_code -eq 'NOT_IMPLEMENTED') 'Other Collect modes must not simulate results.'
    $bare = Join-Path $fixture 'bare.git'
    Invoke-FixtureGit -GitArguments @('init','--bare','-q',$bare)
    $bareResult = CES -Action Collect -Path $bare -ExpectedExit 5
    Assert-Check ($bareResult.reason_code -eq 'COLLECT_REQUIRES_WORKTREE') 'Bare Collect should reject without empty fabricated evidence.'

    $indexHashAfter = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash
    Assert-Check ($indexHashBefore -eq $indexHashAfter) 'Collect modified Git index.'
    Assert-Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Collect wrote CES state to business repository.'
    Write-Output "PASS: EC-003 Collect smoke ($script:count checks)"
} finally {
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
    }
}

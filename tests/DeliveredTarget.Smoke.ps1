#requires -Version 7.0
<#
    EC-004 optional integration smoke (PowerShell 7 + Git).
    Fixture Git writes are confined to a new GUID-scoped temp directory.
    The CES CLI under test is used read-only; nothing is fetched remotely.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI missing.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Invoke-FixtureGit {
    param([string[]] $GitArguments)
    $output = @(& git @GitArguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture git command failed: $($GitArguments -join ' ') — $output" }
    return ($output -join "`n").Trim()
}
function CES {
    param([string] $Path, [int] $ExpectedExit, [string[]] $Extra)
    $args = @('-NoProfile','-File',$cli,'-Action','Collect','-RepoPath',$Path,'-Mode','DeliveredTarget','-Json') + $Extra
    $lines = @(& pwsh @args)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Wrong CES exit: $LASTEXITCODE expected ${ExpectedExit}: $lines"
    Check ($lines.Count -eq 1) 'JSON mode must return one JSON object.'
    $data = $lines[0] | ConvertFrom-Json -Depth 20
    Check ($data.product_version -eq '1.0.0' -and $data.build -eq '1.0.0') 'Version did not increment.'
    Check ($data.next_step -eq 'none' -and $data.read_only -eq $true) 'Unsupported handoff or write claim.'
    return $data
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces ec004 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '仓库 with spaces'
try {
    [void](New-Item -ItemType Directory -Path $repo -Force)
    [void](Invoke-FixtureGit -GitArguments @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'old filename.txt'), "rename preserved`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'tracked.txt'), "before`n")
    [System.IO.File]::WriteAllText((Join-Path $repo '.env'), "SECRET=original`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','.'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base'))
    $base = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','HEAD')

    # A sibling commit is not an ancestor of main's later target.
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'checkout','-qb','sibling',$base))
    [System.IO.File]::WriteAllText((Join-Path $repo 'sibling.txt'), "sibling`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','sibling.txt'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','sibling'))
    $sibling = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','HEAD')
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'checkout','-q','main'))

    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'mv','old filename.txt','new filename.txt'))
    [System.IO.File]::AppendAllText((Join-Path $repo 'tracked.txt'), "committed_change_visible`n")
    [System.IO.File]::AppendAllText((Join-Path $repo '.env'), "SECRET=must_not_leak`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'unicode 中文.txt'), "committed_unicode`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','.'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','target'))
    $target = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','HEAD')
    $selector = @('-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/heads/main')

    # Dirty local checkout must not alter historical commit-range evidence.
    [System.IO.File]::AppendAllText((Join-Path $repo 'tracked.txt'), "staged_not_committed`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','tracked.txt'))
    [System.IO.File]::AppendAllText((Join-Path $repo 'tracked.txt'), "unstaged_not_committed`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'untracked.txt'), "untracked_not_committed`n")
    $index = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($index)) { $index = Join-Path $repo $index }
    $hashBefore = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash

    $plain = CES -Path $repo -ExpectedExit 0 -Extra $selector
    Check ($plain.status -eq 'success') 'Metadata-only commit range should succeed.'
    Check ($plain.data.subject.source_mode -eq 'delivered_target_diff') 'Source mode mismatch.'
    Check ($plain.data.subject.verification_scope -eq 'local_ref_only') 'Local ref is the only proven delivery scope.'
    Check (-not $plain.data.subject.remote_delivery_verified -and -not $plain.data.subject.deployment_verified -and -not $plain.data.subject.pr_association_verified) 'Must not claim remote delivery, deployment, or PR association.'
    Check ($plain.data.changes.count -ge 3) 'Missing committed paths.'
    Check ($plain.data.changes.patch_state -eq 'not_requested') 'Patch unexpectedly emitted by default.'
    Check ($plain.data.snapshot.consistency -eq 'ref_and_inventory_rechecked') 'Ref/inventory was not rechecked.'
    Check (@($plain.data.changes.entries | Where-Object { $_.status -match '^R' -and $_.old_path -eq 'old filename.txt' -and $_.path -eq 'new filename.txt' }).Count -eq 1) 'Rename provenance lost.'
    Check (@($plain.data.changes.entries | Where-Object { $_.path -eq 'unicode 中文.txt' }).Count -eq 1) 'Unicode committed path missing.'
    Check (-not $plain.data.can_persist_ces_state) 'No local CES persistence must be claimed.'

    $rich = CES -Path $repo -ExpectedExit 2 -Extra ($selector + @('-IncludePatches'))
    Check ($rich.status -eq 'partial') 'Skipped protected path requires partial output.'
    Check ($rich.data.changes.patch_state -eq 'included_with_exclusions') 'Patch state must signal exclusions.'
    Check ($rich.data.changes.patch -match 'committed_change_visible') 'Committed patch content missing.'
    Check ($rich.data.changes.patch -notmatch 'must_not_leak') 'Protected file content leaked.'
    Check ($rich.data.changes.patch -notmatch 'staged_not_committed|unstaged_not_committed|untracked_not_committed') 'Working tree polluted pinned commit evidence.'
    Check ($rich.data.changes.patch.EndsWith("`n")) 'Patch trailing newline lost.'
    Check ($rich.data.snapshot.consistency -eq 'ref_inventory_and_available_patch_rechecked') 'Raw patch must be rechecked.'
    Check ($rich.data.changes.excluded_sensitive_paths -gt 0) 'Protected path exclusion not recorded.'

    $same = CES -Path $repo -ExpectedExit 0 -Extra @('-BaseSha',$target,'-TargetSha',$target,'-TargetRef','refs/heads/main','-IncludePatches')
    Check ($same.data.changes.count -eq 0 -and $same.data.changes.patch_state -eq 'empty') 'Equal commits should return a verified empty diff.'
    $badRef = CES -Path $repo -ExpectedExit 4 -Extra @('-BaseSha',$base,'-TargetSha',$sibling,'-TargetRef','refs/heads/main')
    Check ($badRef.reason_code -eq 'TARGET_REF_MISMATCH') 'Mismatched ref should fail closed.'
    $badAncestor = CES -Path $repo -ExpectedExit 4 -Extra @('-BaseSha',$sibling,'-TargetSha',$target,'-TargetRef','refs/heads/main')
    Check ($badAncestor.reason_code -eq 'BASE_NOT_ANCESTOR') 'Nonancestor base must not count as delivered.'
    $shortRef = CES -Path $repo -ExpectedExit 4 -Extra @('-BaseSha',$base,'-TargetSha',$target,'-TargetRef','main')
    Check ($shortRef.reason_code -eq 'FULL_TARGET_REF_REQUIRED') 'Short target ref must be rejected.'
    $badFlag = CES -Path $repo -ExpectedExit 4 -Extra ($selector + @('-IncludeUntrackedContent'))
    Check ($badFlag.reason_code -eq 'UNTRACKED_NOT_APPLICABLE') 'Untracked content flag must not be ignored.'

    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'update-ref','refs/remotes/example/main',$target))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'symbolic-ref','refs/remotes/example/HEAD','refs/remotes/example/main'))
    $symRef = CES -Path $repo -ExpectedExit 4 -Extra @('-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/remotes/example/HEAD')
    Check ($symRef.reason_code -eq 'SYMBOLIC_TARGET_REF') 'Symbolic ref should not count as an exact target branch.'

    $bare = Join-Path $fixture 'bare.git'
    [void](Invoke-FixtureGit -GitArguments @('clone','--bare','-q',$repo,$bare))
    $bareResult = CES -Path $bare -ExpectedExit 2 -Extra $selector
    Check ($bareResult.data.changes.count -ge 3) 'Bare clone must retain object-diff evidence.'
    Check ($bareResult.data.worktree_kind -eq 'bare' -and -not $bareResult.data.stable_root_verified) 'Bare Git cannot be assigned a stable CES worktree.'
    $hashAfter = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash
    Check ($hashBefore -eq $hashAfter) 'CES unexpectedly changed the real index.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'CES created persistent state in analyzed project.'

    Write-Output "PASS: EC-004 DeliveredTarget smoke ($script:checks checks)"
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

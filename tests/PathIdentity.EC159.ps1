#requires -Version 7.0
<#
    EC-159 optional NATIVE development scenarios, deferred for final assisted
    acceptance where PowerShell7/Git/Windows/macOS are available. Only the
    generated OS TEMP fixture is written. No CodeSave approval is exercised.
    These tests do not certify concurrent hostile filesystem races.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$skillRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $skillRoot 'scripts/pathidentity.ps1')
$cli = Join-Path $skillRoot 'scripts/ces.ps1'
$pwshExe = (Get-Command -Name 'pwsh' -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$gitExe = (Get-Command -Name 'git' -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$script:checks = 0

function Check([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "EC159 check failed: $Label" }
    $script:checks++
}
function Expect-Rejection([scriptblock]$Script, [string]$Label) {
    $rejected = $false
    try { & $Script | Out-Null } catch { $rejected = $true }
    Check $rejected $Label
}
function Git([string[]]$Arguments) {
    & $gitExe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Git test fixture command failed: $($Arguments[0])" }
}
function Inspect([string]$Path) {
    $response = @(& $pwshExe -NoProfile -File $cli -Action Inspect -RepoPath $Path -Json)
    $exitCode = $LASTEXITCODE
    Check ($response.Count -eq 1) 'Inspect emits one JSON envelope'
    return [pscustomobject]@{
        code = $exitCode
        response = ($response[0] | ConvertFrom-Json -Depth 32)
    }
}

$base = Join-Path ([System.IO.Path]::GetTempPath()) ('ces-ec159-' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $base 'repo'
$outside = Join-Path $base 'repo-sibling'
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void][System.IO.Directory]::CreateDirectory($outside)
    $selected = Resolve-CesUserPath -Path 'repo' -RelativeTo $base
    Check ($selected.absolute_path -ceq $repo) 'relative user path normalized'
    Check (-not $selected.write_authorized) 'relative path never grants write'
    $contained = Assert-CesContainedPath -Root $repo -Path '.codex/ces/owner.json'
    Check ($contained -ceq (Join-Path $repo '.codex/ces/owner.json')) 'fixed local CES child path'
    Expect-Rejection { Assert-CesContainedPath -Root $repo -Path '../repo-sibling' } 'reject lexical parent traversal'
    Expect-Rejection { Assert-CesContainedPath -Root $repo -Path $outside } 'reject absolute sibling prefix collision'
    Expect-Rejection { Assert-CesContainedPath -Root $repo -Path $repo } 'reject root as storage child'

    $evidence = Join-Path $outside 'saved-collect.json'
    [System.IO.File]::WriteAllText($evidence, '{"fixture":true}')
    $evidenceResult = Resolve-CesEvidencePath -Path $evidence -RelativeTo $base
    Check ($evidenceResult.origin -ceq 'caller_supplied_untrusted_bytes') 'external evidence retained as untrusted'
    Check (-not $evidenceResult.can_authorize_write) 'evidence cannot grant writes'
    Check ((Format-CesPathForLog -Path $evidence -VerifiedRoot $repo) -ceq '<external-or-unverified-path>') 'outside path redacted'
    Check ((Redact-CesKnownPaths -Message "error $evidence" -SensitivePaths @($evidence)) -notmatch [regex]::Escape($evidence)) 'diagnostic path redacted'

    $unknown = Resolve-CesActorIdentity -DisplayName 'Shared Name'
    Check ($unknown.status -ceq 'unknown' -and $null -eq $unknown.actor_key) 'name alone is never identity'
    Expect-Rejection { Resolve-CesActorIdentity -Provider 'github' -Tenant 'public' } 'reject incomplete identity tuple'
    $one = Resolve-CesActorIdentity -Provider 'github' -Tenant 'public' -ImmutableSubjectId '1001' -DisplayName 'Shared Name'
    $two = Resolve-CesActorIdentity -Provider 'github' -Tenant 'public' -ImmutableSubjectId '1002' -DisplayName 'Shared Name'
    $three = Resolve-CesActorIdentity -Provider 'github' -Tenant 'other' -ImmutableSubjectId '1001' -DisplayName 'Shared Name'
    Check ($one.status -ceq 'declared_unverified' -and $null -eq $one.actor_key) 'full caller tuple not authenticated'
    Check (-not $one.can_authorize_write -and -not $one.verified) 'actor assertion is never permission'
    Check ($one.declared_actor_key -cne $two.declared_actor_key) 'same name and tenant different IDs remain separate'
    Check ($one.declared_actor_key -cne $three.declared_actor_key) 'same ID different tenant remain separate'
    Expect-Rejection { Assert-CesVerifiedActor -Actor $one } 'no unverified actor may be elevated'
    Expect-Rejection { Resolve-CesActorIdentity -Provider 'github' -Tenant 'public' -ImmutableSubjectId "bad`n" } 'reject control bytes in actor ID'

    # Symlink case is optional on Windows without developer mode privileges.
    $linkedParent = Join-Path $repo 'redirect'
    $linkMade = $false
    try {
        [void](New-Item -ItemType SymbolicLink -Path $linkedParent -Target $outside -ErrorAction Stop)
        $linkMade = $true
    } catch { Write-Output 'Symlink creation not permitted on host; native symlink scenario NOT_RUN.' }
    if ($linkMade) {
        Expect-Rejection { Assert-CesContainedPath -Root $repo -Path (Join-Path $linkedParent 'saved-collect.json') } 'reject symbolic parent'
        Expect-Rejection { Resolve-CesEvidencePath -Path (Join-Path $linkedParent 'saved-collect.json') -RelativeTo $base } 'reject symlinked evidence parent'
    }

    # Real Git worktrees: the main root must be detected independently of
    # worktree-list ordering, and linked roots must remain read-only.
    Git @('init','-q',$repo)
    Git @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@invalid.example',
        'commit','-q','--allow-empty','-m','EC159 fixture')
    $main = Inspect $repo
    Check ($main.code -eq 0 -and $main.response.data.worktree_kind -ceq 'main') 'main worktree verified'
    Check ($main.response.data.stable_root_verified -eq $true) 'main stable root verified'
    Check ($main.response.data.can_persist_ces_state -eq $false) 'Inspect never grants write'
    $linked = Join-Path $base 'linked'
    Git @('-C',$repo,'worktree','add','--detach','-q',$linked)
    $observed = Inspect $linked
    Check ($observed.response.data.worktree_kind -ceq 'linked') 'linked worktree classified independently'
    Check ($observed.response.data.can_persist_ces_state -eq $false) 'linked worktree cannot grant write'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex'))) 'fixture has no CES store side effect'
    Write-Output "EC-159 native development scenarios passed: $script:checks checks (temp test repo only)."
} finally {
    try { if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue } } catch { }
}

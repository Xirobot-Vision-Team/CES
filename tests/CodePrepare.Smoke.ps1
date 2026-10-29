#requires -Version 7.0
<#
    EC-006 optional integration smoke for read-only CodePrepare Snapshot.
    Runs only on an authorized PowerShell 7 + Git host. All fixture writes
    occur inside a new GUID-scoped temporary directory; CES itself is read-only.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI is missing.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git is missing.' }
$script:checks = 0
function Assert-Check {
    param([bool] $Condition, [string] $Description)
    if (-not $Condition) { throw $Description }
    $script:checks++
}
function Invoke-FixtureGit {
    param([string[]] $Arguments)
    $lines = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture Git command failed: $($Arguments -join ' ') -- $lines" }
    return ($lines -join "`n").Trim()
}
function Run-CES {
    param([string] $Action, [string] $Repo, [int] $ExpectExit, [string[]] $More = @())
    $lines = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Assert-Check ($LASTEXITCODE -eq $ExpectExit) "Wrong $Action exit $LASTEXITCODE; expected $ExpectExit. $lines"
    Assert-Check ($lines.Count -eq 1) 'JSON stdout must contain one object.'
    $r = $lines[0] | ConvertFrom-Json -Depth 32
    Assert-Check ($r.product_version -eq '1.0.0' -and $r.build -eq '1.0.0') 'Build version is stale.'
    Assert-Check ($r.read_only -and $r.next_step -eq 'none') 'A read-only action must not fabricate a handoff.'
    return $r
}
function Save-FixtureSnapshot {
    param([string] $Repo, [string] $File, [string[]] $More, [int] $ExpectExit = 0)
    $result = Run-CES -Action Collect -Repo $Repo -ExpectExit $ExpectExit -More $More
    [System.IO.File]::WriteAllText($File, ($result | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
    return $result
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces codeprepare ec006 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '本地 工程'
$saved = Join-Path $fixture 'saved snapshot.json'
try {
    [void](New-Item -ItemType Directory -Path $repo -Force)
    [void](Invoke-FixtureGit -Arguments @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'api.ps1'), 'before' + "`n")
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'add','api.ps1'))
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base'))
    $base = Invoke-FixtureGit -Arguments @('-C',$repo,'rev-parse','HEAD')
    [System.IO.File]::AppendAllText((Join-Path $repo 'api.ps1'), 'staged alpha' + "`n")
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'add','api.ps1'))
    [System.IO.File]::AppendAllText((Join-Path $repo 'api.ps1'), 'unstaged beta' + "`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'untracked 中文.txt'), 'untracked payload' + "`n")
    $index = Invoke-FixtureGit -Arguments @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($index)) { $index = Join-Path $repo $index }
    $indexHash = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash
    [void](Save-FixtureSnapshot -Repo $repo -File $saved -More @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent'))
    $selectors = @('-Mode','Snapshot','-EvidencePath',$saved)

    $noDisclosure = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 2 -More $selectors
    Assert-Check ($noDisclosure.reason_code -eq 'CODE_PREPARE_CONTENT_REQUIRED') 'Missing disclosure should be a partial response.'
    Assert-Check ($null -eq $noDisclosure.data.review_packet -and -not $noDisclosure.data.prepared) 'No raw content without explicit flags.'
    $patchOnly = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 2 -More ($selectors + @('-IncludePatches'))
    Assert-Check ($null -eq $patchOnly.data.review_packet) 'Untracked content still needs separate explicit disclosure.'
    $ready = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 0 -More ($selectors + @('-IncludePatches','-IncludeUntrackedContent'))
    Assert-Check ($ready.reason_code -eq 'CODE_PREPARE_READY' -and $ready.data.prepared) 'Matched snapshot should produce a real review packet.'
    Assert-Check ($ready.data.review_packet.schema_version -eq 'ces.code_packet.v1') 'Packet schema must be stable.'
    Assert-Check ($ready.data.review_packet.layers.staged.patch -match 'staged alpha') 'Staged patch was lost.'
    Assert-Check ($ready.data.review_packet.layers.unstaged.patch -match 'unstaged beta') 'Unstaged patch was lost.'
    Assert-Check ($ready.data.review_packet.layers.untracked.entries[0].content -match 'untracked payload') 'Untracked bytes were lost.'
    Assert-Check (-not $ready.data.review_packet.provenance.independently_authenticated) 'A saved JSON file is not trusted provenance.'
    Assert-Check (-not $ready.data.scope.remote_delivery_verified -and -not $ready.data.scope.ci_verified) 'Local evidence cannot attest remote or CI state.'
    Assert-Check ($ready.coverage.code_packet_built -and $ready.coverage.content_release_authorized) 'Verified disclosure coverage should be reported.'
    Assert-Check ($indexHash -eq (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash) 'CodePrepare modified the Git index.'
    Assert-Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'CodePrepare created CES persistent state.'

    [System.IO.File]::AppendAllText((Join-Path $repo 'untracked 中文.txt'), 'later' + "`n")
    $stale = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 2 -More ($selectors + @('-IncludePatches','-IncludeUntrackedContent'))
    Assert-Check ($stale.reason_code -eq 'CODE_PREPARE_RECONCILE_NOT_MATCHED') 'Same-path untracked byte drift must block release.'
    Assert-Check ($null -eq $stale.data.review_packet) 'A drifted scope must emit no raw content.'
    [System.IO.File]::WriteAllText((Join-Path $repo 'untracked 中文.txt'), 'untracked payload' + "`n")

    [void](Save-FixtureSnapshot -Repo $repo -File $saved -More @('-Mode','WorkingTree'))
    $metadata = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 2 -More ($selectors + @('-IncludePatches','-IncludeUntrackedContent'))
    Assert-Check ($metadata.reason_code -eq 'CODE_PREPARE_CONTENT_REQUIRED') 'A metadata-only snapshot cannot be upgraded to code content.'
    Assert-Check ($null -eq $metadata.data.review_packet) 'Do not fabricate missing patch bytes.'
    $wrongMode = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 4 -More @('-Mode','DeliveredTarget','-EvidencePath',$saved)
    Assert-Check ($wrongMode.reason_code -eq 'SNAPSHOT_MODE_REQUIRED') 'Source mode cannot be overridden.'
    $wrongSha = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 4 -More ($selectors + @('-BaseSha',$base))
    Assert-Check ($wrongSha.reason_code -eq 'CODE_PREPARE_SELECTORS_NOT_APPLICABLE') 'Commit selectors come from the saved observation.'

    $other = Join-Path $fixture 'another repo'
    [void](New-Item -ItemType Directory -Path $other -Force)
    [void](Invoke-FixtureGit -Arguments @('init','-q',$other))
    $wrongRoot = Run-CES -Action CodePrepare -Repo $other -ExpectExit 4 -More $selectors
    Assert-Check ($wrongRoot.reason_code -eq 'EVIDENCE_REPO_MISMATCH') 'Cross-repository saved evidence is rejected.'
    [System.IO.File]::WriteAllText($saved, '{"not":"a collect"}')
    $invalid = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 4 -More $selectors
    Assert-Check ($invalid.reason_code -eq 'EVIDENCE_INVALID') 'Malformed evidence must fail closed.'

    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'add','api.ps1','untracked 中文.txt'))
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','target'))
    $target = Invoke-FixtureGit -Arguments @('-C',$repo,'rev-parse','HEAD')
    $deliveredSelectors = @('-Mode','DeliveredTarget','-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/heads/main','-IncludePatches')
    [void](Save-FixtureSnapshot -Repo $repo -File $saved -More $deliveredSelectors)
    $delivery = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 0 -More ($selectors + @('-IncludePatches'))
    Assert-Check ($delivery.data.review_packet.layers.changes.patch -match 'staged alpha') 'Pinned commit diff is reviewable.'
    Assert-Check (-not $delivery.data.scope.pr_association_verified) 'DeliveredTarget is not PR attestation.'
    $badUntracked = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 4 -More ($selectors + @('-IncludePatches','-IncludeUntrackedContent'))
    Assert-Check ($badUntracked.reason_code -eq 'UNTRACKED_NOT_APPLICABLE') 'Delivered mode must reject an untracked switch.'
    [System.IO.File]::AppendAllText((Join-Path $repo 'api.ps1'), 'later release' + "`n")
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'add','api.ps1'))
    [void](Invoke-FixtureGit -Arguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','later'))
    $movedRef = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 2 -More ($selectors + @('-IncludePatches'))
    Assert-Check ($movedRef.reason_code -eq 'CODE_PREPARE_RECONCILE_NOT_MATCHED' -and $null -eq $movedRef.data.review_packet) 'Moved local ref invalidates review packet.'

    [void](Save-FixtureSnapshot -Repo $repo -File $saved -More @('-Mode','WorkingTree'))
    $empty = Run-CES -Action CodePrepare -Repo $repo -ExpectExit 0 -More $selectors
    Assert-Check ($empty.reason_code -eq 'CODE_PREPARE_EMPTY' -and -not $empty.data.prepared) 'Clean tree should not fabricate a code diff.'
    Write-Output "PASS: EC-006 CodePrepare smoke ($script:checks checks)"
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

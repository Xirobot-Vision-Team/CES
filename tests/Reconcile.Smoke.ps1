#requires -Version 7.0
<#
    EC-005 optional read-only Reconcile smoke: scratch repositories only.
    Verifies provenance limits, matching, same-path content drift, target-ref
    drift, malformed evidence, wrong repository binding and source immutability.
    Requires an approved local PowerShell 7+ / Git host; not a CI assertion.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI missing.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git is missing.' }
$script:checks = 0
function Check {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Invoke-FixtureGit {
    param([string[]] $GitArguments)
    $out = @(& git @GitArguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture git failure: $($GitArguments -join ' '): $out" }
    return ($out -join "`n").Trim()
}
function CES {
    param([string] $Action, [string] $Repo, [int] $ExpectedExit, [string[]] $More)
    $lines = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Exit for $Action expected ${ExpectedExit}: $lines"
    Check ($lines.Count -eq 1) 'One JSON stdout object must be returned.'
    $r = $lines[0] | ConvertFrom-Json -Depth 32
    Check ($r.product_version -eq '1.0.0' -and $r.build -eq '1.0.0') 'Version mismatch.'
    Check ($r.read_only -eq $true -and $r.next_step -eq 'none') 'No write or fake handoff permitted.'
    return $r
}
function Save-Collect {
    param([string] $Repo, [string] $Path, [string[]] $Extra, [int] $ExpectedExit = 0)
    $r = CES -Action 'Collect' -Repo $Repo -ExpectedExit $ExpectedExit -More $Extra
    [System.IO.File]::WriteAllText($Path, ($r | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
    return $r
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces reconcile ec005 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '中文 repo'
$evidence = Join-Path $fixture 'evidence.json'
try {
    [void](New-Item -ItemType Directory -Path $repo -Force)
    [void](Invoke-FixtureGit -GitArguments @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'normal.txt'), "base`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','.'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base'))
    $base = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','HEAD')
    [System.IO.File]::AppendAllText((Join-Path $repo 'normal.txt'), "unstaged alpha`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'new 中文.txt'), "untracked alpha`n")
    $index = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($index)) { $index = Join-Path $repo $index }
    $indexBefore = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash

    [void](Save-Collect -Repo $repo -Path $evidence -Extra @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent'))
    $same = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$evidence)
    Check ($same.data.verdict -eq 'matched') 'Same source/content must match.'
    Check ($same.data.comparison.head.state -eq 'matched') 'HEAD must be compared.'
    Check ($same.data.comparison.unstaged.patch.state -eq 'matched') 'Patch hash must be compared.'
    Check ($same.data.comparison.untracked.content.state -eq 'matched') 'Untracked bytes must be compared.'
    Check (-not $same.data.previous_snapshot.provenance_authenticated) 'Evidence file is never authenticated provenance.'
    Check ($same.data.comparison.unstaged.patch.PSObject.Properties.Name -notcontains 'text') 'Reconcile must never expose raw patch text.'
    Check (-not $same.data.can_persist_ces_state) 'Reconcile is read-only.'

    # Changed untracked bytes on the SAME path are visible only by content opt-in.
    [System.IO.File]::AppendAllText((Join-Path $repo 'new 中文.txt'), "untracked beta`n")
    $untrackedDrift = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 2 -More @('-EvidencePath',$evidence)
    Check ($untrackedDrift.data.comparison.untracked.inventory.state -eq 'matched') 'Untracked path inventory should be equal.'
    Check ($untrackedDrift.data.comparison.untracked.content.state -eq 'changed') 'Untracked same-path bytes must be compared.'
    [System.IO.File]::WriteAllText((Join-Path $repo 'new 中文.txt'), "untracked alpha`n")

    # An altered saved digest cannot pass the evidence-file integrity guard.
    $savedBytes = [System.IO.File]::ReadAllBytes($evidence)
    $tampered = [System.IO.File]::ReadAllText($evidence) | ConvertFrom-Json -Depth 32
    $tampered.data.unstaged.patch_sha256 = ('0' * 64)
    [System.IO.File]::WriteAllText($evidence, ($tampered | ConvertTo-Json -Depth 32 -Compress))
    $invalidHash = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 4 -More @('-EvidencePath',$evidence)
    Check ($invalidHash.reason_code -eq 'EVIDENCE_INVALID') 'Corrupt source patch hash must be rejected.'
    [System.IO.File]::WriteAllBytes($evidence, $savedBytes)

    # No path/status changes: detect actual UTF-8 source drift by hashes.
    [System.IO.File]::AppendAllText((Join-Path $repo 'normal.txt'), "unstaged beta`n")
    $changed = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 2 -More @('-EvidencePath',$evidence)
    Check ($changed.reason_code -eq 'RECONCILE_CHANGED' -and $changed.data.verdict -eq 'changed') 'Same-path edit must be detected.'
    Check ($changed.data.comparison.unstaged.inventory.state -eq 'matched') 'Path list should remain unchanged.'
    Check ($changed.data.comparison.unstaged.patch.state -eq 'changed') 'Patch digest must identify same-path content drift.'

    # A snapshot with no content requested cannot prove same-path bytes.
    [void](Save-Collect -Repo $repo -Path $evidence -Extra @('-Mode','WorkingTree'))
    [System.IO.File]::AppendAllText((Join-Path $repo 'normal.txt'), "not-visible-to-inventory`n")
    $metadata = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 0 -More @('-EvidencePath',$evidence)
    Check ($metadata.data.verdict -eq 'matched') 'Metadata-only observation compares metadata only.'
    Check ($metadata.data.comparison.unstaged.patch.state -eq 'not_requested') 'Missing contents are not asserted equal.'
    Check ($metadata.data.notes -match 'sampled') 'Non-atomic scope must remain explicit.'

    # Wrong root and malformed input must fail closed.
    $other = Join-Path $fixture 'other repository'
    [void](New-Item -ItemType Directory -Path $other)
    [void](Invoke-FixtureGit -GitArguments @('init','-q',$other))
    $mismatch = CES -Action 'Reconcile' -Repo $other -ExpectedExit 4 -More @('-EvidencePath',$evidence)
    Check ($mismatch.reason_code -eq 'EVIDENCE_REPO_MISMATCH') 'Never cross-compare repositories.'
    [System.IO.File]::WriteAllText($evidence, '{"fabricated":true}')
    $bad = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 4 -More @('-EvidencePath',$evidence)
    Check ($bad.reason_code -eq 'EVIDENCE_INVALID') 'Malformed/forged envelope must not be accepted.'

    # Construct committed target range and reconcile against a moving local ref.
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','normal.txt','new 中文.txt'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','delivered'))
    $target = Invoke-FixtureGit -GitArguments @('-C',$repo,'rev-parse','HEAD')
    $selector = @('-Mode','DeliveredTarget','-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/heads/main')
    [void](Save-Collect -Repo $repo -Path $evidence -Extra $selector)
    $pinned = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 0 -More @('-EvidencePath',$evidence)
    Check ($pinned.data.verdict -eq 'matched' -and $pinned.data.comparison.target_ref.state -eq 'matched') 'Pinned target ref must match.'
    [System.IO.File]::AppendAllText((Join-Path $repo 'normal.txt'), "a second delivery`n")
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'add','normal.txt'))
    [void](Invoke-FixtureGit -GitArguments @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','later'))
    $refDrift = CES -Action 'Reconcile' -Repo $repo -ExpectedExit 2 -More @('-EvidencePath',$evidence)
    Check ($refDrift.data.verdict -eq 'changed' -and $refDrift.data.comparison.target_ref.state -eq 'changed') 'Moving target ref should be explicitly changed.'
    Check (-not $refDrift.data.subject.remote_delivery_verified) 'A local ref never verifies remote delivery.'
    $indexAfter = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash
    # Git fixture writes above legitimately change the index: compare again
    # around an isolated Reconcile invocation instead of against initial state.
    [void](CES -Action 'Reconcile' -Repo $repo -ExpectedExit 2 -More @('-EvidencePath',$evidence))
    $indexAfterReconcile = (Get-FileHash -LiteralPath $index -Algorithm SHA256).Hash
    Check ($indexAfter -eq $indexAfterReconcile) 'Reconcile changed Git index.'
    Check ($indexBefore -ne $null) 'Initial index checksum was recorded.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'CES must not create state.'
    Write-Output "PASS: EC-005 Reconcile smoke ($script:checks checks)"
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

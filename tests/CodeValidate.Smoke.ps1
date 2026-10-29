#requires -Version 7.0
<#
    EC-007 optional local smoke: isolated Git repo, explicit saved Collect,
    separately authored draft, exact packet binding, fail-closed unbound
    anchors, stale source and no CES persistence. Runs ONLY when pwsh exists.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI missing.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git missing.' }
$script:checks = 0
function Assert-Check {
    param([bool] $Condition, [string] $Text)
    if (-not $Condition) { throw $Text }
    $script:checks++
}
function Git-Fix {
    param([string[]] $ArgsList)
    $out = @(& git @ArgsList 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Git fixture command failed: $($ArgsList -join ' ') -- $out" }
    return ($out -join "`n").Trim()
}
function Run-CES {
    param([string] $Action, [string] $Repo, [int] $Exit, [string[]] $More = @())
    $out = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Assert-Check ($LASTEXITCODE -eq $Exit) "Wrong $Action exit $LASTEXITCODE, expected $Exit. $out"
    Assert-Check ($out.Count -eq 1) 'CLI must produce exactly one stdout JSON object.'
    $value = $out[0] | ConvertFrom-Json -Depth 32
    Assert-Check ($value.product_version -eq '1.0.0' -and $value.build -eq '1.0.0') 'Version/build mismatch.'
    Assert-Check ($value.read_only -and $value.next_step -eq 'none') 'Read-only result pretended to advance/save.'
    return $value
}
function Save-Snapshot {
    param([string] $Repo, [string] $Path, [string[]] $Flags)
    $r = Run-CES -Action Collect -Repo $Repo -Exit 0 -More $Flags
    [System.IO.File]::WriteAllText($Path, ($r | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
}
function Write-Draft {
    param([string] $Path, [object] $Draft)
    [System.IO.File]::WriteAllText($Path, ($Draft | ConvertTo-Json -Depth 20 -Compress), [System.Text.UTF8Encoding]::new($false))
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces codevalidate ec007 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '工程 code 01'
$snapshot = Join-Path $fixture 'saved collect.json'
$draftPath = Join-Path $fixture 'review-draft.json'
try {
    [void](New-Item -ItemType Directory -Path $repo -Force)
    [void](Git-Fix -ArgsList @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'worker.ps1'), "first baseline`n")
    [System.IO.File]::WriteAllText((Join-Path $repo 'other.ps1'), "other baseline`n")
    [void](Git-Fix -ArgsList @('-C',$repo,'add','worker.ps1','other.ps1'))
    [void](Git-Fix -ArgsList @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base'))
    $base = Git-Fix -ArgsList @('-C',$repo,'rev-parse','HEAD')
    [System.IO.File]::AppendAllText((Join-Path $repo 'worker.ps1'), "staged alpha marker`n")
    [System.IO.File]::AppendAllText((Join-Path $repo 'other.ps1'), "other staged marker`n")
    [void](Git-Fix -ArgsList @('-C',$repo,'add','worker.ps1','other.ps1'))
    [System.IO.File]::AppendAllText((Join-Path $repo 'worker.ps1'), "unstaged beta marker`n")
    [System.IO.File]::WriteAllText((Join-Path $repo '新笔记.txt'), "original note marker`n")
    $indexPath = Git-Fix -ArgsList @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($indexPath)) { $indexPath = Join-Path $repo $indexPath }
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
    Save-Snapshot -Repo $repo -Path $snapshot -Flags @('-Mode','WorkingTree','-IncludePatches','-IncludeUntrackedContent')
    $scope = @('-Mode','Snapshot','-EvidencePath',$snapshot,'-IncludePatches','-IncludeUntrackedContent')
    $prepared = Run-CES -Action CodePrepare -Repo $repo -Exit 0 -More $scope
    Assert-Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Prerequisite CodePrepare not ready.'
    Assert-Check ($prepared.data.packet_sha256 -cmatch '^[0-9a-f]{64}$') 'CodePrepare did not emit packet digest.'

    $finding1 = [ordered]@{
        id = 'STAGE-1'; title = 'Early-return risk in staged change'; severity = 'high'; confidence = 'medium'
        layer = 'staged'; path = 'worker.ps1'; evidence_quote = '+staged alpha marker'
        reasoning = 'The added marker is in staged source and deserves a call-site review.'
        impact = 'Potential unwanted early return requires confirmation.'
        recommendation = 'Review the actual control flow before proposing a fix.'
        line_start = 2; line_end = 2
    }
    $finding2 = [ordered]@{
        id = 'UNSTAGED-2'; title = 'Unstaged change requires coverage'; severity = 'low'; confidence = 'low'
        layer = 'unstaged'; path = 'worker.ps1'; evidence_quote = '+unstaged beta marker'
        reasoning = 'Unstaged source needs an independent coverage review.'
        impact = 'Test paths might be incomplete in the reviewed workspace.'
        recommendation = 'Inspect test call sites and add checks outside CES.'
    }
    $finding3 = [ordered]@{
        id = 'NOTE-3'; title = 'Review the new nontracked note'; severity = 'info'; confidence = 'high'
        layer = 'untracked'; path = '新笔记.txt'; evidence_quote = 'original note marker'
        reasoning = 'The new note is untracked and omitted from commit diffs.'
        impact = 'The file may be forgotten when making a commit.'
        recommendation = 'Confirm whether this file should be tracked.'
    }
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Three independently checked literal anchors, not proven defects.'
        findings = @($finding1, $finding2, $finding3)
        limitations = @('No CI/test run was observed.')
    }
    Write-Draft -Path $draftPath -Draft $draft
    $selectors = @('-InputPath',$draftPath) + $scope
    $checked = Run-CES -Action CodeValidate -Repo $repo -Exit 0 -More $selectors
    Assert-Check ($checked.reason_code -eq 'CODE_VALIDATE_OK' -and $checked.data.validated) 'Valid draft was not checked.'
    Assert-Check ($checked.data.finding_count -eq 3 -and $checked.data.checked_findings.Count -eq 3) 'Lost finding records.'
    Assert-Check ($checked.data.checked_findings[2].quote_presence -eq 'exact_untracked_file_literal') 'Untracked file anchor grade is wrong.'
    Assert-Check ($checked.data.checked_findings[0].quote_presence -eq 'pathspec_scoped_tracked_diff_literal') 'Tracked patch proof was overstated.'
    Assert-Check (-not $checked.data.semantic_claims_verified -and -not $checked.data.claimed_line_numbers_verified) 'Validator claimed semantic/line proof.'
    Assert-Check ($null -eq $checked.data.checked_findings[0].PSObject.Properties['evidence_quote']) 'Raw quote leaked into checked finding.'
    Assert-Check ($checked.coverage.code_draft_checked -and $checked.coverage.code_findings_anchored) 'Coverage flags missing.'
    Assert-Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Index was touched.'
    Assert-Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'CES state unexpectedly persisted.'

    $draft.packet_sha256 = 'a' * 64
    Write-Draft -Path $draftPath -Draft $draft
    $wrongDigest = Run-CES -Action CodeValidate -Repo $repo -Exit 2 -More $selectors
    Assert-Check ($wrongDigest.reason_code -eq 'CODE_VALIDATE_PACKET_MISMATCH' -and -not $wrongDigest.data.validated) 'Wrong packet hash accepted.'
    $draft.packet_sha256 = $prepared.data.packet_sha256
    $draft.findings[0].path = 'not-present.ps1'
    Write-Draft -Path $draftPath -Draft $draft
    $wrongPath = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($wrongPath.reason_code -eq 'CODE_VALIDATE_EVIDENCE_UNBOUND' -and @($wrongPath.data.checked_findings).Count -eq 0) 'Unbound path accepted.'
    $draft.findings[0].path = 'worker.ps1'
    $draft.findings[0].layer = 'untracked'
    Write-Draft -Path $draftPath -Draft $draft
    $wrongLayer = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($wrongLayer.reason_code -eq 'CODE_VALIDATE_EVIDENCE_UNBOUND') 'Wrong layer accepted.'
    $draft.findings[0].layer = 'staged'
    $draft.findings[0].evidence_quote = '+not present in any source'
    Write-Draft -Path $draftPath -Draft $draft
    $wrongQuote = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($wrongQuote.reason_code -eq 'CODE_VALIDATE_EVIDENCE_UNBOUND') 'Absent literal quote accepted.'
    # The quote occurs in the overall staged patch, but in OTHER file.
    # A pathspec-scoped re-read must reject this false path attribution.
    $draft.findings[0].evidence_quote = '+other staged marker'
    Write-Draft -Path $draftPath -Draft $draft
    $wrongFileQuote = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($wrongFileQuote.reason_code -eq 'CODE_VALIDATE_EVIDENCE_UNBOUND') 'A quote from another file in the same layer was accepted.'
    $draft.findings[0].evidence_quote = '+staged alpha marker'
    $draft.findings[1].id = 'STAGE-1' 
    Write-Draft -Path $draftPath -Draft $draft
    $duplicateID = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($duplicateID.reason_code -eq 'CODE_VALIDATE_DRAFT_INVALID') 'Repeated finding ID accepted.'
    $draft.findings[1].id = 'UNSTAGED-2'
    Write-Draft -Path $draftPath -Draft $draft
    $source = [System.IO.File]::ReadAllText($draftPath)
    [System.IO.File]::WriteAllText($draftPath, ($source.Replace('"task_kind":', '"task_kind":"code_analysis","task_kind":')), [System.Text.UTF8Encoding]::new($false))
    $dupeKey = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More $selectors
    Assert-Check ($dupeKey.reason_code -eq 'CODE_VALIDATE_DRAFT_INVALID') 'Duplicated JSON keys accepted.'
    Write-Draft -Path $draftPath -Draft $draft
    $noConsent = Run-CES -Action CodeValidate -Repo $repo -Exit 2 -More @('-Mode','Snapshot','-EvidencePath',$snapshot,'-InputPath',$draftPath)
    Assert-Check ($noConsent.reason_code -eq 'CODE_VALIDATE_SOURCE_NOT_READY' -and -not $noConsent.data.validated) 'Missing re-authorization was ignored.'
    [System.IO.File]::AppendAllText((Join-Path $repo '新笔记.txt'), "extra drift`n")
    $drift = Run-CES -Action CodeValidate -Repo $repo -Exit 2 -More $selectors
    Assert-Check ($drift.reason_code -eq 'CODE_VALIDATE_SOURCE_NOT_READY' -and -not $drift.data.validated) 'Untracked edit should cause a source gate failure.'
    [System.IO.File]::WriteAllText((Join-Path $repo '新笔记.txt'), "original note marker`n")

    # DeliveredTarget: one pinned commit range and changes layer only.
    [void](Git-Fix -ArgsList @('-C',$repo,'add','worker.ps1','other.ps1','新笔记.txt'))
    [void](Git-Fix -ArgsList @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','target'))
    $target = Git-Fix -ArgsList @('-C',$repo,'rev-parse','HEAD')
    Save-Snapshot -Repo $repo -Path $snapshot -Flags @('-Mode','DeliveredTarget','-BaseSha',$base,'-TargetSha',$target,'-TargetRef','refs/heads/main','-IncludePatches')
    $deliveryScope = @('-Mode','Snapshot','-EvidencePath',$snapshot,'-IncludePatches')
    $packet = Run-CES -Action CodePrepare -Repo $repo -Exit 0 -More $deliveryScope
    $draft.packet_sha256 = $packet.data.packet_sha256
    $draft.saved_collect_sha256 = $packet.data.preparation.saved_collect_sha256
    $draft.findings = @([ordered]@{
        id = 'DELIVERY-1'; title = 'Check pinned commit change'; severity = 'info'; confidence = 'low'
        layer = 'changes'; path = 'worker.ps1'; evidence_quote = '+staged alpha marker'
        reasoning = 'This line is present in the pinned local commit range.'
        impact = 'It might influence downstream behavior after integration.'
        recommendation = 'Review usage context and verify with tests.'
    })
    Write-Draft -Path $draftPath -Draft $draft
    $deliveryChecked = Run-CES -Action CodeValidate -Repo $repo -Exit 0 -More (@('-InputPath',$draftPath) + $deliveryScope)
    Assert-Check ($deliveryChecked.data.source_mode -eq 'delivered_target_diff') 'Pinned target source identity was lost.'
    Assert-Check ($deliveryChecked.data.finding_count -eq 1) 'Pinned commit finding not checked.'
    $wrongMode = Run-CES -Action CodeValidate -Repo $repo -Exit 4 -More @('-Mode','WorkingTree','-EvidencePath',$snapshot,'-InputPath',$draftPath)
    Assert-Check ($wrongMode.reason_code -eq 'SNAPSHOT_MODE_REQUIRED') 'CodeValidate allowed source-mode override.'
    Write-Output "PASS: EC-007 CodeValidate smoke ($script:checks assertions)"
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

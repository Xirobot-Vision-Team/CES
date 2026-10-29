#requires -Version 7.0
<#
    EC-011 opt-in scratch fixture for CodeShow Compare. Builds one truly
    CodeSaved record, then derived self-hashed historical record fixtures to
    exercise grouping/multiplicity, source-mode mismatch and corruption.
    Derived fixtures are NOT claims of real source provenance. Nothing touches
    an actual business repository. Execute on an approved PowerShell 7+Git host.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI unavailable.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check { param([bool]$Ok, [string]$Why)
    if (-not $Ok) { throw $Why }
    $script:checks++
}
function Git-Fixture { param([string[]]$Argv)
    $out = @(& git @Argv 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Git fixture failed: $($Argv -join ' '): $out" }
    return ($out -join "`n").Trim()
}
function Run-CES { param([string]$Action, [string]$Repo, [int]$ExpectedExit, [string[]]$More = @())
    $out = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Wrong $Action exit ($LASTEXITCODE vs $ExpectedExit): $out"
    Check ($out.Count -eq 1) 'Expected one CES JSON envelope.'
    $answer = $out[0] | ConvertFrom-Json -Depth 32
    Check ($answer.product_version -eq '1.0.0' -and $answer.build -eq '1.0.0') 'Wrong CES build.'
    Check ($answer.next_step -eq 'none') 'Nonexistent handoff advertised.'
    Check ($answer.read_only -eq ($Action -ne 'CodeSave')) 'Wrong read-only flag.'
    return $answer
}
function Clone-Record { param([System.Collections.IDictionary]$Record)
    return ($Record | ConvertTo-Json -Depth 32 -Compress | ConvertFrom-Json -AsHashtable -Depth 32)
}
function Store-Record { param([System.Collections.IDictionary]$Record, [string]$Folder)
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 32 -Compress))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $id = 'ci-' + $hash
    [System.IO.File]::WriteAllBytes((Join-Path $Folder ($id + '.json')), $bytes)
    return $id
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces compare ec011 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '项目 with spaces'
$collectFile = Join-Path $fixture 'saved-collect.json'
$draftFile = Join-Path $fixture 'review-draft.json'
$missingId = 'ci-' + ('f' * 64)
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void](Git-Fixture -Argv @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'base.txt'), 'baseline')
    [void](Git-Fixture -Argv @('-C',$repo,'add','base.txt'))
    [void](Git-Fixture -Argv @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','baseline'))
    $headBefore = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    $indexPath = Git-Fixture -Argv @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($indexPath)) { $indexPath = Join-Path $repo $indexPath }
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId',$missingId,'-RightRecordId',$missingId)
    Check ($empty.reason_code -eq 'CODE_SHOW_NOT_FOUND') 'Absent store falsely produced a comparison.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Compare created a store.'
    $missingArgument = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId',$missingId)
    Check ($missingArgument.reason_code -eq 'CODE_SHOW_COMPARE_IDS_REQUIRED') 'Missing right record was accepted.'
    $badId = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId','../owner.json','-RightRecordId',$missingId)
    Check ($badId.reason_code -eq 'CODE_SHOW_INVALID_RECORD_ID') 'Path-like record ID was accepted.'
    $wrongSelector = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId',$missingId,'-RightRecordId',$missingId,'-Limit','50')
    Check ($wrongSelector.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Compare accepted an explicit List limit.'
    $wrongFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId',$missingId,'-RightRecordId',$missingId,'-FindingSeverity','high')
    Check ($wrongFilter.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Compare accepted Findings filter.'
    $wrongList = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','List','-LeftRecordId',$missingId)
    Check ($wrongList.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'List accepted Compare selector.'
    $wrongAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-LeftRecordId',$missingId)
    Check ($wrongAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Inspect accepted Compare selector.'

    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'), "historical quote anchor here`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($collectFile, ($collected | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Could not prepare real evidence fixture.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Comparison seed overview.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Original local note'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'historical quote anchor here'
            reasoning = 'This original untracked note is not attached to a committed revision.'
            impact = 'A checkout reset may remove a loose local note.'
            recommendation = 'Review whether the note belongs in the repository.'
        })
        limitations = @('A historical local working-tree snapshot.')
    }
    [System.IO.File]::WriteAllText($draftFile, ($draft | ConvertTo-Json -Depth 32 -Compress), [System.Text.UTF8Encoding]::new($false))
    $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
    Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'Real checked seed record save failed.'
    $store = Join-Path $repo '.codex/ces/code-insights'
    $seed = Get-Content -LiteralPath (Join-Path $store ($saved.data.record_id + '.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32
    Check ($seed.finding_count -eq 1) 'Unexpected seed record shape.'

    # Multiple distinct findings can cite the SAME exact quotation anchor.
    # Two other anchors appear on only one side each. These synthetic records
    # test historical grouping only, not authenticity or issue resolution.
    $left = Clone-Record -Record $seed
    $onLeftA = Clone-Record -Record $seed
    $onLeftA = $onLeftA.checked_findings[0]
    $onLeftA.id = 'A2'; $onLeftA.title = 'Second interpretation'; $onLeftA.severity = 'high'
    $leftNew = Clone-Record -Record $seed
    $leftNew = $leftNew.checked_findings[0]
    $leftNew.id = 'B1'; $leftNew.title = 'Left only evidence'; $leftNew.path = 'local/a|b Ω.txt'
    $leftNew.quote_sha256 = ('a' * 64)
    $left.checked_findings = @($left.checked_findings[0], $onLeftA, $leftNew)
    $left.finding_count = 3; $left.summary = 'Left-side saved observations.'
    $leftId = Store-Record -Record $left -Folder $store

    $right = Clone-Record -Record $seed
    $right.checked_findings[0].id = 'Z1'
    $right.checked_findings[0].title = 'Changed model interpretation'
    $right.checked_findings[0].severity = 'critical'
    $rightNew = Clone-Record -Record $seed
    $rightNew = $rightNew.checked_findings[0]
    $rightNew.id = 'C1'; $rightNew.title = 'Right only evidence'; $rightNew.path = 'local/a|b Ω.txt'
    $rightNew.quote_sha256 = ('b' * 64)
    $right.checked_findings = @($rightNew, $right.checked_findings[0])
    $right.finding_count = 2; $right.summary = 'Right-side saved observations.'
    $rightId = Store-Record -Record $right -Folder $store

    $compared = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$rightId)
    Check ($compared.reason_code -eq 'CODE_SHOW_OK' -and $compared.data.comparable) 'Valid historical comparison failed.'
    Check ($compared.data.counts.shared_anchor_count -eq 1 -and $compared.data.counts.left_only_anchor_count -eq 1 -and $compared.data.counts.right_only_anchor_count -eq 1) 'Quote-anchor groups were misclassified.'
    Check ($compared.data.counts.shared_anchor_left_finding_count -eq 2 -and $compared.data.counts.shared_anchor_right_finding_count -eq 1) 'Same-anchor multiplicity was lost.'
    Check ($compared.data.shared_anchors[0].left_findings[0].id -ceq 'A2' -and $compared.data.shared_anchors[0].left_findings[1].id -ceq 'F1') 'Finding IDs were not sorted ordinally.'
    Check ($compared.data.shared_anchors[0].right_findings[0].severity -eq 'critical') 'Changed saved interpretation was lost.'
    Check ($compared.data.left_only_anchors[0].anchor.path -ceq 'local/a|b Ω.txt' -and $compared.data.right_only_anchors[0].anchor.quote_sha256 -ceq ('b' * 64)) 'Literal path or differing hashes were confused.'
    Check ($compared.data.left_record.finding_count -eq 3 -and $compared.data.right_record.finding_count -eq 2) 'Record metadata was not preserved.'
    Check (-not ($compared | ConvertTo-Json -Depth 32).Contains('historical quote anchor here')) 'Original source quotation leaked.'
    Check (-not $compared.data.source_revalidated -and -not $compared.data.finding_semantics_verified -and -not $compared.data.claimed_lines_verified) 'Compare asserted nonexistent provenance.'
    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode Compare -RepoPath $repo -LeftRecordId $leftId -RightRecordId $rightId)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('Shared quote anchors: 1')) 'Human-readable Compare output missing.'

    $reversed = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Compare','-LeftRecordId',$rightId,'-RightRecordId',$leftId)
    Check ($reversed.data.counts.shared_anchor_count -eq 1 -and $reversed.data.left_record.record_id -eq $rightId) 'Left/right argument reversal failed.'
    $self = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$leftId)
    Check ($self.data.counts.shared_anchor_count -eq 2 -and $self.data.counts.left_only_anchor_count -eq 0 -and $self.data.counts.right_only_anchor_count -eq 0) 'Self comparison should preserve all anchors.'
    $notFound = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$missingId)
    Check ($notFound.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $notFound.data) 'Missing side was misreported as successful.'

    $other = Clone-Record -Record $seed
    $other.source_mode = 'delivered_target_diff'
    $other.checked_findings[0].layer = 'changes'
    $other.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $other.summary = 'Different historical source mode.'
    $otherId = Store-Record -Record $other -Folder $store
    $mismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$otherId)
    Check ($mismatch.reason_code -eq 'CODE_SHOW_COMPARE_SCOPE_MISMATCH' -and -not $mismatch.data.comparable -and $null -eq $mismatch.data.counts) 'Mixed modes fabricated missing or shared anchors.'

    $recordPath = Join-Path $store ($leftId + '.json')
    $original = [System.IO.File]::ReadAllBytes($recordPath)
    try {
        [System.IO.File]::AppendAllText($recordPath,'tampered')
        $tampered = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$rightId)
        Check ($tampered.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $tampered.data) 'Tampered selected record was emitted as valid comparison.'
    } finally { [System.IO.File]::WriteAllBytes($recordPath,$original) }
    $unexpected = Join-Path $store 'unknown.tmp'
    try {
        [System.IO.File]::WriteAllText($unexpected,'not a CES record')
        $badStore = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Compare','-LeftRecordId',$leftId,'-RightRecordId',$rightId)
        Check ($badStore.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $badStore.data) 'Unrecognized store entry was silently ignored.'
    } finally { [System.IO.File]::Delete($unexpected) }

    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'Compare mutated HEAD.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Compare mutated the index.'
    Write-Output "EC-011 CodeCompare smoke PASS: $script:checks checks in scratch repository."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

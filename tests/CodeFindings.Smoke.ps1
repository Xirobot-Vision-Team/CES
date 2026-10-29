#requires -Version 7.0
<#
    EC-010 optional isolated integration fixture. Creates genuinely CodeSaved
    findings, then derived immutable records only for bounded window testing.
    All writes occur in disposable scratch repositories, not business sources.
    Run manually with pwsh 7+ and Git. No pass is claimed until executed.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI unavailable.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check { param([bool]$Ok, [string]$Reason)
    if (-not $Ok) { throw $Reason }
    $script:checks++
}
function Git-Fixture { param([string[]]$Argv)
    $out = @(& git @Argv 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Fixture Git failed: $($Argv -join ' '): $out" }
    return ($out -join "`n").Trim()
}
function Run-CES { param([string]$Action, [string]$Repo, [int]$ExpectedExit, [string[]]$More = @())
    $out = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Unexpected $Action exit $LASTEXITCODE (expected $ExpectedExit): $out"
    Check ($out.Count -eq 1) 'Expected exactly one JSON object.'
    $response = $out[0] | ConvertFrom-Json -Depth 32
    Check ($response.product_version -eq '1.0.0' -and $response.build -eq '1.0.0') 'Build tag mismatch.'
    Check ($response.next_step -eq 'none') 'Unexpected AI handoff.'
    Check ($response.read_only -eq ($Action -ne 'CodeSave')) 'Incorrect read-only action flag.'
    return $response
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces findings ec010 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '项目 with spaces'
$snapshotFile = Join-Path $fixture 'collect.json'
$draftFile = Join-Path $fixture 'draft.json'
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void](Git-Fixture -Argv @('init','-q','-b','main',$repo))
    [System.IO.File]::WriteAllText((Join-Path $repo 'base.txt'), 'base')
    [void](Git-Fixture -Argv @('-C',$repo,'add','base.txt'))
    [void](Git-Fixture -Argv @('-C',$repo,'-c','user.name=CES Fixture','-c','user.email=fixture@example.invalid','commit','-qm','base'))
    $headBefore = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    $indexPath = Git-Fixture -Argv @('-C',$repo,'rev-parse','--git-path','index')
    if (-not [System.IO.Path]::IsPathRooted($indexPath)) { $indexPath = Join-Path $repo $indexPath }
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings')
    Check ($empty.reason_code -eq 'CODE_SHOW_EMPTY' -and $empty.data.returned_count -eq 0) 'Absent store was not a clean empty Finding view.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Findings created CES state.'
    $emptySelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','Findings','-FindingsRecordIds',(('ci-' + ('a' * 64)) + ',' + ('ci-' + ('b' * 64))))
    Check ($emptySelected.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and
        $null -eq $emptySelected.data -and
        -not (Test-Path -LiteralPath (Join-Path $repo '.codex/ces'))) 'Selected Findings created store or accepted missing records.'
    $badModeSelector = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','List','-FindingSeverity','high')
    Check ($badModeSelector.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'List accepted Finding-only filter.'
    $badAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-FindingPath','a')
    Check ($badAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Inspect silently accepted Finding filter.'
    $badRecord = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-RecordId',('ci-' + ('a' * 64)))
    Check ($badRecord.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Findings accepted Detail selector.'
    $badCursor = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-AfterFindingCursor','../owner.json')
    Check ($badCursor.reason_code -eq 'CODE_SHOW_INVALID_FINDING_CURSOR') 'Findings accepted a traversal-like cursor.'
    $badSeverity = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-FindingSeverity','HIGH')
    Check ($badSeverity.reason_code -eq 'CODE_SHOW_FINDING_FILTER_INVALID') 'Filter enum accepted wrong casing.'
    $emptyFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-FindingPath','')
    Check ($emptyFilter.reason_code -eq 'CODE_SHOW_FINDING_FILTER_INVALID') 'Explicit empty Finding path was silently ignored.'
    $badLimit = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-Limit','101')
    Check ($badLimit.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Findings accepted unbounded page size.'

    # Persist two real checked findings through Collect -> Prepare -> CodeSave.
    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'), "unique CES finding anchor text`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($snapshotFile, ($collected | ConvertTo-Json -Compress -Depth 32), [System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$snapshotFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Could not prepare real test CodeInsight.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Initial Finding overview.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Track loose note'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'unique CES finding anchor text'
            reasoning = 'The loose note exists only as an untracked local file.'
            impact = 'Removing the checkout may lose that local note.'
            recommendation = 'Decide whether the loose note should be committed.'
        })
        limitations = @('Not an immutable source snapshot.')
    }
    $savedIds = [System.Collections.Generic.List[string]]::new()
    foreach ($summary in @('Initial Finding overview.','Second Finding overview.')) {
        $draft.summary = $summary
        [System.IO.File]::WriteAllText($draftFile, ($draft | ConvertTo-Json -Compress -Depth 32), [System.Text.UTF8Encoding]::new($false))
        $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$snapshotFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
        Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'CodeSave did not create valid source test record.'
        $savedIds.Add([string]$saved.data.record_id)
    }
    $page = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-Limit','1','-FindingSeverity','info','-FindingLayer','untracked','-FindingPath','file Ω.txt','-FindingSourceMode','working_tree_diff')
    Check ($page.reason_code -eq 'CODE_SHOW_OK' -and $page.data.returned_count -eq 1) 'Filtered first Finding page incorrect.'
    Check ($page.data.findings[0].finding.id -eq 'F1' -and $page.data.findings[0].finding.path -ceq 'file Ω.txt') 'Literal case-sensitive Unicode path was not preserved.'
    Check ($page.data.has_more_candidates -and $page.data.next_after_finding_cursor -match '^fc1-') 'First Finding cursor missing.'
    Check ($page.data.scanned_record_count -eq 1 -and $page.data.record_count -eq 2) 'Finding page incorrectly scanned unseen records.'
    Check (-not ($page | ConvertTo-Json -Depth 32).Contains('evidence_quote')) 'Finding view leaked raw evidence quotation.'
    $next = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-Limit','1','-FindingSeverity','info','-FindingLayer','untracked','-FindingPath','file Ω.txt','-FindingSourceMode','working_tree_diff','-AfterFindingCursor',$page.data.next_after_finding_cursor)
    Check ($next.data.returned_count -eq 1 -and $next.data.findings[0].record_id -ne $page.data.findings[0].record_id) 'Next Finding cursor repeated the first row.'
    $boundMismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Findings','-FindingSeverity','low','-FindingLayer','untracked','-FindingPath','file Ω.txt','-FindingSourceMode','working_tree_diff','-AfterFindingCursor',$page.data.next_after_finding_cursor)
    Check ($boundMismatch.reason_code -eq 'CODE_SHOW_FINDING_CURSOR_MISMATCH') 'Cursor allowed changed filter semantics.'
    $end = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-Limit','1','-FindingSeverity','info','-FindingLayer','untracked','-FindingPath','file Ω.txt','-FindingSourceMode','working_tree_diff','-AfterFindingCursor',$next.data.next_after_finding_cursor)
    Check ($end.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $end.data.returned_count -eq 0 -and -not $end.data.has_more_candidates) 'Past-the-end cursor was not a clean empty scan.'
    $byPathWrongCase = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-FindingPath','FILE Ω.txt')
    Check ($byPathWrongCase.reason_code -eq 'CODE_SHOW_NO_MATCHES') 'FindingPath was not literal and case-sensitive.'
    $wrongMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-FindingSourceMode','delivered_target_diff')
    Check ($wrongMode.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $wrongMode.data.returned_count -eq 0) 'Source mode filter was ignored.'

    # Derive additional *valid self-hashed* records from a real saved v1
    # record only to test the fixed scan window without dozens of CodeSave
    # repetitions. These are NOT evidence of authenticated authorship.
    $recordsDir = Join-Path $repo '.codex/ces/code-insights'
    $seed = Get-Content -LiteralPath (Join-Path $recordsDir ($savedIds[0] + '.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32
    $originalFindings = @($seed.checked_findings)
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        for ($i = 0; $i -lt 34; $i++) {
            $seed.summary = ('Bounded scan fixture ' + $i)
            if ($i -eq 0) { $seed.checked_findings = @(); $seed.finding_count = 0 }
            else { $seed.checked_findings = $originalFindings; $seed.finding_count = 1 }
            $bytes = $utf8.GetBytes(($seed | ConvertTo-Json -Compress -Depth 32))
            $id = 'ci-' + ([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant())
            [System.IO.File]::WriteAllBytes((Join-Path $recordsDir ($id + '.json')), $bytes)
        }
    } finally { $sha.Dispose() }
    $window = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-FindingSeverity','critical')
    Check ($window.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $window.data.returned_count -eq 0) 'No-match window should not fabricate a finding.'
    Check ($window.data.scanned_record_count -eq 32 -and $window.data.scan_window_exhausted -and $window.data.has_more_candidates) 'Window failed to stop at exactly 32 checked records.'
    Check ($window.data.record_count -eq 36 -and $window.data.next_after_finding_cursor -match '-~$') 'Filtered window continuation must advance after whole record.'
    $tail = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Findings','-FindingSeverity','critical','-AfterFindingCursor',$window.data.next_after_finding_cursor)
    Check ($tail.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $tail.data.scanned_record_count -eq 4 -and -not $tail.data.has_more_candidates) 'No-match traversal failed to finish remaining record window.'
    Check ($null -eq $tail.data.next_after_finding_cursor) 'Finished scan returned an invalid next cursor.'

    # A deliberately removed cursor record cannot silently skip changed state.
    $recordToRemove = $window.data.next_after_finding_cursor -replace '^fc1-[0-9a-f]{64}-(ci-[0-9a-f]{64})-~$', '$1'
    $removePath = Join-Path $recordsDir ($recordToRemove + '.json')
    $backup = [System.IO.File]::ReadAllBytes($removePath)
    try {
        [System.IO.File]::Delete($removePath)
        $stale = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Findings','-FindingSeverity','critical','-AfterFindingCursor',$window.data.next_after_finding_cursor)
        Check ($stale.reason_code -eq 'CODE_SHOW_CURSOR_STALE' -and $null -eq $stale.data) 'Removed record was silently skipped.'
    } finally {
        [System.IO.File]::WriteAllBytes($removePath, $backup)
    }

    # One derived valid record with deliberately unsorted Finding IDs tests
    # precise in-record continuation, even when a 32-record window is crossed.
    $multi = Get-Content -LiteralPath (Join-Path $recordsDir ($savedIds[0] + '.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32
    $fA = ($multi.checked_findings[0] | ConvertTo-Json -Compress -Depth 32) | ConvertFrom-Json -AsHashtable -Depth 32
    $fB = ($multi.checked_findings[0] | ConvertTo-Json -Compress -Depth 32) | ConvertFrom-Json -AsHashtable -Depth 32
    $fC = ($multi.checked_findings[0] | ConvertTo-Json -Compress -Depth 32) | ConvertFrom-Json -AsHashtable -Depth 32
    $fA.id = 'A'; $fA.severity = 'critical'
    $fB.id = 'B'; $fB.severity = 'critical'
    $fC.id = 'C'; $fC.severity = 'critical'
    $multi.checked_findings = @($fC,$fA,$fB)
    $multi.finding_count = 3
    $multi.summary = 'Multiple Finding IDs within one source record.'
    $multiBytes = $utf8.GetBytes(($multi | ConvertTo-Json -Compress -Depth 32))
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $multiId = 'ci-' + ([BitConverter]::ToString($hash.ComputeHash($multiBytes)).Replace('-','').ToLowerInvariant())
    } finally { $hash.Dispose() }
    [System.IO.File]::WriteAllBytes((Join-Path $recordsDir ($multiId + '.json')), $multiBytes)
    $idsSeen = [System.Collections.Generic.List[string]]::new()
    $cursor = $null
    for ($iteration = 0; $iteration -lt 12; $iteration++) {
        $args = @('-Mode','Findings','-FindingSeverity','critical','-Limit','1')
        if ($null -ne $cursor) { $args += @('-AfterFindingCursor',$cursor) }
        $p = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More $args
        foreach ($hit in $p.data.findings) {
            Check ($hit.record_id -eq $multiId) 'Filter leaked a Finding from an unexpected record.'
            $idsSeen.Add([string]$hit.finding.id)
        }
        if (-not $p.data.has_more_candidates) { break }
        $cursor = $p.data.next_after_finding_cursor
        Check (-not [string]::IsNullOrEmpty($cursor)) 'Pagination advertised continuation without a token.'
    }
    Check (($idsSeen -join ',') -ceq 'A,B,C') 'Within-record Finding order or precise continuation failed.'

    # EC-020: exact selected-record Findings over arbitrary SHA scan pages.
    # All chosen records are validated, even when -Limit hides extra rows,
    # while unselected record bodies are intentionally NOT consulted.
    $allFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($recordFile in [System.IO.Directory]::EnumerateFiles($recordsDir)) {
        $allFiles.Add([System.IO.Path]::GetFileNameWithoutExtension($recordFile))
    }
    $allFiles.Sort([System.StringComparer]::Ordinal)
    Check ($allFiles.Count -eq 37) 'Cross-page fixture inventory unexpected.'
    $leftEdge = $allFiles[0]
    $rightEdge = $allFiles[$allFiles.Count - 1]
    $crossSelection = "$rightEdge,$leftEdge"
    $expectedMatches = 0
    foreach ($id in @($leftEdge,$rightEdge)) {
        $r = [System.IO.File]::ReadAllText((Join-Path $recordsDir ($id + '.json'))) |
            ConvertFrom-Json -AsHashtable -Depth 32
        $expectedMatches += @($r.checked_findings).Count
    }
    Check ($expectedMatches -ge 1) 'Selected fixture endpoints unexpectedly have no Findings.'
    $cross = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
        '-Mode','Findings','-FindingsRecordIds',$crossSelection,'-Limit','1')
    Check ($cross.reason_code -eq 'CODE_SHOW_OK' -and $cross.data.record_count -eq 37 -and
        $cross.data.scanned_record_count -eq 2 -and $cross.data.selected_record_count -eq 2) 'Explicit cross-page record scan incorrect.'
    Check ($cross.data.selection_scope -eq 'selected_record_ids' -and
        $cross.data.counts_scope -eq 'only_the_explicitly_selected_records_not_the_whole_store' -and
        $cross.data.selected_record_ids[0] -ceq $leftEdge -and
        $cross.data.selected_record_ids[1] -ceq $rightEdge) 'Selected ID order/scope incorrect.'
    Check ($cross.data.matched_finding_count -eq $expectedMatches -and
        $cross.data.scanned_finding_count -eq $expectedMatches -and
        $cross.data.omitted_matching_count -eq ($expectedMatches - 1) -and
        $cross.data.returned_count -eq 1 -and
        $cross.data.results_truncated -eq ($expectedMatches -gt 1)) 'Selected match/limit/omission counts incorrect.'
    Check (-not $cross.data.has_more_candidates -and $null -eq $cross.data.next_after_finding_cursor -and
        $null -eq $cross.data.after_finding_cursor -and $null -eq $cross.data.scan_window_records) 'Selected scope advertised a fictitious next page.'
    Check (-not (($cross | ConvertTo-Json -Depth 32).Contains('evidence_quote'))) 'Selected Findings leaked source quotation.'

    $multiSelection = "$multiId,$($savedIds[0])"
    $multiSearch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
        '-Mode','Findings','-FindingsRecordIds',$multiSelection,'-FindingSeverity','critical','-Limit','1')
    Check ($multiSearch.data.matched_finding_count -eq 3 -and
        $multiSearch.data.omitted_matching_count -eq 2 -and
        $multiSearch.data.scanned_record_count -eq 2 -and
        $multiSearch.data.scanned_finding_count -eq 4 -and
        $multiSearch.data.findings[0].record_id -ceq $multiId -and
        $multiSearch.data.findings[0].finding.id -ceq 'A') 'Selected multi-Finding filtering, sort or omission failed.'
    $exclude = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
        '-Mode','Findings','-FindingsRecordIds',$crossSelection,'-FindingSourceMode','delivered_target_diff')
    Check ($exclude.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and
        $exclude.data.scanned_record_count -eq 2 -and $exclude.data.matched_finding_count -eq 0) 'Excluded selected modes did not receive checked zero result.'

    $sample24 = ($allFiles.GetRange(0,24).ToArray() -join ',')
    $cap = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
        '-Mode','Findings','-FindingsRecordIds',$sample24,'-Limit','1')
    Check ($cap.data.selected_record_count -eq 24 -and $cap.data.scanned_record_count -eq 24 -and
        $cap.data.returned_count -eq 1 -and $cap.data.results_truncated) '24-record selection stopped checking at the output cap.'
    $tooMany = ($allFiles.GetRange(0,25).ToArray() -join ',')
    foreach ($badSelection in @(
        $leftEdge, "$leftEdge,$leftEdge", "$leftEdge, $rightEdge",
        "$leftEdge,,${rightEdge}", "$($leftEdge.ToUpperInvariant()),$rightEdge", $tooMany, ',')) {
        $invalidSet = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
            '-Mode','Findings','-FindingsRecordIds',$badSelection)
        Check ($invalidSet.reason_code -eq 'CODE_SHOW_FINDINGS_RECORD_IDS_INVALID' -and
            $null -eq $invalidSet.data) 'Malformed FindingsRecordIds accepted.'
    }
    $badCursorPair = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','Findings','-FindingsRecordIds',$crossSelection,'-AfterFindingCursor','')
    Check ($badCursorPair.reason_code -eq 'CODE_SHOW_FINDINGS_SELECTION_CONFLICT' -and
        $null -eq $badCursorPair.data) 'Selected Findings accepted even an empty explicit cursor.'
    $badOtherMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','List','-FindingsRecordIds',$crossSelection)
    Check ($badOtherMode.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Wrong mode accepted selected Findings IDs.'
    $badOtherAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @(
        '-FindingsRecordIds',$crossSelection)
    Check ($badOtherAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Wrong action accepted selected Findings IDs.'

    $missing = 'ci-' + ('f' * 64)
    Check (-not ($allFiles -ccontains $missing)) 'Fixture accidentally used the reserved missing ID.'
    $missingPair = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','Findings','-FindingsRecordIds',"$leftEdge,$missing")
    Check ($missingPair.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and
        $null -eq $missingPair.data) 'Missing selected record was silently ignored.'

    $corruptChosenPath = Join-Path $recordsDir ($leftEdge + '.json')
    $savedChosenBytes = [System.IO.File]::ReadAllBytes($corruptChosenPath)
    try {
        [System.IO.File]::AppendAllText($corruptChosenPath, 'changed after saving')
        $badSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @(
            '-Mode','Findings','-FindingsRecordIds',$crossSelection,'-Limit','1')
        Check ($badSelected.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and
            $null -eq $badSelected.data) 'Corrupt selected body returned partial matched rows.'
        $membershipFirst = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
            '-Mode','Findings','-FindingsRecordIds',"$leftEdge,$missing")
        Check ($membershipFirst.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and
            $null -eq $membershipFirst.data) 'Selected body was read before confirming all requested IDs.'
    } finally {
        [System.IO.File]::WriteAllBytes($corruptChosenPath, $savedChosenBytes)
    }
    # Even if the first selected ID already fills the returned-row cap,
    # corruption of a later selected record must still discard all data.
    $lateId = if ([string]::Compare($savedIds[0],$savedIds[1], [System.StringComparison]::Ordinal) -gt 0) {
        $savedIds[0]
    } else { $savedIds[1] }
    $latePath = Join-Path $recordsDir ($lateId + '.json')
    $savedLateBytes = [System.IO.File]::ReadAllBytes($latePath)
    try {
        [System.IO.File]::AppendAllText($latePath, 'invalid late selected bytes')
        $lateInvalid = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @(
            '-Mode','Findings','-FindingsRecordIds',"$($savedIds[0]),$($savedIds[1])",'-Limit','1')
        Check ($lateInvalid.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and
            $null -eq $lateInvalid.data) 'Selection skipped validating a record after filling Limit.'
    } finally {
        [System.IO.File]::WriteAllBytes($latePath, $savedLateBytes)
    }

    $unselectedId = $allFiles[1]
    Check ($unselectedId -cne $leftEdge -and $unselectedId -cne $rightEdge) 'Unselected fixture ID collision.'
    $unselectedPath = Join-Path $recordsDir ($unselectedId + '.json')
    $savedUnselectedBytes = [System.IO.File]::ReadAllBytes($unselectedPath)
    try {
        [System.IO.File]::AppendAllText($unselectedPath, 'do not read this body')
        $notRead = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
            '-Mode','Findings','-FindingsRecordIds',$crossSelection,'-Limit','1')
        Check ($notRead.data.matched_finding_count -eq $expectedMatches) 'Selected Findings consulted an unselected record body.'
    } finally {
        [System.IO.File]::WriteAllBytes($unselectedPath, $savedUnselectedBytes)
    }

    # Corruption of a record in the actual scan window fails with no rows.
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($f in [System.IO.Directory]::EnumerateFiles($recordsDir)) { $names.Add([System.IO.Path]::GetFileName($f)) }
    $names.Sort([System.StringComparer]::Ordinal)
    $firstRecordPath = Join-Path $recordsDir $names[0]
    $beforeCorruption = [System.IO.File]::ReadAllBytes($firstRecordPath)
    try {
        [System.IO.File]::AppendAllText($firstRecordPath, 'unexpected bytes')
        $invalid = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Findings','-FindingSeverity','critical')
        Check ($invalid.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $invalid.data) 'Corrupt scanned record was emitted as verified data.'
    } finally {
        [System.IO.File]::WriteAllBytes($firstRecordPath, $beforeCorruption)
    }

    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode Findings -RepoPath $repo -FindingSeverity critical)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('Findings returned:')) 'Non-JSON Findings output failed.'
    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'Finding reads modified HEAD.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Finding reads modified index.'
    Write-Output "EC-020 CodeFindings smoke PASS: $script:checks checks in isolated scratch repositories."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

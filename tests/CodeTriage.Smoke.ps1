#requires -Version 7.0
<#
    EC-014/EC-017 optional scratch fixture. ONE real CodeSave seed and synthetic
    content-addressed saved records check file-level Triage semantics.
    Synthetic reports are NOT findings of actual defects. Requires pwsh 7/Git.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cli = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ces.ps1'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'CES CLI unavailable.' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Git unavailable.' }
$script:checks = 0
function Check { param([bool]$Ok,[string]$Why)
    if (-not $Ok) { throw $Why }
    $script:checks++
}
function Git-Fixture { param([string[]]$Argv)
    $output = @(& git @Argv 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Git fixture failed: $($Argv -join ' '): $output" }
    return ($output -join "`n").Trim()
}
function Run-CES { param([string]$Action,[string]$Repo,[int]$ExpectedExit,[string[]]$More=@())
    $output = @(& pwsh -NoProfile -File $cli -Action $Action -RepoPath $Repo -Json @More)
    Check ($LASTEXITCODE -eq $ExpectedExit) "Wrong $Action exit ($LASTEXITCODE vs $ExpectedExit): $output"
    Check ($output.Count -eq 1) 'Expected one CES JSON envelope.'
    $result = $output[0] | ConvertFrom-Json -Depth 32
    Check ($result.product_version -eq '1.0.0' -and $result.build -eq '1.0.0') 'Wrong build.'
    Check ($result.next_step -eq 'none') 'Unexpected staged handoff.'
    Check ($result.read_only -eq ($Action -ne 'CodeSave')) 'Unexpected writer.'
    return $result
}
function Clone-Record { param([System.Collections.IDictionary]$Record)
    return ($Record | ConvertTo-Json -Depth 32 -Compress | ConvertFrom-Json -AsHashtable -Depth 32)
}
function Store-Record { param([System.Collections.IDictionary]$Record,[string]$Folder)
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 32 -Compress))
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = [System.BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
    finally { $hasher.Dispose() }
    $id = 'ci-' + $hash
    [System.IO.File]::WriteAllBytes((Join-Path $Folder ($id + '.json')),$bytes)
    return $id
}
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces triage ec017 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '临时 repo with spaces'
$collectFile = Join-Path $fixture 'collect.json'
$draftFile = Join-Path $fixture 'draft.json'
$missingId = 'ci-' + ('f' * 64)
try {
    [void][System.IO.Directory]::CreateDirectory($repo)
    [void](Git-Fixture -Argv @('init',$repo))
    [void](Git-Fixture -Argv @('-C',$repo,'config','user.name','CES Fixture'))
    [void](Git-Fixture -Argv @('-C',$repo,'config','user.email','fixture@example.invalid'))
    [System.IO.File]::WriteAllText((Join-Path $repo 'tracked.txt'),"baseline`n")
    [void](Git-Fixture -Argv @('-C',$repo,'add','tracked.txt'))
    [void](Git-Fixture -Argv @('-C',$repo,'commit','-m','initial'))
    $headBefore = Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')
    $indexPath = Join-Path $repo '.git/index'
    $indexBefore = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage')
    Check ($empty.reason_code -eq 'CODE_SHOW_EMPTY' -and $empty.data.path_group_count -eq 0 -and $empty.data.returned_group_count -eq 0) 'Empty Triage manufactured path groups.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex'))) 'An empty read created CES state.'
    $emptySelection = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageRecordIds',($missingId+','+('ci-'+('e'*64))))
    Check ($emptySelection.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $emptySelection.data -and -not (Test-Path -LiteralPath (Join-Path $repo '.codex'))) 'No-store explicit selection must fail without creating CES state.'
    $badTop = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageTop','0')
    Check ($badTop.reason_code -eq 'CODE_SHOW_TRIAGE_TOP_INVALID') 'Invalid Top=0 accepted.'
    $badTop2 = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageTop','31')
    Check ($badTop2.reason_code -eq 'CODE_SHOW_TRIAGE_TOP_INVALID') 'Invalid Top=31 accepted.'
    $badFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageSourceMode','WORKING_TREE_DIFF')
    Check ($badFilter.reason_code -eq 'CODE_SHOW_TRIAGE_FILTER_INVALID') 'Case-insensitive source-mode filter accepted.'
    $emptyFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageSourceMode','')
    Check ($emptyFilter.reason_code -eq 'CODE_SHOW_TRIAGE_FILTER_INVALID') 'Explicit empty filter accepted.'
    $badCursor = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-AfterTriageCursor','tg1-bad')
    Check ($badCursor.reason_code -eq 'CODE_SHOW_INVALID_TRIAGE_CURSOR') 'Malformed cursor accepted.'
    $emptyCursor = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-AfterTriageCursor','')
    Check ($emptyCursor.reason_code -eq 'CODE_SHOW_INVALID_TRIAGE_CURSOR') 'Explicit empty cursor accepted.'
    $badSelector = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-RecordId',$missingId)
    Check ($badSelector.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Triage accepted Detail RecordId.'
    $otherMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-TriageTop','1')
    Check ($otherMode.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Overview accepted Triage selector.'
    $wrongAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-TriageSourceMode','working_tree_diff')
    Check ($wrongAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Inspect accepted Triage selector.'

    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'),"exact private triage quote`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($collectFile,($collected | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Fixture preparation failed.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Historical Triage fixture seed.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Local note persistence'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'exact private triage quote'
            reasoning = 'Untracked files may be lost through aggressive source cleanup.'
            impact = 'The untracked local data would no longer be present.'
            recommendation = 'Decide whether to preserve the local note in version control.'
        })
        limitations = @('Synthetic fixture, not a real defect review.')
    }
    [System.IO.File]::WriteAllText($draftFile,($draft | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
    Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'Seed persistence failed.'
    $store = Join-Path $repo '.codex/ces/code-insights'
    $seed = Get-Content -LiteralPath (Join-Path $store ($saved.data.record_id+'.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32

    # Multiple statements/one record and the same exact anchor in >1 record.
    $multi = Clone-Record -Record $seed
    $second = Clone-Record -Record $seed
    $second = $second.checked_findings[0]; $second.id = 'A2'; $second.severity = 'high'
    $multi.checked_findings = @($multi.checked_findings[0], $second)
    $multi.finding_count = 2; $multi.summary = 'Synthetic two-statement report.'
    [void](Store-Record -Record $multi -Folder $store)

    $samePath = Clone-Record -Record $seed
    $samePath.checked_findings[0].severity = 'critical'
    $samePath.checked_findings[0].quote_sha256 = ('1' * 64)
    $samePath.summary = 'Synthetic different anchor same path.'
    [void](Store-Record -Record $samePath -Folder $store)

    $case = Clone-Record -Record $seed
    $case.checked_findings[0].path = 'FILE Ω.txt'
    $case.checked_findings[0].severity = 'low'; $case.summary = 'Synthetic case-variant path.'
    [void](Store-Record -Record $case -Folder $store)

    $rename = Clone-Record -Record $seed
    $rename.checked_findings[0].path_endpoint = 'old_path'
    $rename.checked_findings[0].layer = 'staged'
    $rename.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $rename.checked_findings[0].severity = 'medium'; $rename.summary = 'Synthetic tracked old-path rename endpoint.'
    [void](Store-Record -Record $rename -Folder $store)

    $delivered = Clone-Record -Record $seed
    $delivered.source_mode = 'delivered_target_diff'
    $delivered.checked_findings[0].layer = 'changes'
    $delivered.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $delivered.checked_findings[0].severity = 'critical'; $delivered.summary = 'Synthetic delivered target report.'
    [void](Store-Record -Record $delivered -Folder $store)

    $triage = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-Limit','100','-TriageTop','2')
    Check ($triage.reason_code -eq 'CODE_SHOW_OK' -and $triage.data.mode -eq 'Triage') 'Triage failed to dispatch.'
    Check ($triage.data.record_count -eq 6 -and $triage.data.scanned_record_count -eq 6 -and $triage.data.included_record_count -eq 6 -and -not $triage.data.has_more_candidates) 'Triage candidate scan mismatch.'
    Check ($triage.data.finding_statement_count -eq 7 -and $triage.data.path_group_count -eq 4 -and $triage.data.returned_group_count -eq 2 -and $triage.data.omitted_group_count -eq 2) 'Statements/groups/top truncation units mixed.'
    $first = $triage.data.path_groups[0]; $next = $triage.data.path_groups[1]
    Check ($first.path_exact -ceq 'file Ω.txt' -and $first.source_mode -ceq 'working_tree_diff' -and $first.path_endpoint -ceq 'path' -and $first.highest_reported_severity -eq 'critical') 'Ranking or path grouping wrong.'
    Check ($first.reporting_record_count -eq 3 -and $first.finding_statement_count -eq 4 -and $first.distinct_exact_anchor_count -eq 2 -and $first.cross_record_exact_anchor_count -eq 1) 'Distinct records/statements/evidence anchors conflated.'
    Check ($first.severity_statements.info -eq 2 -and $first.severity_statements.high -eq 1 -and $first.severity_statements.critical -eq 1 -and $first.layer_statements.untracked -eq 4) 'Saved severity and layer bins wrong.'
    Check ($next.source_mode -eq 'delivered_target_diff' -and $next.highest_reported_severity -eq 'critical') 'Cross-source-mode grouping or critical ordering wrong.'
    Check ($triage.data.paths_disclosed -and -not $triage.data.original_quote_or_model_prose_disclosed -and -not $triage.data.source_revalidated -and $triage.data.counts_scope -eq 'this_page_only_not_store_wide_or_cumulative') 'False freshness/privacy/scope claim.'
    $payload = $triage | ConvertTo-Json -Depth 32 -Compress
    Check ($payload.Contains('file Ω.txt') -and -not $payload.Contains('exact private triage quote') -and -not $payload.Contains('Local note persistence')) 'Path absent or source quote/model title leaked.'

    $all = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageTop','30')
    Check ($all.data.path_group_count -eq 4 -and $all.data.returned_group_count -eq 4 -and $all.data.omitted_group_count -eq 0) 'Full page path set truncated unexpectedly.'
    Check ($all.data.path_groups[2].path_endpoint -eq 'old_path' -and $all.data.path_groups[2].layer_statements.staged -eq 1 -and $all.data.path_groups[3].path_exact -ceq 'FILE Ω.txt') 'Rename old_path or exact case distinction lost.'
    $working = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageSourceMode','working_tree_diff')
    Check ($working.data.included_record_count -eq 5 -and $working.data.finding_statement_count -eq 6 -and $working.data.path_group_count -eq 3) 'Triage saved source-mode filter incorrect.'
    $unmatched = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-Limit','1','-TriageSourceMode','delivered_target_diff')
    Check ($unmatched.data.scanned_record_count -ge 1 -and $unmatched.data.included_record_count -le 1) 'Triage one-record limit broken.'

    $zero = Clone-Record -Record $seed
    $zero.checked_findings = @(); $zero.finding_count = 0
    $zero.summary = 'Synthetic report containing zero Finding statements.'
    [void](Store-Record -Record $zero -Folder $store)
    $withZero = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageTop','30')
    Check ($withZero.data.record_count -eq 7 -and $withZero.data.included_record_count -eq 7 -and $withZero.data.records_with_findings_count -eq 6 -and $withZero.data.path_group_count -eq 4 -and $withZero.data.finding_statement_count -eq 7) 'Zero-Finding record created a spurious group or statement.'

    # 37 total records span two hard 24-candidate scan windows. Do NOT add
    # per-page groups as if that were unique paths across the entire store.
    for ($i = 0; $i -lt 30; $i++) {
        $report = Clone-Record -Record $seed
        $report.checked_findings[0].path = ('synthetic/{0:D3}.txt' -f $i)
        $report.checked_findings[0].severity = 'info'
        $report.summary = ('Synthetic triage candidate {0:D3}.' -f $i)
        [void](Store-Record -Record $report -Folder $store)
    }
    $cursor = $null; $firstCursor = $null; $pageCount = 0; $totalScanned = 0
    do {
        $args = @('-Mode','Triage','-Limit','100','-TriageTop','5')
        if ($null -ne $cursor) { $args += @('-AfterTriageCursor',$cursor) }
        $page = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More $args
        Check ($page.data.scanned_record_count -le 24 -and $page.data.returned_group_count -le 5 -and $page.data.path_group_count -ge $page.data.returned_group_count) 'Triage unbounded read or returned groups.'
        $totalScanned += $page.data.scanned_record_count; $pageCount++
        $cursor = $page.data.next_after_triage_cursor
        if ($null -eq $firstCursor -and $null -ne $cursor) { $firstCursor = $cursor }
        Check (($null -ne $cursor) -eq $page.data.has_more_candidates -and $pageCount -le 3) 'Pagination did not advance to completion.'
    } while ($null -ne $cursor)
    Check ($pageCount -eq 2 -and $totalScanned -eq 37 -and $null -ne $firstCursor) 'Triage did not cover all fixed candidates in bounded pages.'
    $mismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-Limit','100','-TriageTop','6','-AfterTriageCursor',$firstCursor)
    Check ($mismatch.reason_code -eq 'CODE_SHOW_TRIAGE_CURSOR_MISMATCH' -and $null -eq $mismatch.data) 'Top setting cursor binding failed.'
    $mismatch2 = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-Limit','100','-TriageTop','5','-TriageSourceMode','working_tree_diff','-AfterTriageCursor',$firstCursor)
    Check ($mismatch2.reason_code -eq 'CODE_SHOW_TRIAGE_CURSOR_MISMATCH' -and $null -eq $mismatch2.data) 'Mode filter cursor binding failed.'
    $staleToken = $firstCursor.Substring(0,69) + $missingId
    $stale = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Triage','-Limit','100','-TriageTop','5','-AfterTriageCursor',$staleToken)
    Check ($stale.reason_code -eq 'CODE_SHOW_CURSOR_STALE' -and $null -eq $stale.data) 'Missing cursor record not rejected.'
    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode Triage -RepoPath $repo -TriageTop 2)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('Path groups ranked:')) 'Non-JSON Triage display failed.'

    # EC-017: aggregate one selected bounded set across unrelated SHA pages.
    # 50 same-path reports ensure that the first and last SHA names cannot
    # occupy the same 24-record page, independent of hash distribution.
    $sharedIds = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt 50; $i++) {
        $report = Clone-Record -Record $seed
        $report.checked_findings[0].path = 'review/shared Ω.cs'
        $report.checked_findings[0].severity = if ($i % 2 -eq 0) { 'high' } else { 'critical' }
        $report.summary = ('Synthetic cross-page triage report {0:D3}.' -f $i)
        $sharedIds.Add((Store-Record -Record $report -Folder $store))
    }
    $sharedIds.Sort([System.StringComparer]::Ordinal)
    $lower = $sharedIds[0]; $upper = $sharedIds[$sharedIds.Count - 1]
    $allNames = @([System.IO.Directory]::GetFiles($store) | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) })
    [array]::Sort($allNames, [System.StringComparer]::Ordinal)
    $lowPosition = [array]::IndexOf($allNames,$lower)
    $highPosition = [array]::IndexOf($allNames,$upper)
    Check ($highPosition - $lowPosition -ge 49 -and [math]::Floor($highPosition / 24) -ne [math]::Floor($lowPosition / 24)) 'Synthetic SHA records did not span Triage scan pages.'

    $idsArg = $upper + ',' + $lower
    $explicit = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageRecordIds',$idsArg)
    Check ($explicit.data.selection_scope -eq 'selected_record_ids' -and $explicit.data.counts_scope -eq 'only_the_explicitly_selected_records_not_the_whole_store' -and $explicit.data.selected_record_count -eq 2) 'Explicit selection scope not reported.'
    Check ($explicit.data.scanned_record_count -eq 2 -and $explicit.data.included_record_count -eq 2 -and $explicit.data.record_count -eq $allNames.Count -and $null -eq $explicit.data.limit) 'Selected record counting vs filename inventory incorrect.'
    Check ($explicit.data.selected_record_ids[0] -ceq $lower -and $explicit.data.selected_record_ids[1] -ceq $upper -and $null -eq $explicit.data.next_after_triage_cursor -and -not $explicit.data.has_more_candidates) 'Selected ordering or cursor suppression wrong.'
    Check ($explicit.data.path_group_count -eq 1 -and $explicit.data.path_groups[0].path_exact -ceq 'review/shared Ω.cs' -and $explicit.data.path_groups[0].reporting_record_count -eq 2 -and $explicit.data.path_groups[0].finding_statement_count -eq 2) 'Cross-page same-path merge broken.'
    Check ($explicit.data.path_groups[0].distinct_exact_anchor_count -eq 1 -and $explicit.data.path_groups[0].cross_record_exact_anchor_count -eq 1) 'Two-record anchor recurrence not counted.'
    Check ($explicit.data.path_groups[0].reporting_record_ids[0] -ceq $lower -and $explicit.data.path_groups[0].reporting_record_ids[1] -ceq $upper) 'Contributing record IDs were not preserved in sorted order.'
    $reversed = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageRecordIds',($lower+','+$upper))
    Check (($explicit.data.path_groups | ConvertTo-Json -Depth 32 -Compress) -ceq ($reversed.data.path_groups | ConvertTo-Json -Depth 32 -Compress)) 'Selected aggregation should be independent of input order.'
    $selectedPayload = $explicit | ConvertTo-Json -Depth 32 -Compress
    Check (-not $selectedPayload.Contains('exact private triage quote') -and -not $selectedPayload.Contains('Synthetic cross-page triage report') -and -not $explicit.data.source_revalidated) 'Selected Triage exposed original quotes, model prose or implied source freshness.'

    $filtered = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageRecordIds',($lower+','+$upper+','+$saved.data.record_id),'-TriageSourceMode','delivered_target_diff')
    Check ($filtered.data.scanned_record_count -eq 3 -and $filtered.data.included_record_count -eq 0 -and $filtered.data.path_group_count -eq 0 -and $filtered.reason_code -eq 'CODE_SHOW_NO_MATCHES') 'Selected source-mode filtering/counting mixed inclusion with scanning.'
    $twentyFour = @($sharedIds | Select-Object -First 24) -join ','
    $bounded = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageRecordIds',$twentyFour)
    Check ($bounded.data.scanned_record_count -eq 24 -and $bounded.data.path_groups[0].reporting_record_count -eq 24) 'Full 24-selected-record window not completely read.'

    $badIds = @('', $lower, ($lower+','+$lower),
        ($lower+','+$upper.ToUpperInvariant()), ($lower+', '+$upper),
        (@($sharedIds | Select-Object -First 25) -join ','))
    foreach ($badId in $badIds) {
        $bad = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageRecordIds',$badId)
        Check ($bad.reason_code -eq 'CODE_SHOW_TRIAGE_RECORD_IDS_INVALID' -and $null -eq $bad.data) 'Malformed selected Triage ID set was accepted.'
    }
    $unknown = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageRecordIds',($lower+','+$missingId))
    Check ($unknown.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $unknown.data) 'Missing selected ID must not produce accepted partial aggregation.'
    $limitConflict = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageRecordIds',$idsArg,'-Limit','50')
    Check ($limitConflict.reason_code -eq 'CODE_SHOW_TRIAGE_SELECTION_CONFLICT') 'Explicit default Limit=50 silently bypassed selection conflict.'
    $cursorConflict = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-TriageRecordIds',$idsArg,'-AfterTriageCursor','tg1-bad')
    Check ($cursorConflict.reason_code -eq 'CODE_SHOW_TRIAGE_SELECTION_CONFLICT') 'Cursor and explicit selection were mixed.'
    $leakMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Recurrence','-TriageRecordIds',$idsArg)
    Check ($leakMode.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Triage set was accepted in Recurrence.'
    $leakAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-TriageRecordIds',$idsArg)
    Check ($leakAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Triage set was accepted in Inspect.'

    # Other store members may be corrupted yet must not be read as bodies.
    $unselectedPath = Join-Path $store ($saved.data.record_id + '.json')
    $unselectedBytes = [System.IO.File]::ReadAllBytes($unselectedPath)
    try {
        [System.IO.File]::AppendAllText($unselectedPath,'unselected tamper')
        $unselectedOk = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Triage','-TriageRecordIds',$idsArg)
        Check ($unselectedOk.reason_code -eq 'CODE_SHOW_OK' -and $unselectedOk.data.scanned_record_count -eq 2) 'Selected Triage read a disjoint, unselected corrupt body.'
    } finally { [System.IO.File]::WriteAllBytes($unselectedPath,$unselectedBytes) }

    # A filtered-out selected body must also be fully SHA/schema checked.
    $selectedPath = Join-Path $store ($upper + '.json')
    $savedBytes = [System.IO.File]::ReadAllBytes($selectedPath)
    try {
        [System.IO.File]::AppendAllText($selectedPath,'tamper')
        $selectedCorrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Triage','-TriageRecordIds',$idsArg,'-TriageSourceMode','delivered_target_diff')
        Check ($selectedCorrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $selectedCorrupt.data) 'Filtered-out selected body corruption was overlooked.'
    } finally { [System.IO.File]::WriteAllBytes($selectedPath,$savedBytes) }

    $paths = [System.IO.Directory]::GetFiles($store)
    [array]::Sort($paths, [System.StringComparer]::Ordinal)
    $firstPath = $paths[0]
    $original = [System.IO.File]::ReadAllBytes($firstPath)
    try {
        [System.IO.File]::AppendAllText($firstPath,'corruption')
        $corrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Triage')
        Check ($corrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $corrupt.data) 'Corrupt Triage window returned accepted ranking.'
    } finally { [System.IO.File]::WriteAllBytes($firstPath,$original) }
    $rogue = Join-Path $store 'unexpected.tmp'
    try {
        [System.IO.File]::WriteAllText($rogue,'rogue')
        $invalid = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Triage')
        Check ($invalid.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $invalid.data) 'Unexpected record entry ignored.'
    } finally { [System.IO.File]::Delete($rogue) }
    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'Triage changed Git HEAD.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Triage changed Git index.'
    Write-Output "EC-017 CodeTriage smoke PASS: $script:checks checks in scratch repository."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

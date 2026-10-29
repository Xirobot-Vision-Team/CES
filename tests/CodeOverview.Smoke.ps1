#requires -Version 7.0
<#
    EC-013/EC-018 scratch fixture. ONE real CodeSave seed plus synthetic
    self-hashed local historical reports, not evidence of real past defects.
    Never run in an actual business repository. Requires PowerShell 7 and Git.
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
    Check ($output.Count -eq 1) 'Expected one JSON envelope.'
    $result = $output[0] | ConvertFrom-Json -Depth 32
    Check ($result.product_version -eq '1.0.0' -and $result.build -eq '1.0.0') 'Wrong build.'
    Check ($result.next_step -eq 'none') 'Unexpected staged handoff.'
    Check ($result.read_only -eq ($Action -ne 'CodeSave')) 'Unexpected write authorization.'
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
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces overview ec018 ' + [guid]::NewGuid().ToString('N'))
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

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview')
    Check ($empty.reason_code -eq 'CODE_SHOW_EMPTY' -and $empty.data.record_count -eq 0 -and $empty.data.counts.distinct_exact_anchor_count -eq 0) 'Empty Overview manufactured records.'
    Check ($empty.data.selection_scope -eq 'scan_window' -and $empty.data.counts_scope -eq 'this_page_only_not_cumulative_or_store_wide') 'Empty Overview scope fabricated aggregation.'
    $absentSet = ('ci-' + ('a' * 64)) + ',' + ('ci-' + ('b' * 64))
    $noSelectedStore = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewRecordIds',$absentSet)
    Check ($noSelectedStore.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $noSelectedStore.data) 'Absent store with explicit selection yielded fabricated zero counts.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex'))) 'An empty read created CES state.'
    $invalidFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewSourceMode','WORKING_TREE_DIFF')
    Check ($invalidFilter.reason_code -eq 'CODE_SHOW_OVERVIEW_FILTER_INVALID') 'Case-insensitive mode filter accepted.'
    $emptyFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewSourceMode','')
    Check ($emptyFilter.reason_code -eq 'CODE_SHOW_OVERVIEW_FILTER_INVALID') 'Explicit empty filter accepted.'
    $invalidCursor = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-AfterOverviewCursor','oc1-bad')
    Check ($invalidCursor.reason_code -eq 'CODE_SHOW_INVALID_OVERVIEW_CURSOR') 'Malformed cursor accepted.'
    $emptyCursor = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-AfterOverviewCursor','')
    Check ($emptyCursor.reason_code -eq 'CODE_SHOW_INVALID_OVERVIEW_CURSOR') 'Explicit empty cursor accepted.'
    $wrongSelector = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-FindingSeverity','high')
    Check ($wrongSelector.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Overview accepted a Finding selector.'
    $wrongRecord = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-RecordId',$missingId)
    Check ($wrongRecord.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Overview accepted RecordId.'
    $wrongAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-OverviewSourceMode','working_tree_diff')
    Check ($wrongAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Inspect accepted Overview filter.'

    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'),"exact private overview quote`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($collectFile,($collected | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Fixture preparation failed.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Historical Overview fixture seed.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Local note persistence'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'exact private overview quote'
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

    $multi = Clone-Record -Record $seed
    $duplicate = Clone-Record -Record $seed
    $duplicate = $duplicate.checked_findings[0]
    $duplicate.id = 'Z2'; $duplicate.severity = 'high'
    $multi.checked_findings = @($multi.checked_findings[0], $duplicate)
    $multi.finding_count = 2; $multi.summary = 'Synthetic two-statement report.'
    [void](Store-Record -Record $multi -Folder $store)

    $other = Clone-Record -Record $seed
    $other.source_mode = 'delivered_target_diff'; $other.checked_findings[0].layer = 'changes'
    $other.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $other.checked_findings[0].severity = 'critical'; $other.summary = 'Synthetic delivered report.'
    $deliveredId = Store-Record -Record $other -Folder $store

    $case = Clone-Record -Record $seed
    $case.checked_findings[0].path = 'FILE Ω.txt'
    $case.checked_findings[0].severity = 'low'; $case.summary = 'Synthetic case-variant path.'
    [void](Store-Record -Record $case -Folder $store)

    $zero = Clone-Record -Record $seed
    $zero.checked_findings = @(); $zero.finding_count = 0
    $zero.summary = 'Synthetic no-Finding report.'
    [void](Store-Record -Record $zero -Folder $store)

    $overview = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-Limit','100')
    Check ($overview.reason_code -eq 'CODE_SHOW_OK' -and $overview.data.mode -eq 'Overview') 'Overview not dispatched.'
    Check ($overview.data.selection_scope -eq 'scan_window' -and $overview.data.selected_record_count -eq $null -and $overview.data.selected_record_ids.Count -eq 0) 'Default Overview scope was not preserved.'
    Check ($overview.data.record_count -eq 5 -and $overview.data.scanned_record_count -eq 5 -and $overview.data.included_record_count -eq 5 -and -not $overview.data.has_more_candidates) 'Initial record inventory or pagination is incorrect.'
    Check ($overview.data.finding_statement_count -eq 5 -and $overview.data.records_with_findings_count -eq 4) 'Record vs Finding statement units mixed.'
    Check ($overview.data.counts.distinct_exact_anchor_count -eq 3 -and $overview.data.counts.repeated_statement_anchor_count -eq 1 -and $overview.data.counts.cross_record_anchor_count -eq 1) 'Exact anchor multiplicity or cross-record dedup is wrong.'
    Check ($overview.data.counts.severity_statements.info -eq 2 -and $overview.data.counts.severity_statements.high -eq 1 -and $overview.data.counts.severity_statements.low -eq 1 -and $overview.data.counts.severity_statements.critical -eq 1 -and $overview.data.counts.severity_statements.medium -eq 0) 'Severity bins incorrect.'
    Check ($overview.data.counts.layer_statements.untracked -eq 4 -and $overview.data.counts.layer_statements.changes -eq 1 -and $overview.data.counts.confidence_statements.medium -eq 5) 'Layer or confidence counts incorrect.'
    Check ($overview.data.counts.source_mode_records.working_tree_diff -eq 4 -and $overview.data.counts.source_mode_records.delivered_target_diff -eq 1) 'Source modes should count records.'
    Check ($overview.data.counts_scope -eq 'this_page_only_not_cumulative_or_store_wide' -and -not $overview.data.source_revalidated -and -not $overview.data.record_authorship_authenticated) 'False coverage claim.'
    $payload = $overview | ConvertTo-Json -Depth 32 -Compress
    Check (-not $payload.Contains('file Ω.txt') -and -not $payload.Contains('exact private overview quote') -and -not $payload.Contains('Local note persistence')) 'Overview leaked path, quote or model-authored prose.'

    $working = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewSourceMode','working_tree_diff')
    Check ($working.data.included_record_count -eq 4 -and $working.data.finding_statement_count -eq 4 -and $working.data.counts.source_mode_records.delivered_target_diff -eq 0) 'Saved source-mode filter failed.'
    $delivered = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewSourceMode','delivered_target_diff')
    Check ($delivered.data.included_record_count -eq 1 -and $delivered.data.counts.cross_record_anchor_count -eq 0) 'Filtered cross-mode statistics fabricated overlap.'

    for ($i = 0; $i -lt 50; $i++) {
        $report = Clone-Record -Record $seed
        $report.checked_findings[0].path = ('synthetic/{0:D3}.txt' -f $i)
        $report.checked_findings[0].severity = 'medium'
        $report.summary = ('Synthetic historical report {0:D3}.' -f $i)
        [void](Store-Record -Record $report -Folder $store)
    }
    $cursor = $null; $firstCursor = $null; $pages = 0; $totalRecords = 0; $totalStatements = 0
    do {
        $args = @('-Mode','Overview','-Limit','100')
        if ($null -ne $cursor) { $args += @('-AfterOverviewCursor',$cursor) }
        $page = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More $args
        Check ($page.data.scanned_record_count -le 24 -and $page.data.included_record_count -le 24) 'Overview scan window exceeded 24 records.'
        Check ($page.data.record_count -eq 55 -and $page.data.scanned_record_count -eq $page.data.included_record_count) 'Unfiltered Overview skipped records.'
        $pages++; $totalRecords += $page.data.included_record_count; $totalStatements += $page.data.finding_statement_count
        $cursor = $page.data.next_after_overview_cursor
        if ($null -eq $firstCursor -and $null -ne $cursor) { $firstCursor = $cursor }
        Check (($null -ne $cursor) -eq $page.data.has_more_candidates -and $pages -le 4) 'Continuation does not advance to exhaustion.'
    } while ($null -ne $cursor)
    Check ($pages -eq 3 -and $totalRecords -eq 55 -and $totalStatements -eq 55) 'Full paginated candidate coverage did not match immutable fixture.'
    Check ($null -ne $firstCursor) 'First cursor missing.'
    $mismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewSourceMode','working_tree_diff','-AfterOverviewCursor',$firstCursor)
    Check ($mismatch.reason_code -eq 'CODE_SHOW_OVERVIEW_CURSOR_MISMATCH' -and $null -eq $mismatch.data) 'Root/filter query cursor binding failed.'
    $staleToken = $firstCursor.Substring(0,69) + $missingId
    $stale = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Overview','-AfterOverviewCursor',$staleToken)
    Check ($stale.reason_code -eq 'CODE_SHOW_CURSOR_STALE' -and $null -eq $stale.data) 'Missing cursor anchor was silently ignored.'
    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode Overview -RepoPath $repo -Limit 10)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('Finding statements in this scope:')) 'Non-JSON Overview formatting failed.'

    # EC-018: explicitly aggregate a selected set across unrelated SHA pages.
    # 50 unique self-hashed reports on the SAME six-field quotation anchor
    # ensure the first and last IDs cannot share a 24-record window.
    $crossPageIds = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt 50; $i++) {
        $report = Clone-Record -Record $seed
        $report.checked_findings[0].path = 'review/shared Ω.cs'
        $report.checked_findings[0].severity = if ($i % 2 -eq 0) { 'high' } else { 'critical' }
        $report.summary = ('Synthetic cross-page overview report {0:D3}.' -f $i)
        $crossPageIds.Add((Store-Record -Record $report -Folder $store))
    }
    $crossPageIds.Sort([System.StringComparer]::Ordinal)
    $lower = $crossPageIds[0]; $upper = $crossPageIds[$crossPageIds.Count - 1]
    $allNames = @([System.IO.Directory]::GetFiles($store) |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) })
    [array]::Sort($allNames, [System.StringComparer]::Ordinal)
    $lowPosition = [array]::IndexOf($allNames,$lower)
    $highPosition = [array]::IndexOf($allNames,$upper)
    Check ($highPosition - $lowPosition -ge 49 -and
        [math]::Floor($highPosition / 24) -ne [math]::Floor($lowPosition / 24)) 'The selected Overview fixture failed to span digest scan pages.'

    $idsArg = $upper + ',' + $lower
    $explicit = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg)
    Check ($explicit.data.selection_scope -eq 'selected_record_ids' -and
        $explicit.data.counts_scope -eq 'only_the_explicitly_selected_records_not_the_whole_store' -and
        $explicit.data.selected_record_count -eq 2) 'Overview selected-set scope was not disclosed.'
    Check ($explicit.data.scanned_record_count -eq 2 -and $explicit.data.included_record_count -eq 2 -and
        $explicit.data.record_count -eq $allNames.Count -and $null -eq $explicit.data.limit) 'Selected Overview inventory/body counting or limit semantics failed.'
    Check ($explicit.data.selected_record_ids[0] -ceq $lower -and $explicit.data.selected_record_ids[1] -ceq $upper -and
        $null -eq $explicit.data.after_overview_cursor -and $null -eq $explicit.data.next_after_overview_cursor -and
        -not $explicit.data.has_more_candidates -and -not $explicit.data.scan_window_exhausted) 'Selected Overview leaked a page cursor or lost sorted IDs.'
    Check ($explicit.data.finding_statement_count -eq 2 -and $explicit.data.records_with_findings_count -eq 2 -and
        $explicit.data.counts.distinct_exact_anchor_count -eq 1 -and
        $explicit.data.counts.repeated_statement_anchor_count -eq 1 -and
        $explicit.data.counts.cross_record_anchor_count -eq 1) 'Cross-page selected exact-anchor counters are wrong.'
    Check ($explicit.data.counts.source_mode_records.working_tree_diff -eq 2 -and
        $explicit.data.counts.layer_statements.untracked -eq 2 -and
        ($explicit.data.counts.severity_statements.high + $explicit.data.counts.severity_statements.critical) -eq 2) 'Selected Overview bins are incorrect.'
    $reverse = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',($lower+','+$upper))
    Check (($explicit.data.counts | ConvertTo-Json -Depth 32 -Compress) -ceq
        ($reverse.data.counts | ConvertTo-Json -Depth 32 -Compress) -and
        ($explicit.data.selected_record_ids -join ',') -ceq ($reverse.data.selected_record_ids -join ',')) 'Selected Overview depends on input ordering.'
    $selectedPayload = $explicit | ConvertTo-Json -Depth 32 -Compress
    Check (-not $selectedPayload.Contains('review/shared Ω.cs') -and -not $selectedPayload.Contains('exact private overview quote') -and
        -not $selectedPayload.Contains('Synthetic cross-page overview report') -and -not $explicit.data.source_revalidated) 'Selected Overview disclosed paths, original quotes, free-form model prose or false source freshness.'

    $mixSet = $upper + ',' + $lower + ',' + $deliveredId
    $filteredSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',$mixSet,'-OverviewSourceMode','delivered_target_diff')
    Check ($filteredSelected.data.scanned_record_count -eq 3 -and $filteredSelected.data.included_record_count -eq 1 -and
        $filteredSelected.data.excluded_record_count -eq 2 -and $filteredSelected.data.finding_statement_count -eq 1 -and
        $filteredSelected.data.counts.source_mode_records.delivered_target_diff -eq 1 -and
        $filteredSelected.data.counts.cross_record_anchor_count -eq 0) 'Selected Overview omitted excluded checks or miscounted filtered records.'
    $noMatches = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg,'-OverviewSourceMode','delivered_target_diff')
    Check ($noMatches.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $noMatches.data.scanned_record_count -eq 2 -and
        $noMatches.data.included_record_count -eq 0 -and $noMatches.data.counts.distinct_exact_anchor_count -eq 0 -and
        -not $noMatches.data.has_more_candidates) 'Selected Overview no-match scope was misrepresented.'
    $fullSet = @($crossPageIds | Select-Object -First 24) -join ','
    $bounded = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',$fullSet)
    Check ($bounded.data.scanned_record_count -eq 24 -and $bounded.data.included_record_count -eq 24 -and
        $bounded.data.counts.distinct_exact_anchor_count -eq 1 -and $bounded.data.counts.cross_record_anchor_count -eq 1 -and
        $bounded.data.finding_statement_count -eq 24 -and -not $bounded.data.has_more_candidates) 'Selected Overview did not fully consume its maximum 24 verified bodies.'

    $invalidSets = @('', $lower, ($lower+','+$lower), ($lower+','+$upper.ToUpperInvariant()),
        ($lower+', '+$upper), ($lower+','), (@($crossPageIds | Select-Object -First 25) -join ','))
    foreach ($badSet in $invalidSets) {
        $invalidSet = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewRecordIds',$badSet)
        Check ($invalidSet.reason_code -eq 'CODE_SHOW_OVERVIEW_RECORD_IDS_INVALID' -and $null -eq $invalidSet.data) 'Malformed selected Overview ID set was accepted.'
    }
    $missingSet = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewRecordIds',($lower+','+$missingId))
    Check ($missingSet.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $missingSet.data) 'Overview partial selected membership was accepted.'
    foreach ($limit in @('50','1','100')) {
        $limitConflict = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg,'-Limit',$limit)
        Check ($limitConflict.reason_code -eq 'CODE_SHOW_OVERVIEW_SELECTION_CONFLICT' -and $null -eq $limitConflict.data) 'Explicit Overview Limit conflict silently bypassed.'
    }
    $cursorConflict = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg,'-AfterOverviewCursor','oc1-bad')
    Check ($cursorConflict.reason_code -eq 'CODE_SHOW_OVERVIEW_SELECTION_CONFLICT') 'Overview cursor combined with selected IDs.'
    $leakMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Triage','-OverviewRecordIds',$idsArg)
    Check ($leakMode.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Overview selected IDs leaked into Triage.'
    $leakAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-OverviewRecordIds',$idsArg)
    Check ($leakAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Overview selected IDs leaked into Inspect.'

    # Unselected corrupted bodies are intentionally not read during an
    # explicitly selected comparison (the filename inventory remains checked).
    $unselectedPath = Join-Path $store ($saved.data.record_id + '.json')
    $unselectedBytes = [System.IO.File]::ReadAllBytes($unselectedPath)
    try {
        [System.IO.File]::AppendAllText($unselectedPath,'unselected tamper')
        $unselectedOk = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg)
        Check ($unselectedOk.reason_code -eq 'CODE_SHOW_OK' -and $unselectedOk.data.scanned_record_count -eq 2) 'Overview selected set unexpectedly read unselected bodies.'
    } finally { [System.IO.File]::WriteAllBytes($unselectedPath,$unselectedBytes) }

    # Even selected records FILTERED OUT by source mode must be checked.
    $selectedPath = Join-Path $store ($upper + '.json')
    $selectedBytes = [System.IO.File]::ReadAllBytes($selectedPath)
    try {
        [System.IO.File]::AppendAllText($selectedPath,'selected tamper')
        $badSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Overview','-OverviewRecordIds',$idsArg,'-OverviewSourceMode','delivered_target_diff')
        Check ($badSelected.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $badSelected.data) 'Overview included partial statistics despite a damaged filtered-out selected body.'
    } finally { [System.IO.File]::WriteAllBytes($selectedPath,$selectedBytes) }

    $paths = [System.IO.Directory]::GetFiles($store)
    [array]::Sort($paths, [System.StringComparer]::Ordinal)
    $firstPath = $paths[0]
    $original = [System.IO.File]::ReadAllBytes($firstPath)
    try {
        [System.IO.File]::AppendAllText($firstPath, 'corruption')
        $corrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Overview')
        Check ($corrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $corrupt.data) 'Corrupt page returned unverified statistics.'
    } finally { [System.IO.File]::WriteAllBytes($firstPath,$original) }
    $rogue = Join-Path $store 'unexpected.tmp'
    try {
        [System.IO.File]::WriteAllText($rogue,'rogue')
        $invalid = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Overview')
        Check ($invalid.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $invalid.data) 'Unknown record inventory entry was ignored.'
    } finally { [System.IO.File]::Delete($rogue) }
    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'Overview changed Git HEAD.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Overview changed Git index.'
    Write-Output "EC-018 CodeOverview smoke PASS: $script:checks checks in scratch repository."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

#requires -Version 7.0
<#
    EC-015/EC-016 optional scratch fixture. A real CodeSave seed plus
    synthetic, self-hashed v1 records exercise page-local recurrence and
    explicit selection spanning arbitrary SHA record windows.
    Synthesized statements are not proof of actual code defects.
    Requires PowerShell 7 and Git; do not mark passed unless executed.
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
    Check ($result.next_step -eq 'none') 'Unexpected handoff.'
    Check ($result.read_only -eq ($Action -ne 'CodeSave')) 'Unexpected CES state writer.'
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
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces recurrence ec015 ' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $fixture '测试 repo with spaces'
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
    $indexBefore = (Get-FileHash -LiteralPath (Join-Path $repo '.git/index') -Algorithm SHA256).Hash

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence')
    Check ($empty.reason_code -eq 'CODE_SHOW_EMPTY' -and $empty.data.distinct_exact_anchor_count -eq 0 -and $empty.data.returned_anchor_count -eq 0) 'Empty store manufactured recurrence.'
    Check (-not (Test-Path -LiteralPath (Join-Path $repo '.codex'))) 'Read-only query created CES storage.'
    $missingOther = 'ci-' + ('e' * 64)
    $emptySelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Recurrence','-RecurrenceRecordIds',"$missingId,$missingOther")
    Check ($emptySelected.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $emptySelected.data) 'Selected record IDs falsely accepted against an absent store.'
    foreach ($invalid in @(
        @{ More=@('-Mode','Recurrence','-RecurrenceTop','0'); Code='CODE_SHOW_RECURRENCE_TOP_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrenceTop','31'); Code='CODE_SHOW_RECURRENCE_TOP_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrenceMinRecords','1'); Code='CODE_SHOW_RECURRENCE_MIN_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrenceMinRecords','25'); Code='CODE_SHOW_RECURRENCE_MIN_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrenceSourceMode','WORKING_TREE_DIFF'); Code='CODE_SHOW_RECURRENCE_FILTER_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrenceSourceMode',''); Code='CODE_SHOW_RECURRENCE_FILTER_INVALID' },
        @{ More=@('-Mode','Recurrence','-RecurrencePath',''); Code='CODE_SHOW_RECURRENCE_FILTER_INVALID' },
        @{ More=@('-Mode','Recurrence','-AfterRecurrenceCursor','rc1-bad'); Code='CODE_SHOW_INVALID_RECURRENCE_CURSOR' },
        @{ More=@('-Mode','Recurrence','-AfterRecurrenceCursor',''); Code='CODE_SHOW_INVALID_RECURRENCE_CURSOR' },
        @{ More=@('-Mode','Recurrence','-RecordId',$missingId); Code='CODE_SHOW_SELECTORS_NOT_APPLICABLE' },
        @{ More=@('-Mode','Recurrence','-IncludePatches'); Code='CODE_SHOW_SELECTORS_NOT_APPLICABLE' },
        @{ More=@('-Mode','Triage','-RecurrenceTop','2'); Code='CODE_SHOW_SELECTORS_NOT_APPLICABLE' }
    )) {
        $bad = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More $invalid.More
        Check ($bad.reason_code -eq $invalid.Code) "Invalid Recurrence selector accepted: $($invalid.More -join ' ')"
    }
    $wrongAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-RecurrencePath','file Ω.txt')
    Check ($wrongAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Non-CodeShow accepted Recurrence selector.'

    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'),"private recurrence quote`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($collectFile,($collected | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Fixture preparation failed.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Historical Recurrence fixture seed.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Fixture local note'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'private recurrence quote'
            reasoning = 'This synthetic note may be lost with local untracked cleanup.'
            impact = 'Data may not survive a fixture-only cleanup operation.'
            recommendation = 'Review whether this fixture note belongs under version control.'
        })
        limitations = @('Synthetic test fixture, not a defect report.')
    }
    [System.IO.File]::WriteAllText($draftFile,($draft | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
    Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'Real saved seed unavailable.'
    $store = Join-Path $repo '.codex/ces/code-insights'
    $seed = Get-Content -LiteralPath (Join-Path $store ($saved.data.record_id+'.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32

    # Duplicate within one report is NOT two reporting records. Across two
    # records it is a repeat, even if the reported severities disagree.
    $multi = Clone-Record -Record $seed
    $secondFinding = Clone-Record -Record $seed
    $secondFinding = $secondFinding.checked_findings[0]
    $secondFinding.id = 'A2'; $secondFinding.severity = 'high'; $secondFinding.confidence = 'low'
    $multi.checked_findings = @($multi.checked_findings[0], $secondFinding)
    $multi.finding_count = 2; $multi.summary = 'Synthetic two-statement variant.'
    $multiId = Store-Record -Record $multi -Folder $store

    $differentQuote = Clone-Record -Record $seed
    $differentQuote.checked_findings[0].quote_sha256 = ('1' * 64)
    $differentQuote.summary = 'Different quotation hash.'
    [void](Store-Record -Record $differentQuote -Folder $store)

    $case = Clone-Record -Record $seed
    $case.checked_findings[0].path = 'FILE Ω.txt'
    $case.summary = 'Case-sensitive path variant.'
    [void](Store-Record -Record $case -Folder $store)

    $mode = Clone-Record -Record $seed
    $mode.source_mode = 'delivered_target_diff'
    $mode.checked_findings[0].layer = 'changes'
    $mode.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $mode.summary = 'Different source mode and layer.'
    [void](Store-Record -Record $mode -Folder $store)

    $zero = Clone-Record -Record $seed
    $zero.checked_findings = @(); $zero.finding_count = 0
    $zero.summary = 'A saved analysis with no checked Finding.'
    [void](Store-Record -Record $zero -Folder $store)

    $recurrence = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-Limit','100')
    Check ($recurrence.reason_code -eq 'CODE_SHOW_OK' -and $recurrence.data.mode -eq 'Recurrence') 'Recurrence did not dispatch.'
    Check ($recurrence.data.record_count -eq 6 -and $recurrence.data.scanned_record_count -eq 6) 'Expected verified scan of six records.'
    Check ($recurrence.data.records_with_findings_count -eq 5 -and $recurrence.data.finding_statement_count -eq 6) 'Filtered report vs statement counts are incorrect.'
    Check ($recurrence.data.distinct_exact_anchor_count -eq 4 -and $recurrence.data.eligible_anchor_count -eq 1 -and $recurrence.data.returned_anchor_count -eq 1) 'Exact anchor equivalence or singleton filtering incorrect.'
    $group = $recurrence.data.anchors[0]
    Check ($group.reporting_record_count -eq 2 -and $group.finding_statement_count -eq 3 -and $group.varying_reported_severities) 'Per-record vs per-statement counts or severity disagreement are wrong.'
    Check ($group.anchor.path -ceq 'file Ω.txt' -and $group.anchor.source_mode -ceq 'working_tree_diff' -and $group.anchor.quote_sha256 -ceq $seed.checked_findings[0].quote_sha256) 'Repeated exact anchor not preserved.'
    Check ($group.record_occurrences.Count -eq 2 -and @($group.record_occurrences.record_id) -ccontains $multiId -and @($group.record_occurrences.record_id) -ccontains $saved.data.record_id) 'Occurrence record IDs missing.'
    $multiOccurrence = @($group.record_occurrences | Where-Object { $_.record_id -ceq $multiId })[0]
    Check ($multiOccurrence.finding_ids.Count -eq 2 -and @($multiOccurrence.finding_ids) -ccontains 'F1' -and @($multiOccurrence.finding_ids) -ccontains 'A2') 'Same-record finding IDs were lost.'
    Check ($recurrence.data.original_quote_or_model_prose_disclosed -eq $false -and -not ($recurrence | ConvertTo-Json -Depth 32 -Compress).Contains('private recurrence quote')) 'Private source quotation leaked.'

    $noMatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceMinRecords','3')
    Check ($noMatch.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $noMatch.data.eligible_anchor_count -eq 0) 'Minimum distinct record threshold was ignored.'
    $caseOnly = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrencePath','FILE Ω.txt')
    Check ($caseOnly.data.eligible_anchor_count -eq 0 -and $caseOnly.data.distinct_exact_anchor_count -eq 1) 'Case-sensitive path filter failed.'
    $exact = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrencePath','file Ω.txt','-RecurrenceSourceMode','working_tree_diff')
    Check ($exact.data.eligible_anchor_count -eq 1 -and $exact.data.distinct_exact_anchor_count -eq 2) 'Exact mode+path filter changed grouping.'

    # Grow past 24 candidates. Page-local results MUST NOT be interpreted
    # as whole-store duplicates; rc1 token must preserve every filter.
    for ($i = 0; $i -lt 30; $i++) {
        $r = Clone-Record -Record $seed
        $r.summary = "Synthetic singleton $i"
        $r.checked_findings[0].quote_sha256 = ('{0:x}' -f ($i + 200)).PadLeft(64,'0')
        [void](Store-Record -Record $r -Folder $store)
    }
    $page = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-Limit','100','-RecurrenceTop','1')
    Check ($page.data.scanned_record_count -eq 24 -and $page.data.record_count -eq 36 -and $page.data.has_more_candidates) '24-record scan window was not enforced.'
    Check ($page.data.returned_anchor_count -le 1 -and $page.data.next_after_recurrence_cursor -cmatch '^rc1-[0-9a-f]{64}-ci-[0-9a-f]{64}$') 'Top or continuation cursor is invalid.'
    $cursor = [string]$page.data.next_after_recurrence_cursor
    $next = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-Limit','100','-RecurrenceTop','1','-AfterRecurrenceCursor',$cursor)
    Check ($next.data.scanned_record_count -eq 12 -and -not $next.data.has_more_candidates) 'Second page should complete the recorded inventory.'
    $mismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Recurrence','-RecurrenceTop','2','-AfterRecurrenceCursor',$cursor)
    Check ($mismatch.reason_code -eq 'CODE_SHOW_RECURRENCE_CURSOR_MISMATCH') 'Changed Top accepted old cursor.'
    $mismatchFilter = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Recurrence','-RecurrenceTop','1','-RecurrencePath','file Ω.txt','-AfterRecurrenceCursor',$cursor)
    Check ($mismatchFilter.reason_code -eq 'CODE_SHOW_RECURRENCE_CURSOR_MISMATCH') 'Changed path accepted old cursor.'
    $mismatchMin = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Recurrence','-RecurrenceTop','1','-RecurrenceMinRecords','3','-AfterRecurrenceCursor',$cursor)
    Check ($mismatchMin.reason_code -eq 'CODE_SHOW_RECURRENCE_CURSOR_MISMATCH') 'Changed min threshold accepted old cursor.'

    # EC-016: select known reports from anywhere in the bounded inventory,
    # without depending on which 24-item SHA page contains either record.
    $pair = "$($saved.data.record_id),$multiId"
    $picked = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceRecordIds',$pair)
    Check ($picked.reason_code -eq 'CODE_SHOW_OK' -and $picked.data.selection_scope -eq 'selected_record_ids') 'Explicit-set Recurrence failed to dispatch.'
    Check ($picked.data.scanned_record_count -eq 2 -and $picked.data.included_record_count -eq 2 -and $picked.data.record_count -eq 36) 'Selected mode read unrelated record bodies or lost inventory count.'
    Check ($picked.data.selected_record_count -eq 2 -and $picked.data.selected_record_ids.Count -eq 2 -and
        @($picked.data.selected_record_ids) -ccontains $multiId -and @($picked.data.selected_record_ids) -ccontains $saved.data.record_id) 'Selected record IDs were not preserved.'
    Check ($picked.data.eligible_anchor_count -eq 1 -and $picked.data.anchors[0].reporting_record_count -eq 2 -and
        $picked.data.anchors[0].finding_statement_count -eq 3) 'Explicit-set anchor aggregation did not separate saved records from Finding statements.'
    Check (-not $picked.data.has_more_candidates -and $null -eq $picked.data.next_after_recurrence_cursor -and
        $picked.data.counts_scope -eq 'only_the_explicitly_selected_records_not_the_whole_store') 'Selected set invented a continuation or global claim.'
    Check (-not ($picked | ConvertTo-Json -Depth 32 -Compress).Contains('private recurrence quote')) 'Explicit selection leaked original source.'
    $flipped = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceRecordIds',"$multiId,$($saved.data.record_id)")
    Check ($flipped.data.selected_record_ids[0] -ceq $picked.data.selected_record_ids[0] -and
        $flipped.data.anchors[0].reporting_record_count -eq 2) 'Selection was order-sensitive.'
    $minThree = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceRecordIds',$pair,'-RecurrenceMinRecords','3')
    Check ($minThree.reason_code -eq 'CODE_SHOW_NO_MATCHES' -and $minThree.data.eligible_anchor_count -eq 0) 'Selected set ignored distinct-record minimum.'
    $modeNone = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceRecordIds',$pair,'-RecurrenceSourceMode','delivered_target_diff')
    Check ($modeNone.data.scanned_record_count -eq 2 -and $modeNone.data.included_record_count -eq 0 -and
        $modeNone.data.eligible_anchor_count -eq 0) 'Selected source-mode filter did not integrity-scan excluded bodies.'
    $knownIds = @((Get-ChildItem -LiteralPath $store -Filter 'ci-*.json' -File | Sort-Object -Property Name).BaseName)
    $edgeCsv = "$($knownIds[0]),$($knownIds[$knownIds.Count-1])"
    $edges = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @('-Mode','Recurrence','-RecurrenceRecordIds',$edgeCsv)
    Check ($knownIds.Count -eq 36 -and $edges.data.scanned_record_count -eq 2 -and
        $edges.data.selected_record_ids[0] -ceq $knownIds[0] -and
        $edges.data.selected_record_ids[1] -ceq $knownIds[$knownIds.Count-1]) 'Nonadjacent SHA-page records could not be selected together.'

    $twentyFive = (0..24 | ForEach-Object { 'ci-' + ('{0:x}' -f ($_+1)).PadLeft(64,'0') }) -join ','
    foreach ($badSelector in @(
        @{ Args=@('-RecurrenceRecordIds',$saved.data.record_id); Code='CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID' },
        @{ Args=@('-RecurrenceRecordIds',"$multiId,$multiId"); Code='CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID' },
        @{ Args=@('-RecurrenceRecordIds',"$multiId, $($saved.data.record_id)"); Code='CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID' },
        @{ Args=@('-RecurrenceRecordIds',$twentyFive); Code='CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID' },
        @{ Args=@('-RecurrenceRecordIds',''); Code='CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID' },
        @{ Args=@('-RecurrenceRecordIds',"$pair",'-Limit','50'); Code='CODE_SHOW_RECURRENCE_SELECTION_CONFLICT' },
        @{ Args=@('-RecurrenceRecordIds',"$pair",'-AfterRecurrenceCursor',$cursor); Code='CODE_SHOW_RECURRENCE_SELECTION_CONFLICT' },
        @{ Args=@('-RecurrenceRecordIds',"$missingId,$multiId"); Code='CODE_SHOW_NOT_FOUND' }
    )) {
        $badSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More (@('-Mode','Recurrence') + $badSelector.Args)
        Check ($badSelected.reason_code -eq $badSelector.Code -and $null -eq $badSelected.data) "Selected-record contract violation accepted: $($badSelector.Args -join ' ')"
    }
    $unrelated = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Overview','-RecurrenceRecordIds',$pair)
    Check ($unrelated.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Other CodeShow modes accepted selected Recurrence IDs.'

    # A candidate's byte integrity corruption refuses ALL aggregates rather
    # than silently treating its Findings as absent or partially returned.
    $first = @(Get-ChildItem -LiteralPath $store -File | Sort-Object Name)[0]
    [System.IO.File]::AppendAllText($first.FullName,'tampering')
    $tamper = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Recurrence')
    Check ($tamper.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $tamper.data) 'Tampered record accepted or partial recurrence leaked.'
    $tamperedPair = "$($first.BaseName),$($knownIds[$knownIds.Count-1])"
    if ($first.BaseName -ceq $knownIds[$knownIds.Count-1]) { $tamperedPair = "$($first.BaseName),$($knownIds[0])" }
    $badSelectedBody = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Recurrence','-RecurrenceRecordIds',$tamperedPair)
    Check ($badSelectedBody.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $badSelectedBody.data) 'Explicit-set corruption did not fail closed.'

    Check ((Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD')) -ceq $headBefore) 'Recurrence changed Git HEAD.'
    Check ((Get-FileHash -LiteralPath (Join-Path $repo '.git/index') -Algorithm SHA256).Hash -ceq $indexBefore) 'Recurrence changed Git index.'
    Write-Output "CodeRecurrence.Smoke: PASS ($script:checks assertions). Scratch fixture cleanup follows."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

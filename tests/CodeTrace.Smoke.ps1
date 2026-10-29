#requires -Version 7.0
<#
    EC-012/EC-019 opt-in scratch fixture: real locally CodeSaved Finding seed followed
    by clearly SYNTHETIC, self-hashed historical records. Tests anchor search,
    same-anchor multiplicity, deterministic continuation, unsafe selectors and
    corruption refusal plus EC-019 exact selected cross-page Trace and
    fail-closed selected-record checking. No authentic defect is inferred.
    Never run in a real business repository.
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
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('ces trace ec019 ' + [guid]::NewGuid().ToString('N'))
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

    $empty = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1')
    Check ($empty.reason_code -eq 'CODE_SHOW_NOT_FOUND') 'Trace fabricated a missing CES store.'
    $missingStoreSet = $missingId + ',ci-' + ('e' * 64)
    $missingStore = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1','-TraceRecordIds',$missingStoreSet)
    Check ($missingStore.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $missingStore.data) 'Selected Trace fabricated records in an absent store.'
    $required = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId)
    Check ($required.reason_code -eq 'CODE_SHOW_TRACE_SELECTORS_REQUIRED') 'Finding selector not required.'
    $badFinding = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','../other')
    Check ($badFinding.reason_code -eq 'CODE_SHOW_TRACE_FINDING_ID_INVALID') 'Path-like Finding ID was accepted.'
    $badRecord = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId','/tmp/file','-FindingId','F1')
    Check ($badRecord.reason_code -eq 'CODE_SHOW_INVALID_RECORD_ID') 'Path-like record ID was accepted.'
    $badToken = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1','-AfterTraceCursor','tc1-bad')
    Check ($badToken.reason_code -eq 'CODE_SHOW_INVALID_TRACE_CURSOR') 'Malformed continuation cursor was accepted.'
    $emptyToken = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1','-AfterTraceCursor','')
    Check ($emptyToken.reason_code -eq 'CODE_SHOW_INVALID_TRACE_CURSOR') 'Explicitly empty cursor was ignored.'
    $wrongScope = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1','-FindingLayer','untracked')
    Check ($wrongScope.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Trace accepted a Findings filter.'
    $wrongMode = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Detail','-RecordId',$missingId,'-FindingId','F1')
    Check ($wrongMode.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Detail accepted Trace selector.'
    $wrongAction = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-FindingId','F1')
    Check ($wrongAction.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Inspect accepted Trace selector.'

    [System.IO.File]::WriteAllText((Join-Path $repo 'file Ω.txt'),"exact quote for trace fixture`n")
    $collected = Run-CES -Action Collect -Repo $repo -ExpectedExit 0 -More @('-Mode','WorkingTree','-IncludeUntrackedContent')
    [System.IO.File]::WriteAllText($collectFile,($collected | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $prepared = Run-CES -Action CodePrepare -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-IncludeUntrackedContent')
    Check ($prepared.reason_code -eq 'CODE_PREPARE_READY') 'Fixture preparation failed.'
    $draft = [ordered]@{
        schema_version = 'ces.code_insight_draft.v1'; task_kind = 'code_analysis'
        packet_sha256 = $prepared.data.packet_sha256
        saved_collect_sha256 = $prepared.data.preparation.saved_collect_sha256
        summary = 'Trace fixture seed.'
        findings = @([ordered]@{
            id = 'F1'; title = 'Local note risks'; severity = 'info'; confidence = 'medium'
            layer = 'untracked'; path = 'file Ω.txt'; evidence_quote = 'exact quote for trace fixture'
            reasoning = 'Local notes are not guaranteed to survive checkout cleanup.'
            impact = 'An ignored or deleted note can be lost.'
            recommendation = 'Choose whether this note should be checked into source.'
        })
        limitations = @('Only an example local snapshot.')
    }
    [System.IO.File]::WriteAllText($draftFile,($draft | ConvertTo-Json -Depth 32 -Compress),[System.Text.UTF8Encoding]::new($false))
    $saved = Run-CES -Action CodeSave -Repo $repo -ExpectedExit 0 -More @('-Mode','Snapshot','-EvidencePath',$collectFile,'-InputPath',$draftFile,'-IncludeUntrackedContent','-ApprovePersist')
    Check ($saved.reason_code -eq 'CODE_SAVE_OK' -and $saved.data.created) 'Seed persistence failed.'
    $store = Join-Path $repo '.codex/ces/code-insights'
    $seedId = [string]$saved.data.record_id
    $seed = Get-Content -LiteralPath (Join-Path $store ($seedId+'.json')) -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32

    $multi = Clone-Record -Record $seed
    $dup = Clone-Record -Record $seed
    $dup = $dup.checked_findings[0]
    $dup.id = 'Z2'; $dup.title = 'Alternative model summary'; $dup.severity = 'high'
    $multi.checked_findings = @($multi.checked_findings[0], $dup)
    $multi.finding_count = 2; $multi.summary = 'Synthetic multiple interpretations.'
    $multiId = Store-Record -Record $multi -Folder $store

    $other = Clone-Record -Record $seed
    $other.source_mode = 'delivered_target_diff'
    $other.checked_findings[0].layer = 'changes'
    $other.checked_findings[0].quote_presence = 'pathspec_scoped_tracked_diff_literal'
    $other.summary = 'Synthetic differing source mode.'
    $otherId = Store-Record -Record $other -Folder $store

    $caseVariant = Clone-Record -Record $seed
    $caseVariant.checked_findings[0].path = 'FILE Ω.txt'
    $caseVariant.summary = 'Synthetic case-distinct path.'
    $caseVariantId = Store-Record -Record $caseVariant -Folder $store

    $hashVariant = Clone-Record -Record $seed
    $hashVariant.checked_findings[0].quote_sha256 = ('a' * 64)
    $hashVariant.summary = 'Synthetic quote-digest mismatch.'
    $hashVariantId = Store-Record -Record $hashVariant -Folder $store

    # Spread nonmatching but syntactically valid records through multiple scan
    # windows; every filename is SHA-addressed and no source provenance is claimed.
    for ($i=0; $i -lt 48; $i++) {
        $record = Clone-Record -Record $seed
        $record.checked_findings[0].path = ('synthetic/{0:D3}|Ω.txt' -f $i)
        $record.summary = ('Synthetic unrelated saved report {0:D3}.' -f $i)
        [void](Store-Record -Record $record -Folder $store)
    }
    $missingFinding = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$seedId,'-FindingId','f1')
    Check ($missingFinding.reason_code -eq 'CODE_SHOW_TRACE_FINDING_NOT_FOUND') 'FindingId case should be exact.'
    $missingSeed = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$missingId,'-FindingId','F1')
    Check ($missingSeed.reason_code -eq 'CODE_SHOW_NOT_FOUND') 'Unknown Trace seed silently accepted.'

    $cursor = $null
    $seen = @{}
    $visitedPages = 0
    $emptyPages = 0
    $firstCursor = $null
    do {
        $arguments = @('-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-Limit','1')
        if ($null -ne $cursor) { $arguments += @('-AfterTraceCursor',$cursor) }
        $page = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More $arguments
        Check ($page.data.mode -eq 'Trace' -and $page.data.trace_basis -eq 'exact_saved_finding_quote_anchor') 'Trace data shape changed.'
        Check ($page.data.scanned_record_count -le 24 -and $page.data.returned_record_count -le 1) 'Trace exceeded a bounded page.'
        Check ($page.data.seed.record_id -eq $seedId -and $page.data.anchor.path -ceq 'file Ω.txt') 'Seed anchor was not derived exactly.'
        Check (-not $page.data.source_revalidated -and -not $page.data.finding_semantics_verified -and -not $page.data.snapshot_atomic) 'False proof claims in Trace.'
        Check (-not ($page | ConvertTo-Json -Depth 32).Contains('exact quote for trace fixture')) 'Original quotation leaked.'
        if ($page.data.returned_record_count -eq 0) { $emptyPages++ }
        foreach ($match in $page.data.matches) {
            Check (-not $seen.ContainsKey($match.record_id)) 'Trace repeated a matching record across pages.'
            $seen[$match.record_id] = $match
            Check ($match.matching_finding_count -eq @($match.findings).Count) 'Match multiplicity disagrees with returned statements.'
        }
        $visitedPages++
        Check ($visitedPages -le 52) 'Cursor made no progress through the bounded store.'
        $cursor = $page.data.next_after_trace_cursor
        if ($null -eq $firstCursor -and $null -ne $cursor) { $firstCursor = $cursor }
        Check (($null -ne $cursor) -eq $page.data.has_more_candidates) 'Trace candidate continuation inconsistency.'
    } while ($null -ne $cursor)
    Check ($visitedPages -ge 3) 'Trace did not paginate the long synthetic record set.'
    Check ($seen.Count -eq 2 -and $seen.ContainsKey($seedId) -and $seen.ContainsKey($multiId) -and -not $seen.ContainsKey($otherId) -and -not $seen.ContainsKey($caseVariantId) -and -not $seen.ContainsKey($hashVariantId)) 'Exact anchor membership or source-mode boundary failed.'
    Check ($seen[$multiId].matching_finding_count -eq 2 -and $seen[$multiId].findings[0].id -eq 'F1' -and $seen[$multiId].findings[1].id -eq 'Z2') 'Within-record same-anchor Findings were collapsed or unsorted.'
    Check ($seen[$multiId].findings[1].severity -eq 'high') 'Saved model interpretation changed unexpectedly.'
    Check ($null -ne $firstCursor) 'Expected an independent valid continuation token.'
    $mismatch = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @('-Mode','Trace','-RecordId',$multiId,'-FindingId','F1','-AfterTraceCursor',$firstCursor)
    Check ($mismatch.reason_code -eq 'CODE_SHOW_TRACE_CURSOR_MISMATCH' -and $null -eq $mismatch.data) 'Cursor was accepted for a different seed.'
    $staleCursor = $firstCursor.Substring(0,69) + $missingId
    $stale = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-AfterTraceCursor',$staleCursor)
    Check ($stale.reason_code -eq 'CODE_SHOW_CURSOR_STALE' -and $null -eq $stale.data) 'Deleted/unrecognized cursor ID silently skipped.'
    $human = @(& pwsh -NoProfile -File $cli -Action CodeShow -Mode Trace -RepoPath $repo -RecordId $seedId -FindingId F1 -Limit 1)
    Check ($LASTEXITCODE -eq 0 -and (@($human) -join ' ').Contains('Matching records in page:')) 'Human-readable Trace output failed.'

    # EC-019: add a matching synthetic record guaranteed to reside in a
    # DIFFERENT ordinal 24-ID digest scan window from the seed. This is a
    # fixture search over synthetic IDs, never a search of user source code.
    $farId = $null
    for ($attempt=0; $attempt -lt 80 -and $null -eq $farId; $attempt++) {
        $farRecord = Clone-Record -Record $seed
        $farRecord.summary = ('Synthetic cross-window same-anchor Trace {0:D3}.' -f $attempt)
        $testId = Store-Record -Record $farRecord -Folder $store
        $allIds = [System.Collections.Generic.List[string]]::new()
        foreach ($file in (Get-ChildItem -LiteralPath $store -File -Filter 'ci-*.json')) {
            $allIds.Add($file.BaseName)
        }
        $allIds.Sort([System.StringComparer]::Ordinal)
        $seedPosition = $allIds.IndexOf($seedId)
        $testPosition = $allIds.IndexOf($testId)
        if ($seedPosition -ge 0 -and $testPosition -ge 0 -and
            [math]::Floor($seedPosition / 24) -ne [math]::Floor($testPosition / 24)) {
            $farId = $testId
        } else {
            [System.IO.File]::Delete((Join-Path $store ($testId + '.json')))
        }
    }
    Check ($null -ne $farId) 'Could not construct a cross-page synthetic matching record.'

    $selected = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @($seedId,$multiId,$farId,$otherId)) {
        if (-not $selected.Contains($id)) { $selected.Add($id) }
    }
    $smallSelectedCsv = [string]::Join(',', $selected.ToArray())
    $selected24 = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $selected) { $selected24.Add($id) }
    foreach ($id in $allIds) {
        if ($selected24.Count -ge 24) { break }
        if (-not $selected24.Contains($id)) { $selected24.Add($id) }
    }
    Check ($selected24.Count -eq 24) 'Synthetic store lacks enough records for selected 24 cap.'
    $backwards = $selected24.ToArray()
    [array]::Reverse($backwards)
    $selected24Csv = [string]::Join(',', $backwards)
    $expectedSorted = $selected24.ToArray()
    [array]::Sort($expectedSorted, [System.StringComparer]::Ordinal)
    $selectedResult = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More @(
        '-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',$selected24Csv)
    Check ($selectedResult.reason_code -eq 'CODE_SHOW_OK' -and
        $selectedResult.data.selection_scope -eq 'selected_record_ids') 'Selected Trace did not dispatch.'
    Check ($selectedResult.data.selected_record_count -eq 24 -and
        $selectedResult.data.scanned_record_count -eq 24 -and
        $selectedResult.data.record_count -eq $allIds.Count) 'Selected Trace miscounted checked bodies or inventory names.'
    Check ([string]::Join(',', [string[]]$selectedResult.data.selected_record_ids) -ceq
        [string]::Join(',', $expectedSorted)) 'Selected Trace IDs were not returned in ordinal order.'
    Check ($selectedResult.data.returned_record_count -eq 3 -and
        @($selectedResult.data.matches | ForEach-Object { $_.record_id }) -ccontains $farId) 'Trace did not find a matching record in another digest window.'
    Check ($selectedResult.data.limit -eq $null -and
        $selectedResult.data.after_trace_cursor -eq $null -and
        $selectedResult.data.next_after_trace_cursor -eq $null -and
        -not $selectedResult.data.has_more_candidates -and
        -not $selectedResult.data.scan_window_exhausted) 'Selected Trace fabricated pagination state.'
    Check ($selectedResult.data.counts_scope -eq 'only_the_explicitly_selected_records_not_the_whole_store' -and
        -not $selectedResult.data.source_revalidated -and -not $selectedResult.data.snapshot_atomic) 'Selected Trace overstated coverage.'
    $selectedIdsOrdered = [string[]]@($selectedResult.data.matches | ForEach-Object { $_.record_id })
    $selectedHitsSorted = [string[]]$selectedIdsOrdered.Clone()
    [array]::Sort($selectedHitsSorted, [System.StringComparer]::Ordinal)
    Check ([string]::Join(',', $selectedIdsOrdered) -ceq [string]::Join(',', $selectedHitsSorted)) 'Matches were not sorted by ordinal record ID.'
    $multiMatch = @($selectedResult.data.matches | Where-Object { $_.record_id -ceq $multiId })
    Check ($multiMatch.Count -eq 1 -and $multiMatch[0].matching_finding_count -eq 2 -and
        $multiMatch[0].findings[0].id -ceq 'F1' -and $multiMatch[0].findings[1].id -ceq 'Z2') 'Selected Trace lost multiple Finding statements.'
    Check (-not ($selectedResult | ConvertTo-Json -Depth 32).Contains('exact quote for trace fixture')) 'Selected Trace disclosed the source quotation.'

    $selectArgs = @('-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',$smallSelectedCsv)
    foreach ($invalidIds in @(
        '', $seedId, ($seedId + ',' + $seedId),
        ($seedId + ', ' + $multiId), ($seedId.ToUpperInvariant() + ',' + $multiId),
        ($seedId + ',../unsafe'),
        ([string]::Join(',', [string[]]@($allIds | Select-Object -First 25))))) {
        $invalidSet = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
            '-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',$invalidIds)
        Check ($invalidSet.reason_code -eq 'CODE_SHOW_TRACE_RECORD_IDS_INVALID' -and $null -eq $invalidSet.data) 'Malformed selected IDs were accepted.'
    }
    $noSeed = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',($multiId+','+$otherId))
    Check ($noSeed.reason_code -eq 'CODE_SHOW_TRACE_SELECTION_SEED_REQUIRED' -and $null -eq $noSeed.data) 'Selection lacking the seed was accepted.'
    $conflictVariants = @(
        @('-Limit','50'), @('-Limit','1'), @('-AfterTraceCursor',''),
        @('-AfterTraceCursor',('tc1-'+('a'*64)+'-'+$seedId))
    )
    foreach ($more in $conflictVariants) {
        $conflict = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More ($selectArgs + [string[]]$more)
        Check ($conflict.reason_code -eq 'CODE_SHOW_TRACE_SELECTION_CONFLICT' -and $null -eq $conflict.data) 'Trace selection mixed with pagination.'
    }
    $modeVariants = @(
        @('-Mode','Detail','-RecordId',$seedId,'-TraceRecordIds',$smallSelectedCsv),
        @('-Mode','Overview','-TraceRecordIds',$smallSelectedCsv),
        @('-Mode','Recurrence','-TraceRecordIds',$smallSelectedCsv)
    )
    foreach ($notForTrace in $modeVariants) {
        $modeViolation = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More ([string[]]$notForTrace)
        Check ($modeViolation.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Trace selection escaped into another CodeShow mode.'
    }
    $actionViolation = Run-CES -Action Inspect -Repo $repo -ExpectedExit 4 -More @('-TraceRecordIds',$smallSelectedCsv)
    Check ($actionViolation.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Trace selection escaped into another action.'
    $badCombination = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More ($selectArgs + @('-FindingSeverity','info'))
    Check ($badCombination.reason_code -eq 'CODE_SHOW_SELECTORS_NOT_APPLICABLE') 'Trace accepted unrelated Finding filters.'

    $absentSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
        '-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',($seedId+','+$missingId))
    Check ($absentSelected.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $absentSelected.data) 'Missing selected record was silently skipped.'
    # Missing ID must be detected from inventory before opening a CORRUPTED
    # seed body: this also protects no-partial-results semantics.
    $seedPath = Join-Path $store ($seedId + '.json')
    $original = [System.IO.File]::ReadAllBytes($seedPath)
    try {
        [System.IO.File]::AppendAllText($seedPath,'tampered')
        $absentFirst = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 4 -More @(
            '-Mode','Trace','-RecordId',$seedId,'-FindingId','F1','-TraceRecordIds',($seedId+','+$missingId))
        Check ($absentFirst.reason_code -eq 'CODE_SHOW_NOT_FOUND' -and $null -eq $absentFirst.data) 'Selected Trace read the corrupt seed before checking all requested IDs.'
    } finally { [System.IO.File]::WriteAllBytes($seedPath,$original) }

    $otherPath = Join-Path $store ($otherId + '.json')
    $otherOriginal = [System.IO.File]::ReadAllBytes($otherPath)
    try {
        [System.IO.File]::AppendAllText($otherPath,'invalid mode-excluded body')
        $wrongModeCorrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More $selectArgs
        Check ($wrongModeCorrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $wrongModeCorrupt.data) 'Nonmatching selected source mode skipped integrity validation.'
    } finally { [System.IO.File]::WriteAllBytes($otherPath,$otherOriginal) }
    $unselectedPath = Join-Path $store ($hashVariantId + '.json')
    $unselectedOriginal = [System.IO.File]::ReadAllBytes($unselectedPath)
    try {
        [System.IO.File]::AppendAllText($unselectedPath,'not selected')
        $ignoredUnselected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 0 -More $selectArgs
        Check ($ignoredUnselected.reason_code -eq 'CODE_SHOW_OK' -and $ignoredUnselected.data.scanned_record_count -eq 4) 'Selected Trace read an unselected record body.'
    } finally { [System.IO.File]::WriteAllBytes($unselectedPath,$unselectedOriginal) }
    $selectedCorruptPath = Join-Path $store ($farId + '.json')
    $selectedOriginal = [System.IO.File]::ReadAllBytes($selectedCorruptPath)
    try {
        [System.IO.File]::AppendAllText($selectedCorruptPath,'selected corruption')
        $badSelected = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More $selectArgs
        Check ($badSelected.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $badSelected.data) 'Corrupt matching selected record leaked partial matches.'
    } finally { [System.IO.File]::WriteAllBytes($selectedCorruptPath,$selectedOriginal) }

    $seedPath = Join-Path $store ($seedId + '.json')
    $original = [System.IO.File]::ReadAllBytes($seedPath)
    try {
        [System.IO.File]::AppendAllText($seedPath,'tampered')
        $corrupt = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Trace','-RecordId',$seedId,'-FindingId','F1')
        Check ($corrupt.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $corrupt.data) 'Corrupt Trace seed emitted findings.'
    } finally { [System.IO.File]::WriteAllBytes($seedPath,$original) }
    $unknown = Join-Path $store 'unknown.tmp'
    try {
        [System.IO.File]::WriteAllText($unknown,'unknown')
        $invalid = Run-CES -Action CodeShow -Repo $repo -ExpectedExit 2 -More @('-Mode','Trace','-RecordId',$seedId,'-FindingId','F1')
        Check ($invalid.reason_code -eq 'CODE_SHOW_RECORD_INVALID_OR_CHANGED' -and $null -eq $invalid.data) 'Unexpected CES store entry ignored.'
    } finally { [System.IO.File]::Delete($unknown) }

    Check ($headBefore -eq (Git-Fixture -Argv @('-C',$repo,'rev-parse','HEAD'))) 'Trace mutated Git HEAD.'
    Check ($indexBefore -eq (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash) 'Trace mutated Git index.'
    Write-Output "EC-019 CodeTrace smoke PASS: $script:checks checks in scratch repository."
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue }
}

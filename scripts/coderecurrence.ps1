#requires -Version 7.0
<#
    EC-015/EC-016: discover exact quotation anchors repeated across DIFFERENT
    saved CodeInsight records without requiring a seed Finding. EC-016 adds
    an explicitly selected, up-to-24-record set spanning arbitrary SHA pages.

    Everything here is historical saved MODEL-REPORTED metadata. The reader
    checks at most 24 candidate record bodies per invocation. It never reads
    the business source, original quote, patch or free-form model reasoning.
    A recurrence is not a verified defect, one Issue, a chronological sequence,
    a fix/regression signal or an authenticated review.
#>

$script:CodeShowRecurrenceWindowRecords = 24
$script:CodeShowRecurrenceCursorPattern = '^rc1-([0-9a-f]{64})-(ci-[0-9a-f]{64})$'
$script:CodeShowRecurrenceDefaultTop = 15
$script:CodeShowRecurrenceMaxTop = 30
$script:CodeShowRecurrenceDefaultMinRecords = 2
$script:CodeShowRecurrenceMaxMinRecords = 24

function Parse-CodeShowRecurrenceRecordIds {
    param([AllowNull()][string] $Value)
    # Deliberately one comma-delimited CLI argument: pwsh -File handles it
    # consistently across native shells; no paths or arbitrary expressions.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 1631) {
        throw 'RecurrenceRecordIds must contain 2..24 comma-separated saved record IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowRecurrenceWindowRecords) {
        throw 'RecurrenceRecordIds must contain 2..24 distinct saved record IDs.'
    }
    $unique = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $unique.Add($part)) {
            throw 'RecurrenceRecordIds must use unique, exact lowercase ci-SHA256 IDs without spaces.'
        }
    }
    foreach ($id in $unique) { Write-Output $id }
}

function Parse-CodeShowRecurrenceCursor {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrEmpty($Value) -or
        $Value -cnotmatch $script:CodeShowRecurrenceCursorPattern) {
        throw 'AfterRecurrenceCursor must be a nonempty rc1 token from a prior Recurrence page.'
    }
    return [pscustomobject]@{
        query_sha256 = [string]$Matches[1]
        record_id = [string]$Matches[2]
    }
}

function Get-CodeShowRecurrenceQueryHash {
    param([string] $VerifiedRoot, [string] $SourceMode, [string] $Path,
        [int] $MinRecords, [int] $Top)
    # Not signed. A stable disambiguator for the selected main root and ALL
    # exact filters/thresholds; never a proof that an earlier page is fresh.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @('ces.recurrence_cursor.v1', $VerifiedRoot, $SourceMode,
            $Path, ([string]$MinRecords), ([string]$Top))) {
        $value = [string]$part
        [void]$builder.Append($value.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($value)
    }
    return Get-HashOfBytes -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function New-CodeShowRecurrenceCursor {
    param([string] $QueryHash, [string] $RecordId)
    return ('rc1-{0}-{1}' -f $QueryHash, $RecordId)
}

function New-CodeShowRecurrenceResult {
    param(
        [string] $VerifiedRoot, [int] $Limit, [int] $Top, [int] $MinRecords,
        [string] $SourceMode, [string] $Path,
        [int] $RecordCount, [int] $ScannedCount, [int] $IncludedCount,
        [int] $RecordsWithFindings, [int] $FindingCount,
        [int] $DistinctAnchors, [int] $EligibleAnchors,
        [object[]] $Anchors, [AllowNull()][object] $Cursor,
        [AllowNull()][string] $NextCursor, [bool] $WindowExhausted,
        [bool] $HasMoreCandidates,
        [string[]] $SelectedRecordIds = @()
    )
    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    $idsToReport = @()
    if ($selectedScope) { $idsToReport = @($SelectedRecordIds) }
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Recurrence'
        basis = if ($selectedScope) {
            'exact_saved_quotation_anchors_across_explicitly_selected_verified_records'
        } else { 'exact_saved_quotation_anchors_repeated_in_this_verified_record_window' }
        selection_scope = if ($selectedScope) { 'selected_record_ids' } else { 'scan_window' }
        selected_record_count = if ($selectedScope) { $SelectedRecordIds.Count } else { $null }
        selected_record_ids = $idsToReport
        filters = [ordered]@{
            source_mode = if ([string]::IsNullOrEmpty($SourceMode)) { $null } else { $SourceMode }
            path_exact = if ([string]::IsNullOrEmpty($Path)) { $null } else { $Path }
        }
        min_distinct_records = $MinRecords
        record_count = $RecordCount
        scanned_record_count = $ScannedCount
        included_record_count = $IncludedCount
        excluded_record_count = ($ScannedCount - $IncludedCount)
        records_with_findings_count = $RecordsWithFindings
        finding_statement_count = $FindingCount
        distinct_exact_anchor_count = $DistinctAnchors
        eligible_anchor_count = $EligibleAnchors
        returned_anchor_count = $Anchors.Count
        omitted_eligible_anchor_count = ($EligibleAnchors - $Anchors.Count)
        anchors = $Anchors
        limit = $Limit
        top = $Top
        scan_window_records = $script:CodeShowRecurrenceWindowRecords
        scan_window_exhausted = $WindowExhausted
        after_recurrence_cursor = if ($null -eq $Cursor) { $null } else {
            New-CodeShowRecurrenceCursor -QueryHash $Cursor.query_sha256 -RecordId $Cursor.record_id
        }
        next_after_recurrence_cursor = if ([string]::IsNullOrEmpty($NextCursor)) { $null } else { $NextCursor }
        has_more_candidates = $HasMoreCandidates
        rank_order = 'distinct_reporting_records_desc_then_statements_desc_then_highest_model_severity_then_ordinal_exact_anchor'
        counts_scope = if ($selectedScope) { 'only_the_explicitly_selected_records_not_the_whole_store' } else { 'this_page_only_not_cumulative_or_store_wide' }
        explanation = if ($selectedScope) {
            'Exactly the selected saved records were checked and grouped, regardless of SHA page boundaries. Source-mode-excluded selected records were still integrity checked. Anchors match only on exact mode/layer/case-sensitive Git path/endpoint/quote SHA-256/proof category; distinct record IDs, not statements, count as recurrence. Unselected records were not read, and neither model repetition nor SHA order proves defects, resolution or time.'
        } else {
            'Exact anchors require saved source mode, layer, case-sensitive Git path, rename endpoint, quote SHA-256 and quote proof category to agree. Only distinct record IDs count toward recurrence; multiple statements in one record do not. Filtered-out record bodies were still checked. Neither different anchors nor unvisited records are evidence of issue resolution, and SHA ordering is not time.'
        }
        paths_and_quote_digests_disclosed = $true
        original_quote_or_model_prose_disclosed = $false
        scanned_records_integrity_checked = $true
        unseen_records_integrity_checked = $false
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        snapshot_atomic = $false
    }
}

function Get-CodeShowRecurrencePage {
    param(
        [string] $Directory, [string] $VerifiedRoot,
        [int] $Limit, [int] $Top, [int] $MinRecords,
        [string] $SourceMode, [string] $Path,
        [AllowNull()][object] $Cursor, [string] $QueryHash,
        [string[]] $SelectedRecordIds = @()
    )
    # The bounded inventory is checked for every filename. Only selected
    # candidate file contents are integrity/schema checked, never unseen ones.
    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    if ($selectedScope) {
        # Defense in depth for direct module callers. Never return aggregates
        # for a selected set only partially checked due to the window cap.
        if ($SelectedRecordIds.Count -lt 2 -or
            $SelectedRecordIds.Count -gt $script:CodeShowRecurrenceWindowRecords -or
            $null -ne $Cursor -or $Limit -ne 50) {
            throw 'CODE_SHOW_RECURRENCE_SELECTION_INVALID: selected set must contain 2..24 IDs without paging.'
        }
        $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($id in $SelectedRecordIds) {
            Assert-CodeShowRecordId -Id $id
            if (-not $sorted.Add($id)) {
                throw 'CODE_SHOW_RECURRENCE_SELECTION_INVALID: duplicate selected ID.'
            }
        }
        $sortedIds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $sorted) { $sortedIds.Add($id) }
        $SelectedRecordIds = $sortedIds.ToArray()
    }
    $allIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if ($selectedScope) {
        foreach ($id in $SelectedRecordIds) {
            if (-not ($allIds -ccontains $id)) {
                throw "CODE_SHOW_RECURRENCE_RECORD_NOT_FOUND: $id is absent from the verified store."
            }
        }
    }
    if ($null -ne $Cursor -and -not ($allIds -ccontains $Cursor.record_id)) {
        throw 'CODE_SHOW_CURSOR_STALE: Recurrence cursor record no longer exists.'
    }

    $groups = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $scanned = 0
    $included = 0
    $recordsWithFindings = 0
    $findingCount = 0
    $lastScannedId = $null
    $limitReached = $false
    $candidateIds = if ($selectedScope) { @($SelectedRecordIds) } else { $allIds }
    foreach ($id in $candidateIds) {
        if ($null -ne $Cursor -and
            [string]::Compare($id, $Cursor.record_id, [System.StringComparison]::Ordinal) -le 0) {
            continue
        }
        if ($scanned -ge $script:CodeShowRecurrenceWindowRecords) { break }
        $checked = Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        $scanned++
        $lastScannedId = $id
        $mode = [string]$checked.record.source_mode
        if (-not [string]::IsNullOrEmpty($SourceMode) -and $mode -cne $SourceMode) { continue }
        $included++
        $recordHasMatchingFinding = $false
        foreach ($finding in $checked.record.checked_findings) {
            if (-not [string]::IsNullOrEmpty($Path) -and [string]$finding.path -cne $Path) { continue }
            $recordHasMatchingFinding = $true
            $findingCount++
            $anchor = Get-CodeShowTraceAnchor -Finding $finding -SourceMode $mode
            $key = Get-CodeCompareAnchorKey -Anchor $anchor
            if (-not $groups.ContainsKey($key)) {
                $groups.Add($key, [pscustomobject]@{
                    key = $key
                    anchor = $anchor
                    severity_rank = 5
                    highest_severity = $null
                    severity = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
                    confidence = [ordered]@{high=0;medium=0;low=0}
                    statement_count = 0
                    records = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
                })
            }
            $group = $groups[$key]
            if (-not $group.records.ContainsKey($id)) {
                $group.records.Add($id, [pscustomobject]@{
                    finding_ids = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
                    statement_count = 0
                    severity_rank = 5
                    strongest_severity = $null
                })
            }
            $occurrence = $group.records[$id]
            [void]$occurrence.finding_ids.Add([string]$finding.id)
            $occurrence.statement_count++
            $group.statement_count++
            $severity = [string]$finding.severity
            $confidence = [string]$finding.confidence
            $group.severity[$severity] = [int]$group.severity[$severity] + 1
            $group.confidence[$confidence] = [int]$group.confidence[$confidence] + 1
            $rank = Get-CodeShowTriageSeverityRank -Severity $severity
            if ($rank -lt $group.severity_rank) {
                $group.severity_rank = $rank
                $group.highest_severity = $severity
            }
            if ($rank -lt $occurrence.severity_rank) {
                $occurrence.severity_rank = $rank
                $occurrence.strongest_severity = $severity
            }
        }
        if ($recordHasMatchingFinding) { $recordsWithFindings++ }
        if (-not $selectedScope -and $included -ge $Limit) { $limitReached = $true; break }
    }

    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during Recurrence.'
    }

    $ranked = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $eligible = 0
    foreach ($group in $groups.Values) {
        if ($group.records.Count -lt $MinRecords) { continue }
        $eligible++
        $variation = 0
        foreach ($value in $group.severity.Values) { if ([int]$value -gt 0) { $variation++ } }
        $occurrences = [System.Collections.Generic.List[object]]::new()
        $sortedRecordIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($id in $group.records.Keys) { [void]$sortedRecordIds.Add($id) }
        foreach ($id in $sortedRecordIds) {
            $record = $group.records[$id]
            $findingIds = [System.Collections.Generic.List[string]]::new()
            foreach ($findingId in $record.finding_ids) { $findingIds.Add([string]$findingId) }
            $occurrences.Add([ordered]@{
                record_id = $id
                finding_ids = $findingIds.ToArray()
                finding_statement_count = $record.statement_count
                highest_reported_severity = $record.strongest_severity
            })
        }
        $entry = [ordered]@{
            anchor = $group.anchor
            reporting_record_count = $group.records.Count
            finding_statement_count = $group.statement_count
            highest_reported_severity = $group.highest_severity
            severity_statements = $group.severity
            confidence_statements = $group.confidence
            varying_reported_severities = ($variation -gt 1)
            record_occurrences = $occurrences.ToArray()
        }
        # All counts are within 24 x 40 verified Finding statements.
        $sortKey = ('{0:D2}:{1:D4}:{2:D1}:{3}' -f `
            ($script:CodeShowRecurrenceWindowRecords - $group.records.Count), `
            ($script:CodeShowRecurrenceWindowRecords * 40 - $group.statement_count), `
            $group.severity_rank, $group.key)
        $ranked.Add($sortKey, $entry)
    }
    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $ranked.Keys) {
        if ($selected.Count -ge $Top) { break }
        $selected.Add($ranked[$key])
    }

    $hasMoreCandidates = $false
    if (-not $selectedScope -and $null -ne $lastScannedId) {
        foreach ($id in $allIds) {
            if ([string]::Compare($id, $lastScannedId, [System.StringComparison]::Ordinal) -gt 0) {
                $hasMoreCandidates = $true
                break
            }
        }
    }
    $nextCursor = if ($hasMoreCandidates) {
        New-CodeShowRecurrenceCursor -QueryHash $QueryHash -RecordId $lastScannedId
    } else { $null }
    return New-CodeShowRecurrenceResult -VerifiedRoot $VerifiedRoot -Limit $Limit -Top $Top `
        -MinRecords $MinRecords -SourceMode $SourceMode -Path $Path `
        -RecordCount $allIds.Count -ScannedCount $scanned -IncludedCount $included `
        -RecordsWithFindings $recordsWithFindings -FindingCount $findingCount `
        -DistinctAnchors $groups.Count -EligibleAnchors $eligible -Anchors $selected.ToArray() `
        -Cursor $Cursor -NextCursor $nextCursor `
        -WindowExhausted ($scanned -ge $script:CodeShowRecurrenceWindowRecords -and $hasMoreCandidates -and -not $limitReached) `
        -HasMoreCandidates $hasMoreCandidates -SelectedRecordIds $SelectedRecordIds
}

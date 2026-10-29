#requires -Version 7.0
<#
    EC-013/EC-018: Bounded, read-only aggregation of already-saved CodeInsight
    findings. EC-018 adds explicitly selected 2..24 verified records from
    arbitrary SHA pages. Counters describe ONLY this checked scope, never the
    entire historical inventory, distinct verified defects or time.
    No saved free-form text, Git path, quote or patch is emitted by Overview.
#>

$script:CodeShowOverviewWindowRecords = 24
$script:CodeShowOverviewCursorPattern = '^oc1-([0-9a-f]{64})-(ci-[0-9a-f]{64})$'

function Parse-CodeShowOverviewRecordIds {
    param([AllowNull()][string] $Value)
    # Accept ONE literal comma-separated string, with no spaces or empty items.
    # 24 * 67-byte record IDs + 23 commas is the longest valid input.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 1631) {
        throw 'OverviewRecordIds must contain 2..24 exact saved record IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowOverviewWindowRecords) {
        throw 'OverviewRecordIds must contain 2..24 distinct saved record IDs.'
    }
    $unique = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $unique.Add($part)) {
            throw 'OverviewRecordIds must be distinct lowercase ci-SHA256 IDs without whitespace.'
        }
    }
    foreach ($id in $unique) { Write-Output $id }
}

function Parse-CodeShowOverviewCursor {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrEmpty($Value) -or
        $Value -cnotmatch $script:CodeShowOverviewCursorPattern) {
        throw 'AfterOverviewCursor must be a nonempty oc1 token returned by a prior Overview page.'
    }
    return [pscustomobject]@{
        query_sha256 = [string]$Matches[1]
        record_id = [string]$Matches[2]
    }
}

function Get-CodeShowOverviewQueryHash {
    param([string] $VerifiedRoot, [string] $SourceMode)
    # Length-prefix all fields; this is a query discriminator, NOT a signature.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @('ces.overview_cursor.v1', $VerifiedRoot, $SourceMode)) {
        $value = [string]$part
        [void]$builder.Append($value.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($value)
    }
    return Get-HashOfBytes -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function New-CodeShowOverviewCursor {
    param([string] $QueryHash, [string] $RecordId)
    return ('oc1-{0}-{1}' -f $QueryHash, $RecordId)
}

function New-CodeShowOverviewCounts {
    # Explicit, zero-filled enum bins are easier for machine and human readers
    # to distinguish from absent/unchecked groups.
    return [ordered]@{
        source_mode_records = [ordered]@{
            working_tree_diff = 0
            delivered_target_diff = 0
        }
        severity_statements = [ordered]@{
            critical = 0; high = 0; medium = 0; low = 0; info = 0
        }
        layer_statements = [ordered]@{
            staged = 0; unstaged = 0; untracked = 0; changes = 0
        }
        confidence_statements = [ordered]@{
            high = 0; medium = 0; low = 0
        }
        distinct_exact_anchor_count = 0
        repeated_statement_anchor_count = 0
        cross_record_anchor_count = 0
    }
}

function New-CodeShowOverviewResult {
    param(
        [string] $VerifiedRoot,
        [int] $Limit,
        [string] $SourceMode,
        [int] $RecordCount,
        [int] $ScannedCount,
        [int] $IncludedCount,
        [int] $RecordsWithFindings,
        [int] $FindingCount,
        [System.Collections.IDictionary] $Counts,
        [AllowNull()][object] $Cursor,
        [AllowNull()][string] $NextCursor,
        [bool] $WindowExhausted,
        [bool] $HasMoreCandidates,
        [string[]] $SelectedRecordIds = @()
    )
    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    $idsToReport = @()
    if ($selectedScope) { $idsToReport = @($SelectedRecordIds) }
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Overview'
        basis = if ($selectedScope) {
            'historical_saved_model_report_statements_in_explicitly_selected_verified_records'
        } else { 'historical_saved_model_report_statements_in_this_verified_page' }
        selection_scope = if ($selectedScope) { 'selected_record_ids' } else { 'scan_window' }
        selected_record_count = if ($selectedScope) { $SelectedRecordIds.Count } else { $null }
        selected_record_ids = $idsToReport
        filters = [ordered]@{
            source_mode = if ([string]::IsNullOrEmpty($SourceMode)) { $null } else { $SourceMode }
        }
        record_count = $RecordCount
        scanned_record_count = $ScannedCount
        included_record_count = $IncludedCount
        excluded_record_count = ($ScannedCount - $IncludedCount)
        records_with_findings_count = $RecordsWithFindings
        finding_statement_count = $FindingCount
        counts = $Counts
        scan_window_records = $script:CodeShowOverviewWindowRecords
        scan_window_exhausted = $WindowExhausted
        limit = if ($selectedScope) { $null } else { $Limit }
        after_overview_cursor = if ($null -eq $Cursor) { $null } else {
            New-CodeShowOverviewCursor -QueryHash $Cursor.query_sha256 -RecordId $Cursor.record_id
        }
        next_after_overview_cursor = if ([string]::IsNullOrEmpty($NextCursor)) { $null } else { $NextCursor }
        has_more_candidates = $HasMoreCandidates
        counts_scope = if ($selectedScope) { 'only_the_explicitly_selected_records_not_the_whole_store' } else { 'this_page_only_not_cumulative_or_store_wide' }
        explanation = if ($selectedScope) {
            'Only the explicitly selected records contribute to the aggregate, even across separate SHA scan pages. Every selected body, including a source-mode-excluded one, was checked; unselected bodies were not read. Statement and exact-anchor counters are historical model report metadata, not verified defects, independence, resolution, chronology, current source or whole-store conclusions.'
        } else {
            'Statement counts describe saved model reports, not verified issues. Exact anchor repeats are byte-identical evidence tuples within this page, not semantic duplicate defects. SHA-ID order is not time; other pages are not included.'
        }
        scanned_records_integrity_checked = $true
        unseen_records_integrity_checked = $false
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        snapshot_atomic = $false
    }
}

function Get-CodeShowOverviewPage {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [int] $Limit,
        [string] $SourceMode,
        [AllowNull()][object] $Cursor,
        [string] $QueryHash,
        [string[]] $SelectedRecordIds = @()
    )
    # Every selected ID must be present in the verified filename inventory
    # before any selected record body is read. Excluded selected modes STILL
    # undergo full digest/schema and second-read validation.
    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    if ($selectedScope) {
        # Defense in depth for direct module callers bypassing the CLI.
        if ($SelectedRecordIds.Count -lt 2 -or
            $SelectedRecordIds.Count -gt $script:CodeShowOverviewWindowRecords -or
            $null -ne $Cursor -or $Limit -ne 50) {
            throw 'CODE_SHOW_OVERVIEW_SELECTION_INVALID: expected 2..24 IDs and no paging.'
        }
        $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($id in $SelectedRecordIds) {
            Assert-CodeShowRecordId -Id $id
            if (-not $sorted.Add($id)) {
                throw 'CODE_SHOW_OVERVIEW_SELECTION_INVALID: duplicate selected ID.'
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
                throw "CODE_SHOW_OVERVIEW_RECORD_NOT_FOUND: $id is absent from the verified store."
            }
        }
    }
    if ($null -ne $Cursor -and -not ($allIds -ccontains $Cursor.record_id)) {
        throw 'CODE_SHOW_CURSOR_STALE: Overview cursor record is absent.'
    }
    $counts = New-CodeShowOverviewCounts
    $anchorStatements = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $anchorRecordCounts = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
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
        if ($scanned -ge $script:CodeShowOverviewWindowRecords) { break }
        $checked = Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        $scanned++
        $lastScannedId = $id
        if (-not [string]::IsNullOrEmpty($SourceMode) -and
            $checked.record.source_mode -cne $SourceMode) { continue }

        $included++
        $mode = [string]$checked.record.source_mode
        $counts.source_mode_records[$mode] = [int]$counts.source_mode_records[$mode] + 1
        if ($checked.record.checked_findings.Count -gt 0) { $recordsWithFindings++ }
        $seenInRecord = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($finding in $checked.record.checked_findings) {
            $findingCount++
            $severity = [string]$finding.severity
            $layer = [string]$finding.layer
            $confidence = [string]$finding.confidence
            $counts.severity_statements[$severity] = [int]$counts.severity_statements[$severity] + 1
            $counts.layer_statements[$layer] = [int]$counts.layer_statements[$layer] + 1
            $counts.confidence_statements[$confidence] = [int]$counts.confidence_statements[$confidence] + 1
            $anchor = Get-CodeShowTraceAnchor -Finding $finding -SourceMode $mode
            $key = Get-CodeCompareAnchorKey -Anchor $anchor
            if (-not $anchorStatements.ContainsKey($key)) { $anchorStatements.Add($key, 0) }
            $anchorStatements[$key] = $anchorStatements[$key] + 1
            [void]$seenInRecord.Add($key)
        }
        foreach ($key in $seenInRecord) {
            if (-not $anchorRecordCounts.ContainsKey($key)) { $anchorRecordCounts.Add($key, 0) }
            $anchorRecordCounts[$key] = $anchorRecordCounts[$key] + 1
        }
        if (-not $selectedScope -and $included -ge $Limit) { $limitReached = $true; break }
    }

    # Never return partial counters if the local inventory changed while read.
    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES local record directory membership changed during Overview.'
    }
    $counts.distinct_exact_anchor_count = $anchorStatements.Count
    foreach ($value in $anchorStatements.Values) {
        if ($value -gt 1) { $counts.repeated_statement_anchor_count++ }
    }
    foreach ($value in $anchorRecordCounts.Values) {
        if ($value -gt 1) { $counts.cross_record_anchor_count++ }
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
        New-CodeShowOverviewCursor -QueryHash $QueryHash -RecordId $lastScannedId
    } else { $null }
    return New-CodeShowOverviewResult -VerifiedRoot $VerifiedRoot -Limit $Limit `
        -SourceMode $SourceMode -RecordCount $allIds.Count -ScannedCount $scanned `
        -IncludedCount $included -RecordsWithFindings $recordsWithFindings `
        -FindingCount $findingCount -Counts $counts -Cursor $Cursor -NextCursor $nextCursor `
        -WindowExhausted (-not $selectedScope -and $scanned -ge $script:CodeShowOverviewWindowRecords -and $hasMoreCandidates -and -not $limitReached) `
        -HasMoreCandidates $hasMoreCandidates -SelectedRecordIds $SelectedRecordIds
}

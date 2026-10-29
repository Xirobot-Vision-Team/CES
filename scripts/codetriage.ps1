#requires -Version 7.0
<#
    EC-014/EC-017: Read-only file-level triage of historical saved
    CodeInsight statements. Ranks exact source-mode/Git-path/rename-endpoint
    groups within either a 24-candidate scan window or an explicitly named
    set of 2..24 verified records spanning arbitrary SHA pages. No automatic
    store-wide ranking or durable linkage is inferred.

    Saved severity is a MODEL REPORT, not a validated defect or risk score.
    This mode intentionally discloses exact Git paths but not model prose,
    source quotations, patches, original file content or line numbers.
#>

$script:CodeShowTriageWindowRecords = 24
$script:CodeShowTriageCursorPattern = '^tg1-([0-9a-f]{64})-(ci-[0-9a-f]{64})$'
$script:CodeShowTriageDefaultTop = 15
$script:CodeShowTriageMaxTop = 30

function Parse-CodeShowTriageRecordIds {
    param([AllowNull()][string] $Value)
    # A single native-shell-safe argument; 24 * 67-character IDs + 23 commas.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 1631) {
        throw 'TriageRecordIds must contain 2..24 comma-separated saved record IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowTriageWindowRecords) {
        throw 'TriageRecordIds must contain 2..24 distinct saved record IDs.'
    }
    $unique = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $unique.Add($part)) {
            throw 'TriageRecordIds requires unique lowercase ci-SHA256 IDs, without whitespace.'
        }
    }
    foreach ($id in $unique) { Write-Output $id }
}

function Parse-CodeShowTriageCursor {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrEmpty($Value) -or
        $Value -cnotmatch $script:CodeShowTriageCursorPattern) {
        throw 'AfterTriageCursor must be a nonempty tg1 token returned by a prior Triage page.'
    }
    return [pscustomobject]@{
        query_sha256 = [string]$Matches[1]
        record_id = [string]$Matches[2]
    }
}

function Get-CodeShowTriageQueryHash {
    param([string] $VerifiedRoot, [string] $SourceMode, [int] $Top)
    # A deterministic query discriminator, not an authentication signature.
    # Include Top so a continuation cannot silently change ranking/coverage.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @('ces.triage_cursor.v1', $VerifiedRoot, $SourceMode, ([string]$Top))) {
        $value = [string]$part
        [void]$builder.Append($value.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($value)
    }
    return Get-HashOfBytes -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function New-CodeShowTriageCursor {
    param([string] $QueryHash, [string] $RecordId)
    return ('tg1-{0}-{1}' -f $QueryHash, $RecordId)
}

function Get-CodeShowTriagePathKey {
    param([string] $SourceMode, [string] $Path, [string] $Endpoint)
    # Do not use a raw delimiter: Git path strings may contain any chosen
    # delimiter, Unicode, whitespace and delimiter-looking substrings.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @($SourceMode, $Path, $Endpoint)) {
        $value = [string]$part
        [void]$builder.Append($value.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($value)
    }
    return $builder.ToString()
}

function Get-CodeShowTriageSeverityRank {
    param([string] $Severity)
    # Rank is highest model-reported severity, not an objective risk score.
    switch -CaseSensitive ($Severity) {
        critical { return 0 }
        high { return 1 }
        medium { return 2 }
        low { return 3 }
        info { return 4 }
        default { throw 'Unexpected saved severity in validated Finding.' }
    }
}

function New-CodeShowTriageBins {
    return [ordered]@{
        severity_statements = [ordered]@{
            critical = 0; high = 0; medium = 0; low = 0; info = 0
        }
        layer_statements = [ordered]@{
            staged = 0; unstaged = 0; untracked = 0; changes = 0
        }
        confidence_statements = [ordered]@{
            high = 0; medium = 0; low = 0
        }
    }
}

function New-CodeShowTriageResult {
    param(
        [string] $VerifiedRoot,
        [int] $Limit,
        [int] $Top,
        [string] $SourceMode,
        [int] $RecordCount,
        [int] $ScannedCount,
        [int] $IncludedCount,
        [int] $RecordsWithFindings,
        [int] $FindingCount,
        [int] $TotalGroups,
        [object[]] $PathGroups,
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
        mode = 'Triage'
        basis = if ($selectedScope) {
            'historical_saved_model_statements_in_explicitly_selected_verified_records'
        } else { 'historical_saved_model_statements_in_this_verified_record_window' }
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
        path_group_count = $TotalGroups
        returned_group_count = $PathGroups.Count
        omitted_group_count = ($TotalGroups - $PathGroups.Count)
        path_groups = $PathGroups
        limit = if ($selectedScope) { $null } else { $Limit }
        top = $Top
        scan_window_records = $script:CodeShowTriageWindowRecords
        scan_window_exhausted = $WindowExhausted
        after_triage_cursor = if ($null -eq $Cursor) { $null } else {
            New-CodeShowTriageCursor -QueryHash $Cursor.query_sha256 -RecordId $Cursor.record_id
        }
        next_after_triage_cursor = if ([string]::IsNullOrEmpty($NextCursor)) { $null } else { $NextCursor }
        has_more_candidates = $HasMoreCandidates
        rank_order = 'highest_model_severity_then_distinct_reporting_records_then_statement_count_then_ordinal_exact_group_key'
        counts_scope = if ($selectedScope) {
            'only_the_explicitly_selected_records_not_the_whole_store'
        } else { 'this_page_only_not_store_wide_or_cumulative' }
        explanation = if ($selectedScope) {
            'All and only the explicitly named saved record bodies were checked, including source-mode-excluded records. File groups use exact saved source mode, case-sensitive Git path and rename endpoint, across SHA pages without claiming chronology. Unselected bodies were not inspected. Model severity and repetition do not verify defects, risk, issue identity or fixes.'
        } else {
            'Grouping uses exact saved source mode, case-sensitive Git path and rename endpoint. Layer bins remain separate. Rankings describe historical model reports, not verified risk, issue identity, current files, fixes or time. Omitted groups and unvisited candidate records are not ranked in this response.'
        }
        paths_disclosed = $true
        original_quote_or_model_prose_disclosed = $false
        scanned_records_integrity_checked = $true
        unseen_records_integrity_checked = $false
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        snapshot_atomic = $false
    }
}

function Get-CodeShowTriagePage {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [int] $Limit,
        [int] $Top,
        [string] $SourceMode,
        [AllowNull()][object] $Cursor,
        [string] $QueryHash,
        [string[]] $SelectedRecordIds = @()
    )
    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    if ($selectedScope) {
        # Defense in depth for a module caller bypassing the public CLI.
        # Never merge a partial selection if someone supplied a page Limit.
        if ($SelectedRecordIds.Count -lt 2 -or
            $SelectedRecordIds.Count -gt $script:CodeShowTriageWindowRecords -or
            $null -ne $Cursor -or $Limit -ne 50) {
            throw 'CODE_SHOW_TRIAGE_SELECTION_INVALID: use 2..24 distinct IDs without paging.'
        }
        $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($id in $SelectedRecordIds) {
            Assert-CodeShowRecordId -Id $id
            if (-not $sorted.Add($id)) {
                throw 'CODE_SHOW_TRIAGE_SELECTION_INVALID: duplicate selected record ID.'
            }
        }
        $orderedIds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $sorted) { $orderedIds.Add($id) }
        $SelectedRecordIds = $orderedIds.ToArray()
    }
    $allIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if ($selectedScope) {
        # Check membership of the entire selected set BEFORE reading a body.
        foreach ($id in $SelectedRecordIds) {
            if (-not ($allIds -ccontains $id)) {
                throw "CODE_SHOW_TRIAGE_RECORD_NOT_FOUND: $id is absent from the verified store."
            }
        }
    }
    if ($null -ne $Cursor -and -not ($allIds -ccontains $Cursor.record_id)) {
        throw 'CODE_SHOW_CURSOR_STALE: Triage cursor record is absent.'
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
        if ($scanned -ge $script:CodeShowTriageWindowRecords) { break }
        $checked = Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        $scanned++
        $lastScannedId = $id
        if (-not [string]::IsNullOrEmpty($SourceMode) -and
            $checked.record.source_mode -cne $SourceMode) { continue }

        $included++
        $mode = [string]$checked.record.source_mode
        if ($checked.record.checked_findings.Count -gt 0) { $recordsWithFindings++ }
        foreach ($finding in $checked.record.checked_findings) {
            $findingCount++
            $path = [string]$finding.path
            $endpoint = [string]$finding.path_endpoint
            $key = Get-CodeShowTriagePathKey -SourceMode $mode -Path $path -Endpoint $endpoint
            if (-not $groups.ContainsKey($key)) {
                $bins = New-CodeShowTriageBins
                $groups.Add($key, [pscustomobject]@{
                    key = $key
                    severity_rank = 5
                    record_ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    anchor_records = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
                    public = [ordered]@{
                        source_mode = $mode
                        path_exact = $path
                        path_endpoint = $endpoint
                        highest_reported_severity = $null
                        reporting_record_count = 0
                        reporting_record_ids = @()
                        finding_statement_count = 0
                        distinct_exact_anchor_count = 0
                        cross_record_exact_anchor_count = 0
                        severity_statements = $bins.severity_statements
                        layer_statements = $bins.layer_statements
                        confidence_statements = $bins.confidence_statements
                    }
                })
            }
            $group = $groups[$key]
            $entry = $group.public
            [void]$group.record_ids.Add($id)
            $entry.finding_statement_count = [int]$entry.finding_statement_count + 1
            $severity = [string]$finding.severity
            $layer = [string]$finding.layer
            $confidence = [string]$finding.confidence
            $entry.severity_statements[$severity] = [int]$entry.severity_statements[$severity] + 1
            $entry.layer_statements[$layer] = [int]$entry.layer_statements[$layer] + 1
            $entry.confidence_statements[$confidence] = [int]$entry.confidence_statements[$confidence] + 1
            $rank = Get-CodeShowTriageSeverityRank -Severity $severity
            if ($rank -lt $group.severity_rank) {
                $group.severity_rank = $rank
                $entry.highest_reported_severity = $severity
            }
            $anchor = Get-CodeShowTraceAnchor -Finding $finding -SourceMode $mode
            $anchorKey = Get-CodeCompareAnchorKey -Anchor $anchor
            if (-not $group.anchor_records.ContainsKey($anchorKey)) {
                $group.anchor_records.Add($anchorKey, [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal))
            }
            [void]$group.anchor_records[$anchorKey].Add($id)
        }
        if (-not $selectedScope -and $included -ge $Limit) { $limitReached = $true; break }
    }

    # Discard ALL counters if the local record inventory changed during scan.
    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during Triage.'
    }

    # Rank only the current page OR explicitly chosen set, never the whole store.
    # Prefix numeric order so a SortedDictionary with Ordinal comparison
    # provides predictable ordering independent of host locale.
    $ranked = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($group in $groups.Values) {
        $entry = $group.public
        $entry.reporting_record_count = $group.record_ids.Count
        $sortedReportIds = [System.Collections.Generic.List[string]]::new()
        $reportIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($recordId in $group.record_ids) { [void]$reportIds.Add($recordId) }
        foreach ($recordId in $reportIds) { $sortedReportIds.Add($recordId) }
        $entry.reporting_record_ids = $sortedReportIds.ToArray()
        $entry.distinct_exact_anchor_count = $group.anchor_records.Count
        foreach ($recordSet in $group.anchor_records.Values) {
            if ($recordSet.Count -gt 1) { $entry.cross_record_exact_anchor_count++ }
        }
        # No more than 24 checked records x 40 statements can be scanned.
        $sortKey = ('{0:D1}:{1:D2}:{2:D4}:{3}' -f [int]$group.severity_rank, `
            ($script:CodeShowTriageWindowRecords - $group.record_ids.Count), `
            ($script:CodeShowTriageWindowRecords * 40 - $entry.finding_statement_count), $group.key)
        $ranked.Add($sortKey, $entry)
    }
    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($sortKey in $ranked.Keys) {
        if ($selected.Count -ge $Top) { break }
        $selected.Add($ranked[$sortKey])
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
        New-CodeShowTriageCursor -QueryHash $QueryHash -RecordId $lastScannedId
    } else { $null }
    return New-CodeShowTriageResult -VerifiedRoot $VerifiedRoot -Limit $Limit -Top $Top `
        -SourceMode $SourceMode -RecordCount $allIds.Count -ScannedCount $scanned `
        -IncludedCount $included -RecordsWithFindings $recordsWithFindings `
        -FindingCount $findingCount -TotalGroups $groups.Count -PathGroups $selected.ToArray() `
        -Cursor $Cursor -NextCursor $nextCursor `
        -WindowExhausted ($scanned -ge $script:CodeShowTriageWindowRecords -and $hasMoreCandidates -and -not $limitReached) `
        -HasMoreCandidates $hasMoreCandidates -SelectedRecordIds $SelectedRecordIds
}

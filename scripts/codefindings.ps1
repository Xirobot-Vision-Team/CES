#requires -Version 7.0
<#
    EC-010 / EC-020: Read-only, bounded Finding view over CodeSaved data.
    The original fc1 page cursor is root/filter bound, not a signature,
    snapshot lock or authentication proof. EC-020 adds exact selected-record
    search across SHA pages without reading unselected record bodies. Selected
    queries verify every chosen body and count omitted matching rows when the
    output -Limit is reached; the selected set has no pagination cursor.
#>

$script:CodeShowFindingWindowRecords = 32
$script:CodeShowFindingCursorPattern = '^fc1-([0-9a-f]{64})-(ci-[0-9a-f]{64})-([A-Za-z][A-Za-z0-9_-]{0,31}|~)$'

$script:CodeShowFindingMaxSelectedRecords = 24

function Parse-CodeShowFindingsRecordIds {
    param([AllowNull()][string] $Value)

    # ONE literal comma-separated argument, no whitespace, duplicate IDs,
    # empty fields, uppercase or abbreviated hexadecimal record selectors.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 1631) {
        throw 'FindingsRecordIds requires 2..24 full, distinct lowercase ci-SHA256 IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowFindingMaxSelectedRecords) {
        throw 'FindingsRecordIds requires 2..24 comma-separated saved IDs.'
    }
    $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $sorted.Add($part)) {
            throw 'FindingsRecordIds contains an invalid, repeated or non-lowercase saved ID.'
        }
    }
    foreach ($id in $sorted) { Write-Output $id }
}

function Test-CodeShowFindingFilters {
    param(
        [System.Collections.IDictionary] $Finding,
        [string] $SavedSourceMode,
        [string] $Severity,
        [string] $Layer,
        [string] $Path,
        [string] $SourceMode
    )
    if (-not [string]::IsNullOrEmpty($Severity) -and $Finding.severity -cne $Severity) { return $false }
    if (-not [string]::IsNullOrEmpty($Layer) -and $Finding.layer -cne $Layer) { return $false }
    if (-not [string]::IsNullOrEmpty($Path) -and $Finding.path -cne $Path) { return $false }
    if (-not [string]::IsNullOrEmpty($SourceMode) -and $SavedSourceMode -cne $SourceMode) { return $false }
    return $true
}

function New-CodeShowFindingRow {
    param([object] $CheckedRecord, [System.Collections.IDictionary] $Finding)
    return [ordered]@{
        record_id = $CheckedRecord.id
        record_sha256 = $CheckedRecord.sha256
        source_mode = $CheckedRecord.record.source_mode
        saved_collect_sha256 = $CheckedRecord.record.saved_collect_sha256
        packet_sha256 = $CheckedRecord.record.packet_sha256
        finding = $Finding
    }
}

function Parse-CodeShowFindingCursor {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    if (-not ($Value -cmatch $script:CodeShowFindingCursorPattern)) {
        throw 'AfterFindingCursor must be a CES fc1 token returned by a prior Findings page.'
    }
    return [pscustomobject]@{
        filter_sha256 = [string]$Matches[1]
        record_id = [string]$Matches[2]
        finding_id = [string]$Matches[3]
    }
}

function Get-CodeShowFindingFilterHash {
    param(
        [string] $VerifiedRoot,
        [string] $Severity,
        [string] $Layer,
        [string] $Path,
        [string] $SourceMode
    )
    # Unambiguous length-prefixing prevents two different filter tuples from
    # producing the same canonical bytes through separator injection.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($piece in @('ces.finding_cursor.v1', $VerifiedRoot, $Severity, $Layer, $Path, $SourceMode)) {
        $part = [string]$piece
        [void]$builder.Append($part.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($part)
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    return Get-HashOfBytes -Bytes $bytes
}

function New-CodeShowFindingCursor {
    param([string] $FilterHash, [string] $RecordId, [string] $FindingId)
    return ('fc1-{0}-{1}-{2}' -f $FilterHash, $RecordId, $FindingId)
}

function Get-CodeShowFindingsPage {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [int] $Limit,
        [AllowNull()][object] $Cursor,
        [string] $FilterHash,
        [string] $Severity,
        [string] $Layer,
        [string] $Path,
        [string] $SourceMode,
        [string[]] $SelectedRecordIds = @()
    )
    if ($SelectedRecordIds.Count -gt 0) {
        if ($null -ne $Cursor) {
            throw 'CODE_SHOW_FINDINGS_SELECTION_INVALID: selection and cursor cannot be combined.'
        }
        $selectedResult = Get-CodeShowFindingsSelected -Directory $Directory -VerifiedRoot $VerifiedRoot `
            -Limit $Limit -Severity $Severity -Layer $Layer -Path $Path `
            -SourceMode $SourceMode -SelectedRecordIds $SelectedRecordIds
        return $selectedResult
    }
    $allIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if ($null -ne $Cursor -and -not ($allIds -ccontains $Cursor.record_id)) {
        throw 'CODE_SHOW_CURSOR_STALE: the cursor record is no longer present in this CES store.'
    }

    $hits = [System.Collections.Generic.List[object]]::new()
    $scannedRecords = 0
    $scannedFindings = 0
    $stopByLimit = $false
    $stopByWindow = $false
    $lastCursor = $null

    foreach ($id in $allIds) {
        if ($null -ne $Cursor) {
            $compared = [string]::Compare($id, $Cursor.record_id, [System.StringComparison]::Ordinal)
            if ($compared -lt 0 -or ($compared -eq 0 -and $Cursor.finding_id -ceq '~')) { continue }
        }
        if ($scannedRecords -ge $script:CodeShowFindingWindowRecords) {
            $stopByWindow = $true
            break
        }
        # Even when a filter excludes a record, verify its full schema and
        # digest: otherwise a bad record could silently look like no finding.
        $checked = Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        $scannedRecords++
        $sorted = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
        foreach ($finding in $checked.record.checked_findings) {
            $sorted.Add([string]$finding.id, $finding)
        }
        if ($null -ne $Cursor -and $id -ceq $Cursor.record_id -and
            $Cursor.finding_id -cne '~' -and -not $sorted.ContainsKey($Cursor.finding_id)) {
            throw 'CODE_SHOW_CURSOR_STALE: the cursor finding is no longer present in its record.'
        }
        foreach ($item in $sorted.GetEnumerator()) {
            if ($null -ne $Cursor -and $id -ceq $Cursor.record_id -and
                [string]::Compare($item.Key, $Cursor.finding_id, [System.StringComparison]::Ordinal) -le 0) {
                continue
            }
            $scannedFindings++
            $finding = $item.Value
            if (-not (Test-CodeShowFindingFilters -Finding $finding `
                -SavedSourceMode $checked.record.source_mode -Severity $Severity `
                -Layer $Layer -Path $Path -SourceMode $SourceMode)) { continue }

            $hits.Add((New-CodeShowFindingRow -CheckedRecord $checked -Finding $finding))
            $lastCursor = New-CodeShowFindingCursor -FilterHash $FilterHash -RecordId $id -FindingId $item.Key
            if ($hits.Count -ge $Limit) {
                $stopByLimit = $true
                break
            }
        }
        if ($stopByLimit) { break }
        # This entire record has now been checked, including zero-match or
        # zero-finding records. ~ is an end-of-record sentinel (not a finding).
        $lastCursor = New-CodeShowFindingCursor -FilterHash $FilterHash -RecordId $id -FindingId '~'
    }

    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during Finding pagination.'
    }
    $hasMoreCandidates = $stopByLimit -or $stopByWindow
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Findings'
        selection_scope = 'scan_window'
        selected_record_ids = $null
        selected_record_count = $null
        counts_scope = 'only_the_current_scan_page_not_the_whole_store'
        matched_finding_count = $null
        omitted_matching_count = $null
        results_truncated = $null
        findings = $hits.ToArray()
        returned_count = $hits.Count
        record_count = $allIds.Count
        scanned_record_count = $scannedRecords
        scanned_finding_count = $scannedFindings
        scan_window_records = $script:CodeShowFindingWindowRecords
        scan_window_exhausted = $stopByWindow
        limit = $Limit
        filters = [ordered]@{
            severity = if ([string]::IsNullOrEmpty($Severity)) { $null } else { $Severity }
            layer = if ([string]::IsNullOrEmpty($Layer)) { $null } else { $Layer }
            path_exact = if ([string]::IsNullOrEmpty($Path)) { $null } else { $Path }
            source_mode = if ([string]::IsNullOrEmpty($SourceMode)) { $null } else { $SourceMode }
        }
        after_finding_cursor = if ($null -eq $Cursor) { $null } else {
            New-CodeShowFindingCursor -FilterHash $Cursor.filter_sha256 -RecordId $Cursor.record_id -FindingId $Cursor.finding_id
        }
        next_after_finding_cursor = if ($hasMoreCandidates) { $lastCursor } else { $null }
        has_more_candidates = [bool]$hasMoreCandidates
        record_integrity_verified = $true
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        snapshot_atomic = $false
    }
}

# EC-020: this is an independent bounded selection, not a continuation of fc1.
# Complete all chosen integrity checks and full match counts before publishing
# even the first returned row; if any chosen member fails, the caller discards
# the entire result. -Limit caps disclosure, NOT the selected-body scan.
function Get-CodeShowFindingsSelected {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [int] $Limit,
        [string] $Severity,
        [string] $Layer,
        [string] $Path,
        [string] $SourceMode,
        [string[]] $SelectedRecordIds
    )
    if ($Limit -lt 1 -or $Limit -gt $script:CodeShowMaxPageSize -or
        $null -eq $SelectedRecordIds -or $SelectedRecordIds.Count -lt 2 -or
        $SelectedRecordIds.Count -gt $script:CodeShowFindingMaxSelectedRecords) {
        throw 'CODE_SHOW_FINDINGS_SELECTION_INVALID: expected 2..24 IDs and -Limit 1..100.'
    }
    # Direct-module callers receive the same exactness and duplicate checks as
    # the CLI. Sorting the set fixes output order independent of user input.
    $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($id in $SelectedRecordIds) {
        Assert-CodeShowRecordId -Id $id
        if (-not $sorted.Add($id)) {
            throw 'CODE_SHOW_FINDINGS_SELECTION_INVALID: duplicate selected record ID.'
        }
    }
    $selected = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $sorted) { $selected.Add($id) }

    $allIds = @(Get-CodeShowRecordIds -Directory $Directory)
    # This full membership check precedes every selected record-body read.
    foreach ($id in $selected) {
        if (-not ($allIds -ccontains $id)) {
            throw "CODE_SHOW_FINDINGS_RECORD_NOT_FOUND: $id is absent from the verified inventory."
        }
    }

    $hits = [System.Collections.Generic.List[object]]::new()
    $matched = 0
    $scannedFindings = 0
    foreach ($id in $selected) {
        $checked = Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        # Even a source-mode-excluded record must pass the entire saved v1
        # shape, digest, second read, and full set of checked Findings.
        $findings = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
        foreach ($finding in $checked.record.checked_findings) {
            $findings.Add([string]$finding.id, $finding)
        }
        foreach ($item in $findings.GetEnumerator()) {
            $scannedFindings++
            if (-not (Test-CodeShowFindingFilters -Finding $item.Value `
                -SavedSourceMode $checked.record.source_mode -Severity $Severity `
                -Layer $Layer -Path $Path -SourceMode $SourceMode)) { continue }
            $matched++
            if ($hits.Count -lt $Limit) {
                $hits.Add((New-CodeShowFindingRow -CheckedRecord $checked -Finding $item.Value))
            }
        }
    }

    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during selected Finding search.'
    }
    $omitted = $matched - $hits.Count
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Findings'
        selection_scope = 'selected_record_ids'
        selected_record_ids = $selected.ToArray()
        selected_record_count = $selected.Count
        counts_scope = 'only_the_explicitly_selected_records_not_the_whole_store'
        matched_finding_count = $matched
        omitted_matching_count = $omitted
        results_truncated = ($omitted -gt 0)
        findings = $hits.ToArray()
        returned_count = $hits.Count
        record_count = $allIds.Count
        scanned_record_count = $selected.Count
        scanned_finding_count = $scannedFindings
        scan_window_records = $null
        scan_window_exhausted = $false
        limit = $Limit
        filters = [ordered]@{
            severity = if ([string]::IsNullOrEmpty($Severity)) { $null } else { $Severity }
            layer = if ([string]::IsNullOrEmpty($Layer)) { $null } else { $Layer }
            path_exact = if ([string]::IsNullOrEmpty($Path)) { $null } else { $Path }
            source_mode = if ([string]::IsNullOrEmpty($SourceMode)) { $null } else { $SourceMode }
        }
        after_finding_cursor = $null
        next_after_finding_cursor = $null
        has_more_candidates = $false
        record_integrity_verified = $true
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        snapshot_atomic = $false
    }
}

#requires -Version 7.0
<#
    EC-012/EC-019: Trace one exact saved quotation anchor in bounded SHA-ID
    scan windows OR across 2..24 explicitly selected saved record IDs.
    The caller selects a real seed RecordId and exact FindingId; CES derives
    the anchor only from that validated saved Finding. Selected sets include
    their seed and are fully verified without reading other record bodies.

    Output is historical model-reported occurrence, NOT issue identity, a
    chronology, a regression/fix, current source validation or a source read.
    Each matching record retains ALL same-anchor Finding interpretations.
#>

$script:CodeShowTraceWindowRecords = 24
$script:CodeShowTraceCursorPattern = '^tc1-([0-9a-f]{64})-(ci-[0-9a-f]{64})$'

function Parse-CodeShowTraceRecordIds {
    param([AllowNull()][string] $Value)
    # One literal native-shell argument: 24 IDs * 67 characters + 23 commas.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 1631) {
        throw 'TraceRecordIds requires 2..24 exact, distinct saved ci-SHA256 IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowTraceWindowRecords) {
        throw 'TraceRecordIds requires 2..24 distinct saved ci-SHA256 IDs.'
    }
    $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $sorted.Add($part)) {
            throw 'TraceRecordIds must use unique lowercase ci-SHA256 IDs, with no whitespace.'
        }
    }
    foreach ($id in $sorted) { Write-Output $id }
}

function Parse-CodeShowTraceCursor {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    if (-not ($Value -cmatch $script:CodeShowTraceCursorPattern)) {
        throw 'AfterTraceCursor must be a CES tc1 token returned by a previous Trace page.'
    }
    return [pscustomobject]@{
        query_sha256 = [string]$Matches[1]
        record_id = [string]$Matches[2]
    }
}

function New-CodeShowTraceCursor {
    param([string] $QueryHash, [string] $RecordId)
    return ('tc1-{0}-{1}' -f $QueryHash, $RecordId)
}

function Get-CodeShowTraceAnchor {
    param([System.Collections.IDictionary] $Finding, [string] $SourceMode)
    return [ordered]@{
        source_mode = $SourceMode
        layer = [string]$Finding.layer
        path = [string]$Finding.path
        path_endpoint = [string]$Finding.path_endpoint
        quote_sha256 = [string]$Finding.quote_sha256
        quote_presence = [string]$Finding.quote_presence
    }
}

function Get-CodeShowTraceQueryHash {
    param(
        [string] $VerifiedRoot,
        [string] $SeedRecordId,
        [string] $SeedFindingId,
        [string] $AnchorKey
    )
    # All five strings are length-prefixed to prevent ambiguous concatenations.
    # This digest binds pagination to the main root + immutable seed + anchor;
    # it is a query discriminator, NOT a signed or authenticated cursor.
    $builder = [System.Text.StringBuilder]::new()
    foreach ($value in @('ces.trace_cursor.v1', $VerifiedRoot, $SeedRecordId, $SeedFindingId, $AnchorKey)) {
        $part = [string]$value
        [void]$builder.Append($part.Length)
        [void]$builder.Append(':')
        [void]$builder.Append($part)
    }
    return Get-HashOfBytes -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function Get-CodeShowTracePage {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [string] $SeedRecordId,
        [string] $SeedFindingId,
        [int] $Limit,
        [AllowNull()][object] $Cursor,
        [string[]] $SelectedRecordIds = @()
    )

    $selectedScope = ($SelectedRecordIds.Count -gt 0)
    if ($selectedScope) {
        # Direct-module callers cannot bypass selected-mode limits or safety.
        if ($SelectedRecordIds.Count -lt 2 -or
            $SelectedRecordIds.Count -gt $script:CodeShowTraceWindowRecords -or
            $null -ne $Cursor -or $Limit -ne 50) {
            throw 'CODE_SHOW_TRACE_SELECTION_INVALID: expected 2..24 IDs, no cursor and default Limit.'
        }
        $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($id in $SelectedRecordIds) {
            Assert-CodeShowRecordId -Id $id
            if (-not $sorted.Add($id)) {
                throw 'CODE_SHOW_TRACE_SELECTION_INVALID: duplicate selected record ID.'
            }
        }
        if (-not $sorted.Contains($SeedRecordId)) {
            throw 'CODE_SHOW_TRACE_SELECTION_INVALID: seed ID must be selected.'
        }
        $sortedIds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in $sorted) { $sortedIds.Add($id) }
        $SelectedRecordIds = $sortedIds.ToArray()
    }

    # Verify the bounded full filename inventory and ALL explicitly selected
    # memberships before opening any selected body (including the seed).
    $allIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if ($selectedScope) {
        foreach ($id in $SelectedRecordIds) {
            if (-not ($allIds -ccontains $id)) {
                throw 'CODE_SHOW_TRACE_RECORD_NOT_FOUND: a selected record is absent.'
            }
        }
    } elseif (-not ($allIds -ccontains $SeedRecordId)) {
        throw 'CODE_SHOW_TRACE_SEED_NOT_FOUND: the selected saved seed record is absent.'
    }
    if ($null -ne $Cursor -and -not ($allIds -ccontains $Cursor.record_id)) {
        throw 'CODE_SHOW_CURSOR_STALE: the Trace cursor record no longer exists.'
    }

    $seed = Read-CodeShowRecord -Directory $Directory -Id $SeedRecordId -VerifiedRoot $VerifiedRoot
    $seedFinding = $null
    foreach ($finding in $seed.record.checked_findings) {
        if ([string]::Equals([string]$finding.id, $SeedFindingId, [System.StringComparison]::Ordinal)) {
            $seedFinding = $finding
            break
        }
    }
    if ($null -eq $seedFinding) {
        throw 'CODE_SHOW_TRACE_FINDING_NOT_FOUND: the exact, case-sensitive seed Finding ID was not found.'
    }
    $anchor = Get-CodeShowTraceAnchor -Finding $seedFinding -SourceMode ([string]$seed.record.source_mode)
    $anchorKey = Get-CodeCompareAnchorKey -Anchor $anchor
    $queryHash = Get-CodeShowTraceQueryHash -VerifiedRoot $VerifiedRoot -SeedRecordId $SeedRecordId -SeedFindingId $SeedFindingId -AnchorKey $anchorKey
    if ($null -ne $Cursor -and $Cursor.query_sha256 -cne $queryHash) {
        throw 'CODE_SHOW_TRACE_CURSOR_MISMATCH: token belongs to a different root or seed anchor.'
    }

    $hits = [System.Collections.Generic.List[object]]::new()
    $scannedRecords = 0
    $scannedFindings = 0
    $lastScannedId = $null
    $limitReached = $false
    $candidateIds = if ($selectedScope) { @($SelectedRecordIds) } else { $allIds }
    foreach ($id in $candidateIds) {
        if ($null -ne $Cursor -and
            [string]::Compare($id, $Cursor.record_id, [System.StringComparison]::Ordinal) -le 0) {
            continue
        }
        if ($scannedRecords -ge $script:CodeShowTraceWindowRecords) { break }
        $checked = if ($id -ceq $SeedRecordId) { $seed } else {
            Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot
        }
        $scannedRecords++
        $lastScannedId = $id
        $scannedFindings += $checked.record.checked_findings.Count

        # An unrelated source mode is still read and schema-checked, but its
        # Findings cannot be reported as an occurrence of the seed anchor.
        $matching = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
        if ($checked.record.source_mode -ceq $anchor.source_mode) {
            foreach ($finding in $checked.record.checked_findings) {
                $candidate = Get-CodeShowTraceAnchor -Finding $finding -SourceMode ([string]$checked.record.source_mode)
                if (-not [string]::Equals((Get-CodeCompareAnchorKey -Anchor $candidate), $anchorKey, [System.StringComparison]::Ordinal)) { continue }
                $matching.Add([string]$finding.id, [ordered]@{
                    id = $finding.id
                    title = $finding.title
                    severity = $finding.severity
                    confidence = $finding.confidence
                    line_start_claimed = $finding.line_start_claimed
                    line_end_claimed = $finding.line_end_claimed
                    line_numbers_verified = $false
                    reasoning = $finding.reasoning
                    impact = $finding.impact
                    recommendation = $finding.recommendation
                })
            }
        }
        if ($matching.Count -gt 0) {
            $statements = [System.Collections.Generic.List[object]]::new()
            foreach ($key in $matching.Keys) { $statements.Add($matching[$key]) }
            $hits.Add([ordered]@{
                record_id = $checked.id
                record_sha256 = $checked.sha256
                source_mode = $checked.record.source_mode
                saved_collect_sha256 = $checked.record.saved_collect_sha256
                packet_sha256 = $checked.record.packet_sha256
                matching_finding_count = $matching.Count
                findings = $statements.ToArray()
            })
            # Limit is in MATCHING RECORDS, not Finding statements. Never
            # truncate multiple statements from a matching record.
            if (-not $selectedScope -and $hits.Count -ge $Limit) {
                $limitReached = $true
                break
            }
        }
    }

    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($allIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during Trace.'
    }
    # Recheck the identity source after scanning; its byte-name digest and
    # exact Finding anchor must still be valid, even across later pages.
    $seedAgain = Read-CodeShowRecord -Directory $Directory -Id $SeedRecordId -VerifiedRoot $VerifiedRoot
    if ($seedAgain.sha256 -cne $seed.sha256) {
        throw 'CES Trace seed changed during the scan.'
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
    $lastCursor = if ($hasMoreCandidates) { New-CodeShowTraceCursor -QueryHash $queryHash -RecordId $lastScannedId } else { $null }
    return [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Trace'
        trace_basis = 'exact_saved_finding_quote_anchor'
        selection_scope = if ($selectedScope) { 'selected_record_ids' } else { 'scan_window' }
        selected_record_count = if ($selectedScope) { $SelectedRecordIds.Count } else { $null }
        selected_record_ids = if ($selectedScope) { @($SelectedRecordIds) } else { @() }
        counts_scope = if ($selectedScope) {
            'only_the_explicitly_selected_records_not_the_whole_store'
        } else { 'this_page_only_not_cumulative_or_store_wide' }
        seed = [ordered]@{
            record_id = $seed.id
            record_sha256 = $seed.sha256
            finding_id = $SeedFindingId
            source_mode = $seed.record.source_mode
        }
        anchor = $anchor
        matches = $hits.ToArray()
        returned_record_count = $hits.Count
        record_count = $allIds.Count
        scanned_record_count = $scannedRecords
        scanned_finding_count = $scannedFindings
        scan_window_records = $script:CodeShowTraceWindowRecords
        scan_window_exhausted = (-not $selectedScope -and $scannedRecords -ge $script:CodeShowTraceWindowRecords -and $hasMoreCandidates -and -not $limitReached)
        limit = if ($selectedScope) { $null } else { $Limit }
        after_trace_cursor = if ($null -eq $Cursor) { $null } else {
            New-CodeShowTraceCursor -QueryHash $Cursor.query_sha256 -RecordId $Cursor.record_id
        }
        next_after_trace_cursor = $lastCursor
        has_more_candidates = [bool]$hasMoreCandidates
        explanation = if ($selectedScope) {
            'Matches cover only the explicitly selected, fully checked historical saved records, which may cross SHA scan windows. Unselected record bodies were not inspected. Identical saved quote anchors do not prove authenticated findings, a live defect, chronological issue history or store-wide absence.'
        } else {
            'Matches are identical saved quotation anchors, not authenticated findings or a time-ordered issue lifecycle. Zero matches in this window do not exclude matches in later windows.'
        }
        record_integrity_verified = $true
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        claimed_lines_verified = $false
        snapshot_atomic = $false
    }
}

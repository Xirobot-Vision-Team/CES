#requires -Version 7.0
<#
    EC-039: An exact, read-only Finding-reference bridge for focused Sequence.
    The only input is the already validated saved CodeInsight record states and
    EC-034 complete exact-anchor journeys. No stored body is opened here.

    Finding IDs are scoped to their OWN saved record. The same spelling in
    two reports is not a shared issue, model claim or verified source defect.
    Only the bounded IDs, five severity labels and canonical anchor indexes
    are returned; no Finding prose, quotation, original source or patch.
#>

function Get-CodeSequenceFocusedAnchorFindingRefs {
    param(
        [object[]] $States,
        [string] $Path,
        [object] $Journeys
    )

    $count = $States.Count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($Path) -or $Path.Length -gt 4096 -or
        $Path.IndexOf([char]0) -ge 0 -or $null -eq $Journeys -or
        $Journeys.path -cne $Path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        [int]$Journeys.selected_record_count -ne $count -or
        $Journeys.position_totals.Count -ne $count -or
        $Journeys.anchors.Count -gt ($count * 40) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $Journeys.anchors.Count -or
        [bool]$Journeys.path_found_in_selected_records -ne ($Journeys.anchors.Count -gt 0)) {
        throw 'Code Sequence focused Finding references require complete, checked exact-anchor journeys.'
    }

    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $anchorCount = $Journeys.anchors.Count
    $indexByAnchorKey = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $refsByAnchor = [object[]]::new($anchorCount)
    $lastKey = $null
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $journey = $Journeys.anchors[$a]
        if ($journey.anchor.path -cne $Path -or
            $journey.observations_in_caller_order.Count -ne $count) {
            throw 'Code Sequence focused Finding reference anchor path or observations changed.'
        }
        $key = Get-CodeCompareAnchorKey -Anchor $journey.anchor
        if ($null -ne $lastKey -and [string]::CompareOrdinal($lastKey, $key) -ge 0) {
            throw 'Code Sequence focused Finding reference anchors are not in canonical ordinal order.'
        }
        if ($indexByAnchorKey.ContainsKey($key)) {
            throw 'Code Sequence focused Finding references include a duplicate anchor.'
        }
        $indexByAnchorKey.Add($key, $a + 1)
        $lastKey = $key
        $refsByAnchor[$a] = [System.Collections.Generic.List[object]]::new()
    }

    $positions = [System.Collections.Generic.List[object]]::new()
    $totalRefs = 0
    $reportedAnchorPositions = 0
    $positionsWithFindings = 0
    for ($i = 0; $i -lt $count; $i++) {
        $state = $States[$i]
        $recordId = [string]$state.checked.id
        $expectedPosition = $Journeys.position_totals[$i]
        if ([int]$expectedPosition.position -ne ($i + 1) -or
            $expectedPosition.record_id -cne $recordId -or
            $state.checked.record.finding_count -gt 40 -or
            $state.groups.Count -gt 40) {
            throw 'Code Sequence focused Finding references have a mismatched checked record position.'
        }
        $byPath = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $groups = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        if ($byPath.ContainsKey($Path)) { $groups = $byPath[$Path] }
        $positionAnchors = [System.Collections.Generic.SortedSet[int]]::new()
        $byFindingId = [System.Collections.Generic.SortedDictionary[string,object]]::new([System.StringComparer]::Ordinal)
        $idsIgnoringCase = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $severityCounts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }

        # Use the checked in-memory grouping, NEVER a new saved-file read.
        foreach ($key in $groups.Keys) {
            $index = 0
            if (-not $indexByAnchorKey.ContainsKey($key)) {
                throw 'Code Sequence focused Finding references encountered an unknown exact anchor.'
            }
            $index = $indexByAnchorKey[$key]
            $group = $groups[$key]
            if ($group.anchor.path -cne $Path -or
                (Get-CodeCompareAnchorKey -Anchor $group.anchor) -cne $key -or
                -not $positionAnchors.Add($index)) {
                throw 'Code Sequence focused Finding references have duplicate or changed anchor membership.'
            }
            $groupRefs = [System.Collections.Generic.List[object]]::new()
            $groupHistogram = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
            foreach ($findingId in $group.findings.Keys) {
                $finding = $group.findings[$findingId]
                $severity = [string]$finding.severity
                if ($finding.id -cne $findingId -or -not ($severityNames -ccontains $severity) -or
                    $byFindingId.ContainsKey($findingId) -or -not $idsIgnoringCase.Add($findingId)) {
                    throw 'Code Sequence focused Finding references found an invalid or duplicate saved Finding ID.'
                }
                $groupHistogram[$severity] = [int]$groupHistogram[$severity] + 1
                $severityCounts[$severity] = [int]$severityCounts[$severity] + 1
                $groupRefs.Add([ordered]@{ finding_id = $findingId; severity = $severity })
                $byFindingId.Add($findingId, [ordered]@{
                    finding_id = $findingId
                    anchor_index_in_anchor_journeys = $index
                    severity = $severity
                })
            }
            $journey = $Journeys.anchors[$index - 1]
            $observation = $journey.observations_in_caller_order[$i]
            if ([int]$observation.position -ne ($i + 1) -or
                $observation.record_id -cne $recordId -or
                -not [bool]$observation.reported -or
                [int]$observation.finding_statement_count -ne $groupRefs.Count -or
                -not (Test-CodeSequenceFocusedSeverityEqual -Left $observation.severity_statement_counts -Right $groupHistogram)) {
                throw 'Code Sequence focused Finding references contradict a saved exact-anchor observation.'
            }
            $refsByAnchor[$index - 1].Add([ordered]@{
                position = $i + 1
                record_id = $recordId
                finding_statement_count = $groupRefs.Count
                finding_refs = $groupRefs.ToArray()
            })
        }

        # Independently re-partition ALL checked Findings at the literal path
        # from the same in-memory record. This catches omissions or an ID
        # accidentally attached to the wrong exact six-field anchor.
        $actualInSourceRecord = 0
        foreach ($finding in $state.checked.record.checked_findings) {
            if ($finding.path -cne $Path) { continue }
            $actualInSourceRecord++
            $id = [string]$finding.id
            if (-not $byFindingId.ContainsKey($id) -or
                $byFindingId[$id].severity -cne $finding.severity) {
                throw 'Code Sequence focused Finding reference mapping differs from the checked saved record.'
            }
            $sourceAnchor = [ordered]@{
                source_mode = [string]$state.checked.record.source_mode
                layer = [string]$finding.layer
                path = [string]$finding.path
                path_endpoint = [string]$finding.path_endpoint
                quote_sha256 = [string]$finding.quote_sha256
                quote_presence = [string]$finding.quote_presence
            }
            $originalKey = Get-CodeCompareAnchorKey -Anchor $sourceAnchor
            $originalIndex = 0
            if (-not $indexByAnchorKey.ContainsKey($originalKey)) {
                throw 'Code Sequence focused Finding reference original quote anchor is absent.'
            }
            $originalIndex = $indexByAnchorKey[$originalKey]
            if ([int]$byFindingId[$id].anchor_index_in_anchor_journeys -ne $originalIndex) {
                throw 'Code Sequence focused Finding reference attached a saved Finding to the wrong anchor.'
            }
        }

        $positionRefs = [System.Collections.Generic.List[object]]::new()
        foreach ($id in $byFindingId.Keys) { $positionRefs.Add($byFindingId[$id]) }
        if ($actualInSourceRecord -ne $positionRefs.Count -or
            [int]$expectedPosition.finding_statement_count -ne $positionRefs.Count -or
            [int]$expectedPosition.reported_exact_anchor_count -ne $positionAnchors.Count -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $expectedPosition.severity_statement_counts -Right $severityCounts)) {
            throw 'Code Sequence focused Finding references do not conserve per-record checked Finding statements.'
        }
        # Check absence as well, not just presence. The zero rows are real
        # observations in selected model reports, not source-state proof.
        for ($a = 0; $a -lt $anchorCount; $a++) {
            $observation = $Journeys.anchors[$a].observations_in_caller_order[$i]
            if ([int]$observation.position -ne ($i + 1) -or
                $observation.record_id -cne $recordId -or
                [bool]$observation.reported -ne $positionAnchors.Contains($a + 1) -or
                (-not [bool]$observation.reported -and
                    ([int]$observation.finding_statement_count -ne 0 -or
                     $null -ne $observation.severity_statement_counts))) {
                throw 'Code Sequence focused Finding reference membership contradicts a non-reported anchor observation.'
            }
        }
        if ($positionRefs.Count -gt 0) { $positionsWithFindings++ }
        $totalRefs += $positionRefs.Count
        $reportedAnchorPositions += $positionAnchors.Count
        $positionAnchorArray = [System.Collections.Generic.List[int]]::new()
        foreach ($index in $positionAnchors) { $positionAnchorArray.Add($index) }
        $positions.Add([ordered]@{
            position = $i + 1
            record_id = $recordId
            reported_anchor_indices_in_anchor_journeys = $positionAnchorArray.ToArray()
            finding_statement_count = $positionRefs.Count
            severity_statement_counts = $severityCounts
            finding_refs = $positionRefs.ToArray()
        })
    }

    $anchors = [System.Collections.Generic.List[object]]::new()
    $anchorRefTotal = 0
    $anchorPositionTotal = 0
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $journey = $Journeys.anchors[$a]
        $anchorPositions = $refsByAnchor[$a]
        $anchorFindingRefs = 0
        foreach ($row in $anchorPositions) { $anchorFindingRefs += [int]$row.finding_statement_count }
        if ($anchorPositions.Count -ne [int]$journey.reporting_record_count -or
            $anchorFindingRefs -ne [int]$journey.finding_statement_occurrences) {
            throw 'Code Sequence focused Finding references do not conserve per-anchor saved statements.'
        }
        $anchorRefTotal += $anchorFindingRefs
        $anchorPositionTotal += $anchorPositions.Count
        $anchors.Add([ordered]@{
            anchor_index_in_anchor_journeys = $a + 1
            presence_pattern = [string]$journey.presence_pattern
            reporting_record_count = $anchorPositions.Count
            finding_statement_occurrences = $anchorFindingRefs
            references_in_caller_order = $anchorPositions.ToArray()
        })
    }
    if ($anchorRefTotal -ne $totalRefs -or
        $totalRefs -ne [int]$Journeys.counts.finding_statement_occurrences -or
        $anchorPositionTotal -ne $reportedAnchorPositions -or
        $anchorPositionTotal -ne [int]$Journeys.counts.reported_exact_anchor_position_occurrences) {
        throw 'Code Sequence focused Finding reference cross-index failed total conservation.'
    }
    return [ordered]@{
        scope = 'complete_saved_record_scoped_Finding_ID_navigation_for_explicit_exact_path'
        path = $Path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $count
        independent_of_sequence_top = $true
        anchor_index_reference = 'one_based_into_complete_anchor_journeys.anchors'
        finding_id_scope = 'within_own_selected_record_only_not_cross_record_identity'
        counts = [ordered]@{
            distinct_exact_anchor_union_count = $anchorCount
            reported_exact_anchor_position_occurrences = $reportedAnchorPositions
            finding_reference_occurrences = $totalRefs
            selected_positions_with_focused_findings_count = $positionsWithFindings
        }
        anchors = $anchors.ToArray()
        positions = $positions.ToArray()
        explanation = 'Each Finding reference is (record_id, finding_id), with a one-based exact-anchor index and the saved model severity label. Both complete views enumerate exactly the same bounded saved statements in caller position or canonical anchor order, including zero-Finding positions. Use CodeShow Trace/Detail for a selected saved record when permitted; Finding ID spelling across separate records has NO identity semantics. Caller order is not verified time. No Finding prose, quotes, source data, extra saved-body read, external action or write.'
    }
}

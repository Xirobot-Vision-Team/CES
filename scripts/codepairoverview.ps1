#requires -Version 7.0
<#
    EC-045: opt-in, complete PATH inventory for ONE caller-selected report pair.
    This bridges the global all-pairs summary to EC-044's one-path pair drilldown.
    All paths (including paths reported only by other selected records) are
    enumerated from already integrity-checked in-memory saved Finding groups.
    No quote, prose, source, Git object, extra stored body, network or write.
#>
function Get-CodeSequencePairOverviewSide {
    param([AllowNull()][object] $Groups, [string] $RecordId)

    $severities = @('critical', 'high', 'medium', 'low', 'info')
    if ($null -eq $Groups) {
        return [ordered]@{
            record_id = $RecordId
            reported_at_saved_path = $false
            distinct_exact_anchor_count = 0
            saved_finding_statement_count = 0
            saved_severity_statement_counts = $null
            original_record_scoped_finding_refs = @()
        }
    }
    if ($Groups.Count -lt 1 -or $Groups.Count -gt 40) {
        throw 'Code Sequence pair overview has an empty or unbounded reported path group.'
    }
    $hist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
    $refsById = [System.Collections.Generic.SortedDictionary[string,string]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $Groups.Keys) {
        $group = $Groups[$key]
        if ($null -eq $group -or $null -eq $group.findings -or $group.findings.Count -lt 1) {
            throw 'Code Sequence pair overview contains an anchor with no original saved Finding.'
        }
        foreach ($id in $group.findings.Keys) {
            $severity = [string]$group.findings[$id].severity
            if ($id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
                -not ($severities -ccontains $severity) -or $refsById.ContainsKey($id)) {
                throw 'Code Sequence pair overview contains an invalid or duplicated original scoped Finding.'
            }
            $refsById.Add($id, $severity)
            $hist[$severity] = [int]$hist[$severity] + 1
        }
    }
    if ($refsById.Count -lt $Groups.Count -or $refsById.Count -gt 40) {
        throw 'Code Sequence pair overview has impossible saved Finding/anchor multiplicity.'
    }
    $refs = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $refsById.Keys) {
        $refs.Add([ordered]@{finding_id=$id; severity=$refsById[$id]})
    }
    return [ordered]@{
        record_id = $RecordId
        reported_at_saved_path = $true
        distinct_exact_anchor_count = $Groups.Count
        saved_finding_statement_count = $refs.Count
        saved_severity_statement_counts = $hist
        original_record_scoped_finding_refs = $refs.ToArray()
    }
}

function Get-CodeSequenceGlobalPairOverview {
    param(
        [int] $PairIndex,
        [object[]] $States,
        [object] $Pairwise,
        [object] $PathIndex
    )

    $n = $States.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $null -eq $Pairwise -or $null -eq $PathIndex -or
        [int]$Pairwise.selected_record_count -ne $n -or
        [int]$Pairwise.pair_count -ne $pairCount -or
        $Pairwise.pairs.Count -ne $pairCount -or
        [int]$PathIndex.selected_record_count -ne $n -or
        [int]$Pairwise.path_disagreement.selected_record_count -ne $n) {
        throw 'Code Sequence pair overview requires complete matching checked global ledgers.'
    }
    if ($PairIndex -lt 1 -or $PairIndex -gt $pairCount) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_NOT_FOUND: pair index is outside the selected report set.'
    }

    $leftPosition = 0; $rightPosition = 0; $ordinal = 0
    for ($l = 1; $l -lt $n; $l++) {
        for ($r = $l + 1; $r -le $n; $r++) {
            $ordinal++
            if ($ordinal -eq $PairIndex) { $leftPosition = $l; $rightPosition = $r }
        }
    }
    $leftState = $States[$leftPosition - 1]
    $rightState = $States[$rightPosition - 1]
    $leftId = [string]$leftState.checked.id
    $rightId = [string]$rightState.checked.id
    $expected = $Pairwise.pairs[$PairIndex - 1]
    if ($leftPosition -lt 1 -or $rightPosition -le $leftPosition -or
        [int]$expected.left_position -ne $leftPosition -or
        [int]$expected.right_position -ne $rightPosition -or
        $expected.left_record_id -cne $leftId -or $expected.right_record_id -cne $rightId) {
        throw 'Code Sequence pair overview canonical report pair membership differs from EC-029.'
    }

    $allPaths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    $byPosition = [System.Collections.Generic.List[object]]::new()
    foreach ($state in $States) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $byPosition.Add($byPath)
        foreach ($path in $byPath.Keys) { [void]$allPaths.Add($path) }
    }
    $leftByPath = $byPosition[$leftPosition - 1]
    $rightByPath = $byPosition[$rightPosition - 1]
    if ($allPaths.Count -gt ($n * 40) -or
        [int]$PathIndex.counts.distinct_saved_path_count -ne $allPaths.Count -or
        [int]$Pairwise.path_disagreement.counts.distinct_saved_path_union_count -ne $allPaths.Count) {
        throw 'Code Sequence pair overview complete selected path union is inconsistent.'
    }

    $totals = [ordered]@{
        distinct_saved_path_union_count = $allPaths.Count
        left_reported_path_count = 0
        right_reported_path_count = 0
        retained_path_count = 0
        left_only_path_count = 0
        right_only_path_count = 0
        neither_reported_path_count = 0
        retained_path_with_anchor_churn_count = 0
        retained_path_with_severity_distribution_change_count = 0
        changed_path_count = 0
        matching_path_count = 0
        severity_histogram_only_changed_path_count = 0
        retained_exact_anchor_count = 0
        left_only_exact_anchor_count = 0
        right_only_exact_anchor_count = 0
        retained_same_severity_exact_anchor_count = 0
        retained_changed_severity_exact_anchor_count = 0
        retained_severity_distribution_changed_count = 0
        exact_anchor_symmetric_difference_count = 0
        left_finding_statement_count = 0
        right_finding_statement_count = 0
    }
    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $deltaAll = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
    $rows = [System.Collections.Generic.List[object]]::new()
    $changedIndices = [System.Collections.Generic.List[int]]::new()
    foreach ($path in $allPaths) {
        $leftPresent = $leftByPath.ContainsKey($path)
        $rightPresent = $rightByPath.ContainsKey($path)
        $leftGroups = if ($leftPresent) { $leftByPath[$path] } else { $null }
        $rightGroups = if ($rightPresent) { $rightByPath[$path] } else { $null }
        $left = Get-CodeSequencePairOverviewSide -Groups $leftGroups -RecordId $leftId
        $right = Get-CodeSequencePairOverviewSide -Groups $rightGroups -RecordId $rightId
        if ([bool]$left.reported_at_saved_path -ne $leftPresent -or
            [bool]$right.reported_at_saved_path -ne $rightPresent) {
            throw 'Code Sequence pair overview path side presence is inconsistent.'
        }
        $reportedCount = 0
        foreach ($byPath in $byPosition) { if ($byPath.ContainsKey($path)) { $reportedCount++ } }
        if ($reportedCount -lt 1 -or $reportedCount -gt $n) {
            throw 'Code Sequence pair overview returned a path without any saved report evidence.'
        }

        $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        if ($leftPresent) { foreach ($key in $leftGroups.Keys) { [void]$keys.Add($key) } }
        if ($rightPresent) { foreach ($key in $rightGroups.Keys) { [void]$keys.Add($key) } }
        $leftOnly = 0; $rightOnly = 0; $retainedSame = 0; $retainedChanged = 0
        $retainedDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        $independentAnchorDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        foreach ($key in $keys) {
            $a = $leftPresent -and $leftGroups.ContainsKey($key)
            $b = $rightPresent -and $rightGroups.ContainsKey($key)
            if ($a -and $b) {
                $leftHistogram = Get-CodeSequenceSeverities -Group $leftGroups[$key]
                $rightHistogram = Get-CodeSequenceSeverities -Group $rightGroups[$key]
                $same = $true
                foreach ($severity in $severityNames) {
                    $difference = [int]$rightHistogram[$severity] - [int]$leftHistogram[$severity]
                    $retainedDelta[$severity] = [int]$retainedDelta[$severity] + $difference
                    $independentAnchorDelta[$severity] = [int]$independentAnchorDelta[$severity] + $difference
                    if ($difference -ne 0) { $same = $false }
                }
                if ($same) { $retainedSame++ } else { $retainedChanged++ }
            } elseif ($a) {
                $leftOnly++
                $leftHistogram = Get-CodeSequenceSeverities -Group $leftGroups[$key]
                foreach ($severity in $severityNames) {
                    $independentAnchorDelta[$severity] = [int]$independentAnchorDelta[$severity] - [int]$leftHistogram[$severity]
                }
            } elseif ($b) {
                $rightOnly++
                $rightHistogram = Get-CodeSequenceSeverities -Group $rightGroups[$key]
                foreach ($severity in $severityNames) {
                    $independentAnchorDelta[$severity] = [int]$independentAnchorDelta[$severity] + [int]$rightHistogram[$severity]
                }
            } else { throw 'Code Sequence pair overview produced an unreported pair anchor.' }
        }
        if (($leftOnly + $retainedSame + $retainedChanged) -ne [int]$left.distinct_exact_anchor_count -or
            ($rightOnly + $retainedSame + $retainedChanged) -ne [int]$right.distinct_exact_anchor_count) {
            throw 'Code Sequence pair overview exact anchor conservation failed at saved path.'
        }
        $changed = ($leftOnly + $rightOnly + $retainedChanged -gt 0)
        $kind = if (-not $leftPresent -and -not $rightPresent) { 'neither_reported' }
            elseif ($leftPresent -and -not $rightPresent) { 'left_only' }
            elseif ($rightPresent -and -not $leftPresent) { 'right_only' }
            elseif ($changed) { 'retained_changed_profile' }
            else { 'retained_same_profile' }
        if ($changed) { $changedIndices.Add($rows.Count + 1); $totals.changed_path_count++ }
        else { $totals.matching_path_count++ }
        if ($leftPresent) { $totals.left_reported_path_count++ }
        if ($rightPresent) { $totals.right_reported_path_count++ }
        if ($leftPresent -and $rightPresent) { $totals.retained_path_count++ }
        if ($kind -ceq 'left_only') { $totals.left_only_path_count++ }
        if ($kind -ceq 'right_only') { $totals.right_only_path_count++ }
        if ($kind -ceq 'neither_reported') { $totals.neither_reported_path_count++ }
        if ($leftPresent -and $rightPresent -and ($leftOnly + $rightOnly -gt 0)) {
            $totals.retained_path_with_anchor_churn_count++
        }
        if ($leftPresent -and $rightPresent -and $retainedChanged -gt 0) {
            $totals.retained_path_with_severity_distribution_change_count++
        }
        if ($changed -and $leftOnly + $rightOnly -eq 0) {
            $totals.severity_histogram_only_changed_path_count++
        }
        $totals.left_only_exact_anchor_count += $leftOnly
        $totals.right_only_exact_anchor_count += $rightOnly
        $totals.retained_same_severity_exact_anchor_count += $retainedSame
        $totals.retained_changed_severity_exact_anchor_count += $retainedChanged
        $totals.retained_severity_distribution_changed_count += $retainedChanged
        $totals.retained_exact_anchor_count += $retainedSame + $retainedChanged
        $totals.left_finding_statement_count += [int]$left.saved_finding_statement_count
        $totals.right_finding_statement_count += [int]$right.saved_finding_statement_count
        $delta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        foreach ($severity in $severityNames) {
            $lv = if ($leftPresent) { [int]$left.saved_severity_statement_counts[$severity] } else { 0 }
            $rv = if ($rightPresent) { [int]$right.saved_severity_statement_counts[$severity] } else { 0 }
            $delta[$severity] = $rv - $lv
            $deltaAll[$severity] = [int]$deltaAll[$severity] + $rv - $lv
            if ([int]$independentAnchorDelta[$severity] -ne $delta[$severity]) {
                throw 'Code Sequence pair overview original Finding references and independent exact-anchor severity bins disagree.'
            }
        }
        $rows.Add([ordered]@{
            path_index = $rows.Count + 1
            path = $path
            reporting_record_count_in_selected_set = $reportedCount
            pair_path_class = $kind
            changed_exact_saved_profile = $changed
            left = $left
            right = $right
            distinct_exact_anchor_union_at_pair_endpoints = $keys.Count
            left_only_exact_anchor_count = $leftOnly
            right_only_exact_anchor_count = $rightOnly
            retained_same_severity_exact_anchor_count = $retainedSame
            retained_changed_severity_exact_anchor_count = $retainedChanged
            saved_finding_statement_count_delta_right_minus_left = [int]$right.saved_finding_statement_count - [int]$left.saved_finding_statement_count
            saved_severity_statement_delta_right_minus_left = $delta
            saved_severity_statement_delta_retained_anchors_right_minus_left = $retainedDelta
        })
    }
    $totals.exact_anchor_symmetric_difference_count = [int]$totals.left_only_exact_anchor_count + [int]$totals.right_only_exact_anchor_count
    $expectedCounts = $expected.counts
    foreach ($key in $expectedCounts.Keys) {
        if (-not $totals.Contains($key) -or [int]$totals[$key] -ne [int]$expectedCounts[$key]) {
            throw "Code Sequence pair overview does not reconcile with the complete global pair count: $key."
        }
    }
    if ($totals.changed_path_count + $totals.matching_path_count -ne $allPaths.Count -or
        $totals.retained_path_count + $totals.left_only_path_count +
            $totals.right_only_path_count + $totals.neither_reported_path_count -ne $allPaths.Count -or
        $totals.retained_same_severity_exact_anchor_count + $totals.retained_changed_severity_exact_anchor_count -ne
            $totals.retained_exact_anchor_count -or
        $changedIndices.Count -ne $totals.changed_path_count -or
        $totals.left_finding_statement_count -ne [int]$leftState.checked.record.finding_count -or
        $totals.right_finding_statement_count -ne [int]$rightState.checked.record.finding_count -or
        [bool]$expected.matches_profile -ne ($totals.changed_path_count -eq 0) -or
        [bool]$expected.severity_histogram_only_difference -ne
            ($totals.changed_path_count -gt 0 -and $totals.exact_anchor_symmetric_difference_count -eq 0)) {
        throw 'Code Sequence pair overview failed statement, pair equality or partition conservation.'
    }
    $sumDelta = 0
    foreach ($severity in $severityNames) { $sumDelta += [int]$deltaAll[$severity] }
    if ($sumDelta -ne ($totals.right_finding_statement_count - $totals.left_finding_statement_count)) {
        throw 'Code Sequence pair overview full severity histogram is inconsistent with original statement totals.'
    }
    return [ordered]@{
        scope = 'one_explicit_canonical_report_pair_all_saved_paths_in_selected_set'
        pair_index_in_pairwise_profile = $PairIndex
        selected_record_count = $n
        left_position = $leftPosition
        right_position = $rightPosition
        left_record_id = $leftId
        right_record_id = $rightId
        independent_of_sequence_top = $true
        counts = $totals
        saved_severity_statement_delta_right_minus_left = $deltaAll
        changed_path_indices = $changedIndices.ToArray()
        paths = $rows.ToArray()
        explanation = 'Paths are the complete ordinal case-sensitive UNION from every selected saved report, including paths absent in both chosen endpoints. Original Finding IDs are separately scoped to their endpoint records; quote-anchor equality and saved severity histograms are NOT issue identity, same model prose, actual source change, fix, regression, priority, authenticated chronology or source freshness. Use SequencePath plus SequencePairIndex for exact anchor drilldown. No raw quote, model prose, extra stored body/source/Git/network read or write.'
    }
}

# EC-046: resolve an unambiguous one-based index from the FULL EC-045
# ordinal path union. This is deliberately a lookup into checked memory,
# not a new source/path lookup or a Top-clipped preview.
function Resolve-CodeSequenceGlobalPairPath {
    param([object] $PairOverview, [int] $PathIndex)

    if ($null -eq $PairOverview -or
        $PairOverview.scope -cne 'one_explicit_canonical_report_pair_all_saved_paths_in_selected_set' -or
        -not [bool]$PairOverview.independent_of_sequence_top -or
        $null -eq $PairOverview.paths -or
        $PairOverview.paths.Count -gt 480 -or
        [int]$PairOverview.counts.distinct_saved_path_union_count -ne $PairOverview.paths.Count) {
        throw 'Code Sequence pair-path navigation requires a complete checked EC-045 path union.'
    }
    if ($PathIndex -lt 1 -or $PathIndex -gt $PairOverview.paths.Count) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_NOT_FOUND: path index is outside this pair overview union.'
    }
    $row = $PairOverview.paths[$PathIndex - 1]
    if ($null -eq $row -or [int]$row.path_index -ne $PathIndex -or
        $row.path -isnot [string] -or [string]::IsNullOrEmpty($row.path) -or
        $row.path.Length -gt 4096 -or $row.path.IndexOf([char]0) -ge 0 -or
        $row.pair_path_class -cnotin @('left_only','right_only',
            'retained_same_profile','retained_changed_profile','neither_reported')) {
        throw 'Code Sequence pair-path index did not resolve to a valid literal saved path.'
    }
    return $row
}

# Independent conservation of the two existing fully checked views:
# EC-045 path-level scoped original Finding IDs vs EC-044's exhaustive
# path-local anchors (which can also include BOTH-endpoint-unreported
# anchors contributed by third selected reports).
function Get-CodeSequenceGlobalPairPathSelection {
    param(
        [object] $PairOverview,
        [object] $SelectedPathRow,
        [object] $SelectedPair,
        [int] $PathIndex
    )

    $row = Resolve-CodeSequenceGlobalPairPath -PairOverview $PairOverview -PathIndex $PathIndex
    if ($row.path -cne $SelectedPathRow.path -or
        [int]$SelectedPathRow.path_index -ne $PathIndex -or
        $null -eq $SelectedPair -or
        $SelectedPair.scope -cne 'one_explicit_canonical_report_pair_all_exact_saved_quote_anchors' -or
        $SelectedPair.path -cne $row.path -or
        [int]$SelectedPair.pair_index_in_anchor_pair_details -ne [int]$PairOverview.pair_index_in_pairwise_profile -or
        [int]$SelectedPair.left_position -ne [int]$PairOverview.left_position -or
        [int]$SelectedPair.right_position -ne [int]$PairOverview.right_position -or
        $SelectedPair.left_record_id -cne $PairOverview.left_record_id -or
        $SelectedPair.right_record_id -cne $PairOverview.right_record_id -or
        [int]$SelectedPair.selected_record_count -ne [int]$PairOverview.selected_record_count -or
        -not [bool]$SelectedPair.independent_of_sequence_top) {
        throw 'Code Sequence indexed path selected a different pair or path than the global overview.'
    }

    $counts = $SelectedPair.counts
    $anchorCount = $SelectedPair.anchors.Count
    if ([int]$counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        $anchorCount -gt 480 -or
        [int]$row.distinct_exact_anchor_union_at_pair_endpoints -ne
            ($anchorCount - [int]$counts.both_unreported_anchor_count) -or
        [int]$row.left_only_exact_anchor_count -ne [int]$counts.left_only_anchor_count -or
        [int]$row.right_only_exact_anchor_count -ne [int]$counts.right_only_anchor_count -or
        [int]$row.retained_same_severity_exact_anchor_count -ne [int]$counts.retained_same_severity_anchor_count -or
        [int]$row.retained_changed_severity_exact_anchor_count -ne [int]$counts.retained_changed_severity_anchor_count -or
        [int]$row.left.saved_finding_statement_count -ne [int]$counts.left_original_finding_statement_count -or
        [int]$row.right.saved_finding_statement_count -ne [int]$counts.right_original_finding_statement_count -or
        [int]$row.saved_finding_statement_count_delta_right_minus_left -ne
            [int]$SelectedPair.saved_finding_statement_count_delta_right_minus_left -or
        [bool]$row.changed_exact_saved_profile -ne ([int]$counts.changed_anchor_count -gt 0) -or
        -not (Test-CodeSequenceFocusedSeverityEqual -Left $row.saved_severity_statement_delta_right_minus_left `
            -Right $SelectedPair.saved_severity_statement_delta_right_minus_left) -or
        -not (Test-CodeSequenceFocusedSeverityEqual -Left $row.saved_severity_statement_delta_retained_anchors_right_minus_left `
            -Right $SelectedPair.saved_severity_statement_delta_retained_anchors_right_minus_left)) {
        throw 'Code Sequence indexed pair path anchor, statement or five-severity marginals disagree.'
    }
    $kind = if ([int]$counts.left_original_finding_statement_count -eq 0 -and
                [int]$counts.right_original_finding_statement_count -eq 0) {
        'neither_reported'
    } elseif ([int]$counts.left_original_finding_statement_count -eq 0) {
        'right_only'
    } elseif ([int]$counts.right_original_finding_statement_count -eq 0) {
        'left_only'
    } elseif ([int]$counts.changed_anchor_count -eq 0) {
        'retained_same_profile'
    } else {
        'retained_changed_profile'
    }
    if ($row.pair_path_class -cne $kind) {
        throw 'Code Sequence indexed pair path profile class differs between complete ledgers.'
    }

    foreach ($side in @('left','right')) {
        $sideRow = $row[$side]
        $expectedRecordId = if ($side -ceq 'left') { $SelectedPair.left_record_id } else { $SelectedPair.right_record_id }
        $refsById = [System.Collections.Generic.SortedDictionary[string,string]]::new([System.StringComparer]::Ordinal)
        $hist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        $reportedAnchors = 0
        foreach ($anchor in $SelectedPair.anchors) {
            $cell = $anchor[$side]
            if ($cell.record_id -cne $expectedRecordId) {
                throw 'Code Sequence indexed pair path has an anchor from another original record.'
            }
            $refs = $cell.original_record_scoped_finding_refs
            if ([bool]$cell.reported_same_exact_saved_quote_anchor -ne ($refs.Count -gt 0) -or
                [int]$cell.saved_finding_statement_count_at_anchor -ne $refs.Count) {
                throw 'Code Sequence indexed pair path has mismatched anchor presence and original Finding multiplicity.'
            }
            if ([bool]$cell.reported_same_exact_saved_quote_anchor) { $reportedAnchors++ }
            foreach ($ref in $refs) {
                $id = [string]$ref.finding_id
                $severity = [string]$ref.severity
                if ($id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
                    $severity -cnotin @('critical','high','medium','low','info') -or
                    $refsById.ContainsKey($id)) {
                    throw 'Code Sequence indexed pair path has a duplicate or invalid original scoped Finding.'
                }
                $refsById.Add($id, $severity)
                $hist[$severity] = [int]$hist[$severity] + 1
            }
        }
        $reported = ($reportedAnchors -gt 0)
        if ([bool]$sideRow.reported_at_saved_path -ne $reported -or
            $sideRow.record_id -cne $expectedRecordId -or
            [int]$sideRow.distinct_exact_anchor_count -ne $reportedAnchors -or
            [int]$sideRow.saved_finding_statement_count -ne $refsById.Count -or
            $sideRow.original_record_scoped_finding_refs.Count -ne $refsById.Count -or
            (($null -eq $sideRow.saved_severity_statement_counts) -eq $reported)) {
            throw 'Code Sequence indexed pair path original record side is inconsistent with anchor evidence.'
        }
        if ($reported -and -not (Test-CodeSequenceFocusedSeverityEqual -Left $hist -Right $sideRow.saved_severity_statement_counts)) {
            throw 'Code Sequence indexed pair path has a mismatched saved severity histogram.'
        }
        $j = 0
        foreach ($id in $refsById.Keys) {
            $original = $sideRow.original_record_scoped_finding_refs[$j]
            if ($original.finding_id -cne $id -or $original.severity -cne $refsById[$id]) {
                throw 'Code Sequence indexed pair path original scoped Finding references differ.'
            }
            $j++
        }
    }

    return [ordered]@{
        scope = 'one_indexed_path_within_selected_report_pair_complete_anchor_drilldown'
        pair_index_in_pairwise_profile = [int]$PairOverview.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = $PathIndex
        path = [string]$row.path
        pair_path_class = [string]$row.pair_path_class
        changed_exact_saved_profile = [bool]$row.changed_exact_saved_profile
        left_record_id = [string]$PairOverview.left_record_id
        right_record_id = [string]$PairOverview.right_record_id
        complete_anchor_union_count = $anchorCount
        both_endpoints_unreported_anchor_count = [int]$counts.both_unreported_anchor_count
        independent_of_sequence_top = $true
        original_finding_refs_conserved = $true
        explanation = 'The path is an exact ordinal index into the COMPLETE selected pair overview, not a guessed or normalized string. The attached path_focus.selected_pair is the complete EC-044 anchor comparison, including anchors unreported by both endpoints but saved in other chosen reports. IDs remain independently scoped to their original saved reports. No source freshness, real defect, fix, chronology, cross-report Finding identity or prose is verified.'
    }
}

# EC-047: the third ordinal narrows the already selected pair/path to ONE
# canonical exact saved quote anchor. Keep both independently built full
# views: EC-044 supplies the selected pair's two original Finding sets;
# EC-043 supplies all caller positions and every unordered report pair.
# This projection joins them only by the canonical in-memory anchor index,
# six-field saved anchor identity and record-scoped original IDs.
function Get-CodeSequenceGlobalPairPathAnchorSelection {
    param(
        [object] $PairOverview,
        [object] $PathSelection,
        [object] $SelectedPair,
        [object] $SelectedAnchor,
        [int] $AnchorIndex
    )

    if ($null -eq $PairOverview -or $null -eq $PathSelection -or
        $null -eq $SelectedPair -or
        $SelectedPair.scope -cne 'one_explicit_canonical_report_pair_all_exact_saved_quote_anchors' -or
        $PathSelection.scope -cne 'one_indexed_path_within_selected_report_pair_complete_anchor_drilldown' -or
        $null -eq $SelectedPair.anchors -or
        [int]$PathSelection.complete_anchor_union_count -ne $SelectedPair.anchors.Count -or
        $SelectedPair.anchors.Count -gt 480 -or
        [int]$SelectedPair.pair_index_in_anchor_pair_details -ne [int]$PairOverview.pair_index_in_pairwise_profile -or
        [int]$PathSelection.pair_index_in_pairwise_profile -ne [int]$PairOverview.pair_index_in_pairwise_profile -or
        $PathSelection.path -cne $SelectedPair.path -or
        -not [bool]$PathSelection.original_finding_refs_conserved -or
        -not [bool]$PathSelection.independent_of_sequence_top) {
        throw 'Code Sequence indexed anchor requires an already reconciled, complete pair-path selection.'
    }
    if ($AnchorIndex -lt 1 -or $AnchorIndex -gt $SelectedPair.anchors.Count) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_NOT_FOUND: canonical anchor index is outside the selected path union.'
    }
    if ($null -eq $SelectedAnchor -or
        $SelectedAnchor.scope -cne 'one_explicit_canonical_exact_saved_quote_anchor_all_selected_positions_and_all_pairs' -or
        $SelectedAnchor.path -cne $PathSelection.path -or
        [int]$SelectedAnchor.anchor_index_in_anchor_journeys -ne $AnchorIndex -or
        [int]$SelectedAnchor.selected_record_count -ne [int]$SelectedPair.selected_record_count -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top) {
        throw 'Code Sequence indexed anchor and exhaustive all-position anchor detail disagree.'
    }
    $n = [int]$SelectedPair.selected_record_count
    $pairCount = [int](($n * ($n - 1)) / 2)
    $pairIndex = [int]$SelectedPair.pair_index_in_anchor_pair_details
    $leftPosition = [int]$SelectedPair.left_position
    $rightPosition = [int]$SelectedPair.right_position
    if ($n -lt 2 -or $n -gt 12 -or $pairIndex -lt 1 -or $pairIndex -gt $pairCount -or
        $leftPosition -lt 1 -or $rightPosition -le $leftPosition -or $rightPosition -gt $n -or
        $SelectedAnchor.positions.Count -ne $n -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        [int]$SelectedAnchor.counts.compared_pair_count -ne $pairCount) {
        throw 'Code Sequence indexed anchor has an inconsistent selected report-pair or anchor ledger size.'
    }
    $pairAnchor = $SelectedPair.anchors[$AnchorIndex - 1]
    $anchorPair = $SelectedAnchor.compared_pairs[$pairIndex - 1]
    if ($null -eq $pairAnchor -or $null -eq $anchorPair -or
        [int]$pairAnchor.anchor_index_in_anchor_journeys -ne $AnchorIndex -or
        $pairAnchor.anchor.path -cne $PathSelection.path -or
        (Get-CodeCompareAnchorKey -Anchor $pairAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -or
        $pairAnchor.anchor_presence_pattern_in_caller_order -cne
            $SelectedAnchor.anchor_presence_pattern_in_caller_order -or
        [int]$anchorPair.pair_index -ne $pairIndex -or
        [int]$anchorPair.left_position -ne $leftPosition -or
        [int]$anchorPair.right_position -ne $rightPosition -or
        $anchorPair.left_record_id -cne $SelectedPair.left_record_id -or
        $anchorPair.right_record_id -cne $SelectedPair.right_record_id -or
        $pairAnchor.anchor_pair_class -cne $anchorPair.anchor_pair_class -or
        [bool]$pairAnchor.anchor_changed_in_pair -ne [bool]$anchorPair.anchor_changed_in_pair -or
        [bool]$pairAnchor.shared_with_internal_unreported_position -ne
            [bool]$anchorPair.shared_with_internal_unreported_position -or
        [int]$pairAnchor.saved_finding_statement_count_delta_right_minus_left -ne
            [int]$anchorPair.saved_finding_statement_count_delta_right_minus_left -or
        -not (Test-CodeSequenceFocusedSeverityEqual -Left $pairAnchor.saved_severity_statement_delta_right_minus_left `
            -Right $anchorPair.saved_severity_statement_delta_right_minus_left)) {
        throw 'Code Sequence indexed anchor contradicts the full selected pair or all-pair quote-anchor comparison.'
    }

    foreach ($side in @('left','right')) {
        $position = if ($side -ceq 'left') { $leftPosition } else { $rightPosition }
        $expectedId = if ($side -ceq 'left') { $SelectedPair.left_record_id } else { $SelectedPair.right_record_id }
        $pairCell = $pairAnchor[$side]
        $anchorCell = $SelectedAnchor.positions[$position - 1]
        if ([int]$pairCell.position -ne $position -or
            [int]$anchorCell.position -ne $position -or
            $pairCell.record_id -cne $expectedId -or $anchorCell.record_id -cne $expectedId -or
            [bool]$pairCell.reported_same_exact_saved_quote_anchor -ne
                [bool]$anchorCell.reported_same_exact_saved_quote_anchor -or
            [int]$pairCell.saved_finding_statement_count_at_anchor -ne
                [int]$anchorCell.saved_finding_statement_count_at_anchor -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $pairCell.saved_severity_statement_counts `
                -Right $anchorCell.saved_severity_statement_counts) -or
            $pairCell.original_record_scoped_finding_refs.Count -ne
                $anchorCell.original_record_scoped_finding_refs.Count -or
            $pairCell.original_record_scoped_finding_refs.Count -gt 40) {
            throw 'Code Sequence indexed anchor original Finding membership or saved severity differs at a pair endpoint.'
        }
        for ($j = 0; $j -lt $pairCell.original_record_scoped_finding_refs.Count; $j++) {
            $p = $pairCell.original_record_scoped_finding_refs[$j]
            $a = $anchorCell.original_record_scoped_finding_refs[$j]
            if ($p.finding_id -cne $a.finding_id -or $p.severity -cne $a.severity) {
                throw 'Code Sequence indexed anchor original Finding IDs cannot be matched to the all-position evidence.'
            }
        }
        if ($side -ceq 'left') {
            if ([int]$anchorPair.left_saved_finding_statement_count_at_anchor -ne
                [int]$pairCell.saved_finding_statement_count_at_anchor) {
                throw 'Code Sequence indexed anchor left-side original Finding statement total differs.'
            }
        } else {
            if ([int]$anchorPair.right_saved_finding_statement_count_at_anchor -ne
                [int]$pairCell.saved_finding_statement_count_at_anchor) {
                throw 'Code Sequence indexed anchor right-side original Finding statement total differs.'
            }
        }
    }

    return [ordered]@{
        scope = 'one_indexed_exact_anchor_within_indexed_report_pair_path'
        pair_index_in_pairwise_profile = $pairIndex
        path_index_in_selected_pair_overview = [int]$PathSelection.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = $AnchorIndex
        path = [string]$PathSelection.path
        anchor = $pairAnchor.anchor
        anchor_pair_class = [string]$pairAnchor.anchor_pair_class
        anchor_changed_in_pair = [bool]$pairAnchor.anchor_changed_in_pair
        shared_with_internal_unreported_position = [bool]$pairAnchor.shared_with_internal_unreported_position
        left_position = $leftPosition
        right_position = $rightPosition
        left = $pairAnchor.left
        right = $pairAnchor.right
        saved_finding_statement_count_delta_right_minus_left = [int]$pairAnchor.saved_finding_statement_count_delta_right_minus_left
        saved_severity_statement_delta_right_minus_left = $pairAnchor.saved_severity_statement_delta_right_minus_left
        selected_record_count = $n
        compared_pair_count = $pairCount
        independent_of_sequence_top = $true
        cross_view_original_finding_refs_conserved = $true
        explanation = 'All three ordinal indexes belong only to these explicitly selected saved reports. Both endpoint original Finding IDs/severities are retained without cross-record matching. path_focus.selected_anchor independently returns every selected position and all unordered pairs, including neither-endpoint-reported anchors. No raw quote, model prose, source/Git/network read, save, verified chronology, semantic defect continuity or fix claim.'
    }
}


# EC-048: pair -> path -> exact saved anchor -> one original record-scoped
# Finding on a specifically selected pair endpoint. Reuse, do not recreate,
# the full EC-042 Finding journey; reject any cross-view identity drift.
function Get-CodeSequenceGlobalPairPathAnchorFindingSelection {
    param(
        [object] $AnchorSelection,
        [object] $SelectedAnchor,
        [object] $SelectedFinding,
        [string] $FindingSide,
        [int] $FindingIndex
    )
    if ($FindingSide -cnotin @('left','right')) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_SELECTOR_INVALID: use a canonical left or right endpoint.'
    }
    if ($null -eq $AnchorSelection -or
        $AnchorSelection.scope -cne 'one_indexed_exact_anchor_within_indexed_report_pair_path' -or
        $null -eq $SelectedAnchor -or
        $SelectedAnchor.scope -cne 'one_explicit_canonical_exact_saved_quote_anchor_all_selected_positions_and_all_pairs' -or
        -not [bool]$AnchorSelection.cross_view_original_finding_refs_conserved -or
        -not [bool]$AnchorSelection.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top) {
        throw 'Code Sequence indexed Finding requires an already checked three-ordinal anchor selection.'
    }
    $endpoint = $AnchorSelection[$FindingSide]
    if ($null -eq $endpoint -or $endpoint.original_record_scoped_finding_refs.Count -gt 40 -or
        $endpoint.original_record_scoped_finding_refs.Count -ne [int]$endpoint.saved_finding_statement_count_at_anchor) {
        throw 'Code Sequence indexed Finding endpoint original reference counts are inconsistent.'
    }
    if ($FindingIndex -lt 1 -or $FindingIndex -gt $endpoint.original_record_scoped_finding_refs.Count) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_NOT_FOUND: original Finding index does not exist at this pair endpoint anchor.'
    }
    $chosen = $endpoint.original_record_scoped_finding_refs[$FindingIndex - 1]
    $recordId = [string]$endpoint.record_id
    $findingId = [string]$chosen.finding_id
    $severity = [string]$chosen.severity
    $position = [int]$endpoint.position
    $anchorIndex = [int]$AnchorSelection.anchor_index_in_anchor_journeys
    $pairIndex = [int]$AnchorSelection.pair_index_in_pairwise_profile
    $selectedN = [int]$AnchorSelection.selected_record_count
    if ($recordId -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $findingId -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
        $severity -cnotin @('critical','high','medium','low','info') -or
        $position -lt 1 -or $position -gt $selectedN -or
        $SelectedAnchor.positions.Count -ne $selectedN -or
        $SelectedAnchor.compared_pairs.Count -ne [int]$AnchorSelection.compared_pair_count -or
        $pairIndex -lt 1 -or $pairIndex -gt $SelectedAnchor.compared_pairs.Count -or
        $AnchorSelection.anchor.path -cne $AnchorSelection.path -or
        $SelectedAnchor.path -cne $AnchorSelection.path -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor)) {
        throw 'Code Sequence indexed Finding selected report identity or exact anchor contradicts the checked view.'
    }
    $positionCell = $SelectedAnchor.positions[$position - 1]
    if ([int]$positionCell.position -ne $position -or
        $positionCell.record_id -cne $recordId -or
        -not [bool]$positionCell.reported_same_exact_saved_quote_anchor -or
        $positionCell.original_record_scoped_finding_refs.Count -ne $endpoint.original_record_scoped_finding_refs.Count) {
        throw 'Code Sequence indexed Finding endpoint is missing from the complete all-position anchor ledger.'
    }
    for ($i=0; $i -lt $endpoint.original_record_scoped_finding_refs.Count; $i++) {
        $leftRef = $endpoint.original_record_scoped_finding_refs[$i]
        $allRef = $positionCell.original_record_scoped_finding_refs[$i]
        if ($leftRef.finding_id -cne $allRef.finding_id -or $leftRef.severity -cne $allRef.severity) {
            throw 'Code Sequence indexed Finding original IDs diverge from complete all-position anchor evidence.'
        }
    }
    $pairCell = $SelectedAnchor.compared_pairs[$pairIndex - 1]
    $other = if ($FindingSide -ceq 'left') { $AnchorSelection.right } else { $AnchorSelection.left }
    $otherPosition = [int]$other.position
    $focusedPairs = @($SelectedFinding.compared_pairs | Where-Object { [int]$_.pair_index -eq $pairIndex })
    if ($null -eq $SelectedFinding -or
        $SelectedFinding.scope -cne 'one_explicit_original_record_scoped_Finding_ID_exact_saved_quote_anchor' -or
        $SelectedFinding.original_record_id -cne $recordId -or
        $SelectedFinding.original_finding_id -cne $findingId -or
        $SelectedFinding.original_saved_severity -cne $severity -or
        [int]$SelectedFinding.original_position -ne $position -or
        [int]$SelectedFinding.anchor_index_in_anchor_journeys -ne $anchorIndex -or
        $SelectedFinding.path -cne $AnchorSelection.path -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedFinding.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor) -or
        -not [bool]$SelectedFinding.independent_of_sequence_top -or
        $SelectedFinding.positions.Count -ne $selectedN -or
        $SelectedFinding.compared_pairs.Count -ne ($selectedN - 1) -or
        $focusedPairs.Count -ne 1 -or
        [int]$pairCell.pair_index -ne $pairIndex -or
        $pairCell.anchor_pair_class -cne $AnchorSelection.anchor_pair_class -or
        $focusedPairs[0].anchor_pair_class -cne $AnchorSelection.anchor_pair_class -or
        $focusedPairs[0].original_side -cne $FindingSide -or
        [int]$focusedPairs[0].counterpart_position -ne $otherPosition -or
        $focusedPairs[0].counterpart_record_id -cne $other.record_id -or
        $focusedPairs[0].counterpart_original_record_scoped_finding_refs.Count -ne
            $other.original_record_scoped_finding_refs.Count) {
        throw 'Code Sequence indexed Finding full saved journey does not match the chosen pair/path/anchor/side.'
    }
    for ($i=0; $i -lt $other.original_record_scoped_finding_refs.Count; $i++) {
        $refA = $other.original_record_scoped_finding_refs[$i]
        $refB = $focusedPairs[0].counterpart_original_record_scoped_finding_refs[$i]
        if ($refA.finding_id -cne $refB.finding_id -or $refA.severity -cne $refB.severity) {
            throw 'Code Sequence indexed Finding original counterpart IDs disagree with the selected report pair.'
        }
    }
    return [ordered]@{
        scope = 'one_indexed_original_record_scoped_Finding_in_pair_path_anchor_endpoint'
        pair_index_in_pairwise_profile = $pairIndex
        path_index_in_selected_pair_overview = [int]$AnchorSelection.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = $anchorIndex
        finding_side = $FindingSide
        finding_index_in_endpoint_anchor = $FindingIndex
        finding_count_at_endpoint_anchor = $endpoint.original_record_scoped_finding_refs.Count
        path = [string]$AnchorSelection.path
        original_record_id = $recordId
        original_record_position = $position
        original_finding_id = $findingId
        original_saved_severity = $severity
        anchor_pair_class = [string]$AnchorSelection.anchor_pair_class
        exact_saved_quote_anchor = $AnchorSelection.anchor
        independent_of_sequence_top = $true
        original_record_scoped_journey_reused = $true
        cross_view_original_finding_ref_conserved = $true
        explanation = 'Canonical side and one-based Finding ordinal select one ORIGINAL ID scoped to that endpoint saved record, never an ID from the other report. path_focus.selected_finding is the unchanged complete EC-042 journey for that original ID. The complete EC-043 all-position/all-pair anchor evidence and EC-044 pair anchor remain present. Same saved quote anchor never proves the identity, severity, resolution, regression or chronology of a real defect. No extra storage/source/Git/network read or writer and no raw quote/model prose.'
    }
}

# EC-049: fifth-level original Finding -> independently scoped original
# counterpart Finding within the SAME selected pair and exact saved anchor.
# Retain BOTH complete EC-042 journeys side by side; no inferred semantic
# Finding-to-Finding identity, severity change, chronology or new I/O.
function Get-CodeSequenceGlobalPairPathAnchorFindingCounterpartSelection {
    param(
        [object] $AnchorSelection,
        [object] $OriginalSelection,
        [object] $OriginalJourney,
        [object] $CounterpartJourney,
        [object] $SelectedAnchor,
        [int] $CounterpartIndex
    )

    if ($null -eq $AnchorSelection -or $null -eq $OriginalSelection -or
        $null -eq $OriginalJourney -or $null -eq $CounterpartJourney -or
        $null -eq $SelectedAnchor -or
        $AnchorSelection.scope -cne 'one_indexed_exact_anchor_within_indexed_report_pair_path' -or
        $OriginalSelection.scope -cne 'one_indexed_original_record_scoped_Finding_in_pair_path_anchor_endpoint' -or
        $OriginalJourney.scope -cne 'one_explicit_original_record_scoped_Finding_ID_exact_saved_quote_anchor' -or
        $CounterpartJourney.scope -cne 'one_explicit_original_record_scoped_Finding_ID_exact_saved_quote_anchor' -or
        $SelectedAnchor.scope -cne 'one_explicit_canonical_exact_saved_quote_anchor_all_selected_positions_and_all_pairs' -or
        -not [bool]$OriginalSelection.cross_view_original_finding_ref_conserved -or
        -not [bool]$AnchorSelection.cross_view_original_finding_refs_conserved -or
        -not [bool]$OriginalJourney.independent_of_sequence_top -or
        -not [bool]$CounterpartJourney.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top) {
        throw 'Code Sequence original Finding counterpart requires complete checked parent and both original journeys.'
    }
    $originalSide = [string]$OriginalSelection.finding_side
    if ($originalSide -cnotin @('left','right')) {
        throw 'Code Sequence original Finding counterpart parent side is invalid.'
    }
    $otherSide = if ($originalSide -ceq 'left') { 'right' } else { 'left' }
    $originalEndpoint = $AnchorSelection[$originalSide]
    $otherEndpoint = $AnchorSelection[$otherSide]
    if ($null -eq $originalEndpoint -or $null -eq $otherEndpoint -or
        $originalEndpoint.original_record_scoped_finding_refs.Count -lt 1 -or
        $originalEndpoint.original_record_scoped_finding_refs.Count -gt 40 -or
        $otherEndpoint.original_record_scoped_finding_refs.Count -gt 40 -or
        [int]$originalEndpoint.saved_finding_statement_count_at_anchor -ne
            $originalEndpoint.original_record_scoped_finding_refs.Count -or
        [int]$otherEndpoint.saved_finding_statement_count_at_anchor -ne
            $otherEndpoint.original_record_scoped_finding_refs.Count) {
        throw 'Code Sequence original Finding counterpart endpoint sets are inconsistent.'
    }
    if ($CounterpartIndex -lt 1 -or
        $CounterpartIndex -gt $otherEndpoint.original_record_scoped_finding_refs.Count) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_NOT_FOUND: the opposite endpoint has no original Finding at that ordinal.'
    }
    $otherRef = $otherEndpoint.original_record_scoped_finding_refs[$CounterpartIndex - 1]
    $originalIndex = [int]$OriginalSelection.finding_index_in_endpoint_anchor
    if ($originalIndex -lt 1 -or
        $originalIndex -gt $originalEndpoint.original_record_scoped_finding_refs.Count) {
        throw 'Code Sequence original Finding counterpart has an invalid parent original Finding ordinal.'
    }
    $originalRef = $originalEndpoint.original_record_scoped_finding_refs[$originalIndex - 1]
    $pairIndex = [int]$AnchorSelection.pair_index_in_pairwise_profile
    $anchorIndex = [int]$AnchorSelection.anchor_index_in_anchor_journeys
    $n = [int]$AnchorSelection.selected_record_count
    $originalPosition = [int]$originalEndpoint.position
    $otherPosition = [int]$otherEndpoint.position
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $pairIndex -lt 1 -or $pairIndex -gt [int]$AnchorSelection.compared_pair_count -or
        $anchorIndex -lt 1 -or $anchorIndex -gt 480 -or
        $originalPosition -lt 1 -or $originalPosition -gt $n -or
        $otherPosition -lt 1 -or $otherPosition -gt $n -or
        $originalPosition -eq $otherPosition -or
        $originalEndpoint.record_id -ceq $otherEndpoint.record_id -or
        $OriginalSelection.original_record_id -cne $originalEndpoint.record_id -or
        [int]$OriginalSelection.original_record_position -ne $originalPosition -or
        $OriginalSelection.original_finding_id -cne $originalRef.finding_id -or
        $OriginalSelection.original_saved_severity -cne $originalRef.severity -or
        [int]$OriginalSelection.finding_count_at_endpoint_anchor -ne
            $originalEndpoint.original_record_scoped_finding_refs.Count -or
        [int]$OriginalSelection.pair_index_in_pairwise_profile -ne $pairIndex -or
        [int]$OriginalSelection.path_index_in_selected_pair_overview -ne
            [int]$AnchorSelection.path_index_in_selected_pair_overview -or
        [int]$OriginalSelection.anchor_index_in_anchor_journeys -ne $anchorIndex -or
        $OriginalSelection.path -cne $AnchorSelection.path -or
        $OriginalSelection.anchor_pair_class -cne $AnchorSelection.anchor_pair_class -or
        $OriginalSelection.original_record_id -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $otherEndpoint.record_id -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $otherRef.finding_id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
        $otherRef.severity -cnotin @('critical','high','medium','low','info') -or
        (Get-CodeCompareAnchorKey -Anchor $OriginalSelection.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor)) {
        throw 'Code Sequence original Finding counterpart parent membership or saved quote-anchor identity changed.'
    }
    foreach ($journey in @($OriginalJourney, $CounterpartJourney)) {
        if ($journey.path -cne $AnchorSelection.path -or
            [int]$journey.anchor_index_in_anchor_journeys -ne $anchorIndex -or
            [int]$journey.selected_record_count -ne $n -or
            $journey.positions.Count -ne $n -or
            $journey.compared_pairs.Count -ne ($n - 1) -or
            (Get-CodeCompareAnchorKey -Anchor $journey.anchor) -cne
                (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor)) {
            throw 'Code Sequence original Finding counterpart full journey lost its canonical selected anchor.'
        }
    }
    if ($OriginalJourney.original_record_id -cne $originalEndpoint.record_id -or
        $OriginalJourney.original_finding_id -cne $originalRef.finding_id -or
        $OriginalJourney.original_saved_severity -cne $originalRef.severity -or
        [int]$OriginalJourney.original_position -ne $originalPosition -or
        $CounterpartJourney.original_record_id -cne $otherEndpoint.record_id -or
        $CounterpartJourney.original_finding_id -cne $otherRef.finding_id -or
        $CounterpartJourney.original_saved_severity -cne $otherRef.severity -or
        [int]$CounterpartJourney.original_position -ne $otherPosition) {
        throw 'Code Sequence original Finding counterpart two independently scoped seed IDs disagree.'
    }

    # Match each original record and every original ID on that endpoint to
    # BOTH EC-042 journeys and EC-043's independent all-position projection.
    foreach ($row in @(
        [ordered]@{ side = $originalSide; endpoint = $originalEndpoint; journey = $OriginalJourney },
        [ordered]@{ side = $otherSide; endpoint = $otherEndpoint; journey = $CounterpartJourney }
    )) {
        $endpoint = $row.endpoint
        $position = [int]$endpoint.position
        $anchorCell = $SelectedAnchor.positions[$position - 1]
        $originalCell = $OriginalJourney.positions[$position - 1]
        $counterpartCell = $CounterpartJourney.positions[$position - 1]
        if ([int]$anchorCell.position -ne $position -or
            $anchorCell.record_id -cne $endpoint.record_id -or
            -not [bool]$anchorCell.reported_same_exact_saved_quote_anchor -or
            $anchorCell.original_record_scoped_finding_refs.Count -ne
                $endpoint.original_record_scoped_finding_refs.Count -or
            $originalCell.record_id -cne $endpoint.record_id -or
            $counterpartCell.record_id -cne $endpoint.record_id -or
            $originalCell.original_record_scoped_finding_refs.Count -ne
                $endpoint.original_record_scoped_finding_refs.Count -or
            $counterpartCell.original_record_scoped_finding_refs.Count -ne
                $endpoint.original_record_scoped_finding_refs.Count) {
            throw 'Code Sequence original Finding counterpart endpoint reports differ across full journeys.'
        }
        for ($i=0; $i -lt $endpoint.original_record_scoped_finding_refs.Count; $i++) {
            $ref = $endpoint.original_record_scoped_finding_refs[$i]
            foreach ($cell in @($anchorCell, $originalCell, $counterpartCell)) {
                if ($cell.original_record_scoped_finding_refs[$i].finding_id -cne $ref.finding_id -or
                    $cell.original_record_scoped_finding_refs[$i].severity -cne $ref.severity) {
                    throw 'Code Sequence original Finding counterpart original IDs/severities diverge.'
                }
            }
        }
    }
    $originalPairs = @($OriginalJourney.compared_pairs | Where-Object { [int]$_.pair_index -eq $pairIndex })
    $otherPairs = @($CounterpartJourney.compared_pairs | Where-Object { [int]$_.pair_index -eq $pairIndex })
    if ($originalPairs.Count -ne 1 -or $otherPairs.Count -ne 1 -or
        $OriginalJourney.compared_pairs.Count -ne ($n - 1) -or
        $CounterpartJourney.compared_pairs.Count -ne ($n - 1) -or
        $originalPairs[0].original_side -cne $originalSide -or
        $otherPairs[0].original_side -cne $otherSide -or
        [int]$originalPairs[0].counterpart_position -ne $otherPosition -or
        [int]$otherPairs[0].counterpart_position -ne $originalPosition -or
        $originalPairs[0].counterpart_record_id -cne $otherEndpoint.record_id -or
        $otherPairs[0].counterpart_record_id -cne $originalEndpoint.record_id -or
        $originalPairs[0].anchor_pair_class -cne $AnchorSelection.anchor_pair_class -or
        $otherPairs[0].anchor_pair_class -cne $AnchorSelection.anchor_pair_class -or
        [bool]$originalPairs[0].anchor_changed_in_pair -ne [bool]$AnchorSelection.anchor_changed_in_pair -or
        [bool]$otherPairs[0].anchor_changed_in_pair -ne [bool]$AnchorSelection.anchor_changed_in_pair -or
        $originalPairs[0].counterpart_original_record_scoped_finding_refs.Count -ne
            $otherEndpoint.original_record_scoped_finding_refs.Count -or
        $otherPairs[0].counterpart_original_record_scoped_finding_refs.Count -ne
            $originalEndpoint.original_record_scoped_finding_refs.Count) {
        throw 'Code Sequence original Finding counterpart pair direction or exhaustive scoped refs differ.'
    }
    for ($i=0; $i -lt $otherEndpoint.original_record_scoped_finding_refs.Count; $i++) {
        $ref = $otherEndpoint.original_record_scoped_finding_refs[$i]
        $linked = $originalPairs[0].counterpart_original_record_scoped_finding_refs[$i]
        if ($linked.finding_id -cne $ref.finding_id -or $linked.severity -cne $ref.severity) {
            throw 'Code Sequence original Finding counterpart forward original-ID pair refs diverge.'
        }
    }
    for ($i=0; $i -lt $originalEndpoint.original_record_scoped_finding_refs.Count; $i++) {
        $ref = $originalEndpoint.original_record_scoped_finding_refs[$i]
        $linked = $otherPairs[0].counterpart_original_record_scoped_finding_refs[$i]
        if ($linked.finding_id -cne $ref.finding_id -or $linked.severity -cne $ref.severity) {
            throw 'Code Sequence original Finding counterpart reverse original-ID pair refs diverge.'
        }
    }
    return [ordered]@{
        scope = 'one_indexed_opposite_original_Finding_with_two_complete_independently_scoped_journeys'
        pair_index_in_pairwise_profile = $pairIndex
        path_index_in_selected_pair_overview = [int]$AnchorSelection.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = $anchorIndex
        path = [string]$AnchorSelection.path
        anchor = $AnchorSelection.anchor
        anchor_pair_class = [string]$AnchorSelection.anchor_pair_class
        anchor_changed_in_pair = [bool]$AnchorSelection.anchor_changed_in_pair
        original_finding_side = $originalSide
        original_finding_index_in_endpoint_anchor = $originalIndex
        original_record_id = [string]$originalEndpoint.record_id
        original_record_position = $originalPosition
        original_finding_id = [string]$originalRef.finding_id
        original_saved_severity = [string]$originalRef.severity
        counterpart_finding_side = $otherSide
        counterpart_finding_index_in_endpoint_anchor = $CounterpartIndex
        counterpart_finding_count_at_opposite_endpoint_anchor = $otherEndpoint.original_record_scoped_finding_refs.Count
        counterpart_record_id = [string]$otherEndpoint.record_id
        counterpart_record_position = $otherPosition
        counterpart_finding_id = [string]$otherRef.finding_id
        counterpart_saved_severity = [string]$otherRef.severity
        shared_exact_saved_quote_anchor = $true
        independent_of_sequence_top = $true
        both_complete_original_record_scoped_journeys_reused = $true
        bidirectional_scoped_original_finding_refs_conserved = $true
        explanation = 'The fifth one-based ordinal selects ONE ORIGINAL Finding from the opposite selected saved report endpoint, not a matched defect. path_focus.selected_finding and path_focus.selected_counterpart_finding each preserve their independent complete EC-042 all-position and seed-related-pair journeys. Matching IDs/anchors do not establish cross-report Finding identity, severity progression, a fix, regression, actual defect, chronology or source freshness. No extra saved body, source, Git, network, writer, quote or model prose.'
    }
}

# EC-050: after both independent original record-scoped Finding journeys are
# selected, partition ALL caller-selected reports by their saved severity
# STATEMENT histogram at the shared exact quote anchor. Cohorts describe
# report profiles, never continuity/equivalence of the two Findings/defects.
# Consume only already verified EC-043 and two unchanged EC-042 projections.
function Get-CodeSequenceOriginalFindingPairProfileCohorts {
    param(
        [object] $AnchorSelection,
        [object] $CounterpartSelection,
        [object] $SelectedAnchor,
        [object] $OriginalJourney,
        [object] $CounterpartJourney
    )

    $n = [int]$AnchorSelection.selected_record_count
    $left = $AnchorSelection.left
    $right = $AnchorSelection.right
    $pairIndex = [int]$AnchorSelection.pair_index_in_pairwise_profile
    $anchorIndex = [int]$AnchorSelection.anchor_index_in_anchor_journeys
    if ($null -eq $CounterpartSelection -or
        $CounterpartSelection.scope -cne 'one_indexed_opposite_original_Finding_with_two_complete_independently_scoped_journeys' -or
        -not [bool]$CounterpartSelection.bidirectional_scoped_original_finding_refs_conserved -or
        -not [bool]$CounterpartSelection.both_complete_original_record_scoped_journeys_reused -or
        -not [bool]$CounterpartSelection.shared_exact_saved_quote_anchor -or
        $null -eq $SelectedAnchor -or $null -eq $OriginalJourney -or
        $null -eq $CounterpartJourney -or $null -eq $left -or $null -eq $right -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $SelectedAnchor.positions.Count -ne $n -or
        $OriginalJourney.positions.Count -ne $n -or
        $CounterpartJourney.positions.Count -ne $n -or
        $SelectedAnchor.compared_pairs.Count -ne (($n * ($n - 1)) / 2) -or
        [int]$CounterpartSelection.pair_index_in_pairwise_profile -ne $pairIndex -or
        [int]$CounterpartSelection.anchor_index_in_anchor_journeys -ne $anchorIndex -or
        [int]$CounterpartSelection.path_index_in_selected_pair_overview -ne
            [int]$AnchorSelection.path_index_in_selected_pair_overview -or
        $CounterpartSelection.path -cne $AnchorSelection.path -or
        $SelectedAnchor.path -cne $AnchorSelection.path -or
        $OriginalJourney.path -cne $AnchorSelection.path -or
        $CounterpartJourney.path -cne $AnchorSelection.path -or
        (Get-CodeCompareAnchorKey -Anchor $CounterpartSelection.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $AnchorSelection.anchor) -or
        [int]$left.position -lt 1 -or [int]$right.position -gt $n -or
        [int]$left.position -ge [int]$right.position -or
        $left.record_id -ceq $right.record_id -or
        $left.original_record_scoped_finding_refs.Count -lt 1 -or
        $right.original_record_scoped_finding_refs.Count -lt 1 -or
        $left.original_record_scoped_finding_refs.Count -gt 40 -or
        $right.original_record_scoped_finding_refs.Count -gt 40 -or
        -not [bool]$CounterpartSelection.independent_of_sequence_top -or
        -not [bool]$OriginalJourney.independent_of_sequence_top -or
        -not [bool]$CounterpartJourney.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top) {
        throw 'Code Sequence selected original Finding pair cohorts require all complete checked fifth-level and original journey projections.'
    }
    $originalSide = [string]$CounterpartSelection.original_finding_side
    if ($originalSide -cnotin @('left','right') -or
        $CounterpartSelection.counterpart_finding_side -cne $(if ($originalSide -ceq 'left') { 'right' } else { 'left' })) {
        throw 'Code Sequence selected original Finding pair cohorts lost the two independent endpoint sides.'
    }
    $leftSelected = if ($originalSide -ceq 'left') {
        [ordered]@{ record_id = [string]$CounterpartSelection.original_record_id;
                    position = [int]$CounterpartSelection.original_record_position;
                    finding_id = [string]$CounterpartSelection.original_finding_id;
                    saved_severity = [string]$CounterpartSelection.original_saved_severity }
    } else {
        [ordered]@{ record_id = [string]$CounterpartSelection.counterpart_record_id;
                    position = [int]$CounterpartSelection.counterpart_record_position;
                    finding_id = [string]$CounterpartSelection.counterpart_finding_id;
                    saved_severity = [string]$CounterpartSelection.counterpart_saved_severity }
    }
    $rightSelected = if ($originalSide -ceq 'right') {
        [ordered]@{ record_id = [string]$CounterpartSelection.original_record_id;
                    position = [int]$CounterpartSelection.original_record_position;
                    finding_id = [string]$CounterpartSelection.original_finding_id;
                    saved_severity = [string]$CounterpartSelection.original_saved_severity }
    } else {
        [ordered]@{ record_id = [string]$CounterpartSelection.counterpart_record_id;
                    position = [int]$CounterpartSelection.counterpart_record_position;
                    finding_id = [string]$CounterpartSelection.counterpart_finding_id;
                    saved_severity = [string]$CounterpartSelection.counterpart_saved_severity }
    }
    if ($leftSelected.record_id -cne $left.record_id -or
        $rightSelected.record_id -cne $right.record_id -or
        [int]$leftSelected.position -ne [int]$left.position -or
        [int]$rightSelected.position -ne [int]$right.position -or
        $leftSelected.finding_id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
        $rightSelected.finding_id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
        $leftSelected.saved_severity -cnotin @('critical','high','medium','low','info') -or
        $rightSelected.saved_severity -cnotin @('critical','high','medium','low','info') -or
        $null -eq $left.saved_severity_statement_counts -or
        $null -eq $right.saved_severity_statement_counts) {
        throw 'Code Sequence original Finding cohorts cannot attach selected record-scoped IDs to canonical left/right endpoints.'
    }

    $sameEndpoints = Test-CodeSequenceFocusedSeverityEqual `
        -Left $left.saved_severity_statement_counts -Right $right.saved_severity_statement_counts
    $expectedPairClass = if ($sameEndpoints) { 'retained_same_severity' } else { 'retained_changed_severity' }
    $pairCell = $SelectedAnchor.compared_pairs[$pairIndex - 1]
    if ([int]$pairCell.pair_index -ne $pairIndex -or
        [int]$pairCell.left_position -ne [int]$left.position -or
        [int]$pairCell.right_position -ne [int]$right.position -or
        $pairCell.anchor_pair_class -cne $expectedPairClass -or
        $AnchorSelection.anchor_pair_class -cne $expectedPairClass -or
        $CounterpartSelection.anchor_pair_class -cne $expectedPairClass -or
        [bool]$AnchorSelection.anchor_changed_in_pair -ne (-not $sameEndpoints) -or
        [bool]$CounterpartSelection.anchor_changed_in_pair -ne (-not $sameEndpoints)) {
        throw 'Code Sequence original Finding pair cohorts disagree with the saved pair five-way anchor partition.'
    }

    $keys = @('absent_anchor', 'matches_left_only', 'matches_right_only',
              'matches_both_endpoints', 'differs_from_both_endpoints')
    $cohorts = [ordered]@{}
    foreach ($key in $keys) { $cohorts[$key] = [System.Collections.Generic.List[int]]::new() }
    $rows = [System.Collections.Generic.List[object]]::new()
    $reportedCount = 0
    $savedStatementTotal = 0
    for ($p = 0; $p -lt $n; $p++) {
        $position = $p + 1
        $anchorCell = $SelectedAnchor.positions[$p]
        $firstCell = $OriginalJourney.positions[$p]
        $otherCell = $CounterpartJourney.positions[$p]
        $reported = [bool]$anchorCell.reported_same_exact_saved_quote_anchor
        $refs = $anchorCell.original_record_scoped_finding_refs
        if ([int]$anchorCell.position -ne $position -or
            [int]$firstCell.position -ne $position -or
            [int]$otherCell.position -ne $position -or
            $anchorCell.record_id -cne $firstCell.record_id -or
            $anchorCell.record_id -cne $otherCell.record_id -or
            [bool]$firstCell.reported_same_exact_saved_quote_anchor -ne $reported -or
            [bool]$otherCell.reported_same_exact_saved_quote_anchor -ne $reported -or
            $refs.Count -gt 40 -or ($reported -and $refs.Count -lt 1) -or
            (-not $reported -and $refs.Count -ne 0) -or
            [int]$anchorCell.saved_finding_statement_count_at_anchor -ne $refs.Count -or
            [int]$firstCell.saved_finding_statement_count_at_anchor -ne $refs.Count -or
            [int]$otherCell.saved_finding_statement_count_at_anchor -ne $refs.Count -or
            $firstCell.original_record_scoped_finding_refs.Count -ne $refs.Count -or
            $otherCell.original_record_scoped_finding_refs.Count -ne $refs.Count -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $anchorCell.saved_severity_statement_counts `
                -Right $firstCell.saved_severity_statement_counts) -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $anchorCell.saved_severity_statement_counts `
                -Right $otherCell.saved_severity_statement_counts)) {
            throw 'Code Sequence original Finding pair cohorts lost checked all-position original reference identity.'
        }
        $actualSeverity = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
        $lastId = $null
        foreach ($r in $refs) {
            $id = [string]$r.finding_id
            $severity = [string]$r.severity
            # Preserve every original ID in this saved-record scope; never
            # use ID spelling to equate separate records' Finding statements.
            if ($id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
                $severity -cnotin @('critical','high','medium','low','info') -or
                ($null -ne $lastId -and [string]::CompareOrdinal($lastId, $id) -ge 0)) {
                throw 'Code Sequence original Finding pair cohorts found malformed original ID/severity evidence.'
            }
            $actualSeverity[$severity] = [int]$actualSeverity[$severity] + 1
            $lastId = $id
        }
        for ($i = 0; $i -lt $refs.Count; $i++) {
            $r = $refs[$i]
            if ($firstCell.original_record_scoped_finding_refs[$i].finding_id -cne $r.finding_id -or
                $firstCell.original_record_scoped_finding_refs[$i].severity -cne $r.severity -or
                $otherCell.original_record_scoped_finding_refs[$i].finding_id -cne $r.finding_id -or
                $otherCell.original_record_scoped_finding_refs[$i].severity -cne $r.severity) {
                throw 'Code Sequence original Finding pair cohorts cannot conserve both original journeys for all positions.'
            }
        }
        if (($reported -and -not (Test-CodeSequenceFocusedSeverityEqual -Left $actualSeverity `
                -Right $anchorCell.saved_severity_statement_counts)) -or
            (-not $reported -and $null -ne $anchorCell.saved_severity_statement_counts)) {
            throw 'Code Sequence original Finding pair cohorts lost the five saved-severity statement totals.'
        }
        if ($position -eq [int]$left.position -or $position -eq [int]$right.position) {
            $endpoint = if ($position -eq [int]$left.position) { $left } else { $right }
            if (-not $reported -or $endpoint.record_id -cne $anchorCell.record_id -or
                $endpoint.original_record_scoped_finding_refs.Count -ne $refs.Count -or
                -not (Test-CodeSequenceFocusedSeverityEqual -Left $endpoint.saved_severity_statement_counts `
                    -Right $anchorCell.saved_severity_statement_counts)) {
                throw 'Code Sequence original Finding cohorts lost the selected pair endpoints.'
            }
            for ($i = 0; $i -lt $refs.Count; $i++) {
                if ($endpoint.original_record_scoped_finding_refs[$i].finding_id -cne $refs[$i].finding_id -or
                    $endpoint.original_record_scoped_finding_refs[$i].severity -cne $refs[$i].severity) {
                    throw 'Code Sequence original Finding cohorts differ from the full original pair endpoint references.'
                }
            }
            $chosen = if ($position -eq [int]$left.position) { $leftSelected } else { $rightSelected }
            if (@($refs | Where-Object { $_.finding_id -ceq $chosen.finding_id -and
                    $_.severity -ceq $chosen.saved_severity }).Count -ne 1) {
                throw 'Code Sequence original Finding cohorts lost selected original report Finding membership.'
            }
        }
        $matchesLeft = $reported -and (Test-CodeSequenceFocusedSeverityEqual `
            -Left $anchorCell.saved_severity_statement_counts -Right $left.saved_severity_statement_counts)
        $matchesRight = $reported -and (Test-CodeSequenceFocusedSeverityEqual `
            -Left $anchorCell.saved_severity_statement_counts -Right $right.saved_severity_statement_counts)
        $category = if (-not $reported) { 'absent_anchor' }
            elseif ($matchesLeft -and $matchesRight) { 'matches_both_endpoints' }
            elseif ($matchesLeft) { 'matches_left_only' }
            elseif ($matchesRight) { 'matches_right_only' }
            else { 'differs_from_both_endpoints' }
        $cohorts[$category].Add($position)
        if ($reported) { $reportedCount++ }
        $savedStatementTotal += $refs.Count
        $rows.Add([ordered]@{
            position = $position
            record_id = [string]$anchorCell.record_id
            reported_same_exact_saved_quote_anchor = $reported
            saved_finding_statement_count_at_anchor = $refs.Count
            saved_severity_statement_counts = if ($reported) { $anchorCell.saved_severity_statement_counts } else { $null }
            original_record_scoped_finding_refs = $refs
            matches_left_endpoint_saved_profile = [bool]$matchesLeft
            matches_right_endpoint_saved_profile = [bool]$matchesRight
            cohort = $category
        })
    }
    if ($reportedCount -ne [int]$OriginalJourney.counts.anchor_reported_position_count -or
        $reportedCount -ne [int]$CounterpartJourney.counts.anchor_reported_position_count -or
        $savedStatementTotal -ne
            [int]$OriginalJourney.counts.original_record_scoped_finding_statement_occurrences_at_anchor -or
        $savedStatementTotal -ne
            [int]$CounterpartJourney.counts.original_record_scoped_finding_statement_occurrences_at_anchor) {
        throw 'Code Sequence original Finding pair cohorts do not conserve either independent journey totals.'
    }
    $positionCohorts = [ordered]@{}
    $recount = 0
    foreach ($key in $keys) {
        $positionCohorts[$key] = $cohorts[$key].ToArray()
        $recount += $positionCohorts[$key].Count
    }
    if ($recount -ne $n -or
        ($sameEndpoints -and ($positionCohorts.matches_left_only.Count -ne 0 -or
            $positionCohorts.matches_right_only.Count -ne 0))) {
        throw 'Code Sequence original Finding pair cohorts are not an exhaustive disjoint position partition.'
    }
    return [ordered]@{
        scope = 'all_selected_report_saved_quote_anchor_severity_profile_cohorts_for_two_independent_original_Findings'
        pair_index_in_pairwise_profile = $pairIndex
        path_index_in_selected_pair_overview = [int]$AnchorSelection.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = $anchorIndex
        path = [string]$AnchorSelection.path
        exact_saved_quote_anchor = $AnchorSelection.anchor
        left_endpoint = [ordered]@{
            record_id = [string]$left.record_id
            position = [int]$left.position
            selected_original_finding_id = $leftSelected.finding_id
            selected_original_saved_severity = $leftSelected.saved_severity
            saved_finding_statement_count_at_anchor = [int]$left.saved_finding_statement_count_at_anchor
            saved_severity_statement_counts = $left.saved_severity_statement_counts
        }
        right_endpoint = [ordered]@{
            record_id = [string]$right.record_id
            position = [int]$right.position
            selected_original_finding_id = $rightSelected.finding_id
            selected_original_saved_severity = $rightSelected.saved_severity
            saved_finding_statement_count_at_anchor = [int]$right.saved_finding_statement_count_at_anchor
            saved_severity_statement_counts = $right.saved_severity_statement_counts
        }
        endpoint_saved_severity_statement_profiles_equal = [bool]$sameEndpoints
        anchor_pair_class = $expectedPairClass
        counts = [ordered]@{
            selected_report_positions = $n
            reported_anchor_positions = $reportedCount
            unreported_anchor_positions = $n - $reportedCount
            saved_finding_statements_at_anchor_all_positions = $savedStatementTotal
            absent_anchor = $positionCohorts.absent_anchor.Count
            matches_left_only = $positionCohorts.matches_left_only.Count
            matches_right_only = $positionCohorts.matches_right_only.Count
            matches_both_endpoints = $positionCohorts.matches_both_endpoints.Count
            differs_from_both_endpoints = $positionCohorts.differs_from_both_endpoints.Count
        }
        cohort_positions = $positionCohorts
        positions = $rows.ToArray()
        independent_of_sequence_top = $true
        complete_ec042_journeys_reused_unchanged = $true
        every_position_scoped_refs_and_five_severity_bins_reconciled = $true
        explanation = 'All selected saved reports are partitioned by EXACT SAME SAVED QUOTE ANCHOR and their five-bin MODEL SEVERITY STATEMENT HISTOGRAM relative to canonical left/right endpoints; absent reports stay an explicit separate cohort. The two selected ORIGINAL Finding IDs remain scoped to their own saved records; matching histogram, quote anchor or ID spelling is NEVER Finding/defect equivalence, actual severity progression, verified source state, chronology, fix or regression. In-memory only, complete even with SequenceTop=1; no extra saved body/source/Git/network read, write, original quote/patch or prose.'
    }
}

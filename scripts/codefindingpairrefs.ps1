#requires -Version 7.0
<#
    EC-040: exact saved report-pair contrasts -> original record-scoped Finding IDs.
    This is a bounded in-memory projection of already checked EC-034, EC-037
    and EC-039 views. It does not read saved bodies or business source.

    A retained exact quote anchor with a different saved severity histogram
    is NOT a matched defect or a Finding-to-Finding transition: IDs on the
    two selected sides remain separate (record_id, finding_id) references.
    Equal histograms do not imply that statements or their prose are equal.
#>

function Get-CodeSequenceFocusedAnchorPairFindingRefs {
    param(
        [object] $Journeys,
        [object] $Details,
        [object] $References
    )

    if ($null -eq $Journeys -or $null -eq $Details -or $null -eq $References) {
        throw 'Code Sequence pair Finding witnesses require complete checked journey, pair and Finding-reference ledgers.'
    }
    $n = [int]$Journeys.selected_record_count
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    $path = [string]$Journeys.path
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($path) -or $path.Length -gt 4096 -or
        $path.IndexOf([char]0) -ge 0 -or
        $Details.path -cne $path -or $References.path -cne $path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Details.independent_of_sequence_top -or
        -not [bool]$References.independent_of_sequence_top -or
        $anchorCount -gt ($n * 40) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        [int]$References.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        $Journeys.position_totals.Count -ne $n -or
        $References.positions.Count -ne $n -or
        $References.anchors.Count -ne $anchorCount -or
        [int]$References.selected_record_count -ne $n -or
        [int]$Details.selected_record_count -ne $n -or
        [int]$Details.pair_count -ne $pairCount -or
        $Details.pairs.Count -ne $pairCount -or
        [int]$References.counts.finding_reference_occurrences -gt ($n * 40)) {
        throw 'Code Sequence pair Finding witnesses received an incomplete or unbounded selection.'
    }

    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $positionIds = [string[]]::new($n)
    $idsByPosition = [object[]]::new($n)
    $consumedByPosition = [int[]]::new($n)
    $totalFindingRefs = 0
    for ($p = 0; $p -lt $n; $p++) {
        $row = $References.positions[$p]
        $positionIds[$p] = [string]$Journeys.position_totals[$p].record_id
        if ([int]$row.position -ne ($p + 1) -or
            $row.record_id -cne $positionIds[$p] -or
            $row.finding_refs.Count -gt 40 -or
            [int]$row.finding_statement_count -ne $row.finding_refs.Count -or
            [int]$Journeys.position_totals[$p].finding_statement_count -ne $row.finding_refs.Count) {
            throw 'Code Sequence pair Finding witnesses have a mismatched record position.'
        }
        $ids = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        $previousId = $null
        $severityHistogram = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        foreach ($ref in $row.finding_refs) {
            $id = [string]$ref.finding_id
            $severity = [string]$ref.severity
            $index = [int]$ref.anchor_index_in_anchor_journeys
            if ([string]::IsNullOrEmpty($id) -or
                ($null -ne $previousId -and [string]::CompareOrdinal($previousId, $id) -ge 0) -or
                -not ($severityNames -ccontains $severity) -or
                $index -lt 1 -or $index -gt $anchorCount -or
                $ids.ContainsKey($id)) {
                throw 'Code Sequence pair Finding witnesses found an invalid sorted per-record Finding reference.'
            }
            $ids.Add($id, $ref)
            $severityHistogram[$severity] = [int]$severityHistogram[$severity] + 1
            $previousId = $id
        }
        if (-not (Test-CodeSequenceFocusedSeverityEqual -Left $severityHistogram -Right $row.severity_statement_counts) -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $severityHistogram -Right $Journeys.position_totals[$p].severity_statement_counts)) {
            throw 'Code Sequence pair Finding witnesses disagree with per-record saved severity totals.'
        }
        $idsByPosition[$p] = $ids
        $totalFindingRefs += $ids.Count
    }
    if ($totalFindingRefs -ne [int]$References.counts.finding_reference_occurrences -or
        $totalFindingRefs -ne [int]$Journeys.counts.finding_statement_occurrences) {
        throw 'Code Sequence pair Finding witnesses have a mismatched Finding statement union.'
    }

    # Build one direct, complete canonical anchor x caller-position matrix.
    # EC-039 stores only reported positions; null cells are explicitly absent.
    $rowsByAnchor = [object[]]::new($anchorCount)
    $histByAnchor = [object[]]::new($anchorCount)
    $allAnchorStatements = 0
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $anchor = $Journeys.anchors[$a]
        $reference = $References.anchors[$a]
        $cells = [object[]]::new($n)
        $histograms = [object[]]::new($n)
        $previousPosition = 0
        $anchorStatements = 0
        if ([int]$reference.anchor_index_in_anchor_journeys -ne ($a + 1) -or
            $reference.presence_pattern -cne $anchor.presence_pattern -or
            $anchor.presence_pattern.Length -ne $n -or
            $anchor.presence_pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $n) {
            throw 'Code Sequence pair Finding witnesses have an inconsistent canonical anchor row.'
        }
        foreach ($r in $reference.references_in_caller_order) {
            $p = [int]$r.position
            if ($p -le $previousPosition -or $p -gt $n -or
                $r.record_id -cne $positionIds[$p - 1] -or
                $cells[$p - 1] -ne $null -or
                $r.finding_refs.Count -lt 1 -or $r.finding_refs.Count -gt 40 -or
                [int]$r.finding_statement_count -ne $r.finding_refs.Count) {
                throw 'Code Sequence pair Finding witnesses encountered invalid or duplicated anchor/record references.'
            }
            $hist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $previousId = $null
            foreach ($f in $r.finding_refs) {
                $id = [string]$f.finding_id
                $severity = [string]$f.severity
                if ([string]::IsNullOrEmpty($id) -or
                    ($null -ne $previousId -and [string]::CompareOrdinal($previousId, $id) -ge 0) -or
                    -not ($severityNames -ccontains $severity) -or
                    -not $idsByPosition[$p - 1].ContainsKey($id) -or
                    [int]$idsByPosition[$p - 1][$id].anchor_index_in_anchor_journeys -ne ($a + 1) -or
                    $idsByPosition[$p - 1][$id].severity -cne $severity) {
                    throw 'Code Sequence pair Finding witnesses mapped an ID to the wrong record, anchor or severity.'
                }
                $hist[$severity] = [int]$hist[$severity] + 1
                $consumedByPosition[$p - 1]++
                $previousId = $id
            }
            $cells[$p - 1] = $r
            $histograms[$p - 1] = $hist
            $anchorStatements += $r.finding_refs.Count
            $previousPosition = $p
        }
        $reporting = 0
        for ($p = 0; $p -lt $n; $p++) {
            $wasReported = ($anchor.presence_pattern[$p] -eq [char]'1')
            $hasRow = ($null -ne $cells[$p])
            $observation = $anchor.observations_in_caller_order[$p]
            if ([int]$observation.position -ne ($p + 1) -or
                $observation.record_id -cne $positionIds[$p] -or
                [bool]$observation.reported -ne $wasReported -or
                $wasReported -ne $hasRow -or
                [int]$observation.finding_statement_count -ne $(if ($hasRow) { $cells[$p].finding_refs.Count } else { 0 }) -or
                ($hasRow -and -not (Test-CodeSequenceFocusedSeverityEqual -Left $histograms[$p] -Right $observation.severity_statement_counts)) -or
                (-not $hasRow -and $null -ne $observation.severity_statement_counts)) {
                throw 'Code Sequence pair Finding witnesses disagree with complete original anchor observations.'
            }
            if ($hasRow) { $reporting++ }
        }
        if ($reporting -ne [int]$anchor.reporting_record_count -or
            $reporting -ne [int]$reference.reporting_record_count -or
            $anchorStatements -ne [int]$anchor.finding_statement_occurrences -or
            $anchorStatements -ne [int]$reference.finding_statement_occurrences) {
            throw 'Code Sequence pair Finding witnesses do not conserve per-anchor reporting and statement counts.'
        }
        $allAnchorStatements += $anchorStatements
        $rowsByAnchor[$a] = $cells
        $histByAnchor[$a] = $histograms
    }
    for ($p = 0; $p -lt $n; $p++) {
        if ($consumedByPosition[$p] -ne $idsByPosition[$p].Count) {
            throw 'Code Sequence pair Finding witnesses omitted or reused an original Finding ID.'
        }
    }
    if ($allAnchorStatements -ne $totalFindingRefs) {
        throw 'Code Sequence pair Finding witnesses failed full anchor-to-position ID conservation.'
    }

    # Each emitted Finding reference is limited to one appearance per pair
    # containing its record. At most (N-1) * original selected references.
    $pairs = [System.Collections.Generic.List[object]]::new()
    $totalChangedPairs = 0; $totalChangedAnchors = 0
    $totalLeftOnly = 0; $totalRightOnly = 0; $totalChangedRetained = 0
    $leftEmitted = 0; $rightEmitted = 0
    for ($left = 0; $left -lt ($n - 1); $left++) {
        for ($right = $left + 1; $right -lt $n; $right++) {
            $pairNumber = $pairs.Count + 1
            $pair = $Details.pairs[$pairNumber - 1]
            if ([int]$pair.pair_index -ne $pairNumber -or
                [int]$pair.left_position -ne ($left + 1) -or
                [int]$pair.right_position -ne ($right + 1) -or
                $pair.left_record_id -cne $positionIds[$left] -or
                $pair.right_record_id -cne $positionIds[$right]) {
                throw 'Code Sequence pair Finding witnesses found a reordered or mismatched report pair.'
            }
            $leftOnly = [System.Collections.Generic.List[int]]::new()
            $rightOnly = [System.Collections.Generic.List[int]]::new()
            $same = [System.Collections.Generic.List[int]]::new()
            $changed = [System.Collections.Generic.List[int]]::new()
            $absent = [System.Collections.Generic.List[int]]::new()
            $crossGap = [System.Collections.Generic.List[int]]::new()
            $changedRows = [System.Collections.Generic.List[object]]::new()
            $retainedChangedDetailIndex = 0
            $lOnlyStatements = 0; $rOnlyStatements = 0
            $lRetainedStatements = 0; $rRetainedStatements = 0
            $lEmittedPair = 0; $rEmittedPair = 0
            $retainedDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}

            for ($a = 0; $a -lt $anchorCount; $a++) {
                $index = $a + 1
                $lRow = $rowsByAnchor[$a][$left]
                $rRow = $rowsByAnchor[$a][$right]
                $hasLeft = ($null -ne $lRow)
                $hasRight = ($null -ne $rRow)
                $ln = if ($hasLeft) { $lRow.finding_refs.Count } else { 0 }
                $rn = if ($hasRight) { $rRow.finding_refs.Count } else { 0 }
                $delta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
                $histEqual = $true
                foreach ($severity in $severityNames) {
                    $lv = if ($hasLeft) { [int]$histByAnchor[$a][$left][$severity] } else { 0 }
                    $rv = if ($hasRight) { [int]$histByAnchor[$a][$right][$severity] } else { 0 }
                    $delta[$severity] = $rv - $lv
                    if ($lv -ne $rv) { $histEqual = $false }
                    if ($hasLeft -and $hasRight) {
                        $retainedDelta[$severity] = [int]$retainedDelta[$severity] + $rv - $lv
                    }
                }
                $gap = $false
                if ($hasLeft -and $hasRight) {
                    $lRetainedStatements += $ln
                    $rRetainedStatements += $rn
                    for ($m = $left + 1; $m -lt $right; $m++) {
                        if ($null -eq $rowsByAnchor[$a][$m]) { $gap = $true; break }
                    }
                    if ($gap) { $crossGap.Add($index) }
                    if ($histEqual) { $same.Add($index); continue }
                    $changed.Add($index)
                    $kind = 'retained_changed_severity'
                    if ($retainedChangedDetailIndex -ge $pair.retained_changed_severity_details.Count) {
                        throw 'Code Sequence pair Finding witnesses lack a retained severity change witness.'
                    }
                    $w = $pair.retained_changed_severity_details[$retainedChangedDetailIndex]
                    if ([int]$w.anchor_index_in_anchor_journeys -ne $index -or
                        [int]$w.left_finding_statement_count -ne $ln -or
                        [int]$w.right_finding_statement_count -ne $rn -or
                        [int]$w.finding_statement_count_delta -ne ($rn - $ln) -or
                        [bool]$w.shared_with_internal_unreported_position -ne $gap -or
                        -not (Test-CodeSequenceFocusedSeverityEqual -Left $w.severity_statement_delta -Right $delta)) {
                        throw 'Code Sequence pair Finding witnesses contradict a retained severity delta.'
                    }
                    $retainedChangedDetailIndex++
                } elseif ($hasLeft) {
                    $leftOnly.Add($index)
                    $lOnlyStatements += $ln
                    $kind = 'left_only'
                } elseif ($hasRight) {
                    $rightOnly.Add($index)
                    $rOnlyStatements += $rn
                    $kind = 'right_only'
                } else {
                    $absent.Add($index)
                    continue
                }

                # Keep original per-side IDs separate. These are NOT paired
                # Finding identities, even when their spellings coincide.
                [object[]] $leftRefs = if ($hasLeft) { @($lRow.finding_refs) } else { @() }
                [object[]] $rightRefs = if ($hasRight) { @($rRow.finding_refs) } else { @() }
                $lEmittedPair += $leftRefs.Count
                $rEmittedPair += $rightRefs.Count
                $changedRows.Add([ordered]@{
                    anchor_index_in_anchor_journeys = $index
                    contrast_kind = $kind
                    left_record_id = $positionIds[$left]
                    right_record_id = $positionIds[$right]
                    left_finding_refs = $leftRefs
                    right_finding_refs = $rightRefs
                    left_finding_statement_count = $ln
                    right_finding_statement_count = $rn
                    finding_statement_count_delta = $rn - $ln
                    severity_statement_delta = $delta
                    shared_with_internal_unreported_position = $gap
                })
            }
            if (($leftOnly -join ',') -cne ($pair.left_only_anchor_indices -join ',') -or
                ($rightOnly -join ',') -cne ($pair.right_only_anchor_indices -join ',') -or
                ($same -join ',') -cne ($pair.retained_same_severity_anchor_indices -join ',') -or
                ($changed -join ',') -cne ($pair.retained_changed_severity_anchor_indices -join ',') -or
                ($absent -join ',') -cne ($pair.both_unreported_anchor_indices -join ',') -or
                ($crossGap -join ',') -cne ($pair.shared_with_internal_unreported_position_anchor_indices -join ',') -or
                $retainedChangedDetailIndex -ne $pair.retained_changed_severity_details.Count -or
                $lOnlyStatements -ne [int]$pair.left_only_finding_statement_count -or
                $rOnlyStatements -ne [int]$pair.right_only_finding_statement_count -or
                $lRetainedStatements -ne [int]$pair.retained_left_finding_statement_count -or
                $rRetainedStatements -ne [int]$pair.retained_right_finding_statement_count -or
                ($changedRows.Count -ne [int]$pair.changed_exact_anchor_count) -or
                (($idsByPosition[$right].Count - $idsByPosition[$left].Count) -ne [int]$pair.finding_statement_count_delta) -or
                -not (Test-CodeSequenceFocusedSeverityEqual -Left $retainedDelta -Right $pair.severity_statement_delta_retained_anchors)) {
                throw 'Code Sequence pair Finding witnesses do not reconcile with complete EC-037 pair partitions.'
            }
            $allDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            foreach ($severity in $severityNames) {
                $allDelta[$severity] = [int]$References.positions[$right].severity_statement_counts[$severity] -
                    [int]$References.positions[$left].severity_statement_counts[$severity]
            }
            if (-not (Test-CodeSequenceFocusedSeverityEqual -Left $allDelta -Right $pair.severity_statement_delta_all_reported_anchors)) {
                throw 'Code Sequence pair Finding witnesses found inconsistent original full-position severity deltas.'
            }
            if ($changedRows.Count -gt 0) { $totalChangedPairs++ }
            $totalChangedAnchors += $changedRows.Count
            $totalLeftOnly += $leftOnly.Count
            $totalRightOnly += $rightOnly.Count
            $totalChangedRetained += $changed.Count
            $leftEmitted += $lEmittedPair
            $rightEmitted += $rEmittedPair
            $pairs.Add([ordered]@{
                pair_index = $pairNumber
                left_position = $left + 1
                right_position = $right + 1
                left_record_id = $positionIds[$left]
                right_record_id = $positionIds[$right]
                changed_exact_anchor_count = $changedRows.Count
                left_changed_finding_reference_occurrences = $lEmittedPair
                right_changed_finding_reference_occurrences = $rEmittedPair
                changed_anchors = $changedRows.ToArray()
            })
        }
    }
    if ($pairs.Count -ne $pairCount -or
        $totalChangedPairs -ne [int]$Details.counts.different_saved_path_profile_pair_count -or
        $totalLeftOnly -ne [int]$Details.counts.left_only_anchor_pair_occurrences -or
        $totalRightOnly -ne [int]$Details.counts.right_only_anchor_pair_occurrences -or
        $totalChangedRetained -ne [int]$Details.counts.retained_changed_severity_anchor_pair_occurrences -or
        $totalChangedAnchors -ne ($totalLeftOnly + $totalRightOnly + $totalChangedRetained) -or
        ($leftEmitted + $rightEmitted) -gt (($n - 1) * $totalFindingRefs)) {
        throw 'Code Sequence pair Finding witnesses failed pair/category or disclosure bound conservation.'
    }
    return [ordered]@{
        scope = 'all_changed_saved_exact_anchor_pairs_with_both_original_record_scoped_Finding_ID_sides'
        path = $path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $n
        pair_count = $pairCount
        independent_of_sequence_top = $true
        pair_index_reference = 'one_based_into_anchor_pair_details.pairs'
        anchor_index_reference = 'one_based_into_anchor_journeys.anchors'
        finding_id_scope = 'separate_within_each_original_saved_record_no_cross_record_Finding_matches'
        counts = [ordered]@{
            pairs_with_changed_exact_anchor_count = $totalChangedPairs
            changed_exact_anchor_pair_occurrences = $totalChangedAnchors
            left_only_anchor_pair_occurrences = $totalLeftOnly
            right_only_anchor_pair_occurrences = $totalRightOnly
            retained_changed_severity_anchor_pair_occurrences = $totalChangedRetained
            left_changed_finding_reference_occurrences = $leftEmitted
            right_changed_finding_reference_occurrences = $rightEmitted
            changed_finding_reference_occurrences = $leftEmitted + $rightEmitted
        }
        pairs = $pairs.ToArray()
        explanation = 'Each pair lists ONLY one-sided exact anchors or retained exact anchors with changed SAVED five-severity Finding-statement histograms, in canonical order. Its left/right arrays carry their own record-scoped original Finding IDs; there is no matching, identity inference or per-Finding severity transition across records. Unchanged-histogram anchors are intentionally absent even when ID spellings or prose differ. Pair order is caller-selected, not authenticated time; unreported does not prove a fix. No source/prose/quote access, extra saved-record read, network or writer. Complete for 2..12 records and not clipped by SequenceTop.'
    }
}

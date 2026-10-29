#requires -Version 7.0
<#
    EC-041: inverse navigation from each ORIGINAL record-scoped Finding ID
    to every unordered selected-report pair that contains that record.

    This is an in-memory, non-mutating projection over checked EC-034,
    EC-037, EC-039 and EC-040 views. Its classification is about SAVED
    quote-anchor and severity-statement histograms, not identities or
    per-Finding changes between records. No extra input, I/O or access.
#>

function Get-CodeSequenceFocusedFindingPairLookup {
    param(
        [object] $Journeys,
        [object] $Details,
        [object] $References,
        [object] $PairReferences
    )

    if ($null -eq $Journeys -or $null -eq $Details -or
        $null -eq $References -or $null -eq $PairReferences) {
        throw 'Code Sequence Finding-to-pair navigation needs all four complete checked views.'
    }
    $n = [int]$Journeys.selected_record_count
    $path = [string]$Journeys.path
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($path) -or $path.Length -gt 4096 -or
        $path.IndexOf([char]0) -ge 0 -or
        $Details.path -cne $path -or $References.path -cne $path -or
        $PairReferences.path -cne $path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Details.independent_of_sequence_top -or
        -not [bool]$References.independent_of_sequence_top -or
        -not [bool]$PairReferences.independent_of_sequence_top -or
        $anchorCount -gt ($n * 40) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        [int]$References.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        $References.anchors.Count -ne $anchorCount -or
        $References.positions.Count -ne $n -or
        $Journeys.position_totals.Count -ne $n -or
        [int]$Details.selected_record_count -ne $n -or
        [int]$References.selected_record_count -ne $n -or
        [int]$PairReferences.selected_record_count -ne $n -or
        [int]$Details.pair_count -ne $pairCount -or
        [int]$PairReferences.pair_count -ne $pairCount -or
        $Details.pairs.Count -ne $pairCount -or
        $PairReferences.pairs.Count -ne $pairCount -or
        [int]$References.counts.finding_reference_occurrences -gt ($n * 40) -or
        [bool]$Journeys.path_found_in_selected_records -ne ($anchorCount -gt 0) -or
        [bool]$References.path_found_in_selected_records -ne ($anchorCount -gt 0) -or
        [bool]$PairReferences.path_found_in_selected_records -ne ($anchorCount -gt 0)) {
        throw 'Code Sequence Finding-to-pair input is incomplete, inconsistent or outside bounds.'
    }

    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $positionIds = [string[]]::new($n)
    $byPosition = [object[]]::new($n)
    $usedIds = [object[]]::new($n)
    $matrix = [object[]]::new($anchorCount)
    $allRefs = 0
    for ($p = 0; $p -lt $n; $p++) {
        $recordRow = $References.positions[$p]
        $positionIds[$p] = [string]$Journeys.position_totals[$p].record_id
        if ([int]$recordRow.position -ne ($p + 1) -or
            $recordRow.record_id -cne $positionIds[$p] -or
            $recordRow.finding_refs.Count -gt 40 -or
            [int]$recordRow.finding_statement_count -ne $recordRow.finding_refs.Count -or
            [int]$Journeys.position_totals[$p].finding_statement_count -ne $recordRow.finding_refs.Count) {
            throw 'Code Sequence Finding-to-pair original saved-record row is inconsistent.'
        }
        $dictionary = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        $usedIds[$p] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $lastId = $null
        $severityCounts = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        foreach ($f in $recordRow.finding_refs) {
            $id = [string]$f.finding_id
            $severity = [string]$f.severity
            $index = [int]$f.anchor_index_in_anchor_journeys
            if ([string]::IsNullOrEmpty($id) -or
                ($null -ne $lastId -and [string]::CompareOrdinal($lastId, $id) -ge 0) -or
                -not ($severityNames -ccontains $severity) -or
                $index -lt 1 -or $index -gt $anchorCount -or
                $dictionary.ContainsKey($id)) {
                throw 'Code Sequence Finding-to-pair found invalid or unsorted original scoped Finding IDs.'
            }
            $dictionary.Add($id, $f)
            $severityCounts[$severity] = [int]$severityCounts[$severity] + 1
            $lastId = $id
        }
        if (-not (Test-CodeSequenceFocusedSeverityEqual -Left $severityCounts -Right $recordRow.severity_statement_counts) -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $severityCounts -Right $Journeys.position_totals[$p].severity_statement_counts)) {
            throw 'Code Sequence Finding-to-pair original record severity distribution is inconsistent.'
        }
        $byPosition[$p] = $dictionary
        $allRefs += $dictionary.Count
    }
    if ($allRefs -ne [int]$References.counts.finding_reference_occurrences -or
        $allRefs -ne [int]$Journeys.counts.finding_statement_occurrences) {
        throw 'Code Sequence Finding-to-pair original Finding union is inconsistent.'
    }

    # Build the canonical anchor x position matrix, including real empty cells.
    # Each scoped Finding ID must be consumed exactly once by this index.
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $anchor = $Journeys.anchors[$a]
        $source = $References.anchors[$a]
        $cells = [object[]]::new($n)
        if ([int]$source.anchor_index_in_anchor_journeys -ne ($a + 1) -or
            $source.presence_pattern -cne $anchor.presence_pattern -or
            $anchor.presence_pattern.Length -ne $n -or
            $anchor.presence_pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $n) {
            throw 'Code Sequence Finding-to-pair canonical anchor identity is inconsistent.'
        }
        $lastPosition = 0
        $totalStatements = 0
        foreach ($r in $source.references_in_caller_order) {
            $p = [int]$r.position
            if ($p -le $lastPosition -or $p -gt $n -or
                $r.record_id -cne $positionIds[$p - 1] -or
                $r.finding_refs.Count -lt 1 -or $r.finding_refs.Count -gt 40 -or
                [int]$r.finding_statement_count -ne $r.finding_refs.Count) {
                throw 'Code Sequence Finding-to-pair anchor/record membership is invalid.'
            }
            $lastId = $null
            $hist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            foreach ($f in $r.finding_refs) {
                $id = [string]$f.finding_id
                $severity = [string]$f.severity
                if ([string]::IsNullOrEmpty($id) -or
                    ($null -ne $lastId -and [string]::CompareOrdinal($lastId, $id) -ge 0) -or
                    -not ($severityNames -ccontains $severity) -or
                    -not $byPosition[$p - 1].ContainsKey($id) -or
                    [int]$byPosition[$p - 1][$id].anchor_index_in_anchor_journeys -ne ($a + 1) -or
                    $byPosition[$p - 1][$id].severity -cne $severity -or
                    -not $usedIds[$p - 1].Add($id)) {
                    throw 'Code Sequence Finding-to-pair reused or remapped an original saved Finding ID.'
                }
                $hist[$severity] = [int]$hist[$severity] + 1
                $lastId = $id
            }
            $cells[$p - 1] = $r
            $totalStatements += $r.finding_refs.Count
            $lastPosition = $p
        }
        $reporting = 0
        for ($p = 0; $p -lt $n; $p++) {
            $observation = $anchor.observations_in_caller_order[$p]
            $hasRow = ($null -ne $cells[$p])
            $observedCount = 0
            $observedHistogram = $null
            if ($hasRow) {
                $observedHistogram = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
                foreach ($f in $cells[$p].finding_refs) {
                    $severity = [string]$f.severity
                    $observedHistogram[$severity] = [int]$observedHistogram[$severity] + 1
                    $observedCount++
                }
            }
            if ([int]$observation.position -ne ($p + 1) -or
                $observation.record_id -cne $positionIds[$p] -or
                [bool]$observation.reported -ne $hasRow -or
                ($anchor.presence_pattern[$p] -eq [char]'1') -ne $hasRow -or
                [int]$observation.finding_statement_count -ne $observedCount -or
                ($hasRow -and -not (Test-CodeSequenceFocusedSeverityEqual -Left $observation.severity_statement_counts -Right $observedHistogram)) -or
                (-not $hasRow -and $null -ne $observation.severity_statement_counts)) {
                throw 'Code Sequence Finding-to-pair original anchor observations are inconsistent.'
            }
            if ($hasRow) { $reporting++ }
        }
        if ([int]$source.reporting_record_count -ne $reporting -or
            [int]$anchor.reporting_record_count -ne $reporting -or
            [int]$source.finding_statement_occurrences -ne $totalStatements -or
            [int]$anchor.finding_statement_occurrences -ne $totalStatements) {
            throw 'Code Sequence Finding-to-pair anchor statement totals do not conserve source evidence.'
        }
        $matrix[$a] = $cells
    }
    for ($p = 0; $p -lt $n; $p++) {
        if ($usedIds[$p].Count -ne $byPosition[$p].Count) {
            throw 'Code Sequence Finding-to-pair lost an original Finding ID.'
        }
    }

    # Independently derive all pair/anchor classes from report membership and
    # saved-severity histograms, then cross-check EC-037 partitions and EC-040
    # changed-ID witness lists before any reverse navigation is emitted.
    $classesByPair = [object[]]::new($pairCount)
    $gapsByPair = [object[]]::new($pairCount)
    $summaryByPair = [object[]]::new($pairCount)
    $pairCursor = 0
    $expectedChangedLeftTotal = 0; $expectedChangedRightTotal = 0
    for ($left = 0; $left -lt ($n - 1); $left++) {
        for ($right = $left + 1; $right -lt $n; $right++) {
            $details = $Details.pairs[$pairCursor]
            $witness = $PairReferences.pairs[$pairCursor]
            if ([int]$details.pair_index -ne ($pairCursor + 1) -or
                [int]$witness.pair_index -ne ($pairCursor + 1) -or
                [int]$details.left_position -ne ($left + 1) -or
                [int]$witness.left_position -ne ($left + 1) -or
                [int]$details.right_position -ne ($right + 1) -or
                [int]$witness.right_position -ne ($right + 1) -or
                $details.left_record_id -cne $positionIds[$left] -or
                $details.right_record_id -cne $positionIds[$right] -or
                $witness.left_record_id -cne $positionIds[$left] -or
                $witness.right_record_id -cne $positionIds[$right]) {
                throw 'Code Sequence Finding-to-pair pair ordering or saved identities changed.'
            }
            $classes = [string[]]::new($anchorCount)
            $gaps = [bool[]]::new($anchorCount)
            $leftOnly = [System.Collections.Generic.List[int]]::new()
            $rightOnly = [System.Collections.Generic.List[int]]::new()
            $retainedSame = [System.Collections.Generic.List[int]]::new()
            $retainedChanged = [System.Collections.Generic.List[int]]::new()
            $bothMissing = [System.Collections.Generic.List[int]]::new()
            $crossGap = [System.Collections.Generic.List[int]]::new()
            $witnessCursor = 0
            $leftChangedRefs = 0; $rightChangedRefs = 0
            $leftStableRefs = 0; $rightStableRefs = 0
            for ($a = 0; $a -lt $anchorCount; $a++) {
                $l = $matrix[$a][$left]
                $r = $matrix[$a][$right]
                $hasLeft = ($null -ne $l)
                $hasRight = ($null -ne $r)
                $kind = ''
                if ($hasLeft -and $hasRight) {
                    $lo = $Journeys.anchors[$a].observations_in_caller_order[$left]
                    $ro = $Journeys.anchors[$a].observations_in_caller_order[$right]
                    if (Test-CodeSequenceFocusedSeverityEqual -Left $lo.severity_statement_counts -Right $ro.severity_statement_counts) {
                        $kind = 'retained_same_severity'; $retainedSame.Add($a + 1)
                        $leftStableRefs += $l.finding_refs.Count
                        $rightStableRefs += $r.finding_refs.Count
                    } else {
                        $kind = 'retained_changed_severity'; $retainedChanged.Add($a + 1)
                    }
                    for ($mid = $left + 1; $mid -lt $right; $mid++) {
                        if ($null -eq $matrix[$a][$mid]) { $gaps[$a] = $true; break }
                    }
                    if ($gaps[$a]) { $crossGap.Add($a + 1) }
                } elseif ($hasLeft) {
                    $kind = 'left_only'; $leftOnly.Add($a + 1)
                } elseif ($hasRight) {
                    $kind = 'right_only'; $rightOnly.Add($a + 1)
                } else {
                    $kind = 'both_unreported'; $bothMissing.Add($a + 1)
                }
                $classes[$a] = $kind
                if ($kind -eq 'both_unreported' -or $kind -eq 'retained_same_severity') { continue }
                if ($witnessCursor -ge $witness.changed_anchors.Count) {
                    throw 'Code Sequence Finding-to-pair changed-pair witness is incomplete.'
                }
                $entry = $witness.changed_anchors[$witnessCursor]
                if ([int]$entry.anchor_index_in_anchor_journeys -ne ($a + 1) -or
                    $entry.contrast_kind -cne $kind -or
                    $entry.left_record_id -cne $positionIds[$left] -or
                    $entry.right_record_id -cne $positionIds[$right] -or
                    [bool]$entry.shared_with_internal_unreported_position -ne $gaps[$a]) {
                    throw 'Code Sequence Finding-to-pair changed-pair anchor or category differs from original.'
                }
                [object[]]$expectedL = if ($hasLeft) { @($l.finding_refs) } else { @() }
                [object[]]$expectedR = if ($hasRight) { @($r.finding_refs) } else { @() }
                if ($entry.left_finding_refs.Count -ne $expectedL.Count -or
                    $entry.right_finding_refs.Count -ne $expectedR.Count -or
                    [int]$entry.left_finding_statement_count -ne $expectedL.Count -or
                    [int]$entry.right_finding_statement_count -ne $expectedR.Count) {
                    throw 'Code Sequence Finding-to-pair changed-pair statement counts differ from originals.'
                }
                for ($i = 0; $i -lt $expectedL.Count; $i++) {
                    if ($entry.left_finding_refs[$i].finding_id -cne $expectedL[$i].finding_id -or
                        $entry.left_finding_refs[$i].severity -cne $expectedL[$i].severity) {
                        throw 'Code Sequence Finding-to-pair changed-pair left Finding ID does not match its record.'
                    }
                }
                for ($i = 0; $i -lt $expectedR.Count; $i++) {
                    if ($entry.right_finding_refs[$i].finding_id -cne $expectedR[$i].finding_id -or
                        $entry.right_finding_refs[$i].severity -cne $expectedR[$i].severity) {
                        throw 'Code Sequence Finding-to-pair changed-pair right Finding ID does not match its record.'
                    }
                }
                $leftChangedRefs += $expectedL.Count
                $rightChangedRefs += $expectedR.Count
                $witnessCursor++
            }
            if (($leftOnly -join ',') -cne ($details.left_only_anchor_indices -join ',') -or
                ($rightOnly -join ',') -cne ($details.right_only_anchor_indices -join ',') -or
                ($retainedSame -join ',') -cne ($details.retained_same_severity_anchor_indices -join ',') -or
                ($retainedChanged -join ',') -cne ($details.retained_changed_severity_anchor_indices -join ',') -or
                ($bothMissing -join ',') -cne ($details.both_unreported_anchor_indices -join ',') -or
                ($crossGap -join ',') -cne ($details.shared_with_internal_unreported_position_anchor_indices -join ',') -or
                $witnessCursor -ne $witness.changed_anchors.Count -or
                $witnessCursor -ne [int]$witness.changed_exact_anchor_count -or
                $leftChangedRefs -ne [int]$witness.left_changed_finding_reference_occurrences -or
                $rightChangedRefs -ne [int]$witness.right_changed_finding_reference_occurrences -or
                ($leftChangedRefs + $leftStableRefs) -ne $byPosition[$left].Count -or
                ($rightChangedRefs + $rightStableRefs) -ne $byPosition[$right].Count) {
                throw 'Code Sequence Finding-to-pair categories or Finding incidence do not conserve checked pair evidence.'
            }
            $classesByPair[$pairCursor] = $classes
            $gapsByPair[$pairCursor] = $gaps
            $summaryByPair[$pairCursor] = [ordered]@{
                pair_index = $pairCursor + 1
                left_position = $left + 1
                right_position = $right + 1
                left_record_id = $positionIds[$left]
                right_record_id = $positionIds[$right]
                left_finding_pair_incidence_count = $byPosition[$left].Count
                right_finding_pair_incidence_count = $byPosition[$right].Count
                changed_left_finding_pair_incidence_count = $leftChangedRefs
                changed_right_finding_pair_incidence_count = $rightChangedRefs
                stable_left_finding_pair_incidence_count = $leftStableRefs
                stable_right_finding_pair_incidence_count = $rightStableRefs
            }
            $expectedChangedLeftTotal += $leftChangedRefs
            $expectedChangedRightTotal += $rightChangedRefs
            $pairCursor++
        }
    }
    if ($pairCursor -ne $pairCount -or
        $expectedChangedLeftTotal -ne [int]$PairReferences.counts.left_changed_finding_reference_occurrences -or
        $expectedChangedRightTotal -ne [int]$PairReferences.counts.right_changed_finding_reference_occurrences -or
        ($expectedChangedLeftTotal + $expectedChangedRightTotal) -ne
            [int]$PairReferences.counts.changed_finding_reference_occurrences) {
        throw 'Code Sequence Finding-to-pair has incorrect complete changed-pair marginals.'
    }

    # Invert EVERY original scoped Finding, including those on anchors which
    # never differ. The pair list is complete and canonical, not Top-capped.
    $positions = [System.Collections.Generic.List[object]]::new()
    $totalIncidences = 0; $changedIncidences = 0; $stableIncidences = 0
    $leftOnlyIncidences = 0; $rightOnlyIncidences = 0
    $retainedChangedIncidences = 0; $retainedSameIncidences = 0
    $gapIncidences = 0; $findingsWithChanges = 0; $findingsStableInAllPairs = 0
    $countByPairLeft = [int[]]::new($pairCount)
    $countByPairRight = [int[]]::new($pairCount)
    $changedByPairLeft = [int[]]::new($pairCount)
    $changedByPairRight = [int[]]::new($pairCount)
    for ($p = 0; $p -lt $n; $p++) {
        $original = $References.positions[$p]
        $findings = [System.Collections.Generic.List[object]]::new()
        $positionChanged = 0; $positionStable = 0
        foreach ($f in $original.finding_refs) {
            $index = [int]$f.anchor_index_in_anchor_journeys
            $comparisons = [System.Collections.Generic.List[object]]::new()
            $changedCount = 0; $stableCount = 0
            $lOnlyCount = 0; $rOnlyCount = 0
            $retainedChangedCount = 0; $retainedSameCount = 0
            for ($k = 0; $k -lt $pairCount; $k++) {
                $pair = $summaryByPair[$k]
                $onLeft = ([int]$pair.left_position -eq ($p + 1))
                $onRight = ([int]$pair.right_position -eq ($p + 1))
                if (-not $onLeft -and -not $onRight) { continue }
                $other = if ($onLeft) { [int]$pair.right_position - 1 } else { [int]$pair.left_position - 1 }
                $kind = [string]$classesByPair[$k][$index - 1]
                if ($kind -ne 'left_only' -and $kind -ne 'right_only' -and
                    $kind -ne 'retained_same_severity' -and $kind -ne 'retained_changed_severity') {
                    throw 'Code Sequence Finding-to-pair classified a reported Finding as unreported.'
                }
                if (($kind -eq 'left_only' -and -not $onLeft) -or
                    ($kind -eq 'right_only' -and -not $onRight)) {
                    throw 'Code Sequence Finding-to-pair reversed a one-sided saved Finding.'
                }
                $counterpart = $matrix[$index - 1][$other]
                $otherCount = if ($null -eq $counterpart) { 0 } else { $counterpart.finding_refs.Count }
                if (($kind -eq 'left_only' -or $kind -eq 'right_only') -ne ($otherCount -eq 0)) {
                    throw 'Code Sequence Finding-to-pair counterpart membership is inconsistent.'
                }
                $changed = ($kind -ne 'retained_same_severity')
                if ($changed) {
                    $changedCount++
                    if ($onLeft) { $changedByPairLeft[$k]++ } else { $changedByPairRight[$k]++ }
                } else { $stableCount++ }
                if ($onLeft) { $countByPairLeft[$k]++ } else { $countByPairRight[$k]++ }
                switch ($kind) {
                    'left_only' { $lOnlyCount++; $leftOnlyIncidences++ }
                    'right_only' { $rOnlyCount++; $rightOnlyIncidences++ }
                    'retained_changed_severity' { $retainedChangedCount++; $retainedChangedIncidences++ }
                    'retained_same_severity' { $retainedSameCount++; $retainedSameIncidences++ }
                }
                if ($gapsByPair[$k][$index - 1]) { $gapIncidences++ }
                $comparisons.Add([ordered]@{
                    pair_index = $k + 1
                    this_side = $(if ($onLeft) { 'left' } else { 'right' })
                    counterpart_position = $other + 1
                    counterpart_record_id = $positionIds[$other]
                    anchor_pair_class = $kind
                    anchor_changed_in_pair = $changed
                    counterpart_finding_statement_count = $otherCount
                    shared_with_internal_unreported_position = [bool]$gapsByPair[$k][$index - 1]
                })
            }
            if ($comparisons.Count -ne ($n - 1) -or
                ($changedCount + $stableCount) -ne $comparisons.Count -or
                ($lOnlyCount + $rOnlyCount + $retainedChangedCount + $retainedSameCount) -ne $comparisons.Count) {
                throw 'Code Sequence Finding-to-pair omitted a report-pair involving an original Finding.'
            }
            if ($changedCount -gt 0) { $findingsWithChanges++ } else { $findingsStableInAllPairs++ }
            $totalIncidences += $comparisons.Count
            $changedIncidences += $changedCount; $stableIncidences += $stableCount
            $positionChanged += $changedCount; $positionStable += $stableCount
            $findings.Add([ordered]@{
                finding_id = [string]$f.finding_id
                severity = [string]$f.severity
                anchor_index_in_anchor_journeys = $index
                pair_incidence_count = $comparisons.Count
                changed_anchor_pair_incidence_count = $changedCount
                stable_anchor_pair_incidence_count = $stableCount
                anchor_pair_classes = [ordered]@{
                    left_only = $lOnlyCount
                    right_only = $rOnlyCount
                    retained_changed_severity = $retainedChangedCount
                    retained_same_severity = $retainedSameCount
                }
                compared_pairs = $comparisons.ToArray()
            })
        }
        $positions.Add([ordered]@{
            position = $p + 1
            record_id = $positionIds[$p]
            finding_reference_count = $findings.Count
            changed_anchor_pair_incidence_count = $positionChanged
            stable_anchor_pair_incidence_count = $positionStable
            finding_refs = $findings.ToArray()
        })
        if ($findings.Count -ne $byPosition[$p].Count -or
            ($positionChanged + $positionStable) -ne (($n - 1) * $findings.Count)) {
            throw 'Code Sequence Finding-to-pair record marginal is inconsistent.'
        }
    }
    for ($k = 0; $k -lt $pairCount; $k++) {
        $pair = $summaryByPair[$k]
        if ($countByPairLeft[$k] -ne [int]$pair.left_finding_pair_incidence_count -or
            $countByPairRight[$k] -ne [int]$pair.right_finding_pair_incidence_count -or
            $changedByPairLeft[$k] -ne [int]$pair.changed_left_finding_pair_incidence_count -or
            $changedByPairRight[$k] -ne [int]$pair.changed_right_finding_pair_incidence_count) {
            throw 'Code Sequence Finding-to-pair inverse list does not reconstruct exact pair witnesses.'
        }
    }
    if ($totalIncidences -ne (($n - 1) * $allRefs) -or
        $totalIncidences -gt (($n - 1) * $n * 40) -or
        $changedIncidences -ne ($expectedChangedLeftTotal + $expectedChangedRightTotal) -or
        ($changedIncidences + $stableIncidences) -ne $totalIncidences -or
        ($leftOnlyIncidences + $rightOnlyIncidences + $retainedChangedIncidences + $retainedSameIncidences) -ne $totalIncidences -or
        ($leftOnlyIncidences + $rightOnlyIncidences + $retainedChangedIncidences) -ne $changedIncidences -or
        ($findingsWithChanges + $findingsStableInAllPairs) -ne $allRefs) {
        throw 'Code Sequence Finding-to-pair final full original Finding coverage failed.'
    }

    return [ordered]@{
        scope = 'every_original_record_scoped_Finding_ID_to_all_involving_saved_report_pairs'
        path = $path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $n
        pair_count = $pairCount
        independent_of_sequence_top = $true
        pair_index_reference = 'one_based_into_anchor_pair_details.pairs_and_anchor_pair_finding_refs.pairs'
        anchor_index_reference = 'one_based_into_anchor_journeys.anchors_and_anchor_finding_refs.anchors'
        finding_id_scope = 'original_record_only_no_cross_record_Finding_identity'
        counts = [ordered]@{
            original_finding_reference_count = $allRefs
            complete_finding_pair_incidence_count = $totalIncidences
            changed_anchor_finding_pair_incidence_count = $changedIncidences
            stable_anchor_finding_pair_incidence_count = $stableIncidences
            left_only_finding_pair_incidence_count = $leftOnlyIncidences
            right_only_finding_pair_incidence_count = $rightOnlyIncidences
            retained_changed_severity_finding_pair_incidence_count = $retainedChangedIncidences
            retained_same_severity_finding_pair_incidence_count = $retainedSameIncidences
            shared_internal_unreported_gap_finding_pair_incidence_count = $gapIncidences
            findings_with_at_least_one_changed_anchor_pair_count = $findingsWithChanges
            findings_with_only_stable_anchor_pairs_count = $findingsStableInAllPairs
        }
        pairs = $summaryByPair
        positions = $positions.ToArray()
        explanation = 'For every original (selected record_id, finding_id), list ALL pair indexes involving that report, including unchanged saved anchor histograms and one-sided changes. The counterpart count and its record/anchor indexes allow joining to anchor_finding_refs without multiplying the other record IDs in this view. A retained_same_severity classification is equality of exact quote anchor and saved severity STATEMENT histogram only, not matching Findings, equal prose, fixed code or verified bug status. Caller order is not verified time. No source, saved Finding text, quotation, new read, writer or remote action; independent of SequenceTop.'
    }
}

#requires -Version 7.0
<#
    EC-054: exhaustive, actually OBSERVED contiguous saved-profile class motifs.
    A motif is a whole caller-position class walk, not just its two endpoint
    classes and never a graph edge path spliced from unrelated observations.
    All N(N-1)/2 spans of length >=2 are indexed under the canonical EC-043
    direct pair ordinal; repeated walks retain exact occurrence provenance,
    genuine position overlap and maximum disjoint occurrence witnesses.
    Same model-statement histogram does NOT authenticate a defect or history.
#>

function Get-CodeSequenceOriginalFindingPairProfileMotifs {
    param(
        [object] $Atlas,
        [object] $Graph,
        [object] $Passages,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Graph -or
        $null -eq $Passages -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence motif projection requires all four validated parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $classCount = [int]$Atlas.counts.distinct_saved_profile_class_count
    $pairCount = [int](($n * ($n - 1)) / 2)
    $severities = @('critical', 'high', 'medium', 'low', 'info')
    if ($Atlas.scope -cne 'complete_saved_quote_anchor_five_severity_histogram_classes_adjacent_transitions_and_returns_for_two_independent_original_Findings' -or
        $Graph.scope -cne 'complete_directed_saved_profile_class_transition_multigraph_and_prior_run_return_witnesses_for_two_independent_original_Findings' -or
        $Passages.scope -cne 'complete_caller_forward_actual_position_pair_profile_passages_and_shortest_longest_contiguous_witnesses' -or
        -not [bool]$Graph.complete_ec051_atlas_and_ec043_step_and_return_pairs_reconciled -or
        -not [bool]$Passages.complete_ec043_pairs_ec051_classes_and_ec052_adjacent_and_return_graph_reconciled -or
        -not [bool]$Passages.two_original_finding_journeys_remain_independent -or
        -not [bool]$Passages.independent_of_sequence_top -or
        -not [bool]$Graph.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $classCount -lt 1 -or $classCount -gt $n -or
        [int]$Graph.counts.selected_report_positions -ne $n -or
        [int]$Passages.counts.selected_report_positions -ne $n -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        [int]$Passages.counts.all_ec043_position_pair_count -ne $pairCount -or
        [int]$Atlas.counts.all_unordered_pair_count -ne $pairCount -or
        $Atlas.positions.Count -ne $n -or $SelectedAnchor.positions.Count -ne $n -or
        $Graph.class_nodes.Count -ne $classCount -or
        $Graph.adjacent_step_edges.Count -ne $n - 1 -or
        $Passages.all_caller_forward_position_pairs.Count -ne $pairCount -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        $Atlas.path -cne $Graph.path -or $Graph.path -cne $Passages.path -or
        $Passages.path -cne $SelectedAnchor.path -or
        [int]$Atlas.pair_index_in_pairwise_profile -ne [int]$Passages.pair_index_in_pairwise_profile -or
        [int]$Graph.pair_index_in_pairwise_profile -ne [int]$Passages.pair_index_in_pairwise_profile -or
        [int]$Atlas.path_index_in_selected_pair_overview -ne [int]$Passages.path_index_in_selected_pair_overview -or
        [int]$Graph.path_index_in_selected_pair_overview -ne [int]$Passages.path_index_in_selected_pair_overview -or
        [int]$Atlas.anchor_index_in_anchor_journeys -ne [int]$Passages.anchor_index_in_anchor_journeys -or
        [int]$Graph.anchor_index_in_anchor_journeys -ne [int]$Passages.anchor_index_in_anchor_journeys -or
        [int]$Passages.anchor_index_in_anchor_journeys -ne [int]$SelectedAnchor.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Atlas.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Graph.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Graph.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Passages.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Passages.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence motif projection has inconsistent verified parent scope or cardinality.'
    }

    # Position identity is ALWAYS taken from the existing original-report
    # ledgers; do not relabel equal histogram classes as shared Findings.
    $classAt = [int[]]::new($n)
    $recordAt = [string[]]::new($n)
    $reportedAt = [bool[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $p = $i + 1
        $atlasPosition = $Atlas.positions[$i]
        $savedPosition = $SelectedAnchor.positions[$i]
        $classIndex = [int]$atlasPosition.profile_class_index
        if ([int]$atlasPosition.position -ne $p -or
            [int]$savedPosition.position -ne $p -or
            [string]::IsNullOrWhiteSpace([string]$atlasPosition.record_id) -or
            $atlasPosition.record_id -cne $savedPosition.record_id -or
            $classIndex -lt 1 -or $classIndex -gt $classCount) {
            throw 'Code Sequence motif encountered an invalid original saved-report position.'
        }
        $node = $Graph.class_nodes[$classIndex - 1]
        if ([int]$node.profile_class_index -ne $classIndex -or
            -not ($node.position_indices -contains $p) -or
            [bool]$node.reported_same_exact_saved_quote_anchor -ne
                [bool]$savedPosition.reported_same_exact_saved_quote_anchor -or
            [int]$node.saved_finding_statement_count_at_anchor -ne
                [int]$savedPosition.saved_finding_statement_count_at_anchor -or
            ((-not [bool]$node.reported_same_exact_saved_quote_anchor) -and
                ($null -ne $node.saved_severity_statement_counts -or
                 $null -ne $savedPosition.saved_severity_statement_counts))) {
            throw 'Code Sequence motif class, absence or saved statement multiplicity is inconsistent.'
        }
        if ([bool]$node.reported_same_exact_saved_quote_anchor) {
            if ($null -eq $node.saved_severity_statement_counts -or
                $null -eq $savedPosition.saved_severity_statement_counts) {
                throw 'Code Sequence motif encountered a reported anchor with no saved histogram.'
            }
            foreach ($sev in $severities) {
                if ([int]$node.saved_severity_statement_counts[$sev] -ne
                    [int]$savedPosition.saved_severity_statement_counts[$sev]) {
                    throw 'Code Sequence motif five-bin saved histogram differs across parent views.'
                }
            }
        }
        $classAt[$i] = $classIndex
        $recordAt[$i] = [string]$savedPosition.record_id
        $reportedAt[$i] = [bool]$savedPosition.reported_same_exact_saved_quote_anchor
    }

    # One real contiguous window per original EC-043 pair; grouping by the
    # ENTIRE class walk prevents A,B,A from collapsing into A,C,A or A,A.
    $windows = [System.Collections.Generic.List[object]]::new()
    $groups = [System.Collections.Generic.List[object]]::new()
    $motifByWalk = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $pairIndex = 0
    $windowsContainingAbsence = 0
    $windowsWithInternalAbsence = 0
    $nearestReturnWindows = 0
    for ($left = 1; $left -lt $n; $left++) {
        for ($right = $left + 1; $right -le $n; $right++) {
            $pairIndex++
            $fromClass = $classAt[$left - 1]
            $toClass = $classAt[$right - 1]
            $passagePair = $Passages.all_caller_forward_position_pairs[$pairIndex - 1]
            $direct = $SelectedAnchor.compared_pairs[$pairIndex - 1]
            $passageGroupIndex = [int]$passagePair.passage_index
            if ([int]$passagePair.ec043_pair_index -ne $pairIndex -or
                [int]$passagePair.from_position -ne $left -or
                [int]$passagePair.to_position -ne $right -or
                $passagePair.from_record_id -cne $recordAt[$left - 1] -or
                $passagePair.to_record_id -cne $recordAt[$right - 1] -or
                [int]$passagePair.from_profile_class_index -ne $fromClass -or
                [int]$passagePair.to_profile_class_index -ne $toClass -or
                [int]$passagePair.adjacent_hop_count -ne $right - $left -or
                [bool]$passagePair.is_adjacent_pair -ne ($right -eq $left + 1) -or
                [bool]$passagePair.changed_saved_profile -ne ($fromClass -ne $toClass) -or
                $passageGroupIndex -lt 1 -or
                $passageGroupIndex -gt $Passages.ordered_class_passages.Count -or
                -not ($Passages.ordered_class_passages[$passageGroupIndex - 1].ec043_pair_indices -contains $pairIndex) -or
                [int]$direct.pair_index -ne $pairIndex -or
                [int]$direct.left_position -ne $left -or
                [int]$direct.right_position -ne $right -or
                $direct.left_record_id -cne $recordAt[$left - 1] -or
                $direct.right_record_id -cne $recordAt[$right - 1] -or
                $direct.anchor_pair_class -cne $passagePair.saved_anchor_pair_class -or
                [bool]$direct.shared_with_internal_unreported_position -ne
                    [bool]$passagePair.direct_pair_has_internal_unreported_gap) {
                throw 'Code Sequence motif cannot reconcile a canonical EC-043 direct pair and EC-053 passage.'
            }
            $classWalk = [System.Collections.Generic.List[int]]::new()
            $recordWalk = [System.Collections.Generic.List[string]]::new()
            $stepWalk = [System.Collections.Generic.List[int]]::new()
            $edgeWalk = [System.Collections.Generic.List[int]]::new()
            $adjacentPairWalk = [System.Collections.Generic.List[int]]::new()
            $absentCount = 0
            $internalAbsentCount = 0
            for ($p = $left; $p -le $right; $p++) {
                $classWalk.Add($classAt[$p - 1])
                $recordWalk.Add($recordAt[$p - 1])
                if (-not $reportedAt[$p - 1]) {
                    $absentCount++
                    if ($p -gt $left -and $p -lt $right) { $internalAbsentCount++ }
                }
                if ($p -lt $right) {
                    $step = $Graph.adjacent_step_edges[$p - 1]
                    $edgeIndex = [int]$step.directed_edge_index
                    $stepDirectIndex = [int]$step.ec043_pair_index
                    $stepDirect = if ($stepDirectIndex -ge 1 -and $stepDirectIndex -le $pairCount) {
                        $SelectedAnchor.compared_pairs[$stepDirectIndex - 1]
                    } else { $null }
                    if ($null -eq $stepDirect -or
                        [int]$step.step_index -ne $p -or
                        [int]$step.from_position -ne $p -or
                        [int]$step.to_position -ne $p + 1 -or
                        [int]$step.from_profile_class_index -ne $classAt[$p - 1] -or
                        [int]$step.to_profile_class_index -ne $classAt[$p] -or
                        $edgeIndex -lt 1 -or $edgeIndex -gt $Graph.directed_edges.Count -or
                        [int]$Graph.directed_edges[$edgeIndex - 1].from_profile_class_index -ne $classAt[$p - 1] -or
                        [int]$Graph.directed_edges[$edgeIndex - 1].to_profile_class_index -ne $classAt[$p] -or
                        -not ($Graph.directed_edges[$edgeIndex - 1].step_indices -contains $p) -or
                        [int]$stepDirect.left_position -ne $p -or
                        [int]$stepDirect.right_position -ne $p + 1 -or
                        $stepDirect.left_record_id -cne $recordAt[$p - 1] -or
                        $stepDirect.right_record_id -cne $recordAt[$p] -or
                        $stepDirect.anchor_pair_class -cne $step.saved_anchor_pair_class) {
                        throw 'Code Sequence motif attempted to use an unwitnessed or detached adjacent edge.'
                    }
                    $stepWalk.Add($p)
                    $edgeWalk.Add($edgeIndex)
                    $adjacentPairWalk.Add($stepDirectIndex)
                }
            }
            $actualGap = $reportedAt[$left - 1] -and $reportedAt[$right - 1] -and
                $internalAbsentCount -gt 0
            if ([bool]$actualGap -ne [bool]$passagePair.direct_pair_has_internal_unreported_gap -or
                $classWalk.Count -ne $right - $left + 1 -or
                $stepWalk.Count -ne $right - $left -or
                $stepWalk.Count -ne $edgeWalk.Count -or
                $stepWalk.Count -ne $adjacentPairWalk.Count) {
                throw 'Code Sequence motif observed walk or internal reporting-gap evidence is inconsistent.'
            }
            if ($absentCount -gt 0) { $windowsContainingAbsence++ }
            if ($internalAbsentCount -gt 0) { $windowsWithInternalAbsence++ }
            if ($null -ne $passagePair.closest_previous_same_class_run_return_index) {
                $nearestReturnWindows++
            }
            $walk = $classWalk.ToArray()
            $walkKey = $walk -join ':'
            if (-not $motifByWalk.ContainsKey($walkKey)) {
                $motifIndex = $groups.Count + 1
                $motifByWalk.Add($walkKey, $motifIndex)
                $groups.Add([ordered]@{
                    motif_index = $motifIndex
                    profile_class_index_walk = $walk
                    position_count_per_occurrence = $walk.Length
                    from_profile_class_index = $fromClass
                    to_profile_class_index = $toClass
                    from_anchor_reported = [bool]$reportedAt[$left - 1]
                    to_anchor_reported = [bool]$reportedAt[$right - 1]
                    saved_anchor_pair_class = [string]$direct.anchor_pair_class
                    occurrence_indices = [System.Collections.Generic.List[int]]::new()
                    ec043_direct_pair_indices = [System.Collections.Generic.List[int]]::new()
                })
            }
            $motifIndex = $motifByWalk[$walkKey]
            $group = $groups[$motifIndex - 1]
            if ([int]$group.position_count_per_occurrence -ne $walk.Length -or
                ($group.profile_class_index_walk -join ':') -cne $walkKey -or
                $group.saved_anchor_pair_class -cne $direct.anchor_pair_class) {
                throw 'Code Sequence motif class-walk identity or first appearance is inconsistent.'
            }
            $window = [ordered]@{
                window_index = $pairIndex
                ec043_direct_pair_index = $pairIndex
                motif_index = $motifIndex
                from_position = $left
                to_position = $right
                from_record_id = [string]$recordAt[$left - 1]
                to_record_id = [string]$recordAt[$right - 1]
                position_count = $right - $left + 1
                adjacent_hop_count = $right - $left
                record_id_walk = $recordWalk.ToArray()
                profile_class_index_walk = $walk
                adjacent_step_indices = $stepWalk.ToArray()
                directed_edge_index_walk = $edgeWalk.ToArray()
                ec043_adjacent_pair_index_walk = $adjacentPairWalk.ToArray()
                saved_anchor_pair_class = [string]$direct.anchor_pair_class
                unreported_anchor_position_count = $absentCount
                internal_unreported_anchor_position_count = $internalAbsentCount
                direct_pair_has_internal_unreported_gap = [bool]$actualGap
                closest_previous_same_class_run_return_index = $passagePair.closest_previous_same_class_run_return_index
            }
            $windows.Add($window)
            $group.occurrence_indices.Add($pairIndex)
            $group.ec043_direct_pair_indices.Add($pairIndex)
        }
    }
    if ($pairIndex -ne $pairCount -or $windows.Count -ne $pairCount -or
        $nearestReturnWindows -ne [int]$Passages.counts.closest_previous_run_return_link_count -or
        $groups.Count -ne $motifByWalk.Count) {
        throw 'Code Sequence motif ledger does not conserve every direct pair/return.'
    }

    # For each equal class walk, preserve EVERY pair of concrete occurrence
    # intervals, distinguishing strict disjointness, a shared endpoint and
    # a larger overlap. Greedy earliest-finish yields the maximum possible
    # number of strictly disjoint equal-length observed windows.
    $outGroups = [System.Collections.Generic.List[object]]::new()
    $totalGroupOccurrences = 0
    $repeatedGroupCount = 0
    $repeatedOccurrenceCount = 0
    $repeatedPairCount = 0
    $disjointPairCount = 0
    $sharedEndpointPairCount = 0
    $overlappingPositionPairCount = 0
    $groupsWithDisjointRepeats = 0
    $longestRepeated = 0
    $longestDisjointRepeated = 0
    for ($gIndex = 0; $gIndex -lt $groups.Count; $gIndex++) {
        $g = $groups[$gIndex]
        $members = $g.occurrence_indices.ToArray()
        $count = $members.Length
        if ($count -lt 1 -or [int]$g.motif_index -ne $gIndex + 1 -or
            $g.position_count_per_occurrence -lt 2 -or
            $g.position_count_per_occurrence -gt $n -or
            $members[0] -lt 1 -or $members[0] -gt $pairCount -or
            $windows[$members[0] - 1].motif_index -ne $gIndex + 1) {
            throw 'Code Sequence motif found a noncanonical or empty class-walk group.'
        }
        $totalGroupOccurrences += $count
        $isRepeated = $count -ge 2
        if ($isRepeated) {
            $repeatedGroupCount++
            $repeatedOccurrenceCount += $count
            $longestRepeated = [Math]::Max($longestRepeated, [int]$g.position_count_per_occurrence)
        }
        $pairWitnesses = [System.Collections.Generic.List[object]]::new()
        $gDisjoint = 0
        $gSharedEndpoint = 0
        $gOverlapping = 0
        for ($i = 0; $i -lt $count; $i++) {
            $firstIndex = [int]$members[$i]
            $first = $windows[$firstIndex - 1]
            if ([int]$first.window_index -ne $firstIndex -or
                [int]$first.motif_index -ne $gIndex + 1 -or
                ($first.profile_class_index_walk -join ':') -cne
                    ($g.profile_class_index_walk -join ':') -or
                [int]$first.position_count -ne [int]$g.position_count_per_occurrence -or
                [int]$g.ec043_direct_pair_indices[$i] -ne $firstIndex -or
                ($i -gt 0 -and $firstIndex -le [int]$members[$i - 1])) {
                throw 'Code Sequence motif occurrence was misgrouped or duplicated.'
            }
            for ($j = $i + 1; $j -lt $count; $j++) {
                $secondIndex = [int]$members[$j]
                $second = $windows[$secondIndex - 1]
                if ([int]$first.from_position -ge [int]$second.from_position -or
                    [int]$second.motif_index -ne $gIndex + 1 -or
                    [int]$second.position_count -ne [int]$first.position_count) {
                    throw 'Code Sequence motif repeated positions have inconsistent canonical order.'
                }
                $sharedPositions = [Math]::Max(0, [int]$first.to_position - [int]$second.from_position + 1)
                if ($sharedPositions -eq 0) {
                    $gDisjoint++
                    $relation = 'disjoint'
                } elseif ($sharedPositions -eq 1) {
                    $gSharedEndpoint++
                    $relation = 'shared_endpoint'
                } else {
                    $gOverlapping++
                    $relation = 'overlapping_positions'
                }
                $pairWitnesses.Add([ordered]@{
                    first_window_index = $firstIndex
                    second_window_index = $secondIndex
                    first_from_position = [int]$first.from_position
                    first_to_position = [int]$first.to_position
                    second_from_position = [int]$second.from_position
                    second_to_position = [int]$second.to_position
                    shared_position_count = $sharedPositions
                    overlap_class = $relation
                })
            }
        }
        if ($pairWitnesses.Count -ne [int](($count * ($count - 1)) / 2)) {
            throw 'Code Sequence motif repeat-pair incidence failed exact conservation.'
        }
        $repeatedPairCount += $pairWitnesses.Count
        $disjointPairCount += $gDisjoint
        $sharedEndpointPairCount += $gSharedEndpoint
        $overlappingPositionPairCount += $gOverlapping

        # Each group contains fixed-width windows, so earliest ending time
        # is an optimal interval-scheduling witness for maximum disjointness.
        $maxDisjointIndices = [System.Collections.Generic.List[int]]::new()
        $lastEnd = 0
        while ($true) {
            $bestIndex = 0
            $bestEnd = $n + 1
            $bestStart = $n + 1
            foreach ($candidateIndex in $members) {
                $candidate = $windows[[int]$candidateIndex - 1]
                $from = [int]$candidate.from_position
                $to = [int]$candidate.to_position
                if ($from -gt $lastEnd -and
                    ($to -lt $bestEnd -or
                        ($to -eq $bestEnd -and $from -lt $bestStart))) {
                    $bestIndex = [int]$candidateIndex
                    $bestEnd = $to
                    $bestStart = $from
                }
            }
            if ($bestIndex -eq 0) { break }
            $maxDisjointIndices.Add($bestIndex)
            $lastEnd = $bestEnd
        }
        if ($maxDisjointIndices.Count -lt 1 -or
            ($gDisjoint -eq 0 -and $maxDisjointIndices.Count -ge 2) -or
            ($gDisjoint -gt 0 -and $maxDisjointIndices.Count -lt 2)) {
            throw 'Code Sequence motif maximal disjoint witness is inconsistent with repeat intervals.'
        }
        if ($gDisjoint -gt 0) {
            $groupsWithDisjointRepeats++
            $longestDisjointRepeated = [Math]::Max(
                $longestDisjointRepeated, [int]$g.position_count_per_occurrence)
        }
        $outGroups.Add([ordered]@{
            motif_index = [int]$g.motif_index
            profile_class_index_walk = $g.profile_class_index_walk
            position_count_per_occurrence = [int]$g.position_count_per_occurrence
            from_profile_class_index = [int]$g.from_profile_class_index
            to_profile_class_index = [int]$g.to_profile_class_index
            from_anchor_reported = [bool]$g.from_anchor_reported
            to_anchor_reported = [bool]$g.to_anchor_reported
            saved_anchor_pair_class = [string]$g.saved_anchor_pair_class
            occurrence_count = $count
            repeats_at_least_twice = [bool]$isRepeated
            has_strictly_disjoint_repeat = ($gDisjoint -gt 0)
            ec043_direct_pair_indices = $g.ec043_direct_pair_indices.ToArray()
            window_indices = $members
            repeated_occurrence_pair_count = $pairWitnesses.Count
            disjoint_occurrence_pair_count = $gDisjoint
            shared_endpoint_occurrence_pair_count = $gSharedEndpoint
            overlapping_positions_occurrence_pair_count = $gOverlapping
            repeated_occurrence_pairs = $pairWitnesses.ToArray()
            maximum_strictly_disjoint_occurrence_count = $maxDisjointIndices.Count
            maximum_strictly_disjoint_window_indices = $maxDisjointIndices.ToArray()
        })
    }
    if ($totalGroupOccurrences -ne $pairCount -or
        $repeatedOccurrenceCount -gt $pairCount -or
        $disjointPairCount + $sharedEndpointPairCount + $overlappingPositionPairCount -ne $repeatedPairCount -or
        $outGroups.Count -ne $groups.Count -or
        $repeatedGroupCount -gt $outGroups.Count -or
        ($repeatedGroupCount -eq 0 -and ($repeatedPairCount -ne 0 -or $longestRepeated -ne 0)) -or
        ($groupsWithDisjointRepeats -eq 0 -and $longestDisjointRepeated -ne 0)) {
        throw 'Code Sequence motif groups failed observed-window or interval conservation.'
    }
    return [ordered]@{
        scope = 'complete_observed_contiguous_saved_profile_class_walk_motifs_and_repeat_overlap_witnesses'
        pair_index_in_pairwise_profile = [int]$Atlas.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Atlas.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Atlas.anchor_index_in_anchor_journeys
        path = [string]$Atlas.path
        exact_saved_quote_anchor = $Atlas.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            distinct_saved_profile_class_count = $classCount
            observed_contiguous_window_count = $pairCount
            distinct_complete_class_walk_motif_count = $outGroups.Count
            singleton_motif_count = $outGroups.Count - $repeatedGroupCount
            repeated_motif_count = $repeatedGroupCount
            repeated_motif_occurrence_count = $repeatedOccurrenceCount
            repeated_occurrence_pair_count = $repeatedPairCount
            strictly_disjoint_repeat_pair_count = $disjointPairCount
            shared_endpoint_repeat_pair_count = $sharedEndpointPairCount
            overlapping_positions_repeat_pair_count = $overlappingPositionPairCount
            motif_with_strictly_disjoint_repeat_count = $groupsWithDisjointRepeats
            longest_repeated_motif_position_count = $longestRepeated
            longest_strictly_disjoint_repeated_motif_position_count = $longestDisjointRepeated
            window_containing_unreported_anchor_count = $windowsContainingAbsence
            window_with_internal_unreported_anchor_count = $windowsWithInternalAbsence
            closest_previous_run_return_endpoint_window_count = $nearestReturnWindows
        }
        all_observed_contiguous_windows = $windows.ToArray()
        ordered_complete_class_walk_motifs = $outGroups.ToArray()
        independent_of_sequence_top = $true
        complete_ec043_pairs_ec051_classes_ec052_real_steps_ec053_passages_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Every window is ONE actual contiguous caller-selected saved-report span (at least two positions), linked to its original EC-043 direct pair and each real EC-052 adjacent step/edge. Motifs group the ENTIRE exact sequence of first-appearance-numbered saved-model five-bin histogram classes, not just endpoints or graph reachability. Repetitions are observations at different caller positions; shared endpoint/overlapping occurrences are distinct from truly disjoint intervals. Null/absent quote-anchor class remains separate from a reported zero histogram. Saved original Finding IDs remain report-scoped, and caller order is not attested chronology: no motif proves defect identity, actual severity, recurrence, fix, regression or risk. No extra saved-body, source/Git/network read, write, quotation or model prose.'
    }
}

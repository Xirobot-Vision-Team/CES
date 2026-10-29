#requires -Version 7.0
<#
    EC-055: pairwise maximal repeated, ACTUALLY OBSERVED contiguous
    saved-profile class walks. Build on EC-054's complete real windows and
    repeat-pair ledger. Extend both occurrences synchronously using saved
    class equality, never stitch unrelated graph edges. Preserve both the
    unconstrained maximal match and EVERY strictly-disjoint maximal match:
    an overlap-limited repetition must not erase shorter disjoint evidence.
    Position order is caller supplied, NOT authenticated chronology; saved
    statement-histogram equality does not authenticate defect identity.
#>

function New-CodeSequenceProfileMaximalRepeatRegion {
    param(
        [int] $RegionIndex,
        [int] $FirstFrom,
        [int] $SecondFrom,
        [int] $PositionCount,
        [int] $N,
        [object[]] $Windows,
        [int[]] $ClassAt,
        [bool] $RequireStrictDisjoint
    )
    $firstTo = $FirstFrom + $PositionCount - 1
    $secondTo = $SecondFrom + $PositionCount - 1
    if ($PositionCount -lt 2 -or $FirstFrom -lt 1 -or $SecondFrom -le $FirstFrom -or
        $firstTo -gt $N -or $secondTo -gt $N) {
        throw 'Code Sequence maximal repeat attempted to create an invalid observed interval.'
    }
    $firstIndex = [int](((($FirstFrom - 1) * (2 * $N - $FirstFrom)) / 2) + $firstTo - $FirstFrom)
    $secondIndex = [int](((($SecondFrom - 1) * (2 * $N - $SecondFrom)) / 2) + $secondTo - $SecondFrom)
    if ($firstIndex -lt 1 -or $secondIndex -lt 1 -or
        $firstIndex -gt $Windows.Count -or $secondIndex -gt $Windows.Count) {
        throw 'Code Sequence maximal repeat lost the canonical EC-043 direct pair witness.'
    }
    $first = $Windows[$firstIndex - 1]
    $second = $Windows[$secondIndex - 1]
    $sameClassWalk = (($first.profile_class_index_walk -join ':') -ceq
        ($second.profile_class_index_walk -join ':'))
    if ([int]$first.window_index -ne $firstIndex -or
        [int]$second.window_index -ne $secondIndex -or
        [int]$first.from_position -ne $FirstFrom -or
        [int]$second.from_position -ne $SecondFrom -or
        [int]$first.to_position -ne $firstTo -or
        [int]$second.to_position -ne $secondTo -or
        [int]$first.motif_index -ne [int]$second.motif_index -or
        [int]$first.position_count -ne $PositionCount -or
        [int]$second.position_count -ne $PositionCount -or
        $first.profile_class_index_walk.Count -ne $PositionCount -or
        -not $sameClassWalk -or
        [int]$first.unreported_anchor_position_count -ne [int]$second.unreported_anchor_position_count) {
        throw 'Code Sequence maximal repeat attempted to use a nonmatching saved class walk.'
    }
    for ($offset = 0; $offset -lt $PositionCount; $offset++) {
        if ([int]$first.profile_class_index_walk[$offset] -ne $ClassAt[$FirstFrom + $offset - 1] -or
            [int]$second.profile_class_index_walk[$offset] -ne $ClassAt[$SecondFrom + $offset - 1]) {
            throw 'Code Sequence maximal repeat disagrees with original selected saved-report classes.'
        }
    }
    $shared = [Math]::Max(0, $firstTo - $SecondFrom + 1)
    $relation = if ($shared -eq 0) { 'disjoint' } elseif ($shared -eq 1) {
        'shared_endpoint'
    } else { 'overlapping_positions' }
    if ($RequireStrictDisjoint -and $shared -ne 0) {
        throw 'Code Sequence maximal strict-disjoint repeat would share an original report position.'
    }
    $canLeft = $FirstFrom -gt 1 -and $SecondFrom -gt 1 -and
        $ClassAt[$FirstFrom - 2] -eq $ClassAt[$SecondFrom - 2]
    $canRight = $firstTo -lt $N -and $secondTo -lt $N -and
        $ClassAt[$firstTo] -eq $ClassAt[$secondTo]
    $canLeftDisjoint = $canLeft -and ($firstTo -lt $SecondFrom - 1)
    $canRightDisjoint = $canRight -and ($firstTo + 1 -lt $SecondFrom)
    if (($RequireStrictDisjoint -and ($canLeftDisjoint -or $canRightDisjoint)) -or
        ((-not $RequireStrictDisjoint) -and ($canLeft -or $canRight))) {
        throw 'Code Sequence maximal repeat emitted a pair that still has an admissible one-step extension.'
    }
    return [ordered]@{
        region_index = $RegionIndex
        first_ec043_direct_pair_index = $firstIndex
        second_ec043_direct_pair_index = $secondIndex
        motif_index = [int]$first.motif_index
        first_from_position = $FirstFrom
        first_to_position = $firstTo
        second_from_position = $SecondFrom
        second_to_position = $secondTo
        position_count_per_occurrence = $PositionCount
        profile_class_index_walk = $first.profile_class_index_walk
        first_record_id_walk = $first.record_id_walk
        second_record_id_walk = $second.record_id_walk
        first_ec052_adjacent_step_indices = $first.adjacent_step_indices
        second_ec052_adjacent_step_indices = $second.adjacent_step_indices
        first_directed_edge_index_walk = $first.directed_edge_index_walk
        second_directed_edge_index_walk = $second.directed_edge_index_walk
        first_ec043_adjacent_pair_index_walk = $first.ec043_adjacent_pair_index_walk
        second_ec043_adjacent_pair_index_walk = $second.ec043_adjacent_pair_index_walk
        unreported_anchor_position_count_per_occurrence = [int]$first.unreported_anchor_position_count
        shared_position_count = $shared
        overlap_class = $relation
        class_equal_left_extension_possible = [bool]$canLeft
        class_equal_right_extension_possible = [bool]$canRight
        class_equal_left_extension_preserving_strict_disjointness_possible = [bool]$canLeftDisjoint
        class_equal_right_extension_preserving_strict_disjointness_possible = [bool]$canRightDisjoint
        requires_strict_disjointness = $RequireStrictDisjoint
        originating_seed_repeat_pair_indices = [System.Collections.Generic.List[int]]::new()
    }
}

function Get-CodeSequenceOriginalFindingPairProfileMaximalRepeats {
    param(
        [object] $Atlas,
        [object] $Graph,
        [object] $Motifs,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Graph -or
        $null -eq $Motifs -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence maximal repeat projection requires all four checked parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $Atlas.scope -cne 'complete_saved_quote_anchor_five_severity_histogram_classes_adjacent_transitions_and_returns_for_two_independent_original_Findings' -or
        $Graph.scope -cne 'complete_directed_saved_profile_class_transition_multigraph_and_prior_run_return_witnesses_for_two_independent_original_Findings' -or
        $Motifs.scope -cne 'complete_observed_contiguous_saved_profile_class_walk_motifs_and_repeat_overlap_witnesses' -or
        -not [bool]$Motifs.complete_ec043_pairs_ec051_classes_ec052_real_steps_ec053_passages_reconciled -or
        -not [bool]$Motifs.two_original_finding_journeys_remain_independent -or
        -not [bool]$Graph.complete_ec051_atlas_and_ec043_step_and_return_pairs_reconciled -or
        -not [bool]$Motifs.independent_of_sequence_top -or
        -not [bool]$Graph.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        [int]$Motifs.counts.selected_report_positions -ne $n -or
        [int]$Graph.counts.selected_report_positions -ne $n -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        [int]$Motifs.counts.observed_contiguous_window_count -ne $pairCount -or
        [int]$Atlas.counts.all_unordered_pair_count -ne $pairCount -or
        $Atlas.positions.Count -ne $n -or
        $SelectedAnchor.positions.Count -ne $n -or
        $Motifs.all_observed_contiguous_windows.Count -ne $pairCount -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        $Graph.adjacent_step_edges.Count -ne $n - 1 -or
        [int]$Motifs.counts.distinct_complete_class_walk_motif_count -ne
            $Motifs.ordered_complete_class_walk_motifs.Count -or
        $Atlas.path -cne $Motifs.path -or $Atlas.path -cne $Graph.path -or
        $Motifs.path -cne $SelectedAnchor.path -or
        [int]$Atlas.pair_index_in_pairwise_profile -ne [int]$Motifs.pair_index_in_pairwise_profile -or
        [int]$Atlas.path_index_in_selected_pair_overview -ne [int]$Motifs.path_index_in_selected_pair_overview -or
        [int]$Atlas.anchor_index_in_anchor_journeys -ne [int]$Motifs.anchor_index_in_anchor_journeys -or
        [int]$Motifs.pair_index_in_pairwise_profile -ne [int]$Graph.pair_index_in_pairwise_profile -or
        [int]$Motifs.path_index_in_selected_pair_overview -ne [int]$Graph.path_index_in_selected_pair_overview -or
        [int]$Motifs.anchor_index_in_anchor_journeys -ne [int]$Graph.anchor_index_in_anchor_journeys -or
        [int]$Motifs.anchor_index_in_anchor_journeys -ne [int]$SelectedAnchor.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Atlas.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Motifs.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Graph.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Motifs.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Motifs.exact_saved_quote_anchor)) {
        throw 'Code Sequence maximal repeat parent selectors, original IDs or cardinalities disagree.'
    }

    # Reconcile the entire EC-054 observed-window ledger to real EC-051
    # selected positions, original EC-043 pair identities, and actual EC-052
    # consecutive step occurrences, not merely equivalent abstract arcs.
    $classAt = [int[]]::new($n)
    $recordAt = [string[]]::new($n)
    for ($p = 1; $p -le $n; $p++) {
        $ap = $Atlas.positions[$p - 1]
        $sp = $SelectedAnchor.positions[$p - 1]
        $cl = [int]$ap.profile_class_index
        if ([int]$ap.position -ne $p -or [int]$sp.position -ne $p -or
            $ap.record_id -cne $sp.record_id -or
            [string]::IsNullOrWhiteSpace([string]$ap.record_id) -or
            $cl -lt 1 -or $cl -gt [int]$Atlas.counts.distinct_saved_profile_class_count) {
            throw 'Code Sequence maximal repeat found an invalid original report class or ID.'
        }
        $classAt[$p - 1] = $cl
        $recordAt[$p - 1] = [string]$ap.record_id
    }
    $windows = [object[]]$Motifs.all_observed_contiguous_windows
    $canonicalIndex = 0
    for ($left = 1; $left -lt $n; $left++) {
        for ($right = $left + 1; $right -le $n; $right++) {
            $canonicalIndex++
            $w = $windows[$canonicalIndex - 1]
            $direct = $SelectedAnchor.compared_pairs[$canonicalIndex - 1]
            $length = $right - $left + 1
            if ([int]$w.window_index -ne $canonicalIndex -or
                [int]$w.ec043_direct_pair_index -ne $canonicalIndex -or
                [int]$w.from_position -ne $left -or [int]$w.to_position -ne $right -or
                [int]$w.position_count -ne $length -or
                $w.profile_class_index_walk.Count -ne $length -or
                $w.record_id_walk.Count -ne $length -or
                $w.adjacent_step_indices.Count -ne $length - 1 -or
                $w.directed_edge_index_walk.Count -ne $length - 1 -or
                $w.ec043_adjacent_pair_index_walk.Count -ne $length - 1 -or
                [int]$direct.pair_index -ne $canonicalIndex -or
                [int]$direct.left_position -ne $left -or [int]$direct.right_position -ne $right -or
                $w.from_record_id -cne $recordAt[$left - 1] -or
                $w.to_record_id -cne $recordAt[$right - 1] -or
                $direct.left_record_id -cne $recordAt[$left - 1] -or
                $direct.right_record_id -cne $recordAt[$right - 1] -or
                $w.saved_anchor_pair_class -cne $direct.anchor_pair_class -or
                [int]$w.motif_index -lt 1 -or
                [int]$w.motif_index -gt $Motifs.ordered_complete_class_walk_motifs.Count) {
                throw 'Code Sequence maximal repeat observed window and EC-043 direct pair are inconsistent.'
            }
            for ($p = $left; $p -le $right; $p++) {
                $offset = $p - $left
                if ([int]$w.profile_class_index_walk[$offset] -ne $classAt[$p - 1] -or
                    $w.record_id_walk[$offset] -cne $recordAt[$p - 1]) {
                    throw 'Code Sequence maximal repeat cannot reconstruct an observed class and original-ID walk.'
                }
                if ($p -lt $right) {
                    $step = $Graph.adjacent_step_edges[$p - 1]
                    if ([int]$w.adjacent_step_indices[$offset] -ne $p -or
                        [int]$step.step_index -ne $p -or
                        [int]$step.from_position -ne $p -or [int]$step.to_position -ne $p + 1 -or
                        [int]$w.directed_edge_index_walk[$offset] -ne [int]$step.directed_edge_index -or
                        [int]$w.ec043_adjacent_pair_index_walk[$offset] -ne [int]$step.ec043_pair_index -or
                        [int]$step.from_profile_class_index -ne $classAt[$p - 1] -or
                        [int]$step.to_profile_class_index -ne $classAt[$p]) {
                        throw 'Code Sequence maximal repeat tried to stitch noncontiguous or mismatched steps.'
                    }
                }
            }
            $g = $Motifs.ordered_complete_class_walk_motifs[[int]$w.motif_index - 1]
            if (($g.profile_class_index_walk -join ':') -cne ($w.profile_class_index_walk -join ':') -or
                -not ($g.window_indices -contains $canonicalIndex)) {
                throw 'Code Sequence maximal repeat observed window was not in its complete motif group.'
            }
        }
    }
    if ($canonicalIndex -ne $pairCount) {
        throw 'Code Sequence maximal repeat missed canonical EC-043 windows.'
    }

    $seeds = [System.Collections.Generic.List[object]]::new()
    $globalRegions = [System.Collections.Generic.List[object]]::new()
    $globalByBounds = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $disjointRegions = [System.Collections.Generic.List[object]]::new()
    $disjointByBounds = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $disjointSeedCount = 0
    $leftExtendibleSeedCount = 0
    $rightExtendibleSeedCount = 0
    $alreadyMaximalSeedCount = 0
    $disjointExtendibleSeedCount = 0
    $maxGlobalLength = 0
    $maxDisjointLength = 0
    $reportedGroupRepeats = 0
    $reportedDisjointPairs = 0
    $seenWindow = [int[]]::new($pairCount)

    foreach ($g in $Motifs.ordered_complete_class_walk_motifs) {
        $motifIndex = [int]$g.motif_index
        if ($motifIndex -lt 1 -or $motifIndex -gt $Motifs.ordered_complete_class_walk_motifs.Count -or
            [int]$Motifs.ordered_complete_class_walk_motifs[$motifIndex - 1].motif_index -ne $motifIndex -or
            $g.window_indices.Count -ne [int]$g.occurrence_count -or
            [int]$g.repeated_occurrence_pair_count -ne $g.repeated_occurrence_pairs.Count -or
            [int]$g.repeated_occurrence_pair_count -ne
                [int](($g.occurrence_count * ($g.occurrence_count - 1)) / 2) -or
            [bool]$g.repeats_at_least_twice -ne ($g.occurrence_count -ge 2)) {
            throw 'Code Sequence maximal repeat found an invalid parent motif repeat partition.'
        }
        if ($g.occurrence_count -ge 2) { $reportedGroupRepeats++ }
        $prevWindowIndex = 0
        foreach ($windowIndex in $g.window_indices) {
            $ix = [int]$windowIndex
            if ($ix -le $prevWindowIndex -or $ix -lt 1 -or $ix -gt $pairCount -or
                [int]$windows[$ix - 1].motif_index -ne $motifIndex -or
                ($windows[$ix - 1].profile_class_index_walk -join ':') -cne
                    ($g.profile_class_index_walk -join ':')) {
                throw 'Code Sequence maximal repeat parent motif membership is invalid.'
            }
            $seenWindow[$ix - 1]++
            $prevWindowIndex = $ix
        }
        $pairOrdinal = 0
        for ($i = 0; $i -lt $g.window_indices.Count; $i++) {
            for ($j = $i + 1; $j -lt $g.window_indices.Count; $j++) {
                $pairOrdinal++
                $parentPair = $g.repeated_occurrence_pairs[$pairOrdinal - 1]
                $firstIndex = [int]$g.window_indices[$i]
                $secondIndex = [int]$g.window_indices[$j]
                $first = $windows[$firstIndex - 1]
                $second = $windows[$secondIndex - 1]
                $firstFrom = [int]$first.from_position
                $secondFrom = [int]$second.from_position
                $len = [int]$first.position_count
                $firstTo = [int]$first.to_position
                $secondTo = [int]$second.to_position
                $shared = [Math]::Max(0, $firstTo - $secondFrom + 1)
                $relation = if ($shared -eq 0) { 'disjoint' } elseif ($shared -eq 1) {
                    'shared_endpoint'
                } else { 'overlapping_positions' }
                if ($firstFrom -ge $secondFrom -or $firstTo -ne $firstFrom + $len - 1 -or
                    $secondTo -ne $secondFrom + $len - 1 -or
                    [int]$parentPair.first_window_index -ne $firstIndex -or
                    [int]$parentPair.second_window_index -ne $secondIndex -or
                    [int]$parentPair.first_from_position -ne $firstFrom -or
                    [int]$parentPair.first_to_position -ne $firstTo -or
                    [int]$parentPair.second_from_position -ne $secondFrom -or
                    [int]$parentPair.second_to_position -ne $secondTo -or
                    [int]$parentPair.shared_position_count -ne $shared -or
                    $parentPair.overlap_class -cne $relation -or
                    ($first.profile_class_index_walk -join ':') -cne
                        ($second.profile_class_index_walk -join ':')) {
                    throw 'Code Sequence maximal repeat cannot reconcile an actual repeated window pair.'
                }
                $seedIndex = $seeds.Count + 1
                $leftMax = 0
                while ($firstFrom - $leftMax -gt 1 -and $secondFrom - $leftMax -gt 1 -and
                    $classAt[$firstFrom - $leftMax - 2] -eq $classAt[$secondFrom - $leftMax - 2]) {
                    $leftMax++
                }
                $rightMax = 0
                while ($firstTo + $rightMax -lt $n -and $secondTo + $rightMax -lt $n -and
                    $classAt[$firstTo + $rightMax] -eq $classAt[$secondTo + $rightMax]) {
                    $rightMax++
                }
                if ($leftMax -gt 0) { $leftExtendibleSeedCount++ }
                if ($rightMax -gt 0) { $rightExtendibleSeedCount++ }
                if ($leftMax -eq 0 -and $rightMax -eq 0) { $alreadyMaximalSeedCount++ }

                $globalFirst = $firstFrom - $leftMax
                $globalSecond = $secondFrom - $leftMax
                $globalLength = $len + $leftMax + $rightMax
                $globalFirstTo = $globalFirst + $globalLength - 1
                $globalSecondTo = $globalSecond + $globalLength - 1
                $globalKey = '{0}:{1}:{2}:{3}' -f $globalFirst, $globalFirstTo, $globalSecond, $globalSecondTo
                if (-not $globalByBounds.ContainsKey($globalKey)) {
                    $newIndex = $globalRegions.Count + 1
                    $region = New-CodeSequenceProfileMaximalRepeatRegion `
                        -RegionIndex $newIndex -FirstFrom $globalFirst -SecondFrom $globalSecond `
                        -PositionCount $globalLength -N $n -Windows $windows -ClassAt $classAt `
                        -RequireStrictDisjoint $false
                    $globalRegions.Add($region)
                    $globalByBounds.Add($globalKey, $newIndex)
                }
                $globalIndex = $globalByBounds[$globalKey]
                $globalRegions[$globalIndex - 1].originating_seed_repeat_pair_indices.Add($seedIndex)
                $maxGlobalLength = [Math]::Max($maxGlobalLength, $globalLength)

                $disjointIndexes = [System.Collections.Generic.List[int]]::new()
                if ($shared -eq 0) {
                    $disjointSeedCount++
                    $reportedDisjointPairs++
                    # Every way of expanding the SAME pair synchronously,
                    # until neither end can advance while preserving ZERO
                    # shared original report positions. An unconstrained
                    # maximum may overlap and must not erase these matches.
                    $capacity = $secondFrom - $firstFrom - $len
                    if ($capacity -lt 0) {
                        throw 'Code Sequence maximal repeat found a negative strictly-disjoint extension capacity.'
                    }
                    if ($capacity -gt 0 -and ($leftMax -gt 0 -or $rightMax -gt 0)) {
                        $disjointExtendibleSeedCount++
                    }
                    $boundedLeft = [Math]::Min($leftMax, $capacity)
                    for ($addLeft = 0; $addLeft -le $boundedLeft; $addLeft++) {
                        $boundedRight = [Math]::Min($rightMax, $capacity - $addLeft)
                        for ($addRight = 0; $addRight -le $boundedRight; $addRight++) {
                            $used = $addLeft + $addRight
                            $canMoreLeft = ($addLeft -lt $leftMax) -and ($used -lt $capacity)
                            $canMoreRight = ($addRight -lt $rightMax) -and ($used -lt $capacity)
                            if ($canMoreLeft -or $canMoreRight) { continue }
                            $dFirst = $firstFrom - $addLeft
                            $dSecond = $secondFrom - $addLeft
                            $dLength = $len + $used
                            $dFirstTo = $dFirst + $dLength - 1
                            $dSecondTo = $dSecond + $dLength - 1
                            $disjointKey = '{0}:{1}:{2}:{3}' -f $dFirst, $dFirstTo, $dSecond, $dSecondTo
                            if (-not $disjointByBounds.ContainsKey($disjointKey)) {
                                $newIndex = $disjointRegions.Count + 1
                                $region = New-CodeSequenceProfileMaximalRepeatRegion `
                                    -RegionIndex $newIndex -FirstFrom $dFirst -SecondFrom $dSecond `
                                    -PositionCount $dLength -N $n -Windows $windows -ClassAt $classAt `
                                    -RequireStrictDisjoint $true
                                $disjointRegions.Add($region)
                                $disjointByBounds.Add($disjointKey, $newIndex)
                            }
                            $disjointIndex = $disjointByBounds[$disjointKey]
                            $disjointRegions[$disjointIndex - 1].originating_seed_repeat_pair_indices.Add($seedIndex)
                            $disjointIndexes.Add($disjointIndex)
                            $maxDisjointLength = [Math]::Max($maxDisjointLength, $dLength)
                        }
                    }
                    if ($disjointIndexes.Count -lt 1) {
                        throw 'Code Sequence maximal repeat lost an original strictly disjoint repeated pair.'
                    }
                }
                $seeds.Add([ordered]@{
                    seed_repeat_pair_index = $seedIndex
                    motif_index = $motifIndex
                    first_window_index = $firstIndex
                    second_window_index = $secondIndex
                    first_from_position = $firstFrom
                    first_to_position = $firstTo
                    second_from_position = $secondFrom
                    second_to_position = $secondTo
                    position_count_per_occurrence = $len
                    shared_position_count = $shared
                    overlap_class = $relation
                    synchronized_equal_class_left_extension_count = $leftMax
                    synchronized_equal_class_right_extension_count = $rightMax
                    already_pairwise_maximal = ($leftMax -eq 0 -and $rightMax -eq 0)
                    synchronized_one_step_left_extension_preserves_strict_disjointness = ($shared -eq 0 -and $leftMax -gt 0 -and $secondFrom -gt $firstTo + 1)
                    synchronized_one_step_right_extension_preserves_strict_disjointness = ($shared -eq 0 -and $rightMax -gt 0 -and $secondFrom -gt $firstTo + 1)
                    pairwise_maximal_region_index = $globalIndex
                    strictly_disjoint_maximal_region_indices = $disjointIndexes.ToArray()
                })
            }
        }
        if ($pairOrdinal -ne $g.repeated_occurrence_pairs.Count) {
            throw 'Code Sequence maximal repeat motif pair order is not canonical.'
        }
    }
    foreach ($count in $seenWindow) {
        if ($count -ne 1) { throw 'Code Sequence maximal repeat did not partition every real observed window once.' }
    }
    if ($seeds.Count -ne [int]$Motifs.counts.repeated_occurrence_pair_count -or
        $reportedGroupRepeats -ne [int]$Motifs.counts.repeated_motif_count -or
        $reportedDisjointPairs -ne [int]$Motifs.counts.strictly_disjoint_repeat_pair_count -or
        $disjointSeedCount -ne $reportedDisjointPairs -or
        ($seeds.Count -eq 0 -and ($globalRegions.Count -ne 0 -or $disjointRegions.Count -ne 0)) -or
        ($disjointSeedCount -eq 0 -and $disjointRegions.Count -ne 0)) {
        throw 'Code Sequence maximal repeat input seed-pair conservation failed.'
    }
    foreach ($region in $globalRegions) {
        if ($region.originating_seed_repeat_pair_indices.Count -lt 1 -or
            [bool]$region.class_equal_left_extension_possible -or
            [bool]$region.class_equal_right_extension_possible) {
            throw 'Code Sequence maximal repeat unconstrained regions are not maximal or have no witnesses.'
        }
    }
    foreach ($region in $disjointRegions) {
        if ($region.originating_seed_repeat_pair_indices.Count -lt 1 -or
            $region.overlap_class -cne 'disjoint' -or
            [bool]$region.class_equal_left_extension_preserving_strict_disjointness_possible -or
            [bool]$region.class_equal_right_extension_preserving_strict_disjointness_possible) {
            throw 'Code Sequence maximal repeat strictly disjoint regions are not maximal or have no witnesses.'
        }
    }
    $globalOutput = [System.Collections.Generic.List[object]]::new()
    foreach ($region in $globalRegions) {
        $copy = [ordered]@{}
        foreach ($key in $region.Keys) {
            if ($key -cne 'originating_seed_repeat_pair_indices') { $copy[$key] = $region[$key] }
        }
        $copy['originating_seed_repeat_pair_indices'] = $region.originating_seed_repeat_pair_indices.ToArray()
        $globalOutput.Add($copy)
    }
    $disjointOutput = [System.Collections.Generic.List[object]]::new()
    foreach ($region in $disjointRegions) {
        $copy = [ordered]@{}
        foreach ($key in $region.Keys) {
            if ($key -cne 'originating_seed_repeat_pair_indices') { $copy[$key] = $region[$key] }
        }
        $copy['originating_seed_repeat_pair_indices'] = $region.originating_seed_repeat_pair_indices.ToArray()
        $disjointOutput.Add($copy)
    }
    return [ordered]@{
        scope = 'pairwise_maximal_real_contiguous_saved_profile_class_repeats_and_all_disjoint_limited_maxima'
        pair_index_in_pairwise_profile = [int]$Motifs.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Motifs.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Motifs.anchor_index_in_anchor_journeys
        path = [string]$Motifs.path
        exact_saved_quote_anchor = $Motifs.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            all_ec043_position_pair_count = $pairCount
            repeated_seed_window_pair_count = $seeds.Count
            seed_pair_with_equal_class_left_extension_count = $leftExtendibleSeedCount
            seed_pair_with_equal_class_right_extension_count = $rightExtendibleSeedCount
            already_pairwise_maximal_seed_pair_count = $alreadyMaximalSeedCount
            pairwise_maximal_repeat_region_count = $globalRegions.Count
            longest_pairwise_maximal_repeat_position_count = $maxGlobalLength
            strictly_disjoint_seed_window_pair_count = $disjointSeedCount
            disjoint_seed_pair_with_possible_disjoint_extension_count = $disjointExtendibleSeedCount
            strictly_disjoint_maximal_repeat_region_count = $disjointRegions.Count
            longest_strictly_disjoint_maximal_repeat_position_count = $maxDisjointLength
        }
        all_real_repeated_window_pair_extensions = $seeds.ToArray()
        pairwise_maximal_repeat_regions = $globalOutput.ToArray()
        strictly_disjoint_maximal_repeat_regions = $disjointOutput.ToArray()
        independent_of_sequence_top = $true
        complete_ec043_window_ec051_class_ec052_adjacent_ec054_motif_pair_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Pairwise maximal means two ACTUALLY observed equal-class contiguous windows cannot be jointly extended one position in either direction. Each seed is a real EC-054 repeat pair, with its exact EC-043 windows and EC-052 saved-report step walks. ALL zero-overlap maximal expansions are separately preserved: extension requiring a shared position is never treated as strictly disjoint, and a longer overlapping maximum never removes its shorter disjoint witnesses. Equal model-severity-statement class walks do not imply a shared semantic Finding or real defect recurrence; caller order is not authenticated chronology. No sixth selector, extra saved body/source/Git/network read, write, raw quote or model reasoning.'
    }
}

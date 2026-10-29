#requires -Version 7.0
<#
    EC-056: group EC-055's ACTUAL maximal region pairs into complete
    saved-profile class-walk families. Lift each family back to every genuine
    EC-054 observed window (not merely the endpoints that happened to be
    pairwise maximal), then enumerate ALL maximum-cardinality sets of
    strictly nonoverlapping original report intervals. Explain which caller
    positions are always, sometimes, or never covered by these optimal sets.
    Reuse the existing checked in-memory views; never infer graph walks,
    real defect identity, verified chronology or source-code changes.
#>

function Get-CodeSequenceOriginalFindingPairProfileRepeatFamilies {
    param(
        [object] $Atlas,
        [object] $Graph,
        [object] $Motifs,
        [object] $Maximal,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Graph -or $null -eq $Motifs -or
        $null -eq $Maximal -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence repeat families require all five checked parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $pairCount = [int](($n * ($n - 1)) / 2)
    $global = @($Maximal.pairwise_maximal_repeat_regions)
    $disjoint = @($Maximal.strictly_disjoint_maximal_repeat_regions)
    $seeds = @($Maximal.all_real_repeated_window_pair_extensions)
    $windows = @($Motifs.all_observed_contiguous_windows)
    $motifGroups = @($Motifs.ordered_complete_class_walk_motifs)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $Maximal.scope -cne 'pairwise_maximal_real_contiguous_saved_profile_class_repeats_and_all_disjoint_limited_maxima' -or
        $Motifs.scope -cne 'complete_observed_contiguous_saved_profile_class_walk_motifs_and_repeat_overlap_witnesses' -or
        $Graph.scope -cne 'complete_directed_saved_profile_class_transition_multigraph_and_prior_run_return_witnesses_for_two_independent_original_Findings' -or
        -not [bool]$Maximal.complete_ec043_window_ec051_class_ec052_adjacent_ec054_motif_pair_reconciled -or
        -not [bool]$Maximal.two_original_finding_journeys_remain_independent -or
        -not [bool]$Maximal.independent_of_sequence_top -or
        -not [bool]$Motifs.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$Graph.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        [int]$Maximal.counts.selected_report_positions -ne $n -or
        [int]$Motifs.counts.selected_report_positions -ne $n -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        [int]$Maximal.counts.all_ec043_position_pair_count -ne $pairCount -or
        [int]$Motifs.counts.observed_contiguous_window_count -ne $pairCount -or
        $windows.Count -ne $pairCount -or
        [int]$Maximal.counts.repeated_seed_window_pair_count -ne $seeds.Count -or
        [int]$Motifs.counts.repeated_occurrence_pair_count -ne $seeds.Count -or
        [int]$Maximal.counts.pairwise_maximal_repeat_region_count -ne $global.Count -or
        [int]$Maximal.counts.strictly_disjoint_maximal_repeat_region_count -ne $disjoint.Count -or
        $Atlas.positions.Count -ne $n -or
        $SelectedAnchor.positions.Count -ne $n -or
        $Graph.adjacent_step_edges.Count -ne $n - 1 -or
        $Motifs.path -cne $Maximal.path -or $Atlas.path -cne $Maximal.path -or
        $SelectedAnchor.path -cne $Maximal.path -or $Graph.path -cne $Maximal.path -or
        [int]$Motifs.pair_index_in_pairwise_profile -ne [int]$Maximal.pair_index_in_pairwise_profile -or
        [int]$Motifs.path_index_in_selected_pair_overview -ne [int]$Maximal.path_index_in_selected_pair_overview -or
        [int]$Motifs.anchor_index_in_anchor_journeys -ne [int]$Maximal.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Motifs.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Maximal.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Maximal.exact_saved_quote_anchor)) {
        throw 'Code Sequence repeat family parent scope, selectors, counts or quote anchor disagree.'
    }

    # Reconstruct original caller positions and verify the real EC-043/052
    # window ledger before assigning ANY maximal region or coverage.
    $classAt = [int[]]::new($n)
    $recordAt = [string[]]::new($n)
    for ($pos = 1; $pos -le $n; $pos++) {
        $ap = $Atlas.positions[$pos - 1]
        $sp = $SelectedAnchor.positions[$pos - 1]
        $cl = [int]$ap.profile_class_index
        if ([int]$ap.position -ne $pos -or [int]$sp.position -ne $pos -or
            $ap.record_id -cne $sp.record_id -or
            [string]::IsNullOrWhiteSpace([string]$ap.record_id) -or
            $cl -lt 1 -or $cl -gt [int]$Atlas.counts.distinct_saved_profile_class_count) {
            throw 'Code Sequence repeat family original report ID/class ledger is inconsistent.'
        }
        $classAt[$pos - 1] = $cl
        $recordAt[$pos - 1] = [string]$ap.record_id
    }
    $canonical = 0
    for ($left = 1; $left -lt $n; $left++) {
        for ($right = $left + 1; $right -le $n; $right++) {
            $canonical++
            $w = $windows[$canonical - 1]
            $direct = $SelectedAnchor.compared_pairs[$canonical - 1]
            $width = $right - $left + 1
            if ([int]$w.window_index -ne $canonical -or
                [int]$w.ec043_direct_pair_index -ne $canonical -or
                [int]$w.from_position -ne $left -or [int]$w.to_position -ne $right -or
                [int]$w.position_count -ne $width -or
                [int]$direct.pair_index -ne $canonical -or
                [int]$direct.left_position -ne $left -or
                [int]$direct.right_position -ne $right -or
                $w.from_record_id -cne $recordAt[$left - 1] -or
                $w.to_record_id -cne $recordAt[$right - 1] -or
                $direct.left_record_id -cne $recordAt[$left - 1] -or
                $direct.right_record_id -cne $recordAt[$right - 1] -or
                $w.record_id_walk.Count -ne $width -or
                $w.profile_class_index_walk.Count -ne $width -or
                $w.adjacent_step_indices.Count -ne $width - 1 -or
                $w.directed_edge_index_walk.Count -ne $width - 1 -or
                $w.ec043_adjacent_pair_index_walk.Count -ne $width - 1 -or
                [int]$w.motif_index -lt 1 -or [int]$w.motif_index -gt $motifGroups.Count) {
                throw 'Code Sequence repeat family lost a canonical EC-043 observed window.'
            }
            for ($p = $left; $p -le $right; $p++) {
                $offset = $p - $left
                if ($w.record_id_walk[$offset] -cne $recordAt[$p - 1] -or
                    [int]$w.profile_class_index_walk[$offset] -ne $classAt[$p - 1]) {
                    throw 'Code Sequence repeat family observed class/record walk is not real.'
                }
                if ($p -lt $right) {
                    $step = $Graph.adjacent_step_edges[$p - 1]
                    if ([int]$step.step_index -ne $p -or
                        [int]$step.from_position -ne $p -or
                        [int]$step.to_position -ne $p + 1 -or
                        [int]$w.adjacent_step_indices[$offset] -ne $p -or
                        [int]$w.directed_edge_index_walk[$offset] -ne [int]$step.directed_edge_index -or
                        [int]$w.ec043_adjacent_pair_index_walk[$offset] -ne [int]$step.ec043_pair_index) {
                        throw 'Code Sequence repeat family found a nonoriginal adjacent step.'
                    }
                }
            }
            $group = $motifGroups[[int]$w.motif_index - 1]
            if (($w.profile_class_index_walk -join ':') -cne
                    ($group.profile_class_index_walk -join ':') -or
                -not ($group.window_indices -contains $canonical)) {
                throw 'Code Sequence repeat family original motif membership is inconsistent.'
            }
        }
    }
    if ($canonical -ne $pairCount) {
        throw 'Code Sequence repeat family observed window ledger is incomplete.'
    }

    # Every EC-055 maximal region maps to exactly ONE EC-054 whole-walk
    # motif. Keep both kinds separate: a disjoint-limited maximum need not
    # be an unconstrained pairwise maximum.
    $families = [System.Collections.Generic.List[object]]::new()
    $familyByMotif = [System.Collections.Generic.Dictionary[int,int]]::new()
    $globalCoverage = [object[]]::new($n)
    $disjointCoverage = [object[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $globalCoverage[$i] = [System.Collections.Generic.List[int]]::new()
        $disjointCoverage[$i] = [System.Collections.Generic.List[int]]::new()
    }
    foreach ($kind in @('global', 'disjoint')) {
        $source = if ($kind -ceq 'global') { $global } else { $disjoint }
        $mustDisjoint = ($kind -ceq 'disjoint')
        for ($i = 0; $i -lt $source.Count; $i++) {
            $region = $source[$i]
            $regionIndex = $i + 1
            $firstIndex = [int]$region.first_ec043_direct_pair_index
            $secondIndex = [int]$region.second_ec043_direct_pair_index
            if ([int]$region.region_index -ne $regionIndex -or
                [bool]$region.requires_strict_disjointness -ne $mustDisjoint -or
                $firstIndex -lt 1 -or $firstIndex -gt $pairCount -or
                $secondIndex -lt 1 -or $secondIndex -gt $pairCount) {
                throw 'Code Sequence repeat family received an invalid parent maximal region.'
            }
            $first = $windows[$firstIndex - 1]
            $second = $windows[$secondIndex - 1]
            $width = [int]$first.position_count
            $shared = [Math]::Max(0, [int]$first.to_position - [int]$second.from_position + 1)
            $relation = if ($shared -eq 0) { 'disjoint' } elseif ($shared -eq 1) {
                'shared_endpoint'
            } else { 'overlapping_positions' }
            if ([int]$first.from_position -ge [int]$second.from_position -or
                [int]$region.first_from_position -ne [int]$first.from_position -or
                [int]$region.first_to_position -ne [int]$first.to_position -or
                [int]$region.second_from_position -ne [int]$second.from_position -or
                [int]$region.second_to_position -ne [int]$second.to_position -or
                [int]$region.position_count_per_occurrence -ne $width -or
                [int]$second.position_count -ne $width -or
                [int]$region.motif_index -ne [int]$first.motif_index -or
                [int]$region.motif_index -ne [int]$second.motif_index -or
                [int]$region.shared_position_count -ne $shared -or
                $region.overlap_class -cne $relation -or
                ($mustDisjoint -and $shared -ne 0) -or
                ($region.profile_class_index_walk -join ':') -cne
                    ($first.profile_class_index_walk -join ':') -or
                ($first.profile_class_index_walk -join ':') -cne
                    ($second.profile_class_index_walk -join ':') -or
                ($region.first_record_id_walk -join '|') -cne ($first.record_id_walk -join '|') -or
                ($region.second_record_id_walk -join '|') -cne ($second.record_id_walk -join '|') -or
                ($region.first_ec052_adjacent_step_indices -join ':') -cne
                    ($first.adjacent_step_indices -join ':') -or
                ($region.second_ec052_adjacent_step_indices -join ':') -cne
                    ($second.adjacent_step_indices -join ':') -or
                ($region.first_directed_edge_index_walk -join ':') -cne
                    ($first.directed_edge_index_walk -join ':') -or
                ($region.second_directed_edge_index_walk -join ':') -cne
                    ($second.directed_edge_index_walk -join ':') -or
                ($region.first_ec043_adjacent_pair_index_walk -join ':') -cne
                    ($first.ec043_adjacent_pair_index_walk -join ':') -or
                ($region.second_ec043_adjacent_pair_index_walk -join ':') -cne
                    ($second.ec043_adjacent_pair_index_walk -join ':') -or
                $region.originating_seed_repeat_pair_indices.Count -lt 1) {
                throw 'Code Sequence repeat family region is not a genuine matching original pair.'
            }
            $canLeft = [int]$first.from_position -gt 1 -and
                [int]$second.from_position -gt 1 -and
                $classAt[[int]$first.from_position - 2] -eq
                    $classAt[[int]$second.from_position - 2]
            $canRight = [int]$first.to_position -lt $n -and
                [int]$second.to_position -lt $n -and
                $classAt[[int]$first.to_position] -eq
                    $classAt[[int]$second.to_position]
            $canLeftDisjoint = $canLeft -and
                ([int]$first.to_position -lt [int]$second.from_position - 1)
            $canRightDisjoint = $canRight -and
                ([int]$first.to_position + 1 -lt [int]$second.from_position)
            if (($mustDisjoint -and ($canLeftDisjoint -or $canRightDisjoint)) -or
                ((-not $mustDisjoint) -and ($canLeft -or $canRight)) -or
                [bool]$region.class_equal_left_extension_possible -ne [bool]$canLeft -or
                [bool]$region.class_equal_right_extension_possible -ne [bool]$canRight -or
                [bool]$region.class_equal_left_extension_preserving_strict_disjointness_possible -ne [bool]$canLeftDisjoint -or
                [bool]$region.class_equal_right_extension_preserving_strict_disjointness_possible -ne [bool]$canRightDisjoint) {
                throw 'Code Sequence repeat family region has an unreported admissible extension.'
            }
            $previousSeed = 0
            foreach ($seedRef in $region.originating_seed_repeat_pair_indices) {
                $si = [int]$seedRef
                if ($si -le $previousSeed -or $si -lt 1 -or $si -gt $seeds.Count) {
                    throw 'Code Sequence repeat family region seed witnesses are not unique and canonical.'
                }
                $seed = $seeds[$si - 1]
                if ([int]$seed.seed_repeat_pair_index -ne $si -or
                    ($kind -ceq 'global' -and [int]$seed.pairwise_maximal_region_index -ne $regionIndex) -or
                    ($kind -ceq 'disjoint' -and
                        -not ($seed.strictly_disjoint_maximal_region_indices -contains $regionIndex)) -or
                    [int]$seed.first_from_position -lt [int]$first.from_position -or
                    [int]$seed.second_from_position -lt [int]$second.from_position -or
                    [int]$seed.first_to_position -gt [int]$first.to_position -or
                    [int]$seed.second_to_position -gt [int]$second.to_position -or
                    ([int]$seed.first_from_position - [int]$first.from_position) -ne
                        ([int]$seed.second_from_position - [int]$second.from_position) -or
                    ([int]$first.to_position - [int]$seed.first_to_position) -ne
                        ([int]$second.to_position - [int]$seed.second_to_position)) {
                    throw 'Code Sequence repeat family parent region does not extend its genuine seed.'
                }
                $previousSeed = $si
            }
            $motifIndex = [int]$region.motif_index
            if (-not $familyByMotif.ContainsKey($motifIndex)) {
                $group = $motifGroups[$motifIndex - 1]
                $occurrenceIndices = @($group.window_indices)
                if ([int]$group.motif_index -ne $motifIndex -or
                    -not [bool]$group.repeats_at_least_twice -or
                    $occurrenceIndices.Count -lt 2 -or
                    [int]$group.occurrence_count -ne $occurrenceIndices.Count -or
                    [int]$group.repeated_occurrence_pair_count -ne
                        (($occurrenceIndices.Count * ($occurrenceIndices.Count - 1)) / 2) -or
                    ($group.profile_class_index_walk -join ':') -cne
                        ($first.profile_class_index_walk -join ':')) {
                    throw 'Code Sequence repeat family did not locate a complete real repeated motif.'
                }
                $occurrences = [System.Collections.Generic.List[object]]::new()
                $prevStart = 0
                for ($oi = 0; $oi -lt $occurrenceIndices.Count; $oi++) {
                    $ix = [int]$occurrenceIndices[$oi]
                    if ($ix -lt 1 -or $ix -gt $pairCount) {
                        throw 'Code Sequence repeat family motif has an invalid original occurrence.'
                    }
                    $w = $windows[$ix - 1]
                    if ([int]$w.window_index -ne $ix -or
                        [int]$w.motif_index -ne $motifIndex -or
                        [int]$w.position_count -ne $width -or
                        [int]$w.unreported_anchor_position_count -ne [int]$first.unreported_anchor_position_count -or
                        [int]$w.from_position -le $prevStart -or
                        ($w.profile_class_index_walk -join ':') -cne
                            ($group.profile_class_index_walk -join ':') -or
                        [int]$group.ec043_direct_pair_indices[$oi] -ne $ix) {
                        throw 'Code Sequence repeat family motif occurrences were duplicated or re-ordered.'
                    }
                    $occurrences.Add([ordered]@{
                        occurrence_index_in_family = $oi + 1
                        ec043_direct_pair_window_index = $ix
                        from_position = [int]$w.from_position
                        to_position = [int]$w.to_position
                        original_record_id_walk = $w.record_id_walk
                        original_ec052_adjacent_step_indices = $w.adjacent_step_indices
                        original_directed_edge_index_walk = $w.directed_edge_index_walk
                        original_ec043_adjacent_pair_index_walk = $w.ec043_adjacent_pair_index_walk
                    })
                    $prevStart = [int]$w.from_position
                }
                $familyIndex = $families.Count + 1
                $familyByMotif.Add($motifIndex, $familyIndex)
                $families.Add([ordered]@{
                    family_index = $familyIndex
                    ec054_complete_class_walk_motif_index = $motifIndex
                    profile_class_index_walk = $group.profile_class_index_walk
                    position_count_per_occurrence = $width
                    unreported_anchor_position_count_per_occurrence = [int]$first.unreported_anchor_position_count
                    actual_observed_occurrence_count = $occurrences.Count
                    all_observed_occurrences = $occurrences.ToArray()
                    ec055_pairwise_maximal_region_indices = [System.Collections.Generic.List[int]]::new()
                    ec055_strictly_disjoint_maximal_region_indices = [System.Collections.Generic.List[int]]::new()
                })
            }
            $family = $families[$familyByMotif[$motifIndex] - 1]
            if ($kind -ceq 'global') {
                $family.ec055_pairwise_maximal_region_indices.Add($regionIndex)
            } else {
                $family.ec055_strictly_disjoint_maximal_region_indices.Add($regionIndex)
            }
            $coverage = if ($mustDisjoint) { $disjointCoverage } else { $globalCoverage }
            for ($p = [int]$first.from_position; $p -le [int]$first.to_position; $p++) {
                if (-not $coverage[$p - 1].Contains($regionIndex)) { $coverage[$p - 1].Add($regionIndex) }
            }
            for ($p = [int]$second.from_position; $p -le [int]$second.to_position; $p++) {
                if (-not $coverage[$p - 1].Contains($regionIndex)) { $coverage[$p - 1].Add($regionIndex) }
            }
        }
    }
    if ($global.Count -eq 0 -and $disjoint.Count -ne 0) {
        throw 'Code Sequence repeat family disjoint maximal pair has no unconstrained maximal origin.'
    }

    # Fail closed for the inverse relationship as well: EVERY original repeat
    # seed must have its exact global region and every separately admitted
    # strictly-disjoint maximal witness. No dangling or synthetic linkage.
    for ($si = 0; $si -lt $seeds.Count; $si++) {
        $seed = $seeds[$si]
        $globalIndex = [int]$seed.pairwise_maximal_region_index
        if ([int]$seed.seed_repeat_pair_index -ne $si + 1 -or
            $globalIndex -lt 1 -or $globalIndex -gt $global.Count -or
            -not ($global[$globalIndex - 1].originating_seed_repeat_pair_indices -contains ($si + 1))) {
            throw 'Code Sequence repeat family original seed lost its global maximal region.'
        }
        if ($seed.overlap_class -cne 'disjoint' -and
            $seed.strictly_disjoint_maximal_region_indices.Count -ne 0) {
            throw 'Code Sequence repeat family overlapping seed invented a disjoint witness.'
        }
        if ($seed.overlap_class -ceq 'disjoint' -and
            $seed.strictly_disjoint_maximal_region_indices.Count -lt 1) {
            throw 'Code Sequence repeat family lost an actual disjoint seed.'
        }
        $seenDisjoint = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($di in $seed.strictly_disjoint_maximal_region_indices) {
            $idx = [int]$di
            if ($idx -lt 1 -or $idx -gt $disjoint.Count -or
                -not $seenDisjoint.Add($idx) -or
                -not ($disjoint[$idx - 1].originating_seed_repeat_pair_indices -contains ($si + 1))) {
                throw 'Code Sequence repeat family seed has a dangling or duplicated disjoint maximum.'
            }
        }
    }

    # N<=12 and all motif occurrences have equal fixed lengths. There are
    # at most N-1 real windows for a given class walk (at most 11); 2^11
    # subsets are affordable. Enumerate EVERY maximum strictly disjoint
    # occurrence packing, rather than one arbitrary greedy witness; then
    # independently reconcile its cardinality with EC-054's greedy optimum.
    $outputFamilies = [System.Collections.Generic.List[object]]::new()
    $familyCoverage = [object[]]::new($n)
    $optimalIndependentCoverage = [object[]]::new($n)
    for ($p = 0; $p -lt $n; $p++) {
        $familyCoverage[$p] = [System.Collections.Generic.List[int]]::new()
        $optimalIndependentCoverage[$p] = [System.Collections.Generic.List[int]]::new()
    }
    $withGlobal = 0
    $withDisjointRegion = 0
    $withIndependentSupport = 0
    $longestFamily = 0
    $highestIndependentSupport = 0
    $allOptimalPackCount = 0
    $allFamilyOccurrenceCount = 0
    foreach ($family in $families) {
        $fi = [int]$family.family_index
        $occurrences = @($family.all_observed_occurrences)
        $m = $occurrences.Count
        if ($m -lt 2 -or $m -gt $n - 1) {
            throw 'Code Sequence repeat family has an impossible original occurrence count.'
        }
        $allFamilyOccurrenceCount += $m
        $longestFamily = [Math]::Max($longestFamily, [int]$family.position_count_per_occurrence)
        if ($family.ec055_pairwise_maximal_region_indices.Count -gt 0) { $withGlobal++ }
        if ($family.ec055_strictly_disjoint_maximal_region_indices.Count -gt 0) { $withDisjointRegion++ }
        $best = 0
        $bestPacks = [System.Collections.Generic.List[object]]::new()
        $maxMask = (1 -shl $m) - 1
        for ($mask = 1; $mask -le $maxMask; $mask++) {
            $chosen = [System.Collections.Generic.List[int]]::new()
            $chosenWindows = [System.Collections.Generic.List[int]]::new()
            $froms = [System.Collections.Generic.List[int]]::new()
            $tos = [System.Collections.Generic.List[int]]::new()
            $covered = [System.Collections.Generic.List[int]]::new()
            $lastEnd = 0
            $valid = $true
            for ($oi = 0; $oi -lt $m; $oi++) {
                if (($mask -band (1 -shl $oi)) -eq 0) { continue }
                $occ = $occurrences[$oi]
                $start = [int]$occ.from_position
                $end = [int]$occ.to_position
                if ($start -le $lastEnd) { $valid = $false; break }
                $chosen.Add($oi + 1)
                $chosenWindows.Add([int]$occ.ec043_direct_pair_window_index)
                $froms.Add($start)
                $tos.Add($end)
                for ($p = $start; $p -le $end; $p++) { $covered.Add($p) }
                $lastEnd = $end
            }
            if (-not $valid -or $chosen.Count -lt $best) { continue }
            if ($chosen.Count -gt $best) {
                $best = $chosen.Count
                $bestPacks.Clear()
            }
            $bestPacks.Add([ordered]@{
                packing_index_in_family = $bestPacks.Count + 1
                original_occurrence_indices_in_family = $chosen.ToArray()
                ec043_direct_pair_window_indices = $chosenWindows.ToArray()
                from_positions = $froms.ToArray()
                to_positions = $tos.ToArray()
                covered_caller_positions = $covered.ToArray()
                original_record_ids_at_covered_positions = @($covered | ForEach-Object { $recordAt[$_ - 1] })
            })
        }
        if ($best -lt 1 -or $bestPacks.Count -lt 1) {
            throw 'Code Sequence repeat family lost all actual maximum packings.'
        }
        $parentMotif = $motifGroups[[int]$family.ec054_complete_class_walk_motif_index - 1]
        if ($best -ne [int]$parentMotif.maximum_strictly_disjoint_occurrence_count -or
            [bool]($best -ge 2) -ne [bool]$parentMotif.has_strictly_disjoint_repeat -or
            $m -ne [int]$parentMotif.occurrence_count) {
            throw 'Code Sequence repeat family optimum disagrees with original EC-054 motif evidence.'
        }
        if ($best -ge 2) { $withIndependentSupport++ }
        $highestIndependentSupport = [Math]::Max($highestIndependentSupport, $best)
        $allOptimalPackCount += $bestPacks.Count
        $packCoverageAt = [int[]]::new($n)
        foreach ($pack in $bestPacks) {
            if ($pack.original_occurrence_indices_in_family.Count -ne $best -or
                $pack.ec043_direct_pair_window_indices.Count -ne $best) {
                throw 'Code Sequence repeat family optimal packing witness length changed.'
            }
            foreach ($p in $pack.covered_caller_positions) { $packCoverageAt[[int]$p - 1]++ }
        }
        $allOccurrenceAt = [bool[]]::new($n)
        foreach ($occ in $occurrences) {
            for ($p = [int]$occ.from_position; $p -le [int]$occ.to_position; $p++) {
                $allOccurrenceAt[$p - 1] = $true
            }
        }
        $positionCoverage = [System.Collections.Generic.List[object]]::new()
        $ever = 0
        $always = 0
        for ($p = 1; $p -le $n; $p++) {
            $count = $packCoverageAt[$p - 1]
            if ($count -gt $bestPacks.Count) { throw 'Code Sequence repeat family pack coverage exceeded its witness count.' }
            $status = if ($count -eq 0) { 'never' } elseif ($count -eq $bestPacks.Count) {
                'always'
            } else { 'sometimes' }
            if ($count -gt 0) { $ever++ }
            if ($count -eq $bestPacks.Count) { $always++ }
            if ($allOccurrenceAt[$p - 1]) { $familyCoverage[$p - 1].Add($fi) }
            if ($best -ge 2 -and $count -gt 0) {
                $optimalIndependentCoverage[$p - 1].Add($fi)
            }
            if (-not $allOccurrenceAt[$p - 1] -and $count -gt 0) {
                throw 'Code Sequence repeat family optimum covered an unobserved saved-report position.'
            }
            $positionCoverage.Add([ordered]@{
                position = $p
                original_record_id = $recordAt[$p - 1]
                in_any_observed_occurrence = [bool]$allOccurrenceAt[$p - 1]
                maximum_packing_inclusion_count = $count
                maximum_packing_inclusion = $status
            })
        }
        $regionEndpointSeen = [bool[]]::new($pairCount)
        foreach ($idx in $family.ec055_pairwise_maximal_region_indices) {
            $r = $global[[int]$idx - 1]
            $regionEndpointSeen[[int]$r.first_ec043_direct_pair_index - 1] = $true
            $regionEndpointSeen[[int]$r.second_ec043_direct_pair_index - 1] = $true
        }
        foreach ($idx in $family.ec055_strictly_disjoint_maximal_region_indices) {
            $r = $disjoint[[int]$idx - 1]
            $regionEndpointSeen[[int]$r.first_ec043_direct_pair_index - 1] = $true
            $regionEndpointSeen[[int]$r.second_ec043_direct_pair_index - 1] = $true
        }
        $regionEndpointIndices = [System.Collections.Generic.List[int]]::new()
        for ($wi = 1; $wi -le $pairCount; $wi++) {
            if ($regionEndpointSeen[$wi - 1]) { $regionEndpointIndices.Add($wi) }
        }
        $outputFamilies.Add([ordered]@{
            family_index = $fi
            ec054_complete_class_walk_motif_index = [int]$family.ec054_complete_class_walk_motif_index
            profile_class_index_walk = $family.profile_class_index_walk
            position_count_per_occurrence = [int]$family.position_count_per_occurrence
            unreported_anchor_position_count_per_occurrence = [int]$family.unreported_anchor_position_count_per_occurrence
            actual_observed_occurrence_count = $m
            all_observed_occurrences = $family.all_observed_occurrences
            ec055_pairwise_maximal_region_indices = $family.ec055_pairwise_maximal_region_indices.ToArray()
            ec055_strictly_disjoint_maximal_region_indices = $family.ec055_strictly_disjoint_maximal_region_indices.ToArray()
            ec055_any_maximal_region_endpoint_window_indices = $regionEndpointIndices.ToArray()
            has_at_least_two_strictly_disjoint_observed_occurrences = ($best -ge 2)
            maximum_strictly_disjoint_observed_occurrence_count = $best
            all_maximum_strictly_disjoint_occurrence_packings = $bestPacks.ToArray()
            maximum_strictly_disjoint_occurrence_packing_count = $bestPacks.Count
            covered_caller_position_count_in_any_maximum_packing = $ever
            covered_caller_position_count_in_every_maximum_packing = $always
            position_coverage_across_all_maximum_packings = $positionCoverage.ToArray()
        })
    }
    if (($global.Count -gt 0 -and $withGlobal -lt 1) -or
        ($global.Count -eq 0 -and $families.Count -ne 0) -or
        $withIndependentSupport -gt [int]$Motifs.counts.motif_with_strictly_disjoint_repeat_count) {
        throw 'Code Sequence repeat family global/disjoint family conservation failed.'
    }
    $selectedCoverage = [System.Collections.Generic.List[object]]::new()
    $coveredBySomeFamily = 0
    $coveredByOptimalIndependent = 0
    for ($p = 1; $p -le $n; $p++) {
        $f = $familyCoverage[$p - 1]
        $o = $optimalIndependentCoverage[$p - 1]
        if ($f.Count -gt 0) { $coveredBySomeFamily++ }
        if ($o.Count -gt 0) { $coveredByOptimalIndependent++ }
        $selectedCoverage.Add([ordered]@{
            position = $p
            original_record_id = $recordAt[$p - 1]
            original_saved_profile_class_index = $classAt[$p - 1]
            observed_maximal_repeat_family_indices = $f.ToArray()
            family_count = $f.Count
            ec055_pairwise_maximal_region_indices = $globalCoverage[$p - 1].ToArray()
            ec055_strictly_disjoint_maximal_region_indices = $disjointCoverage[$p - 1].ToArray()
            maximum_independent_packing_supported_family_indices = $o.ToArray()
            independently_supported_family_count = $o.Count
        })
    }
    return [ordered]@{
        scope = 'actual_maximal_repeat_class_walk_families_all_optimal_disjoint_occurrence_packings_and_position_coverage'
        pair_index_in_pairwise_profile = [int]$Maximal.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Maximal.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Maximal.anchor_index_in_anchor_journeys
        path = [string]$Maximal.path
        exact_saved_quote_anchor = $Maximal.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            all_ec043_position_pair_count = $pairCount
            ec055_pairwise_maximal_repeat_region_count = $global.Count
            ec055_strictly_disjoint_maximal_repeat_region_count = $disjoint.Count
            maximal_repeat_family_count = $outputFamilies.Count
            family_with_unconstrained_maximal_region_count = $withGlobal
            family_with_disjoint_limited_maximal_region_count = $withDisjointRegion
            family_with_two_or_more_strictly_disjoint_observed_occurrences_count = $withIndependentSupport
            total_observed_occurrences_across_families = $allFamilyOccurrenceCount
            longest_maximal_family_position_count_per_occurrence = $longestFamily
            largest_maximum_strictly_disjoint_occurrence_support = $highestIndependentSupport
            total_maximum_strictly_disjoint_occurrence_packings_across_families = $allOptimalPackCount
            caller_positions_covered_by_any_family_occurrence = $coveredBySomeFamily
            caller_positions_covered_by_some_independent_optimal_packing = $coveredByOptimalIndependent
        }
        ordered_maximal_repeat_families = $outputFamilies.ToArray()
        selected_caller_position_repeat_coverage = $selectedCoverage.ToArray()
        independent_of_sequence_top = $true
        complete_ec043_windows_ec052_steps_ec054_motifs_ec055_global_and_disjoint_regions_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Only genuinely observed EC-054 contiguous class walks that participate in EC-055 global and/or disjoint-limited maximal region pairs become families. Every family lists ALL original occurrences, not only two chosen pair endpoints, and ALL maximum-size pairwise strictly nonoverlapping packs; optimal position coverage is always/sometimes/never relative to those packs. A maximum of ONE is NOT independent repeat evidence. Every interval, original saved record ID, EC-043 direct pair and EC-052 step is in the verified in-memory parent views. Equal saved five-severity-statement histogram walks are NOT matched semantic Findings, true recurring bugs, chronological history, fixes, regression, actual severity or risk. No sixth selector, extra record/source/Git/network read or write, raw quote, model prose or business-source patch.'
    }
}

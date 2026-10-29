#requires -Version 7.0
<#
    EC-057: cross-family evidence compatibility for two distinct EC-056
    complete observed class-walk motifs. Independent support within EACH
    family does not imply that both families can use disjoint original report
    positions at once. Enumerate all real two-occurrence witness pairs and
    all combinations of the two families' EC-056 optimum packings. Report
    exact combination counts, deterministic first witnesses and complete
    original-position coverage, never invented graph routes or real defects.
#>

function Get-CodeSequenceOriginalFindingPairProfileJointSupport {
    param(
        [object] $Atlas,
        [object] $Motifs,
        [object] $Families,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Motifs -or
        $null -eq $Families -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence joint repeat support requires four checked parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $f = @($Families.ordered_maximal_repeat_families)
    $windows = @($Motifs.all_observed_contiguous_windows)
    $motifGroups = @($Motifs.ordered_complete_class_walk_motifs)
    $expectedWindows = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $Families.scope -cne 'actual_maximal_repeat_class_walk_families_all_optimal_disjoint_occurrence_packings_and_position_coverage' -or
        $Motifs.scope -cne 'complete_observed_contiguous_saved_profile_class_walk_motifs_and_repeat_overlap_witnesses' -or
        -not [bool]$Families.complete_ec043_windows_ec052_steps_ec054_motifs_ec055_global_and_disjoint_regions_reconciled -or
        -not [bool]$Families.two_original_finding_journeys_remain_independent -or
        -not [bool]$Families.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$Motifs.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        [int]$Families.counts.selected_report_positions -ne $n -or
        [int]$Motifs.counts.selected_report_positions -ne $n -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        [int]$Families.counts.all_ec043_position_pair_count -ne $expectedWindows -or
        $windows.Count -ne $expectedWindows -or
        [int]$Families.counts.maximal_repeat_family_count -ne $f.Count -or
        $Atlas.positions.Count -ne $n -or $SelectedAnchor.positions.Count -ne $n -or
        $Families.path -cne $Motifs.path -or $Families.path -cne $Atlas.path -or
        $Families.path -cne $SelectedAnchor.path -or
        [int]$Families.pair_index_in_pairwise_profile -ne [int]$Motifs.pair_index_in_pairwise_profile -or
        [int]$Families.path_index_in_selected_pair_overview -ne [int]$Motifs.path_index_in_selected_pair_overview -or
        [int]$Families.anchor_index_in_anchor_journeys -ne [int]$Motifs.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Families.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Motifs.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Families.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence joint repeat support scope, parent counts or original anchor disagree.'
    }

    $recordAt = [string[]]::new($n)
    $classAt = [int[]]::new($n)
    for ($pos = 1; $pos -le $n; $pos++) {
        $ap = $Atlas.positions[$pos - 1]
        $sp = $SelectedAnchor.positions[$pos - 1]
        if ([int]$ap.position -ne $pos -or [int]$sp.position -ne $pos -or
            $ap.record_id -cne $sp.record_id -or
            [string]::IsNullOrWhiteSpace([string]$ap.record_id)) {
            throw 'Code Sequence joint repeat support original position IDs disagree.'
        }
        $recordAt[$pos - 1] = [string]$ap.record_id
        $classAt[$pos - 1] = [int]$ap.profile_class_index
    }

    # Independently check each parent's genuine occurrence ledger and ALL
    # optimum packings. Encode actual caller positions (not family ordinals)
    # as a bounded N<=12 bitset; bit intersection means shared report data.
    $options = [object[]]::new($f.Count)
    $optimal = [object[]]::new($f.Count)
    $totalOptions = 0
    $totalPackings = 0
    $supportedFamilies = 0
    $allFamilyOccurrences = 0
    for ($fi = 1; $fi -le $f.Count; $fi++) {
        $family = $f[$fi - 1]
        $mi = [int]$family.ec054_complete_class_walk_motif_index
        if ([int]$family.family_index -ne $fi -or
            $mi -lt 1 -or $mi -gt $motifGroups.Count -or
            ($family.ec055_pairwise_maximal_region_indices.Count +
                $family.ec055_strictly_disjoint_maximal_region_indices.Count) -lt 1) {
            throw 'Code Sequence joint repeat support has a noncanonical maximal family.'
        }
        $group = $motifGroups[$mi - 1]
        $occs = @($family.all_observed_occurrences)
        $width = [int]$family.position_count_per_occurrence
        $m = $occs.Count
        if ($m -lt 2 -or $m -gt $n - 1 -or $width -lt 2 -or
            [int]$family.actual_observed_occurrence_count -ne $m -or
            [int]$group.occurrence_count -ne $m -or
            [int]$group.motif_index -ne $mi -or
            ($group.profile_class_index_walk -join ':') -cne
                ($family.profile_class_index_walk -join ':') -or
            $family.profile_class_index_walk.Count -ne $width -or
            $group.window_indices.Count -ne $m) {
            throw 'Code Sequence joint repeat support family does not match its full-walk motif.'
        }
        $allFamilyOccurrences += $m
        $masks = [int[]]::new($m)
        $previousStart = 0
        for ($oi = 0; $oi -lt $m; $oi++) {
            $occ = $occs[$oi]
            $wi = [int]$occ.ec043_direct_pair_window_index
            if ($wi -lt 1 -or $wi -gt $expectedWindows) {
                throw 'Code Sequence joint repeat support has an impossible observed window.'
            }
            $w = $windows[$wi - 1]
            $start = [int]$occ.from_position
            $end = [int]$occ.to_position
            if ([int]$occ.occurrence_index_in_family -ne $oi + 1 -or
                $start -le $previousStart -or $start -lt 1 -or
                $end -gt $n -or $end - $start + 1 -ne $width -or
                [int]$w.window_index -ne $wi -or
                [int]$w.motif_index -ne $mi -or
                [int]$w.from_position -ne $start -or
                [int]$w.to_position -ne $end -or
                [int]$group.window_indices[$oi] -ne $wi -or
                ($occ.original_record_id_walk -join '|') -cne ($w.record_id_walk -join '|') -or
                ($occ.original_ec052_adjacent_step_indices -join ':') -cne
                    ($w.adjacent_step_indices -join ':') -or
                ($occ.original_directed_edge_index_walk -join ':') -cne
                    ($w.directed_edge_index_walk -join ':') -or
                ($occ.original_ec043_adjacent_pair_index_walk -join ':') -cne
                    ($w.ec043_adjacent_pair_index_walk -join ':') -or
                $occ.original_record_id_walk.Count -ne $width) {
                throw 'Code Sequence joint repeat support did not receive a real canonical occurrence.'
            }
            $mask = 0
            for ($p = $start; $p -le $end; $p++) {
                if ($occ.original_record_id_walk[$p - $start] -cne $recordAt[$p - 1] -or
                    [int]$family.profile_class_index_walk[$p - $start] -ne $classAt[$p - 1]) {
                    throw 'Code Sequence joint repeat support occurrence records/classes are not original.'
                }
                $mask = $mask -bor (1 -shl ($p - 1))
            }
            $masks[$oi] = $mask
            $previousStart = $start
        }
        $twos = [System.Collections.Generic.List[object]]::new()
        for ($a = 0; $a -lt $m; $a++) {
            for ($b = $a + 1; $b -lt $m; $b++) {
                if (($masks[$a] -band $masks[$b]) -ne 0) { continue }
                $twos.Add([ordered]@{
                    first_occurrence_index = $a + 1
                    second_occurrence_index = $b + 1
                    first_ec043_direct_pair_window_index = [int]$occs[$a].ec043_direct_pair_window_index
                    second_ec043_direct_pair_window_index = [int]$occs[$b].ec043_direct_pair_window_index
                    covered_caller_position_mask = ($masks[$a] -bor $masks[$b])
                })
            }
        }
        $options[$fi - 1] = $twos.ToArray()
        $totalOptions += $twos.Count

        # Bounded independent subset recomputation catches missing/duplicate
        # EC-056 maxima, including ties and original occurrence order.
        $best = 0
        $allExpectedOptimalSubsets = [System.Collections.Generic.List[int]]::new()
        for ($subset = 1; $subset -lt (1 -shl $m); $subset++) {
            $used = 0
            $chosenCount = 0
            $valid = $true
            for ($oi = 0; $oi -lt $m; $oi++) {
                if (($subset -band (1 -shl $oi)) -eq 0) { continue }
                if (($used -band $masks[$oi]) -ne 0) { $valid = $false; break }
                $used = $used -bor $masks[$oi]
                $chosenCount++
            }
            if (-not $valid -or $chosenCount -lt $best) { continue }
            if ($chosenCount -gt $best) {
                $best = $chosenCount
                $allExpectedOptimalSubsets.Clear()
            }
            $allExpectedOptimalSubsets.Add($subset)
        }
        $parentPacks = @($family.all_maximum_strictly_disjoint_occurrence_packings)
        if ($best -ne [int]$family.maximum_strictly_disjoint_observed_occurrence_count -or
            ($best -ge 2) -ne [bool]$family.has_at_least_two_strictly_disjoint_observed_occurrences -or
            $parentPacks.Count -ne $allExpectedOptimalSubsets.Count -or
            $parentPacks.Count -ne [int]$family.maximum_strictly_disjoint_occurrence_packing_count -or
            $best -ne [int]$group.maximum_strictly_disjoint_occurrence_count -or
            ($best -ge 2) -ne ($twos.Count -gt 0)) {
            throw 'Code Sequence joint repeat support original family optimum or independence is inconsistent.'
        }
        if ($best -ge 2) { $supportedFamilies++ }
        $packOptions = [System.Collections.Generic.List[object]]::new()
        $coverCount = [int[]]::new($n)
        for ($pi = 0; $pi -lt $parentPacks.Count; $pi++) {
            $pack = $parentPacks[$pi]
            $subset = 0
            $packMask = 0
            $indices = @($pack.original_occurrence_indices_in_family)
            $winIds = [System.Collections.Generic.List[int]]::new()
            $previous = 0
            foreach ($index in $indices) {
                $ii = [int]$index
                if ($ii -le $previous -or $ii -lt 1 -or $ii -gt $m) {
                    throw 'Code Sequence joint repeat support invalid optimum occurrence index.'
                }
                $subset = $subset -bor (1 -shl ($ii - 1))
                $packMask = $packMask -bor $masks[$ii - 1]
                $winIds.Add([int]$occs[$ii - 1].ec043_direct_pair_window_index)
                $previous = $ii
            }
            $covered = [System.Collections.Generic.List[int]]::new()
            $ids = [System.Collections.Generic.List[string]]::new()
            for ($p = 1; $p -le $n; $p++) {
                if (($packMask -band (1 -shl ($p - 1))) -ne 0) {
                    $coverCount[$p - 1]++
                    $covered.Add($p)
                    $ids.Add($recordAt[$p - 1])
                }
            }
            if ([int]$pack.packing_index_in_family -ne $pi + 1 -or
                $indices.Count -ne $best -or
                $subset -ne $allExpectedOptimalSubsets[$pi] -or
                ($winIds.ToArray() -join ':') -cne ($pack.ec043_direct_pair_window_indices -join ':') -or
                ($covered.ToArray() -join ':') -cne ($pack.covered_caller_positions -join ':') -or
                ($ids.ToArray() -join '|') -cne ($pack.original_record_ids_at_covered_positions -join '|')) {
                throw 'Code Sequence joint repeat support parent optimum pack is incomplete or changed.'
            }
            $packOptions.Add([ordered]@{
                packing_index_in_family = $pi + 1
                original_occurrence_indices_in_family = $indices
                ec043_direct_pair_window_indices = $winIds.ToArray()
                covered_caller_position_mask = $packMask
            })
        }
        $parentCoverage = @($family.position_coverage_across_all_maximum_packings)
        if ($parentCoverage.Count -ne $n) {
            throw 'Code Sequence joint repeat support parent optimum coverage is incomplete.'
        }
        for ($p = 1; $p -le $n; $p++) {
            $cnt = $coverCount[$p - 1]
            $label = if ($cnt -eq 0) { 'never' } elseif ($cnt -eq $parentPacks.Count) {
                'always'
            } else { 'sometimes' }
            if ([int]$parentCoverage[$p - 1].position -ne $p -or
                $parentCoverage[$p - 1].original_record_id -cne $recordAt[$p - 1] -or
                [int]$parentCoverage[$p - 1].maximum_packing_inclusion_count -ne $cnt -or
                $parentCoverage[$p - 1].maximum_packing_inclusion -cne $label) {
                throw 'Code Sequence joint repeat support parent position coverage disagrees.'
            }
        }
        $optimal[$fi - 1] = $packOptions.ToArray()
        $totalPackings += $packOptions.Count
    }
    if ($allFamilyOccurrences -ne [int]$Families.counts.total_observed_occurrences_across_families -or
        $totalPackings -ne [int]$Families.counts.total_maximum_strictly_disjoint_occurrence_packings_across_families -or
        $supportedFamilies -ne [int]$Families.counts.family_with_two_or_more_strictly_disjoint_observed_occurrences_count) {
        throw 'Code Sequence joint repeat support parent family totals disagree.'
    }

    # Pairwise compatibility deliberately requires two nonoverlapping REAL
    # windows from EACH DIFFERENT motif. Never mix intervals into a new motif.
    # Local optimum compatibility is separate and stricter than co-support.
    $pairs = [System.Collections.Generic.List[object]]::new()
    $perPositionPairs = [object[]]::new($n)
    $perPositionAlways = [object[]]::new($n)
    for ($p = 0; $p -lt $n; $p++) {
        $perPositionPairs[$p] = [System.Collections.Generic.List[int]]::new()
        $perPositionAlways[$p] = [System.Collections.Generic.List[int]]::new()
    }
    $twoCapablePairs = 0
    $coexistingPairs = 0
    $jointOptimalPairs = 0
    $fourWindowCombinations = [long]0
    $jointOptimalCombinations = [long]0
    $familyCoexists = [object[]]::new($f.Count)
    $familyOptCoexists = [object[]]::new($f.Count)
    for ($i = 0; $i -lt $f.Count; $i++) {
        $familyCoexists[$i] = [System.Collections.Generic.List[int]]::new()
        $familyOptCoexists[$i] = [System.Collections.Generic.List[int]]::new()
    }
    for ($a = 0; $a -lt $f.Count; $a++) {
        for ($b = $a + 1; $b -lt $f.Count; $b++) {
            $left = @($options[$a])
            $right = @($options[$b])
            $lpacks = @($optimal[$a])
            $rpacks = @($optimal[$b])
            $bothCanIndependentlyRepeat = ($left.Count -gt 0 -and $right.Count -gt 0)
            if ($bothCanIndependentlyRepeat) { $twoCapablePairs++ }
            $jointCount = [long]0
            $jointCoverage = [long[]]::new($n)
            $firstJoint = $null
            foreach ($lo in $left) {
                foreach ($ro in $right) {
                    $mask = [int]$lo.covered_caller_position_mask -bor [int]$ro.covered_caller_position_mask
                    if (([int]$lo.covered_caller_position_mask -band [int]$ro.covered_caller_position_mask) -ne 0) { continue }
                    $jointCount++
                    if ($null -eq $firstJoint) {
                        $firstJoint = [ordered]@{
                            left_original_occurrence_indices_in_family = @([int]$lo.first_occurrence_index,[int]$lo.second_occurrence_index)
                            right_original_occurrence_indices_in_family = @([int]$ro.first_occurrence_index,[int]$ro.second_occurrence_index)
                            left_original_ec043_direct_pair_window_indices = @([int]$lo.first_ec043_direct_pair_window_index,[int]$lo.second_ec043_direct_pair_window_index)
                            right_original_ec043_direct_pair_window_indices = @([int]$ro.first_ec043_direct_pair_window_index,[int]$ro.second_ec043_direct_pair_window_index)
                            covered_caller_positions = @()
                            original_record_ids_at_covered_positions = @()
                        }
                    }
                    for ($p = 1; $p -le $n; $p++) {
                        if (($mask -band (1 -shl ($p - 1))) -ne 0) {
                            $jointCoverage[$p - 1]++
                        }
                    }
                }
            }
            # Deterministic canonical first witness: left family occurrence
            # indices lexicographic, then right family indices lexicographic.
            if ($null -ne $firstJoint) {
                $firstMask = 0
                foreach ($ix in $firstJoint.left_original_occurrence_indices_in_family) {
                    $o = $f[$a].all_observed_occurrences[[int]$ix - 1]
                    for ($p = [int]$o.from_position; $p -le [int]$o.to_position; $p++) {
                        $firstMask = $firstMask -bor (1 -shl ($p - 1))
                    }
                }
                foreach ($ix in $firstJoint.right_original_occurrence_indices_in_family) {
                    $o = $f[$b].all_observed_occurrences[[int]$ix - 1]
                    for ($p = [int]$o.from_position; $p -le [int]$o.to_position; $p++) {
                        $firstMask = $firstMask -bor (1 -shl ($p - 1))
                    }
                }
                $firstPositions = [System.Collections.Generic.List[int]]::new()
                $firstIds = [System.Collections.Generic.List[string]]::new()
                for ($p = 1; $p -le $n; $p++) {
                    if (($firstMask -band (1 -shl ($p - 1))) -ne 0) {
                        $firstPositions.Add($p)
                        $firstIds.Add($recordAt[$p - 1])
                    }
                }
                $firstJoint.covered_caller_positions = $firstPositions.ToArray()
                $firstJoint.original_record_ids_at_covered_positions = $firstIds.ToArray()
            }
            $optimalCount = [long]0
            $firstOptimal = $null
            if ($bothCanIndependentlyRepeat) {
                foreach ($lp in $lpacks) {
                    foreach ($rp in $rpacks) {
                        if (([int]$lp.covered_caller_position_mask -band [int]$rp.covered_caller_position_mask) -ne 0) { continue }
                        $optimalCount++
                        if ($null -eq $firstOptimal) {
                            $combined = [int]$lp.covered_caller_position_mask -bor [int]$rp.covered_caller_position_mask
                            $positions = [System.Collections.Generic.List[int]]::new()
                            $ids = [System.Collections.Generic.List[string]]::new()
                            for ($p = 1; $p -le $n; $p++) {
                                if (($combined -band (1 -shl ($p - 1))) -ne 0) {
                                    $positions.Add($p)
                                    $ids.Add($recordAt[$p - 1])
                                }
                            }
                            $firstOptimal = [ordered]@{
                                left_packing_index_in_family = [int]$lp.packing_index_in_family
                                right_packing_index_in_family = [int]$rp.packing_index_in_family
                                left_original_occurrence_indices_in_family = $lp.original_occurrence_indices_in_family
                                right_original_occurrence_indices_in_family = $rp.original_occurrence_indices_in_family
                                left_original_ec043_direct_pair_window_indices = $lp.ec043_direct_pair_window_indices
                                right_original_ec043_direct_pair_window_indices = $rp.ec043_direct_pair_window_indices
                                covered_caller_positions = $positions.ToArray()
                                original_record_ids_at_covered_positions = $ids.ToArray()
                            }
                        }
                    }
                }
            }
            if ($optimalCount -gt 0 -and $jointCount -eq 0) {
                throw 'Code Sequence joint repeat support inferred an impossible simultaneous optimum.'
            }
            $category = if (-not $bothCanIndependentlyRepeat) {
                'a_family_has_no_independent_two_occurrence_support'
            } elseif ($jointCount -eq 0) {
                'observed_position_competition_prevents_joint_independent_support'
            } elseif ($optimalCount -eq 0) {
                'two_families_can_coexist_but_their_separate_optima_compete'
            } else {
                'both_families_separate_optima_can_coexist'
            }
            $pairIndex = $pairs.Count + 1
            if ($jointCount -gt 0) {
                $coexistingPairs++
                $familyCoexists[$a].Add($b + 1)
                $familyCoexists[$b].Add($a + 1)
            }
            if ($optimalCount -gt 0) {
                $jointOptimalPairs++
                $familyOptCoexists[$a].Add($b + 1)
                $familyOptCoexists[$b].Add($a + 1)
            }
            $fourWindowCombinations += $jointCount
            $jointOptimalCombinations += $optimalCount
            $positionCoverage = [System.Collections.Generic.List[object]]::new()
            for ($p = 1; $p -le $n; $p++) {
                $cnt = $jointCoverage[$p - 1]
                if ($cnt -gt $jointCount) {
                    throw 'Code Sequence joint repeat support position covered more times than real witnesses.'
                }
                $label = if ($cnt -eq 0) { 'never' } elseif ($cnt -eq $jointCount) {
                    'always'
                } else { 'sometimes' }
                if ($cnt -gt 0) { $perPositionPairs[$p - 1].Add($pairIndex) }
                if ($cnt -gt 0 -and $cnt -eq $jointCount) {
                    $perPositionAlways[$p - 1].Add($pairIndex)
                }
                $positionCoverage.Add([ordered]@{
                    position = $p
                    original_record_id = $recordAt[$p - 1]
                    joint_independent_witness_inclusion_count = $cnt
                    across_all_joint_independent_witnesses = $label
                })
            }
            $pairs.Add([ordered]@{
                family_pair_index = $pairIndex
                left_maximal_repeat_family_index = $a + 1
                right_maximal_repeat_family_index = $b + 1
                left_ec054_complete_class_walk_motif_index = [int]$f[$a].ec054_complete_class_walk_motif_index
                right_ec054_complete_class_walk_motif_index = [int]$f[$b].ec054_complete_class_walk_motif_index
                left_maximum_strictly_disjoint_occurrence_count = [int]$f[$a].maximum_strictly_disjoint_observed_occurrence_count
                right_maximum_strictly_disjoint_occurrence_count = [int]$f[$b].maximum_strictly_disjoint_observed_occurrence_count
                left_valid_two_occurrence_support_pair_count = $left.Count
                right_valid_two_occurrence_support_pair_count = $right.Count
                both_families_separately_have_independent_repeat_support = $bothCanIndependentlyRepeat
                actual_joint_four_occurrence_witness_combination_count = $jointCount
                two_distinct_families_can_be_independently_supported_together = ($jointCount -gt 0)
                first_original_joint_independent_witness = $firstJoint
                actual_joint_locally_optimal_packing_pair_count = $optimalCount
                both_families_can_retain_their_separate_local_optima = ($optimalCount -gt 0)
                first_joint_locally_optimal_packing_witness = $firstOptimal
                compatibility_class = $category
                position_coverage_across_all_joint_independent_witnesses = $positionCoverage.ToArray()
            })
        }
    }
    $familySummaries = [System.Collections.Generic.List[object]]::new()
    for ($fi = 1; $fi -le $f.Count; $fi++) {
        $familySummaries.Add([ordered]@{
            family_index = $fi
            ec054_complete_class_walk_motif_index = [int]$f[$fi - 1].ec054_complete_class_walk_motif_index
            maximum_strictly_disjoint_occurrence_count = [int]$f[$fi - 1].maximum_strictly_disjoint_observed_occurrence_count
            original_valid_two_occurrence_support_pair_count = @($options[$fi - 1]).Count
            compatible_other_family_indices_for_two_plus_two_original_support = $familyCoexists[$fi - 1].ToArray()
            compatible_other_family_indices_for_both_separate_local_optima = $familyOptCoexists[$fi - 1].ToArray()
        })
    }
    $callerCoverage = [System.Collections.Generic.List[object]]::new()
    $positionsWithJointSupport = 0
    for ($p = 1; $p -le $n; $p++) {
        if ($perPositionPairs[$p - 1].Count -gt 0) { $positionsWithJointSupport++ }
        $callerCoverage.Add([ordered]@{
            position = $p
            original_record_id = $recordAt[$p - 1]
            original_saved_profile_class_index = $classAt[$p - 1]
            compatible_family_pair_indices_with_a_joint_witness_covering_this_position = $perPositionPairs[$p - 1].ToArray()
            compatible_family_pair_indices_covered_in_every_joint_witness = $perPositionAlways[$p - 1].ToArray()
        })
    }
    if ($pairs.Count -ne (($f.Count * ($f.Count - 1)) / 2) -or
        $jointOptimalPairs -gt $coexistingPairs -or
        $coexistingPairs -gt $twoCapablePairs) {
        throw 'Code Sequence joint repeat support pairwise partition failed.'
    }
    return [ordered]@{
        scope = 'pairwise_joint_actual_nonoverlapping_original_repeat_family_evidence_and_compatibility_of_separate_optima'
        pair_index_in_pairwise_profile = [int]$Families.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Families.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Families.anchor_index_in_anchor_journeys
        path = [string]$Families.path
        exact_saved_quote_anchor = $Families.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            maximal_repeat_family_count = $f.Count
            independently_supportable_family_count = $supportedFamilies
            original_valid_two_occurrence_support_pairs_across_families = $totalOptions
            original_ec056_locally_optimal_packings_across_families = $totalPackings
            distinct_maximal_repeat_family_pair_count = $pairs.Count
            family_pairs_with_both_locally_independent_repeat_support = $twoCapablePairs
            family_pairs_with_joint_independent_repeat_support = $coexistingPairs
            family_pairs_with_both_separate_local_maxima_jointly_compatible = $jointOptimalPairs
            family_pairs_with_only_individual_independence_but_no_joint_support = $twoCapablePairs - $coexistingPairs
            family_pairs_with_joint_support_but_competing_local_maxima = $coexistingPairs - $jointOptimalPairs
            actual_joint_four_occurrence_witness_combinations_across_family_pairs = $fourWindowCombinations
            actual_joint_locally_optimal_packing_pair_combinations_across_family_pairs = $jointOptimalCombinations
            caller_positions_with_joint_independent_support_from_some_distinct_family_pair = $positionsWithJointSupport
        }
        ordered_cross_family_support_pairs = $pairs.ToArray()
        ordered_family_joint_support_summaries = $familySummaries.ToArray()
        selected_caller_position_joint_support_coverage = $callerCoverage.ToArray()
        independent_of_sequence_top = $true
        complete_ec054_actual_windows_ec055_maxima_and_ec056_family_all_optimal_packings_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Pairwise independent support means two genuinely observed strictly position-disjoint occurrences of EACH of TWO different complete saved-profile class-walk motifs, with all FOUR original report-position intervals mutually disjoint. Local optimality means both families also attain their respective complete EC-056 maximum packings without sharing any position. A family may be independently supported by itself yet spatially incompatible with another; joint support does not imply joint local optimality. All witnesses use actual original EC-043 windows and caller-selected saved-report record IDs, not graph-reachable synthetic walks. These are saved model severity-statement histogram repeats, NOT semantic Finding matches, historical defect recurrence, true chronology, actual severity, fixes or risk. No sixth selector, additional saved-body/source/Git/network read, raw model quote/prose or write.'
    }
}

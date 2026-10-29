#requires -Version 7.0
<#
    EC-058: complete THREE-family simultaneous, observed-repeat evidence.
    Pairwise compatible EC-057 family pairs do NOT imply a compatible triple.
    Reconstruct real EC-054/056 occurrence masks, reconcile every EC-057 pair,
    enumerate all actual 2+2+2 disjoint windows AND combinations of the
    three EC-056 local maxima. No inferred graph paths, extra selectors,
    report/source/Git/network access, persistence or chronology claims.
#>

function New-CodeSequenceTripleOriginalWitness {
    param(
        [int[]] $FamilyIndexes,
        [object[]] $Choices,
        [object[]] $Families,
        [string[]] $RecordIds,
        [bool] $Optimal = $false
    )
    $mask = 0
    $parts = [System.Collections.Generic.List[object]]::new()
    for ($j = 0; $j -lt $FamilyIndexes.Count; $j++) {
        $fi = $FamilyIndexes[$j]
        $choice = $Choices[$j]
        $mask = $mask -bor [int]$choice.position_mask
        $part = [ordered]@{
            maximal_repeat_family_index = $fi
            ec054_complete_class_walk_motif_index = [int]$Families[$fi - 1].ec054_complete_class_walk_motif_index
            original_occurrence_indices_in_family = @($choice.original_occurrence_indices_in_family)
            original_ec043_direct_pair_window_indices = @($choice.ec043_direct_pair_window_indices)
        }
        if ($Optimal) {
            $part['ec056_local_optimum_packing_index_in_family'] = [int]$choice.packing_index_in_family
        }
        $parts.Add($part)
    }
    $positions = [System.Collections.Generic.List[int]]::new()
    $ids = [System.Collections.Generic.List[string]]::new()
    for ($p = 1; $p -le $RecordIds.Count; $p++) {
        if (($mask -band (1 -shl ($p - 1))) -ne 0) {
            $positions.Add($p)
            $ids.Add($RecordIds[$p - 1])
        }
    }
    return [ordered]@{
        families = $parts.ToArray()
        covered_caller_positions = $positions.ToArray()
        original_record_ids_at_covered_positions = $ids.ToArray()
    }
}

function Get-CodeSequenceOriginalFindingPairProfileTripleSupport {
    param(
        [object] $Atlas,
        [object] $Motifs,
        [object] $Families,
        [object] $Joint,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Motifs -or $null -eq $Families -or
        $null -eq $Joint -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence triple support requires all five already-checked parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $familyRows = @($Families.ordered_maximal_repeat_families)
    $fCount = $familyRows.Count
    $windows = @($Motifs.all_observed_contiguous_windows)
    $groups = @($Motifs.ordered_complete_class_walk_motifs)
    $familySummary = @($Joint.ordered_family_joint_support_summaries)
    $parentPairs = @($Joint.ordered_cross_family_support_pairs)
    $windowCount = [int](($n * ($n - 1)) / 2)
    $expectedPairCount = [int](($fCount * ($fCount - 1)) / 2)
    $expectedTripleCount = [int](($fCount * ($fCount - 1) * ($fCount - 2)) / 6)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $Families.scope -cne 'actual_maximal_repeat_class_walk_families_all_optimal_disjoint_occurrence_packings_and_position_coverage' -or
        $Joint.scope -cne 'pairwise_joint_actual_nonoverlapping_original_repeat_family_evidence_and_compatibility_of_separate_optima' -or
        $Motifs.scope -cne 'complete_observed_contiguous_saved_profile_class_walk_motifs_and_repeat_overlap_witnesses' -or
        -not [bool]$Joint.complete_ec054_actual_windows_ec055_maxima_and_ec056_family_all_optimal_packings_reconciled -or
        -not [bool]$Families.complete_ec043_windows_ec052_steps_ec054_motifs_ec055_global_and_disjoint_regions_reconciled -or
        -not [bool]$Joint.two_original_finding_journeys_remain_independent -or
        -not [bool]$Families.two_original_finding_journeys_remain_independent -or
        -not [bool]$Joint.independent_of_sequence_top -or
        -not [bool]$Families.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$Motifs.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        [int]$Families.counts.selected_report_positions -ne $n -or
        [int]$Joint.counts.selected_report_positions -ne $n -or
        [int]$Motifs.counts.selected_report_positions -ne $n -or
        [int]$Families.counts.maximal_repeat_family_count -ne $fCount -or
        [int]$Joint.counts.maximal_repeat_family_count -ne $fCount -or
        [int]$Joint.counts.distinct_maximal_repeat_family_pair_count -ne $expectedPairCount -or
        $parentPairs.Count -ne $expectedPairCount -or
        $familySummary.Count -ne $fCount -or
        $windows.Count -ne $windowCount -or
        $Atlas.positions.Count -ne $n -or
        $SelectedAnchor.positions.Count -ne $n -or
        $Families.path -cne $Joint.path -or
        $Families.path -cne $Motifs.path -or
        $Families.path -cne $Atlas.path -or
        $Families.path -cne $SelectedAnchor.path -or
        [int]$Families.pair_index_in_pairwise_profile -ne [int]$Joint.pair_index_in_pairwise_profile -or
        [int]$Families.path_index_in_selected_pair_overview -ne [int]$Joint.path_index_in_selected_pair_overview -or
        [int]$Families.anchor_index_in_anchor_journeys -ne [int]$Joint.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Families.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Joint.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Families.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence triple support parents disagree on scope, completeness, selector or anchor.'
    }
    $recordAt = [string[]]::new($n)
    $classAt = [int[]]::new($n)
    for ($p = 1; $p -le $n; $p++) {
        $ap = $Atlas.positions[$p - 1]
        $sp = $SelectedAnchor.positions[$p - 1]
        if ([int]$ap.position -ne $p -or [int]$sp.position -ne $p -or
            $ap.record_id -cne $sp.record_id -or
            [string]::IsNullOrWhiteSpace([string]$ap.record_id)) {
            throw 'Code Sequence triple support original selected position/record identity disagrees.'
        }
        $recordAt[$p - 1] = [string]$ap.record_id
        $classAt[$p - 1] = [int]$ap.profile_class_index
    }

    $twoChoices = [object[]]::new($fCount)
    $optimalChoices = [object[]]::new($fCount)
    $familySupported = [bool[]]::new($fCount)
    $independentlySupported = 0
    $totalTwo = 0
    $totalOptimal = 0
    for ($fi = 1; $fi -le $fCount; $fi++) {
        $family = $familyRows[$fi - 1]
        $mi = [int]$family.ec054_complete_class_walk_motif_index
        if ([int]$family.family_index -ne $fi -or $mi -lt 1 -or
            $mi -gt $groups.Count) {
            throw 'Code Sequence triple support found a noncanonical family or motif index.'
        }
        $group = $groups[$mi - 1]
        $occ = @($family.all_observed_occurrences)
        $width = [int]$family.position_count_per_occurrence
        $m = $occ.Count
        if ($m -lt 2 -or $m -gt $n - 1 -or $width -lt 2 -or
            [int]$family.actual_observed_occurrence_count -ne $m -or
            [int]$group.occurrence_count -ne $m -or
            [int]$group.motif_index -ne $mi -or
            $group.window_indices.Count -ne $m -or
            $family.profile_class_index_walk.Count -ne $width -or
            ($group.profile_class_index_walk -join ':') -cne ($family.profile_class_index_walk -join ':') -or
            [int]$familySummary[$fi - 1].family_index -ne $fi -or
            [int]$familySummary[$fi - 1].ec054_complete_class_walk_motif_index -ne $mi) {
            throw 'Code Sequence triple support lost original motif/family occurrence membership.'
        }
        $occMasks = [int[]]::new($m)
        $priorStart = 0
        for ($oi = 0; $oi -lt $m; $oi++) {
            $o = $occ[$oi]
            $wi = [int]$o.ec043_direct_pair_window_index
            if ($wi -lt 1 -or $wi -gt $windowCount) {
                throw 'Code Sequence triple support received a nonexistent original EC-043 window.'
            }
            $w = $windows[$wi - 1]
            $start = [int]$o.from_position
            $end = [int]$o.to_position
            if ([int]$o.occurrence_index_in_family -ne $oi + 1 -or
                $start -le $priorStart -or $start -lt 1 -or $end -gt $n -or
                $end - $start + 1 -ne $width -or
                [int]$w.window_index -ne $wi -or
                [int]$w.motif_index -ne $mi -or
                [int]$w.from_position -ne $start -or [int]$w.to_position -ne $end -or
                [int]$group.window_indices[$oi] -ne $wi -or
                ($o.original_record_id_walk -join '|') -cne ($w.record_id_walk -join '|') -or
                ($o.original_ec052_adjacent_step_indices -join ':') -cne ($w.adjacent_step_indices -join ':') -or
                ($o.original_directed_edge_index_walk -join ':') -cne ($w.directed_edge_index_walk -join ':') -or
                ($o.original_ec043_adjacent_pair_index_walk -join ':') -cne ($w.ec043_adjacent_pair_index_walk -join ':') -or
                $o.original_record_id_walk.Count -ne $width) {
                throw 'Code Sequence triple support occurrence did not correspond to a real contiguous window.'
            }
            $mask = 0
            for ($p = $start; $p -le $end; $p++) {
                if ($o.original_record_id_walk[$p - $start] -cne $recordAt[$p - 1] -or
                    [int]$family.profile_class_index_walk[$p - $start] -ne $classAt[$p - 1]) {
                    throw 'Code Sequence triple support window changed original saved record/class.'
                }
                $mask = $mask -bor (1 -shl ($p - 1))
            }
            $occMasks[$oi] = $mask
            $priorStart = $start
        }
        $two = [System.Collections.Generic.List[object]]::new()
        for ($left = 0; $left -lt $m; $left++) {
            for ($right = $left + 1; $right -lt $m; $right++) {
                if (($occMasks[$left] -band $occMasks[$right]) -ne 0) { continue }
                $two.Add([ordered]@{
                    original_occurrence_indices_in_family = @(($left + 1), ($right + 1))
                    ec043_direct_pair_window_indices = @([int]$occ[$left].ec043_direct_pair_window_index, [int]$occ[$right].ec043_direct_pair_window_index)
                    position_mask = ($occMasks[$left] -bor $occMasks[$right])
                })
            }
        }
        $twoChoices[$fi - 1] = $two.ToArray()
        $totalTwo += $two.Count
        $max = [int]$family.maximum_strictly_disjoint_observed_occurrence_count
        $packs = @($family.all_maximum_strictly_disjoint_occurrence_packings)
        if ($max -lt 1 -or $max -gt $m -or
            [int]$family.maximum_strictly_disjoint_occurrence_packing_count -ne $packs.Count -or
            [int]$familySummary[$fi - 1].maximum_strictly_disjoint_occurrence_count -ne $max -or
            [int]$familySummary[$fi - 1].original_valid_two_occurrence_support_pair_count -ne $two.Count -or
            ($two.Count -gt 0) -ne ($max -ge 2) -or
            [bool]$family.has_at_least_two_strictly_disjoint_observed_occurrences -ne ($max -ge 2)) {
            throw 'Code Sequence triple support family two-window/maximum count disagrees with EC-056/057.'
        }
        $familySupported[$fi - 1] = $max -ge 2
        if ($max -ge 2) { $independentlySupported++ }
        $optimal = [System.Collections.Generic.List[object]]::new()
        for ($pi = 0; $pi -lt $packs.Count; $pi++) {
            $pack = $packs[$pi]
            $indices = @($pack.original_occurrence_indices_in_family)
            $used = 0
            $previous = 0
            $winIds = [System.Collections.Generic.List[int]]::new()
            foreach ($index in $indices) {
                $oi = [int]$index
                if ($oi -le $previous -or $oi -gt $m -or $oi -lt 1 -or
                    ($used -band $occMasks[$oi - 1]) -ne 0) {
                    throw 'Code Sequence triple support rejected overlapping/noncanonical EC-056 optimum.'
                }
                $used = $used -bor $occMasks[$oi - 1]
                $winIds.Add([int]$occ[$oi - 1].ec043_direct_pair_window_index)
                $previous = $oi
            }
            $coveredPositions = [System.Collections.Generic.List[int]]::new()
            $coveredIds = [System.Collections.Generic.List[string]]::new()
            for ($p = 1; $p -le $n; $p++) {
                if (($used -band (1 -shl ($p - 1))) -ne 0) {
                    $coveredPositions.Add($p)
                    $coveredIds.Add($recordAt[$p - 1])
                }
            }
            if ([int]$pack.packing_index_in_family -ne $pi + 1 -or
                $indices.Count -ne $max -or
                ($winIds.ToArray() -join ':') -cne ($pack.ec043_direct_pair_window_indices -join ':') -or
                ($coveredPositions.ToArray() -join ':') -cne ($pack.covered_caller_positions -join ':') -or
                ($coveredIds.ToArray() -join '|') -cne ($pack.original_record_ids_at_covered_positions -join '|')) {
                throw 'Code Sequence triple support found inconsistent EC-056 optimal packing provenance.'
            }
            $optimal.Add([ordered]@{
                packing_index_in_family = $pi + 1
                original_occurrence_indices_in_family = $indices
                ec043_direct_pair_window_indices = $winIds.ToArray()
                position_mask = $used
            })
        }
        $optimalChoices[$fi - 1] = $optimal.ToArray()
        $totalOptimal += $optimal.Count
    }
    if ($independentlySupported -ne [int]$Joint.counts.independently_supportable_family_count -or
        $totalTwo -ne [int]$Joint.counts.original_valid_two_occurrence_support_pairs_across_families -or
        $totalOptimal -ne [int]$Joint.counts.original_ec056_locally_optimal_packings_across_families) {
        throw 'Code Sequence triple support parent family-wide counts changed.'
    }

    # Reconcile *all* EC-057 pair decisions, even the pairs that never
    # participate in a viable triple; a compatibility graph alone is not
    # sufficient evidence for the new three-family conjunction.
    $pairJoint = [long[,]]::new($fCount, $fCount)
    $pairOptimal = [long[,]]::new($fCount, $fCount)
    $pairIx = 0
    $recountPairs = [long]0
    $recountOptimal = [long]0
    $supportedPairs = 0
    $optimalPairs = 0
    $locallyPossiblePairs = 0
    for ($a = 0; $a -lt $fCount; $a++) {
        for ($b = $a + 1; $b -lt $fCount; $b++) {
            $pairIx++
            $p = $parentPairs[$pairIx - 1]
            $both = $familySupported[$a] -and $familySupported[$b]
            $compatible = [long]0
            $optimalCompatible = [long]0
            foreach ($left in @($twoChoices[$a])) {
                foreach ($right in @($twoChoices[$b])) {
                    if (([int]$left.position_mask -band [int]$right.position_mask) -eq 0) { $compatible++ }
                }
            }
            if ($both) {
                foreach ($left in @($optimalChoices[$a])) {
                    foreach ($right in @($optimalChoices[$b])) {
                        if (([int]$left.position_mask -band [int]$right.position_mask) -eq 0) { $optimalCompatible++ }
                    }
                }
                $locallyPossiblePairs++
            }
            if ($compatible -gt 0) { $supportedPairs++ }
            if ($optimalCompatible -gt 0) { $optimalPairs++ }
            $pairJoint[$a,$b] = $compatible
            $pairOptimal[$a,$b] = $optimalCompatible
            $recountPairs += $compatible
            $recountOptimal += $optimalCompatible
            if ([int]$p.family_pair_index -ne $pairIx -or
                [int]$p.left_maximal_repeat_family_index -ne $a + 1 -or
                [int]$p.right_maximal_repeat_family_index -ne $b + 1 -or
                [int]$p.left_valid_two_occurrence_support_pair_count -ne @($twoChoices[$a]).Count -or
                [int]$p.right_valid_two_occurrence_support_pair_count -ne @($twoChoices[$b]).Count -or
                [bool]$p.both_families_separately_have_independent_repeat_support -ne $both -or
                [long]$p.actual_joint_four_occurrence_witness_combination_count -ne $compatible -or
                [bool]$p.two_distinct_families_can_be_independently_supported_together -ne ($compatible -gt 0) -or
                [long]$p.actual_joint_locally_optimal_packing_pair_count -ne $optimalCompatible -or
                [bool]$p.both_families_can_retain_their_separate_local_optima -ne ($optimalCompatible -gt 0) -or
                (($null -eq $p.first_original_joint_independent_witness) -ne ($compatible -eq 0)) -or
                (($null -eq $p.first_joint_locally_optimal_packing_witness) -ne ($optimalCompatible -eq 0))) {
                throw 'Code Sequence triple support did not reproduce exact EC-057 pairwise feasibility.'
            }
        }
    }
    if ($pairIx -ne $expectedPairCount -or
        $supportedPairs -ne [int]$Joint.counts.family_pairs_with_joint_independent_repeat_support -or
        $locallyPossiblePairs -ne [int]$Joint.counts.family_pairs_with_both_locally_independent_repeat_support -or
        $optimalPairs -ne [int]$Joint.counts.family_pairs_with_both_separate_local_maxima_jointly_compatible -or
        $recountPairs -ne [long]$Joint.counts.actual_joint_four_occurrence_witness_combinations_across_family_pairs -or
        $recountOptimal -ne [long]$Joint.counts.actual_joint_locally_optimal_packing_pair_combinations_across_family_pairs) {
        throw 'Code Sequence triple support EC-057 pair totals were not conserved.'
    }

    $triples = [System.Collections.Generic.List[object]]::new()
    $positionTriples = [object[]]::new($n)
    $positionAlways = [object[]]::new($n)
    for ($p = 0; $p -lt $n; $p++) {
        $positionTriples[$p] = [System.Collections.Generic.List[int]]::new()
        $positionAlways[$p] = [System.Collections.Generic.List[int]]::new()
    }
    $familyTriples = [object[]]::new($fCount)
    $familyOptimalTriples = [object[]]::new($fCount)
    for ($i = 0; $i -lt $fCount; $i++) {
        $familyTriples[$i] = [System.Collections.Generic.List[int]]::new()
        $familyOptimalTriples[$i] = [System.Collections.Generic.List[int]]::new()
    }
    $locallyIndependentTriples = 0
    $pairwiseCliques = 0
    $pairwiseOptimumCliques = 0
    $feasibleTriples = 0
    $locallyOptimalTriples = 0
    $totalSixWitnesses = [long]0
    $totalOptimalWitnesses = [long]0
    for ($a = 0; $a -lt $fCount; $a++) {
        for ($b = $a + 1; $b -lt $fCount; $b++) {
            for ($c = $b + 1; $c -lt $fCount; $c++) {
                $allLocal = $familySupported[$a] -and $familySupported[$b] -and $familySupported[$c]
                $allPairs = $pairJoint[$a,$b] -gt 0 -and
                    $pairJoint[$a,$c] -gt 0 -and $pairJoint[$b,$c] -gt 0
                $allPairOptima = $pairOptimal[$a,$b] -gt 0 -and
                    $pairOptimal[$a,$c] -gt 0 -and $pairOptimal[$b,$c] -gt 0
                if ($allLocal) { $locallyIndependentTriples++ }
                if ($allPairs) { $pairwiseCliques++ }
                if ($allPairOptima) { $pairwiseOptimumCliques++ }
                $actual = [long]0
                $locallyOptimal = [long]0
                $coverage = [long[]]::new($n)
                $first = $null
                $firstOptimum = $null
                # Six actual windows of width >=2 need at least 12 distinct
                # selected positions. This cardinality shortcut skips only
                # impossible work, never clips a real candidate or result.
                $minimumRequired = 2 * ([int]$familyRows[$a].position_count_per_occurrence +
                    [int]$familyRows[$b].position_count_per_occurrence +
                    [int]$familyRows[$c].position_count_per_occurrence)
                if ($allPairs -and $minimumRequired -le $n) {
                    foreach ($aa in @($twoChoices[$a])) {
                        foreach ($bb in @($twoChoices[$b])) {
                            if (([int]$aa.position_mask -band [int]$bb.position_mask) -ne 0) { continue }
                            $abMask = [int]$aa.position_mask -bor [int]$bb.position_mask
                            foreach ($cc in @($twoChoices[$c])) {
                                if (($abMask -band [int]$cc.position_mask) -ne 0) { continue }
                                $actual++
                                $mask = $abMask -bor [int]$cc.position_mask
                                if ($null -eq $first) {
                                    $first = New-CodeSequenceTripleOriginalWitness `
                                        -FamilyIndexes @(($a + 1), ($b + 1), ($c + 1)) `
                                        -Choices @($aa,$bb,$cc) -Families $familyRows -RecordIds $recordAt
                                }
                                for ($pos = 1; $pos -le $n; $pos++) {
                                    if (($mask -band (1 -shl ($pos - 1))) -ne 0) { $coverage[$pos - 1]++ }
                                }
                            }
                        }
                    }
                }
                if ($actual -gt 0 -and -not $allPairs) {
                    throw 'Code Sequence triple support invented a feasible triple absent from its original pairs.'
                }
                if ($allLocal -and $actual -gt 0) {
                    foreach ($aa in @($optimalChoices[$a])) {
                        foreach ($bb in @($optimalChoices[$b])) {
                            if (([int]$aa.position_mask -band [int]$bb.position_mask) -ne 0) { continue }
                            $abMask = [int]$aa.position_mask -bor [int]$bb.position_mask
                            foreach ($cc in @($optimalChoices[$c])) {
                                if (($abMask -band [int]$cc.position_mask) -ne 0) { continue }
                                $locallyOptimal++
                                if ($null -eq $firstOptimum) {
                                    $firstOptimum = New-CodeSequenceTripleOriginalWitness `
                                        -FamilyIndexes @(($a + 1), ($b + 1), ($c + 1)) `
                                        -Choices @($aa,$bb,$cc) -Families $familyRows `
                                        -RecordIds $recordAt -Optimal $true
                                }
                            }
                        }
                    }
                }
                if ($locallyOptimal -gt 0 -and (-not $allPairOptima -or $actual -eq 0)) {
                    throw 'Code Sequence triple support inferred an incompatible three-family local optimum.'
                }
                $status = if (-not $allLocal) {
                    'a_family_has_no_independent_two_occurrence_support'
                } elseif (-not $allPairs) {
                    'at_least_one_family_pair_cannot_jointly_support_independence'
                } elseif ($actual -eq 0) {
                    'every_family_pair_can_coexist_but_no_single_triple_witness_exists'
                } elseif ($locallyOptimal -eq 0) {
                    'all_three_families_can_coexist_but_their_local_optima_compete'
                } else {
                    'all_three_families_local_optima_can_coexist'
                }
                $ti = $triples.Count + 1
                if ($actual -gt 0) {
                    $feasibleTriples++
                    foreach ($ix in @($a, $b, $c)) { $familyTriples[$ix].Add($ti) }
                }
                if ($locallyOptimal -gt 0) {
                    $locallyOptimalTriples++
                    foreach ($ix in @($a, $b, $c)) { $familyOptimalTriples[$ix].Add($ti) }
                }
                $totalSixWitnesses += $actual
                $totalOptimalWitnesses += $locallyOptimal
                $positions = [System.Collections.Generic.List[object]]::new()
                for ($pos = 1; $pos -le $n; $pos++) {
                    $count = $coverage[$pos - 1]
                    if ($count -gt $actual) {
                        throw 'Code Sequence triple support position coverage exceeds real witnesses.'
                    }
                    $label = if ($count -eq 0) { 'never' } elseif ($count -eq $actual) {
                        'always'
                    } else { 'sometimes' }
                    if ($count -gt 0) { $positionTriples[$pos - 1].Add($ti) }
                    if ($count -gt 0 -and $count -eq $actual) { $positionAlways[$pos - 1].Add($ti) }
                    $positions.Add([ordered]@{
                        position = $pos
                        original_record_id = $recordAt[$pos - 1]
                        actual_six_window_witness_inclusion_count = $count
                        across_all_genuine_three_family_witnesses = $label
                    })
                }
                $triples.Add([ordered]@{
                    family_triple_index = $ti
                    ordered_maximal_repeat_family_indices = @(($a + 1), ($b + 1), ($c + 1))
                    ordered_ec054_complete_class_walk_motif_indices = @(
                        [int]$familyRows[$a].ec054_complete_class_walk_motif_index,
                        [int]$familyRows[$b].ec054_complete_class_walk_motif_index,
                        [int]$familyRows[$c].ec054_complete_class_walk_motif_index)
                    original_window_positions_minimum_for_two_occurrences_in_each_family = $minimumRequired
                    all_three_families_separately_have_independent_repeat_support = $allLocal
                    every_distinct_family_pair_can_jointly_support_independence = $allPairs
                    every_distinct_family_pair_can_retain_separate_local_optima = $allPairOptima
                    actual_joint_six_occurrence_witness_combination_count = $actual
                    three_distinct_families_can_be_independently_supported_together = ($actual -gt 0)
                    first_original_joint_six_occurrence_witness = $first
                    actual_joint_three_locally_optimal_packing_combination_count = $locallyOptimal
                    all_three_families_can_retain_their_separate_local_optima = ($locallyOptimal -gt 0)
                    first_original_joint_three_locally_optimal_packing_witness = $firstOptimum
                    compatibility_class = $status
                    position_coverage_across_all_genuine_three_family_witnesses = $positions.ToArray()
                })
            }
        }
    }
    if ($triples.Count -ne $expectedTripleCount -or
        $locallyOptimalTriples -gt $feasibleTriples -or
        $feasibleTriples -gt $pairwiseCliques -or
        $pairwiseCliques -gt $locallyIndependentTriples -or
        $pairwiseOptimumCliques -gt $pairwiseCliques) {
        throw 'Code Sequence triple support complete triple partition/feasibility hierarchy failed.'
    }
    # Max simultaneous supported family count is at most floor(N/4),
    # because each genuine distinct class-walk family needs >=2 disjoint
    # windows of >=2 positions. With N<=12 no fourth family can qualify.
    $maxTogether = if ($feasibleTriples -gt 0) { 3 } elseif ($supportedPairs -gt 0) {
        2
    } elseif ($independentlySupported -gt 0) { 1 } else { 0 }
    $maxOptTogether = if ($locallyOptimalTriples -gt 0) { 3 } elseif ($optimalPairs -gt 0) {
        2
    } elseif ($independentlySupported -gt 0) { 1 } else { 0 }
    if ($maxTogether -gt [math]::Floor($n / 4) -or $maxOptTogether -gt $maxTogether) {
        throw 'Code Sequence triple support exceeded the original caller position capacity.'
    }
    $maxSets = [System.Collections.Generic.List[object]]::new()
    $maxOptimalSets = [System.Collections.Generic.List[object]]::new()
    if ($maxTogether -eq 3 -or $maxOptTogether -eq 3) {
        foreach ($t in $triples) {
            if ($maxTogether -eq 3 -and $t.three_distinct_families_can_be_independently_supported_together) {
                $maxSets.Add(@($t.ordered_maximal_repeat_family_indices))
            }
            if ($maxOptTogether -eq 3 -and $t.all_three_families_can_retain_their_separate_local_optima) {
                $maxOptimalSets.Add(@($t.ordered_maximal_repeat_family_indices))
            }
        }
    }
    if ($maxTogether -eq 2 -or $maxOptTogether -eq 2) {
        foreach ($p in $parentPairs) {
            $pairFamilyIndices = @([int]$p.left_maximal_repeat_family_index,[int]$p.right_maximal_repeat_family_index)
            if ($maxTogether -eq 2 -and $p.two_distinct_families_can_be_independently_supported_together) {
                $maxSets.Add($pairFamilyIndices)
            }
            if ($maxOptTogether -eq 2 -and $p.both_families_can_retain_their_separate_local_optima) {
                $maxOptimalSets.Add($pairFamilyIndices)
            }
        }
    }
    if ($maxTogether -eq 1 -or $maxOptTogether -eq 1) {
        for ($fi = 0; $fi -lt $fCount; $fi++) {
            if ($familySupported[$fi]) {
                if ($maxTogether -eq 1) { $maxSets.Add(@(($fi + 1))) }
                if ($maxOptTogether -eq 1) { $maxOptimalSets.Add(@(($fi + 1))) }
            }
        }
    }
    $familyCoverage = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $fCount; $fi++) {
        $familyCoverage.Add([ordered]@{
            family_index = $fi + 1
            ec054_complete_class_walk_motif_index = [int]$familyRows[$fi].ec054_complete_class_walk_motif_index
            has_independently_disjoint_original_two_occurrence_support = [bool]$familySupported[$fi]
            genuine_three_family_support_triple_indices = $familyTriples[$fi].ToArray()
            locally_optimal_three_family_support_triple_indices = $familyOptimalTriples[$fi].ToArray()
        })
    }
    $positionCoverage = [System.Collections.Generic.List[object]]::new()
    $positionsWithTripleSupport = 0
    for ($p = 1; $p -le $n; $p++) {
        if ($positionTriples[$p - 1].Count -gt 0) { $positionsWithTripleSupport++ }
        $positionCoverage.Add([ordered]@{
            position = $p
            original_record_id = $recordAt[$p - 1]
            original_saved_profile_class_index = $classAt[$p - 1]
            genuine_three_family_support_triple_indices_covering_this_position = $positionTriples[$p - 1].ToArray()
            genuine_three_family_support_triple_indices_covering_this_position_in_every_witness = $positionAlways[$p - 1].ToArray()
        })
    }
    return [ordered]@{
        scope = 'global_three_distinct_family_original_six_window_support_vs_pairwise_compatibility_and_local_optima'
        pair_index_in_pairwise_profile = [int]$Families.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Families.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Families.anchor_index_in_anchor_journeys
        path = [string]$Families.path
        exact_saved_quote_anchor = $Families.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            maximal_repeat_family_count = $fCount
            independently_supportable_family_count = $independentlySupported
            distinct_maximal_repeat_family_triple_count = $triples.Count
            family_triples_with_all_three_independently_supported = $locallyIndependentTriples
            family_triples_where_every_pair_is_jointsupport_compatible = $pairwiseCliques
            family_triples_where_every_pair_local_maxima_are_compatible = $pairwiseOptimumCliques
            family_triples_with_actual_three_family_joint_support = $feasibleTriples
            family_triples_with_compatible_three_local_maxima = $locallyOptimalTriples
            pairwise_compatible_family_triples_without_actual_three_family_support = $pairwiseCliques - $feasibleTriples
            feasible_family_triples_with_competing_three_local_maxima = $feasibleTriples - $locallyOptimalTriples
            actual_six_occurrence_joint_witness_combinations_across_triples = $totalSixWitnesses
            actual_three_locally_optimal_packing_combinations_across_triples = $totalOptimalWitnesses
            globally_maximum_simultaneously_independently_supported_distinct_family_count = $maxTogether
            all_globally_maximum_simultaneously_supported_family_sets_count = $maxSets.Count
            globally_maximum_simultaneously_locally_optimal_distinct_family_count = $maxOptTogether
            all_globally_maximum_simultaneously_locally_optimal_family_sets_count = $maxOptimalSets.Count
            caller_positions_with_actual_three_family_joint_support = $positionsWithTripleSupport
        }
        ordered_cross_family_support_triples = $triples.ToArray()
        all_globally_maximum_simultaneously_supported_family_index_sets = $maxSets.ToArray()
        all_globally_maximum_simultaneously_locally_optimal_family_index_sets = $maxOptimalSets.ToArray()
        ordered_family_triple_support_summaries = $familyCoverage.ToArray()
        selected_caller_position_triple_support_coverage = $positionCoverage.ToArray()
        independent_of_sequence_top = $true
        complete_ec054_real_windows_ec056_family_packings_and_ec057_original_pair_counts_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'All 3-family decisions enumerate only distinct EC-056 complete observed saved-profile class-walk motifs. Each of three families must contribute two REAL internally nonoverlapping EC-043 windows; six windows must be mutually position-disjoint, not merely feasible in each of the three pair comparisons. Separate local-optimum compatibility requires one original EC-056 maximum packing per family with no shared selected position. N=2..12 permits at most three different simultaneously independently supported families, so the global maximum family-count registry is exhaustive within this bounded caller selection. Caller order is not attested chronology; histogram equality is NOT proof of the same original Finding, historical defect repetition, actual severity, fix, regression or risk. No sixth selector, extra saved/source/Git/network read, new saved content, quote/prose disclosure or write.'
    }
}

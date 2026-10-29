#requires -Version 7.0
<#
    EC-081: four ordered, distinct ORIGINAL intermediary reports in a
    hypothetical six-report block p,r,s,t,u,q. No inferred real chronology.

    Read only the already checked public EC-072 original minimal support
    bases. For an unsupported subset T of t middle identities (t=0..3),
    ALL t! orderings of T are still unsupported by monotonicity. Every
    one-bit restoration in frontier(M+p+T) is therefore first at stage t+1.
    Multiply by the exact number of unplaced ordered intermediary identities
    and the original outside-block factorial weight. For |T|=4, all 4!
    permutations are still unsupported exactly when S(M+p+T) is false:
    S(M+p+T+q) then determines first-by-q. This avoids N! permutations,
    ordered-middle quadruple enumeration and reading original evidence again.
#>

function Get-CodeSequenceRetentionPairQuadrupleInterveningProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [object] $PairPrecedence,
        [object] $PairAdjacency,
        [object] $PairSingleIntervening,
        [object] $PairDoubleIntervening,
        [object] $PairTripleIntervening,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        $null -eq $PairAdjacency -or $null -eq $PairSingleIntervening -or
        $null -eq $PairDoubleIntervening -or $null -eq $PairTripleIntervening -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable -or
        -not [bool]$RetentionCube.ec072_exact_minimal_original_retained_bases_reconciled -or
        -not [bool]$RetentionCube.all_original_budget_edge_conservation_identities_verified -or
        -not [bool]$RetentionOrder.all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported -or
        -not [bool]$FixedRank.all_fixed_position_rank_cases_partition_into_before_by_after_or_never -or
        -not [bool]$FixedRank.all_rank_wide_margins_reconcile_independent_ec074_complete_permutations -or
        -not [bool]$PairPrecedence.every_ordered_report_pair_has_six_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairPrecedence.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairPrecedence.all_six_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairAdjacency.each_directed_immediate_report_pair_has_five_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairAdjacency.every_immediate_neighbor_rank_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairAdjacency.every_adjacency_scenario_is_a_subset_of_original_ec076_precedence -or
        -not [bool]$PairAdjacency.all_five_adjacent_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairSingleIntervening.each_directed_pair_single_intervening_case_has_six_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairSingleIntervening.every_original_middle_position_attribution_sums_exactly_to_first_by_middle -or
        -not [bool]$PairSingleIntervening.all_six_one_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairDoubleIntervening.every_directed_pair_double_intervening_case_has_seven_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairDoubleIntervening.both_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairDoubleIntervening.all_seven_double_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairTripleIntervening.every_directed_pair_triple_intervening_case_has_eight_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairTripleIntervening.all_three_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairTripleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairTripleIntervening.every_four_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairTripleIntervening.adjacent_one_two_and_three_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairTripleIntervening.all_eight_triple_intervening_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence four-intervening report requires completely checked EC-072..080 original saved-evidence parents.'
    }

    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $adjacentUniverse = [long]$factorial[$N - 1]
    $precedenceUniverse = [long]($permutations / 2)
    $oneMiddleUniverse = [long]0
    $twoMiddleUniverse = [long]0
    $threeMiddleUniverse = [long]0
    $fourMiddleUniverse = [long]0
    if ($N -ge 3) { $oneMiddleUniverse = [long]($N - 2) * [long]$factorial[$N - 2] }
    if ($N -ge 4) { $twoMiddleUniverse = [long]($N - 3) * [long]$factorial[$N - 2] }
    if ($N -ge 5) { $threeMiddleUniverse = [long]($N - 4) * [long]$factorial[$N - 2] }
    if ($N -ge 6) { $fourMiddleUniverse = [long]($N - 5) * [long]$factorial[$N - 2] }
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $neighborRows = [object[]]$PairAdjacency.directed_immediate_original_report_pair_scenarios
    $singleRows = [object[]]$PairSingleIntervening.directed_original_report_pair_single_intervening_scenarios
    $doubleRows = [object[]]$PairDoubleIntervening.directed_original_report_pair_double_intervening_scenarios
    $tripleRows = [object[]]$PairTripleIntervening.directed_original_report_pair_triple_intervening_scenarios
    $directed = $N * ($N - 1)
    $eligibleDirected = if ($N -ge 6) { $directed } else { 0 }

    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or $parentRows.Count -ne $directed -or
        $neighborRows.Count -ne $directed -or
        $singleRows.Count -ne $(if ($N -lt 3) { 0 } else { $directed }) -or
        $doubleRows.Count -ne $(if ($N -lt 4) { 0 } else { $directed }) -or
        $tripleRows.Count -ne $(if ($N -lt 5) { 0 } else { $directed }) -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [int]$PairAdjacency.original_positions_in_adjacency_universe -ne $N -or
        [int]$PairSingleIntervening.original_positions_in_single_intervening_universe -ne $N -or
        [int]$PairDoubleIntervening.original_positions_in_two_intervening_universe -ne $N -or
        [int]$PairTripleIntervening.original_positions_in_three_intervening_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairAdjacency.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSingleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairDoubleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairTripleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedenceUniverse -or
        [long]$PairAdjacency.full_permutations_per_directed_immediate_report_pair -ne $adjacentUniverse -or
        [long]$PairSingleIntervening.full_permutations_per_directed_pair_with_one_intervening_original_report -ne $oneMiddleUniverse -or
        [long]$PairDoubleIntervening.full_permutations_per_directed_pair_with_two_intervening_original_reports -ne $twoMiddleUniverse -or
        [long]$PairTripleIntervening.full_permutations_per_directed_pair_with_three_intervening_original_reports -ne $threeMiddleUniverse -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence four-intervening report received inconsistent ORIGINAL permutation universes.'
    }
    $sumDistances = $adjacentUniverse + $oneMiddleUniverse + $twoMiddleUniverse + $threeMiddleUniverse + $fourMiddleUniverse
    if ($sumDistances -gt $precedenceUniverse -or
        ($N -le 6 -and $sumDistances -ne $precedenceUniverse)) {
        throw 'Code Sequence zero-through-four-intervening distances cannot partition original directed precedence.'
    }

    # Reconstruct and authenticate monotone ORIGINAL support ONLY from the
    # checked public EC-072 inclusion-minimal retained witness bases.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence four-intervening report received empty, duplicate or out-of-range original basis.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence four-intervening report received nonminimal nested support bases.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $budgetCounts = [int[]]::new($N + 1)
    for ($mask = 0; $mask -lt $size; $mask++) {
        if ($mask -gt 0) { $pop[$mask] = $pop[$mask -shr 1] + ($mask -band 1) }
        if (-not $hasEvidence[$mask]) {
            for ($bitIndex = 0; $bitIndex -lt $N; $bitIndex++) {
                $bit = 1 -shl $bitIndex
                if (($mask -band $bit) -ne 0 -and $hasEvidence[$mask -bxor $bit]) {
                    $hasEvidence[$mask] = $true
                    break
                }
            }
        }
        if ($hasEvidence[$mask]) { $budgetCounts[$pop[$mask]]++ }
    }
    $hasFullSupport = [bool]$hasEvidence[$full]
    if ($hasEvidence[0] -or
        $hasFullSupport -ne ([long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0) -or
        $hasFullSupport -ne [bool]$RetentionOrder.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$FixedRank.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairPrecedence.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairAdjacency.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSingleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairDoubleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairTripleIntervening.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence four-intervening report changed ORIGINAL full/empty saved support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            [int]$budgetRows[$k].subsets_preserving_original_witness_support -ne $budgetCounts[$k]) {
            throw 'Code Sequence four-intervening report disagrees with EC-073 original retention budgets.'
        }
    }

    # frontier[mask] stores exact ORIGINAL bit positions which restore a
    # still-unsupported mask in ONE next report, without a second evidence
    # read or a synthetic support witness.
    $frontier = [int[]]::new($size)
    # Map each single ORIGINAL identity bit to its zero-based caller slot,
    # so a nonempty support frontier is visited only at its SET bits.
    $positionForBit = [int[]]::new($size)
    for ($position = 0; $position -lt $N; $position++) {
        $positionForBit[1 -shl $position] = $position
    }
    if ($N -ge 6 -and $hasFullSupport) {
        for ($mask = 0; $mask -lt $size; $mask++) {
            if ($hasEvidence[$mask]) { continue }
            $remaining = $full -bxor $mask
            for ($bitIndex = 0; $bitIndex -lt $N; $bitIndex++) {
                $bit = 1 -shl $bitIndex
                if (($remaining -band $bit) -ne 0 -and $hasEvidence[$mask -bor $bit]) {
                    $frontier[$mask] = $frontier[$mask] -bor $bit
                }
            }
        }
    }

    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(9)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $pairIndex = 0
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence four-intervening report changed ORIGINAL EC-075 position identity.'
        }
        if ($N -lt 6) { continue }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $stages = [long[]]::new(9)
            $byMiddlePosition = [object[]]::new(4)
            for ($middleSlot = 0; $middleSlot -lt 4; $middleSlot++) {
                $byMiddlePosition[$middleSlot] = [long[]]::new($N)
            }

            if ($hasFullSupport) {
                $m = $other
                while ($true) {
                    $k = $pop[$m]
                    $eligible = $other -bxor $m
                    $c = $pop[$eligible]
                    if ($c -ge 4) {
                        $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 6]
                        $ordersOfFour = [long]$c * [long]($c - 1) * [long]($c - 2) * [long]($c - 3)
                        $countThisPrefix = $ordersOfFour * $weight
                        $local = [long[]]::new(7)
                        if ($hasEvidence[$m]) {
                            $local[0] = $countThisPrefix
                        }
                        else {
                            $withP = $m -bor $pBit
                            if ($hasEvidence[$withP]) {
                                $local[1] = $countThisPrefix
                            }
                            else {
                                # For any unordered T of size t<=3 whose
                                # mask remains unsupported, ALL t! orders
                                # remain unsupported. Append one frontier
                                # bit x and permute the other 3-t slots.
                                # The t=4 case has 4! unsupporting middle
                                # orders; q is next and restores iff S(T+q).
                                $sub = $eligible
                                while ($true) {
                                    $t = $pop[$sub]
                                    if ($t -le 4) {
                                        $prefix = $withP -bor $sub
                                        if (-not $hasEvidence[$prefix]) {
                                            if ($t -eq 4) {
                                                if ($hasEvidence[$prefix -bor $qBit]) {
                                                    $local[6] += [long]24 * $weight
                                                }
                                            }
                                            else {
                                                $stillEligible = $eligible -bxor $sub
                                                $restoringBits = $frontier[$prefix] -band $stillEligible
                                                if ($restoringBits -ne 0) {
                                                    $multiplicity = switch ($t) {
                                                        0 { [long]($c - 1) * ($c - 2) * ($c - 3) }
                                                        1 { [long]($c - 2) * ($c - 3) }
                                                        2 { [long]2 * ($c - 3) }
                                                        3 { [long]6 }
                                                    }
                                                    $valuePerIdentity = [long]$multiplicity * $weight
                                                    $local[2 + $t] += [long]$pop[$restoringBits] * $valuePerIdentity
                                                    $bitsToCredit = $restoringBits
                                                    while ($bitsToCredit -ne 0) {
                                                        $oneIdentityBit = $bitsToCredit -band (-$bitsToCredit)
                                                        $byMiddlePosition[$t][$positionForBit[$oneIdentityBit]] += $valuePerIdentity
                                                        $bitsToCredit = $bitsToCredit -bxor $oneIdentityBit
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if ($sub -eq 0) { break }
                                    $sub = ($sub - 1) -band $eligible
                                }
                            }
                        }
                        $localFirstThroughQ = [long]0
                        for ($stage = 0; $stage -le 6; $stage++) {
                            $stages[$stage] += $local[$stage]
                            $localFirstThroughQ += $local[$stage]
                        }
                        if ($localFirstThroughQ -gt $countThisPrefix) {
                            throw 'Code Sequence four-intervening report overcounted a fixed ORIGINAL prefix.'
                        }
                        $beforePRank[$p * $N + $k] += $local[0]
                        $byPRank[$p * $N + $k] += $local[1]
                        $beforeQRank[$q * $N + $k + 5] += (
                            $local[0] + $local[1] + $local[2] + $local[3] + $local[4] + $local[5])
                        $byQRank[$q * $N + $k + 5] += $local[6]
                    }
                    if ($m -eq 0) { break }
                    $m = ($m - 1) -band $other
                }
                $stages[7] = $fourMiddleUniverse -
                    ($stages[0] + $stages[1] + $stages[2] + $stages[3] +
                     $stages[4] + $stages[5] + $stages[6])
            }
            else {
                $stages[8] = $fourMiddleUniverse
            }

            $stageSum = [long]0
            foreach ($value in $stages) {
                if ($value -lt 0) { throw 'Code Sequence four-intervening report produced a negative FIRST stage.' }
                $stageSum += $value
            }
            if ($stageSum -ne $fourMiddleUniverse) {
                throw 'Code Sequence four-intervening report failed its nine-way conditional order partition.'
            }
            for ($t = 0; $t -lt 4; $t++) {
                $identitySum = [long]0
                for ($r = 0; $r -lt $N; $r++) {
                    $v = [long]$byMiddlePosition[$t][$r]
                    if ($v -lt 0 -or (($r -eq $p -or $r -eq $q) -and $v -ne 0)) {
                        throw 'Code Sequence four-intervening report assigned support to an invalid ORIGINAL middle identity.'
                    }
                    $identitySum += $v
                }
                if ($identitySum -ne $stages[$t + 2]) {
                    throw 'Code Sequence four-intervening report lost exact middle-position attribution.'
                }
            }

            $parent = $parentRows[$pairIndex]
            $neighbor = $neighborRows[$pairIndex]
            $single = $singleRows[$pairIndex]
            $double = $doubleRows[$pairIndex]
            $triple = $tripleRows[$pairIndex]
            $pairIndex++
            foreach ($entry in @($parent, $neighbor, $single, $double, $triple)) {
                if ([int]$entry.first_original_caller_position -ne ($p + 1) -or
                    [int]$entry.second_original_caller_position -ne ($q + 1) -or
                    [int]$entry.first_original_position_bit -ne $pBit -or
                    [int]$entry.second_original_position_bit -ne $qBit) {
                    throw 'Code Sequence four-intervening report changed an EC-076..080 ORIGINAL directed pair identity.'
                }
            }
            if ([long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedenceUniverse -or
                [long]$neighbor.exact_full_permutations_with_first_report_immediately_before_second -ne $adjacentUniverse -or
                [long]$single.exact_full_permutations_with_exactly_one_original_report_between_pair -ne $oneMiddleUniverse -or
                [long]$double.exact_full_permutations_with_exactly_two_original_reports_between_pair -ne $twoMiddleUniverse -or
                [long]$triple.exact_full_permutations_with_exactly_three_original_reports_between_pair -ne $threeMiddleUniverse) {
                throw 'Code Sequence four-intervening report changed a preceding p/q gap universe.'
            }

            # Each of distances 1..5 occurs on a disjoint set of full
            # ORIGINAL orders. Map all four middle FIRST stages only to
            # the EC-076 strictly-between bucket. At N6 these exhaust
            # original p-before-q precedence, category by category.
            $differences = [long[]]@(
                [long]$parent.full_permutations_first_restoring_before_first_report -
                    ([long]$neighbor.full_permutations_first_restoring_before_first_report +
                     [long]$single.full_permutations_first_restoring_before_first_report +
                     [long]$double.full_permutations_first_restoring_before_first_report +
                     [long]$triple.full_permutations_first_restoring_before_first_report + $stages[0]),
                [long]$parent.full_permutations_first_restored_by_first_report -
                    ([long]$neighbor.full_permutations_first_restored_by_first_report +
                     [long]$single.full_permutations_first_restored_by_first_report +
                     [long]$double.full_permutations_first_restored_by_first_report +
                     [long]$triple.full_permutations_first_restored_by_first_report + $stages[1]),
                [long]$parent.full_permutations_first_restoring_strictly_between_reports -
                    ([long]$single.full_permutations_first_restored_by_single_intervening_original_report +
                     [long]$double.full_permutations_first_restored_by_first_intervening_original_report +
                     [long]$double.full_permutations_first_restored_by_second_intervening_original_report +
                     [long]$triple.full_permutations_first_restored_by_first_intervening_original_report +
                     [long]$triple.full_permutations_first_restored_by_second_intervening_original_report +
                     [long]$triple.full_permutations_first_restored_by_third_intervening_original_report +
                     $stages[2] + $stages[3] + $stages[4] + $stages[5]),
                [long]$parent.full_permutations_first_restored_by_second_report -
                    ([long]$neighbor.full_permutations_first_restored_by_second_report +
                     [long]$single.full_permutations_first_restored_by_second_report +
                     [long]$double.full_permutations_first_restored_by_second_report +
                     [long]$triple.full_permutations_first_restored_by_second_report + $stages[6]),
                [long]$parent.full_permutations_first_restoring_after_second_report -
                    ([long]$neighbor.full_permutations_first_restoring_after_second_report +
                     [long]$single.full_permutations_first_restoring_after_second_report +
                     [long]$double.full_permutations_first_restoring_after_second_report +
                     [long]$triple.full_permutations_first_restoring_after_second_report + $stages[7]),
                [long]$parent.full_permutations_never_restoring_saved_evidence -
                    ([long]$neighbor.full_permutations_never_restoring_saved_evidence +
                     [long]$single.full_permutations_never_restoring_saved_evidence +
                     [long]$double.full_permutations_never_restoring_saved_evidence +
                     [long]$triple.full_permutations_never_restoring_saved_evidence + $stages[8])
            )
            foreach ($difference in $differences) {
                if ($difference -lt 0 -or ($N -eq 6 -and $difference -ne 0)) {
                    throw 'Code Sequence zero-through-four ORIGINAL intermediaries contradict EC-076 six-way precedence.'
                }
            }

            $gcd = [long[]]::new(6)
            for ($si = 0; $si -lt 6; $si++) {
                $gcd[$si] = Get-CodeSequenceRetentionOrderGcd -A $stages[$si + 1] -B $fourMiddleUniverse
            }
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                number_of_ordered_distinct_original_middle_identity_quadruples = ($N - 2) * ($N - 3) * ($N - 4) * ($N - 5)
                exact_full_permutations_with_exactly_four_original_reports_between_pair = $fourMiddleUniverse
                full_permutations_first_restoring_before_first_report = $stages[0]
                full_permutations_first_restored_by_first_report = $stages[1]
                full_permutations_first_restored_by_first_intervening_original_report = $stages[2]
                full_permutations_first_restored_by_second_intervening_original_report = $stages[3]
                full_permutations_first_restored_by_third_intervening_original_report = $stages[4]
                full_permutations_first_restored_by_fourth_intervening_original_report = $stages[5]
                full_permutations_first_restored_by_second_report = $stages[6]
                full_permutations_first_restoring_after_second_report = $stages[7]
                full_permutations_never_restoring_saved_evidence = $stages[8]
                first_restored_by_first_intervening_original_caller_position_counts = $byMiddlePosition[0]
                first_restored_by_second_intervening_original_caller_position_counts = $byMiddlePosition[1]
                first_restored_by_third_intervening_original_caller_position_counts = $byMiddlePosition[2]
                first_restored_by_fourth_intervening_original_caller_position_counts = $byMiddlePosition[3]
                exact_reduced_by_first_report_fraction_numerator = [long]($stages[1] / $gcd[0])
                exact_reduced_by_first_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[0])
                exact_reduced_by_first_intervening_report_fraction_numerator = [long]($stages[2] / $gcd[1])
                exact_reduced_by_first_intervening_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[1])
                exact_reduced_by_second_intervening_report_fraction_numerator = [long]($stages[3] / $gcd[2])
                exact_reduced_by_second_intervening_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[2])
                exact_reduced_by_third_intervening_report_fraction_numerator = [long]($stages[4] / $gcd[3])
                exact_reduced_by_third_intervening_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[3])
                exact_reduced_by_fourth_intervening_report_fraction_numerator = [long]($stages[5] / $gcd[4])
                exact_reduced_by_fourth_intervening_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[4])
                exact_reduced_by_second_report_fraction_numerator = [long]($stages[6] / $gcd[5])
                exact_reduced_by_second_report_fraction_denominator = [long]($fourMiddleUniverse / $gcd[5])
            })
            for ($i = 0; $i -lt 9; $i++) { $totals[$i] += $stages[$i] }
        }
    }
    if ($scenarios.Count -ne $eligibleDirected -or $pairIndex -ne $eligibleDirected) {
        throw 'Code Sequence four-intervening report miscounted eligible directed ORIGINAL endpoints.'
    }

    # Independent EC-075 fixed-rank identity: p fixed at j has precisely
    # one q at j+5 when j<=N-5. Conversely q fixed at j has precisely
    # one p at j-5 for j>=6; neither margin gets a combinatorial factor.
    $rankChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentUniverse) {
                throw 'Code Sequence four-intervening report changed the independent EC-075 fixed-rank universe.'
            }
            $expectedPBefore = [long]0; $expectedPBy = [long]0
            $expectedQBefore = [long]0; $expectedQBy = [long]0
            if ($j -le $N - 5) {
                $expectedPBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -ge 6) {
                $expectedQBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedQBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedPBefore -or
                $byPRank[$idx] -ne $expectedPBy -or
                $beforeQRank[$idx] -ne $expectedQBefore -or
                $byQRank[$idx] -ne $expectedQBy) {
                throw 'Code Sequence four-intervening report failed independent EC-075 offset-five margins.'
            }
        }
        $rankChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            number_of_original_rank_cases_reconciled = $N
        })
    }

    # EC-074 is independent of p/q selection: a full original order has
    # N-5 contiguous six-report blocks. A first-support rank step u
    # contributes one to each block containing that exact position.
    $expected = [long[]]::new(9)
    $totalFirst = [long]0
    for ($step = 1; $step -le $N; $step++) {
        if ([int]$stepRows[$step].number_of_first_original_reports_retained -ne $step) {
            throw 'Code Sequence four-intervening report changed the EC-074 first-retained report step.'
        }
        $first = [long]$stepRows[$step].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence four-intervening report received negative EC-074 support mass.' }
        $expected[0] += [long][Math]::Max(0, $N - $step - 5) * $first
        if ($step -le $N - 5) { $expected[1] += $first }
        if ($step -ge 2 -and $step -le $N - 4) { $expected[2] += $first }
        if ($step -ge 3 -and $step -le $N - 3) { $expected[3] += $first }
        if ($step -ge 4 -and $step -le $N - 2) { $expected[4] += $first }
        if ($step -ge 5 -and $step -le $N - 1) { $expected[5] += $first }
        if ($step -ge 6) { $expected[6] += $first }
        $expected[7] += [long][Math]::Max(0, $step - 6) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence four-intervening report disagrees with EC-074 original supported whole orders.'
    }
    $totalIncidences = [long][Math]::Max(0, $N - 5) * $permutations
    if (-not $hasFullSupport) { $expected[8] = $totalIncidences }
    for ($i = 0; $i -lt 9; $i++) {
        if ($totals[$i] -ne $expected[$i]) {
            throw 'Code Sequence four-intervening report failed the independent EC-074 nine-stage incidence.'
        }
    }
    $actualMass = [long]0
    foreach ($value in $totals) { $actualMass += $value }
    if ($actualMass -ne $totalIncidences) {
        throw 'Code Sequence four-intervening report did not conserve contiguous six-report occurrences.'
    }

    return [ordered]@{
        original_positions_in_four_intervening_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_pair_with_four_intervening_original_reports = $fourMiddleUniverse
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_original_report_pair_quadruple_intervening_scenarios = $scenarios.ToArray()
        original_position_five_rank_offset_margins_against_ec075 = $rankChecks.ToArray()
        independent_ec074_first_support_step_quadruple_intervening_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_first_intervening_original_report = $totals[2]
            full_permutations_first_restored_by_second_intervening_original_report = $totals[3]
            full_permutations_first_restored_by_third_intervening_original_report = $totals[4]
            full_permutations_first_restored_by_fourth_intervening_original_report = $totals[5]
            full_permutations_first_restored_by_second_report = $totals[6]
            full_permutations_first_restoring_after_second_report = $totals[7]
            full_permutations_never_restoring_saved_evidence = $totals[8]
            expected_total_quadruple_intervening_pair_occurrences_across_all_orderings = $totalIncidences
        }
        every_directed_pair_quadruple_intervening_case_has_nine_disjoint_exhaustive_first_support_categories = $true
        all_four_middle_original_identity_attributions_sum_to_their_exact_first_support_stages = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_five_rank_offset_margin_matches_independent_ec075_fixed_rank = $true
        adjacent_one_two_three_and_four_middle_cases_are_disjoint_subsets_of_ec076_precedence = $true
        all_nine_quadruple_intervening_first_support_categories_match_independent_ec074_step_counts = $true
        original_n2_n3_n4_n5_have_no_eligible_quadruple_intervening_pair = ($N -lt 6)
        hypothetical_four_intervening_gap_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairQuadrupleIntervening {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency,
        [object] $RetentionPairSingleIntervening,
        [object] $RetentionPairDoubleIntervening,
        [object] $RetentionPairTripleIntervening
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or $null -eq $RetentionPairAdjacency -or
        $null -eq $RetentionPairSingleIntervening -or
        $null -eq $RetentionPairDoubleIntervening -or
        $null -eq $RetentionPairTripleIntervening -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        $RetentionPairAdjacency.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair' -or
        $RetentionPairSingleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_single_intervening_original_report_between_ordered_pair' -or
        $RetentionPairDoubleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_two_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairTripleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_three_ordered_intervening_original_reports_between_ordered_pair' -or
        -not [bool]$RetentionPairTripleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairTripleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairDoubleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairDoubleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairSingleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSingleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization) {
        throw 'Code Sequence pair quadruple-intervening requires the unchanged EC-072..080 original target registry.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    $gCubes = [object[]]$RetentionPivotality.genuine_global_threshold_retention_coverage
    $fCubes = [object[]]$RetentionPivotality.frozen_global_threshold_retention_coverage
    $familyCubes = [object[]]$RetentionPivotality.individual_original_family_retention_coverage
    $gBases = [object[]]$SupportBasisDuality.genuine_global_threshold_retained_support_bases
    $fBases = [object[]]$SupportBasisDuality.frozen_global_threshold_retained_support_bases
    $familyBases = [object[]]$SupportBasisDuality.individual_original_family_retained_support_bases
    $gOrders = [object[]]$RetentionOrderAttribution.genuine_global_threshold_first_support_permutations
    $fOrders = [object[]]$RetentionOrderAttribution.frozen_global_threshold_first_support_permutations
    $familyOrders = [object[]]$RetentionOrderAttribution.individual_original_family_first_support_permutations
    $gRank = [object[]]$RetentionRankConditioning.genuine_global_threshold_fixed_rank_conditioning
    $fRank = [object[]]$RetentionRankConditioning.frozen_global_threshold_fixed_rank_conditioning
    $familyRank = [object[]]$RetentionRankConditioning.individual_original_family_fixed_rank_conditioning
    $gPrecedence = [object[]]$RetentionPairPrecedence.genuine_global_threshold_pair_precedence
    $fPrecedence = [object[]]$RetentionPairPrecedence.frozen_global_threshold_pair_precedence
    $familyPrecedence = [object[]]$RetentionPairPrecedence.individual_original_family_pair_precedence
    $gAdjacency = [object[]]$RetentionPairAdjacency.genuine_global_threshold_pair_adjacency
    $fAdjacency = [object[]]$RetentionPairAdjacency.frozen_global_threshold_pair_adjacency
    $familyAdjacency = [object[]]$RetentionPairAdjacency.individual_original_family_pair_adjacency
    $gSingle = [object[]]$RetentionPairSingleIntervening.genuine_global_threshold_pair_single_intervening
    $fSingle = [object[]]$RetentionPairSingleIntervening.frozen_global_threshold_pair_single_intervening
    $familySingle = [object[]]$RetentionPairSingleIntervening.individual_original_family_pair_single_intervening
    $gDouble = [object[]]$RetentionPairDoubleIntervening.genuine_global_threshold_pair_double_intervening
    $fDouble = [object[]]$RetentionPairDoubleIntervening.frozen_global_threshold_pair_double_intervening
    $familyDouble = [object[]]$RetentionPairDoubleIntervening.individual_original_family_pair_double_intervening
    $gTriple = [object[]]$RetentionPairTripleIntervening.genuine_global_threshold_pair_triple_intervening
    $fTriple = [object[]]$RetentionPairTripleIntervening.frozen_global_threshold_pair_triple_intervening
    $familyTriple = [object[]]$RetentionPairTripleIntervening.individual_original_family_pair_triple_intervening
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairAdjacency.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairSingleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairDoubleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairTripleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairAdjacency.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSingleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairDoubleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairTripleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $gCubes.Count -ne $gAdjacency.Count -or $gCubes.Count -ne $gSingle.Count -or
        $gCubes.Count -ne $gDouble.Count -or $gCubes.Count -ne $gTriple.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $fCubes.Count -ne $fAdjacency.Count -or $fCubes.Count -ne $fSingle.Count -or
        $fCubes.Count -ne $fDouble.Count -or $fCubes.Count -ne $fTriple.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount -or
        $familyAdjacency.Count -ne $familyCount -or $familySingle.Count -ne $familyCount -or
        $familyDouble.Count -ne $familyCount -or $familyTriple.Count -ne $familyCount) {
        throw 'Code Sequence pair quadruple-intervening changed original genuine/frozen/family target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $neighbors = $gAdjacency
        $singles = $gSingle; $doubles = $gDouble; $triples = $gTriple; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $neighbors = $fAdjacency
            $singles = $fSingle; $doubles = $fDouble; $triples = $fTriple; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]
            $neighbor = $neighbors[$i]; $single = $singles[$i]
            $double = $doubles[$i]; $triple = $triples[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $threshold -ne [int]$precedence.original_global_family_capacity_at_least -or
                $threshold -ne [int]$neighbor.original_global_family_capacity_at_least -or
                $threshold -ne [int]$single.original_global_family_capacity_at_least -or
                $threshold -ne [int]$double.original_global_family_capacity_at_least -or
                $threshold -ne [int]$triple.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$neighbor.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$single.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$double.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$triple.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair quadruple-intervening changed original genuine/frozen capacity thresholds.'
            }
            $projection = Get-CodeSequenceRetentionPairQuadrupleInterveningProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence `
                -PairAdjacency $neighbor.exact_first_support_pair_adjacency `
                -PairSingleIntervening $single.exact_first_support_pair_single_intervening `
                -PairDoubleIntervening $double.exact_first_support_pair_double_intervening `
                -PairTripleIntervening $triple.exact_first_support_pair_triple_intervening -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_quadruple_intervening = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]; $neighbor = $familyAdjacency[$fi]
        $single = $familySingle[$fi]; $double = $familyDouble[$fi]
        $triple = $familyTriple[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$neighbor.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$single.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$double.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$triple.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair quadruple-intervening changed an individual ORIGINAL family ID.'
        }
        $g = Get-CodeSequenceRetentionPairQuadrupleInterveningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.genuine_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.genuine_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.genuine_original_first_support_pair_double_intervening `
            -PairTripleIntervening $triple.genuine_original_first_support_pair_triple_intervening -N $n
        $f = Get-CodeSequenceRetentionPairQuadrupleInterveningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.frozen_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.frozen_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.frozen_original_first_support_pair_double_intervening `
            -PairTripleIntervening $triple.frozen_original_first_support_pair_triple_intervening -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_quadruple_intervening = $g
            frozen_original_first_support_pair_quadruple_intervening = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    $fourMiddleUniverse = [long]0
    if ($n -ge 6) { $fourMiddleUniverse = [long]($n - 5) * [long]$factorial[$n - 2] }
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_four_ordered_intervening_original_reports_between_ordered_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_original_pair_with_four_intervening_reports = $fourMiddleUniverse
            directed_original_report_quadruple_intervening_scenarios_per_target = $(if ($n -lt 6) { 0 } else { $n * ($n - 1) })
            original_four_intervening_pair_occurrences_across_all_permutations_per_target = [long]([Math]::Max(0, $n - 5)) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_quadruple_intervening = $gResult.ToArray()
        frozen_global_threshold_pair_quadruple_intervening = $fResult.ToArray()
        individual_original_family_pair_quadruple_intervening = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        original_n2_n3_n4_n5_have_no_eligible_quadruple_intervening_pair = ($n -lt 6)
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_four_intervening_gap_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_four_intervening_gap_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

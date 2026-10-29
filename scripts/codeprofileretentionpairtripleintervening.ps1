#requires -Version 7.0
<#
    EC-080: FIRST original saved-witness support inside hypothetical ordered
    five-report blocks p,r,s,t,q, where the three middle identities are
    DISTINCT ORIGINAL caller positions and do not assert saved chronology.

    Verified public EC-072 minimal ORIGINAL retained support bases alone
    reconstruct the monotone mask support and one-bit restoration frontiers.
    Exact prefix weights k! * (N-k-5)! count each complete compatible order
    without enumerating N! permutations. Unordered middle identity pairs
    conserve both r/s directions exactly. Count stages by first-supported
    report, preserving each middle ORIGINAL identity independently.
    Reconcile EC-073 budgets, EC-074 first-step incidences, EC-075 fixed
    ranks, and disjoint EC-076..079 pair-distance precedence contributions.
#>

function Get-CodeSequenceRetentionPairTripleInterveningProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [object] $PairPrecedence,
        [object] $PairAdjacency,
        [object] $PairSingleIntervening,
        [object] $PairDoubleIntervening,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        $null -eq $PairAdjacency -or $null -eq $PairSingleIntervening -or
        $null -eq $PairDoubleIntervening -or
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
        -not [bool]$PairSingleIntervening.every_two_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairSingleIntervening.all_six_one_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairDoubleIntervening.every_directed_pair_double_intervening_case_has_seven_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairDoubleIntervening.both_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairDoubleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairDoubleIntervening.every_three_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairDoubleIntervening.adjacent_one_middle_and_two_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairDoubleIntervening.all_seven_double_intervening_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence three-intervening report requires fully checked EC-072..079 original saved-evidence projections.'
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
    if ($N -ge 3) { $oneMiddleUniverse = [long]($N - 2) * [long]$factorial[$N - 2] }
    if ($N -ge 4) { $twoMiddleUniverse = [long]($N - 3) * [long]$factorial[$N - 2] }
    if ($N -ge 5) { $threeMiddleUniverse = [long]($N - 4) * [long]$factorial[$N - 2] }
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $neighborRows = [object[]]$PairAdjacency.directed_immediate_original_report_pair_scenarios
    $singleRows = [object[]]$PairSingleIntervening.directed_original_report_pair_single_intervening_scenarios
    $doubleRows = [object[]]$PairDoubleIntervening.directed_original_report_pair_double_intervening_scenarios
    $directed = $N * ($N - 1)
    $eligibleDirected = if ($N -ge 5) { $directed } else { 0 }

    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or $parentRows.Count -ne $directed -or
        $neighborRows.Count -ne $directed -or
        $singleRows.Count -ne $(if ($N -eq 2) { 0 } else { $directed }) -or
        $doubleRows.Count -ne $(if ($N -lt 4) { 0 } else { $directed }) -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [int]$PairAdjacency.original_positions_in_adjacency_universe -ne $N -or
        [int]$PairSingleIntervening.original_positions_in_single_intervening_universe -ne $N -or
        [int]$PairDoubleIntervening.original_positions_in_two_intervening_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairAdjacency.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSingleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairDoubleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedenceUniverse -or
        [long]$PairAdjacency.full_permutations_per_directed_immediate_report_pair -ne $adjacentUniverse -or
        [long]$PairSingleIntervening.full_permutations_per_directed_pair_with_one_intervening_original_report -ne $oneMiddleUniverse -or
        [long]$PairDoubleIntervening.full_permutations_per_directed_pair_with_two_intervening_original_reports -ne $twoMiddleUniverse -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence three-intervening report received inconsistent original report permutation universes.'
    }
    if ($adjacentUniverse + $oneMiddleUniverse + $twoMiddleUniverse + $threeMiddleUniverse -gt $precedenceUniverse -or
        ($N -le 5 -and
            $adjacentUniverse + $oneMiddleUniverse + $twoMiddleUniverse + $threeMiddleUniverse -ne $precedenceUniverse)) {
        throw 'Code Sequence zero-to-three-intervening scenarios cannot partition original report precedence.'
    }

    # Rebuild S(mask) ONLY from checked EC-072 inclusion-minimal ORIGINAL
    # retained support bases. Check all EC-073 cardinality budget counts.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence three-intervening report received empty, invalid or duplicate original basis.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence three-intervening report received nested/nonminimal original support bases.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $budgetSupportCounts = [int[]]::new($N + 1)
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
        if ($hasEvidence[$mask]) { $budgetSupportCounts[$pop[$mask]]++ }
    }
    $hasFullSupport = [bool]$hasEvidence[$full]
    if ($hasEvidence[0] -or
        $hasFullSupport -ne ([long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0) -or
        $hasFullSupport -ne [bool]$RetentionOrder.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$FixedRank.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairPrecedence.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairAdjacency.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSingleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairDoubleIntervening.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence three-intervening report changed ORIGINAL empty/full support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            [int]$budgetRows[$k].subsets_preserving_original_witness_support -ne $budgetSupportCounts[$k]) {
            throw 'Code Sequence three-intervening report disagrees with original EC-073 cardinality budgets.'
        }
    }

    # The one-add frontier of a still-unsupported mask is a bitset of
    # ORIGINAL report identities that FIRST restore evidence at that step.
    $frontier = [int[]]::new($size)
    if ($N -ge 5 -and $hasFullSupport) {
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

    # Four N*N fixed-rank margin matrices: p before/by and q before/by.
    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(8)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $pairIndex = 0
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence three-intervening report changed EC-075 ORIGINAL position identity.'
        }
        if ($N -lt 5) { continue }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $beforeP = [long]0
            $byP = [long]0
            $byFirst = [long]0
            $bySecond = [long]0
            $byThird = [long]0
            $byQ = [long]0
            $byFirstPosition = [long[]]::new($N)
            $bySecondPosition = [long[]]::new($N)
            $byThirdPosition = [long[]]::new($N)

            if ($hasFullSupport) {
                $m = $other
                while ($true) {
                    $k = $pop[$m]
                    $eligibleMiddle = $other -bxor $m
                    $choices = $pop[$eligibleMiddle]
                    if ($choices -ge 3) {
                        # For each exact ORIGINAL prefix mask M, every
                        # permutation(M),p,r,s,t,q,permutation(rest) has
                        # k!*(N-k-5)! full-order multiplicity.
                        $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 5]
                        $orderedMiddleTriples = [long]$choices * [long]($choices - 1) * [long]($choices - 2)
                        $withP = $m -bor $pBit
                        $atBeforeP = [long]0
                        $atByP = [long]0
                        $atByFirst = [long]0
                        $atBySecond = [long]0
                        $atByThird = [long]0
                        $atByQ = [long]0

                        if ($hasEvidence[$m]) {
                            $atBeforeP = $orderedMiddleTriples * $weight
                        }
                        elseif ($hasEvidence[$withP]) {
                            $atByP = $orderedMiddleTriples * $weight
                        }
                        else {
                            # Count first-by-r from ORIGINAL one-add support
                            # bits; each possible r leads to (c-1)(c-2)
                            # ordered remaining s,t identities.
                            $firstBits = $frontier[$withP] -band $eligibleMiddle
                            $firstContribution = [long]($choices - 1) * [long]($choices - 2) * $weight
                            $atByFirst = [long]$pop[$firstBits] * $firstContribution
                            if ($firstBits -ne 0) {
                                for ($r = 0; $r -lt $N; $r++) {
                                    $rBit = 1 -shl $r
                                    if (($firstBits -band $rBit) -ne 0) {
                                        $byFirstPosition[$r] += $firstContribution
                                    }
                                }
                            }

                            # Process each UNORDERED r/s identity pair once.
                            # If M+p+r+s has support, either r->s or s->r
                            # can be first supported at its second middle,
                            # depending on the earlier one-add frontier.
                            # If it has NO support, both ordered prefixes
                            # remain unsupported; every valid t candidate
                            # contributes exactly TWO ordered r/s choices.
                            # Thus the third middle t and later q use
                            # precise factor 2 without replaying both
                            # directions or iterating all complete orders.
                            for ($r = 0; $r -lt $N; $r++) {
                                $rBit = 1 -shl $r
                                if (($eligibleMiddle -band $rBit) -eq 0) { continue }
                                $withFirst = $withP -bor $rBit
                                for ($s = $r + 1; $s -lt $N; $s++) {
                                    $sBit = 1 -shl $s
                                    if (($eligibleMiddle -band $sBit) -eq 0) { continue }
                                    $withSecond = $withFirst -bor $sBit
                                    $thirdChoices = $eligibleMiddle -bxor ($rBit -bor $sBit)
                                    if ($hasEvidence[$withSecond]) {
                                        $secondContribution = [long]($choices - 2) * $weight
                                        if (-not $hasEvidence[$withFirst]) {
                                            $atBySecond += $secondContribution
                                            $bySecondPosition[$s] += $secondContribution
                                        }
                                        if (-not $hasEvidence[$withP -bor $sBit]) {
                                            $atBySecond += $secondContribution
                                            $bySecondPosition[$r] += $secondContribution
                                        }
                                        continue
                                    }
                                    # Since neither two-middle prefix is
                                    # supported, frontier pair+t FIRST
                                    # supports at ORIGINAL t for BOTH r/s
                                    # orders, with exact original identity.
                                    $thirdFirstSupport = $frontier[$withSecond] -band $thirdChoices
                                    $thirdCount = $pop[$thirdFirstSupport]
                                    $atByThird += [long]2 * [long]$thirdCount * $weight
                                    if ($thirdCount -gt 0) {
                                        for ($t = 0; $t -lt $N; $t++) {
                                            $tBit = 1 -shl $t
                                            if (($thirdFirstSupport -band $tBit) -ne 0) {
                                                $byThirdPosition[$t] += [long]2 * $weight
                                            }
                                        }
                                    }
                                    # q follows THIRD ORIGINAL t, never r/s.
                                    # Exclude precisely the t bits that
                                    # already restored before q. A supported
                                    # pair+q means all remaining t restore
                                    # by q; otherwise use pair+q's one-add
                                    # frontier, still with both r/s orders.
                                    $stillUnsupported = $thirdChoices -bxor $thirdFirstSupport
                                    if ($stillUnsupported -ne 0) {
                                        $withSecondQ = $withSecond -bor $qBit
                                        if ($hasEvidence[$withSecondQ]) {
                                            $atByQ += [long]2 * [long]$pop[$stillUnsupported] * $weight
                                        }
                                        else {
                                            $qPivots = $frontier[$withSecondQ] -band $stillUnsupported
                                            $atByQ += [long]2 * [long]$pop[$qPivots] * $weight
                                        }
                                    }
                                }
                            }
                        }

                        $beforeP += $atBeforeP
                        $byP += $atByP
                        $byFirst += $atByFirst
                        $bySecond += $atBySecond
                        $byThird += $atByThird
                        $byQ += $atByQ
                        $beforePRank[$p * $N + $k] += $atBeforeP
                        $byPRank[$p * $N + $k] += $atByP
                        $beforeQRank[$q * $N + $k + 4] += (
                            $atBeforeP + $atByP + $atByFirst + $atBySecond + $atByThird)
                        $byQRank[$q * $N + $k + 4] += $atByQ
                    }
                    if ($m -eq 0) { break }
                    $m = ($m - 1) -band $other
                }
            }
            $afterQ = [long]0
            $never = [long]0
            if ($hasFullSupport) {
                $afterQ = $threeMiddleUniverse - $beforeP - $byP - $byFirst - $bySecond - $byThird - $byQ
            }
            else {
                $never = $threeMiddleUniverse
            }

            $firstTotal = [long]0
            $secondTotal = [long]0
            $thirdTotal = [long]0
            for ($i = 0; $i -lt $N; $i++) {
                $firstTotal += $byFirstPosition[$i]
                $secondTotal += $bySecondPosition[$i]
                $thirdTotal += $byThirdPosition[$i]
                if (($i -eq $p -or $i -eq $q) -and
                    ($byFirstPosition[$i] -ne 0 -or
                     $bySecondPosition[$i] -ne 0 -or
                     $byThirdPosition[$i] -ne 0)) {
                    throw 'Code Sequence three-intervening report attributed first support to a middle endpoint.'
                }
            }
            if ($beforeP -lt 0 -or $byP -lt 0 -or $byFirst -lt 0 -or
                $bySecond -lt 0 -or $byThird -lt 0 -or $byQ -lt 0 -or
                $afterQ -lt 0 -or $never -lt 0 -or
                $firstTotal -ne $byFirst -or $secondTotal -ne $bySecond -or
                $thirdTotal -ne $byThird -or
                $beforeP + $byP + $byFirst + $bySecond + $byThird + $byQ + $afterQ + $never -ne $threeMiddleUniverse) {
                throw 'Code Sequence three-intervening report violated its eight-stage partition or ORIGINAL middle identities.'
            }

            $parent = $parentRows[$pairIndex]
            $neighbor = $neighborRows[$pairIndex]
            $single = $singleRows[$pairIndex]
            $double = $doubleRows[$pairIndex]
            $pairIndex++
            foreach ($entry in @($parent, $neighbor, $single, $double)) {
                if ([int]$entry.first_original_caller_position -ne ($p + 1) -or
                    [int]$entry.second_original_caller_position -ne ($q + 1) -or
                    [int]$entry.first_original_position_bit -ne $pBit -or
                    [int]$entry.second_original_position_bit -ne $qBit) {
                    throw 'Code Sequence three-intervening report changed an EC-076..079 directed ORIGINAL report identity/order.'
                }
            }
            if ([long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedenceUniverse -or
                [long]$neighbor.exact_full_permutations_with_first_report_immediately_before_second -ne $adjacentUniverse -or
                [long]$single.exact_full_permutations_with_exactly_one_original_report_between_pair -ne $oneMiddleUniverse -or
                [long]$double.exact_full_permutations_with_exactly_two_original_reports_between_pair -ne $twoMiddleUniverse) {
                throw 'Code Sequence three-intervening report changed prior original p/q universes.'
            }

            # Distances 1,2,3,4 are nonoverlapping subsets of the
            # EC-076 directed p-before-q scenarios. At N=5 they
            # exhaust every such ordering, category by category.
            $subsetDiffs = [long[]]@(
                [long]$parent.full_permutations_first_restoring_before_first_report -
                    ([long]$neighbor.full_permutations_first_restoring_before_first_report +
                     [long]$single.full_permutations_first_restoring_before_first_report +
                     [long]$double.full_permutations_first_restoring_before_first_report + $beforeP),
                [long]$parent.full_permutations_first_restored_by_first_report -
                    ([long]$neighbor.full_permutations_first_restored_by_first_report +
                     [long]$single.full_permutations_first_restored_by_first_report +
                     [long]$double.full_permutations_first_restored_by_first_report + $byP),
                [long]$parent.full_permutations_first_restoring_strictly_between_reports -
                    ([long]$single.full_permutations_first_restored_by_single_intervening_original_report +
                     [long]$double.full_permutations_first_restored_by_first_intervening_original_report +
                     [long]$double.full_permutations_first_restored_by_second_intervening_original_report +
                     $byFirst + $bySecond + $byThird),
                [long]$parent.full_permutations_first_restored_by_second_report -
                    ([long]$neighbor.full_permutations_first_restored_by_second_report +
                     [long]$single.full_permutations_first_restored_by_second_report +
                     [long]$double.full_permutations_first_restored_by_second_report + $byQ),
                [long]$parent.full_permutations_first_restoring_after_second_report -
                    ([long]$neighbor.full_permutations_first_restoring_after_second_report +
                     [long]$single.full_permutations_first_restoring_after_second_report +
                     [long]$double.full_permutations_first_restoring_after_second_report + $afterQ),
                [long]$parent.full_permutations_never_restoring_saved_evidence -
                    ([long]$neighbor.full_permutations_never_restoring_saved_evidence +
                     [long]$single.full_permutations_never_restoring_saved_evidence +
                     [long]$double.full_permutations_never_restoring_saved_evidence + $never)
            )
            foreach ($diff in $subsetDiffs) {
                if ($diff -lt 0 -or ($N -eq 5 -and $diff -ne 0)) {
                    throw 'Code Sequence original p/q zero-to-three-middle stages contradict EC-076 pair precedence.'
                }
            }

            $gcdP = Get-CodeSequenceRetentionOrderGcd -A $byP -B $threeMiddleUniverse
            $gcdR = Get-CodeSequenceRetentionOrderGcd -A $byFirst -B $threeMiddleUniverse
            $gcdS = Get-CodeSequenceRetentionOrderGcd -A $bySecond -B $threeMiddleUniverse
            $gcdT = Get-CodeSequenceRetentionOrderGcd -A $byThird -B $threeMiddleUniverse
            $gcdQ = Get-CodeSequenceRetentionOrderGcd -A $byQ -B $threeMiddleUniverse
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                number_of_ordered_distinct_original_middle_identity_triples = ($N - 2) * ($N - 3) * ($N - 4)
                exact_full_permutations_with_exactly_three_original_reports_between_pair = $threeMiddleUniverse
                full_permutations_first_restoring_before_first_report = $beforeP
                full_permutations_first_restored_by_first_report = $byP
                full_permutations_first_restored_by_first_intervening_original_report = $byFirst
                full_permutations_first_restored_by_second_intervening_original_report = $bySecond
                full_permutations_first_restored_by_third_intervening_original_report = $byThird
                full_permutations_first_restored_by_second_report = $byQ
                full_permutations_first_restoring_after_second_report = $afterQ
                full_permutations_never_restoring_saved_evidence = $never
                first_restored_by_first_intervening_original_caller_position_counts = $byFirstPosition
                first_restored_by_second_intervening_original_caller_position_counts = $bySecondPosition
                first_restored_by_third_intervening_original_caller_position_counts = $byThirdPosition
                exact_reduced_by_first_report_fraction_numerator = [long]($byP / $gcdP)
                exact_reduced_by_first_report_fraction_denominator = [long]($threeMiddleUniverse / $gcdP)
                exact_reduced_by_first_intervening_report_fraction_numerator = [long]($byFirst / $gcdR)
                exact_reduced_by_first_intervening_report_fraction_denominator = [long]($threeMiddleUniverse / $gcdR)
                exact_reduced_by_second_intervening_report_fraction_numerator = [long]($bySecond / $gcdS)
                exact_reduced_by_second_intervening_report_fraction_denominator = [long]($threeMiddleUniverse / $gcdS)
                exact_reduced_by_third_intervening_report_fraction_numerator = [long]($byThird / $gcdT)
                exact_reduced_by_third_intervening_report_fraction_denominator = [long]($threeMiddleUniverse / $gcdT)
                exact_reduced_by_second_report_fraction_numerator = [long]($byQ / $gcdQ)
                exact_reduced_by_second_report_fraction_denominator = [long]($threeMiddleUniverse / $gcdQ)
            })
            $totals[0] += $beforeP
            $totals[1] += $byP
            $totals[2] += $byFirst
            $totals[3] += $bySecond
            $totals[4] += $byThird
            $totals[5] += $byQ
            $totals[6] += $afterQ
            $totals[7] += $never
        }
    }
    if ($scenarios.Count -ne $eligibleDirected -or $pairIndex -ne $eligibleDirected) {
        throw 'Code Sequence three-intervening report miscounted directed ORIGINAL p/q identities.'
    }

    # EC-075 gives an INDEPENDENT answer at fixed rank: each full order
    # with p at position j<=N-4 identifies exactly one q at j+4. The
    # converse holds for q at j>=5. No extra scaling or bit relabeling.
    $rankChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentUniverse) {
                throw 'Code Sequence three-intervening report received inconsistent EC-075 original fixed rank.'
            }
            $expectedPBefore = [long]0
            $expectedPBy = [long]0
            $expectedQBefore = [long]0
            $expectedQBy = [long]0
            if ($j -le $N - 4) {
                $expectedPBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -ge 5) {
                $expectedQBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedQBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedPBefore -or
                $byPRank[$idx] -ne $expectedPBy -or
                $beforeQRank[$idx] -ne $expectedQBefore -or
                $byQRank[$idx] -ne $expectedQBy) {
                throw 'Code Sequence three-intervening report failed independent EC-075 offset-four exact rank margins.'
            }
        }
        $rankChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            number_of_original_rank_cases_reconciled = $N
        })
    }

    # For each complete ORIGINAL ordering there are N-4 distinct
    # contiguous p,r,s,t,q blocks. Independent EC-074 FIRST(step) means
    # that block FIRST categories have these eight exact coefficients.
    $expected = [long[]]::new(8)
    $totalFirst = [long]0
    for ($step = 1; $step -le $N; $step++) {
        if ([int]$stepRows[$step].number_of_first_original_reports_retained -ne $step) {
            throw 'Code Sequence three-intervening report changed an EC-074 FIRST step identity.'
        }
        $first = [long]$stepRows[$step].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) {
            throw 'Code Sequence three-intervening report received negative EC-074 FIRST support mass.'
        }
        $expected[0] += [long][Math]::Max(0, $N - $step - 4) * $first
        if ($step -le $N - 4) { $expected[1] += $first }
        if ($step -ge 2 -and $step -le $N - 3) { $expected[2] += $first }
        if ($step -ge 3 -and $step -le $N - 2) { $expected[3] += $first }
        if ($step -ge 4 -and $step -le $N - 1) { $expected[4] += $first }
        if ($step -ge 5) { $expected[5] += $first }
        $expected[6] += [long][Math]::Max(0, $step - 5) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence three-intervening report disagrees with supported EC-074 full orders.'
    }
    $totalIncidences = [long]([Math]::Max(0, $N - 4)) * $permutations
    if (-not $hasFullSupport) { $expected[7] = $totalIncidences }
    for ($i = 0; $i -lt 8; $i++) {
        if ($totals[$i] -ne $expected[$i]) {
            throw 'Code Sequence three-intervening report failed independent EC-074 eight-stage FIRST incidence.'
        }
    }
    $partitionMass = [long]0
    foreach ($value in $totals) { $partitionMass += $value }
    if ($partitionMass -ne $totalIncidences) {
        throw 'Code Sequence three-intervening report lost genuine ORIGINAL five-position block incidences.'
    }
    return [ordered]@{
        original_positions_in_three_intervening_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_pair_with_three_intervening_original_reports = $threeMiddleUniverse
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_original_report_pair_triple_intervening_scenarios = $scenarios.ToArray()
        original_position_four_rank_offset_margins_against_ec075 = $rankChecks.ToArray()
        independent_ec074_first_support_step_triple_intervening_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_first_intervening_original_report = $totals[2]
            full_permutations_first_restored_by_second_intervening_original_report = $totals[3]
            full_permutations_first_restored_by_third_intervening_original_report = $totals[4]
            full_permutations_first_restored_by_second_report = $totals[5]
            full_permutations_first_restoring_after_second_report = $totals[6]
            full_permutations_never_restoring_saved_evidence = $totals[7]
            expected_total_triple_intervening_pair_occurrences_across_all_orderings = $totalIncidences
        }
        every_directed_pair_triple_intervening_case_has_eight_disjoint_exhaustive_first_support_categories = $true
        all_three_middle_original_identity_attributions_sum_to_their_exact_first_support_stages = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_four_rank_offset_margin_matches_independent_ec075_fixed_rank = $true
        adjacent_one_two_and_three_middle_cases_are_disjoint_subsets_of_ec076_precedence = $true
        all_eight_triple_intervening_first_support_categories_match_independent_ec074_step_counts = $true
        original_n2_n3_n4_have_no_eligible_triple_intervening_pair = ($N -lt 5)
        hypothetical_three_intervening_gap_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairTripleIntervening {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency,
        [object] $RetentionPairSingleIntervening,
        [object] $RetentionPairDoubleIntervening
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or $null -eq $RetentionPairAdjacency -or
        $null -eq $RetentionPairSingleIntervening -or
        $null -eq $RetentionPairDoubleIntervening -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        $RetentionPairAdjacency.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair' -or
        $RetentionPairSingleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_single_intervening_original_report_between_ordered_pair' -or
        $RetentionPairDoubleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_two_ordered_intervening_original_reports_between_ordered_pair' -or
        -not [bool]$RetentionPairDoubleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairDoubleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairSingleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSingleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization) {
        throw 'Code Sequence pair triple-intervening requires the unchanged EC-072..079 original target registry.'
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
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairAdjacency.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairSingleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairDoubleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairAdjacency.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSingleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairDoubleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $gCubes.Count -ne $gAdjacency.Count -or $gCubes.Count -ne $gSingle.Count -or
        $gCubes.Count -ne $gDouble.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $fCubes.Count -ne $fAdjacency.Count -or $fCubes.Count -ne $fSingle.Count -or
        $fCubes.Count -ne $fDouble.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount -or
        $familyAdjacency.Count -ne $familyCount -or $familySingle.Count -ne $familyCount -or
        $familyDouble.Count -ne $familyCount) {
        throw 'Code Sequence pair triple-intervening changed original genuine/frozen/family target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $neighbors = $gAdjacency
        $singles = $gSingle; $doubles = $gDouble; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $neighbors = $fAdjacency
            $singles = $fSingle; $doubles = $fDouble; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]
            $neighbor = $neighbors[$i]; $single = $singles[$i]
            $double = $doubles[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $threshold -ne [int]$precedence.original_global_family_capacity_at_least -or
                $threshold -ne [int]$neighbor.original_global_family_capacity_at_least -or
                $threshold -ne [int]$single.original_global_family_capacity_at_least -or
                $threshold -ne [int]$double.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$neighbor.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$single.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$double.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair triple-intervening changed original genuine/frozen capacity thresholds.'
            }
            $projection = Get-CodeSequenceRetentionPairTripleInterveningProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence `
                -PairAdjacency $neighbor.exact_first_support_pair_adjacency `
                -PairSingleIntervening $single.exact_first_support_pair_single_intervening `
                -PairDoubleIntervening $double.exact_first_support_pair_double_intervening -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_triple_intervening = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]; $neighbor = $familyAdjacency[$fi]
        $single = $familySingle[$fi]; $double = $familyDouble[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$neighbor.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$single.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$double.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair triple-intervening changed an individual ORIGINAL family ID.'
        }
        $g = Get-CodeSequenceRetentionPairTripleInterveningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.genuine_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.genuine_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.genuine_original_first_support_pair_double_intervening -N $n
        $f = Get-CodeSequenceRetentionPairTripleInterveningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.frozen_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.frozen_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.frozen_original_first_support_pair_double_intervening -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_triple_intervening = $g
            frozen_original_first_support_pair_triple_intervening = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    $threeMiddleUniverse = [long]0
    if ($n -ge 5) { $threeMiddleUniverse = [long]($n - 4) * [long]$factorial[$n - 2] }
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_three_ordered_intervening_original_reports_between_ordered_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_original_pair_with_three_intervening_reports = $threeMiddleUniverse
            directed_original_report_triple_intervening_scenarios_per_target = $(if ($n -lt 5) { 0 } else { $n * ($n - 1) })
            original_three_intervening_pair_occurrences_across_all_permutations_per_target = [long]([Math]::Max(0, $n - 4)) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_triple_intervening = $gResult.ToArray()
        frozen_global_threshold_pair_triple_intervening = $fResult.ToArray()
        individual_original_family_pair_triple_intervening = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        original_n2_n3_n4_have_no_eligible_triple_intervening_pair = ($n -lt 5)
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_three_intervening_gap_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_three_intervening_gap_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

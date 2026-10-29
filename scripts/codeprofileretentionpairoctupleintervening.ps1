#requires -Version 7.0
<#
    EC-085: EIGHT distinct ordered ORIGINAL intermediaries in a hypothetical
    contiguous ten-report block p,r,s,t,u,v,w,x,y,q (not arrival history).

    Exact support-first attribution using public verified EC-072 minimal REAL
    original basis masks. Re-index the EC-084 middle-subset/frontier sum by
    A = M union T: all ways to divide A into an outside prefix M and ordered
    middle prefix T collapse to a! * (N-a-3)! per restoring original bit,
    for each eligible middle slot. First-by-q has a! * (N-a-2)!, and before/by
    p uses k! * (N-k-2)!. This conserves the same complete orders without
    enumerating N! permutations, ordered octuples, or 3^N M/T submasks.
#>

function Get-CodeSequenceRetentionPairOctupleInterveningProjection {
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
        [object] $PairQuadrupleIntervening,
        [object] $PairQuintupleIntervening,
        [object] $PairSextupleIntervening,
        [object] $PairSeptupleIntervening,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        $null -eq $PairAdjacency -or $null -eq $PairSingleIntervening -or
        $null -eq $PairDoubleIntervening -or $null -eq $PairTripleIntervening -or
        $null -eq $PairQuadrupleIntervening -or $null -eq $PairQuintupleIntervening -or
        $null -eq $PairSextupleIntervening -or
        $null -eq $PairSeptupleIntervening -or
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
        -not [bool]$PairTripleIntervening.all_eight_triple_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairQuadrupleIntervening.every_directed_pair_quadruple_intervening_case_has_nine_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairQuadrupleIntervening.all_four_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairQuadrupleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairQuadrupleIntervening.every_five_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairQuadrupleIntervening.adjacent_one_two_three_and_four_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairQuadrupleIntervening.all_nine_quadruple_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairQuintupleIntervening.every_directed_pair_quintuple_intervening_case_has_ten_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairQuintupleIntervening.all_five_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairQuintupleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairQuintupleIntervening.every_six_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairQuintupleIntervening.adjacent_one_two_three_four_and_five_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairQuintupleIntervening.all_ten_quintuple_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairSextupleIntervening.every_directed_pair_sextuple_intervening_case_has_eleven_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairSextupleIntervening.all_six_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairSextupleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairSextupleIntervening.every_seven_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairSextupleIntervening.adjacent_one_two_three_four_five_and_six_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairSextupleIntervening.all_eleven_sextuple_intervening_first_support_categories_match_independent_ec074_step_counts -or
        -not [bool]$PairSeptupleIntervening.every_directed_pair_septuple_intervening_case_has_twelve_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairSeptupleIntervening.all_seven_middle_original_identity_attributions_sum_to_their_exact_first_support_stages -or
        -not [bool]$PairSeptupleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairSeptupleIntervening.every_eight_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairSeptupleIntervening.adjacent_one_two_three_four_five_six_and_seven_middle_cases_are_disjoint_subsets_of_ec076_precedence -or
        -not [bool]$PairSeptupleIntervening.all_twelve_septuple_intervening_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence eight-intervening report requires completely checked EC-072..084 original saved-evidence parents.'
    }

    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $adjacentUniverse = [long]$factorial[$N - 1]
    $precedenceUniverse = [long]($permutations / 2)
    $gapUniverses = [long[]]::new(9)
    $gapUniverses[0] = $adjacentUniverse
    for ($g = 1; $g -le 8; $g++) {
        if ($N -ge ($g + 2)) {
            $gapUniverses[$g] = [long]($N - $g - 1) * [long]$factorial[$N - 2]
        }
    }
    $eightMiddleUniverse = [long]$gapUniverses[8]
    $sumDistances = [long]0
    foreach ($universe in $gapUniverses) { $sumDistances += $universe }
    if ($sumDistances -gt $precedenceUniverse -or
        ($N -le 10 -and $sumDistances -ne $precedenceUniverse)) {
        throw 'Code Sequence zero-through-eight intervening gap universes violate ORIGINAL directed precedence.'
    }

    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $neighborRows = [object[]]$PairAdjacency.directed_immediate_original_report_pair_scenarios
    $singleRows = [object[]]$PairSingleIntervening.directed_original_report_pair_single_intervening_scenarios
    $doubleRows = [object[]]$PairDoubleIntervening.directed_original_report_pair_double_intervening_scenarios
    $tripleRows = [object[]]$PairTripleIntervening.directed_original_report_pair_triple_intervening_scenarios
    $quadRows = [object[]]$PairQuadrupleIntervening.directed_original_report_pair_quadruple_intervening_scenarios
    $quintRows = [object[]]$PairQuintupleIntervening.directed_original_report_pair_quintuple_intervening_scenarios
    $sextRows = [object[]]$PairSextupleIntervening.directed_original_report_pair_sextuple_intervening_scenarios
    $septRows = [object[]]$PairSeptupleIntervening.directed_original_report_pair_septuple_intervening_scenarios
    $directed = $N * ($N - 1)
    $eligibleDirected = if ($N -ge 10) { $directed } else { 0 }
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or $parentRows.Count -ne $directed -or
        $neighborRows.Count -ne $directed -or
        $singleRows.Count -ne $(if ($N -lt 3) { 0 } else { $directed }) -or
        $doubleRows.Count -ne $(if ($N -lt 4) { 0 } else { $directed }) -or
        $tripleRows.Count -ne $(if ($N -lt 5) { 0 } else { $directed }) -or
        $quadRows.Count -ne $(if ($N -lt 6) { 0 } else { $directed }) -or
        $quintRows.Count -ne $(if ($N -lt 7) { 0 } else { $directed }) -or
        $sextRows.Count -ne $(if ($N -lt 8) { 0 } else { $directed }) -or
        $septRows.Count -ne $(if ($N -lt 9) { 0 } else { $directed }) -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [int]$PairAdjacency.original_positions_in_adjacency_universe -ne $N -or
        [int]$PairSingleIntervening.original_positions_in_single_intervening_universe -ne $N -or
        [int]$PairDoubleIntervening.original_positions_in_two_intervening_universe -ne $N -or
        [int]$PairTripleIntervening.original_positions_in_three_intervening_universe -ne $N -or
        [int]$PairQuadrupleIntervening.original_positions_in_four_intervening_universe -ne $N -or
        [int]$PairQuintupleIntervening.original_positions_in_five_intervening_universe -ne $N -or
        [int]$PairSextupleIntervening.original_positions_in_six_intervening_universe -ne $N -or
        [int]$PairSeptupleIntervening.original_positions_in_seven_intervening_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairAdjacency.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSingleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairDoubleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairTripleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairQuadrupleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairQuintupleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSextupleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSeptupleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedenceUniverse -or
        [long]$PairAdjacency.full_permutations_per_directed_immediate_report_pair -ne $gapUniverses[0] -or
        [long]$PairSingleIntervening.full_permutations_per_directed_pair_with_one_intervening_original_report -ne $gapUniverses[1] -or
        [long]$PairDoubleIntervening.full_permutations_per_directed_pair_with_two_intervening_original_reports -ne $gapUniverses[2] -or
        [long]$PairTripleIntervening.full_permutations_per_directed_pair_with_three_intervening_original_reports -ne $gapUniverses[3] -or
        [long]$PairQuadrupleIntervening.full_permutations_per_directed_pair_with_four_intervening_original_reports -ne $gapUniverses[4] -or
        [long]$PairQuintupleIntervening.full_permutations_per_directed_pair_with_five_intervening_original_reports -ne $gapUniverses[5] -or
        [long]$PairSextupleIntervening.full_permutations_per_directed_pair_with_six_intervening_original_reports -ne $gapUniverses[6] -or
        [long]$PairSeptupleIntervening.full_permutations_per_directed_pair_with_seven_intervening_original_reports -ne $gapUniverses[7]) {
        throw 'Code Sequence eight-intervening report received inconsistent ORIGINAL support or gap universes.'
    }

    # Authenticate public ORIGINAL antichain and recover monotone S(mask).
    $support = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $support[$base]) {
            throw 'Code Sequence eight-intervening report received empty, duplicate or out-of-range ORIGINAL basis.'
        }
        $support[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence eight-intervening report received nested nonminimal ORIGINAL bases.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $budgetCounts = [int[]]::new($N + 1)
    for ($mask = 0; $mask -lt $size; $mask++) {
        if ($mask -gt 0) { $pop[$mask] = $pop[$mask -shr 1] + ($mask -band 1) }
        if (-not $support[$mask]) {
            for ($position = 0; $position -lt $N; $position++) {
                $bit = 1 -shl $position
                if (($mask -band $bit) -ne 0 -and $support[$mask -bxor $bit]) {
                    $support[$mask] = $true
                    break
                }
            }
        }
        if ($support[$mask]) { $budgetCounts[$pop[$mask]]++ }
    }
    $hasFullSupport = [bool]$support[$full]
    if ($support[0] -or
        $hasFullSupport -ne ([long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0) -or
        $hasFullSupport -ne [bool]$RetentionOrder.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$FixedRank.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairPrecedence.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairAdjacency.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSingleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairDoubleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairTripleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairQuadrupleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairQuintupleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSextupleIntervening.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSeptupleIntervening.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence eight-intervening report changed ORIGINAL full/empty saved evidence support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            [int]$budgetRows[$k].subsets_preserving_original_witness_support -ne $budgetCounts[$k]) {
            throw 'Code Sequence eight-intervening report disagrees with EC-073 original retention budget.'
        }
    }

    $frontier = [int[]]::new($size)
    $positionForBit = [int[]]::new($size)
    for ($position = 0; $position -lt $N; $position++) {
        $positionForBit[1 -shl $position] = $position
    }
    if ($N -ge 10 -and $hasFullSupport) {
        for ($mask = 0; $mask -lt $size; $mask++) {
            if ($support[$mask]) { continue }
            $remaining = $full -bxor $mask
            for ($position = 0; $position -lt $N; $position++) {
                $bit = 1 -shl $position
                if (($remaining -band $bit) -ne 0 -and $support[$mask -bor $bit]) {
                    $frontier[$mask] = $frontier[$mask] -bor $bit
                }
            }
        }
    }

    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(13)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $pairIndex = 0
    $ordinalMiddleNames = [string[]]@('first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth')
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence eight-intervening report changed ORIGINAL EC-075 position identity.'
        }
        if ($N -lt 10) { continue }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $stages = [long[]]::new(13)
            $byMiddlePosition = [object[]]::new(8)
            for ($slot = 0; $slot -lt 8; $slot++) { $byMiddlePosition[$slot] = [long[]]::new($N) }

            if ($hasFullSupport) {
                # Before/by p: a fixed outside-original prefix M has all
                # eight middle orders + remaining suffix: k! * (N-k-2)!.
                $m = $other
                while ($true) {
                    $k = $pop[$m]
                    if ($k -le ($N - 10)) {
                        $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 2]
                        $indexP = $p * $N + $k
                        $indexQ = $q * $N + $k + 9
                        if ($support[$m]) {
                            $stages[0] += $weight
                            $beforePRank[$indexP] += $weight
                            $beforeQRank[$indexQ] += $weight
                        }
                        elseif ($support[$m -bor $pBit]) {
                            $stages[1] += $weight
                            $byPRank[$indexP] += $weight
                            $beforeQRank[$indexQ] += $weight
                        }
                    }
                    if ($m -eq 0) { break }
                    $m = ($m - 1) -band $other
                }

                # Let A be all non-endpoint reports before a potential FIRST
                # restoring middle identity x. Any split A=M union T with
                # |T|=t, |M|=a-t, where 0<=t<=7, yields the same exact
                # integer weight a!*(N-a-3)! after summing all splits.
                # This reduces the old 3^N prefix/submask sum to 2^N masks.
                $aMask = $other
                while ($true) {
                    $a = $pop[$aMask]
                    $withP = $aMask -bor $pBit
                    if (-not $support[$withP] -and $a -le ($N - 3)) {
                        $restoringBits = $frontier[$withP] -band ($other -bxor $aMask)
                        if ($restoringBits -ne 0) {
                            $minSlot = [Math]::Max(0, $a - ($N - 10))
                            $maxSlot = [Math]::Min(7, $a)
                            $weight = [long]$factorial[$a] * [long]$factorial[$N - $a - 3]
                            $restoringCount = $pop[$restoringBits]
                            for ($slot = $minSlot; $slot -le $maxSlot; $slot++) {
                                $k = $a - $slot
                                $stages[$slot + 2] += [long]$restoringCount * $weight
                                $beforeQRank[$q * $N + $k + 9] += [long]$restoringCount * $weight
                                $bitsToCredit = $restoringBits
                                while ($bitsToCredit -ne 0) {
                                    $oneBit = $bitsToCredit -band (-$bitsToCredit)
                                    $byMiddlePosition[$slot][$positionForBit[$oneBit]] += $weight
                                    $bitsToCredit = $bitsToCredit -bxor $oneBit
                                }
                            }
                        }
                    }
                    # First-by-q: all eight intermediate identities are in A,
                    # and (p+A) is still unsupported. A has a! arrangements
                    # across outside prefix and ordered intermediate slots.
                    if ($a -ge 8 -and -not $support[$withP] -and $support[$withP -bor $qBit]) {
                        $weight = [long]$factorial[$a] * [long]$factorial[$N - $a - 2]
                        $stages[10] += $weight
                        $byQRank[$q * $N + $a + 1] += $weight
                    }
                    if ($aMask -eq 0) { break }
                    $aMask = ($aMask - 1) -band $other
                }
                $firstThroughQ = [long]0
                for ($stage = 0; $stage -le 10; $stage++) { $firstThroughQ += $stages[$stage] }
                if ($firstThroughQ -gt $eightMiddleUniverse) {
                    throw 'Code Sequence eight-intervening report overcounted first support in a directed scenario.'
                }
                $stages[11] = $eightMiddleUniverse - $firstThroughQ
            }
            else {
                $stages[12] = $eightMiddleUniverse
            }
            $mass = [long]0
            foreach ($value in $stages) {
                if ($value -lt 0) { throw 'Code Sequence eight-intervening report produced a negative FIRST stage.' }
                $mass += $value
            }
            if ($mass -ne $eightMiddleUniverse) {
                throw 'Code Sequence eight-intervening report failed its thirteen-category conditional order partition.'
            }
            for ($slot = 0; $slot -lt 8; $slot++) {
                $identitySum = [long]0
                for ($r = 0; $r -lt $N; $r++) {
                    $value = [long]$byMiddlePosition[$slot][$r]
                    if ($value -lt 0 -or (($r -eq $p -or $r -eq $q) -and $value -ne 0)) {
                        throw 'Code Sequence eight-intervening report attributed middle first support to an ORIGINAL endpoint.'
                    }
                    $identitySum += $value
                }
                if ($identitySum -ne $stages[$slot + 2]) {
                    throw 'Code Sequence eight-intervening report lost an ORIGINAL middle identity attribution.'
                }
            }

            # Disjoint predecessor gaps 0..7 must embed in exact EC-076
            # precedence, along with our newly conditioned distance eight.
            $parent = $parentRows[$pairIndex]
            $neighbor = $neighborRows[$pairIndex]
            $single = $singleRows[$pairIndex]
            $double = $doubleRows[$pairIndex]
            $triple = $tripleRows[$pairIndex]
            $quad = $quadRows[$pairIndex]
            $quint = $quintRows[$pairIndex]
            $sext = $sextRows[$pairIndex]
            $sept = $septRows[$pairIndex]
            $pairIndex++
            $predecessors = [object[]]@($neighbor, $single, $double, $triple, $quad, $quint, $sext, $sept)
            foreach ($entry in @($parent) + $predecessors) {
                if ([int]$entry.first_original_caller_position -ne ($p + 1) -or
                    [int]$entry.second_original_caller_position -ne ($q + 1) -or
                    [int]$entry.first_original_position_bit -ne $pBit -or
                    [int]$entry.second_original_position_bit -ne $qBit) {
                    throw 'Code Sequence eight-intervening report changed an EC-076..084 ORIGINAL directed identity.'
                }
            }
            if ([long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedenceUniverse -or
                [long]$neighbor.exact_full_permutations_with_first_report_immediately_before_second -ne $gapUniverses[0] -or
                [long]$single.exact_full_permutations_with_exactly_one_original_report_between_pair -ne $gapUniverses[1] -or
                [long]$double.exact_full_permutations_with_exactly_two_original_reports_between_pair -ne $gapUniverses[2] -or
                [long]$triple.exact_full_permutations_with_exactly_three_original_reports_between_pair -ne $gapUniverses[3] -or
                [long]$quad.exact_full_permutations_with_exactly_four_original_reports_between_pair -ne $gapUniverses[4] -or
                [long]$quint.exact_full_permutations_with_exactly_five_original_reports_between_pair -ne $gapUniverses[5] -or
                [long]$sext.exact_full_permutations_with_exactly_six_original_reports_between_pair -ne $gapUniverses[6] -or
                [long]$sept.exact_full_permutations_with_exactly_seven_original_reports_between_pair -ne $gapUniverses[7]) {
                throw 'Code Sequence eight-intervening report changed an earlier directed ORIGINAL gap universe.'
            }
            $prior = [long[]]::new(6)
            for ($prevGap = 0; $prevGap -le 7; $prevGap++) {
                $entry = $predecessors[$prevGap]
                $prior[0] += [long]$entry.full_permutations_first_restoring_before_first_report
                $prior[1] += [long]$entry.full_permutations_first_restored_by_first_report
                $prior[3] += [long]$entry.full_permutations_first_restored_by_second_report
                $prior[4] += [long]$entry.full_permutations_first_restoring_after_second_report
                $prior[5] += [long]$entry.full_permutations_never_restoring_saved_evidence
                if ($prevGap -eq 1) {
                    $prior[2] += [long]$entry.full_permutations_first_restored_by_single_intervening_original_report
                }
                elseif ($prevGap -ge 2) {
                    for ($slot = 0; $slot -lt $prevGap; $slot++) {
                        $property = 'full_permutations_first_restored_by_' + $ordinalMiddleNames[$slot] + '_intervening_original_report'
                        $prior[2] += [long]$entry.$property
                    }
                }
            }
            $newBetween = [long]0
            for ($slot = 2; $slot -le 9; $slot++) { $newBetween += $stages[$slot] }
            $deltas = [long[]]@(
                ([long]$parent.full_permutations_first_restoring_before_first_report - $prior[0] - $stages[0]),
                ([long]$parent.full_permutations_first_restored_by_first_report - $prior[1] - $stages[1]),
                ([long]$parent.full_permutations_first_restoring_strictly_between_reports - $prior[2] - $newBetween),
                ([long]$parent.full_permutations_first_restored_by_second_report - $prior[3] - $stages[10]),
                ([long]$parent.full_permutations_first_restoring_after_second_report - $prior[4] - $stages[11]),
                ([long]$parent.full_permutations_never_restoring_saved_evidence - $prior[5] - $stages[12])
            )
            foreach ($difference in $deltas) {
                if ($difference -lt 0 -or ($N -eq 10 -and $difference -ne 0)) {
                    throw 'Code Sequence zero-through-eight ORIGINAL gap families contradict EC-076 precedence.'
                }
            }

            $gcd = [long[]]::new(10)
            for ($i = 0; $i -lt 10; $i++) {
                $gcd[$i] = Get-CodeSequenceRetentionOrderGcd -A $stages[$i + 1] -B $eightMiddleUniverse
            }
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                number_of_ordered_distinct_original_middle_identity_octuples = [long]([long]$factorial[$N - 2] / [long]$factorial[$N - 10])
                exact_full_permutations_with_exactly_eight_original_reports_between_pair = $eightMiddleUniverse
                full_permutations_first_restoring_before_first_report = $stages[0]
                full_permutations_first_restored_by_first_report = $stages[1]
                full_permutations_first_restored_by_first_intervening_original_report = $stages[2]
                full_permutations_first_restored_by_second_intervening_original_report = $stages[3]
                full_permutations_first_restored_by_third_intervening_original_report = $stages[4]
                full_permutations_first_restored_by_fourth_intervening_original_report = $stages[5]
                full_permutations_first_restored_by_fifth_intervening_original_report = $stages[6]
                full_permutations_first_restored_by_sixth_intervening_original_report = $stages[7]
                full_permutations_first_restored_by_seventh_intervening_original_report = $stages[8]
                full_permutations_first_restored_by_eighth_intervening_original_report = $stages[9]
                full_permutations_first_restored_by_second_report = $stages[10]
                full_permutations_first_restoring_after_second_report = $stages[11]
                full_permutations_never_restoring_saved_evidence = $stages[12]
                first_restored_by_first_intervening_original_caller_position_counts = $byMiddlePosition[0]
                first_restored_by_second_intervening_original_caller_position_counts = $byMiddlePosition[1]
                first_restored_by_third_intervening_original_caller_position_counts = $byMiddlePosition[2]
                first_restored_by_fourth_intervening_original_caller_position_counts = $byMiddlePosition[3]
                first_restored_by_fifth_intervening_original_caller_position_counts = $byMiddlePosition[4]
                first_restored_by_sixth_intervening_original_caller_position_counts = $byMiddlePosition[5]
                first_restored_by_seventh_intervening_original_caller_position_counts = $byMiddlePosition[6]
                first_restored_by_eighth_intervening_original_caller_position_counts = $byMiddlePosition[7]
                exact_reduced_by_first_report_fraction_numerator = [long]($stages[1] / $gcd[0])
                exact_reduced_by_first_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[0])
                exact_reduced_by_first_intervening_report_fraction_numerator = [long]($stages[2] / $gcd[1])
                exact_reduced_by_first_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[1])
                exact_reduced_by_second_intervening_report_fraction_numerator = [long]($stages[3] / $gcd[2])
                exact_reduced_by_second_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[2])
                exact_reduced_by_third_intervening_report_fraction_numerator = [long]($stages[4] / $gcd[3])
                exact_reduced_by_third_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[3])
                exact_reduced_by_fourth_intervening_report_fraction_numerator = [long]($stages[5] / $gcd[4])
                exact_reduced_by_fourth_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[4])
                exact_reduced_by_fifth_intervening_report_fraction_numerator = [long]($stages[6] / $gcd[5])
                exact_reduced_by_fifth_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[5])
                exact_reduced_by_sixth_intervening_report_fraction_numerator = [long]($stages[7] / $gcd[6])
                exact_reduced_by_sixth_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[6])
                exact_reduced_by_seventh_intervening_report_fraction_numerator = [long]($stages[8] / $gcd[7])
                exact_reduced_by_seventh_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[7])
                exact_reduced_by_eighth_intervening_report_fraction_numerator = [long]($stages[9] / $gcd[8])
                exact_reduced_by_eighth_intervening_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[8])
                exact_reduced_by_second_report_fraction_numerator = [long]($stages[10] / $gcd[9])
                exact_reduced_by_second_report_fraction_denominator = [long]($eightMiddleUniverse / $gcd[9])
            })
            for ($i = 0; $i -lt 13; $i++) { $totals[$i] += $stages[$i] }
        }
    }
    if ($scenarios.Count -ne $eligibleDirected -or $pairIndex -ne $eligibleDirected) {
        throw 'Code Sequence eight-intervening report miscounted eligible directed ORIGINAL endpoints.'
    }

    # Fixed p rank j pairs only with q at rank j+9, and vice versa.
    # Independent EC-075 fixed-position margins must match without scaling.
    $rankChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentUniverse) {
                throw 'Code Sequence eight-intervening report changed independent EC-075 fixed-rank universe.'
            }
            $expectedPBefore = [long]0; $expectedPBy = [long]0
            $expectedQBefore = [long]0; $expectedQBy = [long]0
            if ($j -le ($N - 9)) {
                $expectedPBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -ge 10) {
                $expectedQBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedQBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedPBefore -or
                $byPRank[$idx] -ne $expectedPBy -or
                $beforeQRank[$idx] -ne $expectedQBefore -or
                $byQRank[$idx] -ne $expectedQBy) {
                throw 'Code Sequence eight-intervening report failed independent EC-075 offset-nine first-support margins.'
            }
        }
        $rankChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            number_of_original_rank_cases_reconciled = $N
        })
    }

    # Independent EC-074 FIRST-rank incidence for all consecutive ten-report blocks.
    $expected = [long[]]::new(13)
    $totalFirst = [long]0
    for ($step = 1; $step -le $N; $step++) {
        if ([int]$stepRows[$step].number_of_first_original_reports_retained -ne $step) {
            throw 'Code Sequence eight-intervening report changed EC-074 first-retained rank.'
        }
        $first = [long]$stepRows[$step].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence eight-intervening report received negative EC-074 first-support mass.' }
        $expected[0] += [long][Math]::Max(0, $N - $step - 9) * $first
        if ($step -le ($N - 9)) { $expected[1] += $first }
        for ($middleSlot = 1; $middleSlot -le 8; $middleSlot++) {
            if ($step -ge ($middleSlot + 1) -and $step -le ($N - 9 + $middleSlot)) {
                $expected[$middleSlot + 1] += $first
            }
        }
        if ($step -ge 10) { $expected[10] += $first }
        $expected[11] += [long][Math]::Max(0, $step - 10) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence eight-intervening report disagrees with EC-074 original whole-order support.'
    }
    $totalIncidences = [long][Math]::Max(0, $N - 9) * $permutations
    if (-not $hasFullSupport) { $expected[12] = $totalIncidences }
    for ($i = 0; $i -lt 13; $i++) {
        if ($totals[$i] -ne $expected[$i]) {
            throw 'Code Sequence eight-intervening report failed independent EC-074 thirteen-stage FIRST ledger.'
        }
    }
    $actualMass = [long]0
    foreach ($value in $totals) { $actualMass += $value }
    if ($actualMass -ne $totalIncidences) {
        throw 'Code Sequence eight-intervening report did not conserve ten-report ORIGINAL block occurrences.'
    }
    return [ordered]@{
        original_positions_in_eight_intervening_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_pair_with_eight_intervening_original_reports = $eightMiddleUniverse
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_original_report_pair_octuple_intervening_scenarios = $scenarios.ToArray()
        original_position_nine_rank_offset_margins_against_ec075 = $rankChecks.ToArray()
        independent_ec074_first_support_step_octuple_intervening_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_first_intervening_original_report = $totals[2]
            full_permutations_first_restored_by_second_intervening_original_report = $totals[3]
            full_permutations_first_restored_by_third_intervening_original_report = $totals[4]
            full_permutations_first_restored_by_fourth_intervening_original_report = $totals[5]
            full_permutations_first_restored_by_fifth_intervening_original_report = $totals[6]
            full_permutations_first_restored_by_sixth_intervening_original_report = $totals[7]
            full_permutations_first_restored_by_seventh_intervening_original_report = $totals[8]
            full_permutations_first_restored_by_eighth_intervening_original_report = $totals[9]
            full_permutations_first_restored_by_second_report = $totals[10]
            full_permutations_first_restoring_after_second_report = $totals[11]
            full_permutations_never_restoring_saved_evidence = $totals[12]
            expected_total_octuple_intervening_pair_occurrences_across_all_orderings = $totalIncidences
        }
        every_directed_pair_octuple_intervening_case_has_thirteen_disjoint_exhaustive_first_support_categories = $true
        all_eight_middle_original_identity_attributions_sum_to_their_exact_first_support_stages = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_nine_rank_offset_margin_matches_independent_ec075_fixed_rank = $true
        adjacent_one_two_three_four_five_six_seven_and_eight_middle_cases_are_disjoint_subsets_of_ec076_precedence = $true
        all_thirteen_octuple_intervening_first_support_categories_match_independent_ec074_step_counts = $true
        original_n2_n3_n4_n5_n6_n7_n8_n9_have_no_eligible_octuple_intervening_pair = ($N -lt 10)
        hypothetical_eight_intervening_gap_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairOctupleIntervening {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency,
        [object] $RetentionPairSingleIntervening,
        [object] $RetentionPairDoubleIntervening,
        [object] $RetentionPairTripleIntervening,
        [object] $RetentionPairQuadrupleIntervening,
        [object] $RetentionPairQuintupleIntervening,
        [object] $RetentionPairSextupleIntervening,
        [object] $RetentionPairSeptupleIntervening
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or $null -eq $RetentionPairAdjacency -or
        $null -eq $RetentionPairSingleIntervening -or
        $null -eq $RetentionPairDoubleIntervening -or
        $null -eq $RetentionPairTripleIntervening -or
        $null -eq $RetentionPairQuadrupleIntervening -or
        $null -eq $RetentionPairQuintupleIntervening -or
        $null -eq $RetentionPairSextupleIntervening -or
        $null -eq $RetentionPairSeptupleIntervening -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        $RetentionPairAdjacency.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair' -or
        $RetentionPairSingleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_single_intervening_original_report_between_ordered_pair' -or
        $RetentionPairDoubleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_two_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairTripleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_three_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairQuadrupleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_four_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairQuintupleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_five_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairSextupleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_six_ordered_intervening_original_reports_between_ordered_pair' -or
        $RetentionPairSeptupleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_seven_ordered_intervening_original_reports_between_ordered_pair' -or
        -not [bool]$RetentionPairQuintupleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairQuintupleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairSextupleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSextupleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairSeptupleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSeptupleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairQuadrupleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairQuadrupleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairTripleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairTripleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairDoubleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairDoubleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairSingleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSingleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization) {
        throw 'Code Sequence pair octuple-intervening requires the unchanged EC-072..084 original target registry.'
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
    $gQuad = [object[]]$RetentionPairQuadrupleIntervening.genuine_global_threshold_pair_quadruple_intervening
    $fQuad = [object[]]$RetentionPairQuadrupleIntervening.frozen_global_threshold_pair_quadruple_intervening
    $familyQuad = [object[]]$RetentionPairQuadrupleIntervening.individual_original_family_pair_quadruple_intervening
    $gQuint = [object[]]$RetentionPairQuintupleIntervening.genuine_global_threshold_pair_quintuple_intervening
    $fQuint = [object[]]$RetentionPairQuintupleIntervening.frozen_global_threshold_pair_quintuple_intervening
    $familyQuint = [object[]]$RetentionPairQuintupleIntervening.individual_original_family_pair_quintuple_intervening
    $gSext = [object[]]$RetentionPairSextupleIntervening.genuine_global_threshold_pair_sextuple_intervening
    $fSext = [object[]]$RetentionPairSextupleIntervening.frozen_global_threshold_pair_sextuple_intervening
    $familySext = [object[]]$RetentionPairSextupleIntervening.individual_original_family_pair_sextuple_intervening
    $gSept = [object[]]$RetentionPairSeptupleIntervening.genuine_global_threshold_pair_septuple_intervening
    $fSept = [object[]]$RetentionPairSeptupleIntervening.frozen_global_threshold_pair_septuple_intervening
    $familySept = [object[]]$RetentionPairSeptupleIntervening.individual_original_family_pair_septuple_intervening
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
        [int]$RetentionPairQuadrupleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairQuintupleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairSextupleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairSeptupleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairAdjacency.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSingleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairDoubleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairTripleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairQuadrupleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairQuintupleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSextupleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSeptupleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $gCubes.Count -ne $gAdjacency.Count -or $gCubes.Count -ne $gSingle.Count -or
        $gCubes.Count -ne $gDouble.Count -or $gCubes.Count -ne $gTriple.Count -or $gCubes.Count -ne $gQuad.Count -or $gCubes.Count -ne $gQuint.Count -or
        $gCubes.Count -ne $gSext.Count -or $gCubes.Count -ne $gSept.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $fCubes.Count -ne $fAdjacency.Count -or $fCubes.Count -ne $fSingle.Count -or
        $fCubes.Count -ne $fDouble.Count -or $fCubes.Count -ne $fTriple.Count -or $fCubes.Count -ne $fQuad.Count -or $fCubes.Count -ne $fQuint.Count -or
        $fCubes.Count -ne $fSext.Count -or $fCubes.Count -ne $fSept.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount -or
        $familyAdjacency.Count -ne $familyCount -or $familySingle.Count -ne $familyCount -or
        $familyDouble.Count -ne $familyCount -or $familyTriple.Count -ne $familyCount -or
        $familyQuad.Count -ne $familyCount -or $familyQuint.Count -ne $familyCount -or
        $familySext.Count -ne $familyCount -or $familySept.Count -ne $familyCount) {
        throw 'Code Sequence pair octuple-intervening changed original genuine/frozen/family target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $neighbors = $gAdjacency
        $singles = $gSingle; $doubles = $gDouble; $triples = $gTriple; $quads = $gQuad; $quints = $gQuint; $sexts = $gSext; $septs = $gSept; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $neighbors = $fAdjacency
            $singles = $fSingle; $doubles = $fDouble; $triples = $fTriple; $quads = $fQuad; $quints = $fQuint; $sexts = $fSext; $septs = $fSept; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]
            $neighbor = $neighbors[$i]; $single = $singles[$i]
            $double = $doubles[$i]; $triple = $triples[$i]; $quad = $quads[$i]; $quint = $quints[$i]; $sext = $sexts[$i]; $sept = $septs[$i]
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
                $threshold -ne [int]$quad.original_global_family_capacity_at_least -or
                $threshold -ne [int]$quint.original_global_family_capacity_at_least -or
                $threshold -ne [int]$sext.original_global_family_capacity_at_least -or
                $threshold -ne [int]$sept.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$neighbor.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$single.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$double.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$triple.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$quad.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$quint.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$sext.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$sept.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair octuple-intervening changed original genuine/frozen capacity thresholds.'
            }
            $projection = Get-CodeSequenceRetentionPairOctupleInterveningProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence `
                -PairAdjacency $neighbor.exact_first_support_pair_adjacency `
                -PairSingleIntervening $single.exact_first_support_pair_single_intervening `
                -PairDoubleIntervening $double.exact_first_support_pair_double_intervening `
                -PairTripleIntervening $triple.exact_first_support_pair_triple_intervening `
                -PairQuadrupleIntervening $quad.exact_first_support_pair_quadruple_intervening `
                -PairQuintupleIntervening $quint.exact_first_support_pair_quintuple_intervening `
                -PairSextupleIntervening $sext.exact_first_support_pair_sextuple_intervening `
                -PairSeptupleIntervening $sept.exact_first_support_pair_septuple_intervening -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_octuple_intervening = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]; $neighbor = $familyAdjacency[$fi]
        $single = $familySingle[$fi]; $double = $familyDouble[$fi]
        $triple = $familyTriple[$fi]; $quad = $familyQuad[$fi]; $quint = $familyQuint[$fi]; $sext = $familySext[$fi]; $sept = $familySept[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$neighbor.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$single.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$double.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$triple.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$quad.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$quint.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$sext.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$sept.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair octuple-intervening changed an individual ORIGINAL family ID.'
        }
        $g = Get-CodeSequenceRetentionPairOctupleInterveningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.genuine_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.genuine_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.genuine_original_first_support_pair_double_intervening `
            -PairTripleIntervening $triple.genuine_original_first_support_pair_triple_intervening `
            -PairQuadrupleIntervening $quad.genuine_original_first_support_pair_quadruple_intervening `
            -PairQuintupleIntervening $quint.genuine_original_first_support_pair_quintuple_intervening `
            -PairSextupleIntervening $sext.genuine_original_first_support_pair_sextuple_intervening `
            -PairSeptupleIntervening $sept.genuine_original_first_support_pair_septuple_intervening -N $n
        $f = Get-CodeSequenceRetentionPairOctupleInterveningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.frozen_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.frozen_original_first_support_pair_single_intervening `
            -PairDoubleIntervening $double.frozen_original_first_support_pair_double_intervening `
            -PairTripleIntervening $triple.frozen_original_first_support_pair_triple_intervening `
            -PairQuadrupleIntervening $quad.frozen_original_first_support_pair_quadruple_intervening `
            -PairQuintupleIntervening $quint.frozen_original_first_support_pair_quintuple_intervening `
            -PairSextupleIntervening $sext.frozen_original_first_support_pair_sextuple_intervening `
            -PairSeptupleIntervening $sept.frozen_original_first_support_pair_septuple_intervening -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_octuple_intervening = $g
            frozen_original_first_support_pair_octuple_intervening = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    $eightMiddleUniverse = [long]0
    if ($n -ge 10) { $eightMiddleUniverse = [long]($n - 9) * [long]$factorial[$n - 2] }
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_eight_ordered_intervening_original_reports_between_ordered_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_original_pair_with_eight_intervening_reports = $eightMiddleUniverse
            directed_original_report_octuple_intervening_scenarios_per_target = $(if ($n -lt 10) { 0 } else { $n * ($n - 1) })
            original_eight_intervening_pair_occurrences_across_all_permutations_per_target = [long]([Math]::Max(0, $n - 9)) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_octuple_intervening = $gResult.ToArray()
        frozen_global_threshold_pair_octuple_intervening = $fResult.ToArray()
        individual_original_family_pair_octuple_intervening = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        original_n2_n3_n4_n5_n6_n7_n8_n9_have_no_eligible_octuple_intervening_pair = ($n -lt 10)
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_eight_intervening_gap_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_eight_intervening_gap_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

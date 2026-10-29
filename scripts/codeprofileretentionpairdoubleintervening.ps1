#requires -Version 7.0
<#
    EC-079: exact FIRST original saved-witness restoration across an ordered
    ORIGINAL four-report block p,r,s,q in a hypothetical full permutation.
    The identities of both middle reports vary without changing the original
    caller report/bit order. A directed p/q case has (N-3)*(N-2)! orders for
    N>=4, and no cases for N=2 or 3.

    Public EC-072 minimal ORIGINAL support bases alone determine S(mask).
    Evaluate every original prefix M and eligible first middle r with
    k!*(N-k-4)! weights, aggregating all possible second middles s by
    their exact one-bit support frontier. The frontier makes the second
    intermediary's original identity observable without iterating all
    complete N! permutations or rereading private evidence. Reconcile with
    EC-073/074/075 and disjoint EC-076/077/078 pair stages.
#>

function Get-CodeSequenceRetentionPairDoubleInterveningProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [object] $PairPrecedence,
        [object] $PairAdjacency,
        [object] $PairSingleIntervening,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        $null -eq $PairAdjacency -or $null -eq $PairSingleIntervening -or
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
        -not [bool]$PairSingleIntervening.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairSingleIntervening.every_two_rank_offset_margin_matches_independent_ec075_fixed_rank -or
        -not [bool]$PairSingleIntervening.each_one_intervening_and_adjacent_scenario_disjoint_within_ec076_precedence -or
        -not [bool]$PairSingleIntervening.all_six_one_intervening_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence two-intervening report requires complete original EC-072/073/074/075/076/077/078 evidence.'
    }
    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $adjacentUniverse = [long]$factorial[$N - 1]
    $precedenceUniverse = [long]($permutations / 2)
    $oneMiddleUniverse = [long]0
    if ($N -ge 3) { $oneMiddleUniverse = [long]($N - 2) * [long]$factorial[$N - 2] }
    $twoMiddleUniverse = [long]0
    if ($N -ge 4) { $twoMiddleUniverse = [long]($N - 3) * [long]$factorial[$N - 2] }
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $neighborRows = [object[]]$PairAdjacency.directed_immediate_original_report_pair_scenarios
    $singleRows = [object[]]$PairSingleIntervening.directed_original_report_pair_single_intervening_scenarios
    $eligibleDirected = if ($N -ge 4) { $N * ($N - 1) } else { 0 }
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or
        $parentRows.Count -ne ($N * ($N - 1)) -or
        $neighborRows.Count -ne $parentRows.Count -or
        $singleRows.Count -ne $(if ($N -eq 2) { 0 } else { $N * ($N - 1) }) -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [int]$PairAdjacency.original_positions_in_adjacency_universe -ne $N -or
        [int]$PairSingleIntervening.original_positions_in_single_intervening_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairAdjacency.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairSingleIntervening.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedenceUniverse -or
        [long]$PairAdjacency.full_permutations_per_directed_immediate_report_pair -ne $adjacentUniverse -or
        [long]$PairSingleIntervening.full_permutations_per_directed_pair_with_one_intervening_original_report -ne $oneMiddleUniverse -or
        [long]$FixedRank.complete_permutations_per_original_position_per_fixed_rank -ne $adjacentUniverse -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence two-intervening report encountered inconsistent original permutation universes.'
    }
    if ($adjacentUniverse + $oneMiddleUniverse + $twoMiddleUniverse -gt $precedenceUniverse -or
        ($N -le 4 -and $adjacentUniverse + $oneMiddleUniverse + $twoMiddleUniverse -ne $precedenceUniverse)) {
        throw 'Code Sequence zero/one/two-middle ordered pair universes violate disjoint original precedence.'
    }

    # Build monotone Boolean ORIGINAL support and its one-add frontier solely
    # from the checked public original inclusion-minimal retained bases.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence two-intervening report received an invalid or repeated original support basis.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence two-intervening report received nonminimal original bases.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $supportedByBudget = [int[]]::new($N + 1)
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
        if ($hasEvidence[$mask]) { $supportedByBudget[$pop[$mask]]++ }
    }
    $hasFullSupport = [bool]$hasEvidence[$full]
    if ($hasEvidence[0] -or
        $hasFullSupport -ne ([long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0) -or
        $hasFullSupport -ne [bool]$RetentionOrder.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$FixedRank.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairPrecedence.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairAdjacency.full_original_selection_has_saved_witness_support -or
        $hasFullSupport -ne [bool]$PairSingleIntervening.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence two-intervening report changed ORIGINAL empty/full support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            [int]$budgetRows[$k].subsets_preserving_original_witness_support -ne $supportedByBudget[$k]) {
            throw 'Code Sequence two-intervening report disagrees with EC-073 supported original budgets.'
        }
    }
    $addFrontier = [int[]]::new($size)
    if ($hasFullSupport -and $N -ge 4) {
        for ($mask = 0; $mask -lt $size; $mask++) {
            if ($hasEvidence[$mask]) { continue }
            $candidateBits = $full -bxor $mask
            for ($bitIndex = 0; $bitIndex -lt $N; $bitIndex++) {
                $bit = 1 -shl $bitIndex
                if (($candidateBits -band $bit) -ne 0 -and $hasEvidence[$mask -bor $bit]) {
                    $addFrontier[$mask] = $addFrontier[$mask] -bor $bit
                }
            }
        }
    }

    # Four independent N*N rank margins: p before/by and q before/by.
    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(7)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $pairIndex = 0
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence two-intervening report changed EC-075 original position identity.'
        }
        if ($N -lt 4) { continue }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $beforeP = [long]0
            $byP = [long]0
            $byFirst = [long]0
            $bySecond = [long]0
            $byQ = [long]0
            $byFirstPosition = [long[]]::new($N)
            $bySecondPosition = [long[]]::new($N)
            $m = $other
            if ($hasFullSupport) {
                while ($true) {
                    $k = $pop[$m]
                    $eligibleMiddle = $other -bxor $m
                    $choices = $pop[$eligibleMiddle]
                    if ($choices -ge 2) {
                        # k originals before p, then two DISTINCT ORIGINAL
                        # middle reports r,s, then q, then N-k-4 reports.
                        $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 4]
                        $orderedMiddlePairs = [long]$choices * [long]($choices - 1)
                        $withP = $m -bor $pBit
                        $atBeforeP = [long]0
                        $atByP = [long]0
                        $atByFirst = [long]0
                        $atBySecond = [long]0
                        $atByQ = [long]0
                        if ($hasEvidence[$m]) {
                            $atBeforeP = $orderedMiddlePairs * $weight
                        }
                        elseif ($hasEvidence[$withP]) {
                            $atByP = $orderedMiddlePairs * $weight
                        }
                        else {
                            for ($r = 0; $r -lt $N; $r++) {
                                $rBit = 1 -shl $r
                                if (($eligibleMiddle -band $rBit) -eq 0) { continue }
                                $withFirst = $withP -bor $rBit
                                $possibleSecond = $eligibleMiddle -bxor $rBit
                                if ($hasEvidence[$withFirst]) {
                                    $contribution = [long]($choices - 1) * $weight
                                    $atByFirst += $contribution
                                    $byFirstPosition[$r] += $contribution
                                    continue
                                }
                                # Support-frontier bitset computes all EXACT
                                # second-middle restoration candidates with
                                # no quadratic r*s scan in sparse cases.
                                $secondFirstSupport = $addFrontier[$withFirst] -band $possibleSecond
                                $secondCount = $pop[$secondFirstSupport]
                                $atBySecond += [long]$secondCount * $weight
                                if ($secondCount -gt 0) {
                                    for ($s = 0; $s -lt $N; $s++) {
                                        $sBit = 1 -shl $s
                                        if (($secondFirstSupport -band $sBit) -ne 0) {
                                            $bySecondPosition[$s] += $weight
                                        }
                                    }
                                }
                                $stillUnrestored = $possibleSecond -band (-bnot $secondFirstSupport)
                                if ($stillUnrestored -ne 0) {
                                    $withFirstQ = $withFirst -bor $qBit
                                    if ($hasEvidence[$withFirstQ]) {
                                        $atByQ += [long]$pop[$stillUnrestored] * $weight
                                    }
                                    else {
                                        # A support step at q after s can
                                        # only be new when s is pivotal in
                                        # mask (M+p+r+q), while s itself was
                                        # NOT pivotal in (M+p+r).
                                        $qPivots = $addFrontier[$withFirstQ] -band $stillUnrestored
                                        $atByQ += [long]$pop[$qPivots] * $weight
                                    }
                                }
                            }
                        }
                        $beforeP += $atBeforeP
                        $byP += $atByP
                        $byFirst += $atByFirst
                        $bySecond += $atBySecond
                        $byQ += $atByQ
                        $beforePRank[$p * $N + $k] += $atBeforeP
                        $byPRank[$p * $N + $k] += $atByP
                        $beforeQRank[$q * $N + $k + 3] += $atBeforeP + $atByP + $atByFirst + $atBySecond
                        $byQRank[$q * $N + $k + 3] += $atByQ
                    }
                    if ($m -eq 0) { break }
                    $m = ($m - 1) -band $other
                }
            }
            $afterQ = [long]0
            $never = [long]0
            if ($hasFullSupport) { $afterQ = $twoMiddleUniverse - $beforeP - $byP - $byFirst - $bySecond - $byQ }
            else { $never = $twoMiddleUniverse }
            $firstAttributionTotal = [long]0
            $secondAttributionTotal = [long]0
            for ($i = 0; $i -lt $N; $i++) {
                $firstAttributionTotal += $byFirstPosition[$i]
                $secondAttributionTotal += $bySecondPosition[$i]
                if (($i -eq $p -or $i -eq $q) -and
                    ($byFirstPosition[$i] -ne 0 -or $bySecondPosition[$i] -ne 0)) {
                    throw 'Code Sequence two-intervening report credited first support to an endpoint intermediary.'
                }
            }
            if ($beforeP -lt 0 -or $byP -lt 0 -or $byFirst -lt 0 -or
                $bySecond -lt 0 -or $byQ -lt 0 -or $afterQ -lt 0 -or $never -lt 0 -or
                $firstAttributionTotal -ne $byFirst -or $secondAttributionTotal -ne $bySecond -or
                $beforeP + $byP + $byFirst + $bySecond + $byQ + $afterQ + $never -ne $twoMiddleUniverse) {
                throw 'Code Sequence two-intervening report violated its seven-stage partition or original middle identities.'
            }
            $parent = $parentRows[$pairIndex]
            $neighbor = $neighborRows[$pairIndex]
            $single = $singleRows[$pairIndex]
            $pairIndex++
            if ([int]$parent.first_original_caller_position -ne ($p + 1) -or
                [int]$parent.second_original_caller_position -ne ($q + 1) -or
                [int]$parent.first_original_position_bit -ne $pBit -or
                [int]$parent.second_original_position_bit -ne $qBit -or
                [int]$neighbor.first_original_caller_position -ne ($p + 1) -or
                [int]$neighbor.second_original_caller_position -ne ($q + 1) -or
                [int]$neighbor.first_original_position_bit -ne $pBit -or
                [int]$neighbor.second_original_position_bit -ne $qBit -or
                [int]$single.first_original_caller_position -ne ($p + 1) -or
                [int]$single.second_original_caller_position -ne ($q + 1) -or
                [int]$single.first_original_position_bit -ne $pBit -or
                [int]$single.second_original_position_bit -ne $qBit -or
                [long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedenceUniverse -or
                [long]$neighbor.exact_full_permutations_with_first_report_immediately_before_second -ne $adjacentUniverse -or
                [long]$single.exact_full_permutations_with_exactly_one_original_report_between_pair -ne $oneMiddleUniverse) {
                throw 'Code Sequence two-intervening report changed prior original p/q bits or scenario order.'
            }
            # All THREE nonoverlapping rank distances are subsets of the
            # EC-076 p-before-q six stages. At N4 they exhaust precedence.
            $subsetDiffs = [long[]]@(
                [long]$parent.full_permutations_first_restoring_before_first_report -
                    ([long]$neighbor.full_permutations_first_restoring_before_first_report + [long]$single.full_permutations_first_restoring_before_first_report + $beforeP),
                [long]$parent.full_permutations_first_restored_by_first_report -
                    ([long]$neighbor.full_permutations_first_restored_by_first_report + [long]$single.full_permutations_first_restored_by_first_report + $byP),
                [long]$parent.full_permutations_first_restoring_strictly_between_reports -
                    ([long]$single.full_permutations_first_restored_by_single_intervening_original_report + $byFirst + $bySecond),
                [long]$parent.full_permutations_first_restored_by_second_report -
                    ([long]$neighbor.full_permutations_first_restored_by_second_report + [long]$single.full_permutations_first_restored_by_second_report + $byQ),
                [long]$parent.full_permutations_first_restoring_after_second_report -
                    ([long]$neighbor.full_permutations_first_restoring_after_second_report + [long]$single.full_permutations_first_restoring_after_second_report + $afterQ),
                [long]$parent.full_permutations_never_restoring_saved_evidence -
                    ([long]$neighbor.full_permutations_never_restoring_saved_evidence + [long]$single.full_permutations_never_restoring_saved_evidence + $never)
            )
            foreach ($diff in $subsetDiffs) {
                if ($diff -lt 0 -or ($N -eq 4 -and $diff -ne 0)) {
                    throw 'Code Sequence zero/one/two-intervening stages do not fit EC-076 original pair precedence.'
                }
            }
            $gcdP = Get-CodeSequenceRetentionOrderGcd -A $byP -B $twoMiddleUniverse
            $gcdR = Get-CodeSequenceRetentionOrderGcd -A $byFirst -B $twoMiddleUniverse
            $gcdS = Get-CodeSequenceRetentionOrderGcd -A $bySecond -B $twoMiddleUniverse
            $gcdQ = Get-CodeSequenceRetentionOrderGcd -A $byQ -B $twoMiddleUniverse
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                number_of_ordered_distinct_original_middle_identity_pairs = ($N - 2) * ($N - 3)
                exact_full_permutations_with_exactly_two_original_reports_between_pair = $twoMiddleUniverse
                full_permutations_first_restoring_before_first_report = $beforeP
                full_permutations_first_restored_by_first_report = $byP
                full_permutations_first_restored_by_first_intervening_original_report = $byFirst
                full_permutations_first_restored_by_second_intervening_original_report = $bySecond
                full_permutations_first_restored_by_second_report = $byQ
                full_permutations_first_restoring_after_second_report = $afterQ
                full_permutations_never_restoring_saved_evidence = $never
                first_restored_by_first_intervening_original_caller_position_counts = $byFirstPosition
                first_restored_by_second_intervening_original_caller_position_counts = $bySecondPosition
                exact_reduced_by_first_report_fraction_numerator = [long]($byP / $gcdP)
                exact_reduced_by_first_report_fraction_denominator = [long]($twoMiddleUniverse / $gcdP)
                exact_reduced_by_first_intervening_report_fraction_numerator = [long]($byFirst / $gcdR)
                exact_reduced_by_first_intervening_report_fraction_denominator = [long]($twoMiddleUniverse / $gcdR)
                exact_reduced_by_second_intervening_report_fraction_numerator = [long]($bySecond / $gcdS)
                exact_reduced_by_second_intervening_report_fraction_denominator = [long]($twoMiddleUniverse / $gcdS)
                exact_reduced_by_second_report_fraction_numerator = [long]($byQ / $gcdQ)
                exact_reduced_by_second_report_fraction_denominator = [long]($twoMiddleUniverse / $gcdQ)
            })
            $totals[0] += $beforeP
            $totals[1] += $byP
            $totals[2] += $byFirst
            $totals[3] += $bySecond
            $totals[4] += $byQ
            $totals[5] += $afterQ
            $totals[6] += $never
        }
    }
    if ($scenarios.Count -ne $eligibleDirected -or $pairIndex -ne $eligibleDirected) {
        throw 'Code Sequence two-intervening report miscounted original directed p/q identities.'
    }

    # Exact EC-075 fixed-rank margins: each ordering with original p at
    # rank j<=N-3 has exactly one q at j+3; conversely each q at rank j>=4
    # has exactly one p at j-3. No multiplicity factors or report reindexing.
    $rankChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentUniverse) {
                throw 'Code Sequence two-intervening report encountered modified EC-075 rank identities.'
            }
            $expectedPBefore = [long]0
            $expectedPBy = [long]0
            $expectedQBefore = [long]0
            $expectedQBy = [long]0
            if ($j -le $N - 3) {
                $expectedPBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -ge 4) {
                $expectedQBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedQBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedPBefore -or
                $byPRank[$idx] -ne $expectedPBy -or
                $beforeQRank[$idx] -ne $expectedQBefore -or
                $byQRank[$idx] -ne $expectedQBy) {
                throw 'Code Sequence two-intervening report failed independent EC-075 exact four-rank-block margins.'
            }
        }
        $rankChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            number_of_original_rank_cases_reconciled = $N
        })
    }

    # Each complete ordering has N-3 contiguous four-report p,r,s,q blocks.
    # Independent EC-074 FIRST(t) supplies precise seven-stage incidence.
    $expected = [long[]]::new(7)
    $totalFirst = [long]0
    for ($t = 1; $t -le $N; $t++) {
        if ([int]$stepRows[$t].number_of_first_original_reports_retained -ne $t) {
            throw 'Code Sequence two-intervening report changed an EC-074 original FIRST step.'
        }
        $first = [long]$stepRows[$t].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence two-intervening report received negative EC-074 FIRST mass.' }
        $expected[0] += [long][Math]::Max(0, $N - $t - 3) * $first
        if ($t -le $N - 3) { $expected[1] += $first }
        if ($t -ge 2 -and $t -le $N - 2) { $expected[2] += $first }
        if ($t -ge 3 -and $t -le $N - 1) { $expected[3] += $first }
        if ($t -ge 4) { $expected[4] += $first }
        $expected[5] += [long][Math]::Max(0, $t - 4) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence two-intervening report violates EC-074 total supported full orders.'
    }
    $totalIncidences = [long]([Math]::Max(0, $N - 3)) * $permutations
    if (-not $hasFullSupport) { $expected[6] = $totalIncidences }
    for ($i = 0; $i -lt 7; $i++) {
        if ($totals[$i] -ne $expected[$i]) {
            throw 'Code Sequence two-intervening report failed independent EC-074 exact seven-stage FIRST conservation.'
        }
    }
    if ($totals[0] + $totals[1] + $totals[2] + $totals[3] + $totals[4] + $totals[5] + $totals[6] -ne $totalIncidences) {
        throw 'Code Sequence two-intervening report lost original contiguous four-report incidences.'
    }
    return [ordered]@{
        original_positions_in_two_intervening_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_pair_with_two_intervening_original_reports = $twoMiddleUniverse
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_original_report_pair_double_intervening_scenarios = $scenarios.ToArray()
        original_position_three_rank_offset_margins_against_ec075 = $rankChecks.ToArray()
        independent_ec074_first_support_step_double_intervening_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_first_intervening_original_report = $totals[2]
            full_permutations_first_restored_by_second_intervening_original_report = $totals[3]
            full_permutations_first_restored_by_second_report = $totals[4]
            full_permutations_first_restoring_after_second_report = $totals[5]
            full_permutations_never_restoring_saved_evidence = $totals[6]
            expected_total_double_intervening_pair_occurrences_across_all_orderings = $totalIncidences
        }
        every_directed_pair_double_intervening_case_has_seven_disjoint_exhaustive_first_support_categories = $true
        both_middle_original_identity_attributions_sum_to_their_exact_first_support_stages = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_three_rank_offset_margin_matches_independent_ec075_fixed_rank = $true
        adjacent_one_middle_and_two_middle_cases_are_disjoint_subsets_of_ec076_precedence = $true
        all_seven_double_intervening_first_support_categories_match_independent_ec074_step_counts = $true
        original_n2_n3_have_no_eligible_double_intervening_pair = ($N -lt 4)
        hypothetical_two_intervening_gap_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairDoubleIntervening {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency,
        [object] $RetentionPairSingleIntervening
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or $null -eq $RetentionPairAdjacency -or
        $null -eq $RetentionPairSingleIntervening -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        $RetentionPairAdjacency.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair' -or
        $RetentionPairSingleIntervening.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_single_intervening_original_report_between_ordered_pair' -or
        -not [bool]$RetentionPairSingleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairSingleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization) {
        throw 'Code Sequence pair double-intervening requires the unchanged EC-072..078 original target registry.'
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
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairAdjacency.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairSingleIntervening.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairAdjacency.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairSingleIntervening.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $gCubes.Count -ne $gAdjacency.Count -or $gCubes.Count -ne $gSingle.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $fCubes.Count -ne $fAdjacency.Count -or $fCubes.Count -ne $fSingle.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount -or
        $familyAdjacency.Count -ne $familyCount -or $familySingle.Count -ne $familyCount) {
        throw 'Code Sequence pair double-intervening changed original genuine/frozen/family target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $neighbors = $gAdjacency
        $singles = $gSingle; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $neighbors = $fAdjacency
            $singles = $fSingle; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]
            $neighbor = $neighbors[$i]; $single = $singles[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $threshold -ne [int]$precedence.original_global_family_capacity_at_least -or
                $threshold -ne [int]$neighbor.original_global_family_capacity_at_least -or
                $threshold -ne [int]$single.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$neighbor.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$single.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair double-intervening changed original genuine/frozen capacity thresholds.'
            }
            $projection = Get-CodeSequenceRetentionPairDoubleInterveningProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence `
                -PairAdjacency $neighbor.exact_first_support_pair_adjacency `
                -PairSingleIntervening $single.exact_first_support_pair_single_intervening -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_double_intervening = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]; $neighbor = $familyAdjacency[$fi]
        $single = $familySingle[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$neighbor.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$single.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair double-intervening changed an individual ORIGINAL family ID.'
        }
        $g = Get-CodeSequenceRetentionPairDoubleInterveningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.genuine_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.genuine_original_first_support_pair_single_intervening -N $n
        $f = Get-CodeSequenceRetentionPairDoubleInterveningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.frozen_original_first_support_pair_adjacency `
            -PairSingleIntervening $single.frozen_original_first_support_pair_single_intervening -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_double_intervening = $g
            frozen_original_first_support_pair_double_intervening = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    $twoMiddleUniverse = [long]0
    if ($n -ge 4) { $twoMiddleUniverse = [long]($n - 3) * [long]$factorial[$n - 2] }
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_two_ordered_intervening_original_reports_between_ordered_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_original_pair_with_two_intervening_reports = $twoMiddleUniverse
            directed_original_report_double_intervening_scenarios_per_target = $(if ($n -lt 4) { 0 } else { $n * ($n - 1) })
            original_two_intervening_pair_occurrences_across_all_permutations_per_target = [long]([Math]::Max(0, $n - 3)) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_double_intervening = $gResult.ToArray()
        frozen_global_threshold_pair_double_intervening = $fResult.ToArray()
        individual_original_family_pair_double_intervening = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        original_n2_n3_have_no_eligible_double_intervening_pair = ($n -lt 4)
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_two_intervening_gap_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_two_intervening_gap_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

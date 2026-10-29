#requires -Version 7.0
<#
    EC-078: exact first ORIGINAL saved-witness restoration when two distinct
    ORIGINAL report identities p and q have EXACTLY ONE ORIGINAL report r
    between them in a hypothetical complete ordering: ... p,r,q ... .

    For fixed directed p/q, the middle identity is not fixed. There are
    (N-2)*(N-2)! compatible complete ORIGINAL orderings for N>=3. The
    six mutually exclusive first-support stages are before p, by p, by the
    single intervening original report, by q, after q, or never.

    For each original prefix M without p/q and candidate r outside M,
    weight the pattern M,p,r,q,remaining by |M|!*(N-|M|-3)!.
    Consume only already-validated EC-072 public original minimal retained
    bases, check EC-073 cardinality coverage, and independently conserve
    exact EC-075 fixed ranks, EC-074 first steps, EC-076 pair precedence and
    EC-077 adjacency plus this one-gap disjoint subset. The original frozen
    EC-056 full-selection optima are NEVER reoptimized. This is hypothetical
    ordering math, not historical chronology, inferred repair or probability.
#>

function Get-CodeSequenceRetentionPairSingleInterveningProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [object] $PairPrecedence,
        [object] $PairAdjacency,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        $null -eq $PairAdjacency -or
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
        -not [bool]$PairAdjacency.all_five_adjacent_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence single-intervening report requires complete EC-072/073/074/075/076/077 ORIGINAL evidence.'
    }
    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $adjacentUniverse = [long]$factorial[$N - 1]
    $precedenceUniverse = [long]($permutations / 2)
    $gapUniverse = [long]0
    if ($N -ge 3) { $gapUniverse = [long]($N - 2) * [long]$factorial[$N - 2] }
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $neighborRows = [object[]]$PairAdjacency.directed_immediate_original_report_pair_scenarios
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or
        $parentRows.Count -ne ($N * ($N - 1)) -or
        $neighborRows.Count -ne $parentRows.Count -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [int]$PairAdjacency.original_positions_in_adjacency_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairAdjacency.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedenceUniverse -or
        [long]$PairAdjacency.full_permutations_per_directed_immediate_report_pair -ne $adjacentUniverse -or
        [long]$FixedRank.complete_permutations_per_original_position_per_fixed_rank -ne $adjacentUniverse -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence single-intervening report encountered inconsistent original permutation universes.'
    }
    if ($adjacentUniverse + $gapUniverse -gt $precedenceUniverse -or
        ($N -eq 3 -and $adjacentUniverse + $gapUniverse -ne $precedenceUniverse)) {
        throw 'Code Sequence one-intervening and immediately adjacent universes are not disjoint precedence subsets.'
    }

    # Independently reconstruct support for all 2^N ORIGINAL retained masks,
    # using no EC-060 private histograms, record bodies, or new source reads.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence one-intervening report received a repeated or invalid public original witness basis.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence one-intervening report received nonminimal original witness bases.'
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
        $hasFullSupport -ne [bool]$PairAdjacency.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence one-intervening report changed ORIGINAL empty/full saved-evidence support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            $supportedByBudget[$k] -ne [int]$budgetRows[$k].subsets_preserving_original_witness_support) {
            throw 'Code Sequence one-intervening report disagrees with independent EC-073 original retained budgets.'
        }
    }

    # For each ORIGINAL p,q, sum over every eligible ORIGINAL intermediary
    # r and original prefix M. A single full ordering with q exactly two ranks
    # after p has exactly one (p,r,q); no ordering is double-counted.
    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(6)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $parentIndex = 0
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence one-intervening report changed an EC-075 original caller-position identity.'
        }
        if ($N -eq 2) { continue } # No valid middle report, no directed scenario.
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $beforeP = [long]0
            $byP = [long]0
            $byMiddle = [long]0
            $byQ = [long]0
            $byMiddlePosition = [long[]]::new($N)
            $m = $other
            if ($hasFullSupport) {
                while ($true) {
                    $k = $pop[$m]
                    $remainingMiddle = $other -bxor $m
                    $choices = $pop[$remainingMiddle]
                    if ($choices -gt 0) {
                        $withP = $m -bor $pBit
                        # k originals, p, one remaining r, q, then N-k-3.
                        $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 3]
                        $atBeforeP = [long]0
                        $atByP = [long]0
                        $atByMiddle = [long]0
                        $atByQ = [long]0
                        if ($hasEvidence[$m]) {
                            $atBeforeP = [long]$choices * $weight
                        }
                        elseif ($hasEvidence[$withP]) {
                            $atByP = [long]$choices * $weight
                        }
                        else {
                            # Identity-sensitive middle attribution: preserve
                            # the ORIGINAL r bit; never recode/reindex a report.
                            for ($r = 0; $r -lt $N; $r++) {
                                $rBit = 1 -shl $r
                                if (($remainingMiddle -band $rBit) -eq 0) { continue }
                                $withMiddle = $withP -bor $rBit
                                if ($hasEvidence[$withMiddle]) {
                                    $atByMiddle += $weight
                                    $byMiddlePosition[$r] += $weight
                                }
                                elseif ($hasEvidence[$withMiddle -bor $qBit]) {
                                    $atByQ += $weight
                                }
                            }
                        }
                        $beforeP += $atBeforeP
                        $byP += $atByP
                        $byMiddle += $atByMiddle
                        $byQ += $atByQ
                        # p is at k+1, q at k+3; one and only one p/r/q
                        # triple fits at each eligible rank for each ordering.
                        $beforePRank[$p * $N + $k] += $atBeforeP
                        $byPRank[$p * $N + $k] += $atByP
                        $beforeQRank[$q * $N + $k + 2] += $atBeforeP + $atByP + $atByMiddle
                        $byQRank[$q * $N + $k + 2] += $atByQ
                    }
                    if ($m -eq 0) { break }
                    $m = ($m - 1) -band $other
                }
            }
            $afterQ = [long]0
            $never = [long]0
            if ($hasFullSupport) { $afterQ = $gapUniverse - $beforeP - $byP - $byMiddle - $byQ }
            else { $never = $gapUniverse }
            $middleTotal = [long]0
            for ($r = 0; $r -lt $N; $r++) {
                if ($r -eq $p -or $r -eq $q) {
                    if ($byMiddlePosition[$r] -ne 0) {
                        throw 'Code Sequence one-intervening report assigned middle restoration to an endpoint.'
                    }
                }
                $middleTotal += $byMiddlePosition[$r]
            }
            if ($beforeP -lt 0 -or $byP -lt 0 -or $byMiddle -lt 0 -or $byQ -lt 0 -or
                $afterQ -lt 0 -or $never -lt 0 -or $middleTotal -ne $byMiddle -or
                $beforeP + $byP + $byMiddle + $byQ + $afterQ + $never -ne $gapUniverse) {
                throw 'Code Sequence one-intervening report violated its exact six-stage partition or middle identity.'
            }
            $parent = $parentRows[$parentIndex]
            $adjacent = $neighborRows[$parentIndex]
            $parentIndex++
            if ([int]$parent.first_original_caller_position -ne ($p + 1) -or
                [int]$parent.second_original_caller_position -ne ($q + 1) -or
                [int]$parent.first_original_position_bit -ne $pBit -or
                [int]$parent.second_original_position_bit -ne $qBit -or
                [int]$adjacent.first_original_caller_position -ne ($p + 1) -or
                [int]$adjacent.second_original_caller_position -ne ($q + 1) -or
                [int]$adjacent.first_original_position_bit -ne $pBit -or
                [int]$adjacent.second_original_position_bit -ne $qBit -or
                [long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedenceUniverse -or
                [long]$adjacent.exact_full_permutations_with_first_report_immediately_before_second -ne $adjacentUniverse -or
                $beforeP + [long]$adjacent.full_permutations_first_restoring_before_first_report -gt [long]$parent.full_permutations_first_restoring_before_first_report -or
                $byP + [long]$adjacent.full_permutations_first_restored_by_first_report -gt [long]$parent.full_permutations_first_restored_by_first_report -or
                $byMiddle -gt [long]$parent.full_permutations_first_restoring_strictly_between_reports -or
                $byQ + [long]$adjacent.full_permutations_first_restored_by_second_report -gt [long]$parent.full_permutations_first_restored_by_second_report -or
                $afterQ + [long]$adjacent.full_permutations_first_restoring_after_second_report -gt [long]$parent.full_permutations_first_restoring_after_second_report -or
                $never + [long]$adjacent.full_permutations_never_restoring_saved_evidence -gt [long]$parent.full_permutations_never_restoring_saved_evidence) {
                throw 'Code Sequence one-intervening and adjacent cases overlap or exceed EC-076 original precedence.'
            }
            if ($N -eq 3 -and (
                $beforeP + [long]$adjacent.full_permutations_first_restoring_before_first_report -ne [long]$parent.full_permutations_first_restoring_before_first_report -or
                $byP + [long]$adjacent.full_permutations_first_restored_by_first_report -ne [long]$parent.full_permutations_first_restored_by_first_report -or
                $byMiddle -ne [long]$parent.full_permutations_first_restoring_strictly_between_reports -or
                $byQ + [long]$adjacent.full_permutations_first_restored_by_second_report -ne [long]$parent.full_permutations_first_restored_by_second_report -or
                $afterQ + [long]$adjacent.full_permutations_first_restoring_after_second_report -ne [long]$parent.full_permutations_first_restoring_after_second_report -or
                $never + [long]$adjacent.full_permutations_never_restoring_saved_evidence -ne [long]$parent.full_permutations_never_restoring_saved_evidence)) {
                throw 'Code Sequence N3 precedence is not exactly adjacency plus one-intervening cases.'
            }
            $gcdP = Get-CodeSequenceRetentionOrderGcd -A $byP -B $gapUniverse
            $gcdMiddle = Get-CodeSequenceRetentionOrderGcd -A $byMiddle -B $gapUniverse
            $gcdQ = Get-CodeSequenceRetentionOrderGcd -A $byQ -B $gapUniverse
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                number_of_eligible_distinct_original_intervening_reports = $N - 2
                exact_full_permutations_with_exactly_one_original_report_between_pair = $gapUniverse
                full_permutations_first_restoring_before_first_report = $beforeP
                full_permutations_first_restored_by_first_report = $byP
                full_permutations_first_restored_by_single_intervening_original_report = $byMiddle
                full_permutations_first_restored_by_second_report = $byQ
                full_permutations_first_restoring_after_second_report = $afterQ
                full_permutations_never_restoring_saved_evidence = $never
                first_restored_by_intervening_original_caller_position_counts = $byMiddlePosition
                exact_reduced_by_first_report_fraction_numerator = [long]($byP / $gcdP)
                exact_reduced_by_first_report_fraction_denominator = [long]($gapUniverse / $gcdP)
                exact_reduced_by_intervening_report_fraction_numerator = [long]($byMiddle / $gcdMiddle)
                exact_reduced_by_intervening_report_fraction_denominator = [long]($gapUniverse / $gcdMiddle)
                exact_reduced_by_second_report_fraction_numerator = [long]($byQ / $gcdQ)
                exact_reduced_by_second_report_fraction_denominator = [long]($gapUniverse / $gcdQ)
            })
            $totals[0] += $beforeP
            $totals[1] += $byP
            $totals[2] += $byMiddle
            $totals[3] += $byQ
            $totals[4] += $afterQ
            $totals[5] += $never
        }
    }
    $expectedScenarios = if ($N -eq 2) { 0 } else { $N * ($N - 1) }
    if ($scenarios.Count -ne $expectedScenarios -or $parentIndex -ne $expectedScenarios) {
        throw 'Code Sequence one-intervening report changed original directed pair scenario indexing.'
    }

    # Independent EC-075 fixed-rank check. Every whole ordering with p at
    # rank j<=N-2 has exactly one q two positions later; every ordering with
    # q at j>=3 has exactly one p two positions earlier. No (N-j) multiplier.
    $positionChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentUniverse) {
                throw 'Code Sequence one-intervening report received an altered EC-075 original rank case.'
            }
            $expectedPBefore = [long]0
            $expectedPBy = [long]0
            $expectedQBefore = [long]0
            $expectedQBy = [long]0
            if ($j -le $N - 2) {
                $expectedPBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -ge 3) {
                $expectedQBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedQBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedPBefore -or
                $byPRank[$idx] -ne $expectedPBy -or
                $beforeQRank[$idx] -ne $expectedQBefore -or
                $byQRank[$idx] -ne $expectedQBy) {
                throw 'Code Sequence one-intervening report failed EC-075 exact two-position-offset rank margins.'
            }
        }
        $positionChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            number_of_original_rank_cases_reconciled = $N
        })
    }

    # In each original full ordering FIRST supported at step s, there are
    # exactly N-2 directed pairs with one report between them. Across them:
    # before-p max(N-s-2,0), by-p [s<=N-2], by-r [2<=s<=N-1],
    # by-q [s>=3], after-q max(s-3,0); unsupported contributes only never.
    $expected = [long[]]::new(6)
    $totalFirst = [long]0
    for ($s = 1; $s -le $N; $s++) {
        if ([int]$stepRows[$s].number_of_first_original_reports_retained -ne $s) {
            throw 'Code Sequence one-intervening report lost an original EC-074 step identity.'
        }
        $first = [long]$stepRows[$s].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence one-intervening report encountered negative EC-074 restoration.' }
        $expected[0] += [long][Math]::Max(0, $N - $s - 2) * $first
        if ($s -le $N - 2) { $expected[1] += $first }
        if ($s -ge 2 -and $s -le $N - 1) { $expected[2] += $first }
        if ($s -ge 3) { $expected[3] += $first }
        $expected[4] += [long][Math]::Max(0, $s - 3) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence one-intervening report mismatches the EC-074 full-ordering support boundary.'
    }
    $totalGapIncidences = [long]($N - 2) * $permutations
    if (-not $hasFullSupport) { $expected[5] = $totalGapIncidences }
    for ($i = 0; $i -lt 6; $i++) {
        if ($totals[$i] -ne $expected[$i]) {
            throw 'Code Sequence one-intervening report failed independent EC-074 gap-one FIRST-step conservation.'
        }
    }
    if ($totals[0] + $totals[1] + $totals[2] + $totals[3] + $totals[4] + $totals[5] -ne $totalGapIncidences) {
        throw 'Code Sequence one-intervening report lost exact one-gap pair occurrences.'
    }
    return [ordered]@{
        original_positions_in_single_intervening_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_pair_with_one_intervening_original_report = $gapUniverse
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_original_report_pair_single_intervening_scenarios = $scenarios.ToArray()
        original_position_two_rank_offset_margins_against_ec075 = $positionChecks.ToArray()
        independent_ec074_first_support_step_single_intervening_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_single_intervening_original_report = $totals[2]
            full_permutations_first_restored_by_second_report = $totals[3]
            full_permutations_first_restoring_after_second_report = $totals[4]
            full_permutations_never_restoring_saved_evidence = $totals[5]
            expected_total_one_intervening_report_pair_occurrences_across_all_orderings = $totalGapIncidences
        }
        each_directed_pair_single_intervening_case_has_six_disjoint_exhaustive_first_support_categories = $true
        every_original_middle_position_attribution_sums_exactly_to_first_by_middle = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_two_rank_offset_margin_matches_independent_ec075_fixed_rank = $true
        each_one_intervening_and_adjacent_scenario_disjoint_within_ec076_precedence = $true
        all_six_one_intervening_first_support_categories_match_independent_ec074_step_counts = $true
        original_n2_has_no_eligible_single_intervening_pair = ($N -eq 2)
        hypothetical_one_intervening_gap_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairSingleIntervening {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or $null -eq $RetentionPairAdjacency -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        $RetentionPairAdjacency.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair' -or
        -not [bool]$RetentionPairAdjacency.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairPrecedence.independent_of_sequence_top_and_original_finding_seed_side) {
        throw 'Code Sequence pair single-intervening requires the complete unchanged EC-072/073/074/075/076/077 target registry.'
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
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairAdjacency.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairAdjacency.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $gCubes.Count -ne $gAdjacency.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $fCubes.Count -ne $fAdjacency.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount -or
        $familyAdjacency.Count -ne $familyCount) {
        throw 'Code Sequence pair single-intervening encountered changed original genuine/frozen/family indexing.'
    }
    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $neighbors = $gAdjacency; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $neighbors = $fAdjacency; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]; $neighbor = $neighbors[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $threshold -ne [int]$precedence.original_global_family_capacity_at_least -or
                $threshold -ne [int]$neighbor.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$neighbor.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair single-intervening changed an original genuine/frozen global threshold.'
            }
            $projection = Get-CodeSequenceRetentionPairSingleInterveningProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence `
                -PairAdjacency $neighbor.exact_first_support_pair_adjacency -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_single_intervening = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]; $neighbor = $familyAdjacency[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$neighbor.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair single-intervening changed an original individual repeat-family identity.'
        }
        $g = Get-CodeSequenceRetentionPairSingleInterveningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.genuine_original_first_support_pair_adjacency -N $n
        $f = Get-CodeSequenceRetentionPairSingleInterveningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence `
            -PairAdjacency $neighbor.frozen_original_first_support_pair_adjacency -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_single_intervening = $g
            frozen_original_first_support_pair_single_intervening = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_single_intervening_original_report_between_ordered_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_original_pair_with_one_intervening_report = [long]([Math]::Max(0, $n - 2)) * [long]$factorial[$n - 2]
            directed_original_report_single_intervening_scenarios_per_target = $(if ($n -eq 2) { 0 } else { $n * ($n - 1) })
            original_one_intervening_pair_occurrences_across_all_permutations_per_target = [long]($n - 2) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_single_intervening = $gResult.ToArray()
        frozen_global_threshold_pair_single_intervening = $fResult.ToArray()
        individual_original_family_pair_single_intervening = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        original_n2_has_no_eligible_single_intervening_pair = ($n -eq 2)
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_one_intervening_gap_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_one_intervening_gap_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

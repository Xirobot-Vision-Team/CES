#requires -Version 7.0
<#
    EC-077: first ORIGINAL saved-witness restoration conditioned on two
    DISTINCT ORIGINAL report identities p and q appearing IMMEDIATELY
    consecutively, with p directly before q (no intermediate report).

    Each directed adjacency has exactly (N-1)! complete hypothetical original
    report permutations. Decompose them by the original subset M before p:
    w(M)=|M|!*(N-|M|-2)!, then p, q, and all remaining originals.
    The first original saved evidence appears before p, by p, by q, after q,
    or never. No intermediate category is possible for adjacent positions.

    Reconstruct the monotone support predicate only from checked public
    EC-072 inclusion-minimal ORIGINAL retained bases, recheck EC-073 original
    retained budgets, independently conserve EC-075 rank-specific margins,
    EC-074 first-step totals and subset bounds of EC-076 precedence results.
    EC-056 original-frozen capacity stays frozen. No new selectors, history,
    saved quote/source/Git/network reads, or business worktree writes.
#>

function Get-CodeSequenceRetentionPairAdjacencyProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [object] $PairPrecedence,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or $null -eq $PairPrecedence -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable -or
        -not [bool]$RetentionCube.ec072_exact_minimal_original_retained_bases_reconciled -or
        -not [bool]$RetentionCube.all_original_budget_edge_conservation_identities_verified -or
        -not [bool]$RetentionOrder.all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported -or
        -not [bool]$FixedRank.all_fixed_position_rank_cases_partition_into_before_by_after_or_never -or
        -not [bool]$FixedRank.all_rank_wide_margins_reconcile_independent_ec074_complete_permutations -or
        -not [bool]$PairPrecedence.every_ordered_report_pair_has_six_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairPrecedence.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage -or
        -not [bool]$PairPrecedence.every_original_position_precedence_margin_matches_ec075_fixed_rank -or
        -not [bool]$PairPrecedence.all_six_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence pair adjacency requires completed EC-072/073/074/075/076 ORIGINAL evidence.'
    }
    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $adjacentPermutations = [long]$factorial[$N - 1]
    $precedencePermutations = [long]($permutations / 2)
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne ($N + 1) -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne ($N + 1) -or $parentRows.Count -ne ($N * ($N - 1)) -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $permutations -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $precedencePermutations -or
        [long]$FixedRank.complete_permutations_per_original_position_per_fixed_rank -ne $adjacentPermutations -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence pair adjacency received inconsistent original report or permutation universes.'
    }

    # Reconstruct every original retained-mask support state independently.
    # An antichain of REAL public EC-072 minimal support bases is mandatory.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence pair adjacency received an invalid or repeated original support basis.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence pair adjacency received nonminimal original retained support bases.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $supportedByBudget = [int[]]::new($N + 1)
    for ($mask = 0; $mask -lt $size; $mask++) {
        if ($mask -gt 0) { $pop[$mask] = $pop[$mask -shr 1] + ($mask -band 1) }
        if (-not $hasEvidence[$mask]) {
            for ($p = 0; $p -lt $N; $p++) {
                $bit = 1 -shl $p
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
        $hasFullSupport -ne [bool]$PairPrecedence.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence pair adjacency changed the real original empty/full support boundary.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            $supportedByBudget[$k] -ne [int]$budgetRows[$k].subsets_preserving_original_witness_support) {
            throw 'Code Sequence pair adjacency public EC-072 closure disagrees with independent EC-073 budgets.'
        }
    }

    # At p fixed at rank j<N, exactly one other report is immediately NEXT.
    # At q fixed at rank j>1, exactly one other report is immediately PRIOR.
    # Aggregate identities/ranks independently of the preceding EC-076 result.
    $beforePRank = [long[]]::new($N * $N)
    $byPRank = [long[]]::new($N * $N)
    $beforeQRank = [long[]]::new($N * $N)
    $byQRank = [long[]]::new($N * $N)
    $totals = [long[]]::new(5)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    $parentIndex = 0
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $pRank = $rankPositions[$p]
        if ([int]$pRank.original_caller_position -ne ($p + 1) -or
            [int]$pRank.original_position_bit -ne $pBit -or
            ([object[]]$pRank.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence pair adjacency lost an EC-075 original caller-position identity.'
        }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $beforeP = [long]0
            $byP = [long]0
            $byQ = [long]0
            $m = $other
            while ($true) {
                $k = $pop[$m]
                $withP = $m -bor $pBit
                $withPQ = $withP -bor $qBit
                # k originals before p, then p directly followed by q;
                # all remaining N-k-2 originals occur after q.
                $weight = [long]$factorial[$k] * [long]$factorial[$N - $k - 2]
                $before = [long]0
                $first = [long]0
                $second = [long]0
                if ($hasEvidence[$m]) { $before = $weight }
                elseif ($hasEvidence[$withP]) { $first = $weight }
                elseif ($hasEvidence[$withPQ]) { $second = $weight }
                $beforeP += $before
                $byP += $first
                $byQ += $second
                $beforePRank[$p * $N + $k] += $before
                $byPRank[$p * $N + $k] += $first
                $beforeQRank[$q * $N + $k + 1] += $before + $first
                $byQRank[$q * $N + $k + 1] += $second
                if ($m -eq 0) { break }
                $m = ($m - 1) -band $other
            }
            $afterQ = [long]0
            $never = [long]0
            if ($hasFullSupport) { $afterQ = $adjacentPermutations - $beforeP - $byP - $byQ }
            else { $never = $adjacentPermutations }
            if ($beforeP -lt 0 -or $byP -lt 0 -or $byQ -lt 0 -or $afterQ -lt 0 -or
                $never -lt 0 -or $beforeP + $byP + $byQ + $afterQ + $never -ne $adjacentPermutations) {
                throw 'Code Sequence pair adjacency violated its five-state exact ordering partition.'
            }
            $parent = $parentRows[$parentIndex]
            $parentIndex++
            if ([int]$parent.first_original_caller_position -ne ($p + 1) -or
                [int]$parent.second_original_caller_position -ne ($q + 1) -or
                [int]$parent.first_original_position_bit -ne $pBit -or
                [int]$parent.second_original_position_bit -ne $qBit -or
                [long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $precedencePermutations -or
                $beforeP -gt [long]$parent.full_permutations_first_restoring_before_first_report -or
                $byP -gt [long]$parent.full_permutations_first_restored_by_first_report -or
                $byQ -gt [long]$parent.full_permutations_first_restored_by_second_report -or
                $afterQ -gt [long]$parent.full_permutations_first_restoring_after_second_report -or
                $never -gt [long]$parent.full_permutations_never_restoring_saved_evidence) {
                throw 'Code Sequence pair adjacency is not an original-identity-preserving subset of EC-076 precedence.'
            }
            $gcdP = Get-CodeSequenceRetentionOrderGcd -A $byP -B $adjacentPermutations
            $gcdQ = Get-CodeSequenceRetentionOrderGcd -A $byQ -B $adjacentPermutations
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                exact_full_permutations_with_first_report_immediately_before_second = $adjacentPermutations
                full_permutations_first_restoring_before_first_report = $beforeP
                full_permutations_first_restored_by_first_report = $byP
                full_permutations_first_restored_by_second_report = $byQ
                full_permutations_first_restoring_after_second_report = $afterQ
                full_permutations_never_restoring_saved_evidence = $never
                exact_reduced_by_first_report_fraction_numerator = [long]($byP / $gcdP)
                exact_reduced_by_first_report_fraction_denominator = [long]($adjacentPermutations / $gcdP)
                exact_reduced_by_second_report_fraction_numerator = [long]($byQ / $gcdQ)
                exact_reduced_by_second_report_fraction_denominator = [long]($adjacentPermutations / $gcdQ)
            })
            $totals[0] += $beforeP
            $totals[1] += $byP
            $totals[2] += $byQ
            $totals[3] += $afterQ
            $totals[4] += $never
        }
    }
    if ($parentIndex -ne $parentRows.Count -or $scenarios.Count -ne ($N * ($N - 1))) {
        throw 'Code Sequence pair adjacency lost an original ordered pair or altered its EC-076 indexing.'
    }

    # Independent EC-075 check: every complete hypothetical ordering where
    # p is at j<N is counted exactly ONCE as (p, its next report); similarly
    # every ordering with q at j>1 is counted ONCE as (its prior report, q).
    $positionChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            $idx = $p * $N + $j - 1
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $adjacentPermutations) {
                throw 'Code Sequence pair adjacency found an altered EC-075 original fixed-rank case.'
            }
            $expectedPriorBefore = [long]0
            $expectedPriorBy = [long]0
            $expectedNextBefore = [long]0
            $expectedNextBy = [long]0
            if ($j -lt $N) {
                $expectedNextBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedNextBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($j -gt 1) {
                $expectedPriorBefore = [long]$case.full_permutations_first_restoring_before_this_position
                $expectedPriorBy = [long]$case.full_permutations_first_restored_by_this_position
            }
            if ($beforePRank[$idx] -ne $expectedNextBefore -or
                $byPRank[$idx] -ne $expectedNextBy -or
                $beforeQRank[$idx] -ne $expectedPriorBefore -or
                $byQRank[$idx] -ne $expectedPriorBy) {
                throw 'Code Sequence pair adjacency disagreed with independent EC-075 fixed-rank immediate-neighbor margins.'
            }
        }
        $positionChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            rank_cases_reconciled_as_immediate_first_or_second_report = $N
        })
    }

    # An ordering whose first support is at step s contains precisely N-1
    # adjacent ordered pairs. Before p: max(N-s-1,0); by p: [s<N]; by q:
    # [s>1]; after q: max(s-2,0). No strictly-between stage is possible.
    $expected = [long[]]::new(5)
    $totalFirst = [long]0
    for ($s = 1; $s -le $N; $s++) {
        if ([int]$stepRows[$s].number_of_first_original_reports_retained -ne $s) {
            throw 'Code Sequence pair adjacency received an altered EC-074 step identity.'
        }
        $first = [long]$stepRows[$s].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence pair adjacency received negative EC-074 counts.' }
        $expected[0] += ([long][Math]::Max(0, $N - $s - 1)) * $first
        if ($s -lt $N) { $expected[1] += $first }
        if ($s -gt 1) { $expected[2] += $first }
        $expected[3] += ([long][Math]::Max(0, $s - 2)) * $first
        $totalFirst += $first
    }
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence pair adjacency disagreed with EC-074 full-ordering support.'
    }
    if (-not $hasFullSupport) { $expected[4] = [long]($N - 1) * $permutations }
    for ($c = 0; $c -lt 5; $c++) {
        if ($totals[$c] -ne $expected[$c]) {
            throw 'Code Sequence pair adjacency failed independent EC-074 adjacent-first-step conservation.'
        }
    }
    $allAdjacentPairOrderings = [long]($N - 1) * $permutations
    if (($totals[0] + $totals[1] + $totals[2] + $totals[3] + $totals[4]) -ne $allAdjacentPairOrderings) {
        throw 'Code Sequence pair adjacency lost complete directed adjacent report pairs.'
    }
    return [ordered]@{
        original_positions_in_adjacency_universe = $N
        total_distinct_full_original_permutations = $permutations
        full_permutations_per_directed_immediate_report_pair = $adjacentPermutations
        full_original_selection_has_saved_witness_support = $hasFullSupport
        directed_immediate_original_report_pair_scenarios = $scenarios.ToArray()
        original_position_immediate_neighbor_rank_margins_against_ec075 = $positionChecks.ToArray()
        independent_ec074_first_support_step_adjacency_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $totals[0]
            full_permutations_first_restored_by_first_report = $totals[1]
            full_permutations_first_restored_by_second_report = $totals[2]
            full_permutations_first_restoring_after_second_report = $totals[3]
            full_permutations_never_restoring_saved_evidence = $totals[4]
            expected_total_adjacent_pairs_across_all_hypothetical_original_orderings = $allAdjacentPairOrderings
        }
        each_directed_immediate_report_pair_has_five_disjoint_exhaustive_first_support_categories = $true
        no_original_report_can_first_restore_strictly_between_immediately_adjacent_reports = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_immediate_neighbor_rank_margin_matches_independent_ec075_fixed_rank = $true
        every_adjacency_scenario_is_a_subset_of_original_ec076_precedence = $true
        all_five_adjacent_first_support_categories_match_independent_ec074_step_counts = $true
        pair_adjacency_is_not_authenticated_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairAdjacency {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning,
        [object] $RetentionPairPrecedence
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $null -eq $RetentionPairPrecedence -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        $RetentionPairPrecedence.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence' -or
        -not [bool]$RetentionPairPrecedence.independent_of_sequence_top_and_original_finding_seed_side) {
        throw 'Code Sequence pair adjacency requires the complete unchanged EC-072/073/074/075/076 target registry.'
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
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $gCubes.Count -ne $gRank.Count -or $gCubes.Count -ne $gPrecedence.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $fCubes.Count -ne $fRank.Count -or $fCubes.Count -ne $fPrecedence.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount -or
        $familyPrecedence.Count -ne $familyCount) {
        throw 'Code Sequence pair adjacency encountered changed original genuine/frozen/family indexing.'
    }
    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders
        $ranks = $gRank; $precedences = $gPrecedence; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders
            $ranks = $fRank; $precedences = $fPrecedence; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]; $basis = $bases[$i]; $order = $orders[$i]
            $rank = $ranks[$i]; $precedence = $precedences[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $threshold -ne [int]$precedence.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$precedence.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair adjacency changed an original genuine/frozen global threshold.'
            }
            $projection = Get-CodeSequenceRetentionPairAdjacencyProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning `
                -PairPrecedence $precedence.exact_first_support_pair_precedence -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_adjacency = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]; $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]; $rank = $familyRank[$fi]
        $precedence = $familyPrecedence[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$precedence.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair adjacency changed an original individual repeat-family identity.'
        }
        $g = Get-CodeSequenceRetentionPairAdjacencyProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.genuine_original_first_support_pair_precedence -N $n
        $f = Get-CodeSequenceRetentionPairAdjacencyProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning `
            -PairPrecedence $precedence.frozen_original_first_support_pair_precedence -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_adjacency = $g
            frozen_original_first_support_pair_adjacency = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_immediately_adjacent_ordered_report_pair'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_directed_immediate_original_pair = [long]$factorial[$n - 1]
            directed_original_report_adjacency_scenarios_per_target = $n * ($n - 1)
            original_adjacent_pair_occurrences_across_all_permutations_per_target = [long]($n - 1) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_adjacency = $gResult.ToArray()
        frozen_global_threshold_pair_adjacency = $fResult.ToArray()
        individual_original_family_pair_adjacency = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_adjacency_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_adjacency_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

#requires -Version 7.0
<#
    EC-076: exact first ORIGINAL saved-witness support CONDITIONED on the
    relative precedence of two distinct ORIGINAL report identities p and q.

    For every ordered p != q, enumerate the N!/2 complete hypothetical
    orderings where p occurs before q. Partition first support into before p,
    by p, strictly between p and q, by q, after q, or never. Sum supported
    ORIGINAL prefix subsets using exact factorial weights (no permutation
    sampling), then independently reconcile every EC-075 fixed-rank margin
    and all five EC-074 first-support-step combinatorial margins.

    The checked EC-072 minimal retained ORIGINAL bases are the only support
    source in this projection; compare the independently reconstructed 2^N
    predicate against actual EC-073 budget coverage. ORIGINAL EC-056 frozen
    full-selection packing evidence stays frozen. No quote/source/network/Git
    reads, no record changes, no change to selectors, and no chronology claim.
#>

function Get-CodeSequenceRetentionPairPrecedenceProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [object] $FixedRank,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        $null -eq $FixedRank -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable -or
        -not [bool]$RetentionCube.ec072_exact_minimal_original_retained_bases_reconciled -or
        -not [bool]$RetentionCube.all_original_budget_edge_conservation_identities_verified -or
        -not [bool]$RetentionOrder.all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported -or
        -not [bool]$FixedRank.all_fixed_position_rank_cases_partition_into_before_by_after_or_never -or
        -not [bool]$FixedRank.all_rank_wide_margins_reconcile_independent_ec074_complete_permutations) {
        throw 'Code Sequence pair precedence requires complete verified EC-072/073/074/075 ORIGINAL evidence.'
    }
    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $half = [long]($permutations / 2)
    $fixedRankPermutations = [long]$factorial[$N - 1]
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $budgetRows = [object[]]$RetentionCube.retained_original_budget_coverage
    $rankPositions = [object[]]$FixedRank.original_position_conditioned_on_fixed_hypothetical_rank
    $stepRows = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count -or
        $budgetRows.Count -ne $N + 1 -or $rankPositions.Count -ne $N -or
        $stepRows.Count -ne $N + 1 -or
        [int]$FixedRank.original_positions_in_fixed_ordering_universe -ne $N -or
        [long]$FixedRank.total_distinct_full_original_permutations -ne $permutations -or
        [long]$FixedRank.complete_permutations_per_original_position_per_fixed_rank -ne $fixedRankPermutations -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations) {
        throw 'Code Sequence pair precedence found changed ORIGINAL identity, cube or ordering denominators.'
    }

    # Independent public-basis upward closure. No private EC-060 witness
    # histogram access. A strict antichain prevents an accidental inflated
    # or duplicate support certificate from silently changing this result.
    $hasEvidence = [bool[]]::new($size)
    foreach ($base in $bases) {
        if ($base -le 0 -or $base -gt $full -or $hasEvidence[$base]) {
            throw 'Code Sequence pair precedence received invalid or duplicated ORIGINAL minimal retained bases.'
        }
        $hasEvidence[$base] = $true
    }
    for ($i = 0; $i -lt $bases.Count; $i++) {
        for ($j = $i + 1; $j -lt $bases.Count; $j++) {
            if ((($bases[$i] -band $bases[$j]) -eq $bases[$i]) -or
                (($bases[$i] -band $bases[$j]) -eq $bases[$j])) {
                throw 'Code Sequence pair precedence received a nonminimal ORIGINAL retained support basis.'
            }
        }
    }
    $pop = [int[]]::new($size)
    $supportedByBudget = [int[]]::new($N + 1)
    for ($mask = 0; $mask -lt $size; $mask++) {
        if ($mask -gt 0) {
            $pop[$mask] = $pop[$mask -shr 1] + ($mask -band 1)
        }
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
        $hasFullSupport -ne [bool]$FixedRank.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence pair precedence disagreed with genuine ORIGINAL empty/full witness support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ([int]$budgetRows[$k].number_of_retained_original_positions -ne $k -or
            $supportedByBudget[$k] -ne [int]$budgetRows[$k].subsets_preserving_original_witness_support) {
            throw 'Code Sequence pair precedence minimal-basis reconstruction disagrees with independent EC-073 coverage.'
        }
    }

    # First index is the original caller position, second index is the
    # *OTHER* original report forced to appear later/earlier. Exactly N*(N-1)
    # ordered scenarios; never emit a same-report pseudo-comparison.
    $beforeFirstByP = [long[]]::new($N)
    $byFirstByP = [long[]]::new($N)
    $beforeSecondByQ = [long[]]::new($N)
    $bySecondByQ = [long[]]::new($N)
    $sum = [long[]]::new(6)
    $scenarios = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $pBit = 1 -shl $p
        $rankP = $rankPositions[$p]
        if ([int]$rankP.original_caller_position -ne $p + 1 -or
            [int]$rankP.original_position_bit -ne $pBit -or
            ([object[]]$rankP.scenarios_by_fixed_hypothetical_rank).Count -ne $N) {
            throw 'Code Sequence pair precedence changed an EC-075 ORIGINAL report-position identity.'
        }
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $qBit = 1 -shl $q
            $other = $full -bxor ($pBit -bor $qBit)
            $beforeP = [long]0
            $byP = [long]0
            $beforeQ = [long]0
            $byQ = [long]0

            # Every prefix K of positions other than p,q occurs exactly once:
            #   p immediately after K, with q later: |K|!*(N-|K|-1)!
            #   q immediately after K + p: (|K|+1)!*(N-|K|-2)!
            # Only true, original supported masks are counted. The two
            # formulas are independent prefix decompositions of p-before-q.
            $m = $other
            while ($true) {
                $k = $pop[$m]
                $withP = $m -bor $pBit
                $withPQ = $withP -bor $qBit
                $wP = [long]$factorial[$k] * [long]$factorial[$N - $k - 1]
                $wQ = [long]$factorial[$k + 1] * [long]$factorial[$N - $k - 2]
                if ($hasEvidence[$m]) { $beforeP += $wP }
                if (-not $hasEvidence[$m] -and $hasEvidence[$withP]) { $byP += $wP }
                if ($hasEvidence[$withP]) { $beforeQ += $wQ }
                if (-not $hasEvidence[$withP] -and $hasEvidence[$withPQ]) { $byQ += $wQ }
                if ($m -eq 0) { break }
                $m = ($m - 1) -band $other
            }
            $between = $beforeQ - $beforeP - $byP
            $afterQ = [long]0
            $never = [long]0
            if ($hasFullSupport) { $afterQ = $half - $beforeQ - $byQ }
            else { $never = $half }
            if ($beforeP -lt 0 -or $byP -lt 0 -or $between -lt 0 -or
                $byQ -lt 0 -or $afterQ -lt 0 -or $never -lt 0 -or
                $beforeP + $byP + $between + $byQ + $afterQ + $never -ne $half) {
                throw 'Code Sequence pair precedence violated its exact six-way ORIGINAL ordering partition.'
            }
            $gcdP = Get-CodeSequenceRetentionOrderGcd -A $byP -B $half
            $gcdQ = Get-CodeSequenceRetentionOrderGcd -A $byQ -B $half
            $scenarios.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                exact_complete_permutations_with_first_original_report_before_second = $half
                full_permutations_first_restoring_before_first_report = $beforeP
                full_permutations_first_restored_by_first_report = $byP
                full_permutations_first_restoring_strictly_between_reports = $between
                full_permutations_first_restored_by_second_report = $byQ
                full_permutations_first_restoring_after_second_report = $afterQ
                full_permutations_never_restoring_saved_evidence = $never
                exact_reduced_by_first_report_fraction_numerator = [long]($byP / $gcdP)
                exact_reduced_by_first_report_fraction_denominator = [long]($half / $gcdP)
                exact_reduced_by_second_report_fraction_numerator = [long]($byQ / $gcdQ)
                exact_reduced_by_second_report_fraction_denominator = [long]($half / $gcdQ)
            })
            $beforeFirstByP[$p] += $beforeP
            $byFirstByP[$p] += $byP
            $beforeSecondByQ[$q] += $beforeQ
            $bySecondByQ[$q] += $byQ
            $sum[0] += $beforeP
            $sum[1] += $byP
            $sum[2] += $between
            $sum[3] += $byQ
            $sum[4] += $afterQ
            $sum[5] += $never
        }
    }

    # Independent conditional margins: in a fixed-rank j ordering there are
    # exactly N-j distinct choices for q AFTER p, and j-1 choices for p
    # BEFORE q. A single EC-075 rank cell has (N-1)! complete orderings.
    # These comparisons detect wrong orientation/position indexing even when
    # individual six-way rows happen to sum to N!/2.
    $positionChecks = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $rankCases = [object[]]$rankPositions[$p].scenarios_by_fixed_hypothetical_rank
        $expectedBeforeFirst = [long]0
        $expectedByFirst = [long]0
        $expectedBeforeSecond = [long]0
        $expectedBySecond = [long]0
        for ($j = 1; $j -le $N; $j++) {
            $case = $rankCases[$j - 1]
            if ([int]$case.original_report_fixed_at_hypothetical_rank -ne $j -or
                [long]$case.exact_full_permutations_with_this_report_fixed_at_rank -ne $fixedRankPermutations) {
                throw 'Code Sequence pair precedence found an altered EC-075 rank case.'
            }
            $before = [long]$case.full_permutations_first_restoring_before_this_position
            $by = [long]$case.full_permutations_first_restored_by_this_position
            $expectedBeforeFirst += [long]($N - $j) * $before
            $expectedByFirst += [long]($N - $j) * $by
            $expectedBeforeSecond += [long]($j - 1) * $before
            $expectedBySecond += [long]($j - 1) * $by
        }
        if ($beforeFirstByP[$p] -ne $expectedBeforeFirst -or
            $byFirstByP[$p] -ne $expectedByFirst -or
            $beforeSecondByQ[$p] -ne $expectedBeforeSecond -or
            $bySecondByQ[$p] -ne $expectedBySecond) {
            throw 'Code Sequence pair precedence disagreed with independently fixed EC-075 report-rank margins.'
        }
        $positionChecks.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            across_all_later_reports_first_support_before_this_report = $beforeFirstByP[$p]
            across_all_later_reports_first_support_by_this_report = $byFirstByP[$p]
            across_all_earlier_reports_first_support_before_this_report = $beforeSecondByQ[$p]
            across_all_earlier_reports_first_support_by_this_report = $bySecondByQ[$p]
        })
    }

    # Independent complete-ordering ledger: a permutation with first support
    # at step s contributes C(N-s,2) pairs BOTH AFTER the event (before p),
    # N-s event-at-p pairs, (s-1)*(N-s) strictly straddling pairs, s-1
    # event-at-q pairs, and C(s-1,2) pairs BOTH BEFORE the event (after q).
    # Exactly C(N,2) correctly oriented report pairs exist per permutation.
    $expected = [long[]]::new(6)
    $totalFirst = [long]0
    for ($s = 1; $s -le $N; $s++) {
        if ([int]$stepRows[$s].number_of_first_original_reports_retained -ne $s) {
            throw 'Code Sequence pair precedence found an altered EC-074 first-support step.'
        }
        $first = [long]$stepRows[$s].permutations_first_restoring_saved_evidence_at_this_step
        if ($first -lt 0) { throw 'Code Sequence pair precedence received negative EC-074 first-support orderings.' }
        $prior = $s - 1
        $later = $N - $s
        $expected[0] += [long](Get-CodeSequenceDuodecetWithholdingChoose -N $later -K 2) * $first
        $expected[1] += [long]$later * $first
        $expected[2] += [long]$prior * [long]$later * $first
        $expected[3] += [long]$prior * $first
        $expected[4] += [long](Get-CodeSequenceDuodecetWithholdingChoose -N $prior -K 2) * $first
        $totalFirst += $first
    }
    $pairCount = Get-CodeSequenceDuodecetWithholdingChoose -N $N -K 2
    if ($totalFirst -ne [long]([int]$hasFullSupport * $permutations)) {
        throw 'Code Sequence pair precedence disagreed with the EC-074 fully supported ordering universe.'
    }
    if (-not $hasFullSupport) { $expected[5] = [long]$pairCount * $permutations }
    for ($k = 0; $k -lt 6; $k++) {
        if ($sum[$k] -ne $expected[$k]) {
            throw 'Code Sequence pair precedence failed independent EC-074 first-step aggregate conservation.'
        }
    }
    if ($scenarios.Count -ne ($N * ($N - 1)) -or
        ($sum[0] + $sum[1] + $sum[2] + $sum[3] + $sum[4] + $sum[5]) -ne
            ([long]$pairCount * $permutations)) {
        throw 'Code Sequence pair precedence lost or duplicated a possible ordered ORIGINAL report pair.'
    }
    return [ordered]@{
        original_positions_in_precedence_universe = $N
        total_distinct_full_original_permutations = $permutations
        exactly_half_the_orderings_per_directed_report_pair = $half
        full_original_selection_has_saved_witness_support = $hasFullSupport
        ordered_original_report_pair_precedence_scenarios = $scenarios.ToArray()
        original_position_margins_against_every_ec075_fixed_rank = $positionChecks.ToArray()
        independent_ec074_first_support_step_pair_precedence_ledger = [ordered]@{
            full_permutations_first_restoring_before_first_report = $sum[0]
            full_permutations_first_restored_by_first_report = $sum[1]
            full_permutations_first_restoring_strictly_between_reports = $sum[2]
            full_permutations_first_restored_by_second_report = $sum[3]
            full_permutations_first_restoring_after_second_report = $sum[4]
            full_permutations_never_restoring_saved_evidence = $sum[5]
            expected_total_combinations_across_all_hypothetical_original_orderings = [long]$pairCount * $permutations
        }
        every_ordered_report_pair_has_six_disjoint_exhaustive_first_support_categories = $true
        every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage = $true
        every_original_position_precedence_margin_matches_ec075_fixed_rank = $true
        all_six_first_support_categories_match_independent_ec074_step_counts = $true
        pair_precedence_is_not_authenticated_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairPrecedence {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution,
        [object] $RetentionRankConditioning
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or $null -eq $RetentionRankConditioning -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        $RetentionRankConditioning.scope -cne 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank' -or
        -not [bool]$RetentionRankConditioning.independent_of_sequence_top_and_original_finding_seed_side) {
        throw 'Code Sequence pair precedence requires completed unchanged EC-072/073/074/075 ORIGINAL targets.'
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
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionRankConditioning.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionRankConditioning.counts.original_maximal_repeat_family_count -ne $familyCount -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or $gCubes.Count -ne $gRank.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or $fCubes.Count -ne $fRank.Count -or
        $familyCubes.Count -ne $familyCount -or $familyBases.Count -ne $familyCount -or
        $familyOrders.Count -ne $familyCount -or $familyRank.Count -ne $familyCount) {
        throw 'Code Sequence pair precedence encountered changed ORIGINAL target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $bases = $gBases; $orders = $gOrders; $ranks = $gRank; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $bases = $fBases; $orders = $fOrders; $ranks = $fRank; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $cube = $cubes[$i]
            $basis = $bases[$i]
            $order = $orders[$i]
            $rank = $ranks[$i]
            $threshold = [int]$cube.original_global_family_capacity_at_least
            $baseline = [int]$cube.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $threshold -ne [int]$rank.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$rank.original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair precedence found an altered ORIGINAL genuine/frozen threshold.'
            }
            $projection = Get-CodeSequenceRetentionPairPrecedenceProjection `
                -RetentionCube $cube.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution `
                -FixedRank $rank.exact_first_support_fixed_rank_conditioning -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_pair_precedence = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $cube = $familyCubes[$fi]
        $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]
        $rank = $familyRank[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$rank.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence pair precedence changed an ORIGINAL family identity.'
        }
        $g = Get-CodeSequenceRetentionPairPrecedenceProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution `
            -FixedRank $rank.genuine_original_first_support_fixed_rank_conditioning -N $n
        $f = Get-CodeSequenceRetentionPairPrecedenceProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution `
            -FixedRank $rank.frozen_original_first_support_fixed_rank_conditioning -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_precedence = $g
            frozen_original_first_support_pair_precedence = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_ordered_report_pair_precedence'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            exact_permutations_per_ordered_original_report_pair = [long]([long]$factorial[$n] / 2)
            ordered_original_report_pair_scenarios_per_target = $n * ($n - 1)
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_pair_precedence = $gResult.ToArray()
        frozen_global_threshold_pair_precedence = $fResult.ToArray()
        individual_original_family_pair_precedence = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_precedence_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_precedence_is_not_real_defect_priority_risk_or_causal_repair = $true
    }
}

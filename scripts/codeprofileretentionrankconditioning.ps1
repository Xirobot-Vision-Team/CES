#requires -Version 7.0
<#
    EC-075: exact first ORIGINAL saved-evidence restoration, CONDITIONED on
    placing one fixed original report position p at hypothetical rank j.

    Reconstruct the Boolean evidence predicate ONLY from the already checked
    EC-072 inclusion-minimal ORIGINAL kept bases. Independently reconcile
    its entire 2^N support table with the separately checked EC-073 coverage
    and its exact p/j directed pivotal edges with EC-074 permutation counts.
    Each of the (N-1)! complete permutations with p fixed at rank j has
    exactly one of: evidence first before p, restored by p, first after p,
    or never restored. All arithmetic is exact Int64 for N<=12.

    These are mathematical *counterfactual original identity orderings*,
    not measured arrivals, verified chronology or empirical probabilities.
    No saved bodies/quotes, Git, source or network reads, business writes,
    private witness resequencing or frozen-optimum recomputation.
#>

function Get-CodeSequenceRetentionRankConditioningProjection {
    param(
        [object] $RetentionCube,
        [object] $VerifiedBasisBlock,
        [object] $RetentionOrder,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or $null -eq $RetentionOrder -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable -or
        -not [bool]$RetentionCube.ec072_exact_minimal_original_retained_bases_reconciled -or
        -not [bool]$RetentionCube.all_original_budget_edge_conservation_identities_verified -or
        -not [bool]$RetentionOrder.each_original_directed_pivotal_edge_weighted_by_actual_complete_permutation_multiplicity -or
        -not [bool]$RetentionOrder.first_support_step_counts_equal_independent_supported_budget_differences -or
        -not [bool]$RetentionOrder.all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported) {
        throw 'Code Sequence fixed-rank conditioning requires complete verified EC-072/073/074 original evidence.'
    }
    $size = 1 -shl $N
    $full = $size - 1
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $fixedRankPermutations = [long]$factorial[$N - 1]
    $coverage = [object[]]$RetentionCube.retained_original_budget_coverage
    $originalPositions = [object[]]$RetentionCube.original_position_pivotal_additions
    $orderPositions = [object[]]$RetentionOrder.original_position_first_support_permutation_attribution
    $orderSteps = [object[]]$RetentionOrder.first_support_restoration_by_retained_step
    $bases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    if ([int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1)) -or
        $coverage.Count -ne $N + 1 -or $originalPositions.Count -ne $N -or
        $orderPositions.Count -ne $N -or $orderSteps.Count -ne $N + 1 -or
        [long]$RetentionOrder.total_distinct_permutations_of_original_caller_positions -ne $permutations -or
        [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -ne $bases.Count) {
        throw 'Code Sequence fixed-rank conditioning found an altered original cube, basis or permutation denominator.'
    }

    # Independent of EC-073's private multiplicity histogram and EC-074's
    # weighted pivotal edges: compute all retained-mask support from the
    # PUBLIC, independently verified EC-072 minimal original basis masks.
    # Parent/submask m - bit is always smaller than m; so this is a complete
    # one-pass upward closure, not a search of guessed representative edges.
    $hasEvidence = [bool[]]::new($size)
    foreach ($basis in $bases) {
        if ($basis -le 0 -or $basis -gt $full -or $hasEvidence[$basis]) {
            throw 'Code Sequence fixed-rank conditioning received an invalid or duplicate original witness basis.'
        }
        $hasEvidence[$basis] = $true
    }
    $supportedCountByBudget = [int[]]::new($N + 1)
    for ($mask = 0; $mask -lt $size; $mask++) {
        if (-not $hasEvidence[$mask]) {
            for ($p = 0; $p -lt $N; $p++) {
                $bit = 1 -shl $p
                if (($mask -band $bit) -ne 0 -and $hasEvidence[$mask -bxor $bit]) {
                    $hasEvidence[$mask] = $true
                    break
                }
            }
        }
        if ($hasEvidence[$mask]) {
            $supportedCountByBudget[(Get-CodeSequenceResiliencePopcount -Mask $mask)]++
        }
    }
    $hasFullSupport = [bool]$hasEvidence[$full]
    if ($hasEvidence[0] -or
        $hasFullSupport -ne ([long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0) -or
        $hasFullSupport -ne [bool]$RetentionOrder.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence fixed-rank conditioning disagreed with original empty/full witness support.'
    }
    for ($k = 0; $k -le $N; $k++) {
        if ($supportedCountByBudget[$k] -ne [int]$coverage[$k].subsets_preserving_original_witness_support) {
            throw 'Code Sequence fixed-rank conditioning minimal bases disagree with independent EC-073 budget coverage.'
        }
    }

    $beforeRankTotals = [long[]]::new($N + 1)
    $byRankTotals = [long[]]::new($N + 1)
    $afterRankTotals = [long[]]::new($N + 1)
    $neverRankTotals = [long[]]::new($N + 1)
    $positionRows = [System.Collections.Generic.List[object]]::new()

    # Every fixed-p slice has exactly C(N-1,j-1) feasible (j-1)-prefix
    # retained masks without p. Each such mask represents precisely
    # (j-1)!*(N-j)! complete orderings with p at rank j. Check every one
    # against the *independently reconstructed* original retained predicate.
    for ($p = 0; $p -lt $N; $p++) {
        $bit = 1 -shl $p
        $parent = $originalPositions[$p]
        $old = $orderPositions[$p]
        $parentBins = [object[]]$parent.pivotal_additions_by_other_retained_budget
        $oldBins = [object[]]$old.by_first_support_step
        if ([int]$parent.original_caller_position -ne $p + 1 -or
            [int]$parent.original_position_bit -ne $bit -or
            [int]$old.original_caller_position -ne $p + 1 -or
            [int]$old.original_position_bit -ne $bit -or
            $parentBins.Count -ne $N -or $oldBins.Count -ne $N) {
            throw 'Code Sequence fixed-rank conditioning found a changed original report position identity.'
        }
        $supportedBeforeByRank = [int[]]::new($N + 1)
        $supportedAfterByRank = [int[]]::new($N + 1)
        for ($mask = 0; $mask -lt $size; $mask++) {
            if (($mask -band $bit) -ne 0) { continue }
            $rank = (Get-CodeSequenceResiliencePopcount -Mask $mask) + 1
            if ($hasEvidence[$mask]) { $supportedBeforeByRank[$rank]++ }
            if ($hasEvidence[$mask -bor $bit]) { $supportedAfterByRank[$rank]++ }
        }
        $fixedRanks = [System.Collections.Generic.List[object]]::new()
        $creditedToPosition = [long]0
        for ($j = 1; $j -le $N; $j++) {
            $prefixSets = Get-CodeSequenceDuodecetWithholdingChoose -N ($N - 1) -K ($j - 1)
            $prefixSupported = [int]$supportedBeforeByRank[$j]
            $withPositionSupported = [int]$supportedAfterByRank[$j]
            $pivot = $withPositionSupported - $prefixSupported
            if ($prefixSupported -lt 0 -or $withPositionSupported -lt $prefixSupported -or
                $withPositionSupported -gt $prefixSets -or
                $pivot -ne [int]$parentBins[$j - 1].pivotal_original_position_additions -or
                [int]$parentBins[$j - 1].number_of_other_retained_original_positions -ne $j - 1) {
                throw 'Code Sequence fixed-rank conditioning disagreed with an actual EC-073 original pivotal edge budget.'
            }
            $weight = [long]$factorial[$j - 1] * [long]$factorial[$N - $j]
            $before = [long]$prefixSupported * $weight
            $byPosition = [long]$pivot * $weight
            $after = [long]0
            $never = [long]0
            if ($hasFullSupport) { $after = $fixedRankPermutations - $before - $byPosition }
            else { $never = $fixedRankPermutations }
            if ($before -lt 0 -or $byPosition -lt 0 -or $after -lt 0 -or
                $before + $byPosition + $after + $never -ne $fixedRankPermutations -or
                $byPosition -ne [long]$oldBins[$j - 1].full_original_permutations_restored_by_this_position_at_this_step) {
                throw 'Code Sequence fixed-rank conditioning lost a unique original complete ordering or EC-074 attribution.'
            }
            $gcd = Get-CodeSequenceRetentionOrderGcd -A $byPosition -B $fixedRankPermutations
            $fixedRanks.Add([ordered]@{
                original_report_fixed_at_hypothetical_rank = $j
                exact_full_permutations_with_this_report_fixed_at_rank = $fixedRankPermutations
                original_prefix_sets_without_this_position = $prefixSets
                original_prefix_sets_with_evidence_before_position = $prefixSupported
                original_prefix_sets_with_evidence_after_adding_position = $withPositionSupported
                full_permutations_first_restoring_before_this_position = $before
                full_permutations_first_restored_by_this_position = $byPosition
                full_permutations_first_restoring_after_this_position = $after
                full_permutations_never_restoring_saved_evidence = $never
                exact_reduced_by_position_given_fixed_rank_fraction_numerator = [long]($byPosition / $gcd)
                exact_reduced_by_position_given_fixed_rank_fraction_denominator = [long]($fixedRankPermutations / $gcd)
            })
            $beforeRankTotals[$j] += $before
            $byRankTotals[$j] += $byPosition
            $afterRankTotals[$j] += $after
            $neverRankTotals[$j] += $never
            $creditedToPosition += $byPosition
        }
        if ($creditedToPosition -ne [long]$old.exact_permutations_in_which_this_position_first_restores_saved_evidence) {
            throw 'Code Sequence fixed-rank conditioning disagreed with the total EC-074 original position attribution.'
        }
        $positionRows.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = $bit
            exact_permutations_first_restored_by_this_position_across_every_possible_fixed_rank = $creditedToPosition
            scenarios_by_fixed_hypothetical_rank = $fixedRanks.ToArray()
        })
    }

    $rankLedger = [System.Collections.Generic.List[object]]::new()
    for ($j = 1; $j -le $N; $j++) {
        # In any complete ordering there is exactly one original position at
        # rank j. Thus summing independently conditioned rows across *all*
        # p must recover the unconditional EC-074 counts before/at/after j.
        $expectBefore = [long]$orderSteps[$j - 1].permutations_with_saved_evidence_after_this_step
        $expectBy = [long]$orderSteps[$j].permutations_first_restoring_saved_evidence_at_this_step
        $expectAfter = [long]0
        $expectNever = [long]0
        if ($hasFullSupport) {
            $expectAfter = $permutations - [long]$orderSteps[$j].permutations_with_saved_evidence_after_this_step
        } else { $expectNever = $permutations }
        if ($beforeRankTotals[$j] -ne $expectBefore -or
            $byRankTotals[$j] -ne $expectBy -or
            $afterRankTotals[$j] -ne $expectAfter -or
            $neverRankTotals[$j] -ne $expectNever -or
            $beforeRankTotals[$j] + $byRankTotals[$j] + $afterRankTotals[$j] + $neverRankTotals[$j] -ne $permutations) {
            throw 'Code Sequence fixed-rank conditioning failed independent EC-074 rank-wide complete-ordering partition.'
        }
        $rankLedger.Add([ordered]@{
            hypothetical_rank_occupied_by_one_original_position = $j
            full_permutations_first_restoring_before_rank = $beforeRankTotals[$j]
            full_permutations_first_restoring_at_rank = $byRankTotals[$j]
            full_permutations_first_restoring_after_rank = $afterRankTotals[$j]
            full_permutations_never_restoring_saved_evidence = $neverRankTotals[$j]
        })
    }
    return [ordered]@{
        original_positions_in_fixed_ordering_universe = $N
        total_distinct_full_original_permutations = $permutations
        complete_permutations_per_original_position_per_fixed_rank = $fixedRankPermutations
        full_original_selection_has_saved_witness_support = $hasFullSupport
        original_position_conditioned_on_fixed_hypothetical_rank = $positionRows.ToArray()
        independent_full_ordering_conservation_across_all_positions_at_each_rank = $rankLedger.ToArray()
        all_fixed_position_rank_cases_partition_into_before_by_after_or_never = $true
        every_public_ec072_basis_reconstruction_matches_independent_ec073_original_coverage = $true
        every_fixed_position_pivotal_step_matches_original_ec073_edges_and_ec074_counts = $true
        all_rank_wide_margins_reconcile_independent_ec074_complete_permutations = $true
        hypothetical_fixed_rank_is_not_authenticated_arrival_time_or_measured_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionRankConditioning {
    param(
        [object] $RetentionPivotality,
        [object] $SupportBasisDuality,
        [object] $RetentionOrderAttribution
    )

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $null -eq $RetentionOrderAttribution -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $RetentionOrderAttribution.scope -cne 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position' -or
        -not [bool]$RetentionPivotality.each_original_directed_edge_counted_once_and_all_budget_identities_verified -or
        -not [bool]$SupportBasisDuality.every_excluded_position_in_every_minimal_cut_has_a_real_minimal_basis_restoration -or
        -not [bool]$RetentionOrderAttribution.all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported) {
        throw 'Code Sequence fixed-rank conditioning requires completed unchanged EC-072/073/074 original evidence outputs.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $families = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    $gCubes = [object[]]$RetentionPivotality.genuine_global_threshold_retention_coverage
    $fCubes = [object[]]$RetentionPivotality.frozen_global_threshold_retention_coverage
    $familyCubes = [object[]]$RetentionPivotality.individual_original_family_retention_coverage
    $gBases = [object[]]$SupportBasisDuality.genuine_global_threshold_retained_support_bases
    $fBases = [object[]]$SupportBasisDuality.frozen_global_threshold_retained_support_bases
    $familyBases = [object[]]$SupportBasisDuality.individual_original_family_retained_support_bases
    $gOrders = [object[]]$RetentionOrderAttribution.genuine_global_threshold_first_support_permutations
    $fOrders = [object[]]$RetentionOrderAttribution.frozen_global_threshold_first_support_permutations
    $familyOrders = [object[]]$RetentionOrderAttribution.individual_original_family_first_support_permutations
    if ($n -lt 2 -or $n -gt 12 -or $families -lt 0 -or $families -gt 66 -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionOrderAttribution.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $families -or
        [int]$RetentionOrderAttribution.counts.original_maximal_repeat_family_count -ne $families -or
        $gCubes.Count -ne $gBases.Count -or $gCubes.Count -ne $gOrders.Count -or
        $fCubes.Count -ne $fBases.Count -or $fCubes.Count -ne $fOrders.Count -or
        $familyCubes.Count -ne $families -or $familyBases.Count -ne $families -or
        $familyOrders.Count -ne $families) {
        throw 'Code Sequence fixed-rank conditioning encountered changed ORIGINAL global/family target indexing.'
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $cubes = $gCubes; $basisRows = $gBases; $orderRows = $gOrders; $sink = $gResult
        if ($kind -ceq 'frozen') {
            $cubes = $fCubes; $basisRows = $fBases; $orderRows = $fOrders; $sink = $fResult
        }
        for ($i = 0; $i -lt $cubes.Count; $i++) {
            $target = $cubes[$i]
            $basis = $basisRows[$i]
            $order = $orderRows[$i]
            $threshold = [int]$target.original_global_family_capacity_at_least
            $baseline = [int]$target.original_full_selection_global_family_capacity
            if ($threshold -ne [int]$basis.original_global_family_capacity_at_least -or
                $threshold -ne [int]$order.original_global_family_capacity_at_least -or
                $baseline -ne [int]$basis.original_full_selection_global_family_capacity -or
                $baseline -ne [int]$order.original_full_selection_global_family_capacity) {
                throw 'Code Sequence fixed-rank conditioning found a mismatched ORIGINAL global threshold.'
            }
            $projection = Get-CodeSequenceRetentionRankConditioningProjection `
                -RetentionCube $target.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations `
                -RetentionOrder $order.exact_first_support_permutation_attribution -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $baseline
                exact_first_support_fixed_rank_conditioning = $projection
            })
        }
    }
    $familyResults = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $families; $fi++) {
        $cube = $familyCubes[$fi]
        $basis = $familyBases[$fi]
        $order = $familyOrders[$fi]
        if ([int]$cube.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$order.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence fixed-rank conditioning found changed original family identity.'
        }
        $g = Get-CodeSequenceRetentionRankConditioningProjection `
            -RetentionCube $cube.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.genuine_original_first_support_permutation_attribution -N $n
        $f = Get-CodeSequenceRetentionRankConditioningProjection `
            -RetentionCube $cube.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations `
            -RetentionOrder $order.frozen_original_first_support_permutation_attribution -N $n
        $familyResults.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_fixed_rank_conditioning = $g
            frozen_original_first_support_fixed_rank_conditioning = $f
        })
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_first_saved_evidence_restoration_conditioned_on_fixed_report_rank'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $families
            exact_original_distinct_permutations_per_target = [long]$factorials[$n]
            exact_permutations_given_one_original_position_at_one_fixed_rank = [long]$factorials[$n - 1]
            fixed_rank_scenarios_per_target = $n * $n
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $familyResults.Count
        }
        genuine_global_threshold_fixed_rank_conditioning = $gResult.ToArray()
        frozen_global_threshold_fixed_rank_conditioning = $fResult.ToArray()
        individual_original_family_fixed_rank_conditioning = $familyResults.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        hypothetical_rank_is_not_authenticated_chronology_or_empirical_probability = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        conditional_evidence_attribution_is_not_a_real_defect_risk_rank_or_causal_repair = $true
    }
}

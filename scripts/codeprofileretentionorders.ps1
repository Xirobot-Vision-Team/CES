#requires -Version 7.0
<#
    EC-074: exact permutation-order first-support restoration of ORIGINAL saved
    witness evidence. EC-073 already proves every supported original retained
    set and every absent-to-present single-position directed cube edge; EC-074
    interprets each actual edge as k!*(N-k-1)! complete permutations whose
    first k retained positions are that edge's K, followed by its new bit.

    This is exhaustive COMBINATORIAL accounting over hypothetical permutations
    of the fixed caller-selected report IDs. It does not resequence witnesses,
    authenticate report chronology, sample users or predict real-world risk,
    cause, defect severity or repair success. No file/Git/network/source I/O.
#>

function Get-CodeSequenceRetentionOrderFactorials {
    param([int] $N)
    if ($N -lt 2 -or $N -gt 12) {
        throw 'Code Sequence permutation-order analysis accepts only 2..12 original positions.'
    }
    $factorials = [long[]]::new($N + 1)
    $factorials[0] = [long]1
    for ($i = 1; $i -le $N; $i++) {
        $factorials[$i] = $factorials[$i - 1] * [long]$i
    }
    return ,$factorials
}

function Get-CodeSequenceRetentionOrderGcd {
    param([long] $A, [long] $B)
    if ($A -lt 0 -or $B -le 0) {
        throw 'Code Sequence permutation fraction requires nonnegative numerator and positive denominator.'
    }
    while ($B -ne 0) {
        $remainder = $A % $B
        $A = $B
        $B = $remainder
    }
    return $A
}

function Get-CodeSequenceRetentionOrderAttributionProjection {
    param([object] $RetentionCube, [object] $VerifiedBasisBlock, [int] $N)

    $size = 1 -shl $N
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $RetentionCube -or
        $null -eq $VerifiedBasisBlock -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable -or
        -not [bool]$RetentionCube.ec072_exact_minimal_original_retained_bases_reconciled -or
        -not [bool]$RetentionCube.all_original_budget_edge_conservation_identities_verified -or
        -not [bool]$RetentionCube.pivotal_position_if_and_only_if_present_in_original_minimal_basis_and_cut -or
        [int]$RetentionCube.original_retained_mask_count -ne $size -or
        [int]$RetentionCube.original_directed_single_position_addition_edge_count -ne ($N * ($size -shr 1))) {
        throw 'Code Sequence retention orders require the complete verified ORIGINAL EC-072/073 cube.'
    }
    $coverage = [object[]]$RetentionCube.retained_original_budget_coverage
    $positions = [object[]]$RetentionCube.original_position_pivotal_additions
    $basisPositions = [object[]]$VerifiedBasisBlock.original_position_basis_and_cut_incidence
    if ($coverage.Count -ne $N + 1 -or $positions.Count -ne $N -or
        $basisPositions.Count -ne $N -or
        [string]$RetentionCube.minimum_retained_original_positions_with_real_support -cne
            [string]$VerifiedBasisBlock.minimum_original_positions_to_retain_for_support) {
        throw 'Code Sequence retention orders encountered changed ORIGINAL budgets, positions or basis minima.'
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $permutations = [long]$factorial[$N]
    $fullHasSupport = [long]$RetentionCube.full_original_selection_saved_witness_multiplicity -gt 0
    $firstSupportOrderingsByStep = [long[]]::new($N + 1)
    $budgetStep = [System.Collections.Generic.List[object]]::new()
    $pivotEdgesByBudget = 0
    $previousCumulative = [long]0
    $supportedMaskTotal = 0

    # Exactly k!*(N-k)! permutations start with any particular k-element K.
    # EC-073 has already checked every actual K, not just a sample. For a
    # monotone evidence predicate, the cumulative first-support distribution
    # is exactly the difference between consecutive cumulative counts.
    for ($k = 0; $k -le $N; $k++) {
        $bin = $coverage[$k]
        $combinationCount = Get-CodeSequenceDuodecetWithholdingChoose -N $N -K $k
        $supported = [int]$bin.subsets_preserving_original_witness_support
        $unsupported = [int]$bin.subsets_without_original_witness_support
        if ([int]$bin.number_of_retained_original_positions -ne $k -or
            [int]$bin.possible_original_retained_subsets -ne $combinationCount -or
            $supported -lt 0 -or $unsupported -lt 0 -or
            $supported + $unsupported -ne $combinationCount) {
            throw 'Code Sequence retention orders found a nonexact original retained-budget partition.'
        }
        $supportedMaskTotal += $supported
        $cumulativeSupported = [long]$supported * $factorial[$k] * $factorial[$N - $k]
        $firstAtStep = $cumulativeSupported - $previousCumulative
        if ($firstAtStep -lt 0 -or $cumulativeSupported -gt $permutations -or
            ($k -eq 0 -and ($supported -ne 0 -or $firstAtStep -ne 0))) {
            throw 'Code Sequence retention orders violated monotone cumulative permutation support.'
        }
        if ($k -gt 0) {
            $previousBin = $coverage[$k - 1]
            $edgeCount = [long]$previousBin.pivotal_one_position_additions_to_next_budget
            $edgeWeight = $factorial[$k - 1] * $factorial[$N - $k]
            if ($edgeCount -lt 0 -or $edgeCount * $edgeWeight -ne $firstAtStep) {
                throw 'Code Sequence retention orders disagreed with exact EC-073 budget edge conservation.'
            }
            $pivotEdgesByBudget += $edgeCount
        } elseif ([int]$bin.pivotal_one_position_additions_to_next_budget -lt 0) {
            throw 'Code Sequence retention orders found negative original pivot edges.'
        }
        $firstSupportOrderingsByStep[$k] = $firstAtStep
        $budgetStep.Add([ordered]@{
            number_of_first_original_reports_retained = $k
            original_retained_subsets_at_this_budget = $combinationCount
            supported_original_subsets_at_this_budget = $supported
            permutations_with_saved_evidence_after_this_step = $cumulativeSupported
            permutations_without_saved_evidence_after_this_step = $permutations - $cumulativeSupported
            permutations_first_restoring_saved_evidence_at_this_step = $firstAtStep
        })
        $previousCumulative = $cumulativeSupported
    }
    if ($supportedMaskTotal -ne [int]$RetentionCube.supported_retained_original_mask_count -or
        $size - $supportedMaskTotal -ne [int]$RetentionCube.unsupported_retained_original_mask_count -or
        $pivotEdgesByBudget -ne [long]$RetentionCube.total_evidence_pivotal_directed_addition_edges -or
        $previousCumulative -ne [long]([int]$fullHasSupport * $permutations)) {
        throw 'Code Sequence retention orders failed exact original full-selection evidence conservation.'
    }

    $positionResults = [System.Collections.Generic.List[object]]::new()
    $weightedByStep = [long[]]::new($N + 1)
    $weightedAllPositions = [long]0
    $rawAllEdges = 0
    $weightedByPosition = [long[]]::new($N)
    for ($p = 0; $p -lt $N; $p++) {
        $parent = $positions[$p]
        $basisPosition = $basisPositions[$p]
        $bit = 1 -shl $p
        $bins = [object[]]$parent.pivotal_additions_by_other_retained_budget
        if ([int]$parent.original_caller_position -ne $p + 1 -or
            [int]$parent.original_position_bit -ne $bit -or
            [int]$parent.original_other_retained_masks_considered -ne ($size -shr 1) -or
            [int]$basisPosition.original_caller_position -ne $p + 1 -or
            $bins.Count -ne $N) {
            throw 'Code Sequence retention orders encountered altered original report-position identity.'
        }
        $stepRows = [System.Collections.Generic.List[object]]::new()
        $rawEdges = 0
        $weighted = [long]0
        $firstStep = $null
        $lastStep = $null
        for ($k = 0; $k -lt $N; $k++) {
            $edge = $bins[$k]
            $possible = Get-CodeSequenceDuodecetWithholdingChoose -N ($N - 1) -K $k
            $pivot = [int]$edge.pivotal_original_position_additions
            if ([int]$edge.number_of_other_retained_original_positions -ne $k -or
                [int]$edge.other_original_position_subsets_considered -ne $possible -or
                $pivot -lt 0 -or $pivot -gt $possible) {
                throw 'Code Sequence retention orders has an impossible original-position edge budget.'
            }
            $contribution = [long]$pivot * $factorial[$k] * $factorial[$N - 1 - $k]
            $rawEdges += $pivot
            $weighted += $contribution
            $weightedByStep[$k + 1] += $contribution
            if ($contribution -gt 0) {
                if ($null -eq $firstStep) { $firstStep = $k + 1 }
                $lastStep = $k + 1
            }
            $stepRows.Add([ordered]@{
                first_evidence_restoration_at_retained_step = $k + 1
                actual_ec073_pivotal_original_edges = $pivot
                full_original_permutations_restored_by_this_position_at_this_step = $contribution
            })
        }
        $certificate = $parent.smallest_numeric_actual_restoration_edge
        if ($rawEdges -ne [int]$parent.pivotal_addition_count_across_all_other_retained_masks -or
            ($weighted -gt 0) -ne ($rawEdges -gt 0) -or
            ($rawEdges -gt 0) -ne ([int]$basisPosition.inclusion_minimal_support_bases_containing_position -gt 0) -or
            ($rawEdges -gt 0) -ne ([int]$basisPosition.inclusion_minimal_loss_cuts_containing_position -gt 0) -or
            ($rawEdges -gt 0) -ne ($null -ne $certificate)) {
            throw 'Code Sequence retention orders disagreed with the EC-072/073 pivotal position certificates.'
        }
        if ($null -ne $certificate) {
            $realBasis = [int]$certificate.real_ec072_inclusion_minimal_basis_now_supported
            $before = [int]$certificate.other_original_retained_mask_without_position
            $after = [int]$certificate.retained_mask_after_adding_original_position
            $registeredBases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
            if (($before -band $bit) -ne 0 -or $after -ne ($before -bor $bit) -or
                ($realBasis -band $bit) -eq 0 -or ($realBasis -band $after) -ne $realBasis -or
                $registeredBases -notcontains $realBasis) {
                throw 'Code Sequence retention orders received a false ORIGINAL EC-073 recovery basis.'
            }
        }
        $divisor = Get-CodeSequenceRetentionOrderGcd -A $weighted -B $permutations
        $weightedByPosition[$p] = $weighted
        $weightedAllPositions += $weighted
        $rawAllEdges += $rawEdges
        $positionResults.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = $bit
            exact_permutations_in_which_this_position_first_restores_saved_evidence = $weighted
            original_permutations_in_full_enumeration = $permutations
            exact_reduced_attribution_fraction_numerator = [long]($weighted / $divisor)
            exact_reduced_attribution_fraction_denominator = [long]($permutations / $divisor)
            earliest_possible_first_support_step = $firstStep
            latest_possible_first_support_step = $lastStep
            by_first_support_step = $stepRows.ToArray()
            original_ec073_minimal_real_restoration_certificate = $certificate
        })
    }
    if ($rawAllEdges -ne [long]$RetentionCube.total_evidence_pivotal_directed_addition_edges -or
        $weightedAllPositions -ne [long]([int]$fullHasSupport * $permutations)) {
        throw 'Code Sequence retention orders did not assign each full ordering exactly one first-support position.'
    }
    for ($j = 0; $j -le $N; $j++) {
        if ($weightedByStep[$j] -ne $firstSupportOrderingsByStep[$j]) {
            throw 'Code Sequence retention orders failed independent position-to-step partition conservation.'
        }
    }
    $actualEarliest = $null
    for ($j = 1; $j -le $N; $j++) {
        if ($firstSupportOrderingsByStep[$j] -gt 0) { $actualEarliest = $j; break }
    }
    if ([string]$actualEarliest -cne
            [string]$RetentionCube.minimum_retained_original_positions_with_real_support) {
        throw 'Code Sequence retention orders changed the exact EC-072/073 first feasible support budget.'
    }

    # Descending exact full-permutation counts are navigational only; no risk,
    # defect priority, temporal ordering or real-world causal attribution.
    $navigation = [System.Collections.Generic.List[object]]::new()
    $visited = [bool[]]::new($N)
    for ($rank = 1; $rank -le $N; $rank++) {
        $selected = -1
        for ($p = 0; $p -lt $N; $p++) {
            if ($visited[$p]) { continue }
            if ($selected -lt 0 -or $weightedByPosition[$p] -gt $weightedByPosition[$selected]) {
                $selected = $p
            }
        }
        if ($selected -lt 0) { throw 'Code Sequence retention orders lost an original navigational position.' }
        $visited[$selected] = $true
        $navigation.Add([ordered]@{
            navigation_order_not_causal_rank = $rank
            original_caller_position = $selected + 1
            exact_first_support_permutations = $weightedByPosition[$selected]
        })
    }

    return [ordered]@{
        total_distinct_permutations_of_original_caller_positions = $permutations
        full_original_selection_has_saved_witness_support = [bool]$fullHasSupport
        first_feasible_original_retained_step = $actualEarliest
        first_support_restoration_by_retained_step = $budgetStep.ToArray()
        total_full_permutations_with_exactly_one_first_support_restoration = $weightedAllPositions
        original_position_first_support_permutation_attribution = $positionResults.ToArray()
        original_positions_sorted_by_first_support_permutation_count = $navigation.ToArray()
        each_original_directed_pivotal_edge_weighted_by_actual_complete_permutation_multiplicity = $true
        first_support_step_counts_equal_independent_supported_budget_differences = $true
        all_full_orderings_partitioned_by_unique_first_restoration_or_never_supported = $true
        attribution_is_uniform_theoretical_order_combinatorics_not_observed_frequency = $true
        saved_evidence_attribution_does_not_prove_real_world_causality_or_repair = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionOrderAttribution {
    param([object] $RetentionPivotality, [object] $SupportBasisDuality)

    if ($null -eq $RetentionPivotality -or $null -eq $SupportBasisDuality -or
        $RetentionPivotality.scope -cne 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        -not [bool]$RetentionPivotality.each_original_directed_edge_counted_once_and_all_budget_identities_verified -or
        -not [bool]$RetentionPivotality.reconciles_ec072_all_minimal_retained_bases_and_position_criticality -or
        -not [bool]$RetentionPivotality.uses_ec071_exact_original_position_bit_legend_without_reindexing -or
        -not [bool]$SupportBasisDuality.every_excluded_position_in_every_minimal_cut_has_a_real_minimal_basis_restoration) {
        throw 'Code Sequence retention orders require completed unchanged EC-072/073 ORIGINAL evidence targets.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $f = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    $gRows = [object[]]$RetentionPivotality.genuine_global_threshold_retention_coverage
    $oRows = [object[]]$RetentionPivotality.frozen_global_threshold_retention_coverage
    $fRows = [object[]]$RetentionPivotality.individual_original_family_retention_coverage
    $gBases = [object[]]$SupportBasisDuality.genuine_global_threshold_retained_support_bases
    $oBases = [object[]]$SupportBasisDuality.frozen_global_threshold_retained_support_bases
    $fBases = [object[]]$SupportBasisDuality.individual_original_family_retained_support_bases
    $expectedSize = 1 -shl $n
    if ($n -lt 2 -or $n -gt 12 -or $f -lt 0 -or $f -gt 66 -or
        [int]$RetentionPivotality.counts.exact_original_retained_masks_checked_per_target -ne $expectedSize -or
        [int]$RetentionPivotality.counts.exact_original_directed_position_additions_checked_per_target -ne ($n * ($expectedSize -shr 1)) -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $f -or
        $gRows.Count -ne $gBases.Count -or $oRows.Count -ne $oBases.Count -or
        $fRows.Count -ne $f -or $fBases.Count -ne $f -or
        $gRows.Count -ne [int]$RetentionPivotality.counts.genuine_original_global_thresholds -or
        $oRows.Count -ne [int]$RetentionPivotality.counts.frozen_original_global_thresholds) {
        throw 'Code Sequence retention orders encountered inconsistent ORIGINAL target cardinality.'
    }
    $resultG = [System.Collections.Generic.List[object]]::new()
    $resultO = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in @('genuine', 'frozen')) {
        $rows = $gRows
        $basisRows = $gBases
        $sink = $resultG
        if ($kind -ceq 'frozen') { $rows = $oRows; $basisRows = $oBases; $sink = $resultO }
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $target = $rows[$i]
            $basis = $basisRows[$i]
            if ([int]$target.original_global_family_capacity_at_least -ne
                    [int]$basis.original_global_family_capacity_at_least -or
                [int]$target.original_full_selection_global_family_capacity -ne
                    [int]$basis.original_full_selection_global_family_capacity) {
                throw 'Code Sequence retention orders found a changed ORIGINAL global threshold.'
            }
            $projection = Get-CodeSequenceRetentionOrderAttributionProjection `
                -RetentionCube $target.original_retention_budget_coverage_and_pivotal_additions `
                -VerifiedBasisBlock $basis.retained_position_support_basis_and_loss_cut_restorations -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = [int]$target.original_global_family_capacity_at_least
                original_full_selection_global_family_capacity = [int]$target.original_full_selection_global_family_capacity
                exact_first_support_permutation_attribution = $projection
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $f; $fi++) {
        $target = $fRows[$fi]
        $basis = $fBases[$fi]
        if ([int]$target.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$basis.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence retention orders found changed original family indexing.'
        }
        $g = Get-CodeSequenceRetentionOrderAttributionProjection `
            -RetentionCube $target.genuine_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.genuine_retained_position_support_basis_and_restorations -N $n
        $o = Get-CodeSequenceRetentionOrderAttributionProjection `
            -RetentionCube $target.frozen_original_retention_budget_coverage_and_pivotal_additions `
            -VerifiedBasisBlock $basis.frozen_retained_position_support_basis_and_restorations -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_permutation_attribution = $g
            frozen_original_first_support_permutation_attribution = $o
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_permutation_first_saved_evidence_restoration_by_step_and_pivotal_position'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            exact_original_distinct_permutations_per_target = $factorial[$n]
            genuine_original_global_thresholds = $resultG.Count
            frozen_original_global_thresholds = $resultO.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_first_support_permutations = $resultG.ToArray()
        frozen_global_threshold_first_support_permutations = $resultO.ToArray()
        individual_original_family_first_support_permutations = $families.ToArray()
        original_saved_report_identity_and_caller_order_used_only_as_fixed_bit_legend = $true
        only_theoretical_uniform_original_permutations_not_authenticated_chronology = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        original_full_selection_frozen_optima_not_reoptimized = $true
        no_new_saved_quotes_source_git_network_reads_or_business_source_writes = $true
        permutation_attribution_is_not_defect_severity_risk_priority_or_causal_repair = $true
    }
}

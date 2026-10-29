#requires -Version 7.0
<#
    EC-073: exact ORIGINAL report retention-budget coverage and one-position
    evidence pivotality. For a retained original subset K, a witness exists
    exactly when a verified EC-060 ORIGINAL union-mask witness is inside K.
    Adding a missing original position p is pivotal when evidence is absent
    on K and present on K | bit(p). Enumerate every one of the N*2^(N-1)
    *directed* edges of the original subset cube, N=2..12.

    Distinguish genuine witness combinations from original EC-056 frozen
    full-selection locally optimal combinations; do not reoptimize, resequence,
    read saved quote bodies/source/Git/network, or write repository state.
    Pivotality measures sensitivity of SAVED EVIDENCE, not causal importance,
    severity or a recommended real-world software repair.
#>

function Get-CodeSequenceRetentionPivotalityProjection {
    param([long[]] $UnionMaskHistogram, [object] $VerifiedBasisBlock, [int] $N)

    $size = 1 -shl $N
    $full = $size - 1
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $VerifiedBasisBlock -or
        $null -eq $UnionMaskHistogram -or $UnionMaskHistogram.Count -ne $size -or
        -not [bool]$VerifiedBasisBlock.every_ec071_original_cut_dual_and_every_excluded_position_restorable) {
        throw 'Code Sequence retention pivotality requires a verified EC-072 ORIGINAL basis frontier.'
    }

    # Reconstruct from the reconciled PRIVATE witness multiplicities, not from
    # public example bases alone. A basis/cut mismatch must fail closed.
    $projection = Get-CodeSequenceSupportBasisProjection -UnionMaskHistogram $UnionMaskHistogram -N $N
    $survivors = [long[]]$projection.surviving_by_exclusion_mask
    $representative = [int[]]$projection.smallest_reachable_support_basis_by_retained_mask
    $bases = [int[]]$projection.minimal_retained_support_masks
    $registeredBases = [int[]]$VerifiedBasisBlock.inclusion_minimal_retained_original_position_masks
    $positionsFromBasis = [object[]]$VerifiedBasisBlock.original_position_basis_and_cut_incidence
    if (($bases -join ',') -cne ($registeredBases -join ',') -or
        $bases.Count -ne [int]$VerifiedBasisBlock.inclusion_minimal_retained_support_basis_count -or
        $positionsFromBasis.Count -ne $N) {
        throw 'Code Sequence retention pivotality disagrees with the exact EC-072 retained bases.'
    }

    $covered = [int[]]::new($N + 1)
    $pivotal = [int[]]::new($N)
    $firstOther = [int[]]::new($N)
    $firstBasis = [int[]]::new($N)
    $perPositionBudget = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $firstOther[$p] = -1
        $firstBasis[$p] = -1
        $perPositionBudget.Add([int[]]::new($N))
    }

    # Each retained K participates in exactly one coverage bin; for every
    # missing bit p it is the unique starting endpoint of one directed edge.
    # Thus edges cannot be double-counted or skipped by this traversal.
    for ($kept = 0; $kept -lt $size; $kept++) {
        $k = Get-CodeSequenceResiliencePopcount -Mask $kept
        $hasSupport = $survivors[$full -bxor $kept] -gt 0
        if ($hasSupport) {
            $covered[$k]++
            if ($representative[$kept] -le 0) {
                throw 'Code Sequence retention pivotality has support without a real EC-072 basis.'
            }
        } elseif ($representative[$kept] -ne -1) {
            throw 'Code Sequence retention pivotality has a false positive retained support certificate.'
        }
        for ($p = 0; $p -lt $N; $p++) {
            $bit = 1 -shl $p
            if (($kept -band $bit) -ne 0) { continue }
            $augmented = $kept -bor $bit
            $afterSupport = $survivors[$full -bxor $augmented] -gt 0
            if ($hasSupport -and -not $afterSupport) {
                throw 'Code Sequence retention pivotality violated original evidence upward monotonicity.'
            }
            if (-not $hasSupport -and $afterSupport) {
                # The actual representative basis MUST use the newly added
                # original bit; otherwise it would already be present in K.
                $realBasis = $representative[$augmented]
                if ($realBasis -le 0 -or ($realBasis -band $bit) -eq 0 -or
                    ($realBasis -band $augmented) -ne $realBasis -or
                    $bases -notcontains $realBasis) {
                    throw 'Code Sequence retention pivotality fabricated a one-position ORIGINAL recovery edge.'
                }
                $pivotal[$p]++
                $perPositionBudget[$p][$k]++
                if ($firstOther[$p] -lt 0) {
                    $firstOther[$p] = $kept
                    $firstBasis[$p] = $realBasis
                }
            }
        }
    }

    $totalRetainedSupport = 0
    $totalPivotalEdges = 0
    $edgeEntries = [System.Collections.Generic.List[object]]::new()
    for ($k = 0; $k -le $N; $k++) {
        $possible = Get-CodeSequenceDuodecetWithholdingChoose -N $N -K $k
        if ($covered[$k] -lt 0 -or $covered[$k] -gt $possible) {
            throw 'Code Sequence retention pivotality invented impossible budget coverage.'
        }
        $totalRetainedSupport += $covered[$k]
        # Directed edges into budget k+1: every positive upper endpoint has
        # k+1 incoming edges; positive lower endpoints generate N-k edges
        # that remain positive. Their difference counts exactly pivot edges.
        $expectedPivotalAtK = 0
        $countedPivotalAtK = 0
        if ($k -lt $N) {
            $expectedPivotalAtK = ($k + 1) * $covered[$k + 1] -
                ($N - $k) * $covered[$k]
            for ($p = 0; $p -lt $N; $p++) {
                $countedPivotalAtK += [int]$perPositionBudget[$p][$k]
            }
            if ($expectedPivotalAtK -lt 0 -or $countedPivotalAtK -ne $expectedPivotalAtK -or
                ($N - $k) * $covered[$k] -gt ($k + 1) * $covered[$k + 1]) {
                throw 'Code Sequence retention pivotality violated the exact Boolean cube edge budget identity.'
            }
        }
        $edgeEntries.Add([ordered]@{
            number_of_retained_original_positions = $k
            possible_original_retained_subsets = $possible
            subsets_preserving_original_witness_support = $covered[$k]
            subsets_without_original_witness_support = $possible - $covered[$k]
            pivotal_one_position_additions_to_next_budget = $expectedPivotalAtK
        })
        $totalPivotalEdges += $expectedPivotalAtK
    }
    if ($totalRetainedSupport -lt 0 -or $totalRetainedSupport -gt $size -or
        $covered[0] -ne 0 -or
        $covered[$N] -ne [int]($survivors[0] -gt 0)) {
        throw 'Code Sequence retention pivotality failed empty/full ORIGINAL mask conservation.'
    }

    $firstFeasibleBudget = $null
    for ($k = 0; $k -le $N; $k++) {
        if ($covered[$k] -gt 0) { $firstFeasibleBudget = $k; break }
    }
    if ([string]$firstFeasibleBudget -cne
            [string]$VerifiedBasisBlock.minimum_original_positions_to_retain_for_support) {
        throw 'Code Sequence retention pivotality changed EC-072 minimum original kept positions.'
    }

    $positionLedger = [System.Collections.Generic.List[object]]::new()
    $directPivotalTotal = 0
    for ($p = 0; $p -lt $N; $p++) {
        $baselinePosition = $positionsFromBasis[$p]
        if ([int]$baselinePosition.original_caller_position -ne $p + 1) {
            throw 'Code Sequence retention pivotality found a changed original position registry.'
        }
        $pivotByBudget = [System.Collections.Generic.List[object]]::new()
        $summed = 0
        for ($k = 0; $k -lt $N; $k++) {
            $number = [int]$perPositionBudget[$p][$k]
            $available = Get-CodeSequenceDuodecetWithholdingChoose -N ($N - 1) -K $k
            if ($number -lt 0 -or $number -gt $available) {
                throw 'Code Sequence retention pivotality exceeded the original position edge count.'
            }
            $summed += $number
            $pivotByBudget.Add([ordered]@{
                number_of_other_retained_original_positions = $k
                other_original_position_subsets_considered = $available
                pivotal_original_position_additions = $number
            })
        }
        if ($summed -ne $pivotal[$p] -or
            ($pivotal[$p] -gt 0) -ne ([int]$baselinePosition.inclusion_minimal_support_bases_containing_position -gt 0) -or
            ($pivotal[$p] -gt 0) -ne ([int]$baselinePosition.inclusion_minimal_loss_cuts_containing_position -gt 0) -or
            (($pivotal[$p] -gt 0) -ne ($firstOther[$p] -ge 0))) {
            throw 'Code Sequence retention pivotality disagrees with the EC-072 original position relevance ledger.'
        }
        $directPivotalTotal += $summed
        $restorationExample = $null
        if ($firstOther[$p] -ge 0) {
            $other = $firstOther[$p]
            $bit = 1 -shl $p
            $realBasis = $firstBasis[$p]
            if (($other -band $bit) -ne 0 -or ($realBasis -band $bit) -eq 0 -or
                $survivors[$full -bxor $other] -ne 0 -or
                $survivors[$full -bxor ($other -bor $bit)] -le 0) {
                throw 'Code Sequence retention pivotality invalidated an original one-bit recovery example.'
            }
            $restorationExample = [ordered]@{
                other_original_retained_mask_without_position = $other
                retained_mask_after_adding_original_position = $other -bor $bit
                real_ec072_inclusion_minimal_basis_now_supported = $realBasis
            }
        }
        $positionLedger.Add([ordered]@{
            original_caller_position = $p + 1
            original_position_bit = 1 -shl $p
            pivotal_addition_count_across_all_other_retained_masks = $summed
            original_other_retained_masks_considered = ($size -shr 1)
            pivotal_additions_by_other_retained_budget = $pivotByBudget.ToArray()
            smallest_numeric_actual_restoration_edge = $restorationExample
            ec072_position_present_in_any_minimal_support_basis = ($pivotal[$p] -gt 0)
        })
    }
    if ($directPivotalTotal -ne $totalPivotalEdges) {
        throw 'Code Sequence retention pivotality lost original one-position directed edges.'
    }

    # Human navigation: order by how often adding one ORIGINAL report changes
    # SAVED evidence; stable lower original position breaks ties. This is NOT
    # an importance, risk, priority, recency or causal defect ranking.
    $ranked = [System.Collections.Generic.List[object]]::new()
    $taken = [bool[]]::new($N)
    for ($rank = 1; $rank -le $N; $rank++) {
        $selected = -1
        for ($p = 0; $p -lt $N; $p++) {
            if ($taken[$p]) { continue }
            if ($selected -lt 0 -or $pivotal[$p] -gt $pivotal[$selected]) {
                $selected = $p
            }
        }
        if ($selected -lt 0) { throw 'Code Sequence retention pivotality failed deterministic position navigation.' }
        $taken[$selected] = $true
        $ranked.Add([ordered]@{
            navigation_order = $rank
            original_caller_position = $selected + 1
            pivotal_addition_count = $pivotal[$selected]
        })
    }

    return [ordered]@{
        full_original_selection_saved_witness_multiplicity = [long]$survivors[0]
        original_retained_mask_count = $size
        original_directed_single_position_addition_edge_count = $N * ($size -shr 1)
        supported_retained_original_mask_count = $totalRetainedSupport
        unsupported_retained_original_mask_count = $size - $totalRetainedSupport
        minimum_retained_original_positions_with_real_support = $firstFeasibleBudget
        retained_original_budget_coverage = $edgeEntries.ToArray()
        total_evidence_pivotal_directed_addition_edges = $totalPivotalEdges
        original_position_pivotal_additions = $positionLedger.ToArray()
        original_positions_sorted_by_evidence_pivotal_addition_count = $ranked.ToArray()
        ec072_exact_minimal_original_retained_bases_reconciled = $true
        all_original_budget_edge_conservation_identities_verified = $true
        pivotal_position_if_and_only_if_present_in_original_minimal_basis_and_cut = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPivotality {
    param([object] $ResilienceFrontier, [object] $SupportBasisDuality,
        [object] $WitnessAggregates)

    if ($null -eq $ResilienceFrontier -or $null -eq $SupportBasisDuality -or
        $null -eq $WitnessAggregates -or
        $ResilienceFrontier.scope -cne 'complete_original_report_withholding_resilience_frontiers_exact_saved_witness_masks_no_resequencing' -or
        $SupportBasisDuality.scope -cne 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$SupportBasisDuality.all_ec071_minimal_loss_cuts_have_exact_original_basis_hitting_set_duality -or
        -not [bool]$SupportBasisDuality.every_excluded_position_in_every_minimal_cut_has_a_real_minimal_basis_restoration) {
        throw 'Code Sequence retention pivotality requires both completed ORIGINAL EC-071 and EC-072 results.'
    }
    $n = [int]$ResilienceFrontier.counts.selected_original_report_positions
    $f = [int]$ResilienceFrontier.counts.original_maximal_repeat_family_count
    $baselineG = [int]$ResilienceFrontier.counts.original_global_independent_maximum
    $baselineO = [int]$ResilienceFrontier.counts.original_global_frozen_maximum
    $size = 1 -shl $n
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $recordIds = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $legend = [object[]]$ResilienceFrontier.original_caller_position_bit_legend
    $basisG = [object[]]$SupportBasisDuality.genuine_global_threshold_retained_support_bases
    $basisO = [object[]]$SupportBasisDuality.frozen_global_threshold_retained_support_bases
    $basisFamilies = [object[]]$SupportBasisDuality.individual_original_family_retained_support_bases
    $resilienceFamilies = [object[]]$ResilienceFrontier.original_family_extinction_frontiers
    if ($n -lt 2 -or $n -gt 12 -or $f -lt 0 -or $f -gt 66 -or
        $baselineG -lt 0 -or $baselineG -gt 3 -or $baselineO -lt 0 -or $baselineO -gt $baselineG -or
        $singles.Count -ne $f -or
        $pairs.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 2) -or
        $triples.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 3) -or
        $legend.Count -ne $n -or $recordIds.Count -ne $n -or $classes.Count -ne $n -or
        $basisG.Count -ne $baselineG -or $basisO.Count -ne $baselineO -or
        $basisFamilies.Count -ne $f -or $resilienceFamilies.Count -ne $f -or
        [int]$SupportBasisDuality.counts.original_selected_report_positions -ne $n -or
        [int]$SupportBasisDuality.counts.original_maximal_repeat_family_count -ne $f -or
        [int]$SupportBasisDuality.counts.original_exclusion_masks_checked -ne $size) {
        throw 'Code Sequence retention pivotality found modified original selection or family cardinality.'
    }
    for ($p = 0; $p -lt $n; $p++) {
        if ([int]$legend[$p].original_caller_position -ne $p + 1 -or
            [int]$legend[$p].exclusion_mask_bit -ne (1 -shl $p) -or
            [string]$legend[$p].original_saved_record_id -cne $recordIds[$p] -or
            [int]$legend[$p].original_saved_profile_class_index -ne $classes[$p]) {
            throw 'Code Sequence retention pivotality found changed ORIGINAL report bit identity.'
        }
    }

    # Rebuild original GENUINE and FROZEN histograms from private EC-060 source.
    # The single-family buckets are also kept, so an original family with no
    # witness gets a real zero-support ledger rather than an invented score.
    $tierG = [System.Collections.Generic.List[object]]::new()
    $tierO = [System.Collections.Generic.List[object]]::new()
    $familyG = [System.Collections.Generic.List[object]]::new()
    $familyO = [System.Collections.Generic.List[object]]::new()
    foreach ($tier in @(
        [pscustomobject]@{ Rows = $singles; Minimum = 4 },
        [pscustomobject]@{ Rows = $pairs; Minimum = 8 },
        [pscustomobject]@{ Rows = $triples; Minimum = 12 }
    )) {
        $globalG = [long[]]::new($size)
        $globalO = [long[]]::new($size)
        $ordinal = 0
        foreach ($source in [object[]]$tier.Rows) {
            $ordinal++
            if ($null -eq $source -or [int]$source.registry_index -ne $ordinal -or
                $null -eq $source.genuine -or $null -eq $source.original_local_optima) {
                throw 'Code Sequence retention pivotality lost an ORIGINAL independent/frozen witness source.'
            }
            $oneG = $null; $oneO = $null
            if ([int]$tier.Minimum -eq 4) {
                if (([int[]]$source.family_indices).Count -ne 1 -or
                    [int]$source.family_indices[0] -ne $ordinal) {
                    throw 'Code Sequence retention pivotality found changed individual original family indexing.'
                }
                $oneG = [long[]]::new($size)
                $oneO = [long[]]::new($size)
            }
            Add-CodeSequenceResilienceHistogram -Aggregate $source.genuine `
                -Bucket $globalG -N $n -MinimumOriginalPositions ([int]$tier.Minimum) `
                -AdditionalBucket $oneG
            Add-CodeSequenceResilienceHistogram -Aggregate $source.original_local_optima `
                -Bucket $globalO -N $n -MinimumOriginalPositions ([int]$tier.Minimum) `
                -AdditionalBucket $oneO
            if ([int]$tier.Minimum -eq 4) {
                $familyG.Add($oneG)
                $familyO.Add($oneO)
            }
        }
        $tierG.Add($globalG)
        $tierO.Add($globalO)
    }

    $globalThresholdG = [System.Collections.Generic.List[object]]::new()
    $globalThresholdO = [System.Collections.Generic.List[object]]::new()
    foreach ($orientation in @('genuine', 'frozen')) {
        # Keep typed Lists as single objects; do not pipeline-enumerate a
        # zero/one-member List via an if-expression assignment.
        $previous = $basisG
        $sources = $tierG
        $baseline = $baselineG
        $sink = $globalThresholdG
        if ($orientation -ceq 'frozen') {
            $previous = $basisO
            $sources = $tierO
            $baseline = $baselineO
            $sink = $globalThresholdO
        }
        for ($t = $baseline; $t -ge 1; $t--) {
            $histogram = [long[]]::new($size)
            for ($level = $t; $level -le 3; $level++) {
                $source = [long[]]$sources[$level - 1]
                for ($mask = 1; $mask -lt $size; $mask++) { $histogram[$mask] += $source[$mask] }
            }
            $old = $previous[$baseline - $t]
            if ($null -eq $old -or [int]$old.original_global_family_capacity_at_least -ne $t -or
                [int]$old.original_full_selection_global_family_capacity -ne $baseline) {
                throw 'Code Sequence retention pivotality encountered an inconsistent original capacity threshold.'
            }
            $projection = Get-CodeSequenceRetentionPivotalityProjection `
                -UnionMaskHistogram $histogram `
                -VerifiedBasisBlock $old.retained_position_support_basis_and_loss_cut_restorations -N $n
            if ($projection.full_original_selection_saved_witness_multiplicity -le 0) {
                throw 'Code Sequence retention pivotality found an unreachable advertised original capacity.'
            }
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $t
                original_full_selection_global_family_capacity = $baseline
                original_retention_budget_coverage_and_pivotal_additions = $projection
            })
        }
    }

    $families = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $f; $fi++) {
        $prior = $basisFamilies[$fi]
        $resilience = $resilienceFamilies[$fi]
        if ([int]$prior.original_maximal_repeat_family_index -ne $fi + 1 -or
            [int]$resilience.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence retention pivotality changed original family ordinal.'
        }
        $projectG = Get-CodeSequenceRetentionPivotalityProjection `
            -UnionMaskHistogram ([long[]]$familyG[$fi]) `
            -VerifiedBasisBlock $prior.genuine_retained_position_support_basis_and_restorations -N $n
        $projectO = Get-CodeSequenceRetentionPivotalityProjection `
            -UnionMaskHistogram ([long[]]$familyO[$fi]) `
            -VerifiedBasisBlock $prior.frozen_retained_position_support_basis_and_restorations -N $n
        if ($projectG.full_original_selection_saved_witness_multiplicity -ne
                [long]$resilience.originally_independent_two_window_combination_count -or
            $projectO.full_original_selection_saved_witness_multiplicity -ne
                [long]$resilience.original_full_selection_frozen_optimum_packing_count -or
            $projectO.full_original_selection_saved_witness_multiplicity -gt
                $projectG.full_original_selection_saved_witness_multiplicity) {
            throw 'Code Sequence retention pivotality changed an original family witness baseline.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_retention_budget_coverage_and_pivotal_additions = $projectG
            frozen_original_retention_budget_coverage_and_pivotal_additions = $projectO
        })
    }

    return [ordered]@{
        scope = 'exact_original_retention_budget_coverage_and_single_position_evidence_pivotality'
        pair_index_in_pairwise_profile = [int]$ResilienceFrontier.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$ResilienceFrontier.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$ResilienceFrontier.anchor_index_in_anchor_journeys
        path = [string]$ResilienceFrontier.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            exact_original_retained_masks_checked_per_target = $size
            exact_original_directed_position_additions_checked_per_target = $n * ($size -shr 1)
            genuine_original_global_thresholds = $globalThresholdG.Count
            frozen_original_global_thresholds = $globalThresholdO.Count
            original_individual_family_targets = $families.Count
        }
        genuine_global_threshold_retention_coverage = $globalThresholdG.ToArray()
        frozen_global_threshold_retention_coverage = $globalThresholdO.ToArray()
        individual_original_family_retention_coverage = $families.ToArray()
        uses_ec071_exact_original_position_bit_legend_without_reindexing = $true
        reconciles_ec072_all_minimal_retained_bases_and_position_criticality = $true
        each_original_directed_edge_counted_once_and_all_budget_identities_verified = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        original_full_selection_frozen_optima_not_reoptimized = $true
        original_saved_order_not_authenticated_time_or_new_adjacency = $true
        source_git_network_reads_or_business_worktree_writes = $false
        position_pivotality_proves_real_world_causal_importance_or_fix = $false
    }
}

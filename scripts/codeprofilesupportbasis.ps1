#requires -Version 7.0
<#
    EC-072: exact minimal ORIGINAL retained-position witness bases, dual to
    EC-071 inclusion-minimal withholding cuts. A kept mask K supports a
    threshold precisely if at least one real ORIGINAL witness-union mask M
    is a subset of K. An exclusion E destroys that threshold precisely if
    E intersects every minimal kept basis. Frozen EC-056 full-selection
    choices are never re-optimized after withholding.

    For each previously verified minimal loss cut, prove that restoring ANY
    one excluded position makes a real minimal kept basis available again.
    These are evidence/sensitivity certificates, NOT causal repairs.
    Operates solely on already reconciled in-memory EC-060 histograms and
    the authenticated EC-071 child: no saved-body/source/Git/network I/O.
#>

function Get-CodeSequenceSupportBasisProjection {
    param([long[]] $UnionMaskHistogram, [int] $N)

    $size = 1 -shl $N
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $UnionMaskHistogram -or
        $UnionMaskHistogram.Count -ne $size -or $UnionMaskHistogram[0] -ne 0) {
        throw 'Code Sequence support basis requires a bounded genuine ORIGINAL union-mask histogram.'
    }
    $full = $size - 1
    # The existing exact EC-071 subset-zeta primitive retains actual witness
    # multiplicities. Reverse the exclusion mask to obtain existence for K.
    $survivors = [long[]](Get-CodeSequenceResilienceAllExclusionSurvivors `
        -OriginalUnionMaskWeights $UnionMaskHistogram -N $N)
    $representative = [int[]]::new($size)
    for ($k = 0; $k -lt $size; $k++) { $representative[$k] = -1 }
    $basis = [System.Collections.Generic.List[int]]::new()

    # Numerically increasing masks place every immediate proper subset first.
    # representative[K] is the smallest-numbered inclusion-minimal real
    # support mask contained in K, or -1 if K has no real witness at all.
    for ($kept = 0; $kept -lt $size; $kept++) {
        $best = -1
        for ($bit = 1; $bit -lt $size; $bit = $bit -shl 1) {
            if (($kept -band $bit) -eq 0) { continue }
            $candidate = $representative[$kept -bxor $bit]
            if ($candidate -ge 0 -and ($best -lt 0 -or $candidate -lt $best)) {
                $best = $candidate
            }
        }
        $hasEvidence = $survivors[$full -bxor $kept] -gt 0
        if (-not $hasEvidence) {
            if ($best -ge 0) {
                throw 'Code Sequence support basis violated survivor upward monotonicity.'
            }
            continue
        }
        if ($best -ge 0) {
            $representative[$kept] = $best
        } else {
            # If no proper retained subset works, the exact mask itself must
            # be present in the source histogram, not a fabricated certificate.
            if ($UnionMaskHistogram[$kept] -le 0 -or $kept -eq 0) {
                throw 'Code Sequence support basis cannot find an ORIGINAL minimal witness.'
            }
            $basis.Add($kept)
            $representative[$kept] = $kept
        }
    }
    if ((($representative[$full] -ge 0) -ne ($survivors[0] -gt 0)) -or
        $representative[0] -ne -1 -or $survivors[$full] -ne 0) {
        throw 'Code Sequence support basis failed ORIGINAL boundary reconciliation.'
    }
    return [pscustomobject]@{
        surviving_by_exclusion_mask = $survivors
        minimal_retained_support_masks = [int[]]$basis.ToArray()
        smallest_reachable_support_basis_by_retained_mask = $representative
    }
}

function Get-CodeSequenceSupportBasisDualCertificate {
    param([object] $Projection, [int[]] $ExistingCutMasks,
        [object] $ExistingSmallestCut, [int] $ExistingCutCount, [int] $N)

    $size = 1 -shl $N
    $full = $size - 1
    $survivors = [long[]]$Projection.surviving_by_exclusion_mask
    $bases = [int[]]$Projection.minimal_retained_support_masks
    $representative = [int[]]$Projection.smallest_reachable_support_basis_by_retained_mask
    if ($survivors.Count -ne $size -or $representative.Count -ne $size -or
        $null -eq $ExistingCutMasks -or $ExistingCutMasks.Count -ne $ExistingCutCount) {
        throw 'Code Sequence support basis encountered a truncated EC-071 cut frontier.'
    }
    $actualCuts = [int[]](Get-CodeSequenceResilienceMinimalCuts `
        -SurvivingByExclusionMask $survivors -Threshold 1)
    $actualMinimum = Get-CodeSequenceResilienceSmallestCutSize -Masks $actualCuts
    if (($actualCuts -join ',') -cne ($ExistingCutMasks -join ',') -or
        [string]$actualMinimum -cne [string]$ExistingSmallestCut) {
        throw 'Code Sequence support basis does not dualize the exact EC-071 ORIGINAL loss frontier.'
    }
    $minimumKeep = Get-CodeSequenceResilienceSmallestCutSize -Masks $bases
    $basisBySize = [int[]]::new($N + 1)
    $basisIncidence = [int[]]::new($N)
    $cutIncidence = [int[]]::new($N)
    foreach ($basis in $bases) {
        if ($basis -le 0 -or $basis -gt $full -or
            $representative[$basis] -ne $basis) {
            throw 'Code Sequence support basis registered a nonminimal retained-position set.'
        }
        $basisBySize[(Get-CodeSequenceResiliencePopcount -Mask $basis)]++
        for ($p = 0; $p -lt $N; $p++) {
            if (($basis -band (1 -shl $p)) -ne 0) { $basisIncidence[$p]++ }
        }
    }
    $certificates = [System.Collections.Generic.List[object]]::new()
    foreach ($cut in $actualCuts) {
        $keptAfterCut = $full -bxor $cut
        if ($cut -le 0 -or $cut -gt $full -or
            $representative[$keptAfterCut] -ne -1 -or $survivors[$cut] -ne 0) {
            throw 'Code Sequence support basis accepted a cut with remaining ORIGINAL witness evidence.'
        }
        $onePositionRestorations = [System.Collections.Generic.List[int]]::new()
        for ($p = 0; $p -lt $N; $p++) {
            $bit = 1 -shl $p
            if (($cut -band $bit) -eq 0) { continue }
            $cutIncidence[$p]++
            $basis = $representative[$keptAfterCut -bor $bit]
            # Every excluded position MUST have a concrete minimal ORIGINAL
            # basis which is otherwise wholly outside the loss-inducing cut.
            # The exact crossing is ONE bit, the reinstated position alone.
            if ($basis -le 0 -or $basis -gt $full -or
                ($basis -band $cut) -ne $bit -or
                $survivors[$cut -bxor $bit] -le 0) {
                throw 'Code Sequence support basis could not certify one-position restoration for a minimal loss cut.'
            }
            $onePositionRestorations.Add($basis)
        }
        if ($onePositionRestorations.Count -ne (Get-CodeSequenceResiliencePopcount -Mask $cut)) {
            throw 'Code Sequence support basis lost an original critical cut position.'
        }
        $certificates.Add([ordered]@{
            original_exclusion_mask = $cut
            minimal_retained_basis_mask_for_each_restored_excluded_position = `
                [int[]]$onePositionRestorations.ToArray()
        })
    }
    $bySize = [System.Collections.Generic.List[object]]::new()
    for ($k = 0; $k -le $N; $k++) {
        $bySize.Add([ordered]@{
            retained_original_position_count = $k
            inclusion_minimal_retained_support_basis_count = $basisBySize[$k]
        })
    }
    $byPosition = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $N; $p++) {
        $byPosition.Add([ordered]@{
            original_caller_position = $p + 1
            inclusion_minimal_support_bases_containing_position = $basisIncidence[$p]
            inclusion_minimal_loss_cuts_containing_position = $cutIncidence[$p]
        })
    }
    return [ordered]@{
        minimum_original_positions_to_retain_for_support = $minimumKeep
        inclusion_minimal_retained_support_basis_count = $bases.Count
        inclusion_minimal_retained_original_position_masks = $bases
        original_retained_basis_cardinality_summary = $bySize.ToArray()
        original_position_basis_and_cut_incidence = $byPosition.ToArray()
        verified_ec071_inclusion_minimal_exclusion_cut_count = $actualCuts.Count
        exact_single_position_restoration_certificates = $certificates.ToArray()
        every_ec071_original_cut_dual_and_every_excluded_position_restorable = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileSupportBasisDuality {
    param([object] $ResilienceFrontier, [object] $WitnessAggregates)

    if ($null -eq $ResilienceFrontier -or $null -eq $WitnessAggregates -or
        $ResilienceFrontier.scope -cne 'complete_original_report_withholding_resilience_frontiers_exact_saved_witness_masks_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$ResilienceFrontier.all_ec059_to_ec070_original_exclusion_rows_reconciled -or
        -not [bool]$ResilienceFrontier.all_six_genuine_and_frozen_original_survivor_levels_reconstructed_from_private_weighted_masks) {
        throw 'Code Sequence support basis requires a completed exact ORIGINAL resilience frontier.'
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
    if ($n -lt 2 -or $n -gt 12 -or $f -lt 0 -or $f -gt 66 -or
        $baselineG -lt 0 -or $baselineG -gt 3 -or
        $baselineO -lt 0 -or $baselineO -gt $baselineG -or
        $recordIds.Count -ne $n -or $classes.Count -ne $n -or $legend.Count -ne $n -or
        $singles.Count -ne $f -or
        $pairs.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 2) -or
        $triples.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 3) -or
        ([object[]]$ResilienceFrontier.original_family_extinction_frontiers).Count -ne $f -or
        ([object[]]$ResilienceFrontier.genuine_global_loss_threshold_frontiers).Count -ne $baselineG -or
        ([object[]]$ResilienceFrontier.frozen_global_loss_threshold_frontiers).Count -ne $baselineO) {
        throw 'Code Sequence support basis rejected changed original family or selection cardinality.'
    }
    for ($p = 0; $p -lt $n; $p++) {
        if ([int]$legend[$p].original_caller_position -ne $p + 1 -or
            [string]$legend[$p].original_saved_record_id -cne $recordIds[$p] -or
            [int]$legend[$p].original_saved_profile_class_index -ne $classes[$p] -or
            [int]$legend[$p].exclusion_mask_bit -ne (1 -shl $p)) {
            throw 'Code Sequence support basis changed a verified ORIGINAL bit legend.'
        }
    }

    # Independent from the public cut lists: rebuild actual per-tier and
    # per-family ORIGINAL source masks. Combine ALL source tiers >= t, not
    # just tier t; a surviving higher-tier witness also proves threshold t.
    $tierG = [System.Collections.Generic.List[object]]::new()
    $tierO = [System.Collections.Generic.List[object]]::new()
    $familyG = [System.Collections.Generic.List[object]]::new()
    $familyO = [System.Collections.Generic.List[object]]::new()
    foreach ($tier in @(
        [pscustomobject]@{ Rows = $singles; Minimum = 4 },
        [pscustomobject]@{ Rows = $pairs; Minimum = 8 },
        [pscustomobject]@{ Rows = $triples; Minimum = 12 }
    )) {
        $oneTierG = [long[]]::new($size)
        $oneTierO = [long[]]::new($size)
        $ordinal = 0
        foreach ($source in [object[]]$tier.Rows) {
            $ordinal++
            if ($null -eq $source -or [int]$source.registry_index -ne $ordinal -or
                $null -eq $source.genuine -or $null -eq $source.original_local_optima) {
                throw 'Code Sequence support basis lost an ORIGINAL private family source.'
            }
            $singleG = $null; $singleO = $null
            if ([int]$tier.Minimum -eq 4) {
                if (([int[]]$source.family_indices).Count -ne 1 -or
                    [int]$source.family_indices[0] -ne $ordinal) {
                    throw 'Code Sequence support basis found a changed original family index.'
                }
                $singleG = [long[]]::new($size)
                $singleO = [long[]]::new($size)
            }
            Add-CodeSequenceResilienceHistogram -Aggregate $source.genuine `
                -Bucket $oneTierG -N $n -MinimumOriginalPositions ([int]$tier.Minimum) `
                -AdditionalBucket $singleG
            Add-CodeSequenceResilienceHistogram -Aggregate $source.original_local_optima `
                -Bucket $oneTierO -N $n -MinimumOriginalPositions ([int]$tier.Minimum) `
                -AdditionalBucket $singleO
            if ([int]$tier.Minimum -eq 4) {
                $familyG.Add($singleG)
                $familyO.Add($singleO)
            }
        }
        $tierG.Add($oneTierG)
        $tierO.Add($oneTierO)
    }

    $globalG = [System.Collections.Generic.List[object]]::new()
    $globalO = [System.Collections.Generic.List[object]]::new()
    foreach ($orientation in @('genuine','frozen')) {
        # Retain the typed Lists and even one-row frontier arrays as objects.
        # PowerShell pipeline output in an if-expression can unroll an empty
        # List into $null or a singleton array into a scalar. Both silently
        # break valid original baseline=0/1 support before EC-073 can run.
        $parentRows = [object[]]$ResilienceFrontier.genuine_global_loss_threshold_frontiers
        $sourceTiers = $tierG
        $baseline = $baselineG
        $sink = $globalG
        if ($orientation -ceq 'frozen') {
            $parentRows = [object[]]$ResilienceFrontier.frozen_global_loss_threshold_frontiers
            $sourceTiers = $tierO
            $baseline = $baselineO
            $sink = $globalO
        }
        for ($t = $baseline; $t -ge 1; $t--) {
            $sourceHistogram = [long[]]::new($size)
            for ($level = $t; $level -le 3; $level++) {
                $histogram = [long[]]$sourceTiers[$level - 1]
                for ($mask = 1; $mask -lt $size; $mask++) {
                    $sourceHistogram[$mask] += $histogram[$mask]
                }
            }
            $projection = Get-CodeSequenceSupportBasisProjection `
                -UnionMaskHistogram $sourceHistogram -N $n
            $existing = $parentRows[$baseline - $t]
            if ([int]$existing.original_global_maximum -ne $baseline -or
                [int]$existing.residual_global_maximum_strictly_below -ne $t -or
                $projection.surviving_by_exclusion_mask[0] -le 0) {
                throw 'Code Sequence support basis changed an achievable ORIGINAL global threshold.'
            }
            $dual = Get-CodeSequenceSupportBasisDualCertificate -Projection $projection `
                -ExistingCutMasks ([int[]]$existing.inclusion_minimal_original_exclusion_masks) `
                -ExistingSmallestCut $existing.minimum_withheld_original_positions `
                -ExistingCutCount ([int]$existing.inclusion_minimal_cut_count) -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $t
                original_full_selection_global_family_capacity = $baseline
                retained_position_support_basis_and_loss_cut_restorations = $dual
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $f; $fi++) {
        $existing = $ResilienceFrontier.original_family_extinction_frontiers[$fi]
        if ([int]$existing.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence support basis original family frontier indexing changed.'
        }
        $projectionG = Get-CodeSequenceSupportBasisProjection `
            -UnionMaskHistogram ([long[]]$familyG[$fi]) -N $n
        $projectionO = Get-CodeSequenceSupportBasisProjection `
            -UnionMaskHistogram ([long[]]$familyO[$fi]) -N $n
        if ($projectionG.surviving_by_exclusion_mask[0] -ne
                [long]$existing.originally_independent_two_window_combination_count -or
            $projectionO.surviving_by_exclusion_mask[0] -ne
                [long]$existing.original_full_selection_frozen_optimum_packing_count -or
            $projectionO.surviving_by_exclusion_mask[0] -gt $projectionG.surviving_by_exclusion_mask[0]) {
            throw 'Code Sequence support basis changed original independent/frozen family support.'
        }
        $dualG = Get-CodeSequenceSupportBasisDualCertificate -Projection $projectionG `
            -ExistingCutMasks ([int[]]$existing.genuine_inclusion_minimal_extinction_original_exclusion_masks) `
            -ExistingSmallestCut $existing.genuine_minimum_original_positions_to_extinguish_family `
            -ExistingCutCount ([int]$existing.genuine_inclusion_minimal_extinction_cut_count) -N $n
        $dualO = Get-CodeSequenceSupportBasisDualCertificate -Projection $projectionO `
            -ExistingCutMasks ([int[]]$existing.frozen_inclusion_minimal_extinction_original_exclusion_masks) `
            -ExistingSmallestCut $existing.frozen_minimum_original_positions_to_extinguish_family `
            -ExistingCutCount ([int]$existing.frozen_inclusion_minimal_extinction_cut_count) -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_retained_position_support_basis_and_restorations = $dualG
            frozen_retained_position_support_basis_and_restorations = $dualO
        })
    }
    return [ordered]@{
        scope = 'minimal_retained_original_witness_bases_and_exact_exclusion_cut_restoration_duality'
        pair_index_in_pairwise_profile = [int]$ResilienceFrontier.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$ResilienceFrontier.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$ResilienceFrontier.anchor_index_in_anchor_journeys
        path = [string]$ResilienceFrontier.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            original_exclusion_masks_checked = $size
            genuine_original_global_maximum = $baselineG
            frozen_original_global_maximum = $baselineO
            genuine_global_threshold_support_basis_frontiers = $globalG.Count
            frozen_global_threshold_support_basis_frontiers = $globalO.Count
            individual_original_family_basis_frontiers = $families.Count
        }
        genuine_global_threshold_retained_support_bases = $globalG.ToArray()
        frozen_global_threshold_retained_support_bases = $globalO.ToArray()
        individual_original_family_retained_support_bases = $families.ToArray()
        shares_exact_original_bit_legend_with_ec071 = $true
        all_ec071_minimal_loss_cuts_have_exact_original_basis_hitting_set_duality = $true
        every_excluded_position_in_every_minimal_cut_has_a_real_minimal_basis_restoration = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        original_full_selection_frozen_optima_not_reoptimized = $true
        original_saved_order_not_authenticated_time_or_new_adjacency = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_defect_recency_causation_fix_or_regression_proven = $false
    }
}

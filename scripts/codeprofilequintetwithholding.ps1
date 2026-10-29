#requires -Version 7.0
<#
    EC-063: five ORIGINAL caller positions withheld simultaneously.
    Only project genuine, already observed windows and frozen EC-056 original
    full-selection optimum packings from EC-060 private union-mask witnesses.
    Validate the complete EC-062 quartet parent before extending its evidence.
    Never delete/reindex reports, manufacture new adjacent windows, or infer
    that changes in saved model statements are real fixes or causes.
#>

function Get-CodeSequenceQuintetWithholdingChoose {
    param([int] $N, [int] $K)
    if ($K -lt 0 -or $K -gt $N -or $N -lt 0) { return 0 }
    $v = [long]1
    for ($i = 1; $i -le $K; $i++) {
        $v = [long](($v * ($N - $i + 1)) / $i)
    }
    return [int]$v
}

function Get-CodeSequenceQuintetWithholdingMask {
    param([int[]] $Positions, [int] $N)
    if ($Positions.Count -lt 4 -or $Positions.Count -gt 5 -or
        $N -lt 2 -or $N -gt 12) {
        throw 'Code Sequence fifth-order withholding requires four or five ORIGINAL positions.'
    }
    $mask = 0
    $last = -1
    foreach ($position in $Positions) {
        if ($position -le $last -or $position -lt 0 -or $position -ge $N) {
            throw 'Code Sequence fifth-order withholding requires strictly ascending original positions.'
        }
        $mask = $mask -bor (1 -shl $position)
        $last = $position
    }
    return [int]$mask
}

function Get-CodeSequenceQuintetWithholdingRemainingCount {
    param([object] $Aggregate, [int] $N, [int[]] $Positions)
    $excluded = Get-CodeSequenceQuintetWithholdingMask -Positions $Positions -N $N
    $size = 1 -shl $Positions.Count
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $included = [long[]]$Aggregate.original_position_inclusion_counts
    $pairOverlaps = [long[]]$Aggregate.original_pair_intersection_counts
    $original = [long]$Aggregate.original_combination_count
    if ($masks.Count -ne $weights.Count -or $included.Count -ne $N -or
        $pairOverlaps.Count -ne ($N * $N) -or $original -lt 0) {
        throw 'Code Sequence fifth-order withholding lost its conserved private original witness histogram.'
    }
    if ($original -eq 0) {
        if ($masks.Count -ne 0) {
            throw 'Code Sequence fifth-order withholding found witnesses in an empty original registry.'
        }
        return [long]0
    }
    $subsets = [long[]]::new($size)
    $surviving = [long]0
    $allMasksTotal = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = $masks[$i]
        $weight = $weights[$i]
        if ($weight -le 0 -or $mask -le 0 -or $mask -ge (1 -shl $N)) {
            throw 'Code Sequence fifth-order withholding found invalid original mask or multiplicity.'
        }
        $allMasksTotal += $weight
        if (($mask -band $excluded) -eq 0) { $surviving += $weight }
        $local = 0
        for ($j = 0; $j -lt $Positions.Count; $j++) {
            if (($mask -band (1 -shl $Positions[$j])) -ne 0) {
                $local = $local -bor (1 -shl $j)
            }
        }
        # Real 3/4/5-way intersection terms must use the ACTUAL original
        # common witness masks. Independent pairwise margins cannot supply them.
        $sub = $local
        while ($sub -gt 0) {
            $subsets[$sub] += $weight
            $sub = ($sub - 1) -band $local
        }
    }
    if ($allMasksTotal -ne $original) {
        throw 'Code Sequence fifth-order withholding changed original full witness multiplicity.'
    }
    # Two independent computations: direct disjoint original masks above,
    # and full five-term inclusion/exclusion below. First/second orders are
    # sourced from EC-060's independently checked original marginal ledgers.
    $expected = $original
    for ($sub = 1; $sub -lt $size; $sub++) {
        $bits = [System.Collections.Generic.List[int]]::new()
        for ($j = 0; $j -lt $Positions.Count; $j++) {
            if (($sub -band (1 -shl $j)) -ne 0) { $bits.Add($Positions[$j]) }
        }
        $value = [long]$subsets[$sub]
        if ($bits.Count -eq 1) {
            $value = [long]$included[$bits[0]]
        } elseif ($bits.Count -eq 2) {
            $value = [long]$pairOverlaps[($bits[0] * $N) + $bits[1]]
        }
        if (($bits.Count % 2) -eq 1) { $expected -= $value }
        else { $expected += $value }
    }
    if ($surviving -ne $expected -or $surviving -gt $original -or $surviving -lt 0) {
        throw 'Code Sequence fifth-order withholding violated exact original inclusion/exclusion.'
    }
    return [long]$surviving
}

function Get-CodeSequenceQuintetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int[]] $Positions)
    $genuineTotal = [long]0
    $optimumTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $optimumIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $optimumSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceQuintetWithholdingRemainingCount -Aggregate $row.genuine `
            -N $N -Positions $Positions
        $o = Get-CodeSequenceQuintetWithholdingRemainingCount -Aggregate $row.original_local_optima `
            -N $N -Positions $Positions
        $genuineTotal += $g
        $optimumTotal += $o
        if ($g -gt 0) {
            $genuineIndices.Add([int]$row.registry_index)
            $genuineSets.Add([int[]]$row.family_indices)
        }
        if ($o -gt 0) {
            $optimumIndices.Add([int]$row.registry_index)
            $optimumSets.Add([int[]]$row.family_indices)
        }
    }
    return [ordered]@{
        genuine_total = $genuineTotal
        original_local_optimum_total = $optimumTotal
        genuine_registry_indices = $genuineIndices.ToArray()
        original_local_optimum_registry_indices = $optimumIndices.ToArray()
        genuine_family_sets = $genuineSets.ToArray()
        original_local_optimum_family_sets = $optimumSets.ToArray()
    }
}

function Get-CodeSequenceQuintetWithholdingActiveRows {
    param([object[]] $Rows)
    $active = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        if ([long]$row.genuine.original_combination_count -gt 0 -or
            [long]$row.original_local_optima.original_combination_count -gt 0) {
            $active.Add($row)
        }
    }
    return ,($active.ToArray())
}

function Assert-CodeSequenceQuintetWithholdingMaskCapacity {
    param([object[]] $Rows, [int] $MinimumOriginalPositions)
    foreach ($row in $Rows) {
        foreach ($aggregate in @($row.genuine,$row.original_local_optima)) {
            foreach ($mask in [int[]]$aggregate.nonzero_original_union_masks) {
                $bits = 0
                $value = $mask
                while ($value -ne 0) { $bits += ($value -band 1); $value = $value -shr 1 }
                if ($bits -lt $MinimumOriginalPositions) {
                    throw 'Code Sequence fifth-order withholding found fewer original positions than a genuine disjoint-window witness requires.'
                }
            }
        }
    }
}

function Get-CodeSequenceQuintetWithholdingEmptyJointLayer {
    return [ordered]@{
        genuine_total = [long]0
        original_local_optimum_total = [long]0
        genuine_registry_indices = [int[]]@()
        original_local_optimum_registry_indices = [int[]]@()
        genuine_family_sets = [object[]]@()
        original_local_optimum_family_sets = [object[]]@()
    }
}

function Get-CodeSequenceQuintetWithholdingFifthOnlyFamilyIndices {
    param(
        [object[]] $OriginalParentQuartets,
        [int[]] $QuintetConstituentQuartetIndices,
        [int[]] $SurvivingQuintetFamilyIndices,
        [bool] $OriginalLocalOptima
    )
    if ($QuintetConstituentQuartetIndices.Count -ne 5) {
        throw 'Code Sequence fifth-order family criticality requires five original constituent quartets.'
    }
    $eligible = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt 5; $i++) {
        $qi = $QuintetConstituentQuartetIndices[$i]
        if ($qi -le 0 -or $qi -gt $OriginalParentQuartets.Count) {
            throw 'Code Sequence fifth-order family criticality lost its original quartet index.'
        }
        $parent = $OriginalParentQuartets[$qi - 1]
        $parentIndices = if ($OriginalLocalOptima) {
            [int[]]$parent.original_local_optimum_family_indices
        } else {
            [int[]]$parent.independently_supported_family_indices
        }
        $thisParent = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($family in $parentIndices) {
            if ($family -lt 1) { throw 'Code Sequence fifth-order family criticality found an invalid original family ID.' }
            [void]$thisParent.Add($family)
        }
        if ($i -eq 0) { $eligible.UnionWith($thisParent) }
        else { $eligible.IntersectWith($thisParent) }
    }
    # A family is specifically FIFTH-order-only when every original quartet
    # reports it, but the complete quintet removes all of its original
    # witnesses. This is separate from GLOBAL family-count criticality.
    foreach ($family in $SurvivingQuintetFamilyIndices) { [void]$eligible.Remove($family) }
    $result = [int[]]@($eligible | Sort-Object)
    return ,$result
}

function Assert-CodeSequenceQuintetWithholdingParentParticipation {
    param([object] $ReconstructedLedger, [object[]] $OriginalPublicRows)
    if ($OriginalPublicRows.Count -ne $ReconstructedLedger.criticalG.Count) {
        throw 'Code Sequence fifth-order withholding lost EC-062 original parent incidence rows.'
    }
    for ($i = 0; $i -lt $OriginalPublicRows.Count; $i++) {
        $row = $OriginalPublicRows[$i]
        if ([int]$row.quartets_reducing_original_independent_maximum -ne $ReconstructedLedger.criticalG[$i] -or
            [int]$row.quartets_reducing_original_local_optimum_maximum -ne $ReconstructedLedger.criticalO[$i] -or
            [int]$row.minimally_fourth_order_critical_quartets_for_original_independent_maximum -ne $ReconstructedLedger.minimalG[$i] -or
            [int]$row.minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum -ne $ReconstructedLedger.minimalO[$i] -or
            [int]$row.quartets_with_additional_independent_loss_beyond_stronger_triple -ne $ReconstructedLedger.extraG[$i] -or
            [int]$row.quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple -ne $ReconstructedLedger.extraO[$i]) {
            throw 'Code Sequence fifth-order withholding disagrees with EC-062 original parent participation.'
        }
    }
}

function Assert-CodeSequenceQuintetWithholdingQuartetBridge {
    param(
        [object[]] $Singles, [object[]] $Pairs, [object[]] $Triples,
        [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [string[]] $RecordIds, [int[]] $Classes,
        [int] $N
    )
    # EC-062 has already reconciled EC-061. Reproduce every public EC-062
    # quartet from the original sparse witnesses, including both complete
    # maximizing-set registries, all criticality lists and participation.
    $rows = [object[]]$QuartetWithholding.ordered_original_position_quartet_withholding
    $parentTripleRows = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $pairRows = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $baseG = [int]$QuartetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$QuartetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    $criticalG = [System.Collections.Generic.List[int]]::new()
    $criticalO = [System.Collections.Generic.List[int]]::new()
    $minimalG = [System.Collections.Generic.List[int]]::new()
    $minimalO = [System.Collections.Generic.List[int]]::new()
    $extraG = [System.Collections.Generic.List[int]]::new()
    $extraO = [System.Collections.Generic.List[int]]::new()
    $posLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $N
    $pairLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $pairRows.Count
    $tripleLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentTripleRows.Count
    $ordinal = 0
    for ($p = 0; $p -lt $N; $p++) {
        for ($q = $p + 1; $q -lt $N; $q++) {
            for ($r = $q + 1; $r -lt $N; $r++) {
                for ($s = $r + 1; $s -lt $N; $s++) {
                    $ordinal++
                    $row = $rows[$ordinal - 1]
                    $positions = [int[]]@($p,$q,$r,$s)
                    $pairIndices = [int[]]@(
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $p -Q $q)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $p -Q $r)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $p -Q $s)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $q -Q $r)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $q -Q $s)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $r -Q $s)
                    )
                    $tripleIndices = [int[]]@(
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $N -P $p -Q $q -R $r)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $N -P $p -Q $q -R $s)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $N -P $p -Q $r -R $s)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $N -P $q -Q $r -R $s)
                    )
                    $maxParentG = $baseG; $maxParentO = $baseO
                    foreach ($ti in $tripleIndices) {
                        $parent = $parentTripleRows[$ti - 1]
                        $maxParentG = [math]::Min($maxParentG,
                            [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                        $maxParentO = [math]::Min($maxParentO,
                            [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                    }
                    $one = Get-CodeSequenceQuintetWithholdingLayer -Rows $Singles -N $N -Positions $positions
                    $two = Get-CodeSequenceQuintetWithholdingLayer -Rows $Pairs -N $N -Positions $positions
                    $three = Get-CodeSequenceQuintetWithholdingLayer -Rows $Triples -N $N -Positions $positions
                    $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $two `
                        -Triple $three -OriginalLocalOptima $false
                    $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $two `
                        -Triple $three -OriginalLocalOptima $true
                    $g = [int]$gMax.distinct_family_count
                    $o = [int]$oMax.distinct_family_count
                    $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
                    $minimalOnlyG = $reducedG -and $maxParentG -eq $baseG
                    $minimalOnlyO = $reducedO -and $maxParentO -eq $baseO
                    $additionalG = [int]$maxParentG - $g
                    $additionalO = [int]$maxParentO - $o
                    if ($null -eq $row -or [int]$row.original_position_quartet_index -ne $ordinal -or
                        ($row.withheld_original_caller_positions -join ':') -cne
                            "$(($p+1)):$(($q+1)):$(($r+1)):$(($s+1))" -or
                        ($row.withheld_original_record_ids -join ':') -cne
                            "$($RecordIds[$p]):$($RecordIds[$q]):$($RecordIds[$r]):$($RecordIds[$s])" -or
                        ($row.original_saved_profile_class_indices -join ':') -cne
                            "$($Classes[$p]):$($Classes[$q]):$($Classes[$r]):$($Classes[$s])" -or
                        ($row.original_constituent_position_pair_indices -join ':') -cne ($pairIndices -join ':') -or
                        ($row.original_constituent_position_triple_indices -join ':') -cne ($tripleIndices -join ':') -or
                        [long]$row.surviving_original_independent_two_window_combinations -ne $one.genuine_total -or
                        [long]$row.surviving_original_joint_four_window_combinations -ne $two.genuine_total -or
                        [long]$row.surviving_original_joint_six_window_combinations -ne $three.genuine_total -or
                        [long]$row.surviving_original_full_selection_local_optimum_individual_packings -ne $one.original_local_optimum_total -or
                        [long]$row.surviving_original_full_selection_joint_local_optimum_packing_pairs -ne $two.original_local_optimum_total -or
                        [long]$row.surviving_original_full_selection_joint_local_optimum_packing_triples -ne $three.original_local_optimum_total -or
                        [int]$row.globally_maximum_simultaneously_independently_supported_distinct_family_count -ne $g -or
                        [int]$row.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count -ne $o -or
                        [bool]$row.reduces_original_global_maximum_independent_family_count -ne $reducedG -or
                        [bool]$row.reduces_original_global_maximum_original_local_optimum_family_count -ne $reducedO -or
                        [bool]$row.minimally_fourth_order_critical_for_original_independent_maximum -ne $minimalOnlyG -or
                        [bool]$row.minimally_fourth_order_critical_for_original_local_optimum_maximum -ne $minimalOnlyO -or
                        [int]$row.strongest_constituent_triple_independent_family_maximum -ne $maxParentG -or
                        [int]$row.strongest_constituent_triple_original_local_optimum_family_maximum -ne $maxParentO -or
                        [int]$row.additional_independent_family_loss_beyond_stronger_triple_exclusion -ne $additionalG -or
                        [int]$row.additional_original_local_optimum_family_loss_beyond_stronger_triple_exclusion -ne $additionalO) {
                        throw 'Code Sequence fifth-order withholding disagrees with an original EC-062 quartet parent.'
                    }
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $one.genuine_registry_indices -Expected $row.independently_supported_family_indices
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $two.genuine_registry_indices -Expected $row.jointly_supported_family_pair_indices
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $three.genuine_registry_indices -Expected $row.jointly_supported_family_triple_indices
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $one.original_local_optimum_registry_indices -Expected $row.original_local_optimum_family_indices
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $two.original_local_optimum_registry_indices -Expected $row.jointly_compatible_original_local_optimum_family_pair_indices
                    Assert-CodeSequencePairWithholdingOrdinalList -Actual $three.original_local_optimum_registry_indices -Expected $row.jointly_compatible_original_local_optimum_family_triple_indices
                    Assert-CodeSequenceWithholdingFamilySets -Actual $gMax.all_attaining_family_index_sets -Expected $row.all_attaining_family_index_sets
                    Assert-CodeSequenceWithholdingFamilySets -Actual $oMax.all_attaining_family_index_sets -Expected $row.all_attaining_original_local_optimum_family_index_sets
                    if ($reducedG) { $criticalG.Add($ordinal) }; if ($reducedO) { $criticalO.Add($ordinal) }
                    if ($minimalOnlyG) { $minimalG.Add($ordinal) }; if ($minimalOnlyO) { $minimalO.Add($ordinal) }
                    if ($additionalG -gt 0) { $extraG.Add($ordinal) }; if ($additionalO -gt 0) { $extraO.Add($ordinal) }
                    $flags = @{
                        ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                        MinimalG = [bool]$minimalOnlyG; MinimalO = [bool]$minimalOnlyO
                        ExtraG = [bool]($additionalG -gt 0); ExtraO = [bool]($additionalO -gt 0)
                    }
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $posLedger -Indices $positions @flags
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedger -Indices $pairIndices -OneBased @flags
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedger -Indices $tripleIndices -OneBased @flags
                }
            }
        }
    }
    if ($ordinal -ne $rows.Count -or
        $ordinal -ne [int]$QuartetWithholding.counts.unordered_original_position_quartet_count -or
        [int]$QuartetWithholding.counts.number_of_quartets_reducing_original_independent_maximum -ne $criticalG.Count -or
        [int]$QuartetWithholding.counts.number_of_quartets_reducing_original_local_optimum_maximum -ne $criticalO.Count -or
        [int]$QuartetWithholding.counts.number_of_minimally_fourth_order_critical_quartets_for_original_independent_maximum -ne $minimalG.Count -or
        [int]$QuartetWithholding.counts.number_of_minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum -ne $minimalO.Count -or
        [int]$QuartetWithholding.counts.number_of_quartets_with_additional_independent_loss_beyond_stronger_triple -ne $extraG.Count -or
        [int]$QuartetWithholding.counts.number_of_quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple -ne $extraO.Count) {
        throw 'Code Sequence fifth-order withholding found truncated original quartet parent.'
    }
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $criticalG.ToArray() -Expected $QuartetWithholding.original_position_quartet_indices_reducing_independent_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $criticalO.ToArray() -Expected $QuartetWithholding.original_position_quartet_indices_reducing_original_local_optimum_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $minimalG.ToArray() -Expected $QuartetWithholding.minimally_fourth_order_critical_quartet_indices_for_independent_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $minimalO.ToArray() -Expected $QuartetWithholding.minimally_fourth_order_critical_quartet_indices_for_original_local_optimum_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $extraG.ToArray() -Expected $QuartetWithholding.quartet_indices_causing_additional_independent_loss_vs_stronger_triple
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $extraO.ToArray() -Expected $QuartetWithholding.quartet_indices_causing_additional_original_local_optimum_loss_vs_stronger_triple
    Assert-CodeSequenceQuintetWithholdingParentParticipation -ReconstructedLedger $posLedger `
        -OriginalPublicRows $QuartetWithholding.ordered_original_position_quartet_participation
    Assert-CodeSequenceQuintetWithholdingParentParticipation -ReconstructedLedger $pairLedger `
        -OriginalPublicRows $QuartetWithholding.ordered_original_pair_quartet_participation
    Assert-CodeSequenceQuintetWithholdingParentParticipation -ReconstructedLedger $tripleLedger `
        -OriginalPublicRows $QuartetWithholding.ordered_original_triple_quartet_participation
}

function Get-CodeSequenceOriginalFindingPairProfileQuintetPositionWithholding {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $WitnessAggregates)
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $TripleWithholding -or
        $null -eq $QuartetWithholding -or $null -eq $WitnessAggregates -or
        $QuartetWithholding.scope -cne 'unordered_four_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$QuartetWithholding.complete_original_ec061_triple_projections_and_private_witness_masks_reconciled -or
        -not [bool]$QuartetWithholding.independent_of_sequence_top -or
        -not [bool]$QuartetWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence fifth-order withholding requires complete original EC-062 quartet parent and private original witnesses.'
    }
    $n = [int]$QuartetWithholding.counts.selected_report_positions
    $f = [int]$QuartetWithholding.counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $parentQuartets = [object[]]$QuartetWithholding.ordered_original_position_quartet_withholding
    $parentPairs = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $parentTriples = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $baseG = [int]$QuartetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$QuartetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $f -lt 0 -or $f -gt 66 -or $records.Count -ne $n -or $classes.Count -ne $n -or
        $Atlas.positions.Count -ne $n -or [int]$Atlas.counts.selected_report_positions -ne $n -or
        $singles.Count -ne $f -or
        $pairs.Count -ne (Get-CodeSequenceQuintetWithholdingChoose -N $f -K 2) -or
        $triples.Count -ne (Get-CodeSequenceQuintetWithholdingChoose -N $f -K 3) -or
        $parentPairs.Count -ne (Get-CodeSequenceQuintetWithholdingChoose -N $n -K 2) -or
        $parentTriples.Count -ne (Get-CodeSequenceQuintetWithholdingChoose -N $n -K 3) -or
        $parentQuartets.Count -ne (Get-CodeSequenceQuintetWithholdingChoose -N $n -K 4) -or
        [int]$PairWithholding.counts.selected_report_positions -ne $n -or
        [int]$TripleWithholding.counts.selected_report_positions -ne $n -or
        [int]$TripleWithholding.counts.original_maximal_repeat_family_count -ne $f -or
        [int]$PairWithholding.counts.original_maximal_repeat_family_count -ne $f -or
        [int]$PairWithholding.counts.original_global_maximum_independently_supported_distinct_family_count -ne $baseG -or
        [int]$TripleWithholding.counts.original_global_maximum_independently_supported_distinct_family_count -ne $baseG -or
        [int]$PairWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count -ne $baseO -or
        [int]$TripleWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count -ne $baseO -or
        $baseG -lt 0 -or $baseG -gt 3 -or $baseO -lt 0 -or $baseO -gt $baseG) {
        throw 'Code Sequence fifth-order withholding found inconsistent original report/family cardinality.'
    }
    for ($i = 0; $i -lt $n; $i++) {
        if ([int]$Atlas.positions[$i].position -ne $i + 1 -or
            $Atlas.positions[$i].record_id -cne $records[$i] -or
            [int]$Atlas.positions[$i].profile_class_index -ne $classes[$i]) {
            throw 'Code Sequence fifth-order withholding changed original report positions or saved classes.'
        }
    }
    for ($level = 1; $level -le 3; $level++) {
        if ($level -eq 1) { $group = $singles }
        elseif ($level -eq 2) { $group = $pairs }
        else { $group = $triples }
        $order = 0
        foreach ($entry in $group) {
            $order++
            if ([int]$entry.registry_index -ne $order) {
                throw 'Code Sequence fifth-order withholding changed an original family registry ordinal.'
            }
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $entry.genuine -N $n
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $entry.original_local_optima -N $n
        }
    }
    $activeSingles = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $singles
    $activePairs = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $pairs
    $activeTriples = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $triples
    Assert-CodeSequenceQuintetWithholdingQuartetBridge -Singles $activeSingles -Pairs $activePairs `
        -Triples $activeTriples -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -RecordIds $records -Classes $classes -N $n
    # A real pair of independently supported families needs >=8 *distinct*
    # original positions (four nonoverlapping motif occurrences); a triple
    # needs >=12. At N<=12, five exclusions leave at most seven positions.
    # Validate the footprint of each private original mask ONCE; thereafter
    # pair/triple survivors are provably empty without 792 repeated scans.
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $pairs -MinimumOriginalPositions 8
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $triples -MinimumOriginalPositions 12
    $emptyJoint = Get-CodeSequenceQuintetWithholdingEmptyJointLayer
    $quartetIndexByMask = [System.Collections.Generic.Dictionary[int,int]]::new()
    foreach ($row in $parentQuartets) {
        $originalPositions = [int[]]$row.withheld_original_caller_positions
        $zeroBased = [int[]]@($originalPositions | ForEach-Object { $_ - 1 })
        $mask = Get-CodeSequenceQuintetWithholdingMask -Positions $zeroBased -N $n
        if ($quartetIndexByMask.ContainsKey($mask)) {
            throw 'Code Sequence fifth-order withholding found duplicate original quartet parent.'
        }
        $quartetIndexByMask.Add($mask,[int]$row.original_position_quartet_index)
    }
    $result = [System.Collections.Generic.List[object]]::new()
    $criticalG = [System.Collections.Generic.List[int]]::new()
    $criticalO = [System.Collections.Generic.List[int]]::new()
    $minimalG = [System.Collections.Generic.List[int]]::new()
    $minimalO = [System.Collections.Generic.List[int]]::new()
    $extraG = [System.Collections.Generic.List[int]]::new()
    $extraO = [System.Collections.Generic.List[int]]::new()
    $familyOnlyG = [System.Collections.Generic.List[int]]::new()
    $familyOnlyO = [System.Collections.Generic.List[int]]::new()
    $familyOnlyGEvents = [long]0
    $familyOnlyOEvents = [long]0
    $posLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $n
    $pairLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentPairs.Count
    $tripleLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentTriples.Count
    $quartetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentQuartets.Count
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 5) { $minG = $baseG; $minO = $baseO; $maxG = 0; $maxO = 0 }
    $ordinal = 0
    for ($p = 0; $p -lt $n; $p++) {
        for ($q = $p + 1; $q -lt $n; $q++) {
            for ($r = $q + 1; $r -lt $n; $r++) {
                for ($s = $r + 1; $s -lt $n; $s++) {
                    for ($t = $s + 1; $t -lt $n; $t++) {
                        $ordinal++
                        $positions = [int[]]@($p,$q,$r,$s,$t)
                        $pairIndices = [System.Collections.Generic.List[int]]::new()
                        $tripleIndices = [System.Collections.Generic.List[int]]::new()
                        $quartetIndices = [System.Collections.Generic.List[int]]::new()
                        for ($a = 0; $a -lt 5; $a++) {
                            for ($b = $a + 1; $b -lt 5; $b++) {
                                $pairIndices.Add((Get-CodeSequenceTripleWithholdingPairOrdinal `
                                    -N $n -P $positions[$a] -Q $positions[$b]))
                                for ($c = $b + 1; $c -lt 5; $c++) {
                                    $tripleIndices.Add((Get-CodeSequenceQuartetWithholdingTripleOrdinal `
                                        -N $n -P $positions[$a] -Q $positions[$b] -R $positions[$c]))
                                }
                            }
                        }
                        for ($excludedIndex = 0; $excludedIndex -lt 5; $excludedIndex++) {
                            $other = [System.Collections.Generic.List[int]]::new()
                            for ($a = 0; $a -lt 5; $a++) {
                                if ($a -ne $excludedIndex) { $other.Add($positions[$a]) }
                            }
                            $mask = Get-CodeSequenceQuintetWithholdingMask -Positions $other.ToArray() -N $n
                            if (-not $quartetIndexByMask.ContainsKey($mask)) {
                                throw 'Code Sequence fifth-order withholding lost an original constituent quartet.'
                            }
                            $quartetIndices.Add($quartetIndexByMask[$mask])
                        }
                        $pairOrdinals = $pairIndices.ToArray()
                        $tripleOrdinals = $tripleIndices.ToArray()
                        $quartetOrdinals = [int[]]@($quartetIndices.ToArray() | Sort-Object)
                        $one = Get-CodeSequenceQuintetWithholdingLayer -Rows $activeSingles `
                            -N $n -Positions $positions
                        $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                            -Triple $emptyJoint -OriginalLocalOptima $false
                        $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                            -Triple $emptyJoint -OriginalLocalOptima $true
                        $g = [int]$gMax.distinct_family_count
                        $o = [int]$oMax.distinct_family_count
                        $fifthOnlyFamiliesG = Get-CodeSequenceQuintetWithholdingFifthOnlyFamilyIndices `
                            -OriginalParentQuartets $parentQuartets -QuintetConstituentQuartetIndices $quartetOrdinals `
                            -SurvivingQuintetFamilyIndices $one.genuine_registry_indices -OriginalLocalOptima $false
                        $fifthOnlyFamiliesO = Get-CodeSequenceQuintetWithholdingFifthOnlyFamilyIndices `
                            -OriginalParentQuartets $parentQuartets -QuintetConstituentQuartetIndices $quartetOrdinals `
                            -SurvivingQuintetFamilyIndices $one.original_local_optimum_registry_indices -OriginalLocalOptima $true
                        if ($fifthOnlyFamiliesG.Count -gt 0) { $familyOnlyG.Add($ordinal) }
                        if ($fifthOnlyFamiliesO.Count -gt 0) { $familyOnlyO.Add($ordinal) }
                        $familyOnlyGEvents += $fifthOnlyFamiliesG.Count
                        $familyOnlyOEvents += $fifthOnlyFamiliesO.Count
                        $parentMinG = $baseG; $parentMinO = $baseO
                        foreach ($qi in $quartetOrdinals) {
                            $parent = $parentQuartets[$qi - 1]
                            if ([int]$parent.original_position_quartet_index -ne $qi) {
                                throw 'Code Sequence fifth-order withholding lost original quartet order.'
                            }
                            $parentMinG = [math]::Min($parentMinG,
                                [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                            $parentMinO = [math]::Min($parentMinO,
                                [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                        }
                        if ($g -gt [math]::Floor(($n - 5) / 4) -or $g -gt $parentMinG -or
                            $o -gt $parentMinO -or $o -gt $g -or $g -gt $baseG -or $o -gt $baseO) {
                            throw 'Code Sequence fifth-order withholding violated real-window capacity or quartet monotonicity.'
                        }
                        $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
                        $fifthOnlyG = $reducedG -and $parentMinG -eq $baseG
                        $fifthOnlyO = $reducedO -and $parentMinO -eq $baseO
                        $additionalG = [int]$parentMinG - $g
                        $additionalO = [int]$parentMinO - $o
                        if ($reducedG) { $criticalG.Add($ordinal) }; if ($reducedO) { $criticalO.Add($ordinal) }
                        if ($fifthOnlyG) { $minimalG.Add($ordinal) }; if ($fifthOnlyO) { $minimalO.Add($ordinal) }
                        if ($additionalG -gt 0) { $extraG.Add($ordinal) }; if ($additionalO -gt 0) { $extraO.Add($ordinal) }
                        $flags = @{
                            ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                            MinimalG = [bool]$fifthOnlyG; MinimalO = [bool]$fifthOnlyO
                            ExtraG = [bool]($additionalG -gt 0); ExtraO = [bool]($additionalO -gt 0)
                        }
                        Add-CodeSequenceQuartetWithholdingParticipation -Ledger $posLedger -Indices $positions @flags
                        Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedger -Indices $pairOrdinals -OneBased @flags
                        Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedger -Indices $tripleOrdinals -OneBased @flags
                        Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quartetLedger -Indices $quartetOrdinals -OneBased @flags
                        $minG = [math]::Min($minG,$g); $maxG = [math]::Max($maxG,$g)
                        $minO = [math]::Min($minO,$o); $maxO = [math]::Max($maxO,$o)
                        $result.Add([ordered]@{
                            original_position_quintet_index = $ordinal
                            withheld_original_caller_positions = [int[]]@(($p+1),($q+1),($r+1),($s+1),($t+1))
                            withheld_original_record_ids = [string[]]@($records[$p],$records[$q],$records[$r],$records[$s],$records[$t])
                            original_saved_profile_class_indices = [int[]]@($classes[$p],$classes[$q],$classes[$r],$classes[$s],$classes[$t])
                            original_constituent_position_pair_indices = $pairOrdinals
                            original_constituent_position_triple_indices = $tripleOrdinals
                            original_constituent_position_quartet_indices = $quartetOrdinals
                            surviving_original_independent_two_window_combinations = $one.genuine_total
                            surviving_original_joint_four_window_combinations = [long]0
                            surviving_original_joint_six_window_combinations = [long]0
                            surviving_original_full_selection_local_optimum_individual_packings = $one.original_local_optimum_total
                            surviving_original_full_selection_joint_local_optimum_packing_pairs = [long]0
                            surviving_original_full_selection_joint_local_optimum_packing_triples = [long]0
                            independently_supported_family_indices = $one.genuine_registry_indices
                            jointly_supported_family_pair_indices = [int[]]@()
                            jointly_supported_family_triple_indices = [int[]]@()
                            original_local_optimum_family_indices = $one.original_local_optimum_registry_indices
                            genuinely_fifth_order_only_lost_original_family_indices = $fifthOnlyFamiliesG
                            frozen_original_optimum_fifth_order_only_lost_original_family_indices = $fifthOnlyFamiliesO
                            jointly_compatible_original_local_optimum_family_pair_indices = [int[]]@()
                            jointly_compatible_original_local_optimum_family_triple_indices = [int[]]@()
                            globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                            all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                            reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                            globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                            all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                            reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                            minimally_fifth_order_critical_for_original_independent_maximum = [bool]$fifthOnlyG
                            minimally_fifth_order_critical_for_original_local_optimum_maximum = [bool]$fifthOnlyO
                            strongest_constituent_quartet_independent_family_maximum = $parentMinG
                            strongest_constituent_quartet_original_local_optimum_family_maximum = $parentMinO
                            additional_independent_family_loss_beyond_stronger_quartet_exclusion = $additionalG
                            additional_original_local_optimum_family_loss_beyond_stronger_quartet_exclusion = $additionalO
                        })
                    }
                }
            }
        }
    }
    if ($ordinal -ne (Get-CodeSequenceQuintetWithholdingChoose -N $n -K 5)) {
        throw 'Code Sequence fifth-order withholding did not enumerate every ORIGINAL quintet.'
    }
    $perPosition = [System.Collections.Generic.List[object]]::new()
    $perPair = [System.Collections.Generic.List[object]]::new()
    $perTriple = [System.Collections.Generic.List[object]]::new()
    $perQuartet = [System.Collections.Generic.List[object]]::new()
    $incidenceTable = @(
        @($posLedger,$perPosition,'position',$n,1),
        @($pairLedger,$perPair,'pair',$parentPairs.Count,2),
        @($tripleLedger,$perTriple,'triple',$parentTriples.Count,3),
        @($quartetLedger,$perQuartet,'quartet',$parentQuartets.Count,4)
    )
    foreach ($kind in $incidenceTable) {
        $ledger = $kind[0]; $out = $kind[1]; $name = [string]$kind[2]
        $count = [int]$kind[3]; $level = [int]$kind[4]
        for ($i = 0; $i -lt $count; $i++) {
            $memberPositions = if ($level -eq 1) { [int[]]@($i+1) }
                elseif ($level -eq 2) { [int[]]$parentPairs[$i].withheld_original_caller_positions }
                elseif ($level -eq 3) { [int[]]$parentTriples[$i].withheld_original_caller_positions }
                else { [int[]]$parentQuartets[$i].withheld_original_caller_positions }
            $row = [ordered]@{
                original_constituent_type = $name
                original_constituent_index = $i + 1
                original_caller_positions = $memberPositions
                number_of_position_quintets_containing_constituent = (Get-CodeSequenceQuintetWithholdingChoose -N ($n-$level) -K (5-$level))
                quintets_reducing_original_independent_maximum = $ledger.criticalG[$i]
                quintets_reducing_original_local_optimum_maximum = $ledger.criticalO[$i]
                minimally_fifth_order_critical_quintets_for_original_independent_maximum = $ledger.minimalG[$i]
                minimally_fifth_order_critical_quintets_for_original_local_optimum_maximum = $ledger.minimalO[$i]
                quintets_with_additional_independent_loss_beyond_stronger_quartet = $ledger.extraG[$i]
                quintets_with_additional_original_local_optimum_loss_beyond_stronger_quartet = $ledger.extraO[$i]
            }
            if ($level -eq 1) {
                $row['original_record_id'] = $records[$i]
                $row['original_saved_profile_class_index'] = $classes[$i]
            }
            $out.Add($row)
        }
    }
    foreach ($property in @('criticalG','criticalO','minimalG','minimalO','extraG','extraO')) {
        $matching = switch ($property) {
            'criticalG' { $criticalG.Count }; 'criticalO' { $criticalO.Count }
            'minimalG' { $minimalG.Count }; 'minimalO' { $minimalO.Count }
            'extraG' { $extraG.Count }; 'extraO' { $extraO.Count }
        }
        $totalPosition = [long]0; $totalPair = [long]0; $totalTriple = [long]0; $totalQuartet = [long]0
        foreach ($v in $posLedger[$property]) { $totalPosition += $v }
        foreach ($v in $pairLedger[$property]) { $totalPair += $v }
        foreach ($v in $tripleLedger[$property]) { $totalTriple += $v }
        foreach ($v in $quartetLedger[$property]) { $totalQuartet += $v }
        if ($totalPosition -ne (5 * [long]$matching) -or
            $totalPair -ne (10 * [long]$matching) -or
            $totalTriple -ne (10 * [long]$matching) -or
            $totalQuartet -ne (5 * [long]$matching)) {
            throw 'Code Sequence fifth-order withholding lost exact 5/10/10/5 original participation incidence.'
        }
    }
    return [ordered]@{
        scope = 'unordered_five_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$QuartetWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$QuartetWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$QuartetWithholding.anchor_index_in_anchor_journeys
        path = [string]$QuartetWithholding.path
        exact_saved_quote_anchor = $QuartetWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            unordered_original_position_quintet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baseG
            original_global_maximum_original_locally_optimal_distinct_family_count = $baseO
            number_of_quintets_reducing_original_independent_maximum = $criticalG.Count
            number_of_quintets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_fifth_order_critical_quintets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_fifth_order_critical_quintets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_quintets_with_additional_independent_loss_beyond_stronger_quartet = $extraG.Count
            number_of_quintets_with_additional_original_local_optimum_loss_beyond_stronger_quartet = $extraO.Count
            number_of_quintets_with_genuinely_fifth_order_only_original_family_loss = $familyOnlyG.Count
            number_of_quintets_with_frozen_original_optimum_fifth_order_only_family_loss = $familyOnlyO.Count
            genuine_fifth_order_only_original_family_loss_events = $familyOnlyGEvents
            frozen_original_optimum_fifth_order_only_family_loss_events = $familyOnlyOEvents
            minimum_global_independent_family_maximum_after_five_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_five_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_five_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_five_withheld_positions = $maxO
        }
        original_position_quintet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_quintet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_fifth_order_critical_quintet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_fifth_order_critical_quintet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        quintet_indices_causing_additional_independent_loss_vs_stronger_quartet = $extraG.ToArray()
        quintet_indices_causing_additional_original_local_optimum_loss_vs_stronger_quartet = $extraO.ToArray()
        quintet_indices_with_genuinely_fifth_order_only_original_family_loss = $familyOnlyG.ToArray()
        quintet_indices_with_frozen_original_optimum_fifth_order_only_family_loss = $familyOnlyO.ToArray()
        ordered_original_position_quintet_withholding = $result.ToArray()
        ordered_original_position_quintet_participation = $perPosition.ToArray()
        ordered_original_pair_quintet_participation = $perPair.ToArray()
        ordered_original_triple_quintet_participation = $perTriple.ToArray()
        ordered_original_quartet_quintet_participation = $perQuartet.ToArray()
        complete_original_ec062_quartet_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'For each complete ascending original report-position quintet, count ONLY the previously observed genuine two-window motif combinations and separately frozen original full-selection optimal family packings that avoid all five positions. Preserve exact original report IDs and ancestor pair/triple/quartet ordinals. In N<=12, withholding five leaves at most seven positions, so no genuine or frozen four-/six-window jointly independent family combination can survive. All original weighted masks and EVERY EC-062 parent quartet are checked; true five-way inclusion/exclusion is reconciled to direct original masked survival. Fifth-order-only global criticality requires each constituent original quartet to preserve the baseline while the whole quintet reduces it; separately expose each original family with a genuine or frozen witness in all five constituent quartets but no surviving witness in the quintet, even when the global count was already reduced. Additional loss beyond the strongest constituent quartet is tracked independently. Input order is not authenticated chronology, histogram agreement is not proof of real Finding identity or recurrence, and simulated evidence exclusion is not record deletion, source editing, causal intervention, repair, regression or verified risk.'
    }
}

#requires -Version 7.0
<#
    EC-062: exhaustive FOUR-original-position evidence withholding.
    Reuse ONLY the private EC-060 original full-selection witness masks after
    the unchanged EC-061 triple projection succeeds. Never splice former
    neighbors, infer new occurrences, reread evidence or re-optimize frozen
    original EC-056 packings. Minimal FOURTH-order loss requires ALL FOUR
    original constituent triple exclusions to preserve the baseline maximum.
#>

function Get-CodeSequenceQuartetWithholdingTripleOrdinal {
    param([int] $N, [int] $P, [int] $Q, [int] $R)
    if ($N -lt 3 -or $N -gt 12 -or $P -lt 0 -or $P -ge $Q -or
        $Q -ge $R -or $R -ge $N) {
        throw 'Code Sequence quartet withholding requires ascending ORIGINAL triple positions.'
    }
    # Exact ONE-based EC-061 canonical p/q/r outer-to-inner ordinal.
    $before = 0
    for ($a = 0; $a -lt $P; $a++) {
        $afterA = $N - $a - 1
        $before += [int](($afterA * ($afterA - 1)) / 2)
    }
    for ($b = $P + 1; $b -lt $Q; $b++) {
        $before += $N - $b - 1
    }
    return [int]($before + $R - $Q)
}

function Get-CodeSequenceQuartetWithholdingRemainingCount {
    param(
        [object] $Aggregate,
        [int] $N,
        [int] $P,
        [int] $Q,
        [int] $R,
        [int] $S
    )
    if ($P -lt 0 -or $P -ge $Q -or $Q -ge $R -or
        $R -ge $S -or $S -ge $N -or $N -gt 12) {
        throw 'Code Sequence quartet withholding requires four ascending original positions.'
    }
    $positions = [int[]]@($P,$Q,$R,$S)
    $excluded = (1 -shl $P) -bor (1 -shl $Q) -bor (1 -shl $R) -bor (1 -shl $S)
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $included = [long[]]$Aggregate.original_position_inclusion_counts
    $pairOverlaps = [long[]]$Aggregate.original_pair_intersection_counts
    if ($masks.Count -ne $weights.Count -or $included.Count -ne $N -or
        $pairOverlaps.Count -ne ($N * $N)) {
        throw 'Code Sequence quartet withholding lost its conserved original mask histogram.'
    }
    # Original genuine windows are represented by weighted original-position
    # UNION masks. This counts all separate witnesses having an equal mask.
    $survivors = [long]0
    $fourIntersection = [long]0
    $tripleIntersections = [long[]]::new(4)
    $tripleMasks = [int[]]@(
        ($excluded -bxor (1 -shl $P))
        ($excluded -bxor (1 -shl $Q))
        ($excluded -bxor (1 -shl $R))
        ($excluded -bxor (1 -shl $S))
    )
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $overlap = $masks[$i] -band $excluded
        $weight = $weights[$i]
        if ($weight -le 0) {
            throw 'Code Sequence quartet withholding lost original witness multiplicity.'
        }
        if ($overlap -eq 0) { $survivors += $weight }
        if ($overlap -eq $excluded) { $fourIntersection += $weight }
        for ($t = 0; $t -lt 4; $t++) {
            if (($overlap -band $tripleMasks[$t]) -eq $tripleMasks[$t]) {
                $tripleIntersections[$t] += $weight
            }
        }
    }
    # Independent four-term inclusion/exclusion on the EXACT ORIGINAL masks:
    # total - sum(Ip) + sum(Ipq) - sum(Ipqr) + I(pqrs).
    $expected = [long]$Aggregate.original_combination_count
    foreach ($pos in $positions) { $expected -= $included[$pos] }
    for ($a = 0; $a -lt 4; $a++) {
        for ($b = $a + 1; $b -lt 4; $b++) {
            $expected += $pairOverlaps[($positions[$a] * $N) + $positions[$b]]
        }
    }
    foreach ($count in $tripleIntersections) { $expected -= $count }
    $expected += $fourIntersection
    if ($survivors -lt 0 -or $survivors -gt [long]$Aggregate.original_combination_count -or
        $survivors -ne $expected) {
        throw 'Code Sequence quartet withholding violated exact fourth-order inclusion/exclusion.'
    }
    return [long]$survivors
}

function Get-CodeSequenceQuartetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int] $P, [int] $Q, [int] $R, [int] $S)
    $genuineTotal = [long]0
    $optimumTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $optimumIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $optimumSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceQuartetWithholdingRemainingCount -Aggregate $row.genuine `
            -N $N -P $P -Q $Q -R $R -S $S
        $o = Get-CodeSequenceQuartetWithholdingRemainingCount -Aggregate $row.original_local_optima `
            -N $N -P $P -Q $Q -R $R -S $S
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

function Assert-CodeSequenceQuartetWithholdingTripleBridge {
    param(
        [object[]] $Singles,
        [object[]] $Pairs,
        [object[]] $Triples,
        [object] $TripleWithholding,
        [object] $PairWithholding,
        [string[]] $RecordIds,
        [int[]] $Classes,
        [int] $N
    )
    # Regenerate EVERY EC-061 publicly exposed triple from the original
    # histogram: totals, nonzero ordinals, maximizing sets, identities,
    # prior pair membership, and fourth-order-relevant criticality flags.
    $rows = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $parentPairs = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $baseG = [int]$TripleWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$TripleWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    $criticalG = [System.Collections.Generic.List[int]]::new()
    $criticalO = [System.Collections.Generic.List[int]]::new()
    $minimalG = [System.Collections.Generic.List[int]]::new()
    $minimalO = [System.Collections.Generic.List[int]]::new()
    $extraG = [System.Collections.Generic.List[int]]::new()
    $extraO = [System.Collections.Generic.List[int]]::new()
    $ordinal = 0
    for ($p = 0; $p -lt $N; $p++) {
        for ($q = $p + 1; $q -lt $N; $q++) {
            for ($r = $q + 1; $r -lt $N; $r++) {
                $ordinal++
                $row = $rows[$ordinal - 1]
                $pairIndices = [int[]]@(
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $p -Q $q)
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $p -Q $r)
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $N -P $q -Q $r)
                )
                $sg = Get-CodeSequenceTripleWithholdingLayer -Rows $Singles -N $N -P $p -Q $q -R $r
                $dg = Get-CodeSequenceTripleWithholdingLayer -Rows $Pairs -N $N -P $p -Q $q -R $r
                $tg = Get-CodeSequenceTripleWithholdingLayer -Rows $Triples -N $N -P $p -Q $q -R $r
                $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $sg -Pair $dg `
                    -Triple $tg -OriginalLocalOptima $false
                $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $sg -Pair $dg `
                    -Triple $tg -OriginalLocalOptima $true
                $g = [int]$gMax.distinct_family_count
                $o = [int]$oMax.distinct_family_count
                $minPairG = $baseG
                $minPairO = $baseO
                foreach ($pi in $pairIndices) {
                    $parentPair = $parentPairs[$pi - 1]
                    $minPairG = [math]::Min($minPairG,
                        [int]$parentPair.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                    $minPairO = [math]::Min($minPairO,
                        [int]$parentPair.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                }
                $reducedG = $g -lt $baseG
                $reducedO = $o -lt $baseO
                $thirdOnlyG = $reducedG -and $minPairG -eq $baseG
                $thirdOnlyO = $reducedO -and $minPairO -eq $baseO
                $extraLossG = [int]$minPairG - $g
                $extraLossO = [int]$minPairO - $o
                if ([int]$row.original_position_triple_index -ne $ordinal -or
                    ($row.withheld_original_caller_positions -join ':') -cne "$(($p + 1)):$(($q + 1)):$(($r + 1))" -or
                    ($row.withheld_original_record_ids -join ':') -cne
                        "$($RecordIds[$p]):$($RecordIds[$q]):$($RecordIds[$r])" -or
                    ($row.original_saved_profile_class_indices -join ':') -cne
                        "$($Classes[$p]):$($Classes[$q]):$($Classes[$r])" -or
                    ($row.original_constituent_position_pair_indices -join ':') -cne ($pairIndices -join ':') -or
                    [long]$row.surviving_original_independent_two_window_combinations -ne $sg.genuine_total -or
                    [long]$row.surviving_original_joint_four_window_combinations -ne $dg.genuine_total -or
                    [long]$row.surviving_original_joint_six_window_combinations -ne $tg.genuine_total -or
                    [long]$row.surviving_original_full_selection_local_optimum_individual_packings -ne $sg.original_local_optimum_total -or
                    [long]$row.surviving_original_full_selection_joint_local_optimum_packing_pairs -ne $dg.original_local_optimum_total -or
                    [long]$row.surviving_original_full_selection_joint_local_optimum_packing_triples -ne $tg.original_local_optimum_total -or
                    [int]$row.globally_maximum_simultaneously_independently_supported_distinct_family_count -ne $g -or
                    [int]$row.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count -ne $o -or
                    [bool]$row.reduces_original_global_maximum_independent_family_count -ne $reducedG -or
                    [bool]$row.reduces_original_global_maximum_original_local_optimum_family_count -ne $reducedO -or
                    [bool]$row.minimally_third_order_critical_for_original_independent_maximum -ne $thirdOnlyG -or
                    [bool]$row.minimally_third_order_critical_for_original_local_optimum_maximum -ne $thirdOnlyO -or
                    [int]$row.strongest_constituent_pair_independent_family_maximum -ne $minPairG -or
                    [int]$row.strongest_constituent_pair_original_local_optimum_family_maximum -ne $minPairO -or
                    [int]$row.additional_independent_family_loss_beyond_stronger_pair_exclusion -ne $extraLossG -or
                    [int]$row.additional_original_local_optimum_family_loss_beyond_stronger_pair_exclusion -ne $extraLossO) {
                    throw 'Code Sequence quartet withholding disagrees with the complete EC-061 triple parent.'
                }
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $sg.genuine_registry_indices -Expected $row.independently_supported_family_indices
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $dg.genuine_registry_indices -Expected $row.jointly_supported_family_pair_indices
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $tg.genuine_registry_indices -Expected $row.jointly_supported_family_triple_indices
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $sg.original_local_optimum_registry_indices -Expected $row.original_local_optimum_family_indices
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $dg.original_local_optimum_registry_indices -Expected $row.jointly_compatible_original_local_optimum_family_pair_indices
                Assert-CodeSequencePairWithholdingOrdinalList -Actual $tg.original_local_optimum_registry_indices -Expected $row.jointly_compatible_original_local_optimum_family_triple_indices
                Assert-CodeSequenceWithholdingFamilySets -Actual $gMax.all_attaining_family_index_sets -Expected $row.all_attaining_family_index_sets
                Assert-CodeSequenceWithholdingFamilySets -Actual $oMax.all_attaining_family_index_sets -Expected $row.all_attaining_original_local_optimum_family_index_sets
                if ($reducedG) { $criticalG.Add($ordinal) }
                if ($reducedO) { $criticalO.Add($ordinal) }
                if ($thirdOnlyG) { $minimalG.Add($ordinal) }
                if ($thirdOnlyO) { $minimalO.Add($ordinal) }
                if ($extraLossG -gt 0) { $extraG.Add($ordinal) }
                if ($extraLossO -gt 0) { $extraO.Add($ordinal) }
            }
        }
    }
    if ($ordinal -ne $rows.Count -or
        $ordinal -ne [int]$TripleWithholding.counts.unordered_original_position_triple_count -or
        [int]$TripleWithholding.counts.number_of_triples_reducing_original_independent_maximum -ne $criticalG.Count -or
        [int]$TripleWithholding.counts.number_of_triples_reducing_original_local_optimum_maximum -ne $criticalO.Count -or
        [int]$TripleWithholding.counts.number_of_minimally_third_order_critical_triples_for_original_independent_maximum -ne $minimalG.Count -or
        [int]$TripleWithholding.counts.number_of_minimally_third_order_critical_triples_for_original_local_optimum_maximum -ne $minimalO.Count -or
        [int]$TripleWithholding.counts.number_of_triples_with_additional_independent_family_loss_beyond_stronger_pair -ne $extraG.Count -or
        [int]$TripleWithholding.counts.number_of_triples_with_additional_original_local_optimum_family_loss_beyond_stronger_pair -ne $extraO.Count) {
        throw 'Code Sequence quartet withholding found a truncated EC-061 triple parent.'
    }
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $criticalG.ToArray() -Expected $TripleWithholding.original_position_triple_indices_reducing_independent_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $criticalO.ToArray() -Expected $TripleWithholding.original_position_triple_indices_reducing_original_local_optimum_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $minimalG.ToArray() -Expected $TripleWithholding.minimally_third_order_critical_triple_indices_for_independent_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $minimalO.ToArray() -Expected $TripleWithholding.minimally_third_order_critical_triple_indices_for_original_local_optimum_maximum
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $extraG.ToArray() -Expected $TripleWithholding.triple_indices_causing_additional_independent_loss_vs_stronger_pair
    Assert-CodeSequencePairWithholdingOrdinalList -Actual $extraO.ToArray() -Expected $TripleWithholding.triple_indices_causing_additional_original_local_optimum_loss_vs_stronger_pair
}

function Assert-CodeSequenceQuartetWithholdingParticipation {
    param([int[]] $ByPosition, [int[]] $ByPair, [int[]] $ByTriple, [int] $MatchingQuartets)
    $positionTotal = [long]0; $pairTotal = [long]0; $tripleTotal = [long]0
    foreach ($x in $ByPosition) { $positionTotal += $x }
    foreach ($x in $ByPair) { $pairTotal += $x }
    foreach ($x in $ByTriple) { $tripleTotal += $x }
    if ($positionTotal -ne (4 * [long]$MatchingQuartets) -or
        $pairTotal -ne (6 * [long]$MatchingQuartets) -or
        $tripleTotal -ne (4 * [long]$MatchingQuartets)) {
        throw 'Code Sequence quartet withholding lost exact position/pair/triple criticality incidence.'
    }
}

function New-CodeSequenceQuartetWithholdingParticipationLedger {
    param([int] $Count)
    return @{
        criticalG = [int[]]::new($Count)
        criticalO = [int[]]::new($Count)
        minimalG = [int[]]::new($Count)
        minimalO = [int[]]::new($Count)
        extraG = [int[]]::new($Count)
        extraO = [int[]]::new($Count)
    }
}

function Add-CodeSequenceQuartetWithholdingParticipation {
    param(
        [object] $Ledger,
        [int[]] $Indices,
        [bool] $ReducedG,
        [bool] $ReducedO,
        [bool] $MinimalG,
        [bool] $MinimalO,
        [bool] $ExtraG,
        [bool] $ExtraO,
        [switch] $OneBased
    )
    foreach ($given in $Indices) {
        $slot = $given
        if ($OneBased) { $slot-- }
        if ($slot -lt 0 -or $slot -ge $Ledger.criticalG.Count) {
            throw 'Code Sequence quartet withholding encountered invalid original participation ordinal.'
        }
        if ($ReducedG) { $Ledger.criticalG[$slot]++ }
        if ($ReducedO) { $Ledger.criticalO[$slot]++ }
        if ($MinimalG) { $Ledger.minimalG[$slot]++ }
        if ($MinimalO) { $Ledger.minimalO[$slot]++ }
        if ($ExtraG) { $Ledger.extraG[$slot]++ }
        if ($ExtraO) { $Ledger.extraO[$slot]++ }
    }
}

function Get-CodeSequenceOriginalFindingPairProfileQuartetPositionWithholding {
    param(
        [object] $Atlas,
        [object] $PairWithholding,
        [object] $TripleWithholding,
        [object] $WitnessAggregates
    )
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or
        $null -eq $TripleWithholding -or $null -eq $WitnessAggregates -or
        $PairWithholding.scope -cne 'unordered_two_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $TripleWithholding.scope -cne 'unordered_three_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$TripleWithholding.complete_original_ec060_pair_projections_and_private_witness_masks_reconciled -or
        -not [bool]$TripleWithholding.independent_of_sequence_top -or
        -not [bool]$TripleWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence quartet withholding requires complete EC-061 original triples and private witnesses.'
    }
    $n = [int]$TripleWithholding.counts.selected_report_positions
    $f = [int]$TripleWithholding.counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $pairRecords = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $tripleRecords = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $originalG = [int]$TripleWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $originalO = [int]$TripleWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $f -lt 0 -or $f -gt 66 -or $records.Count -ne $n -or $classes.Count -ne $n -or
        $Atlas.positions.Count -ne $n -or [int]$Atlas.counts.selected_report_positions -ne $n -or
        $singles.Count -ne $f -or
        $pairs.Count -ne [int](($f * ($f - 1)) / 2) -or
        $triples.Count -ne [int](($f * ($f - 1) * ($f - 2)) / 6) -or
        $pairRecords.Count -ne [int](($n * ($n - 1)) / 2) -or
        $tripleRecords.Count -ne [int](($n * ($n - 1) * ($n - 2)) / 6) -or
        [int]$PairWithholding.counts.selected_report_positions -ne $n -or
        [int]$PairWithholding.counts.original_maximal_repeat_family_count -ne $f -or
        [int]$PairWithholding.counts.original_global_maximum_independently_supported_distinct_family_count -ne $originalG -or
        [int]$PairWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count -ne $originalO -or
        $originalG -lt 0 -or $originalG -gt 3 -or $originalO -lt 0 -or $originalO -gt $originalG) {
        throw 'Code Sequence quartet withholding found inconsistent original parent cardinalities.'
    }
    for ($i = 0; $i -lt $n; $i++) {
        if ([int]$Atlas.positions[$i].position -ne $i + 1 -or
            $Atlas.positions[$i].record_id -cne $records[$i] -or
            [int]$Atlas.positions[$i].profile_class_index -ne $classes[$i]) {
            throw 'Code Sequence quartet withholding changed original caller report identities.'
        }
    }
    for ($level = 1; $level -le 3; $level++) {
        if ($level -eq 1) { $group = $singles }
        elseif ($level -eq 2) { $group = $pairs }
        else { $group = $triples }
        $expected = 0
        foreach ($entry in $group) {
            $expected++
            if ([int]$entry.registry_index -ne $expected) {
                throw 'Code Sequence quartet withholding changed original family registry order.'
            }
            # Prove masks still conserve their full original zero/one/two-way
            # ledgers before using exact third/fourth intersections.
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $entry.genuine -N $n
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $entry.original_local_optima -N $n
        }
    }
    Assert-CodeSequenceQuartetWithholdingTripleBridge -Singles $singles -Pairs $pairs `
        -Triples $triples -TripleWithholding $TripleWithholding -PairWithholding $PairWithholding `
        -RecordIds $records -Classes $classes -N $n

    $rows = [System.Collections.Generic.List[object]]::new()
    $criticalG = [System.Collections.Generic.List[int]]::new()
    $criticalO = [System.Collections.Generic.List[int]]::new()
    $minimalG = [System.Collections.Generic.List[int]]::new()
    $minimalO = [System.Collections.Generic.List[int]]::new()
    $extraG = [System.Collections.Generic.List[int]]::new()
    $extraO = [System.Collections.Generic.List[int]]::new()
    $posLedgers = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $n
    $pairLedgers = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $pairRecords.Count
    $tripleLedgers = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $tripleRecords.Count
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 4) {
        $minG = $originalG; $maxG = 0
        $minO = $originalO; $maxO = 0
    }
    $ordinal = 0
    for ($p = 0; $p -lt $n; $p++) {
        for ($q = $p + 1; $q -lt $n; $q++) {
            for ($r = $q + 1; $r -lt $n; $r++) {
                for ($s = $r + 1; $s -lt $n; $s++) {
                    $ordinal++
                    $tripleIndices = [int[]]@(
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $n -P $p -Q $q -R $r)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $n -P $p -Q $q -R $s)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $n -P $p -Q $r -R $s)
                        (Get-CodeSequenceQuartetWithholdingTripleOrdinal -N $n -P $q -Q $r -R $s)
                    )
                    $pairIndices = [int[]]@(
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $p -Q $q)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $p -Q $r)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $p -Q $s)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $q -Q $r)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $q -Q $s)
                        (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $r -Q $s)
                    )
                    $minTripleG = $originalG
                    $minTripleO = $originalO
                    foreach ($ti in $tripleIndices) {
                        $tr = $tripleRecords[$ti - 1]
                        if ([int]$tr.original_position_triple_index -ne $ti) {
                            throw 'Code Sequence quartet withholding lost original EC-061 triple ordering.'
                        }
                        $minTripleG = [math]::Min($minTripleG,
                            [int]$tr.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                        $minTripleO = [math]::Min($minTripleO,
                            [int]$tr.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                    }
                    $one = Get-CodeSequenceQuartetWithholdingLayer -Rows $singles -N $n -P $p -Q $q -R $r -S $s
                    $two = Get-CodeSequenceQuartetWithholdingLayer -Rows $pairs -N $n -P $p -Q $q -R $r -S $s
                    $three = Get-CodeSequenceQuartetWithholdingLayer -Rows $triples -N $n -P $p -Q $q -R $r -S $s
                    $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $two `
                        -Triple $three -OriginalLocalOptima $false
                    $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $two `
                        -Triple $three -OriginalLocalOptima $true
                    $g = [int]$gMax.distinct_family_count
                    $o = [int]$oMax.distinct_family_count
                    $capacity = [int][math]::Floor(($n - 4) / 4)
                    if ($g -gt $capacity -or $g -gt $minTripleG -or $o -gt $minTripleO -or
                        $g -gt $originalG -or $o -gt $originalO -or $o -gt $g -or
                        $three.genuine_total -ne 0 -or $three.original_local_optimum_total -ne 0) {
                        throw 'Code Sequence quartet withholding violated original triple monotonicity or N-4 capacity.'
                    }
                    $reducedG = $g -lt $originalG
                    $reducedO = $o -lt $originalO
                    $fourthG = $reducedG -and $minTripleG -eq $originalG
                    $fourthO = $reducedO -and $minTripleO -eq $originalO
                    $additionalG = [int]$minTripleG - $g
                    $additionalO = [int]$minTripleO - $o
                    if ($reducedG) { $criticalG.Add($ordinal) }
                    if ($reducedO) { $criticalO.Add($ordinal) }
                    if ($fourthG) { $minimalG.Add($ordinal) }
                    if ($fourthO) { $minimalO.Add($ordinal) }
                    if ($additionalG -gt 0) { $extraG.Add($ordinal) }
                    if ($additionalO -gt 0) { $extraO.Add($ordinal) }
                    $ledgerFlags = @{
                        ReducedG = [bool]$reducedG
                        ReducedO = [bool]$reducedO
                        MinimalG = [bool]$fourthG
                        MinimalO = [bool]$fourthO
                        ExtraG = [bool]($additionalG -gt 0)
                        ExtraO = [bool]($additionalO -gt 0)
                    }
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $posLedgers `
                        -Indices ([int[]]@($p,$q,$r,$s)) @ledgerFlags
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedgers `
                        -Indices $pairIndices -OneBased @ledgerFlags
                    Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedgers `
                        -Indices $tripleIndices -OneBased @ledgerFlags
                    $minG = [math]::Min($minG,$g); $maxG = [math]::Max($maxG,$g)
                    $minO = [math]::Min($minO,$o); $maxO = [math]::Max($maxO,$o)
                    $rows.Add([ordered]@{
                        original_position_quartet_index = $ordinal
                        withheld_original_caller_positions = [int[]]@(($p + 1),($q + 1),($r + 1),($s + 1))
                        withheld_original_record_ids = [string[]]@($records[$p],$records[$q],$records[$r],$records[$s])
                        original_saved_profile_class_indices = [int[]]@($classes[$p],$classes[$q],$classes[$r],$classes[$s])
                        original_constituent_position_pair_indices = $pairIndices
                        original_constituent_position_triple_indices = $tripleIndices
                        surviving_original_independent_two_window_combinations = $one.genuine_total
                        surviving_original_joint_four_window_combinations = $two.genuine_total
                        surviving_original_joint_six_window_combinations = $three.genuine_total
                        surviving_original_full_selection_local_optimum_individual_packings = $one.original_local_optimum_total
                        surviving_original_full_selection_joint_local_optimum_packing_pairs = $two.original_local_optimum_total
                        surviving_original_full_selection_joint_local_optimum_packing_triples = $three.original_local_optimum_total
                        independently_supported_family_indices = $one.genuine_registry_indices
                        jointly_supported_family_pair_indices = $two.genuine_registry_indices
                        jointly_supported_family_triple_indices = $three.genuine_registry_indices
                        original_local_optimum_family_indices = $one.original_local_optimum_registry_indices
                        jointly_compatible_original_local_optimum_family_pair_indices = $two.original_local_optimum_registry_indices
                        jointly_compatible_original_local_optimum_family_triple_indices = $three.original_local_optimum_registry_indices
                        globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                        all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                        reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                        globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                        all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                        reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                        minimally_fourth_order_critical_for_original_independent_maximum = [bool]$fourthG
                        minimally_fourth_order_critical_for_original_local_optimum_maximum = [bool]$fourthO
                        strongest_constituent_triple_independent_family_maximum = $minTripleG
                        strongest_constituent_triple_original_local_optimum_family_maximum = $minTripleO
                        additional_independent_family_loss_beyond_stronger_triple_exclusion = $additionalG
                        additional_original_local_optimum_family_loss_beyond_stronger_triple_exclusion = $additionalO
                    })
                }
            }
        }
    }
    if ($ordinal -ne [int](($n * ($n - 1) * ($n - 2) * ($n - 3)) / 24)) {
        throw 'Code Sequence quartet withholding omitted an original position quartet.'
    }
    $perPosition = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $n; $i++) {
        $containing = [int]((($n - 1) * ($n - 2) * ($n - 3)) / 6)
        $perPosition.Add([ordered]@{
            original_caller_position = $i + 1
            original_record_id = $records[$i]
            original_saved_profile_class_index = $classes[$i]
            number_of_position_quartets_containing_position = $containing
            quartets_reducing_original_independent_maximum = $posLedgers.criticalG[$i]
            quartets_reducing_original_local_optimum_maximum = $posLedgers.criticalO[$i]
            minimally_fourth_order_critical_quartets_for_original_independent_maximum = $posLedgers.minimalG[$i]
            minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum = $posLedgers.minimalO[$i]
            quartets_with_additional_independent_loss_beyond_stronger_triple = $posLedgers.extraG[$i]
            quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple = $posLedgers.extraO[$i]
        })
    }
    $perPair = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $pairRecords.Count; $i++) {
        $perPair.Add([ordered]@{
            original_position_pair_index = $i + 1
            withheld_original_caller_positions = [int[]]$pairRecords[$i].withheld_original_caller_positions
            number_of_position_quartets_containing_pair = [int]((($n - 2) * ($n - 3)) / 2)
            quartets_reducing_original_independent_maximum = $pairLedgers.criticalG[$i]
            quartets_reducing_original_local_optimum_maximum = $pairLedgers.criticalO[$i]
            minimally_fourth_order_critical_quartets_for_original_independent_maximum = $pairLedgers.minimalG[$i]
            minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum = $pairLedgers.minimalO[$i]
            quartets_with_additional_independent_loss_beyond_stronger_triple = $pairLedgers.extraG[$i]
            quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple = $pairLedgers.extraO[$i]
        })
    }
    $perTriple = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $tripleRecords.Count; $i++) {
        $perTriple.Add([ordered]@{
            original_position_triple_index = $i + 1
            withheld_original_caller_positions = [int[]]$tripleRecords[$i].withheld_original_caller_positions
            number_of_position_quartets_containing_triple = $n - 3
            quartets_reducing_original_independent_maximum = $tripleLedgers.criticalG[$i]
            quartets_reducing_original_local_optimum_maximum = $tripleLedgers.criticalO[$i]
            minimally_fourth_order_critical_quartets_for_original_independent_maximum = $tripleLedgers.minimalG[$i]
            minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum = $tripleLedgers.minimalO[$i]
            quartets_with_additional_independent_loss_beyond_stronger_triple = $tripleLedgers.extraG[$i]
            quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple = $tripleLedgers.extraO[$i]
        })
    }
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.criticalG `
        -ByPair $pairLedgers.criticalG -ByTriple $tripleLedgers.criticalG -MatchingQuartets $criticalG.Count
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.criticalO `
        -ByPair $pairLedgers.criticalO -ByTriple $tripleLedgers.criticalO -MatchingQuartets $criticalO.Count
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.minimalG `
        -ByPair $pairLedgers.minimalG -ByTriple $tripleLedgers.minimalG -MatchingQuartets $minimalG.Count
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.minimalO `
        -ByPair $pairLedgers.minimalO -ByTriple $tripleLedgers.minimalO -MatchingQuartets $minimalO.Count
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.extraG `
        -ByPair $pairLedgers.extraG -ByTriple $tripleLedgers.extraG -MatchingQuartets $extraG.Count
    Assert-CodeSequenceQuartetWithholdingParticipation -ByPosition $posLedgers.extraO `
        -ByPair $pairLedgers.extraO -ByTriple $tripleLedgers.extraO -MatchingQuartets $extraO.Count
    return [ordered]@{
        scope = 'unordered_four_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$TripleWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$TripleWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$TripleWithholding.anchor_index_in_anchor_journeys
        path = [string]$TripleWithholding.path
        exact_saved_quote_anchor = $TripleWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            unordered_original_position_quartet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $originalG
            original_global_maximum_original_locally_optimal_distinct_family_count = $originalO
            number_of_quartets_reducing_original_independent_maximum = $criticalG.Count
            number_of_quartets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_fourth_order_critical_quartets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_fourth_order_critical_quartets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_quartets_with_additional_independent_loss_beyond_stronger_triple = $extraG.Count
            number_of_quartets_with_additional_original_local_optimum_loss_beyond_stronger_triple = $extraO.Count
            minimum_global_independent_family_maximum_after_four_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_four_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_four_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_four_withheld_positions = $maxO
        }
        original_position_quartet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_quartet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_fourth_order_critical_quartet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_fourth_order_critical_quartet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        quartet_indices_causing_additional_independent_loss_vs_stronger_triple = $extraG.ToArray()
        quartet_indices_causing_additional_original_local_optimum_loss_vs_stronger_triple = $extraO.ToArray()
        ordered_original_position_quartet_withholding = $rows.ToArray()
        ordered_original_position_quartet_participation = $perPosition.ToArray()
        ordered_original_pair_quartet_participation = $perPair.ToArray()
        ordered_original_triple_quartet_participation = $perTriple.ToArray()
        complete_original_ec061_triple_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'For EVERY ascending original caller-position quartet, discard ONLY preexisting truly observed motif windows that touch at least one of the four positions. The exact multiplicity-weighted original two-/four-/six-window witnesses and separately frozen EC-056 local-optimum packings are projected without report deletion, new adjacency, reoptimization, source access or repository writes. FOURTH-order minimal criticality requires each of the four original constituent three-position exclusions separately to preserve the original global distinct-family maximum, but the simultaneous four-position exclusion to reduce it. Separately report additional loss beyond the strongest constituent triple, including when that triple was already critical. Saved histogram patterns and input caller order do not prove real Finding identity, historical chronology, defect recurrence, causal effects, severity, fix, regression or risk.'
    }
}

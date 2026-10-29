#requires -Version 7.0
<#
    EC-061: exhaustive THREE-original-caller-position evidence withholding.
    Use only EC-060's PRIVATE, already-conserved, multiplicity-weighted
    EC-059 original union masks. No new window, record, read, selector, or
    re-optimization. A genuinely third-order critical triple loses a global
    family maximum although EVERY constituent position pair preserves it.
#>

function Get-CodeSequenceTripleWithholdingPairOrdinal {
    param([int] $N, [int] $P, [int] $Q)
    if ($N -lt 2 -or $N -gt 12 -or $P -lt 0 -or $P -ge $Q -or $Q -ge $N) {
        throw 'Code Sequence triple withholding needs ascending ORIGINAL pair positions.'
    }
    # Exact one-based index in EC-060's p-outer/q-inner pair enumeration.
    return [int]((($P * ((2 * $N) - $P - 1)) / 2) + $Q - $P)
}

function Assert-CodeSequenceTripleWithholdingPrivateAggregate {
    param([object] $Aggregate, [int] $N)
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $included = [long[]]$Aggregate.original_position_inclusion_counts
    $pairs = [long[]]$Aggregate.original_pair_intersection_counts
    if ($masks.Count -ne $weights.Count -or $included.Count -ne $N -or
        $pairs.Count -ne ($N * $N)) {
        throw 'Code Sequence triple withholding lost the privately conserved EC-060 histogram shape.'
    }
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $sum = [long]0
    $positionTotals = [long[]]::new($N)
    $pairTotals = [long[]]::new($N * $N)
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = $masks[$i]
        $weight = $weights[$i]
        if ($mask -le 0 -or $mask -ge (1 -shl $N) -or $weight -le 0 -or
            -not $seen.Add($mask)) {
            throw 'Code Sequence triple withholding encountered an invalid or repeated histogram mask.'
        }
        $sum += $weight
        for ($p = 0; $p -lt $N; $p++) {
            if (($mask -band (1 -shl $p)) -eq 0) { continue }
            $positionTotals[$p] += $weight
            for ($q = $p + 1; $q -lt $N; $q++) {
                if (($mask -band (1 -shl $q)) -ne 0) {
                    $pairTotals[($p * $N) + $q] += $weight
                }
            }
        }
    }
    if ($sum -ne [long]$Aggregate.original_combination_count) {
        throw 'Code Sequence triple withholding lost exact witness multiplicity.'
    }
    for ($p = 0; $p -lt $N; $p++) {
        if ($positionTotals[$p] -ne $included[$p]) {
            throw 'Code Sequence triple withholding disagrees with EC-060 original inclusion counts.'
        }
        for ($q = $p + 1; $q -lt $N; $q++) {
            $idx = ($p * $N) + $q
            if ($pairTotals[$idx] -ne $pairs[$idx]) {
                throw 'Code Sequence triple withholding disagrees with EC-060 pair intersections.'
            }
        }
    }
}

function Get-CodeSequenceTripleWithholdingRemainingCount {
    param(
        [object] $Aggregate,
        [int] $N,
        [int] $P,
        [int] $Q,
        [int] $R
    )
    if ($P -lt 0 -or $P -ge $Q -or $Q -ge $R -or $R -ge $N) {
        throw 'Code Sequence triple withholding requires three ascending original positions.'
    }
    $excluded = (1 -shl $P) -bor (1 -shl $Q) -bor (1 -shl $R)
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $directSurvivors = [long]0
    $threeWayOverlap = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $overlap = $masks[$i] -band $excluded
        if ($overlap -eq 0) { $directSurvivors += $weights[$i] }
        if ($overlap -eq $excluded) { $threeWayOverlap += $weights[$i] }
    }
    # Independent inclusion/exclusion arithmetic, exact even for distinct
    # original witnesses sharing a union mask. One- and two-way counts are
    # the same parent ledgers already reconciled with EC-059 and EC-060.
    $included = [long[]]$Aggregate.original_position_inclusion_counts
    $pairOverlaps = [long[]]$Aggregate.original_pair_intersection_counts
    $inclusionExclusion = [long]$Aggregate.original_combination_count -
        $included[$P] - $included[$Q] - $included[$R] +
        $pairOverlaps[($P * $N) + $Q] +
        $pairOverlaps[($P * $N) + $R] +
        $pairOverlaps[($Q * $N) + $R] - $threeWayOverlap
    if ($directSurvivors -ne $inclusionExclusion -or $directSurvivors -lt 0 -or
        $directSurvivors -gt [long]$Aggregate.original_combination_count) {
        throw 'Code Sequence triple withholding failed exact three-way witness conservation.'
    }
    return [long]$directSurvivors
}

function Get-CodeSequenceTripleWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int] $P, [int] $Q, [int] $R)
    $genuineTotal = [long]0
    $optimumTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $optimumIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $optimumSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceTripleWithholdingRemainingCount -Aggregate $row.genuine -N $N -P $P -Q $Q -R $R
        $o = Get-CodeSequenceTripleWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -P $P -Q $Q -R $R
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

function Assert-CodeSequenceTripleWithholdingPairBridge {
    param(
        [object[]] $Singles,
        [object[]] $Pairs,
        [object[]] $Triples,
        [object[]] $PairRecords,
        [int] $N
    )
    # Verify the entire original EC-060 public projection against the
    # privately handed-off rows before starting any new triple projection.
    $ordinal = 0
    for ($p = 0; $p -lt $N; $p++) {
        for ($q = $p + 1; $q -lt $N; $q++) {
            $ordinal++
            $one = $PairRecords[$ordinal - 1]
            $s = Get-CodeSequencePairWithholdingLayer -Rows $Singles -N $N -P $p -Q $q
            $d = Get-CodeSequencePairWithholdingLayer -Rows $Pairs -N $N -P $p -Q $q
            $t = Get-CodeSequencePairWithholdingLayer -Rows $Triples -N $N -P $p -Q $q
            $g = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $false
            $o = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $true
            if ([int]$one.original_position_pair_index -ne $ordinal -or
                ($one.withheld_original_caller_positions -join ':') -cne "$(($p + 1)):$(($q + 1))" -or
                [long]$one.surviving_original_independent_two_window_combinations -ne $s.genuine_total -or
                [long]$one.surviving_original_joint_four_window_combinations -ne $d.genuine_total -or
                [long]$one.surviving_original_joint_six_window_combinations -ne $t.genuine_total -or
                [long]$one.surviving_original_full_selection_local_optimum_individual_packings -ne $s.original_local_optimum_total -or
                [long]$one.surviving_original_full_selection_joint_local_optimum_packing_pairs -ne $d.original_local_optimum_total -or
                [long]$one.surviving_original_full_selection_joint_local_optimum_packing_triples -ne $t.original_local_optimum_total -or
                [int]$one.globally_maximum_simultaneously_independently_supported_distinct_family_count -ne [int]$g.distinct_family_count -or
                [int]$one.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count -ne [int]$o.distinct_family_count) {
                throw 'Code Sequence triple withholding could not reproduce EC-060 pair-projection totals.'
            }
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $s.genuine_registry_indices -Expected $one.independently_supported_family_indices
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $d.genuine_registry_indices -Expected $one.jointly_supported_family_pair_indices
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $t.genuine_registry_indices -Expected $one.jointly_supported_family_triple_indices
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $s.original_local_optimum_registry_indices -Expected $one.original_local_optimum_family_indices
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $d.original_local_optimum_registry_indices -Expected $one.jointly_compatible_original_local_optimum_family_pair_indices
            Assert-CodeSequencePairWithholdingOrdinalList -Actual $t.original_local_optimum_registry_indices -Expected $one.jointly_compatible_original_local_optimum_family_triple_indices
            Assert-CodeSequenceWithholdingFamilySets -Actual $g.all_attaining_family_index_sets -Expected $one.all_attaining_family_index_sets
            Assert-CodeSequenceWithholdingFamilySets -Actual $o.all_attaining_family_index_sets -Expected $one.all_attaining_original_local_optimum_family_index_sets
        }
    }
    if ($ordinal -ne $PairRecords.Count) {
        throw 'Code Sequence triple withholding pair bridge omitted an original position pair.'
    }
}

function Assert-CodeSequenceTripleWithholdingParticipation {
    param([int[]] $ByPosition, [int[]] $ByPair, [int] $MatchingTriples)
    $positionSum = [long]0
    $pairSum = [long]0
    foreach ($c in $ByPosition) { $positionSum += $c }
    foreach ($c in $ByPair) { $pairSum += $c }
    if ($positionSum -ne (3 * [long]$MatchingTriples) -or
        $pairSum -ne (3 * [long]$MatchingTriples)) {
        throw 'Code Sequence triple withholding did not conserve criticality participation.'
    }
}

function Get-CodeSequenceOriginalFindingPairProfileTriplePositionWithholding {
    param(
        [object] $Atlas,
        [object] $PairWithholding,
        [object] $WitnessAggregates
    )
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $WitnessAggregates -or
        $PairWithholding.scope -cne 'unordered_two_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$PairWithholding.complete_original_ec059_witness_masks_and_every_single_position_projection_reconciled -or
        -not [bool]$PairWithholding.independent_of_sequence_top -or
        -not [bool]$PairWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence triple withholding requires complete conserved EC-060 original evidence.'
    }
    $n = [int]$PairWithholding.counts.selected_report_positions
    $f = [int]$PairWithholding.counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $pairRecords = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $originalGenuine = [int]$PairWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $originalFrozen = [int]$PairWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $f -lt 0 -or $f -gt 66 -or $records.Count -ne $n -or $classes.Count -ne $n -or
        $Atlas.positions.Count -ne $n -or $singles.Count -ne $f -or
        $pairs.Count -ne [int](($f * ($f - 1)) / 2) -or
        $triples.Count -ne [int](($f * ($f - 1) * ($f - 2)) / 6) -or
        $pairRecords.Count -ne [int](($n * ($n - 1)) / 2) -or
        [int]$PairWithholding.counts.unordered_original_position_pair_count -ne $pairRecords.Count -or
        [int]$Atlas.counts.selected_report_positions -ne $n -or
        $originalGenuine -lt 0 -or $originalGenuine -gt 3 -or
        $originalFrozen -lt 0 -or $originalFrozen -gt $originalGenuine) {
        throw 'Code Sequence triple withholding found an inconsistent parent original cardinality.'
    }
    for ($p = 0; $p -lt $n; $p++) {
        if ([int]$Atlas.positions[$p].position -ne $p + 1 -or
            $Atlas.positions[$p].record_id -cne $records[$p] -or
            [int]$Atlas.positions[$p].profile_class_index -ne $classes[$p]) {
            throw 'Code Sequence triple withholding original caller identity changed.'
        }
    }
    for ($level = 1; $level -le 3; $level++) {
        if ($level -eq 1) { $group = $singles }
        elseif ($level -eq 2) { $group = $pairs }
        else { $group = $triples }
        $expected = 0
        foreach ($row in $group) {
            $expected++
            if ([int]$row.registry_index -ne $expected) {
                throw 'Code Sequence triple withholding changed an original family registry ordinal.'
            }
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $row.genuine -N $n
            Assert-CodeSequenceTripleWithholdingPrivateAggregate -Aggregate $row.original_local_optima -N $n
        }
    }
    Assert-CodeSequenceTripleWithholdingPairBridge -Singles $singles -Pairs $pairs `
        -Triples $triples -PairRecords $pairRecords -N $n

    $resultRows = [System.Collections.Generic.List[object]]::new()
    $criticalG = [System.Collections.Generic.List[int]]::new()
    $criticalO = [System.Collections.Generic.List[int]]::new()
    $minimalG = [System.Collections.Generic.List[int]]::new()
    $minimalO = [System.Collections.Generic.List[int]]::new()
    $extraG = [System.Collections.Generic.List[int]]::new()
    $extraO = [System.Collections.Generic.List[int]]::new()
    $positionG = [int[]]::new($n)
    $positionO = [int[]]::new($n)
    $positionMinimalG = [int[]]::new($n)
    $positionMinimalO = [int[]]::new($n)
    $positionExtraG = [int[]]::new($n)
    $positionExtraO = [int[]]::new($n)
    $pairG = [int[]]::new($pairRecords.Count)
    $pairO = [int[]]::new($pairRecords.Count)
    $pairMinimalG = [int[]]::new($pairRecords.Count)
    $pairMinimalO = [int[]]::new($pairRecords.Count)
    $pairExtraG = [int[]]::new($pairRecords.Count)
    $pairExtraO = [int[]]::new($pairRecords.Count)
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 3) {
        $minG = $originalGenuine; $maxG = 0
        $minO = $originalFrozen; $maxO = 0
    }
    $ordinal = 0
    for ($p = 0; $p -lt $n; $p++) {
        for ($q = $p + 1; $q -lt $n; $q++) {
            for ($r = $q + 1; $r -lt $n; $r++) {
                $ordinal++
                $pairIndexes = [int[]]@(
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $p -Q $q)
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $p -Q $r)
                    (Get-CodeSequenceTripleWithholdingPairOrdinal -N $n -P $q -Q $r)
                )
                $minPairG = $originalGenuine
                $minPairO = $originalFrozen
                foreach ($pairIndex in $pairIndexes) {
                    $parent = $pairRecords[$pairIndex - 1]
                    if ($parent.original_position_pair_index -ne $pairIndex) {
                        throw 'Code Sequence triple withholding mismatched a canonical original pair index.'
                    }
                    $minPairG = [math]::Min($minPairG, [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                    $minPairO = [math]::Min($minPairO, [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                }
                $s = Get-CodeSequenceTripleWithholdingLayer -Rows $singles -N $n -P $p -Q $q -R $r
                $d = Get-CodeSequenceTripleWithholdingLayer -Rows $pairs -N $n -P $p -Q $q -R $r
                $t = Get-CodeSequenceTripleWithholdingLayer -Rows $triples -N $n -P $p -Q $q -R $r
                $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $false
                $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $true
                $g = [int]$gMax.distinct_family_count
                $o = [int]$oMax.distinct_family_count
                $capacity = [int][math]::Floor(($n - 3) / 4)
                if ($g -gt $capacity -or $o -gt $g -or $g -gt $minPairG -or
                    $o -gt $minPairO -or $g -gt $originalGenuine -or $o -gt $originalFrozen -or
                    $t.genuine_total -ne 0 -or $t.original_local_optimum_total -ne 0) {
                    throw 'Code Sequence triple withholding violated monotonicity or the N-3 capacity bound.'
                }
                $reducedG = $g -lt $originalGenuine
                $reducedO = $o -lt $originalFrozen
                $thirdOrderG = $reducedG -and $minPairG -eq $originalGenuine
                $thirdOrderO = $reducedO -and $minPairO -eq $originalFrozen
                $furtherG = [int]$minPairG - $g
                $furtherO = [int]$minPairO - $o
                if ($reducedG) { $criticalG.Add($ordinal) }
                if ($reducedO) { $criticalO.Add($ordinal) }
                if ($thirdOrderG) { $minimalG.Add($ordinal) }
                if ($thirdOrderO) { $minimalO.Add($ordinal) }
                if ($furtherG -gt 0) { $extraG.Add($ordinal) }
                if ($furtherO -gt 0) { $extraO.Add($ordinal) }
                foreach ($pos in @($p,$q,$r)) {
                    if ($reducedG) { $positionG[$pos]++ }
                    if ($reducedO) { $positionO[$pos]++ }
                    if ($thirdOrderG) { $positionMinimalG[$pos]++ }
                    if ($thirdOrderO) { $positionMinimalO[$pos]++ }
                    if ($furtherG -gt 0) { $positionExtraG[$pos]++ }
                    if ($furtherO -gt 0) { $positionExtraO[$pos]++ }
                }
                foreach ($pi in $pairIndexes) {
                    $idx = $pi - 1
                    if ($reducedG) { $pairG[$idx]++ }
                    if ($reducedO) { $pairO[$idx]++ }
                    if ($thirdOrderG) { $pairMinimalG[$idx]++ }
                    if ($thirdOrderO) { $pairMinimalO[$idx]++ }
                    if ($furtherG -gt 0) { $pairExtraG[$idx]++ }
                    if ($furtherO -gt 0) { $pairExtraO[$idx]++ }
                }
                $minG = [math]::Min($minG,$g); $maxG = [math]::Max($maxG,$g)
                $minO = [math]::Min($minO,$o); $maxO = [math]::Max($maxO,$o)
                $resultRows.Add([ordered]@{
                    original_position_triple_index = $ordinal
                    withheld_original_caller_positions = [int[]]@(($p + 1),($q + 1),($r + 1))
                    withheld_original_record_ids = [string[]]@($records[$p],$records[$q],$records[$r])
                    original_saved_profile_class_indices = [int[]]@($classes[$p],$classes[$q],$classes[$r])
                    original_constituent_position_pair_indices = $pairIndexes
                    surviving_original_independent_two_window_combinations = $s.genuine_total
                    surviving_original_joint_four_window_combinations = $d.genuine_total
                    surviving_original_joint_six_window_combinations = $t.genuine_total
                    surviving_original_full_selection_local_optimum_individual_packings = $s.original_local_optimum_total
                    surviving_original_full_selection_joint_local_optimum_packing_pairs = $d.original_local_optimum_total
                    surviving_original_full_selection_joint_local_optimum_packing_triples = $t.original_local_optimum_total
                    independently_supported_family_indices = $s.genuine_registry_indices
                    jointly_supported_family_pair_indices = $d.genuine_registry_indices
                    jointly_supported_family_triple_indices = $t.genuine_registry_indices
                    original_local_optimum_family_indices = $s.original_local_optimum_registry_indices
                    jointly_compatible_original_local_optimum_family_pair_indices = $d.original_local_optimum_registry_indices
                    jointly_compatible_original_local_optimum_family_triple_indices = $t.original_local_optimum_registry_indices
                    globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                    all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                    reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                    globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                    all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                    reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                    minimally_third_order_critical_for_original_independent_maximum = [bool]$thirdOrderG
                    minimally_third_order_critical_for_original_local_optimum_maximum = [bool]$thirdOrderO
                    strongest_constituent_pair_independent_family_maximum = $minPairG
                    strongest_constituent_pair_original_local_optimum_family_maximum = $minPairO
                    additional_independent_family_loss_beyond_stronger_pair_exclusion = $furtherG
                    additional_original_local_optimum_family_loss_beyond_stronger_pair_exclusion = $furtherO
                })
            }
        }
    }
    if ($ordinal -ne [int](($n * ($n - 1) * ($n - 2)) / 6)) {
        throw 'Code Sequence triple withholding failed complete original triple enumeration.'
    }
    $positionRows = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $n; $p++) {
        $positionRows.Add([ordered]@{
            original_caller_position = $p + 1
            original_record_id = $records[$p]
            original_saved_profile_class_index = $classes[$p]
            number_of_position_triples_containing_position = [int]((($n - 1) * ($n - 2)) / 2)
            triples_reducing_original_independent_maximum = $positionG[$p]
            triples_reducing_original_local_optimum_maximum = $positionO[$p]
            minimally_third_order_critical_triples_for_original_independent_maximum = $positionMinimalG[$p]
            minimally_third_order_critical_triples_for_original_local_optimum_maximum = $positionMinimalO[$p]
            triples_with_additional_independent_loss_beyond_stronger_pair = $positionExtraG[$p]
            triples_with_additional_original_local_optimum_loss_beyond_stronger_pair = $positionExtraO[$p]
        })
    }
    $pairRows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $pairRecords.Count; $i++) {
        $source = $pairRecords[$i]
        $pairRows.Add([ordered]@{
            original_position_pair_index = $i + 1
            withheld_original_caller_positions = [int[]]$source.withheld_original_caller_positions
            number_of_position_triples_containing_pair = [int]($n - 2)
            triples_reducing_original_independent_maximum = $pairG[$i]
            triples_reducing_original_local_optimum_maximum = $pairO[$i]
            minimally_third_order_critical_triples_for_original_independent_maximum = $pairMinimalG[$i]
            minimally_third_order_critical_triples_for_original_local_optimum_maximum = $pairMinimalO[$i]
            triples_with_additional_independent_loss_beyond_stronger_pair = $pairExtraG[$i]
            triples_with_additional_original_local_optimum_loss_beyond_stronger_pair = $pairExtraO[$i]
        })
    }
    # Each triple is counted for exactly 3 original positions and 3 pairs.
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionG -ByPair $pairG -MatchingTriples $criticalG.Count
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionO -ByPair $pairO -MatchingTriples $criticalO.Count
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionMinimalG -ByPair $pairMinimalG -MatchingTriples $minimalG.Count
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionMinimalO -ByPair $pairMinimalO -MatchingTriples $minimalO.Count
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionExtraG -ByPair $pairExtraG -MatchingTriples $extraG.Count
    Assert-CodeSequenceTripleWithholdingParticipation -ByPosition $positionExtraO -ByPair $pairExtraO -MatchingTriples $extraO.Count
    return [ordered]@{
        scope = 'unordered_three_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$PairWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$PairWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$PairWithholding.anchor_index_in_anchor_journeys
        path = [string]$PairWithholding.path
        exact_saved_quote_anchor = $PairWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            unordered_original_position_triple_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $originalGenuine
            original_global_maximum_original_locally_optimal_distinct_family_count = $originalFrozen
            number_of_triples_reducing_original_independent_maximum = $criticalG.Count
            number_of_triples_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_third_order_critical_triples_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_third_order_critical_triples_for_original_local_optimum_maximum = $minimalO.Count
            number_of_triples_with_additional_independent_family_loss_beyond_stronger_pair = $extraG.Count
            number_of_triples_with_additional_original_local_optimum_family_loss_beyond_stronger_pair = $extraO.Count
            minimum_global_independent_family_maximum_after_three_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_three_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_three_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_three_withheld_positions = $maxO
        }
        original_position_triple_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_triple_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_third_order_critical_triple_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_third_order_critical_triple_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        triple_indices_causing_additional_independent_loss_vs_stronger_pair = $extraG.ToArray()
        triple_indices_causing_additional_original_local_optimum_loss_vs_stronger_pair = $extraO.ToArray()
        ordered_original_position_triple_withholding = $resultRows.ToArray()
        ordered_original_position_triple_participation = $positionRows.ToArray()
        ordered_original_pair_triple_participation = $pairRows.ToArray()
        complete_original_ec060_pair_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'For EVERY unordered triple of ORIGINAL caller-selected report positions, exclude only EXISTING originally observed complete motif windows touching at least one of those three positions. No renumbered report sequence, newly stitched adjacency, record deletion or re-optimized EC-056 full-selection local maximum is admitted. Surviving genuine original two/four/six-window witness combinations and the separate original full-selection locally optimal packings retain multiplicity of distinct real witnesses sharing a position union. Minimal THIRD-ORDER criticality means ALL three constituent PAIR exclusions preserve the original maximum but the simultaneous triple does not. Additional family loss beyond the strongest constituent pair is tracked separately, even if that pair already reduced support. Saved model-profile histogram sensitivity is not causal removal, authentic Finding identity, historical chronology, a fix, regression or proven risk.'
    }
}

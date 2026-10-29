#requires -Version 7.0
<#
    EC-060: exact two-ORIGINAL-position evidence withholding.  Reuse the
    already-conserved EC-059 witness mask arrays; do not read records again.
    Joint exclusion is measured against actual original windows, NEVER a
    shortened/rejoined report sequence. Frozen optimum refers to the full
    original selection, not a newly optimized post-exclusion packing.
#>

function Get-CodeSequencePairWithholdingValidatedAggregate {
    param(
        [object[]] $MasksByFamily,
        [object] $Original,
        [int] $N
    )
    $indices = [int[]]$Original.family_indices
    $hist = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $MasksByFamily `
        -FamilyIndices $indices -PositionCount $N -IncludeMaskHistogram
    if ([long]$hist.combination_count -ne [long]$Original.combination_count -or
        $hist.original_position_witness_inclusion_counts.Count -ne $N -or
        $hist.multiplicity_by_original_position_union_mask.Count -ne (1 -shl $N)) {
        throw 'Code Sequence two-position withholding did not conserve EC-059 parent witness totals.'
    }
    for ($p = 0; $p -lt $N; $p++) {
        if ([long]$hist.original_position_witness_inclusion_counts[$p] -ne
                [long]$Original.original_position_witness_inclusion_counts[$p]) {
            throw 'Code Sequence two-position withholding disagrees with an original single-position inclusion ledger.'
        }
    }
    # Count witnesses whose ORIGINAL coverage touches both excluded positions.
    # This is an exact multiplicity-weighted intersection, not the minimum of
    # two EC-059 survivor totals (nor a sum of independent pairwise cliques).
    $intersections = [long[]]::new($N * $N)
    $checkTotal = [long]0
    $checkPositions = [long[]]::new($N)
    foreach ($mask in $hist.nonzero_original_position_union_masks) {
        $mask = [int]$mask
        if ($mask -le 0 -or $mask -ge (1 -shl $N)) {
            throw 'Code Sequence two-position withholding encountered an invalid original witness mask.'
        }
        $weight = [long]$hist.multiplicity_by_original_position_union_mask[$mask]
        if ($weight -le 0) {
            throw 'Code Sequence two-position withholding lost witness mask multiplicity.'
        }
        $checkTotal += $weight
        for ($p = 0; $p -lt $N; $p++) {
            if (($mask -band (1 -shl $p)) -eq 0) { continue }
            $checkPositions[$p] += $weight
            for ($q = $p + 1; $q -lt $N; $q++) {
                if (($mask -band (1 -shl $q)) -ne 0) {
                    $intersections[($p * $N) + $q] += $weight
                }
            }
        }
    }
    if ($checkTotal -ne [long]$Original.combination_count) {
        throw 'Code Sequence two-position withholding mask weights do not sum to the original exact witness count.'
    }
    for ($p = 0; $p -lt $N; $p++) {
        if ($checkPositions[$p] -ne [long]$Original.original_position_witness_inclusion_counts[$p]) {
            throw 'Code Sequence two-position withholding mask weights violate original position conservation.'
        }
    }
    # EC-061: retain the exact sparse, multiplicity-weighted ORIGINAL masks
    # privately. The public EC-060 payload and older EC-059 contract stay
    # identical; the later triple projection does not reread evidence.
    $sparseMasks = [int[]]$hist.nonzero_original_position_union_masks
    $sparseWeights = [long[]]::new($sparseMasks.Count)
    for ($i = 0; $i -lt $sparseMasks.Count; $i++) {
        $sparseWeights[$i] = [long]$hist.multiplicity_by_original_position_union_mask[$sparseMasks[$i]]
    }
    return [ordered]@{
        original_combination_count = [long]$hist.combination_count
        original_position_inclusion_counts = $checkPositions
        original_pair_intersection_counts = $intersections
        nonzero_original_union_masks = $sparseMasks
        nonzero_original_union_mask_multiplicities = $sparseWeights
    }
}

function Get-CodeSequencePairWithholdingRemainingCount {
    param(
        [object] $Aggregate,
        [int] $N,
        [int] $P,
        [int] $Q = -1
    )
    if ($P -lt 0 -or $P -ge $N -or $Q -ge $N -or
        ($Q -ge 0 -and $Q -le $P)) {
        throw 'Code Sequence two-position withholding requires original ascending zero-based positions.'
    }
    $remaining = [long]$Aggregate.original_combination_count -
        [long]$Aggregate.original_position_inclusion_counts[$P]
    if ($Q -ge 0) {
        $remaining -= [long]$Aggregate.original_position_inclusion_counts[$Q]
        $remaining += [long]$Aggregate.original_pair_intersection_counts[($P * $N) + $Q]
        $singleQ = [long]$Aggregate.original_combination_count -
            [long]$Aggregate.original_position_inclusion_counts[$Q]
        if ($remaining -gt $singleQ) {
            throw 'Code Sequence two-position withholding added witnesses after an exclusion.'
        }
    }
    if ($remaining -lt 0 -or $remaining -gt [long]$Aggregate.original_combination_count) {
        throw 'Code Sequence two-position withholding witness survivors are out of bounds.'
    }
    return [long]$remaining
}

function Get-CodeSequencePairWithholdingLayer {
    param(
        [object[]] $Rows,
        [int] $N,
        [int] $P,
        [int] $Q = -1
    )
    $genuineTotal = [long]0
    $optimumTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $optimumIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $optimumSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequencePairWithholdingRemainingCount -Aggregate $row.genuine -N $N -P $P -Q $Q
        $o = Get-CodeSequencePairWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -P $P -Q $Q
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

function Get-CodeSequencePairWithholdingGlobalMaximum {
    param(
        [object] $Single,
        [object] $Pair,
        [object] $Triple,
        [bool] $OriginalLocalOptima
    )
    foreach ($level in @(3,2,1)) {
        # Direct assignment preserves an outer object[] containing ONE set.
        # Expression-output capture would flatten it into an int[] and turn
        # a single 3-family maximizer into three unrelated entries.
        if ($level -eq 3) { $layer = $Triple }
        elseif ($level -eq 2) { $layer = $Pair }
        else { $layer = $Single }
        if ($OriginalLocalOptima) {
            $sets = $layer.original_local_optimum_family_sets
        } else {
            $sets = $layer.genuine_family_sets
        }
        if ($sets.Count -gt 0) {
            return [ordered]@{
                distinct_family_count = $level
                all_attaining_family_index_sets = $sets
            }
        }
    }
    return [ordered]@{ distinct_family_count = 0; all_attaining_family_index_sets = @() }
}

function Assert-CodeSequencePairWithholdingOrdinalList {
    param([object[]] $Actual, [object[]] $Expected)
    if ((@($Actual) -join ':') -cne (@($Expected) -join ':')) {
        throw 'Code Sequence two-position withholding disagrees with an original surviving ordinal registry.'
    }
}

function Get-CodeSequenceOriginalFindingPairProfilePairPositionWithholding {
    param(
        [object] $Atlas,
        [object] $Triple,
        [object] $Withholding,
        [object] $WitnessIndex,
        [ref] $WitnessAggregatesOut
    )
    if ($null -eq $Atlas -or $null -eq $Triple -or
        $null -eq $Withholding -or $null -eq $WitnessIndex -or
        $Withholding.scope -cne 'single_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        -not [bool]$Withholding.complete_original_ec054_windows_ec056_packings_ec057_pairs_and_ec058_triples_reconciled -or
        -not [bool]$Withholding.two_original_finding_journeys_remain_independent -or
        -not [bool]$Withholding.independent_of_sequence_top) {
        throw 'Code Sequence two-position withholding requires the completed, conserved EC-059 baseline.'
    }
    $n = [int]$Withholding.counts.selected_report_positions
    $f = [int]$Withholding.counts.original_maximal_repeat_family_count
    $originalRecords = [string[]]$WitnessIndex.original_record_ids
    $originalClasses = [int[]]$WitnessIndex.original_profile_classes
    $singleParents = @($WitnessIndex.single_family_rows)
    $pairParents = @($WitnessIndex.cross_family_pair_rows)
    $tripleParents = @($WitnessIndex.cross_family_triple_rows)
    $singleWithheld = @($Withholding.ordered_single_original_position_withholding)
    $two = [object[]]$WitnessIndex.genuine_two_window_masks_by_family
    $optima = [object[]]$WitnessIndex.frozen_optimum_packing_masks_by_family
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $f -lt 0 -or $f -gt 66 -or $originalRecords.Count -ne $n -or
        $originalClasses.Count -ne $n -or $Atlas.positions.Count -ne $n -or
        $singleWithheld.Count -ne $n -or $two.Count -ne $f -or
        $optima.Count -ne $f -or $singleParents.Count -ne $f -or
        $pairParents.Count -ne [int](($f * ($f - 1)) / 2) -or
        $tripleParents.Count -ne [int](($f * ($f - 1) * ($f - 2)) / 6) -or
        [int]$Triple.counts.selected_report_positions -ne $n -or
        [int]$Triple.counts.maximal_repeat_family_count -ne $f -or
        $Withholding.path -cne $Triple.path -or
        [int]$Withholding.pair_index_in_pairwise_profile -ne [int]$Triple.pair_index_in_pairwise_profile -or
        [int]$Withholding.path_index_in_selected_pair_overview -ne [int]$Triple.path_index_in_selected_pair_overview -or
        [int]$Withholding.anchor_index_in_anchor_journeys -ne [int]$Triple.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Withholding.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Triple.exact_saved_quote_anchor)) {
        throw 'Code Sequence two-position withholding original evidence or selector scope changed.'
    }
    for ($p = 0; $p -lt $n; $p++) {
        $ap = $Atlas.positions[$p]
        $prior = $singleWithheld[$p]
        if ([int]$ap.position -ne $p + 1 -or
            $ap.record_id -cne $originalRecords[$p] -or
            [int]$ap.profile_class_index -ne $originalClasses[$p] -or
            [int]$prior.withheld_original_caller_position -ne $p + 1 -or
            $prior.withheld_original_record_id -cne $originalRecords[$p] -or
            [int]$prior.original_saved_profile_class_index -ne $originalClasses[$p]) {
            throw 'Code Sequence two-position withholding original saved position identities changed.'
        }
    }

    # Rebuild original mask histograms from the PRIVATE masks supplied by the
    # already successful EC-059 provenance conservation. A different ORIGINAL
    # window combination with the SAME union mask retains its multiplicity.
    $singleRows = [System.Collections.Generic.List[object]]::new()
    $pairRows = [System.Collections.Generic.List[object]]::new()
    $tripleRows = [System.Collections.Generic.List[object]]::new()
    foreach ($level in @(1,2,3)) {
        # Do not pipe array/list objects through an if-expression: PS output
        # enumeration loses singleton family registries and empty List objects.
        if ($level -eq 1) {
            $parents = $singleParents
            $destination = $singleRows
        } elseif ($level -eq 2) {
            $parents = $pairParents
            $destination = $pairRows
        } else {
            $parents = $tripleParents
            $destination = $tripleRows
        }
        for ($i = 0; $i -lt $parents.Count; $i++) {
            $row = $parents[$i]
            $indices = [int[]]$row.family_indices
            if ($indices.Count -ne $level -or
                [int]$indices[0] -lt 1 -or [int]$indices[-1] -gt $f -or
                (($indices | Sort-Object -Unique).Count -ne $level)) {
                throw 'Code Sequence two-position withholding found an invalid original family set.'
            }
            $g = Get-CodeSequencePairWithholdingValidatedAggregate -MasksByFamily $two `
                -Original ([ordered]@{
                    family_indices = $indices
                    combination_count = $row.genuine.combination_count
                    original_position_witness_inclusion_counts = $row.genuine.original_position_witness_inclusion_counts
                }) -N $n
            $o = Get-CodeSequencePairWithholdingValidatedAggregate -MasksByFamily $optima `
                -Original ([ordered]@{
                    family_indices = $indices
                    combination_count = $row.original_local_optima.combination_count
                    original_position_witness_inclusion_counts = $row.original_local_optima.original_position_witness_inclusion_counts
                }) -N $n
            $destination.Add([ordered]@{
                registry_index = $i + 1
                family_indices = $indices
                genuine = $g
                original_local_optima = $o
            })
        }
    }
    $singles = $singleRows.ToArray()
    $pairs = $pairRows.ToArray()
    $triples = $tripleRows.ToArray()
    $oneIndependent = [int[]]::new($n)
    $oneFrozen = [int[]]::new($n)
    $baselineMax = [int]$Withholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baselineFrozen = [int]$Withholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($baselineMax -ne [int]$Triple.counts.globally_maximum_simultaneously_independently_supported_distinct_family_count -or
        $baselineFrozen -ne [int]$Triple.counts.globally_maximum_simultaneously_locally_optimal_distinct_family_count) {
        throw 'Code Sequence two-position withholding baseline global maxima disagree with the conserved triple ledger.'
    }
    # Re-project every previously published EC-059 singleton before
    # calculating any pair. This is an independent arithmetic bridge between
    # the full original mask histogram and unchanged earlier public results.
    for ($p = 0; $p -lt $n; $p++) {
        $one = $singleWithheld[$p]
        $s = Get-CodeSequencePairWithholdingLayer -Rows $singles -N $n -P $p
        $d = Get-CodeSequencePairWithholdingLayer -Rows $pairs -N $n -P $p
        $t = Get-CodeSequencePairWithholdingLayer -Rows $triples -N $n -P $p
        $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $false
        $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $true
        if ([long]$one.surviving_original_independent_two_window_combinations -ne $s.genuine_total -or
            [long]$one.surviving_original_joint_four_window_combinations -ne $d.genuine_total -or
            [long]$one.surviving_original_joint_six_window_combinations -ne $t.genuine_total -or
            [long]$one.surviving_original_full_selection_local_optimum_individual_packings -ne $s.original_local_optimum_total -or
            [long]$one.surviving_original_full_selection_joint_local_optimum_packing_pairs -ne $d.original_local_optimum_total -or
            [long]$one.surviving_original_full_selection_joint_local_optimum_packing_triples -ne $t.original_local_optimum_total -or
            [int]$one.globally_maximum_simultaneously_independently_supported_distinct_family_count -ne [int]$gMax.distinct_family_count -or
            [int]$one.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count -ne [int]$oMax.distinct_family_count) {
            throw 'Code Sequence two-position withholding could not reproduce original EC-059 per-position totals.'
        }
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $s.genuine_registry_indices -Expected $one.independently_supported_family_indices
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $d.genuine_registry_indices -Expected $one.jointly_supported_family_pair_indices
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $t.genuine_registry_indices -Expected $one.jointly_supported_family_triple_indices
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $s.original_local_optimum_registry_indices -Expected $one.original_local_optimum_family_indices
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $d.original_local_optimum_registry_indices -Expected $one.jointly_compatible_original_local_optimum_family_pair_indices
        Assert-CodeSequencePairWithholdingOrdinalList -Actual $t.original_local_optimum_registry_indices -Expected $one.jointly_compatible_original_local_optimum_family_triple_indices
        Assert-CodeSequenceWithholdingFamilySets -Actual $gMax.all_attaining_family_index_sets -Expected $one.all_attaining_family_index_sets
        Assert-CodeSequenceWithholdingFamilySets -Actual $oMax.all_attaining_family_index_sets -Expected $one.all_attaining_original_local_optimum_family_index_sets
        $oneIndependent[$p] = [int]$gMax.distinct_family_count
        $oneFrozen[$p] = [int]$oMax.distinct_family_count
    }

    $allPairs = [System.Collections.Generic.List[object]]::new()
    $critical = [System.Collections.Generic.List[int]]::new()
    $criticalFrozen = [System.Collections.Generic.List[int]]::new()
    $minimalCritical = [System.Collections.Generic.List[int]]::new()
    $minimalCriticalFrozen = [System.Collections.Generic.List[int]]::new()
    $extraBeyondSingle = [System.Collections.Generic.List[int]]::new()
    $extraBeyondSingleFrozen = [System.Collections.Generic.List[int]]::new()
    $recordPairCritical = [int[]]::new($n)
    $recordPairCriticalFrozen = [int[]]::new($n)
    $recordMinimalCritical = [int[]]::new($n)
    $recordMinimalCriticalFrozen = [int[]]::new($n)
    $minAfter = $baselineMax; $maxAfter = 0
    $minFrozenAfter = $baselineFrozen; $maxFrozenAfter = 0
    $ordinal = 0
    for ($p = 0; $p -lt $n; $p++) {
        for ($q = $p + 1; $q -lt $n; $q++) {
            $ordinal++
            $s = Get-CodeSequencePairWithholdingLayer -Rows $singles -N $n -P $p -Q $q
            $d = Get-CodeSequencePairWithholdingLayer -Rows $pairs -N $n -P $p -Q $q
            $t = Get-CodeSequencePairWithholdingLayer -Rows $triples -N $n -P $p -Q $q
            $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $false
            $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $s -Pair $d -Triple $t -OriginalLocalOptima $true
            $g = [int]$gMax.distinct_family_count
            $o = [int]$oMax.distinct_family_count
            if ($g -gt [math]::Floor(($n - 2) / 4) -or
                $g -gt [math]::Min($oneIndependent[$p], $oneIndependent[$q]) -or
                $o -gt [math]::Min($oneFrozen[$p], $oneFrozen[$q]) -or
                $o -gt $g -or $g -gt $baselineMax -or $o -gt $baselineFrozen) {
                throw 'Code Sequence two-position withholding violated monotonicity or the N-2 family capacity bound.'
            }
            $reduced = $g -lt $baselineMax
            $reducedFrozen = $o -lt $baselineFrozen
            $minimallyJointCritical = $reduced -and $oneIndependent[$p] -eq $baselineMax -and $oneIndependent[$q] -eq $baselineMax
            $minimallyJointCriticalFrozen = $reducedFrozen -and $oneFrozen[$p] -eq $baselineFrozen -and $oneFrozen[$q] -eq $baselineFrozen
            $extra = [int][math]::Min($oneIndependent[$p], $oneIndependent[$q]) - $g
            $extraFrozen = [int][math]::Min($oneFrozen[$p], $oneFrozen[$q]) - $o
            if ($reduced) { $critical.Add($ordinal); $recordPairCritical[$p]++; $recordPairCritical[$q]++ }
            if ($reducedFrozen) { $criticalFrozen.Add($ordinal); $recordPairCriticalFrozen[$p]++; $recordPairCriticalFrozen[$q]++ }
            if ($minimallyJointCritical) { $minimalCritical.Add($ordinal); $recordMinimalCritical[$p]++; $recordMinimalCritical[$q]++ }
            if ($minimallyJointCriticalFrozen) { $minimalCriticalFrozen.Add($ordinal); $recordMinimalCriticalFrozen[$p]++; $recordMinimalCriticalFrozen[$q]++ }
            if ($extra -gt 0) { $extraBeyondSingle.Add($ordinal) }
            if ($extraFrozen -gt 0) { $extraBeyondSingleFrozen.Add($ordinal) }
            $minAfter = [math]::Min($minAfter, $g); $maxAfter = [math]::Max($maxAfter, $g)
            $minFrozenAfter = [math]::Min($minFrozenAfter, $o); $maxFrozenAfter = [math]::Max($maxFrozenAfter, $o)
            $allPairs.Add([ordered]@{
                original_position_pair_index = $ordinal
                withheld_original_caller_positions = [int[]]@(($p + 1),($q + 1))
                withheld_original_record_ids = [string[]]@($originalRecords[$p],$originalRecords[$q])
                original_saved_profile_class_indices = [int[]]@($originalClasses[$p],$originalClasses[$q])
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
                reduces_original_global_maximum_independent_family_count = [bool]$reduced
                globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedFrozen
                minimally_joint_critical_for_original_independent_maximum = [bool]$minimallyJointCritical
                minimally_joint_critical_for_original_local_optimum_maximum = [bool]$minimallyJointCriticalFrozen
                additional_independent_family_loss_beyond_stronger_single_exclusion = $extra
                additional_original_local_optimum_family_loss_beyond_stronger_single_exclusion = $extraFrozen
            })
        }
    }
    if ($ordinal -ne [int](($n * ($n - 1)) / 2)) {
        throw 'Code Sequence two-position withholding did not enumerate every unordered original pair.'
    }
    $perPosition = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $n; $p++) {
        $perPosition.Add([ordered]@{
            original_caller_position = $p + 1
            original_record_id = $originalRecords[$p]
            original_saved_profile_class_index = $originalClasses[$p]
            number_of_position_pairs_containing_position = $n - 1
            pairs_reducing_original_independent_maximum = $recordPairCritical[$p]
            pairs_reducing_original_local_optimum_maximum = $recordPairCriticalFrozen[$p]
            minimally_joint_critical_pairs_for_original_independent_maximum = $recordMinimalCritical[$p]
            minimally_joint_critical_pairs_for_original_local_optimum_maximum = $recordMinimalCriticalFrozen[$p]
        })
    }
    if ($null -ne $WitnessAggregatesOut) {
        $WitnessAggregatesOut.Value = [ordered]@{
            scope = 'ec060_reconciled_private_original_union_mask_witness_histograms'
            original_record_ids = $originalRecords
            original_profile_classes = $originalClasses
            single_family_rows = $singles
            cross_family_pair_rows = $pairs
            cross_family_triple_rows = $triples
        }
    }
    return [ordered]@{
        scope = 'unordered_two_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$Withholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Withholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Withholding.anchor_index_in_anchor_journeys
        path = [string]$Withholding.path
        exact_saved_quote_anchor = $Withholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            unordered_original_position_pair_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baselineMax
            original_global_maximum_original_locally_optimal_distinct_family_count = $baselineFrozen
            number_of_pairs_reducing_original_independent_maximum = $critical.Count
            number_of_pairs_reducing_original_local_optimum_maximum = $criticalFrozen.Count
            number_of_minimally_joint_critical_pairs_for_original_independent_maximum = $minimalCritical.Count
            number_of_minimally_joint_critical_pairs_for_original_local_optimum_maximum = $minimalCriticalFrozen.Count
            number_of_pairs_with_additional_independent_family_loss_beyond_stronger_single_exclusion = $extraBeyondSingle.Count
            number_of_pairs_with_additional_original_local_optimum_family_loss_beyond_stronger_single_exclusion = $extraBeyondSingleFrozen.Count
            minimum_global_independent_family_maximum_after_two_withheld_positions = $minAfter
            maximum_global_independent_family_maximum_after_two_withheld_positions = $maxAfter
            minimum_global_original_local_optimum_family_maximum_after_two_withheld_positions = $minFrozenAfter
            maximum_global_original_local_optimum_family_maximum_after_two_withheld_positions = $maxFrozenAfter
        }
        original_position_pair_indices_reducing_independent_maximum = $critical.ToArray()
        original_position_pair_indices_reducing_original_local_optimum_maximum = $criticalFrozen.ToArray()
        minimally_joint_critical_position_pair_indices_for_independent_maximum = $minimalCritical.ToArray()
        minimally_joint_critical_position_pair_indices_for_original_local_optimum_maximum = $minimalCriticalFrozen.ToArray()
        pair_indices_causing_additional_independent_family_loss_vs_stronger_single = $extraBeyondSingle.ToArray()
        pair_indices_causing_additional_original_local_optimum_family_loss_vs_stronger_single = $extraBeyondSingleFrozen.ToArray()
        ordered_original_position_pair_withholding = $allPairs.ToArray()
        ordered_original_position_pair_participation = $perPosition.ToArray()
        complete_original_ec059_witness_masks_and_every_single_position_projection_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'For EVERY unordered pair of ORIGINAL caller-selected report positions, discard only PRE-EXISTING complete observed motif windows touching either original position; never renumber, join former neighbors, rerun class-walk detection or edit saved records. Recount all genuine original disjoint two/four/six-window combinations with exact union-mask multiplicities, separately retaining only originally full-selection EC-056 locally optimal packings. Distinguish reduction already caused by one position from a MINIMALLY JOINT CRITICAL pair whose two individual exclusions preserve the original maximum. These are model-statement histogram counterfactual exclusions, not a factual report deletion, attested event chronology, semantic Finding identity, causality, defect recurrence, severity, fix, regression or risk.'
    }
}

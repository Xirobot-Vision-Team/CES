#requires -Version 7.0
<#
    EC-071: exact resilience frontiers across ALL ORIGINAL caller-position
    withholding orders 0..N (N=2..12). A set is inclusion-minimal only when
    EVERY proper subset preserves the relevant evidence/capacity threshold.
    Original saved-order positions are not dates or reconstructed adjacency.

    The source is the already reconciled PRIVATE EC-060 original witness-mask
    histogram; original EC-056 locally optimal packs remain FROZEN. Nothing
    reads saved quote bodies, working trees, Git, network or writes any state.
#>

function Get-CodeSequenceResiliencePopcount {
    param([int] $Mask)
    $count = 0
    while ($Mask -gt 0) {
        $count += ($Mask -band 1)
        $Mask = $Mask -shr 1
    }
    return [int]$count
}

function Add-CodeSequenceResilienceHistogram {
    param([object] $Aggregate, [long[]] $Bucket, [int] $N,
        [int] $MinimumOriginalPositions, [long[]] $AdditionalBucket = $null)
    $size = 1 -shl $N
    if ($null -eq $Aggregate -or $Bucket.Count -ne $size -or
        ($null -ne $AdditionalBucket -and $AdditionalBucket.Count -ne $size)) {
        throw 'Code Sequence resilience frontier missing private original mask histogram.'
    }
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $expected = [long]$Aggregate.original_combination_count
    if ($expected -lt 0 -or $masks.Count -ne $weights.Count) {
        throw 'Code Sequence resilience frontier original witness-mask multiplicities are inconsistent.'
    }
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $actual = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = [int]$masks[$i]
        $weight = [long]$weights[$i]
        if ($mask -le 0 -or $mask -ge $size -or $weight -le 0 -or
            -not $seen.Add($mask) -or
            (Get-CodeSequenceResiliencePopcount -Mask $mask) -lt $MinimumOriginalPositions) {
            throw 'Code Sequence resilience frontier rejected a fabricated, duplicate or undersized original witness.'
        }
        $Bucket[$mask] += $weight
        if ($null -ne $AdditionalBucket) { $AdditionalBucket[$mask] += $weight }
        $actual += $weight
    }
    if ($actual -ne $expected) {
        throw 'Code Sequence resilience frontier altered private original witness multiplicity.'
    }
}

function Get-CodeSequenceResilienceAllExclusionSurvivors {
    param([long[]] $OriginalUnionMaskWeights, [int] $N)
    $size = 1 -shl $N
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $OriginalUnionMaskWeights -or
        $OriginalUnionMaskWeights.Count -ne $size -or $OriginalUnionMaskWeights[0] -ne 0) {
        throw 'Code Sequence resilience frontier expected a bounded original-mask histogram.'
    }
    $included = [long[]]::new($size)
    [array]::Copy($OriginalUnionMaskWeights, $included, $size)
    # Standard SUBSET zeta transform: included[A] is the weighted number of
    # ORIGINAL witnesses whose exact union mask is a subset of A. Omitting E
    # therefore leaves included[full XOR E]. One transform replaces per-cut
    # witness rescans, and preserves exact multiplicities of equal union masks.
    for ($bit = 0; $bit -lt $N; $bit++) {
        $bitMask = 1 -shl $bit
        for ($mask = 0; $mask -lt $size; $mask++) {
            if (($mask -band $bitMask) -ne 0) {
                $included[$mask] += $included[$mask -bxor $bitMask]
            }
        }
    }
    $remaining = [long[]]::new($size)
    $full = $size - 1
    for ($excluded = 0; $excluded -lt $size; $excluded++) {
        $remaining[$excluded] = $included[$full -bxor $excluded]
    }
    if ($remaining[$full] -ne 0) {
        throw 'Code Sequence resilience frontier invented witnesses with every original report withheld.'
    }
    return ,$remaining
}

function Get-CodeSequenceResilienceMinimalCuts {
    param([long[]] $SurvivingByExclusionMask, [long] $Threshold)
    $size = $SurvivingByExclusionMask.Count
    $cuts = [System.Collections.Generic.List[int]]::new()
    if ($Threshold -le 0 -or $SurvivingByExclusionMask[0] -lt $Threshold) {
        $empty = [int[]]@()
        return ,$empty
    }
    # For a monotone decreasing property, checking the immediate deletion of
    # each member is NECESSARY AND SUFFICIENT for inclusion-minimality.
    for ($mask = 1; $mask -lt $size; $mask++) {
        if ($SurvivingByExclusionMask[$mask] -ge $Threshold) { continue }
        $minimal = $true
        for ($bit = 1; $bit -lt $size; $bit = $bit -shl 1) {
            if (($mask -band $bit) -ne 0 -and
                $SurvivingByExclusionMask[$mask -bxor $bit] -lt $Threshold) {
                $minimal = $false
                break
            }
        }
        if ($minimal) { $cuts.Add($mask) }
    }
    $answer = [int[]]$cuts.ToArray()
    return ,$answer
}

function Get-CodeSequenceResilienceLexicographicOrdinal {
    param([int[]] $OneBasedPositions, [int] $N)
    # Rank ascending ORIGINAL combinations by the same nested-loop ordering
    # used by all prior EC-059..070 level ledgers. Ordinals are one-based.
    $rank = 1
    $previous = 0
    for ($i = 0; $i -lt $OneBasedPositions.Count; $i++) {
        for ($candidate = $previous + 1; $candidate -lt $OneBasedPositions[$i]; $candidate++) {
            $rank += Get-CodeSequenceDuodecetWithholdingChoose `
                -N ($N - $candidate) -K ($OneBasedPositions.Count - $i - 1)
        }
        $previous = [int]$OneBasedPositions[$i]
    }
    return [int]$rank
}

function Get-CodeSequenceResilienceSmallestCutSize {
    param([int[]] $Masks)
    if ($null -eq $Masks -or $Masks.Count -eq 0) { return $null }
    $minimum = 13
    foreach ($mask in $Masks) {
        $minimum = [math]::Min($minimum, (Get-CodeSequenceResiliencePopcount -Mask $mask))
    }
    return [int]$minimum
}

function Assert-CodeSequenceResilienceSavedIndices {
    param([int[]] $Indices, [int] $Maximum)
    $previous = 0
    foreach ($index in $Indices) {
        if ($index -le $previous -or $index -gt $Maximum) {
            throw 'Code Sequence resilience frontier found changed original family registry indices.'
        }
        $previous = $index
    }
}

function Get-CodeSequenceOriginalFindingPairProfileResilienceFrontier {
    param([object[]] $Layers, [object] $WitnessAggregates)

    $names = [string[]]@('single','pair','triple','quartet','quintet','sextet',
        'septet','octet','nonet','decet','undecet','duodecet')
    $rowsNames = [string[]]@('ordered_single_original_position_withholding',
        'ordered_original_position_pair_withholding',
        'ordered_original_position_triple_withholding',
        'ordered_original_position_quartet_withholding',
        'ordered_original_position_quintet_withholding',
        'ordered_original_position_sextet_withholding',
        'ordered_original_position_septet_withholding',
        'ordered_original_position_octet_withholding',
        'ordered_original_position_nonet_withholding',
        'ordered_original_position_decet_withholding',
        'ordered_original_position_undecet_withholding',
        'ordered_original_position_duodecet_withholding')
    $scopeNames = [string[]]@(
        'single_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_two_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_three_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_four_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_five_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_six_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_seven_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_eight_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_nine_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_ten_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_eleven_original_report_position_withholding_exact_original_witness_survival_no_resequencing',
        'unordered_twelve_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
    )
    if ($null -eq $Layers -or $Layers.Count -ne 12 -or $null -eq $WitnessAggregates -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        $null -eq $Layers[0] -or $null -eq $Layers[11] -or
        -not [bool]$Layers[11].complete_original_ec069_undecet_projections_and_private_witness_masks_reconciled) {
        throw 'Code Sequence resilience frontier requires all twelve completed original withholding levels.'
    }
    $n = [int]$Layers[0].counts.selected_report_positions
    $f = [int]$Layers[0].counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $f -lt 0 -or $f -gt 66 -or $records.Count -ne $n -or $classes.Count -ne $n -or
        $singles.Count -ne $f -or
        $pairs.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 2) -or
        $triples.Count -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $f -K 3)) {
        throw 'Code Sequence resilience frontier original selected report/family provenance changed.'
    }
    $baselineG = [int]$Layers[0].counts.original_global_maximum_independently_supported_distinct_family_count
    $baselineO = [int]$Layers[0].counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($baselineG -lt 0 -or $baselineG -gt 3 -or $baselineO -lt 0 -or $baselineO -gt $baselineG) {
        throw 'Code Sequence resilience frontier original global baseline is invalid.'
    }

    $size = 1 -shl $n
    $full = $size - 1
    # Explicitly hold each registry array as one element: PowerShell otherwise
    # flattens empty and singleton arrays when passing through expressions.
    $sources = @(
        [pscustomobject]@{ Rows = $singles; Minimum = 4 },
        [pscustomobject]@{ Rows = $pairs; Minimum = 8 },
        [pscustomobject]@{ Rows = $triples; Minimum = 12 }
    )
    $allG = [System.Collections.Generic.List[object]]::new()
    $allO = [System.Collections.Generic.List[object]]::new()
    $singleFamilyG = [System.Collections.Generic.List[object]]::new()
    $singleFamilyO = [System.Collections.Generic.List[object]]::new()
    foreach ($source in $sources) {
        $globalBucketG = [long[]]::new($size)
        $globalBucketO = [long[]]::new($size)
        $ordinal = 0
        foreach ($one in [object[]]$source.Rows) {
            $ordinal++
            if ([int]$one.registry_index -ne $ordinal -or $null -eq $one.genuine -or
                $null -eq $one.original_local_optima) {
                throw 'Code Sequence resilience frontier source family registry changed.'
            }
            $localG = $null; $localO = $null
            if ([int]$source.Minimum -eq 4) {
                if (([int[]]$one.family_indices).Count -ne 1 -or
                    [int]$one.family_indices[0] -ne $ordinal) {
                    throw 'Code Sequence resilience frontier lost an original family identity.'
                }
                $localG = [long[]]::new($size)
                $localO = [long[]]::new($size)
            }
            Add-CodeSequenceResilienceHistogram -Aggregate $one.genuine -Bucket $globalBucketG `
                -N $n -MinimumOriginalPositions ([int]$source.Minimum) -AdditionalBucket $localG
            Add-CodeSequenceResilienceHistogram -Aggregate $one.original_local_optima -Bucket $globalBucketO `
                -N $n -MinimumOriginalPositions ([int]$source.Minimum) -AdditionalBucket $localO
            if ([int]$source.Minimum -eq 4) {
                $singleFamilyG.Add((Get-CodeSequenceResilienceAllExclusionSurvivors -OriginalUnionMaskWeights $localG -N $n))
                $singleFamilyO.Add((Get-CodeSequenceResilienceAllExclusionSurvivors -OriginalUnionMaskWeights $localO -N $n))
            }
        }
        $allG.Add((Get-CodeSequenceResilienceAllExclusionSurvivors -OriginalUnionMaskWeights $globalBucketG -N $n))
        $allO.Add((Get-CodeSequenceResilienceAllExclusionSurvivors -OriginalUnionMaskWeights $globalBucketO -N $n))
    }
    $singleCountG = [long[]]$allG[0]; $pairCountG = [long[]]$allG[1]; $tripleCountG = [long[]]$allG[2]
    $singleCountO = [long[]]$allO[0]; $pairCountO = [long[]]$allO[1]; $tripleCountO = [long[]]$allO[2]
    if ($singleCountG[0] -ne [long]$Layers[0].counts.originally_independent_two_window_combinations -or
        $pairCountG[0] -ne [long]$Layers[0].counts.originally_joint_four_window_combinations -or
        $tripleCountG[0] -ne [long]$Layers[0].counts.originally_joint_six_window_combinations) {
        throw 'Code Sequence resilience frontier original unwithheld witness evidence disagrees with EC-059.'
    }

    $maxG = [long[]]::new($size)
    $maxO = [long[]]::new($size)
    $sizes = [int[]]::new($size)
    $sizeTotals = [int[]]::new($n + 1)
    $minsG = [int[]]::new($n + 1)
    $maxsG = [int[]]::new($n + 1)
    $minsO = [int[]]::new($n + 1)
    $maxsO = [int[]]::new($n + 1)
    $reducedG = [int[]]::new($n + 1)
    $reducedO = [int[]]::new($n + 1)
    $extinguishedG = [int[]]::new($n + 1)
    $extinguishedO = [int[]]::new($n + 1)
    for ($k = 0; $k -le $n; $k++) { $minsG[$k] = 4; $minsO[$k] = 4 }
    for ($mask = 0; $mask -lt $size; $mask++) {
        $k = Get-CodeSequenceResiliencePopcount -Mask $mask
        $sizes[$mask] = $k
        $sizeTotals[$k]++
        $g = if ($tripleCountG[$mask] -gt 0) { 3 } elseif ($pairCountG[$mask] -gt 0) {
            2
        } elseif ($singleCountG[$mask] -gt 0) { 1 } else { 0 }
        $o = if ($tripleCountO[$mask] -gt 0) { 3 } elseif ($pairCountO[$mask] -gt 0) {
            2
        } elseif ($singleCountO[$mask] -gt 0) { 1 } else { 0 }
        $maxG[$mask] = $g; $maxO[$mask] = $o
        $minsG[$k] = [math]::Min($minsG[$k],$g); $maxsG[$k] = [math]::Max($maxsG[$k],$g)
        $minsO[$k] = [math]::Min($minsO[$k],$o); $maxsO[$k] = [math]::Max($maxsO[$k],$o)
        if ($g -lt $baselineG) { $reducedG[$k]++ }
        if ($o -lt $baselineO) { $reducedO[$k]++ }
        if ($g -eq 0) { $extinguishedG[$k]++ }
        if ($o -eq 0) { $extinguishedO[$k]++ }
        if ($o -gt $g -or $g -gt $baselineG -or $o -gt $baselineO -or
            $singleCountO[$mask] -gt $singleCountG[$mask] -or
            $pairCountO[$mask] -gt $pairCountG[$mask] -or
            $tripleCountO[$mask] -gt $tripleCountG[$mask] -or
            $g -gt [math]::Floor(($n - $k) / 4) -or
            $o -gt [math]::Floor(($n - $k) / 4)) {
            throw 'Code Sequence resilience frontier violated original disjoint-window capacity.'
        }
        if ($mask -gt 0) {
            for ($bit = 1; $bit -lt $size; $bit = $bit -shl 1) {
                if (($mask -band $bit) -eq 0) { continue }
                $parent = $mask -bxor $bit
                if ($g -gt $maxG[$parent] -or $o -gt $maxO[$parent] -or
                    $singleCountG[$mask] -gt $singleCountG[$parent] -or
                    $pairCountG[$mask] -gt $pairCountG[$parent] -or
                    $tripleCountG[$mask] -gt $tripleCountG[$parent] -or
                    $singleCountO[$mask] -gt $singleCountO[$parent] -or
                    $pairCountO[$mask] -gt $pairCountO[$parent] -or
                    $tripleCountO[$mask] -gt $tripleCountO[$parent]) {
                    throw 'Code Sequence resilience frontier found false witness survival monotonicity.'
                }
            }
        }
    }
    if ($maxG[0] -ne $baselineG -or $maxO[0] -ne $baselineO -or
        $maxG[$full] -ne 0 -or $maxO[$full] -ne 0) {
        throw 'Code Sequence resilience frontier changed original baseline or full-exclusion zero capacity.'
    }

    # Map each of the preexisting TWELVE checked level ledgers into one complete
    # 2^N Boolean cube. No path normalization or fictional new adjacency.
    $seen = [bool[]]::new($size)
    $seen[0] = $true
    $observedCount = 1
    $originalKey = Get-CodeCompareAnchorKey -Anchor $Layers[0].exact_saved_quote_anchor
    for ($level = 1; $level -le 12; $level++) {
        $layer = $Layers[$level - 1]
        if ($null -eq $layer -or $layer.scope -cne $scopeNames[$level - 1] -or
            $layer.path -cne $Layers[0].path -or
            [int]$layer.pair_index_in_pairwise_profile -ne [int]$Layers[0].pair_index_in_pairwise_profile -or
            [int]$layer.path_index_in_selected_pair_overview -ne [int]$Layers[0].path_index_in_selected_pair_overview -or
            [int]$layer.anchor_index_in_anchor_journeys -ne [int]$Layers[0].anchor_index_in_anchor_journeys -or
            (Get-CodeCompareAnchorKey -Anchor $layer.exact_saved_quote_anchor) -cne $originalKey -or
            [int]$layer.counts.selected_report_positions -ne $n -or
            [int]$layer.counts.original_maximal_repeat_family_count -ne $f -or
            [int]$layer.counts.original_global_maximum_independently_supported_distinct_family_count -ne $baselineG -or
            [int]$layer.counts.original_global_maximum_original_locally_optimal_distinct_family_count -ne $baselineO -or
            -not [bool]$layer.independent_of_sequence_top -or
            -not [bool]$layer.two_original_finding_journeys_remain_independent) {
            throw 'Code Sequence resilience frontier rejected a changed original withholding parent scope.'
        }
        $property = $rowsNames[$level - 1]
        $layerRows = [object[]]$layer[$property]
        $expected = Get-CodeSequenceDuodecetWithholdingChoose -N $n -K $level
        if ($layerRows.Count -ne $expected) {
            throw 'Code Sequence resilience frontier missing original parent exclusion sets.'
        }
        $ordinal = 0
        foreach ($row in $layerRows) {
            $ordinal++
            $positions = if ($level -eq 1) {
                [int[]]@([int]$row.withheld_original_caller_position)
            } else {
                [int[]]$row.withheld_original_caller_positions
            }
            if ($positions.Count -ne $level) {
                throw 'Code Sequence resilience frontier original exclusion set has the wrong order.'
            }
            if ($row -isnot [System.Collections.IDictionary]) {
                throw 'Code Sequence resilience frontier expected an original checked position ledger.'
            }
            $required = [string[]]@(
                'surviving_original_independent_two_window_combinations',
                'surviving_original_joint_four_window_combinations',
                'surviving_original_joint_six_window_combinations',
                'surviving_original_full_selection_local_optimum_individual_packings',
                'surviving_original_full_selection_joint_local_optimum_packing_pairs',
                'surviving_original_full_selection_joint_local_optimum_packing_triples',
                'independently_supported_family_indices',
                'original_local_optimum_family_indices',
                'globally_maximum_simultaneously_independently_supported_distinct_family_count',
                'globally_maximum_simultaneously_original_locally_optimal_distinct_family_count',
                'reduces_original_global_maximum_independent_family_count',
                'reduces_original_global_maximum_original_local_optimum_family_count'
            )
            foreach ($field in $required) {
                if (-not $row.Contains($field)) {
                    throw 'Code Sequence resilience frontier rejected a missing original survivor property.'
                }
            }
            $mask = 0
            $previous = 0
            $rowRecordIds = if ($level -eq 1) {
                [string[]]@([string]$row.withheld_original_record_id)
            } else { [string[]]$row.withheld_original_record_ids }
            $rowClasses = if ($level -eq 1) {
                [int[]]@([int]$row.original_saved_profile_class_index)
            } else { [int[]]$row.original_saved_profile_class_indices }
            if ($rowRecordIds.Count -ne $level -or $rowClasses.Count -ne $level) {
                throw 'Code Sequence resilience frontier lost original report identity arrays.'
            }
            for ($i = 0; $i -lt $positions.Count; $i++) {
                $p = [int]$positions[$i]
                if ($p -le $previous -or $p -gt $n -or
                    $rowRecordIds[$i] -cne $records[$p - 1] -or
                    $rowClasses[$i] -ne $classes[$p - 1]) {
                    throw 'Code Sequence resilience frontier changed a caller position/ID/profile class.'
                }
                $previous = $p
                $mask = $mask -bor (1 -shl ($p - 1))
            }
            $expectedOrdinal = Get-CodeSequenceResilienceLexicographicOrdinal `
                -OneBasedPositions $positions -N $n
            if ($expectedOrdinal -ne $ordinal) {
                throw 'Code Sequence resilience frontier original subset order changed.'
            }
            if ($level -gt 1) {
                $ordinalField = 'original_position_' + $names[$level - 1] + '_index'
                if (-not $row.Contains($ordinalField) -or
                    [int]$row[$ordinalField] -ne $ordinal) {
                    throw 'Code Sequence resilience frontier parent ordinal changed.'
                }
            }
            if ($seen[$mask]) { throw 'Code Sequence resilience frontier duplicated an original exclusion set.' }
            $seen[$mask] = $true
            $observedCount++

            if ([long]$row.surviving_original_independent_two_window_combinations -ne $singleCountG[$mask] -or
                [long]$row.surviving_original_joint_four_window_combinations -ne $pairCountG[$mask] -or
                [long]$row.surviving_original_joint_six_window_combinations -ne $tripleCountG[$mask] -or
                [long]$row.surviving_original_full_selection_local_optimum_individual_packings -ne $singleCountO[$mask] -or
                [long]$row.surviving_original_full_selection_joint_local_optimum_packing_pairs -ne $pairCountO[$mask] -or
                [long]$row.surviving_original_full_selection_joint_local_optimum_packing_triples -ne $tripleCountO[$mask] -or
                [int]$row.globally_maximum_simultaneously_independently_supported_distinct_family_count -ne $maxG[$mask] -or
                [int]$row.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count -ne $maxO[$mask] -or
                [bool]$row.reduces_original_global_maximum_independent_family_count -ne ($maxG[$mask] -lt $baselineG) -or
                [bool]$row.reduces_original_global_maximum_original_local_optimum_family_count -ne ($maxO[$mask] -lt $baselineO)) {
                throw 'Code Sequence resilience frontier found a parent row inconsistent with ORIGINAL weighted witness masks.'
            }
            $actualG = [int[]]$row.independently_supported_family_indices
            $actualO = [int[]]$row.original_local_optimum_family_indices
            Assert-CodeSequenceResilienceSavedIndices -Indices $actualG -Maximum $f
            Assert-CodeSequenceResilienceSavedIndices -Indices $actualO -Maximum $f
            $expectedG = [System.Collections.Generic.List[int]]::new()
            $expectedO = [System.Collections.Generic.List[int]]::new()
            for ($fi = 0; $fi -lt $f; $fi++) {
                if (([long[]]$singleFamilyG[$fi])[$mask] -gt 0) { $expectedG.Add($fi + 1) }
                if (([long[]]$singleFamilyO[$fi])[$mask] -gt 0) { $expectedO.Add($fi + 1) }
            }
            if (($expectedG.ToArray() -join ',') -cne ($actualG -join ',') -or
                ($expectedO.ToArray() -join ',') -cne ($actualO -join ',')) {
                throw 'Code Sequence resilience frontier found false independent per-family survival.'
            }
        }
    }
    if ($observedCount -ne $size -or ($seen -contains $false)) {
        throw 'Code Sequence resilience frontier did not cover the complete ORIGINAL 0..N exclusion cube.'
    }
    for ($k = 0; $k -le $n; $k++) {
        if ($sizeTotals[$k] -ne (Get-CodeSequenceDuodecetWithholdingChoose -N $n -K $k) -or
            $minsG[$k] -gt 3 -or $minsO[$k] -gt 3) {
            throw 'Code Sequence resilience frontier lost an original exclusion cardinality.'
        }
    }

    $globalG = [System.Collections.Generic.List[object]]::new()
    $globalO = [System.Collections.Generic.List[object]]::new()
    $firstLossG = [int[]]@()
    $firstLossO = [int[]]@()
    $totalExtinctionG = [int[]]@()
    $totalExtinctionO = [int[]]@()
    $globalFirstG = [int[]]::new($n + 1)
    $globalFirstO = [int[]]::new($n + 1)
    $familyFirstG = [int[]]::new($n + 1)
    $familyFirstO = [int[]]::new($n + 1)
    foreach ($orientation in @('genuine','frozen')) {
        if ($orientation -ceq 'genuine') { $vector = $maxG; $baseline = $baselineG; $sink = $globalG }
        else { $vector = $maxO; $baseline = $baselineO; $sink = $globalO }
        for ($threshold = $baseline; $threshold -ge 1; $threshold--) {
            $cuts = [int[]](Get-CodeSequenceResilienceMinimalCuts -SurvivingByExclusionMask $vector -Threshold $threshold)
            $cutSize = Get-CodeSequenceResilienceSmallestCutSize -Masks $cuts
            $sink.Add([ordered]@{
                original_global_maximum = $baseline
                residual_global_maximum_strictly_below = $threshold
                minimum_withheld_original_positions = $cutSize
                inclusion_minimal_cut_count = $cuts.Count
                inclusion_minimal_original_exclusion_masks = $cuts
            })
            if ($threshold -eq $baseline) {
                if ($orientation -ceq 'genuine') { $firstLossG = $cuts }
                else { $firstLossO = $cuts }
            }
            if ($threshold -eq 1) {
                if ($orientation -ceq 'genuine') { $totalExtinctionG = $cuts }
                else { $totalExtinctionO = $cuts }
            }
        }
    }
    foreach ($mask in $firstLossG) { $globalFirstG[$sizes[$mask]]++ }
    foreach ($mask in $firstLossO) { $globalFirstO[$sizes[$mask]]++ }
    $familyCuts = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $f; $fi++) {
        $vectorG = [long[]]$singleFamilyG[$fi]
        $vectorO = [long[]]$singleFamilyO[$fi]
        if ($vectorO[0] -gt $vectorG[0]) {
            throw 'Code Sequence resilience frontier fabricated a frozen optimum family.'
        }
        $cutsG = [int[]](Get-CodeSequenceResilienceMinimalCuts -SurvivingByExclusionMask $vectorG -Threshold 1)
        $cutsO = [int[]](Get-CodeSequenceResilienceMinimalCuts -SurvivingByExclusionMask $vectorO -Threshold 1)
        foreach ($mask in $cutsG) { $familyFirstG[$sizes[$mask]]++ }
        foreach ($mask in $cutsO) { $familyFirstO[$sizes[$mask]]++ }
        $familyCuts.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            originally_independent_two_window_combination_count = $vectorG[0]
            original_full_selection_frozen_optimum_packing_count = $vectorO[0]
            genuine_minimum_original_positions_to_extinguish_family = (Get-CodeSequenceResilienceSmallestCutSize -Masks $cutsG)
            genuine_inclusion_minimal_extinction_cut_count = $cutsG.Count
            genuine_inclusion_minimal_extinction_original_exclusion_masks = $cutsG
            frozen_minimum_original_positions_to_extinguish_family = (Get-CodeSequenceResilienceSmallestCutSize -Masks $cutsO)
            frozen_inclusion_minimal_extinction_cut_count = $cutsO.Count
            frozen_inclusion_minimal_extinction_original_exclusion_masks = $cutsO
        })
    }
    $legend = [System.Collections.Generic.List[object]]::new()
    for ($p = 0; $p -lt $n; $p++) {
        $legend.Add([ordered]@{
            original_caller_position = $p + 1
            original_saved_record_id = $records[$p]
            original_saved_profile_class_index = $classes[$p]
            exclusion_mask_bit = 1 -shl $p
        })
    }
    $bySize = [System.Collections.Generic.List[object]]::new()
    for ($k = 0; $k -le $n; $k++) {
        $bySize.Add([ordered]@{
            withheld_original_position_count = $k
            original_exclusion_subset_count = $sizeTotals[$k]
            minimum_independent_distinct_family_maximum = $minsG[$k]
            maximum_independent_distinct_family_maximum = $maxsG[$k]
            minimum_frozen_distinct_family_maximum = $minsO[$k]
            maximum_frozen_distinct_family_maximum = $maxsO[$k]
            subsets_reducing_original_independent_maximum = $reducedG[$k]
            subsets_reducing_original_frozen_maximum = $reducedO[$k]
            subsets_eliminating_all_independent_support = $extinguishedG[$k]
            subsets_eliminating_all_frozen_support = $extinguishedO[$k]
            inclusion_minimal_global_first_loss_cuts_genuine = $globalFirstG[$k]
            inclusion_minimal_global_first_loss_cuts_frozen = $globalFirstO[$k]
            summed_inclusion_minimal_individual_family_extinctions_genuine = $familyFirstG[$k]
            summed_inclusion_minimal_individual_family_extinctions_frozen = $familyFirstO[$k]
        })
    }
    return [ordered]@{
        scope = 'complete_original_report_withholding_resilience_frontiers_exact_saved_witness_masks_no_resequencing'
        pair_index_in_pairwise_profile = [int]$Layers[0].pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Layers[0].path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Layers[0].anchor_index_in_anchor_journeys
        path = [string]$Layers[0].path
        counts = [ordered]@{
            selected_original_report_positions = $n
            original_maximal_repeat_family_count = $f
            original_exclusion_sets_including_empty = $size
            nonempty_original_exclusion_sets = $size - 1
            original_global_independent_maximum = $baselineG
            original_global_frozen_maximum = $baselineO
            genuine_inclusion_minimal_global_first_loss_cut_count = $firstLossG.Count
            frozen_inclusion_minimal_global_first_loss_cut_count = $firstLossO.Count
            genuine_inclusion_minimal_complete_support_extinction_cut_count = $totalExtinctionG.Count
            frozen_inclusion_minimal_complete_support_extinction_cut_count = $totalExtinctionO.Count
            genuine_minimum_positions_for_first_global_loss = (Get-CodeSequenceResilienceSmallestCutSize -Masks $firstLossG)
            frozen_minimum_positions_for_first_global_loss = (Get-CodeSequenceResilienceSmallestCutSize -Masks $firstLossO)
            genuine_minimum_positions_for_total_support_extinction = (Get-CodeSequenceResilienceSmallestCutSize -Masks $totalExtinctionG)
            frozen_minimum_positions_for_total_support_extinction = (Get-CodeSequenceResilienceSmallestCutSize -Masks $totalExtinctionO)
        }
        original_caller_position_bit_legend = $legend.ToArray()
        genuine_global_loss_threshold_frontiers = $globalG.ToArray()
        frozen_global_loss_threshold_frontiers = $globalO.ToArray()
        original_family_extinction_frontiers = $familyCuts.ToArray()
        original_exclusion_cardinality_summary = $bySize.ToArray()
        all_ec059_to_ec070_original_exclusion_rows_reconciled = $true
        all_six_genuine_and_frozen_original_survivor_levels_reconstructed_from_private_weighted_masks = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        original_full_selection_local_optima_frozen_not_reoptimized = $true
        no_original_window_resequencing_or_new_adjacency = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_defect_recency_causation_fix_or_regression_proven = $false
    }
}

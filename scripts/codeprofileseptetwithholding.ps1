#requires -Version 7.0
<#
    EC-065: SEVEN simultaneous exclusions of ORIGINAL caller report positions.
    Work only from the EC-060 reconciled PRIVATE union-mask witness histograms,
    with EC-056 original full-selection optimum packs kept frozen. The selected
    record order is NOT a chronology; never stitch removed-position neighbors,
    authenticate identity of a defect, or mutate any repository or saved record.
#>

function Get-CodeSequenceSeptetWithholdingChoose {
    param([int] $N, [int] $K)
    if ($N -lt 0 -or $K -lt 0 -or $K -gt $N) { return 0 }
    $result = [long]1
    for ($i = 1; $i -le $K; $i++) {
        $result = [long](($result * ($N - $i + 1)) / $i)
    }
    return [int]$result
}

function Get-CodeSequenceSeptetWithholdingMask {
    param([int[]] $Positions, [int] $N)
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $Positions -or
        $Positions.Count -lt 4 -or $Positions.Count -gt 7) {
        throw 'Code Sequence seventh-order position masks require four through seven ORIGINAL positions.'
    }
    $mask = 0
    $last = -1
    foreach ($position in $Positions) {
        if ($position -le $last -or $position -lt 0 -or $position -ge $N) {
            throw 'Code Sequence seventh-order masks require strictly ascending original caller positions.'
        }
        $mask = $mask -bor (1 -shl $position)
        $last = $position
    }
    return [int]$mask
}

function Get-CodeSequenceSeptetWithholdingRemainingCount {
    param([object] $Aggregate, [int] $N, [int[]] $Positions)
    if ($Positions.Count -ne 7) {
        throw 'Code Sequence seventh-order evidence projection requires seven ORIGINAL positions.'
    }
    $excludedMask = Get-CodeSequenceSeptetWithholdingMask -Positions $Positions -N $N
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $singles = [long[]]$Aggregate.original_position_inclusion_counts
    $pairs = [long[]]$Aggregate.original_pair_intersection_counts
    $total = [long]$Aggregate.original_combination_count
    if ($masks.Count -ne $weights.Count -or $singles.Count -ne $N -or
        $pairs.Count -ne ($N * $N) -or $total -lt 0) {
        throw 'Code Sequence seventh-order withholding lacks conserved original EC-060 evidence.'
    }
    # Reconstruct every REAL nonempty subset intersection of the seven
    # excluded original positions; no higher-order terms are approximated.
    $intersections = [long[]]::new(128)
    $direct = [long]0
    $conserved = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = [int]$masks[$i]
        $multiplicity = [long]$weights[$i]
        if ($mask -le 0 -or $mask -ge (1 -shl $N) -or $multiplicity -le 0) {
            throw 'Code Sequence seventh-order withholding found a non-original/invalid witness mask.'
        }
        $conserved += $multiplicity
        if (($mask -band $excludedMask) -eq 0) { $direct += $multiplicity }
        $covered = 0
        for ($j = 0; $j -lt 7; $j++) {
            if (($mask -band (1 -shl $Positions[$j])) -ne 0) {
                $covered = $covered -bor (1 -shl $j)
            }
        }
        $subset = $covered
        while ($subset -gt 0) {
            $intersections[$subset] += $multiplicity
            $subset = ($subset - 1) -band $covered
        }
    }
    if ($conserved -ne $total) {
        throw 'Code Sequence seventh-order withholding altered original witness multiplicity.'
    }
    # T - 7 I1 + 21 I2 - 35 I3 + 35 I4 - 21 I5 + 7 I6 - I7.
    # Reconcile every original first/second margin to EC-060 and independently
    # count masks that survive all seven exclusions.
    $byInclusionExclusion = $total
    for ($subset = 1; $subset -lt 128; $subset++) {
        $size = 0
        $first = -1; $second = -1
        for ($j = 0; $j -lt 7; $j++) {
            if (($subset -band (1 -shl $j)) -ne 0) {
                if ($size -eq 0) { $first = $Positions[$j] }
                elseif ($size -eq 1) { $second = $Positions[$j] }
                $size++
            }
        }
        $value = [long]$intersections[$subset]
        if ($size -eq 1) {
            if ($value -ne [long]$singles[$first]) {
                throw 'Code Sequence seventh-order evidence disagrees with an original position marginal.'
            }
            $value = [long]$singles[$first]
        } elseif ($size -eq 2) {
            if ($value -ne [long]$pairs[($first * $N) + $second]) {
                throw 'Code Sequence seventh-order evidence disagrees with an original pair intersection.'
            }
            $value = [long]$pairs[($first * $N) + $second]
        }
        if (($size % 2) -eq 1) { $byInclusionExclusion -= $value }
        else { $byInclusionExclusion += $value }
    }
    if ($direct -ne $byInclusionExclusion -or $direct -lt 0 -or $direct -gt $total) {
        throw 'Code Sequence seventh-order exact original-mask inclusion/exclusion failed.'
    }
    return [long]$direct
}

function Get-CodeSequenceSeptetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int[]] $Positions)
    $genuineTotal = [long]0
    $frozenTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $frozenIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $frozenSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceSeptetWithholdingRemainingCount -Aggregate $row.genuine -N $N -Positions $Positions
        $o = Get-CodeSequenceSeptetWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -Positions $Positions
        $genuineTotal += $g
        $frozenTotal += $o
        if ($g -gt 0) {
            $genuineIndices.Add([int]$row.registry_index)
            $genuineSets.Add([int[]]$row.family_indices)
        }
        if ($o -gt 0) {
            $frozenIndices.Add([int]$row.registry_index)
            $frozenSets.Add([int[]]$row.family_indices)
        }
    }
    return [ordered]@{
        genuine_total = $genuineTotal
        original_local_optimum_total = $frozenTotal
        genuine_registry_indices = $genuineIndices.ToArray()
        original_local_optimum_registry_indices = $frozenIndices.ToArray()
        genuine_family_sets = $genuineSets.ToArray()
        original_local_optimum_family_sets = $frozenSets.ToArray()
    }
}

function Assert-CodeSequenceSeptetWithholdingParent {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $WitnessAggregates)
    # Replay ALL EC-064 fields from EC-060 original masks and the complete
    # EC-063 parent. This transitively verifies EC-062, EC-061 and EC-060.
    $replayed = Get-CodeSequenceOriginalFindingPairProfileSextetPositionWithholding `
        -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -WitnessAggregates $WitnessAggregates
    $expected = ConvertTo-Json -InputObject $replayed -Depth 80 -Compress
    $actual = ConvertTo-Json -InputObject $SextetWithholding -Depth 80 -Compress
    if ($expected -cne $actual) {
        throw 'Code Sequence seventh-order view differs from the COMPLETE original EC-064 sextet output.'
    }
}

function Get-CodeSequenceSeptetWithholdingSeventhOnlyFamilyIndices {
    param([object[]] $Parents, [int[]] $SextetOrdinals,
        [int[]] $SurvivingFamilyIndices, [int] $FamilyCount, [bool] $OriginalLocalOptima)
    if ($SextetOrdinals.Count -ne 7) {
        throw 'Code Sequence seventh-order original-family loss requires all seven sextet parents.'
    }
    $commonFamilies = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt 7; $i++) {
        $ordinal = [int]$SextetOrdinals[$i]
        if ($ordinal -lt 1 -or $ordinal -gt $Parents.Count -or
            [int]$Parents[$ordinal - 1].original_position_sextet_index -ne $ordinal) {
            throw 'Code Sequence seventh-order loss lost a genuine original sextet ancestor.'
        }
        $parent = $Parents[$ordinal - 1]
        $candidateIndices = if ($OriginalLocalOptima) {
            [int[]]$parent.original_local_optimum_family_indices
        } else { [int[]]$parent.independently_supported_family_indices }
        $set = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($candidate in $candidateIndices) {
            if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $set.Add($candidate)) {
                throw 'Code Sequence seventh-order family loss found an invalid original ancestor registry.'
            }
        }
        if ($i -eq 0) { $commonFamilies.UnionWith($set) }
        else { $commonFamilies.IntersectWith($set) }
    }
    foreach ($candidate in $SurvivingFamilyIndices) { [void]$commonFamilies.Remove($candidate) }
    $answer = [int[]]@($commonFamilies | Sort-Object)
    return ,$answer
}

function Assert-CodeSequenceSeptetWithholdingFamilySubset {
    param([int[]] $Children, [int[]] $Parents, [int] $FamilyCount)
    $allowed = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($candidate in $Parents) {
        if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $allowed.Add($candidate)) {
            throw 'Code Sequence seventh-order family subset found an invalid original sextet registry.'
        }
    }
    foreach ($candidate in $Children) {
        if (-not $allowed.Contains($candidate)) {
            throw 'Code Sequence seventh-order family witness was fabricated across removed positions.'
        }
    }
}

function Get-CodeSequenceSeptetWithholdingAncestorRegistry {
    param([object[]] $Rows, [int] $N, [int] $K, [string] $OrdinalName)
    $result = [System.Collections.Generic.Dictionary[int,int]]::new()
    if ($Rows.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $N -K $K)) {
        throw 'Code Sequence seventh-order ancestry does not cover every original parent position set.'
    }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        if ([int]$row.$OrdinalName -ne ($i + 1)) {
            throw 'Code Sequence seventh-order ancestor index is not in canonical original order.'
        }
        $positions = [int[]]@($row.withheld_original_caller_positions | ForEach-Object { [int]$_ - 1 })
        if ($positions.Count -ne $K) {
            throw 'Code Sequence seventh-order ancestor lost its original position cardinality.'
        }
        $mask = Get-CodeSequenceSeptetWithholdingMask -Positions $positions -N $N
        if ($result.ContainsKey($mask)) {
            throw 'Code Sequence seventh-order ancestor registry has duplicate original position sets.'
        }
        $result.Add($mask, $i + 1)
    }
    return ,$result
}

function Get-CodeSequenceOriginalFindingPairProfileSeptetPositionWithholding {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $WitnessAggregates)
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $TripleWithholding -or
        $null -eq $QuartetWithholding -or $null -eq $QuintetWithholding -or
        $null -eq $SextetWithholding -or $null -eq $WitnessAggregates -or
        $SextetWithholding.scope -cne 'unordered_six_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$SextetWithholding.complete_original_ec063_quintet_projections_and_private_witness_masks_reconciled -or
        -not [bool]$SextetWithholding.independent_of_sequence_top -or
        -not [bool]$SextetWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence seventh-order view requires fully reconciled original EC-064 sextets.'
    }
    $n = [int]$SextetWithholding.counts.selected_report_positions
    $familyCount = [int]$SextetWithholding.counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $parentPairs = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $parentTriples = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $parentQuartets = [object[]]$QuartetWithholding.ordered_original_position_quartet_withholding
    $parentQuintets = [object[]]$QuintetWithholding.ordered_original_position_quintet_withholding
    $parentSextets = [object[]]$SextetWithholding.ordered_original_position_sextet_withholding
    $baseG = [int]$SextetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$SextetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $familyCount -lt 0 -or $familyCount -gt 66 -or
        $records.Count -ne $n -or $classes.Count -ne $n -or $singles.Count -ne $familyCount -or
        $pairs.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $familyCount -K 2) -or
        $triples.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $familyCount -K 3) -or
        $parentPairs.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 2) -or
        $parentTriples.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 3) -or
        $parentQuartets.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 4) -or
        $parentQuintets.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 5) -or
        $parentSextets.Count -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 6) -or
        $baseG -lt 0 -or $baseG -gt 3 -or $baseO -lt 0 -or $baseO -gt $baseG) {
        throw 'Code Sequence seventh-order ancestry or original witness counts are inconsistent.'
    }
    Assert-CodeSequenceSeptetWithholdingParent -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -SextetWithholding $SextetWithholding `
        -WitnessAggregates $WitnessAggregates
    $activeSingles = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $singles
    # Four mutually nonoverlapping original windows across two different
    # families need at least EIGHT positions; three families need TWELVE.
    # Seven exclusions from N<=12 leave at most five original positions.
    # Validate original footprints before relying on the impossibility bound.
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $pairs -MinimumOriginalPositions 8
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $triples -MinimumOriginalPositions 12
    $emptyJoint = Get-CodeSequenceQuintetWithholdingEmptyJointLayer
    $quartetIndex = Get-CodeSequenceSeptetWithholdingAncestorRegistry -Rows $parentQuartets `
        -N $n -K 4 -OrdinalName 'original_position_quartet_index'
    $quintetIndex = Get-CodeSequenceSeptetWithholdingAncestorRegistry -Rows $parentQuintets `
        -N $n -K 5 -OrdinalName 'original_position_quintet_index'
    $sextetIndex = Get-CodeSequenceSeptetWithholdingAncestorRegistry -Rows $parentSextets `
        -N $n -K 6 -OrdinalName 'original_position_sextet_index'

    $rows = [System.Collections.Generic.List[object]]::new()
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
    $positionLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $n
    $pairLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentPairs.Count
    $tripleLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentTriples.Count
    $quartetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentQuartets.Count
    $quintetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentQuintets.Count
    $sextetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentSextets.Count
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 7) { $minG = $baseG; $minO = $baseO; $maxG = 0; $maxO = 0 }
    $ordinal = 0
    for ($a = 0; $a -lt $n; $a++) {
      for ($b = $a + 1; $b -lt $n; $b++) {
       for ($c = $b + 1; $c -lt $n; $c++) {
        for ($d = $c + 1; $d -lt $n; $d++) {
         for ($e = $d + 1; $e -lt $n; $e++) {
          for ($f = $e + 1; $f -lt $n; $f++) {
           for ($h = $f + 1; $h -lt $n; $h++) {
            $ordinal++
            $positions = [int[]]@($a,$b,$c,$d,$e,$f,$h)
            $pairOrdinalList = [System.Collections.Generic.List[int]]::new()
            $tripleOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quartetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quintetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $sextetOrdinalList = [System.Collections.Generic.List[int]]::new()
            # Recover all GENUINE original parent ordinals. Removing positions
            # does not reindex a report or create any new observed motif step.
            for ($subset = 1; $subset -lt 128; $subset++) {
                $selected = [System.Collections.Generic.List[int]]::new()
                for ($bit = 0; $bit -lt 7; $bit++) {
                    if (($subset -band (1 -shl $bit)) -ne 0) {
                        $selected.Add([int]$positions[$bit])
                    }
                }
                $k = $selected.Count
                if ($k -eq 2) {
                    $pairOrdinalList.Add((Get-CodeSequenceTripleWithholdingPairOrdinal `
                        -N $n -P $selected[0] -Q $selected[1]))
                } elseif ($k -eq 3) {
                    $tripleOrdinalList.Add((Get-CodeSequenceQuartetWithholdingTripleOrdinal `
                        -N $n -P $selected[0] -Q $selected[1] -R $selected[2]))
                } elseif ($k -ge 4 -and $k -le 6) {
                    $mask = Get-CodeSequenceSeptetWithholdingMask -Positions ($selected.ToArray()) -N $n
                    $registry = if ($k -eq 4) { $quartetIndex }
                        elseif ($k -eq 5) { $quintetIndex }
                        else { $sextetIndex }
                    if (-not $registry.ContainsKey($mask)) {
                        throw 'Code Sequence seventh-order lost an ORIGINAL constituent position registry.'
                    }
                    if ($k -eq 4) { $quartetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 5) { $quintetOrdinalList.Add($registry[$mask]) }
                    else { $sextetOrdinalList.Add($registry[$mask]) }
                }
            }
            $pairIndices = [int[]]@($pairOrdinalList.ToArray() | Sort-Object)
            $tripleIndices = [int[]]@($tripleOrdinalList.ToArray() | Sort-Object)
            $quartetIndices = [int[]]@($quartetOrdinalList.ToArray() | Sort-Object)
            $quintetIndices = [int[]]@($quintetOrdinalList.ToArray() | Sort-Object)
            $sextetIndices = [int[]]@($sextetOrdinalList.ToArray() | Sort-Object)
            if ($pairIndices.Count -ne 21 -or $tripleIndices.Count -ne 35 -or
                $quartetIndices.Count -ne 35 -or $quintetIndices.Count -ne 21 -or
                $sextetIndices.Count -ne 7 -or
                @($pairIndices | Select-Object -Unique).Count -ne 21 -or
                @($tripleIndices | Select-Object -Unique).Count -ne 35 -or
                @($quartetIndices | Select-Object -Unique).Count -ne 35 -or
                @($quintetIndices | Select-Object -Unique).Count -ne 21 -or
                @($sextetIndices | Select-Object -Unique).Count -ne 7) {
                throw 'Code Sequence seventh-order has lost one of its 21/35/35/21/7 original ancestors.'
            }
            $one = Get-CodeSequenceSeptetWithholdingLayer -Rows $activeSingles -N $n -Positions $positions
            $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $false
            $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $true
            $g = [int]$gMax.distinct_family_count
            $o = [int]$oMax.distinct_family_count
            $parentMinG = $baseG; $parentMinO = $baseO
            foreach ($si in $sextetIndices) {
                $parent = $parentSextets[$si - 1]
                if ([int]$parent.original_position_sextet_index -ne $si) {
                    throw 'Code Sequence seventh-order changed an original sextet parent ordinal.'
                }
                $parentMinG = [math]::Min($parentMinG,
                    [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                $parentMinO = [math]::Min($parentMinO,
                    [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                if ([long]$one.genuine_total -gt [long]$parent.surviving_original_independent_two_window_combinations -or
                    [long]$one.original_local_optimum_total -gt [long]$parent.surviving_original_full_selection_local_optimum_individual_packings) {
                    throw 'Code Sequence seventh-order fabricated more witnesses than an original sextet parent.'
                }
                Assert-CodeSequenceSeptetWithholdingFamilySubset `
                    -Children $one.genuine_registry_indices -Parents $parent.independently_supported_family_indices `
                    -FamilyCount $familyCount
                Assert-CodeSequenceSeptetWithholdingFamilySubset `
                    -Children $one.original_local_optimum_registry_indices -Parents $parent.original_local_optimum_family_indices `
                    -FamilyCount $familyCount
            }
            if ($g -gt [math]::Floor(($n - 7) / 4) -or $g -gt $parentMinG -or
                $o -gt $parentMinO -or $o -gt $g -or $g -gt $baseG -or $o -gt $baseO) {
                throw 'Code Sequence seventh-order broke original-window capacity/monotonicity.'
            }
            $seventhOnlyG = Get-CodeSequenceSeptetWithholdingSeventhOnlyFamilyIndices `
                -Parents $parentSextets -SextetOrdinals $sextetIndices `
                -SurvivingFamilyIndices $one.genuine_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $false
            $seventhOnlyO = Get-CodeSequenceSeptetWithholdingSeventhOnlyFamilyIndices `
                -Parents $parentSextets -SextetOrdinals $sextetIndices `
                -SurvivingFamilyIndices $one.original_local_optimum_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $true
            if ($seventhOnlyG.Count -gt 0) { $familyOnlyG.Add($ordinal) }
            if ($seventhOnlyO.Count -gt 0) { $familyOnlyO.Add($ordinal) }
            $familyOnlyGEvents += $seventhOnlyG.Count
            $familyOnlyOEvents += $seventhOnlyO.Count
            $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
            $minimalSeventhG = $reducedG -and $parentMinG -eq $baseG
            $minimalSeventhO = $reducedO -and $parentMinO -eq $baseO
            $additionalG = [int]$parentMinG - $g
            $additionalO = [int]$parentMinO - $o
            if ($additionalG -lt 0 -or $additionalO -lt 0) {
                throw 'Code Sequence seventh-order increased capacity by withholding another original report.'
            }
            if ($reducedG) { $criticalG.Add($ordinal) }
            if ($reducedO) { $criticalO.Add($ordinal) }
            if ($minimalSeventhG) { $minimalG.Add($ordinal) }
            if ($minimalSeventhO) { $minimalO.Add($ordinal) }
            if ($additionalG -gt 0) { $extraG.Add($ordinal) }
            if ($additionalO -gt 0) { $extraO.Add($ordinal) }
            $flags = @{
                ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                MinimalG = [bool]$minimalSeventhG; MinimalO = [bool]$minimalSeventhO
                ExtraG = [bool]($additionalG -gt 0); ExtraO = [bool]($additionalO -gt 0)
            }
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $positionLedger -Indices $positions @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedger -Indices $pairIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedger -Indices $tripleIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quartetLedger -Indices $quartetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quintetLedger -Indices $quintetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $sextetLedger -Indices $sextetIndices -OneBased @flags
            $minG = [math]::Min($minG, $g); $maxG = [math]::Max($maxG, $g)
            $minO = [math]::Min($minO, $o); $maxO = [math]::Max($maxO, $o)
            $originalOneBased = [System.Collections.Generic.List[int]]::new()
            $recordIds = [System.Collections.Generic.List[string]]::new()
            $profileClasses = [System.Collections.Generic.List[int]]::new()
            foreach ($pos in $positions) {
                $originalOneBased.Add([int]($pos + 1))
                $recordIds.Add($records[$pos])
                $profileClasses.Add($classes[$pos])
            }
            $rows.Add([ordered]@{
                original_position_septet_index = $ordinal
                withheld_original_caller_positions = $originalOneBased.ToArray()
                withheld_original_record_ids = $recordIds.ToArray()
                original_saved_profile_class_indices = $profileClasses.ToArray()
                original_constituent_position_pair_indices = $pairIndices
                original_constituent_position_triple_indices = $tripleIndices
                original_constituent_position_quartet_indices = $quartetIndices
                original_constituent_position_quintet_indices = $quintetIndices
                original_constituent_position_sextet_indices = $sextetIndices
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
                genuinely_seventh_order_only_lost_original_family_indices = $seventhOnlyG
                frozen_original_optimum_seventh_order_only_lost_original_family_indices = $seventhOnlyO
                jointly_compatible_original_local_optimum_family_pair_indices = [int[]]@()
                jointly_compatible_original_local_optimum_family_triple_indices = [int[]]@()
                globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                minimally_seventh_order_critical_for_original_independent_maximum = [bool]$minimalSeventhG
                minimally_seventh_order_critical_for_original_local_optimum_maximum = [bool]$minimalSeventhO
                strongest_constituent_sextet_independent_family_maximum = $parentMinG
                strongest_constituent_sextet_original_local_optimum_family_maximum = $parentMinO
                additional_independent_family_loss_beyond_stronger_sextet_exclusion = $additionalG
                additional_original_local_optimum_family_loss_beyond_stronger_sextet_exclusion = $additionalO
            })
           }
          }
         }
        }
       }
      }
    }
    if ($ordinal -ne (Get-CodeSequenceSeptetWithholdingChoose -N $n -K 7)) {
        throw 'Code Sequence seventh-order did not enumerate all canonical original seven-position combinations.'
    }

    $perPosition = [System.Collections.Generic.List[object]]::new()
    $perPair = [System.Collections.Generic.List[object]]::new()
    $perTriple = [System.Collections.Generic.List[object]]::new()
    $perQuartet = [System.Collections.Generic.List[object]]::new()
    $perQuintet = [System.Collections.Generic.List[object]]::new()
    $perSextet = [System.Collections.Generic.List[object]]::new()
    $participation = @(
        @($positionLedger,$perPosition,'position',$n,1),
        @($pairLedger,$perPair,'pair',$parentPairs.Count,2),
        @($tripleLedger,$perTriple,'triple',$parentTriples.Count,3),
        @($quartetLedger,$perQuartet,'quartet',$parentQuartets.Count,4),
        @($quintetLedger,$perQuintet,'quintet',$parentQuintets.Count,5),
        @($sextetLedger,$perSextet,'sextet',$parentSextets.Count,6)
    )
    foreach ($element in $participation) {
        $ledger = $element[0]; $output = $element[1]
        $name = [string]$element[2]; $count = [int]$element[3]; $level = [int]$element[4]
        for ($i = 0; $i -lt $count; $i++) {
            $originalPositions = if ($level -eq 1) { [int[]]@($i + 1) }
                elseif ($level -eq 2) { [int[]]$parentPairs[$i].withheld_original_caller_positions }
                elseif ($level -eq 3) { [int[]]$parentTriples[$i].withheld_original_caller_positions }
                elseif ($level -eq 4) { [int[]]$parentQuartets[$i].withheld_original_caller_positions }
                elseif ($level -eq 5) { [int[]]$parentQuintets[$i].withheld_original_caller_positions }
                else { [int[]]$parentSextets[$i].withheld_original_caller_positions }
            $row = [ordered]@{
                original_constituent_type = $name
                original_constituent_index = $i + 1
                original_caller_positions = $originalPositions
                number_of_position_septets_containing_constituent = (Get-CodeSequenceSeptetWithholdingChoose -N ($n - $level) -K (7 - $level))
                septets_reducing_original_independent_maximum = $ledger.criticalG[$i]
                septets_reducing_original_local_optimum_maximum = $ledger.criticalO[$i]
                minimally_seventh_order_critical_septets_for_original_independent_maximum = $ledger.minimalG[$i]
                minimally_seventh_order_critical_septets_for_original_local_optimum_maximum = $ledger.minimalO[$i]
                septets_with_additional_independent_loss_beyond_stronger_sextet = $ledger.extraG[$i]
                septets_with_additional_original_local_optimum_loss_beyond_stronger_sextet = $ledger.extraO[$i]
            }
            if ($level -eq 1) {
                $row['original_record_id'] = $records[$i]
                $row['original_saved_profile_class_index'] = $classes[$i]
            }
            $output.Add($row)
        }
    }
    foreach ($category in @('criticalG','criticalO','minimalG','minimalO','extraG','extraO')) {
        $matching = switch ($category) {
            'criticalG' { $criticalG.Count }; 'criticalO' { $criticalO.Count }
            'minimalG' { $minimalG.Count }; 'minimalO' { $minimalO.Count }
            'extraG' { $extraG.Count }; 'extraO' { $extraO.Count }
        }
        $ledgers = @($positionLedger,$pairLedger,$tripleLedger,$quartetLedger,$quintetLedger,$sextetLedger)
        $expectedMemberships = [long[]]@(7,21,35,35,21,7)
        for ($level = 0; $level -lt $ledgers.Count; $level++) {
            $observed = [long]0
            foreach ($value in $ledgers[$level][$category]) { $observed += [long]$value }
            if ($observed -ne ([long]$matching * $expectedMemberships[$level])) {
                throw 'Code Sequence seventh-order broke exact 7/21/35/35/21/7 original participation conservation.'
            }
        }
    }
    return [ordered]@{
        scope = 'unordered_seven_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$SextetWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$SextetWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$SextetWithholding.anchor_index_in_anchor_journeys
        path = [string]$SextetWithholding.path
        exact_saved_quote_anchor = $SextetWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            unordered_original_position_septet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baseG
            original_global_maximum_original_locally_optimal_distinct_family_count = $baseO
            number_of_septets_reducing_original_independent_maximum = $criticalG.Count
            number_of_septets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_seventh_order_critical_septets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_seventh_order_critical_septets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_septets_with_additional_independent_loss_beyond_stronger_sextet = $extraG.Count
            number_of_septets_with_additional_original_local_optimum_loss_beyond_stronger_sextet = $extraO.Count
            number_of_septets_with_genuinely_seventh_order_only_original_family_loss = $familyOnlyG.Count
            number_of_septets_with_frozen_original_optimum_seventh_order_only_family_loss = $familyOnlyO.Count
            genuine_seventh_order_only_original_family_loss_events = $familyOnlyGEvents
            frozen_original_optimum_seventh_order_only_family_loss_events = $familyOnlyOEvents
            minimum_global_independent_family_maximum_after_seven_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_seven_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_seven_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_seven_withheld_positions = $maxO
        }
        original_position_septet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_septet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_seventh_order_critical_septet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_seventh_order_critical_septet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        septet_indices_causing_additional_independent_loss_vs_stronger_sextet = $extraG.ToArray()
        septet_indices_causing_additional_original_local_optimum_loss_vs_stronger_sextet = $extraO.ToArray()
        septet_indices_with_genuinely_seventh_order_only_original_family_loss = $familyOnlyG.ToArray()
        septet_indices_with_frozen_original_optimum_seventh_order_only_family_loss = $familyOnlyO.ToArray()
        ordered_original_position_septet_withholding = $rows.ToArray()
        ordered_original_position_septet_participation = $perPosition.ToArray()
        ordered_original_pair_septet_participation = $perPair.ToArray()
        ordered_original_triple_septet_participation = $perTriple.ToArray()
        ordered_original_quartet_septet_participation = $perQuartet.ToArray()
        ordered_original_quintet_septet_participation = $perQuintet.ToArray()
        ordered_original_sextet_septet_participation = $perSextet.ToArray()
        complete_original_ec064_sextet_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        no_original_window_resequencing_or_new_adjacency = $true
        original_full_selection_local_optima_frozen_not_reoptimized = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_finding_historical_order_defect_recurrence_fix_regression_or_causality_proven = $false
    }
}

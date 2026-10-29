#requires -Version 7.0
<#
    EC-064: SIX simultaneous exclusions of ORIGINAL selected report positions.
    All evidence is the EC-060 checked private multiplicity-weighted original
    window-union masks, including frozen EC-056 full-selection local optima.
    Never splice withheld positions into new observations or infer chronology,
    verified identical defects, repairs or causality from model histograms.
#>

function Get-CodeSequenceSextetWithholdingChoose {
    param([int] $N, [int] $K)
    if ($N -lt 0 -or $K -lt 0 -or $K -gt $N) { return 0 }
    $answer = [long]1
    for ($i = 1; $i -le $K; $i++) {
        $answer = [long](($answer * ($N - $i + 1)) / $i)
    }
    return [int]$answer
}

function Get-CodeSequenceSextetWithholdingMask {
    param([int[]] $Positions, [int] $N)
    if ($N -lt 2 -or $N -gt 12 -or $Positions.Count -lt 4 -or $Positions.Count -gt 6) {
        throw 'Code Sequence sixth-order withholding requires four, five or six original positions.'
    }
    $mask = 0
    $last = -1
    foreach ($position in $Positions) {
        if ($position -le $last -or $position -lt 0 -or $position -ge $N) {
            throw 'Code Sequence sixth-order withholding requires strictly ascending ORIGINAL positions.'
        }
        $mask = $mask -bor (1 -shl $position)
        $last = $position
    }
    return [int]$mask
}

function Get-CodeSequenceSextetWithholdingRemainingCount {
    param([object] $Aggregate, [int] $N, [int[]] $Positions)
    if ($Positions.Count -ne 6) {
        throw 'Code Sequence sixth-order inclusion/exclusion requires six original positions.'
    }
    $excluded = Get-CodeSequenceSextetWithholdingMask -Positions $Positions -N $N
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $included = [long[]]$Aggregate.original_position_inclusion_counts
    $pairIntersections = [long[]]$Aggregate.original_pair_intersection_counts
    $original = [long]$Aggregate.original_combination_count
    if ($masks.Count -ne $weights.Count -or $included.Count -ne $N -or
        $pairIntersections.Count -ne ($N * $N) -or $original -lt 0) {
        throw 'Code Sequence sixth-order withholding lost the original EC-060 private witness ledger.'
    }
    # Record the REAL intersections for every nonempty subset of the six
    # positions. Distinct witness combinations sharing a union mask retain
    # their original multiplicities; the excluded reports are never reindexed.
    $intersections = [long[]]::new(64)
    $directSurvivors = [long]0
    $conservedTotal = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $witness = [int]$masks[$i]
        $weight = [long]$weights[$i]
        if ($weight -le 0 -or $witness -le 0 -or $witness -ge (1 -shl $N)) {
            throw 'Code Sequence sixth-order withholding found an invalid original union mask/multiplicity.'
        }
        $conservedTotal += $weight
        if (($witness -band $excluded) -eq 0) { $directSurvivors += $weight }
        $present = 0
        for ($j = 0; $j -lt 6; $j++) {
            if (($witness -band (1 -shl $Positions[$j])) -ne 0) {
                $present = $present -bor (1 -shl $j)
            }
        }
        $subset = $present
        while ($subset -gt 0) {
            $intersections[$subset] += $weight
            $subset = ($subset - 1) -band $present
        }
    }
    if ($conservedTotal -ne $original) {
        throw 'Code Sequence sixth-order withholding changed original full-selection witness multiplicity.'
    }
    # Independent sixth-order calculation: T - 6*I1 + 15*I2 - 20*I3
    # + 15*I4 - 6*I5 + I6 (actual intersections, never estimated from pairs).
    # The EC-060 original single/pair margins are checked against the freshly
    # enumerated intersections before using their separately conserved values.
    $byExclusion = $original
    for ($subset = 1; $subset -lt 64; $subset++) {
        $size = 0
        $first = -1; $second = -1
        for ($j = 0; $j -lt 6; $j++) {
            if (($subset -band (1 -shl $j)) -ne 0) {
                if ($size -eq 0) { $first = $Positions[$j] }
                elseif ($size -eq 1) { $second = $Positions[$j] }
                $size++
            }
        }
        $count = [long]$intersections[$subset]
        if ($size -eq 1) {
            if ($count -ne [long]$included[$first]) {
                throw 'Code Sequence sixth-order withholding disagrees with an original first-order marginal.'
            }
            $count = [long]$included[$first]
        } elseif ($size -eq 2) {
            if ($count -ne [long]$pairIntersections[($first * $N) + $second]) {
                throw 'Code Sequence sixth-order withholding disagrees with an original second-order intersection.'
            }
            $count = [long]$pairIntersections[($first * $N) + $second]
        }
        if (($size % 2) -eq 1) { $byExclusion -= $count }
        else { $byExclusion += $count }
    }
    if ($directSurvivors -ne $byExclusion -or
        $directSurvivors -lt 0 -or $directSurvivors -gt $original) {
        throw 'Code Sequence sixth-order withholding failed exact six-way original inclusion/exclusion.'
    }
    return [long]$directSurvivors
}

function Get-CodeSequenceSextetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int[]] $Positions)
    $totalGenuine = [long]0
    $totalFrozen = [long]0
    $supported = [System.Collections.Generic.List[int]]::new()
    $frozen = [System.Collections.Generic.List[int]]::new()
    $supportedSets = [System.Collections.Generic.List[object]]::new()
    $frozenSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceSextetWithholdingRemainingCount -Aggregate $row.genuine -N $N -Positions $Positions
        $o = Get-CodeSequenceSextetWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -Positions $Positions
        $totalGenuine += $g
        $totalFrozen += $o
        if ($g -gt 0) {
            $supported.Add([int]$row.registry_index)
            $supportedSets.Add([int[]]$row.family_indices)
        }
        if ($o -gt 0) {
            $frozen.Add([int]$row.registry_index)
            $frozenSets.Add([int[]]$row.family_indices)
        }
    }
    return [ordered]@{
        genuine_total = $totalGenuine
        original_local_optimum_total = $totalFrozen
        genuine_registry_indices = $supported.ToArray()
        original_local_optimum_registry_indices = $frozen.ToArray()
        genuine_family_sets = $supportedSets.ToArray()
        original_local_optimum_family_sets = $frozenSets.ToArray()
    }
}

function Assert-CodeSequenceSextetWithholdingParent {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding, [object] $WitnessAggregates)
    # Re-execute the ORIGINAL EC-063 construction. This itself rechecks the
    # complete EC-062 projection, EC-061/060 lineage, all private masks and
    # the exact 5/10/10/5 parent incidences. Compare the ENTIRE public EC-063
    # tree, including every surviving count, original identity, registry,
    # fifth-order-only family loss, all global maximizers and summary ledger.
    $replayed = Get-CodeSequenceOriginalFindingPairProfileQuintetPositionWithholding `
        -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -WitnessAggregates $WitnessAggregates
    $expected = ConvertTo-Json -InputObject $replayed -Depth 80 -Compress
    $observed = ConvertTo-Json -InputObject $QuintetWithholding -Depth 80 -Compress
    if ($expected -cne $observed) {
        throw 'Code Sequence sixth-order withholding disagrees with the FULL original EC-063 quintet parent.'
    }
}

function Get-CodeSequenceSextetWithholdingSixthOnlyFamilyIndices {
    param([object[]] $ParentRows, [int[]] $QuintetOrdinals, [int[]] $SurvivingIndices,
        [int] $FamilyCount, [bool] $OriginalLocalOptima)
    if ($QuintetOrdinals.Count -ne 6) {
        throw 'Code Sequence sixth-order family sensitivity requires all six original constituent quintets.'
    }
    $intersection = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt 6; $i++) {
        $ordinal = [int]$QuintetOrdinals[$i]
        if ($ordinal -lt 1 -or $ordinal -gt $ParentRows.Count -or
            [int]$ParentRows[$ordinal - 1].original_position_quintet_index -ne $ordinal) {
            throw 'Code Sequence sixth-order family sensitivity lost the original quintet ordinal.'
        }
        $original = $ParentRows[$ordinal - 1]
        $candidates = if ($OriginalLocalOptima) {
            [int[]]$original.original_local_optimum_family_indices
        } else { [int[]]$original.independently_supported_family_indices }
        $parentSet = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($candidate in $candidates) {
            if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $parentSet.Add($candidate)) {
                throw 'Code Sequence sixth-order family sensitivity found invalid/duplicate original family indices.'
            }
        }
        if ($i -eq 0) { $intersection.UnionWith($parentSet) }
        else { $intersection.IntersectWith($parentSet) }
    }
    foreach ($survivor in $SurvivingIndices) { [void]$intersection.Remove($survivor) }
    $result = [int[]]@($intersection | Sort-Object)
    return ,$result
}

function Assert-CodeSequenceSextetWithholdingFamilySubset {
    param([int[]] $Survivors, [int[]] $ParentSurvivors, [int] $FamilyCount)
    $eligible = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($index in $ParentSurvivors) {
        if ($index -lt 1 -or $index -gt $FamilyCount -or -not $eligible.Add($index)) {
            throw 'Code Sequence sixth-order withholding found an invalid original parent family registry.'
        }
    }
    foreach ($index in $Survivors) {
        if (-not $eligible.Contains($index)) {
            throw 'Code Sequence sixth-order withholding manufactured a family excluded by its quintet parent.'
        }
    }
}

function Get-CodeSequenceOriginalFindingPairProfileSextetPositionWithholding {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding, [object] $WitnessAggregates)
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $TripleWithholding -or
        $null -eq $QuartetWithholding -or $null -eq $QuintetWithholding -or
        $null -eq $WitnessAggregates -or
        $QuintetWithholding.scope -cne 'unordered_five_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$QuintetWithholding.complete_original_ec062_quartet_projections_and_private_witness_masks_reconciled -or
        -not [bool]$QuintetWithholding.independent_of_sequence_top -or
        -not [bool]$QuintetWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence sixth-order withholding requires fully reconciled EC-063 original quintet parent and private masks.'
    }
    $n = [int]$QuintetWithholding.counts.selected_report_positions
    $familyCount = [int]$QuintetWithholding.counts.original_maximal_repeat_family_count
    $records = [string[]]$WitnessAggregates.original_record_ids
    $classes = [int[]]$WitnessAggregates.original_profile_classes
    $singles = [object[]]$WitnessAggregates.single_family_rows
    $pairs = [object[]]$WitnessAggregates.cross_family_pair_rows
    $triples = [object[]]$WitnessAggregates.cross_family_triple_rows
    $parentPairs = [object[]]$PairWithholding.ordered_original_position_pair_withholding
    $parentTriples = [object[]]$TripleWithholding.ordered_original_position_triple_withholding
    $parentQuartets = [object[]]$QuartetWithholding.ordered_original_position_quartet_withholding
    $parentQuintets = [object[]]$QuintetWithholding.ordered_original_position_quintet_withholding
    $baseG = [int]$QuintetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$QuintetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $familyCount -lt 0 -or $familyCount -gt 66 -or
        $records.Count -ne $n -or $classes.Count -ne $n -or $singles.Count -ne $familyCount -or
        $pairs.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $familyCount -K 2) -or
        $triples.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $familyCount -K 3) -or
        $parentPairs.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $n -K 2) -or
        $parentTriples.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $n -K 3) -or
        $parentQuartets.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $n -K 4) -or
        $parentQuintets.Count -ne (Get-CodeSequenceSextetWithholdingChoose -N $n -K 5) -or
        $baseG -lt 0 -or $baseG -gt 3 -or $baseO -lt 0 -or $baseO -gt $baseG) {
        throw 'Code Sequence sixth-order withholding found inconsistent original parent/cardinality or baseline maxima.'
    }
    Assert-CodeSequenceSextetWithholdingParent -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -WitnessAggregates $WitnessAggregates
    $activeSingles = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $singles
    # Genuine two-family support entails four mutually nonoverlapping windows,
    # each of length >=2, hence >=8 distinct original positions. Three families
    # need >=12. N<=12 minus six exclusions <=6: both layers are impossible.
    # The full EC-063 parent replay already verifies each original footprint.
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $pairs -MinimumOriginalPositions 8
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $triples -MinimumOriginalPositions 12
    $emptyJoint = Get-CodeSequenceQuintetWithholdingEmptyJointLayer
    $quartetByMask = [System.Collections.Generic.Dictionary[int,int]]::new()
    foreach ($row in $parentQuartets) {
        $pos = [int[]]@($row.withheld_original_caller_positions | ForEach-Object { $_ - 1 })
        $mask = Get-CodeSequenceSextetWithholdingMask -Positions $pos -N $n
        if ($quartetByMask.ContainsKey($mask)) { throw 'Code Sequence sixth-order withholding found a duplicate original quartet parent.' }
        $quartetByMask.Add($mask,[int]$row.original_position_quartet_index)
    }
    $quintetByMask = [System.Collections.Generic.Dictionary[int,int]]::new()
    foreach ($row in $parentQuintets) {
        $pos = [int[]]@($row.withheld_original_caller_positions | ForEach-Object { $_ - 1 })
        $mask = Get-CodeSequenceSextetWithholdingMask -Positions $pos -N $n
        if ($quintetByMask.ContainsKey($mask)) { throw 'Code Sequence sixth-order withholding found a duplicate original quintet parent.' }
        $quintetByMask.Add($mask,[int]$row.original_position_quintet_index)
    }
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
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 6) { $minG = $baseG; $minO = $baseO; $maxG = 0; $maxO = 0 }
    $ordinal = 0
    for ($p = 0; $p -lt $n; $p++) {
      for ($q = $p + 1; $q -lt $n; $q++) {
       for ($r = $q + 1; $r -lt $n; $r++) {
        for ($s = $r + 1; $s -lt $n; $s++) {
         for ($t = $s + 1; $t -lt $n; $t++) {
          for ($u = $t + 1; $u -lt $n; $u++) {
            $ordinal++
            $positions = [int[]]@($p,$q,$r,$s,$t,$u)
            $pairOrdinals = [System.Collections.Generic.List[int]]::new()
            $tripleOrdinals = [System.Collections.Generic.List[int]]::new()
            $quartetOrdinals = [System.Collections.Generic.List[int]]::new()
            $quintetOrdinals = [System.Collections.Generic.List[int]]::new()
            for ($a = 0; $a -lt 6; $a++) {
                for ($b = $a + 1; $b -lt 6; $b++) {
                    $pairOrdinals.Add((Get-CodeSequenceTripleWithholdingPairOrdinal `
                        -N $n -P $positions[$a] -Q $positions[$b]))
                    for ($c = $b + 1; $c -lt 6; $c++) {
                        $tripleOrdinals.Add((Get-CodeSequenceQuartetWithholdingTripleOrdinal `
                            -N $n -P $positions[$a] -Q $positions[$b] -R $positions[$c]))
                        for ($d = $c + 1; $d -lt 6; $d++) {
                            $mask4 = Get-CodeSequenceSextetWithholdingMask `
                                -Positions ([int[]]@($positions[$a],$positions[$b],$positions[$c],$positions[$d])) -N $n
                            if (-not $quartetByMask.ContainsKey($mask4)) {
                                throw 'Code Sequence sixth-order withholding lost an original constituent quartet.'
                            }
                            $quartetOrdinals.Add($quartetByMask[$mask4])
                            for ($e = $d + 1; $e -lt 6; $e++) {
                                $mask5 = Get-CodeSequenceSextetWithholdingMask `
                                    -Positions ([int[]]@($positions[$a],$positions[$b],$positions[$c],$positions[$d],$positions[$e])) -N $n
                                if (-not $quintetByMask.ContainsKey($mask5)) {
                                    throw 'Code Sequence sixth-order withholding lost an original constituent quintet.'
                                }
                                $quintetOrdinals.Add($quintetByMask[$mask5])
                            }
                        }
                    }
                }
            }
            $pairIndices = [int[]]@($pairOrdinals.ToArray() | Sort-Object)
            $tripleIndices = [int[]]@($tripleOrdinals.ToArray() | Sort-Object)
            $quartetIndices = [int[]]@($quartetOrdinals.ToArray() | Sort-Object)
            $quintetIndices = [int[]]@($quintetOrdinals.ToArray() | Sort-Object)
            if ($pairIndices.Count -ne 15 -or $tripleIndices.Count -ne 20 -or
                $quartetIndices.Count -ne 15 -or $quintetIndices.Count -ne 6 -or
                @($pairIndices | Select-Object -Unique).Count -ne 15 -or
                @($tripleIndices | Select-Object -Unique).Count -ne 20 -or
                @($quartetIndices | Select-Object -Unique).Count -ne 15 -or
                @($quintetIndices | Select-Object -Unique).Count -ne 6) {
                throw 'Code Sequence sixth-order withholding lost distinct original 15/20/15/6 constituent ordinals.'
            }
            $one = Get-CodeSequenceSextetWithholdingLayer -Rows $activeSingles -N $n -Positions $positions
            $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $false
            $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $true
            $g = [int]$gMax.distinct_family_count
            $o = [int]$oMax.distinct_family_count
            $parentMinG = $baseG; $parentMinO = $baseO
            foreach ($qi in $quintetIndices) {
                $parent = $parentQuintets[$qi - 1]
                if ([int]$parent.original_position_quintet_index -ne $qi) {
                    throw 'Code Sequence sixth-order withholding changed original quintet order.'
                }
                $parentMinG = [math]::Min($parentMinG,
                    [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                $parentMinO = [math]::Min($parentMinO,
                    [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                if ([long]$one.genuine_total -gt [long]$parent.surviving_original_independent_two_window_combinations -or
                    [long]$one.original_local_optimum_total -gt [long]$parent.surviving_original_full_selection_local_optimum_individual_packings) {
                    throw 'Code Sequence sixth-order withholding exceeded surviving original quintet witness counts.'
                }
                Assert-CodeSequenceSextetWithholdingFamilySubset -Survivors $one.genuine_registry_indices `
                    -ParentSurvivors $parent.independently_supported_family_indices -FamilyCount $familyCount
                Assert-CodeSequenceSextetWithholdingFamilySubset -Survivors $one.original_local_optimum_registry_indices `
                    -ParentSurvivors $parent.original_local_optimum_family_indices -FamilyCount $familyCount
            }
            if ($g -gt [math]::Floor(($n - 6)/4) -or $g -gt $parentMinG -or
                $o -gt $parentMinO -or $o -gt $g -or $g -gt $baseG -or $o -gt $baseO) {
                throw 'Code Sequence sixth-order withholding violated original support capacity or quintet monotonicity.'
            }
            $sixthOnlyFamiliesG = Get-CodeSequenceSextetWithholdingSixthOnlyFamilyIndices `
                -ParentRows $parentQuintets -QuintetOrdinals $quintetIndices `
                -SurvivingIndices $one.genuine_registry_indices -FamilyCount $familyCount -OriginalLocalOptima $false
            $sixthOnlyFamiliesO = Get-CodeSequenceSextetWithholdingSixthOnlyFamilyIndices `
                -ParentRows $parentQuintets -QuintetOrdinals $quintetIndices `
                -SurvivingIndices $one.original_local_optimum_registry_indices -FamilyCount $familyCount -OriginalLocalOptima $true
            if ($sixthOnlyFamiliesG.Count -gt 0) { $familyOnlyG.Add($ordinal) }
            if ($sixthOnlyFamiliesO.Count -gt 0) { $familyOnlyO.Add($ordinal) }
            $familyOnlyGEvents += $sixthOnlyFamiliesG.Count
            $familyOnlyOEvents += $sixthOnlyFamiliesO.Count
            $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
            $sixthOnlyG = $reducedG -and $parentMinG -eq $baseG
            $sixthOnlyO = $reducedO -and $parentMinO -eq $baseO
            $additionalG = [int]$parentMinG - $g
            $additionalO = [int]$parentMinO - $o
            if ($reducedG) { $criticalG.Add($ordinal) }; if ($reducedO) { $criticalO.Add($ordinal) }
            if ($sixthOnlyG) { $minimalG.Add($ordinal) }; if ($sixthOnlyO) { $minimalO.Add($ordinal) }
            if ($additionalG -gt 0) { $extraG.Add($ordinal) }; if ($additionalO -gt 0) { $extraO.Add($ordinal) }
            $flags = @{
                ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                MinimalG = [bool]$sixthOnlyG; MinimalO = [bool]$sixthOnlyO
                ExtraG = [bool]($additionalG -gt 0); ExtraO = [bool]($additionalO -gt 0)
            }
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $positionLedger -Indices $positions @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedger -Indices $pairIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedger -Indices $tripleIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quartetLedger -Indices $quartetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quintetLedger -Indices $quintetIndices -OneBased @flags
            $minG = [math]::Min($minG,$g); $maxG = [math]::Max($maxG,$g)
            $minO = [math]::Min($minO,$o); $maxO = [math]::Max($maxO,$o)
            $oneBased = [System.Collections.Generic.List[int]]::new()
            $recordIds = [System.Collections.Generic.List[string]]::new()
            $profileClasses = [System.Collections.Generic.List[int]]::new()
            foreach ($pos in $positions) {
                $oneBased.Add($pos + 1)
                $recordIds.Add($records[$pos])
                $profileClasses.Add($classes[$pos])
            }
            $rows.Add([ordered]@{
                original_position_sextet_index = $ordinal
                withheld_original_caller_positions = $oneBased.ToArray()
                withheld_original_record_ids = $recordIds.ToArray()
                original_saved_profile_class_indices = $profileClasses.ToArray()
                original_constituent_position_pair_indices = $pairIndices
                original_constituent_position_triple_indices = $tripleIndices
                original_constituent_position_quartet_indices = $quartetIndices
                original_constituent_position_quintet_indices = $quintetIndices
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
                genuinely_sixth_order_only_lost_original_family_indices = $sixthOnlyFamiliesG
                frozen_original_optimum_sixth_order_only_lost_original_family_indices = $sixthOnlyFamiliesO
                jointly_compatible_original_local_optimum_family_pair_indices = [int[]]@()
                jointly_compatible_original_local_optimum_family_triple_indices = [int[]]@()
                globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                minimally_sixth_order_critical_for_original_independent_maximum = [bool]$sixthOnlyG
                minimally_sixth_order_critical_for_original_local_optimum_maximum = [bool]$sixthOnlyO
                strongest_constituent_quintet_independent_family_maximum = $parentMinG
                strongest_constituent_quintet_original_local_optimum_family_maximum = $parentMinO
                additional_independent_family_loss_beyond_stronger_quintet_exclusion = $additionalG
                additional_original_local_optimum_family_loss_beyond_stronger_quintet_exclusion = $additionalO
            })
          }
         }
        }
       }
      }
    }
    if ($ordinal -ne (Get-CodeSequenceSextetWithholdingChoose -N $n -K 6)) {
        throw 'Code Sequence sixth-order withholding did not enumerate all ORIGINAL six-position sets.'
    }
    $perPosition = [System.Collections.Generic.List[object]]::new()
    $perPair = [System.Collections.Generic.List[object]]::new()
    $perTriple = [System.Collections.Generic.List[object]]::new()
    $perQuartet = [System.Collections.Generic.List[object]]::new()
    $perQuintet = [System.Collections.Generic.List[object]]::new()
    $incidence = @(
        @($positionLedger,$perPosition,'position',$n,1),
        @($pairLedger,$perPair,'pair',$parentPairs.Count,2),
        @($tripleLedger,$perTriple,'triple',$parentTriples.Count,3),
        @($quartetLedger,$perQuartet,'quartet',$parentQuartets.Count,4),
        @($quintetLedger,$perQuintet,'quintet',$parentQuintets.Count,5)
    )
    foreach ($kind in $incidence) {
        $ledger = $kind[0]; $out = $kind[1]; $name = [string]$kind[2]
        $count = [int]$kind[3]; $level = [int]$kind[4]
        for ($i = 0; $i -lt $count; $i++) {
            $originalPositions = if ($level -eq 1) { [int[]]@($i+1) }
                elseif ($level -eq 2) { [int[]]$parentPairs[$i].withheld_original_caller_positions }
                elseif ($level -eq 3) { [int[]]$parentTriples[$i].withheld_original_caller_positions }
                elseif ($level -eq 4) { [int[]]$parentQuartets[$i].withheld_original_caller_positions }
                else { [int[]]$parentQuintets[$i].withheld_original_caller_positions }
            $entry = [ordered]@{
                original_constituent_type = $name
                original_constituent_index = $i + 1
                original_caller_positions = $originalPositions
                number_of_position_sextets_containing_constituent = (Get-CodeSequenceSextetWithholdingChoose -N ($n-$level) -K (6-$level))
                sextets_reducing_original_independent_maximum = $ledger.criticalG[$i]
                sextets_reducing_original_local_optimum_maximum = $ledger.criticalO[$i]
                minimally_sixth_order_critical_sextets_for_original_independent_maximum = $ledger.minimalG[$i]
                minimally_sixth_order_critical_sextets_for_original_local_optimum_maximum = $ledger.minimalO[$i]
                sextets_with_additional_independent_loss_beyond_stronger_quintet = $ledger.extraG[$i]
                sextets_with_additional_original_local_optimum_loss_beyond_stronger_quintet = $ledger.extraO[$i]
            }
            if ($level -eq 1) {
                $entry['original_record_id'] = $records[$i]
                $entry['original_saved_profile_class_index'] = $classes[$i]
            }
            $out.Add($entry)
        }
    }
    foreach ($category in @('criticalG','criticalO','minimalG','minimalO','extraG','extraO')) {
        $matching = switch ($category) {
            'criticalG' { $criticalG.Count }; 'criticalO' { $criticalO.Count }
            'minimalG' { $minimalG.Count }; 'minimalO' { $minimalO.Count }
            'extraG' { $extraG.Count }; 'extraO' { $extraO.Count }
        }
        $ledgers = @($positionLedger,$pairLedger,$tripleLedger,$quartetLedger,$quintetLedger)
        $expectedMembership = [long[]]@(6,15,20,15,6)
        for ($level = 0; $level -lt $ledgers.Count; $level++) {
            $observed = [long]0
            foreach ($count in $ledgers[$level][$category]) { $observed += [long]$count }
            if ($observed -ne ($expectedMembership[$level] * [long]$matching)) {
                throw 'Code Sequence sixth-order withholding lost exact 6/15/20/15/6 original participation incidence.'
            }
        }
    }
    return [ordered]@{
        scope = 'unordered_six_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$QuintetWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$QuintetWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$QuintetWithholding.anchor_index_in_anchor_journeys
        path = [string]$QuintetWithholding.path
        exact_saved_quote_anchor = $QuintetWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            unordered_original_position_sextet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baseG
            original_global_maximum_original_locally_optimal_distinct_family_count = $baseO
            number_of_sextets_reducing_original_independent_maximum = $criticalG.Count
            number_of_sextets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_sixth_order_critical_sextets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_sixth_order_critical_sextets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_sextets_with_additional_independent_loss_beyond_stronger_quintet = $extraG.Count
            number_of_sextets_with_additional_original_local_optimum_loss_beyond_stronger_quintet = $extraO.Count
            number_of_sextets_with_genuinely_sixth_order_only_original_family_loss = $familyOnlyG.Count
            number_of_sextets_with_frozen_original_optimum_sixth_order_only_family_loss = $familyOnlyO.Count
            genuine_sixth_order_only_original_family_loss_events = $familyOnlyGEvents
            frozen_original_optimum_sixth_order_only_family_loss_events = $familyOnlyOEvents
            minimum_global_independent_family_maximum_after_six_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_six_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_six_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_six_withheld_positions = $maxO
        }
        original_position_sextet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_sextet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_sixth_order_critical_sextet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_sixth_order_critical_sextet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        sextet_indices_causing_additional_independent_loss_vs_stronger_quintet = $extraG.ToArray()
        sextet_indices_causing_additional_original_local_optimum_loss_vs_stronger_quintet = $extraO.ToArray()
        sextet_indices_with_genuinely_sixth_order_only_original_family_loss = $familyOnlyG.ToArray()
        sextet_indices_with_frozen_original_optimum_sixth_order_only_family_loss = $familyOnlyO.ToArray()
        ordered_original_position_sextet_withholding = $rows.ToArray()
        ordered_original_position_sextet_participation = $perPosition.ToArray()
        ordered_original_pair_sextet_participation = $perPair.ToArray()
        ordered_original_triple_sextet_participation = $perTriple.ToArray()
        ordered_original_quartet_sextet_participation = $perQuartet.ToArray()
        ordered_original_quintet_sextet_participation = $perQuintet.ToArray()
        complete_original_ec063_quintet_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        no_original_window_resequencing_or_new_adjacency = $true
        original_full_selection_local_optima_frozen_not_reoptimized = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_finding_historical_order_defect_recurrence_fix_regression_or_causality_proven = $false
    }
}

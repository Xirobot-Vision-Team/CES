#requires -Version 7.0
<#
    EC-068: TEN simultaneous exclusions of ORIGINAL caller report positions.
    Work only from the EC-060 reconciled PRIVATE union-mask witness histograms,
    with EC-056 original full-selection optimum packs kept frozen. The selected
    record order is NOT a chronology; never stitch removed-position neighbors,
    authenticate identity of a defect, or mutate any repository or saved record.
#>

function Get-CodeSequenceDecetWithholdingChoose {
    param([int] $N, [int] $K)
    if ($N -lt 0 -or $K -lt 0 -or $K -gt $N) { return 0 }
    $result = [long]1
    for ($i = 1; $i -le $K; $i++) {
        $result = [long](($result * ($N - $i + 1)) / $i)
    }
    return [int]$result
}

function Get-CodeSequenceDecetWithholdingMask {
    param([int[]] $Positions, [int] $N)
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $Positions -or
        $Positions.Count -lt 4 -or $Positions.Count -gt 10) {
        throw 'Code Sequence tenth-order position masks require four through ten ORIGINAL positions.'
    }
    $mask = 0
    $last = -1
    foreach ($position in $Positions) {
        if ($position -le $last -or $position -lt 0 -or $position -ge $N) {
            throw 'Code Sequence tenth-order masks require strictly ascending original caller positions.'
        }
        $mask = $mask -bor (1 -shl $position)
        $last = $position
    }
    return [int]$mask
}

function Get-CodeSequenceDecetWithholdingRemainingCount {
    param([object] $Aggregate, [int] $N, [int[]] $Positions)
    if ($Positions.Count -ne 10) {
        throw 'Code Sequence tenth-order evidence projection requires ten ORIGINAL positions.'
    }
    $excludedMask = Get-CodeSequenceDecetWithholdingMask -Positions $Positions -N $N
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $singles = [long[]]$Aggregate.original_position_inclusion_counts
    $pairs = [long[]]$Aggregate.original_pair_intersection_counts
    $total = [long]$Aggregate.original_combination_count
    if ($masks.Count -ne $weights.Count -or $singles.Count -ne $N -or
        $pairs.Count -ne ($N * $N) -or $total -lt 0) {
        throw 'Code Sequence tenth-order withholding lacks conserved original EC-060 evidence.'
    }
    # Bucket each ORIGINAL witness by exactly which excluded original slots it
    # covers, retaining source multiplicity. A superset zeta transform then
    # yields ALL 1023 true intersection totals in 10*512 additions instead of
    # iterating all 1023 subsets for each witness. Nothing is inferred from parents.
    $intersections = [long[]]::new(1024)
    $direct = [long]0
    $conserved = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = [int]$masks[$i]
        $multiplicity = [long]$weights[$i]
        if ($mask -le 0 -or $mask -ge (1 -shl $N) -or $multiplicity -le 0) {
            throw 'Code Sequence tenth-order withholding found an invalid original union mask.'
        }
        # A true independent two-window witness needs >=4 disjoint original
        # positions. Excluding 10 of N<=12 leaves at most 0..2 original slots.
        $footprint = 0
        $work = $mask
        while ($work -gt 0) { $footprint += ($work -band 1); $work = $work -shr 1 }
        if ($footprint -lt 4) {
            throw 'Code Sequence tenth-order found fabricated independent evidence using fewer than four originals.'
        }
        $conserved += $multiplicity
        if (($mask -band $excludedMask) -eq 0) { $direct += $multiplicity }
        $covered = 0
        for ($bit = 0; $bit -lt 10; $bit++) {
            if (($mask -band (1 -shl $Positions[$bit])) -ne 0) {
                $covered = $covered -bor (1 -shl $bit)
            }
        }
        $intersections[$covered] += $multiplicity
    }
    if ($conserved -ne $total) {
        throw 'Code Sequence tenth-order withholding altered original witness multiplicities.'
    }
    for ($bit = 0; $bit -lt 10; $bit++) {
        $bitMask = 1 -shl $bit
        for ($subset = 0; $subset -lt 1024; $subset++) {
            if (($subset -band $bitMask) -eq 0) {
                $intersections[$subset] += $intersections[$subset -bor $bitMask]
            }
        }
    }
    if ($intersections[0] -ne $total) {
        throw 'Code Sequence tenth-order intersection reconstruction lost original weighted evidence.'
    }
    # T - I1 + I2 - I3 + I4 - I5 + I6 - I7 + I8 - I9 + I10.
    # Independently reconcile EVERY first and second intersection with the
    # saved EC-060 margins, not just the total or the final zero bound.
    $byInclusionExclusion = $total
    for ($subset = 1; $subset -lt 1024; $subset++) {
        $size = 0
        $first = -1; $second = -1
        for ($bit = 0; $bit -lt 10; $bit++) {
            if (($subset -band (1 -shl $bit)) -ne 0) {
                if ($size -eq 0) { $first = $Positions[$bit] }
                elseif ($size -eq 1) { $second = $Positions[$bit] }
                $size++
            }
        }
        $value = [long]$intersections[$subset]
        if ($size -eq 1) {
            if ($value -ne [long]$singles[$first]) {
                throw 'Code Sequence tenth-order disagrees with an original position marginal.'
            }
            $value = [long]$singles[$first]
        } elseif ($size -eq 2) {
            if ($value -ne [long]$pairs[($first * $N) + $second]) {
                throw 'Code Sequence tenth-order disagrees with an original pair intersection.'
            }
            $value = [long]$pairs[($first * $N) + $second]
        }
        if (($size % 2) -eq 1) { $byInclusionExclusion -= $value }
        else { $byInclusionExclusion += $value }
    }
    if ($direct -ne $byInclusionExclusion -or $direct -ne 0) {
        throw 'Code Sequence tenth-order direct/exact original-mask survival or 2-slot capacity failed.'
    }
    return [long]$direct
}

function Get-CodeSequenceDecetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int[]] $Positions)
    $genuineTotal = [long]0
    $frozenTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $frozenIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $frozenSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceDecetWithholdingRemainingCount -Aggregate $row.genuine -N $N -Positions $Positions
        $o = Get-CodeSequenceDecetWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -Positions $Positions
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

function Assert-CodeSequenceDecetWithholdingParent {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $SeptetWithholding,
        [object] $OctetWithholding, [object] $NonetWithholding, [object] $WitnessAggregates)
    # Replay and compare the COMPLETE EC-067 nonet output, including its
    # earlier full EC-066, EC-065 ... EC-060 parent reconciliation chain.
    $replayed = Get-CodeSequenceOriginalFindingPairProfileNonetPositionWithholding `
        -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -SextetWithholding $SextetWithholding `
        -SeptetWithholding $SeptetWithholding -OctetWithholding $OctetWithholding `
        -WitnessAggregates $WitnessAggregates
    $expected = ConvertTo-Json -InputObject $replayed -Depth 80 -Compress
    $actual = ConvertTo-Json -InputObject $NonetWithholding -Depth 80 -Compress
    if ($expected -cne $actual) {
        throw 'Code Sequence tenth-order view differs from the COMPLETE original EC-067 nonet output.'
    }
}

function Get-CodeSequenceDecetWithholdingTenthOnlyFamilyIndices {
    param([object[]] $Parents, [int[]] $NonetOrdinals,
        [int[]] $SurvivingFamilyIndices, [int] $FamilyCount, [bool] $OriginalLocalOptima)
    if ($NonetOrdinals.Count -ne 10) {
        throw 'Code Sequence tenth-order original-family loss requires all ten nonet parents.'
    }
    $commonFamilies = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt 10; $i++) {
        $ordinal = [int]$NonetOrdinals[$i]
        if ($ordinal -lt 1 -or $ordinal -gt $Parents.Count -or
            [int]$Parents[$ordinal - 1].original_position_nonet_index -ne $ordinal) {
            throw 'Code Sequence tenth-order loss lost a genuine original nonet ancestor.'
        }
        $parent = $Parents[$ordinal - 1]
        $candidateIndices = if ($OriginalLocalOptima) {
            [int[]]$parent.original_local_optimum_family_indices
        } else { [int[]]$parent.independently_supported_family_indices }
        $set = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($candidate in $candidateIndices) {
            if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $set.Add($candidate)) {
                throw 'Code Sequence tenth-order family loss found an invalid original ancestor registry.'
            }
        }
        if ($i -eq 0) { $commonFamilies.UnionWith($set) }
        else { $commonFamilies.IntersectWith($set) }
    }
    foreach ($candidate in $SurvivingFamilyIndices) { [void]$commonFamilies.Remove($candidate) }
    $answer = [int[]]@($commonFamilies | Sort-Object)
    return ,$answer
}

function Assert-CodeSequenceDecetWithholdingFamilySubset {
    param([int[]] $Children, [int[]] $Parents, [int] $FamilyCount)
    $allowed = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($candidate in $Parents) {
        if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $allowed.Add($candidate)) {
            throw 'Code Sequence tenth-order family subset found an invalid original nonet registry.'
        }
    }
    foreach ($candidate in $Children) {
        if (-not $allowed.Contains($candidate)) {
            throw 'Code Sequence tenth-order family witness was fabricated across removed positions.'
        }
    }
}

function Get-CodeSequenceDecetWithholdingAncestorRegistry {
    param([object[]] $Rows, [int] $N, [int] $K, [string] $OrdinalName)
    $result = [System.Collections.Generic.Dictionary[int,int]]::new()
    if ($Rows.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $N -K $K)) {
        throw 'Code Sequence tenth-order ancestry does not cover every original parent position set.'
    }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        if ([int]$row.$OrdinalName -ne ($i + 1)) {
            throw 'Code Sequence tenth-order ancestor index is not in canonical original order.'
        }
        $positions = [int[]]@($row.withheld_original_caller_positions | ForEach-Object { [int]$_ - 1 })
        if ($positions.Count -ne $K) {
            throw 'Code Sequence tenth-order ancestor lost its original position cardinality.'
        }
        $mask = Get-CodeSequenceDecetWithholdingMask -Positions $positions -N $N
        if ($result.ContainsKey($mask)) {
            throw 'Code Sequence tenth-order ancestor registry has duplicate original position sets.'
        }
        $result.Add($mask, $i + 1)
    }
    return ,$result
}

function Get-CodeSequenceOriginalFindingPairProfileDecetPositionWithholding {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $SeptetWithholding,
        [object] $OctetWithholding, [object] $NonetWithholding, [object] $WitnessAggregates)
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $TripleWithholding -or
        $null -eq $QuartetWithholding -or $null -eq $QuintetWithholding -or
        $null -eq $SextetWithholding -or $null -eq $SeptetWithholding -or $null -eq $OctetWithholding -or
        $null -eq $NonetWithholding -or
        $null -eq $WitnessAggregates -or
        $NonetWithholding.scope -cne 'unordered_nine_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$NonetWithholding.complete_original_ec066_octet_projections_and_private_witness_masks_reconciled -or
        -not [bool]$NonetWithholding.independent_of_sequence_top -or
        -not [bool]$NonetWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence tenth-order view requires fully reconciled original EC-067 nonets.'
    }
    $n = [int]$NonetWithholding.counts.selected_report_positions
    $familyCount = [int]$NonetWithholding.counts.original_maximal_repeat_family_count
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
    $parentSeptets = [object[]]$SeptetWithholding.ordered_original_position_septet_withholding
    $parentOctets = [object[]]$OctetWithholding.ordered_original_position_octet_withholding
    $parentNonets = [object[]]$NonetWithholding.ordered_original_position_nonet_withholding
    $baseG = [int]$NonetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$NonetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $familyCount -lt 0 -or $familyCount -gt 66 -or
        $records.Count -ne $n -or $classes.Count -ne $n -or $singles.Count -ne $familyCount -or
        $pairs.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $familyCount -K 2) -or
        $triples.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $familyCount -K 3) -or
        $parentPairs.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 2) -or
        $parentTriples.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 3) -or
        $parentQuartets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 4) -or
        $parentQuintets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 5) -or
        $parentSextets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 6) -or
        $parentSeptets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 7) -or
        $parentOctets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 8) -or
        $parentNonets.Count -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 9) -or
        $baseG -lt 0 -or $baseG -gt 3 -or $baseO -lt 0 -or $baseO -gt $baseG) {
        throw 'Code Sequence tenth-order ancestry or original witness counts are inconsistent.'
    }
    Assert-CodeSequenceDecetWithholdingParent -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -SextetWithholding $SextetWithholding `
        -SeptetWithholding $SeptetWithholding -OctetWithholding $OctetWithholding `
        -NonetWithholding $NonetWithholding -WitnessAggregates $WitnessAggregates
    $activeSingles = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $singles
    # Four mutually nonoverlapping original windows across two different
    # families need at least EIGHT positions; three families need TWELVE.
    # Ten exclusions from N<=12 leave at most TWO original positions.
    # Validate original footprints before relying on the impossibility bound.
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $pairs -MinimumOriginalPositions 8
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $triples -MinimumOriginalPositions 12
    $emptyJoint = Get-CodeSequenceQuintetWithholdingEmptyJointLayer
    $quartetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentQuartets `
        -N $n -K 4 -OrdinalName 'original_position_quartet_index'
    $quintetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentQuintets `
        -N $n -K 5 -OrdinalName 'original_position_quintet_index'
    $sextetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentSextets `
        -N $n -K 6 -OrdinalName 'original_position_sextet_index'
    $septetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentSeptets `
        -N $n -K 7 -OrdinalName 'original_position_septet_index'
    $octetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentOctets `
        -N $n -K 8 -OrdinalName 'original_position_octet_index'
    $nonetIndex = Get-CodeSequenceDecetWithholdingAncestorRegistry -Rows $parentNonets `
        -N $n -K 9 -OrdinalName 'original_position_nonet_index'

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
    $septetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentSeptets.Count
    $octetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentOctets.Count
    $nonetLedger = New-CodeSequenceQuartetWithholdingParticipationLedger -Count $parentNonets.Count
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 10) { $minG = $baseG; $minO = $baseO; $maxG = 0; $maxO = 0 }
    $ordinal = 0
    for ($a = 0; $a -lt $n; $a++) {
      for ($b = $a + 1; $b -lt $n; $b++) {
       for ($c = $b + 1; $c -lt $n; $c++) {
        for ($d = $c + 1; $d -lt $n; $d++) {
         for ($e = $d + 1; $e -lt $n; $e++) {
          for ($f = $e + 1; $f -lt $n; $f++) {
           for ($h = $f + 1; $h -lt $n; $h++) {
            for ($i = $h + 1; $i -lt $n; $i++) {
             for ($j = $i + 1; $j -lt $n; $j++) {
             for ($z = $j + 1; $z -lt $n; $z++) {
            $ordinal++
            $positions = [int[]]@($a,$b,$c,$d,$e,$f,$h,$i,$j,$z)
            $pairOrdinalList = [System.Collections.Generic.List[int]]::new()
            $tripleOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quartetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quintetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $sextetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $septetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $octetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $nonetOrdinalList = [System.Collections.Generic.List[int]]::new()
            # Recover all GENUINE original parent ordinals. Removing positions
            # does not reindex a report or create any new observed motif step.
            for ($subset = 1; $subset -lt 1024; $subset++) {
                $selected = [System.Collections.Generic.List[int]]::new()
                for ($bit = 0; $bit -lt 10; $bit++) {
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
                } elseif ($k -ge 4 -and $k -le 9) {
                    $mask = Get-CodeSequenceDecetWithholdingMask -Positions ($selected.ToArray()) -N $n
                    $registry = if ($k -eq 4) { $quartetIndex }
                        elseif ($k -eq 5) { $quintetIndex }
                        elseif ($k -eq 6) { $sextetIndex }
                        elseif ($k -eq 7) { $septetIndex }
                        elseif ($k -eq 8) { $octetIndex }
                        else { $nonetIndex }
                    if (-not $registry.ContainsKey($mask)) {
                        throw 'Code Sequence tenth-order lost an ORIGINAL constituent position registry.'
                    }
                    if ($k -eq 4) { $quartetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 5) { $quintetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 6) { $sextetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 7) { $septetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 8) { $octetOrdinalList.Add($registry[$mask]) }
                    else { $nonetOrdinalList.Add($registry[$mask]) }
                }
            }
            $pairIndices = [int[]]@($pairOrdinalList.ToArray() | Sort-Object)
            $tripleIndices = [int[]]@($tripleOrdinalList.ToArray() | Sort-Object)
            $quartetIndices = [int[]]@($quartetOrdinalList.ToArray() | Sort-Object)
            $quintetIndices = [int[]]@($quintetOrdinalList.ToArray() | Sort-Object)
            $sextetIndices = [int[]]@($sextetOrdinalList.ToArray() | Sort-Object)
            $septetIndices = [int[]]@($septetOrdinalList.ToArray() | Sort-Object)
            $octetIndices = [int[]]@($octetOrdinalList.ToArray() | Sort-Object)
            $nonetIndices = [int[]]@($nonetOrdinalList.ToArray() | Sort-Object)
            # Use named entries to preserve each int[] as ONE registry; do
            # not accidentally unroll an array into separate ordinal checks.
            $levels = @(
                [pscustomobject]@{ Indices = $pairIndices; Expected = 45 },
                [pscustomobject]@{ Indices = $tripleIndices; Expected = 120 },
                [pscustomobject]@{ Indices = $quartetIndices; Expected = 210 },
                [pscustomobject]@{ Indices = $quintetIndices; Expected = 252 },
                [pscustomobject]@{ Indices = $sextetIndices; Expected = 210 },
                [pscustomobject]@{ Indices = $septetIndices; Expected = 120 },
                [pscustomobject]@{ Indices = $octetIndices; Expected = 45 },
                [pscustomobject]@{ Indices = $nonetIndices; Expected = 10 }
            )
            foreach ($level in $levels) {
                if ($level.Indices.Count -ne [int]$level.Expected -or
                    @($level.Indices | Select-Object -Unique).Count -ne [int]$level.Expected) {
                    throw 'Code Sequence tenth-order lost one of its 45/120/210/252/210/120/45/10 original ancestor sets.'
                }
            }
            $one = Get-CodeSequenceDecetWithholdingLayer -Rows $activeSingles -N $n -Positions $positions
            $gMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $false
            $oMax = Get-CodeSequencePairWithholdingGlobalMaximum -Single $one -Pair $emptyJoint `
                -Triple $emptyJoint -OriginalLocalOptima $true
            $g = [int]$gMax.distinct_family_count
            $o = [int]$oMax.distinct_family_count
            if ($one.genuine_total -ne 0 -or $one.original_local_optimum_total -ne 0 -or
                $one.genuine_registry_indices.Count -ne 0 -or
                $one.original_local_optimum_registry_indices.Count -ne 0 -or
                $g -ne 0 -or $o -ne 0 -or
                $gMax.all_attaining_family_index_sets.Count -ne 0 -or
                $oMax.all_attaining_family_index_sets.Count -ne 0) {
                throw 'Code Sequence tenth-order invented a 4-position witness in at most 2 surviving originals.'
            }
            $parentMinG = $baseG; $parentMinO = $baseO
            foreach ($si in $nonetIndices) {
                $parent = $parentNonets[$si - 1]
                if ([int]$parent.original_position_nonet_index -ne $si) {
                    throw 'Code Sequence tenth-order changed an original nonet parent ordinal.'
                }
                $parentMinG = [math]::Min($parentMinG,
                    [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                $parentMinO = [math]::Min($parentMinO,
                    [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                if ([long]$one.genuine_total -gt [long]$parent.surviving_original_independent_two_window_combinations -or
                    [long]$one.original_local_optimum_total -gt [long]$parent.surviving_original_full_selection_local_optimum_individual_packings) {
                    throw 'Code Sequence tenth-order fabricated more witnesses than an original nonet parent.'
                }
                Assert-CodeSequenceDecetWithholdingFamilySubset `
                    -Children $one.genuine_registry_indices -Parents $parent.independently_supported_family_indices `
                    -FamilyCount $familyCount
                Assert-CodeSequenceDecetWithholdingFamilySubset `
                    -Children $one.original_local_optimum_registry_indices -Parents $parent.original_local_optimum_family_indices `
                    -FamilyCount $familyCount
            }
            if ($g -gt [math]::Floor(($n - 10) / 4) -or
                $o -gt [math]::Floor(($n - 10) / 4) -or
                $g -gt $parentMinG -or $o -gt $parentMinO -or $o -gt $g -or $g -gt $baseG -or $o -gt $baseO) {
                throw 'Code Sequence tenth-order broke original-window capacity/monotonicity.'
            }
            $tenthOnlyG = Get-CodeSequenceDecetWithholdingTenthOnlyFamilyIndices `
                -Parents $parentNonets -NonetOrdinals $nonetIndices `
                -SurvivingFamilyIndices $one.genuine_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $false
            $tenthOnlyO = Get-CodeSequenceDecetWithholdingTenthOnlyFamilyIndices `
                -Parents $parentNonets -NonetOrdinals $nonetIndices `
                -SurvivingFamilyIndices $one.original_local_optimum_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $true
            if ($tenthOnlyG.Count -gt 0) { $familyOnlyG.Add($ordinal) }
            if ($tenthOnlyO.Count -gt 0) { $familyOnlyO.Add($ordinal) }
            $familyOnlyGEvents += $tenthOnlyG.Count
            $familyOnlyOEvents += $tenthOnlyO.Count
            $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
            $minimalTenthG = $reducedG -and $parentMinG -eq $baseG
            $minimalTenthO = $reducedO -and $parentMinO -eq $baseO
            $additionalG = [int]$parentMinG - $g
            $additionalO = [int]$parentMinO - $o
            if ($additionalG -lt 0 -or $additionalO -lt 0) {
                throw 'Code Sequence tenth-order increased capacity by withholding another original report.'
            }
            if ($reducedG) { $criticalG.Add($ordinal) }
            if ($reducedO) { $criticalO.Add($ordinal) }
            if ($minimalTenthG) { $minimalG.Add($ordinal) }
            if ($minimalTenthO) { $minimalO.Add($ordinal) }
            if ($additionalG -gt 0) { $extraG.Add($ordinal) }
            if ($additionalO -gt 0) { $extraO.Add($ordinal) }
            $flags = @{
                ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                MinimalG = [bool]$minimalTenthG; MinimalO = [bool]$minimalTenthO
                ExtraG = [bool]($additionalG -gt 0); ExtraO = [bool]($additionalO -gt 0)
            }
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $positionLedger -Indices $positions @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $pairLedger -Indices $pairIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $tripleLedger -Indices $tripleIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quartetLedger -Indices $quartetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $quintetLedger -Indices $quintetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $sextetLedger -Indices $sextetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $septetLedger -Indices $septetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $octetLedger -Indices $octetIndices -OneBased @flags
            Add-CodeSequenceQuartetWithholdingParticipation -Ledger $nonetLedger -Indices $nonetIndices -OneBased @flags
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
                original_position_decet_index = $ordinal
                withheld_original_caller_positions = $originalOneBased.ToArray()
                withheld_original_record_ids = $recordIds.ToArray()
                original_saved_profile_class_indices = $profileClasses.ToArray()
                original_constituent_position_pair_indices = $pairIndices
                original_constituent_position_triple_indices = $tripleIndices
                original_constituent_position_quartet_indices = $quartetIndices
                original_constituent_position_quintet_indices = $quintetIndices
                original_constituent_position_sextet_indices = $sextetIndices
                original_constituent_position_septet_indices = $septetIndices
                original_constituent_position_octet_indices = $octetIndices
                original_constituent_position_nonet_indices = $nonetIndices
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
                genuinely_tenth_order_only_lost_original_family_indices = $tenthOnlyG
                frozen_original_optimum_tenth_order_only_lost_original_family_indices = $tenthOnlyO
                jointly_compatible_original_local_optimum_family_pair_indices = [int[]]@()
                jointly_compatible_original_local_optimum_family_triple_indices = [int[]]@()
                globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                minimally_tenth_order_critical_for_original_independent_maximum = [bool]$minimalTenthG
                minimally_tenth_order_critical_for_original_local_optimum_maximum = [bool]$minimalTenthO
                strongest_constituent_nonet_independent_family_maximum = $parentMinG
                strongest_constituent_nonet_original_local_optimum_family_maximum = $parentMinO
                additional_independent_family_loss_beyond_stronger_nonet_exclusion = $additionalG
                additional_original_local_optimum_family_loss_beyond_stronger_nonet_exclusion = $additionalO
            })
            }
            }
            }
           }
          }
         }
        }
       }
      }
    }
    if ($ordinal -ne (Get-CodeSequenceDecetWithholdingChoose -N $n -K 10)) {
        throw 'Code Sequence tenth-order did not enumerate all canonical original ten-position combinations.'
    }

    $perPosition = [System.Collections.Generic.List[object]]::new()
    $perPair = [System.Collections.Generic.List[object]]::new()
    $perTriple = [System.Collections.Generic.List[object]]::new()
    $perQuartet = [System.Collections.Generic.List[object]]::new()
    $perQuintet = [System.Collections.Generic.List[object]]::new()
    $perSextet = [System.Collections.Generic.List[object]]::new()
    $perSeptet = [System.Collections.Generic.List[object]]::new()
    $perOctet = [System.Collections.Generic.List[object]]::new()
    $perNonet = [System.Collections.Generic.List[object]]::new()
    # Typed descriptor rows avoid PowerShell array-expression flattening when
    # one constituent level happens to be empty (N<level).
    $participation = @(
        [pscustomobject]@{ Ledger = $positionLedger; Output = $perPosition; Name = 'position'; Count = $n; Level = 1 },
        [pscustomobject]@{ Ledger = $pairLedger; Output = $perPair; Name = 'pair'; Count = $parentPairs.Count; Level = 2 },
        [pscustomobject]@{ Ledger = $tripleLedger; Output = $perTriple; Name = 'triple'; Count = $parentTriples.Count; Level = 3 },
        [pscustomobject]@{ Ledger = $quartetLedger; Output = $perQuartet; Name = 'quartet'; Count = $parentQuartets.Count; Level = 4 },
        [pscustomobject]@{ Ledger = $quintetLedger; Output = $perQuintet; Name = 'quintet'; Count = $parentQuintets.Count; Level = 5 },
        [pscustomobject]@{ Ledger = $sextetLedger; Output = $perSextet; Name = 'sextet'; Count = $parentSextets.Count; Level = 6 },
        [pscustomobject]@{ Ledger = $septetLedger; Output = $perSeptet; Name = 'septet'; Count = $parentSeptets.Count; Level = 7 },
        [pscustomobject]@{ Ledger = $octetLedger; Output = $perOctet; Name = 'octet'; Count = $parentOctets.Count; Level = 8 },
        [pscustomobject]@{ Ledger = $nonetLedger; Output = $perNonet; Name = 'nonet'; Count = $parentNonets.Count; Level = 9 }
    )
    foreach ($element in $participation) {
        $ledger = $element.Ledger; $output = $element.Output
        $name = [string]$element.Name; $count = [int]$element.Count; $level = [int]$element.Level
        for ($i = 0; $i -lt $count; $i++) {
            $originalPositions = if ($level -eq 1) { [int[]]@($i + 1) }
                elseif ($level -eq 2) { [int[]]$parentPairs[$i].withheld_original_caller_positions }
                elseif ($level -eq 3) { [int[]]$parentTriples[$i].withheld_original_caller_positions }
                elseif ($level -eq 4) { [int[]]$parentQuartets[$i].withheld_original_caller_positions }
                elseif ($level -eq 5) { [int[]]$parentQuintets[$i].withheld_original_caller_positions }
                elseif ($level -eq 6) { [int[]]$parentSextets[$i].withheld_original_caller_positions }
                elseif ($level -eq 7) { [int[]]$parentSeptets[$i].withheld_original_caller_positions }
                elseif ($level -eq 8) { [int[]]$parentOctets[$i].withheld_original_caller_positions }
                else { [int[]]$parentNonets[$i].withheld_original_caller_positions }
            $row = [ordered]@{
                original_constituent_type = $name
                original_constituent_index = $i + 1
                original_caller_positions = $originalPositions
                number_of_position_decets_containing_constituent = (Get-CodeSequenceDecetWithholdingChoose -N ($n - $level) -K (10 - $level))
                decets_reducing_original_independent_maximum = $ledger.criticalG[$i]
                decets_reducing_original_local_optimum_maximum = $ledger.criticalO[$i]
                minimally_tenth_order_critical_decets_for_original_independent_maximum = $ledger.minimalG[$i]
                minimally_tenth_order_critical_decets_for_original_local_optimum_maximum = $ledger.minimalO[$i]
                decets_with_additional_independent_loss_beyond_stronger_nonet = $ledger.extraG[$i]
                decets_with_additional_original_local_optimum_loss_beyond_stronger_nonet = $ledger.extraO[$i]
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
        $ledgers = @($positionLedger,$pairLedger,$tripleLedger,$quartetLedger,$quintetLedger,$sextetLedger,$septetLedger,$octetLedger,$nonetLedger)
        $expectedMemberships = [long[]]@(10,45,120,210,252,210,120,45,10)
        for ($level = 0; $level -lt $ledgers.Count; $level++) {
            $observed = [long]0
            foreach ($value in $ledgers[$level][$category]) { $observed += [long]$value }
            if ($observed -ne ([long]$matching * $expectedMemberships[$level])) {
                throw 'Code Sequence tenth-order broke exact 10/45/120/210/252/210/120/45/10 original participation conservation.'
            }
        }
    }
    return [ordered]@{
        scope = 'unordered_ten_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$NonetWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$NonetWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$NonetWithholding.anchor_index_in_anchor_journeys
        path = [string]$NonetWithholding.path
        exact_saved_quote_anchor = $NonetWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            unordered_original_position_decet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baseG
            original_global_maximum_original_locally_optimal_distinct_family_count = $baseO
            number_of_decets_reducing_original_independent_maximum = $criticalG.Count
            number_of_decets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_tenth_order_critical_decets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_tenth_order_critical_decets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_decets_with_additional_independent_loss_beyond_stronger_nonet = $extraG.Count
            number_of_decets_with_additional_original_local_optimum_loss_beyond_stronger_nonet = $extraO.Count
            number_of_decets_with_genuinely_tenth_order_only_original_family_loss = $familyOnlyG.Count
            number_of_decets_with_frozen_original_optimum_tenth_order_only_family_loss = $familyOnlyO.Count
            genuine_tenth_order_only_original_family_loss_events = $familyOnlyGEvents
            frozen_original_optimum_tenth_order_only_family_loss_events = $familyOnlyOEvents
            minimum_global_independent_family_maximum_after_ten_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_ten_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_ten_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_ten_withheld_positions = $maxO
        }
        original_position_decet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_decet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_tenth_order_critical_decet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_tenth_order_critical_decet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        decet_indices_causing_additional_independent_loss_vs_stronger_nonet = $extraG.ToArray()
        decet_indices_causing_additional_original_local_optimum_loss_vs_stronger_nonet = $extraO.ToArray()
        decet_indices_with_genuinely_tenth_order_only_original_family_loss = $familyOnlyG.ToArray()
        decet_indices_with_frozen_original_optimum_tenth_order_only_family_loss = $familyOnlyO.ToArray()
        ordered_original_position_decet_withholding = $rows.ToArray()
        ordered_original_position_decet_participation = $perPosition.ToArray()
        ordered_original_pair_decet_participation = $perPair.ToArray()
        ordered_original_triple_decet_participation = $perTriple.ToArray()
        ordered_original_quartet_decet_participation = $perQuartet.ToArray()
        ordered_original_quintet_decet_participation = $perQuintet.ToArray()
        ordered_original_sextet_decet_participation = $perSextet.ToArray()
        ordered_original_septet_decet_participation = $perSeptet.ToArray()
        ordered_original_octet_decet_participation = $perOctet.ToArray()
        ordered_original_nonet_decet_participation = $perNonet.ToArray()
        complete_original_ec067_nonet_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        no_original_window_resequencing_or_new_adjacency = $true
        original_full_selection_local_optima_frozen_not_reoptimized = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_finding_historical_order_defect_recurrence_fix_regression_or_causality_proven = $false
    }
}


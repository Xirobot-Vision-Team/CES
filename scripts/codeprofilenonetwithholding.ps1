#requires -Version 7.0
<#
    EC-067: NINE simultaneous exclusions of ORIGINAL caller report positions.
    Work only from the EC-060 reconciled PRIVATE union-mask witness histograms,
    with EC-056 original full-selection optimum packs kept frozen. The selected
    record order is NOT a chronology; never stitch removed-position neighbors,
    authenticate identity of a defect, or mutate any repository or saved record.
#>

function Get-CodeSequenceNonetWithholdingChoose {
    param([int] $N, [int] $K)
    if ($N -lt 0 -or $K -lt 0 -or $K -gt $N) { return 0 }
    $result = [long]1
    for ($i = 1; $i -le $K; $i++) {
        $result = [long](($result * ($N - $i + 1)) / $i)
    }
    return [int]$result
}

function Get-CodeSequenceNonetWithholdingMask {
    param([int[]] $Positions, [int] $N)
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $Positions -or
        $Positions.Count -lt 4 -or $Positions.Count -gt 9) {
        throw 'Code Sequence ninth-order position masks require four through nine ORIGINAL positions.'
    }
    $mask = 0
    $last = -1
    foreach ($position in $Positions) {
        if ($position -le $last -or $position -lt 0 -or $position -ge $N) {
            throw 'Code Sequence ninth-order masks require strictly ascending original caller positions.'
        }
        $mask = $mask -bor (1 -shl $position)
        $last = $position
    }
    return [int]$mask
}

function Get-CodeSequenceNonetWithholdingRemainingCount {
    param([object] $Aggregate, [int] $N, [int[]] $Positions)
    if ($Positions.Count -ne 9) {
        throw 'Code Sequence ninth-order evidence projection requires nine ORIGINAL positions.'
    }
    $excludedMask = Get-CodeSequenceNonetWithholdingMask -Positions $Positions -N $N
    $masks = [int[]]$Aggregate.nonzero_original_union_masks
    $weights = [long[]]$Aggregate.nonzero_original_union_mask_multiplicities
    $singles = [long[]]$Aggregate.original_position_inclusion_counts
    $pairs = [long[]]$Aggregate.original_pair_intersection_counts
    $total = [long]$Aggregate.original_combination_count
    if ($masks.Count -ne $weights.Count -or $singles.Count -ne $N -or
        $pairs.Count -ne ($N * $N) -or $total -lt 0) {
        throw 'Code Sequence ninth-order withholding lacks conserved original EC-060 evidence.'
    }
    # Bucket each ORIGINAL witness by exactly which excluded original slots it
    # covers, retaining source multiplicity. A superset zeta transform then
    # yields ALL 511 true intersection totals in 9*256 additions instead of
    # iterating 511 subsets for each witness. Nothing is inferred from parents.
    $intersections = [long[]]::new(512)
    $direct = [long]0
    $conserved = [long]0
    for ($i = 0; $i -lt $masks.Count; $i++) {
        $mask = [int]$masks[$i]
        $multiplicity = [long]$weights[$i]
        if ($mask -le 0 -or $mask -ge (1 -shl $N) -or $multiplicity -le 0) {
            throw 'Code Sequence ninth-order withholding found an invalid original union mask.'
        }
        # A true independent two-window witness needs >=4 disjoint original
        # positions. Excluding 9 of N<=12 leaves only 0..3 original slots.
        $footprint = 0
        $work = $mask
        while ($work -gt 0) { $footprint += ($work -band 1); $work = $work -shr 1 }
        if ($footprint -lt 4) {
            throw 'Code Sequence ninth-order found fabricated independent evidence using fewer than four originals.'
        }
        $conserved += $multiplicity
        if (($mask -band $excludedMask) -eq 0) { $direct += $multiplicity }
        $covered = 0
        for ($bit = 0; $bit -lt 9; $bit++) {
            if (($mask -band (1 -shl $Positions[$bit])) -ne 0) {
                $covered = $covered -bor (1 -shl $bit)
            }
        }
        $intersections[$covered] += $multiplicity
    }
    if ($conserved -ne $total) {
        throw 'Code Sequence ninth-order withholding altered original witness multiplicities.'
    }
    for ($bit = 0; $bit -lt 9; $bit++) {
        $bitMask = 1 -shl $bit
        for ($subset = 0; $subset -lt 512; $subset++) {
            if (($subset -band $bitMask) -eq 0) {
                $intersections[$subset] += $intersections[$subset -bor $bitMask]
            }
        }
    }
    if ($intersections[0] -ne $total) {
        throw 'Code Sequence ninth-order intersection reconstruction lost original weighted evidence.'
    }
    # T - sum(I1) + sum(I2) - sum(I3) + ... + sum(I8) - I9.
    # Independently reconcile EVERY first and second intersection with the
    # saved EC-060 margins, not just the total or the final zero bound.
    $byInclusionExclusion = $total
    for ($subset = 1; $subset -lt 512; $subset++) {
        $size = 0
        $first = -1; $second = -1
        for ($bit = 0; $bit -lt 9; $bit++) {
            if (($subset -band (1 -shl $bit)) -ne 0) {
                if ($size -eq 0) { $first = $Positions[$bit] }
                elseif ($size -eq 1) { $second = $Positions[$bit] }
                $size++
            }
        }
        $value = [long]$intersections[$subset]
        if ($size -eq 1) {
            if ($value -ne [long]$singles[$first]) {
                throw 'Code Sequence ninth-order disagrees with an original position marginal.'
            }
            $value = [long]$singles[$first]
        } elseif ($size -eq 2) {
            if ($value -ne [long]$pairs[($first * $N) + $second]) {
                throw 'Code Sequence ninth-order disagrees with an original pair intersection.'
            }
            $value = [long]$pairs[($first * $N) + $second]
        }
        if (($size % 2) -eq 1) { $byInclusionExclusion -= $value }
        else { $byInclusionExclusion += $value }
    }
    if ($direct -ne $byInclusionExclusion -or $direct -ne 0) {
        throw 'Code Sequence ninth-order direct/exact original-mask survival or 3-slot capacity failed.'
    }
    return [long]$direct
}

function Get-CodeSequenceNonetWithholdingLayer {
    param([object[]] $Rows, [int] $N, [int[]] $Positions)
    $genuineTotal = [long]0
    $frozenTotal = [long]0
    $genuineIndices = [System.Collections.Generic.List[int]]::new()
    $frozenIndices = [System.Collections.Generic.List[int]]::new()
    $genuineSets = [System.Collections.Generic.List[object]]::new()
    $frozenSets = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $g = Get-CodeSequenceNonetWithholdingRemainingCount -Aggregate $row.genuine -N $N -Positions $Positions
        $o = Get-CodeSequenceNonetWithholdingRemainingCount -Aggregate $row.original_local_optima -N $N -Positions $Positions
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

function Assert-CodeSequenceNonetWithholdingParent {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $SeptetWithholding,
        [object] $OctetWithholding, [object] $WitnessAggregates)
    # Replay and compare the COMPLETE EC-066 octet output, including its
    # earlier full EC-065, EC-064 ... EC-060 parent reconciliation chain.
    $replayed = Get-CodeSequenceOriginalFindingPairProfileOctetPositionWithholding `
        -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -SextetWithholding $SextetWithholding `
        -SeptetWithholding $SeptetWithholding -WitnessAggregates $WitnessAggregates
    $expected = ConvertTo-Json -InputObject $replayed -Depth 80 -Compress
    $actual = ConvertTo-Json -InputObject $OctetWithholding -Depth 80 -Compress
    if ($expected -cne $actual) {
        throw 'Code Sequence ninth-order view differs from the COMPLETE original EC-066 octet output.'
    }
}

function Get-CodeSequenceNonetWithholdingNinthOnlyFamilyIndices {
    param([object[]] $Parents, [int[]] $OctetOrdinals,
        [int[]] $SurvivingFamilyIndices, [int] $FamilyCount, [bool] $OriginalLocalOptima)
    if ($OctetOrdinals.Count -ne 9) {
        throw 'Code Sequence ninth-order original-family loss requires all nine octet parents.'
    }
    $commonFamilies = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt 9; $i++) {
        $ordinal = [int]$OctetOrdinals[$i]
        if ($ordinal -lt 1 -or $ordinal -gt $Parents.Count -or
            [int]$Parents[$ordinal - 1].original_position_octet_index -ne $ordinal) {
            throw 'Code Sequence ninth-order loss lost a genuine original octet ancestor.'
        }
        $parent = $Parents[$ordinal - 1]
        $candidateIndices = if ($OriginalLocalOptima) {
            [int[]]$parent.original_local_optimum_family_indices
        } else { [int[]]$parent.independently_supported_family_indices }
        $set = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($candidate in $candidateIndices) {
            if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $set.Add($candidate)) {
                throw 'Code Sequence ninth-order family loss found an invalid original ancestor registry.'
            }
        }
        if ($i -eq 0) { $commonFamilies.UnionWith($set) }
        else { $commonFamilies.IntersectWith($set) }
    }
    foreach ($candidate in $SurvivingFamilyIndices) { [void]$commonFamilies.Remove($candidate) }
    $answer = [int[]]@($commonFamilies | Sort-Object)
    return ,$answer
}

function Assert-CodeSequenceNonetWithholdingFamilySubset {
    param([int[]] $Children, [int[]] $Parents, [int] $FamilyCount)
    $allowed = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($candidate in $Parents) {
        if ($candidate -lt 1 -or $candidate -gt $FamilyCount -or -not $allowed.Add($candidate)) {
            throw 'Code Sequence ninth-order family subset found an invalid original octet registry.'
        }
    }
    foreach ($candidate in $Children) {
        if (-not $allowed.Contains($candidate)) {
            throw 'Code Sequence ninth-order family witness was fabricated across removed positions.'
        }
    }
}

function Get-CodeSequenceNonetWithholdingAncestorRegistry {
    param([object[]] $Rows, [int] $N, [int] $K, [string] $OrdinalName)
    $result = [System.Collections.Generic.Dictionary[int,int]]::new()
    if ($Rows.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $N -K $K)) {
        throw 'Code Sequence ninth-order ancestry does not cover every original parent position set.'
    }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        if ([int]$row.$OrdinalName -ne ($i + 1)) {
            throw 'Code Sequence ninth-order ancestor index is not in canonical original order.'
        }
        $positions = [int[]]@($row.withheld_original_caller_positions | ForEach-Object { [int]$_ - 1 })
        if ($positions.Count -ne $K) {
            throw 'Code Sequence ninth-order ancestor lost its original position cardinality.'
        }
        $mask = Get-CodeSequenceNonetWithholdingMask -Positions $positions -N $N
        if ($result.ContainsKey($mask)) {
            throw 'Code Sequence ninth-order ancestor registry has duplicate original position sets.'
        }
        $result.Add($mask, $i + 1)
    }
    return ,$result
}

function Get-CodeSequenceOriginalFindingPairProfileNonetPositionWithholding {
    param([object] $Atlas, [object] $PairWithholding, [object] $TripleWithholding,
        [object] $QuartetWithholding, [object] $QuintetWithholding,
        [object] $SextetWithholding, [object] $SeptetWithholding,
        [object] $OctetWithholding, [object] $WitnessAggregates)
    if ($null -eq $Atlas -or $null -eq $PairWithholding -or $null -eq $TripleWithholding -or
        $null -eq $QuartetWithholding -or $null -eq $QuintetWithholding -or
        $null -eq $SextetWithholding -or $null -eq $SeptetWithholding -or $null -eq $OctetWithholding -or
        $null -eq $WitnessAggregates -or
        $OctetWithholding.scope -cne 'unordered_eight_original_report_position_withholding_exact_original_witness_survival_no_resequencing' -or
        $WitnessAggregates.scope -cne 'ec060_reconciled_private_original_union_mask_witness_histograms' -or
        -not [bool]$OctetWithholding.complete_original_ec065_septet_projections_and_private_witness_masks_reconciled -or
        -not [bool]$OctetWithholding.independent_of_sequence_top -or
        -not [bool]$OctetWithholding.two_original_finding_journeys_remain_independent) {
        throw 'Code Sequence ninth-order view requires fully reconciled original EC-066 octets.'
    }
    $n = [int]$OctetWithholding.counts.selected_report_positions
    $familyCount = [int]$OctetWithholding.counts.original_maximal_repeat_family_count
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
    $baseG = [int]$OctetWithholding.counts.original_global_maximum_independently_supported_distinct_family_count
    $baseO = [int]$OctetWithholding.counts.original_global_maximum_original_locally_optimal_distinct_family_count
    if ($n -lt 2 -or $n -gt 12 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $familyCount -lt 0 -or $familyCount -gt 66 -or
        $records.Count -ne $n -or $classes.Count -ne $n -or $singles.Count -ne $familyCount -or
        $pairs.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $familyCount -K 2) -or
        $triples.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $familyCount -K 3) -or
        $parentPairs.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 2) -or
        $parentTriples.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 3) -or
        $parentQuartets.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 4) -or
        $parentQuintets.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 5) -or
        $parentSextets.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 6) -or
        $parentSeptets.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 7) -or
        $parentOctets.Count -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 8) -or
        $baseG -lt 0 -or $baseG -gt 3 -or $baseO -lt 0 -or $baseO -gt $baseG) {
        throw 'Code Sequence ninth-order ancestry or original witness counts are inconsistent.'
    }
    Assert-CodeSequenceNonetWithholdingParent -Atlas $Atlas -PairWithholding $PairWithholding `
        -TripleWithholding $TripleWithholding -QuartetWithholding $QuartetWithholding `
        -QuintetWithholding $QuintetWithholding -SextetWithholding $SextetWithholding `
        -SeptetWithholding $SeptetWithholding -OctetWithholding $OctetWithholding `
        -WitnessAggregates $WitnessAggregates
    $activeSingles = Get-CodeSequenceQuintetWithholdingActiveRows -Rows $singles
    # Four mutually nonoverlapping original windows across two different
    # families need at least EIGHT positions; three families need TWELVE.
    # Nine exclusions from N<=12 leave at most THREE original positions.
    # Validate original footprints before relying on the impossibility bound.
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $pairs -MinimumOriginalPositions 8
    Assert-CodeSequenceQuintetWithholdingMaskCapacity -Rows $triples -MinimumOriginalPositions 12
    $emptyJoint = Get-CodeSequenceQuintetWithholdingEmptyJointLayer
    $quartetIndex = Get-CodeSequenceNonetWithholdingAncestorRegistry -Rows $parentQuartets `
        -N $n -K 4 -OrdinalName 'original_position_quartet_index'
    $quintetIndex = Get-CodeSequenceNonetWithholdingAncestorRegistry -Rows $parentQuintets `
        -N $n -K 5 -OrdinalName 'original_position_quintet_index'
    $sextetIndex = Get-CodeSequenceNonetWithholdingAncestorRegistry -Rows $parentSextets `
        -N $n -K 6 -OrdinalName 'original_position_sextet_index'
    $septetIndex = Get-CodeSequenceNonetWithholdingAncestorRegistry -Rows $parentSeptets `
        -N $n -K 7 -OrdinalName 'original_position_septet_index'
    $octetIndex = Get-CodeSequenceNonetWithholdingAncestorRegistry -Rows $parentOctets `
        -N $n -K 8 -OrdinalName 'original_position_octet_index'

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
    $minG = $null; $maxG = $null; $minO = $null; $maxO = $null
    if ($n -ge 9) { $minG = $baseG; $minO = $baseO; $maxG = 0; $maxO = 0 }
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
            $ordinal++
            $positions = [int[]]@($a,$b,$c,$d,$e,$f,$h,$i,$j)
            $pairOrdinalList = [System.Collections.Generic.List[int]]::new()
            $tripleOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quartetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $quintetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $sextetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $septetOrdinalList = [System.Collections.Generic.List[int]]::new()
            $octetOrdinalList = [System.Collections.Generic.List[int]]::new()
            # Recover all GENUINE original parent ordinals. Removing positions
            # does not reindex a report or create any new observed motif step.
            for ($subset = 1; $subset -lt 512; $subset++) {
                $selected = [System.Collections.Generic.List[int]]::new()
                for ($bit = 0; $bit -lt 9; $bit++) {
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
                } elseif ($k -ge 4 -and $k -le 8) {
                    $mask = Get-CodeSequenceNonetWithholdingMask -Positions ($selected.ToArray()) -N $n
                    $registry = if ($k -eq 4) { $quartetIndex }
                        elseif ($k -eq 5) { $quintetIndex }
                        elseif ($k -eq 6) { $sextetIndex }
                        elseif ($k -eq 7) { $septetIndex }
                        else { $octetIndex }
                    if (-not $registry.ContainsKey($mask)) {
                        throw 'Code Sequence ninth-order lost an ORIGINAL constituent position registry.'
                    }
                    if ($k -eq 4) { $quartetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 5) { $quintetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 6) { $sextetOrdinalList.Add($registry[$mask]) }
                    elseif ($k -eq 7) { $septetOrdinalList.Add($registry[$mask]) }
                    else { $octetOrdinalList.Add($registry[$mask]) }
                }
            }
            $pairIndices = [int[]]@($pairOrdinalList.ToArray() | Sort-Object)
            $tripleIndices = [int[]]@($tripleOrdinalList.ToArray() | Sort-Object)
            $quartetIndices = [int[]]@($quartetOrdinalList.ToArray() | Sort-Object)
            $quintetIndices = [int[]]@($quintetOrdinalList.ToArray() | Sort-Object)
            $sextetIndices = [int[]]@($sextetOrdinalList.ToArray() | Sort-Object)
            $septetIndices = [int[]]@($septetOrdinalList.ToArray() | Sort-Object)
            $octetIndices = [int[]]@($octetOrdinalList.ToArray() | Sort-Object)
            # Use named entries to preserve each int[] as ONE registry; do
            # not accidentally unroll an array into separate ordinal checks.
            $levels = @(
                [pscustomobject]@{ Indices = $pairIndices; Expected = 36 },
                [pscustomobject]@{ Indices = $tripleIndices; Expected = 84 },
                [pscustomobject]@{ Indices = $quartetIndices; Expected = 126 },
                [pscustomobject]@{ Indices = $quintetIndices; Expected = 126 },
                [pscustomobject]@{ Indices = $sextetIndices; Expected = 84 },
                [pscustomobject]@{ Indices = $septetIndices; Expected = 36 },
                [pscustomobject]@{ Indices = $octetIndices; Expected = 9 }
            )
            foreach ($level in $levels) {
                if ($level.Indices.Count -ne [int]$level.Expected -or
                    @($level.Indices | Select-Object -Unique).Count -ne [int]$level.Expected) {
                    throw 'Code Sequence ninth-order lost one of its 36/84/126/126/84/36/9 original ancestor sets.'
                }
            }
            $one = Get-CodeSequenceNonetWithholdingLayer -Rows $activeSingles -N $n -Positions $positions
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
                throw 'Code Sequence ninth-order invented a 4-position witness in at most 3 surviving originals.'
            }
            $parentMinG = $baseG; $parentMinO = $baseO
            foreach ($si in $octetIndices) {
                $parent = $parentOctets[$si - 1]
                if ([int]$parent.original_position_octet_index -ne $si) {
                    throw 'Code Sequence ninth-order changed an original octet parent ordinal.'
                }
                $parentMinG = [math]::Min($parentMinG,
                    [int]$parent.globally_maximum_simultaneously_independently_supported_distinct_family_count)
                $parentMinO = [math]::Min($parentMinO,
                    [int]$parent.globally_maximum_simultaneously_original_locally_optimal_distinct_family_count)
                if ([long]$one.genuine_total -gt [long]$parent.surviving_original_independent_two_window_combinations -or
                    [long]$one.original_local_optimum_total -gt [long]$parent.surviving_original_full_selection_local_optimum_individual_packings) {
                    throw 'Code Sequence ninth-order fabricated more witnesses than an original octet parent.'
                }
                Assert-CodeSequenceNonetWithholdingFamilySubset `
                    -Children $one.genuine_registry_indices -Parents $parent.independently_supported_family_indices `
                    -FamilyCount $familyCount
                Assert-CodeSequenceNonetWithholdingFamilySubset `
                    -Children $one.original_local_optimum_registry_indices -Parents $parent.original_local_optimum_family_indices `
                    -FamilyCount $familyCount
            }
            if ($g -gt [math]::Floor(($n - 9) / 4) -or
                $o -gt [math]::Floor(($n - 9) / 4) -or
                $g -gt $parentMinG -or $o -gt $parentMinO -or $o -gt $g -or $g -gt $baseG -or $o -gt $baseO) {
                throw 'Code Sequence ninth-order broke original-window capacity/monotonicity.'
            }
            $ninthOnlyG = Get-CodeSequenceNonetWithholdingNinthOnlyFamilyIndices `
                -Parents $parentOctets -OctetOrdinals $octetIndices `
                -SurvivingFamilyIndices $one.genuine_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $false
            $ninthOnlyO = Get-CodeSequenceNonetWithholdingNinthOnlyFamilyIndices `
                -Parents $parentOctets -OctetOrdinals $octetIndices `
                -SurvivingFamilyIndices $one.original_local_optimum_registry_indices -FamilyCount $familyCount `
                -OriginalLocalOptima $true
            if ($ninthOnlyG.Count -gt 0) { $familyOnlyG.Add($ordinal) }
            if ($ninthOnlyO.Count -gt 0) { $familyOnlyO.Add($ordinal) }
            $familyOnlyGEvents += $ninthOnlyG.Count
            $familyOnlyOEvents += $ninthOnlyO.Count
            $reducedG = $g -lt $baseG; $reducedO = $o -lt $baseO
            $minimalNinthG = $reducedG -and $parentMinG -eq $baseG
            $minimalNinthO = $reducedO -and $parentMinO -eq $baseO
            $additionalG = [int]$parentMinG - $g
            $additionalO = [int]$parentMinO - $o
            if ($additionalG -lt 0 -or $additionalO -lt 0) {
                throw 'Code Sequence ninth-order increased capacity by withholding another original report.'
            }
            if ($reducedG) { $criticalG.Add($ordinal) }
            if ($reducedO) { $criticalO.Add($ordinal) }
            if ($minimalNinthG) { $minimalG.Add($ordinal) }
            if ($minimalNinthO) { $minimalO.Add($ordinal) }
            if ($additionalG -gt 0) { $extraG.Add($ordinal) }
            if ($additionalO -gt 0) { $extraO.Add($ordinal) }
            $flags = @{
                ReducedG = [bool]$reducedG; ReducedO = [bool]$reducedO
                MinimalG = [bool]$minimalNinthG; MinimalO = [bool]$minimalNinthO
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
                original_position_nonet_index = $ordinal
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
                genuinely_ninth_order_only_lost_original_family_indices = $ninthOnlyG
                frozen_original_optimum_ninth_order_only_lost_original_family_indices = $ninthOnlyO
                jointly_compatible_original_local_optimum_family_pair_indices = [int[]]@()
                jointly_compatible_original_local_optimum_family_triple_indices = [int[]]@()
                globally_maximum_simultaneously_independently_supported_distinct_family_count = $g
                all_attaining_family_index_sets = $gMax.all_attaining_family_index_sets
                reduces_original_global_maximum_independent_family_count = [bool]$reducedG
                globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $o
                all_attaining_original_local_optimum_family_index_sets = $oMax.all_attaining_family_index_sets
                reduces_original_global_maximum_original_local_optimum_family_count = [bool]$reducedO
                minimally_ninth_order_critical_for_original_independent_maximum = [bool]$minimalNinthG
                minimally_ninth_order_critical_for_original_local_optimum_maximum = [bool]$minimalNinthO
                strongest_constituent_octet_independent_family_maximum = $parentMinG
                strongest_constituent_octet_original_local_optimum_family_maximum = $parentMinO
                additional_independent_family_loss_beyond_stronger_octet_exclusion = $additionalG
                additional_original_local_optimum_family_loss_beyond_stronger_octet_exclusion = $additionalO
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
    if ($ordinal -ne (Get-CodeSequenceNonetWithholdingChoose -N $n -K 9)) {
        throw 'Code Sequence ninth-order did not enumerate all canonical original nine-position combinations.'
    }

    $perPosition = [System.Collections.Generic.List[object]]::new()
    $perPair = [System.Collections.Generic.List[object]]::new()
    $perTriple = [System.Collections.Generic.List[object]]::new()
    $perQuartet = [System.Collections.Generic.List[object]]::new()
    $perQuintet = [System.Collections.Generic.List[object]]::new()
    $perSextet = [System.Collections.Generic.List[object]]::new()
    $perSeptet = [System.Collections.Generic.List[object]]::new()
    $perOctet = [System.Collections.Generic.List[object]]::new()
    $participation = @(
        @($positionLedger,$perPosition,'position',$n,1),
        @($pairLedger,$perPair,'pair',$parentPairs.Count,2),
        @($tripleLedger,$perTriple,'triple',$parentTriples.Count,3),
        @($quartetLedger,$perQuartet,'quartet',$parentQuartets.Count,4),
        @($quintetLedger,$perQuintet,'quintet',$parentQuintets.Count,5),
        @($sextetLedger,$perSextet,'sextet',$parentSextets.Count,6),
        @($septetLedger,$perSeptet,'septet',$parentSeptets.Count,7),
        @($octetLedger,$perOctet,'octet',$parentOctets.Count,8)
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
                elseif ($level -eq 6) { [int[]]$parentSextets[$i].withheld_original_caller_positions }
                elseif ($level -eq 7) { [int[]]$parentSeptets[$i].withheld_original_caller_positions }
                else { [int[]]$parentOctets[$i].withheld_original_caller_positions }
            $row = [ordered]@{
                original_constituent_type = $name
                original_constituent_index = $i + 1
                original_caller_positions = $originalPositions
                number_of_position_nonets_containing_constituent = (Get-CodeSequenceNonetWithholdingChoose -N ($n - $level) -K (9 - $level))
                nonets_reducing_original_independent_maximum = $ledger.criticalG[$i]
                nonets_reducing_original_local_optimum_maximum = $ledger.criticalO[$i]
                minimally_ninth_order_critical_nonets_for_original_independent_maximum = $ledger.minimalG[$i]
                minimally_ninth_order_critical_nonets_for_original_local_optimum_maximum = $ledger.minimalO[$i]
                nonets_with_additional_independent_loss_beyond_stronger_octet = $ledger.extraG[$i]
                nonets_with_additional_original_local_optimum_loss_beyond_stronger_octet = $ledger.extraO[$i]
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
        $ledgers = @($positionLedger,$pairLedger,$tripleLedger,$quartetLedger,$quintetLedger,$sextetLedger,$septetLedger,$octetLedger)
        $expectedMemberships = [long[]]@(9,36,84,126,126,84,36,9)
        for ($level = 0; $level -lt $ledgers.Count; $level++) {
            $observed = [long]0
            foreach ($value in $ledgers[$level][$category]) { $observed += [long]$value }
            if ($observed -ne ([long]$matching * $expectedMemberships[$level])) {
                throw 'Code Sequence ninth-order broke exact 9/36/84/126/126/84/36/9 original participation conservation.'
            }
        }
    }
    return [ordered]@{
        scope = 'unordered_nine_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$OctetWithholding.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$OctetWithholding.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$OctetWithholding.anchor_index_in_anchor_journeys
        path = [string]$OctetWithholding.path
        exact_saved_quote_anchor = $OctetWithholding.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            unordered_original_position_nonet_count = $ordinal
            original_global_maximum_independently_supported_distinct_family_count = $baseG
            original_global_maximum_original_locally_optimal_distinct_family_count = $baseO
            number_of_nonets_reducing_original_independent_maximum = $criticalG.Count
            number_of_nonets_reducing_original_local_optimum_maximum = $criticalO.Count
            number_of_minimally_ninth_order_critical_nonets_for_original_independent_maximum = $minimalG.Count
            number_of_minimally_ninth_order_critical_nonets_for_original_local_optimum_maximum = $minimalO.Count
            number_of_nonets_with_additional_independent_loss_beyond_stronger_octet = $extraG.Count
            number_of_nonets_with_additional_original_local_optimum_loss_beyond_stronger_octet = $extraO.Count
            number_of_nonets_with_genuinely_ninth_order_only_original_family_loss = $familyOnlyG.Count
            number_of_nonets_with_frozen_original_optimum_ninth_order_only_family_loss = $familyOnlyO.Count
            genuine_ninth_order_only_original_family_loss_events = $familyOnlyGEvents
            frozen_original_optimum_ninth_order_only_family_loss_events = $familyOnlyOEvents
            minimum_global_independent_family_maximum_after_nine_withheld_positions = $minG
            maximum_global_independent_family_maximum_after_nine_withheld_positions = $maxG
            minimum_global_original_local_optimum_family_maximum_after_nine_withheld_positions = $minO
            maximum_global_original_local_optimum_family_maximum_after_nine_withheld_positions = $maxO
        }
        original_position_nonet_indices_reducing_independent_maximum = $criticalG.ToArray()
        original_position_nonet_indices_reducing_original_local_optimum_maximum = $criticalO.ToArray()
        minimally_ninth_order_critical_nonet_indices_for_independent_maximum = $minimalG.ToArray()
        minimally_ninth_order_critical_nonet_indices_for_original_local_optimum_maximum = $minimalO.ToArray()
        nonet_indices_causing_additional_independent_loss_vs_stronger_octet = $extraG.ToArray()
        nonet_indices_causing_additional_original_local_optimum_loss_vs_stronger_octet = $extraO.ToArray()
        nonet_indices_with_genuinely_ninth_order_only_original_family_loss = $familyOnlyG.ToArray()
        nonet_indices_with_frozen_original_optimum_ninth_order_only_family_loss = $familyOnlyO.ToArray()
        ordered_original_position_nonet_withholding = $rows.ToArray()
        ordered_original_position_nonet_participation = $perPosition.ToArray()
        ordered_original_pair_nonet_participation = $perPair.ToArray()
        ordered_original_triple_nonet_participation = $perTriple.ToArray()
        ordered_original_quartet_nonet_participation = $perQuartet.ToArray()
        ordered_original_quintet_nonet_participation = $perQuintet.ToArray()
        ordered_original_sextet_nonet_participation = $perSextet.ToArray()
        ordered_original_septet_nonet_participation = $perSeptet.ToArray()
        ordered_original_octet_nonet_participation = $perOctet.ToArray()
        complete_original_ec066_octet_projections_and_private_witness_masks_reconciled = $true
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        no_original_window_resequencing_or_new_adjacency = $true
        original_full_selection_local_optima_frozen_not_reoptimized = $true
        source_git_network_reads_or_business_worktree_writes = $false
        semantic_same_real_finding_historical_order_defect_recurrence_fix_regression_or_causality_proven = $false
    }
}


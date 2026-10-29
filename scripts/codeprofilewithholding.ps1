#requires -Version 7.0
<#
    EC-059: exact single-original-position evidence withholding, retaining
    the existing EC-054 observed windows and EC-056 full-selection maxima.
    This is NOT a re-sequencing of saved reports: removing a position does
    not create an adjacent window between its former neighbors. Each result
    counts only original, independently verified 1/2/3-family witnesses.
    Original EC-056 local optimum packings are deliberately frozen; they are
    not silently re-optimized against a shorter counterfactual selection.
#>

function Get-CodeSequenceWithholdingMaskAggregate {
    param(
        [object[]] $MasksByFamily,
        [int[]] $FamilyIndices,
        [int] $PositionCount,
        [switch] $IncludeMaskHistogram
    )
    if ($PositionCount -lt 2 -or $PositionCount -gt 12 -or
        $FamilyIndices.Count -lt 1 -or $FamilyIndices.Count -gt 3) {
        throw 'Code Sequence withholding witness shape is outside N=2..12, family cardinality 1..3.'
    }
    $maskLimit = 1 -shl $PositionCount
    $histogram = [long[]]::new($maskLimit)
    $nonzeroMasks = [System.Collections.Generic.List[int]]::new()
    $first = [int[]]$MasksByFamily[$FamilyIndices[0] - 1]
    if ($FamilyIndices.Count -eq 1) {
        foreach ($a in $first) {
            if ($a -le 0 -or $a -ge $maskLimit) { throw 'Code Sequence withholding saw an out-of-range witness mask.' }
            if ($histogram[$a] -eq 0) { $nonzeroMasks.Add($a) }
            $histogram[$a]++
        }
    } elseif ($FamilyIndices.Count -eq 2) {
        $second = [int[]]$MasksByFamily[$FamilyIndices[1] - 1]
        foreach ($a in $first) {
            foreach ($b in $second) {
                if (($a -band $b) -eq 0) {
                    $union = $a -bor $b
                    if ($histogram[$union] -eq 0) { $nonzeroMasks.Add($union) }
                    $histogram[$union]++
                }
            }
        }
    } else {
        $second = [int[]]$MasksByFamily[$FamilyIndices[1] - 1]
        $third = [int[]]$MasksByFamily[$FamilyIndices[2] - 1]
        foreach ($a in $first) {
            foreach ($b in $second) {
                if (($a -band $b) -ne 0) { continue }
                $ab = $a -bor $b
                foreach ($c in $third) {
                    if (($ab -band $c) -eq 0) {
                        $union = $ab -bor $c
                        if ($histogram[$union] -eq 0) { $nonzeroMasks.Add($union) }
                        $histogram[$union]++
                    }
                }
            }
        }
    }
    $total = [long]0
    $covered = [long[]]::new($PositionCount)
    foreach ($mask in $nonzeroMasks) {
        $multiplicity = $histogram[$mask]
        if ($multiplicity -eq 0) { continue }
        $total += $multiplicity
        for ($pos = 0; $pos -lt $PositionCount; $pos++) {
            if (($mask -band (1 -shl $pos)) -ne 0) {
                $covered[$pos] += $multiplicity
            }
        }
    }
    if ($histogram[0] -ne 0) { throw 'Code Sequence withholding admitted a zero-position witness.' }
    $result = [ordered]@{
        combination_count = $total
        original_position_witness_inclusion_counts = $covered
    }
    # EC-060: optional PRIVATE exact original-position union mask histogram.
    # Legacy EC-059 callers still receive their identical two-field aggregate.
    if ($IncludeMaskHistogram) {
        $result['nonzero_original_position_union_masks'] = $nonzeroMasks.ToArray()
        $result['multiplicity_by_original_position_union_mask'] = $histogram
    }
    return $result
}

function Get-CodeSequenceWithholdingMaximumFamilySets {
    param(
        [object[]] $Singles,
        [object[]] $Pairs,
        [object[]] $Triples,
        [int] $WithheldPosition,
        [bool] $OriginalLocalOptima
    )
    foreach ($level in @(3,2,1)) {
        $rows = if ($level -eq 3) { $Triples } elseif ($level -eq 2) { $Pairs } else { $Singles }
        $sets = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $rows) {
            $aggregate = if ($OriginalLocalOptima) { $row.original_local_optima } else { $row.genuine }
            $survivors = [long]$aggregate.combination_count
            if ($WithheldPosition -gt 0) {
                $survivors -= [long]$aggregate.original_position_witness_inclusion_counts[$WithheldPosition - 1]
            }
            if ($survivors -lt 0) { throw 'Code Sequence withholding produced negative genuine witness support.' }
            if ($survivors -gt 0) { $sets.Add([int[]]$row.family_indices) }
        }
        if ($sets.Count -gt 0) {
            return [ordered]@{ distinct_family_count = $level; all_attaining_family_index_sets = $sets.ToArray() }
        }
    }
    return [ordered]@{ distinct_family_count = 0; all_attaining_family_index_sets = @() }
}

function Assert-CodeSequenceWithholdingFamilySets {
    param([object[]] $Actual, [object[]] $Expected)
    if ($Actual.Count -ne $Expected.Count) {
        throw 'Code Sequence withholding global maximum set count disagrees with EC-058.'
    }
    for ($i = 0; $i -lt $Actual.Count; $i++) {
        if ((@($Actual[$i]) -join ':') -cne (@($Expected[$i]) -join ':')) {
            throw 'Code Sequence withholding global maximum set identities disagree with EC-058.'
        }
    }
}

function Get-CodeSequenceOriginalFindingPairProfilePositionWithholding {
    param(
        [object] $Atlas,
        [object] $Motifs,
        [object] $Families,
        [object] $Joint,
        [object] $Triple,
        [object] $SelectedAnchor,
        [ref] $WitnessMasksOut
    )
    if ($null -eq $Atlas -or $null -eq $Motifs -or $null -eq $Families -or
        $null -eq $Joint -or $null -eq $Triple -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence withholding requires the complete already-checked parent views.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $familyRows = @($Families.ordered_maximal_repeat_families)
    $pairRows = @($Joint.ordered_cross_family_support_pairs)
    $tripleRows = @($Triple.ordered_cross_family_support_triples)
    $summaries = @($Joint.ordered_family_joint_support_summaries)
    $observed = @($Motifs.all_observed_contiguous_windows)
    $f = $familyRows.Count
    $pairCount = [int](($f * ($f - 1)) / 2)
    $tripleCount = [int](($f * ($f - 1) * ($f - 2)) / 6)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or $n -gt 12 -or
        $Triple.scope -cne 'global_three_distinct_family_original_six_window_support_vs_pairwise_compatibility_and_local_optima' -or
        -not [bool]$Triple.complete_ec054_real_windows_ec056_family_packings_and_ec057_original_pair_counts_reconciled -or
        -not [bool]$Triple.two_original_finding_journeys_remain_independent -or
        -not [bool]$Triple.independent_of_sequence_top -or
        [int]$Triple.counts.selected_report_positions -ne $n -or
        [int]$Triple.counts.maximal_repeat_family_count -ne $f -or
        [int]$Joint.counts.maximal_repeat_family_count -ne $f -or
        [int]$Triple.counts.distinct_maximal_repeat_family_triple_count -ne $tripleCount -or
        [int]$Joint.counts.distinct_maximal_repeat_family_pair_count -ne $pairCount -or
        $tripleRows.Count -ne $tripleCount -or $pairRows.Count -ne $pairCount -or
        $summaries.Count -ne $f -or $observed.Count -ne (($n * ($n - 1)) / 2) -or
        $Atlas.positions.Count -ne $n -or $SelectedAnchor.positions.Count -ne $n -or
        $Families.path -cne $Triple.path -or $Joint.path -cne $Triple.path -or
        $Motifs.path -cne $Triple.path -or $SelectedAnchor.path -cne $Triple.path -or
        [int]$Families.pair_index_in_pairwise_profile -ne [int]$Triple.pair_index_in_pairwise_profile -or
        [int]$Families.path_index_in_selected_pair_overview -ne [int]$Triple.path_index_in_selected_pair_overview -or
        [int]$Families.anchor_index_in_anchor_journeys -ne [int]$Triple.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Triple.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Families.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Triple.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence withholding parents changed selector, completeness or original scope.'
    }
    $records = [string[]]::new($n)
    $classes = [int[]]::new($n)
    for ($p = 1; $p -le $n; $p++) {
        $ap = $Atlas.positions[$p - 1]
        $sp = $SelectedAnchor.positions[$p - 1]
        if ([int]$ap.position -ne $p -or [int]$sp.position -ne $p -or
            $ap.record_id -cne $sp.record_id -or
            [string]::IsNullOrWhiteSpace([string]$ap.record_id)) {
            throw 'Code Sequence withholding original saved record position changed.'
        }
        $records[$p - 1] = [string]$ap.record_id
        $classes[$p - 1] = [int]$ap.profile_class_index
    }

    # Reconstruct ORIGINAL full-window position masks; a deleted position
    # never joins previously nonadjacent original windows. EC-058 has already
    # reconciled provenance and parent optimality, and we recheck the masks,
    # class/record walks and every original packing before using them.
    $twoMasks = [object[]]::new($f)
    $optimumMasks = [object[]]::new($f)
    $rawOptimumPackingCount = 0
    $singleRows = [System.Collections.Generic.List[object]]::new()
    for ($fi = 1; $fi -le $f; $fi++) {
        $family = $familyRows[$fi - 1]
        $occs = @($family.all_observed_occurrences)
        $m = $occs.Count
        $width = [int]$family.position_count_per_occurrence
        $max = [int]$family.maximum_strictly_disjoint_observed_occurrence_count
        $packs = @($family.all_maximum_strictly_disjoint_occurrence_packings)
        if ([int]$family.family_index -ne $fi -or $width -lt 2 -or
            $m -lt 2 -or $m -gt $n - 1 -or $max -lt 1 -or $max -gt $m -or
            $family.profile_class_index_walk.Count -ne $width -or
            $packs.Count -ne [int]$family.maximum_strictly_disjoint_occurrence_packing_count -or
            [int]$family.actual_observed_occurrence_count -ne $m -or
            [int]$summaries[$fi - 1].family_index -ne $fi) {
            throw 'Code Sequence withholding found invalid EC-056 family/packing cardinality.'
        }
        $occMasks = [int[]]::new($m)
        $prevStart = 0
        for ($oi = 0; $oi -lt $m; $oi++) {
            $o = $occs[$oi]
            $wi = [int]$o.ec043_direct_pair_window_index
            $start = [int]$o.from_position
            $end = [int]$o.to_position
            if ($wi -lt 1 -or $wi -gt $observed.Count -or $start -le $prevStart -or
                $start -lt 1 -or $end -gt $n -or $end - $start + 1 -ne $width -or
                [int]$o.occurrence_index_in_family -ne $oi + 1 -or
                [int]$observed[$wi - 1].window_index -ne $wi -or
                [int]$observed[$wi - 1].motif_index -ne [int]$family.ec054_complete_class_walk_motif_index -or
                [int]$observed[$wi - 1].from_position -ne $start -or
                [int]$observed[$wi - 1].to_position -ne $end -or
                ($o.original_record_id_walk -join '|') -cne ($observed[$wi - 1].record_id_walk -join '|')) {
                throw 'Code Sequence withholding found a nonoriginal observed contiguous motif window.'
            }
            $mask = 0
            for ($p = $start; $p -le $end; $p++) {
                if ($o.original_record_id_walk[$p - $start] -cne $records[$p - 1] -or
                    [int]$family.profile_class_index_walk[$p - $start] -ne $classes[$p - 1]) {
                    throw 'Code Sequence withholding window differs from original saved report classes.'
                }
                $mask = $mask -bor (1 -shl ($p - 1))
            }
            $occMasks[$oi] = $mask
            $prevStart = $start
        }
        $two = [System.Collections.Generic.List[int]]::new()
        for ($a = 0; $a -lt $m; $a++) {
            for ($b = $a + 1; $b -lt $m; $b++) {
                if (($occMasks[$a] -band $occMasks[$b]) -eq 0) {
                    $two.Add($occMasks[$a] -bor $occMasks[$b])
                }
            }
        }
        if ($two.Count -ne [int]$summaries[$fi - 1].original_valid_two_occurrence_support_pair_count -or
            ($two.Count -gt 0) -ne ($max -ge 2)) {
            throw 'Code Sequence withholding original two-occurrence count disagrees with EC-057.'
        }
        $opts = [System.Collections.Generic.List[int]]::new()
        for ($pi = 0; $pi -lt $packs.Count; $pi++) {
            $pack = $packs[$pi]
            $items = @($pack.original_occurrence_indices_in_family)
            $used = 0
            $prev = 0
            $indices = [System.Collections.Generic.List[int]]::new()
            foreach ($item in $items) {
                $oi = [int]$item
                if ($oi -le $prev -or $oi -lt 1 -or $oi -gt $m -or
                    ($used -band $occMasks[$oi - 1]) -ne 0) {
                    throw 'Code Sequence withholding original local optimum repeats or overlaps.'
                }
                $used = $used -bor $occMasks[$oi - 1]
                $indices.Add([int]$occs[$oi - 1].ec043_direct_pair_window_index)
                $prev = $oi
            }
            $coveredPositions = [System.Collections.Generic.List[int]]::new()
            $coveredIds = [System.Collections.Generic.List[string]]::new()
            for ($p = 1; $p -le $n; $p++) {
                if (($used -band (1 -shl ($p - 1))) -ne 0) {
                    $coveredPositions.Add($p)
                    $coveredIds.Add($records[$p - 1])
                }
            }
            if ([int]$pack.packing_index_in_family -ne $pi + 1 -or
                $items.Count -ne $max -or
                ($indices.ToArray() -join ':') -cne ($pack.ec043_direct_pair_window_indices -join ':') -or
                ($coveredPositions.ToArray() -join ':') -cne ($pack.covered_caller_positions -join ':') -or
                ($coveredIds.ToArray() -join '|') -cne ($pack.original_record_ids_at_covered_positions -join '|')) {
                throw 'Code Sequence withholding failed original EC-056 packing provenance check.'
            }
            if ($max -ge 2) { $opts.Add($used) }
        }
        $rawOptimumPackingCount += $packs.Count
        $twoMasks[$fi - 1] = $two.ToArray()
        $optimumMasks[$fi - 1] = $opts.ToArray()
        $familyIndices = [int[]]@($fi)
        $genuine = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $twoMasks `
            -FamilyIndices $familyIndices -PositionCount $n
        $optimal = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $optimumMasks `
            -FamilyIndices $familyIndices -PositionCount $n
        if ([long]$genuine.combination_count -ne $two.Count -or
            [long]$optimal.combination_count -ne $opts.Count) {
            throw 'Code Sequence withholding failed single-family witness enumeration.'
        }
        $singleRows.Add([ordered]@{
            family_indices = $familyIndices
            family_index = $fi
            genuine = $genuine
            original_local_optima = $optimal
        })
    }
    if ($rawOptimumPackingCount -ne [int]$Joint.counts.original_ec056_locally_optimal_packings_across_families) {
        throw 'Code Sequence withholding original unfiltered EC-056 optimum count changed.'
    }

    $pairRowsOut = [System.Collections.Generic.List[object]]::new()
    $tripleRowsOut = [System.Collections.Generic.List[object]]::new()
    $pairIx = 0
    $pairGenuineTotal = [long]0
    $pairOptimalTotal = [long]0
    for ($a = 1; $a -le $f; $a++) {
        for ($b = $a + 1; $b -le $f; $b++) {
            $pairIx++
            $indices = [int[]]@($a,$b)
            $joint = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $twoMasks `
                -FamilyIndices $indices -PositionCount $n
            $optimal = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $optimumMasks `
                -FamilyIndices $indices -PositionCount $n
            $prior = $pairRows[$pairIx - 1]
            if ([int]$prior.family_pair_index -ne $pairIx -or
                [int]$prior.left_maximal_repeat_family_index -ne $a -or
                [int]$prior.right_maximal_repeat_family_index -ne $b -or
                [long]$prior.actual_joint_four_occurrence_witness_combination_count -ne [long]$joint.combination_count -or
                [long]$prior.actual_joint_locally_optimal_packing_pair_count -ne [long]$optimal.combination_count -or
                $prior.position_coverage_across_all_joint_independent_witnesses.Count -ne $n) {
                throw 'Code Sequence withholding pair witness ledger disagrees with EC-057.'
            }
            for ($p = 1; $p -le $n; $p++) {
                $c = $prior.position_coverage_across_all_joint_independent_witnesses[$p - 1]
                if ([int]$c.position -ne $p -or $c.original_record_id -cne $records[$p - 1] -or
                    [long]$c.joint_independent_witness_inclusion_count -ne
                        [long]$joint.original_position_witness_inclusion_counts[$p - 1]) {
                    throw 'Code Sequence withholding pair inclusion count does not conserve original witnesses.'
                }
            }
            $pairGenuineTotal += [long]$joint.combination_count
            $pairOptimalTotal += [long]$optimal.combination_count
            $pairRowsOut.Add([ordered]@{
                family_indices = $indices
                family_pair_index = $pairIx
                genuine = $joint
                original_local_optima = $optimal
            })
        }
    }
    if ($pairIx -ne $pairCount -or
        $pairGenuineTotal -ne [long]$Joint.counts.actual_joint_four_occurrence_witness_combinations_across_family_pairs -or
        $pairOptimalTotal -ne [long]$Joint.counts.actual_joint_locally_optimal_packing_pair_combinations_across_family_pairs) {
        throw 'Code Sequence withholding all EC-057 pair totals did not reconcile.'
    }
    $tripleIx = 0
    $tripleGenuineTotal = [long]0
    $tripleOptimalTotal = [long]0
    for ($a = 1; $a -le $f; $a++) {
        for ($b = $a + 1; $b -le $f; $b++) {
            for ($c = $b + 1; $c -le $f; $c++) {
                $tripleIx++
                $indices = [int[]]@($a,$b,$c)
                $genuine = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $twoMasks `
                    -FamilyIndices $indices -PositionCount $n
                $optimal = Get-CodeSequenceWithholdingMaskAggregate -MasksByFamily $optimumMasks `
                    -FamilyIndices $indices -PositionCount $n
                $prior = $tripleRows[$tripleIx - 1]
                if ([int]$prior.family_triple_index -ne $tripleIx -or
                    ($prior.ordered_maximal_repeat_family_indices -join ':') -cne ($indices -join ':') -or
                    [long]$prior.actual_joint_six_occurrence_witness_combination_count -ne [long]$genuine.combination_count -or
                    [long]$prior.actual_joint_three_locally_optimal_packing_combination_count -ne [long]$optimal.combination_count -or
                    $prior.position_coverage_across_all_genuine_three_family_witnesses.Count -ne $n) {
                    throw 'Code Sequence withholding triple witness ledger disagrees with EC-058.'
                }
                for ($p = 1; $p -le $n; $p++) {
                    $entry = $prior.position_coverage_across_all_genuine_three_family_witnesses[$p - 1]
                    if ([int]$entry.position -ne $p -or
                        $entry.original_record_id -cne $records[$p - 1] -or
                        [long]$entry.actual_six_window_witness_inclusion_count -ne
                            [long]$genuine.original_position_witness_inclusion_counts[$p - 1]) {
                        throw 'Code Sequence withholding triple inclusion count does not conserve original witnesses.'
                    }
                }
                $tripleGenuineTotal += [long]$genuine.combination_count
                $tripleOptimalTotal += [long]$optimal.combination_count
                $tripleRowsOut.Add([ordered]@{
                    family_indices = $indices
                    family_triple_index = $tripleIx
                    genuine = $genuine
                    original_local_optima = $optimal
                })
            }
        }
    }
    if ($tripleIx -ne $tripleCount -or
        $tripleGenuineTotal -ne [long]$Triple.counts.actual_six_occurrence_joint_witness_combinations_across_triples -or
        $tripleOptimalTotal -ne [long]$Triple.counts.actual_three_locally_optimal_packing_combinations_across_triples) {
        throw 'Code Sequence withholding all EC-058 triple totals did not reconcile.'
    }

    $singleArray = $singleRows.ToArray()
    $pairArray = $pairRowsOut.ToArray()
    $tripleArray = $tripleRowsOut.ToArray()
    $baseline = Get-CodeSequenceWithholdingMaximumFamilySets -Singles $singleArray `
        -Pairs $pairArray -Triples $tripleArray -WithheldPosition 0 -OriginalLocalOptima $false
    $baselineOptimal = Get-CodeSequenceWithholdingMaximumFamilySets -Singles $singleArray `
        -Pairs $pairArray -Triples $tripleArray -WithheldPosition 0 -OriginalLocalOptima $true
    if ([int]$baseline.distinct_family_count -ne
            [int]$Triple.counts.globally_maximum_simultaneously_independently_supported_distinct_family_count -or
        [int]$baselineOptimal.distinct_family_count -ne
            [int]$Triple.counts.globally_maximum_simultaneously_locally_optimal_distinct_family_count) {
        throw 'Code Sequence withholding did not reproduce the original EC-058 global maximum.'
    }
    Assert-CodeSequenceWithholdingFamilySets -Actual $baseline.all_attaining_family_index_sets `
        -Expected $Triple.all_globally_maximum_simultaneously_supported_family_index_sets
    Assert-CodeSequenceWithholdingFamilySets -Actual $baselineOptimal.all_attaining_family_index_sets `
        -Expected $Triple.all_globally_maximum_simultaneously_locally_optimal_family_index_sets

    $positions = [System.Collections.Generic.List[object]]::new()
    $positionsReducingMaximum = [System.Collections.Generic.List[int]]::new()
    $positionsReducingFrozenOptimum = [System.Collections.Generic.List[int]]::new()
    $minAfter = $baseline.distinct_family_count
    $maxAfter = 0
    $minOptAfter = $baselineOptimal.distinct_family_count
    $maxOptAfter = 0
    for ($p = 1; $p -le $n; $p++) {
        $survivorSingles = [System.Collections.Generic.List[int]]::new()
        $survivorPairs = [System.Collections.Generic.List[int]]::new()
        $survivorTriples = [System.Collections.Generic.List[int]]::new()
        $survivorOptimalSingles = [System.Collections.Generic.List[int]]::new()
        $survivorOptimalPairs = [System.Collections.Generic.List[int]]::new()
        $survivorOptimalTriples = [System.Collections.Generic.List[int]]::new()
        $singleCount = [long]0; $pairCountAfter = [long]0; $tripleCountAfter = [long]0
        $singleOptimalCount = [long]0; $pairOptimalCountAfter = [long]0; $tripleOptimalCountAfter = [long]0
        foreach ($r in $singleArray) {
            $left = [long]$r.genuine.combination_count -
                [long]$r.genuine.original_position_witness_inclusion_counts[$p - 1]
            $leftOpt = [long]$r.original_local_optima.combination_count -
                [long]$r.original_local_optima.original_position_witness_inclusion_counts[$p - 1]
            $singleCount += $left; $singleOptimalCount += $leftOpt
            if ($left -gt 0) { $survivorSingles.Add([int]$r.family_index) }
            if ($leftOpt -gt 0) { $survivorOptimalSingles.Add([int]$r.family_index) }
        }
        foreach ($r in $pairArray) {
            $left = [long]$r.genuine.combination_count -
                [long]$r.genuine.original_position_witness_inclusion_counts[$p - 1]
            $leftOpt = [long]$r.original_local_optima.combination_count -
                [long]$r.original_local_optima.original_position_witness_inclusion_counts[$p - 1]
            $pairCountAfter += $left; $pairOptimalCountAfter += $leftOpt
            if ($left -gt 0) { $survivorPairs.Add([int]$r.family_pair_index) }
            if ($leftOpt -gt 0) { $survivorOptimalPairs.Add([int]$r.family_pair_index) }
        }
        foreach ($r in $tripleArray) {
            $left = [long]$r.genuine.combination_count -
                [long]$r.genuine.original_position_witness_inclusion_counts[$p - 1]
            $leftOpt = [long]$r.original_local_optima.combination_count -
                [long]$r.original_local_optima.original_position_witness_inclusion_counts[$p - 1]
            $tripleCountAfter += $left; $tripleOptimalCountAfter += $leftOpt
            if ($left -gt 0) { $survivorTriples.Add([int]$r.family_triple_index) }
            if ($leftOpt -gt 0) { $survivorOptimalTriples.Add([int]$r.family_triple_index) }
        }
        $after = Get-CodeSequenceWithholdingMaximumFamilySets -Singles $singleArray `
            -Pairs $pairArray -Triples $tripleArray -WithheldPosition $p -OriginalLocalOptima $false
        $afterOpt = Get-CodeSequenceWithholdingMaximumFamilySets -Singles $singleArray `
            -Pairs $pairArray -Triples $tripleArray -WithheldPosition $p -OriginalLocalOptima $true
        $maxFamilies = [int]$after.distinct_family_count
        $maxFrozenFamilies = [int]$afterOpt.distinct_family_count
        $expected = if ($survivorTriples.Count -gt 0) { 3 } elseif ($survivorPairs.Count -gt 0) {
            2
        } elseif ($survivorSingles.Count -gt 0) { 1 } else { 0 }
        $expectedOpt = if ($survivorOptimalTriples.Count -gt 0) { 3 } elseif ($survivorOptimalPairs.Count -gt 0) {
            2
        } elseif ($survivorOptimalSingles.Count -gt 0) { 1 } else { 0 }
        if ($expected -ne $maxFamilies -or $expectedOpt -ne $maxFrozenFamilies -or
            $maxFrozenFamilies -gt $maxFamilies -or
            $maxFamilies -gt $baseline.distinct_family_count -or
            $maxFrozenFamilies -gt $baselineOptimal.distinct_family_count -or
            $maxFamilies -gt [math]::Floor(($n - 1) / 4)) {
            throw 'Code Sequence withholding monotonicity or independent original position capacity failed.'
        }
        $reduced = $maxFamilies -lt [int]$baseline.distinct_family_count
        $reducedOpt = $maxFrozenFamilies -lt [int]$baselineOptimal.distinct_family_count
        if ($reduced) { $positionsReducingMaximum.Add($p) }
        if ($reducedOpt) { $positionsReducingFrozenOptimum.Add($p) }
        $minAfter = [math]::Min($minAfter, $maxFamilies)
        $maxAfter = [math]::Max($maxAfter, $maxFamilies)
        $minOptAfter = [math]::Min($minOptAfter, $maxFrozenFamilies)
        $maxOptAfter = [math]::Max($maxOptAfter, $maxFrozenFamilies)
        $positions.Add([ordered]@{
            withheld_original_caller_position = $p
            withheld_original_record_id = $records[$p - 1]
            original_saved_profile_class_index = $classes[$p - 1]
            surviving_original_independent_two_window_combinations = $singleCount
            surviving_original_joint_four_window_combinations = $pairCountAfter
            surviving_original_joint_six_window_combinations = $tripleCountAfter
            surviving_original_full_selection_local_optimum_individual_packings = $singleOptimalCount
            surviving_original_full_selection_joint_local_optimum_packing_pairs = $pairOptimalCountAfter
            surviving_original_full_selection_joint_local_optimum_packing_triples = $tripleOptimalCountAfter
            independently_supported_family_indices = $survivorSingles.ToArray()
            jointly_supported_family_pair_indices = $survivorPairs.ToArray()
            jointly_supported_family_triple_indices = $survivorTriples.ToArray()
            original_local_optimum_family_indices = $survivorOptimalSingles.ToArray()
            jointly_compatible_original_local_optimum_family_pair_indices = $survivorOptimalPairs.ToArray()
            jointly_compatible_original_local_optimum_family_triple_indices = $survivorOptimalTriples.ToArray()
            globally_maximum_simultaneously_independently_supported_distinct_family_count = $maxFamilies
            all_attaining_family_index_sets = $after.all_attaining_family_index_sets
            reduces_original_global_maximum_independent_family_count = $reduced
            globally_maximum_simultaneously_original_locally_optimal_distinct_family_count = $maxFrozenFamilies
            all_attaining_original_local_optimum_family_index_sets = $afterOpt.all_attaining_family_index_sets
            reduces_original_global_maximum_original_local_optimum_family_count = $reducedOpt
        })
    }
    # EC-060 receives only internal arrays ALREADY verified by the EC-059
    # conservation gate. They are never added to the public EC-059 JSON.
    if ($null -ne $WitnessMasksOut) {
        $WitnessMasksOut.Value = [ordered]@{
            original_record_ids = $records
            original_profile_classes = $classes
            genuine_two_window_masks_by_family = $twoMasks
            frozen_optimum_packing_masks_by_family = $optimumMasks
            single_family_rows = $singleArray
            cross_family_pair_rows = $pairArray
            cross_family_triple_rows = $tripleArray
        }
    }
    return [ordered]@{
        scope = 'single_original_report_position_withholding_exact_original_witness_survival_no_resequencing'
        pair_index_in_pairwise_profile = [int]$Triple.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Triple.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Triple.anchor_index_in_anchor_journeys
        path = [string]$Triple.path
        exact_saved_quote_anchor = $Triple.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            original_maximal_repeat_family_count = $f
            originally_independent_two_window_combinations = [long](($singleArray | ForEach-Object { $_.genuine.combination_count } | Measure-Object -Sum).Sum)
            originally_joint_four_window_combinations = $pairGenuineTotal
            originally_joint_six_window_combinations = $tripleGenuineTotal
            original_global_maximum_independently_supported_distinct_family_count = [int]$baseline.distinct_family_count
            original_global_maximum_original_locally_optimal_distinct_family_count = [int]$baselineOptimal.distinct_family_count
            number_of_individual_positions_that_reduce_global_independent_family_maximum = $positionsReducingMaximum.Count
            number_of_individual_positions_that_reduce_global_original_local_optimum_maximum = $positionsReducingFrozenOptimum.Count
            minimum_global_independent_family_maximum_after_one_withheld_position = $minAfter
            maximum_global_independent_family_maximum_after_one_withheld_position = $maxAfter
            minimum_global_original_local_optimum_family_maximum_after_one_withheld_position = $minOptAfter
            maximum_global_original_local_optimum_family_maximum_after_one_withheld_position = $maxOptAfter
        }
        original_global_maximum_independent_family_index_sets = $baseline.all_attaining_family_index_sets
        original_global_maximum_original_local_optimum_family_index_sets = $baselineOptimal.all_attaining_family_index_sets
        original_caller_positions_that_reduce_global_independent_family_maximum = $positionsReducingMaximum.ToArray()
        original_caller_positions_that_reduce_global_original_local_optimum_maximum = $positionsReducingFrozenOptimum.ToArray()
        ordered_single_original_position_withholding = $positions.ToArray()
        independent_of_sequence_top = $true
        two_original_finding_journeys_remain_independent = $true
        complete_original_ec054_windows_ec056_packings_ec057_pairs_and_ec058_triples_reconciled = $true
        explanation = 'For EACH original caller-selected saved report position, discard every PRE-EXISTING real EC-054 observed motif window containing that position; preserve the original report positions, IDs, class walks and all other already-observed window identities. Count surviving independent two-window family witnesses, jointly disjoint four-window pair witnesses and six-window triple witnesses; count separately the survivors of ORIGINAL full-selection EC-056 local maximum packings without reoptimizing them for the withheld input. Recompute every attainable distinct family maximum and all attaining sets. This is evidence withholding, NOT removing a saved CodeInsight, deleting a report, joining previously nonadjacent positions into new motifs, an attested time/causal intervention or proof of Finding identity, defect recurrence, real severity, fix, regression or risk. No additional selector, persisted content, source/Git/network reads or writes.'
    }
}

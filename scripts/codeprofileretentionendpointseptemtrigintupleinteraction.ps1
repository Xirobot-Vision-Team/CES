#requires -Version 7.0
<#
    EC-131: 37 distinct WHOLE genuine ORIGINAL FULL SCC direct-link removals.
    Read-only ORIGINAL selected Finding-pair Sequence projection, after fully
    rederiving/whole-JSON-authenticating the genuine EC-130 cardinality-36 parent.

    Enumerate <=4094 true complete directed outgoing SCC vertex boundaries;
    canonical subset-minimal (s,t) cut DNFs with exact memoized cardinality-37
    Shannon/binomial counting give 37 disjoint minimum-sufficient loss tiers.
    The <=12-SCC acyclic graph bound proves strict37-positive cuts impossible;
    preserve exact lower 36 tiers and skip nonexistent strict37 sparse rows.
    Max C(66,37)=4,472,995,859,186,094,240 (Int64); conservative 132x reporter
    upper bound 590,435,453,412,564,439,680 requires exact BigInteger output.
    No ~508,520.754 TiB dense bitmap, source mutation or new evidence reading.
#>

function ConvertTo-CodeSequenceThirtySevenExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence thirty_seven-link reported a negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    # Decimal string avoids lossy floating-point/JSON BigInteger serializer shape.
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceThirtySevenLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence thirty_seven-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 38)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 37 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectThirtySevenLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 37 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 38 -or
        $null -eq $Indices -or $Indices.Length -ne 37) {
        throw 'Code Sequence thirty_seven-link scenario requires thirty_seven ordered genuine ORIGINAL FULL direct-link indices in a 37..66-link universe.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 37; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence thirty_seven-link rank requires THIRTY_SEVEN DISTINCT ASCENDING original FULL direct-SCC link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 36 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 37]) {
        throw 'Code Sequence thirty_seven-link rank escaped the original FULL direct-link combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalThirtySevenLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 37 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 38 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 37]) {
        throw 'Code Sequence thirty_seven-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(37)
    $previous = -1
    for ($position = 0; $position -lt 36; $position++) {
        $suffix = 36 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence thirty_seven-link inversion exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[36] = [int]($previous + $remaining + 1)
    if ($indices[36] -le $indices[35] -or $indices[36] -ge $LinkCount) {
        throw 'Code Sequence thirty_seven-link inversion generated repeated or absent ORIGINAL direct links.'
    }
    return ,$indices
}
function Test-CodeSequenceThirtySevenLinkCutContainsSortedSubset {
    param([int[]] $Candidate, [int[]] $Smaller)
    if ($null -eq $Candidate -or $null -eq $Smaller -or
        $Candidate.Length -lt $Smaller.Length) { return $false }
    $i = 0; $j = 0
    while ($i -lt $Candidate.Length -and $j -lt $Smaller.Length) {
        if ($Candidate[$i] -eq $Smaller[$j]) { $i++; $j++ }
        elseif ($Candidate[$i] -lt $Smaller[$j]) { $i++ }
        else { return $false }
    }
    return ($j -eq $Smaller.Length)
}

function ConvertTo-CodeSequenceThirtySevenLinkCanonicalCutFamily {
    param([object[]] $Cuts)
    $byKey = [System.Collections.Generic.Dictionary[string,int[]]]::new([System.StringComparer]::Ordinal)
    $satisfiedByEmptyCut = $false
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            [int[]]$cut = [int[]]$raw
            if ($null -eq $cut) { continue }
            if ($cut.Length -eq 0) {
                # Do not mask malformed later terms merely because the DNF is
                # already satisfied. Validate the entire supplied cut family.
                $satisfiedByEmptyCut = $true
                continue
            }
            if ($cut.Length -gt 37) {
                throw 'Code Sequence thirty_seven-link cut family cannot require more than thirty_seven removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence thirty_seven-link cut family contains unordered, repeated or invalid original link indices.'
                }
                $parts.Add(('{0:D2}' -f $edge))
                $previous = $edge
            }
            $key = ('{0:D2}:{1}' -f $cut.Length, ($parts -join '.'))
            if (-not $byKey.ContainsKey($key)) { $byKey.Add($key, $cut) }
        }
    }
    if ($satisfiedByEmptyCut) {
        return [pscustomobject]@{ cuts = [object[]]@(); key = 'SAT'; satisfied = $true }
    }
    if ($byKey.Count -eq 0) {
        return [pscustomobject]@{ cuts = [object[]]@(); key = ''; satisfied = $false }
    }
    [string[]]$keys = [string[]]$byKey.Keys
    [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    $accepted = [System.Collections.Generic.List[object]]::new()
    $acceptedKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $keys) {
        [int[]]$candidate = $byKey[$key]
        $redundant = $false
        foreach ($existingObject in $accepted) {
            [int[]]$existing = [int[]]$existingObject
            if (Test-CodeSequenceThirtySevenLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
                $redundant = $true
                break
            }
        }
        if (-not $redundant) {
            $accepted.Add($candidate)
            $acceptedKeys.Add($key)
        }
    }
    return [pscustomobject]@{
        cuts = $accepted.ToArray()
        key = ($acceptedKeys -join ';')
        satisfied = $false
    }
}

function Get-CodeSequenceThirtySevenLinkCutDnfCountState {
    param(
        [object] $Family,
        [int] $NextEdge,
        [int] $RemainingDeletions,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($RemainingDeletions -lt 0 -or $NextEdge -lt 0 -or $NextEdge -gt $LinkCount -or
        $RemainingDeletions -gt $LinkCount - $NextEdge) { return [long]0 }
    if ([bool]$Family.satisfied) {
        return [long]$Choose[$LinkCount - $NextEdge, $RemainingDeletions]
    }
    [object[]]$cuts = [object[]]$Family.cuts
    if ($cuts.Length -eq 0) { return [long]0 }
    [int[]]$first = [int[]]$cuts[0]
    if ($RemainingDeletions -eq 0 -or $first.Length -gt $RemainingDeletions) { return [long]0 }
    if ($RemainingDeletions -eq $LinkCount - $NextEdge) { return [long]1 }

    # Include E even if a caller supplies a memo across distinct target graphs.
    $memoKey = "$LinkCount|$NextEdge|$RemainingDeletions|$($Family.key)"
    [long]$cached = 0
    if ($Memo.TryGetValue($memoKey, [ref]$cached)) { return $cached }

    $pivot = $LinkCount
    foreach ($raw in $cuts) {
        [int[]]$cut = [int[]]$raw
        if ($cut.Length -gt 0 -and $cut[0] -lt $pivot) { $pivot = $cut[0] }
    }
    if ($pivot -lt $NextEdge -or $pivot -ge $LinkCount) {
        throw 'Code Sequence thirty_seven-link memoized cut counter lost its canonical undecided edge frontier.'
    }
    $gap = $pivot - $NextEdge

    $keptRaw = [System.Collections.Generic.List[object]]::new()
    $deletedRaw = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $cuts) {
        [int[]]$cut = [int[]]$raw
        if ($cut[0] -eq $pivot) {
            [int[]]$tail = [int[]]::new($cut.Length - 1)
            if ($tail.Length -gt 0) { [Array]::Copy($cut, 1, $tail, 0, $tail.Length) }
            $deletedRaw.Add($tail)
        } else {
            $keptRaw.Add($cut)
            $deletedRaw.Add($cut)
        }
    }
    $keptFamily = ConvertTo-CodeSequenceThirtySevenLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceThirtySevenLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceThirtySevenLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceThirtySevenLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 37]) {
        throw 'Code Sequence thirty_seven-link memoized cut counter exceeded the exact thirty_seven-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

function Get-CodeSequenceThirtySevenLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 37 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 38) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 37) { return [long]0 }
        throw 'Code Sequence thirty_seven-link DNF counter requires a valid 0..66 original-link universe.'
    }
    # Validate every supplied edge BEFORE subsumption/satisfaction reduction.
    # Otherwise an out-of-universe cut hidden behind a valid smaller cut could
    # be discarded unnoticed and corrupt the trust boundary of this API.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence thirty_seven-link DNF cut references an absent ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceThirtySevenLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 37] }
    if ($family.cuts.Length -eq 0) { return [long]0 }

    # A dense original E=37 or E=38 source reaches the high-cardinality
    # boundary with at most ONE untouched FULL edge. Avoid a full recursive
    # cut-DNF walk: E=37 has one all-deleted case; at E=38, the only ways to
    # avoid every cut are to keep an edge appearing in EVERY cut. Equivalently
    # C(38,37) - |intersection(all cut terms)|, exact for arbitrary cut DNFs.
    # The upstream canonicalizer has already verified and minimized all terms.
    if ($LinkCount -eq 37) { return [long]1 }
    if ($LinkCount -eq 38) {
        [long]$commonMask = ([long]1 -shl 38) - 1
        foreach ($raw in $family.cuts) {
            [long]$termMask = 0
            foreach ($edge in ([int[]]$raw)) {
                $termMask = $termMask -bor ([long]1 -shl $edge)
            }
            $commonMask = $commonMask -band $termMask
            if ($commonMask -eq 0) { break }
        }
        [int]$untouchedCasesAvoidingAllCuts = 0
        for ($edge = 0; $edge -lt 38; $edge++) {
            if (($commonMask -band ([long]1 -shl $edge)) -ne 0) {
                $untouchedCasesAvoidingAllCuts++
            }
        }
        return [long](38 - $untouchedCasesAvoidingAllCuts)
    }

    # Reuse canonical subproblem counts for the same (s,t) over thresholds 1..37.
    # The memo key includes the FULL residual cut family, edge frontier and
    # remaining deletion budget; sharing it never merges different predicates.
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    return Get-CodeSequenceThirtySevenLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 37 -LinkCount $LinkCount -Choose $Choose -Memo $Memo
}

function Get-CodeSequenceEndpointDominanceThirtySevenLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [object] $TripleInteraction,
        [object] $QuadrupleInteraction,
        [object] $QuintupleInteraction,
        [object] $SextupleInteraction,
        [object] $SeptupleInteraction,
        [object] $OctupleInteraction,
        [object] $NonupleInteraction,
        [object] $DecupleInteraction,
        [object] $UndecupleInteraction,
        [object] $DuodecupleInteraction,
        [object] $TredecupleInteraction,
        [object] $QuattuordecupleInteraction,
        [object] $QuindecupleInteraction,
        [object] $SexdecupleInteraction,
        [object] $SeptendecupleInteraction,
        [object] $OctodecupleInteraction,
        [object] $NovemdecupleInteraction,
        [object] $VigintupleInteraction,
        [object] $UnvigintupleInteraction,
        [object] $DuovigintupleInteraction,
        [object] $TrevigintupleInteraction,
        [object] $QuattuorvigintupleInteraction,
        [object] $QuinquevigintupleInteraction,
        [object] $SexvigintupleInteraction,
        [object] $SeptemvigintupleInteraction,
        [object] $OctovigintupleInteraction,
        [object] $NovemvigintupleInteraction,
        [object] $TrigintupleInteraction,
        [object] $UntrigintupleInteraction,
        [object] $DuotrigintupleInteraction,
        [object] $TretrigintupleInteraction,
        [object] $QuattuortrigintupleInteraction,
        [object] $QuinquetrigintupleInteraction,
        [object] $SextrigintupleInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or $null -eq $TripleInteraction -or
        $null -eq $QuadrupleInteraction -or $null -eq $QuintupleInteraction -or
        $null -eq $SextupleInteraction -or $null -eq $SeptupleInteraction -or
        $null -eq $OctupleInteraction -or $null -eq $NonupleInteraction -or
        $null -eq $DecupleInteraction -or $null -eq $UndecupleInteraction -or
        $null -eq $DuodecupleInteraction -or $null -eq $TredecupleInteraction -or
        $null -eq $QuattuordecupleInteraction -or $null -eq $QuindecupleInteraction -or
        $null -eq $SexdecupleInteraction -or $null -eq $SeptendecupleInteraction -or
        $null -eq $OctodecupleInteraction -or
        $null -eq $UnvigintupleInteraction -or
        -not [bool]$UnvigintupleInteraction.every_scenario_deletes_twenty_one_distinct_whole_original_direct_scc_links_from_full_dag -or
        $null -eq $DuovigintupleInteraction -or
        -not [bool]$DuovigintupleInteraction.every_scenario_deletes_twenty_two_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$DuovigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_and_strictly_twenty_second_only_loss -or
        -not [bool]$DuovigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_two_removed_links -or
        -not [bool]$DuovigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$DuovigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        $null -eq $TrevigintupleInteraction -or
        $null -eq $QuattuorvigintupleInteraction -or
        $null -eq $QuinquevigintupleInteraction -or
        -not [bool]$QuinquevigintupleInteraction.every_scenario_deletes_twenty_five_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$QuinquevigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_and_strictly_twenty_fifth_only_loss -or
        -not [bool]$QuinquevigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_five_removed_links -or
        -not [bool]$QuinquevigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$QuinquevigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        $null -eq $SexvigintupleInteraction -or
        -not [bool]$SexvigintupleInteraction.every_scenario_deletes_twenty_six_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SexvigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_and_strictly_twenty_sixth_only_loss -or
        -not [bool]$SexvigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_six_removed_links -or
        -not [bool]$SexvigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SexvigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        $null -eq $NovemvigintupleInteraction -or
        [string]$NovemvigintupleInteraction.scope -cne 'exact_strictly_twenty_ninth_order_twenty_nine_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$NovemvigintupleInteraction.only_consumed_checked_ec093_to_ec122_original_graph_projections -or
        -not [bool]$NovemvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$NovemvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$NovemvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $TrigintupleInteraction -or
        [string]$TrigintupleInteraction.scope -cne 'exact_strictly_thirtieth_order_thirty_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$TrigintupleInteraction.only_consumed_checked_ec093_to_ec123_original_graph_projections -or
        -not [bool]$TrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$TrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$TrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $UntrigintupleInteraction -or
        [string]$UntrigintupleInteraction.scope -cne 'exact_strictly_thirty_first_order_thirty_one_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$UntrigintupleInteraction.only_consumed_checked_ec093_to_ec124_original_graph_projections -or
        -not [bool]$UntrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$UntrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$UntrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $DuotrigintupleInteraction -or
        $null -eq $TretrigintupleInteraction -or
        $null -eq $QuattuortrigintupleInteraction -or
        $null -eq $QuinquetrigintupleInteraction -or
        $null -eq $SextrigintupleInteraction -or
        [string]$SextrigintupleInteraction.scope -cne 'exact_strictly_thirty_sixth_order_thirty_six_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$SextrigintupleInteraction.every_scenario_deletes_thirty_six_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SextrigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_thirty_fifth_and_strictly_thirty_sixth_only_loss -or
        -not [bool]$SextrigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SextrigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$QuinquetrigintupleInteraction.every_scenario_deletes_thirty_five_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$QuinquetrigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_and_strictly_thirty_fifth_only_loss -or
        -not [bool]$QuinquetrigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_thirty_five_removed_links -or
        -not [bool]$QuinquetrigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$QuinquetrigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        [string]$QuattuortrigintupleInteraction.scope -cne 'exact_strictly_thirty_fourth_order_thirty_four_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$QuattuortrigintupleInteraction.only_consumed_checked_ec093_to_ec127_original_graph_projections -or
        -not [bool]$QuattuortrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$QuattuortrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$QuattuortrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$TretrigintupleInteraction.scope -cne 'exact_strictly_thirty_third_order_thirty_three_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$TretrigintupleInteraction.only_consumed_checked_ec093_to_ec126_original_graph_projections -or
        -not [bool]$TretrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$TretrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$TretrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$DuotrigintupleInteraction.scope -cne 'exact_strictly_thirty_second_order_thirty_two_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$DuotrigintupleInteraction.only_consumed_checked_ec093_to_ec125_original_graph_projections -or
        -not [bool]$DuotrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$DuotrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$DuotrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $OctovigintupleInteraction -or
        [string]$OctovigintupleInteraction.scope -cne 'exact_strictly_twenty_eighth_order_twenty_eight_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$OctovigintupleInteraction.only_consumed_checked_ec093_to_ec121_original_graph_projections -or
        -not [bool]$OctovigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$OctovigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$OctovigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $SeptemvigintupleInteraction -or
        -not [bool]$SeptemvigintupleInteraction.every_scenario_deletes_twenty_seven_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SeptemvigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_and_strictly_twenty_seventh_only_loss -or
        -not [bool]$SeptemvigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_seven_removed_links -or
        -not [bool]$SeptemvigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SeptemvigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$TrevigintupleInteraction.every_scenario_deletes_twenty_three_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$TrevigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_and_strictly_twenty_third_only_loss -or
        -not [bool]$TrevigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_three_removed_links -or
        -not [bool]$TrevigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$TrevigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$QuattuorvigintupleInteraction.every_scenario_deletes_twenty_four_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$QuattuorvigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_and_strictly_twenty_fourth_only_loss -or
        -not [bool]$QuattuorvigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_four_removed_links -or
        -not [bool]$QuattuorvigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$QuattuorvigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        $null -eq $VigintupleInteraction -or
        -not [bool]$VigintupleInteraction.every_scenario_deletes_twenty_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$VigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_and_strictly_twentieth_only_loss -or
        -not [bool]$VigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_removed_links -or
        -not [bool]$VigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$VigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        $null -eq $NovemdecupleInteraction -or
        -not [bool]$NovemdecupleInteraction.every_scenario_deletes_nineteen_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$NovemdecupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_and_strictly_nineteenth_only_loss -or
        -not [bool]$NovemdecupleInteraction.original_redundant_shortcuts_remain_unless_one_of_nineteen_removed_links -or
        -not [bool]$NovemdecupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$NovemdecupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$OctodecupleInteraction.every_scenario_deletes_eighteen_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$OctodecupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_and_strictly_eighteenth_only_loss -or
        -not [bool]$OctodecupleInteraction.original_redundant_shortcuts_remain_unless_one_of_eighteen_removed_links -or
        -not [bool]$OctodecupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$OctodecupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$SeptendecupleInteraction.every_scenario_deletes_seventeen_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SeptendecupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_and_strictly_seventeenth_only_loss -or
        -not [bool]$SeptendecupleInteraction.original_redundant_shortcuts_remain_unless_one_of_seventeen_removed_links -or
        -not [bool]$SeptendecupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SeptendecupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
        -not [bool]$SexdecupleInteraction.every_scenario_deletes_sixteen_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SexdecupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_and_strictly_sixteenth_only_loss -or
        -not [bool]$SexdecupleInteraction.original_redundant_shortcuts_remain_unless_one_of_sixteen_removed_links -or
        -not [bool]$SexdecupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SexdecupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence thirty_seven-link interaction requires checked EC-093 through EC-130 ORIGINAL projections.'
    }
    # EC-130 is not trusted from header, totals, example or an empty row list.
    # Rebuild the ENTIRE real k36 EC-130 parent using checked original EC-093..129
    # data and compare every public field, including nonempty FIRST proofs,
    # original sparse ranks, all 35 loss orders, and exact BigInteger totals.
    $fresh = Get-CodeSequenceEndpointDominanceThirtySixLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -PairInteraction $PairInteraction `
        -TripleInteraction $TripleInteraction -QuadrupleInteraction $QuadrupleInteraction `
        -QuintupleInteraction $QuintupleInteraction -SextupleInteraction $SextupleInteraction `
        -SeptupleInteraction $SeptupleInteraction -OctupleInteraction $OctupleInteraction `
        -NonupleInteraction $NonupleInteraction -DecupleInteraction $DecupleInteraction `
        -UndecupleInteraction $UndecupleInteraction -DuodecupleInteraction $DuodecupleInteraction `
        -TredecupleInteraction $TredecupleInteraction -QuattuordecupleInteraction $QuattuordecupleInteraction `
        -QuindecupleInteraction $QuindecupleInteraction -SexdecupleInteraction $SexdecupleInteraction `
        -SeptendecupleInteraction $SeptendecupleInteraction `
        -OctodecupleInteraction $OctodecupleInteraction `
        -NovemdecupleInteraction $NovemdecupleInteraction `
        -VigintupleInteraction $VigintupleInteraction `
        -UnvigintupleInteraction $UnvigintupleInteraction `
        -DuovigintupleInteraction $DuovigintupleInteraction `
        -TrevigintupleInteraction $TrevigintupleInteraction `
        -QuattuorvigintupleInteraction $QuattuorvigintupleInteraction `
        -QuinquevigintupleInteraction $QuinquevigintupleInteraction `
        -SexvigintupleInteraction $SexvigintupleInteraction `
        -SeptemvigintupleInteraction $SeptemvigintupleInteraction `
        -OctovigintupleInteraction $OctovigintupleInteraction `
        -NovemvigintupleInteraction $NovemvigintupleInteraction `
        -TrigintupleInteraction $TrigintupleInteraction `
        -UntrigintupleInteraction $UntrigintupleInteraction `
        -DuotrigintupleInteraction $DuotrigintupleInteraction `
        -TretrigintupleInteraction $TretrigintupleInteraction `
        -QuattuortrigintupleInteraction $QuattuortrigintupleInteraction `
        -QuinquetrigintupleInteraction $QuinquetrigintupleInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 70 -Compress) -cne
        (ConvertTo-Json -InputObject $SextrigintupleInteraction -Depth 70 -Compress)) {
        throw 'Code Sequence thirty_seven-link interaction rejected changed EC-130 thirty-sixth-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$TretrigintupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$TretrigintupleInteraction.exact_original_direct_component_link_count -ne $linkCount -or
        [int]$SextrigintupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$SextrigintupleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence thirty_seven-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence thirty_seven-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence thirty_seven-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence thirty_seven-link interaction found duplicated or invalid FULL original direct SCC links.'
        }
        $fromByLink[$i] = $from
        $toByLink[$i] = $to
        $directRows[$from] = $directRows[$from] -bor (1 -shl $to)
    }
    [int[]]$baseline = (Get-CodeSequenceDominanceThreeLinkClosureBits `
        -ComponentCount $componentCount -FullDirectRows $directRows -DirectLinks $links).Rows
    [int[]]$upstreamBaseline = (Get-CodeSequenceDominanceTwoLinkClosureBits `
        -ComponentCount $componentCount -DirectLinks $links).Rows
    for ($s = 0; $s -lt $componentCount; $s++) {
        if ($baseline[$s] -ne $upstreamBaseline[$s]) {
            throw 'Code Sequence thirty_seven-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    # The original FULL SCC condensation must be antisymmetric: any mutual
    # reachability would collapse distinct vertices into one original SCC.
    # Check this precondition explicitly before relying on the 36-edge bound.
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = $s + 1; $t -lt $componentCount; $t++) {
            if (($baseline[$s] -band (1 -shl $t)) -ne 0 -and
                ($baseline[$t] -band (1 -shl $s)) -ne 0) {
                throw 'Code Sequence thirty_seven-link cannot certify saturation for cyclic distinct original SCCs.'
            }
        }
    }
    [long[,]]$choose = New-CodeSequenceThirtySevenLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 37]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=37 real FULL links can affect a thirty_seven-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 37) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 37) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..37, the exact number of thirty_seven-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,37) graph closures and any C(E,37)-bit mask.
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(38)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(38)
    $positiveRanks = [System.Collections.Generic.HashSet[long]]::new()
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = 0; $t -lt $componentCount; $t++) {
            if ($s -eq $t -or ($baseline[$s] -band (1 -shl $t)) -eq 0 -or
                $scenarioCount -eq 0) { continue }
            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $perPair = [System.Collections.Generic.List[int[]]]::new()
            foreach ($candidate in $cuts) {
                if (($candidate.source_side_bitset -band (1 -shl $s)) -eq 0 -or
                    ($candidate.source_side_bitset -band (1 -shl $t)) -ne 0) { continue }
                [int[]]$boundary = [int[]]$candidate.outgoing_whole_original_link_indices
                if ($seen.Add(($boundary -join ','))) { $perPair.Add($boundary) }
            }
            if ($perPair.Count -eq 0) { continue }

            $ascending = [System.Collections.Generic.List[int[]]]::new()
            $thresholdCuts = [System.Collections.Generic.List[object]]::new()
            $thresholdMemo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
            [long]$previousCumulative = 0
            for ($order = 1; $order -le 37; $order++) {
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceThirtySevenLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    if ($order -eq 37) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectThirtySevenLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                [long]$cumulative = 0
                if ($thresholdCuts.Count -gt 0) {
                    $cumulative = Get-CodeSequenceThirtySevenLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence thirty_seven-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence thirty_seven-link minimal cut registry exceeded its source candidate family.'
            }
        }
    }
    # Tight finite-size bound: a complete outgoing source-side cut in an
    # original simple SCC condensation DAG has at most floor(m*m/4) edges.
    # With m<=12 this is <=36, so strictly-37-only is *impossible*, even
    # when E>=37; earlier minimum-loss tiers can remain nonzero.
    $maximumOutgoingCut = [int][math]::Floor(($componentCount * $componentCount) / 4)
    if ($maximumOutgoingCut -gt 36 -or $positiveRanks.Count -ne 0 -or
        $tierSum[37] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[37] -ne [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence thirty_seven-link model violated the proven 12-SCC / 36-outgoing-edge saturation bound.'
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence thirty_seven-link strictly thirty_seventh-only cases exceed the bounded directed-cut universe.'
    }

    # No sparse output expansion at k=37: for at most twelve ORIGINAL SCCs,
    # every complete outgoing SCC vertex boundary has at most 36 FULL edges.
    # The exact cardinality-37 aggregate STILL counts all minimum-loss orders
    # 1..36; omitting nonexisting strict-37 positive rows saves memory/work.
    $rows = [System.Collections.Generic.List[object]]::new()

    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 37; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    # Disjoint per-relation minimum-cut tiers cannot count more ordered
    # reachable SCC/reporter relations than physically exist per scenario.
    # Cast BEFORE multiplying: the conservative N12/E66 reporter ceiling is
    # above Int64 even though the exact 37-deletion scenario count is not.
    [System.Numerics.BigInteger]$maxComponentIncidences = [System.Numerics.BigInteger]($componentCount * ($componentCount - 1)) * $scenarioCount
    [System.Numerics.BigInteger]$maxReporterIncidences = [System.Numerics.BigInteger]($N * ($N - 1)) * $scenarioCount
    if ($allLosses -gt $maxComponentIncidences -or
        $allReporterMass -gt $maxReporterIncidences -or
        $positiveRanks.Count -gt 4094) {
        throw 'Code Sequence thirty_seven-link original SCC/reporter incidence or bounded positive cut invariant failed.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        maximum_possible_complete_outgoing_original_scc_cut_size = $maximumOutgoingCut
        original_scc_directed_cut_saturation_bound_36_for_at_most_12_components = $true
        all_strictly_thirty_seventh_only_positive_rows_proven_impossible = $true
        exact_original_direct_component_link_count = $linkCount
        exact_thirty_seven_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_thirty_seventh_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_thirty_seventh_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[1])
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[1])
        sum_of_pair_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[2])
        sum_of_pair_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[2])
        sum_of_triple_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[3])
        sum_of_triple_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[3])
        sum_of_quadruple_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[4])
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[4])
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[5])
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[5])
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[6])
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[6])
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[7])
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[7])
        sum_of_strictly_eighth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[8])
        sum_of_strictly_eighth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[8])
        sum_of_strictly_ninth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[9])
        sum_of_strictly_ninth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[9])
        sum_of_strictly_tenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[10])
        sum_of_strictly_tenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[10])
        sum_of_strictly_eleventh_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[11])
        sum_of_strictly_eleventh_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[11])
        sum_of_strictly_twelfth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[12])
        sum_of_strictly_twelfth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[12])
        sum_of_strictly_thirteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[13])
        sum_of_strictly_thirteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[13])
        sum_of_strictly_fourteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[14])
        sum_of_strictly_fourteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[14])
        sum_of_strictly_fifteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[15])
        sum_of_strictly_fifteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[15])
        sum_of_strictly_sixteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[16])
        sum_of_strictly_sixteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[16])
        sum_of_strictly_seventeenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[17])
        sum_of_strictly_seventeenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[17])
        sum_of_strictly_eighteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[18])
        sum_of_strictly_eighteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[18])
        sum_of_strictly_nineteenth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[19])
        sum_of_strictly_nineteenth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[19])
        sum_of_strictly_twentieth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[20])
        sum_of_strictly_twentieth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[20])
        sum_of_strictly_twenty_first_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[21])
        sum_of_strictly_twenty_first_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[21])
        sum_of_strictly_twenty_second_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[22])
        sum_of_strictly_twenty_second_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[22])
        sum_of_strictly_twenty_third_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[23])
        sum_of_strictly_twenty_third_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[23])
        sum_of_strictly_twenty_fourth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[24])
        sum_of_strictly_twenty_fourth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[24])
        sum_of_strictly_twenty_fifth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[25])
        sum_of_strictly_twenty_fifth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[25])
        sum_of_strictly_twenty_sixth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[26])
        sum_of_strictly_twenty_sixth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[26])
        sum_of_strictly_twenty_seventh_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[27])
        sum_of_strictly_twenty_seventh_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[27])
        sum_of_strictly_twenty_eighth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[28])
        sum_of_strictly_twenty_eighth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[28])
        sum_of_strictly_twenty_ninth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[29])
        sum_of_strictly_thirtieth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[30])
        sum_of_strictly_thirty_second_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[32])
        sum_of_strictly_thirty_third_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[33])
        sum_of_strictly_thirty_fourth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[34])
        sum_of_strictly_thirty_fifth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[35])
        sum_of_strictly_thirty_sixth_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[36])
        sum_of_strictly_thirty_seventh_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[37])
        sum_of_strictly_twenty_ninth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[29])
        sum_of_strictly_thirtieth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[30])
        sum_of_strictly_thirty_first_only_new_component_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierSum[31])
        sum_of_strictly_thirty_first_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[31])
        sum_of_strictly_thirty_second_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[32])
        sum_of_strictly_thirty_third_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[33])
        sum_of_strictly_thirty_fourth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[34])
        sum_of_strictly_thirty_fifth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[35])
        sum_of_strictly_thirty_sixth_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[36])
        sum_of_strictly_thirty_seventh_only_new_original_reporter_pair_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $tierReporterSum[37])
        sum_of_combined_full_graph_component_pair_loss_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $allLosses)
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_thirty_seven_link_scenarios = (ConvertTo-CodeSequenceThirtySevenExactCount -Value $allReporterMass)
        original_direct_link_septemtrigintuples_with_strictly_thirty_seventh_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_thirty_seven = $cuts.Count
        all_thirty_seven_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_37_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_thirty_seven_deletions = $true
        thirty_seventh_only_positive_scenarios_are_exact_thirty_seven_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_thirty_seventh_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_thirty_seven_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_thirty_fifth_thirty_sixth_and_strictly_thirty_seventh_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_thirty_seven_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptemtrigintupleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction,
        [object] $RetentionEndpointTripleInteraction,
        [object] $RetentionEndpointQuadrupleInteraction,
        [object] $RetentionEndpointQuintupleInteraction,
        [object] $RetentionEndpointSextupleInteraction,
        [object] $RetentionEndpointSeptupleInteraction,
        [object] $RetentionEndpointOctupleInteraction,
        [object] $RetentionEndpointNonupleInteraction,
        [object] $RetentionEndpointDecupleInteraction,
        [object] $RetentionEndpointUndecupleInteraction,
        [object] $RetentionEndpointDuodecupleInteraction,
        [object] $RetentionEndpointTredecupleInteraction,
        [object] $RetentionEndpointQuattuordecupleInteraction,
        [object] $RetentionEndpointQuindecupleInteraction,
        [object] $RetentionEndpointSexdecupleInteraction,
        [object] $RetentionEndpointSeptendecupleInteraction,
        [object] $RetentionEndpointOctodecupleInteraction,
        [object] $RetentionEndpointNovemdecupleInteraction,
        [object] $RetentionEndpointVigintupleInteraction,
        [object] $RetentionEndpointUnvigintupleInteraction,
        [object] $RetentionEndpointDuovigintupleInteraction,
        [object] $RetentionEndpointTrevigintupleInteraction,
        [object] $RetentionEndpointQuattuorvigintupleInteraction,
        [object] $RetentionEndpointQuinquevigintupleInteraction,
        [object] $RetentionEndpointSexvigintupleInteraction,
        [object] $RetentionEndpointSeptemvigintupleInteraction,
        [object] $RetentionEndpointOctovigintupleInteraction,
        [object] $RetentionEndpointNovemvigintupleInteraction,
        [object] $RetentionEndpointTrigintupleInteraction,
        [object] $RetentionEndpointUntrigintupleInteraction,
        [object] $RetentionEndpointDuotrigintupleInteraction,
        [object] $RetentionEndpointTretrigintupleInteraction,
        [object] $RetentionEndpointQuattuortrigintupleInteraction,
        [object] $RetentionEndpointQuinquetrigintupleInteraction,
        [object] $RetentionEndpointSextrigintupleInteraction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        $null -eq $RetentionEndpointPairInteraction -or
        $null -eq $RetentionEndpointTripleInteraction -or
        $null -eq $RetentionEndpointQuadrupleInteraction -or
        $null -eq $RetentionEndpointQuintupleInteraction -or
        $null -eq $RetentionEndpointSextupleInteraction -or
        $null -eq $RetentionEndpointSeptupleInteraction -or
        $null -eq $RetentionEndpointOctupleInteraction -or
        $null -eq $RetentionEndpointNonupleInteraction -or
        $null -eq $RetentionEndpointDecupleInteraction -or
        $null -eq $RetentionEndpointUndecupleInteraction -or
        $null -eq $RetentionEndpointDuodecupleInteraction -or
        $null -eq $RetentionEndpointTredecupleInteraction -or
        $null -eq $RetentionEndpointQuattuordecupleInteraction -or
        $null -eq $RetentionEndpointQuindecupleInteraction -or
        $null -eq $RetentionEndpointSexdecupleInteraction -or
        $null -eq $RetentionEndpointSeptendecupleInteraction -or
        $null -eq $RetentionEndpointOctodecupleInteraction -or
        $null -eq $RetentionEndpointUnvigintupleInteraction -or
        [string]$RetentionEndpointUnvigintupleInteraction.scope -cne 'exact_strictly_twenty_first_order_twenty_one_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointUnvigintupleInteraction.only_consumed_checked_ec093_to_ec114_original_graph_projections -or
        $null -eq $RetentionEndpointDuovigintupleInteraction -or
        [string]$RetentionEndpointDuovigintupleInteraction.scope -cne 'exact_strictly_twenty_second_order_twenty_two_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointDuovigintupleInteraction.only_consumed_checked_ec093_to_ec115_original_graph_projections -or
        -not [bool]$RetentionEndpointDuovigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointDuovigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointDuovigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointTrevigintupleInteraction -or
        $null -eq $RetentionEndpointQuattuorvigintupleInteraction -or
        $null -eq $RetentionEndpointQuinquevigintupleInteraction -or
        [string]$RetentionEndpointQuinquevigintupleInteraction.scope -cne 'exact_strictly_twenty_fifth_order_twenty_five_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuinquevigintupleInteraction.only_consumed_checked_ec093_to_ec118_original_graph_projections -or
        -not [bool]$RetentionEndpointQuinquevigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuinquevigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuinquevigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointSexvigintupleInteraction -or
        [string]$RetentionEndpointSexvigintupleInteraction.scope -cne 'exact_strictly_twenty_sixth_order_twenty_six_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSexvigintupleInteraction.only_consumed_checked_ec093_to_ec119_original_graph_projections -or
        -not [bool]$RetentionEndpointSexvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSexvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointSexvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointSeptemvigintupleInteraction -or
        [string]$RetentionEndpointSeptemvigintupleInteraction.scope -cne 'exact_strictly_twenty_seventh_order_twenty_seven_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSeptemvigintupleInteraction.only_consumed_checked_ec093_to_ec120_original_graph_projections -or
        -not [bool]$RetentionEndpointSeptemvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSeptemvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointSeptemvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointNovemvigintupleInteraction -or
        [string]$RetentionEndpointNovemvigintupleInteraction.scope -cne 'exact_strictly_twenty_ninth_order_twenty_nine_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointNovemvigintupleInteraction.only_consumed_checked_ec093_to_ec122_original_graph_projections -or
        -not [bool]$RetentionEndpointNovemvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointNovemvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointNovemvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointTrigintupleInteraction -or
        [string]$RetentionEndpointTrigintupleInteraction.scope -cne 'exact_strictly_thirtieth_order_thirty_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointTrigintupleInteraction.only_consumed_checked_ec093_to_ec123_original_graph_projections -or
        -not [bool]$RetentionEndpointTrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointTrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointTrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointUntrigintupleInteraction -or
        $null -eq $RetentionEndpointDuotrigintupleInteraction -or
        $null -eq $RetentionEndpointTretrigintupleInteraction -or
        $null -eq $RetentionEndpointQuattuortrigintupleInteraction -or
        [string]$RetentionEndpointQuattuortrigintupleInteraction.scope -cne 'exact_strictly_thirty_fourth_order_thirty_four_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuattuortrigintupleInteraction.only_consumed_checked_ec093_to_ec127_original_graph_projections -or
        -not [bool]$RetentionEndpointQuattuortrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuattuortrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuattuortrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointQuinquetrigintupleInteraction -or
        $null -eq $RetentionEndpointSextrigintupleInteraction -or
        [string]$RetentionEndpointSextrigintupleInteraction.scope -cne 'exact_strictly_thirty_sixth_order_thirty_six_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSextrigintupleInteraction.only_consumed_checked_ec093_to_ec129_original_graph_projections -or
        -not [bool]$RetentionEndpointSextrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSextrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointQuinquetrigintupleInteraction.scope -cne 'exact_strictly_thirty_fifth_order_thirty_five_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuinquetrigintupleInteraction.only_consumed_checked_ec093_to_ec128_original_graph_projections -or
        -not [bool]$RetentionEndpointQuinquetrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuinquetrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuinquetrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointTretrigintupleInteraction.scope -cne 'exact_strictly_thirty_third_order_thirty_three_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointTretrigintupleInteraction.only_consumed_checked_ec093_to_ec126_original_graph_projections -or
        -not [bool]$RetentionEndpointTretrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointTretrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointTretrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointDuotrigintupleInteraction.scope -cne 'exact_strictly_thirty_second_order_thirty_two_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointDuotrigintupleInteraction.only_consumed_checked_ec093_to_ec125_original_graph_projections -or
        -not [bool]$RetentionEndpointDuotrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointDuotrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointDuotrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointUntrigintupleInteraction.scope -cne 'exact_strictly_thirty_first_order_thirty_one_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointUntrigintupleInteraction.only_consumed_checked_ec093_to_ec124_original_graph_projections -or
        -not [bool]$RetentionEndpointUntrigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointUntrigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointUntrigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointOctovigintupleInteraction -or
        [string]$RetentionEndpointOctovigintupleInteraction.scope -cne 'exact_strictly_twenty_eighth_order_twenty_eight_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointOctovigintupleInteraction.only_consumed_checked_ec093_to_ec121_original_graph_projections -or
        -not [bool]$RetentionEndpointOctovigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointOctovigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointOctovigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointQuattuorvigintupleInteraction.scope -cne 'exact_strictly_twenty_fourth_order_twenty_four_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuattuorvigintupleInteraction.only_consumed_checked_ec093_to_ec117_original_graph_projections -or
        -not [bool]$RetentionEndpointQuattuorvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuattuorvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuattuorvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointTrevigintupleInteraction.scope -cne 'exact_strictly_twenty_third_order_twenty_three_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointTrevigintupleInteraction.only_consumed_checked_ec093_to_ec116_original_graph_projections -or
        -not [bool]$RetentionEndpointTrevigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointTrevigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointTrevigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointVigintupleInteraction -or
        [string]$RetentionEndpointVigintupleInteraction.scope -cne 'exact_strictly_twentieth_order_twenty_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointVigintupleInteraction.only_consumed_checked_ec093_to_ec113_original_graph_projections -or
        -not [bool]$RetentionEndpointVigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointVigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointVigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        $null -eq $RetentionEndpointNovemdecupleInteraction -or
        [string]$RetentionEndpointNovemdecupleInteraction.scope -cne 'exact_strictly_nineteenth_order_nineteen_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointNovemdecupleInteraction.only_consumed_checked_ec093_to_ec112_original_graph_projections -or
        -not [bool]$RetentionEndpointNovemdecupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointNovemdecupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointNovemdecupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointOctodecupleInteraction.scope -cne 'exact_strictly_eighteenth_order_eighteen_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointOctodecupleInteraction.only_consumed_checked_ec093_to_ec111_original_graph_projections -or
        -not [bool]$RetentionEndpointOctodecupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointOctodecupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointOctodecupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointSeptendecupleInteraction.scope -cne 'exact_strictly_seventeenth_order_seventeen_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSeptendecupleInteraction.only_consumed_checked_ec093_to_ec110_original_graph_projections -or
        -not [bool]$RetentionEndpointSeptendecupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSeptendecupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointSeptendecupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
        [string]$RetentionEndpointSexdecupleInteraction.scope -cne 'exact_strictly_sixteenth_order_sixteen_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSexdecupleInteraction.only_consumed_checked_ec093_to_ec109_original_graph_projections -or
        -not [bool]$RetentionEndpointSexdecupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSexdecupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointSexdecupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence thirty_seven-link interaction requires successful ORIGINAL selector and checked EC-130.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence thirty_seven-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction,
        $RetentionEndpointTripleInteraction, $RetentionEndpointQuadrupleInteraction,
        $RetentionEndpointQuintupleInteraction, $RetentionEndpointSextupleInteraction,
        $RetentionEndpointSeptupleInteraction, $RetentionEndpointOctupleInteraction,
        $RetentionEndpointNonupleInteraction, $RetentionEndpointDecupleInteraction,
        $RetentionEndpointUndecupleInteraction, $RetentionEndpointDuodecupleInteraction,
        $RetentionEndpointTredecupleInteraction, $RetentionEndpointQuattuordecupleInteraction,
        $RetentionEndpointQuindecupleInteraction, $RetentionEndpointSexdecupleInteraction,
        $RetentionEndpointSeptendecupleInteraction, $RetentionEndpointOctodecupleInteraction,
        $RetentionEndpointNovemdecupleInteraction, $RetentionEndpointVigintupleInteraction,
        $RetentionEndpointUnvigintupleInteraction, $RetentionEndpointDuovigintupleInteraction,
        $RetentionEndpointTrevigintupleInteraction, $RetentionEndpointQuattuorvigintupleInteraction,
        $RetentionEndpointQuinquevigintupleInteraction,
        $RetentionEndpointSexvigintupleInteraction, $RetentionEndpointSeptemvigintupleInteraction,
        $RetentionEndpointOctovigintupleInteraction,
        $RetentionEndpointNovemvigintupleInteraction,
        $RetentionEndpointTrigintupleInteraction,
        $RetentionEndpointUntrigintupleInteraction,
        $RetentionEndpointDuotrigintupleInteraction,
        $RetentionEndpointTretrigintupleInteraction,
        $RetentionEndpointQuattuortrigintupleInteraction,
        $RetentionEndpointQuinquetrigintupleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence thirty_seven-link interaction detected changed original caller/pair/path/anchor provenance.'
        }
    }
    [object[]]$topsG = [object[]]$RetentionEndpointDominanceTopology.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$topsF = [object[]]$RetentionEndpointDominanceTopology.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$redsG = [object[]]$RetentionEndpointDominanceReduction.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$redsF = [object[]]$RetentionEndpointDominanceReduction.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$onesG = [object[]]$RetentionEndpointLinkImpact.genuine_global_threshold_endpoint_link_impact
    [object[]]$onesF = [object[]]$RetentionEndpointLinkImpact.frozen_global_threshold_endpoint_link_impact
    [object[]]$twosG = [object[]]$RetentionEndpointPairInteraction.genuine_global_threshold_endpoint_pair_interaction
    [object[]]$twosF = [object[]]$RetentionEndpointPairInteraction.frozen_global_threshold_endpoint_pair_interaction
    [object[]]$threesG = [object[]]$RetentionEndpointTripleInteraction.genuine_global_threshold_endpoint_triple_interaction
    [object[]]$threesF = [object[]]$RetentionEndpointTripleInteraction.frozen_global_threshold_endpoint_triple_interaction
    [object[]]$foursG = [object[]]$RetentionEndpointQuadrupleInteraction.genuine_global_threshold_endpoint_quadruple_interaction
    [object[]]$foursF = [object[]]$RetentionEndpointQuadrupleInteraction.frozen_global_threshold_endpoint_quadruple_interaction
    [object[]]$fivesG = [object[]]$RetentionEndpointQuintupleInteraction.genuine_global_threshold_endpoint_quintuple_interaction
    [object[]]$fivesF = [object[]]$RetentionEndpointQuintupleInteraction.frozen_global_threshold_endpoint_quintuple_interaction
    [object[]]$sixesG = [object[]]$RetentionEndpointSextupleInteraction.genuine_global_threshold_endpoint_sextuple_interaction
    [object[]]$sixesF = [object[]]$RetentionEndpointSextupleInteraction.frozen_global_threshold_endpoint_sextuple_interaction
    [object[]]$sevensG = [object[]]$RetentionEndpointSeptupleInteraction.genuine_global_threshold_endpoint_septuple_interaction
    [object[]]$sevensF = [object[]]$RetentionEndpointSeptupleInteraction.frozen_global_threshold_endpoint_septuple_interaction
    [object[]]$eightsG = [object[]]$RetentionEndpointOctupleInteraction.genuine_global_threshold_endpoint_octuple_interaction
    [object[]]$eightsF = [object[]]$RetentionEndpointOctupleInteraction.frozen_global_threshold_endpoint_octuple_interaction
    [object[]]$ninesG = [object[]]$RetentionEndpointNonupleInteraction.genuine_global_threshold_endpoint_nonuple_interaction
    [object[]]$ninesF = [object[]]$RetentionEndpointNonupleInteraction.frozen_global_threshold_endpoint_nonuple_interaction
    [object[]]$tensG = [object[]]$RetentionEndpointDecupleInteraction.genuine_global_threshold_endpoint_decuple_interaction
    [object[]]$tensF = [object[]]$RetentionEndpointDecupleInteraction.frozen_global_threshold_endpoint_decuple_interaction
    [object[]]$elevensG = [object[]]$RetentionEndpointUndecupleInteraction.genuine_global_threshold_endpoint_undecuple_interaction
    [object[]]$elevensF = [object[]]$RetentionEndpointUndecupleInteraction.frozen_global_threshold_endpoint_undecuple_interaction
    [object[]]$twelvesG = [object[]]$RetentionEndpointDuodecupleInteraction.genuine_global_threshold_endpoint_duodecuple_interaction
    [object[]]$twelvesF = [object[]]$RetentionEndpointDuodecupleInteraction.frozen_global_threshold_endpoint_duodecuple_interaction
    [object[]]$thirteensG = [object[]]$RetentionEndpointTredecupleInteraction.genuine_global_threshold_endpoint_tredecuple_interaction
    [object[]]$thirteensF = [object[]]$RetentionEndpointTredecupleInteraction.frozen_global_threshold_endpoint_tredecuple_interaction
    [object[]]$fourteensG = [object[]]$RetentionEndpointQuattuordecupleInteraction.genuine_global_threshold_endpoint_quattuordecuple_interaction
    [object[]]$fourteensF = [object[]]$RetentionEndpointQuattuordecupleInteraction.frozen_global_threshold_endpoint_quattuordecuple_interaction
    [object[]]$fifteensG = [object[]]$RetentionEndpointQuindecupleInteraction.genuine_global_threshold_endpoint_quindecuple_interaction
    [object[]]$fifteensF = [object[]]$RetentionEndpointQuindecupleInteraction.frozen_global_threshold_endpoint_quindecuple_interaction
    [object[]]$sixteensG = [object[]]$RetentionEndpointSexdecupleInteraction.genuine_global_threshold_endpoint_sexdecuple_interaction
    [object[]]$sixteensF = [object[]]$RetentionEndpointSexdecupleInteraction.frozen_global_threshold_endpoint_sexdecuple_interaction
    [object[]]$seventeensG = [object[]]$RetentionEndpointSeptendecupleInteraction.genuine_global_threshold_endpoint_septendecuple_interaction
    [object[]]$seventeensF = [object[]]$RetentionEndpointSeptendecupleInteraction.frozen_global_threshold_endpoint_septendecuple_interaction
    [object[]]$eighteensG = [object[]]$RetentionEndpointOctodecupleInteraction.genuine_global_threshold_endpoint_octodecuple_interaction
    [object[]]$eighteensF = [object[]]$RetentionEndpointOctodecupleInteraction.frozen_global_threshold_endpoint_octodecuple_interaction
    [object[]]$nineteensG = [object[]]$RetentionEndpointNovemdecupleInteraction.genuine_global_threshold_endpoint_novemdecuple_interaction
    [object[]]$twentyG = [object[]]$RetentionEndpointVigintupleInteraction.genuine_global_threshold_endpoint_vigintuple_interaction
    [object[]]$nineteensF = [object[]]$RetentionEndpointNovemdecupleInteraction.frozen_global_threshold_endpoint_novemdecuple_interaction
    [object[]]$twentyF = [object[]]$RetentionEndpointVigintupleInteraction.frozen_global_threshold_endpoint_vigintuple_interaction
    [object[]]$twentyOneG = [object[]]$RetentionEndpointUnvigintupleInteraction.genuine_global_threshold_endpoint_unvigintuple_interaction
    [object[]]$twentyTwoG = [object[]]$RetentionEndpointDuovigintupleInteraction.genuine_global_threshold_endpoint_duovigintuple_interaction
    [object[]]$twentyOneF = [object[]]$RetentionEndpointUnvigintupleInteraction.frozen_global_threshold_endpoint_unvigintuple_interaction
    [object[]]$twentyTwoF = [object[]]$RetentionEndpointDuovigintupleInteraction.frozen_global_threshold_endpoint_duovigintuple_interaction
    [object[]]$twentyThreeG = [object[]]$RetentionEndpointTrevigintupleInteraction.genuine_global_threshold_endpoint_trevigintuple_interaction
    [object[]]$twentyFourG = [object[]]$RetentionEndpointQuattuorvigintupleInteraction.genuine_global_threshold_endpoint_quattuorvigintuple_interaction
    [object[]]$twentyFiveG = [object[]]$RetentionEndpointQuinquevigintupleInteraction.genuine_global_threshold_endpoint_quinquevigintuple_interaction
    [object[]]$twentyThreeF = [object[]]$RetentionEndpointTrevigintupleInteraction.frozen_global_threshold_endpoint_trevigintuple_interaction
    [object[]]$twentyFourF = [object[]]$RetentionEndpointQuattuorvigintupleInteraction.frozen_global_threshold_endpoint_quattuorvigintuple_interaction
    [object[]]$twentyFiveF = [object[]]$RetentionEndpointQuinquevigintupleInteraction.frozen_global_threshold_endpoint_quinquevigintuple_interaction
    [object[]]$twentySixG = [object[]]$RetentionEndpointSexvigintupleInteraction.genuine_global_threshold_endpoint_sexvigintuple_interaction
    [object[]]$twentySixF = [object[]]$RetentionEndpointSexvigintupleInteraction.frozen_global_threshold_endpoint_sexvigintuple_interaction
    [object[]]$twentySevenG = [object[]]$RetentionEndpointSeptemvigintupleInteraction.genuine_global_threshold_endpoint_septemvigintuple_interaction
    [object[]]$twentySevenF = [object[]]$RetentionEndpointSeptemvigintupleInteraction.frozen_global_threshold_endpoint_septemvigintuple_interaction
    [object[]]$twentyEightG = [object[]]$RetentionEndpointOctovigintupleInteraction.genuine_global_threshold_endpoint_octovigintuple_interaction
    [object[]]$twentyEightF = [object[]]$RetentionEndpointOctovigintupleInteraction.frozen_global_threshold_endpoint_octovigintuple_interaction
    [object[]]$twentyNineG = [object[]]$RetentionEndpointNovemvigintupleInteraction.genuine_global_threshold_endpoint_novemvigintuple_interaction
    [object[]]$twentyNineF = [object[]]$RetentionEndpointNovemvigintupleInteraction.frozen_global_threshold_endpoint_novemvigintuple_interaction
    [object[]]$thirtyG = [object[]]$RetentionEndpointTrigintupleInteraction.genuine_global_threshold_endpoint_trigintuple_interaction
    [object[]]$thirtyF = [object[]]$RetentionEndpointTrigintupleInteraction.frozen_global_threshold_endpoint_trigintuple_interaction
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    [object[]]$threeFamilies = [object[]]$RetentionEndpointTripleInteraction.individual_original_family_endpoint_triple_interaction
    [object[]]$fourFamilies = [object[]]$RetentionEndpointQuadrupleInteraction.individual_original_family_endpoint_quadruple_interaction
    [object[]]$fiveFamilies = [object[]]$RetentionEndpointQuintupleInteraction.individual_original_family_endpoint_quintuple_interaction
    [object[]]$sixFamilies = [object[]]$RetentionEndpointSextupleInteraction.individual_original_family_endpoint_sextuple_interaction
    [object[]]$sevenFamilies = [object[]]$RetentionEndpointSeptupleInteraction.individual_original_family_endpoint_septuple_interaction
    [object[]]$eightFamilies = [object[]]$RetentionEndpointOctupleInteraction.individual_original_family_endpoint_octuple_interaction
    [object[]]$nineFamilies = [object[]]$RetentionEndpointNonupleInteraction.individual_original_family_endpoint_nonuple_interaction
    [object[]]$tenFamilies = [object[]]$RetentionEndpointDecupleInteraction.individual_original_family_endpoint_decuple_interaction
    [object[]]$elevenFamilies = [object[]]$RetentionEndpointUndecupleInteraction.individual_original_family_endpoint_undecuple_interaction
    [object[]]$twelveFamilies = [object[]]$RetentionEndpointDuodecupleInteraction.individual_original_family_endpoint_duodecuple_interaction
    [object[]]$thirteenFamilies = [object[]]$RetentionEndpointTredecupleInteraction.individual_original_family_endpoint_tredecuple_interaction
    [object[]]$fourteenFamilies = [object[]]$RetentionEndpointQuattuordecupleInteraction.individual_original_family_endpoint_quattuordecuple_interaction
    [object[]]$fifteenFamilies = [object[]]$RetentionEndpointQuindecupleInteraction.individual_original_family_endpoint_quindecuple_interaction
    [object[]]$sixteenFamilies = [object[]]$RetentionEndpointSexdecupleInteraction.individual_original_family_endpoint_sexdecuple_interaction
    [object[]]$seventeenFamilies = [object[]]$RetentionEndpointSeptendecupleInteraction.individual_original_family_endpoint_septendecuple_interaction
    [object[]]$eighteenFamilies = [object[]]$RetentionEndpointOctodecupleInteraction.individual_original_family_endpoint_octodecuple_interaction
    [object[]]$nineteenFamilies = [object[]]$RetentionEndpointNovemdecupleInteraction.individual_original_family_endpoint_novemdecuple_interaction
    [object[]]$twentyFamilies = [object[]]$RetentionEndpointVigintupleInteraction.individual_original_family_endpoint_vigintuple_interaction
    [object[]]$twentyOneFamilies = [object[]]$RetentionEndpointUnvigintupleInteraction.individual_original_family_endpoint_unvigintuple_interaction
    [object[]]$twentyTwoFamilies = [object[]]$RetentionEndpointDuovigintupleInteraction.individual_original_family_endpoint_duovigintuple_interaction
    [object[]]$twentyThreeFamilies = [object[]]$RetentionEndpointTrevigintupleInteraction.individual_original_family_endpoint_trevigintuple_interaction
    [object[]]$twentyFourFamilies = [object[]]$RetentionEndpointQuattuorvigintupleInteraction.individual_original_family_endpoint_quattuorvigintuple_interaction
    [object[]]$twentyFiveFamilies = [object[]]$RetentionEndpointQuinquevigintupleInteraction.individual_original_family_endpoint_quinquevigintuple_interaction
    [object[]]$twentySixFamilies = [object[]]$RetentionEndpointSexvigintupleInteraction.individual_original_family_endpoint_sexvigintuple_interaction
    [object[]]$twentySevenFamilies = [object[]]$RetentionEndpointSeptemvigintupleInteraction.individual_original_family_endpoint_septemvigintuple_interaction
    [object[]]$twentyEightFamilies = [object[]]$RetentionEndpointOctovigintupleInteraction.individual_original_family_endpoint_octovigintuple_interaction
    [object[]]$twentyNineFamilies = [object[]]$RetentionEndpointNovemvigintupleInteraction.individual_original_family_endpoint_novemvigintuple_interaction
    [object[]]$thirtyFamilies = [object[]]$RetentionEndpointTrigintupleInteraction.individual_original_family_endpoint_trigintuple_interaction
    [object[]]$thirtyOneG = [object[]]$RetentionEndpointUntrigintupleInteraction.genuine_global_threshold_endpoint_untrigintuple_interaction
    [object[]]$thirtyOneF = [object[]]$RetentionEndpointUntrigintupleInteraction.frozen_global_threshold_endpoint_untrigintuple_interaction
    [object[]]$thirtyOneFamilies = [object[]]$RetentionEndpointUntrigintupleInteraction.individual_original_family_endpoint_untrigintuple_interaction
    [object[]]$thirtyTwoG = [object[]]$RetentionEndpointDuotrigintupleInteraction.genuine_global_threshold_endpoint_duotrigintuple_interaction
    [object[]]$thirtyTwoF = [object[]]$RetentionEndpointDuotrigintupleInteraction.frozen_global_threshold_endpoint_duotrigintuple_interaction
    [object[]]$thirtyTwoFamilies = [object[]]$RetentionEndpointDuotrigintupleInteraction.individual_original_family_endpoint_duotrigintuple_interaction
    [object[]]$thirtyThreeG = [object[]]$RetentionEndpointTretrigintupleInteraction.genuine_global_threshold_endpoint_tretrigintuple_interaction
    [object[]]$thirtyThreeF = [object[]]$RetentionEndpointTretrigintupleInteraction.frozen_global_threshold_endpoint_tretrigintuple_interaction
    [object[]]$thirtyThreeFamilies = [object[]]$RetentionEndpointTretrigintupleInteraction.individual_original_family_endpoint_tretrigintuple_interaction
    [object[]]$thirtyFourG = [object[]]$RetentionEndpointQuattuortrigintupleInteraction.genuine_global_threshold_endpoint_quattuortrigintuple_interaction
    [object[]]$thirtyFourF = [object[]]$RetentionEndpointQuattuortrigintupleInteraction.frozen_global_threshold_endpoint_quattuortrigintuple_interaction
    [object[]]$thirtyFourFamilies = [object[]]$RetentionEndpointQuattuortrigintupleInteraction.individual_original_family_endpoint_quattuortrigintuple_interaction
    [object[]]$thirtyFiveG = [object[]]$RetentionEndpointQuinquetrigintupleInteraction.genuine_global_threshold_endpoint_quinquetrigintuple_interaction
    [object[]]$thirtySixG = [object[]]$RetentionEndpointSextrigintupleInteraction.genuine_global_threshold_endpoint_sextrigintuple_interaction
    [object[]]$thirtyFiveF = [object[]]$RetentionEndpointQuinquetrigintupleInteraction.frozen_global_threshold_endpoint_quinquetrigintuple_interaction
    [object[]]$thirtySixF = [object[]]$RetentionEndpointSextrigintupleInteraction.frozen_global_threshold_endpoint_sextrigintuple_interaction
    [object[]]$thirtyFiveFamilies = [object[]]$RetentionEndpointQuinquetrigintupleInteraction.individual_original_family_endpoint_quinquetrigintuple_interaction
    [object[]]$thirtySixFamilies = [object[]]$RetentionEndpointSextrigintupleInteraction.individual_original_family_endpoint_sextrigintuple_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $threesG.Length -ne 3 -or $threesF.Length -ne 3 -or
        $foursG.Length -ne 3 -or $foursF.Length -ne 3 -or
        $fivesG.Length -ne 3 -or $fivesF.Length -ne 3 -or
        $sixesG.Length -ne 3 -or $sixesF.Length -ne 3 -or
        $sevensG.Length -ne 3 -or $sevensF.Length -ne 3 -or
        $eightsG.Length -ne 3 -or $eightsF.Length -ne 3 -or
        $ninesG.Length -ne 3 -or $ninesF.Length -ne 3 -or
        $tensG.Length -ne 3 -or $tensF.Length -ne 3 -or
        $elevensG.Length -ne 3 -or $elevensF.Length -ne 3 -or
        $twelvesG.Length -ne 3 -or $twelvesF.Length -ne 3 -or
        $thirteensG.Length -ne 3 -or $thirteensF.Length -ne 3 -or
        $fourteensG.Length -ne 3 -or $fourteensF.Length -ne 3 -or
        $fifteensG.Length -ne 3 -or $fifteensF.Length -ne 3 -or
        $sixteensG.Length -ne 3 -or $sixteensF.Length -ne 3 -or
        $seventeensG.Length -ne 3 -or $seventeensF.Length -ne 3 -or
        $eighteensG.Length -ne 3 -or $eighteensF.Length -ne 3 -or
        $nineteensG.Length -ne 3 -or $nineteensF.Length -ne 3 -or $twentyG.Length -ne 3 -or $twentyF.Length -ne 3 -or
        $twentyOneG.Length -ne 3 -or $twentyOneF.Length -ne 3 -or
        $twentyTwoG.Length -ne 3 -or $twentyTwoF.Length -ne 3 -or
        $twentyThreeG.Length -ne 3 -or $twentyThreeF.Length -ne 3 -or
        $twentyFourG.Length -ne 3 -or $twentyFourF.Length -ne 3 -or
        $twentyFiveG.Length -ne 3 -or $twentyFiveF.Length -ne 3 -or
        $twentySixG.Length -ne 3 -or $twentySixF.Length -ne 3 -or
        $twentySevenG.Length -ne 3 -or $twentySevenF.Length -ne 3 -or
        $twentyEightG.Length -ne 3 -or $twentyEightF.Length -ne 3 -or
        $twentyNineG.Length -ne 3 -or $twentyNineF.Length -ne 3 -or
        $thirtyG.Length -ne 3 -or $thirtyF.Length -ne 3 -or
        $thirtyOneG.Length -ne 3 -or $thirtyOneF.Length -ne 3 -or
        $thirtyTwoG.Length -ne 3 -or $thirtyTwoF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount -or
        $threeFamilies.Length -ne $familyCount -or $fourFamilies.Length -ne $familyCount -or
        $fiveFamilies.Length -ne $familyCount -or $sixFamilies.Length -ne $familyCount -or
        $sevenFamilies.Length -ne $familyCount -or
        $eightFamilies.Length -ne $familyCount -or
        $nineFamilies.Length -ne $familyCount -or
        $tenFamilies.Length -ne $familyCount -or
        $elevenFamilies.Length -ne $familyCount -or
        $twelveFamilies.Length -ne $familyCount -or
        $thirteenFamilies.Length -ne $familyCount -or
        $fourteenFamilies.Length -ne $familyCount -or
        $fifteenFamilies.Length -ne $familyCount -or
        $sixteenFamilies.Length -ne $familyCount -or
        $seventeenFamilies.Length -ne $familyCount -or
        $eighteenFamilies.Length -ne $familyCount -or
        $nineteenFamilies.Length -ne $familyCount -or $twentyFamilies.Length -ne $familyCount -or
        $twentyOneFamilies.Length -ne $familyCount -or
        $twentyTwoFamilies.Length -ne $familyCount -or
        $twentyThreeFamilies.Length -ne $familyCount -or
        $twentyFourFamilies.Length -ne $familyCount -or
        $twentyFiveFamilies.Length -ne $familyCount -or
        $twentySixFamilies.Length -ne $familyCount -or
        $twentySevenFamilies.Length -ne $familyCount -or
        $twentyEightFamilies.Length -ne $familyCount -or
        $twentyNineFamilies.Length -ne $familyCount -or
        $thirtyFamilies.Length -ne $familyCount -or
        $thirtyOneFamilies.Length -ne $familyCount -or
        $thirtyTwoFamilies.Length -ne $familyCount -or
        $thirtyThreeG.Length -ne 3 -or $thirtyThreeF.Length -ne 3 -or
        $thirtyThreeFamilies.Length -ne $familyCount -or
        $thirtyFourG.Length -ne 3 -or $thirtyFourF.Length -ne 3 -or
        $thirtyFourFamilies.Length -ne $familyCount -or
        $thirtyFiveG.Length -ne 3 -or $thirtyFiveF.Length -ne 3 -or
        $thirtyFiveFamilies.Length -ne $familyCount -or
        $thirtySixG.Length -ne 3 -or $thirtySixF.Length -ne 3 -or
        $thirtySixFamilies.Length -ne $familyCount) {
        throw 'Code Sequence thirty_seven-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
    }
    $genuine = [System.Collections.Generic.List[object]]::new()
    $frozen = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $tops = if ($mode -eq 0) { $topsG } else { $topsF }
        $reds = if ($mode -eq 0) { $redsG } else { $redsF }
        $ones = if ($mode -eq 0) { $onesG } else { $onesF }
        $twos = if ($mode -eq 0) { $twosG } else { $twosF }
        $threes = if ($mode -eq 0) { $threesG } else { $threesF }
        $fours = if ($mode -eq 0) { $foursG } else { $foursF }
        $fives = if ($mode -eq 0) { $fivesG } else { $fivesF }
        $sixes = if ($mode -eq 0) { $sixesG } else { $sixesF }
        $sevens = if ($mode -eq 0) { $sevensG } else { $sevensF }
        $eights = if ($mode -eq 0) { $eightsG } else { $eightsF }
        $nines = if ($mode -eq 0) { $ninesG } else { $ninesF }
        $tens = if ($mode -eq 0) { $tensG } else { $tensF }
        $elevens = if ($mode -eq 0) { $elevensG } else { $elevensF }
        $twelves = if ($mode -eq 0) { $twelvesG } else { $twelvesF }
        $thirteens = if ($mode -eq 0) { $thirteensG } else { $thirteensF }
        $fourteens = if ($mode -eq 0) { $fourteensG } else { $fourteensF }
        $fifteens = if ($mode -eq 0) { $fifteensG } else { $fifteensF }
        $sixteens = if ($mode -eq 0) { $sixteensG } else { $sixteensF }
        $seventeens = if ($mode -eq 0) { $seventeensG } else { $seventeensF }
        $eighteens = if ($mode -eq 0) { $eighteensG } else { $eighteensF }
        $nineteens = if ($mode -eq 0) { $nineteensG } else { $nineteensF }
        $twenties = if ($mode -eq 0) { $twentyG } else { $twentyF }
        $twentyOnes = if ($mode -eq 0) { $twentyOneG } else { $twentyOneF }
        $twentyTwos = if ($mode -eq 0) { $twentyTwoG } else { $twentyTwoF }
        $twentyThrees = if ($mode -eq 0) { $twentyThreeG } else { $twentyThreeF }
        $twentyFours = if ($mode -eq 0) { $twentyFourG } else { $twentyFourF }
        $twentyFives = if ($mode -eq 0) { $twentyFiveG } else { $twentyFiveF }
        $twentySixes = if ($mode -eq 0) { $twentySixG } else { $twentySixF }
        $twentySevens = if ($mode -eq 0) { $twentySevenG } else { $twentySevenF }
        $twentyEights = if ($mode -eq 0) { $twentyEightG } else { $twentyEightF }
        $twentyNines = if ($mode -eq 0) { $twentyNineG } else { $twentyNineF }
        $thirties = if ($mode -eq 0) { $thirtyG } else { $thirtyF }
        $thirtyOnes = if ($mode -eq 0) { $thirtyOneG } else { $thirtyOneF }
        $thirtyTwos = if ($mode -eq 0) { $thirtyTwoG } else { $thirtyTwoF }
        $thirtyThrees = if ($mode -eq 0) { $thirtyThreeG } else { $thirtyThreeF }
        $thirtyFours = if ($mode -eq 0) { $thirtyFourG } else { $thirtyFourF }
        $thirtyFives = if ($mode -eq 0) { $thirtyFiveG } else { $thirtyFiveF }
        $thirtySixes = if ($mode -eq 0) { $thirtySixG } else { $thirtySixF }
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            $two = $twos[$i]; $three = $threes[$i]; $four = $fours[$i]
            $five = $fives[$i]; $six = $sixes[$i]; $seven = $sevens[$i]
            $eight = $eights[$i]; $nine = $nines[$i]; $ten = $tens[$i]
            $eleven = $elevens[$i]; $twelve = $twelves[$i]
            $thirteen = $thirteens[$i]; $fourteen = $fourteens[$i]
            $fifteen = $fifteens[$i]; $sixteen = $sixteens[$i]
            $seventeen = $seventeens[$i]
            $eighteen = $eighteens[$i]
            $nineteen = $nineteens[$i]
            $twenty = $twenties[$i]
            $twentyOne = $twentyOnes[$i]
            $twentyTwo = $twentyTwos[$i]
            $twentyThree = $twentyThrees[$i]
            $twentyFour = $twentyFours[$i]
            $twentyFive = $twentyFives[$i]
            $twentySix = $twentySixes[$i]
            $twentySeven = $twentySevens[$i]
            $twentyEight = $twentyEights[$i]
            $twentyNine = $twentyNines[$i]
            $thirty = $thirties[$i]
            $thirtyOne = $thirtyOnes[$i]
            $thirtyTwo = $thirtyTwos[$i]
            $thirtyThree = $thirtyThrees[$i]
            $thirtyFour = $thirtyFours[$i]
            $thirtyFive = $thirtyFives[$i]
            $thirtySix = $thirtySixes[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or $null -eq $four -or
                $null -eq $five -or $null -eq $six -or $null -eq $seven -or
                $null -eq $eight -or $null -eq $nine -or $null -eq $ten -or
                $null -eq $eleven -or $null -eq $twelve -or $null -eq $thirteen -or $null -eq $fourteen -or $null -eq $fifteen -or $null -eq $sixteen -or $null -eq $seventeen -or $null -eq $eighteen -or
                $null -eq $nineteen -or $null -eq $twenty -or $null -eq $twentyOne -or $null -eq $twentyTwo -or $null -eq $twentyThree -or $null -eq $twentyFour -or $null -eq $twentyFive -or $null -eq $twentySix -or $null -eq $twentySeven -or $null -eq $twentyEight -or $null -eq $twentyNine -or $null -eq $thirty -or $null -eq $thirtyOne -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$one.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$two.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$three.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$four.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$five.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$six.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$seven.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$eight.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$nine.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$ten.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$eleven.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twelve.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$fourteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$fifteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$sixteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$seventeen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$eighteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$nineteen.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twenty.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyOne.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyTwo.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyThree.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyFour.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyFive.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentySix.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentySeven.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyEight.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$twentyNine.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirty.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtyOne.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtyTwo.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtyThree.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtyFour.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtyFive.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$thirtySix.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$three.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$four.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$five.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$six.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$seven.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$eight.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$nine.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$ten.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$eleven.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twelve.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$fourteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$fifteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$sixteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$seventeen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$eighteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$nineteen.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twenty.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyOne.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyTwo.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyThree.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyFour.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyFive.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentySix.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentySeven.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyEight.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$twentyNine.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirty.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtyOne.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtyTwo.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtyThree.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtyFour.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtyFive.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$thirtySix.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence thirty_seven-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_thirty_seventh_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceThirtySevenLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction `
                        -TripleInteraction $three.exact_strictly_triple_only_original_scc_link_removal_interaction `
                        -QuadrupleInteraction $four.exact_strictly_fourth_only_original_scc_link_removal_interaction `
                        -QuintupleInteraction $five.exact_strictly_fifth_only_original_scc_link_removal_interaction `
                        -SextupleInteraction $six.exact_strictly_sixth_only_original_scc_link_removal_interaction `
                        -SeptupleInteraction $seven.exact_strictly_seventh_only_original_scc_link_removal_interaction `
                        -OctupleInteraction $eight.exact_strictly_eighth_only_original_scc_link_removal_interaction `
                        -NonupleInteraction $nine.exact_strictly_ninth_only_original_scc_link_removal_interaction `
                        -DecupleInteraction $ten.exact_strictly_tenth_only_original_scc_link_removal_interaction `
                        -UndecupleInteraction $eleven.exact_strictly_eleventh_only_original_scc_link_removal_interaction `
                    -DuodecupleInteraction $twelve.exact_strictly_twelfth_only_original_scc_link_removal_interaction `
                    -TredecupleInteraction $thirteen.exact_strictly_thirteenth_only_original_scc_link_removal_interaction `
                        -QuattuordecupleInteraction $fourteen.exact_strictly_fourteenth_only_original_scc_link_removal_interaction `
                        -QuindecupleInteraction $fifteen.exact_strictly_fifteenth_only_original_scc_link_removal_interaction `
                        -SexdecupleInteraction $sixteen.exact_strictly_sixteenth_only_original_scc_link_removal_interaction `
                        -SeptendecupleInteraction $seventeen.exact_strictly_seventeenth_only_original_scc_link_removal_interaction `
                        -OctodecupleInteraction $eighteen.exact_strictly_eighteenth_only_original_scc_link_removal_interaction `
                        -NovemdecupleInteraction $nineteen.exact_strictly_nineteenth_only_original_scc_link_removal_interaction `
                        -VigintupleInteraction $twenty.exact_strictly_twentieth_only_original_scc_link_removal_interaction `
                        -UnvigintupleInteraction $twentyOne.exact_strictly_twenty_first_only_original_scc_link_removal_interaction `
                        -DuovigintupleInteraction $twentyTwo.exact_strictly_twenty_second_only_original_scc_link_removal_interaction `
                        -TrevigintupleInteraction $twentyThree.exact_strictly_twenty_third_only_original_scc_link_removal_interaction `
                        -QuattuorvigintupleInteraction $twentyFour.exact_strictly_twenty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquevigintupleInteraction $twentyFive.exact_strictly_twenty_fifth_only_original_scc_link_removal_interaction `
                    -SexvigintupleInteraction $twentySix.exact_strictly_twenty_sixth_only_original_scc_link_removal_interaction `
                    -SeptemvigintupleInteraction $twentySeven.exact_strictly_twenty_seventh_only_original_scc_link_removal_interaction `
                    -OctovigintupleInteraction $twentyEight.exact_strictly_twenty_eighth_only_original_scc_link_removal_interaction `
                    -NovemvigintupleInteraction $twentyNine.exact_strictly_twenty_ninth_only_original_scc_link_removal_interaction `
                    -TrigintupleInteraction $thirty.exact_strictly_thirtieth_only_original_scc_link_removal_interaction `
                    -UntrigintupleInteraction $thirtyOne.exact_strictly_thirty_first_only_original_scc_link_removal_interaction `
                    -DuotrigintupleInteraction $thirtyTwo.exact_strictly_thirty_second_only_original_scc_link_removal_interaction `
                    -TretrigintupleInteraction $thirtyThree.exact_strictly_thirty_third_only_original_scc_link_removal_interaction `
                    -QuattuortrigintupleInteraction $thirtyFour.exact_strictly_thirty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquetrigintupleInteraction $thirtyFive.exact_strictly_thirty_fifth_only_original_scc_link_removal_interaction `
                    -SextrigintupleInteraction $thirtySix.exact_strictly_thirty_sixth_only_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        $two = $twoFamilies[$i]; $three = $threeFamilies[$i]; $four = $fourFamilies[$i]
        $five = $fiveFamilies[$i]; $six = $sixFamilies[$i]; $seven = $sevenFamilies[$i]
        $eight = $eightFamilies[$i]; $nine = $nineFamilies[$i]; $ten = $tenFamilies[$i]
        $eleven = $elevenFamilies[$i]; $twelve = $twelveFamilies[$i]
        $thirteen = $thirteenFamilies[$i]; $fourteen = $fourteenFamilies[$i]
        $fifteen = $fifteenFamilies[$i]; $sixteen = $sixteenFamilies[$i]
        $seventeen = $seventeenFamilies[$i]
        $eighteen = $eighteenFamilies[$i]
        $nineteen = $nineteenFamilies[$i]
        $twenty = $twentyFamilies[$i]
        $twentyOne = $twentyOneFamilies[$i]
        $twentyTwo = $twentyTwoFamilies[$i]
        $twentyThree = $twentyThreeFamilies[$i]
        $twentyFour = $twentyFourFamilies[$i]
        $twentyFive = $twentyFiveFamilies[$i]
        $twentySix = $twentySixFamilies[$i]
        $twentySeven = $twentySevenFamilies[$i]
        $twentyEight = $twentyEightFamilies[$i]
        $twentyNine = $twentyNineFamilies[$i]
        $thirty = $thirtyFamilies[$i]
        $thirtyOne = $thirtyOneFamilies[$i]
        $thirtyTwo = $thirtyTwoFamilies[$i]
        $thirtyThree = $thirtyThreeFamilies[$i]
        $thirtyFour = $thirtyFourFamilies[$i]
        $thirtyFive = $thirtyFiveFamilies[$i]
        $thirtySix = $thirtySixFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or $null -eq $four -or
            $null -eq $five -or $null -eq $six -or $null -eq $seven -or
                $null -eq $eight -or $null -eq $nine -or $null -eq $ten -or
                $null -eq $eleven -or $null -eq $twelve -or $null -eq $thirteen -or $null -eq $fourteen -or $null -eq $fifteen -or $null -eq $sixteen -or $null -eq $seventeen -or
                $null -eq $eighteen -or $null -eq $nineteen -or $null -eq $twenty -or $null -eq $twentyOne -or $null -eq $twentyTwo -or $null -eq $twentyThree -or
                $null -eq $twentyFour -or $null -eq $twentyFive -or $null -eq $twentySix -or $null -eq $twentySeven -or $null -eq $twentyEight -or $null -eq $twentyNine -or $null -eq $thirty -or $null -eq $thirtyOne -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$three.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$four.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$five.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$six.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$seven.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$eight.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$nine.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$ten.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$eleven.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twelve.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$fourteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$fifteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$sixteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$seventeen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$eighteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$nineteen.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twenty.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyOne.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyTwo.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyThree.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyFour.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyFive.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentySix.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentySeven.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyEight.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$twentyNine.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirty.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtyOne.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtyTwo.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtyThree.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtyFour.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtyFive.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$thirtySix.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence thirty_seven-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_thirty_seventh_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceThirtySevenLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.genuine_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.genuine_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.genuine_exact_strictly_fifth_only_original_scc_link_removal_interaction `
                    -SextupleInteraction $six.genuine_exact_strictly_sixth_only_original_scc_link_removal_interaction `
                    -SeptupleInteraction $seven.genuine_exact_strictly_seventh_only_original_scc_link_removal_interaction `
                    -OctupleInteraction $eight.genuine_exact_strictly_eighth_only_original_scc_link_removal_interaction `
                    -NonupleInteraction $nine.genuine_exact_strictly_ninth_only_original_scc_link_removal_interaction `
                    -DecupleInteraction $ten.genuine_exact_strictly_tenth_only_original_scc_link_removal_interaction `
                    -UndecupleInteraction $eleven.genuine_exact_strictly_eleventh_only_original_scc_link_removal_interaction `
                    -DuodecupleInteraction $twelve.genuine_exact_strictly_twelfth_only_original_scc_link_removal_interaction `
                    -TredecupleInteraction $thirteen.genuine_exact_strictly_thirteenth_only_original_scc_link_removal_interaction `
                    -QuattuordecupleInteraction $fourteen.genuine_exact_strictly_fourteenth_only_original_scc_link_removal_interaction `
                    -QuindecupleInteraction $fifteen.genuine_exact_strictly_fifteenth_only_original_scc_link_removal_interaction `
                    -SexdecupleInteraction $sixteen.genuine_exact_strictly_sixteenth_only_original_scc_link_removal_interaction `
                    -SeptendecupleInteraction $seventeen.genuine_exact_strictly_seventeenth_only_original_scc_link_removal_interaction `
                    -OctodecupleInteraction $eighteen.genuine_exact_strictly_eighteenth_only_original_scc_link_removal_interaction `
                    -NovemdecupleInteraction $nineteen.genuine_exact_strictly_nineteenth_only_original_scc_link_removal_interaction `
                    -VigintupleInteraction $twenty.genuine_exact_strictly_twentieth_only_original_scc_link_removal_interaction `
                    -UnvigintupleInteraction $twentyOne.genuine_exact_strictly_twenty_first_only_original_scc_link_removal_interaction `
                    -DuovigintupleInteraction $twentyTwo.genuine_exact_strictly_twenty_second_only_original_scc_link_removal_interaction `
                    -TrevigintupleInteraction $twentyThree.genuine_exact_strictly_twenty_third_only_original_scc_link_removal_interaction `
                    -QuattuorvigintupleInteraction $twentyFour.genuine_exact_strictly_twenty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquevigintupleInteraction $twentyFive.genuine_exact_strictly_twenty_fifth_only_original_scc_link_removal_interaction `
                    -SexvigintupleInteraction $twentySix.genuine_exact_strictly_twenty_sixth_only_original_scc_link_removal_interaction `
                    -SeptemvigintupleInteraction $twentySeven.genuine_exact_strictly_twenty_seventh_only_original_scc_link_removal_interaction `
                    -OctovigintupleInteraction $twentyEight.genuine_exact_strictly_twenty_eighth_only_original_scc_link_removal_interaction `
                    -NovemvigintupleInteraction $twentyNine.genuine_exact_strictly_twenty_ninth_only_original_scc_link_removal_interaction `
                    -TrigintupleInteraction $thirty.genuine_exact_strictly_thirtieth_only_original_scc_link_removal_interaction `
                    -UntrigintupleInteraction $thirtyOne.genuine_exact_strictly_thirty_first_only_original_scc_link_removal_interaction `
                    -DuotrigintupleInteraction $thirtyTwo.genuine_exact_strictly_thirty_second_only_original_scc_link_removal_interaction `
                    -TretrigintupleInteraction $thirtyThree.genuine_exact_strictly_thirty_third_only_original_scc_link_removal_interaction `
                    -QuattuortrigintupleInteraction $thirtyFour.genuine_exact_strictly_thirty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquetrigintupleInteraction $thirtyFive.genuine_exact_strictly_thirty_fifth_only_original_scc_link_removal_interaction `
                    -SextrigintupleInteraction $thirtySix.genuine_exact_strictly_thirty_sixth_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_thirty_seventh_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceThirtySevenLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.frozen_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.frozen_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.frozen_exact_strictly_fifth_only_original_scc_link_removal_interaction `
                    -SextupleInteraction $six.frozen_exact_strictly_sixth_only_original_scc_link_removal_interaction `
                    -SeptupleInteraction $seven.frozen_exact_strictly_seventh_only_original_scc_link_removal_interaction `
                    -OctupleInteraction $eight.frozen_exact_strictly_eighth_only_original_scc_link_removal_interaction `
                    -NonupleInteraction $nine.frozen_exact_strictly_ninth_only_original_scc_link_removal_interaction `
                    -DecupleInteraction $ten.frozen_exact_strictly_tenth_only_original_scc_link_removal_interaction `
                    -UndecupleInteraction $eleven.frozen_exact_strictly_eleventh_only_original_scc_link_removal_interaction `
                    -DuodecupleInteraction $twelve.frozen_exact_strictly_twelfth_only_original_scc_link_removal_interaction `
                    -TredecupleInteraction $thirteen.frozen_exact_strictly_thirteenth_only_original_scc_link_removal_interaction `
                    -QuattuordecupleInteraction $fourteen.frozen_exact_strictly_fourteenth_only_original_scc_link_removal_interaction `
                    -QuindecupleInteraction $fifteen.frozen_exact_strictly_fifteenth_only_original_scc_link_removal_interaction `
                    -SexdecupleInteraction $sixteen.frozen_exact_strictly_sixteenth_only_original_scc_link_removal_interaction `
                    -SeptendecupleInteraction $seventeen.frozen_exact_strictly_seventeenth_only_original_scc_link_removal_interaction `
                    -OctodecupleInteraction $eighteen.frozen_exact_strictly_eighteenth_only_original_scc_link_removal_interaction `
                    -NovemdecupleInteraction $nineteen.frozen_exact_strictly_nineteenth_only_original_scc_link_removal_interaction `
                    -VigintupleInteraction $twenty.frozen_exact_strictly_twentieth_only_original_scc_link_removal_interaction `
                    -UnvigintupleInteraction $twentyOne.frozen_exact_strictly_twenty_first_only_original_scc_link_removal_interaction `
                    -DuovigintupleInteraction $twentyTwo.frozen_exact_strictly_twenty_second_only_original_scc_link_removal_interaction `
                    -TrevigintupleInteraction $twentyThree.frozen_exact_strictly_twenty_third_only_original_scc_link_removal_interaction `
                    -QuattuorvigintupleInteraction $twentyFour.frozen_exact_strictly_twenty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquevigintupleInteraction $twentyFive.frozen_exact_strictly_twenty_fifth_only_original_scc_link_removal_interaction `
                    -SexvigintupleInteraction $twentySix.frozen_exact_strictly_twenty_sixth_only_original_scc_link_removal_interaction `
                    -SeptemvigintupleInteraction $twentySeven.frozen_exact_strictly_twenty_seventh_only_original_scc_link_removal_interaction `
                    -OctovigintupleInteraction $twentyEight.frozen_exact_strictly_twenty_eighth_only_original_scc_link_removal_interaction `
                    -NovemvigintupleInteraction $twentyNine.frozen_exact_strictly_twenty_ninth_only_original_scc_link_removal_interaction `
                    -TrigintupleInteraction $thirty.frozen_exact_strictly_thirtieth_only_original_scc_link_removal_interaction `
                    -UntrigintupleInteraction $thirtyOne.frozen_exact_strictly_thirty_first_only_original_scc_link_removal_interaction `
                    -DuotrigintupleInteraction $thirtyTwo.frozen_exact_strictly_thirty_second_only_original_scc_link_removal_interaction `
                    -TretrigintupleInteraction $thirtyThree.frozen_exact_strictly_thirty_third_only_original_scc_link_removal_interaction `
                    -QuattuortrigintupleInteraction $thirtyFour.frozen_exact_strictly_thirty_fourth_only_original_scc_link_removal_interaction `
                    -QuinquetrigintupleInteraction $thirtyFive.frozen_exact_strictly_thirty_fifth_only_original_scc_link_removal_interaction `
                    -SextrigintupleInteraction $thirtySix.frozen_exact_strictly_thirty_sixth_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_thirty_seventh_order_thirty_seven_distinct_original_scc_full_graph_link_removal_interaction'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            genuine_original_global_thresholds = $genuine.Count
            frozen_original_global_thresholds = $frozen.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_endpoint_septemtrigintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_septemtrigintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_septemtrigintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec130_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

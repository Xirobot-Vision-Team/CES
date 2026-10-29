#requires -Version 7.0
<#
    EC-116: 22 distinct WHOLE genuine ORIGINAL FULL SCC direct-link removals.
    Read-only ORIGINAL selected Finding-pair Sequence projection, after fully
    rederiving/whole-JSON-authenticating the genuine EC-115 cardinality-21 parent.

    Enumerate <=4094 true complete directed outgoing SCC vertex boundaries;
    canonical subset-minimal (s,t) cut DNFs with exact memoized cardinality-22
    Shannon/binomial counting give 22 disjoint minimum-sufficient loss tiers.
    Expand only true strictly-22-only 22-edge cut scenarios, not C(E,22) masks.
    Max C(66,22)=182,183,167,981,760,400 (Int64); conservative 132x reporter
    upper bound 24,048,178,173,592,372,800 requires exact BigInteger output.
    No ~20,711.828 TiB dense bitmap, source mutation or new evidence reading.
#>

function ConvertTo-CodeSequenceTwentyTwoExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence twenty-two-link reported a negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    # Decimal string avoids lossy floating-point/JSON BigInteger serializer shape.
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceTwentyTwoLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence twenty-two-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 23)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 22 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectTwentyTwoLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 22 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 23 -or
        $null -eq $Indices -or $Indices.Length -ne 22) {
        throw 'Code Sequence twenty-two-link scenario requires twenty-two ordered genuine ORIGINAL FULL direct-link indices in a 22..66-link universe.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 22; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence twenty-two-link rank requires TWENTY-TWO DISTINCT ASCENDING original FULL direct-SCC link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 21 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 22]) {
        throw 'Code Sequence twenty-two-link rank escaped the original FULL direct-link combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalTwentyTwoLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 22 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 23 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 22]) {
        throw 'Code Sequence twenty-two-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(22)
    $previous = -1
    for ($position = 0; $position -lt 21; $position++) {
        $suffix = 21 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence twenty-two-link inversion exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[21] = [int]($previous + $remaining + 1)
    if ($indices[21] -le $indices[20] -or $indices[21] -ge $LinkCount) {
        throw 'Code Sequence twenty-two-link inversion generated repeated or absent ORIGINAL direct links.'
    }
    return ,$indices
}
function Test-CodeSequenceTwentyTwoLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceTwentyTwoLinkCanonicalCutFamily {
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
            if ($cut.Length -gt 22) {
                throw 'Code Sequence twenty-two-link cut family cannot require more than twenty-two removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence twenty-two-link cut family contains unordered, repeated or invalid original link indices.'
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
            if (Test-CodeSequenceTwentyTwoLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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

function Get-CodeSequenceTwentyTwoLinkCutDnfCountState {
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
        throw 'Code Sequence twenty-two-link memoized cut counter lost its canonical undecided edge frontier.'
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
    $keptFamily = ConvertTo-CodeSequenceTwentyTwoLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceTwentyTwoLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceTwentyTwoLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceTwentyTwoLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 22]) {
        throw 'Code Sequence twenty-two-link memoized cut counter exceeded the exact twenty-two-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

function Get-CodeSequenceTwentyTwoLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 22 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 23) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 22) { return [long]0 }
        throw 'Code Sequence twenty-two-link DNF counter requires a valid 0..66 original-link universe.'
    }
    # Validate every supplied edge BEFORE subsumption/satisfaction reduction.
    # Otherwise an out-of-universe cut hidden behind a valid smaller cut could
    # be discarded unnoticed and corrupt the trust boundary of this API.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence twenty-two-link DNF cut references an absent ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceTwentyTwoLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 22] }
    if ($family.cuts.Length -eq 0) { return [long]0 }
    # Reuse canonical subproblem counts for the same (s,t) over thresholds 1..22.
    # The memo key includes the FULL residual cut family, edge frontier and
    # remaining deletion budget; sharing it never merges different predicates.
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    return Get-CodeSequenceTwentyTwoLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 22 -LinkCount $LinkCount -Choose $Choose -Memo $Memo
}

function Get-CodeSequenceTwentyTwoLinkSmallestContainedCutOrder {
    param(
        [int[]] $TwentyTwoIndices,
        [System.Collections.Generic.List[int[]]] $CutsByAscendingCardinality
    )
    if ($null -eq $TwentyTwoIndices -or $TwentyTwoIndices.Length -ne 22 -or
        $null -eq $CutsByAscendingCardinality) {
        throw 'Code Sequence twenty-two-link sparse lookup requires twenty-two canonical original links and complete minimal cuts.'
    }
    foreach ($cut in $CutsByAscendingCardinality) {
        if (Test-CodeSequenceTwentyTwoLinkCutContainsSortedSubset -Candidate $TwentyTwoIndices -Smaller $cut) {
            return [int]$cut.Length
        }
    }
    return 0
}

function Get-CodeSequenceEndpointDominanceTwentyTwoLinkInteractionProjection {
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
        -not [bool]$UnvigintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_and_strictly_twenty_first_only_loss -or
        -not [bool]$UnvigintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_twenty_one_removed_links -or
        -not [bool]$UnvigintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$UnvigintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write -or
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
        throw 'Code Sequence twenty-two-link interaction requires checked EC-093 through EC-115 ORIGINAL projections.'
    }
    # EC-115 is not trusted from flags, totals, or a sample row. Recalculate
    # the ENTIRE 21-link parent from the checked EC-093..114 hierarchy and
    # compare the whole public JSON, including genuine nonempty sparse cases.
    $fresh = Get-CodeSequenceEndpointDominanceTwentyOneLinkInteractionProjection `
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
        -VigintupleInteraction $VigintupleInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 70 -Compress) -cne
        (ConvertTo-Json -InputObject $UnvigintupleInteraction -Depth 70 -Compress)) {
        throw 'Code Sequence twenty-two-link interaction rejected changed EC-115 twenty-first-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$UnvigintupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$UnvigintupleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence twenty-two-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence twenty-two-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence twenty-two-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence twenty-two-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence twenty-two-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    [long[,]]$choose = New-CodeSequenceTwentyTwoLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 22]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=22 real FULL links can affect a twenty-two-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 22) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 22) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..22, the exact number of twenty-two-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,22) graph closures and any C(E,22)-bit mask.
    [object[]]$cutsPerOrderedPair = [object[]]::new($componentCount * $componentCount)
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(23)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(23)
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
            for ($order = 1; $order -le 22; $order++) {
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceTwentyTwoLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    if ($order -eq 22) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectTwentyTwoLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                [long]$cumulative = 0
                if ($thresholdCuts.Count -gt 0) {
                    $cumulative = Get-CodeSequenceTwentyTwoLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence twenty-two-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence twenty-two-link minimal cut registry exceeded its source candidate family.'
            }
            $cutsPerOrderedPair[$s * $componentCount + $t] = $ascending
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence twenty-two-link strictly twenty-second-only cases exceed the bounded directed-cut universe.'
    }

    # Strict twenty-second-only scenarios are exactly accepted minimal twenty-two-edge
    # outgoing cuts for at least one ordered SCC relation. Expand only those.
    [long[]]$sortedPositive = [long[]]::new($positiveRanks.Count)
    $positiveRanks.CopyTo($sortedPositive)
    [Array]::Sort($sortedPositive)
    $rows = [System.Collections.Generic.List[object]]::new()
    [long]$sparseTwentySecondTotal = 0
    [long]$sparseTwentySecondMass = 0
    foreach ($rank in $sortedPositive) {
        [int[]]$twentyTwo = Get-CodeSequenceOriginalTwentyTwoLinkIndicesFromRank `
            -Rank $rank -LinkCount $linkCount -Choose $choose
        if ((Get-CodeSequenceOriginalDirectTwentyTwoLinkRank -LinkCount $linkCount -Choose $choose -Indices $twentyTwo) -ne $rank) {
            throw 'Code Sequence twenty-two-link sparse scenario lost canonical original edge rank.'
        }
        [long[]]$counts = [long[]]::new(23)
        [long[]]$mass = [long[]]::new(23)
        $novelRows = [System.Collections.Generic.List[object]]::new()
        for ($s = 0; $s -lt $componentCount; $s++) {
            for ($t = 0; $t -lt $componentCount; $t++) {
                [System.Collections.Generic.List[int[]]]$pairCuts = $cutsPerOrderedPair[$s * $componentCount + $t]
                if ($null -eq $pairCuts) { continue }
                $order = Get-CodeSequenceTwentyTwoLinkSmallestContainedCutOrder `
                    -TwentyTwoIndices $twentyTwo -CutsByAscendingCardinality $pairCuts
                if ($order -eq 0) { continue }
                if ($order -lt 1 -or $order -gt 22 -or $s -eq $t -or
                    ($baseline[$s] -band (1 -shl $t)) -eq 0) {
                    throw 'Code Sequence twenty-two-link sparse row included a non-original or reflexive SCC loss.'
                }
                $pairMass = [long]$weights[$s] * $weights[$t]
                $counts[$order]++
                $mass[$order] += $pairMass
                if ($order -eq 22) {
                    $novelRows.Add([ordered]@{
                        from_strict_component_index = $s + 1
                        to_strict_component_index = $t + 1
                        exact_ordered_original_reporter_pair_multiplicity = $pairMass
                    })
                }
            }
        }
        # Derive total incidence from the actual tier vector rather than
        # maintaining a fragile 22-term copied expression in each consumer.
        [long]$jointComponentLosses = 0
        [long]$jointReporterLosses = 0
        for ($order = 1; $order -le 22; $order++) {
            $jointComponentLosses += $counts[$order]
            $jointReporterLosses += $mass[$order]
        }
        if ($counts[22] -lt 1 -or $novelRows.Count -ne $counts[22] -or
            $jointComponentLosses -gt $componentCount * ($componentCount - 1) -or
            $jointReporterLosses -gt [long]$N * ($N - 1)) {
            throw 'Code Sequence twenty-two-link positive scenario did not conserve disjoint loss orders.'
        }
        $sparseTwentySecondTotal += $counts[22]
        $sparseTwentySecondMass += $mass[22]
        $linkRows = [System.Collections.Generic.List[object]]::new()
        foreach ($linkIndex in $twentyTwo) {
            $link = $links[$linkIndex]
            $linkRows.Add([ordered]@{
                original_direct_link_index_in_ec095 = $linkIndex + 1
                dominant_component_index = [int]$link.dominant_component_index
                subordinate_component_index = [int]$link.subordinate_component_index
                indispensable_alone = [bool]$link.indispensable_for_original_strict_component_reachability
                original_ec089_unordered_pair_indices = [int[]]$link.original_ec089_unordered_pair_indices
                exact_sum_of_direct_strict_first_credit_advantages = [long]$link.exact_sum_of_direct_strict_first_credit_advantages
            })
        }
        $rows.Add([ordered]@{
            first_original_direct_link_index_in_ec095 = $twentyTwo[0] + 1
            second_original_direct_link_index_in_ec095 = $twentyTwo[1] + 1
            third_original_direct_link_index_in_ec095 = $twentyTwo[2] + 1
            fourth_original_direct_link_index_in_ec095 = $twentyTwo[3] + 1
            fifth_original_direct_link_index_in_ec095 = $twentyTwo[4] + 1
            sixth_original_direct_link_index_in_ec095 = $twentyTwo[5] + 1
            seventh_original_direct_link_index_in_ec095 = $twentyTwo[6] + 1
            eighth_original_direct_link_index_in_ec095 = $twentyTwo[7] + 1
            ninth_original_direct_link_index_in_ec095 = $twentyTwo[8] + 1
            tenth_original_direct_link_index_in_ec095 = $twentyTwo[9] + 1
            eleventh_original_direct_link_index_in_ec095 = $twentyTwo[10] + 1
            twelfth_original_direct_link_index_in_ec095 = $twentyTwo[11] + 1
            thirteenth_original_direct_link_index_in_ec095 = $twentyTwo[12] + 1
            fourteenth_original_direct_link_index_in_ec095 = $twentyTwo[13] + 1
            fifteenth_original_direct_link_index_in_ec095 = $twentyTwo[14] + 1
            sixteenth_original_direct_link_index_in_ec095 = $twentyTwo[15] + 1
            seventeenth_original_direct_link_index_in_ec095 = $twentyTwo[16] + 1
            eighteenth_original_direct_link_index_in_ec095 = $twentyTwo[17] + 1
            nineteenth_original_direct_link_index_in_ec095 = $twentyTwo[18] + 1
            twentieth_original_direct_link_index_in_ec095 = $twentyTwo[19] + 1
            twenty_first_original_direct_link_index_in_ec095 = $twentyTwo[20] + 1
            twenty_second_original_direct_link_index_in_ec095 = $twentyTwo[21] + 1
            twenty_two_whole_original_direct_links_in_canonical_order = $linkRows.ToArray()
            exact_unique_single_link_loss_component_pairs = $counts[1]
            exact_unique_single_link_loss_original_reporter_pairs = $mass[1]
            exact_additional_loss_by_some_pair_but_no_single_component_pairs = $counts[2]
            exact_additional_loss_by_some_pair_but_no_single_original_reporter_pairs = $mass[2]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_component_pairs = $counts[3]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_original_reporter_pairs = $mass[3]
            exact_additional_loss_by_some_quadruple_but_no_smaller_subset_component_pairs = $counts[4]
            exact_additional_loss_by_some_quadruple_but_no_smaller_subset_original_reporter_pairs = $mass[4]
            exact_additional_loss_by_some_quintuple_but_no_smaller_subset_component_pairs = $counts[5]
            exact_additional_loss_by_some_quintuple_but_no_smaller_subset_original_reporter_pairs = $mass[5]
            exact_additional_loss_by_some_sextuple_but_no_smaller_subset_component_pairs = $counts[6]
            exact_additional_loss_by_some_sextuple_but_no_smaller_subset_original_reporter_pairs = $mass[6]
            exact_additional_loss_by_some_septuple_but_no_smaller_subset_component_pairs = $counts[7]
            exact_additional_loss_by_some_septuple_but_no_smaller_subset_original_reporter_pairs = $mass[7]
            exact_additional_loss_by_some_octuple_but_no_smaller_subset_component_pairs = $counts[8]
            exact_additional_loss_by_some_octuple_but_no_smaller_subset_original_reporter_pairs = $mass[8]
            exact_additional_loss_by_some_nonuple_but_no_smaller_subset_component_pairs = $counts[9]
            exact_additional_loss_by_some_nonuple_but_no_smaller_subset_original_reporter_pairs = $mass[9]
            exact_additional_loss_by_some_decuple_but_no_smaller_subset_component_pairs = $counts[10]
            exact_additional_loss_by_some_decuple_but_no_smaller_subset_original_reporter_pairs = $mass[10]
            exact_additional_loss_by_some_undecuple_but_no_smaller_subset_component_pairs = $counts[11]
            exact_additional_loss_by_some_undecuple_but_no_smaller_subset_original_reporter_pairs = $mass[11]
            exact_additional_loss_by_some_duodecuple_but_no_smaller_subset_component_pairs = $counts[12]
            exact_additional_loss_by_some_duodecuple_but_no_smaller_subset_original_reporter_pairs = $mass[12]
            exact_additional_loss_by_some_tredecuple_but_no_smaller_subset_component_pairs = $counts[13]
            exact_additional_loss_by_some_tredecuple_but_no_smaller_subset_original_reporter_pairs = $mass[13]
            exact_additional_loss_by_some_quattuordecuple_but_no_smaller_subset_component_pairs = $counts[14]
            exact_additional_loss_by_some_quattuordecuple_but_no_smaller_subset_original_reporter_pairs = $mass[14]
            exact_additional_loss_by_some_quindecuple_but_no_smaller_subset_component_pairs = $counts[15]
            exact_additional_loss_by_some_quindecuple_but_no_smaller_subset_original_reporter_pairs = $mass[15]
            exact_additional_loss_by_some_sexdecuple_but_no_smaller_subset_component_pairs = $counts[16]
            exact_additional_loss_by_some_sexdecuple_but_no_smaller_subset_original_reporter_pairs = $mass[16]
            exact_additional_loss_by_some_septendecuple_but_no_smaller_subset_component_pairs = $counts[17]
            exact_additional_loss_by_some_septendecuple_but_no_smaller_subset_original_reporter_pairs = $mass[17]
            exact_additional_loss_by_some_octodecuple_but_no_smaller_subset_component_pairs = $counts[18]
            exact_additional_loss_by_some_octodecuple_but_no_smaller_subset_original_reporter_pairs = $mass[18]
            exact_additional_loss_by_some_novemdecuple_but_no_smaller_subset_component_pairs = $counts[19]
            exact_additional_loss_by_some_novemdecuple_but_no_smaller_subset_original_reporter_pairs = $mass[19]
            exact_additional_loss_by_some_vigintuple_but_no_smaller_subset_component_pairs = $counts[20]
            exact_additional_loss_by_some_vigintuple_but_no_smaller_subset_original_reporter_pairs = $mass[20]
            exact_additional_loss_by_some_unvigintuple_but_no_smaller_subset_component_pairs = $counts[21]
            exact_additional_loss_by_some_unvigintuple_but_no_smaller_subset_original_reporter_pairs = $mass[21]
            exact_joint_twenty_two_link_full_component_pair_losses = $jointComponentLosses
            exact_joint_twenty_two_link_full_original_reporter_pair_losses = $jointReporterLosses
            new_loss_only_if_all_twenty_two_original_links_are_removed = [ordered]@{
                exact_new_component_pair_count = $counts[22]
                exact_new_original_reporter_pair_count = $mass[22]
                newly_lost_component_pairs_in_canonical_order = $novelRows.ToArray()
            }
        })
    }
    if ($rows.Count -ne $positiveRanks.Count -or $rows.Count -gt $scenarioCount -or
        $sparseTwentySecondTotal -ne $tierSum[22] -or $sparseTwentySecondMass -ne $tierReporterSum[22]) {
        throw 'Code Sequence twenty-two-link sparse twenty-second-only rows disagree with exact memoized cut-DNF incidences.'
    }
    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 22; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_component_link_count = $linkCount
        exact_twenty_two_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_twenty_second_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_twenty_second_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[1])
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[1])
        sum_of_pair_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[2])
        sum_of_pair_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[2])
        sum_of_triple_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[3])
        sum_of_triple_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[3])
        sum_of_quadruple_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[4])
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[4])
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[5])
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[5])
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[6])
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[6])
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[7])
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[7])
        sum_of_strictly_eighth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[8])
        sum_of_strictly_eighth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[8])
        sum_of_strictly_ninth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[9])
        sum_of_strictly_ninth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[9])
        sum_of_strictly_tenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[10])
        sum_of_strictly_tenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[10])
        sum_of_strictly_eleventh_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[11])
        sum_of_strictly_eleventh_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[11])
        sum_of_strictly_twelfth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[12])
        sum_of_strictly_twelfth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[12])
        sum_of_strictly_thirteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[13])
        sum_of_strictly_thirteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[13])
        sum_of_strictly_fourteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[14])
        sum_of_strictly_fourteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[14])
        sum_of_strictly_fifteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[15])
        sum_of_strictly_fifteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[15])
        sum_of_strictly_sixteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[16])
        sum_of_strictly_sixteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[16])
        sum_of_strictly_seventeenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[17])
        sum_of_strictly_seventeenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[17])
        sum_of_strictly_eighteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[18])
        sum_of_strictly_eighteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[18])
        sum_of_strictly_nineteenth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[19])
        sum_of_strictly_nineteenth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[19])
        sum_of_strictly_twentieth_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[20])
        sum_of_strictly_twentieth_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[20])
        sum_of_strictly_twenty_first_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[21])
        sum_of_strictly_twenty_first_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[21])
        sum_of_strictly_twenty_second_only_new_component_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierSum[22])
        sum_of_strictly_twenty_second_only_new_original_reporter_pair_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $tierReporterSum[22])
        sum_of_combined_full_graph_component_pair_loss_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $allLosses)
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_twenty_two_link_scenarios = (ConvertTo-CodeSequenceTwentyTwoExactCount -Value $allReporterMass)
        original_direct_link_duovigintuples_with_strictly_twenty_second_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_twenty_two = $cuts.Count
        all_twenty_two_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_22_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_twenty_two_deletions = $true
        twenty_second_only_positive_scenarios_are_exact_twenty_two_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_twenty_second_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_twenty_two_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_and_strictly_twenty_second_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_twenty_two_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuovigintupleInteraction {
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
        [object] $RetentionEndpointUnvigintupleInteraction
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
        -not [bool]$RetentionEndpointUnvigintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointUnvigintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointUnvigintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write -or
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
        throw 'Code Sequence twenty-two-link interaction requires successful ORIGINAL selector and checked EC-115.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence twenty-two-link interaction received invalid ORIGINAL reporter/family counts.'
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
        $RetentionEndpointUnvigintupleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence twenty-two-link interaction detected changed original caller/pair/path/anchor provenance.'
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
    [object[]]$twentyOneF = [object[]]$RetentionEndpointUnvigintupleInteraction.frozen_global_threshold_endpoint_unvigintuple_interaction
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
        $twentyOneFamilies.Length -ne $familyCount) {
        throw 'Code Sequence twenty-two-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
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
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or $null -eq $four -or
                $null -eq $five -or $null -eq $six -or $null -eq $seven -or
                $null -eq $eight -or $null -eq $nine -or $null -eq $ten -or
                $null -eq $eleven -or $null -eq $twelve -or $null -eq $thirteen -or $null -eq $fourteen -or $null -eq $fifteen -or $null -eq $sixteen -or $null -eq $seventeen -or $null -eq $eighteen -or
                $null -eq $nineteen -or $null -eq $twenty -or $null -eq $twentyOne -or
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
                [int]$twentyOne.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence twenty-two-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_twenty_second_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceTwentyTwoLinkInteractionProjection `
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
                        -UnvigintupleInteraction $twentyOne.exact_strictly_twenty_first_only_original_scc_link_removal_interaction -N $n)
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
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or $null -eq $four -or
            $null -eq $five -or $null -eq $six -or $null -eq $seven -or
                $null -eq $eight -or $null -eq $nine -or $null -eq $ten -or
                $null -eq $eleven -or $null -eq $twelve -or $null -eq $thirteen -or $null -eq $fourteen -or $null -eq $fifteen -or $null -eq $sixteen -or $null -eq $seventeen -or
                $null -eq $eighteen -or $null -eq $nineteen -or $null -eq $twenty -or $null -eq $twentyOne -or
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
            [int]$twentyOne.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence twenty-two-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_twenty_second_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceTwentyTwoLinkInteractionProjection `
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
                    -UnvigintupleInteraction $twentyOne.genuine_exact_strictly_twenty_first_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_twenty_second_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceTwentyTwoLinkInteractionProjection `
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
                    -UnvigintupleInteraction $twentyOne.frozen_exact_strictly_twenty_first_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_twenty_second_order_twenty_two_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_duovigintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_duovigintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_duovigintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec115_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

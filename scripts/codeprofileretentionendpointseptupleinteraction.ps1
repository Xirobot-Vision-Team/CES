#requires -Version 7.0
<#
    EC-101: exact SEVENTH-only reachability loss from removing SEVEN distinct
    complete ORIGINAL direct SCC links from the FULL condensed DAG.

    For each originally reachable ordered component pair (s,t), a seven-link
    deletion disconnects it iff an original proper s-containing/t-excluding
    vertex-side outgoing boundary is fully removed. Enumerate at most
    2^C - 2 <= 4094 original vertex sets, keep boundaries of size <=7,
    deduplicate and discard strictly redundant supersets PER SCC pair.

    Do NOT materialize C(E,7) scenarios or a 778,789,440-bit classification
    mask. For each cut-order threshold 1..7, count exact seven-edge supersets
    of the pair's minimal monotone cut DNF with a canonical memoized Shannon
    recursion. Free edge gaps collapse through binomial coefficients. The
    successive cumulative differences are the seven disjoint minimum-cut
    tiers. Only genuine seventh-only cases expand; each is itself a complete
    original SEVEN-edge outgoing boundary, so <=4094 sparse rows globally.

    No re-SCC, graph re-optimization, source read, state write, or empirical
    defect/reliability/probability/priority inference is authorized.
#>

function New-CodeSequenceSevenLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence seven-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 8)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 7 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectSevenLinkRank {
    param(
        [int] $LinkCount, [long[,]] $Choose,
        [int] $A, [int] $B, [int] $C, [int] $D, [int] $E, [int] $F, [int] $G
    )
    [int[]]$seven = @($A, $B, $C, $D, $E, $F, $G)
    [Array]::Sort($seven)
    $a=$seven[0]; $b=$seven[1]; $c=$seven[2]; $d=$seven[3]
    $e=$seven[4]; $f=$seven[5]; $g=$seven[6]
    if ($LinkCount -lt 7 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 8 -or
        $a -lt 0 -or $a -ge $b -or $b -ge $c -or $c -ge $d -or
        $d -ge $e -or $e -ge $f -or $f -ge $g -or $g -ge $LinkCount) {
        throw 'Code Sequence seven-link scenario requires SEVEN DISTINCT genuine original direct-SCC link indices.'
    }
    return [long](
        $Choose[$LinkCount, 7] - $Choose[$LinkCount - $a, 7] +
        $Choose[$LinkCount - $a - 1, 6] - $Choose[$LinkCount - $b, 6] +
        $Choose[$LinkCount - $b - 1, 5] - $Choose[$LinkCount - $c, 5] +
        $Choose[$LinkCount - $c - 1, 4] - $Choose[$LinkCount - $d, 4] +
        $Choose[$LinkCount - $d - 1, 3] - $Choose[$LinkCount - $e, 3] +
        $Choose[$LinkCount - $e - 1, 2] - $Choose[$LinkCount - $f, 2] +
        $g - $f - 1)
}

function Get-CodeSequenceOriginalSevenLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 7 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 8 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 7]) {
        throw 'Code Sequence seven-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$seven = [int[]]::new(7)
    $previous = -1
    for ($position = 0; $position -lt 6; $position++) {
        $suffix = 6 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence seven-link inversion exhausted valid lexicographic combinations.'
        }
        $seven[$position] = $candidate
        $previous = $candidate
    }
    $seven[6] = [int]($previous + $remaining + 1)
    if ($seven[6] -le $seven[5] -or $seven[6] -ge $LinkCount) {
        throw 'Code Sequence seven-link inversion generated repeated or absent original direct links.'
    }
    return ,$seven
}

function Test-CodeSequenceSevenLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceSevenLinkCanonicalCutFamily {
    param([object[]] $Cuts)
    $byKey = [System.Collections.Generic.Dictionary[string,int[]]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            [int[]]$cut = [int[]]$raw
            if ($null -eq $cut) { continue }
            if ($cut.Length -eq 0) {
                return [pscustomobject]@{ cuts = [object[]]@(); key = 'SAT'; satisfied = $true }
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence seven-link cut family contains unordered, repeated or invalid original link indices.'
                }
                $parts.Add(('{0:D2}' -f $edge))
                $previous = $edge
            }
            $key = ('{0:D2}:{1}' -f $cut.Length, ($parts -join '.'))
            if (-not $byKey.ContainsKey($key)) { $byKey.Add($key, $cut) }
        }
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
            if (Test-CodeSequenceSevenLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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

function Get-CodeSequenceSevenLinkCutDnfCountState {
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

    $memoKey = "$NextEdge|$RemainingDeletions|$($Family.key)"
    [long]$cached = 0
    if ($Memo.TryGetValue($memoKey, [ref]$cached)) { return $cached }

    $pivot = $LinkCount
    foreach ($raw in $cuts) {
        [int[]]$cut = [int[]]$raw
        if ($cut.Length -gt 0 -and $cut[0] -lt $pivot) { $pivot = $cut[0] }
    }
    if ($pivot -lt $NextEdge -or $pivot -ge $LinkCount) {
        throw 'Code Sequence seven-link memoized cut counter lost its canonical undecided edge frontier.'
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
    $keptFamily = ConvertTo-CodeSequenceSevenLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceSevenLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceSevenLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceSevenLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 7]) {
        throw 'Code Sequence seven-link memoized cut counter exceeded the exact seven-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

function Get-CodeSequenceSevenLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose
    )
    if ($LinkCount -lt 7 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 8) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 7) { return [long]0 }
        throw 'Code Sequence seven-link DNF counter requires a valid 0..66 original-link universe.'
    }
    $family = ConvertTo-CodeSequenceSevenLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 7] }
    if ($family.cuts.Length -eq 0) { return [long]0 }
    $memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    return Get-CodeSequenceSevenLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 7 -LinkCount $LinkCount -Choose $Choose -Memo $memo
}

function Get-CodeSequenceSevenLinkSmallestContainedCutOrder {
    param(
        [int[]] $SevenIndices,
        [System.Collections.Generic.List[int[]]] $CutsByAscendingCardinality
    )
    if ($null -eq $SevenIndices -or $SevenIndices.Length -ne 7 -or
        $null -eq $CutsByAscendingCardinality) {
        throw 'Code Sequence seven-link sparse lookup requires seven canonical original links and complete minimal cuts.'
    }
    foreach ($cut in $CutsByAscendingCardinality) {
        if (Test-CodeSequenceSevenLinkCutContainsSortedSubset -Candidate $SevenIndices -Smaller $cut) {
            return [int]$cut.Length
        }
    }
    return 0
}

function Get-CodeSequenceEndpointDominanceSevenLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [object] $TripleInteraction,
        [object] $QuadrupleInteraction,
        [object] $QuintupleInteraction,
        [object] $SextupleInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or $null -eq $TripleInteraction -or
        $null -eq $QuadrupleInteraction -or $null -eq $QuintupleInteraction -or
        $null -eq $SextupleInteraction -or
        -not [bool]$SextupleInteraction.every_scenario_deletes_six_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$SextupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_and_strictly_sixth_only_loss -or
        -not [bool]$SextupleInteraction.original_redundant_shortcuts_remain_unless_one_of_six_removed_links -or
        -not [bool]$SextupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$SextupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence seven-link interaction requires checked EC-093 through EC-100 ORIGINAL projections.'
    }
    # Rebuild and compare the COMPLETE EC-100 projection before adding any
    # seventh-order claim. This recursively reauthenticates EC-099..089.
    $fresh = Get-CodeSequenceEndpointDominanceSixLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -PairInteraction $PairInteraction `
        -TripleInteraction $TripleInteraction -QuadrupleInteraction $QuadrupleInteraction `
        -QuintupleInteraction $QuintupleInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 70 -Compress) -cne
        (ConvertTo-Json -InputObject $SextupleInteraction -Depth 70 -Compress)) {
        throw 'Code Sequence seven-link interaction rejected changed EC-100 sixth-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$SextupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$SextupleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence seven-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence seven-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence seven-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence seven-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence seven-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    [long[,]]$choose = New-CodeSequenceSevenLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 7]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=7 real FULL links can affect a seven-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 7) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 7) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..7, the exact number of seven-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,7) graph closures and any C(E,7)-bit mask.
    [object[]]$cutsPerOrderedPair = [object[]]::new($componentCount * $componentCount)
    [long[]]$tierSum = [long[]]::new(8)
    [long[]]$tierReporterSum = [long[]]::new(8)
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
            [long]$previousCumulative = 0
            for ($order = 1; $order -le 7; $order++) {
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceSevenLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    if ($order -eq 7) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectSevenLinkRank `
                            -LinkCount $linkCount -Choose $choose `
                            -A $boundary[0] -B $boundary[1] -C $boundary[2] -D $boundary[3] `
                            -E $boundary[4] -F $boundary[5] -G $boundary[6]))
                    }
                }
                [long]$cumulative = 0
                if ($thresholdCuts.Count -gt 0) {
                    $cumulative = Get-CodeSequenceSevenLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence seven-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += $added
                $tierReporterSum[$order] += $added * [long]$weights[$s] * $weights[$t]
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence seven-link minimal cut registry exceeded its source candidate family.'
            }
            $cutsPerOrderedPair[$s * $componentCount + $t] = $ascending
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence seven-link strictly seventh-only cases exceed the bounded directed-cut universe.'
    }

    # Strict seventh-only scenarios are exactly accepted minimal seven-edge
    # outgoing cuts for at least one ordered SCC relation. Expand only those.
    [long[]]$sortedPositive = [long[]]::new($positiveRanks.Count)
    $positiveRanks.CopyTo($sortedPositive)
    [Array]::Sort($sortedPositive)
    $rows = [System.Collections.Generic.List[object]]::new()
    [long]$sparseSeventhTotal = 0
    [long]$sparseSeventhMass = 0
    foreach ($rank in $sortedPositive) {
        [int[]]$seven = Get-CodeSequenceOriginalSevenLinkIndicesFromRank `
            -Rank $rank -LinkCount $linkCount -Choose $choose
        if ((Get-CodeSequenceOriginalDirectSevenLinkRank -LinkCount $linkCount -Choose $choose `
            -A $seven[0] -B $seven[1] -C $seven[2] -D $seven[3] `
            -E $seven[4] -F $seven[5] -G $seven[6]) -ne $rank) {
            throw 'Code Sequence seven-link sparse scenario lost canonical original edge rank.'
        }
        [long[]]$counts = [long[]]::new(8)
        [long[]]$mass = [long[]]::new(8)
        $novelRows = [System.Collections.Generic.List[object]]::new()
        for ($s = 0; $s -lt $componentCount; $s++) {
            for ($t = 0; $t -lt $componentCount; $t++) {
                [System.Collections.Generic.List[int[]]]$pairCuts = $cutsPerOrderedPair[$s * $componentCount + $t]
                if ($null -eq $pairCuts) { continue }
                $order = Get-CodeSequenceSevenLinkSmallestContainedCutOrder `
                    -SevenIndices $seven -CutsByAscendingCardinality $pairCuts
                if ($order -eq 0) { continue }
                if ($order -lt 1 -or $order -gt 7 -or $s -eq $t -or
                    ($baseline[$s] -band (1 -shl $t)) -eq 0) {
                    throw 'Code Sequence seven-link sparse row included a non-original or reflexive SCC loss.'
                }
                $pairMass = [long]$weights[$s] * $weights[$t]
                $counts[$order]++
                $mass[$order] += $pairMass
                if ($order -eq 7) {
                    $novelRows.Add([ordered]@{
                        from_strict_component_index = $s + 1
                        to_strict_component_index = $t + 1
                        exact_ordered_original_reporter_pair_multiplicity = $pairMass
                    })
                }
            }
        }
        if ($counts[7] -lt 1 -or $novelRows.Count -ne $counts[7] -or
            $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5] + $counts[6] + $counts[7] -gt
                $componentCount * ($componentCount - 1)) {
            throw 'Code Sequence seven-link positive scenario did not conserve disjoint loss orders.'
        }
        $sparseSeventhTotal += $counts[7]
        $sparseSeventhMass += $mass[7]
        $linkRows = [System.Collections.Generic.List[object]]::new()
        foreach ($linkIndex in $seven) {
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
            first_original_direct_link_index_in_ec095 = $seven[0] + 1
            second_original_direct_link_index_in_ec095 = $seven[1] + 1
            third_original_direct_link_index_in_ec095 = $seven[2] + 1
            fourth_original_direct_link_index_in_ec095 = $seven[3] + 1
            fifth_original_direct_link_index_in_ec095 = $seven[4] + 1
            sixth_original_direct_link_index_in_ec095 = $seven[5] + 1
            seventh_original_direct_link_index_in_ec095 = $seven[6] + 1
            seven_whole_original_direct_links_in_canonical_order = $linkRows.ToArray()
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
            exact_joint_seven_link_full_component_pair_losses = $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5] + $counts[6] + $counts[7]
            exact_joint_seven_link_full_original_reporter_pair_losses = $mass[1] + $mass[2] + $mass[3] + $mass[4] + $mass[5] + $mass[6] + $mass[7]
            new_loss_only_if_all_seven_original_links_are_removed = [ordered]@{
                exact_new_component_pair_count = $counts[7]
                exact_new_original_reporter_pair_count = $mass[7]
                newly_lost_component_pairs_in_canonical_order = $novelRows.ToArray()
            }
        })
    }
    if ($rows.Count -ne $positiveRanks.Count -or $rows.Count -gt $scenarioCount -or
        $sparseSeventhTotal -ne $tierSum[7] -or $sparseSeventhMass -ne $tierReporterSum[7]) {
        throw 'Code Sequence seven-link sparse seventh-only rows disagree with exact memoized cut-DNF incidences.'
    }
    [long]$allLosses = 0
    [long]$allReporterMass = 0
    for ($order = 1; $order -le 7; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_component_link_count = $linkCount
        exact_seven_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_seventh_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_seventh_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_seven_link_scenarios = $tierSum[1]
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[1]
        sum_of_pair_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[2]
        sum_of_pair_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[2]
        sum_of_triple_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[3]
        sum_of_triple_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[3]
        sum_of_quadruple_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[4]
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[4]
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[5]
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[5]
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[6]
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[6]
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_seven_link_scenarios = $tierSum[7]
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_seven_link_scenarios = $tierReporterSum[7]
        sum_of_combined_full_graph_component_pair_loss_incidences_across_seven_link_scenarios = $allLosses
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_seven_link_scenarios = $allReporterMass
        original_direct_link_septuples_with_strictly_seventh_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_seven = $cuts.Count
        all_seven_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_7_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_seven_deletions = $true
        seventh_only_positive_scenarios_are_exact_seven_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_seventh_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_seven_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_and_strictly_seventh_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_seven_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptupleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction,
        [object] $RetentionEndpointTripleInteraction,
        [object] $RetentionEndpointQuadrupleInteraction,
        [object] $RetentionEndpointQuintupleInteraction,
        [object] $RetentionEndpointSextupleInteraction
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
        [string]$RetentionEndpointSextupleInteraction.scope -cne 'exact_strictly_sixth_order_six_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointSextupleInteraction.only_consumed_checked_ec093_to_ec099_original_graph_projections -or
        -not [bool]$RetentionEndpointSextupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointSextupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointSextupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence seven-link interaction requires successful ORIGINAL selector and checked EC-100.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence seven-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction,
        $RetentionEndpointTripleInteraction, $RetentionEndpointQuadrupleInteraction,
        $RetentionEndpointQuintupleInteraction, $RetentionEndpointSextupleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence seven-link interaction detected changed original caller/pair/path/anchor provenance.'
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
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    [object[]]$threeFamilies = [object[]]$RetentionEndpointTripleInteraction.individual_original_family_endpoint_triple_interaction
    [object[]]$fourFamilies = [object[]]$RetentionEndpointQuadrupleInteraction.individual_original_family_endpoint_quadruple_interaction
    [object[]]$fiveFamilies = [object[]]$RetentionEndpointQuintupleInteraction.individual_original_family_endpoint_quintuple_interaction
    [object[]]$sixFamilies = [object[]]$RetentionEndpointSextupleInteraction.individual_original_family_endpoint_sextuple_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $threesG.Length -ne 3 -or $threesF.Length -ne 3 -or
        $foursG.Length -ne 3 -or $foursF.Length -ne 3 -or
        $fivesG.Length -ne 3 -or $fivesF.Length -ne 3 -or
        $sixesG.Length -ne 3 -or $sixesF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount -or
        $threeFamilies.Length -ne $familyCount -or $fourFamilies.Length -ne $familyCount -or
        $fiveFamilies.Length -ne $familyCount -or $sixFamilies.Length -ne $familyCount) {
        throw 'Code Sequence seven-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
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
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            $two = $twos[$i]; $three = $threes[$i]; $four = $fours[$i]
            $five = $fives[$i]; $six = $sixes[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or $null -eq $four -or
                $null -eq $five -or $null -eq $six -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$one.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$two.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$three.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$four.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$five.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$six.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$three.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$four.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$five.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$six.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence seven-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_seventh_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceSevenLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction `
                        -TripleInteraction $three.exact_strictly_triple_only_original_scc_link_removal_interaction `
                        -QuadrupleInteraction $four.exact_strictly_fourth_only_original_scc_link_removal_interaction `
                        -QuintupleInteraction $five.exact_strictly_fifth_only_original_scc_link_removal_interaction `
                        -SextupleInteraction $six.exact_strictly_sixth_only_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        $two = $twoFamilies[$i]; $three = $threeFamilies[$i]; $four = $fourFamilies[$i]
        $five = $fiveFamilies[$i]; $six = $sixFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or $null -eq $four -or
            $null -eq $five -or $null -eq $six -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$three.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$four.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$five.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$six.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence seven-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_seventh_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceSevenLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.genuine_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.genuine_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.genuine_exact_strictly_fifth_only_original_scc_link_removal_interaction `
                    -SextupleInteraction $six.genuine_exact_strictly_sixth_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_seventh_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceSevenLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.frozen_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.frozen_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.frozen_exact_strictly_fifth_only_original_scc_link_removal_interaction `
                    -SextupleInteraction $six.frozen_exact_strictly_sixth_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_seventh_order_seven_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_septuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_septuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_septuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec100_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

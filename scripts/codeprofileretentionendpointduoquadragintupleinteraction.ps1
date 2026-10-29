#requires -Version 7.0
<#
    EC-136: exact removal of 42 WHOLE genuine ORIGINAL FULL SCC direct links.
    Add one read-only selected Finding-pair Sequence projection after genuine
    whole-public-JSON EC-135 k41 parent replay across all actual targets.

    For every originally reachable ordered SCC pair, project true full-graph
    complete outward vertex cuts (<=4094), subset-minimize their cut DNF,
    and count C(E,42) deletions via exact memoized Shannon/binomial recursion.
    Derive 42 disjoint minimum-sufficient-loss tiers with BigInteger-safe
    reporter weights. Original SCC-DAGs on at most 12 vertices have no outward
    cut larger than 36: strict orders 37, 38, 39, 40, 41 and 42 are therefore zero, but
    genuine inherited orders 1..36 still count without truncation.

    E42/E43/E44/E45/E46 exact all-deleted/one/two/three/four-kept complements bypass recursion.
    E46 counts ordered kept pairs/triples with masked fourth-edge choices, never 4-kept sets.
    C(66,42) fits Int64; 132 times its reporter incidence ceiling does not.
    No scenario-size bitmaps, synthetic edges, extra evidence or Git writes.
#>

function ConvertTo-CodeSequenceFortyTwoExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence forty-two-link reported a negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    # Decimal string avoids lossy floating-point/JSON BigInteger serializer shape.
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceFortyTwoLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence forty-two-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 43)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 42 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFortyTwoLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 42 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 43 -or
        $null -eq $Indices -or $Indices.Length -ne 42) {
        throw 'Code Sequence forty-two-link scenario requires forty-two ordered genuine ORIGINAL FULL direct-link indices in a 42..66-link universe.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 42; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence forty-two-link rank requires FORTY-TWO DISTINCT ASCENDING original FULL direct-SCC link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 41 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 42]) {
        throw 'Code Sequence forty-two-link rank escaped the original FULL direct-link combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalFortyTwoLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 42 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 43 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 42]) {
        throw 'Code Sequence forty-two-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(42)
    $previous = -1
    for ($position = 0; $position -lt 41; $position++) {
        $suffix = 41 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence forty-two-link inversion exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[41] = [int]($previous + $remaining + 1)
    if ($indices[41] -le $indices[40] -or $indices[41] -ge $LinkCount) {
        throw 'Code Sequence forty-two-link inversion generated repeated or absent ORIGINAL direct links.'
    }
    return ,$indices
}
function Test-CodeSequenceFortyTwoLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceFortyTwoLinkCanonicalCutFamily {
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
            if ($cut.Length -gt 42) {
                throw 'Code Sequence forty-two-link cut family cannot require more than forty-two removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence forty-two-link cut family contains unordered, repeated or invalid original link indices.'
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
            if (Test-CodeSequenceFortyTwoLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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

function Get-CodeSequenceFortyTwoLinkCutDnfCountState {
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
        throw 'Code Sequence forty-two-link memoized cut counter lost its canonical undecided edge frontier.'
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
    $keptFamily = ConvertTo-CodeSequenceFortyTwoLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceFortyTwoLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceFortyTwoLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceFortyTwoLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 42]) {
        throw 'Code Sequence forty-two-link memoized cut counter exceeded the exact forty-two-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

function Get-CodeSequenceFortyTwoLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 42 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 43) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 42) { return [long]0 }
        throw 'Code Sequence forty-two-link DNF counter requires a valid 0..66 original-link universe.'
    }
    # Validate every supplied edge BEFORE subsumption/satisfaction reduction.
    # Otherwise an out-of-universe cut hidden behind a valid smaller cut could
    # be discarded unnoticed and corrupt the trust boundary of this API.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence forty-two-link DNF cut references an absent ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceFortyTwoLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 42] }
    if ($family.cuts.Length -eq 0) { return [long]0 }

    # Exact near-full-removal complements (k=42): E42 all removed; E43
    # one surviving edge; E44 two; E45 three; E46 four. A surviving edge-set avoids
    # the monotone cut DNF iff it intersects EVERY canonical cut. Count
    # hitting 1/2/3/4-survivor subsets directly by bitmask intersections,
    # never enumerate C(E,42) deleted-edge scenarios or build bitmaps.
    if ($LinkCount -eq 42) { return [long]1 }
    if ($LinkCount -ge 43 -and $LinkCount -le 46) {
        [long]$universeMask = ([long]1 -shl $LinkCount) - 1
        $termMasks = [System.Collections.Generic.List[long]]::new()
        [long]$commonMask = $universeMask
        foreach ($raw in $family.cuts) {
            [long]$termMask = 0
            foreach ($edge in ([int[]]$raw)) {
                $termMask = $termMask -bor ([long]1 -shl $edge)
            }
            $termMasks.Add($termMask)
            $commonMask = $commonMask -band $termMask
        }
        if ($LinkCount -eq 43) {
            [int]$avoiding = [System.Numerics.BitOperations]::PopCount([uint64]$commonMask)
            return [long]($Choose[43,42] - $avoiding)
        }
        if ($LinkCount -eq 44) {
            [int]$twoKeptAvoiding = 0
            for ($first = 0; $first -lt 44; $first++) {
                [long]$firstBit = [long]1 -shl $first
                [long]$requiredSecondMask = $universeMask
                foreach ($termMask in $termMasks) {
                    if (($termMask -band $firstBit) -eq 0) {
                        $requiredSecondMask = $requiredSecondMask -band $termMask
                        if ($requiredSecondMask -eq 0) { break }
                    }
                }
                [long]$higherBits = $universeMask -band (-bnot (([long]1 -shl ($first + 1)) - 1))
                [long]$eligibleSecondBits = $requiredSecondMask -band $higherBits
                $twoKeptAvoiding += [System.Numerics.BitOperations]::PopCount([uint64]$eligibleSecondBits)
            }
            [long]$satisfied = $Choose[44,42] - $twoKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[44,42]) {
                throw 'Code Sequence forty-two-link two-survivor complement violated exact C(44,42).'
            }
            return $satisfied
        }
        if ($LinkCount -eq 45) {
            # Three survivors: for each first two kept edges (i,j), any cut
            # already hit by either can be ignored. The third kept edge must
            # belong to the INTERSECTION of all remaining unhit cuts. Only
            # higher third indices are counted, so triples are unique. This
            # costs O(E^2 * canonicalCutCount) and O(canonicalCutCount) memory;
            # there is no C(45,42) deletion enumeration, graph closure or DNF
            # recursion on this edge-case boundary.
            [long]$threeKeptAvoiding = 0
            for ($first = 0; $first -lt 45; $first++) {
                [long]$firstBit = [long]1 -shl $first
                for ($second = $first + 1; $second -lt 45; $second++) {
                    [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                    [long]$requiredThirdMask = $universeMask
                    foreach ($termMask in $termMasks) {
                        if (($termMask -band $keptPairMask) -eq 0) {
                            $requiredThirdMask = $requiredThirdMask -band $termMask
                            if ($requiredThirdMask -eq 0) { break }
                        }
                    }
                    [long]$higherBits = $universeMask -band (-bnot (([long]1 -shl ($second + 1)) - 1))
                    $threeKeptAvoiding += [System.Numerics.BitOperations]::PopCount([uint64]($requiredThirdMask -band $higherBits))
                }
            }
            [long]$satisfied = $Choose[45,42] - $threeKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[45,42]) {
                throw 'Code Sequence forty-two-link three-survivor complement violated exact C(45,42).'
            }
            return $satisfied
        }

        # Four survivors (E=46). Fix the two earliest kept links (i,j),
        # discard all cuts already hit by them, then for each third kept link
        # k>j intersect only still-unhit cuts to obtain all eligible fourth
        # links l>k. Every quadruple has exactly one (i,j,k,l) ordering, but
        # no quadruple deletion mask, residual SCC closure or scenario bitmap
        # is ever constructed. The pair-already-hits-all case contributes
        # C(45-j,2) combinations in one exact binomial lookup.
        [long]$fourKeptAvoiding = 0
        for ($first = 0; $first -lt 43; $first++) {
            [long]$firstBit = [long]1 -shl $first
            for ($second = $first + 1; $second -lt 44; $second++) {
                [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                $unhitAfterPair = [System.Collections.Generic.List[long]]::new()
                foreach ($termMask in $termMasks) {
                    if (($termMask -band $keptPairMask) -eq 0) {
                        $unhitAfterPair.Add($termMask)
                    }
                }
                if ($unhitAfterPair.Count -eq 0) {
                    $fourKeptAvoiding += $Choose[45 - $second, 2]
                    continue
                }
                for ($third = $second + 1; $third -lt 45; $third++) {
                    [long]$thirdBit = [long]1 -shl $third
                    [long]$allowedFourthMask = $universeMask
                    foreach ($termMask in $unhitAfterPair) {
                        if (($termMask -band $thirdBit) -eq 0) {
                            $allowedFourthMask = $allowedFourthMask -band $termMask
                            if ($allowedFourthMask -eq 0) { break }
                        }
                    }
                    [long]$higherBits = $universeMask -band (-bnot (([long]1 -shl ($third + 1)) - 1))
                    $fourKeptAvoiding += [System.Numerics.BitOperations]::PopCount([uint64]($allowedFourthMask -band $higherBits))
                }
            }
        }
        [long]$satisfied = $Choose[46,42] - $fourKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[46,42]) {
            throw 'Code Sequence forty-two-link four-survivor complement violated exact C(46,42).'
        }
        return $satisfied
    }

    # Reuse canonical subproblem counts for the same (s,t) over thresholds 1..42.
    # The memo key includes the FULL residual cut family, edge frontier and
    # remaining deletion budget; sharing it never merges different predicates.
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    return Get-CodeSequenceFortyTwoLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 42 -LinkCount $LinkCount -Choose $Choose -Memo $Memo
}

# EC-136 keeps all 135 former outputs bytewise untouched; the parent was
# authenticated as one complete public JSON object BEFORE constructing this child.
function Get-CodeSequenceEndpointDominanceFortyTwoLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $ParentFortyOne,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $ParentFortyOne -or
        -not [bool]$ParentFortyOne.every_scenario_deletes_forty_one_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$ParentFortyOne.original_scc_directed_cut_saturation_bound_36_for_at_most_12_components -or
        -not [bool]$ParentFortyOne.all_strictly_forty_first_only_positive_rows_proven_impossible -or
        -not [bool]$ParentFortyOne.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$ParentFortyOne.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence forty-two-link projection requires the checked EC-135 actual original FULL SCC parent.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$ParentFortyOne.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$ParentFortyOne.exact_original_direct_component_link_count -ne $linkCount -or
        [int]$ParentFortyOne.original_positions_in_impact_universe -ne $N) {
        throw 'Code Sequence forty-two-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence forty-two-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence forty-two-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence forty-two-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence forty-two-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    # The original FULL SCC condensation must be antisymmetric: any mutual
    # reachability would collapse distinct vertices into one original SCC.
    # Check this precondition explicitly before relying on the 36-edge bound.
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = $s + 1; $t -lt $componentCount; $t++) {
            if (($baseline[$s] -band (1 -shl $t)) -ne 0 -and
                ($baseline[$t] -band (1 -shl $s)) -ne 0) {
                throw 'Code Sequence forty-two-link cannot certify saturation for cyclic distinct original SCCs.'
            }
        }
    }
    [long[,]]$choose = New-CodeSequenceFortyTwoLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 42]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=42 real FULL links can affect a forty-two-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 42) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 42) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..42, the exact number of forty-two-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,42) graph closures and any C(E,42)-bit mask.
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(43)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(43)
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
            for ($order = 1; $order -le 42; $order++) {
                $newMinimalCut = $false
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceFortyTwoLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    $newMinimalCut = $true
                    if ($order -eq 42) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectFortyTwoLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                # No newly minimal boundary => same monotone DNF and same
                # exact-cardinality count; do not re-solve an identical DNF.
                [long]$cumulative = $previousCumulative
                if ($newMinimalCut) {
                    $cumulative = Get-CodeSequenceFortyTwoLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence forty-two-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence forty-two-link minimal cut registry exceeded its source candidate family.'
            }
        }
    }
    # Tight finite-size bound: a complete outgoing source-side cut in an
    # original simple SCC condensation DAG has at most floor(m*m/4) edges.
    # With m<=12 this is <=36, so strictly-37/38/39/40/41/42-only losses are
    # all impossible, even when E>=42; earlier tiers remain nonzero.
    $maximumOutgoingCut = [int][math]::Floor(($componentCount * $componentCount) / 4)
    if ($maximumOutgoingCut -gt 36 -or $positiveRanks.Count -ne 0 -or
        $tierSum[37] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[37] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[38] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[38] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[39] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[39] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[40] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[40] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[41] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[41] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[42] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[42] -ne [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence forty-two-link model violated the proven 12-SCC / 36-outgoing-edge saturation bound.'
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence forty-two-link strictly forty-second-only cases exceed the bounded directed-cut universe.'
    }

    # No sparse output expansion at k=42: for at most twelve ORIGINAL SCCs,
    # every complete outgoing SCC vertex boundary has at most 36 FULL edges.
    # Exact cardinality-42 still counts earlier loss orders 1..36;
    # skipping nonexistent strict-37/38/39/40/41/42 rows avoids fabricated evidence.
    $rows = [System.Collections.Generic.List[object]]::new()

    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 42; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    # Disjoint per-relation minimum-cut tiers cannot count more ordered
    # reachable SCC/reporter relations than physically exist per scenario.
    # Cast BEFORE multiplying: the conservative N12/E66 reporter ceiling is
    # above Int64 even though the exact 42-deletion scenario count is not.
    [System.Numerics.BigInteger]$maxComponentIncidences = [System.Numerics.BigInteger]($componentCount * ($componentCount - 1)) * $scenarioCount
    [System.Numerics.BigInteger]$maxReporterIncidences = [System.Numerics.BigInteger]($N * ($N - 1)) * $scenarioCount
    if ($allLosses -gt $maxComponentIncidences -or
        $allReporterMass -gt $maxReporterIncidences -or
        $positiveRanks.Count -gt 4094) {
        throw 'Code Sequence forty-two-link original SCC/reporter incidence or bounded positive cut invariant failed.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        maximum_possible_complete_outgoing_original_scc_cut_size = $maximumOutgoingCut
        original_scc_directed_cut_saturation_bound_36_for_at_most_12_components = $true
        all_strictly_forty_second_only_positive_rows_proven_impossible = $true
        exact_original_direct_component_link_count = $linkCount
        exact_forty_two_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_forty_second_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_forty_second_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[1])
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[1])
        sum_of_pair_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[2])
        sum_of_pair_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[2])
        sum_of_triple_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[3])
        sum_of_triple_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[3])
        sum_of_quadruple_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[4])
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[4])
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[5])
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[5])
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[6])
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[6])
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[7])
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[7])
        sum_of_strictly_eighth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[8])
        sum_of_strictly_eighth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[8])
        sum_of_strictly_ninth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[9])
        sum_of_strictly_ninth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[9])
        sum_of_strictly_tenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[10])
        sum_of_strictly_tenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[10])
        sum_of_strictly_eleventh_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[11])
        sum_of_strictly_eleventh_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[11])
        sum_of_strictly_twelfth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[12])
        sum_of_strictly_twelfth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[12])
        sum_of_strictly_thirteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[13])
        sum_of_strictly_thirteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[13])
        sum_of_strictly_fourteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[14])
        sum_of_strictly_fourteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[14])
        sum_of_strictly_fifteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[15])
        sum_of_strictly_fifteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[15])
        sum_of_strictly_sixteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[16])
        sum_of_strictly_sixteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[16])
        sum_of_strictly_seventeenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[17])
        sum_of_strictly_seventeenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[17])
        sum_of_strictly_eighteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[18])
        sum_of_strictly_eighteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[18])
        sum_of_strictly_nineteenth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[19])
        sum_of_strictly_nineteenth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[19])
        sum_of_strictly_twentieth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[20])
        sum_of_strictly_twentieth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[20])
        sum_of_strictly_twenty_first_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[21])
        sum_of_strictly_twenty_first_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[21])
        sum_of_strictly_twenty_second_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[22])
        sum_of_strictly_twenty_second_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[22])
        sum_of_strictly_twenty_third_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[23])
        sum_of_strictly_twenty_third_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[23])
        sum_of_strictly_twenty_fourth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[24])
        sum_of_strictly_twenty_fourth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[24])
        sum_of_strictly_twenty_fifth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[25])
        sum_of_strictly_twenty_fifth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[25])
        sum_of_strictly_twenty_sixth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[26])
        sum_of_strictly_twenty_sixth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[26])
        sum_of_strictly_twenty_seventh_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[27])
        sum_of_strictly_twenty_seventh_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[27])
        sum_of_strictly_twenty_eighth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[28])
        sum_of_strictly_twenty_eighth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[28])
        sum_of_strictly_twenty_ninth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[29])
        sum_of_strictly_thirtieth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[30])
        sum_of_strictly_thirty_second_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[32])
        sum_of_strictly_thirty_third_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[33])
        sum_of_strictly_thirty_fourth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[34])
        sum_of_strictly_thirty_fifth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[35])
        sum_of_strictly_thirty_sixth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[36])
        sum_of_strictly_thirty_seventh_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[37])
        sum_of_strictly_twenty_ninth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[29])
        sum_of_strictly_thirtieth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[30])
        sum_of_strictly_thirty_first_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[31])
        sum_of_strictly_thirty_first_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[31])
        sum_of_strictly_thirty_second_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[32])
        sum_of_strictly_thirty_third_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[33])
        sum_of_strictly_thirty_fourth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[34])
        sum_of_strictly_thirty_fifth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[35])
        sum_of_strictly_thirty_sixth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[36])
        sum_of_strictly_thirty_seventh_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[37])
        sum_of_strictly_thirty_eighth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[38])
        sum_of_strictly_thirty_eighth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[38])
        sum_of_strictly_thirty_ninth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[39])
        sum_of_strictly_thirty_ninth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[39])
        sum_of_strictly_fortieth_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[40])
        sum_of_strictly_fortieth_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[40])
        sum_of_strictly_forty_first_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[41])
        sum_of_strictly_forty_second_only_new_component_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierSum[42])
        sum_of_strictly_forty_first_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[41])
        sum_of_strictly_forty_second_only_new_original_reporter_pair_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $tierReporterSum[42])
        sum_of_combined_full_graph_component_pair_loss_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $allLosses)
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_forty_two_link_scenarios = (ConvertTo-CodeSequenceFortyTwoExactCount -Value $allReporterMass)
        original_direct_link_duoquadragintuples_with_strictly_forty_second_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_forty_two = $cuts.Count
        all_forty_two_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_42_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_forty_two_deletions = $true
        forty_second_only_positive_scenarios_are_exact_forty_two_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_forty_second_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_forty_two_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_thirty_fifth_thirty_sixth_thirty_seventh_thirty_eighth_thirty_ninth_fortieth_forty_first_and_strictly_forty_second_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_forty_two_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

# The public entry point accepts exactly the already selected read-only Sequence
# path. No new record, Git, disk, network, seed, Top or family selection occurs.
function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuoquadragintupleInteraction {
    param([System.Collections.IDictionary] $PathFocus)
    if ($null -eq $PathFocus) {
        throw 'Code Sequence EC-136 needs the existing selected ORIGINAL Finding-pair path.'
    }
    $piv = $PathFocus['selected_original_finding_pair_profile_retention_pivotality']
    $suppliedParent = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_unquadragintuple_interaction']
    $topologies = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_topology']
    $reductions = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_reduction']
    if ($null -eq $piv -or $null -eq $suppliedParent -or
        $null -eq $topologies -or $null -eq $reductions) {
        throw 'Code Sequence EC-136 did not receive checked original SCC topology, reduction and EC-135 parent.'
    }

    # IMPORTANT: NEVER trust an EC-135 summary/flag/header or previous cache.
    # Replay its entire actual 41-link calculation through all EC-093..134
    # original parents, and compare the COMPLETE public JSON including each
    # genuine/frozen threshold, every real family, all 41 incidence tiers,
    # the EC-089/095 FIRST edge lineage, empty strict41 witnesses and bounds.
    # This comparison happens before creating ANY EC-136 projection.
    $freshParent = Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUnquadragintupleInteraction -PathFocus $PathFocus
    if ((ConvertTo-Json -InputObject $freshParent -Depth 100 -Compress) -cne
        (ConvertTo-Json -InputObject $suppliedParent -Depth 100 -Compress)) {
        throw 'Code Sequence EC-136 rejected modified whole-public-JSON EC-135 parent (original FIRST/SCC/tiers/family).'
    }

    [int]$n = $piv.counts.original_selected_report_positions
    [int]$familyCount = $piv.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$suppliedParent.counts.original_selected_report_positions -ne $n -or
        [int]$suppliedParent.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [string]$suppliedParent.path -cne [string]$piv.path -or
        [int]$suppliedParent.pair_index_in_pairwise_profile -ne [int]$piv.pair_index_in_pairwise_profile -or
        [int]$suppliedParent.path_index_in_selected_pair_overview -ne [int]$piv.path_index_in_selected_pair_overview -or
        [int]$suppliedParent.anchor_index_in_anchor_journeys -ne [int]$piv.anchor_index_in_anchor_journeys) {
        throw 'Code Sequence EC-136 changed the checked original Finding-pair identity or reporter universe.'
    }

    [object[]]$gTop = [object[]]$topologies.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$fTop = [object[]]$topologies.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$gRed = [object[]]$reductions.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$fRed = [object[]]$reductions.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$gParent = [object[]]$suppliedParent.genuine_global_threshold_endpoint_unquadragintuple_interaction
    [object[]]$fParent = [object[]]$suppliedParent.frozen_global_threshold_endpoint_unquadragintuple_interaction
    [object[]]$famTop = [object[]]$topologies.individual_original_family_endpoint_dominance_topology
    [object[]]$famRed = [object[]]$reductions.individual_original_family_endpoint_dominance_reduction
    [object[]]$famParent = [object[]]$suppliedParent.individual_original_family_endpoint_unquadragintuple_interaction
    if ($gTop.Length -ne 3 -or $fTop.Length -ne 3 -or
        $gRed.Length -ne 3 -or $fRed.Length -ne 3 -or
        $gParent.Length -ne 3 -or $fParent.Length -ne 3 -or
        $famTop.Length -ne $familyCount -or $famRed.Length -ne $familyCount -or
        $famParent.Length -ne $familyCount) {
        throw 'Code Sequence EC-136 changed genuine/frozen global thresholds or actual original repeat-family target counts.'
    }
    $genuine = [System.Collections.Generic.List[object]]::new()
    $frozen = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        [object[]]$topSet = if ($mode -eq 0) { $gTop } else { $fTop }
        [object[]]$redSet = if ($mode -eq 0) { $gRed } else { $fRed }
        [object[]]$parentSet = if ($mode -eq 0) { $gParent } else { $fParent }
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $topSet[$i]; $red = $redSet[$i]; $parent = $parentSet[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $parent -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$parent.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$top.original_full_selection_global_family_capacity -ne
                    [int]$parent.original_full_selection_global_family_capacity -or
                [int]$red.original_full_selection_global_family_capacity -ne
                    [int]$parent.original_full_selection_global_family_capacity) {
                throw 'Code Sequence EC-136 drifted from actual original threshold identity/capacity.'
            }
            $graph = Get-CodeSequenceEndpointDominanceFortyTwoLinkInteractionProjection `
                -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                -ParentFortyOne $parent.exact_strictly_forty_first_only_original_scc_link_removal_interaction -N $n
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_forty_second_only_original_scc_link_removal_interaction = $graph
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $famTop[$i]; $red = $famRed[$i]; $parent = $famParent[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $parent -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$parent.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence EC-136 drifted from one actual original repeat family index.'
        }
        $graphG = Get-CodeSequenceEndpointDominanceFortyTwoLinkInteractionProjection `
            -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
            -ParentFortyOne $parent.genuine_exact_strictly_forty_first_only_original_scc_link_removal_interaction -N $n
        $graphF = Get-CodeSequenceEndpointDominanceFortyTwoLinkInteractionProjection `
            -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
            -ParentFortyOne $parent.frozen_exact_strictly_forty_first_only_original_scc_link_removal_interaction -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_forty_second_only_original_scc_link_removal_interaction = $graphG
            frozen_exact_strictly_forty_second_only_original_scc_link_removal_interaction = $graphF
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_forty_second_order_forty_two_distinct_original_scc_full_graph_link_removal_interaction'
        pair_index_in_pairwise_profile = [int]$piv.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$piv.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$piv.anchor_index_in_anchor_journeys
        path = [string]$piv.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            genuine_original_global_thresholds = $genuine.Count
            frozen_original_global_thresholds = $frozen.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_endpoint_duoquadragintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_duoquadragintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_duoquadragintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec135_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

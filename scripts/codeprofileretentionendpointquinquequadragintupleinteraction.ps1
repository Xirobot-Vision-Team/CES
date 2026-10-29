#requires -Version 7.0
<#
    EC-139: exact cardinality45 deletion of genuine ORIGINAL FULL SCC direct links.
    Add one read-only original selected Finding-pair Sequence child after whole
    public-JSON replay of authentic EC-138 k44 across all real global/family targets.

    Each reachable original SCC pair has at most 4094 genuine outward cut sides.
    Canonical minimal cut DNFs, memoized Shannon/binomial exact cardinality45
    counting and cumulative differences give 45 disjoint minimum-sufficient
    SCC/reporter-weighted loss tiers. Since m<=12, strictly orders 37..45
    cannot appear although real orders 1..36 remain counted.

    E45..51 use exact 0..6 kept-link complements. New E52 seven-survivor
    exact hitting-CNF memoization prunes unhit clauses, counts free prefixes
    binomially, and resolves one/two clauses by inclusion-exclusion. Never
    materialize C(52,45)=133,784,560 scenarios or per-scenario SCC closures.
    C(66,45) fits signed Int64; reporter aggregates use BigInteger.
#>

function ConvertTo-CodeSequenceFortyFiveExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence forty-five-link reported a negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    # Decimal string avoids lossy floating-point/JSON BigInteger serializer shape.
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceFortyFiveLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence forty-five-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 46)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 45 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFortyFiveLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 45 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 46 -or
        $null -eq $Indices -or $Indices.Length -ne 45) {
        throw 'Code Sequence forty-five-link scenario requires forty-five ordered genuine ORIGINAL FULL direct-link indices in a 45..66-link universe.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 45; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence forty-five-link rank requires FORTY-FIVE DISTINCT ASCENDING original FULL direct-SCC link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 44 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 45]) {
        throw 'Code Sequence forty-five-link rank escaped the original FULL direct-link combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalFortyFiveLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 45 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 46 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 45]) {
        throw 'Code Sequence forty-five-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(45)
    $previous = -1
    for ($position = 0; $position -lt 44; $position++) {
        $suffix = 44 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence forty-five-link inversion exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[44] = [int]($previous + $remaining + 1)
    if ($indices[44] -le $indices[43] -or $indices[44] -ge $LinkCount) {
        throw 'Code Sequence forty-five-link inversion generated repeated or absent ORIGINAL direct links.'
    }
    return ,$indices
}
function Test-CodeSequenceFortyFiveLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceFortyFiveLinkCanonicalCutFamily {
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
            if ($cut.Length -gt 45) {
                throw 'Code Sequence forty-five-link cut family cannot require more than forty-five removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence forty-five-link cut family contains unordered, repeated or invalid original link indices.'
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
            if (Test-CodeSequenceFortyFiveLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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

function Get-CodeSequenceFortyFiveLinkCutDnfCountState {
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
        throw 'Code Sequence forty-five-link memoized cut counter lost its canonical undecided edge frontier.'
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
    $keptFamily = ConvertTo-CodeSequenceFortyFiveLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceFortyFiveLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceFortyFiveLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceFortyFiveLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 45]) {
        throw 'Code Sequence forty-five-link memoized cut counter exceeded the exact forty-five-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

# Exact survivor-CNF solver for E52 / k45: every surviving original FULL link
# set avoiding the deleted-cut DNF must hit EVERY canonical source-side cut.
# Keep all masks in their stable source order; memoize by (frontier, survivors,
# unsatisfied masks). Edge decisions never materialize C(52,45) cases.
function Get-CodeSequenceFortyFiveLinkKeptCutHittingState {
    param(
        [long[]] $UnhitMasks,
        [int] $NextEdge,
        [int] $RemainingKept,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    [int]$available = $LinkCount - $NextEdge
    if ($NextEdge -lt 0 -or $NextEdge -gt $LinkCount -or
        $RemainingKept -lt 0 -or $RemainingKept -gt $available) { return [long]0 }
    if ($null -eq $UnhitMasks -or $UnhitMasks.Length -eq 0) {
        return [long]$Choose[$available, $RemainingKept]
    }
    if ($RemainingKept -eq 0) { return [long]0 }
    [long]$universe = ([long]1 -shl $LinkCount) - 1
    [long]$future = $universe -band (-bnot (([long]1 -shl $NextEdge) - 1))
    [long]$neededBits = 0
    # Greedy disjoint-clause packing gives a rigorous lower bound on how many
    # kept links are still necessary. Even its non-optimal value may prune.
    [long]$packedBits = 0
    [int]$packedCount = 0
    foreach ($unhit in $UnhitMasks) {
        [long]$options = $unhit -band $future
        if ($options -eq 0) { return [long]0 }
        $neededBits = $neededBits -bor $options
        if (($options -band $packedBits) -eq 0) {
            $packedCount++
            $packedBits = $packedBits -bor $options
            if ($packedCount -gt $RemainingKept) { return [long]0 }
        }
    }
    if ($RemainingKept -eq $available) { return [long]1 }
    if ($UnhitMasks.Length -le 2) {
        # Inclusion-exclusion over 1/2 still-unsatisfied clauses. An r-kept
        # suffix fails a clause iff all of that clause's available links are
        # deleted. Single/double terms need no recursive decisions at all.
        [long]$a = $UnhitMasks[0] -band $future
        [int]$sizeA = [System.Numerics.BitOperations]::PopCount([uint64]$a)
        [long]$count = $Choose[$available, $RemainingKept] -
            $Choose[$available - $sizeA, $RemainingKept]
        if ($UnhitMasks.Length -eq 2) {
            [long]$b = $UnhitMasks[1] -band $future
            [int]$sizeB = [System.Numerics.BitOperations]::PopCount([uint64]$b)
            [int]$sizeUnion = [System.Numerics.BitOperations]::PopCount([uint64]($a -bor $b))
            $count -= $Choose[$available - $sizeB, $RemainingKept]
            $count += $Choose[$available - $sizeUnion, $RemainingKept]
        }
        if ($count -lt 0 -or $count -gt $Choose[$available, $RemainingKept]) {
            throw 'Code Sequence forty-five-link survivor inclusion-exclusion exceeded its exact subset universe.'
        }
        return $count
    }
    $key = "$LinkCount|H|$NextEdge|$RemainingKept|$($UnhitMasks -join ',')"
    [long]$cached = 0
    if ($Memo.TryGetValue($key, [ref]$cached)) { return $cached }

    # The lowest still-relevant original edge is the Shannon pivot. All edges
    # before it are FREE and can be picked in exact binomial batches.
    [int]$pivot = [System.Numerics.BitOperations]::TrailingZeroCount([uint64]$neededBits)
    [int]$gap = $pivot - $NextEdge
    if ($gap -lt 0 -or $pivot -ge $LinkCount) {
        throw 'Code Sequence forty-five-link survivor cut solver lost its canonical decision frontier.'
    }
    [long]$pivotBit = [long]1 -shl $pivot
    $stillUnhitIfKept = [System.Collections.Generic.List[long]]::new()
    foreach ($mask in $UnhitMasks) {
        if (($mask -band $pivotBit) -eq 0) { $stillUnhitIfKept.Add($mask) }
    }
    [long[]]$keptRemainder = $stillUnhitIfKept.ToArray()
    [long]$total = 0
    for ($free = 0; $free -le [Math]::Min($gap, $RemainingKept); $free++) {
        [long]$ways = $Choose[$gap, $free]
        [int]$afterFree = $RemainingKept - $free
        # Delete this pivot link: still every prior unhit cut must be hit.
        $total += $ways * (Get-CodeSequenceFortyFiveLinkKeptCutHittingState `
            -UnhitMasks $UnhitMasks -NextEdge ($pivot + 1) -RemainingKept $afterFree `
            -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        if ($afterFree -ge 1) {
            # Keep this pivot: it hits every clause containing this original
            # link, and reduces exactly one retained-link budget.
            $total += $ways * (Get-CodeSequenceFortyFiveLinkKeptCutHittingState `
                -UnhitMasks $keptRemainder -NextEdge ($pivot + 1) -RemainingKept ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$available, $RemainingKept]) {
        throw 'Code Sequence forty-five-link survivor recursion exceeded its exact kept-subset universe.'
    }
    $Memo[$key] = $total
    return $total
}

function Get-CodeSequenceFortyFiveLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 45 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 46) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 45) { return [long]0 }
        throw 'Code Sequence forty-five-link DNF counter requires a valid 0..66 original-link universe.'
    }
    # Validate every supplied edge BEFORE subsumption/satisfaction reduction.
    # Otherwise an out-of-universe cut hidden behind a valid smaller cut could
    # be discarded unnoticed and corrupt the trust boundary of this API.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence forty-five-link DNF cut references an absent ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceFortyFiveLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 45] }
    if ($family.cuts.Length -eq 0) { return [long]0 }
    if ($family.cuts.Length -eq 1) {
        # One genuine canonical cut W: a k45 deletion satisfies this DNF
        # iff it contains all |W| actual links. Count the remaining deletions
        # directly, without running any survivor-prefix search or recursion.
        [int]$cutSize = ([int[]]$family.cuts[0]).Length
        return [long]$Choose[$LinkCount - $cutSize, 45 - $cutSize]
    }

    # Exact near-full-removal complements (k=45): E45 all removed; E46
    # one surviving edge; E47 two; E48 three; E49 four; E50 five; E51 six. A surviving edge-set avoids
    # the monotone cut DNF iff it intersects EVERY canonical cut. Count
    # hitting 1/2/3/4/5/6-survivor subsets directly by bitmask intersections,
    # never enumerate C(E,45) deleted-edge scenarios or build bitmaps.
    if ($LinkCount -eq 45) { return [long]1 }
    if ($LinkCount -ge 46 -and $LinkCount -le 52) {
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
        if ($LinkCount -eq 46) {
            [int]$avoiding = [System.Numerics.BitOperations]::PopCount([uint64]$commonMask)
            return [long]($Choose[46,45] - $avoiding)
        }
        if ($LinkCount -eq 47) {
            [int]$twoKeptAvoiding = 0
            for ($first = 0; $first -lt 47; $first++) {
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
            [long]$satisfied = $Choose[47,45] - $twoKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[47,45]) {
                throw 'Code Sequence forty-five-link two-survivor complement violated exact C(47,45).'
            }
            return $satisfied
        }
        if ($LinkCount -eq 48) {
            # Three survivors: for each first two kept edges (i,j), any cut
            # already hit by either can be ignored. The third kept edge must
            # belong to the INTERSECTION of all remaining unhit cuts. Only
            # higher third indices are counted, so triples are unique. This
            # costs O(E^2 * canonicalCutCount) and O(canonicalCutCount) memory;
            # there is no C(48,45) deletion enumeration, graph closure or DNF
            # recursion on this edge-case boundary.
            [long]$threeKeptAvoiding = 0
            for ($first = 0; $first -lt 48; $first++) {
                [long]$firstBit = [long]1 -shl $first
                for ($second = $first + 1; $second -lt 48; $second++) {
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
            [long]$satisfied = $Choose[48,45] - $threeKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[48,45]) {
                throw 'Code Sequence forty-five-link three-survivor complement violated exact C(48,45).'
            }
            return $satisfied
        }

        if ($LinkCount -eq 49) {
            # Four survivors (E=49). Fix the two earliest kept links (i,j),
            # discard all cuts already hit by them, then for each third kept link
            # k>j intersect only still-unhit cuts to obtain all eligible fourth
            # links l>k. Every quadruple has exactly one (i,j,k,l) ordering, but
            # no quadruple deletion mask, residual SCC closure or scenario bitmap
            # is ever constructed. The pair-already-hits-all case contributes
            # C(48-j,2) combinations in one exact binomial lookup.
            [long]$fourKeptAvoiding = 0
            for ($first = 0; $first -lt 46; $first++) {
                [long]$firstBit = [long]1 -shl $first
                for ($second = $first + 1; $second -lt 47; $second++) {
                    [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                    $unhitAfterPair = [System.Collections.Generic.List[long]]::new()
                    foreach ($termMask in $termMasks) {
                        if (($termMask -band $keptPairMask) -eq 0) {
                            $unhitAfterPair.Add($termMask)
                        }
                    }
                    if ($unhitAfterPair.Count -eq 0) {
                        $fourKeptAvoiding += $Choose[48 - $second, 2]
                        continue
                    }
                    for ($third = $second + 1; $third -lt 48; $third++) {
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
            [long]$satisfied = $Choose[49,45] - $fourKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[49,45]) {
                throw 'Code Sequence forty-five-link four-survivor complement violated exact C(49,45).'
            }
            return $satisfied
        }

        if ($LinkCount -eq 50) {
            # Five survivors (E=50). Count HITTING quintets without visiting
        # C(50,45) removal cases. Fix the first kept pair, cache only cuts
        # not hit by it, and collapse the remaining suffix when all cuts
        # are already hit. Otherwise fix the third and fourth kept links;
        # intersect still-missed cut masks to popcount all possible fifth
        # indices greater than the fourth. Every quintet has one ordered
        # (i,j,k,l,h) prefix and is counted exactly once; NO SCC closure,
        # scenario bitmap, or five-kept tuple is materialized.
        [long]$fiveKeptAvoiding = 0
        for ($first = 0; $first -lt 46; $first++) {
            [long]$firstBit = [long]1 -shl $first
            for ($second = $first + 1; $second -lt 47; $second++) {
                [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                $unhitAfterPair = [System.Collections.Generic.List[long]]::new()
                foreach ($termMask in $termMasks) {
                    if (($termMask -band $keptPairMask) -eq 0) {
                        $unhitAfterPair.Add($termMask)
                    }
                }
                if ($unhitAfterPair.Count -eq 0) {
                    # E50 minus the first j+1 indices gives 49-j later
                    # links; any 3 of these complete a hitting quintet.
                    $fiveKeptAvoiding += $Choose[49 - $second, 3]
                    continue
                }
                for ($third = $second + 1; $third -lt 48; $third++) {
                    [long]$thirdBit = [long]1 -shl $third
                    $unhitAfterTriple = [System.Collections.Generic.List[long]]::new()
                    foreach ($termMask in $unhitAfterPair) {
                        if (($termMask -band $thirdBit) -eq 0) {
                            $unhitAfterTriple.Add($termMask)
                        }
                    }
                    if ($unhitAfterTriple.Count -eq 0) {
                        $fiveKeptAvoiding += $Choose[49 - $third, 2]
                        continue
                    }
                    for ($fourth = $third + 1; $fourth -lt 49; $fourth++) {
                        [long]$fourthBit = [long]1 -shl $fourth
                        [long]$allowedFifthMask = $universeMask
                        foreach ($termMask in $unhitAfterTriple) {
                            if (($termMask -band $fourthBit) -eq 0) {
                                $allowedFifthMask = $allowedFifthMask -band $termMask
                                if ($allowedFifthMask -eq 0) { break }
                            }
                        }
                        [long]$higherBits = $universeMask -band (-bnot (([long]1 -shl ($fourth + 1)) - 1))
                        $fiveKeptAvoiding += [System.Numerics.BitOperations]::PopCount([uint64]($allowedFifthMask -band $higherBits))
                    }
                }
            }
        }
        [long]$satisfied = $Choose[50,45] - $fiveKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[50,45]) {
            throw 'Code Sequence forty-five-link five-survivor complement violated exact C(50,45).'
        }
        return $satisfied
        }

    if ($LinkCount -eq 51) {
        # E51/k45 leaves six real original FULL edges. Count surviving six-edge
        # HITTING sets, which are precisely the deletion sets avoiding the
        # canonical monotone cut DNF. Every surviving ordered prefix is visited
        # at most once; no C(51,45)=15,890,700 cases or graph closures are built.
        # When the prefix already hits every cut, its suffix is collapsed into
        # a binomial. A missed cut without any higher possible hit prunes the
        # entire prefix. The sixth edge is counted with a single PopCount.
        [long]$sixKeptAvoiding = 0
        for ($first = 0; $first -lt 46; $first++) {
            [long]$firstBit = [long]1 -shl $first
            for ($second = $first + 1; $second -lt 47; $second++) {
                [long]$pairMask = $firstBit -bor ([long]1 -shl $second)
                $missedPair = [System.Collections.Generic.List[long]]::new()
                [long]$laterPairMask = $universeMask -band (-bnot (([long]1 -shl ($second + 1)) - 1))
                $impossible = $false
                foreach ($termMask in $termMasks) {
                    if (($termMask -band $pairMask) -eq 0) {
                        if (($termMask -band $laterPairMask) -eq 0) { $impossible = $true; break }
                        $missedPair.Add($termMask)
                    }
                }
                if ($impossible) { continue }
                if ($missedPair.Count -eq 0) {
                    $sixKeptAvoiding += $Choose[50 - $second, 4]
                    continue
                }
                for ($third = $second + 1; $third -lt 48; $third++) {
                    [long]$thirdBit = [long]1 -shl $third
                    $missedTriple = [System.Collections.Generic.List[long]]::new()
                    [long]$laterTripleMask = $universeMask -band (-bnot (([long]1 -shl ($third + 1)) - 1))
                    $impossible = $false
                    foreach ($termMask in $missedPair) {
                        if (($termMask -band $thirdBit) -eq 0) {
                            if (($termMask -band $laterTripleMask) -eq 0) { $impossible = $true; break }
                            $missedTriple.Add($termMask)
                        }
                    }
                    if ($impossible) { continue }
                    if ($missedTriple.Count -eq 0) {
                        $sixKeptAvoiding += $Choose[50 - $third, 3]
                        continue
                    }
                    for ($fourth = $third + 1; $fourth -lt 49; $fourth++) {
                        [long]$fourthBit = [long]1 -shl $fourth
                        $missedQuad = [System.Collections.Generic.List[long]]::new()
                        [long]$laterQuadMask = $universeMask -band (-bnot (([long]1 -shl ($fourth + 1)) - 1))
                        $impossible = $false
                        foreach ($termMask in $missedTriple) {
                            if (($termMask -band $fourthBit) -eq 0) {
                                if (($termMask -band $laterQuadMask) -eq 0) { $impossible = $true; break }
                                $missedQuad.Add($termMask)
                            }
                        }
                        if ($impossible) { continue }
                        if ($missedQuad.Count -eq 0) {
                            $sixKeptAvoiding += $Choose[50 - $fourth, 2]
                            continue
                        }
                        for ($fifth = $fourth + 1; $fifth -lt 50; $fifth++) {
                            [long]$fifthBit = [long]1 -shl $fifth
                            [long]$requiredSixthMask = $universeMask
                            foreach ($termMask in $missedQuad) {
                                if (($termMask -band $fifthBit) -eq 0) {
                                    $requiredSixthMask = $requiredSixthMask -band $termMask
                                    if ($requiredSixthMask -eq 0) { break }
                                }
                            }
                            [long]$higherBits = $universeMask -band (-bnot (([long]1 -shl ($fifth + 1)) - 1))
                            $sixKeptAvoiding += [System.Numerics.BitOperations]::PopCount([uint64]($requiredSixthMask -band $higherBits))
                        }
                    }
                }
            }
        }
        [long]$satisfied = $Choose[51,45] - $sixKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[51,45]) {
            throw 'Code Sequence forty-five-link six-survivor complement violated exact C(51,45).'
        }
        return $satisfied
    }
    if ($LinkCount -eq 52) {
        # New EC-139 boundary: seven real FULL SCC links are retained.
        # The other 45 are deleted. Count the 7-kept hitting CNF by memoized
        # symbolic clauses (with disjoint-clause pruning, free-link binomials
        # and 1/2-clause exact inclusion-exclusion). No C(52,45)=133,784,560
        # scenario enumeration/bitmap, SCC closure or distinct 7-set objects.
        if ($null -eq $Memo) {
            $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
        }
        [long]$sevenKeptAvoiding = Get-CodeSequenceFortyFiveLinkKeptCutHittingState `
            -UnhitMasks $termMasks.ToArray() -NextEdge 0 -RemainingKept 7 `
            -LinkCount 52 -Choose $Choose -Memo $Memo
        [long]$satisfied = $Choose[52,45] - $sevenKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[52,45]) {
            throw 'Code Sequence forty-five-link seven-survivor complement violated exact C(52,45).'
        }
        return $satisfied
    }
    }
    # Reuse canonical subproblem counts for the same (s,t) over thresholds 1..45.
    # The memo key includes the FULL residual cut family, edge frontier and
    # remaining deletion budget; sharing it never merges different predicates.
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    return Get-CodeSequenceFortyFiveLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 45 -LinkCount $LinkCount -Choose $Choose -Memo $Memo
}

# EC-139 keeps all 138 earlier outputs untouched; the parent was
# authenticated as one complete public JSON object BEFORE constructing this child.
function Get-CodeSequenceEndpointDominanceFortyFiveLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $ParentFortyFour,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $ParentFortyFour -or
        -not [bool]$ParentFortyFour.every_scenario_deletes_forty_four_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$ParentFortyFour.original_scc_directed_cut_saturation_bound_36_for_at_most_12_components -or
        -not [bool]$ParentFortyFour.all_strictly_forty_fourth_only_positive_rows_proven_impossible -or
        -not [bool]$ParentFortyFour.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$ParentFortyFour.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence forty-five-link projection requires the checked EC-138 actual original FULL SCC parent.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$ParentFortyFour.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$ParentFortyFour.exact_original_direct_component_link_count -ne $linkCount -or
        [int]$ParentFortyFour.original_positions_in_impact_universe -ne $N) {
        throw 'Code Sequence forty-five-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence forty-five-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence forty-five-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence forty-five-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence forty-five-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    # The original FULL SCC condensation must be antisymmetric: any mutual
    # reachability would collapse distinct vertices into one original SCC.
    # Check this precondition explicitly before relying on the 36-edge bound.
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = $s + 1; $t -lt $componentCount; $t++) {
            if (($baseline[$s] -band (1 -shl $t)) -ne 0 -and
                ($baseline[$t] -band (1 -shl $s)) -ne 0) {
                throw 'Code Sequence forty-five-link cannot certify saturation for cyclic distinct original SCCs.'
            }
        }
    }
    [long[,]]$choose = New-CodeSequenceFortyFiveLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 45]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=45 real FULL links can affect a forty-five-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 45) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 45) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..45, the exact number of forty-five-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,44) graph closures and any C(E,44)-bit mask.
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(46)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(46)
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
            for ($order = 1; $order -le 45; $order++) {
                $newMinimalCut = $false
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceFortyFiveLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    $newMinimalCut = $true
                    if ($order -eq 45) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectFortyFiveLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                # No newly minimal boundary => same monotone DNF and same
                # exact-cardinality count; do not re-solve an identical DNF.
                [long]$cumulative = $previousCumulative
                if ($newMinimalCut) {
                    $cumulative = Get-CodeSequenceFortyFiveLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence forty-five-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence forty-five-link minimal cut registry exceeded its source candidate family.'
            }
        }
    }
    # Tight finite-size bound: a complete outgoing source-side cut in an
    # original simple SCC condensation DAG has at most floor(m*m/4) edges.
    # With m<=12 this is <=36, so strictly-37/38/39/40/41/42/43/44/45-only losses are
    # all impossible, even when E>=45; earlier tiers remain nonzero.
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
        $tierReporterSum[42] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[43] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[43] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[44] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[44] -ne [System.Numerics.BigInteger]::Zero -or
        $tierSum[45] -ne [System.Numerics.BigInteger]::Zero -or
        $tierReporterSum[45] -ne [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence forty-five-link model violated the proven 12-SCC / 36-outgoing-edge saturation bound.'
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence forty-five-link strictly forty-fifth-only cases exceed the bounded directed-cut universe.'
    }

    # No sparse output expansion at k=45: for at most twelve ORIGINAL SCCs,
    # every complete outgoing SCC vertex boundary has at most 36 FULL edges.
    # Exact cardinality-45 still counts earlier loss orders 1..36;
    # skipping nonexistent strict-37/38/39/40/41/42/43/44/45 rows avoids fabricated evidence.
    $rows = [System.Collections.Generic.List[object]]::new()

    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 45; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    # Disjoint per-relation minimum-cut tiers cannot count more ordered
    # reachable SCC/reporter relations than physically exist per scenario.
    # Cast BEFORE multiplying: the conservative N12/E66 reporter ceiling is
    # above Int64 even though the exact 45-deletion scenario count is not.
    [System.Numerics.BigInteger]$maxComponentIncidences = [System.Numerics.BigInteger]($componentCount * ($componentCount - 1)) * $scenarioCount
    [System.Numerics.BigInteger]$maxReporterIncidences = [System.Numerics.BigInteger]($N * ($N - 1)) * $scenarioCount
    if ($allLosses -gt $maxComponentIncidences -or
        $allReporterMass -gt $maxReporterIncidences -or
        $positiveRanks.Count -gt 4094) {
        throw 'Code Sequence forty-five-link original SCC/reporter incidence or bounded positive cut invariant failed.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        maximum_possible_complete_outgoing_original_scc_cut_size = $maximumOutgoingCut
        original_scc_directed_cut_saturation_bound_36_for_at_most_12_components = $true
        all_strictly_forty_fifth_only_positive_rows_proven_impossible = $true
        exact_original_direct_component_link_count = $linkCount
        exact_forty_five_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_forty_fifth_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_forty_fifth_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[1])
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[1])
        sum_of_pair_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[2])
        sum_of_pair_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[2])
        sum_of_triple_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[3])
        sum_of_triple_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[3])
        sum_of_quadruple_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[4])
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[4])
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[5])
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[5])
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[6])
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[6])
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[7])
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[7])
        sum_of_strictly_eighth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[8])
        sum_of_strictly_eighth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[8])
        sum_of_strictly_ninth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[9])
        sum_of_strictly_ninth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[9])
        sum_of_strictly_tenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[10])
        sum_of_strictly_tenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[10])
        sum_of_strictly_eleventh_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[11])
        sum_of_strictly_eleventh_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[11])
        sum_of_strictly_twelfth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[12])
        sum_of_strictly_twelfth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[12])
        sum_of_strictly_thirteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[13])
        sum_of_strictly_thirteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[13])
        sum_of_strictly_fourteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[14])
        sum_of_strictly_fourteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[14])
        sum_of_strictly_fifteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[15])
        sum_of_strictly_fifteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[15])
        sum_of_strictly_sixteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[16])
        sum_of_strictly_sixteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[16])
        sum_of_strictly_seventeenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[17])
        sum_of_strictly_seventeenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[17])
        sum_of_strictly_eighteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[18])
        sum_of_strictly_eighteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[18])
        sum_of_strictly_nineteenth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[19])
        sum_of_strictly_nineteenth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[19])
        sum_of_strictly_twentieth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[20])
        sum_of_strictly_twentieth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[20])
        sum_of_strictly_twenty_first_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[21])
        sum_of_strictly_twenty_first_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[21])
        sum_of_strictly_twenty_second_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[22])
        sum_of_strictly_twenty_second_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[22])
        sum_of_strictly_twenty_third_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[23])
        sum_of_strictly_twenty_third_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[23])
        sum_of_strictly_twenty_fourth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[24])
        sum_of_strictly_twenty_fourth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[24])
        sum_of_strictly_twenty_fifth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[25])
        sum_of_strictly_twenty_fifth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[25])
        sum_of_strictly_twenty_sixth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[26])
        sum_of_strictly_twenty_sixth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[26])
        sum_of_strictly_twenty_seventh_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[27])
        sum_of_strictly_twenty_seventh_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[27])
        sum_of_strictly_twenty_eighth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[28])
        sum_of_strictly_twenty_eighth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[28])
        sum_of_strictly_twenty_ninth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[29])
        sum_of_strictly_thirtieth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[30])
        sum_of_strictly_thirty_second_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[32])
        sum_of_strictly_thirty_third_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[33])
        sum_of_strictly_thirty_fourth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[34])
        sum_of_strictly_thirty_fifth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[35])
        sum_of_strictly_thirty_sixth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[36])
        sum_of_strictly_thirty_seventh_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[37])
        sum_of_strictly_twenty_ninth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[29])
        sum_of_strictly_thirtieth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[30])
        sum_of_strictly_thirty_first_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[31])
        sum_of_strictly_thirty_first_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[31])
        sum_of_strictly_thirty_second_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[32])
        sum_of_strictly_thirty_third_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[33])
        sum_of_strictly_thirty_fourth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[34])
        sum_of_strictly_thirty_fifth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[35])
        sum_of_strictly_thirty_sixth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[36])
        sum_of_strictly_thirty_seventh_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[37])
        sum_of_strictly_thirty_eighth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[38])
        sum_of_strictly_thirty_eighth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[38])
        sum_of_strictly_thirty_ninth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[39])
        sum_of_strictly_thirty_ninth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[39])
        sum_of_strictly_fortieth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[40])
        sum_of_strictly_fortieth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[40])
        sum_of_strictly_forty_first_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[41])
        sum_of_strictly_forty_second_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[42])
        sum_of_strictly_forty_third_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[43])
        sum_of_strictly_forty_first_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[41])
        sum_of_strictly_forty_second_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[42])
        sum_of_strictly_forty_third_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[43])
        sum_of_strictly_forty_fourth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[44])
        sum_of_strictly_forty_fourth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[44])
        sum_of_strictly_forty_fifth_only_new_component_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierSum[45])
        sum_of_strictly_forty_fifth_only_new_original_reporter_pair_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $tierReporterSum[45])
        sum_of_combined_full_graph_component_pair_loss_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $allLosses)
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_forty_five_link_scenarios = (ConvertTo-CodeSequenceFortyFiveExactCount -Value $allReporterMass)
        original_direct_link_quinquequadragintuples_with_strictly_forty_fifth_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_forty_five = $cuts.Count
        all_forty_five_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_45_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_forty_five_deletions = $true
        forty_fifth_only_positive_scenarios_are_exact_forty_five_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_forty_fifth_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_forty_five_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_thirty_fifth_thirty_sixth_thirty_seventh_thirty_eighth_thirty_ninth_fortieth_forty_first_forty_second_forty_third_forty_fourth_and_strictly_forty_fifth_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_forty_five_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

# The public entry point accepts exactly the already selected read-only Sequence
# path. No new record, Git, disk, network, seed, Top or family selection occurs.
function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquequadragintupleInteraction {
    param([System.Collections.IDictionary] $PathFocus)
    if ($null -eq $PathFocus) {
        throw 'Code Sequence EC-139 needs the existing selected ORIGINAL Finding-pair path.'
    }
    $piv = $PathFocus['selected_original_finding_pair_profile_retention_pivotality']
    $suppliedParent = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuorquadragintuple_interaction']
    $topologies = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_topology']
    $reductions = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_reduction']
    if ($null -eq $piv -or $null -eq $suppliedParent -or
        $null -eq $topologies -or $null -eq $reductions) {
        throw 'Code Sequence EC-139 did not receive checked original SCC topology, reduction and EC-138 parent.'
    }

    # IMPORTANT: NEVER trust an EC-138 summary/flag/header or previous cache.
    # Replay its entire actual 44-link calculation through all EC-093..137
    # original parents, and compare the COMPLETE public JSON including each
    # genuine/frozen threshold, every real family, all 44 parent incidence tiers,
    # the EC-089/095 FIRST edge lineage, empty strict44 witnesses and bounds.
    # This comparison happens before creating ANY EC-139 projection.
    $freshParent = Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuorquadragintupleInteraction -PathFocus $PathFocus
    if ((ConvertTo-Json -InputObject $freshParent -Depth 100 -Compress) -cne
        (ConvertTo-Json -InputObject $suppliedParent -Depth 100 -Compress)) {
        throw 'Code Sequence EC-139 rejected modified whole-public-JSON EC-138 parent (original FIRST/SCC/tiers/family).'
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
        throw 'Code Sequence EC-139 changed the checked original Finding-pair identity or reporter universe.'
    }

    [object[]]$gTop = [object[]]$topologies.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$fTop = [object[]]$topologies.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$gRed = [object[]]$reductions.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$fRed = [object[]]$reductions.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$gParent = [object[]]$suppliedParent.genuine_global_threshold_endpoint_quattuorquadragintuple_interaction
    [object[]]$fParent = [object[]]$suppliedParent.frozen_global_threshold_endpoint_quattuorquadragintuple_interaction
    [object[]]$famTop = [object[]]$topologies.individual_original_family_endpoint_dominance_topology
    [object[]]$famRed = [object[]]$reductions.individual_original_family_endpoint_dominance_reduction
    [object[]]$famParent = [object[]]$suppliedParent.individual_original_family_endpoint_quattuorquadragintuple_interaction
    if ($gTop.Length -ne 3 -or $fTop.Length -ne 3 -or
        $gRed.Length -ne 3 -or $fRed.Length -ne 3 -or
        $gParent.Length -ne 3 -or $fParent.Length -ne 3 -or
        $famTop.Length -ne $familyCount -or $famRed.Length -ne $familyCount -or
        $famParent.Length -ne $familyCount) {
        throw 'Code Sequence EC-139 changed genuine/frozen global thresholds or actual original repeat-family target counts.'
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
                throw 'Code Sequence EC-139 drifted from actual original threshold identity/capacity.'
            }
            $graph = Get-CodeSequenceEndpointDominanceFortyFiveLinkInteractionProjection `
                -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                -ParentFortyFour $parent.exact_strictly_forty_fourth_only_original_scc_link_removal_interaction -N $n
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_forty_fifth_only_original_scc_link_removal_interaction = $graph
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
            throw 'Code Sequence EC-139 drifted from one actual original repeat family index.'
        }
        $graphG = Get-CodeSequenceEndpointDominanceFortyFiveLinkInteractionProjection `
            -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
            -ParentFortyFour $parent.genuine_exact_strictly_forty_fourth_only_original_scc_link_removal_interaction -N $n
        $graphF = Get-CodeSequenceEndpointDominanceFortyFiveLinkInteractionProjection `
            -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
            -ParentFortyFour $parent.frozen_exact_strictly_forty_fourth_only_original_scc_link_removal_interaction -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_forty_fifth_only_original_scc_link_removal_interaction = $graphG
            frozen_exact_strictly_forty_fifth_only_original_scc_link_removal_interaction = $graphF
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_forty_fifth_order_forty_five_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_quinquequadragintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_quinquequadragintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_quinquequadragintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec138_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

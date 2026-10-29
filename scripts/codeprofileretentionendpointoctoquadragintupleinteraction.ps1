#requires -Version 7.0
<#
    EC-142 / V4.52 / R142: selected read-only original SCC FULL graph
    cardinality-48 exact reachability-deletion interaction. Recompute and
    authenticate the WHOLE real EC-141 k47 parent JSON first.

    Inherited exact orders 1..36 remain accounted for every one of the
    C(E,48) sets of 48 distinct original FULL SCC directed links; an authentic
    <=12-vertex condensation DAG has outgoing source-side cuts <=36, so
    strict orders 37..48 have no witness rows. Enumerate <=4094 real source
    sides, canonical subset-minimal cut DNFs, binomial/Shannon counts and
    reporter-multiplicity incidence tiers, without per-scenario closures.

    E48..E54 use exact zero-to-six-kept complements; E55..E57 reuse exact
    seven-to-nine-kept hit-cut CNFs. NEW E58 retains ten FULL original links:
    solve survivor hitting-CNF using forced singleton obligations, canonical
    clause absorption, disjoint packing, free-link binomial convolution,
    disconnected-incidence polynomial factorization, <=4-clause IE, and
    memoized highest-incidence-edge Shannon decomposition. Never enumerate
    C(58,48)=52,179,482,355 deletion subsets or build scenario bitmaps.
    C(66,48)=6,848,956,078,664,700, with BigInteger reporter aggregation.
#>

function ConvertTo-CodeSequenceFortyEightExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence forty-eight-link reported a negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    # Decimal string avoids lossy floating-point/JSON BigInteger serializer shape.
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceFortyEightLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence forty-eight-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 49)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 48 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFortyEightLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 48 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 49 -or
        $null -eq $Indices -or $Indices.Length -ne 48) {
        throw 'Code Sequence forty-eight-link scenario requires forty-eight ordered genuine ORIGINAL FULL direct-link indices in a 48..66-link universe.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 48; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence forty-eight-link rank requires FORTY-EIGHT DISTINCT ASCENDING original FULL direct-SCC link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 47 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 48]) {
        throw 'Code Sequence forty-eight-link rank escaped the original FULL direct-link combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalFortyEightLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 48 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 49 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 48]) {
        throw 'Code Sequence forty-eight-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(48)
    $previous = -1
    for ($position = 0; $position -lt 47; $position++) {
        $suffix = 47 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence forty-eight-link inversion exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[47] = [int]($previous + $remaining + 1)
    if ($indices[47] -le $indices[46] -or $indices[47] -ge $LinkCount) {
        throw 'Code Sequence forty-eight-link inversion generated repeated or absent ORIGINAL direct links.'
    }
    return ,$indices
}
function Test-CodeSequenceFortyEightLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceFortyEightLinkCanonicalCutFamily {
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
            if ($cut.Length -gt 48) {
                throw 'Code Sequence forty-eight-link cut family cannot require more than forty-eight removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence forty-eight-link cut family contains unordered, repeated or invalid original link indices.'
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
            if (Test-CodeSequenceFortyEightLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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

function Get-CodeSequenceFortyEightLinkCutDnfCountState {
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
        throw 'Code Sequence forty-eight-link memoized cut counter lost its canonical undecided edge frontier.'
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
    $keptFamily = ConvertTo-CodeSequenceFortyEightLinkCanonicalCutFamily -Cuts $keptRaw.ToArray()
    $deletedFamily = ConvertTo-CodeSequenceFortyEightLinkCanonicalCutFamily -Cuts $deletedRaw.ToArray()

    [long]$total = 0
    $maxFreeDeletes = [Math]::Min($gap, $RemainingDeletions)
    for ($freeDeletes = 0; $freeDeletes -le $maxFreeDeletes; $freeDeletes++) {
        [long]$ways = $Choose[$gap, $freeDeletes]
        $afterFree = $RemainingDeletions - $freeDeletes
        if ([bool]$keptFamily.satisfied -or $keptFamily.cuts.Length -gt 0) {
            $total += $ways * (Get-CodeSequenceFortyEightLinkCutDnfCountState `
                -Family $keptFamily -NextEdge ($pivot + 1) -RemainingDeletions $afterFree `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
        if ($afterFree -ge 1 -and ([bool]$deletedFamily.satisfied -or $deletedFamily.cuts.Length -gt 0)) {
            $total += $ways * (Get-CodeSequenceFortyEightLinkCutDnfCountState `
                -Family $deletedFamily -NextEdge ($pivot + 1) -RemainingDeletions ($afterFree - 1) `
                -LinkCount $LinkCount -Choose $Choose -Memo $Memo)
        }
    }
    if ($total -lt 0 -or $total -gt $Choose[$LinkCount, 48]) {
        throw 'Code Sequence forty-eight-link memoized cut counter exceeded the exact forty-eight-link scenario universe.'
    }
    $Memo[$memoKey] = $total
    return $total
}

# Exact survivor-CNF solver for E55..E58 / k48: every surviving original FULL link
# set avoiding the deleted-cut DNF must hit EVERY canonical source-side cut.
# Keep only canonical residual cut masks; memoize by (available links, survivors,
# unsatisfied masks). Edge decisions never materialize C(56,48) cases.
# Exact cardinality-limited kept-link hitting CNF. The original FULL links
# form at most a 58-bit universe at this near-complete deletion boundary.
# Every still-unhit source-side cut is a required survivor clause. The state
# contains ONLY undecided available original edges and exact survivor budget.
# It never materializes a deletion set, per-scenario SCC graph or bitmap.
function Get-CodeSequenceFortyEightLinkKeptCutHittingState {
    param(
        [long[]] $UnhitMasks,
        [long] $AvailableMask,
        [int] $RemainingKept,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($AvailableMask -lt 0 -or $RemainingKept -lt 0) { return [long]0 }
    [int]$available = [System.Numerics.BitOperations]::PopCount([uint64]$AvailableMask)
    if ($RemainingKept -gt $available) { return [long]0 }
    if ($null -eq $UnhitMasks -or $UnhitMasks.Length -eq 0) {
        return [long]$Choose[$available, $RemainingKept]
    }
    if ($RemainingKept -eq 0) { return [long]0 }

    # A deleted decision can remove a bit from several clauses; canonicalize
    # their remaining masks, detect a completely un-hittable original cut,
    # and collapse duplicates before any memo lookup or branching.
    $unique = [System.Collections.Generic.HashSet[long]]::new()
    [long]$forced = 0
    foreach ($raw in $UnhitMasks) {
        [long]$mask = $raw -band $AvailableMask
        if ($mask -eq 0) { return [long]0 }
        if ($unique.Add($mask) -and (($mask -band ($mask - 1)) -eq 0)) {
            # The sole remaining original edge in this clause MUST survive.
            $forced = $forced -bor $mask
        }
    }
    [long[]]$masks = [long[]]::new($unique.Count)
    $unique.CopyTo($masks)
    [Array]::Sort($masks)

    if ($forced -ne 0) {
        [int]$mustKeep = [System.Numerics.BitOperations]::PopCount([uint64]$forced)
        if ($mustKeep -gt $RemainingKept) { return [long]0 }
        $pending = [System.Collections.Generic.List[long]]::new()
        foreach ($mask in $masks) {
            if (($mask -band $forced) -eq 0) { $pending.Add($mask) }
        }
        # Each forced link is charged exactly once; free suffix counts still
        # include all other genuine ORIGINAL links, never invented edges.
        return Get-CodeSequenceFortyEightLinkKeptCutHittingState `
            -UnhitMasks $pending.ToArray() `
            -AvailableMask ($AvailableMask -band (-bnot $forced)) `
            -RemainingKept ($RemainingKept - $mustKeep) -Choose $Choose -Memo $Memo
    }

    # Subsumed clauses are redundant for hitting: hit A implies hit B when
    # A is a subset of B. Remove them when the family is modest; retaining
    # them for a large family is still exact and avoids quadratic overhead.
    if ($masks.Length -le 256 -and $masks.Length -gt 1) {
        $minimal = [System.Collections.Generic.List[long]]::new()
        foreach ($mask in $masks) {
            $dominated = $false
            foreach ($other in $masks) {
                if ($other -eq $mask) { continue }
                if (($other -band $mask) -eq $other) {
                    $dominated = $true
                    break
                }
            }
            if (-not $dominated) { $minimal.Add($mask) }
        }
        $masks = $minimal.ToArray()
    }

    # Available ORIGINAL edges absent from EVERY unhit clause are free.
    # Distribute their retained budget by exact binomials; a single recursive
    # subproblem represents whole classes of otherwise different edge sets.
    [long]$relevant = 0
    foreach ($mask in $masks) { $relevant = $relevant -bor $mask }
    [long]$freeMask = $AvailableMask -band (-bnot $relevant)
    if ($freeMask -ne 0) {
        [int]$freeCount = [System.Numerics.BitOperations]::PopCount([uint64]$freeMask)
        [long]$totalFree = 0
        for ($keptFree = 0; $keptFree -le [Math]::Min($freeCount, $RemainingKept); $keptFree++) {
            $ways = [long]$Choose[$freeCount, $keptFree]
            $subtotal = Get-CodeSequenceFortyEightLinkKeptCutHittingState `
                -UnhitMasks $masks -AvailableMask $relevant `
                -RemainingKept ($RemainingKept - $keptFree) -Choose $Choose -Memo $Memo
            $totalFree += $ways * $subtotal
        }
        if ($totalFree -lt 0 -or $totalFree -gt $Choose[$available, $RemainingKept]) {
            throw 'Code Sequence forty-eight-link free survivor edges exceeded the exact cardinality universe.'
        }
        return $totalFree
    }

    # Any collection of pairwise-disjoint required clauses needs at least
    # one distinct survivor per clause. A greedy packing is a safe lower bound.
    # Try smaller clauses first, strengthening the bound without solving the
    # NP-hard maximum packing subproblem.
    [long]$packed = 0
    [int]$minimumRequired = 0
    [object[]]$smallFirst = @($masks | Sort-Object { [System.Numerics.BitOperations]::PopCount([uint64]$_) })
    foreach ($maskValue in $smallFirst) {
        [long]$mask = [long]$maskValue
        if (($mask -band $packed) -eq 0) {
            $minimumRequired++
            $packed = $packed -bor $mask
            if ($minimumRequired -gt $RemainingKept) { return [long]0 }
        }
    }

    if ($RemainingKept -eq $available) { return [long]1 }

    # Up to 4 clauses have an exact closed inclusion-exclusion sum:
    # keep at least one edge of each clause. This is not an approximation.
    if ($masks.Length -le 4) {
        [long]$exact = 0
        [int]$subsets = 1 -shl $masks.Length
        for ($selection = 0; $selection -lt $subsets; $selection++) {
            [long]$blocked = 0
            [int]$parity = 0
            for ($j = 0; $j -lt $masks.Length; $j++) {
                if (($selection -band (1 -shl $j)) -ne 0) {
                    $blocked = $blocked -bor $masks[$j]
                    $parity++
                }
            }
            [int]$remainingAvailable = $available - [System.Numerics.BitOperations]::PopCount([uint64]$blocked)
            $term = [long]$Choose[$remainingAvailable, $RemainingKept]
            if (($parity % 2) -eq 0) { $exact += $term }
            else { $exact -= $term }
        }
        if ($exact -lt 0 -or $exact -gt $Choose[$available, $RemainingKept]) {
            throw 'Code Sequence forty-eight-link 4-clause survivor IE violated cardinality bounds.'
        }
        return $exact
    }

    # EC-142: factorize disconnected CNF incidence components. Every cut
    # belongs to exactly one component because its original-edge mask cannot
    # cross components. Survivor choices factor as a PRODUCT of exact
    # cardinality-generating polynomials; coefficient convolution counts each
    # kept-edge set once. This makes disjoint ten-cut E58 cases tractable
    # without C(58,10) survivor enumeration, a scenario bitmap or SCC closure.
    $key = "$AvailableMask|$RemainingKept|$($masks -join ',')"
    [long]$cached = 0
    if ($Memo.TryGetValue($key, [ref]$cached)) { return $cached }
    if ($masks.Length -le 512) {
        $pieces = [System.Collections.Generic.List[long]]::new()
        [long]$unseen = $relevant
        while ($unseen -ne 0) {
            [int]$seedIndex = [System.Numerics.BitOperations]::TrailingZeroCount([uint64]$unseen)
            [long]$piece = [long]1 -shl $seedIndex
            $changed = $true
            while ($changed) {
                $changed = $false
                foreach ($mask in $masks) {
                    if (($mask -band $piece) -ne 0 -and
                        ($mask -band (-bnot $piece)) -ne 0) {
                        $piece = $piece -bor $mask
                        $changed = $true
                    }
                }
            }
            $pieces.Add($piece)
            $unseen = $unseen -band (-bnot $piece)
        }
        if ($pieces.Count -gt 1) {
            [long[]]$coefficients = [long[]]::new($RemainingKept + 1)
            $coefficients[0] = 1
            [int]$processed = 0
            foreach ($piece in $pieces) {
                $pieceCuts = [System.Collections.Generic.List[long]]::new()
                foreach ($mask in $masks) {
                    if (($mask -band $piece) -ne 0) {
                        # A CNF cut crossing piece boundaries would invalidate
                        # polynomial multiplication: reject rather than guess.
                        if (($mask -band (-bnot $piece)) -ne 0) {
                            throw 'Code Sequence k48 disconnected-cut factorization mixed original links.'
                        }
                        $pieceCuts.Add($mask)
                    }
                }
                [int]$pieceSize = [System.Numerics.BitOperations]::PopCount([uint64]$piece)
                [long[]]$next = [long[]]::new($RemainingKept + 1)
                for ($keptPiece = 0; $keptPiece -le [Math]::Min($pieceSize, $RemainingKept); $keptPiece++) {
                    [long]$countPiece = Get-CodeSequenceFortyEightLinkKeptCutHittingState `
                        -UnhitMasks $pieceCuts.ToArray() -AvailableMask $piece `
                        -RemainingKept $keptPiece -Choose $Choose -Memo $Memo
                    if ($countPiece -eq 0) { continue }
                    for ($prior = 0; $prior -le [Math]::Min($processed, $RemainingKept - $keptPiece); $prior++) {
                        if ($coefficients[$prior] -ne 0) {
                            $next[$prior + $keptPiece] += $coefficients[$prior] * $countPiece
                        }
                    }
                }
                $coefficients = $next
                $processed += $pieceSize
            }
            [long]$factored = $coefficients[$RemainingKept]
            if ($factored -lt 0 -or $factored -gt $Choose[$available, $RemainingKept]) {
                throw 'Code Sequence k48 disconnected original survivor components violated cardinality bounds.'
            }
            $Memo[$key] = $factored
            return $factored
        }
    }

    # Exact Shannon recursion. Pick an edge participating in the largest
    # number of unhit clauses so the kept branch discharges maximum evidence.
    # Unlike prefix enumeration, this may pivot anywhere; AvailableMask makes
    # both branches unambiguous, and the no-clause/free cases stay binomial.
    # Real E58 may place an eligible SCC link at index 56 or 57;
    # all 0..65 genuine original-link indices must fit the pivot counters.
    [int[]]$occurrences = [int[]]::new(66)
    foreach ($mask in $masks) {
        [long]$bits = $mask
        while ($bits -ne 0) {
            [int]$edge = [System.Numerics.BitOperations]::TrailingZeroCount([uint64]$bits)
            $occurrences[$edge]++
            $bits = $bits -band ($bits - 1)
        }
    }
    [int]$pivot = -1
    [int]$best = -1
    for ($edge = 0; $edge -lt 66; $edge++) {
        if ($occurrences[$edge] -gt $best) { $best = $occurrences[$edge]; $pivot = $edge }
    }
    if ($pivot -lt 0 -or $best -le 0 -or
        ($AvailableMask -band ([long]1 -shl $pivot)) -eq 0) {
        throw 'Code Sequence forty-eight-link survivor pivot escaped genuine available original links.'
    }
    [long]$pivotBit = [long]1 -shl $pivot
    [long]$rest = $AvailableMask -band (-bnot $pivotBit)
    $afterKeep = [System.Collections.Generic.List[long]]::new()
    foreach ($mask in $masks) {
        if (($mask -band $pivotBit) -eq 0) { $afterKeep.Add($mask) }
    }
    [long]$total = Get-CodeSequenceFortyEightLinkKeptCutHittingState `
        -UnhitMasks $masks -AvailableMask $rest -RemainingKept $RemainingKept `
        -Choose $Choose -Memo $Memo
    if ($RemainingKept -gt 0) {
        $total += Get-CodeSequenceFortyEightLinkKeptCutHittingState `
            -UnhitMasks $afterKeep.ToArray() -AvailableMask $rest `
            -RemainingKept ($RemainingKept - 1) -Choose $Choose -Memo $Memo
    }
    if ($total -lt 0 -or $total -gt $Choose[$available, $RemainingKept]) {
        throw 'Code Sequence forty-eight-link survivor Shannon recursion violated exact bounds.'
    }
    $Memo[$key] = $total
    return $total
}

function Get-CodeSequenceFortyEightLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 48 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 49) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 48) { return [long]0 }
        throw 'Code Sequence forty-eight-link DNF counter requires a valid 0..66 original-link universe.'
    }
    # Validate every supplied edge BEFORE subsumption/satisfaction reduction.
    # Otherwise an out-of-universe cut hidden behind a valid smaller cut could
    # be discarded unnoticed and corrupt the trust boundary of this API.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence forty-eight-link DNF cut references an absent ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceFortyEightLinkCanonicalCutFamily -Cuts $Cuts
    if ([bool]$family.satisfied) { return [long]$Choose[$LinkCount, 48] }
    if ($family.cuts.Length -eq 0) { return [long]0 }
    if ($family.cuts.Length -eq 1) {
        # One genuine canonical cut W: a k48 deletion satisfies this DNF
        # iff it contains all |W| actual links. Count the remaining deletions
        # directly, without running any survivor-prefix search or recursion.
        [int]$cutSize = ([int[]]$family.cuts[0]).Length
        return [long]$Choose[$LinkCount - $cutSize, 48 - $cutSize]
    }

    # Exact near-full-removal complements (k=48): E48 all deleted; E49 one surviving edge; E50 two; E51 three;
    # E52 four; E53 five; E54 six. A surviving edge-set avoids
    # the monotone cut DNF iff it intersects EVERY canonical cut. Count
    # hitting 1/2/3/4/5/6-survivor subsets directly by bitmask intersections,
    # never enumerate C(E,48) deleted-edge scenarios or build bitmaps.
    if ($LinkCount -eq 48) { return [long]1 }
    if ($LinkCount -ge 49 -and $LinkCount -le 58) {
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
        if ($LinkCount -eq 49) {
            [int]$avoiding = [System.Numerics.BitOperations]::PopCount([uint64]$commonMask)
            return [long]($Choose[49,48] - $avoiding)
        }
        if ($LinkCount -eq 50) {
            [int]$twoKeptAvoiding = 0
            for ($first = 0; $first -lt 50; $first++) {
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
            [long]$satisfied = $Choose[50,48] - $twoKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[50,48]) {
                throw 'Code Sequence forty-eight-link two-survivor complement violated exact C(50,48).'
            }
            return $satisfied
        }
        if ($LinkCount -eq 51) {
            # Three survivors: for each first two kept edges (i,j), any cut
            # already hit by either can be ignored. The third kept edge must
            # belong to the INTERSECTION of all remaining unhit cuts. Only
            # higher third indices are counted, so triples are unique. This
            # costs O(E^2 * canonicalCutCount) and O(canonicalCutCount) memory;
            # there is no C(51,48) deletion enumeration, graph closure or DNF
            # recursion on this edge-case boundary.
            [long]$threeKeptAvoiding = 0
            for ($first = 0; $first -lt 51; $first++) {
                [long]$firstBit = [long]1 -shl $first
                for ($second = $first + 1; $second -lt 51; $second++) {
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
            [long]$satisfied = $Choose[51,48] - $threeKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[51,48]) {
                throw 'Code Sequence forty-eight-link three-survivor complement violated exact C(51,48).'
            }
            return $satisfied
        }

        if ($LinkCount -eq 52) {
            # Four survivors (E=52). Fix the two earliest kept links (i,j),
            # discard all cuts already hit by them, then for each third kept link
            # k>j intersect only still-unhit cuts to obtain all eligible fourth
            # links l>k. Every quadruple has exactly one (i,j,k,l) ordering, but
            # no quadruple deletion mask, residual SCC closure or scenario bitmap
            # is ever constructed. The pair-already-hits-all case contributes
            # C(51-j,2) combinations in one exact binomial lookup.
            [long]$fourKeptAvoiding = 0
            for ($first = 0; $first -lt 49; $first++) {
                [long]$firstBit = [long]1 -shl $first
                for ($second = $first + 1; $second -lt 50; $second++) {
                    [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                    $unhitAfterPair = [System.Collections.Generic.List[long]]::new()
                    foreach ($termMask in $termMasks) {
                        if (($termMask -band $keptPairMask) -eq 0) {
                            $unhitAfterPair.Add($termMask)
                        }
                    }
                    if ($unhitAfterPair.Count -eq 0) {
                        $fourKeptAvoiding += $Choose[51 - $second, 2]
                        continue
                    }
                    for ($third = $second + 1; $third -lt 51; $third++) {
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
            [long]$satisfied = $Choose[52,48] - $fourKeptAvoiding
            if ($satisfied -lt 0 -or $satisfied -gt $Choose[52,48]) {
                throw 'Code Sequence forty-eight-link four-survivor complement violated exact C(52,48).'
            }
            return $satisfied
        }

        if ($LinkCount -eq 53) {
            # Five survivors (E=53). Count HITTING quintets without visiting
        # C(53,48) removal cases. Fix the first kept pair, cache only cuts
        # not hit by it, and collapse the remaining suffix when all cuts
        # are already hit. Otherwise fix the third and fourth kept links;
        # intersect still-missed cut masks to popcount all possible fifth
        # indices greater than the fourth. Every quintet has one ordered
        # (i,j,k,l,h) prefix and is counted exactly once; NO SCC closure,
        # scenario bitmap, or five-kept tuple is materialized.
        [long]$fiveKeptAvoiding = 0
        for ($first = 0; $first -lt 49; $first++) {
            [long]$firstBit = [long]1 -shl $first
            for ($second = $first + 1; $second -lt 50; $second++) {
                [long]$keptPairMask = $firstBit -bor ([long]1 -shl $second)
                $unhitAfterPair = [System.Collections.Generic.List[long]]::new()
                foreach ($termMask in $termMasks) {
                    if (($termMask -band $keptPairMask) -eq 0) {
                        $unhitAfterPair.Add($termMask)
                    }
                }
                if ($unhitAfterPair.Count -eq 0) {
                    # E52 minus the first j+1 indices gives 52-j later
                    # links; any 3 of these complete a hitting quintet.
                    $fiveKeptAvoiding += $Choose[52 - $second, 3]
                    continue
                }
                for ($third = $second + 1; $third -lt 51; $third++) {
                    [long]$thirdBit = [long]1 -shl $third
                    $unhitAfterTriple = [System.Collections.Generic.List[long]]::new()
                    foreach ($termMask in $unhitAfterPair) {
                        if (($termMask -band $thirdBit) -eq 0) {
                            $unhitAfterTriple.Add($termMask)
                        }
                    }
                    if ($unhitAfterTriple.Count -eq 0) {
                        $fiveKeptAvoiding += $Choose[52 - $third, 2]
                        continue
                    }
                    for ($fourth = $third + 1; $fourth -lt 52; $fourth++) {
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
        [long]$satisfied = $Choose[53,48] - $fiveKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[53,48]) {
            throw 'Code Sequence forty-eight-link five-survivor complement violated exact C(53,48).'
        }
        return $satisfied
        }

    if ($LinkCount -eq 54) {
        # E53/k48 leaves six real original FULL edges. Count surviving six-edge
        # HITTING sets, which are precisely the deletion sets avoiding the
        # canonical monotone cut DNF. Every surviving ordered prefix is visited
        # at most once; no C(54,48)=15,890,700 cases or graph closures are built.
        # When the prefix already hits every cut, its suffix is collapsed into
        # a binomial. A missed cut without any higher possible hit prunes the
        # entire prefix. The sixth edge is counted with a single PopCount.
        [long]$sixKeptAvoiding = 0
        for ($first = 0; $first -lt 49; $first++) {
            [long]$firstBit = [long]1 -shl $first
            for ($second = $first + 1; $second -lt 50; $second++) {
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
                    $sixKeptAvoiding += $Choose[53 - $second, 4]
                    continue
                }
                for ($third = $second + 1; $third -lt 51; $third++) {
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
                        $sixKeptAvoiding += $Choose[53 - $third, 3]
                        continue
                    }
                    for ($fourth = $third + 1; $fourth -lt 52; $fourth++) {
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
                            $sixKeptAvoiding += $Choose[53 - $fourth, 2]
                            continue
                        }
                        for ($fifth = $fourth + 1; $fifth -lt 53; $fifth++) {
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
        [long]$satisfied = $Choose[54,48] - $sixKeptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[54,48]) {
            throw 'Code Sequence forty-eight-link six-survivor complement violated exact C(54,48).'
        }
        return $satisfied
    }
    if ($LinkCount -ge 55 -and $LinkCount -le 58) {
        # EC-142: E55/E56/E57 retain exact seven/eight/nine-survivor
        # cases, and NEW E58 retains TEN genuine FULL SCC directed edges.
        # Hitting every original cut is the complement of deleting a cut;
        # count this CNF exactly with forced edges, disjoint-clause pruning,
        # canonical memoized branching, component factorization, free-edge binomials and <=4-clause IE.
        # Never enumerate C(58,48)=52,179,482,355 deletion sets.
        if ($null -eq $Memo) {
            $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
        }
        [int]$keptCount = $LinkCount - 48
        [long]$keptAvoiding = Get-CodeSequenceFortyEightLinkKeptCutHittingState `
            -UnhitMasks $termMasks.ToArray() -AvailableMask $universeMask `
            -RemainingKept $keptCount -Choose $Choose -Memo $Memo
        [long]$satisfied = $Choose[$LinkCount,48] - $keptAvoiding
        if ($satisfied -lt 0 -or $satisfied -gt $Choose[$LinkCount,48]) {
            throw 'Code Sequence forty-eight-link 7/8/9/10 survivor complement violated exact C(E,48).'
        }
        return $satisfied
    }
    }
    # Reuse canonical subproblem counts for the same (s,t) over thresholds 1..48.
    # The memo key includes the FULL residual cut family, edge frontier and
    # remaining deletion budget; sharing it never merges different predicates.
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    return Get-CodeSequenceFortyEightLinkCutDnfCountState -Family $family -NextEdge 0 `
        -RemainingDeletions 48 -LinkCount $LinkCount -Choose $Choose -Memo $Memo
}

# EC-142 keeps all 141 earlier outputs untouched; the parent was
# authenticated as one complete public JSON object BEFORE constructing this child.
function Get-CodeSequenceEndpointDominanceFortyEightLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $ParentFortySeven,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $ParentFortySeven -or
        -not [bool]$ParentFortySeven.every_scenario_deletes_forty_seven_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$ParentFortySeven.original_scc_directed_cut_saturation_bound_36_for_at_most_12_components -or
        -not [bool]$ParentFortySeven.all_strictly_forty_seventh_only_positive_rows_proven_impossible -or
        -not [bool]$ParentFortySeven.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$ParentFortySeven.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence forty-eight-link projection requires the checked EC-141 k47 original FULL SCC parent.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$ParentFortySeven.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$ParentFortySeven.exact_original_direct_component_link_count -ne $linkCount -or
        [int]$ParentFortySeven.original_positions_in_impact_universe -ne $N) {
        throw 'Code Sequence forty-eight-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence forty-eight-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence forty-eight-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence forty-eight-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence forty-eight-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    # The original FULL SCC condensation must be antisymmetric: any mutual
    # reachability would collapse distinct vertices into one original SCC.
    # Check this precondition explicitly before relying on the 36-edge bound.
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = $s + 1; $t -lt $componentCount; $t++) {
            if (($baseline[$s] -band (1 -shl $t)) -ne 0 -and
                ($baseline[$t] -band (1 -shl $s)) -ne 0) {
                throw 'Code Sequence forty-eight-link cannot certify saturation for cyclic distinct original SCCs.'
            }
        }
    }
    [long[,]]$choose = New-CodeSequenceFortyEightLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 48]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=46 real FULL links can affect a forty-eight-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 48) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 48) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..47, the exact number of forty-eight-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,48) graph closures and any C(E,48)-bit mask.
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(49)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(49)
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
            for ($order = 1; $order -le 48; $order++) {
                $newMinimalCut = $false
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceFortyEightLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    $newMinimalCut = $true
                    if ($order -eq 48) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectFortyEightLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                # No newly minimal boundary => same monotone DNF and same
                # exact-cardinality count; do not re-solve an identical DNF.
                [long]$cumulative = $previousCumulative
                if ($newMinimalCut) {
                    $cumulative = Get-CodeSequenceFortyEightLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence forty-eight-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence forty-eight-link minimal cut registry exceeded its source candidate family.'
            }
        }
    }
    # Tight finite-size bound: a complete outgoing source-side cut in an
    # original simple SCC condensation DAG has at most floor(m*m/4) edges.
    # With m<=12 this is <=36, so strictly-37..48-only losses are
    # all impossible, even when E>=46; earlier tiers remain nonzero.
    $maximumOutgoingCut = [int][math]::Floor(($componentCount * $componentCount) / 4)
    if ($maximumOutgoingCut -gt 36 -or $positiveRanks.Count -ne 0) {
        throw 'Code Sequence forty-eight-link source violates the 12-SCC / 36-edge complete-cut bound.'
    }
    for ($strictOrder = 37; $strictOrder -le 48; $strictOrder++) {
        if ($tierSum[$strictOrder] -ne [System.Numerics.BigInteger]::Zero -or
            $tierReporterSum[$strictOrder] -ne [System.Numerics.BigInteger]::Zero) {
            throw 'Code Sequence forty-eight-link model invented an impossible strict order above 36.'
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence forty-eight-link strictly forty-eightth-only cases exceed the bounded directed-cut universe.'
    }

    # No sparse output expansion at k=48: for at most twelve ORIGINAL SCCs,
    # every complete outgoing SCC vertex boundary has at most 36 FULL edges.
    # Exact cardinality-48 still counts earlier loss orders 1..36;
    # skipping nonexistent strict-37..48 rows avoids fabricated evidence.
    $rows = [System.Collections.Generic.List[object]]::new()

    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 48; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    # Disjoint per-relation minimum-cut tiers cannot count more ordered
    # reachable SCC/reporter relations than physically exist per scenario.
    # Cast BEFORE multiplying: the BigInteger operands preserve conservative N12/E66 mass bounds
    # even if later scenario limits are expanded beyond signed Int64.
    [System.Numerics.BigInteger]$maxComponentIncidences = [System.Numerics.BigInteger]($componentCount * ($componentCount - 1)) * $scenarioCount
    [System.Numerics.BigInteger]$maxReporterIncidences = [System.Numerics.BigInteger]($N * ($N - 1)) * $scenarioCount
    if ($allLosses -gt $maxComponentIncidences -or
        $allReporterMass -gt $maxReporterIncidences -or
        $positiveRanks.Count -gt 4094) {
        throw 'Code Sequence forty-eight-link original SCC/reporter incidence or bounded positive cut invariant failed.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        maximum_possible_complete_outgoing_original_scc_cut_size = $maximumOutgoingCut
        original_scc_directed_cut_saturation_bound_36_for_at_most_12_components = $true
        all_strictly_forty_eighth_only_positive_rows_proven_impossible = $true
        exact_original_direct_component_link_count = $linkCount
        exact_forty_eight_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_forty_eighth_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_forty_eighth_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[1])
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[1])
        sum_of_pair_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[2])
        sum_of_pair_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[2])
        sum_of_triple_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[3])
        sum_of_triple_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[3])
        sum_of_quadruple_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[4])
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[4])
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[5])
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[5])
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[6])
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[6])
        sum_of_strictly_seventh_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[7])
        sum_of_strictly_seventh_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[7])
        sum_of_strictly_eighth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[8])
        sum_of_strictly_eighth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[8])
        sum_of_strictly_ninth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[9])
        sum_of_strictly_ninth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[9])
        sum_of_strictly_tenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[10])
        sum_of_strictly_tenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[10])
        sum_of_strictly_eleventh_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[11])
        sum_of_strictly_eleventh_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[11])
        sum_of_strictly_twelfth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[12])
        sum_of_strictly_twelfth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[12])
        sum_of_strictly_thirteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[13])
        sum_of_strictly_thirteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[13])
        sum_of_strictly_fourteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[14])
        sum_of_strictly_fourteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[14])
        sum_of_strictly_fifteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[15])
        sum_of_strictly_fifteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[15])
        sum_of_strictly_sixteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[16])
        sum_of_strictly_sixteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[16])
        sum_of_strictly_seventeenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[17])
        sum_of_strictly_seventeenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[17])
        sum_of_strictly_eighteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[18])
        sum_of_strictly_eighteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[18])
        sum_of_strictly_nineteenth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[19])
        sum_of_strictly_nineteenth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[19])
        sum_of_strictly_twentieth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[20])
        sum_of_strictly_twentieth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[20])
        sum_of_strictly_twenty_first_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[21])
        sum_of_strictly_twenty_first_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[21])
        sum_of_strictly_twenty_second_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[22])
        sum_of_strictly_twenty_second_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[22])
        sum_of_strictly_twenty_third_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[23])
        sum_of_strictly_twenty_third_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[23])
        sum_of_strictly_twenty_fourth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[24])
        sum_of_strictly_twenty_fourth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[24])
        sum_of_strictly_twenty_fifth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[25])
        sum_of_strictly_twenty_fifth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[25])
        sum_of_strictly_twenty_sixth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[26])
        sum_of_strictly_twenty_sixth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[26])
        sum_of_strictly_twenty_seventh_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[27])
        sum_of_strictly_twenty_seventh_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[27])
        sum_of_strictly_twenty_eighth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[28])
        sum_of_strictly_twenty_eighth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[28])
        sum_of_strictly_twenty_ninth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[29])
        sum_of_strictly_thirtieth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[30])
        sum_of_strictly_thirty_second_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[32])
        sum_of_strictly_thirty_third_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[33])
        sum_of_strictly_thirty_fourth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[34])
        sum_of_strictly_thirty_fifth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[35])
        sum_of_strictly_thirty_sixth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[36])
        sum_of_strictly_thirty_seventh_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[37])
        sum_of_strictly_twenty_ninth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[29])
        sum_of_strictly_thirtieth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[30])
        sum_of_strictly_thirty_first_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[31])
        sum_of_strictly_thirty_first_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[31])
        sum_of_strictly_thirty_second_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[32])
        sum_of_strictly_thirty_third_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[33])
        sum_of_strictly_thirty_fourth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[34])
        sum_of_strictly_thirty_fifth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[35])
        sum_of_strictly_thirty_sixth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[36])
        sum_of_strictly_thirty_seventh_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[37])
        sum_of_strictly_thirty_eighth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[38])
        sum_of_strictly_thirty_eighth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[38])
        sum_of_strictly_thirty_ninth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[39])
        sum_of_strictly_thirty_ninth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[39])
        sum_of_strictly_fortieth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[40])
        sum_of_strictly_fortieth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[40])
        sum_of_strictly_forty_first_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[41])
        sum_of_strictly_forty_second_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[42])
        sum_of_strictly_forty_third_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[43])
        sum_of_strictly_forty_first_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[41])
        sum_of_strictly_forty_second_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[42])
        sum_of_strictly_forty_third_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[43])
        sum_of_strictly_forty_fourth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[44])
        sum_of_strictly_forty_fourth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[44])
        sum_of_strictly_forty_fifth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[45])
        sum_of_strictly_forty_fifth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[45])
        sum_of_strictly_forty_sixth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[46])
        sum_of_strictly_forty_seventh_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[47])
        sum_of_strictly_forty_sixth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[46])
        sum_of_strictly_forty_seventh_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[47])
        sum_of_strictly_forty_eighth_only_new_component_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierSum[48])
        sum_of_strictly_forty_eighth_only_new_original_reporter_pair_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $tierReporterSum[48])
        sum_of_combined_full_graph_component_pair_loss_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $allLosses)
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_forty_eight_link_scenarios = (ConvertTo-CodeSequenceFortyEightExactCount -Value $allReporterMass)
        original_direct_link_octoquadragintuples_with_strictly_forty_eighth_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_forty_eight = $cuts.Count
        all_forty_seven_link_scenarios_counted_via_exact_memoized_scc_directed_cut_dnf_not_per_scenario_graph_closure = $true
        no_c_e_48_bitset_or_dense_scenario_objects_allocated = $true
        memoized_monotone_cut_dnf_counts_exact_cardinality_forty_eight_deletions = $true
        forty_eighth_only_positive_scenarios_are_exact_forty_eight_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_forty_eighth_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_forty_eight_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_sixth_seventh_eighth_ninth_tenth_eleventh_twelfth_thirteenth_fourteenth_fifteenth_sixteenth_seventeenth_eighteenth_nineteenth_twentieth_twenty_first_twenty_second_twenty_third_twenty_fourth_twenty_fifth_twenty_sixth_twenty_seventh_twenty_eighth_twenty_ninth_thirtieth_thirty_first_thirty_second_thirty_third_thirty_fourth_thirty_fifth_thirty_sixth_thirty_seventh_thirty_eighth_thirty_ninth_fortieth_forty_first_forty_second_forty_third_forty_fourth_forty_fifth_forty_sixth_forty_seventh_and_strictly_forty_eighth_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_forty_eight_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

# The public entry point accepts exactly the already selected read-only Sequence
# path. No new record, Git, disk, network, seed, Top or family selection occurs.
function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctoquadragintupleInteraction {
    param([System.Collections.IDictionary] $PathFocus)
    if ($null -eq $PathFocus) {
        throw 'Code Sequence EC-142 needs the existing selected ORIGINAL Finding-pair path.'
    }
    $piv = $PathFocus['selected_original_finding_pair_profile_retention_pivotality']
    $suppliedParent = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_septemquadragintuple_interaction']
    $topologies = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_topology']
    $reductions = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_reduction']
    if ($null -eq $piv -or $null -eq $suppliedParent -or
        $null -eq $topologies -or $null -eq $reductions) {
        throw 'Code Sequence EC-142 did not receive checked original SCC topology, reduction and EC-141 parent.'
    }

    # IMPORTANT: NEVER trust an EC-141 summary/flag/header or previous cache.
    # Replay its entire actual 47-link calculation through EC-093..140
    # original parents, and compare COMPLETE public JSON including each
    # genuine/frozen threshold, every real family, all 47 inherited tiers,
    # EC-089/095 FIRST lineage, empty strict47 witnesses and bounds.
    # This comparison happens before creating ANY EC-142 projection.
    $freshParent = Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptemquadragintupleInteraction -PathFocus $PathFocus
    if ((ConvertTo-Json -InputObject $freshParent -Depth 100 -Compress) -cne
        (ConvertTo-Json -InputObject $suppliedParent -Depth 100 -Compress)) {
        throw 'Code Sequence EC-142 rejected modified whole-public-JSON EC-141 parent (original FIRST/SCC/tiers/family).'
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
        throw 'Code Sequence EC-142 changed the checked original Finding-pair identity or reporter universe.'
    }

    [object[]]$gTop = [object[]]$topologies.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$fTop = [object[]]$topologies.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$gRed = [object[]]$reductions.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$fRed = [object[]]$reductions.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$gParent = [object[]]$suppliedParent.genuine_global_threshold_endpoint_septemquadragintuple_interaction
    [object[]]$fParent = [object[]]$suppliedParent.frozen_global_threshold_endpoint_septemquadragintuple_interaction
    [object[]]$famTop = [object[]]$topologies.individual_original_family_endpoint_dominance_topology
    [object[]]$famRed = [object[]]$reductions.individual_original_family_endpoint_dominance_reduction
    [object[]]$famParent = [object[]]$suppliedParent.individual_original_family_endpoint_septemquadragintuple_interaction
    if ($gTop.Length -ne 3 -or $fTop.Length -ne 3 -or
        $gRed.Length -ne 3 -or $fRed.Length -ne 3 -or
        $gParent.Length -ne 3 -or $fParent.Length -ne 3 -or
        $famTop.Length -ne $familyCount -or $famRed.Length -ne $familyCount -or
        $famParent.Length -ne $familyCount) {
        throw 'Code Sequence EC-142 changed genuine/frozen global thresholds or actual original repeat-family target counts.'
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
                throw 'Code Sequence EC-142 drifted from actual original threshold identity/capacity.'
            }
            $graph = Get-CodeSequenceEndpointDominanceFortyEightLinkInteractionProjection `
                -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                -ParentFortySeven $parent.exact_strictly_forty_seventh_only_original_scc_link_removal_interaction -N $n
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_forty_eighth_only_original_scc_link_removal_interaction = $graph
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
            throw 'Code Sequence EC-142 drifted from one actual original repeat family index.'
        }
        $graphG = Get-CodeSequenceEndpointDominanceFortyEightLinkInteractionProjection `
            -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
            -ParentFortySeven $parent.genuine_exact_strictly_forty_seventh_only_original_scc_link_removal_interaction -N $n
        $graphF = Get-CodeSequenceEndpointDominanceFortyEightLinkInteractionProjection `
            -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
            -ParentFortySeven $parent.frozen_exact_strictly_forty_seventh_only_original_scc_link_removal_interaction -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_forty_eighth_only_original_scc_link_removal_interaction = $graphG
            frozen_exact_strictly_forty_eighth_only_original_scc_link_removal_interaction = $graphF
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_forty_eighth_order_forty_eight_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_octoquadragintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_octoquadragintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_octoquadragintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec141_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

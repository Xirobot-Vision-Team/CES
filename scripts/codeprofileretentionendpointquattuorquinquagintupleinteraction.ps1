#requires -Version 7.0
<#
    EC-148 / V4.58 / R148 — selected ORIGINAL FULL SCC reachability when
    exactly 54 distinct whole original directed SCC links are deleted.

    Chain of custody: independently rerun the actual EC147 k53 public parent
    and compare its entire public JSON before adding this read-only child.
    The original SCC DAG is simple, m<=12, E<=66, so complete outgoing
    boundaries have size <=36. Nonetheless every inherited minimum-loss
    tier 1..36 is counted over C(E,54), never assumed zero.

    All nontrivial cardinality-54 predicates use the existing exact
    survivor-hitting CNF polynomial/Shannon engine, not C(E,54) enumerations.
    For E<=63 its entire positive 63-bit mask is safe; E64..66 branch only
    on real high original indices 63..65 (at most eight assignments), then
    solve low-63-bit residual clauses and binomial survivor budgets. Empty
    cuts, singleton cuts, an empty predicate, unattainable budgets, and
    E54 all-deleted boundary are independently and exactly covered.
#>

function ConvertTo-CodeSequenceFiftyFourExactCount {
    param([System.Numerics.BigInteger] $Value)
    if ($Value -lt [System.Numerics.BigInteger]::Zero) {
        throw 'Code Sequence fifty-four-link reported negative exact incidence.'
    }
    if ($Value -le [System.Numerics.BigInteger]([long]::MaxValue)) { return [long]$Value }
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function New-CodeSequenceFiftyFourLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence fifty-four-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    # The complete 0..66 binomial triangle is within signed Int64;
    # the second dimension includes C(E,54), C(E,53), and all CNF coefficients.
    [long[,]]$choose = [long[,]]::new($LinkCount + 1, 55)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 54 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFiftyFourLinkRank {
    param([int] $LinkCount, [long[,]] $Choose, [int[]] $Indices)
    if ($LinkCount -lt 54 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 55 -or
        $null -eq $Indices -or $Indices.Length -ne 54) {
        throw 'Code Sequence fifty-four-link rank requires 54 genuine ORIGINAL FULL links in E54..66.'
    }
    [int]$previous = -1
    [long]$rank = 0
    for ($position = 0; $position -lt 54; $position++) {
        [int]$index = $Indices[$position]
        if ($index -le $previous -or $index -ge $LinkCount) {
            throw 'Code Sequence fifty-four-link rank requires 54 DISTINCT ASCENDING genuine original link indices.'
        }
        for ($candidate = $previous + 1; $candidate -lt $index; $candidate++) {
            $rank += $Choose[$LinkCount - $candidate - 1, 53 - $position]
        }
        $previous = $index
    }
    if ($rank -lt 0 -or $rank -ge $Choose[$LinkCount, 54]) {
        throw 'Code Sequence fifty-four-link rank escaped the exact original combination universe.'
    }
    return $rank
}

function Get-CodeSequenceOriginalFiftyFourLinkIndicesFromRank {
    param([long] $Rank, [int] $LinkCount, [long[,]] $Choose)
    if ($LinkCount -lt 54 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 55 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 54]) {
        throw 'Code Sequence fifty-four-link interaction received invalid canonical deletion rank.'
    }
    [long]$remaining = $Rank
    [int[]]$indices = [int[]]::new(54)
    [int]$previous = -1
    for ($position = 0; $position -lt 53; $position++) {
        [int]$suffix = 53 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            [long]$block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence fifty-four-link inverse rank exhausted valid lexicographic combinations.'
        }
        $indices[$position] = $candidate
        $previous = $candidate
    }
    $indices[53] = [int]($previous + $remaining + 1)
    if ($indices[53] -le $indices[52] -or $indices[53] -ge $LinkCount) {
        throw 'Code Sequence fifty-four-link inverse rank yielded absent or repeated ORIGINAL direct links.'
    }
    return ,$indices
}

function Test-CodeSequenceFiftyFourLinkCutContainsSortedSubset {
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

function ConvertTo-CodeSequenceFiftyFourLinkCanonicalCutFamily {
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
            if ($cut.Length -gt 54) {
                throw 'Code Sequence fifty-four-link cut family cannot require more than 54 removed links.'
            }
            $previous = -1
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($edge in $cut) {
                if ($edge -lt 0 -or $edge -le $previous -or $edge -gt 65) {
                    throw 'Code Sequence fifty-four-link cut family contains unordered, repeated or invalid original link indices.'
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
            if (Test-CodeSequenceFiftyFourLinkCutContainsSortedSubset -Candidate $candidate -Smaller $existing) {
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


# Count a k54 monotone deletion-cut DNF by complementing to EXACTLY E-54
# survivor edges. This calls the existing EC-143 exact positive-63-bit CNF
# engine, including forcing, clause absorption, incidence-component products,
# free-edge binomials, <=4-clause IE and Shannon memoization. No scenario
# materialization or per-removal SCC closure is permitted.
function Get-CodeSequenceFiftyFourLinkCutDnfScenarioCount {
    param(
        [object[]] $Cuts,
        [int] $LinkCount,
        [long[,]] $Choose,
        [System.Collections.Generic.Dictionary[string,long]] $Memo
    )
    if ($LinkCount -lt 54 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 55) {
        if ($LinkCount -ge 0 -and $LinkCount -lt 54) { return [long]0 }
        throw 'Code Sequence fifty-four-link counter requires a valid 0..66 genuine ORIGINAL FULL-link universe.'
    }
    # Validate the complete supplied family before any normalization, including
    # terms hidden by smaller cuts or a satisfied empty cut.
    if ($null -ne $Cuts) {
        foreach ($raw in $Cuts) {
            if ($null -eq $raw) { continue }
            foreach ($edge in ([int[]]$raw)) {
                if ($edge -lt 0 -or $edge -ge $LinkCount) {
                    throw 'Code Sequence fifty-four-link DNF references an absent genuine ORIGINAL FULL direct link.'
                }
            }
        }
    }
    $family = ConvertTo-CodeSequenceFiftyFourLinkCanonicalCutFamily -Cuts $Cuts
    [long]$universe = $Choose[$LinkCount, 54]
    if ([bool]$family.satisfied) { return $universe }
    if ($family.cuts.Length -eq 0) { return [long]0 }
    if ($family.cuts.Length -eq 1) {
        [int]$size = ([int[]]$family.cuts[0]).Length
        return [long]$Choose[$LinkCount - $size, 54 - $size]
    }
    if ($LinkCount -eq 54) { return [long]1 }
    if ($null -eq $Memo) {
        $Memo = [System.Collections.Generic.Dictionary[string,long]]::new([System.StringComparer]::Ordinal)
    }
    [int]$survivors = $LinkCount - 54
    [long]$lowUniverse = if ($LinkCount -ge 63) {
        [long]::MaxValue
    } else {
        ([long]1 -shl $LinkCount) - 1
    }
    $lowMasks = [System.Collections.Generic.List[long]]::new()
    $highMasks = [System.Collections.Generic.List[int]]::new()
    foreach ($raw in $family.cuts) {
        [long]$low = 0
        [int]$high = 0
        foreach ($edge in ([int[]]$raw)) {
            if ($edge -lt 63) { $low = $low -bor ([long]1 -shl $edge) }
            else { $high = $high -bor (1 -shl ($edge - 63)) }
        }
        $lowMasks.Add($low)
        $highMasks.Add($high)
    }
    [long]$keptAvoiding = 0
    [int]$highCount = [Math]::Max(0, $LinkCount - 63)
    # Exactly one high-edge assignment corresponds to each survivor set.
    # The 0-high-edge case is a single branch over E<=63, not a special
    # approximation; E64..66 visit no more than 2^3=8 assignments.
    for ($keptHigh = 0; $keptHigh -lt (1 -shl $highCount); $keptHigh++) {
        [int]$needLow = $survivors - [System.Numerics.BitOperations]::PopCount([uint32]$keptHigh)
        if ($needLow -lt 0 -or $needLow -gt [Math]::Min($LinkCount,63)) { continue }
        $residual = [System.Collections.Generic.List[long]]::new()
        $unhittable = $false
        for ($i = 0; $i -lt $lowMasks.Count; $i++) {
            if (($highMasks[$i] -band $keptHigh) -ne 0) { continue }
            [long]$clause = $lowMasks[$i]
            if ($clause -eq 0) { $unhittable = $true; break }
            $residual.Add($clause)
        }
        if ($unhittable) { continue }
        [long]$ways = Get-CodeSequenceFortyNineLinkKeptCutHittingState `
            -UnhitMasks $residual.ToArray() -AvailableMask $lowUniverse `
            -RemainingKept $needLow -Choose $Choose -Memo $Memo
        $keptAvoiding += $ways
        if ($keptAvoiding -lt 0 -or $keptAvoiding -gt $universe) {
            throw 'Code Sequence fifty-four-link high-frontier CNF overflowed genuine C(E,54).'
        }
    }
    [long]$removedCutLoss = $universe - $keptAvoiding
    if ($removedCutLoss -lt 0 -or $removedCutLoss -gt $universe) {
        throw 'Code Sequence fifty-four-link cut complement violated genuine cardinality bounds.'
    }
    return $removedCutLoss
}

function Get-CodeSequenceEndpointDominanceFiftyFourLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $ParentFiftyThree,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $ParentFiftyThree -or
        -not [bool]$ParentFiftyThree.every_scenario_deletes_fifty_three_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$ParentFiftyThree.original_scc_directed_cut_saturation_bound_36_for_at_most_12_components -or
        -not [bool]$ParentFiftyThree.all_strictly_fifty_third_only_positive_rows_proven_impossible -or
        -not [bool]$ParentFiftyThree.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$ParentFiftyThree.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence fifty-four-link projection requires the checked EC-147 k53 original FULL SCC parent.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$ParentFiftyThree.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$ParentFiftyThree.exact_original_direct_component_link_count -ne $linkCount -or
        [int]$ParentFiftyThree.original_positions_in_impact_universe -ne $N) {
        throw 'Code Sequence fifty-four-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence fifty-four-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence fifty-four-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence fifty-four-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence fifty-four-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    # The original FULL SCC condensation must be antisymmetric: any mutual
    # reachability would collapse distinct vertices into one original SCC.
    # Check this precondition explicitly before relying on the 36-edge bound.
    for ($s = 0; $s -lt $componentCount; $s++) {
        for ($t = $s + 1; $t -lt $componentCount; $t++) {
            if (($baseline[$s] -band (1 -shl $t)) -ne 0 -and
                ($baseline[$t] -band (1 -shl $s)) -ne 0) {
                throw 'Code Sequence fifty-four-link cannot certify saturation for cyclic distinct original SCCs.'
            }
        }
    }
    [long[,]]$choose = New-CodeSequenceFiftyFourLinkBinomialTable -LinkCount $linkCount
    [long]$scenarioCount = $choose[$linkCount, 54]

    # Enumerate at most 4094 original SCC vertex sides. Only complete outgoing
    # boundaries with <=54 real FULL links can affect a fifty-four-link deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 54) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 54) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # Per reachable SCC pair, retain only subset-minimal cuts. For threshold
    # q=1..54, the exact number of 54-edge deletion scenarios with SOME cut
    # of size <=q is the exact cardinality of a monotone cut DNF. Count that
    # cardinality by memoized edge decisions and binomially collapsed free
    # gaps; successive cumulative differences are the disjoint minimum-cut
    # tiers. This avoids C(E,54) graph closures and any C(E,54)-bit mask.
    [System.Numerics.BigInteger[]]$tierSum = [System.Numerics.BigInteger[]]::new(55)
    [System.Numerics.BigInteger[]]$tierReporterSum = [System.Numerics.BigInteger[]]::new(55)
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
            for ($order = 1; $order -le 54; $order++) {
                $newMinimalCut = $false
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceFiftyFourLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    $thresholdCuts.Add($boundary)
                    $newMinimalCut = $true
                    if ($order -eq 54) {
                        [void]$positiveRanks.Add((Get-CodeSequenceOriginalDirectFiftyFourLinkRank `
                            -LinkCount $linkCount -Choose $choose -Indices $boundary))
                    }
                }
                # No newly minimal boundary => same monotone DNF and same
                # exact-cardinality count; do not re-solve an identical DNF.
                [long]$cumulative = $previousCumulative
                # Once EVERY k54 deletion loses the same original relation,
                # further cuts cannot increase the cumulative DNF count.
                # Retain the exact minimal-cut registry but avoid repeated
                # exponential CNF work for logically saturated thresholds.
                if ($newMinimalCut -and $previousCumulative -lt $scenarioCount) {
                    $cumulative = Get-CodeSequenceFiftyFourLinkCutDnfScenarioCount `
                        -Cuts $thresholdCuts.ToArray() -LinkCount $linkCount -Choose $choose -Memo $thresholdMemo
                }
                [long]$added = $cumulative - $previousCumulative
                if ($added -lt 0 -or $cumulative -gt $scenarioCount) {
                    throw 'Code Sequence fifty-four-link cut DNF violated cumulative minimum-cut tier monotonicity.'
                }
                $tierSum[$order] += [System.Numerics.BigInteger]$added
                $tierReporterSum[$order] += ([System.Numerics.BigInteger]$added * $weights[$s] * $weights[$t])
                $previousCumulative = $cumulative
            }
            if ($ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence fifty-four-link minimal cut registry exceeded its source candidate family.'
            }
        }
    }
    # Tight finite-size bound: a complete outgoing source-side cut in an
    # original simple SCC condensation DAG has at most floor(m*m/4) edges.
    # With m<=12 this is <=36, so strictly-37..54-only losses are
    # all impossible, even when E>=54; earlier tiers remain nonzero.
    $maximumOutgoingCut = [int][math]::Floor(($componentCount * $componentCount) / 4)
    if ($maximumOutgoingCut -gt 36 -or $positiveRanks.Count -ne 0) {
        throw 'Code Sequence fifty-four-link source violates the 12-SCC / 36-edge complete-cut bound.'
    }
    for ($strictOrder = 37; $strictOrder -le 54; $strictOrder++) {
        if ($tierSum[$strictOrder] -ne [System.Numerics.BigInteger]::Zero -or
            $tierReporterSum[$strictOrder] -ne [System.Numerics.BigInteger]::Zero) {
            throw 'Code Sequence fifty-four-link model invented an impossible strict order above 36.'
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence fifty-four-link strictly fifty-fourth-only cases exceed the bounded directed-cut universe.'
    }

    # No sparse output expansion at k=54: for at most twelve ORIGINAL SCCs,
    # every complete outgoing SCC vertex boundary has at most 36 FULL edges.
    # Exact cardinality-54 still counts earlier loss orders 1..36;
    # skipping nonexistent strict-37..54 rows avoids fabricated evidence.
    $rows = [System.Collections.Generic.List[object]]::new()

    [System.Numerics.BigInteger]$allLosses = [System.Numerics.BigInteger]::Zero
    [System.Numerics.BigInteger]$allReporterMass = [System.Numerics.BigInteger]::Zero
    for ($order = 1; $order -le 54; $order++) {
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
        throw 'Code Sequence fifty-four-link original SCC/reporter incidence or bounded positive cut invariant failed.'
    }
    # Explicit cardinality-54 public projection. Both per-tier count series are
    # emitted by the same ordinal registry: an earlier tier can never be
    # accidentally overwritten or silently skipped when k grows.
    $result = [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        maximum_possible_complete_outgoing_original_scc_cut_size = $maximumOutgoingCut
        original_scc_directed_cut_saturation_bound_36_for_at_most_12_components = $true
        all_strictly_fifty_fourth_only_positive_rows_proven_impossible = $true
        exact_original_direct_component_link_count = $linkCount
        exact_fifty_four_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_fifty_fourth_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_fifty_fourth_only_new_component_reachability_loss = $scenarioCount - $rows.Count
    }
    [string[]]$ordinals = @(
        'first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth',
        'ninth', 'tenth', 'eleventh', 'twelfth', 'thirteenth', 'fourteenth', 'fifteenth', 'sixteenth',
        'seventeenth', 'eighteenth', 'nineteenth', 'twentieth', 'twenty_first', 'twenty_second', 'twenty_third', 'twenty_fourth',
        'twenty_fifth', 'twenty_sixth', 'twenty_seventh', 'twenty_eighth', 'twenty_ninth', 'thirtieth', 'thirty_first', 'thirty_second',
        'thirty_third', 'thirty_fourth', 'thirty_fifth', 'thirty_sixth', 'thirty_seventh', 'thirty_eighth', 'thirty_ninth', 'fortieth',
        'forty_first', 'forty_second', 'forty_third', 'forty_fourth', 'forty_fifth', 'forty_sixth', 'forty_seventh', 'forty_eighth',
        'forty_ninth', 'fiftieth', 'fifty_first', 'fifty_second', 'fifty_third', 'fifty_fourth'
    )
    if ($ordinals.Length -ne 54) {
        throw 'Code Sequence fifty-four-link tier ordinal registry is incomplete.'
    }
    for ($order = 1; $order -le 54; $order++) {
        $stem = switch ($order) {
            1 { 'unique_single_loss' }
            2 { 'pair_only_new' }
            3 { 'triple_only_new' }
            4 { 'quadruple_only_new' }
            default { 'strictly_' + $ordinals[$order - 1] + '_only_new' }
        }
        $prefix = 'sum_of_' + $stem
        $result[$prefix + '_component_pair_incidences_across_fifty_four_link_scenarios'] = (ConvertTo-CodeSequenceFiftyFourExactCount -Value $tierSum[$order])
        $result[$prefix + '_original_reporter_pair_incidences_across_fifty_four_link_scenarios'] = (ConvertTo-CodeSequenceFiftyFourExactCount -Value $tierReporterSum[$order])
    }
    $result['sum_of_combined_full_graph_component_pair_loss_incidences_across_fifty_four_link_scenarios'] = (ConvertTo-CodeSequenceFiftyFourExactCount -Value $allLosses)
    $result['sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_fifty_four_link_scenarios'] = (ConvertTo-CodeSequenceFiftyFourExactCount -Value $allReporterMass)
    $result['original_direct_link_quattuorquinquagintuples_with_strictly_fifty_fourth_only_new_reachability_loss'] = $rows.ToArray()
    $result['exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_fifty_four'] = $cuts.Count
    $result['all_fifty_four_link_scenarios_counted_via_exact_scc_cut_cnf_not_per_scenario_graph_closure'] = $true
    $result['no_c_e_54_bitset_or_dense_scenario_objects_allocated'] = $true
    $result['monotone_cut_dnf_counts_exact_cardinality_fifty_four_deletions'] = $true
    $result['fifty_fourth_only_positive_scenarios_are_exact_fifty_four_edge_outgoing_directed_cuts'] = $true
    $result['sparse_rows_omit_zero_fifty_fourth_order_cases_but_not_their_exact_aggregates'] = $true
    $result['every_scenario_deletes_fifty_four_distinct_whole_original_direct_scc_links_from_full_dag'] = $true
    $result['minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_' +
        (($ordinals[4..52] -join '_') + '_and_strictly_fifty_fourth_only_loss')] = $true
    $result['source_scc_members_and_internal_cycles_held_fixed'] = $true
    $result['original_redundant_shortcuts_remain_unless_one_of_fifty_four_removed_links'] = $true
    $result['positive_first_equality_and_zero_first_ties_never_become_strict_links'] = $true
    $result['no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority'] = $true
    $result['no_new_evidence_read_permutation_mask_git_network_or_business_write'] = $true
    return $result
}

# The public entry point accepts exactly the already selected read-only Sequence
# path. No new record, Git, disk, network, seed, Top or family selection occurs.
function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuorquinquagintupleInteraction {
    param([System.Collections.IDictionary] $PathFocus)
    if ($null -eq $PathFocus) {
        throw 'Code Sequence EC-148 needs the existing selected ORIGINAL Finding-pair path.'
    }
    $piv = $PathFocus['selected_original_finding_pair_profile_retention_pivotality']
    $suppliedParent = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_trequinquagintuple_interaction']
    $topologies = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_topology']
    $reductions = $PathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_reduction']
    if ($null -eq $piv -or $null -eq $suppliedParent -or
        $null -eq $topologies -or $null -eq $reductions) {
        throw 'Code Sequence EC-148 did not receive checked original SCC topology, reduction and EC-147 parent.'
    }

    # IMPORTANT: NEVER trust an EC-147 summary/flag/header or previous cache.
    # Replay its entire actual 53-link calculation through EC-093..146
    # original parents, and compare COMPLETE public JSON including each
    # genuine/frozen threshold, every real family, all 53 inherited tiers,
    # EC-089/095 FIRST lineage, empty strict53 witnesses and bounds.
    # This comparison happens before creating ANY EC-148 projection.
    $freshParent = Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTrequinquagintupleInteraction -PathFocus $PathFocus
    if ((ConvertTo-Json -InputObject $freshParent -Depth 100 -Compress) -cne
        (ConvertTo-Json -InputObject $suppliedParent -Depth 100 -Compress)) {
        throw 'Code Sequence EC-148 rejected modified whole-public-JSON EC-147 parent (original FIRST/SCC/tiers/family).'
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
        throw 'Code Sequence EC-148 changed the checked original Finding-pair identity or reporter universe.'
    }

    [object[]]$gTop = [object[]]$topologies.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$fTop = [object[]]$topologies.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$gRed = [object[]]$reductions.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$fRed = [object[]]$reductions.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$gParent = [object[]]$suppliedParent.genuine_global_threshold_endpoint_trequinquagintuple_interaction
    [object[]]$fParent = [object[]]$suppliedParent.frozen_global_threshold_endpoint_trequinquagintuple_interaction
    [object[]]$famTop = [object[]]$topologies.individual_original_family_endpoint_dominance_topology
    [object[]]$famRed = [object[]]$reductions.individual_original_family_endpoint_dominance_reduction
    [object[]]$famParent = [object[]]$suppliedParent.individual_original_family_endpoint_trequinquagintuple_interaction
    if ($gTop.Length -ne 3 -or $fTop.Length -ne 3 -or
        $gRed.Length -ne 3 -or $fRed.Length -ne 3 -or
        $gParent.Length -ne 3 -or $fParent.Length -ne 3 -or
        $famTop.Length -ne $familyCount -or $famRed.Length -ne $familyCount -or
        $famParent.Length -ne $familyCount) {
        throw 'Code Sequence EC-148 changed genuine/frozen global thresholds or actual original repeat-family target counts.'
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
                throw 'Code Sequence EC-148 drifted from actual original threshold identity/capacity.'
            }
            $graph = Get-CodeSequenceEndpointDominanceFiftyFourLinkInteractionProjection `
                -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                -ParentFiftyThree $parent.exact_strictly_fifty_third_only_original_scc_link_removal_interaction -N $n
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_fifty_fourth_only_original_scc_link_removal_interaction = $graph
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
            throw 'Code Sequence EC-148 drifted from one actual original repeat family index.'
        }
        $graphG = Get-CodeSequenceEndpointDominanceFiftyFourLinkInteractionProjection `
            -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
            -ParentFiftyThree $parent.genuine_exact_strictly_fifty_third_only_original_scc_link_removal_interaction -N $n
        $graphF = Get-CodeSequenceEndpointDominanceFiftyFourLinkInteractionProjection `
            -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
            -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
            -ParentFiftyThree $parent.frozen_exact_strictly_fifty_third_only_original_scc_link_removal_interaction -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_fifty_fourth_only_original_scc_link_removal_interaction = $graphG
            frozen_exact_strictly_fifty_fourth_only_original_scc_link_removal_interaction = $graphF
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_fifty_fourth_order_fifty_four_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_quattuorquinquagintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_quattuorquinquagintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_quattuorquinquagintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec147_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

#requires -Version 7.0
<#
    EC-100: exact SIXTH-only reachability loss from removing SIX distinct
    complete ORIGINAL direct SCC links from the FULL condensed DAG.

    For each originally reachable ordered component pair (s,t), a six-link
    deletion disconnects it iff an original proper s-containing/t-excluding
    vertex-side outgoing boundary is fully removed. Enumerate at most
    2^C - 2 <= 4094 original vertex sets, keep boundaries of size <=6,
    deduplicate and discard strictly redundant supersets PER SCC pair.
    Process remaining cuts in increasing cardinality. A transient packed
    BitArray of C(E,6) <= 90,858,768 bits (10.9 MiB at E=66) assigns each
    loss to its smallest sufficient original cut order (1..6), including
    zero-sixth-only scenarios. Only genuine sixth-only cases expand; each
    one is a complete original SIX-edge boundary, so <=4094 sparse rows.
    No re-SCC, graph re-optimization, source read, state write, or empirical
    defect/reliability/probability/priority inference is authorized.
#>

function New-CodeSequenceSixLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence six-link interaction requires 0..66 genuine original FULL SCC links.'
    }
    [int[,]]$choose = [int[,]]::new($LinkCount + 1, 7)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 6 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectSixLinkRank {
    param(
        [int] $LinkCount, [int[,]] $Choose,
        [int] $A, [int] $B, [int] $C, [int] $D, [int] $E, [int] $F
    )
    # Sparse-only helper: accept arbitrary caller order, reject any duplicate
    # or fabricated edge, and convert to zero-based lexicographic rank.
    [int[]]$six = @($A, $B, $C, $D, $E, $F)
    [Array]::Sort($six)
    $a=$six[0]; $b=$six[1]; $c=$six[2]
    $d=$six[3]; $e=$six[4]; $f=$six[5]
    if ($LinkCount -lt 6 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 7 -or
        $a -lt 0 -or $a -ge $b -or $b -ge $c -or $c -ge $d -or
        $d -ge $e -or $e -ge $f -or $f -ge $LinkCount) {
        throw 'Code Sequence six-link scenario requires SIX DISTINCT genuine original direct-SCC link indices.'
    }
    return [int](
        $Choose[$LinkCount, 6] - $Choose[$LinkCount - $a, 6] +
        $Choose[$LinkCount - $a - 1, 5] - $Choose[$LinkCount - $b, 5] +
        $Choose[$LinkCount - $b - 1, 4] - $Choose[$LinkCount - $c, 4] +
        $Choose[$LinkCount - $c - 1, 3] - $Choose[$LinkCount - $d, 3] +
        $Choose[$LinkCount - $d - 1, 2] - $Choose[$LinkCount - $e, 2] +
        $f - $e - 1)
}

function Get-CodeSequenceOriginalSixLinkIndicesFromRank {
    param([int] $Rank, [int] $LinkCount, [int[,]] $Choose)
    if ($LinkCount -lt 6 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 7 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 6]) {
        throw 'Code Sequence six-link interaction received invalid canonical deletion rank.'
    }
    $remaining = $Rank
    [int[]]$six = [int[]]::new(6)
    $previous = -1
    for ($position = 0; $position -lt 5; $position++) {
        $suffix = 5 - $position
        for ($candidate = $previous + 1; $candidate -le $LinkCount - ($suffix + 1); $candidate++) {
            $block = $Choose[$LinkCount - $candidate - 1, $suffix]
            if ($remaining -lt $block) { break }
            $remaining -= $block
        }
        if ($candidate -gt $LinkCount - ($suffix + 1)) {
            throw 'Code Sequence six-link inversion exhausted valid lexicographic combinations.'
        }
        $six[$position] = $candidate
        $previous = $candidate
    }
    $six[5] = $previous + $remaining + 1
    if ($six[5] -le $six[4] -or $six[5] -ge $LinkCount) {
        throw 'Code Sequence six-link inversion generated repeated or absent original direct links.'
    }
    return ,$six
}

function Test-CodeSequenceSixLinkCutContainsSortedSubset {
    param([int[]] $Candidate, [int[]] $Smaller)
    # Both are strictly increasing genuine full-edge indices. The caller
    # only passes already accepted shorter/equal outgoing boundaries.
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

function Add-CodeSequenceSixLinkCutSupersets {
    param(
        [int[]] $CutIndices, [int] $LinkCount, [int[,]] $Choose,
        [System.Collections.BitArray] $AlreadyClassified,
        [System.Collections.Generic.HashSet[int]] $PositiveSixthOnlyRanks
    )
    $order = if ($null -eq $CutIndices) { 0 } else { $CutIndices.Length }
    if ($order -lt 1 -or $order -gt 6 -or $LinkCount -lt 6 -or
        $null -eq $Choose -or $null -eq $AlreadyClassified -or
        $AlreadyClassified.Length -ne $Choose[$LinkCount, 6] -or
        $null -eq $PositiveSixthOnlyRanks) {
        throw 'Code Sequence six-link completion requires one to six genuine original outgoing-cut links.'
    }
    $missing = 6 - $order
    [int[]]$available = [int[]]::new($LinkCount - $order)
    $next = 0; $cutCursor = 0
    for ($i = 0; $i -lt $LinkCount; $i++) {
        if ($cutCursor -lt $order -and $CutIndices[$cutCursor] -eq $i) {
            $cutCursor++
        } else {
            $available[$next] = $i
            $next++
        }
    }
    if ($cutCursor -ne $order -or $next -ne $available.Length) {
        throw 'Code Sequence six-link outgoing cut contained absent, unordered or repeated original link.'
    }
    [int[]]$positions = [int[]]::new($missing)
    for ($i = 0; $i -lt $missing; $i++) { $positions[$i] = $i }
    [int[]]$six = [int[]]::new(6)
    [long]$added = 0
    $scenarioCount = [int]$Choose[$LinkCount, 6]
    while ($true) {
        # Merge two already increasing sequences, avoiding an expensive
        # sort per completion (up to C(65,5) for a singleton cut).
        $cutCursor = 0; $complementCursor = 0
        for ($slot = 0; $slot -lt 6; $slot++) {
            if ($cutCursor -eq $order) {
                $six[$slot] = $available[$positions[$complementCursor]]
                $complementCursor++
            } elseif ($complementCursor -eq $missing -or
                $CutIndices[$cutCursor] -lt $available[$positions[$complementCursor]]) {
                $six[$slot] = $CutIndices[$cutCursor]
                $cutCursor++
            } else {
                $six[$slot] = $available[$positions[$complementCursor]]
                $complementCursor++
            }
        }
        $a=$six[0];$b=$six[1];$c=$six[2]
        $d=$six[3];$e=$six[4];$f=$six[5]
        $rank = [int](
            $Choose[$LinkCount, 6] - $Choose[$LinkCount - $a, 6] +
            $Choose[$LinkCount - $a - 1, 5] - $Choose[$LinkCount - $b, 5] +
            $Choose[$LinkCount - $b - 1, 4] - $Choose[$LinkCount - $c, 4] +
            $Choose[$LinkCount - $c - 1, 3] - $Choose[$LinkCount - $d, 3] +
            $Choose[$LinkCount - $d - 1, 2] - $Choose[$LinkCount - $e, 2] +
            $f - $e - 1)
        if ($rank -lt 0 -or $rank -ge $scenarioCount) {
            throw 'Code Sequence six-link cut completion generated an invalid canonical rank.'
        }
        if (-not $AlreadyClassified[$rank]) {
            $AlreadyClassified[$rank] = $true
            $added++
            if ($order -eq 6) { [void]$PositiveSixthOnlyRanks.Add($rank) }
        }
        if ($missing -eq 0) { break }
        $slot = $missing - 1
        while ($slot -ge 0 -and $positions[$slot] -eq ($available.Length - $missing + $slot)) {
            $slot--
        }
        if ($slot -lt 0) { break }
        $positions[$slot]++
        for ($j = $slot + 1; $j -lt $missing; $j++) { $positions[$j] = $positions[$j - 1] + 1 }
    }
    return $added
}

function Get-CodeSequenceSixLinkSmallestContainedCutOrder {
    param(
        [int[]] $SixIndices,
        [System.Collections.Generic.List[int[]]] $CutsByAscendingCardinality
    )
    if ($null -eq $SixIndices -or $SixIndices.Length -ne 6 -or
        $null -eq $CutsByAscendingCardinality) {
        throw 'Code Sequence six-link sparse lookup requires six canonical original links and complete minimal cuts.'
    }
    foreach ($cut in $CutsByAscendingCardinality) {
        if (Test-CodeSequenceSixLinkCutContainsSortedSubset -Candidate $SixIndices -Smaller $cut) {
            return [int]$cut.Length
        }
    }
    return 0
}

function Get-CodeSequenceEndpointDominanceSixLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [object] $TripleInteraction,
        [object] $QuadrupleInteraction,
        [object] $QuintupleInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or $null -eq $TripleInteraction -or
        $null -eq $QuadrupleInteraction -or $null -eq $QuintupleInteraction -or
        -not [bool]$QuintupleInteraction.every_scenario_deletes_five_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$QuintupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_and_strictly_fifth_only_loss -or
        -not [bool]$QuintupleInteraction.original_redundant_shortcuts_remain_unless_one_of_five_removed_links -or
        -not [bool]$QuintupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$QuintupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence six-link interaction requires checked EC-093 through EC-099 ORIGINAL projections.'
    }
    # Regenerate every EC-099 field, including all five-tier aggregate counts
    # and sparse fifth-only original links, transitive back to EC-089 FIRST.
    $fresh = Get-CodeSequenceEndpointDominanceFiveLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -PairInteraction $PairInteraction `
        -TripleInteraction $TripleInteraction -QuadrupleInteraction $QuadrupleInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 60 -Compress) -cne
        (ConvertTo-Json -InputObject $QuintupleInteraction -Depth 60 -Compress)) {
        throw 'Code Sequence six-link interaction rejected changed EC-099 fifth-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$QuintupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$QuintupleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence six-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence six-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence six-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence six-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence six-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    [int[,]]$choose = New-CodeSequenceSixLinkBinomialTable -LinkCount $linkCount
    $scenarioCount = [int]$choose[$linkCount, 6]

    # Enumerate bounded source-side vertex sets once for this target, never
    # original model-witness permutations or changed SCC memberships.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $all = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $all; $subset++) {
            $boundary = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $fromByLink[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $toByLink[$linkIndex])) -eq 0) {
                    $boundary.Add($linkIndex)
                    if ($boundary.Count -gt 6) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 6) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # One transient BitArray per reachable SCC pair (~10.9 MiB worst-case),
    # not N^2 enormous arrays or 90.9M graph closures. For each (s,t),
    # drop superfluous cuts containing an already-known smaller cut.
    # Per-pair cut families are retained only for bounded sparse drilldown.
    [object[]]$cutsPerOrderedPair = [object[]]::new($componentCount * $componentCount)
    [long[]]$tierSum = [long[]]::new(7)
    [long[]]$tierReporterSum = [long[]]::new(7)
    $positiveRanks = [System.Collections.Generic.HashSet[int]]::new()
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
            # Always store in ASCENDING cut order so sparse replay can
            # short-circuit on the first contained boundary.
            $ascending = [System.Collections.Generic.List[int[]]]::new()
            [System.Collections.BitArray]$covered = [System.Collections.BitArray]::new($scenarioCount)
            [long]$coveredCount = 0
            for ($order = 1; $order -le 6; $order++) {
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $redundant = $false
                    foreach ($smaller in $ascending) {
                        if (Test-CodeSequenceSixLinkCutContainsSortedSubset `
                            -Candidate $boundary -Smaller $smaller) {
                            $redundant = $true
                            break
                        }
                    }
                    if ($redundant) { continue }
                    $ascending.Add($boundary)
                    [long]$added = Add-CodeSequenceSixLinkCutSupersets `
                        -CutIndices $boundary -LinkCount $linkCount -Choose $choose `
                        -AlreadyClassified $covered -PositiveSixthOnlyRanks $positiveRanks
                    $tierSum[$order] += $added
                    $tierReporterSum[$order] += $added * [long]$weights[$s] * $weights[$t]
                    $coveredCount += $added
                }
            }
            if ($coveredCount -gt $scenarioCount -or $ascending.Count -gt $perPair.Count) {
                throw 'Code Sequence six-link cut classes exceeded the complete six-link scenario universe.'
            }
            $cutsPerOrderedPair[$s * $componentCount + $t] = $ascending
            # Drop the temporary mask before moving to the next ordered SCC pair.
            $covered = $null
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence six-link strictly sixth-only cases exceed the bounded directed-cut universe.'
    }

    # Strictly sixth-only requires an original complete SIX-edge outgoing
    # cut. At most 4094 distinct vertex-side cuts yield sparse rows.
    [int[]]$sortedPositive = [int[]]::new($positiveRanks.Count)
    $positiveRanks.CopyTo($sortedPositive)
    [Array]::Sort($sortedPositive)
    $rows = [System.Collections.Generic.List[object]]::new()
    [long]$sparseSixthTotal = 0
    [long]$sparseSixthMass = 0
    foreach ($rank in $sortedPositive) {
        [int[]]$six = Get-CodeSequenceOriginalSixLinkIndicesFromRank `
            -Rank $rank -LinkCount $linkCount -Choose $choose
        if ((Get-CodeSequenceOriginalDirectSixLinkRank -LinkCount $linkCount -Choose $choose `
            -A $six[0] -B $six[1] -C $six[2] -D $six[3] -E $six[4] -F $six[5]) -ne $rank) {
            throw 'Code Sequence six-link sparse scenario lost canonical original edge rank.'
        }
        [long[]]$counts = [long[]]::new(7)
        [long[]]$mass = [long[]]::new(7)
        $novelRows = [System.Collections.Generic.List[object]]::new()
        for ($s = 0; $s -lt $componentCount; $s++) {
            for ($t = 0; $t -lt $componentCount; $t++) {
                [System.Collections.Generic.List[int[]]]$pairCuts = $cutsPerOrderedPair[$s * $componentCount + $t]
                if ($null -eq $pairCuts) { continue }
                $order = Get-CodeSequenceSixLinkSmallestContainedCutOrder `
                    -SixIndices $six -CutsByAscendingCardinality $pairCuts
                if ($order -eq 0) { continue }
                if ($order -lt 1 -or $order -gt 6 -or $s -eq $t -or
                    ($baseline[$s] -band (1 -shl $t)) -eq 0) {
                    throw 'Code Sequence six-link sparse row included a non-original or reflexive SCC loss.'
                }
                $pairMass = [long]$weights[$s] * $weights[$t]
                $counts[$order]++
                $mass[$order] += $pairMass
                if ($order -eq 6) {
                    $novelRows.Add([ordered]@{
                        from_strict_component_index = $s + 1
                        to_strict_component_index = $t + 1
                        exact_ordered_original_reporter_pair_multiplicity = $pairMass
                    })
                }
            }
        }
        if ($counts[6] -lt 1 -or $novelRows.Count -ne $counts[6] -or
            $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5] + $counts[6] -gt
                $componentCount * ($componentCount - 1)) {
            throw 'Code Sequence six-link positive scenario did not conserve disjoint loss orders.'
        }
        $sparseSixthTotal += $counts[6]
        $sparseSixthMass += $mass[6]
        $linkRows = [System.Collections.Generic.List[object]]::new()
        foreach ($linkIndex in $six) {
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
            first_original_direct_link_index_in_ec095 = $six[0] + 1
            second_original_direct_link_index_in_ec095 = $six[1] + 1
            third_original_direct_link_index_in_ec095 = $six[2] + 1
            fourth_original_direct_link_index_in_ec095 = $six[3] + 1
            fifth_original_direct_link_index_in_ec095 = $six[4] + 1
            sixth_original_direct_link_index_in_ec095 = $six[5] + 1
            six_whole_original_direct_links_in_canonical_order = $linkRows.ToArray()
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
            exact_joint_six_link_full_component_pair_losses = $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5] + $counts[6]
            exact_joint_six_link_full_original_reporter_pair_losses = $mass[1] + $mass[2] + $mass[3] + $mass[4] + $mass[5] + $mass[6]
            new_loss_only_if_all_six_original_links_are_removed = [ordered]@{
                exact_new_component_pair_count = $counts[6]
                exact_new_original_reporter_pair_count = $mass[6]
                newly_lost_component_pairs_in_canonical_order = $novelRows.ToArray()
            }
        })
    }
    if ($rows.Count -ne $positiveRanks.Count -or $rows.Count -gt $scenarioCount -or
        $sparseSixthTotal -ne $tierSum[6] -or $sparseSixthMass -ne $tierReporterSum[6]) {
        throw 'Code Sequence six-link sparse sixth-only rows disagree with complete directed-cut scenario incidences.'
    }
    [long]$allLosses = 0
    [long]$allReporterMass = 0
    for ($order = 1; $order -le 6; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_component_link_count = $linkCount
        exact_six_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_sixth_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_sixth_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_six_link_scenarios = $tierSum[1]
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[1]
        sum_of_pair_only_new_component_pair_incidences_across_six_link_scenarios = $tierSum[2]
        sum_of_pair_only_new_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[2]
        sum_of_triple_only_new_component_pair_incidences_across_six_link_scenarios = $tierSum[3]
        sum_of_triple_only_new_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[3]
        sum_of_quadruple_only_new_component_pair_incidences_across_six_link_scenarios = $tierSum[4]
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[4]
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_six_link_scenarios = $tierSum[5]
        sum_of_strictly_sixth_only_new_component_pair_incidences_across_six_link_scenarios = $tierSum[6]
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[5]
        sum_of_strictly_sixth_only_new_original_reporter_pair_incidences_across_six_link_scenarios = $tierReporterSum[6]
        sum_of_combined_full_graph_component_pair_loss_incidences_across_six_link_scenarios = $allLosses
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_six_link_scenarios = $allReporterMass
        original_direct_link_sextuples_with_strictly_sixth_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_six = $cuts.Count
        all_six_link_scenarios_counted_via_exact_scc_directed_edge_cuts_not_per_scenario_graph_closure = $true
        bounded_transient_bitset_per_original_reachable_scc_pair_not_per_scenario_object = $true
        sixth_only_positive_scenarios_are_exact_six_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_sixth_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_six_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_fifth_and_strictly_sixth_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_six_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSextupleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction,
        [object] $RetentionEndpointTripleInteraction,
        [object] $RetentionEndpointQuadrupleInteraction,
        [object] $RetentionEndpointQuintupleInteraction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        $null -eq $RetentionEndpointPairInteraction -or
        $null -eq $RetentionEndpointTripleInteraction -or
        $null -eq $RetentionEndpointQuadrupleInteraction -or
        $null -eq $RetentionEndpointQuintupleInteraction -or
        [string]$RetentionEndpointQuintupleInteraction.scope -cne 'exact_strictly_fifth_order_five_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuintupleInteraction.only_consumed_checked_ec093_to_ec098_original_graph_projections -or
        -not [bool]$RetentionEndpointQuintupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuintupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuintupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence six-link interaction requires successful ORIGINAL selector and checked EC-099.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence six-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction,
        $RetentionEndpointTripleInteraction, $RetentionEndpointQuadrupleInteraction,
        $RetentionEndpointQuintupleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence six-link interaction detected changed original caller/pair/path/anchor provenance.'
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
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    [object[]]$threeFamilies = [object[]]$RetentionEndpointTripleInteraction.individual_original_family_endpoint_triple_interaction
    [object[]]$fourFamilies = [object[]]$RetentionEndpointQuadrupleInteraction.individual_original_family_endpoint_quadruple_interaction
    [object[]]$fiveFamilies = [object[]]$RetentionEndpointQuintupleInteraction.individual_original_family_endpoint_quintuple_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $threesG.Length -ne 3 -or $threesF.Length -ne 3 -or
        $foursG.Length -ne 3 -or $foursF.Length -ne 3 -or
        $fivesG.Length -ne 3 -or $fivesF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount -or
        $threeFamilies.Length -ne $familyCount -or
        $fourFamilies.Length -ne $familyCount -or
        $fiveFamilies.Length -ne $familyCount) {
        throw 'Code Sequence six-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
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
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            $two = $twos[$i]; $three = $threes[$i]; $four = $fours[$i]; $five = $fives[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or $null -eq $four -or $null -eq $five -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$one.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$two.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$three.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$four.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$five.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$three.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$four.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$five.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence six-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_sixth_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceSixLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction `
                        -TripleInteraction $three.exact_strictly_triple_only_original_scc_link_removal_interaction `
                        -QuadrupleInteraction $four.exact_strictly_fourth_only_original_scc_link_removal_interaction `
                        -QuintupleInteraction $five.exact_strictly_fifth_only_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        $two = $twoFamilies[$i]; $three = $threeFamilies[$i]; $four = $fourFamilies[$i]; $five = $fiveFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or $null -eq $four -or $null -eq $five -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$three.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$four.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$five.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence six-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_sixth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceSixLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.genuine_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.genuine_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.genuine_exact_strictly_fifth_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_sixth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceSixLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.frozen_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.frozen_exact_strictly_fourth_only_original_scc_link_removal_interaction `
                    -QuintupleInteraction $five.frozen_exact_strictly_fifth_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_sixth_order_six_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_sextuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_sextuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_sextuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec099_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

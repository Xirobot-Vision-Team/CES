#requires -Version 7.0
<#
    EC-099: exact FIFTH-order reachability loss after deleting FIVE distinct
    complete ORIGINAL direct SCC links from the FULL condensed DAG.

    For an originally reachable SCC pair (s,t), the simultaneous deletion
    F disconnects s from t exactly when a proper vertex subset U (s in U,
    t not in U) has its complete FULL outgoing edge boundary inside F.
    At most 4094 proper subsets exist (C<=12). Only actual boundaries of
    cardinality 1..5 matter. Propagate their exact five-link supersets in
    ascending boundary size into a transient BitArray; the first boundary
    reaching a scenario assigns the smallest sufficient loss order, 1..5.
    This accounts for all C(E,5)<=8,936,928 scenarios with bounded working
    memory (~1.1 MiB per SCC pair at E=66), no per-scenario graph closure,
    and no 8.9-million-row result. A fifth-only positive scenario must be
    itself a five-edge FULL boundary, so at most 4094 sparse rows exist.

    The complete EC-098 projection is regenerated and byte-semantically
    compared before any new results; that lineage rechecks EC-097..089.
    The SCC membership, all other original shortcuts and EC-071 caller
    positions remain fixed. These are hypothetical saved-comparison graph
    effects, NOT real fault rates, chronology, causality or repair priority.
#>

function New-CodeSequenceFiveLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence five-link interaction requires 0..66 genuine FULL original SCC links.'
    }
    [int[,]]$choose = [int[,]]::new($LinkCount + 1, 6)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 5 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFiveLinkRank {
    param(
        [int] $LinkCount,
        [int[,]] $Choose,
        [int] $A, [int] $B, [int] $C, [int] $D, [int] $E
    )
    # Five-input nine-comparator sorting network. Accept any caller order
    # but reject repeated, fabricated or out-of-universe SCC edge indices.
    if ($A -gt $B) { $swap=$A; $A=$B; $B=$swap }
    if ($D -gt $E) { $swap=$D; $D=$E; $E=$swap }
    if ($C -gt $E) { $swap=$C; $C=$E; $E=$swap }
    if ($C -gt $D) { $swap=$C; $C=$D; $D=$swap }
    if ($B -gt $E) { $swap=$B; $B=$E; $E=$swap }
    if ($A -gt $D) { $swap=$A; $A=$D; $D=$swap }
    if ($A -gt $C) { $swap=$A; $A=$C; $C=$swap }
    if ($B -gt $D) { $swap=$B; $B=$D; $D=$swap }
    if ($B -gt $C) { $swap=$B; $B=$C; $C=$swap }
    if ($LinkCount -lt 5 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 6 -or
        $A -lt 0 -or $A -ge $B -or $B -ge $C -or $C -ge $D -or
        $D -ge $E -or $E -ge $LinkCount) {
        throw 'Code Sequence five-link scenario requires FIVE DISTINCT genuine original direct-SCC link indices.'
    }
    # Zero-based lex rank, with C(n,k)=0 for n<k (Pascal table).
    return [int](
        $Choose[$LinkCount, 5] - $Choose[$LinkCount - $A, 5] +
        $Choose[$LinkCount - $A - 1, 4] - $Choose[$LinkCount - $B, 4] +
        $Choose[$LinkCount - $B - 1, 3] - $Choose[$LinkCount - $C, 3] +
        $Choose[$LinkCount - $C - 1, 2] - $Choose[$LinkCount - $D, 2] +
        $E - $D - 1)
}

function Get-CodeSequenceOriginalFiveLinkIndicesFromRank {
    param([int] $Rank, [int] $LinkCount, [int[,]] $Choose)
    if ($LinkCount -lt 5 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Choose.GetLength(0) -ne $LinkCount + 1 -or $Choose.GetLength(1) -ne 6 -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 5]) {
        throw 'Code Sequence five-link interaction received an invalid canonical deletion rank.'
    }
    $remainder = $Rank
    for ($a = 0; $a -le $LinkCount - 5; $a++) {
        $block = $Choose[$LinkCount - $a - 1, 4]
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    for ($b = $a + 1; $b -le $LinkCount - 4; $b++) {
        $block = $Choose[$LinkCount - $b - 1, 3]
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    for ($c = $b + 1; $c -le $LinkCount - 3; $c++) {
        $block = $Choose[$LinkCount - $c - 1, 2]
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    for ($d = $c + 1; $d -le $LinkCount - 2; $d++) {
        $block = $LinkCount - $d - 1
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    $e = $d + $remainder + 1
    if ($a -ge $b -or $b -ge $c -or $c -ge $d -or $d -ge $e -or $e -ge $LinkCount) {
        throw 'Code Sequence five-link lexicographic rank inversion generated non-distinct or imaginary SCC links.'
    }
    return ,([int[]]@($a, $b, $c, $d, $e))
}

function Add-CodeSequenceFiveLinkCutSupersets {
    param(
        [int[]] $CutIndices,
        [int] $LinkCount,
        [int[,]] $Choose,
        [System.Collections.BitArray] $AlreadyClassified,
        [System.Collections.Generic.HashSet[int]] $PositiveFifthOnlyRanks
    )
    $order = if ($null -eq $CutIndices) { 0 } else { $CutIndices.Length }
    if ($order -lt 1 -or $order -gt 5 -or $LinkCount -lt 5 -or
        $null -eq $Choose -or $null -eq $AlreadyClassified -or
        $AlreadyClassified.Length -ne $Choose[$LinkCount, 5] -or
        $null -eq $PositiveFifthOnlyRanks) {
        throw 'Code Sequence five-link completion requires one to five genuine FULL original outgoing-cut links.'
    }
    # Every COMPLETION is five distinct links. No repeated links can be
    # introduced by choosing among the complement of this checked cut.
    $missing = 5 - $order
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
        throw 'Code Sequence five-link directed cut contained an absent, duplicate or unordered SCC index.'
    }
    [int[]]$positions = [int[]]::new($missing)
    for ($i = 0; $i -lt $missing; $i++) { $positions[$i] = $i }
    [int[]]$five = [int[]]::new(5)
    [long]$newlyClassified = 0
    $scenarioCount = [int]$Choose[$LinkCount, 5]
    while ($true) {
        for ($i = 0; $i -lt $order; $i++) { $five[$i] = $CutIndices[$i] }
        for ($i = 0; $i -lt $missing; $i++) { $five[$order + $i] = $available[$positions[$i]] }
        [Array]::Sort($five)
        # In-line constant-time lex rank avoids millions of PowerShell
        # function invocations. Sorting five integers occurs in .NET.
        $a=$five[0]; $b=$five[1]; $c=$five[2]; $d=$five[3]; $e=$five[4]
        $rank = [int](
            $Choose[$LinkCount, 5] - $Choose[$LinkCount - $a, 5] +
            $Choose[$LinkCount - $a - 1, 4] - $Choose[$LinkCount - $b, 4] +
            $Choose[$LinkCount - $b - 1, 3] - $Choose[$LinkCount - $c, 3] +
            $Choose[$LinkCount - $c - 1, 2] - $Choose[$LinkCount - $d, 2] +
            $e - $d - 1)
        if ($rank -lt 0 -or $rank -ge $scenarioCount) {
            throw 'Code Sequence five-link directed-cut completion produced an invalid scenario rank.'
        }
        if (-not $AlreadyClassified[$rank]) {
            $AlreadyClassified[$rank] = $true
            $newlyClassified++
            if ($order -eq 5) { [void]$PositiveFifthOnlyRanks.Add($rank) }
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
    return $newlyClassified
}

function Get-CodeSequenceFiveLinkSmallestContainedCutOrder {
    param(
        [int[]] $FiveIndices,
        [System.Collections.Generic.List[int[]]] $CutsByAscendingCardinality
    )
    if ($null -eq $FiveIndices -or $FiveIndices.Length -ne 5 -or
        $null -eq $CutsByAscendingCardinality) {
        throw 'Code Sequence five-link sparse drilldown requires canonical deletion edges and complete original cut candidates.'
    }
    # Both sequences are already sorted. Two-pointer membership tests avoid
    # constructing all 31 nonempty subsets of every sparse five-link row.
    foreach ($cut in $CutsByAscendingCardinality) {
        $i=0; $j=0
        while ($i -lt $cut.Length -and $j -lt 5) {
            if ($cut[$i] -eq $FiveIndices[$j]) { $i++; $j++ }
            elseif ($cut[$i] -gt $FiveIndices[$j]) { $j++ }
            else { break }
        }
        if ($i -eq $cut.Length) { return [int]$cut.Length }
    }
    return 0
}

function Get-CodeSequenceEndpointDominanceFiveLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [object] $TripleInteraction,
        [object] $QuadrupleInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or $null -eq $TripleInteraction -or
        $null -eq $QuadrupleInteraction -or
        -not [bool]$QuadrupleInteraction.every_scenario_deletes_four_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$QuadrupleInteraction.minimum_outgoing_cut_size_partitions_single_pair_triple_and_strictly_fourth_only_loss -or
        -not [bool]$QuadrupleInteraction.original_redundant_shortcuts_remain_unless_one_of_four_removed_links -or
        -not [bool]$QuadrupleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$QuadrupleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence five-link interaction requires checked EC-093 through EC-098 ORIGINAL projections.'
    }
    # Regenerate the ENTIRE parent (including zero-case aggregate counts and
    # sparse original pair IDs). This transitively checks EC-097/096/095/094
    # and ORIGINAL EC-089 positive-FIRST SCC construction.
    $fresh = Get-CodeSequenceEndpointDominanceFourLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -PairInteraction $PairInteraction `
        -TripleInteraction $TripleInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 60 -Compress) -cne
        (ConvertTo-Json -InputObject $QuadrupleInteraction -Depth 60 -Compress)) {
        throw 'Code Sequence five-link interaction rejected changed EC-098 fourth-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$QuadrupleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$QuadrupleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence five-link interaction received changed original SCC or FULL direct links.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$fromByLink = [int[]]::new($linkCount)
    [int[]]$toByLink = [int[]]::new($linkCount)
    for ($s = 0; $s -lt $componentCount; $s++) {
        [int[]]$members = [int[]]$components[$s].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence five-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$s] = $members.Length
        $directRows[$s] = 1 -shl $s
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence five-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence five-link interaction found duplicated or invalid FULL original direct SCC links.'
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
            throw 'Code Sequence five-link interaction changed inherited ORIGINAL FULL SCC reachability.'
        }
    }
    [int[,]]$choose = New-CodeSequenceFiveLinkBinomialTable -LinkCount $linkCount
    $scenarioCount = [int]$choose[$linkCount, 5]

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
                    if ($boundary.Count -gt 5) { break }
                }
            }
            if ($boundary.Count -ge 1 -and $boundary.Count -le 5) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $boundary.ToArray()
                })
            }
        }
    }

    # One transient scenario BitArray per reachable SCC pair: no N^2 times
    # 8.9M class-byte storage. Count new coverage by FIRST cut cardinality.
    # Per-pair cut families are retained only for bounded sparse drilldown.
    [object[]]$cutsPerOrderedPair = [object[]]::new($componentCount * $componentCount)
    [long[]]$tierSum = [long[]]::new(6)
    [long[]]$tierReporterSum = [long[]]::new(6)
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
            for ($order = 1; $order -le 5; $order++) {
                foreach ($boundary in $perPair) {
                    if ($boundary.Length -ne $order) { continue }
                    $ascending.Add($boundary)
                    [long]$added = Add-CodeSequenceFiveLinkCutSupersets `
                        -CutIndices $boundary -LinkCount $linkCount -Choose $choose `
                        -AlreadyClassified $covered -PositiveFifthOnlyRanks $positiveRanks
                    $tierSum[$order] += $added
                    $tierReporterSum[$order] += $added * [long]$weights[$s] * $weights[$t]
                    $coveredCount += $added
                }
            }
            if ($coveredCount -gt $scenarioCount -or $ascending.Count -ne $perPair.Count) {
                throw 'Code Sequence five-link cut classes exceeded the complete five-link scenario universe.'
            }
            $cutsPerOrderedPair[$s * $componentCount + $t] = $ascending
            # Drop the very large temporary mask before the next SCC pair.
            $covered = $null
        }
    }
    if ($positiveRanks.Count -gt $cuts.Count) {
        throw 'Code Sequence five-link strictly fifth-only cases exceed the bounded directed-cut universe.'
    }

    # A strictly fifth-order positive scenario is EXACTLY an original
    # five-edge outgoing cut, possibly for several SCC pairs. Hence the
    # detailed result is bounded by <=4094, independent of C(E,5).
    [int[]]$sortedPositive = [int[]]::new($positiveRanks.Count)
    $positiveRanks.CopyTo($sortedPositive)
    [Array]::Sort($sortedPositive)
    $rows = [System.Collections.Generic.List[object]]::new()
    [long]$sparseFifthTotal = 0
    [long]$sparseFifthMass = 0
    foreach ($rank in $sortedPositive) {
        [int[]]$five = Get-CodeSequenceOriginalFiveLinkIndicesFromRank `
            -Rank $rank -LinkCount $linkCount -Choose $choose
        if ((Get-CodeSequenceOriginalDirectFiveLinkRank -LinkCount $linkCount -Choose $choose `
            -A $five[0] -B $five[1] -C $five[2] -D $five[3] -E $five[4]) -ne $rank) {
            throw 'Code Sequence five-link sparse scenario lost canonical original edge rank.'
        }
        [long[]]$counts = [long[]]::new(6)
        [long[]]$mass = [long[]]::new(6)
        $novelRows = [System.Collections.Generic.List[object]]::new()
        for ($s = 0; $s -lt $componentCount; $s++) {
            for ($t = 0; $t -lt $componentCount; $t++) {
                [System.Collections.Generic.List[int[]]]$pairCuts = $cutsPerOrderedPair[$s * $componentCount + $t]
                if ($null -eq $pairCuts) { continue }
                $order = Get-CodeSequenceFiveLinkSmallestContainedCutOrder `
                    -FiveIndices $five -CutsByAscendingCardinality $pairCuts
                if ($order -eq 0) { continue }
                if ($order -lt 1 -or $order -gt 5 -or $s -eq $t -or
                    ($baseline[$s] -band (1 -shl $t)) -eq 0) {
                    throw 'Code Sequence five-link sparse row included a non-original or reflexive SCC loss.'
                }
                $pairMass = [long]$weights[$s] * $weights[$t]
                $counts[$order]++
                $mass[$order] += $pairMass
                if ($order -eq 5) {
                    $novelRows.Add([ordered]@{
                        from_strict_component_index = $s + 1
                        to_strict_component_index = $t + 1
                        exact_ordered_original_reporter_pair_multiplicity = $pairMass
                    })
                }
            }
        }
        if ($counts[5] -lt 1 -or $novelRows.Count -ne $counts[5] -or
            $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5] -gt
                $componentCount * ($componentCount - 1)) {
            throw 'Code Sequence five-link positive scenario did not conserve disjoint loss orders.'
        }
        $sparseFifthTotal += $counts[5]
        $sparseFifthMass += $mass[5]
        $linkRows = [System.Collections.Generic.List[object]]::new()
        foreach ($linkIndex in $five) {
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
            first_original_direct_link_index_in_ec095 = $five[0] + 1
            second_original_direct_link_index_in_ec095 = $five[1] + 1
            third_original_direct_link_index_in_ec095 = $five[2] + 1
            fourth_original_direct_link_index_in_ec095 = $five[3] + 1
            fifth_original_direct_link_index_in_ec095 = $five[4] + 1
            five_whole_original_direct_links_in_canonical_order = $linkRows.ToArray()
            exact_unique_single_link_loss_component_pairs = $counts[1]
            exact_unique_single_link_loss_original_reporter_pairs = $mass[1]
            exact_additional_loss_by_some_pair_but_no_single_component_pairs = $counts[2]
            exact_additional_loss_by_some_pair_but_no_single_original_reporter_pairs = $mass[2]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_component_pairs = $counts[3]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_original_reporter_pairs = $mass[3]
            exact_additional_loss_by_some_quadruple_but_no_smaller_subset_component_pairs = $counts[4]
            exact_additional_loss_by_some_quadruple_but_no_smaller_subset_original_reporter_pairs = $mass[4]
            exact_joint_five_link_full_component_pair_losses = $counts[1] + $counts[2] + $counts[3] + $counts[4] + $counts[5]
            exact_joint_five_link_full_original_reporter_pair_losses = $mass[1] + $mass[2] + $mass[3] + $mass[4] + $mass[5]
            new_loss_only_if_all_five_original_links_are_removed = [ordered]@{
                exact_new_component_pair_count = $counts[5]
                exact_new_original_reporter_pair_count = $mass[5]
                newly_lost_component_pairs_in_canonical_order = $novelRows.ToArray()
            }
        })
    }
    if ($rows.Count -ne $positiveRanks.Count -or $rows.Count -gt $scenarioCount -or
        $sparseFifthTotal -ne $tierSum[5] -or $sparseFifthMass -ne $tierReporterSum[5]) {
        throw 'Code Sequence five-link sparse fifth-only rows disagree with complete directed-cut scenario incidences.'
    }
    [long]$allLosses = 0
    [long]$allReporterMass = 0
    for ($order = 1; $order -le 5; $order++) {
        $allLosses += $tierSum[$order]
        $allReporterMass += $tierReporterSum[$order]
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_component_link_count = $linkCount
        exact_five_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_fifth_only_new_component_reachability_loss = $rows.Count
        exact_scenarios_without_strictly_fifth_only_new_component_reachability_loss = $scenarioCount - $rows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_five_link_scenarios = $tierSum[1]
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_five_link_scenarios = $tierReporterSum[1]
        sum_of_pair_only_new_component_pair_incidences_across_five_link_scenarios = $tierSum[2]
        sum_of_pair_only_new_original_reporter_pair_incidences_across_five_link_scenarios = $tierReporterSum[2]
        sum_of_triple_only_new_component_pair_incidences_across_five_link_scenarios = $tierSum[3]
        sum_of_triple_only_new_original_reporter_pair_incidences_across_five_link_scenarios = $tierReporterSum[3]
        sum_of_quadruple_only_new_component_pair_incidences_across_five_link_scenarios = $tierSum[4]
        sum_of_quadruple_only_new_original_reporter_pair_incidences_across_five_link_scenarios = $tierReporterSum[4]
        sum_of_strictly_fifth_only_new_component_pair_incidences_across_five_link_scenarios = $tierSum[5]
        sum_of_strictly_fifth_only_new_original_reporter_pair_incidences_across_five_link_scenarios = $tierReporterSum[5]
        sum_of_combined_full_graph_component_pair_loss_incidences_across_five_link_scenarios = $allLosses
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_five_link_scenarios = $allReporterMass
        original_direct_link_quintuples_with_strictly_fifth_only_new_reachability_loss = $rows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_five = $cuts.Count
        all_five_link_scenarios_counted_via_exact_scc_directed_edge_cuts_not_per_scenario_graph_closure = $true
        bounded_transient_bitset_per_original_reachable_scc_pair_not_per_scenario_object = $true
        fifth_only_positive_scenarios_are_exact_five_edge_outgoing_directed_cuts = $true
        sparse_rows_omit_zero_fifth_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_five_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_quadruple_and_strictly_fifth_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_five_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuintupleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction,
        [object] $RetentionEndpointTripleInteraction,
        [object] $RetentionEndpointQuadrupleInteraction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        $null -eq $RetentionEndpointPairInteraction -or
        $null -eq $RetentionEndpointTripleInteraction -or
        $null -eq $RetentionEndpointQuadrupleInteraction -or
        [string]$RetentionEndpointQuadrupleInteraction.scope -cne 'exact_strictly_fourth_order_four_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointQuadrupleInteraction.only_consumed_checked_ec093_to_ec097_original_graph_projections -or
        -not [bool]$RetentionEndpointQuadrupleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointQuadrupleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointQuadrupleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence five-link interaction requires successful ORIGINAL selector and checked EC-098.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence five-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction,
        $RetentionEndpointTripleInteraction, $RetentionEndpointQuadrupleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence five-link interaction detected changed original caller/pair/path/anchor provenance.'
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
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    [object[]]$threeFamilies = [object[]]$RetentionEndpointTripleInteraction.individual_original_family_endpoint_triple_interaction
    [object[]]$fourFamilies = [object[]]$RetentionEndpointQuadrupleInteraction.individual_original_family_endpoint_quadruple_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $threesG.Length -ne 3 -or $threesF.Length -ne 3 -or
        $foursG.Length -ne 3 -or $foursF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount -or
        $threeFamilies.Length -ne $familyCount -or
        $fourFamilies.Length -ne $familyCount) {
        throw 'Code Sequence five-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
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
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            $two = $twos[$i]; $three = $threes[$i]; $four = $fours[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or $null -eq $four -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$one.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$two.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$three.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$four.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$three.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$four.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence five-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_fifth_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceFiveLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction `
                        -TripleInteraction $three.exact_strictly_triple_only_original_scc_link_removal_interaction `
                        -QuadrupleInteraction $four.exact_strictly_fourth_only_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        $two = $twoFamilies[$i]; $three = $threeFamilies[$i]; $four = $fourFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or $null -eq $four -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$three.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$four.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence five-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_fifth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceFiveLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.genuine_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.genuine_exact_strictly_fourth_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_fifth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceFiveLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.frozen_exact_strictly_triple_only_original_scc_link_removal_interaction `
                    -QuadrupleInteraction $four.frozen_exact_strictly_fourth_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_fifth_order_five_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_quintuple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_quintuple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_quintuple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec098_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

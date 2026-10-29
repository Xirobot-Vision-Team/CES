#requires -Version 7.0
<#
    EC-098: exact FOURTH-order loss when FOUR distinct whole ORIGINAL direct
    SCC links are deleted together from the FULL original condensation.

    A cut-set algorithm replaces a 720,720-scenario, per-scenario graph
    closure. For any originally reachable ordered SCC pair (s,t), deletion
    set D disconnects s from t iff it contains the complete outgoing
    directed boundary of some SCC-vertex set U with s in U and t outside.
    Enumerate at most 2^12-2 proper U once, retain only boundaries of 1..4
    actual direct links, and mark their distinct four-link supersets. The
    smallest boundary size contained in any four-link deletion classifies
    that SCC pair's loss into disjoint first/second/third/fourth order.
    This is exact for ALL C(E,4) interventions, including their zero-loss
    scenarios; only genuinely fourth-order cases expand into detail.

    All predecessor EC-097 projection bytes are regenerated and compared,
    transitively checking EC-096/095/094/093 and original EC-089 witnesses.
    SCC membership, redundant FULL links and canonical caller order stay
    fixed. No ORIGINAL saved-witness permutations, fresh reads or writes.
    These are hypothetical reachability cuts, not empirical reliability,
    observed faults, causality, chronology, severity or repair priority.
#>

function New-CodeSequenceFourLinkBinomialTable {
    param([int] $LinkCount)
    if ($LinkCount -lt 0 -or $LinkCount -gt 66) {
        throw 'Code Sequence four-link interaction requires 0..66 real original SCC links.'
    }
    [int[,]]$choose = [int[,]]::new($LinkCount + 1, 5)
    $choose[0, 0] = 1
    for ($n = 1; $n -le $LinkCount; $n++) {
        $choose[$n, 0] = 1
        for ($k = 1; $k -le 4 -and $k -le $n; $k++) {
            $choose[$n, $k] = $choose[$n - 1, $k - 1] + $choose[$n - 1, $k]
        }
    }
    return ,$choose
}

function Get-CodeSequenceOriginalDirectFourLinkRank {
    param(
        [int] $LinkCount,
        [int[,]] $Choose,
        [int] $A,
        [int] $B,
        [int] $C,
        [int] $D
    )
    # Constant-size sorting network: avoid Sort-Object and temporary arrays
    # for hundreds of thousands of four-link supersets.
    if ($A -gt $B) { $swap = $A; $A = $B; $B = $swap }
    if ($C -gt $D) { $swap = $C; $C = $D; $D = $swap }
    if ($A -gt $C) { $swap = $A; $A = $C; $C = $swap }
    if ($B -gt $D) { $swap = $B; $B = $D; $D = $swap }
    if ($B -gt $C) { $swap = $B; $B = $C; $C = $swap }
    if ($LinkCount -lt 4 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $A -lt 0 -or $A -ge $B -or $B -ge $C -or $C -ge $D -or
        $D -ge $LinkCount) {
        throw 'Code Sequence four-link scenario requires four DISTINCT actual original direct-link indices.'
    }
    # Zero-based lexicographic rank of a<b<c<d, with C(n,k)=0 for n<k.
    return [int](
        $Choose[$LinkCount, 4] - $Choose[$LinkCount - $A, 4] +
        $Choose[$LinkCount - $A - 1, 3] - $Choose[$LinkCount - $B, 3] +
        $Choose[$LinkCount - $B - 1, 2] - $Choose[$LinkCount - $C, 2] +
        $D - $C - 1)
}

function Get-CodeSequenceOriginalFourLinkIndicesFromRank {
    param([int] $Rank, [int] $LinkCount, [int[,]] $Choose)
    if ($LinkCount -lt 4 -or $LinkCount -gt 66 -or $null -eq $Choose -or
        $Rank -lt 0 -or $Rank -ge $Choose[$LinkCount, 4]) {
        throw 'Code Sequence four-link interaction received an invalid canonical scenario rank.'
    }
    $remainder = $Rank
    for ($a = 0; $a -le $LinkCount - 4; $a++) {
        $block = $Choose[$LinkCount - $a - 1, 3]
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    for ($b = $a + 1; $b -le $LinkCount - 3; $b++) {
        $block = $Choose[$LinkCount - $b - 1, 2]
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    for ($c = $b + 1; $c -le $LinkCount - 2; $c++) {
        $block = $LinkCount - $c - 1
        if ($remainder -lt $block) { break }
        $remainder -= $block
    }
    $d = $c + $remainder + 1
    if ($a -ge $b -or $b -ge $c -or $c -ge $d -or $d -ge $LinkCount) {
        throw 'Code Sequence four-link rank inversion did not produce four actual distinct links.'
    }
    return ,([int[]]@($a, $b, $c, $d))
}

function Add-CodeSequenceFourLinkCutSupersets {
    param(
        [int[]] $CutIndices,
        [int] $LinkCount,
        [int[,]] $Choose,
        [byte[]] $LowestCutOrderByScenario,
        [System.Collections.Generic.List[int]] $TouchedScenarios
    )
    $order = if ($null -eq $CutIndices) { 0 } else { $CutIndices.Length }
    if ($order -lt 1 -or $order -gt 4 -or $LinkCount -lt 4 -or
        $null -eq $LowestCutOrderByScenario -or
        $LowestCutOrderByScenario.Length -ne $Choose[$LinkCount, 4] -or
        $null -eq $TouchedScenarios) {
        throw 'Code Sequence four-link cut completion requires one to four real FULL direct-link cut edges.'
    }
    [int[]]$available = [int[]]::new($LinkCount - $order)
    $next = 0; $cutPos = 0
    for ($i = 0; $i -lt $LinkCount; $i++) {
        if ($cutPos -lt $order -and $CutIndices[$cutPos] -eq $i) {
            $cutPos++
        } else {
            $available[$next] = $i
            $next++
        }
    }
    if ($cutPos -ne $order -or $next -ne $available.Length) {
        throw 'Code Sequence four-link cut completion found duplicate, unsorted or absent ORIGINAL links.'
    }
    # A directed edge boundary K disconnects every originally reachable
    # (s,t) that crosses its vertex cut. Any four-set containing K is thus
    # a loss scenario. Keep its LOWEST witnessed cut cardinality, so losses
    # from lower-order subsets cannot be counted again as fourth-order.
    switch ($order) {
        1 {
            for ($a = 0; $a -lt $available.Length - 2; $a++) {
                for ($b = $a + 1; $b -lt $available.Length - 1; $b++) {
                    for ($c = $b + 1; $c -lt $available.Length; $c++) {
                        $rank = Get-CodeSequenceOriginalDirectFourLinkRank `
                            -LinkCount $LinkCount -Choose $Choose -A $CutIndices[0] `
                            -B $available[$a] -C $available[$b] -D $available[$c]
                        $old = $LowestCutOrderByScenario[$rank]
                        if ($old -eq 0) { $TouchedScenarios.Add($rank) }
                        if ($old -eq 0 -or $old -gt 1) { $LowestCutOrderByScenario[$rank] = [byte]1 }
                    }
                }
            }
        }
        2 {
            for ($a = 0; $a -lt $available.Length - 1; $a++) {
                for ($b = $a + 1; $b -lt $available.Length; $b++) {
                    $rank = Get-CodeSequenceOriginalDirectFourLinkRank `
                        -LinkCount $LinkCount -Choose $Choose -A $CutIndices[0] `
                        -B $CutIndices[1] -C $available[$a] -D $available[$b]
                    $old = $LowestCutOrderByScenario[$rank]
                    if ($old -eq 0) { $TouchedScenarios.Add($rank) }
                    if ($old -eq 0 -or $old -gt 2) { $LowestCutOrderByScenario[$rank] = [byte]2 }
                }
            }
        }
        3 {
            foreach ($extra in $available) {
                $rank = Get-CodeSequenceOriginalDirectFourLinkRank `
                    -LinkCount $LinkCount -Choose $Choose -A $CutIndices[0] `
                    -B $CutIndices[1] -C $CutIndices[2] -D $extra
                $old = $LowestCutOrderByScenario[$rank]
                if ($old -eq 0) { $TouchedScenarios.Add($rank) }
                if ($old -eq 0 -or $old -gt 3) { $LowestCutOrderByScenario[$rank] = [byte]3 }
            }
        }
        4 {
            $rank = Get-CodeSequenceOriginalDirectFourLinkRank `
                -LinkCount $LinkCount -Choose $Choose -A $CutIndices[0] `
                -B $CutIndices[1] -C $CutIndices[2] -D $CutIndices[3]
            $old = $LowestCutOrderByScenario[$rank]
            if ($old -eq 0) { $TouchedScenarios.Add($rank) }
            if ($old -eq 0 -or $old -gt 4) { $LowestCutOrderByScenario[$rank] = [byte]4 }
        }
    }
}

function Get-CodeSequenceEndpointDominanceFourLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [object] $TripleInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or $null -eq $TripleInteraction -or
        -not [bool]$TripleInteraction.every_scenario_deletes_three_distinct_whole_original_direct_scc_links_from_full_dag -or
        -not [bool]$TripleInteraction.unique_single_plus_pair_only_plus_strictly_triple_only_partition_all_triple_loss -or
        -not [bool]$TripleInteraction.source_scc_members_and_internal_cycles_held_fixed -or
        -not [bool]$TripleInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence four-link interaction requires checked EC-093 through EC-097 ORIGINAL projections.'
    }
    # The complete EC-097 output, including every sparse third-order row and
    # all C(E,3) zero-case incidences, is regenerated. It recursively checks
    # EC-096, EC-095, EC-094, true EC-089 FIRST margins and SCC membership.
    $fresh = Get-CodeSequenceEndpointDominanceThreeLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -PairInteraction $PairInteraction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 50 -Compress) -cne
        (ConvertTo-Json -InputObject $TripleInteraction -Depth 50 -Compress)) {
        throw 'Code Sequence four-link interaction rejected changed EC-097 third-order ORIGINAL evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    $linkCount = $links.Length
    if ($componentCount -lt 1 -or $componentCount -gt $N -or
        $linkCount -gt [int]($componentCount * ($componentCount - 1) / 2) -or
        [int]$TripleInteraction.exact_strongly_connected_component_count -ne $componentCount -or
        [int]$TripleInteraction.exact_original_direct_component_link_count -ne $linkCount) {
        throw 'Code Sequence four-link interaction received changed original SCC/link membership.'
    }
    [int[]]$weights = [int[]]::new($componentCount)
    [int[]]$directRows = [int[]]::new($componentCount)
    [int[]]$edgeFrom = [int[]]::new($linkCount)
    [int[]]$edgeTo = [int[]]::new($linkCount)
    for ($source = 0; $source -lt $componentCount; $source++) {
        [int[]]$members = [int[]]$components[$source].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence four-link interaction found an empty ORIGINAL SCC.'
        }
        $weights[$source] = $members.Length
        $directRows[$source] = 1 -shl $source
    }
    for ($i = 0; $i -lt $linkCount; $i++) {
        $link = $links[$i]
        if ($null -eq $link) { throw 'Code Sequence four-link interaction found an absent original direct SCC link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $to -lt 0 -or $from -ge $componentCount -or
            $to -ge $componentCount -or $from -eq $to -or
            ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence four-link interaction received duplicated or invalid original FULL SCC link.'
        }
        $edgeFrom[$i] = $from
        $edgeTo[$i] = $to
        $directRows[$from] = $directRows[$from] -bor (1 -shl $to)
    }
    [int[]]$baseline = (Get-CodeSequenceDominanceThreeLinkClosureBits `
        -ComponentCount $componentCount -FullDirectRows $directRows -DirectLinks $links).Rows
    [int[]]$checkedBaseline = (Get-CodeSequenceDominanceTwoLinkClosureBits `
        -ComponentCount $componentCount -DirectLinks $links).Rows
    for ($source = 0; $source -lt $componentCount; $source++) {
        if ($baseline[$source] -ne $checkedBaseline[$source]) {
            throw 'Code Sequence four-link interaction changed prior FULL original reachability.'
        }
    }
    [int[,]]$choose = New-CodeSequenceFourLinkBinomialTable -LinkCount $linkCount
    $scenarioCount = [int]$choose[$linkCount, 4]

    # The same complete original condensed graph is used for every target.
    # SCC vertex sets are <=4094, rather than C(66,4)=720720 full closures.
    # A boundary's links are all actual direct links, including shortcuts;
    # component membership/cycles are never recalculated after deletion.
    $cuts = [System.Collections.Generic.List[object]]::new()
    if ($scenarioCount -gt 0) {
        $allComponentsBits = (1 -shl $componentCount) - 1
        for ($subset = 1; $subset -lt $allComponentsBits; $subset++) {
            $crossing = [System.Collections.Generic.List[int]]::new()
            for ($linkIndex = 0; $linkIndex -lt $linkCount; $linkIndex++) {
                if (($subset -band (1 -shl $edgeFrom[$linkIndex])) -ne 0 -and
                    ($subset -band (1 -shl $edgeTo[$linkIndex])) -eq 0) {
                    $crossing.Add($linkIndex)
                    if ($crossing.Count -gt 4) { break }
                }
            }
            if ($crossing.Count -gt 0 -and $crossing.Count -le 4) {
                $cuts.Add([pscustomobject]@{
                    source_side_bitset = $subset
                    outgoing_whole_original_link_indices = $crossing.ToArray()
                })
            }
        }
    }

    [object[]]$orderPerOriginalPair = [object[]]::new($componentCount * $componentCount)
    $positiveRanks = [System.Collections.Generic.HashSet[int]]::new()
    [long[]]$tierSum = [long[]]::new(5)
    [long[]]$tierWeightSum = [long[]]::new(5)
    for ($source = 0; $source -lt $componentCount; $source++) {
        for ($target = 0; $target -lt $componentCount; $target++) {
            if ($source -eq $target -or ($baseline[$source] -band (1 -shl $target)) -eq 0 -or
                $scenarioCount -eq 0) { continue }
            $seenCuts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $pairCuts = [System.Collections.Generic.List[int[]]]::new()
            foreach ($candidate in $cuts) {
                if (($candidate.source_side_bitset -band (1 -shl $source)) -eq 0 -or
                    ($candidate.source_side_bitset -band (1 -shl $target)) -ne 0) { continue }
                [int[]]$cut = [int[]]$candidate.outgoing_whole_original_link_indices
                $key = $cut -join ','
                if ($seenCuts.Add($key)) { $pairCuts.Add($cut) }
            }
            # Only source-target pairs with a cut of <=4 edges can possibly
            # lose reachability under four deletions. Avoid allocating a
            # 720720-byte class table for every dense-graph pair needlessly.
            if ($pairCuts.Count -eq 0) { continue }
            [byte[]]$orders = [byte[]]::new($scenarioCount)
            $touched = [System.Collections.Generic.List[int]]::new()
            foreach ($cut in $pairCuts) {
                Add-CodeSequenceFourLinkCutSupersets -CutIndices $cut -LinkCount $linkCount `
                    -Choose $choose -LowestCutOrderByScenario $orders -TouchedScenarios $touched
            }
            foreach ($scenarioRank in $touched) {
                $order = [int]$orders[$scenarioRank]
                if ($order -lt 1 -or $order -gt 4) {
                    throw 'Code Sequence four-link cut propagation left an invalid minimal boundary order.'
                }
                $tierSum[$order]++
                $tierWeightSum[$order] += [long]$weights[$source] * $weights[$target]
                if ($order -eq 4) { [void]$positiveRanks.Add($scenarioRank) }
            }
            $orderPerOriginalPair[$source * $componentCount + $target] = $orders
        }
    }

    # Materialize only true fourth-order scenarios; every other scenario was
    # counted above (including missing-by-design zero reachability losses).
    [int[]]$sortedPositive = [int[]]::new($positiveRanks.Count)
    $positiveRanks.CopyTo($sortedPositive)
    [Array]::Sort($sortedPositive)
    $positiveRows = [System.Collections.Generic.List[object]]::new()
    [long]$sparseFourthSum = 0
    [long]$sparseFourthWeight = 0
    foreach ($scenarioRank in $sortedPositive) {
        [int[]]$fourIndices = Get-CodeSequenceOriginalFourLinkIndicesFromRank `
            -Rank $scenarioRank -LinkCount $linkCount -Choose $choose
        if ((Get-CodeSequenceOriginalDirectFourLinkRank -LinkCount $linkCount -Choose $choose `
            -A $fourIndices[0] -B $fourIndices[1] -C $fourIndices[2] -D $fourIndices[3]) -ne $scenarioRank) {
            throw 'Code Sequence four-link sparse scenario lost canonical link rank provenance.'
        }
        [long[]]$count = [long[]]::new(5)
        [long[]]$weight = [long[]]::new(5)
        $newRows = [System.Collections.Generic.List[object]]::new()
        for ($source = 0; $source -lt $componentCount; $source++) {
            for ($target = 0; $target -lt $componentCount; $target++) {
                [byte[]]$classes = $orderPerOriginalPair[$source * $componentCount + $target]
                if ($null -eq $classes) { continue }
                $order = [int]$classes[$scenarioRank]
                if ($order -eq 0) { continue }
                if ($order -lt 1 -or $order -gt 4 -or $source -eq $target -or
                    ($baseline[$source] -band (1 -shl $target)) -eq 0) {
                    throw 'Code Sequence four-link sparse scenario contained a non-original/reflexive loss.'
                }
                $originalMass = [long]$weights[$source] * $weights[$target]
                $count[$order]++
                $weight[$order] += $originalMass
                if ($order -eq 4) {
                    $newRows.Add([ordered]@{
                        from_strict_component_index = $source + 1
                        to_strict_component_index = $target + 1
                        exact_ordered_original_reporter_pair_multiplicity = $originalMass
                    })
                }
            }
        }
        if ($count[4] -lt 1 -or $newRows.Count -ne $count[4] -or
            $count[1] + $count[2] + $count[3] + $count[4] -gt $componentCount * ($componentCount - 1)) {
            throw 'Code Sequence four-link positive scenario violated full-graph loss partition.'
        }
        $sparseFourthSum += $count[4]
        $sparseFourthWeight += $weight[4]
        $linkDescriptions = [System.Collections.Generic.List[object]]::new()
        foreach ($linkIndex in $fourIndices) {
            $link = $links[$linkIndex]
            $linkDescriptions.Add([ordered]@{
                original_direct_link_index_in_ec095 = $linkIndex + 1
                dominant_component_index = [int]$link.dominant_component_index
                subordinate_component_index = [int]$link.subordinate_component_index
                indispensable_alone = [bool]$link.indispensable_for_original_strict_component_reachability
                original_ec089_unordered_pair_indices = [int[]]$link.original_ec089_unordered_pair_indices
                exact_sum_of_direct_strict_first_credit_advantages = [long]$link.exact_sum_of_direct_strict_first_credit_advantages
            })
        }
        $positiveRows.Add([ordered]@{
            first_original_direct_link_index_in_ec095 = $fourIndices[0] + 1
            second_original_direct_link_index_in_ec095 = $fourIndices[1] + 1
            third_original_direct_link_index_in_ec095 = $fourIndices[2] + 1
            fourth_original_direct_link_index_in_ec095 = $fourIndices[3] + 1
            four_whole_original_direct_links_in_canonical_order = $linkDescriptions.ToArray()
            exact_unique_single_link_loss_component_pairs = $count[1]
            exact_unique_single_link_loss_original_reporter_pairs = $weight[1]
            exact_additional_loss_by_some_pair_but_no_single_component_pairs = $count[2]
            exact_additional_loss_by_some_pair_but_no_single_original_reporter_pairs = $weight[2]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_component_pairs = $count[3]
            exact_additional_loss_by_some_triple_but_no_smaller_subset_original_reporter_pairs = $weight[3]
            exact_joint_four_link_full_component_pair_losses = $count[1] + $count[2] + $count[3] + $count[4]
            exact_joint_four_link_full_original_reporter_pair_losses = $weight[1] + $weight[2] + $weight[3] + $weight[4]
            new_loss_only_if_all_four_original_links_are_removed = [ordered]@{
                exact_new_component_pair_count = $count[4]
                exact_new_original_reporter_pair_count = $weight[4]
                newly_lost_component_pairs_in_canonical_order = $newRows.ToArray()
            }
        })
    }
    if ($positiveRows.Count -gt $scenarioCount -or $positiveRows.Count -ne $positiveRanks.Count -or
        $sparseFourthSum -ne $tierSum[4] -or $sparseFourthWeight -ne $tierWeightSum[4]) {
        throw 'Code Sequence four-link sparse rows do not conserve original fourth-order incidence totals.'
    }
    [long]$combined = $tierSum[1] + $tierSum[2] + $tierSum[3] + $tierSum[4]
    [long]$combinedMass = $tierWeightSum[1] + $tierWeightSum[2] + $tierWeightSum[3] + $tierWeightSum[4]
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_component_link_count = $linkCount
        exact_four_distinct_original_direct_link_removal_scenario_count = $scenarioCount
        exact_scenarios_with_strictly_fourth_only_new_component_reachability_loss = $positiveRows.Count
        exact_scenarios_without_strictly_fourth_only_new_component_reachability_loss = $scenarioCount - $positiveRows.Count
        sum_of_unique_single_loss_component_pair_incidences_across_four_link_scenarios = $tierSum[1]
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_four_link_scenarios = $tierWeightSum[1]
        sum_of_pair_only_new_component_pair_incidences_across_four_link_scenarios = $tierSum[2]
        sum_of_pair_only_new_original_reporter_pair_incidences_across_four_link_scenarios = $tierWeightSum[2]
        sum_of_triple_only_new_component_pair_incidences_across_four_link_scenarios = $tierSum[3]
        sum_of_triple_only_new_original_reporter_pair_incidences_across_four_link_scenarios = $tierWeightSum[3]
        sum_of_strictly_fourth_only_new_component_pair_incidences_across_four_link_scenarios = $tierSum[4]
        sum_of_strictly_fourth_only_new_original_reporter_pair_incidences_across_four_link_scenarios = $tierWeightSum[4]
        sum_of_combined_full_graph_component_pair_loss_incidences_across_four_link_scenarios = $combined
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_four_link_scenarios = $combinedMass
        original_direct_link_quadruples_with_strictly_fourth_only_new_reachability_loss = $positiveRows.ToArray()
        exact_distinct_original_scc_vertex_cut_candidates_of_size_at_most_four = $cuts.Count
        all_four_link_scenarios_counted_via_exact_scc_directed_edge_cuts_not_per_scenario_graph_closure = $true
        sparse_rows_omit_zero_fourth_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_four_distinct_whole_original_direct_scc_links_from_full_dag = $true
        minimum_outgoing_cut_size_partitions_single_pair_triple_and_strictly_fourth_only_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_four_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuadrupleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction,
        [object] $RetentionEndpointTripleInteraction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        $null -eq $RetentionEndpointPairInteraction -or
        $null -eq $RetentionEndpointTripleInteraction -or
        [string]$RetentionEndpointTripleInteraction.scope -cne 'exact_strictly_third_order_three_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointTripleInteraction.only_consumed_checked_ec093_to_ec096_original_graph_projections -or
        -not [bool]$RetentionEndpointTripleInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointTripleInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointTripleInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence four-link interaction requires successful ORIGINAL selector and checked EC-097.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence four-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction, $RetentionEndpointTripleInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence four-link interaction detected changed original caller/pair/path/anchor provenance.'
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
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    [object[]]$threeFamilies = [object[]]$RetentionEndpointTripleInteraction.individual_original_family_endpoint_triple_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $threesG.Length -ne 3 -or $threesF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount -or
        $threeFamilies.Length -ne $familyCount) {
        throw 'Code Sequence four-link interaction lost a genuine/frozen or actual ORIGINAL family target.'
    }
    $genuine = [System.Collections.Generic.List[object]]::new()
    $frozen = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $tops = if ($mode -eq 0) { $topsG } else { $topsF }
        $reds = if ($mode -eq 0) { $redsG } else { $redsF }
        $ones = if ($mode -eq 0) { $onesG } else { $onesF }
        $twos = if ($mode -eq 0) { $twosG } else { $twosF }
        $threes = if ($mode -eq 0) { $threesG } else { $threesF }
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            $two = $twos[$i]; $three = $threes[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                $null -eq $two -or $null -eq $three -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$one.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$two.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$three.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$three.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence four-link interaction reindexed an ORIGINAL >=3/2/1 threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_fourth_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceFourLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction `
                        -TripleInteraction $three.exact_strictly_triple_only_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        $two = $twoFamilies[$i]; $three = $threeFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            $null -eq $two -or $null -eq $three -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$three.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence four-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_fourth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceFourLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.genuine_exact_strictly_triple_only_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_fourth_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceFourLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction `
                    -TripleInteraction $three.frozen_exact_strictly_triple_only_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_fourth_order_four_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_quadruple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_quadruple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_quadruple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec097_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

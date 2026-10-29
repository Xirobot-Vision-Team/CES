#requires -Version 7.0
<#
    EC-093: exact ORIGINAL endpoint FIRST-credit strict-dominance topology.

    Interpret only EC-092's checked full-gap original a<b comparisons:
    a_more -> a to b, b_more -> b to a, equal -> no strict arc.
    Equal means equal hypothetical FIRST-credit counts, including 0/0;
    equal edges are not reachability links or an equivalence relation.

    Compute directed strict reachability, strongly connected components,
    and the condensation DAG's longest-path layers without enumerating any
    ORIGINAL report permutations, masks or historical saved evidence. This
    is a comparison topology, never chronology, empirical likelihood,
    confidence, defect severity, or an instruction to prioritize repairs.
#>

function Get-CodeSequenceEndpointDominanceTopologyProjection {
    param(
        [object] $EndpointCreditGraph,
        [int] $N
    )

    if ($null -eq $EndpointCreditGraph -or $N -lt 2 -or $N -gt 12 -or
        -not [bool]$EndpointCreditGraph.every_original_pair_direction_and_gap_is_exhaustive_and_disjoint -or
        -not [bool]$EndpointCreditGraph.every_reporter_first_credit_matches_ec089_and_ec091_original_identity -or
        -not [bool]$EndpointCreditGraph.endpoint_first_only_conditional_shares_are_null_when_ineligible -or
        -not [bool]$EndpointCreditGraph.all_first_restoration_mass_matches_independent_ec074_ec076_ec089 -or
        -not [bool]$EndpointCreditGraph.nonendpoint_or_never_restoration_is_never_attributed_to_a_or_b -or
        -not [bool]$EndpointCreditGraph.no_new_evidence_read_mask_enumeration_git_network_or_business_write) {
        throw 'Code Sequence endpoint dominance topology requires a checked EC-092 ORIGINAL credit graph.'
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorials[$N]
    $pairCount = [int]($N * ($N - 1) / 2)
    $edges = [object[]]$EndpointCreditGraph.original_unordered_endpoint_credit_edges
    $nodes = [object[]]$EndpointCreditGraph.original_reporter_endpoint_credit_nodes
    if ([int]$EndpointCreditGraph.original_positions_in_credit_graph -ne $N -or
        [int]$EndpointCreditGraph.exact_unordered_original_pair_edge_count -ne $pairCount -or
        [long]$EndpointCreditGraph.total_distinct_full_original_permutations -ne $full -or
        [long]$EndpointCreditGraph.exact_total_original_pair_ordering_incidences -ne [long]$pairCount * $full -or
        $edges.Count -ne $pairCount -or $nodes.Count -ne $N) {
        throw 'Code Sequence endpoint dominance topology received the wrong ORIGINAL graph universe.'
    }

    # The graph is small (N<=12). A boolean transitive closure makes strict
    # cycles explicit without imposing a fictitious total order on ties.
    $reach = [bool[,]]::new($N, $N)
    $wins = [int[]]::new($N)
    $losses = [int[]]::new($N)
    $ties = [int[]]::new($N)
    $unsupportedTies = [int[]]::new($N)
    $credits = [long[]]::new($N)
    $arcs = [System.Collections.Generic.List[object]]::new()
    $equalEdges = [System.Collections.Generic.List[object]]::new()
    $endpointTotal = [long]0
    $residualTotal = [long]0
    $noEndpointPairs = 0
    $index = 0
    for ($a = 0; $a -lt $N; $a++) {
        $reach[$a, $a] = $true
        for ($b = $a + 1; $b -lt $N; $b++) {
            $edge = $edges[$index]
            $index++
            if ($null -eq $edge -or
                [int]$edge.original_unordered_pair_index_in_ec089 -ne $index -or
                [int]$edge.original_report_a_caller_position -ne $a + 1 -or
                [int]$edge.original_report_b_caller_position -ne $b + 1 -or
                [int]$edge.original_report_a_position_bit -ne (1 -shl $a) -or
                [int]$edge.original_report_b_position_bit -ne (1 -shl $b) -or
                [long]$edge.exact_full_original_orderings_across_both_directions -ne $full) {
                throw 'Code Sequence endpoint dominance topology lost the canonical EC-089 ORIGINAL pair identity.'
            }
            $creditA = [long]$edge.first_restored_by_original_a_across_all_gaps
            $creditB = [long]$edge.first_restored_by_original_b_across_all_gaps
            $credited = [long]$edge.first_restored_by_either_endpoint_across_all_gaps
            $neither = [long]$edge.neither_endpoint_first_across_all_gaps
            $difference = $creditA - $creditB
            if ($creditA -lt 0 -or $creditB -lt 0 -or $neither -lt 0 -or
                $creditA + $creditB -ne $credited -or $credited + $neither -ne $full -or
                [long]$edge.exact_signed_original_a_minus_b_first_credit_count -ne $difference) {
                throw 'Code Sequence endpoint dominance topology received inconsistent endpoint FIRST mass.'
            }
            # Do not promote a 0/0 tie to an apparent positive shared FIRST
            # credit, or turn a non-endpoint first into an endpoint win.
            $expectedA = Get-CodeSequenceEndpointCreditConditionalShare -Credited $creditA -EndpointFirst $credited
            $expectedB = Get-CodeSequenceEndpointCreditConditionalShare -Credited $creditB -EndpointFirst $credited
            $shareA = $edge.exact_reduced_a_share_given_either_endpoint_first
            $shareB = $edge.exact_reduced_b_share_given_either_endpoint_first
            if (($null -eq $expectedA) -ne ($null -eq $shareA) -or
                ($null -eq $expectedB) -ne ($null -eq $shareB)) {
                throw 'Code Sequence endpoint dominance topology changed null endpoint FIRST conditioning.'
            }
            if ($null -ne $expectedA -and
                ([long]$expectedA.numerator -ne [long]$shareA.numerator -or
                 [long]$expectedA.denominator -ne [long]$shareA.denominator -or
                 [long]$expectedB.numerator -ne [long]$shareB.numerator -or
                 [long]$expectedB.denominator -ne [long]$shareB.denominator)) {
                throw 'Code Sequence endpoint dominance topology changed exact endpoint FIRST shares.'
            }
            $signedExpected = Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $difference -Denominator $full
            $signedShare = $edge.exact_reduced_signed_a_minus_b_credit_fraction_over_full_pair
            if ($null -eq $signedShare -or
                [long]$signedShare.numerator -ne [long]$signedExpected.numerator -or
                [long]$signedShare.denominator -ne [long]$signedExpected.denominator) {
                throw 'Code Sequence endpoint dominance topology changed exact signed ORIGINAL pair FIRST-credit fraction.'
            }
            if (-not [bool]$EndpointCreditGraph.full_original_selection_has_saved_witness_support -and $credited -ne 0) {
                throw 'Code Sequence endpoint dominance topology invented support for an unsupported ORIGINAL target.'
            }
            $relation = [string]$edge.original_a_vs_b_endpoint_credit_relation
            $expectedRelation = Get-CodeSequenceEndpointCreditRelation -A $creditA -B $creditB
            if ($relation -cne $expectedRelation) {
                throw 'Code Sequence endpoint dominance topology received a false strict endpoint relation.'
            }
            $credits[$a] += $creditA
            $credits[$b] += $creditB
            $endpointTotal += $credited
            $residualTotal += $neither
            if ($credited -eq 0) {
                $noEndpointPairs++
                $unsupportedTies[$a]++
                $unsupportedTies[$b]++
            }
            if ($relation -ceq 'equal') {
                $ties[$a]++
                $ties[$b]++
                $equalEdges.Add([ordered]@{
                    original_unordered_pair_index_in_ec089 = $index
                    original_report_a_caller_position = $a + 1
                    original_report_b_caller_position = $b + 1
                    exact_first_credit_per_original_endpoint = $creditA
                    neither_endpoint_received_first_credit = ($credited -eq 0)
                })
                continue
            }
            $winner = if ($relation -ceq 'a_more') { $a } else { $b }
            $loser = if ($relation -ceq 'a_more') { $b } else { $a }
            $winnerCredit = if ($winner -eq $a) { $creditA } else { $creditB }
            $loserCredit = if ($winner -eq $a) { $creditB } else { $creditA }
            if ($winnerCredit -le $loserCredit -or $reach[$winner, $loser]) {
                throw 'Code Sequence endpoint dominance topology received duplicate/non-strict comparison.'
            }
            $reach[$winner, $loser] = $true
            $wins[$winner]++
            $losses[$loser]++
            $arcs.Add([ordered]@{
                original_unordered_pair_index_in_ec089 = $index
                original_winner_caller_position = $winner + 1
                original_winner_position_bit = 1 -shl $winner
                original_loser_caller_position = $loser + 1
                original_loser_position_bit = 1 -shl $loser
                winner_endpoint_first_credit = $winnerCredit
                loser_endpoint_first_credit = $loserCredit
                exact_strict_winner_minus_loser_first_credit_count = $winnerCredit - $loserCredit
            })
        }
    }
    if ($arcs.Count + $equalEdges.Count -ne $pairCount -or
        $endpointTotal -ne [long]$EndpointCreditGraph.total_first_restored_by_any_original_pair_endpoint -or
        $residualTotal -ne [long]$EndpointCreditGraph.total_neither_endpoint_first_ordering_incidences -or
        $endpointTotal + $residualTotal -ne [long]$pairCount * $full) {
        throw 'Code Sequence endpoint dominance topology failed the complete ORIGINAL pair ledger.'
    }

    # Warshall closure: a path is a chain of strictly higher *pair-specific*
    # credit counts. It is not itself a direct pair comparison.
    for ($k = 0; $k -lt $N; $k++) {
        for ($i = 0; $i -lt $N; $i++) {
            if (-not $reach[$i, $k]) { continue }
            for ($j = 0; $j -lt $N; $j++) {
                if ($reach[$k, $j]) { $reach[$i, $j] = $true }
            }
        }
    }
    $componentOf = [int[]]::new($N)
    $membersByComponent = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $N; $i++) {
        if ($componentOf[$i] -ne 0) { continue }
        $id = $membersByComponent.Count + 1
        $members = [System.Collections.Generic.List[int]]::new()
        for ($j = 0; $j -lt $N; $j++) {
            if ($reach[$i, $j] -and $reach[$j, $i]) {
                if ($componentOf[$j] -ne 0) {
                    throw 'Code Sequence endpoint dominance topology double-assigned a strict SCC.'
                }
                $componentOf[$j] = $id
                $members.Add($j + 1)
            }
        }
        if ($members.Count -lt 1) { throw 'Code Sequence endpoint dominance topology lost an ORIGINAL reporter.' }
        $membersByComponent.Add($members.ToArray())
    }
    $componentCount = $membersByComponent.Count
    $componentArcCounts = [int[,]]::new($componentCount, $componentCount)
    $componentArcMass = [long[,]]::new($componentCount, $componentCount)
    $componentPairIds = @{}
    $internalCounts = [int[]]::new($componentCount)
    $externalStrictCount = 0
    foreach ($arc in $arcs) {
        $winnerIndex = [int]$arc.original_winner_caller_position - 1
        $loserIndex = [int]$arc.original_loser_caller_position - 1
        $src = $componentOf[$winnerIndex] - 1
        $dst = $componentOf[$loserIndex] - 1
        if ($src -eq $dst) {
            $internalCounts[$src]++
            continue
        }
        if ($reach[$loserIndex, $winnerIndex]) {
            throw 'Code Sequence endpoint dominance topology split a strict cycle across components.'
        }
        $externalStrictCount++
        $componentArcCounts[$src, $dst]++
        $componentArcMass[$src, $dst] += [long]$arc.exact_strict_winner_minus_loser_first_credit_count
        $key = "$src/$dst"
        if (-not $componentPairIds.ContainsKey($key)) {
            $componentPairIds[$key] = [System.Collections.Generic.List[int]]::new()
        }
        $componentPairIds[$key].Add([int]$arc.original_unordered_pair_index_in_ec089)
    }
    $componentOut = [int[]]::new($componentCount)
    $componentIn = [int[]]::new($componentCount)
    $componentLinks = [System.Collections.Generic.List[object]]::new()
    for ($src = 0; $src -lt $componentCount; $src++) {
        for ($dst = 0; $dst -lt $componentCount; $dst++) {
            if ($componentArcCounts[$src, $dst] -le 0) { continue }
            $componentOut[$src]++
            $componentIn[$dst]++
            $componentLinks.Add([ordered]@{
                dominant_component_index = $src + 1
                subordinate_component_index = $dst + 1
                original_direct_strict_comparison_count = $componentArcCounts[$src, $dst]
                exact_sum_of_strict_first_credit_advantages = $componentArcMass[$src, $dst]
                original_ec089_unordered_pair_indices = $componentPairIds["$src/$dst"].ToArray()
            })
        }
    }

    # Kahn topological walk, deterministic by minimal ORIGINAL caller index.
    # Layer 0 contains all source SCCs; for any other SCC layer is one plus
    # the MAXIMUM predecessor layer (not an empirical ranking).
    $remainingIn = [int[]]$componentIn.Clone()
    $layer = [int[]]::new($componentCount)
    $visited = [bool[]]::new($componentCount)
    $maxLayer = 0
    for ($step = 0; $step -lt $componentCount; $step++) {
        $next = -1
        for ($c = 0; $c -lt $componentCount; $c++) {
            if (-not $visited[$c] -and $remainingIn[$c] -eq 0) { $next = $c; break }
        }
        if ($next -lt 0) { throw 'Code Sequence endpoint dominance topology condensed graph is not acyclic.' }
        $visited[$next] = $true
        if ($layer[$next] -gt $maxLayer) { $maxLayer = $layer[$next] }
        for ($dst = 0; $dst -lt $componentCount; $dst++) {
            if ($componentArcCounts[$next, $dst] -eq 0) { continue }
            $candidate = $layer[$next] + 1
            if ($candidate -gt $layer[$dst]) { $layer[$dst] = $candidate }
            $remainingIn[$dst]--
            if ($remainingIn[$dst] -lt 0) { throw 'Code Sequence endpoint dominance topology overcounted a condensed edge.' }
        }
    }
    $components = [System.Collections.Generic.List[object]]::new()
    $sourceComponents = 0
    $cycleComponents = 0
    $internalTotal = 0
    for ($c = 0; $c -lt $componentCount; $c++) {
        if ($componentIn[$c] -eq 0) { $sourceComponents++ }
        $members = [int[]]$membersByComponent[$c]
        if ($members.Count -gt 1) { $cycleComponents++ }
        $internalTotal += $internalCounts[$c]
        $components.Add([ordered]@{
            strict_component_index = $c + 1
            original_member_caller_positions = $members
            original_member_position_bits = @($members | ForEach-Object { 1 -shl ($_ - 1) })
            contains_strict_directed_cycle = ($members.Count -gt 1)
            original_internal_strict_comparison_count = $internalCounts[$c]
            incoming_direct_component_count = $componentIn[$c]
            outgoing_direct_component_count = $componentOut[$c]
            longest_strict_dominance_predecessor_layer = $layer[$c]
        })
    }
    $reporters = [System.Collections.Generic.List[object]]::new()
    $sumCredits = [long]0
    $sumWins = 0
    $sumLosses = 0
    $sumTies = 0
    $sumNoEndpoint = 0
    for ($r = 0; $r -lt $N; $r++) {
        $node = $nodes[$r]
        if ($null -eq $node -or
            [int]$node.original_reporter_caller_position -ne $r + 1 -or
            [int]$node.original_reporter_position_bit -ne (1 -shl $r) -or
            [int]$node.original_distinct_endpoint_partner_count -ne $N - 1 -or
            [int]$node.original_pairs_with_more_endpoint_first_credit_than_partner -ne $wins[$r] -or
            [int]$node.original_pairs_with_less_endpoint_first_credit_than_partner -ne $losses[$r] -or
            [int]$node.original_pairs_with_equal_endpoint_first_credit -ne $ties[$r] -or
            [int]$node.original_pairs_with_no_endpoint_first_credit -ne $unsupportedTies[$r] -or
            [long]$node.first_restored_as_either_endpoint_across_partners -ne $credits[$r] -or
            [long]$node.first_restored_as_earlier_endpoint_across_partners +
                [long]$node.first_restored_as_later_endpoint_across_partners -ne $credits[$r] -or
            $wins[$r] + $losses[$r] + $ties[$r] -ne $N - 1 -or
            $componentOf[$r] -lt 1) {
            throw 'Code Sequence endpoint dominance topology contradicted an ORIGINAL EC-092 reporter node.'
        }
        $expectedShare = Get-CodeSequenceEndpointCreditConditionalShare -Credited $credits[$r] -EndpointFirst $endpointTotal
        $share = $node.exact_reduced_reporter_share_of_all_original_endpoint_first_credit
        if (($null -eq $expectedShare) -ne ($null -eq $share)) {
            throw 'Code Sequence endpoint dominance topology changed ORIGINAL reporter null share.'
        }
        if ($null -ne $expectedShare -and
            ([long]$expectedShare.numerator -ne [long]$share.numerator -or
             [long]$expectedShare.denominator -ne [long]$share.denominator)) {
            throw 'Code Sequence endpoint dominance topology altered reporter FIRST credit share.'
        }
        $reachable = [System.Collections.Generic.List[int]]::new()
        for ($q = 0; $q -lt $N; $q++) {
            if ($q -ne $r -and $reach[$r, $q]) { $reachable.Add($q + 1) }
        }
        $cid = $componentOf[$r] - 1
        $reporters.Add([ordered]@{
            original_reporter_caller_position = $r + 1
            original_reporter_position_bit = 1 -shl $r
            strict_component_index = $cid + 1
            longest_strict_dominance_predecessor_layer = $layer[$cid]
            direct_more_credit_partner_count = $wins[$r]
            direct_less_credit_partner_count = $losses[$r]
            direct_equal_credit_partner_count = $ties[$r]
            direct_no_endpoint_first_credit_partner_count = $unsupportedTies[$r]
            original_positions_reachable_by_one_or_more_strict_comparison_arcs = $reachable.ToArray()
            exact_distinct_other_reporters_reachable_by_strict_paths = $reachable.Count
            first_restored_as_endpoint_across_partners = $credits[$r]
        })
        $sumCredits += $credits[$r]
        $sumWins += $wins[$r]
        $sumLosses += $losses[$r]
        $sumTies += $ties[$r]
        $sumNoEndpoint += $unsupportedTies[$r]
    }
    if ($sumCredits -ne $endpointTotal -or $sumWins -ne $arcs.Count -or
        $sumLosses -ne $arcs.Count -or $sumTies -ne 2 * $equalEdges.Count -or
        $sumNoEndpoint -ne 2 * $noEndpointPairs -or
        $internalTotal + $externalStrictCount -ne $arcs.Count) {
        throw 'Code Sequence endpoint dominance topology lost edge/node/SCC conservation.'
    }
    return [ordered]@{
        original_positions_in_dominance_universe = $N
        exact_unordered_original_pair_count = $pairCount
        total_distinct_full_original_permutations = $full
        full_original_selection_has_saved_witness_support = [bool]$EndpointCreditGraph.full_original_selection_has_saved_witness_support
        original_direct_strict_credit_advantage_arcs = $arcs.ToArray()
        original_direct_equal_credit_pairs = $equalEdges.ToArray()
        original_reporter_strict_dominance_profiles = $reporters.ToArray()
        original_strict_dominance_components = $components.ToArray()
        original_condensed_strict_dominance_component_arcs = $componentLinks.ToArray()
        exact_direct_strict_advantage_count = $arcs.Count
        exact_direct_equal_credit_pair_count = $equalEdges.Count
        exact_equal_credit_pairs_with_no_endpoint_first = $noEndpointPairs
        exact_strongly_connected_component_count = $componentCount
        exact_nontrivial_strict_cycle_component_count = $cycleComponents
        exact_condensed_direct_component_arc_count = $componentLinks.Count
        exact_strict_dominance_source_component_count = $sourceComponents
        exact_maximum_longest_predecessor_layer = $maxLayer
        every_original_pair_has_exactly_one_strict_arc_or_equal_pair = $true
        equal_credit_pairs_are_not_treated_as_strict_paths_or_equivalence = $true
        strict_cycles_are_collapsed_without_fabricated_total_ranking = $true
        all_reporter_and_pair_first_credit_matches_checked_ec092 = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDominanceTopology {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointCreditGraph
    )
    if ($null -eq $RetentionPivotality -or $null -eq $RetentionEndpointCreditGraph -or
        -not [bool]$RetentionEndpointCreditGraph.only_consumed_checked_ec089_and_ec091_public_original_projections -or
        -not [bool]$RetentionEndpointCreditGraph.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionEndpointCreditGraph.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointCreditGraph.endpoint_credit_is_hypothetical_incidence_not_real_time_or_probability -or
        -not [bool]$RetentionEndpointCreditGraph.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence endpoint dominance topology requires the unchanged original saved-Finding selector and checked EC-092.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionEndpointCreditGraph.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionEndpointCreditGraph.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionEndpointCreditGraph.counts.original_unordered_pair_edges_per_target -ne ($n * ($n - 1) / 2) -or
        [int]$RetentionEndpointCreditGraph.counts.original_reporter_credit_nodes_per_target -ne $n -or
        [int]$RetentionEndpointCreditGraph.counts.original_gap_cases_per_pair_edge -ne $n - 1 -or
        [int]$RetentionEndpointCreditGraph.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
        [int]$RetentionEndpointCreditGraph.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
        [int]$RetentionEndpointCreditGraph.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
        [string]$RetentionEndpointCreditGraph.path -cne [string]$RetentionPivotality.path) {
        throw 'Code Sequence endpoint dominance topology changed ORIGINAL path/anchor/target provenance.'
    }
    $g = [object[]]$RetentionEndpointCreditGraph.genuine_global_threshold_endpoint_credit_graph
    $f = [object[]]$RetentionEndpointCreditGraph.frozen_global_threshold_endpoint_credit_graph
    $families = [object[]]$RetentionEndpointCreditGraph.individual_original_family_endpoint_credit_graph
    if ($g.Count -ne 3 -or $f.Count -ne 3 -or $families.Count -ne $familyCount) {
        throw 'Code Sequence endpoint dominance topology omitted genuine/frozen thresholds or original families.'
    }
    $gOut = [System.Collections.Generic.List[object]]::new()
    $fOut = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $sourceTargets = if ($mode -eq 0) { $g } else { $f }
        $output = if ($mode -eq 0) { $gOut } else { $fOut }
        for ($i = 0; $i -lt 3; $i++) {
            $source = $sourceTargets[$i]
            if ($null -eq $source -or [int]$source.original_global_family_capacity_at_least -ne 3 - $i) {
                throw 'Code Sequence endpoint dominance topology reindexed a genuine/frozen global threshold.'
            }
            $output.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$source.original_full_selection_global_family_capacity
                exact_original_endpoint_first_credit_strict_dominance_topology = `
                    (Get-CodeSequenceEndpointDominanceTopologyProjection `
                        -EndpointCreditGraph $source.exact_original_endpoint_first_credit_comparison_graph -N $n)
            })
        }
    }
    $familyOut = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $source = $families[$i]
        if ($null -eq $source -or [int]$source.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence endpoint dominance topology reindexed an original repeat family.'
        }
        $familyOut.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_endpoint_first_credit_strict_dominance_topology = `
                (Get-CodeSequenceEndpointDominanceTopologyProjection `
                    -EndpointCreditGraph $source.genuine_original_endpoint_first_credit_comparison_graph -N $n)
            frozen_original_endpoint_first_credit_strict_dominance_topology = `
                (Get-CodeSequenceEndpointDominanceTopologyProjection `
                    -EndpointCreditGraph $source.frozen_original_endpoint_first_credit_comparison_graph -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_original_endpoint_first_credit_strict_dominance_topology'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            original_reporter_nodes_per_target = $n
            genuine_original_global_thresholds = $gOut.Count
            frozen_original_global_thresholds = $fOut.Count
            individual_original_family_targets = $familyOut.Count
        }
        genuine_global_threshold_endpoint_dominance_topology = $gOut.ToArray()
        frozen_global_threshold_endpoint_dominance_topology = $fOut.ToArray()
        individual_original_family_endpoint_dominance_topology = $familyOut.ToArray()
        only_consumed_checked_ec092_public_original_endpoint_credit_graph = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        strict_comparison_paths_are_not_chronology_probability_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

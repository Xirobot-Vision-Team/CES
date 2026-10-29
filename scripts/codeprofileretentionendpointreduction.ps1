#requires -Version 7.0
<#
    EC-094: exact ORIGINAL strict endpoint-FIRST dominance condensation reduction.

    Read ONLY the already checked EC-093 strict-comparison topology. Audit its
    ORIGINAL caller/pair identities, strict/equal partition, endpoint FIRST
    incidence, strict reachability and SCC/condensation before doing any work.
    Find the unique transitive reduction of the *acyclic SCC condensation*,
    never of a possibly cyclic ORIGINAL reporter graph. For each dispensable
    direct SCC link, give the shortest, lexicographically first alternate
    component path and one actual original EC-089 pair index per path hop.

    A route is a graph proof, not additional saved support, an additive credit
    margin, authenticated chronology, model confidence or a repair ranking.
    No saved-record/quote/source/Git/network read, permutation, optimization
    or business write is permitted by this projection.
#>

function Get-CodeSequenceDominanceAlternativeComponentRoute {
    param(
        [int[,]] $LinkCounts,
        [int[,]] $FirstPairIndices,
        [int] $ComponentCount,
        [int] $SourceIndex,
        [int] $TargetIndex
    )
    # Breadth-first paths with ordered neighbors: shortest path first, and
    # lexicographically smallest component-index sequence for equal lengths.
    # The requested direct edge is excluded for the ENTIRE traversal.
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([ordered]@{
        component_indices = [int[]]@($SourceIndex + 1)
        original_pair_indices = [int[]]@()
    })
    $seen = [bool[]]::new($ComponentCount)
    $seen[$SourceIndex] = $true
    while ($queue.Count -gt 0) {
        $state = $queue.Dequeue()
        $route = [int[]]$state.component_indices
        $pairIds = [int[]]$state.original_pair_indices
        $current = $route[$route.Length - 1] - 1
        for ($next = 0; $next -lt $ComponentCount; $next++) {
            if ($LinkCounts[$current, $next] -eq 0 -or
                ($current -eq $SourceIndex -and $next -eq $TargetIndex) -or
                $seen[$next]) { continue }
            if ($FirstPairIndices[$current, $next] -lt 1) {
                throw 'Code Sequence dominance reduction has an unproven component route hop.'
            }
            $nextRoute = [int[]](@($route) + @($next + 1))
            $nextPairIds = [int[]](@($pairIds) + @($FirstPairIndices[$current, $next]))
            if ($next -eq $TargetIndex) {
                if ($nextRoute.Length -lt 3 -or $nextPairIds.Length -ne $nextRoute.Length - 1) {
                    throw 'Code Sequence dominance reduction fabricated an alternate direct-link route.'
                }
                return [ordered]@{
                    original_component_indices = $nextRoute
                    original_ec089_pair_index_witness_per_hop = $nextPairIds
                    exact_alternative_component_hop_count = $nextPairIds.Length
                }
            }
            $seen[$next] = $true
            $queue.Enqueue([ordered]@{
                component_indices = $nextRoute
                original_pair_indices = $nextPairIds
            })
        }
    }
    return $null
}

function Get-CodeSequenceEndpointDominanceReductionProjection {
    param(
        [object] $DominanceTopology,
        [int] $N
    )
    if ($null -eq $DominanceTopology -or $N -lt 2 -or $N -gt 12 -or
        -not [bool]$DominanceTopology.every_original_pair_has_exactly_one_strict_arc_or_equal_pair -or
        -not [bool]$DominanceTopology.equal_credit_pairs_are_not_treated_as_strict_paths_or_equivalence -or
        -not [bool]$DominanceTopology.strict_cycles_are_collapsed_without_fabricated_total_ranking -or
        -not [bool]$DominanceTopology.all_reporter_and_pair_first_credit_matches_checked_ec092 -or
        -not [bool]$DominanceTopology.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence dominance reduction requires a checked EC-093 ORIGINAL strict topology.'
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorials[$N]
    $pairCount = [int]($N * ($N - 1) / 2)
    $strictArcs = [object[]]$DominanceTopology.original_direct_strict_credit_advantage_arcs
    $equalPairs = [object[]]$DominanceTopology.original_direct_equal_credit_pairs
    $profiles = [object[]]$DominanceTopology.original_reporter_strict_dominance_profiles
    $components = [object[]]$DominanceTopology.original_strict_dominance_components
    $links = [object[]]$DominanceTopology.original_condensed_strict_dominance_component_arcs
    $componentCount = $components.Length
    if ([int]$DominanceTopology.original_positions_in_dominance_universe -ne $N -or
        [int]$DominanceTopology.exact_unordered_original_pair_count -ne $pairCount -or
        [long]$DominanceTopology.total_distinct_full_original_permutations -ne $full -or
        $strictArcs.Length + $equalPairs.Length -ne $pairCount -or
        $strictArcs.Length -ne [int]$DominanceTopology.exact_direct_strict_advantage_count -or
        $equalPairs.Length -ne [int]$DominanceTopology.exact_direct_equal_credit_pair_count -or
        $profiles.Length -ne $N -or $componentCount -lt 1 -or $componentCount -gt $N -or
        $componentCount -ne [int]$DominanceTopology.exact_strongly_connected_component_count -or
        $links.Length -ne [int]$DominanceTopology.exact_condensed_direct_component_arc_count) {
        throw 'Code Sequence dominance reduction received the wrong ORIGINAL graph universe.'
    }

    # Canonical EC-089 a<b pair indices are shared by strict arcs AND equal
    # pairs; there is exactly one entry per pair. Independently reconstruct
    # both report endpoint credit ledgers, not just the parent's flags.
    $pairA = [int[]]::new($pairCount + 1)
    $pairB = [int[]]::new($pairCount + 1)
    $index = 0
    for ($a = 1; $a -le $N; $a++) {
        for ($b = $a + 1; $b -le $N; $b++) {
            $index++
            $pairA[$index] = $a
            $pairB[$index] = $b
        }
    }
    $pairSeen = [bool[]]::new($pairCount + 1)
    $reach = [bool[,]]::new($N, $N)
    $wins = [int[]]::new($N)
    $losses = [int[]]::new($N)
    $ties = [int[]]::new($N)
    $zeroTies = [int[]]::new($N)
    $credits = [long[]]::new($N)
    for ($p = 0; $p -lt $N; $p++) { $reach[$p, $p] = $true }
    $totalCredit = [long]0
    $previousIndex = 0
    foreach ($arc in $strictArcs) {
        if ($null -eq $arc) { throw 'Code Sequence dominance reduction received a null strict arc.' }
        $pairIndex = [int]$arc.original_unordered_pair_index_in_ec089
        $w = [int]$arc.original_winner_caller_position
        $l = [int]$arc.original_loser_caller_position
        $wc = [long]$arc.winner_endpoint_first_credit
        $lc = [long]$arc.loser_endpoint_first_credit
        if ($pairIndex -le $previousIndex -or $pairIndex -lt 1 -or $pairIndex -gt $pairCount -or
            $pairSeen[$pairIndex] -or $w -lt 1 -or $w -gt $N -or $l -lt 1 -or $l -gt $N -or $w -eq $l -or
            -not (($w -eq $pairA[$pairIndex] -and $l -eq $pairB[$pairIndex]) -or
                  ($w -eq $pairB[$pairIndex] -and $l -eq $pairA[$pairIndex])) -or
            [int]$arc.original_winner_position_bit -ne (1 -shl ($w - 1)) -or
            [int]$arc.original_loser_position_bit -ne (1 -shl ($l - 1)) -or
            $wc -le $lc -or $lc -lt 0 -or $wc + $lc -gt $full -or
            [long]$arc.exact_strict_winner_minus_loser_first_credit_count -ne ($wc - $lc)) {
            throw 'Code Sequence dominance reduction rejected a forged ORIGINAL strict pair/credit identity.'
        }
        $previousIndex = $pairIndex
        $pairSeen[$pairIndex] = $true
        $wins[$w - 1]++
        $losses[$l - 1]++
        $credits[$w - 1] += $wc
        $credits[$l - 1] += $lc
        $totalCredit += $wc + $lc
        $reach[$w - 1, $l - 1] = $true
    }
    $previousIndex = 0
    $zeroPairCount = 0
    foreach ($pair in $equalPairs) {
        if ($null -eq $pair) { throw 'Code Sequence dominance reduction received a null equal pair.' }
        $pairIndex = [int]$pair.original_unordered_pair_index_in_ec089
        $v = [long]$pair.exact_first_credit_per_original_endpoint
        if ($pairIndex -le $previousIndex -or $pairIndex -lt 1 -or $pairIndex -gt $pairCount -or
            $pairSeen[$pairIndex] -or
            [int]$pair.original_report_a_caller_position -ne $pairA[$pairIndex] -or
            [int]$pair.original_report_b_caller_position -ne $pairB[$pairIndex] -or
            $v -lt 0 -or $v * 2 -gt $full -or
            [bool]$pair.neither_endpoint_received_first_credit -ne ($v -eq 0)) {
            throw 'Code Sequence dominance reduction rejected a forged equal or 0/0 ORIGINAL pair.'
        }
        $previousIndex = $pairIndex
        $pairSeen[$pairIndex] = $true
        $a = $pairA[$pairIndex] - 1
        $b = $pairB[$pairIndex] - 1
        $ties[$a]++
        $ties[$b]++
        $credits[$a] += $v
        $credits[$b] += $v
        $totalCredit += 2 * $v
        if ($v -eq 0) {
            $zeroPairCount++
            $zeroTies[$a]++
            $zeroTies[$b]++
        }
    }
    for ($pairIndex = 1; $pairIndex -le $pairCount; $pairIndex++) {
        if (-not $pairSeen[$pairIndex]) {
            throw 'Code Sequence dominance reduction omitted an ORIGINAL unordered pair.'
        }
    }
    if ($zeroPairCount -ne [int]$DominanceTopology.exact_equal_credit_pairs_with_no_endpoint_first -or
        $totalCredit -gt [long]$pairCount * $full -or
        (-not [bool]$DominanceTopology.full_original_selection_has_saved_witness_support -and $totalCredit -ne 0)) {
        throw 'Code Sequence dominance reduction attributed FIRST credit to an unsupported ORIGINAL target.'
    }

    # Recompute directed closure and the unique min-caller-position SCC
    # partition. Merely trusting supplied parent SCC labels could silently
    # make an essential edge look dispensable, so this is deliberately strict.
    for ($k = 0; $k -lt $N; $k++) {
        for ($i = 0; $i -lt $N; $i++) {
            if (-not $reach[$i, $k]) { continue }
            for ($j = 0; $j -lt $N; $j++) {
                if ($reach[$k, $j]) { $reach[$i, $j] = $true }
            }
        }
    }
    $componentOf = [int[]]::new($N)
    $expectedMembers = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $N; $i++) {
        if ($componentOf[$i] -ne 0) { continue }
        $members = [System.Collections.Generic.List[int]]::new()
        $id = $expectedMembers.Count + 1
        for ($j = 0; $j -lt $N; $j++) {
            if ($reach[$i, $j] -and $reach[$j, $i]) {
                if ($componentOf[$j] -ne 0) {
                    throw 'Code Sequence dominance reduction found overlapping strict SCCs.'
                }
                $componentOf[$j] = $id
                $members.Add($j + 1)
            }
        }
        $expectedMembers.Add([int[]]$members.ToArray())
    }
    if ($expectedMembers.Count -ne $componentCount) {
        throw 'Code Sequence dominance reduction found incorrect parent SCC membership.'
    }
    $cycleCount = 0
    for ($c = 0; $c -lt $componentCount; $c++) {
        $members = [int[]]$expectedMembers[$c]
        $parentComponent = $components[$c]
        $bits = [System.Collections.Generic.List[int]]::new()
        foreach ($p in $members) { $bits.Add((1 -shl ($p - 1))) }
        if ($null -eq $parentComponent -or
            [int]$parentComponent.strict_component_index -ne $c + 1 -or
            (([int[]]$parentComponent.original_member_caller_positions) -join ',') -cne ($members -join ',') -or
            (([int[]]$parentComponent.original_member_position_bits) -join ',') -cne ($bits.ToArray() -join ',') -or
            [bool]$parentComponent.contains_strict_directed_cycle -ne ($members.Length -gt 1)) {
            throw 'Code Sequence dominance reduction changed strict SCC identity/cycle status.'
        }
        if ($members.Length -gt 1) { $cycleCount++ }
    }
    if ($cycleCount -ne [int]$DominanceTopology.exact_nontrivial_strict_cycle_component_count) {
        throw 'Code Sequence dominance reduction omitted a strict cyclic component.'
    }

    $linkCounts = [int[,]]::new($componentCount, $componentCount)
    $linkMargins = [long[,]]::new($componentCount, $componentCount)
    $linkPairs = @{}
    $internalCounts = [int[]]::new($componentCount)
    $crossArcCount = 0
    foreach ($arc in $strictArcs) {
        $src = $componentOf[[int]$arc.original_winner_caller_position - 1] - 1
        $dst = $componentOf[[int]$arc.original_loser_caller_position - 1] - 1
        if ($src -eq $dst) { $internalCounts[$src]++; continue }
        if ($reach[[int]$arc.original_loser_caller_position - 1, [int]$arc.original_winner_caller_position - 1]) {
            throw 'Code Sequence dominance reduction split a strict directed cycle.'
        }
        $crossArcCount++
        $linkCounts[$src, $dst]++
        $linkMargins[$src, $dst] += [long]$arc.exact_strict_winner_minus_loser_first_credit_count
        $key = "$src/$dst"
        if (-not $linkPairs.ContainsKey($key)) { $linkPairs[$key] = [System.Collections.Generic.List[int]]::new() }
        $linkPairs[$key].Add([int]$arc.original_unordered_pair_index_in_ec089)
    }
    $incoming = [int[]]::new($componentCount)
    $outgoing = [int[]]::new($componentCount)
    $firstPairs = [int[,]]::new($componentCount, $componentCount)
    $originalLinks = [System.Collections.Generic.List[object]]::new()
    $nextLink = 0
    $totalCrossMargin = [long]0
    for ($src = 0; $src -lt $componentCount; $src++) {
        for ($dst = 0; $dst -lt $componentCount; $dst++) {
            if ($linkCounts[$src, $dst] -eq 0) { continue }
            if ($src -eq $dst -or $nextLink -ge $links.Length) {
                throw 'Code Sequence dominance reduction received a non-DAG/extra parent component link.'
            }
            $parentLink = $links[$nextLink]
            $nextLink++
            $pairIndices = [int[]]$linkPairs["$src/$dst"].ToArray()
            if ($null -eq $parentLink -or
                [int]$parentLink.dominant_component_index -ne $src + 1 -or
                [int]$parentLink.subordinate_component_index -ne $dst + 1 -or
                [int]$parentLink.original_direct_strict_comparison_count -ne $linkCounts[$src, $dst] -or
                [long]$parentLink.exact_sum_of_strict_first_credit_advantages -ne $linkMargins[$src, $dst] -or
                (([int[]]$parentLink.original_ec089_unordered_pair_indices) -join ',') -cne ($pairIndices -join ',')) {
                throw 'Code Sequence dominance reduction received a forged condensed link/pair margin.'
            }
            $incoming[$dst]++
            $outgoing[$src]++
            $totalCrossMargin += $linkMargins[$src, $dst]
            $firstPairs[$src, $dst] = $pairIndices[0]
            $originalLinks.Add([ordered]@{
                dominant_component_index = $src + 1
                subordinate_component_index = $dst + 1
                original_direct_strict_comparison_count = $linkCounts[$src, $dst]
                exact_sum_of_direct_strict_first_credit_advantages = $linkMargins[$src, $dst]
                original_ec089_unordered_pair_indices = $pairIndices
            })
        }
    }
    $totalInternal = 0
    foreach ($count in $internalCounts) { $totalInternal += $count }
    if ($nextLink -ne $links.Length -or
        $crossArcCount + $totalInternal -ne $strictArcs.Length) {
        throw 'Code Sequence dominance reduction lost direct ORIGINAL strict comparisons.'
    }

    # Independently verify original longest-predecessor DAG layering and
    # ORIGINAL reporter strict reachability from direct comparison arcs.
    $remaining = [int[]]$incoming.Clone()
    $visited = [bool[]]::new($componentCount)
    $layers = [int[]]::new($componentCount)
    $maxLayer = 0
    $sourceCount = 0
    for ($c = 0; $c -lt $componentCount; $c++) { if ($incoming[$c] -eq 0) { $sourceCount++ } }
    for ($step = 0; $step -lt $componentCount; $step++) {
        $next = -1
        for ($c = 0; $c -lt $componentCount; $c++) {
            if (-not $visited[$c] -and $remaining[$c] -eq 0) { $next = $c; break }
        }
        if ($next -lt 0) { throw 'Code Sequence dominance reduction received a cyclic condensation graph.' }
        $visited[$next] = $true
        if ($layers[$next] -gt $maxLayer) { $maxLayer = $layers[$next] }
        for ($dst = 0; $dst -lt $componentCount; $dst++) {
            if ($linkCounts[$next, $dst] -eq 0) { continue }
            $candidate = $layers[$next] + 1
            if ($candidate -gt $layers[$dst]) { $layers[$dst] = $candidate }
            $remaining[$dst]--
            if ($remaining[$dst] -lt 0) { throw 'Code Sequence dominance reduction double-decremented a DAG link.' }
        }
    }
    if ($sourceCount -ne [int]$DominanceTopology.exact_strict_dominance_source_component_count -or
        $maxLayer -ne [int]$DominanceTopology.exact_maximum_longest_predecessor_layer) {
        throw 'Code Sequence dominance reduction changed original source SCCs or DAG layers.'
    }
    for ($c = 0; $c -lt $componentCount; $c++) {
        $parentComponent = $components[$c]
        if ([int]$parentComponent.original_internal_strict_comparison_count -ne $internalCounts[$c] -or
            [int]$parentComponent.incoming_direct_component_count -ne $incoming[$c] -or
            [int]$parentComponent.outgoing_direct_component_count -ne $outgoing[$c] -or
            [int]$parentComponent.longest_strict_dominance_predecessor_layer -ne $layers[$c]) {
            throw 'Code Sequence dominance reduction altered a parent SCC arc ledger or layer.'
        }
    }
    $sumCredits = [long]0
    $sumWins = 0
    $sumLosses = 0
    $sumTies = 0
    $sumZeroTies = 0
    for ($r = 0; $r -lt $N; $r++) {
        $profile = $profiles[$r]
        $reachable = [System.Collections.Generic.List[int]]::new()
        for ($q = 0; $q -lt $N; $q++) {
            if ($q -ne $r -and $reach[$r, $q]) { $reachable.Add($q + 1) }
        }
        if ($null -eq $profile -or
            [int]$profile.original_reporter_caller_position -ne $r + 1 -or
            [int]$profile.original_reporter_position_bit -ne (1 -shl $r) -or
            [int]$profile.strict_component_index -ne $componentOf[$r] -or
            [int]$profile.longest_strict_dominance_predecessor_layer -ne $layers[$componentOf[$r] - 1] -or
            [int]$profile.direct_more_credit_partner_count -ne $wins[$r] -or
            [int]$profile.direct_less_credit_partner_count -ne $losses[$r] -or
            [int]$profile.direct_equal_credit_partner_count -ne $ties[$r] -or
            [int]$profile.direct_no_endpoint_first_credit_partner_count -ne $zeroTies[$r] -or
            [long]$profile.first_restored_as_endpoint_across_partners -ne $credits[$r] -or
            [int]$profile.exact_distinct_other_reporters_reachable_by_strict_paths -ne $reachable.Count -or
            (([int[]]$profile.original_positions_reachable_by_one_or_more_strict_comparison_arcs) -join ',') -cne ($reachable.ToArray() -join ',') -or
            $wins[$r] + $losses[$r] + $ties[$r] -ne $N - 1) {
            throw 'Code Sequence dominance reduction contradicted ORIGINAL EC-093 reporter path/credit.'
        }
        $sumCredits += $credits[$r]
        $sumWins += $wins[$r]
        $sumLosses += $losses[$r]
        $sumTies += $ties[$r]
        $sumZeroTies += $zeroTies[$r]
    }
    if ($sumCredits -ne $totalCredit -or $sumWins -ne $strictArcs.Length -or
        $sumLosses -ne $strictArcs.Length -or $sumTies -ne 2 * $equalPairs.Length -or
        $sumZeroTies -ne 2 * $zeroPairCount) {
        throw 'Code Sequence dominance reduction lost the complete ORIGINAL reporter credit ledger.'
    }

    # Compute the unique DAG transitive reduction, with reproducible alternate
    # proof routes for discarded direct links. Credit *margins* live on the
    # original direct links; they must never be summed along an alternate path.
    $reduced = [bool[,]]::new($componentCount, $componentCount)
    $reducedCounts = [int[,]]::new($componentCount, $componentCount)
    $allReach = [bool[,]]::new($componentCount, $componentCount)
    for ($c = 0; $c -lt $componentCount; $c++) { $allReach[$c, $c] = $true }
    for ($src = 0; $src -lt $componentCount; $src++) {
        for ($dst = 0; $dst -lt $componentCount; $dst++) {
            if ($linkCounts[$src, $dst] -gt 0) { $allReach[$src, $dst] = $true }
        }
    }
    for ($k = 0; $k -lt $componentCount; $k++) {
        for ($i = 0; $i -lt $componentCount; $i++) {
            if (-not $allReach[$i, $k]) { continue }
            for ($j = 0; $j -lt $componentCount; $j++) {
                if ($allReach[$k, $j]) { $allReach[$i, $j] = $true }
            }
        }
    }
    $essentialIn = [int[]]::new($componentCount)
    $essentialOut = [int[]]::new($componentCount)
    $essentialCount = 0
    $redundantCount = 0
    $essentialArcs = 0
    $redundantArcs = 0
    $essentialMargin = [long]0
    $redundantMargin = [long]0
    foreach ($link in $originalLinks) {
        $src = [int]$link.dominant_component_index - 1
        $dst = [int]$link.subordinate_component_index - 1
        $alternative = Get-CodeSequenceDominanceAlternativeComponentRoute `
            -LinkCounts $linkCounts -FirstPairIndices $firstPairs `
            -ComponentCount $componentCount -SourceIndex $src -TargetIndex $dst
        $indispensable = ($null -eq $alternative)
        if ($indispensable) {
            $essentialCount++
            $essentialArcs += [int]$link.original_direct_strict_comparison_count
            $essentialMargin += [long]$link.exact_sum_of_direct_strict_first_credit_advantages
            $essentialIn[$dst]++
            $essentialOut[$src]++
            $reduced[$src, $dst] = $true
            $reducedCounts[$src, $dst] = 1
        } else {
            $redundantCount++
            $redundantArcs += [int]$link.original_direct_strict_comparison_count
            $redundantMargin += [long]$link.exact_sum_of_direct_strict_first_credit_advantages
        }
    }
    if ($essentialCount + $redundantCount -ne $links.Length -or
        $essentialArcs + $redundantArcs -ne $crossArcCount -or
        $essentialMargin + $redundantMargin -ne $totalCrossMargin) {
        throw 'Code Sequence dominance reduction failed direct-link credit conservation.'
    }
    $reducedReach = [bool[,]]::new($componentCount, $componentCount)
    for ($i = 0; $i -lt $componentCount; $i++) {
        for ($j = 0; $j -lt $componentCount; $j++) {
            $reducedReach[$i, $j] = ($i -eq $j -or $reduced[$i, $j])
        }
    }
    for ($k = 0; $k -lt $componentCount; $k++) {
        for ($i = 0; $i -lt $componentCount; $i++) {
            if (-not $reducedReach[$i, $k]) { continue }
            for ($j = 0; $j -lt $componentCount; $j++) {
                if ($reducedReach[$k, $j]) { $reducedReach[$i, $j] = $true }
            }
        }
    }
    # Witnesses must use ONLY the links actually retained by the unique
    # reduction. A path relying on another discarded link would not itself
    # certify the delivered reduced graph. BFS fixes both shortest length
    # and lexical tie breaking, with an existing EC-089 pair ID at each hop.
    $linkResults = [System.Collections.Generic.List[object]]::new()
    foreach ($link in $originalLinks) {
        $src = [int]$link.dominant_component_index - 1
        $dst = [int]$link.subordinate_component_index - 1
        $indispensable = $reduced[$src, $dst]
        $alternative = $null
        if (-not $indispensable) {
            $alternative = Get-CodeSequenceDominanceAlternativeComponentRoute `
                -LinkCounts $reducedCounts -FirstPairIndices $firstPairs `
                -ComponentCount $componentCount -SourceIndex $src -TargetIndex $dst
            if ($null -eq $alternative) {
                throw 'Code Sequence dominance reduction cannot witness a discarded direct link in the retained DAG.'
            }
        }
        $linkResults.Add([ordered]@{
            dominant_component_index = $src + 1
            subordinate_component_index = $dst + 1
            original_direct_strict_comparison_count = [int]$link.original_direct_strict_comparison_count
            exact_sum_of_direct_strict_first_credit_advantages = [long]$link.exact_sum_of_direct_strict_first_credit_advantages
            original_ec089_unordered_pair_indices = [int[]]$link.original_ec089_unordered_pair_indices
            indispensable_for_original_strict_component_reachability = $indispensable
            shortest_lexicographic_alternative_component_route = $alternative
        })
    }
    $componentResults = [System.Collections.Generic.List[object]]::new()
    $sinkCount = 0
    for ($c = 0; $c -lt $componentCount; $c++) {
        if ($outgoing[$c] -eq 0) { $sinkCount++ }
        $descendants = [System.Collections.Generic.List[int]]::new()
        $ancestors = [System.Collections.Generic.List[int]]::new()
        $reachableOriginal = [System.Collections.Generic.List[int]]::new()
        for ($d = 0; $d -lt $componentCount; $d++) {
            if ($allReach[$c, $d] -ne $reducedReach[$c, $d]) {
                throw 'Code Sequence dominance reduction lost a strict SCC path.'
            }
            if ($c -ne $d -and $allReach[$c, $d]) {
                if ($allReach[$d, $c]) { throw 'Code Sequence dominance reduction found a condensation cycle.' }
                $descendants.Add($d + 1)
            }
            if ($c -ne $d -and $allReach[$d, $c]) { $ancestors.Add($d + 1) }
        }
        for ($p = 0; $p -lt $N; $p++) {
            $other = $componentOf[$p] - 1
            if ($c -ne $other -and $allReach[$c, $other]) { $reachableOriginal.Add($p + 1) }
        }
        $componentResults.Add([ordered]@{
            strict_component_index = $c + 1
            original_member_caller_positions = [int[]]$expectedMembers[$c]
            original_member_position_bits = [int[]]$components[$c].original_member_position_bits
            longest_strict_dominance_predecessor_layer = $layers[$c]
            source_component = ($incoming[$c] -eq 0)
            sink_component = ($outgoing[$c] -eq 0)
            incoming_indispensable_component_link_count = $essentialIn[$c]
            outgoing_indispensable_component_link_count = $essentialOut[$c]
            reachable_other_component_indices = $descendants.ToArray()
            exact_reachable_other_component_count = $descendants.Count
            ancestor_other_component_indices = $ancestors.ToArray()
            exact_ancestor_other_component_count = $ancestors.Count
            reachable_original_reporter_positions_outside_component = $reachableOriginal.ToArray()
        })
    }
    return [ordered]@{
        original_positions_in_reduction_universe = $N
        exact_unordered_original_pair_count = $pairCount
        total_distinct_full_original_permutations = $full
        full_original_selection_has_saved_witness_support = [bool]$DominanceTopology.full_original_selection_has_saved_witness_support
        exact_original_strict_direct_comparison_count = $strictArcs.Length
        exact_original_equal_credit_pair_count = $equalPairs.Length
        exact_original_equal_pairs_without_endpoint_first = $zeroPairCount
        exact_strongly_connected_component_count = $componentCount
        exact_original_condensed_direct_component_link_count = $links.Length
        exact_indispensable_condensed_direct_component_link_count = $essentialCount
        exact_redundant_condensed_direct_component_link_count = $redundantCount
        exact_original_cross_component_strict_comparison_count = $crossArcCount
        exact_indispensable_link_underlying_direct_comparison_count = $essentialArcs
        exact_redundant_link_underlying_direct_comparison_count = $redundantArcs
        exact_total_cross_component_direct_credit_advantage = $totalCrossMargin
        exact_indispensable_link_direct_credit_advantage = $essentialMargin
        exact_redundant_link_direct_credit_advantage = $redundantMargin
        exact_source_component_count = $sourceCount
        exact_sink_component_count = $sinkCount
        original_condensed_component_link_reduction = $linkResults.ToArray()
        original_component_reachability_after_reduction = $componentResults.ToArray()
        every_original_strict_component_path_is_preserved = $true
        each_discarded_direct_link_has_shortest_deterministic_alternative_with_original_pair_witnesses = $true
        no_equal_pair_or_no_first_credit_is_used_as_a_strict_route = $true
        original_direct_credit_advantages_are_not_summed_along_alternative_paths = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDominanceReduction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology
    )
    if ($null -eq $RetentionPivotality -or $null -eq $RetentionEndpointDominanceTopology -or
        -not [bool]$RetentionEndpointDominanceTopology.only_consumed_checked_ec092_public_original_endpoint_credit_graph -or
        -not [bool]$RetentionEndpointDominanceTopology.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionEndpointDominanceTopology.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointDominanceTopology.strict_comparison_paths_are_not_chronology_probability_or_repair_priority -or
        -not [bool]$RetentionEndpointDominanceTopology.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence dominance reduction requires the successful ORIGINAL selector and checked EC-093 topology.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionEndpointDominanceTopology.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionEndpointDominanceTopology.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionEndpointDominanceTopology.counts.original_unordered_pair_comparisons_per_target -ne ($n * ($n - 1) / 2) -or
        [int]$RetentionEndpointDominanceTopology.counts.original_reporter_nodes_per_target -ne $n -or
        [int]$RetentionEndpointDominanceTopology.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
        [int]$RetentionEndpointDominanceTopology.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
        [int]$RetentionEndpointDominanceTopology.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
        [string]$RetentionEndpointDominanceTopology.path -cne [string]$RetentionPivotality.path) {
        throw 'Code Sequence dominance reduction changed original pair/path/anchor/target provenance.'
    }
    $genuine = [object[]]$RetentionEndpointDominanceTopology.genuine_global_threshold_endpoint_dominance_topology
    $frozen = [object[]]$RetentionEndpointDominanceTopology.frozen_global_threshold_endpoint_dominance_topology
    $families = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    if ($genuine.Length -ne 3 -or $frozen.Length -ne 3 -or $families.Length -ne $familyCount) {
        throw 'Code Sequence dominance reduction lost genuine/frozen thresholds or ORIGINAL families.'
    }
    $genuineOutput = [System.Collections.Generic.List[object]]::new()
    $frozenOutput = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $targets = if ($mode -eq 0) { $genuine } else { $frozen }
        $output = if ($mode -eq 0) { $genuineOutput } else { $frozenOutput }
        for ($t = 0; $t -lt 3; $t++) {
            $source = $targets[$t]
            if ($null -eq $source -or [int]$source.original_global_family_capacity_at_least -ne 3 - $t) {
                throw 'Code Sequence dominance reduction reindexed an ORIGINAL threshold.'
            }
            $output.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $t
                original_full_selection_global_family_capacity = [int]$source.original_full_selection_global_family_capacity
                exact_original_strict_condensation_transitive_reduction = `
                    (Get-CodeSequenceEndpointDominanceReductionProjection `
                        -DominanceTopology $source.exact_original_endpoint_first_credit_strict_dominance_topology -N $n)
            })
        }
    }
    $familyOutput = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $source = $families[$i]
        if ($null -eq $source -or [int]$source.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence dominance reduction reindexed an ORIGINAL repeat family.'
        }
        $familyOutput.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_strict_condensation_transitive_reduction = `
                (Get-CodeSequenceEndpointDominanceReductionProjection `
                    -DominanceTopology $source.genuine_original_endpoint_first_credit_strict_dominance_topology -N $n)
            frozen_original_strict_condensation_transitive_reduction = `
                (Get-CodeSequenceEndpointDominanceReductionProjection `
                    -DominanceTopology $source.frozen_original_endpoint_first_credit_strict_dominance_topology -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_original_strict_condensation_transitive_reduction_with_pair_witnesses'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            genuine_original_global_thresholds = $genuineOutput.Count
            frozen_original_global_thresholds = $frozenOutput.Count
            individual_original_family_targets = $familyOutput.Count
        }
        genuine_global_threshold_endpoint_dominance_reduction = $genuineOutput.ToArray()
        frozen_global_threshold_endpoint_dominance_reduction = $frozenOutput.ToArray()
        individual_original_family_endpoint_dominance_reduction = $familyOutput.ToArray()
        only_consumed_checked_ec093_public_original_strict_topology = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        component_route_witnesses_are_not_credit_addition_real_time_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

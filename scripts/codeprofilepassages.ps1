#requires -Version 7.0
<#
    EC-053: all canonical saved-anchor position pairs partitioned by the
    ORDERED histogram class at their caller-left and caller-right endpoints.
    Unlike abstract graph reachability, every witness is one ACTUAL contiguous
    span of the supplied caller-position sequence, reconstructed only from
    the already checked EC-043 pair ledger and EC-052 adjacent-step graph.
    Neither position order nor a matched histogram is real defect history.
#>

function New-CodeSequenceObservedProfilePassageWitness {
    param(
        [object] $Pair,
        [object] $Graph,
        [int[]] $ClassAt,
        [object] $SelectedAnchor
    )
    $start = [int]$Pair.from_position
    $finish = [int]$Pair.to_position
    if ($start -lt 1 -or $finish -gt $ClassAt.Length -or $start -ge $finish -or
        [int]$Pair.ec043_pair_index -lt 1 -or
        [int]$Pair.ec043_pair_index -gt $SelectedAnchor.compared_pairs.Count) {
        throw 'Code Sequence observed profile passage has an invalid endpoint span.'
    }
    $classWalk = [System.Collections.Generic.List[int]]::new()
    $stepWalk = [System.Collections.Generic.List[int]]::new()
    $edgeWalk = [System.Collections.Generic.List[int]]::new()
    $adjacentPairWalk = [System.Collections.Generic.List[int]]::new()
    for ($p = $start; $p -le $finish; $p++) {
        $classWalk.Add($ClassAt[$p - 1])
        if ($p -lt $finish) {
            $step = $Graph.adjacent_step_edges[$p - 1]
            $edgeIndex = [int]$step.directed_edge_index
            if ([int]$step.step_index -ne $p -or
                [int]$step.from_position -ne $p -or
                [int]$step.to_position -ne $p + 1 -or
                [int]$step.from_profile_class_index -ne $ClassAt[$p - 1] -or
                [int]$step.to_profile_class_index -ne $ClassAt[$p] -or
                $edgeIndex -lt 1 -or $edgeIndex -gt $Graph.directed_edges.Count -or
                [int]$Graph.directed_edges[$edgeIndex - 1].from_profile_class_index -ne $ClassAt[$p - 1] -or
                [int]$Graph.directed_edges[$edgeIndex - 1].to_profile_class_index -ne $ClassAt[$p] -or
                -not ($Graph.directed_edges[$edgeIndex - 1].step_indices -contains $p)) {
                throw 'Code Sequence observed profile passage is not a real adjacent class-edge walk.'
            }
            $stepWalk.Add($p)
            $edgeWalk.Add($edgeIndex)
            $adjacentPairWalk.Add([int]$step.ec043_pair_index)
        }
    }
    $direct = $SelectedAnchor.compared_pairs[[int]$Pair.ec043_pair_index - 1]
    if ([int]$direct.left_position -ne $start -or
        [int]$direct.right_position -ne $finish -or
        $direct.left_record_id -cne $Pair.from_record_id -or
        $direct.right_record_id -cne $Pair.to_record_id -or
        $direct.anchor_pair_class -cne $Pair.saved_anchor_pair_class -or
        [bool]$direct.shared_with_internal_unreported_position -ne
            [bool]$Pair.direct_pair_has_internal_unreported_gap) {
        throw 'Code Sequence observed profile passage has an inconsistent direct EC-043 pair.'
    }
    return [ordered]@{
        from_position = $start
        to_position = $finish
        from_record_id = [string]$Pair.from_record_id
        to_record_id = [string]$Pair.to_record_id
        from_profile_class_index = [int]$Pair.from_profile_class_index
        to_profile_class_index = [int]$Pair.to_profile_class_index
        adjacent_hop_count = $finish - $start
        class_walk = $classWalk.ToArray()
        adjacent_step_indices = $stepWalk.ToArray()
        directed_edge_index_walk = $edgeWalk.ToArray()
        ec043_adjacent_pair_index_walk = $adjacentPairWalk.ToArray()
        ec043_direct_pair_index = [int]$Pair.ec043_pair_index
        ec043_direct_pair_class = [string]$Pair.saved_anchor_pair_class
        direct_pair_has_internal_unreported_gap = [bool]$Pair.direct_pair_has_internal_unreported_gap
        distinct_intervening_third_profile_class_count = [int]$Pair.distinct_intervening_third_profile_class_count
        crosses_other_class_between_equal_endpoints = [bool]$Pair.crosses_other_class_between_equal_endpoints
        closest_previous_same_class_run_return_index = $Pair.closest_previous_same_class_run_return_index
    }
}

function Get-CodeSequenceOriginalFindingPairProfilePassages {
    param(
        [object] $Atlas,
        [object] $Graph,
        [object] $SelectedAnchor
    )
    if ($null -eq $Atlas -or $null -eq $Graph -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence observed profile passages require the validated atlas, graph and pair ledger.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $classCount = [int]$Atlas.counts.distinct_saved_profile_class_count
    $pairCount = [int](($n * ($n - 1)) / 2)
    $severities = @('critical', 'high', 'medium', 'low', 'info')
    if ($Atlas.scope -cne 'complete_saved_quote_anchor_five_severity_histogram_classes_adjacent_transitions_and_returns_for_two_independent_original_Findings' -or
        $Graph.scope -cne 'complete_directed_saved_profile_class_transition_multigraph_and_prior_run_return_witnesses_for_two_independent_original_Findings' -or
        -not [bool]$Graph.complete_ec051_atlas_and_ec043_step_and_return_pairs_reconciled -or
        -not [bool]$Graph.two_original_finding_journeys_remain_independent -or
        -not [bool]$Graph.independent_of_sequence_top -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $classCount -lt 1 -or $classCount -gt $n -or
        [int]$Graph.counts.selected_report_positions -ne $n -or
        [int]$Graph.counts.profile_class_node_count -ne $classCount -or
        [int]$Graph.counts.adjacent_step_count -ne $n - 1 -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        $Atlas.positions.Count -ne $n -or
        $Graph.class_nodes.Count -ne $classCount -or
        $Graph.adjacent_step_edges.Count -ne $n - 1 -or
        $SelectedAnchor.positions.Count -ne $n -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        [int]$Atlas.counts.all_unordered_pair_count -ne $pairCount -or
        $Atlas.path -cne $Graph.path -or $Graph.path -cne $SelectedAnchor.path -or
        [int]$Atlas.pair_index_in_pairwise_profile -ne [int]$Graph.pair_index_in_pairwise_profile -or
        [int]$Atlas.path_index_in_selected_pair_overview -ne [int]$Graph.path_index_in_selected_pair_overview -or
        [int]$Atlas.anchor_index_in_anchor_journeys -ne [int]$Graph.anchor_index_in_anchor_journeys -or
        [int]$Graph.anchor_index_in_anchor_journeys -ne [int]$SelectedAnchor.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Atlas.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $Graph.exact_saved_quote_anchor) -or
        (Get-CodeCompareAnchorKey -Anchor $Graph.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence observed profile passages have inconsistent parent scopes.'
    }

    $classAt = [int[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $p = $i + 1
        $a = $Atlas.positions[$i]
        $s = $SelectedAnchor.positions[$i]
        $c = [int]$a.profile_class_index
        if ($c -lt 1 -or $c -gt $classCount -or
            [int]$a.position -ne $p -or [int]$s.position -ne $p -or
            $a.record_id -cne $s.record_id -or
            [int]$Graph.class_nodes[$c - 1].profile_class_index -ne $c -or
            -not ($Graph.class_nodes[$c - 1].position_indices -contains $p) -or
            [bool]$Graph.class_nodes[$c - 1].reported_same_exact_saved_quote_anchor -ne
                [bool]$s.reported_same_exact_saved_quote_anchor -or
            [int]$Graph.class_nodes[$c - 1].saved_finding_statement_count_at_anchor -ne
                [int]$s.saved_finding_statement_count_at_anchor) {
            throw 'Code Sequence observed profile passages disagree with atlas class/position evidence.'
        }
        foreach ($sev in $severities) {
            if ([bool]$s.reported_same_exact_saved_quote_anchor -and
                [int]$Graph.class_nodes[$c - 1].saved_severity_statement_counts[$sev] -ne
                    [int]$s.saved_severity_statement_counts[$sev]) {
                throw 'Code Sequence observed profile passages disagree on a saved severity bin.'
            }
        }
        $classAt[$i] = $c
    }

    # The EC-052 return witness is tied to ONE exact direct nonadjacent pair;
    # do not mark all same-class endpoint combinations as nearest-run returns.
    $returnsAtDirectPair = [System.Collections.Generic.Dictionary[int,int]]::new()
    for ($i = 0; $i -lt $Graph.prior_run_return_witnesses.Count; $i++) {
        $returnWitness = $Graph.prior_run_return_witnesses[$i]
        $directIndex = [int]$returnWitness.ec043_direct_pair_index
        $from = [int]$returnWitness.from_position
        $to = [int]$returnWitness.to_position
        if ([int]$returnWitness.return_index -ne $i + 1 -or
            $directIndex -lt 1 -or $directIndex -gt $pairCount -or
            $from -lt 1 -or $to -gt $n -or $to -le $from + 1 -or
            $classAt[$from - 1] -ne $classAt[$to - 1] -or
            $classAt[$from - 1] -ne [int]$returnWitness.profile_class_index -or
            $returnsAtDirectPair.ContainsKey($directIndex)) {
            throw 'Code Sequence observed passages found invalid or duplicate nearest-run return linkage.'
        }
        $returnsAtDirectPair.Add($directIndex, $i + 1)
    }

    $groups = [System.Collections.Generic.List[object]]::new()
    $groupIndexes = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $pairs = [System.Collections.Generic.List[object]]::new()
    $pairClasses = [ordered]@{
        left_only = 0; right_only = 0; both_unreported = 0
        retained_same_severity = 0; retained_changed_severity = 0
    }
    $sameClassPairs = 0
    $adjacentPairs = 0
    $crossesOtherClassPairs = 0
    $gapPairs = 0
    $linkedReturns = 0
    $index = 0
    for ($left = 1; $left -lt $n; $left++) {
        for ($right = $left + 1; $right -le $n; $right++) {
            $index++
            $fromClass = $classAt[$left - 1]
            $toClass = $classAt[$right - 1]
            $fromNode = $Graph.class_nodes[$fromClass - 1]
            $toNode = $Graph.class_nodes[$toClass - 1]
            $leftReported = [bool]$fromNode.reported_same_exact_saved_quote_anchor
            $rightReported = [bool]$toNode.reported_same_exact_saved_quote_anchor
            $kind = if ($leftReported) {
                if ($rightReported) {
                    if ($fromClass -eq $toClass) { 'retained_same_severity' }
                    else { 'retained_changed_severity' }
                } else { 'left_only' }
            } elseif ($rightReported) { 'right_only' } else { 'both_unreported' }
            $statementDelta = [int]$toNode.saved_finding_statement_count_at_anchor -
                [int]$fromNode.saved_finding_statement_count_at_anchor
            $severityDelta = [ordered]@{}
            foreach ($sev in $severities) {
                $firstBin = if ($leftReported) { [int]$fromNode.saved_severity_statement_counts[$sev] } else { 0 }
                $secondBin = if ($rightReported) { [int]$toNode.saved_severity_statement_counts[$sev] } else { 0 }
                $severityDelta[$sev] = $secondBin - $firstBin
            }
            $gap = $false
            $thirdClasses = [System.Collections.Generic.HashSet[int]]::new()
            for ($inside = $left + 1; $inside -lt $right; $inside++) {
                $midClass = $classAt[$inside - 1]
                if ($midClass -ne $fromClass -and $midClass -ne $toClass) {
                    [void]$thirdClasses.Add($midClass)
                }
                if ($leftReported -and $rightReported -and
                    -not [bool]$Graph.class_nodes[$midClass - 1].reported_same_exact_saved_quote_anchor) {
                    $gap = $true
                }
            }
            $crossesOther = $fromClass -eq $toClass -and $thirdClasses.Count -gt 0
            $direct = $SelectedAnchor.compared_pairs[$index - 1]
            if ([int]$direct.pair_index -ne $index -or
                [int]$direct.left_position -ne $left -or
                [int]$direct.right_position -ne $right -or
                $direct.left_record_id -cne $Atlas.positions[$left - 1].record_id -or
                $direct.right_record_id -cne $Atlas.positions[$right - 1].record_id -or
                $direct.anchor_pair_class -cne $kind -or
                [bool]$direct.anchor_changed_in_pair -ne ($fromClass -ne $toClass) -or
                [bool]$direct.shared_with_internal_unreported_position -ne $gap -or
                [int]$direct.left_saved_finding_statement_count_at_anchor -ne
                    [int]$fromNode.saved_finding_statement_count_at_anchor -or
                [int]$direct.right_saved_finding_statement_count_at_anchor -ne
                    [int]$toNode.saved_finding_statement_count_at_anchor -or
                [int]$direct.saved_finding_statement_count_delta_right_minus_left -ne $statementDelta) {
                throw 'Code Sequence observed passage disagrees with one of the complete EC-043 canonical pairs.'
            }
            foreach ($sev in $severities) {
                if ([int]$direct.saved_severity_statement_delta_right_minus_left[$sev] -ne [int]$severityDelta[$sev]) {
                    throw 'Code Sequence observed profile passage has a nonconserved saved severity delta.'
                }
            }
            if ($right -eq $left + 1) {
                $adjacentPairs++
                $step = $Graph.adjacent_step_edges[$left - 1]
                if ([int]$step.step_index -ne $left -or
                    [int]$step.ec043_pair_index -ne $index -or
                    [int]$step.from_profile_class_index -ne $fromClass -or
                    [int]$step.to_profile_class_index -ne $toClass -or
                    $step.saved_anchor_pair_class -cne $kind) {
                    throw 'Code Sequence observed passages disagree with an adjacent graph edge.'
                }
            }
            if ($fromClass -eq $toClass) { $sameClassPairs++ }
            if ($crossesOther) { $crossesOtherClassPairs++ }
            if ($gap) { $gapPairs++ }
            $pairClasses[$kind]++

            $key = '{0}:{1}' -f $fromClass, $toClass
            if (-not $groupIndexes.ContainsKey($key)) {
                $groupIndex = $groups.Count + 1
                $groupIndexes.Add($key, $groupIndex)
                $groups.Add([ordered]@{
                    passage_index = $groupIndex
                    from_profile_class_index = $fromClass
                    to_profile_class_index = $toClass
                    same_profile_class = ($fromClass -eq $toClass)
                    from_anchor_reported = $leftReported
                    to_anchor_reported = $rightReported
                    saved_anchor_pair_class = $kind
                    saved_finding_statement_delta_right_minus_left = $statementDelta
                    saved_severity_statement_delta_right_minus_left = $severityDelta
                    ec043_pair_indices = [System.Collections.Generic.List[int]]::new()
                    adjacent_pair_count = 0
                    pair_with_internal_unreported_gap_count = 0
                    equal_endpoint_pair_crossing_other_profile_class_count = 0
                    nearest_previous_run_return_pair_count = 0
                    shortest = $null
                    longest = $null
                })
            }
            $groupIndex = $groupIndexes[$key]
            $group = $groups[$groupIndex - 1]
            if ($group.saved_anchor_pair_class -cne $kind -or
                [int]$group.saved_finding_statement_delta_right_minus_left -ne $statementDelta -or
                [bool]$group.from_anchor_reported -ne $leftReported -or
                [bool]$group.to_anchor_reported -ne $rightReported) {
                throw 'Code Sequence observed profile passage grouped incompatible endpoint classes.'
            }
            foreach ($sev in $severities) {
                if ([int]$group.saved_severity_statement_delta_right_minus_left[$sev] -ne [int]$severityDelta[$sev]) {
                    throw 'Code Sequence observed passage group has inconsistent five-bin saved histograms.'
                }
            }
            $returnIndex = $null
            if ($returnsAtDirectPair.ContainsKey($index)) {
                $returnIndex = [int]$returnsAtDirectPair[$index]
                $returnWitness = $Graph.prior_run_return_witnesses[$returnIndex - 1]
                if ($fromClass -ne $toClass -or -not $crossesOther -or
                    [int]$returnWitness.from_position -ne $left -or
                    [int]$returnWitness.to_position -ne $right -or
                    $returnWitness.from_record_id -cne $direct.left_record_id -or
                    $returnWitness.to_record_id -cne $direct.right_record_id -or
                    $returnWitness.ec043_direct_pair_class -cne $kind -or
                    [bool]$returnWitness.direct_pair_has_internal_unreported_gap -ne $gap) {
                    throw 'Code Sequence observed passage does not agree with its EC-052 closest-run return.'
                }
                $linkedReturns++
                $group.nearest_previous_run_return_pair_count++
            }
            $pair = [ordered]@{
                ec043_pair_index = $index
                from_position = $left
                to_position = $right
                from_record_id = [string]$direct.left_record_id
                to_record_id = [string]$direct.right_record_id
                from_profile_class_index = $fromClass
                to_profile_class_index = $toClass
                passage_index = $groupIndex
                adjacent_hop_count = $right - $left
                is_adjacent_pair = ($right -eq $left + 1)
                saved_anchor_pair_class = $kind
                changed_saved_profile = ($fromClass -ne $toClass)
                distinct_intervening_third_profile_class_count = $thirdClasses.Count
                crosses_other_class_between_equal_endpoints = [bool]$crossesOther
                direct_pair_has_internal_unreported_gap = [bool]$gap
                closest_previous_same_class_run_return_index = $returnIndex
            }
            $pairs.Add($pair)
            $group.ec043_pair_indices.Add($index)
            if ($pair.is_adjacent_pair) { $group.adjacent_pair_count++ }
            if ($gap) { $group.pair_with_internal_unreported_gap_count++ }
            if ($crossesOther) { $group.equal_endpoint_pair_crossing_other_profile_class_count++ }
            if ($null -eq $group.shortest -or $pair.adjacent_hop_count -lt $group.shortest.adjacent_hop_count) {
                $group.shortest = $pair
            }
            if ($null -eq $group.longest -or $pair.adjacent_hop_count -gt $group.longest.adjacent_hop_count) {
                $group.longest = $pair
            }
        }
    }
    if ($index -ne $pairCount -or $pairs.Count -ne $pairCount -or
        $adjacentPairs -ne $n - 1 -or
        $linkedReturns -ne $returnsAtDirectPair.Count -or
        $linkedReturns -ne $Graph.prior_run_return_witnesses.Count -or
        $sameClassPairs -ne ($pairClasses.retained_same_severity + $pairClasses.both_unreported)) {
        throw 'Code Sequence observed profile passage failed pair/return conservation.'
    }
    foreach ($kind in $pairClasses.Keys) {
        if ([int]$pairClasses[$kind] -ne [int]$Atlas.all_unordered_pair_class_counts[$kind]) {
            throw 'Code Sequence observed profile passages disagree with the EC-051 full pair-class histogram.'
        }
    }

    $outputGroups = [System.Collections.Generic.List[object]]::new()
    $groupPairs = 0
    $groupAdjacencies = 0
    $groupReturns = 0
    $groupGaps = 0
    $groupCrossings = 0
    $groupSameClass = 0
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $g = $groups[$i]
        $count = $g.ec043_pair_indices.Count
        if ([int]$g.passage_index -ne $i + 1 -or $count -lt 1 -or
            $null -eq $g.shortest -or $null -eq $g.longest) {
            throw 'Code Sequence observed passages found an empty/noncanonical class pair group.'
        }
        if ($g.same_profile_class) { $groupSameClass++ }
        $groupPairs += $count
        $groupAdjacencies += $g.adjacent_pair_count
        $groupReturns += $g.nearest_previous_run_return_pair_count
        $groupGaps += $g.pair_with_internal_unreported_gap_count
        $groupCrossings += $g.equal_endpoint_pair_crossing_other_profile_class_count
        $shortest = New-CodeSequenceObservedProfilePassageWitness -Pair $g.shortest `
            -Graph $Graph -ClassAt $classAt -SelectedAnchor $SelectedAnchor
        $longest = New-CodeSequenceObservedProfilePassageWitness -Pair $g.longest `
            -Graph $Graph -ClassAt $classAt -SelectedAnchor $SelectedAnchor
        $previousPairIndex = 0
        foreach ($groupPairIndex in $g.ec043_pair_indices) {
            $at = [int]$groupPairIndex
            if ($at -le $previousPairIndex -or $at -gt $pairCount -or $at -lt 1) {
                throw 'Code Sequence observed class passage contains duplicate, invalid or unsorted EC-043 pair indexes.'
            }
            $member = $pairs[$at - 1]
            if ([int]$member.ec043_pair_index -ne $at -or
                [int]$member.passage_index -ne [int]$g.passage_index -or
                [int]$member.from_profile_class_index -ne [int]$g.from_profile_class_index -or
                [int]$member.to_profile_class_index -ne [int]$g.to_profile_class_index) {
                throw 'Code Sequence observed class passage group contains a detached report pair.'
            }
            $previousPairIndex = $at
        }
        if ($shortest.adjacent_hop_count -gt $longest.adjacent_hop_count) {
            throw 'Code Sequence observed class passage extrema have inconsistent real span lengths.'
        }
        $outputGroups.Add([ordered]@{
            passage_index = [int]$g.passage_index
            from_profile_class_index = [int]$g.from_profile_class_index
            to_profile_class_index = [int]$g.to_profile_class_index
            same_profile_class = [bool]$g.same_profile_class
            from_anchor_reported = [bool]$g.from_anchor_reported
            to_anchor_reported = [bool]$g.to_anchor_reported
            saved_anchor_pair_class = [string]$g.saved_anchor_pair_class
            saved_finding_statement_delta_right_minus_left = [int]$g.saved_finding_statement_delta_right_minus_left
            saved_severity_statement_delta_right_minus_left = $g.saved_severity_statement_delta_right_minus_left
            ordered_position_pair_count = $count
            adjacent_position_pair_count = [int]$g.adjacent_pair_count
            nonadjacent_position_pair_count = $count - [int]$g.adjacent_pair_count
            pair_with_internal_unreported_gap_count = [int]$g.pair_with_internal_unreported_gap_count
            equal_endpoint_pair_crossing_other_profile_class_count = [int]$g.equal_endpoint_pair_crossing_other_profile_class_count
            nearest_previous_run_return_pair_count = [int]$g.nearest_previous_run_return_pair_count
            ec043_pair_indices = $g.ec043_pair_indices.ToArray()
            shortest_observed_contiguous_passage = $shortest
            longest_observed_contiguous_passage = $longest
        })
    }
    if ($groupPairs -ne $pairCount -or $groupAdjacencies -ne $n - 1 -or
        $groupReturns -ne $linkedReturns -or $groupGaps -ne $gapPairs -or
        $groupCrossings -ne $crossesOtherClassPairs -or
        $outputGroups.Count -ne $groupIndexes.Count) {
        throw 'Code Sequence observed profile passage groups do not partition all checked direct report pairs.'
    }
    return [ordered]@{
        scope = 'complete_caller_forward_actual_position_pair_profile_passages_and_shortest_longest_contiguous_witnesses'
        pair_index_in_pairwise_profile = [int]$Atlas.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Atlas.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Atlas.anchor_index_in_anchor_journeys
        path = [string]$Atlas.path
        exact_saved_quote_anchor = $Atlas.exact_saved_quote_anchor
        counts = [ordered]@{
            selected_report_positions = $n
            distinct_profile_class_count = $classCount
            all_ec043_position_pair_count = $pairCount
            ordered_class_passage_group_count = $outputGroups.Count
            same_class_passage_group_count = $groupSameClass
            different_class_passage_group_count = $outputGroups.Count - $groupSameClass
            same_class_position_pair_count = $sameClassPairs
            different_class_position_pair_count = $pairCount - $sameClassPairs
            adjacent_position_pair_count = $adjacentPairs
            nonadjacent_position_pair_count = $pairCount - $adjacentPairs
            equal_endpoint_pair_crossing_other_profile_class_count = $crossesOtherClassPairs
            pair_with_reported_endpoints_and_internal_unreported_gap_count = $gapPairs
            closest_previous_run_return_link_count = $linkedReturns
        }
        ec043_pair_class_counts = $pairClasses
        ordered_class_passages = $outputGroups.ToArray()
        all_caller_forward_position_pairs = $pairs.ToArray()
        independent_of_sequence_top = $true
        complete_ec043_pairs_ec051_classes_and_ec052_adjacent_and_return_graph_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'All N choose 2 EC-043 pairs are grouped by ORDERED caller-left to caller-right exact saved-model severity-statement histogram classes. Every shortest and longest witness is an actually observed contiguous span of caller-selected positions, not a synthetic graph path formed by splicing independent edge occurrences. Same-class endpoint pairs can cross other classes, but only an exact EC-052 immediately-previous-run endpoint pair is linked to that return. Absent anchor is a distinct null class. Caller order is not attested chronology; matching histograms and repeated passages do not establish the same original Finding, real issue recurrence, fix, severity, regression or risk. No quote/model prose, extra saved body, source/Git/network read or write.'
    }
}

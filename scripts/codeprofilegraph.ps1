#requires -Version 7.0
<#
    EC-052: Directed saved-profile transition graph and exact return witnesses.

    Read ONLY the already reconciled EC-051 histogram atlas and EC-043 exact
    quote-anchor pair ledger. Every arc is a consecutive CALLER-ORDER report
    position comparison; repeated arcs are grouped by ordered profile class
    endpoints, not by original Finding ID, issue identity or elapsed time.
    A return witness is the entire bounded walk from the PREVIOUS contiguous
    run of the same class to its next run, including self-loops in between.
#>
function Get-CodeSequenceOriginalFindingPairProfileTransitionGraph {
    param(
        [object] $Atlas,
        [object] $SelectedAnchor
    )

    $severities = @('critical', 'high', 'medium', 'low', 'info')
    if ($null -eq $Atlas -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence saved-profile transition graph requires the checked atlas and anchor ledger.'
    }
    $n = [int]$Atlas.counts.selected_report_positions
    $classCount = [int]$Atlas.counts.distinct_saved_profile_class_count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($Atlas.scope -cne 'complete_saved_quote_anchor_five_severity_histogram_classes_adjacent_transitions_and_returns_for_two_independent_original_Findings' -or
        -not [bool]$Atlas.complete_ec050_cohorts_and_ec043_all_pairs_reconciled -or
        -not [bool]$Atlas.two_original_finding_journeys_remain_independent -or
        -not [bool]$Atlas.independent_of_sequence_top -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $classCount -lt 1 -or $classCount -gt $n -or
        $Atlas.positions.Count -ne $n -or
        $Atlas.classes.Count -ne $classCount -or
        $Atlas.adjacent_comparisons.Count -ne ($n - 1) -or
        $Atlas.profile_runs.Count -lt 1 -or $Atlas.profile_runs.Count -gt $n -or
        $SelectedAnchor.positions.Count -ne $n -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        $Atlas.path -cne $SelectedAnchor.path -or
        [int]$Atlas.anchor_index_in_anchor_journeys -ne [int]$SelectedAnchor.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Atlas.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor) -or
        [int]$Atlas.counts.all_unordered_pair_count -ne $pairCount -or
        [int]$Atlas.counts.adjacent_comparison_count -ne ($n - 1)) {
        throw 'Code Sequence saved-profile transition graph has inconsistent atlas/anchor scope.'
    }

    # Reconstruct the complete first-appearance class partition. In
    # particular, ABSENT is one null class, never a zero-Finding histogram.
    $classAt = [int[]]::new($n)
    $nodeWork = [System.Collections.Generic.List[object]]::new()
    $absentClasses = 0
    for ($c = 0; $c -lt $classCount; $c++) {
        $profile = $Atlas.classes[$c]
        $index = $c + 1
        $members = $profile.position_indices
        $reported = [bool]$profile.reported_same_exact_saved_quote_anchor
        $statementCount = [int]$profile.saved_finding_statement_count_at_anchor
        $histogram = $profile.saved_severity_statement_counts
        if ([int]$profile.class_index -ne $index -or $members.Count -lt 1 -or
            [int]$profile.position_count -ne $members.Count -or
            [int]$profile.first_seen_position -ne [int]$members[0] -or
            $profile.representative_record_id -cne $Atlas.positions[[int]$members[0] - 1].record_id -or
            ($reported -and ($null -eq $histogram -or $histogram.Count -ne 5 -or $statementCount -lt 1)) -or
            (-not $reported -and ($null -ne $histogram -or $statementCount -ne 0))) {
            throw 'Code Sequence transition graph found an invalid histogram class representative.'
        }
        $sum = 0
        if ($reported) {
            foreach ($severity in $severities) {
                $bin = [int]$histogram[$severity]
                if ($bin -lt 0 -or $bin -gt 40) {
                    throw 'Code Sequence transition graph found an out-of-range saved severity bin.'
                }
                $sum += $bin
            }
            if ($sum -ne $statementCount) {
                throw 'Code Sequence transition graph histogram fails statement conservation.'
            }
        } else { $absentClasses++ }
        $previous = 0
        foreach ($member in $members) {
            $position = [int]$member
            if ($position -lt 1 -or $position -gt $n -or $position -le $previous -or
                $classAt[$position - 1] -ne 0) {
                throw 'Code Sequence transition graph class members duplicate, overlap or are unsorted.'
            }
            $classAt[$position - 1] = $index
            $previous = $position
        }
        $nodeWork.Add([ordered]@{
            profile_class_index = $index
            first_seen_position = [int]$members[0]
            last_seen_position = [int]$members[$members.Count - 1]
            reported_same_exact_saved_quote_anchor = $reported
            saved_finding_statement_count_at_anchor = $statementCount
            saved_severity_statement_counts = $histogram
            position_indices = $members
            run_indices = [System.Collections.Generic.List[int]]::new()
            incoming_adjacent_step_count = 0
            outgoing_adjacent_step_count = 0
            incoming_changed_step_count = 0
            outgoing_changed_step_count = 0
            returning_run_count = 0
        })
    }
    if ($absentClasses -ne [int]$Atlas.counts.absent_anchor_profile_class_count -or $absentClasses -gt 1) {
        throw 'Code Sequence transition graph disagrees on absent saved-profile classes.'
    }
    $firstSeen = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt $n; $i++) {
        $position = $i + 1
        $atlasRow = $Atlas.positions[$i]
        $anchorRow = $SelectedAnchor.positions[$i]
        $classIndex = $classAt[$i]
        if ($classIndex -lt 1 -or [int]$atlasRow.position -ne $position -or
            [int]$atlasRow.profile_class_index -ne $classIndex -or
            [int]$anchorRow.position -ne $position -or
            $atlasRow.record_id -cne $anchorRow.record_id -or
            [bool]$atlasRow.reported_same_exact_saved_quote_anchor -ne [bool]$nodeWork[$classIndex - 1].reported_same_exact_saved_quote_anchor -or
            [bool]$anchorRow.reported_same_exact_saved_quote_anchor -ne [bool]$nodeWork[$classIndex - 1].reported_same_exact_saved_quote_anchor -or
            [int]$anchorRow.saved_finding_statement_count_at_anchor -ne [int]$nodeWork[$classIndex - 1].saved_finding_statement_count_at_anchor -or
            (-not [bool]$nodeWork[$classIndex - 1].reported_same_exact_saved_quote_anchor -and
                $null -ne $anchorRow.saved_severity_statement_counts)) {
            throw 'Code Sequence transition graph class/position evidence differs from EC-043.'
        }
        foreach ($severity in $severities) {
            if ([bool]$nodeWork[$classIndex - 1].reported_same_exact_saved_quote_anchor -and
                [int]$anchorRow.saved_severity_statement_counts[$severity] -ne
                    [int]$nodeWork[$classIndex - 1].saved_severity_statement_counts[$severity]) {
                throw 'Code Sequence transition graph has inconsistent saved severity counts.'
            }
        }
        if ($firstSeen.Add($classIndex) -and $nodeWork[$classIndex - 1].first_seen_position -ne $position) {
            throw 'Code Sequence transition graph class numbering is not first-appearance order.'
        }
        if ($classIndex -gt $firstSeen.Count) {
            throw 'Code Sequence transition graph has noncanonical class indexes.'
        }
    }
    if ($firstSeen.Count -ne $classCount) {
        throw 'Code Sequence transition graph has an incomplete class partition.'
    }

    # First appearance in the adjacent position walk fixes edge numbering.
    # An ordered A->B edge is NOT the same as B->A. A->A is a real stable
    # adjacent comparison (reported-stable or both-unreported), not a return.
    $edgeIndexes = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $edgeWork = [System.Collections.Generic.List[object]]::new()
    $stepWork = [System.Collections.Generic.List[object]]::new()
    $edgeAtStep = [int[]]::new($n - 1)
    $priorClasses = [System.Collections.Generic.HashSet[int]]::new()
    [void]$priorClasses.Add($classAt[0])
    $returnClasses = [System.Collections.Generic.HashSet[int]]::new()
    $changedSteps = 0
    $selfSteps = 0
    $returnedSteps = 0
    for ($i = 0; $i -lt $n - 1; $i++) {
        $step = $i + 1
        $from = $classAt[$i]
        $to = $classAt[$i + 1]
        $left = $nodeWork[$from - 1]
        $right = $nodeWork[$to - 1]
        $different = $from -ne $to
        $returned = $different -and $priorClasses.Contains($to)
        $comparison = $Atlas.adjacent_comparisons[$i]
        $expectedKind = if ($left.reported_same_exact_saved_quote_anchor) {
            if ($right.reported_same_exact_saved_quote_anchor) {
                if ($different) { 'retained_changed_severity' } else { 'retained_same_severity' }
            } else { 'left_only' }
        } elseif ($right.reported_same_exact_saved_quote_anchor) { 'right_only' }
        else { 'both_unreported' }
        $expectedPairIndex = [int]((($step - 1) * $n) - (($step - 1) * $step / 2) + 1)
        $anchorPair = $SelectedAnchor.compared_pairs[$expectedPairIndex - 1]
        $statementDelta = [int]$right.saved_finding_statement_count_at_anchor - [int]$left.saved_finding_statement_count_at_anchor
        $delta = [ordered]@{}
        foreach ($severity in $severities) {
            $lv = if ($left.reported_same_exact_saved_quote_anchor) { [int]$left.saved_severity_statement_counts[$severity] } else { 0 }
            $rv = if ($right.reported_same_exact_saved_quote_anchor) { [int]$right.saved_severity_statement_counts[$severity] } else { 0 }
            $delta[$severity] = $rv - $lv
        }
        if ([int]$comparison.from_position -ne $step -or [int]$comparison.to_position -ne $step + 1 -or
            [int]$comparison.from_profile_class_index -ne $from -or
            [int]$comparison.to_profile_class_index -ne $to -or
            $comparison.from_record_id -cne $Atlas.positions[$i].record_id -or
            $comparison.to_record_id -cne $Atlas.positions[$i + 1].record_id -or
            [int]$comparison.ec043_pair_index -ne $expectedPairIndex -or
            $comparison.saved_anchor_pair_class -cne $expectedKind -or
            [bool]$comparison.changed_saved_profile -ne $different -or
            [bool]$comparison.returns_to_earlier_nonadjacent_profile_class -ne $returned -or
            [int]$comparison.saved_finding_statement_delta_right_minus_left -ne $statementDelta -or
            [int]$anchorPair.pair_index -ne $expectedPairIndex -or
            [int]$anchorPair.left_position -ne $step -or [int]$anchorPair.right_position -ne $step + 1 -or
            $anchorPair.left_record_id -cne $comparison.from_record_id -or
            $anchorPair.right_record_id -cne $comparison.to_record_id -or
            $anchorPair.anchor_pair_class -cne $expectedKind -or
            [bool]$anchorPair.anchor_changed_in_pair -ne $different -or
            [bool]$anchorPair.shared_with_internal_unreported_position -or
            [int]$anchorPair.left_saved_finding_statement_count_at_anchor -ne [int]$left.saved_finding_statement_count_at_anchor -or
            [int]$anchorPair.right_saved_finding_statement_count_at_anchor -ne [int]$right.saved_finding_statement_count_at_anchor -or
            [int]$anchorPair.saved_finding_statement_count_delta_right_minus_left -ne $statementDelta) {
            throw 'Code Sequence transition graph disagrees with EC-051 adjacent and EC-043 canonical pair evidence.'
        }
        foreach ($severity in $severities) {
            if ([int]$comparison.saved_severity_statement_delta_right_minus_left[$severity] -ne [int]$delta[$severity] -or
                [int]$anchorPair.saved_severity_statement_delta_right_minus_left[$severity] -ne [int]$delta[$severity]) {
                throw 'Code Sequence transition graph signed severity delta disagrees with the adjacent ledgers.'
            }
        }
        $left.outgoing_adjacent_step_count++
        $right.incoming_adjacent_step_count++
        if ($different) {
            $changedSteps++
            $left.outgoing_changed_step_count++
            $right.incoming_changed_step_count++
        } else { $selfSteps++ }
        if ($returned) { $returnedSteps++; [void]$returnClasses.Add($to) }
        $key = '{0}:{1}' -f $from, $to
        if (-not $edgeIndexes.ContainsKey($key)) {
            $edgeIndex = $edgeWork.Count + 1
            $edgeIndexes.Add($key, $edgeIndex)
            $edgeWork.Add([ordered]@{
                edge_index = $edgeIndex
                from_profile_class_index = $from
                to_profile_class_index = $to
                is_self_loop = (-not $different)
                saved_anchor_pair_class = $expectedKind
                saved_finding_statement_delta_right_minus_left = $statementDelta
                saved_severity_statement_delta_right_minus_left = $delta
                step_indices = [System.Collections.Generic.List[int]]::new()
                ec043_pair_indices = [System.Collections.Generic.List[int]]::new()
                returned_step_indices = [System.Collections.Generic.List[int]]::new()
            })
        }
        $edgeIndex = $edgeIndexes[$key]
        $edge = $edgeWork[$edgeIndex - 1]
        if ($edge.saved_anchor_pair_class -cne $expectedKind -or
            [int]$edge.saved_finding_statement_delta_right_minus_left -ne $statementDelta) {
            throw 'Code Sequence transition graph grouped incompatible directed saved-profile edges.'
        }
        foreach ($severity in $severities) {
            if ([int]$edge.saved_severity_statement_delta_right_minus_left[$severity] -ne [int]$delta[$severity]) {
                throw 'Code Sequence transition graph grouped incompatible saved severity histograms.'
            }
        }
        $edge.step_indices.Add($step)
        $edge.ec043_pair_indices.Add($expectedPairIndex)
        if ($returned) { $edge.returned_step_indices.Add($step) }
        $edgeAtStep[$i] = $edgeIndex
        $stepWork.Add([ordered]@{
            step_index = $step
            from_position = $step
            to_position = $step + 1
            from_record_id = [string]$comparison.from_record_id
            to_record_id = [string]$comparison.to_record_id
            from_profile_class_index = $from
            to_profile_class_index = $to
            directed_edge_index = $edgeIndex
            ec043_pair_index = $expectedPairIndex
            saved_anchor_pair_class = $expectedKind
            changed_saved_profile = $different
            returns_to_earlier_nonadjacent_profile_class = [bool]$returned
        })
        [void]$priorClasses.Add($to)
    }

    # A maximal class run is one visit. Each REVISIT links to the closest
    # previous run of that very same class. Preserve EVERY position/edge hop
    # in the return witness, including intervening stable/absent self-loops.
    $lastRunForClass = [int[]]::new($classCount)
    $returnWork = [System.Collections.Generic.List[object]]::new()
    $nextStart = 1
    $previousRunClass = 0
    for ($r = 0; $r -lt $Atlas.profile_runs.Count; $r++) {
        $run = $Atlas.profile_runs[$r]
        $runIndex = $r + 1
        $classIndex = [int]$run.profile_class_index
        $start = [int]$run.start_position
        $end = [int]$run.end_position
        if ([int]$run.run_index -ne $runIndex -or $start -ne $nextStart -or
            $end -lt $start -or $end -gt $n -or
            [int]$run.selected_report_count -ne ($end - $start + 1) -or
            $classIndex -lt 1 -or $classIndex -gt $classCount -or
            $classIndex -eq $previousRunClass) {
            throw 'Code Sequence transition graph found invalid or nonmaximal class runs.'
        }
        for ($p = $start; $p -le $end; $p++) {
            if ($classAt[$p - 1] -ne $classIndex -or
                ($p -lt $end -and [bool]$Atlas.adjacent_comparisons[$p - 1].changed_saved_profile)) {
                throw 'Code Sequence transition graph run crosses a changed saved profile.'
            }
        }
        if ($start -gt 1 -and -not [bool]$Atlas.adjacent_comparisons[$start - 2].changed_saved_profile) {
            throw 'Code Sequence transition graph run boundary omits a real class change.'
        }
        $node = $nodeWork[$classIndex - 1]
        $node.run_indices.Add($runIndex)
        $lastRun = $lastRunForClass[$classIndex - 1]
        if ($lastRun -ne 0) {
            $priorRun = $Atlas.profile_runs[$lastRun - 1]
            $fromPosition = [int]$priorRun.end_position
            $toPosition = $start
            if ($toPosition -le $fromPosition + 1 -or
                -not [bool]$Atlas.adjacent_comparisons[$start - 2].returns_to_earlier_nonadjacent_profile_class) {
                throw 'Code Sequence transition graph found a false/nonadjacent profile return.'
            }
            $classWalk = [System.Collections.Generic.List[int]]::new()
            $edgeWalk = [System.Collections.Generic.List[int]]::new()
            $stepWalk = [System.Collections.Generic.List[int]]::new()
            $interveningClasses = [System.Collections.Generic.HashSet[int]]::new()
            for ($p = $fromPosition; $p -le $toPosition; $p++) {
                $walkClass = $classAt[$p - 1]
                $classWalk.Add($walkClass)
                if ($p -gt $fromPosition -and $p -lt $toPosition) {
                    if ($walkClass -eq $classIndex) {
                        throw 'Code Sequence transition graph return skipped a closer same-class run.'
                    }
                    [void]$interveningClasses.Add($walkClass)
                }
                if ($p -lt $toPosition) {
                    $stepWalk.Add($p)
                    $edgeWalk.Add($edgeAtStep[$p - 1])
                }
            }
            if ($interveningClasses.Count -lt 1 -or
                $classWalk[0] -ne $classIndex -or
                $classWalk[$classWalk.Count - 1] -ne $classIndex -or
                $edgeWalk.Count -ne $toPosition - $fromPosition) {
                throw 'Code Sequence transition graph return is not a complete closed class walk.'
            }
            # Independent direct EC-043 comparison over the ENTIRE return
            # interval, as distinct from its fully witnessed adjacent hops.
            $directIndex = [int]((($fromPosition - 1) * $n) -
                ((($fromPosition - 1) * $fromPosition) / 2) + ($toPosition - $fromPosition))
            $directPair = $SelectedAnchor.compared_pairs[$directIndex - 1]
            $expectedDirectKind = if ($node.reported_same_exact_saved_quote_anchor) {
                'retained_same_severity'
            } else { 'both_unreported' }
            $gap = $false
            if ($node.reported_same_exact_saved_quote_anchor) {
                for ($p = $fromPosition + 1; $p -lt $toPosition; $p++) {
                    if (-not [bool]$nodeWork[$classAt[$p - 1] - 1].reported_same_exact_saved_quote_anchor) {
                        $gap = $true
                        break
                    }
                }
            }
            if ([int]$directPair.pair_index -ne $directIndex -or
                [int]$directPair.left_position -ne $fromPosition -or
                [int]$directPair.right_position -ne $toPosition -or
                $directPair.left_record_id -cne $Atlas.positions[$fromPosition - 1].record_id -or
                $directPair.right_record_id -cne $Atlas.positions[$toPosition - 1].record_id -or
                $directPair.anchor_pair_class -cne $expectedDirectKind -or
                [bool]$directPair.anchor_changed_in_pair -or
                [bool]$directPair.shared_with_internal_unreported_position -ne $gap -or
                [int]$directPair.left_saved_finding_statement_count_at_anchor -ne [int]$node.saved_finding_statement_count_at_anchor -or
                [int]$directPair.right_saved_finding_statement_count_at_anchor -ne [int]$node.saved_finding_statement_count_at_anchor -or
                [int]$directPair.saved_finding_statement_count_delta_right_minus_left -ne 0) {
                throw 'Code Sequence transition graph return fails its EC-043 endpoint-to-endpoint witness.'
            }
            foreach ($severity in $severities) {
                if ([int]$directPair.saved_severity_statement_delta_right_minus_left[$severity] -ne 0) {
                    throw 'Code Sequence transition graph return endpoints disagree in one saved severity bin.'
                }
            }
            $node.returning_run_count++
            $returnWork.Add([ordered]@{
                return_index = $returnWork.Count + 1
                profile_class_index = $classIndex
                previous_run_index = $lastRun
                returning_run_index = $runIndex
                from_position = $fromPosition
                to_position = $toPosition
                from_record_id = [string]$Atlas.positions[$fromPosition - 1].record_id
                to_record_id = [string]$Atlas.positions[$toPosition - 1].record_id
                intervening_run_count = $runIndex - $lastRun - 1
                distinct_intervening_profile_class_count = $interveningClasses.Count
                adjacent_hop_count = $toPosition - $fromPosition
                class_walk = $classWalk.ToArray()
                adjacent_step_indices = $stepWalk.ToArray()
                directed_edge_index_walk = $edgeWalk.ToArray()
                ec043_direct_pair_index = $directIndex
                ec043_direct_pair_class = $expectedDirectKind
                direct_pair_has_internal_unreported_gap = [bool]$gap
            })
        } elseif ($node.first_seen_position -ne $start) {
            throw 'Code Sequence transition graph first class run does not begin at class first appearance.'
        }
        $lastRunForClass[$classIndex - 1] = $runIndex
        $previousRunClass = $classIndex
        $nextStart = $end + 1
    }
    if ($nextStart -ne $n + 1 -or
        $returnWork.Count -ne $returnedSteps -or
        $returnedSteps -ne [int]$Atlas.counts.return_to_prior_nonadjacent_profile_occurrence_count -or
        $returnClasses.Count -ne [int]$Atlas.counts.distinct_returned_profile_class_count -or
        $changedSteps -ne [int]$Atlas.counts.adjacent_changed_profile_count -or
        $selfSteps -ne [int]$Atlas.counts.adjacent_matching_profile_count -or
        $Atlas.profile_runs.Count -ne $changedSteps + 1) {
        throw 'Code Sequence transition graph fails step/run/return conservation.'
    }

    $nodes = [System.Collections.Generic.List[object]]::new()
    $nodeMemberTotal = 0
    $runMemberTotal = 0
    foreach ($node in $nodeWork) {
        $nodeMemberTotal += $node.position_indices.Count
        $runMemberTotal += $node.run_indices.Count
        $nodes.Add([ordered]@{
            profile_class_index = [int]$node.profile_class_index
            first_seen_position = [int]$node.first_seen_position
            last_seen_position = [int]$node.last_seen_position
            reported_same_exact_saved_quote_anchor = [bool]$node.reported_same_exact_saved_quote_anchor
            saved_finding_statement_count_at_anchor = [int]$node.saved_finding_statement_count_at_anchor
            saved_severity_statement_counts = $node.saved_severity_statement_counts
            position_indices = $node.position_indices
            run_indices = $node.run_indices.ToArray()
            incoming_adjacent_step_count = [int]$node.incoming_adjacent_step_count
            outgoing_adjacent_step_count = [int]$node.outgoing_adjacent_step_count
            incoming_changed_step_count = [int]$node.incoming_changed_step_count
            outgoing_changed_step_count = [int]$node.outgoing_changed_step_count
            returning_run_count = [int]$node.returning_run_count
        })
    }
    $edges = [System.Collections.Generic.List[object]]::new()
    $edgeOccurrences = 0
    $selfEdges = 0
    $reusedEdges = 0
    $repeatOccurrences = 0
    $edgeReturnOccurrences = 0
    foreach ($edge in $edgeWork) {
        $stepIndices = $edge.step_indices.ToArray()
        $occurrences = $stepIndices.Count
        if ($occurrences -lt 1 -or [int]$edge.ec043_pair_indices.Count -ne $occurrences) {
            throw 'Code Sequence transition graph has a detached directed edge.'
        }
        $edgeOccurrences += $occurrences
        $edgeReturnOccurrences += $edge.returned_step_indices.Count
        if ($edge.is_self_loop) { $selfEdges++ }
        if ($occurrences -gt 1) { $reusedEdges++; $repeatOccurrences += $occurrences - 1 }
        $edges.Add([ordered]@{
            edge_index = [int]$edge.edge_index
            from_profile_class_index = [int]$edge.from_profile_class_index
            to_profile_class_index = [int]$edge.to_profile_class_index
            is_self_loop = [bool]$edge.is_self_loop
            saved_anchor_pair_class = [string]$edge.saved_anchor_pair_class
            saved_finding_statement_delta_right_minus_left = [int]$edge.saved_finding_statement_delta_right_minus_left
            saved_severity_statement_delta_right_minus_left = $edge.saved_severity_statement_delta_right_minus_left
            occurrence_count = $occurrences
            first_step_index = $stepIndices[0]
            last_step_index = $stepIndices[$occurrences - 1]
            step_indices = $stepIndices
            ec043_pair_indices = $edge.ec043_pair_indices.ToArray()
            returned_step_indices = $edge.returned_step_indices.ToArray()
        })
    }
    $totalIncoming = 0
    $totalOutgoing = 0
    $totalIncomingChanged = 0
    $totalOutgoingChanged = 0
    $totalReturningRuns = 0
    foreach ($node in $nodeWork) {
        $totalIncoming += $node.incoming_adjacent_step_count
        $totalOutgoing += $node.outgoing_adjacent_step_count
        $totalIncomingChanged += $node.incoming_changed_step_count
        $totalOutgoingChanged += $node.outgoing_changed_step_count
        $totalReturningRuns += $node.returning_run_count
    }
    if ($nodeMemberTotal -ne $n -or $runMemberTotal -ne $Atlas.profile_runs.Count -or
        $edgeOccurrences -ne $n - 1 -or $edgeReturnOccurrences -ne $returnedSteps -or
        $totalIncoming -ne $n - 1 -or $totalOutgoing -ne $n - 1 -or
        $totalIncomingChanged -ne $changedSteps -or $totalOutgoingChanged -ne $changedSteps -or
        $totalReturningRuns -ne $returnWork.Count -or
        $stepWork.Count -ne $n - 1 -or $edges.Count -ne $edgeIndexes.Count) {
        throw 'Code Sequence transition graph failed class/edge/visit conservation.'
    }

    return [ordered]@{
        scope = 'complete_directed_saved_profile_class_transition_multigraph_and_prior_run_return_witnesses_for_two_independent_original_Findings'
        pair_index_in_pairwise_profile = [int]$Atlas.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Atlas.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Atlas.anchor_index_in_anchor_journeys
        path = [string]$Atlas.path
        exact_saved_quote_anchor = $Atlas.exact_saved_quote_anchor
        left_endpoint_profile_class_index = [int]$Atlas.left_endpoint_profile_class_index
        right_endpoint_profile_class_index = [int]$Atlas.right_endpoint_profile_class_index
        counts = [ordered]@{
            selected_report_positions = $n
            profile_class_node_count = $classCount
            directed_edge_count = $edges.Count
            changed_directed_edge_count = $edges.Count - $selfEdges
            self_loop_directed_edge_count = $selfEdges
            reused_directed_edge_count = $reusedEdges
            repeated_directed_edge_occurrence_count = $repeatOccurrences
            adjacent_step_count = $n - 1
            changed_adjacent_step_count = $changedSteps
            self_loop_adjacent_step_count = $selfSteps
            contiguous_profile_run_count = $Atlas.profile_runs.Count
            return_to_previous_run_witness_count = $returnWork.Count
            distinct_returned_profile_class_count = $returnClasses.Count
        }
        class_nodes = $nodes.ToArray()
        directed_edges = $edges.ToArray()
        adjacent_step_edges = $stepWork.ToArray()
        prior_run_return_witnesses = $returnWork.ToArray()
        independent_of_sequence_top = $true
        complete_ec051_atlas_and_ec043_step_and_return_pairs_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Every directed arc is a change or stable self-loop between consecutive caller-selected SAVED MODEL severity-statement histogram classes. Repeated arcs are the same ordered histogram endpoints, not matched Findings. A return witness is the complete position-by-position class/edge walk from the immediately previous SAME-CLASS run through a different class to a new run, independently checked against the nonadjacent EC-043 direct endpoint pair. Absence stays a null class, never a reported zero. Caller position order is not verified chronology; no semantic issue identity, real severity change, risk, fix, regression or elapsed-time assertion is made. No model prose, saved quote text, source/Git/network access or writes.'
    }
}

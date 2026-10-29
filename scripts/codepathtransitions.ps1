#requires -Version 7.0
<#
    EC-032: Caller-ordered transition and return-to-profile journeys for each
    exact saved Git path across an already validated CodeShow Sequence.
    Operates only on in-memory CodeCompare groups, NEVER on live business files
    or extra stored report bodies. Caller order is not authenticated time.
#>

function Test-CodeSequenceTransitionHotspotRanksBefore {
    param([object] $Candidate, [object] $Existing)
    if ([int]$Candidate.profile_transition_count -ne [int]$Existing.profile_transition_count) {
        return ([int]$Candidate.profile_transition_count -gt [int]$Existing.profile_transition_count)
    }
    if ([int]$Candidate.return_to_prior_profile_count -ne [int]$Existing.return_to_prior_profile_count) {
        return ([int]$Candidate.return_to_prior_profile_count -gt [int]$Existing.return_to_prior_profile_count)
    }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

function Get-CodeSequencePathProfileTransitions {
    param(
        [object[]] $States,
        [object[]] $ExpectedAdjacentPathDeltas,
        [object[]] $ExpectedAllPairs,
        [object] $PathClasses,
        [int] $Top
    )

    $count = $States.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        $ExpectedAdjacentPathDeltas.Count -ne ($count - 1) -or
        $ExpectedAllPairs.Count -ne $pairCount -or $null -eq $PathClasses -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence saved-path transitions require complete checked adjacent, pair and path-class evidence.'
    }

    $byPosition = [System.Collections.Generic.List[object]]::new()
    $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        $grouped = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $byPosition.Add($grouped)
        foreach ($path in $grouped.Keys) { [void]$paths.Add($path) }
    }

    $stepMetrics = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $count; $i++) {
        $stepMetrics.Add([ordered]@{
            step = $i
            previous_position = $i
            next_position = $i + 1
            previous_record_id = [string]$States[$i - 1].checked.id
            next_record_id = [string]$States[$i].checked.id
            previous_reported_path_count = 0
            next_reported_path_count = 0
            retained_path_count = 0
            previous_only_path_count = 0
            next_only_path_count = 0
            matching_path_profile_count = 0
            both_unreported_matching_path_count = 0
            changed_path_profile_count = 0
            retained_path_with_anchor_churn_count = 0
            retained_path_with_severity_change_count = 0
            severity_histogram_only_change_count = 0
            previous_only_exact_anchor_count = 0
            next_only_exact_anchor_count = 0
            retained_severity_changed_anchor_count = 0
            return_to_prior_profile_count = 0
            return_to_reported_profile_count = 0
            return_to_unreported_profile_count = 0
            reported_after_unreported_gap_count = 0
        })
    }

    $transitionBins = [int[]]::new($count)
    $hotspots = [System.Collections.Generic.List[object]]::new()
    $unchangedPaths = 0; $changedPaths = 0; $multipleChanges = 0
    $pathsWithReturn = 0; $pathsWithReportedReturn = 0
    $pathsWithUnreportedReturn = 0; $pathsWithGapReappearance = 0
    $totalTransitions = 0; $totalReturns = 0; $totalReportedReturns = 0
    $totalUnreportedReturns = 0; $totalGapReappearances = 0
    $totalRuns = 0; $longestRun = 0

    foreach ($path in $paths) {
        # Allocate local classes in order of FIRST selected-position appearance.
        # Reuse exactly EC-031's equality predicate: same six-field anchors and
        # per-retained-anchor five-severity Finding-statement histogram.
        # A null path profile is one shared unreported class, NOT file absence.
        $reported = [bool[]]::new($count)
        $profiles = [object[]]::new($count)
        $classIds = [int[]]::new($count)
        $classes = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            $reported[$i] = $byPosition[$i].ContainsKey($path)
            $profiles[$i] = if ($reported[$i]) { $byPosition[$i][$path] } else { $null }
            $classIndex = -1
            for ($j = 0; $j -lt $classes.Count; $j++) {
                if (Test-CodeSequenceSavedPathProfilesEqual -Left $profiles[$i] `
                        -Right $classes[$j].profile) {
                    $classIndex = $j
                    break
                }
            }
            if ($classIndex -lt 0) {
                $classIndex = $classes.Count
                $classes.Add([pscustomobject]@{
                    profile = $profiles[$i]
                    first_position = $i + 1
                    reported = [bool]$reported[$i]
                })
            }
            $classIds[$i] = $classIndex + 1
        }
        if ($classes.Count -lt 1 -or $classes.Count -gt $count) {
            throw 'Code Sequence saved-path transition class count outside selected positions.'
        }

        $events = [System.Collections.Generic.List[object]]::new()
        $runs = [System.Collections.Generic.List[object]]::new()
        $runStart = 1
        $profileReturns = 0; $reportedReturns = 0
        $unreportedReturns = 0; $gapReappearances = 0
        $seenReported = [bool]$reported[0]

        for ($i = 1; $i -lt $count; $i++) {
            $step = $stepMetrics[$i - 1]
            $previousReported = [bool]$reported[$i - 1]
            $nextReported = [bool]$reported[$i]
            if ($previousReported) { $step.previous_reported_path_count++ }
            if ($nextReported) { $step.next_reported_path_count++ }
            if ($previousReported -and $nextReported) { $step.retained_path_count++ }
            elseif ($previousReported) { $step.previous_only_path_count++ }
            elseif ($nextReported) { $step.next_only_path_count++ }
            else { $step.both_unreported_matching_path_count++ }

            if ($classIds[$i - 1] -eq $classIds[$i]) {
                $step.matching_path_profile_count++
            } else {
                # Profile transitions can be a saved-path report start, end,
                # anchor churn, severity-statement change, or both changes.
                # They are NEVER interpreted as fixes or regressions.
                $before = $profiles[$i - 1]
                $after = $profiles[$i]
                $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
                if ($previousReported) { foreach ($key in $before.Keys) { [void]$keys.Add($key) } }
                if ($nextReported) { foreach ($key in $after.Keys) { [void]$keys.Add($key) } }
                $previousOnly = 0; $nextOnly = 0; $severityChanged = 0
                foreach ($key in $keys) {
                    $inPrevious = $previousReported -and $before.ContainsKey($key)
                    $inNext = $nextReported -and $after.ContainsKey($key)
                    if ($inPrevious -and $inNext) {
                        $oldSeverity = Get-CodeSequenceSeverities -Group $before[$key]
                        $newSeverity = Get-CodeSequenceSeverities -Group $after[$key]
                        foreach ($severity in @('critical','high','medium','low','info')) {
                            if ([int]$oldSeverity[$severity] -ne [int]$newSeverity[$severity]) {
                                $severityChanged++
                                break
                            }
                        }
                    } elseif ($inPrevious) { $previousOnly++ }
                    else { $nextOnly++ }
                }
                $anchorDifference = $previousOnly + $nextOnly
                if ($anchorDifference + $severityChanged -le 0 -or
                    ($previousReported -and -not $nextReported -and $previousOnly -ne $before.Count) -or
                    ($nextReported -and -not $previousReported -and $nextOnly -ne $after.Count)) {
                    throw 'Code Sequence changed local class without an exact anchor/severity difference.'
                }
                $step.changed_path_profile_count++
                $step.previous_only_exact_anchor_count += $previousOnly
                $step.next_only_exact_anchor_count += $nextOnly
                $step.retained_severity_changed_anchor_count += $severityChanged
                $kind = if (-not $previousReported) { 'became_reported' } `
                    elseif (-not $nextReported) { 'became_unreported' } else { 'reported_profile_changed' }
                if ($previousReported -and $nextReported) {
                    if ($anchorDifference -gt 0) { $step.retained_path_with_anchor_churn_count++ }
                    if ($severityChanged -gt 0) { $step.retained_path_with_severity_change_count++ }
                    if ($anchorDifference -eq 0) { $step.severity_histogram_only_change_count++ }
                }

                # A return is a class already observed BEFORE this position,
                # separated from that earlier instance by a DIFFERENT class.
                # Class id is path-local; it has no meaning for another path.
                $classFirst = [int]$classes[$classIds[$i] - 1].first_position
                $isReturn = ($classFirst -lt ($i + 1))
                $isReportedReturn = ($isReturn -and $nextReported)
                $isUnreportedReturn = ($isReturn -and -not $nextReported)
                # Unlike a same-profile return, a reported-after-gap event
                # need NOT have the same report profile as before the gap.
                $isGapReappearance = (-not $previousReported -and $nextReported -and $seenReported)
                if ($isReturn) {
                    $profileReturns++
                    $step.return_to_prior_profile_count++
                }
                if ($isReportedReturn) {
                    $reportedReturns++
                    $step.return_to_reported_profile_count++
                }
                if ($isUnreportedReturn) {
                    $unreportedReturns++
                    $step.return_to_unreported_profile_count++
                }
                if ($isGapReappearance) {
                    $gapReappearances++
                    $step.reported_after_unreported_gap_count++
                }
                $events.Add([ordered]@{
                    previous_position = $i
                    next_position = $i + 1
                    previous_record_id = [string]$States[$i - 1].checked.id
                    next_record_id = [string]$States[$i].checked.id
                    from_profile_class = $classIds[$i - 1]
                    to_profile_class = $classIds[$i]
                    transition_kind = $kind
                    previous_reported = $previousReported
                    next_reported = $nextReported
                    previous_only_exact_anchor_count = $previousOnly
                    next_only_exact_anchor_count = $nextOnly
                    retained_severity_changed_anchor_count = $severityChanged
                    severity_histogram_only_change = ($anchorDifference -eq 0 -and $severityChanged -gt 0)
                    returns_to_prior_profile = $isReturn
                    returns_to_reported_profile = $isReportedReturn
                    returns_to_unreported_profile = $isUnreportedReturn
                    reported_after_unreported_gap = $isGapReappearance
                    first_seen_destination_class_at_position = $classFirst
                })
                $runs.Add([ordered]@{
                    run_index = $runs.Count + 1
                    start_position = $runStart
                    end_position = $i
                    length_in_selected_positions = $i - $runStart + 1
                    profile_class = $classIds[$i - 1]
                    path_reported = $previousReported
                })
                $runStart = $i + 1
            }
            if ($nextReported) { $seenReported = $true }
        }
        $runs.Add([ordered]@{
            run_index = $runs.Count + 1
            start_position = $runStart
            end_position = $count
            length_in_selected_positions = $count - $runStart + 1
            profile_class = $classIds[$count - 1]
            path_reported = [bool]$reported[$count - 1]
        })
        $transitions = $events.Count
        if ($runs.Count -ne ($transitions + 1)) {
            throw 'Code Sequence per-path profile runs do not partition position transitions.'
        }
        $localLongest = 0; $runMembers = 0
        foreach ($run in $runs) {
            $runMembers += $run.length_in_selected_positions
            if ($run.length_in_selected_positions -gt $localLongest) {
                $localLongest = $run.length_in_selected_positions
            }
        }
        if ($runMembers -ne $count -or $localLongest -lt 1) {
            throw 'Code Sequence profile runs lost selected positions.'
        }
        if ($localLongest -gt $longestRun) { $longestRun = $localLongest }
        $totalRuns += $runs.Count
        $transitionBins[$transitions]++
        $totalTransitions += $transitions
        $totalReturns += $profileReturns
        $totalReportedReturns += $reportedReturns
        $totalUnreportedReturns += $unreportedReturns
        $totalGapReappearances += $gapReappearances
        if ($profileReturns -gt 0) { $pathsWithReturn++ }
        if ($reportedReturns -gt 0) { $pathsWithReportedReturn++ }
        if ($unreportedReturns -gt 0) { $pathsWithUnreportedReturn++ }
        if ($gapReappearances -gt 0) { $pathsWithGapReappearance++ }
        if ($transitions -eq 0) { $unchangedPaths++; continue }
        $changedPaths++
        if ($transitions -gt 1) { $multipleChanges++ }

        # Navigation previews are capped by PATHS ONLY. Every selected
        # position, run and transition for a displayed path stays complete.
        $positions = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            $positions.Add([ordered]@{
                position = $i + 1
                record_id = [string]$States[$i].checked.id
                profile_class = $classIds[$i]
                path_reported = [bool]$reported[$i]
            })
        }
        $candidate = [ordered]@{
            path = $path
            distinct_profile_class_count = $classes.Count
            profile_transition_count = $transitions
            return_to_prior_profile_count = $profileReturns
            return_to_reported_profile_count = $reportedReturns
            return_to_unreported_profile_count = $unreportedReturns
            reported_after_unreported_gap_count = $gapReappearances
            longest_stable_run_in_selected_positions = $localLongest
            position_profile_classes = $positions.ToArray()
            profile_runs = $runs.ToArray()
            transition_events = $events.ToArray()
        }
        for ($at = 0; $at -lt $hotspots.Count; $at++) {
            if (Test-CodeSequenceTransitionHotspotRanksBefore -Candidate $candidate -Existing $hotspots[$at]) {
                break
            }
        }
        if ($at -lt $Top) {
            $hotspots.Insert($at, $candidate)
            if ($hotspots.Count -gt $Top) { $hotspots.RemoveAt($Top) }
        }
    }

    # Complete adjacent step summaries (including paths unreported on BOTH
    # sides) are reconciled with the independently built EC-025/029 records.
    # These checks are small and do not open or validate any new file.
    for ($i = 0; $i -lt $stepMetrics.Count; $i++) {
        $s = $stepMetrics[$i]
        $expected = $ExpectedAdjacentPathDeltas[$i]
        $c = $expected.counts
        $adjacentPair = $null
        foreach ($pair in $ExpectedAllPairs) {
            if ([int]$pair.left_position -eq ($i + 1) -and
                [int]$pair.right_position -eq ($i + 2)) {
                $adjacentPair = $pair
                break
            }
        }
        if ($null -eq $adjacentPair -or
            $s.previous_record_id -cne $expected.previous_record_id -or
            $s.next_record_id -cne $expected.next_record_id -or
            $s.previous_record_id -cne $adjacentPair.left_record_id -or
            $s.next_record_id -cne $adjacentPair.right_record_id -or
            $s.matching_path_profile_count + $s.changed_path_profile_count -ne $paths.Count -or
            $s.changed_path_profile_count -ne [int]$c.changed_path_count -or
            $s.changed_path_profile_count -ne [int]$adjacentPair.counts.changed_path_count -or
            [bool]$adjacentPair.matches_profile -ne ($s.changed_path_profile_count -eq 0) -or
            $s.previous_reported_path_count -ne [int]$c.previous_reported_path_count -or
            $s.next_reported_path_count -ne [int]$c.next_reported_path_count -or
            $s.retained_path_count -ne [int]$c.retained_path_count -or
            $s.previous_only_path_count -ne [int]$c.previous_only_path_count -or
            $s.next_only_path_count -ne [int]$c.next_only_path_count -or
            $s.retained_path_with_anchor_churn_count -ne [int]$c.retained_path_with_anchor_churn_count -or
            $s.retained_path_with_severity_change_count -ne [int]$c.retained_path_with_severity_distribution_change_count -or
            $s.previous_only_exact_anchor_count -ne [int]$c.previous_only_exact_anchor_count -or
            $s.next_only_exact_anchor_count -ne [int]$c.next_only_exact_anchor_count -or
            $s.retained_severity_changed_anchor_count -ne [int]$c.retained_severity_distribution_changed_count) {
            # Anchor churn and retained severity changes overlap; only the
            # EC-025 changed-path value is compared above, not their sum.
            throw 'Code Sequence saved-path transitions contradict EC-025/029 adjacent comparisons.'
        }
        if ($s.both_unreported_matching_path_count -ne ($paths.Count -
                $s.retained_path_count - $s.previous_only_path_count - $s.next_only_path_count) -or
            $s.return_to_prior_profile_count -ne ($s.return_to_reported_profile_count +
                $s.return_to_unreported_profile_count)) {
            throw 'Code Sequence saved-path transition categories lost unreported or returned classes.'
        }
    }

    $distribution = [System.Collections.Generic.List[object]]::new()
    $binnedPaths = 0; $weightedTransitions = 0
    for ($n = 0; $n -lt $count; $n++) {
        $distribution.Add([ordered]@{ profile_transition_count = $n; saved_path_count = $transitionBins[$n] })
        $binnedPaths += $transitionBins[$n]
        $weightedTransitions += $n * $transitionBins[$n]
    }
    $stepsTotal = 0; $stepReturns = 0; $stepReportedReturns = 0
    $stepUnreportedReturns = 0; $stepGapReappearances = 0
    foreach ($step in $stepMetrics) {
        $stepsTotal += $step.changed_path_profile_count
        $stepReturns += $step.return_to_prior_profile_count
        $stepReportedReturns += $step.return_to_reported_profile_count
        $stepUnreportedReturns += $step.return_to_unreported_profile_count
        $stepGapReappearances += $step.reported_after_unreported_gap_count
    }
    $old = $PathClasses.counts
    if ($binnedPaths -ne $paths.Count -or $weightedTransitions -ne $totalTransitions -or
        $stepsTotal -ne $totalTransitions -or $totalRuns -ne ($paths.Count + $totalTransitions) -or
        $old.distinct_saved_path_union_count -ne $paths.Count -or
        $old.paths_with_single_profile_class_count -ne $unchangedPaths -or
        $old.paths_with_multiple_profile_classes_count -ne $changedPaths -or
        $totalReturns -ne $stepReturns -or
        $totalReportedReturns -ne $stepReportedReturns -or
        $totalUnreportedReturns -ne $stepUnreportedReturns -or
        $totalGapReappearances -ne $stepGapReappearances -or
        $totalReturns -ne ($totalReportedReturns + $totalUnreportedReturns) -or
        $hotspots.Count -ne [Math]::Min($Top, $changedPaths) -or
        ($paths.Count -gt 0 -and $longestRun -lt 1) -or
        ($paths.Count -eq 0 -and $longestRun -ne 0)) {
        throw 'Code Sequence saved-path profile journey accounting is inconsistent.'
    }
    return [ordered]@{
        scope = 'exact_saved_paths_across_caller_ordered_selected_positions_not_verified_time'
        basis = 'EC031_path_local_exact_six_field_anchor_and_five_severity_statement_profile_classes'
        selected_record_count = $count
        step_count = $count - 1
        counts = [ordered]@{
            distinct_saved_path_union_count = $paths.Count
            paths_with_no_profile_transitions_count = $unchangedPaths
            paths_with_profile_transitions_count = $changedPaths
            paths_with_multiple_profile_transitions_count = $multipleChanges
            paths_with_return_to_prior_profile_count = $pathsWithReturn
            paths_with_return_to_reported_profile_count = $pathsWithReportedReturn
            paths_with_return_to_unreported_profile_count = $pathsWithUnreportedReturn
            paths_reported_again_after_unreported_gap_count = $pathsWithGapReappearance
            adjacent_profile_transition_occurrences = $totalTransitions
            return_to_prior_profile_occurrences = $totalReturns
            return_to_reported_profile_occurrences = $totalReportedReturns
            return_to_unreported_profile_occurrences = $totalUnreportedReturns
            reported_again_after_unreported_gap_occurrences = $totalGapReappearances
            total_profile_run_count = $totalRuns
            longest_stable_run_in_selected_positions = $longestRun
        }
        profile_transition_count_distribution = $distribution.ToArray()
        adjacent_steps = $stepMetrics.ToArray()
        preview_top = $Top
        hotspots = $hotspots.ToArray()
        omitted_hotspots = $changedPaths - $hotspots.Count
        hotspots_truncated = ($changedPaths -gt $hotspots.Count)
        explanation = 'Each case-sensitive saved path has its own caller-ordered sequence of exact anchor/severity-statement profile classes. Adjacent changes, profile runs, nonconsecutive returns to a previously observed class, returns to reported/unreported classes, and reported-after-unreported gaps are counted separately. A gap return need not return to the SAME reported class. Full 0..N-1 transition bins and adjacent totals cover every saved path, including positions where a path is unreported in both records; only ranked changed-path preview rows are clipped. Returned classes are historical model-report identities, never source fixes, defect reintroductions, verified chronology, risk levels or deployment evidence. No saved body or business source is opened beyond those already verified by Sequence.'
    }
}

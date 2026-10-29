#requires -Version 7.0
<#
    EC-033: Untruncated, requested-path profile journey in an already checked
    CodeShow Sequence. This is intentionally a separate path-local projection:
    -SequenceTop never hides the requested path, even when it is stable or
    never reported. Reuse ONLY the validated in-memory saved anchor groups;
    do not inspect a business path, new record body, timestamps, or the store.
#>

function Get-CodeSequenceFocusedPathProfileJourney {
    param(
        [object[]] $States,
        [string] $Path,
        [object] $ExistingFocus,
        [object] $GlobalPathClasses,
        [object] $GlobalPathTransitions
    )

    $count = $States.Count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($Path) -or $Path.Length -gt 4096 -or
        $Path.IndexOf([char]0) -ge 0 -or
        $null -eq $ExistingFocus -or $null -eq $GlobalPathClasses -or
        $null -eq $GlobalPathTransitions -or
        $ExistingFocus.path -cne $Path -or
        $ExistingFocus.record_summaries.Count -ne $count -or
        $ExistingFocus.steps.Count -ne ($count - 1) -or
        $GlobalPathTransitions.adjacent_steps.Count -ne ($count - 1)) {
        throw 'Code Sequence focused path journey requires a checked, matching path focus and complete global projections.'
    }

    # No wildcard, path normalization, path existence test, or case folding.
    # Each stored anchor group is already digest/schema/owner checked.
    $profiles = [object[]]::new($count)
    $reported = [bool[]]::new($count)
    $classNumbers = [int[]]::new($count)
    $classes = [System.Collections.Generic.List[object]]::new()
    $positions = [System.Collections.Generic.List[object]]::new()
    $reportedPositions = 0; $totalStatements = 0
    $firstReportedPosition = $null; $lastReportedPosition = $null
    $severities = @('critical','high','medium','low','info')

    for ($i = 0; $i -lt $count; $i++) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $States[$i].groups
        $reported[$i] = $byPath.ContainsKey($Path)
        $profiles[$i] = if ($reported[$i]) { $byPath[$Path] } else { $null }
        $anchorCount = if ($reported[$i]) { $profiles[$i].Count } else { 0 }
        $statementCount = 0
        $severityCounts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
        if ($reported[$i]) {
            $reportedPositions++
            if ($null -eq $firstReportedPosition) { $firstReportedPosition = $i + 1 }
            $lastReportedPosition = $i + 1
            foreach ($group in $profiles[$i].Values) {
                $statementCount += $group.findings.Count
                $histogram = Get-CodeSequenceSeverities -Group $group
                foreach ($severity in $severities) {
                    $severityCounts[$severity] = [int]$severityCounts[$severity] + [int]$histogram[$severity]
                }
            }
        }
        $totalStatements += $statementCount
        $matchingSummary = $ExistingFocus.record_summaries[$i]
        if ($matchingSummary.record_id -cne $States[$i].checked.id -or
            [int]$matchingSummary.matching_exact_anchor_count -ne $anchorCount -or
            [int]$matchingSummary.matching_finding_statement_count -ne $statementCount -or
            [bool]$matchingSummary.path_reported -ne [bool]$reported[$i]) {
            throw 'Code Sequence focused path journey contradicts the checked focused record summaries.'
        }

        # Profile representatives are compared by EC-031's exact anchor keys
        # PLUS each retained anchor's five-severity statement histogram.
        # An unreported path has ONE shared null-profile class.
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
                representative_position = $i + 1
                path_reported = [bool]$reported[$i]
                exact_anchor_count = $anchorCount
                finding_statement_count = $statementCount
                severity_statement_counts = $severityCounts
                positions = [System.Collections.Generic.List[int]]::new()
                record_ids = [System.Collections.Generic.List[string]]::new()
            })
        }
        $classNumbers[$i] = $classIndex + 1
        $classes[$classIndex].positions.Add($i + 1)
        $classes[$classIndex].record_ids.Add([string]$States[$i].checked.id)
        $positions.Add([ordered]@{
            position = $i + 1
            record_id = [string]$States[$i].checked.id
            profile_class = $classNumbers[$i]
            path_reported = [bool]$reported[$i]
            exact_anchor_count = $anchorCount
            finding_statement_count = $statementCount
            severity_statement_counts = $severityCounts
        })
    }

    if ($reportedPositions -ne [int]$ExistingFocus.matching_record_count -or
        $totalStatements -ne [int]$ExistingFocus.matching_finding_statement_count -or
        [bool]$ExistingFocus.path_found_in_selected_records -ne ($reportedPositions -gt 0)) {
        throw 'Code Sequence focused path reporting totals contradict the original focus.'
    }
    $classRows = [System.Collections.Generic.List[object]]::new()
    $reportedClasses = 0; $unreportedClasses = 0
    for ($j = 0; $j -lt $classes.Count; $j++) {
        $c = $classes[$j]
        if ($c.path_reported) { $reportedClasses++ } else { $unreportedClasses++ }
        $classRows.Add([ordered]@{
            profile_class = $j + 1
            representative_position = $c.representative_position
            representative_record_id = [string]$States[$c.representative_position - 1].checked.id
            path_reported = $c.path_reported
            exact_anchor_count = $c.exact_anchor_count
            finding_statement_count = $c.finding_statement_count
            severity_statement_counts = $c.severity_statement_counts
            member_count = $c.positions.Count
            positions = $c.positions.ToArray()
            record_ids = $c.record_ids.ToArray()
        })
    }
    if (($reportedPositions -eq 0 -and ($classes.Count -ne 1 -or $unreportedClasses -ne 1)) -or
        ($reportedPositions -gt 0 -and $reportedClasses -lt 1) -or $unreportedClasses -gt 1) {
        throw 'Code Sequence focused path journey lost its unreported or first-seen profile classes.'
    }

    # Untruncated adjacent events and maximal contiguous equal-class runs.
    # A nonconsecutive exact return is distinct from a path appearing after
    # an unreported gap with a *different* saved profile.
    $runs = [System.Collections.Generic.List[object]]::new()
    $events = [System.Collections.Generic.List[object]]::new()
    $runStart = 1
    $seenReported = [bool]$reported[0]
    $returnCount = 0; $reportedReturnCount = 0; $unreportedReturnCount = 0
    $gapReappearanceCount = 0
    for ($i = 1; $i -lt $count; $i++) {
        $previous = $profiles[$i - 1]
        $next = $profiles[$i]
        $previousReported = [bool]$reported[$i - 1]
        $nextReported = [bool]$reported[$i]
        $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        if ($previousReported) { foreach ($key in $previous.Keys) { [void]$keys.Add($key) } }
        if ($nextReported) { foreach ($key in $next.Keys) { [void]$keys.Add($key) } }
        $previousOnly = 0; $nextOnly = 0; $retained = 0; $severityChanged = 0
        foreach ($key in $keys) {
            $was = $previousReported -and $previous.ContainsKey($key)
            $now = $nextReported -and $next.ContainsKey($key)
            if ($was -and $now) {
                $retained++
                $oldHistogram = Get-CodeSequenceSeverities -Group $previous[$key]
                $newHistogram = Get-CodeSequenceSeverities -Group $next[$key]
                foreach ($severity in $severities) {
                    if ([int]$oldHistogram[$severity] -ne [int]$newHistogram[$severity]) {
                        $severityChanged++
                        break
                    }
                }
            } elseif ($was) { $previousOnly++ }
            else { $nextOnly++ }
        }
        $step = $ExistingFocus.steps[$i - 1]
        $globalStep = $GlobalPathTransitions.adjacent_steps[$i - 1]
        if ([int]$step.step -ne $i -or
            $step.previous_record_id -cne $States[$i - 1].checked.id -or
            $step.next_record_id -cne $States[$i].checked.id -or
            [int]$step.counts.retained_exact_anchor_count -ne $retained -or
            [int]$step.counts.previous_only_exact_anchor_count -ne $previousOnly -or
            [int]$step.counts.next_only_exact_anchor_count -ne $nextOnly -or
            [int]$step.counts.retained_severity_distribution_changed_count -ne $severityChanged -or
            [int]$globalStep.step -ne $i -or
            $globalStep.previous_record_id -cne $step.previous_record_id -or
            $globalStep.next_record_id -cne $step.next_record_id) {
            throw 'Code Sequence focused path journey differs from the existing adjacent step evidence.'
        }
        $changed = ($classNumbers[$i - 1] -ne $classNumbers[$i])
        if ($changed -ne (($previousOnly + $nextOnly + $severityChanged) -gt 0)) {
            throw 'Code Sequence focused path class transition disagrees with exact anchor/severity counts.'
        }
        if ($changed) {
            $classFirst = [int]$classes[$classNumbers[$i] - 1].representative_position
            $isReturn = ($classFirst -lt ($i + 1))
            $isReportedReturn = ($isReturn -and $nextReported)
            $isUnreportedReturn = ($isReturn -and -not $nextReported)
            $afterGap = (-not $previousReported -and $nextReported -and $seenReported)
            if ($isReturn) { $returnCount++ }
            if ($isReportedReturn) { $reportedReturnCount++ }
            if ($isUnreportedReturn) { $unreportedReturnCount++ }
            if ($afterGap) { $gapReappearanceCount++ }
            $transitionKind = if (-not $previousReported) { 'became_reported' } `
                elseif (-not $nextReported) { 'became_unreported' } else { 'reported_profile_changed' }
            $events.Add([ordered]@{
                previous_position = $i
                next_position = $i + 1
                previous_record_id = [string]$States[$i - 1].checked.id
                next_record_id = [string]$States[$i].checked.id
                from_profile_class = $classNumbers[$i - 1]
                to_profile_class = $classNumbers[$i]
                transition_kind = $transitionKind
                previous_reported = $previousReported
                next_reported = $nextReported
                previous_only_exact_anchor_count = $previousOnly
                next_only_exact_anchor_count = $nextOnly
                retained_severity_changed_anchor_count = $severityChanged
                severity_histogram_only_change = (($previousOnly + $nextOnly) -eq 0 -and $severityChanged -gt 0)
                returns_to_prior_profile = $isReturn
                returns_to_reported_profile = $isReportedReturn
                returns_to_unreported_profile = $isUnreportedReturn
                reported_after_unreported_gap = $afterGap
                first_seen_destination_class_at_position = $classFirst
            })
            $runs.Add([ordered]@{
                run_index = $runs.Count + 1
                start_position = $runStart
                end_position = $i
                length_in_selected_positions = $i - $runStart + 1
                profile_class = $classNumbers[$i - 1]
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
        profile_class = $classNumbers[$count - 1]
        path_reported = [bool]$reported[$count - 1]
    })
    $longestRun = 0; $runPositionSum = 0
    foreach ($run in $runs) {
        $runPositionSum += $run.length_in_selected_positions
        if ($run.length_in_selected_positions -gt $longestRun) {
            $longestRun = $run.length_in_selected_positions
        }
    }
    if ($runs.Count -ne ($events.Count + 1) -or $runPositionSum -ne $count -or
        $returnCount -ne ($reportedReturnCount + $unreportedReturnCount) -or
        $events.Count -gt ($count - 1)) {
        throw 'Code Sequence focused path run or return accounting is inconsistent.'
    }

    # Independently check matching global top rows WHEN the exact path
    # happens to be in one; no dependence on being ranked into any preview.
    $globalHotspot = $null
    foreach ($hotspot in $GlobalPathTransitions.hotspots) {
        if ([string]::Equals([string]$hotspot.path, $Path, [System.StringComparison]::Ordinal)) {
            $globalHotspot = $hotspot
            break
        }
    }
    if ($null -ne $globalHotspot) {
        if ([int]$globalHotspot.profile_transition_count -ne $events.Count -or
            [int]$globalHotspot.return_to_prior_profile_count -ne $returnCount -or
            [int]$globalHotspot.return_to_reported_profile_count -ne $reportedReturnCount -or
            [int]$globalHotspot.return_to_unreported_profile_count -ne $unreportedReturnCount -or
            [int]$globalHotspot.reported_after_unreported_gap_count -ne $gapReappearanceCount -or
            [int]$globalHotspot.longest_stable_run_in_selected_positions -ne $longestRun -or
            [int]$globalHotspot.distinct_profile_class_count -ne $classes.Count -or
            $globalHotspot.transition_events.Count -ne $events.Count -or
            $globalHotspot.profile_runs.Count -ne $runs.Count -or
            (@($globalHotspot.position_profile_classes | ForEach-Object { $_.profile_class }) -join ',') -cne
                ($classNumbers -join ',')) {
            throw 'Code Sequence focused path journey contradicts the ranked EC-032 path preview.'
        }
    }
    foreach ($hotspot in $GlobalPathClasses.hotspots) {
        if ([string]::Equals([string]$hotspot.path, $Path, [System.StringComparison]::Ordinal)) {
            if ([int]$hotspot.distinct_profile_class_count -ne $classes.Count -or
                $hotspot.profile_classes.Count -ne $classes.Count -or
                (@($hotspot.position_profile_classes | ForEach-Object { $_.profile_class }) -join ',') -cne
                    ($classNumbers -join ',')) {
                throw 'Code Sequence focused path classes disagree with the EC-031 local class preview.'
            }
            break
        }
    }
    if ($reportedPositions -gt 0 -and
        ($GlobalPathClasses.counts.distinct_saved_path_union_count -lt 1 -or
         $GlobalPathTransitions.counts.distinct_saved_path_union_count -lt 1)) {
        throw 'Code Sequence focused reported path was lost from the global saved path union.'
    }

    return [ordered]@{
        scope = 'one_literal_case_sensitive_saved_path_across_checked_caller_positions_not_time'
        path = $Path
        path_found_in_selected_records = ($reportedPositions -gt 0)
        selected_record_count = $count
        included_in_global_transition_hotspots = ($null -ne $globalHotspot)
        independent_of_sequence_top = $true
        counts = [ordered]@{
            reporting_position_count = $reportedPositions
            unreported_position_count = $count - $reportedPositions
            first_reported_position = $firstReportedPosition
            last_reported_position = $lastReportedPosition
            finding_statement_occurrences = $totalStatements
            distinct_profile_class_count = $classes.Count
            reported_profile_class_count = $reportedClasses
            unreported_profile_class_count = $unreportedClasses
            profile_transition_count = $events.Count
            profile_run_count = $runs.Count
            longest_stable_run_in_selected_positions = $longestRun
            return_to_prior_profile_count = $returnCount
            return_to_reported_profile_count = $reportedReturnCount
            return_to_unreported_profile_count = $unreportedReturnCount
            reported_after_unreported_gap_count = $gapReappearanceCount
        }
        position_profile_classes = $positions.ToArray()
        profile_classes = $classRows.ToArray()
        profile_runs = $runs.ToArray()
        transition_events = $events.ToArray()
        explanation = 'A requested exact saved path is returned in full regardless of SequenceTop or global hotspot ranking, including unchanged paths and a single unreported class/run for a path never cited by the selected model reports. Class identity uses exact saved quotation-anchor membership and retained-anchor severity-statement histograms; positional membership, representative summaries, maximal runs and changed-step events are complete. No missing citation proves a missing source file, resolved defect, chronological repair/regression or verified code state. No additional saved record body, business file or writer was accessed.'
    }
}

# EC-034: the path-specific trajectory preview of EC-023 is intentionally
# capped. Provide a separate, COMPLETE anchor-by-anchor navigation ledger for
# an EXPLICIT literal focus using only already checked in-memory groups.
# The total number of anchors is bounded by 12 records x 40 Findings.
function Test-CodeSequenceFocusedSeverityEqual {
    param([AllowNull()][object] $Left, [AllowNull()][object] $Right)

    if ($null -eq $Left -or $null -eq $Right) {
        return ($null -eq $Left -and $null -eq $Right)
    }
    foreach ($severity in @('critical','high','medium','low','info')) {
        if ([int]$Left[$severity] -ne [int]$Right[$severity]) { return $false }
    }
    return $true
}

function Get-CodeSequenceFocusedAnchorJourneys {
    param(
        [object[]] $States,
        [string] $Path,
        [object] $ExistingFocus,
        [object] $ExistingProfileJourney
    )

    $count = $States.Count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($Path) -or $Path.Length -gt 4096 -or
        $Path.IndexOf([char]0) -ge 0 -or $null -eq $ExistingFocus -or
        $null -eq $ExistingProfileJourney -or
        $ExistingFocus.path -cne $Path -or $ExistingProfileJourney.path -cne $Path -or
        $ExistingFocus.record_summaries.Count -ne $count -or
        $ExistingProfileJourney.position_profile_classes.Count -ne $count -or
        $ExistingFocus.steps.Count -ne ($count - 1)) {
        throw 'Code Sequence anchor journeys require a complete checked literal path focus and path profile journey.'
    }

    $maps = [System.Collections.Generic.List[object]]::new()
    $allKeys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $count; $i++) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $States[$i].groups
        $groupMap = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        if ($byPath.ContainsKey($Path)) {
            $groupMap = $byPath[$Path]
            foreach ($key in $groupMap.Keys) { [void]$allKeys.Add($key) }
        }
        $maps.Add($groupMap)
    }
    if ($allKeys.Count -gt ($count * 40)) {
        throw 'Code Sequence focused anchor union exceeds checked saved Finding bounds.'
    }

    $perPositionAnchors = [int[]]::new($count)
    $perPositionStatements = [int[]]::new($count)
    $perPositionSeverities = [object[]]::new($count)
    for ($i = 0; $i -lt $count; $i++) {
        $perPositionSeverities[$i] = [ordered]@{
            critical = 0; high = 0; medium = 0; low = 0; info = 0
        }
    }
    $stepCounts = [object[]]::new($count - 1)
    for ($i = 0; $i -lt ($count - 1); $i++) {
        $stepCounts[$i] = [ordered]@{
            previous_only_exact_anchor_count = 0
            next_only_exact_anchor_count = 0
            retained_severity_distribution_changed_count = 0
        }
    }
    $supportCounts = [int[]]::new($count + 1)
    $every = 0; $once = 0; $multipleNotEvery = 0
    $reappeared = 0; $firstAndLast = 0; $severityVaried = 0
    $presenceTransitions = 0; $severityTransitions = 0
    $totalStatementOccurrences = 0; $totalPresenceRuns = 0; $totalEvents = 0
    $all = [System.Collections.Generic.List[object]]::new()
    $severityNames = @('critical','high','medium','low','info')

    # Every sorted exact key has at least one checked supporting saved record.
    # No wildcard expansion, case folding, live file read or source quote copy.
    foreach ($key in $allKeys) {
        $anchor = $null
        $observations = [System.Collections.Generic.List[object]]::new()
        $pattern = [System.Text.StringBuilder]::new()
        $presentPositions = [bool[]]::new($count)
        $histograms = [object[]]::new($count)
        $statementCounts = [int[]]::new($count)
        $support = 0; $anchorStatements = 0
        $firstPosition = $null; $lastPosition = $null
        $firstHistogram = $null; $varied = $false
        $hadReport = $false; $unreportedGapAfterReport = $false
        $reportedAfterGap = $false

        for ($i = 0; $i -lt $count; $i++) {
            $present = $maps[$i].ContainsKey($key)
            $presentPositions[$i] = $present
            [void]$pattern.Append($(if ($present) { '1' } else { '0' }))
            if ($present) {
                $group = $maps[$i][$key]
                if ($null -eq $anchor) { $anchor = $group.anchor }
                $histogram = Get-CodeSequenceSeverities -Group $group
                $histograms[$i] = $histogram
                $statementCounts[$i] = $group.findings.Count
                $support++
                if ($null -eq $firstPosition) { $firstPosition = $i + 1 }
                $lastPosition = $i + 1
                if ($unreportedGapAfterReport) { $reportedAfterGap = $true }
                $hadReport = $true
                $unreportedGapAfterReport = $false
                if ($null -eq $firstHistogram) { $firstHistogram = $histogram }
                elseif (-not (Test-CodeSequenceFocusedSeverityEqual -Left $firstHistogram -Right $histogram)) {
                    $varied = $true
                }
                $perPositionAnchors[$i]++
                $perPositionStatements[$i] += $statementCounts[$i]
                foreach ($severity in $severityNames) {
                    $perPositionSeverities[$i][$severity] = [int]$perPositionSeverities[$i][$severity] + [int]$histogram[$severity]
                }
            } elseif ($hadReport) {
                $unreportedGapAfterReport = $true
            }
            $anchorStatements += $statementCounts[$i]
            $observations.Add([ordered]@{
                position = $i + 1
                record_id = [string]$States[$i].checked.id
                reported = $present
                finding_statement_count = $statementCounts[$i]
                severity_statement_counts = if ($present) { $histograms[$i] } else { $null }
            })
        }
        if ($support -lt 1 -or $null -eq $anchor) {
            throw 'Code Sequence focused anchor journey contained an unsupported exact anchor.'
        }
        $totalStatementOccurrences += $anchorStatements
        $supportCounts[$support]++
        if ($support -eq $count) { $every++ }
        elseif ($support -eq 1) { $once++ }
        else { $multipleNotEvery++ }
        if ($reportedAfterGap) { $reappeared++ }
        if ($presentPositions[0] -and $presentPositions[$count - 1]) { $firstAndLast++ }
        if ($varied) { $severityVaried++ }

        # Runs partition ALL caller positions, including explicit absence runs.
        # Events describe only adjacent 0/1 transitions or retained-anchor
        # changes to the five-severity Finding-STATEMENT histogram.
        $runs = [System.Collections.Generic.List[object]]::new()
        $events = [System.Collections.Generic.List[object]]::new()
        $runStart = 1
        $presenceEventCount = 0
        $everPreviouslyReported = [bool]$presentPositions[0]
        for ($i = 1; $i -lt $count; $i++) {
            $was = [bool]$presentPositions[$i - 1]
            $now = [bool]$presentPositions[$i]
            if ($was -ne $now) {
                $presenceTransitions++
                $kind = if ($now) { 'became_reported' } else { 'became_unreported' }
                if ($was) { $stepCounts[$i - 1].previous_only_exact_anchor_count++ }
                else { $stepCounts[$i - 1].next_only_exact_anchor_count++ }
            } elseif ($was -and -not (Test-CodeSequenceFocusedSeverityEqual `
                    -Left $histograms[$i - 1] -Right $histograms[$i])) {
                $kind = 'retained_severity_histogram_changed'
                $stepCounts[$i - 1].retained_severity_distribution_changed_count++
                $severityTransitions++
            } else {
                $kind = $null
            }
            if ($was -ne $now) {
                $presenceEventCount++
                $runs.Add([ordered]@{
                    run_index = $runs.Count + 1
                    start_position = $runStart
                    end_position = $i
                    length_in_selected_positions = $i - $runStart + 1
                    reported = $was
                })
                $runStart = $i + 1
            }
            if ($null -ne $kind) {
                $events.Add([ordered]@{
                    previous_position = $i
                    next_position = $i + 1
                    previous_record_id = [string]$States[$i - 1].checked.id
                    next_record_id = [string]$States[$i].checked.id
                    transition_kind = $kind
                    previously_reported = $was
                    next_reported = $now
                    previous_finding_statement_count = $statementCounts[$i - 1]
                    next_finding_statement_count = $statementCounts[$i]
                    previous_severity_statement_counts = if ($was) { $histograms[$i - 1] } else { $null }
                    next_severity_statement_counts = if ($now) { $histograms[$i] } else { $null }
                    reported_after_unreported_gap = (-not $was -and $now -and $everPreviouslyReported)
                })
            }
            if ($now) { $everPreviouslyReported = $true }
        }
        $runs.Add([ordered]@{
            run_index = $runs.Count + 1
            start_position = $runStart
            end_position = $count
            length_in_selected_positions = $count - $runStart + 1
            reported = [bool]$presentPositions[$count - 1]
        })
        $runPositions = 0
        foreach ($run in $runs) { $runPositions += $run.length_in_selected_positions }
        if ($runPositions -ne $count -or $runs.Count -gt $count -or
            $events.Count -gt ($count - 1) -or ($runs.Count - 1) -ne $presenceEventCount) {
            throw 'Code Sequence focused anchor presence runs or adjacent events do not partition the selection.'
        }
        $totalPresenceRuns += $runs.Count
        $totalEvents += $events.Count
        $all.Add([ordered]@{
            anchor = $anchor
            presence_pattern = $pattern.ToString()
            reporting_record_count = $support
            finding_statement_occurrences = $anchorStatements
            first_reported_position = $firstPosition
            last_reported_position = $lastPosition
            reported_after_unreported_gap = $reportedAfterGap
            severity_distribution_varied_across_reported_positions = $varied
            observations_in_caller_order = $observations.ToArray()
            presence_runs = $runs.ToArray()
            transition_events = $events.ToArray()
        })
    }

    # Unlike preview rows, independent complete old summaries MUST agree for
    # every position, every adjacent step, support bin, and the whole union.
    $positionRows = [System.Collections.Generic.List[object]]::new()
    $statementSum = 0
    for ($i = 0; $i -lt $count; $i++) {
        $summary = $ExistingFocus.record_summaries[$i]
        $profile = $ExistingProfileJourney.position_profile_classes[$i]
        if ($summary.record_id -cne $States[$i].checked.id -or
            $profile.record_id -cne $States[$i].checked.id -or
            [int]$summary.matching_exact_anchor_count -ne $perPositionAnchors[$i] -or
            [int]$summary.matching_finding_statement_count -ne $perPositionStatements[$i] -or
            [bool]$summary.path_reported -ne ($perPositionAnchors[$i] -gt 0) -or
            [int]$profile.exact_anchor_count -ne $perPositionAnchors[$i] -or
            [int]$profile.finding_statement_count -ne $perPositionStatements[$i] -or
            [bool]$profile.path_reported -ne ($perPositionAnchors[$i] -gt 0) -or
            -not (Test-CodeSequenceFocusedSeverityEqual `
                -Left $profile.severity_statement_counts -Right $perPositionSeverities[$i])) {
            throw 'Code Sequence focused anchor per-position totals contradict checked path projections.'
        }
        $severityStatementSum = 0
        foreach ($severity in $severityNames) {
            $severityStatementSum += [int]$perPositionSeverities[$i][$severity]
        }
        if ($severityStatementSum -ne $perPositionStatements[$i]) {
            throw 'Code Sequence focused anchor severity categories lost or duplicated saved Finding statements.'
        }
        $statementSum += $perPositionStatements[$i]
        $positionRows.Add([ordered]@{
            position = $i + 1
            record_id = [string]$States[$i].checked.id
            reported_exact_anchor_count = $perPositionAnchors[$i]
            finding_statement_count = $perPositionStatements[$i]
            severity_statement_counts = $perPositionSeverities[$i]
        })
    }
    for ($i = 0; $i -lt ($count - 1); $i++) {
        $step = $ExistingFocus.steps[$i]
        if ([int]$step.step -ne ($i + 1) -or
            $step.previous_record_id -cne $States[$i].checked.id -or
            $step.next_record_id -cne $States[$i + 1].checked.id -or
            [int]$step.counts.previous_only_exact_anchor_count -ne
                $stepCounts[$i].previous_only_exact_anchor_count -or
            [int]$step.counts.next_only_exact_anchor_count -ne
                $stepCounts[$i].next_only_exact_anchor_count -or
            [int]$step.counts.retained_severity_distribution_changed_count -ne
                $stepCounts[$i].retained_severity_distribution_changed_count -or
            [int]$step.previous_finding_statement_count -ne $perPositionStatements[$i] -or
            [int]$step.next_finding_statement_count -ne $perPositionStatements[$i + 1]) {
            throw 'Code Sequence focused anchor adjacent transitions contradict checked path step totals.'
        }
    }
    $oldTrajectory = $ExistingFocus.anchor_trajectory
    $oldCounts = $oldTrajectory.counts
    if ($all.Count -ne [int]$oldCounts.distinct_exact_anchor_union_count -or
        $every -ne [int]$oldCounts.reported_in_every_record_count -or
        $once -ne [int]$oldCounts.reported_once_count -or
        $multipleNotEvery -ne [int]$oldCounts.reported_in_multiple_but_not_every_record_count -or
        $reappeared -ne [int]$oldCounts.reappeared_after_at_least_one_unreported_position_count -or
        $firstAndLast -ne [int]$oldCounts.reported_in_first_and_last_count -or
        $severityVaried -ne [int]$oldCounts.severity_distribution_varied_across_reported_positions_count -or
        $presenceTransitions -ne [int]$oldCounts.presence_transitions_across_adjacent_pairs_count -or
        $statementSum -ne $totalStatementOccurrences -or
        $statementSum -ne [int]$ExistingFocus.matching_finding_statement_count -or
        $oldTrajectory.reporting_record_count_distribution.Count -ne $count) {
        throw 'Code Sequence focused anchor union disagrees with complete saved trajectory or Finding totals.'
    }
    $supportDistribution = [System.Collections.Generic.List[object]]::new()
    $supportWeighted = 0
    for ($n = 1; $n -le $count; $n++) {
        $supportWeighted += $n * $supportCounts[$n]
        if ([int]$oldTrajectory.reporting_record_count_distribution[$n - 1].reporting_record_count -ne $n -or
            [int]$oldTrajectory.reporting_record_count_distribution[$n - 1].distinct_exact_anchor_count -ne
                $supportCounts[$n]) {
            throw 'Code Sequence focused anchor support distribution contradicts existing trajectory.'
        }
        $supportDistribution.Add([ordered]@{
            reporting_record_count = $n
            distinct_exact_anchor_count = $supportCounts[$n]
        })
    }
    $positionAnchorSum = 0
    foreach ($number in $perPositionAnchors) { $positionAnchorSum += $number }
    if ($totalPresenceRuns -ne ($all.Count + $presenceTransitions) -or
        $totalEvents -ne ($presenceTransitions + $severityTransitions) -or
        $positionAnchorSum -ne $supportWeighted -or
        ($every + $once + $multipleNotEvery) -ne $all.Count -or
        [bool]$ExistingFocus.path_found_in_selected_records -ne ($all.Count -gt 0) -or
        [bool]$ExistingProfileJourney.path_found_in_selected_records -ne ($all.Count -gt 0)) {
        throw 'Code Sequence focused anchor occurrence conservation failed.'
    }

    return [ordered]@{
        scope = 'complete_exact_six_field_saved_anchor_journeys_for_one_literal_path_not_time'
        path = $Path
        path_found_in_selected_records = ($all.Count -gt 0)
        independent_of_sequence_top = $true
        selected_record_count = $count
        sort_order = 'ordinal_canonical_exact_anchor_key_not_risk_or_time'
        counts = [ordered]@{
            distinct_exact_anchor_union_count = $all.Count
            finding_statement_occurrences = $totalStatementOccurrences
            reported_exact_anchor_position_occurrences = $positionAnchorSum
            reported_in_every_record_count = $every
            reported_once_count = $once
            reported_in_multiple_but_not_every_record_count = $multipleNotEvery
            reappeared_after_at_least_one_unreported_position_count = $reappeared
            reported_in_first_and_last_count = $firstAndLast
            severity_distribution_varied_across_reported_positions_count = $severityVaried
            presence_transitions_across_adjacent_pairs_count = $presenceTransitions
            retained_severity_histogram_transition_count = $severityTransitions
            anchor_presence_run_count = $totalPresenceRuns
            anchor_transition_event_count = $totalEvents
        }
        reporting_record_count_distribution = $supportDistribution.ToArray()
        position_totals = $positionRows.ToArray()
        adjacent_step_totals = $stepCounts
        anchors = $all.ToArray()
        explanation = 'Every exact six-field saved quote anchor on the explicitly requested case-sensitive Git path is shown regardless of SequenceTop, in canonical ordinal order. Each includes every selected record position, presence bits, saved Finding-statement multiplicity and five-severity histogram, complete maximal presence/absence runs and adjacent presence/severity changes. Absence from a selected model report is not evidence of missing source or defect resolution; caller order does not prove time. No original quotation, model prose, source read or write is performed.'
    }
}

# EC-035: group the complete EC-034 anchor ledger by an exact 0/1 reporting
# pattern. This is purely a projection of checked, already-returned metadata:
# no new saved-record/body read, source access, selection, or write. Cohort
# anchor_indices are one-based indexes into anchor_journeys.anchors.
function Get-CodeSequenceFocusedAnchorCohorts {
    param([object] $Journeys)

    if ($null -eq $Journeys) {
        throw 'Code Sequence focused anchor cohorts require a complete anchor ledger.'
    }
    $count = [int]$Journeys.selected_record_count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty([string]$Journeys.path) -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        $null -eq $Journeys.anchors -or
        $Journeys.anchors.Count -gt ($count * 40) -or
        $Journeys.position_totals.Count -ne $count -or
        $Journeys.adjacent_step_totals.Count -ne ($count - 1) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $Journeys.anchors.Count) {
        throw 'Code Sequence focused anchor cohorts received an incomplete bounded anchor ledger.'
    }

    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $cohortsByPattern = [System.Collections.Generic.SortedDictionary[string,object]]::new(
        [System.StringComparer]::Ordinal)
    $shapes = [ordered]@{
        every_position = 0
        one_position = 0
        contiguous_partial = 0
        reappeared_after_gap = 0
    }
    $reappearedCount = 0
    $variedCount = 0
    $observedAnchorPositions = 0
    $observedStatements = 0

    for ($anchorIndex = 0; $anchorIndex -lt $Journeys.anchors.Count; $anchorIndex++) {
        $anchor = $Journeys.anchors[$anchorIndex]
        $pattern = [string]$anchor.presence_pattern
        if ($pattern.Length -ne $count -or $pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $count) {
            throw 'Code Sequence focused anchor cohort found an invalid presence pattern or observation count.'
        }
        $presentPositions = [System.Collections.Generic.List[int]]::new()
        $absentPositions = [System.Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            if ($pattern[$i] -eq [char]'1') { $presentPositions.Add($i + 1) }
            else { $absentPositions.Add($i + 1) }
        }
        $support = $presentPositions.Count
        $gapped = [regex]::IsMatch($pattern, '10+1')
        if ($support -lt 1 -or $support -ne [int]$anchor.reporting_record_count -or
            $gapped -ne [bool]$anchor.reported_after_unreported_gap) {
            throw 'Code Sequence focused anchor cohort disagrees with exact anchor support or reporting gaps.'
        }
        $shape = if ($support -eq $count) { 'every_position' }
            elseif ($support -eq 1) { 'one_position' }
            elseif ($gapped) { 'reappeared_after_gap' }
            else { 'contiguous_partial' }

        if (-not $cohortsByPattern.ContainsKey($pattern)) {
            $positionHistograms = [object[]]::new($count)
            for ($i = 0; $i -lt $count; $i++) {
                $positionHistograms[$i] = [ordered]@{
                    critical = 0; high = 0; medium = 0; low = 0; info = 0
                }
            }
            $cohortsByPattern.Add($pattern, [pscustomobject]@{
                pattern = $pattern
                shape = $shape
                support = $support
                present_positions = $presentPositions.ToArray()
                absent_positions = $absentPositions.ToArray()
                anchor_indices = [System.Collections.Generic.List[int]]::new()
                finding_statements = 0
                varied_anchors = 0
                statement_totals = [int[]]::new($count)
                severity_totals = $positionHistograms
                retained_severity_changes = [int[]]::new($count - 1)
            })
        }
        $cohort = $cohortsByPattern[$pattern]
        $cohort.anchor_indices.Add($anchorIndex + 1)
        if ($cohort.shape -cne $shape -or $cohort.support -ne $support) {
            throw 'Code Sequence focused anchor cohort mixed incompatible reporting patterns.'
        }
        $anchorStatements = 0
        $firstReportedHistogram = $null
        $varied = $false
        for ($i = 0; $i -lt $count; $i++) {
            $observation = $anchor.observations_in_caller_order[$i]
            $present = ($pattern[$i] -eq [char]'1')
            if ([int]$observation.position -ne ($i + 1) -or
                $observation.record_id -cne $Journeys.position_totals[$i].record_id -or
                [bool]$observation.reported -ne $present) {
                throw 'Code Sequence focused anchor cohort found inconsistent caller-order observations.'
            }
            $statements = [int]$observation.finding_statement_count
            $histogram = $observation.severity_statement_counts
            if (($present -and ($statements -lt 1 -or $null -eq $histogram)) -or
                (-not $present -and ($statements -ne 0 -or $null -ne $histogram))) {
                throw 'Code Sequence focused anchor cohort found inconsistent statement presence.'
            }
            $histogramSum = 0
            if ($present) {
                foreach ($severity in $severityNames) {
                    $value = [int]$histogram[$severity]
                    if ($value -lt 0) {
                        throw 'Code Sequence focused anchor cohort found a negative saved-severity count.'
                    }
                    $histogramSum += $value
                    $cohort.severity_totals[$i][$severity] =
                        [int]$cohort.severity_totals[$i][$severity] + $value
                }
                if ($null -eq $firstReportedHistogram) { $firstReportedHistogram = $histogram }
                elseif (-not (Test-CodeSequenceFocusedSeverityEqual `
                        -Left $firstReportedHistogram -Right $histogram)) {
                    $varied = $true
                }
            }
            if ($histogramSum -ne $statements) {
                throw 'Code Sequence focused anchor cohort lost saved Finding-statement multiplicity.'
            }
            $cohort.statement_totals[$i] += $statements
            $anchorStatements += $statements
            if ($i -gt 0 -and $present -and $pattern[$i - 1] -eq [char]'1') {
                $previousHistogram = $anchor.observations_in_caller_order[$i - 1].severity_statement_counts
                if (-not (Test-CodeSequenceFocusedSeverityEqual `
                        -Left $previousHistogram -Right $histogram)) {
                    $cohort.retained_severity_changes[$i - 1]++
                }
            }
        }
        if ($anchorStatements -ne [int]$anchor.finding_statement_occurrences -or
            $varied -ne [bool]$anchor.severity_distribution_varied_across_reported_positions) {
            throw 'Code Sequence focused anchor cohort contradicts exact anchor severity history.'
        }
        $cohort.finding_statements += $anchorStatements
        if ($varied) {
            $cohort.varied_anchors++
            $variedCount++
        }
        if ($gapped) { $reappearedCount++ }
        $shapes[$shape] = [int]$shapes[$shape] + 1
        $observedAnchorPositions += $support
        $observedStatements += $anchorStatements
    }

    # All groups are complete, sorted by the ordinal binary presence pattern.
    # Indices retain EC-034's canonical six-field anchor ordering.
    $all = [System.Collections.Generic.List[object]]::new()
    $positionAnchors = [int[]]::new($count)
    $positionStatements = [int[]]::new($count)
    $positionSeverities = [object[]]::new($count)
    for ($i = 0; $i -lt $count; $i++) {
        $positionSeverities[$i] = [ordered]@{
            critical = 0; high = 0; medium = 0; low = 0; info = 0
        }
    }
    $stepPreviousOnly = [int[]]::new($count - 1)
    $stepNextOnly = [int[]]::new($count - 1)
    $stepSeverityChanged = [int[]]::new($count - 1)
    $groupedAnchors = 0
    $groupedStatements = 0

    foreach ($cohort in $cohortsByPattern.Values) {
        $anchorCount = $cohort.anchor_indices.Count
        $groupedAnchors += $anchorCount
        $groupedStatements += $cohort.finding_statements
        $observations = [System.Collections.Generic.List[object]]::new()
        $stepRows = [System.Collections.Generic.List[object]]::new()
        $cohortAnchorPositions = 0
        for ($i = 0; $i -lt $count; $i++) {
            $present = $cohort.pattern[$i] -eq [char]'1'
            $hereAnchors = if ($present) { $anchorCount } else { 0 }
            $cohortAnchorPositions += $hereAnchors
            $positionAnchors[$i] += $hereAnchors
            $positionStatements[$i] += [int]$cohort.statement_totals[$i]
            foreach ($severity in $severityNames) {
                $positionSeverities[$i][$severity] =
                    [int]$positionSeverities[$i][$severity] +
                    [int]$cohort.severity_totals[$i][$severity]
            }
            $observations.Add([ordered]@{
                position = $i + 1
                record_id = [string]$Journeys.position_totals[$i].record_id
                reported = $present
                exact_anchor_count = $hereAnchors
                finding_statement_count = [int]$cohort.statement_totals[$i]
                severity_statement_counts = $cohort.severity_totals[$i]
            })
            if ($i -eq 0) { continue }
            $was = $cohort.pattern[$i - 1] -eq [char]'1'
            $oldOnly = if ($was -and -not $present) { $anchorCount } else { 0 }
            $newOnly = if (-not $was -and $present) { $anchorCount } else { 0 }
            $severityChanged = [int]$cohort.retained_severity_changes[$i - 1]
            if ($severityChanged -lt 0 -or $severityChanged -gt $anchorCount -or
                ($severityChanged -gt 0 -and (-not $was -or -not $present))) {
                throw 'Code Sequence focused anchor cohort invented a retained-anchor change.'
            }
            $stepPreviousOnly[$i - 1] += $oldOnly
            $stepNextOnly[$i - 1] += $newOnly
            $stepSeverityChanged[$i - 1] += $severityChanged
            $stepRows.Add([ordered]@{
                previous_position = $i
                next_position = $i + 1
                previous_only_exact_anchor_count = $oldOnly
                next_only_exact_anchor_count = $newOnly
                retained_severity_histogram_changed_count = $severityChanged
            })
        }
        if ($cohortAnchorPositions -ne ($anchorCount * $cohort.support)) {
            throw 'Code Sequence focused anchor cohort support weighting failed.'
        }
        $all.Add([ordered]@{
            cohort_index = $all.Count + 1
            presence_pattern = $cohort.pattern
            lifecycle_shape = $cohort.shape
            reporting_record_count = $cohort.support
            present_positions = $cohort.present_positions
            absent_positions = $cohort.absent_positions
            distinct_exact_anchor_count = $anchorCount
            anchor_indices_in_anchor_journeys = $cohort.anchor_indices.ToArray()
            anchor_position_occurrences = $cohortAnchorPositions
            finding_statement_occurrences = $cohort.finding_statements
            severity_varied_exact_anchor_count = $cohort.varied_anchors
            observations_in_caller_order = $observations.ToArray()
            adjacent_step_totals = $stepRows.ToArray()
        })
    }

    $positionRows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $count; $i++) {
        $prior = $Journeys.position_totals[$i]
        if ([int]$prior.position -ne ($i + 1) -or
            [int]$prior.reported_exact_anchor_count -ne $positionAnchors[$i] -or
            [int]$prior.finding_statement_count -ne $positionStatements[$i] -or
            -not (Test-CodeSequenceFocusedSeverityEqual `
                -Left $prior.severity_statement_counts -Right $positionSeverities[$i])) {
            throw 'Code Sequence focused anchor cohort position totals contradict the checked exact-anchor ledger.'
        }
        $positionRows.Add([ordered]@{
            position = $i + 1
            record_id = [string]$prior.record_id
            reported_exact_anchor_count = $positionAnchors[$i]
            finding_statement_count = $positionStatements[$i]
            severity_statement_counts = $positionSeverities[$i]
        })
    }
    $stepRows = [System.Collections.Generic.List[object]]::new()
    $presenceChanges = 0
    $severityChanges = 0
    for ($i = 0; $i -lt ($count - 1); $i++) {
        $prior = $Journeys.adjacent_step_totals[$i]
        if ([int]$prior.previous_only_exact_anchor_count -ne $stepPreviousOnly[$i] -or
            [int]$prior.next_only_exact_anchor_count -ne $stepNextOnly[$i] -or
            [int]$prior.retained_severity_distribution_changed_count -ne $stepSeverityChanged[$i]) {
            throw 'Code Sequence focused anchor cohort steps contradict the checked exact-anchor ledger.'
        }
        $presenceChanges += $stepPreviousOnly[$i] + $stepNextOnly[$i]
        $severityChanges += $stepSeverityChanged[$i]
        $stepRows.Add([ordered]@{
            previous_position = $i + 1
            next_position = $i + 2
            previous_only_exact_anchor_count = $stepPreviousOnly[$i]
            next_only_exact_anchor_count = $stepNextOnly[$i]
            retained_severity_histogram_changed_count = $stepSeverityChanged[$i]
        })
    }

    $old = $Journeys.counts
    if ($groupedAnchors -ne [int]$old.distinct_exact_anchor_union_count -or
        $groupedStatements -ne [int]$old.finding_statement_occurrences -or
        $observedStatements -ne $groupedStatements -or
        $observedAnchorPositions -ne [int]$old.reported_exact_anchor_position_occurrences -or
        $reappearedCount -ne [int]$old.reappeared_after_at_least_one_unreported_position_count -or
        $variedCount -ne [int]$old.severity_distribution_varied_across_reported_positions_count -or
        $presenceChanges -ne [int]$old.presence_transitions_across_adjacent_pairs_count -or
        $severityChanges -ne [int]$old.retained_severity_histogram_transition_count -or
        ([int]$shapes.every_position + [int]$shapes.one_position +
         [int]$shapes.contiguous_partial + [int]$shapes.reappeared_after_gap) -ne $groupedAnchors -or
        [int]$shapes.every_position -ne [int]$old.reported_in_every_record_count -or
        [int]$shapes.one_position -ne [int]$old.reported_once_count) {
        throw 'Code Sequence focused anchor cohort global conservation failed.'
    }
    return [ordered]@{
        scope = 'complete_presence_pattern_cohorts_within_one_checked_literal_saved_path_not_time'
        path = [string]$Journeys.path
        path_found_in_selected_records = ($groupedAnchors -gt 0)
        independent_of_sequence_top = $true
        selected_record_count = $count
        sort_order = 'ordinal_binary_presence_pattern_anchor_indices_reference_canonical_anchor_journeys'
        counts = [ordered]@{
            distinct_presence_pattern_cohort_count = $all.Count
            distinct_exact_anchor_union_count = $groupedAnchors
            reported_exact_anchor_position_occurrences = $observedAnchorPositions
            finding_statement_occurrences = $groupedStatements
            every_position_exact_anchor_count = [int]$shapes.every_position
            one_position_exact_anchor_count = [int]$shapes.one_position
            contiguous_partial_exact_anchor_count = [int]$shapes.contiguous_partial
            reappeared_after_gap_exact_anchor_count = [int]$shapes.reappeared_after_gap
            severity_varied_exact_anchor_count = $variedCount
            presence_transitions_across_adjacent_pairs_count = $presenceChanges
            retained_severity_histogram_transition_count = $severityChanges
        }
        position_totals = $positionRows.ToArray()
        adjacent_step_totals = $stepRows.ToArray()
        cohorts = $all.ToArray()
        explanation = 'Groups complete exact saved quote-anchor histories by identical 0/1 reporting patterns across caller-selected records. Every cohort lists 1-based indexes into the complete anchor_journeys.anchors ledger and all saved-position Finding-statement and five-severity totals. Different severity distributions can coexist inside one reporting-pattern cohort and are counted, not assumed equal. An unreported path has no cohort. This is not verified chronology, defect persistence, repair, regression or current source truth.'
    }
}

# EC-036: every unordered caller-position pair on ONE explicitly focused saved
# path. Compare complete EC-034 exact-anchor observations (not capped previews),
# reconcile reporting membership independently against EC-035 cohorts and
# profile equality against EC-033. No extra record, Git, source or network IO.
function Get-CodeSequenceFocusedAnchorPairwise {
    param([object] $Journeys, [object] $Cohorts, [object] $ProfileJourney)

    if ($null -eq $Journeys -or $null -eq $Cohorts -or $null -eq $ProfileJourney) {
        throw 'Code Sequence focused anchor pairwise comparison requires all complete prior focused projections.'
    }
    $count = [int]$Journeys.selected_record_count
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty([string]$Journeys.path) -or
        $Journeys.path -cne $Cohorts.path -or $Journeys.path -cne $ProfileJourney.path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Cohorts.independent_of_sequence_top -or
        -not [bool]$ProfileJourney.independent_of_sequence_top -or
        $anchorCount -gt ($count * 40) -or
        $Journeys.position_totals.Count -ne $count -or
        $Journeys.adjacent_step_totals.Count -ne ($count - 1) -or
        $Cohorts.position_totals.Count -ne $count -or
        $Cohorts.adjacent_step_totals.Count -ne ($count - 1) -or
        $ProfileJourney.position_profile_classes.Count -ne $count -or
        [int]$Cohorts.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        [bool]$Journeys.path_found_in_selected_records -ne ($anchorCount -gt 0) -or
        [bool]$Cohorts.path_found_in_selected_records -ne ($anchorCount -gt 0) -or
        [bool]$ProfileJourney.path_found_in_selected_records -ne ($anchorCount -gt 0)) {
        throw 'Code Sequence focused anchor pairwise comparison received an incomplete bounded path ledger.'
    }

    $severities = @('critical', 'high', 'medium', 'low', 'info')
    $anchorRows = [System.Collections.Generic.List[object]]::new()
    $supportSum = 0
    $reportedStatementSum = 0
    # Preflight each anchor's complete N observations and source-record identity.
    # No historical quote string or model Finding prose enters this projection.
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $anchor = $Journeys.anchors[$a]
        $pattern = [string]$anchor.presence_pattern
        if ($pattern.Length -ne $count -or $pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $count) {
            throw 'Code Sequence focused anchor pairwise comparison found an invalid exact-anchor reporting pattern.'
        }
        $support = 0
        $statements = 0
        for ($i = 0; $i -lt $count; $i++) {
            $observation = $anchor.observations_in_caller_order[$i]
            $present = ($pattern[$i] -eq [char]'1')
            if ([int]$observation.position -ne ($i + 1) -or
                $observation.record_id -cne $Journeys.position_totals[$i].record_id -or
                $observation.record_id -cne $ProfileJourney.position_profile_classes[$i].record_id -or
                [bool]$observation.reported -ne $present) {
                throw 'Code Sequence focused anchor pairwise comparison received a misaligned observation.'
            }
            $statementCount = [int]$observation.finding_statement_count
            if ($present) {
                if ($statementCount -lt 1 -or $null -eq $observation.severity_statement_counts) {
                    throw 'Code Sequence focused anchor pairwise comparison lost a reported Finding statement.'
                }
                $support++
                $histogramSum = 0
                foreach ($severity in $severities) {
                    $part = [int]$observation.severity_statement_counts[$severity]
                    if ($part -lt 0) { throw 'Code Sequence focused anchor pairwise comparison saw a negative saved-severity count.' }
                    $histogramSum += $part
                }
                if ($histogramSum -ne $statementCount) {
                    throw 'Code Sequence focused anchor pairwise comparison found an incomplete saved-severity histogram.'
                }
            } elseif ($statementCount -ne 0 -or $null -ne $observation.severity_statement_counts) {
                throw 'Code Sequence focused anchor pairwise comparison found statements attached to an unreported anchor.'
            }
            $statements += $statementCount
        }
        if ($support -lt 1 -or $support -ne [int]$anchor.reporting_record_count -or
            $statements -ne [int]$anchor.finding_statement_occurrences -or
            [bool]$anchor.reported_after_unreported_gap -ne
                [regex]::IsMatch($pattern, '10+1')) {
            throw 'Code Sequence focused anchor pairwise comparison contradicts anchor support or reporting gaps.'
        }
        $supportSum += $support
        $reportedStatementSum += $statements
        $anchorRows.Add([ordered]@{
            anchor_index_in_anchor_journeys = $a + 1
            reporting_record_count = $support
            compared_reported_pair_count = 0
            contrasting_reported_unreported_pair_count = 0
            both_unreported_pair_count = 0
            retained_identical_severity_histogram_pair_count = 0
            retained_changed_severity_histogram_pair_count = 0
            shared_with_internal_unreported_position_pair_count = 0
        })
    }
    if ($supportSum -ne [int]$Journeys.counts.reported_exact_anchor_position_occurrences -or
        $reportedStatementSum -ne [int]$Journeys.counts.finding_statement_occurrences) {
        throw 'Code Sequence focused anchor pairwise comparison failed original occurrence conservation.'
    }

    $totals = [ordered]@{
        identical_saved_path_profile_pair_count = 0
        differing_saved_path_profile_pair_count = 0
        both_unreported_path_pair_count = 0
        both_reported_path_pair_count = 0
        pair_with_anchor_membership_difference_count = 0
        severity_only_difference_pair_count = 0
        mixed_anchor_and_severity_difference_pair_count = 0
        zero_shared_anchor_nonempty_union_pair_count = 0
        pair_with_internal_reporting_gap_for_shared_anchor_count = 0
        left_only_exact_anchor_pair_occurrences = 0
        right_only_exact_anchor_pair_occurrences = 0
        retained_exact_anchor_pair_occurrences = 0
        retained_identical_severity_histogram_anchor_pair_occurrences = 0
        retained_changed_severity_histogram_anchor_pair_occurrences = 0
        both_unreported_exact_anchor_pair_occurrences = 0
        shared_anchor_with_internal_unreported_position_pair_occurrences = 0
        exact_anchor_symmetric_difference_pair_occurrences = 0
    }
    $distanceBins = [System.Collections.Generic.List[object]]::new()
    for ($distance = 1; $distance -lt $count; $distance++) {
        $distanceBins.Add([ordered]@{
            caller_position_distance = $distance
            compared_pair_count = 0
            identical_saved_path_profile_pair_count = 0
            severity_only_difference_pair_count = 0
            exact_anchor_symmetric_difference_occurrences = 0
            retained_changed_severity_histogram_anchor_occurrences = 0
            shared_anchor_with_internal_unreported_position_occurrences = 0
        })
    }

    $pairs = [System.Collections.Generic.List[object]]::new()
    for ($left = 0; $left -lt ($count - 1); $left++) {
        for ($right = $left + 1; $right -lt $count; $right++) {
            $leftOnly = 0; $rightOnly = 0; $retained = 0
            $sameSeverity = 0; $changedSeverity = 0
            $neither = 0; $withInternalGap = 0
            for ($a = 0; $a -lt $anchorCount; $a++) {
                $anchor = $Journeys.anchors[$a]
                $pattern = [string]$anchor.presence_pattern
                $was = ($pattern[$left] -eq [char]'1')
                $now = ($pattern[$right] -eq [char]'1')
                $frequency = $anchorRows[$a]
                if ($was -and $now) {
                    $retained++
                    $frequency.compared_reported_pair_count++
                    if (Test-CodeSequenceFocusedSeverityEqual `
                            -Left $anchor.observations_in_caller_order[$left].severity_statement_counts `
                            -Right $anchor.observations_in_caller_order[$right].severity_statement_counts) {
                        $sameSeverity++
                        $frequency.retained_identical_severity_histogram_pair_count++
                    } else {
                        $changedSeverity++
                        $frequency.retained_changed_severity_histogram_pair_count++
                    }
                    $gapInside = $false
                    for ($middle = $left + 1; $middle -lt $right; $middle++) {
                        if ($pattern[$middle] -eq [char]'0') { $gapInside = $true; break }
                    }
                    if ($gapInside) {
                        $withInternalGap++
                        $frequency.shared_with_internal_unreported_position_pair_count++
                    }
                } elseif ($was) {
                    $leftOnly++
                    $frequency.contrasting_reported_unreported_pair_count++
                } elseif ($now) {
                    $rightOnly++
                    $frequency.contrasting_reported_unreported_pair_count++
                } else {
                    $neither++
                    $frequency.both_unreported_pair_count++
                }
            }
            $leftCount = $leftOnly + $retained
            $rightCount = $rightOnly + $retained
            $union = $leftOnly + $rightOnly + $retained
            $symmetricDifference = $leftOnly + $rightOnly
            $sameProfile = ($symmetricDifference -eq 0 -and $changedSeverity -eq 0)
            $onlySeverity = ($symmetricDifference -eq 0 -and $changedSeverity -gt 0)
            $classesAgree = ([int]$ProfileJourney.position_profile_classes[$left].profile_class -eq
                [int]$ProfileJourney.position_profile_classes[$right].profile_class)

            # An independent cohort-based membership pass is intentionally
            # separate from the anchor-by-anchor frequency and severity pass.
            $cohortLeft = 0; $cohortRight = 0; $cohortRetained = 0
            foreach ($cohort in $Cohorts.cohorts) {
                $pattern = [string]$cohort.presence_pattern
                $weight = [int]$cohort.distinct_exact_anchor_count
                if ($pattern.Length -ne $count -or $weight -lt 1) {
                    throw 'Code Sequence focused anchor pairwise comparison received an invalid cohort.'
                }
                $coWas = ($pattern[$left] -eq [char]'1')
                $coNow = ($pattern[$right] -eq [char]'1')
                if ($coWas) { $cohortLeft += $weight }
                if ($coNow) { $cohortRight += $weight }
                if ($coWas -and $coNow) { $cohortRetained += $weight }
            }
            if ($leftCount -ne [int]$Journeys.position_totals[$left].reported_exact_anchor_count -or
                $rightCount -ne [int]$Journeys.position_totals[$right].reported_exact_anchor_count -or
                $leftCount -ne [int]$Cohorts.position_totals[$left].reported_exact_anchor_count -or
                $rightCount -ne [int]$Cohorts.position_totals[$right].reported_exact_anchor_count -or
                $cohortLeft -ne $leftCount -or $cohortRight -ne $rightCount -or
                $cohortRetained -ne $retained -or $union + $neither -ne $anchorCount -or
                $sameSeverity + $changedSeverity -ne $retained -or
                $sameProfile -ne $classesAgree) {
                throw 'Code Sequence focused pairwise anchor membership contradicts complete cohorts or local profile classes.'
            }
            if ($right -eq ($left + 1)) {
                $adjacent = $Journeys.adjacent_step_totals[$left]
                $adjacentCohort = $Cohorts.adjacent_step_totals[$left]
                if ([int]$adjacent.previous_only_exact_anchor_count -ne $leftOnly -or
                    [int]$adjacent.next_only_exact_anchor_count -ne $rightOnly -or
                    [int]$adjacent.retained_severity_distribution_changed_count -ne $changedSeverity -or
                    [int]$adjacentCohort.previous_only_exact_anchor_count -ne $leftOnly -or
                    [int]$adjacentCohort.next_only_exact_anchor_count -ne $rightOnly -or
                    [int]$adjacentCohort.retained_severity_histogram_changed_count -ne $changedSeverity -or
                    $withInternalGap -ne 0) {
                    throw 'Code Sequence focused pairwise adjacent comparison contradicts checked sequence steps.'
                }
            }

            $distance = $right - $left
            $bin = $distanceBins[$distance - 1]
            $bin.compared_pair_count++
            if ($sameProfile) {
                $totals.identical_saved_path_profile_pair_count++
                $bin.identical_saved_path_profile_pair_count++
            } else { $totals.differing_saved_path_profile_pair_count++ }
            if ($union -eq 0) { $totals.both_unreported_path_pair_count++ }
            if ($leftCount -gt 0 -and $rightCount -gt 0) {
                $totals.both_reported_path_pair_count++
            }
            if ($symmetricDifference -gt 0) {
                $totals.pair_with_anchor_membership_difference_count++
            }
            if ($onlySeverity) {
                $totals.severity_only_difference_pair_count++
                $bin.severity_only_difference_pair_count++
            }
            if ($symmetricDifference -gt 0 -and $changedSeverity -gt 0) {
                $totals.mixed_anchor_and_severity_difference_pair_count++
            }
            if ($retained -eq 0 -and $union -gt 0) {
                $totals.zero_shared_anchor_nonempty_union_pair_count++
            }
            if ($withInternalGap -gt 0) {
                $totals.pair_with_internal_reporting_gap_for_shared_anchor_count++
            }
            $totals.left_only_exact_anchor_pair_occurrences += $leftOnly
            $totals.right_only_exact_anchor_pair_occurrences += $rightOnly
            $totals.retained_exact_anchor_pair_occurrences += $retained
            $totals.retained_identical_severity_histogram_anchor_pair_occurrences += $sameSeverity
            $totals.retained_changed_severity_histogram_anchor_pair_occurrences += $changedSeverity
            $totals.both_unreported_exact_anchor_pair_occurrences += $neither
            $totals.shared_anchor_with_internal_unreported_position_pair_occurrences += $withInternalGap
            $totals.exact_anchor_symmetric_difference_pair_occurrences += $symmetricDifference
            $bin.exact_anchor_symmetric_difference_occurrences += $symmetricDifference
            $bin.retained_changed_severity_histogram_anchor_occurrences += $changedSeverity
            $bin.shared_anchor_with_internal_unreported_position_occurrences += $withInternalGap

            $pairs.Add([ordered]@{
                pair_index = $pairs.Count + 1
                left_position = $left + 1
                right_position = $right + 1
                left_record_id = [string]$Journeys.position_totals[$left].record_id
                right_record_id = [string]$Journeys.position_totals[$right].record_id
                caller_position_distance = $distance
                left_reported_exact_anchor_count = $leftCount
                right_reported_exact_anchor_count = $rightCount
                left_finding_statement_count = [int]$Journeys.position_totals[$left].finding_statement_count
                right_finding_statement_count = [int]$Journeys.position_totals[$right].finding_statement_count
                union_exact_anchor_count = $union
                retained_exact_anchor_count = $retained
                left_only_exact_anchor_count = $leftOnly
                right_only_exact_anchor_count = $rightOnly
                both_unreported_exact_anchor_count = $neither
                retained_identical_severity_histogram_anchor_count = $sameSeverity
                retained_changed_severity_histogram_anchor_count = $changedSeverity
                shared_anchor_with_internal_unreported_position_count = $withInternalGap
                anchor_symmetric_difference_count = $symmetricDifference
                same_saved_path_profile = $sameProfile
                severity_only_difference = $onlySeverity
                both_unreported_path = ($union -eq 0)
            })
        }
    }

    # Every exact anchor participates in exactly choose(N,2) position pairs.
    # Frequency counts are 1-based references into anchor_journeys.anchors.
    $byAnchorMembership = 0; $byAnchorSame = 0; $byAnchorChanged = 0
    $byAnchorAbsent = 0; $byAnchorGap = 0
    foreach ($row in $anchorRows) {
        $support = [int]$row.reporting_record_count
        $sharedExpected = [int](($support * ($support - 1)) / 2)
        $mixedExpected = $support * ($count - $support)
        $absent = $count - $support
        $absentExpected = [int](($absent * ($absent - 1)) / 2)
        $anchor = $Journeys.anchors[([int]$row.anchor_index_in_anchor_journeys - 1)]
        if ([int]$row.compared_reported_pair_count -ne $sharedExpected -or
            [int]$row.contrasting_reported_unreported_pair_count -ne $mixedExpected -or
            [int]$row.both_unreported_pair_count -ne $absentExpected -or
            [int]$row.retained_identical_severity_histogram_pair_count +
                [int]$row.retained_changed_severity_histogram_pair_count -ne $sharedExpected -or
            [int]$row.shared_with_internal_unreported_position_pair_count -gt $sharedExpected -or
            (([int]$row.shared_with_internal_unreported_position_pair_count -gt 0) -ne
                [bool]$anchor.reported_after_unreported_gap)) {
            throw 'Code Sequence focused anchor pairwise comparison failed exact-anchor combinatorial conservation.'
        }
        $byAnchorMembership += [int]$row.contrasting_reported_unreported_pair_count
        $byAnchorSame += [int]$row.retained_identical_severity_histogram_pair_count
        $byAnchorChanged += [int]$row.retained_changed_severity_histogram_pair_count
        $byAnchorAbsent += [int]$row.both_unreported_pair_count
        $byAnchorGap += [int]$row.shared_with_internal_unreported_position_pair_count
    }
    $sumBinPairs = 0; $sumBinIdentical = 0; $sumBinSeverityOnly = 0
    $sumBinChurn = 0; $sumBinSeverityChanged = 0; $sumBinGap = 0
    foreach ($bin in $distanceBins) {
        if ([int]$bin.compared_pair_count -ne ($count - [int]$bin.caller_position_distance)) {
            throw 'Code Sequence focused anchor pairwise comparison lost a caller-distance pair.'
        }
        $sumBinPairs += [int]$bin.compared_pair_count
        $sumBinIdentical += [int]$bin.identical_saved_path_profile_pair_count
        $sumBinSeverityOnly += [int]$bin.severity_only_difference_pair_count
        $sumBinChurn += [int]$bin.exact_anchor_symmetric_difference_occurrences
        $sumBinSeverityChanged += [int]$bin.retained_changed_severity_histogram_anchor_occurrences
        $sumBinGap += [int]$bin.shared_anchor_with_internal_unreported_position_occurrences
    }
    if ($pairs.Count -ne $pairCount -or $sumBinPairs -ne $pairCount -or
        [int]$totals.identical_saved_path_profile_pair_count +
            [int]$totals.differing_saved_path_profile_pair_count -ne $pairCount -or
        $sumBinIdentical -ne [int]$totals.identical_saved_path_profile_pair_count -or
        $sumBinSeverityOnly -ne [int]$totals.severity_only_difference_pair_count -or
        $sumBinChurn -ne [int]$totals.exact_anchor_symmetric_difference_pair_occurrences -or
        $sumBinSeverityChanged -ne [int]$totals.retained_changed_severity_histogram_anchor_pair_occurrences -or
        $sumBinGap -ne [int]$totals.shared_anchor_with_internal_unreported_position_pair_occurrences -or
        $byAnchorMembership -ne [int]$totals.exact_anchor_symmetric_difference_pair_occurrences -or
        $byAnchorSame -ne [int]$totals.retained_identical_severity_histogram_anchor_pair_occurrences -or
        $byAnchorChanged -ne [int]$totals.retained_changed_severity_histogram_anchor_pair_occurrences -or
        $byAnchorAbsent -ne [int]$totals.both_unreported_exact_anchor_pair_occurrences -or
        $byAnchorGap -ne [int]$totals.shared_anchor_with_internal_unreported_position_pair_occurrences -or
        [int]$totals.left_only_exact_anchor_pair_occurrences +
            [int]$totals.right_only_exact_anchor_pair_occurrences +
            [int]$totals.retained_exact_anchor_pair_occurrences +
            [int]$totals.both_unreported_exact_anchor_pair_occurrences -ne ($pairCount * $anchorCount) -or
        [int]$totals.left_only_exact_anchor_pair_occurrences +
            [int]$totals.right_only_exact_anchor_pair_occurrences +
            2 * [int]$totals.retained_exact_anchor_pair_occurrences -ne (($count - 1) * $supportSum)) {
        throw 'Code Sequence focused anchor pairwise comparison failed full pair/anchor/distance conservation.'
    }

    return [ordered]@{
        scope = 'every_unordered_pair_of_checked_caller_positions_for_one_literal_saved_path_not_time'
        path = [string]$Journeys.path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $count
        pair_count = $pairCount
        independent_of_sequence_top = $true
        pair_order = 'left_position_ascending_then_right_position_ascending'
        anchor_index_order = 'one_based_indices_into_complete_anchor_journeys'
        counts = $totals
        caller_distance_distribution = $distanceBins.ToArray()
        anchor_pair_frequencies = $anchorRows.ToArray()
        pairs = $pairs.ToArray()
        explanation = 'Untruncated unordered saved-report-position comparisons for the explicitly requested exact Git path. Membership, histogram equality, cross-gap shared anchors and anchor pair frequencies refer only to already checked saved six-field quote anchors, never verified time, source state, risk, defect recurrence or repair. A shared anchor with an unreported intermediate selected position is a reporting gap, not proof of regression. All original quotation/model prose remains undisclosed; no extra saved body, Git file, network access or write occurs.'
    }
}

# EC-037: make the complete EC-036 position pairs actionable by returning
# canonical one-based anchor indices for EVERY category of EVERY pair. The
# five buckets partition the EC-034 anchor union, while the cross-gap list
# deliberately overlaps retained buckets. Five-bin signed severity deltas
# describe saved Finding STATEMENTS, not severity changes of real defects.
# No saved body/source read, caller option, writer, or external action.
function Get-CodeSequenceFocusedAnchorPairDetails {
    param([object] $Journeys, [object] $Pairwise)

    if ($null -eq $Journeys -or $null -eq $Pairwise) {
        throw 'Code Sequence anchor pair details require both complete checked path projections.'
    }
    $count = [int]$Journeys.selected_record_count
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty([string]$Journeys.path) -or
        $Journeys.path -cne $Pairwise.path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Pairwise.independent_of_sequence_top -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        $anchorCount -gt ($count * 40) -or
        $Journeys.position_totals.Count -ne $count -or
        [int]$Pairwise.pair_count -ne $pairCount -or
        $Pairwise.pairs.Count -ne $pairCount -or
        $Pairwise.anchor_pair_frequencies.Count -ne $anchorCount) {
        throw 'Code Sequence anchor pair details received an incomplete bounded exact-path pair ledger.'
    }

    $severityNames = @('critical','high','medium','low','info')
    $frequencyLeftOnly = [int[]]::new($anchorCount)
    $frequencyRightOnly = [int[]]::new($anchorCount)
    $frequencySame = [int[]]::new($anchorCount)
    $frequencyChanged = [int[]]::new($anchorCount)
    $frequencyAbsent = [int[]]::new($anchorCount)
    $frequencyGap = [int[]]::new($anchorCount)
    $details = [System.Collections.Generic.List[object]]::new()
    $ranking = [System.Collections.Generic.List[object]]::new()
    $totalLeftOnly = 0; $totalRightOnly = 0
    $totalSame = 0; $totalChanged = 0; $totalAbsent = 0
    $totalGap = 0; $totalChangingPairs = 0
    $totalCrossGapChangedSeverity = 0

    for ($left = 0; $left -lt ($count - 1); $left++) {
        for ($right = $left + 1; $right -lt $count; $right++) {
            $pairNumber = $details.Count + 1
            $pair = $Pairwise.pairs[$pairNumber - 1]
            if ([int]$pair.pair_index -ne $pairNumber -or
                [int]$pair.left_position -ne ($left + 1) -or
                [int]$pair.right_position -ne ($right + 1) -or
                $pair.left_record_id -cne $Journeys.position_totals[$left].record_id -or
                $pair.right_record_id -cne $Journeys.position_totals[$right].record_id) {
                throw 'Code Sequence anchor pair details saw reordered or changed caller positions.'
            }

            $leftOnly = [System.Collections.Generic.List[int]]::new()
            $rightOnly = [System.Collections.Generic.List[int]]::new()
            $retainedSame = [System.Collections.Generic.List[int]]::new()
            $retainedChanged = [System.Collections.Generic.List[int]]::new()
            $bothAbsent = [System.Collections.Generic.List[int]]::new()
            $crossGap = [System.Collections.Generic.List[int]]::new()
            $changedSeverityDetails = [System.Collections.Generic.List[object]]::new()
            $leftAllHist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $rightAllHist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $leftRetainedHist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $rightRetainedHist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $leftOnlyStatements = 0; $rightOnlyStatements = 0
            $leftRetainedStatements = 0; $rightRetainedStatements = 0
            $crossGapChanged = 0

            for ($a = 0; $a -lt $anchorCount; $a++) {
                $anchor = $Journeys.anchors[$a]
                $pattern = [string]$anchor.presence_pattern
                if ($pattern.Length -ne $count -or $pattern -match '[^01]' -or
                    $anchor.observations_in_caller_order.Count -ne $count) {
                    throw 'Code Sequence anchor pair details saw invalid exact-anchor observations.'
                }
                $was = ($pattern[$left] -eq [char]'1')
                $now = ($pattern[$right] -eq [char]'1')
                $leftObs = $anchor.observations_in_caller_order[$left]
                $rightObs = $anchor.observations_in_caller_order[$right]
                $leftStatements = [int]$leftObs.finding_statement_count
                $rightStatements = [int]$rightObs.finding_statement_count
                if ([bool]$leftObs.reported -ne $was -or [bool]$rightObs.reported -ne $now -or
                    ($was -and ($leftStatements -lt 1 -or $null -eq $leftObs.severity_statement_counts)) -or
                    ($now -and ($rightStatements -lt 1 -or $null -eq $rightObs.severity_statement_counts)) -or
                    (-not $was -and ($leftStatements -ne 0 -or $null -ne $leftObs.severity_statement_counts)) -or
                    (-not $now -and ($rightStatements -ne 0 -or $null -ne $rightObs.severity_statement_counts))) {
                    throw 'Code Sequence anchor pair details found inconsistent report presence or statement multiplicity.'
                }

                $severityDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
                foreach ($severity in $severityNames) {
                    $lv = if ($was) { [int]$leftObs.severity_statement_counts[$severity] } else { 0 }
                    $rv = if ($now) { [int]$rightObs.severity_statement_counts[$severity] } else { 0 }
                    $leftAllHist[$severity] = [int]$leftAllHist[$severity] + $lv
                    $rightAllHist[$severity] = [int]$rightAllHist[$severity] + $rv
                    if ($was -and $now) {
                        $leftRetainedHist[$severity] = [int]$leftRetainedHist[$severity] + $lv
                        $rightRetainedHist[$severity] = [int]$rightRetainedHist[$severity] + $rv
                        $severityDelta[$severity] = $rv - $lv
                    }
                }

                $index = $a + 1
                if ($was -and $now) {
                    $leftRetainedStatements += $leftStatements
                    $rightRetainedStatements += $rightStatements
                    $gap = $false
                    for ($middle = $left + 1; $middle -lt $right; $middle++) {
                        if ($pattern[$middle] -eq [char]'0') { $gap = $true; break }
                    }
                    if ($gap) {
                        $crossGap.Add($index)
                        $frequencyGap[$a]++
                    }
                    if (Test-CodeSequenceFocusedSeverityEqual `
                            -Left $leftObs.severity_statement_counts `
                            -Right $rightObs.severity_statement_counts) {
                        $retainedSame.Add($index)
                        $frequencySame[$a]++
                    } else {
                        $retainedChanged.Add($index)
                        $frequencyChanged[$a]++
                        if ($gap) { $crossGapChanged++ }
                        $changedSeverityDetails.Add([ordered]@{
                            anchor_index_in_anchor_journeys = $index
                            left_finding_statement_count = $leftStatements
                            right_finding_statement_count = $rightStatements
                            finding_statement_count_delta = $rightStatements - $leftStatements
                            severity_statement_delta = $severityDelta
                            shared_with_internal_unreported_position = $gap
                        })
                    }
                } elseif ($was) {
                    $leftOnly.Add($index)
                    $frequencyLeftOnly[$a]++
                    $leftOnlyStatements += $leftStatements
                } elseif ($now) {
                    $rightOnly.Add($index)
                    $frequencyRightOnly[$a]++
                    $rightOnlyStatements += $rightStatements
                } else {
                    $bothAbsent.Add($index)
                    $frequencyAbsent[$a]++
                }
            }

            $changeCount = $leftOnly.Count + $rightOnly.Count + $retainedChanged.Count
            $leftFullDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $retainedDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
            $leftCheck = 0; $rightCheck = 0
            $retainedLeftCheck = 0; $retainedRightCheck = 0
            foreach ($severity in $severityNames) {
                $lv = [int]$leftAllHist[$severity]
                $rv = [int]$rightAllHist[$severity]
                $leftCheck += $lv
                $rightCheck += $rv
                $retainedLeftCheck += [int]$leftRetainedHist[$severity]
                $retainedRightCheck += [int]$rightRetainedHist[$severity]
                $leftFullDelta[$severity] = $rv - $lv
                $retainedDelta[$severity] = [int]$rightRetainedHist[$severity] - [int]$leftRetainedHist[$severity]
            }
            if ($leftOnly.Count -ne [int]$pair.left_only_exact_anchor_count -or
                $rightOnly.Count -ne [int]$pair.right_only_exact_anchor_count -or
                $retainedSame.Count -ne [int]$pair.retained_identical_severity_histogram_anchor_count -or
                $retainedChanged.Count -ne [int]$pair.retained_changed_severity_histogram_anchor_count -or
                $bothAbsent.Count -ne [int]$pair.both_unreported_exact_anchor_count -or
                $crossGap.Count -ne [int]$pair.shared_anchor_with_internal_unreported_position_count -or
                $changedSeverityDetails.Count -ne $retainedChanged.Count -or
                ($leftOnly.Count + $rightOnly.Count + $retainedSame.Count +
                    $retainedChanged.Count + $bothAbsent.Count) -ne $anchorCount -or
                $changeCount -ne ([int]$pair.anchor_symmetric_difference_count +
                    [int]$pair.retained_changed_severity_histogram_anchor_count) -or
                ($changeCount -eq 0) -ne [bool]$pair.same_saved_path_profile -or
                ($leftOnly.Count + $rightOnly.Count -eq 0 -and $retainedChanged.Count -gt 0) -ne
                    [bool]$pair.severity_only_difference -or
                $leftCheck -ne ([int]$leftOnlyStatements + $leftRetainedStatements) -or
                $rightCheck -ne ([int]$rightOnlyStatements + $rightRetainedStatements) -or
                $leftCheck -ne [int]$pair.left_finding_statement_count -or
                $rightCheck -ne [int]$pair.right_finding_statement_count -or
                $retainedLeftCheck -ne $leftRetainedStatements -or
                $retainedRightCheck -ne $rightRetainedStatements -or
                -not (Test-CodeSequenceFocusedSeverityEqual `
                    -Left $leftAllHist -Right $Journeys.position_totals[$left].severity_statement_counts) -or
                -not (Test-CodeSequenceFocusedSeverityEqual `
                    -Left $rightAllHist -Right $Journeys.position_totals[$right].severity_statement_counts)) {
                throw 'Code Sequence anchor pair details do not reconcile to complete saved pair/position totals.'
            }

            $totalLeftOnly += $leftOnly.Count
            $totalRightOnly += $rightOnly.Count
            $totalSame += $retainedSame.Count
            $totalChanged += $retainedChanged.Count
            $totalAbsent += $bothAbsent.Count
            $totalGap += $crossGap.Count
            $totalCrossGapChangedSeverity += $crossGapChanged
            if ($changeCount -gt 0) { $totalChangingPairs++ }

            $details.Add([ordered]@{
                pair_index = $pairNumber
                left_position = $left + 1
                right_position = $right + 1
                left_record_id = [string]$pair.left_record_id
                right_record_id = [string]$pair.right_record_id
                changed_exact_anchor_count = $changeCount
                left_only_anchor_indices = $leftOnly.ToArray()
                right_only_anchor_indices = $rightOnly.ToArray()
                retained_same_severity_anchor_indices = $retainedSame.ToArray()
                retained_changed_severity_anchor_indices = $retainedChanged.ToArray()
                both_unreported_anchor_indices = $bothAbsent.ToArray()
                shared_with_internal_unreported_position_anchor_indices = $crossGap.ToArray()
                retained_changed_severity_details = $changedSeverityDetails.ToArray()
                left_only_finding_statement_count = $leftOnlyStatements
                right_only_finding_statement_count = $rightOnlyStatements
                retained_left_finding_statement_count = $leftRetainedStatements
                retained_right_finding_statement_count = $rightRetainedStatements
                finding_statement_count_delta = $rightCheck - $leftCheck
                severity_statement_delta_all_reported_anchors = $leftFullDelta
                severity_statement_delta_retained_anchors = $retainedDelta
            })

            # Every pair is ranked (including zero-change pairs), purely by
            # number of differing exact anchors then gap count then pair index.
            $rank = [ordered]@{
                pair_index = $pairNumber
                changed_exact_anchor_count = $changeCount
                shared_with_internal_unreported_position_anchor_count = $crossGap.Count
            }
            $insertAt = $ranking.Count
            for ($k = 0; $k -lt $ranking.Count; $k++) {
                $old = $ranking[$k]
                if ($changeCount -gt [int]$old.changed_exact_anchor_count -or
                    ($changeCount -eq [int]$old.changed_exact_anchor_count -and
                     $crossGap.Count -gt [int]$old.shared_with_internal_unreported_position_anchor_count)) {
                    $insertAt = $k
                    break
                }
            }
            $ranking.Insert($insertAt, $rank)
        }
    }

    if ($details.Count -ne $pairCount -or $ranking.Count -ne $pairCount -or
        $totalLeftOnly -ne [int]$Pairwise.counts.left_only_exact_anchor_pair_occurrences -or
        $totalRightOnly -ne [int]$Pairwise.counts.right_only_exact_anchor_pair_occurrences -or
        $totalSame -ne [int]$Pairwise.counts.retained_identical_severity_histogram_anchor_pair_occurrences -or
        $totalChanged -ne [int]$Pairwise.counts.retained_changed_severity_histogram_anchor_pair_occurrences -or
        $totalAbsent -ne [int]$Pairwise.counts.both_unreported_exact_anchor_pair_occurrences -or
        $totalGap -ne [int]$Pairwise.counts.shared_anchor_with_internal_unreported_position_pair_occurrences -or
        $totalChangingPairs -ne [int]$Pairwise.counts.differing_saved_path_profile_pair_count) {
        throw 'Code Sequence anchor pair details failed all-pair category conservation.'
    }
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $frequency = $Pairwise.anchor_pair_frequencies[$a]
        if ([int]$frequency.anchor_index_in_anchor_journeys -ne ($a + 1) -or
            [int]$frequency.compared_reported_pair_count -ne
                ($frequencySame[$a] + $frequencyChanged[$a]) -or
            [int]$frequency.contrasting_reported_unreported_pair_count -ne
                ($frequencyLeftOnly[$a] + $frequencyRightOnly[$a]) -or
            [int]$frequency.retained_identical_severity_histogram_pair_count -ne $frequencySame[$a] -or
            [int]$frequency.retained_changed_severity_histogram_pair_count -ne $frequencyChanged[$a] -or
            [int]$frequency.both_unreported_pair_count -ne $frequencyAbsent[$a] -or
            [int]$frequency.shared_with_internal_unreported_position_pair_count -ne $frequencyGap[$a]) {
            throw 'Code Sequence anchor pair details disagreed with canonical per-anchor pair frequencies.'
        }
    }
    return [ordered]@{
        scope = 'complete_per_pair_exact_anchor_indices_and_signed_saved_severity_statement_deltas'
        path = [string]$Journeys.path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $count
        pair_count = $pairCount
        independent_of_sequence_top = $true
        anchor_indices_reference = 'one_based_into_anchor_journeys.anchors_in_exact_ordinal_order'
        pair_indices_reference = 'one_based_into_anchor_pairwise.pairs_in_caller_position_order'
        ranking_order = 'changed_exact_anchor_count_desc_then_cross_gap_shared_anchor_count_desc_then_pair_index_asc_not_risk'
        counts = [ordered]@{
            different_saved_path_profile_pair_count = $totalChangingPairs
            left_only_anchor_pair_occurrences = $totalLeftOnly
            right_only_anchor_pair_occurrences = $totalRightOnly
            retained_same_severity_anchor_pair_occurrences = $totalSame
            retained_changed_severity_anchor_pair_occurrences = $totalChanged
            both_unreported_anchor_pair_occurrences = $totalAbsent
            shared_with_internal_unreported_position_anchor_pair_occurrences = $totalGap
            shared_cross_gap_and_severity_changed_anchor_pair_occurrences = $totalCrossGapChangedSeverity
        }
        ranked_pairs = $ranking.ToArray()
        pairs = $details.ToArray()
        explanation = 'For every pair of caller-selected saved records, the five canonical index lists are disjoint and exhaust the exact saved anchor union. The shared-intermediate-gap index list is intentionally overlapping. Signed critical/high/medium/low/info deltas are counts of saved model Finding statements (right minus left), not verified changes to a defect or source severity. Ranking is change magnitude in the selected reports, not time, priority or risk. Nothing is clipped by SequenceTop and no new source/store reads, quotations, writers or remote actions are introduced.'
    }
}


# EC-038: invert the already checked complete EC-037 per-pair index partitions.
# Instead of scanning every pair to answer "where did this exact saved quote
# anchor differ?", return a canonical anchor -> pair-index lookup, including
# all non-differing pairs and the overlapping internal-reporting-gap pairs.
# Retained changed-severity events carry signed saved Finding-statement deltas.
# Only bounded checked in-memory projections are used; no extra reads/writes.
function Get-CodeSequenceFocusedAnchorPairLookup {
    param([object] $Journeys, [object] $Pairwise, [object] $Details)

    if ($null -eq $Journeys -or $null -eq $Pairwise -or $null -eq $Details) {
        throw 'Code Sequence anchor-pair lookup requires three complete checked projections.'
    }
    $count = [int]$Journeys.selected_record_count
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty([string]$Journeys.path) -or
        $Journeys.path -cne $Pairwise.path -or $Journeys.path -cne $Details.path -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Pairwise.independent_of_sequence_top -or
        -not [bool]$Details.independent_of_sequence_top -or
        $anchorCount -gt ($count * 40) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        [int]$Pairwise.pair_count -ne $pairCount -or
        [int]$Details.pair_count -ne $pairCount -or
        $Pairwise.pairs.Count -ne $pairCount -or
        $Details.pairs.Count -ne $pairCount -or
        $Pairwise.anchor_pair_frequencies.Count -ne $anchorCount -or
        $Journeys.position_totals.Count -ne $count) {
        throw 'Code Sequence anchor-pair lookup received an incomplete focused ledger.'
    }

    # These are intentionally FIVE exclusive categories. The sixth field,
    # intermediate unreporting, is an overlapping annotation of retained pairs.
    $categories = @(
        [pscustomobject]@{ name = 'left_only'; field = 'left_only_anchor_indices' },
        [pscustomobject]@{ name = 'right_only'; field = 'right_only_anchor_indices' },
        [pscustomobject]@{ name = 'retained_same_severity'; field = 'retained_same_severity_anchor_indices' },
        [pscustomobject]@{ name = 'retained_changed_severity'; field = 'retained_changed_severity_anchor_indices' },
        [pscustomobject]@{ name = 'both_unreported'; field = 'both_unreported_anchor_indices' }
    )
    $severityNames = @('critical','high','medium','low','info')
    $working = [System.Collections.Generic.List[object]]::new()
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $anchor = $Journeys.anchors[$a]
        $pattern = [string]$anchor.presence_pattern
        if ($pattern.Length -ne $count -or $pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $count -or
            [int]$anchor.reporting_record_count -lt 1) {
            throw 'Code Sequence anchor-pair lookup received an invalid canonical anchor journey.'
        }
        $working.Add([pscustomobject]@{
            pattern = $pattern
            observations = $anchor.observations_in_caller_order
            reporting_record_count = [int]$anchor.reporting_record_count
            buckets = [ordered]@{
                left_only = [System.Collections.Generic.List[int]]::new()
                right_only = [System.Collections.Generic.List[int]]::new()
                retained_same_severity = [System.Collections.Generic.List[int]]::new()
                retained_changed_severity = [System.Collections.Generic.List[int]]::new()
                both_unreported = [System.Collections.Generic.List[int]]::new()
            }
            changed_pairs = [System.Collections.Generic.List[int]]::new()
            shared_gap_pairs = [System.Collections.Generic.List[int]]::new()
            retained_changed_events = [System.Collections.Generic.List[object]]::new()
        })
    }

    $crossGapChangedCount = 0
    for ($p = 0; $p -lt $pairCount; $p++) {
        $number = $p + 1
        $detail = $Details.pairs[$p]
        $pair = $Pairwise.pairs[$p]
        $left = [int]$pair.left_position - 1
        $right = [int]$pair.right_position - 1
        if ([int]$detail.pair_index -ne $number -or
            [int]$pair.pair_index -ne $number -or
            $left -lt 0 -or $right -ge $count -or $left -ge $right -or
            [int]$detail.left_position -ne ($left + 1) -or
            [int]$detail.right_position -ne ($right + 1) -or
            $detail.left_record_id -cne $pair.left_record_id -or
            $detail.right_record_id -cne $pair.right_record_id -or
            $pair.left_record_id -cne $Journeys.position_totals[$left].record_id -or
            $pair.right_record_id -cne $Journeys.position_totals[$right].record_id) {
            throw 'Code Sequence anchor-pair lookup found a reordered or mismatched saved pair.'
        }
        $seen = [bool[]]::new($anchorCount)
        $members = 0; $changedMembers = 0
        foreach ($category in $categories) {
            $previousIndex = 0
            foreach ($rawIndex in $detail[$category.field]) {
                $index = [int]$rawIndex
                if ($index -le $previousIndex -or $index -gt $anchorCount -or
                    $index -lt 1 -or $seen[$index - 1]) {
                    throw 'Code Sequence anchor-pair lookup found an unordered, duplicate or out-of-range anchor index.'
                }
                $previousIndex = $index
                $seen[$index - 1] = $true
                $members++
                $row = $working[$index - 1]
                $was = ($row.pattern[$left] -eq [char]'1')
                $now = ($row.pattern[$right] -eq [char]'1')
                $sameSeverity = $false
                if ($was -and $now) {
                    $sameSeverity = Test-CodeSequenceFocusedSeverityEqual `
                        -Left $row.observations[$left].severity_statement_counts `
                        -Right $row.observations[$right].severity_statement_counts
                }
                $correct = switch ($category.name) {
                    'left_only' { $was -and -not $now }
                    'right_only' { -not $was -and $now }
                    'retained_same_severity' { $was -and $now -and $sameSeverity }
                    'retained_changed_severity' { $was -and $now -and -not $sameSeverity }
                    'both_unreported' { -not $was -and -not $now }
                }
                if (-not $correct) {
                    throw 'Code Sequence anchor-pair lookup contradicts saved position presence or severity.'
                }
                $row.buckets[$category.name].Add($number)
                if ($category.name -eq 'left_only' -or
                    $category.name -eq 'right_only' -or
                    $category.name -eq 'retained_changed_severity') {
                    $changedMembers++
                    $row.changed_pairs.Add($number)
                }
            }
        }
        if ($members -ne $anchorCount -or
            $changedMembers -ne [int]$detail.changed_exact_anchor_count) {
            throw 'Code Sequence anchor-pair lookup categories do not partition the exact-anchor union.'
        }

        $previousGapIndex = 0
        $gapSeen = [bool[]]::new($anchorCount)
        foreach ($rawIndex in $detail.shared_with_internal_unreported_position_anchor_indices) {
            $index = [int]$rawIndex
            if ($index -le $previousGapIndex -or $index -gt $anchorCount -or $index -lt 1) {
                throw 'Code Sequence anchor-pair lookup found invalid cross-gap indices.'
            }
            $previousGapIndex = $index
            $row = $working[$index - 1]
            $gap = $false
            for ($middle = $left + 1; $middle -lt $right; $middle++) {
                if ($row.pattern[$middle] -eq [char]'0') { $gap = $true; break }
            }
            if ($row.pattern[$left] -ne [char]'1' -or
                $row.pattern[$right] -ne [char]'1' -or -not $gap) {
                throw 'Code Sequence anchor-pair lookup confused a report gap with anchor absence.'
            }
            $gapSeen[$index - 1] = $true
            $row.shared_gap_pairs.Add($number)
        }
        # Check completeness as well as correctness of the overlapping gap
        # indices: a retained pair has a gap iff its saved presence pattern
        # contains a zero strictly between these caller positions.
        for ($a = 0; $a -lt $anchorCount; $a++) {
            $row = $working[$a]
            $expectedGap = $false
            if ($row.pattern[$left] -eq [char]'1' -and
                $row.pattern[$right] -eq [char]'1') {
                for ($middle = $left + 1; $middle -lt $right; $middle++) {
                    if ($row.pattern[$middle] -eq [char]'0') {
                        $expectedGap = $true
                        break
                    }
                }
            }
            if ($gapSeen[$a] -ne $expectedGap) {
                throw 'Code Sequence anchor-pair lookup omitted or invented an intermediate reporting gap.'
            }
        }

        $changedIndices = $detail.retained_changed_severity_anchor_indices
        $events = $detail.retained_changed_severity_details
        if ($changedIndices.Count -ne $events.Count) {
            throw 'Code Sequence anchor-pair lookup saw incomplete severity change witnesses.'
        }
        for ($j = 0; $j -lt $events.Count; $j++) {
            $changeWitness = $events[$j]
            $index = [int]$changedIndices[$j]
            $row = $working[$index - 1]
            $leftObs = $row.observations[$left]
            $rightObs = $row.observations[$right]
            $hasGap = ($row.shared_gap_pairs.Count -gt 0 -and
                $row.shared_gap_pairs[$row.shared_gap_pairs.Count - 1] -eq $number)
            if ([int]$changeWitness.anchor_index_in_anchor_journeys -ne $index -or
                [int]$changeWitness.left_finding_statement_count -ne [int]$leftObs.finding_statement_count -or
                [int]$changeWitness.right_finding_statement_count -ne [int]$rightObs.finding_statement_count -or
                [int]$changeWitness.finding_statement_count_delta -ne
                    ([int]$rightObs.finding_statement_count - [int]$leftObs.finding_statement_count) -or
                [bool]$changeWitness.shared_with_internal_unreported_position -ne $hasGap) {
                throw 'Code Sequence anchor-pair lookup found an incorrect retained severity witness.'
            }
            foreach ($severity in $severityNames) {
                if ([int]$changeWitness.severity_statement_delta[$severity] -ne
                    ([int]$rightObs.severity_statement_counts[$severity] -
                        [int]$leftObs.severity_statement_counts[$severity])) {
                    throw 'Code Sequence anchor-pair lookup found a signed severity delta mismatch.'
                }
            }
            if ($hasGap) { $crossGapChangedCount++ }
            $row.retained_changed_events.Add([ordered]@{
                pair_index = $number
                left_position = $left + 1
                right_position = $right + 1
                left_finding_statement_count = [int]$leftObs.finding_statement_count
                right_finding_statement_count = [int]$rightObs.finding_statement_count
                finding_statement_count_delta = [int]$changeWitness.finding_statement_count_delta
                severity_statement_delta = $changeWitness.severity_statement_delta
                shared_with_internal_unreported_position = $hasGap
            })
        }
    }

    $anchors = [System.Collections.Generic.List[object]]::new()
    $ranking = [System.Collections.Generic.List[object]]::new()
    $totals = [ordered]@{
        distinct_exact_anchor_count = $anchorCount
        anchors_differing_in_at_least_one_pair_count = 0
        anchors_with_retained_severity_difference_count = 0
        anchors_shared_across_an_internal_reporting_gap_count = 0
        left_only_anchor_pair_occurrences = 0
        right_only_anchor_pair_occurrences = 0
        retained_same_severity_anchor_pair_occurrences = 0
        retained_changed_severity_anchor_pair_occurrences = 0
        both_unreported_anchor_pair_occurrences = 0
        shared_with_internal_unreported_position_anchor_pair_occurrences = 0
        shared_cross_gap_and_severity_changed_anchor_pair_occurrences = $crossGapChangedCount
        changed_anchor_pair_occurrences = 0
    }
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $row = $working[$a]
        $freq = $Pairwise.anchor_pair_frequencies[$a]
        $leftOnly = $row.buckets.left_only.Count
        $rightOnly = $row.buckets.right_only.Count
        $same = $row.buckets.retained_same_severity.Count
        $changed = $row.buckets.retained_changed_severity.Count
        $absent = $row.buckets.both_unreported.Count
        $gap = $row.shared_gap_pairs.Count
        $changedPairs = $row.changed_pairs.Count
        if ($leftOnly + $rightOnly + $same + $changed + $absent -ne $pairCount -or
            $changedPairs -ne ($leftOnly + $rightOnly + $changed) -or
            $changed -ne $row.retained_changed_events.Count -or
            [int]$freq.anchor_index_in_anchor_journeys -ne ($a + 1) -or
            [int]$freq.reporting_record_count -ne $row.reporting_record_count -or
            [int]$freq.compared_reported_pair_count -ne ($same + $changed) -or
            [int]$freq.contrasting_reported_unreported_pair_count -ne ($leftOnly + $rightOnly) -or
            [int]$freq.retained_identical_severity_histogram_pair_count -ne $same -or
            [int]$freq.retained_changed_severity_histogram_pair_count -ne $changed -or
            [int]$freq.both_unreported_pair_count -ne $absent -or
            [int]$freq.shared_with_internal_unreported_position_pair_count -ne $gap) {
            throw 'Code Sequence anchor-pair lookup contradicts the checked per-anchor pair frequency ledger.'
        }
        if ($changedPairs -gt 0) { $totals.anchors_differing_in_at_least_one_pair_count++ }
        if ($changed -gt 0) { $totals.anchors_with_retained_severity_difference_count++ }
        if ($gap -gt 0) { $totals.anchors_shared_across_an_internal_reporting_gap_count++ }
        $totals.left_only_anchor_pair_occurrences += $leftOnly
        $totals.right_only_anchor_pair_occurrences += $rightOnly
        $totals.retained_same_severity_anchor_pair_occurrences += $same
        $totals.retained_changed_severity_anchor_pair_occurrences += $changed
        $totals.both_unreported_anchor_pair_occurrences += $absent
        $totals.shared_with_internal_unreported_position_anchor_pair_occurrences += $gap
        $totals.changed_anchor_pair_occurrences += $changedPairs
        $anchors.Add([ordered]@{
            anchor_index_in_anchor_journeys = $a + 1
            presence_pattern = $row.pattern
            reporting_record_count = $row.reporting_record_count
            changed_pair_count = $changedPairs
            left_only_pair_indices = $row.buckets.left_only.ToArray()
            right_only_pair_indices = $row.buckets.right_only.ToArray()
            retained_same_severity_pair_indices = $row.buckets.retained_same_severity.ToArray()
            retained_changed_severity_pair_indices = $row.buckets.retained_changed_severity.ToArray()
            both_unreported_pair_indices = $row.buckets.both_unreported.ToArray()
            changed_pair_indices = $row.changed_pairs.ToArray()
            shared_with_internal_unreported_position_pair_indices = $row.shared_gap_pairs.ToArray()
            retained_changed_severity_events = $row.retained_changed_events.ToArray()
        })
        $rank = [ordered]@{
            anchor_index_in_anchor_journeys = $a + 1
            changed_pair_count = $changedPairs
            retained_changed_severity_pair_count = $changed
            shared_with_internal_unreported_position_pair_count = $gap
        }
        $insertAt = $ranking.Count
        for ($k = 0; $k -lt $ranking.Count; $k++) {
            $old = $ranking[$k]
            if ($changedPairs -gt [int]$old.changed_pair_count -or
                ($changedPairs -eq [int]$old.changed_pair_count -and
                    $changed -gt [int]$old.retained_changed_severity_pair_count) -or
                ($changedPairs -eq [int]$old.changed_pair_count -and
                    $changed -eq [int]$old.retained_changed_severity_pair_count -and
                    $gap -gt [int]$old.shared_with_internal_unreported_position_pair_count)) {
                $insertAt = $k; break
            }
        }
        $ranking.Insert($insertAt, $rank)
    }
    if ($ranking.Count -ne $anchorCount -or
        $totals.left_only_anchor_pair_occurrences -ne [int]$Details.counts.left_only_anchor_pair_occurrences -or
        $totals.right_only_anchor_pair_occurrences -ne [int]$Details.counts.right_only_anchor_pair_occurrences -or
        $totals.retained_same_severity_anchor_pair_occurrences -ne [int]$Details.counts.retained_same_severity_anchor_pair_occurrences -or
        $totals.retained_changed_severity_anchor_pair_occurrences -ne [int]$Details.counts.retained_changed_severity_anchor_pair_occurrences -or
        $totals.both_unreported_anchor_pair_occurrences -ne [int]$Details.counts.both_unreported_anchor_pair_occurrences -or
        $totals.shared_with_internal_unreported_position_anchor_pair_occurrences -ne
            [int]$Details.counts.shared_with_internal_unreported_position_anchor_pair_occurrences -or
        $crossGapChangedCount -ne [int]$Details.counts.shared_cross_gap_and_severity_changed_anchor_pair_occurrences -or
        $totals.changed_anchor_pair_occurrences -ne
            ([int]$Pairwise.counts.exact_anchor_symmetric_difference_pair_occurrences +
                [int]$Pairwise.counts.retained_changed_severity_histogram_anchor_pair_occurrences) -or
        ($pairCount * $anchorCount) -ne
            ($totals.left_only_anchor_pair_occurrences + $totals.right_only_anchor_pair_occurrences +
                $totals.retained_same_severity_anchor_pair_occurrences +
                $totals.retained_changed_severity_anchor_pair_occurrences +
                $totals.both_unreported_anchor_pair_occurrences)) {
        throw 'Code Sequence anchor-pair lookup failed complete pair/anchor conservation.'
    }
    return [ordered]@{
        scope = 'complete_inverse_index_from_every_exact_anchor_to_all_caller_position_pairs'
        path = [string]$Journeys.path
        path_found_in_selected_records = ($anchorCount -gt 0)
        selected_record_count = $count
        pair_count = $pairCount
        independent_of_sequence_top = $true
        anchor_indices_reference = 'one_based_into_anchor_journeys.anchors_in_exact_ordinal_order'
        pair_indices_reference = 'one_based_into_anchor_pair_details.pairs_and_anchor_pairwise.pairs'
        ranking_order = 'changed_pair_count_desc_then_retained_changed_severity_pairs_desc_then_shared_gap_pairs_desc_then_anchor_index_asc_not_risk'
        counts = $totals
        ranked_anchors = $ranking.ToArray()
        anchors = $anchors.ToArray()
        explanation = 'For each canonical saved quote anchor, five sorted pair-index lists partition every selected unordered report pair; changed_pair_indices is the sorted union of one-sided and retained severity-changed pairs, and shared internal unreporting is an overlapping annotation. Retained severity-change events contain signed right-minus-left saved Finding-statement deltas only. Ranking measures contrast within caller-selected saved reports, not verified time, risk, issue identity, source defects or fixes. No SequenceTop clipping, additional store/source reads or side effects.'
    }
}

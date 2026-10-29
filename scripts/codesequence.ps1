#requires -Version 7.0
<#
    EC-021..EC-052: caller-ordered comparison of 2..12 explicitly selected saved
    CodeInsight reports. Every chosen body is integrity/schema checked before
    a result is accepted, including records with no findings. Record order is
    supplied by the caller; SHA IDs and array position are NOT timestamps.

    Reuse the exact six-field CodeCompare anchor. Do not infer that a quote
    anchor represents one issue, a reported absence represents a fix, or a
    changed model severity histogram proves actual risk changes. No original
    quotations, model reasoning or source patch is exposed by this view.
#>

$script:CodeShowSequenceMaxRecords = 12
$script:CodeShowSequenceDefaultTop = 10
$script:CodeShowSequenceMaxTop = 20

function Parse-CodeShowSequenceRecordIds {
    param([AllowNull()][string] $Value)

    # One argument with NO leading/trailing spaces, empty fields, uppercase
    # names, path-like selectors or repeated IDs. Unlike other selected views,
    # preserve caller order: it is the only defined order for this operation.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 815) {
        throw 'SequenceRecordIds requires 2..12 full, distinct lowercase ci-SHA256 IDs.'
    }
    $parts = @($Value.Split([char]','))
    if ($parts.Count -lt 2 -or $parts.Count -gt $script:CodeShowSequenceMaxRecords) {
        throw 'SequenceRecordIds requires 2..12 comma-separated saved IDs.'
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($part in $parts) {
        if ($part -cnotmatch $script:CodeShowRecordIdPattern -or -not $seen.Add($part)) {
            throw 'SequenceRecordIds contains an invalid or repeated saved ID.'
        }
    }
    foreach ($id in $parts) { Write-Output $id }
}

function Get-CodeSequenceSeverities {
    param([AllowNull()][object] $Group)
    $counts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    if ($null -ne $Group) {
        foreach ($entry in $Group.findings.Values) {
            $severity = [string]$entry.severity
            $counts[$severity] = [int]$counts[$severity] + 1
        }
    }
    return $counts
}

function Get-CodeSequenceGroupStatementCount {
    param([object] $Groups)
    $total = 0
    foreach ($group in $Groups.Values) { $total += $group.findings.Count }
    return $total
}

function Get-CodeSequencePreview {
    param([object] $Anchor, [AllowNull()][object] $Previous, [AllowNull()][object] $Next)
    # Only bounded metadata from a fully checked v1 saved record. In
    # particular, no free-form summary/title/reasoning/impact is copied.
    return [ordered]@{
        anchor = $Anchor
        previous_finding_statement_count = if ($null -eq $Previous) { 0 } else { $Previous.findings.Count }
        next_finding_statement_count = if ($null -eq $Next) { 0 } else { $Next.findings.Count }
        previous_severity_counts = (Get-CodeSequenceSeverities -Group $Previous)
        next_severity_counts = (Get-CodeSequenceSeverities -Group $Next)
    }
}

function Get-CodeSequenceStep {
    param(
        [int] $Step,
        [object] $Previous,
        [object] $Next,
        [int] $Top
    )
    $previousGroups = $Previous.groups
    $nextGroups = $Next.groups
    $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $previousGroups.Keys) { [void]$keys.Add($key) }
    foreach ($key in $nextGroups.Keys) { [void]$keys.Add($key) }

    $retained = 0
    $previousOnly = 0
    $nextOnly = 0
    $severityChanged = 0
    $previousPreview = [System.Collections.Generic.List[object]]::new()
    $nextPreview = [System.Collections.Generic.List[object]]::new()
    $changedPreview = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $keys) {
        $hadPrevious = $previousGroups.ContainsKey($key)
        $hasNext = $nextGroups.ContainsKey($key)
        $left = if ($hadPrevious) { $previousGroups[$key] } else { $null }
        $right = if ($hasNext) { $nextGroups[$key] } else { $null }
        if ($hadPrevious -and $hasNext) {
            $retained++
            $oldSeverities = Get-CodeSequenceSeverities -Group $left
            $newSeverities = Get-CodeSequenceSeverities -Group $right
            $changed = $false
            foreach ($severity in @('critical','high','medium','low','info')) {
                if ($oldSeverities[$severity] -ne $newSeverities[$severity]) { $changed = $true; break }
            }
            if ($changed) {
                $severityChanged++
                if ($changedPreview.Count -lt $Top) {
                    $changedPreview.Add((Get-CodeSequencePreview -Anchor $left.anchor -Previous $left -Next $right))
                }
            }
        } elseif ($hadPrevious) {
            $previousOnly++
            if ($previousPreview.Count -lt $Top) {
                $previousPreview.Add((Get-CodeSequencePreview -Anchor $left.anchor -Previous $left -Next $null))
            }
        } else {
            $nextOnly++
            if ($nextPreview.Count -lt $Top) {
                $nextPreview.Add((Get-CodeSequencePreview -Anchor $right.anchor -Previous $null -Next $right))
            }
        }
    }

    return [ordered]@{
        step = $Step
        previous_record_id = $Previous.checked.id
        next_record_id = $Next.checked.id
        previous_anchor_count = $previousGroups.Count
        next_anchor_count = $nextGroups.Count
        # For a path-scoped group map, report ONLY statements for that path.
        # For the unfiltered map this is identical to the checked record count.
        previous_finding_statement_count = (Get-CodeSequenceGroupStatementCount -Groups $previousGroups)
        next_finding_statement_count = (Get-CodeSequenceGroupStatementCount -Groups $nextGroups)
        counts = [ordered]@{
            retained_exact_anchor_count = $retained
            previous_only_exact_anchor_count = $previousOnly
            next_only_exact_anchor_count = $nextOnly
            retained_severity_distribution_changed_count = $severityChanged
        }
        previews = [ordered]@{
            previous_only = $previousPreview.ToArray()
            next_only = $nextPreview.ToArray()
            retained_severity_distribution_changed = $changedPreview.ToArray()
        }
        omitted_previews = [ordered]@{
            previous_only = $previousOnly - $previousPreview.Count
            next_only = $nextOnly - $nextPreview.Count
            retained_severity_distribution_changed = $severityChanged - $changedPreview.Count
        }
        previews_truncated = (($previousOnly -gt $previousPreview.Count) -or
            ($nextOnly -gt $nextPreview.Count) -or ($severityChanged -gt $changedPreview.Count))
    }
}


# EC-022: a second, *selection-wide* view of the same verified anchor groups.
# Counts represent presence across the caller's positions, not chronological
# survival, actual bug lifecycle, or equivalence of Finding statements.
function Get-CodeSequenceTrajectoryPreview {
    param(
        [string] $Key,
        [object] $Anchor,
        [string] $Pattern,
        [int] $ReportingCount,
        [object[]] $States
    )
    $observations = [System.Collections.Generic.List[object]]::new()
    foreach ($state in $States) {
        $present = $state.groups.ContainsKey($Key)
        $group = if ($present) { $state.groups[$Key] } else { $null }
        $observations.Add([ordered]@{
            record_id = $state.checked.id
            reported = $present
            finding_statement_count = if ($present) { $group.findings.Count } else { 0 }
            severity_counts = if ($present) { Get-CodeSequenceSeverities -Group $group } else { $null }
        })
    }
    return [ordered]@{
        anchor = $Anchor
        presence_pattern = $Pattern
        reporting_record_count = $ReportingCount
        observations_in_caller_order = $observations.ToArray()
    }
}

function Get-CodeSequenceTrajectory {
    param(
        [object[]] $States,
        [int] $Top,
        [AllowNull()][object] $PathFilter = $null
    )

    if ($States.Count -lt 2 -or $States.Count -gt $script:CodeShowSequenceMaxRecords -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence trajectory requires 2..12 checked records and Top 1..20.'
    }
    if ($null -ne $PathFilter -and $PathFilter -isnot [string]) {
        throw 'CODE_SHOW_SEQUENCE_SELECTOR_INVALID: path filter must be a string or null.'
    }

    $allKeys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        foreach ($key in $state.groups.Keys) { [void]$allKeys.Add($key) }
    }

    $everyCount = 0
    $onceCount = 0
    $multipleNotAllCount = 0
    $reappearedCount = 0
    $firstLastCount = 0
    $severityVariedCount = 0
    $presenceTransitions = 0
    $supportCounts = [ordered]@{}
    for ($n = 1; $n -le $States.Count; $n++) { $supportCounts[[string]$n] = 0 }
    $everyPreview = [System.Collections.Generic.List[object]]::new()
    $oncePreview = [System.Collections.Generic.List[object]]::new()
    $reappearedPreview = [System.Collections.Generic.List[object]]::new()
    $severityPreview = [System.Collections.Generic.List[object]]::new()

    # SortedSet produces an exact ordinal order even for paths that differ
    # only by case, have Unicode, or contain punctuation resembling a key.
    foreach ($key in $allKeys) {
        $pattern = [System.Text.StringBuilder]::new()
        $reported = 0
        $previousPresent = $false
        $hasReported = $false
        $gapAfterReport = $false
        $reappeared = $false
        $firstHistogram = $null
        $severityVaried = $false
        $anchor = $null
        for ($i = 0; $i -lt $States.Count; $i++) {
            $groupMap = $States[$i].groups
            $present = $groupMap.ContainsKey($key)
            [void]$pattern.Append($(if ($present) { '1' } else { '0' }))
            if ($i -gt 0 -and $present -ne $previousPresent) { $presenceTransitions++ }
            $previousPresent = $present
            if (-not $present) {
                if ($hasReported) { $gapAfterReport = $true }
                continue
            }
            $reported++
            $hasReported = $true
            if ($gapAfterReport) { $reappeared = $true }
            $group = $groupMap[$key]
            if ($null -eq $anchor) { $anchor = $group.anchor }
            $severities = Get-CodeSequenceSeverities -Group $group
            if ($null -eq $firstHistogram) {
                $firstHistogram = $severities
            } else {
                foreach ($severity in @('critical','high','medium','low','info')) {
                    if ($firstHistogram[$severity] -ne $severities[$severity]) {
                        $severityVaried = $true
                        break
                    }
                }
            }
        }
        # Every discovered key came from a checked report; no zero-support
        # key may enter the histogram or previews.
        if ($reported -lt 1) { throw 'Code Sequence trajectory encountered an unsupported empty anchor.' }
        $supportCounts[[string]$reported] = [int]$supportCounts[[string]$reported] + 1
        $patternText = $pattern.ToString()
        $isEvery = ($reported -eq $States.Count)
        $isOnce = ($reported -eq 1)
        if ($isEvery) { $everyCount++ }
        elseif ($isOnce) { $onceCount++ }
        else { $multipleNotAllCount++ }
        if ($reappeared) { $reappearedCount++ }
        if ($patternText.StartsWith('1', [System.StringComparison]::Ordinal) -and
            $patternText.EndsWith('1', [System.StringComparison]::Ordinal)) {
            $firstLastCount++
        }
        if ($severityVaried) { $severityVariedCount++ }

        if (($isEvery -and $everyPreview.Count -lt $Top) -or
            ($isOnce -and $oncePreview.Count -lt $Top) -or
            ($reappeared -and $reappearedPreview.Count -lt $Top) -or
            ($severityVaried -and $severityPreview.Count -lt $Top)) {
            $preview = Get-CodeSequenceTrajectoryPreview -Key $key -Anchor $anchor `
                -Pattern $patternText -ReportingCount $reported -States $States
            if ($isEvery -and $everyPreview.Count -lt $Top) { $everyPreview.Add($preview) }
            if ($isOnce -and $oncePreview.Count -lt $Top) { $oncePreview.Add($preview) }
            if ($reappeared -and $reappearedPreview.Count -lt $Top) { $reappearedPreview.Add($preview) }
            if ($severityVaried -and $severityPreview.Count -lt $Top) { $severityPreview.Add($preview) }
        }
    }

    $coverage = [System.Collections.Generic.List[object]]::new()
    for ($n = 1; $n -le $States.Count; $n++) {
        $coverage.Add([ordered]@{
            reporting_record_count = $n
            distinct_exact_anchor_count = [int]$supportCounts[[string]$n]
        })
    }
    return [ordered]@{
        scope = if ($null -eq $PathFilter) {
            'all_explicitly_selected_records_in_caller_order_not_time'
        } else {
            'exact_path_within_selected_records_in_caller_order_not_time'
        }
        basis = 'exact_saved_six_field_quote_anchor'
        selected_record_count = $States.Count
        counts = [ordered]@{
            distinct_exact_anchor_union_count = $allKeys.Count
            reported_in_every_record_count = $everyCount
            reported_once_count = $onceCount
            reported_in_multiple_but_not_every_record_count = $multipleNotAllCount
            reappeared_after_at_least_one_unreported_position_count = $reappearedCount
            reported_in_first_and_last_count = $firstLastCount
            severity_distribution_varied_across_reported_positions_count = $severityVariedCount
            presence_transitions_across_adjacent_pairs_count = $presenceTransitions
        }
        reporting_record_count_distribution = $coverage.ToArray()
        preview_sort_order = 'ordinal_exact_anchor_key_not_severity_priority_or_time'
        preview_top_per_category = $Top
        previews = [ordered]@{
            reported_in_every_record = $everyPreview.ToArray()
            reported_once = $oncePreview.ToArray()
            reappeared_after_gap = $reappearedPreview.ToArray()
            severity_distribution_varied = $severityPreview.ToArray()
        }
        omitted_previews = [ordered]@{
            reported_in_every_record = $everyCount - $everyPreview.Count
            reported_once = $onceCount - $oncePreview.Count
            reappeared_after_gap = $reappearedCount - $reappearedPreview.Count
            severity_distribution_varied = $severityVariedCount - $severityPreview.Count
        }
        previews_truncated = (($everyCount -gt $everyPreview.Count) -or
            ($onceCount -gt $oncePreview.Count) -or
            ($reappearedCount -gt $reappearedPreview.Count) -or
            ($severityVariedCount -gt $severityPreview.Count))
        explanation = 'Position bits follow user-supplied order, not authenticated time. A 1 means at least one model statement used this exact anchor in that saved record; 0 means it was not reported there, not absent from actual code. A gap followed by another 1 is only a reporting reappearance, not a proven regression. Changed severity histograms are changed model statement counts, not proven risk changes. Only bounded previews disclose historical paths and quote digests; exact totals always cover every selected record.'
    }
}

# EC-023: independent exact-path drill-down. Do not mutate the original
# selected group maps: the unfocused steps/trajectory must remain complete.
# The caller's literal Git path is used ONLY as a case-sensitive string
# comparator against checked saved Finding anchors, never as a file path.
function Get-CodeSequencePathFocus {
    param([object[]] $States, [string] $Path, [int] $Top)

    $focusedStates = [System.Collections.Generic.List[object]]::new()
    $summaries = [System.Collections.Generic.List[object]]::new()
    $reportingRecords = 0
    $findingStatements = 0
    foreach ($state in $States) {
        $groups = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        foreach ($key in $state.groups.Keys) {
            $group = $state.groups[$key]
            if ([string]::Equals([string]$group.anchor.path, $Path, [System.StringComparison]::Ordinal)) {
                $groups.Add($key, $group)
            }
        }
        $statements = Get-CodeSequenceGroupStatementCount -Groups $groups
        if ($statements -gt 0) { $reportingRecords++ }
        $findingStatements += $statements
        $focusedStates.Add([pscustomobject]@{ checked = $state.checked; groups = $groups })
        $summaries.Add([ordered]@{
            record_id = $state.checked.id
            matching_exact_anchor_count = $groups.Count
            matching_finding_statement_count = $statements
            path_reported = ($groups.Count -gt 0)
        })
    }

    $steps = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $focusedStates.Count; $i++) {
        $steps.Add((Get-CodeSequenceStep -Step $i -Previous $focusedStates[$i-1] `
            -Next $focusedStates[$i] -Top $Top))
    }
    $trajectory = Get-CodeSequenceTrajectory -States ($focusedStates.ToArray()) -Top $Top -PathFilter $Path

    return [ordered]@{
        scope = 'exact_literal_case_sensitive_saved_anchor_path_within_selected_records'
        path = $Path
        path_match = 'ordinal_case_sensitive_exact_no_glob_no_filesystem_access'
        path_found_in_selected_records = ($reportingRecords -gt 0)
        selected_record_count = $States.Count
        matching_record_count = $reportingRecords
        matching_finding_statement_count = $findingStatements
        record_summaries = $summaries.ToArray()
        step_count = $steps.Count
        steps = $steps.ToArray()
        anchor_trajectory = $trajectory
        explanation = 'Path focus is a separate historical saved-anchor projection. Unfiltered record summaries, steps and trajectory are unchanged. All selected record bodies were checked even if this literal path matched none. A zero match does not establish that the file is safe, unchanged, or absent from source; it only means no checked saved anchor used this exact case-sensitive path. Preview limits still do not truncate counted anchors.'
    }
}

# EC-024: discover exact historical paths from the SAME fully checked groups.
# This index deliberately measures report-path presence and exact-anchor churn
# separately: a reported path can remain present when all its anchors change.
# Ranking is a navigational heuristic, NEVER a severity or real defect score.
function Test-CodeSequencePathRanksBefore {
    param([object] $Candidate, [object] $Existing)

    $left = [int]$Candidate.exact_anchor_presence_transitions_across_adjacent_pairs_count
    $right = [int]$Existing.exact_anchor_presence_transitions_across_adjacent_pairs_count
    if ($left -ne $right) { return ($left -gt $right) }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

# EC-025: attribute EVERY adjacent exact-anchor delta to its saved Git path.
# Paths are grouped with ordinal case-sensitive keys; no live file is opened.
# A retained path can still contain completely different quotation anchors.
# A severity-histogram-only change also merits a row, even with no anchor churn.
function Get-CodeSequenceGroupsByPath {
    param([object] $Groups)

    $result = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $Groups.Keys) {
        $group = $Groups[$key]
        $path = [string]$group.anchor.path
        if (-not $result.ContainsKey($path)) {
            $result.Add($path, [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal))
        }
        $result[$path].Add($key, $group)
    }
    # Prevent PowerShell pipeline unrolling a dictionary into entries.
    return ,$result
}

function Get-CodeSequencePathStepDeltas {
    param([object[]] $States, [object[]] $ExpectedSteps, [int] $Top)

    if ($States.Count -lt 2 -or $States.Count -gt $script:CodeShowSequenceMaxRecords -or
        $ExpectedSteps.Count -ne ($States.Count - 1) -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence path step attribution requires checked adjacent steps and Top 1..20.'
    }
    $result = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $States.Count; $i++) {
        $previousByPath = Get-CodeSequenceGroupsByPath -Groups $States[$i - 1].groups
        $nextByPath = Get-CodeSequenceGroupsByPath -Groups $States[$i].groups
        $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($path in $previousByPath.Keys) { [void]$paths.Add($path) }
        foreach ($path in $nextByPath.Keys) { [void]$paths.Add($path) }

        $retainedPaths = 0
        $previousOnlyPaths = 0
        $nextOnlyPaths = 0
        $retainedPathsWithAnchorChurn = 0
        $retainedPathsWithSeverityChange = 0
        $changedPaths = 0
        $retainedAnchors = 0
        $previousOnlyAnchors = 0
        $nextOnlyAnchors = 0
        $severityChangedAnchors = 0
        $previousStatements = 0
        $nextStatements = 0
        $topChanged = [System.Collections.Generic.List[object]]::new()

        foreach ($path in $paths) {
            $wasReported = $previousByPath.ContainsKey($path)
            $isReported = $nextByPath.ContainsKey($path)
            $left = if ($wasReported) { $previousByPath[$path] } else { $null }
            $right = if ($isReported) { $nextByPath[$path] } else { $null }
            $pathStatus = if ($wasReported -and $isReported) { 'retained' } elseif ($wasReported) { 'previous_only' } else { 'next_only' }
            if ($pathStatus -eq 'retained') { $retainedPaths++ }
            elseif ($pathStatus -eq 'previous_only') { $previousOnlyPaths++ }
            else { $nextOnlyPaths++ }

            $leftCount = if ($wasReported) { $left.Count } else { 0 }
            $rightCount = if ($isReported) { $right.Count } else { 0 }
            $leftStatements = if ($wasReported) { Get-CodeSequenceGroupStatementCount -Groups $left } else { 0 }
            $rightStatements = if ($isReported) { Get-CodeSequenceGroupStatementCount -Groups $right } else { 0 }
            $previousStatements += $leftStatements
            $nextStatements += $rightStatements
            $anchors = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            if ($wasReported) { foreach ($key in $left.Keys) { [void]$anchors.Add($key) } }
            if ($isReported) { foreach ($key in $right.Keys) { [void]$anchors.Add($key) } }

            $pathRetained = 0
            $pathPreviousOnly = 0
            $pathNextOnly = 0
            $pathSeverityChanged = 0
            foreach ($key in $anchors) {
                $hadAnchor = $wasReported -and $left.ContainsKey($key)
                $hasAnchor = $isReported -and $right.ContainsKey($key)
                if ($hadAnchor -and $hasAnchor) {
                    $pathRetained++
                    $beforeSeverities = Get-CodeSequenceSeverities -Group $left[$key]
                    $afterSeverities = Get-CodeSequenceSeverities -Group $right[$key]
                    foreach ($severity in @('critical', 'high', 'medium', 'low', 'info')) {
                        if ($beforeSeverities[$severity] -ne $afterSeverities[$severity]) {
                            $pathSeverityChanged++
                            break
                        }
                    }
                } elseif ($hadAnchor) { $pathPreviousOnly++ }
                else { $pathNextOnly++ }
            }
            if ($pathRetained + $pathPreviousOnly -ne $leftCount -or
                $pathRetained + $pathNextOnly -ne $rightCount) {
                throw 'Code Sequence path step attribution lost an exact anchor.'
            }
            $retainedAnchors += $pathRetained
            $previousOnlyAnchors += $pathPreviousOnly
            $nextOnlyAnchors += $pathNextOnly
            $severityChangedAnchors += $pathSeverityChanged
            $pathAnchorChurn = $pathPreviousOnly + $pathNextOnly
            if ($pathStatus -eq 'retained' -and $pathAnchorChurn -gt 0) { $retainedPathsWithAnchorChurn++ }
            if ($pathStatus -eq 'retained' -and $pathSeverityChanged -gt 0) { $retainedPathsWithSeverityChange++ }

            # Only changed paths are candidates for the bounded preview:
            # a path may be unchanged in exact anchors but have a changed
            # saved model severity-statement distribution.
            if ($pathAnchorChurn -gt 0 -or $pathSeverityChanged -gt 0) {
                $changedPaths++
                $candidate = [ordered]@{
                    path = $path
                    path_status = $pathStatus
                    previous_reported = $wasReported
                    next_reported = $isReported
                    previous_distinct_exact_anchor_count = $leftCount
                    next_distinct_exact_anchor_count = $rightCount
                    previous_finding_statement_count = $leftStatements
                    next_finding_statement_count = $rightStatements
                    retained_exact_anchor_count = $pathRetained
                    previous_only_exact_anchor_count = $pathPreviousOnly
                    next_only_exact_anchor_count = $pathNextOnly
                    retained_severity_distribution_changed_count = $pathSeverityChanged
                    exact_anchor_presence_transitions_across_adjacent_pairs_count = $pathAnchorChurn
                }
                # Reuse the global path index's deterministic ordinal tie break.
                # The rank represents report churn, never urgency or risk.
                for ($position = 0; $position -lt $topChanged.Count; $position++) {
                    if (Test-CodeSequencePathRanksBefore -Candidate $candidate -Existing $topChanged[$position]) { break }
                }
                if ($position -lt $Top) {
                    $topChanged.Insert($position, $candidate)
                    if ($topChanged.Count -gt $Top) { $topChanged.RemoveAt($Top) }
                }
            }
        }
        $expected = $ExpectedSteps[$i - 1]
        # Cross-check a separately computed, full exact-anchor step; a Top
        # preview must never be allowed to replace complete attribution.
        if ($retainedPaths + $previousOnlyPaths -ne $previousByPath.Count -or
            $retainedPaths + $nextOnlyPaths -ne $nextByPath.Count -or
            $retainedAnchors -ne $expected.counts.retained_exact_anchor_count -or
            $previousOnlyAnchors -ne $expected.counts.previous_only_exact_anchor_count -or
            $nextOnlyAnchors -ne $expected.counts.next_only_exact_anchor_count -or
            $severityChangedAnchors -ne $expected.counts.retained_severity_distribution_changed_count -or
            $previousStatements -ne $expected.previous_finding_statement_count -or
            $nextStatements -ne $expected.next_finding_statement_count -or
            $expected.step -ne $i -or
            $expected.previous_record_id -cne $States[$i - 1].checked.id -or
            $expected.next_record_id -cne $States[$i].checked.id) {
            throw 'Code Sequence path step attribution failed checked adjacent-step reconciliation.'
        }
        $result.Add([ordered]@{
            step = $i
            previous_record_id = $States[$i - 1].checked.id
            next_record_id = $States[$i].checked.id
            counts = [ordered]@{
                previous_reported_path_count = $previousByPath.Count
                next_reported_path_count = $nextByPath.Count
                retained_path_count = $retainedPaths
                previous_only_path_count = $previousOnlyPaths
                next_only_path_count = $nextOnlyPaths
                retained_path_with_anchor_churn_count = $retainedPathsWithAnchorChurn
                retained_path_with_severity_distribution_change_count = $retainedPathsWithSeverityChange
                changed_path_count = $changedPaths
                retained_exact_anchor_count = $retainedAnchors
                previous_only_exact_anchor_count = $previousOnlyAnchors
                next_only_exact_anchor_count = $nextOnlyAnchors
                retained_severity_distribution_changed_count = $severityChangedAnchors
                exact_anchor_presence_transitions_across_adjacent_pairs_count = ($previousOnlyAnchors + $nextOnlyAnchors)
                previous_finding_statement_count = $previousStatements
                next_finding_statement_count = $nextStatements
            }
            preview_top = $Top
            changed_paths = $topChanged.ToArray()
            omitted_changed_paths = $changedPaths - $topChanged.Count
            changed_paths_truncated = ($changedPaths -gt $topChanged.Count)
        })
    }
    return ,$result.ToArray()
}

# EC-026: across the WHOLE caller-ordered selection, identify saved paths
# whose reports change in more than one adjacent step. Unlike a single large
# one-step anchor churn, repeated changed steps are visible as a separate
# navigational signal. This is not an issue/risk ranking or a time series.
function Test-CodeSequenceChangeHotspotRanksBefore {
    param([object] $Candidate, [object] $Existing)

    $left = [int]$Candidate.changed_step_count
    $right = [int]$Existing.changed_step_count
    if ($left -ne $right) { return ($left -gt $right) }
    $left = [int]$Candidate.exact_anchor_presence_transitions_across_adjacent_pairs_count
    $right = [int]$Existing.exact_anchor_presence_transitions_across_adjacent_pairs_count
    if ($left -ne $right) { return ($left -gt $right) }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

function Get-CodeSequencePathChangeProfile {
    param(
        [object[]] $States,
        [object] $Paths,
        [object[]] $ExpectedStepDeltas,
        [int] $Top,
        [int] $ExpectedAnchorTransitions
    )

    $stepCount = $States.Count - 1
    if ($States.Count -lt 2 -or $States.Count -gt $script:CodeShowSequenceMaxRecords -or
        $ExpectedStepDeltas.Count -ne $stepCount -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence path change profile requires checked adjacent steps and Top 1..20.'
    }

    # Reuse ONLY the already validated grouped saved reports. Keeping a full
    # per-position path map also makes a path with identical anchors and
    # identical severity statements distinguishable from a changed path.
    $byPosition = [System.Collections.Generic.List[object]]::new()
    foreach ($state in $States) {
        $byPosition.Add((Get-CodeSequenceGroupsByPath -Groups $state.groups))
    }
    $changedByStep = [int[]]::new($stepCount)
    $enteredByStep = [int[]]::new($stepCount)
    $leftByStep = [int[]]::new($stepCount)
    $retainedChurnByStep = [int[]]::new($stepCount)
    $retainedSeverityByStep = [int[]]::new($stepCount)
    $anchorTransitionsByStep = [int[]]::new($stepCount)
    $severityChangedAnchorsByStep = [int[]]::new($stepCount)
    $changeSupport = [int[]]::new($stepCount + 1)
    $topChanged = [System.Collections.Generic.List[object]]::new()
    $changedPaths = 0
    $repeatChangedPaths = 0
    $changedEveryStepPaths = 0
    $anchorChurnPaths = 0
    $severityChangedPaths = 0
    $severityOnlyPaths = 0
    $changedOccurrences = 0
    $anchorChurnOccurrences = 0
    $severityChangedOccurrences = 0
    $severityOnlyOccurrences = 0
    $pathPresenceOccurrences = 0
    $anchorTransitionsTotal = 0

    foreach ($path in $Paths) {
        $pattern = [System.Text.StringBuilder]::new()
        foreach ($map in $byPosition) {
            [void]$pattern.Append($(if ($map.ContainsKey($path)) { '1' } else { '0' }))
        }
        $changes = [System.Collections.Generic.List[object]]::new()
        $changedCount = 0
        $churnSteps = 0
        $severitySteps = 0
        $severityOnlySteps = 0
        $presenceSteps = 0
        $pathAnchorTransitions = 0
        $currentRun = 0
        $longestRun = 0

        for ($i = 1; $i -lt $byPosition.Count; $i++) {
            $beforeMap = $byPosition[$i - 1]
            $afterMap = $byPosition[$i]
            $beforePresent = $beforeMap.ContainsKey($path)
            $afterPresent = $afterMap.ContainsKey($path)
            $beforeGroups = if ($beforePresent) { $beforeMap[$path] } else { $null }
            $afterGroups = if ($afterPresent) { $afterMap[$path] } else { $null }
            $anchorKeys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            if ($beforePresent) { foreach ($key in $beforeGroups.Keys) { [void]$anchorKeys.Add($key) } }
            if ($afterPresent) { foreach ($key in $afterGroups.Keys) { [void]$anchorKeys.Add($key) } }
            $churn = 0
            $severityChangedAnchors = 0
            foreach ($key in $anchorKeys) {
                $hadAnchor = $beforePresent -and $beforeGroups.ContainsKey($key)
                $hasAnchor = $afterPresent -and $afterGroups.ContainsKey($key)
                if ($hadAnchor -and $hasAnchor) {
                    $oldCounts = Get-CodeSequenceSeverities -Group $beforeGroups[$key]
                    $newCounts = Get-CodeSequenceSeverities -Group $afterGroups[$key]
                    foreach ($severity in @('critical', 'high', 'medium', 'low', 'info')) {
                        if ($oldCounts[$severity] -ne $newCounts[$severity]) {
                            $severityChangedAnchors++
                            break
                        }
                    }
                } else {
                    $churn++
                }
            }
            $presentChanged = ($beforePresent -ne $afterPresent)
            $changed = ($churn -gt 0 -or $severityChangedAnchors -gt 0)
            $anchorTransitionsByStep[$i - 1] += $churn
            $severityChangedAnchorsByStep[$i - 1] += $severityChangedAnchors
            $pathAnchorTransitions += $churn
            if ($beforePresent -and -not $afterPresent) { $leftByStep[$i - 1]++ }
            if (-not $beforePresent -and $afterPresent) { $enteredByStep[$i - 1]++ }
            if ($beforePresent -and $afterPresent -and $churn -gt 0) { $retainedChurnByStep[$i - 1]++ }
            if ($beforePresent -and $afterPresent -and $severityChangedAnchors -gt 0) { $retainedSeverityByStep[$i - 1]++ }

            if (-not $changed) { $currentRun = 0; continue }
            $changedByStep[$i - 1]++
            $changedCount++
            $changedOccurrences++
            $currentRun++
            if ($currentRun -gt $longestRun) { $longestRun = $currentRun }
            if ($churn -gt 0) { $churnSteps++; $anchorChurnOccurrences++ }
            if ($severityChangedAnchors -gt 0) { $severitySteps++; $severityChangedOccurrences++ }
            if ($churn -eq 0 -and $severityChangedAnchors -gt 0) {
                $severityOnlySteps++; $severityOnlyOccurrences++
            }
            if ($presentChanged) { $presenceSteps++; $pathPresenceOccurrences++ }
            $kind = if (-not $beforePresent) { 'started_reporting' }
                elseif (-not $afterPresent) { 'stopped_reporting' }
                elseif ($churn -gt 0 -and $severityChangedAnchors -gt 0) { 'retained_anchor_and_severity_change' }
                elseif ($churn -gt 0) { 'retained_anchor_churn' }
                else { 'retained_severity_only' }
            $changes.Add([ordered]@{
                step = $i
                kind = $kind
                path_presence_changed = $presentChanged
                exact_anchor_presence_transitions_count = $churn
                retained_severity_distribution_changed_count = $severityChangedAnchors
            })
        }
        $changeSupport[$changedCount]++
        $anchorTransitionsTotal += $pathAnchorTransitions
        if ($changedCount -eq 0) { continue }
        $changedPaths++
        if ($changedCount -ge 2) { $repeatChangedPaths++ }
        if ($changedCount -eq $stepCount) { $changedEveryStepPaths++ }
        if ($churnSteps -gt 0) { $anchorChurnPaths++ }
        if ($severitySteps -gt 0) { $severityChangedPaths++ }
        if ($severityOnlySteps -gt 0) { $severityOnlyPaths++ }
        $candidate = [ordered]@{
            path = $path
            presence_pattern = $pattern.ToString()
            changed_step_count = $changedCount
            longest_consecutive_changed_step_run = $longestRun
            path_presence_transition_step_count = $presenceSteps
            anchor_churn_step_count = $churnSteps
            retained_severity_distribution_changed_step_count = $severitySteps
            retained_severity_only_step_count = $severityOnlySteps
            exact_anchor_presence_transitions_across_adjacent_pairs_count = $pathAnchorTransitions
            changes_in_caller_order = $changes.ToArray()
        }
        for ($position = 0; $position -lt $topChanged.Count; $position++) {
            if (Test-CodeSequenceChangeHotspotRanksBefore -Candidate $candidate -Existing $topChanged[$position]) { break }
        }
        if ($position -lt $Top) {
            $topChanged.Insert($position, $candidate)
            if ($topChanged.Count -gt $Top) { $topChanged.RemoveAt($Top) }
        }
    }

    # Independently rebuilt per-path changes MUST equal EC-025's full,
    # untruncated adjacent-step accounting, including severity-only steps.
    $expectedChangedOccurrences = 0
    $expectedPathTransitions = 0
    $expectedAnchorTransitions = 0
    for ($i = 0; $i -lt $stepCount; $i++) {
        $expected = $ExpectedStepDeltas[$i]
        $c = $expected.counts
        if ($expected.step -ne ($i + 1) -or
            $changedByStep[$i] -ne $c.changed_path_count -or
            $enteredByStep[$i] -ne $c.next_only_path_count -or
            $leftByStep[$i] -ne $c.previous_only_path_count -or
            $retainedChurnByStep[$i] -ne $c.retained_path_with_anchor_churn_count -or
            $retainedSeverityByStep[$i] -ne $c.retained_path_with_severity_distribution_change_count -or
            $anchorTransitionsByStep[$i] -ne $c.exact_anchor_presence_transitions_across_adjacent_pairs_count -or
            $severityChangedAnchorsByStep[$i] -ne $c.retained_severity_distribution_changed_count) {
            throw 'Code Sequence path change profile contradicts complete path step attribution.'
        }
        $expectedChangedOccurrences += [int]$c.changed_path_count
        $expectedPathTransitions += [int]$c.previous_only_path_count + [int]$c.next_only_path_count
        $expectedAnchorTransitions += [int]$c.exact_anchor_presence_transitions_across_adjacent_pairs_count
    }
    $histogramPaths = 0
    $histogramWeightedChanges = 0
    $distribution = [System.Collections.Generic.List[object]]::new()
    for ($n = 0; $n -le $stepCount; $n++) {
        $histogramPaths += $changeSupport[$n]
        $histogramWeightedChanges += $n * $changeSupport[$n]
        $distribution.Add([ordered]@{
            changed_adjacent_step_count = $n
            saved_path_count = $changeSupport[$n]
        })
    }
    if ($histogramPaths -ne $Paths.Count -or
        $histogramWeightedChanges -ne $changedOccurrences -or
        $expectedChangedOccurrences -ne $changedOccurrences -or
        $expectedPathTransitions -ne $pathPresenceOccurrences -or
        $anchorTransitionsTotal -ne $ExpectedAnchorTransitions -or
        $expectedAnchorTransitions -ne $anchorTransitionsTotal -or
        $changedPaths -ne ($Paths.Count - $changeSupport[0])) {
        throw 'Code Sequence path change profile totals do not reconcile with selected saved paths.'
    }

    return [ordered]@{
        scope = 'caller_ordered_selected_historical_saved_path_changes_not_time'
        ranking = 'changed_adjacent_step_count_desc_then_exact_anchor_presence_transitions_desc_then_ordinal_path_asc_not_risk'
        selected_record_count = $States.Count
        adjacent_step_count = $stepCount
        counts = [ordered]@{
            distinct_saved_path_count = $Paths.Count
            paths_with_any_changed_step_count = $changedPaths
            paths_changed_in_multiple_steps_count = $repeatChangedPaths
            paths_changed_in_every_adjacent_step_count = $changedEveryStepPaths
            paths_with_anchor_churn_step_count = $anchorChurnPaths
            paths_with_retained_severity_change_step_count = $severityChangedPaths
            paths_with_retained_severity_only_step_count = $severityOnlyPaths
            changed_path_step_occurrences = $changedOccurrences
            path_presence_transition_step_occurrences = $pathPresenceOccurrences
            anchor_churn_path_step_occurrences = $anchorChurnOccurrences
            retained_severity_changed_path_step_occurrences = $severityChangedOccurrences
            retained_severity_only_path_step_occurrences = $severityOnlyOccurrences
            exact_anchor_presence_transitions_across_adjacent_pairs_count = $anchorTransitionsTotal
        }
        changed_step_count_distribution = $distribution.ToArray()
        preview_top = $Top
        hotspots = $topChanged.ToArray()
        omitted_hotspots = $changedPaths - $topChanged.Count
        hotspots_truncated = ($changedPaths -gt $topChanged.Count)
        explanation = 'Rank changed historical saved Git paths by how many caller-adjacent steps had any exact-anchor presence churn or retained-anchor severity-statement difference; break ties by total exact-anchor transitions then ordinal case-sensitive path. A severity-only step counts even with zero anchor transitions. Bounded previews include complete change steps for each shown path, but not unshown paths; histograms and totals are untruncated. Record order is caller-supplied, not verified chronology. Changes are saved model reports, not live files, real defects, or proven severity/risk changes.'
    }
}

function Get-CodeSequencePathIndex {
    param(
        [object[]] $States,
        [int] $Top,
        [int] $ExpectedAnchorUnion,
        [int] $ExpectedAnchorTransitions,
        [int] $ExpectedFindingStatements,
        [object[]] $ExpectedSteps
    )

    if ($States.Count -lt 2 -or $States.Count -gt $script:CodeShowSequenceMaxRecords -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence path index requires 2..12 checked records and Top 1..20.'
    }
    $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        foreach ($group in $state.groups.Values) { [void]$paths.Add([string]$group.anchor.path) }
    }

    $everyCount = 0
    $onceCount = 0
    $multipleNotAllCount = 0
    $gapReturnCount = 0
    $pathTransitionsTotal = 0
    $anchorTransitionsTotal = 0
    $anchorUnionTotal = 0
    $findingStatementsTotal = 0
    $supportBins = [ordered]@{}
    for ($n = 1; $n -le $States.Count; $n++) { $supportBins[[string]$n] = 0 }
    $topPaths = [System.Collections.Generic.List[object]]::new()

    # Each checked anchor has exactly one case-sensitive saved path. We can
    # partition the groups without reopening the record or checking source.
    foreach ($path in $paths) {
        $groupsByPosition = [System.Collections.Generic.List[object]]::new()
        $keysInPath = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
        $observations = [System.Collections.Generic.List[object]]::new()
        $pattern = [System.Text.StringBuilder]::new()
        $reportingCount = 0
        $pathStatementCount = 0
        $pathTransitions = 0
        $lastPathPresent = $false
        $seenReport = $false
        $gapAfterReport = $false
        $reappeared = $false

        for ($i = 0; $i -lt $States.Count; $i++) {
            $map = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
            foreach ($key in $States[$i].groups.Keys) {
                $group = $States[$i].groups[$key]
                if ([string]::Equals([string]$group.anchor.path, $path, [System.StringComparison]::Ordinal)) {
                    $map.Add($key, $group)
                    [void]$keysInPath.Add($key)
                }
            }
            $groupsByPosition.Add($map)
            $present = ($map.Count -gt 0)
            [void]$pattern.Append($(if ($present) { '1' } else { '0' }))
            if ($i -gt 0 -and $present -ne $lastPathPresent) { $pathTransitions++ }
            $lastPathPresent = $present
            if ($present) {
                $reportingCount++
                if ($gapAfterReport) { $reappeared = $true }
                $seenReport = $true
            } elseif ($seenReport) {
                $gapAfterReport = $true
            }
            $statementCount = Get-CodeSequenceGroupStatementCount -Groups $map
            $pathStatementCount += $statementCount
            $observations.Add([ordered]@{
                record_id = $States[$i].checked.id
                reported = $present
                distinct_exact_anchor_count = $map.Count
                finding_statement_count = $statementCount
            })
        }
        if ($reportingCount -lt 1 -or $keysInPath.Count -lt 1) {
            throw 'Code Sequence path index encountered an unsupported empty saved path.'
        }

        # Count 0<->1 changes for each exact six-field anchor, not just changes
        # in path participation. Two different anchors at one continuously
        # reported path can contribute churn without a path transition.
        $anchorTransitions = 0
        foreach ($key in $keysInPath) {
            $wasPresent = $false
            for ($i = 0; $i -lt $groupsByPosition.Count; $i++) {
                $present = $groupsByPosition[$i].ContainsKey($key)
                if ($i -gt 0 -and $present -ne $wasPresent) { $anchorTransitions++ }
                $wasPresent = $present
            }
        }
        $supportBins[[string]$reportingCount] = [int]$supportBins[[string]$reportingCount] + 1
        if ($reportingCount -eq $States.Count) { $everyCount++ }
        elseif ($reportingCount -eq 1) { $onceCount++ }
        else { $multipleNotAllCount++ }
        if ($reappeared) { $gapReturnCount++ }
        $pathTransitionsTotal += $pathTransitions
        $anchorTransitionsTotal += $anchorTransitions
        $anchorUnionTotal += $keysInPath.Count
        $findingStatementsTotal += $pathStatementCount

        $candidate = [ordered]@{
            path = $path
            presence_pattern = $pattern.ToString()
            reporting_record_count = $reportingCount
            distinct_exact_anchor_union_count = $keysInPath.Count
            finding_statement_count_across_selected_records = $pathStatementCount
            path_presence_transitions_across_adjacent_pairs_count = $pathTransitions
            exact_anchor_presence_transitions_across_adjacent_pairs_count = $anchorTransitions
            reappeared_after_unreported_position = $reappeared
            observations_in_caller_order = $observations.ToArray()
        }
        # Keep only Top ranked previews in memory, while calculating ALL paths.
        # Never use Sort-Object: its default culture/case behavior could merge
        # case-distinct paths or reorder the ordinal tie-break.
        for ($position = 0; $position -lt $topPaths.Count; $position++) {
            if (Test-CodeSequencePathRanksBefore -Candidate $candidate -Existing $topPaths[$position]) { break }
        }
        if ($position -lt $Top) {
            $topPaths.Insert($position, $candidate)
            if ($topPaths.Count -gt $Top) { $topPaths.RemoveAt($Top) }
        }
    }

    # These are partitions of the same fully validated checked groups as
    # unfiltered anchor_trajectory. Reject a coding/accounting inconsistency,
    # rather than returning an apparently complete but contradictory index.
    if ($anchorUnionTotal -ne $ExpectedAnchorUnion -or
        $anchorTransitionsTotal -ne $ExpectedAnchorTransitions -or
        $findingStatementsTotal -ne $ExpectedFindingStatements) {
        throw 'Code Sequence path index failed the selected-anchor accounting cross-check.'
    }
    # EC-025: independently attribute every adjacent step by path, not just
    # the whole-selection path preview. Reconcile both levels before accepting.
    $stepDeltas = Get-CodeSequencePathStepDeltas -States $States -ExpectedSteps $ExpectedSteps -Top $Top
    $sumPathTransitions = 0
    $sumAnchorTransitions = 0
    foreach ($stepDelta in $stepDeltas) {
        $sumPathTransitions += $stepDelta.counts.previous_only_path_count + $stepDelta.counts.next_only_path_count
        $sumAnchorTransitions += $stepDelta.counts.exact_anchor_presence_transitions_across_adjacent_pairs_count
    }
    if ($stepDeltas.Count -ne $States.Count - 1 -or
        $sumPathTransitions -ne $pathTransitionsTotal -or
        $sumAnchorTransitions -ne $anchorTransitionsTotal) {
        throw 'Code Sequence path step attribution disagrees with full path index totals.'
    }
    # EC-026: count distinct changed adjacent steps per path (including
    # severity-only steps) across the entire selected report sequence.
    $changeProfile = Get-CodeSequencePathChangeProfile -States $States -Paths $paths `
        -ExpectedStepDeltas $stepDeltas -Top $Top -ExpectedAnchorTransitions $anchorTransitionsTotal
    $distribution = [System.Collections.Generic.List[object]]::new()
    for ($n = 1; $n -le $States.Count; $n++) {
        $distribution.Add([ordered]@{
            reporting_record_count = $n
            saved_path_count = [int]$supportBins[[string]$n]
        })
    }
    return [ordered]@{
        scope = 'exact_saved_anchor_paths_in_caller_ordered_selected_records_not_time'
        path_match = 'ordinal_case_sensitive_exact_saved_anchor_path_not_filesystem'
        ranking = 'exact_anchor_presence_transitions_desc_then_saved_path_ordinal_asc_not_severity_or_risk'
        step_delta_scope = 'each_adjacent_caller_position_pair_exact_saved_path_not_time'
        step_delta_ranking = 'changed_paths_only_exact_anchor_presence_transitions_desc_then_ordinal_path_asc'
        selected_record_count = $States.Count
        counts = [ordered]@{
            distinct_saved_path_count = $paths.Count
            reported_in_every_record_path_count = $everyCount
            reported_once_path_count = $onceCount
            reported_in_multiple_but_not_every_record_path_count = $multipleNotAllCount
            reappeared_after_unreported_position_path_count = $gapReturnCount
            path_presence_transitions_across_adjacent_pairs_count = $pathTransitionsTotal
            exact_anchor_presence_transitions_across_adjacent_pairs_count = $anchorTransitionsTotal
            distinct_exact_anchor_union_count = $anchorUnionTotal
            finding_statement_count_across_selected_records = $findingStatementsTotal
        }
        reporting_record_count_distribution = $distribution.ToArray()
        preview_top = $Top
        # N-1 complete adjacent path diagnostics; only changed_paths previews
        # inside each step are subject to Top clipping.
        step_deltas = $stepDeltas
        change_profile = $changeProfile
        paths = $topPaths.ToArray()
        omitted_paths = $paths.Count - $topPaths.Count
        paths_truncated = ($paths.Count -gt $topPaths.Count)
        explanation = 'Discover exact historical saved paths and N-1 adjacent path change summaries over these selected reports only. A path can stay reported while exact anchors churn, or change its reported severities without anchor churn. Per-step changed-path previews and cross-step change hotspots are capped independently; full change-step histograms and totals are not clipped. Ranking is not risk, verified time, fix or regression. SequencePath may independently drill into an exact returned path. No original quotes or source files are accessed.'
    }
}

# EC-027: compare the FIRST caller-selected saved report with EVERY later
# selected position, including nonadjacent positions. A path that changes in
# intermediate reports but returns to the same exact-anchor + five-severity
# statement histograms can be identified without assuming verified time or
# opening any saved/unselected source file. Reuse EC-021 exact-anchor checks
# and EC-025 complete path attribution for each baseline pair.
function Get-CodeSequenceBaselineDrift {
    param(
        [object[]] $States,
        [object] $ExpectedFirstAdjacentPathDelta,
        [int] $Top
    )

    if ($States.Count -lt 2 -or $States.Count -gt $script:CodeShowSequenceMaxRecords -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop -or
        $null -eq $ExpectedFirstAdjacentPathDelta) {
        throw 'Code Sequence baseline comparison requires 2..12 checked selected records and Top 1..20.'
    }

    $baseline = $States[0]
    $baselineStatementCount = Get-CodeSequenceGroupStatementCount -Groups $baseline.groups
    $comparisons = [System.Collections.Generic.List[object]]::new()
    $matched = 0
    $different = 0
    $returned = 0
    $severityOnly = 0
    $maxAnchorDifference = 0
    $maxChangedPaths = 0
    $previousMatched = $true
    $latestMatched = $false
    $latestReturned = $false

    for ($i = 1; $i -lt $States.Count; $i++) {
        $current = $States[$i]
        # The existing adjacent routines accept ANY two fully checked states.
        # In this projection, step=1 means baseline-to-selected pair, NOT
        # necessarily adjacent positions in the original selected sequence.
        $pair = @($baseline, $current)
        $anchorDelta = Get-CodeSequenceStep -Step 1 -Previous $baseline -Next $current -Top 1
        $pathDeltas = Get-CodeSequencePathStepDeltas -States $pair -ExpectedSteps @($anchorDelta) -Top $Top
        if ($pathDeltas.Count -ne 1) {
            throw 'Code Sequence baseline comparison did not return exactly one complete path attribution.'
        }
        $pathDelta = $pathDeltas[0]
        $c = $pathDelta.counts
        $symmetricDifference = [int]$c.previous_only_exact_anchor_count + [int]$c.next_only_exact_anchor_count
        $hasDifference = ([int]$c.changed_path_count -gt 0)
        $sameProfile = -not $hasDifference
        $isReturn = ($sameProfile -and -not $previousMatched)

        # Path accounting includes every retained exact anchor's five-severity
        # statement histogram, even when the path and anchor presence agree.
        # Free-form model prose/identity is deliberately NOT compared.
        if (($sameProfile -and ($symmetricDifference -ne 0 -or
                    [int]$c.retained_severity_distribution_changed_count -ne 0)) -or
            ($hasDifference -and ($symmetricDifference -eq 0 -and
                    [int]$c.retained_severity_distribution_changed_count -eq 0)) -or
            [int]$c.retained_exact_anchor_count + [int]$c.previous_only_exact_anchor_count -ne $baseline.groups.Count -or
            [int]$c.retained_exact_anchor_count + [int]$c.next_only_exact_anchor_count -ne $current.groups.Count -or
            [int]$c.previous_finding_statement_count -ne $baselineStatementCount -or
            [int]$c.next_finding_statement_count -ne (Get-CodeSequenceGroupStatementCount -Groups $current.groups) -or
            $pathDelta.previous_record_id -cne $baseline.checked.id -or
            $pathDelta.next_record_id -cne $current.checked.id) {
            throw 'Code Sequence baseline comparison failed complete anchor/statement reconciliation.'
        }

        # The baseline-to-position-2 comparison must be identical to the
        # independently calculated FIRST original adjacent-step path delta.
        if ($i -eq 1) {
            $expected = $ExpectedFirstAdjacentPathDelta
            if ($expected.step -ne 1 -or
                $expected.previous_record_id -cne $pathDelta.previous_record_id -or
                $expected.next_record_id -cne $pathDelta.next_record_id -or
                $expected.counts.Count -ne $c.Count) {
                throw 'Code Sequence baseline first-pair identity contradicts original adjacent attribution.'
            }
            foreach ($field in $c.Keys) {
                if (-not $expected.counts.Contains($field) -or
                    [int]$expected.counts[$field] -ne [int]$c[$field]) {
                    throw 'Code Sequence baseline first-pair counts contradict original adjacent attribution.'
                }
            }
        }

        # Rename the shared path helper's previous/next metadata locally:
        # here it always means baseline vs chosen position, not chronology.
        $preview = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $pathDelta.changed_paths) {
            $preview.Add([ordered]@{
                path = $entry.path
                comparison_status = if ($entry.path_status -eq 'previous_only') { 'baseline_only' }
                    elseif ($entry.path_status -eq 'next_only') { 'compared_only' } else { 'retained' }
                baseline_reported = $entry.previous_reported
                compared_reported = $entry.next_reported
                baseline_distinct_exact_anchor_count = $entry.previous_distinct_exact_anchor_count
                compared_distinct_exact_anchor_count = $entry.next_distinct_exact_anchor_count
                baseline_finding_statement_count = $entry.previous_finding_statement_count
                compared_finding_statement_count = $entry.next_finding_statement_count
                retained_exact_anchor_count = $entry.retained_exact_anchor_count
                baseline_only_exact_anchor_count = $entry.previous_only_exact_anchor_count
                compared_only_exact_anchor_count = $entry.next_only_exact_anchor_count
                retained_severity_distribution_changed_count = $entry.retained_severity_distribution_changed_count
                exact_anchor_symmetric_difference_count = $entry.exact_anchor_presence_transitions_across_adjacent_pairs_count
            })
        }
        if ($pathDelta.omitted_changed_paths -ne ([int]$c.changed_path_count - $preview.Count)) {
            throw 'Code Sequence baseline preview clipping contradicts full changed-path count.'
        }

        $counts = [ordered]@{
            baseline_reported_path_count = $c.previous_reported_path_count
            compared_reported_path_count = $c.next_reported_path_count
            retained_path_count = $c.retained_path_count
            baseline_only_path_count = $c.previous_only_path_count
            compared_only_path_count = $c.next_only_path_count
            retained_path_with_anchor_churn_count = $c.retained_path_with_anchor_churn_count
            retained_path_with_severity_distribution_change_count = $c.retained_path_with_severity_distribution_change_count
            changed_path_count = $c.changed_path_count
            retained_exact_anchor_count = $c.retained_exact_anchor_count
            baseline_only_exact_anchor_count = $c.previous_only_exact_anchor_count
            compared_only_exact_anchor_count = $c.next_only_exact_anchor_count
            retained_severity_distribution_changed_count = $c.retained_severity_distribution_changed_count
            exact_anchor_symmetric_difference_count = $symmetricDifference
            baseline_finding_statement_count = $c.previous_finding_statement_count
            compared_finding_statement_count = $c.next_finding_statement_count
        }
        $comparisons.Add([ordered]@{
            baseline_position = 1
            compared_position = $i + 1
            baseline_record_id = $baseline.checked.id
            compared_record_id = $current.checked.id
            matches_baseline_profile = $sameProfile
            returns_to_baseline_profile_after_previous_difference = $isReturn
            counts = $counts
            preview_top = $Top
            changed_paths = $preview.ToArray()
            omitted_changed_paths = $pathDelta.omitted_changed_paths
            changed_paths_truncated = $pathDelta.changed_paths_truncated
        })

        if ($sameProfile) { $matched++ } else { $different++ }
        $previousMatched = $sameProfile
        if ($isReturn) { $returned++ }
        if ($hasDifference -and $symmetricDifference -eq 0) { $severityOnly++ }
        if ($symmetricDifference -gt $maxAnchorDifference) { $maxAnchorDifference = $symmetricDifference }
        if ([int]$c.changed_path_count -gt $maxChangedPaths) { $maxChangedPaths = [int]$c.changed_path_count }
        $latestMatched = $sameProfile
        $latestReturned = $isReturn
    }
    if ($comparisons.Count -ne ($States.Count - 1) -or
        $matched + $different -ne $comparisons.Count -or
        $returned -gt $matched -or $severityOnly -gt $different) {
        throw 'Code Sequence baseline comparisons have inconsistent complete position totals.'
    }

    # EC-028: complete path-level persistence over the same baseline pairs.
    $pathPersistence = Get-CodeSequenceBaselinePathPersistence -States $States `
        -Comparisons ($comparisons.ToArray()) -Top $Top

    return [ordered]@{
        scope = 'first_caller_selected_record_compared_to_every_later_position_not_time'
        basis = 'exact_saved_six_field_quote_anchor_and_per_anchor_five_severity_statement_histogram'
        baseline_position = 1
        baseline_record_id = $baseline.checked.id
        selected_record_count = $States.Count
        comparison_count = $comparisons.Count
        counts = [ordered]@{
            matches_baseline_profile_position_count = $matched
            differs_from_baseline_profile_position_count = $different
            returns_to_baseline_profile_after_previous_difference_position_count = $returned
            severity_histogram_only_difference_position_count = $severityOnly
            maximum_exact_anchor_symmetric_difference_count = $maxAnchorDifference
            maximum_changed_path_count = $maxChangedPaths
        }
        last_position_matches_baseline_profile = $latestMatched
        last_position_returns_to_baseline_profile_after_previous_difference = $latestReturned
        preview_top_per_comparison = $Top
        comparisons = $comparisons.ToArray()
        path_persistence = $pathPersistence
        explanation = 'The first caller-selected, fully checked saved model report is the baseline for every later chosen position, including nonadjacent ones. Exact-anchor symmetric difference counts anchor presence on only one side; they are NOT a sum of chronological step transitions. Matching profiles require the same exact quotation-anchor set and per-anchor five-severity Finding-statement counts; model prose, Finding IDs and saved record bytes may still differ. A return after a different immediately preceding selected position means a later saved reporting profile matches the first again, not that a defect was resolved or code reverted. Changed-path previews are independently capped; all pair counts remain complete. Caller order is not verified time, current source is not read, and no additional selected or unselected saved body is opened.'
    }
}

# EC-028: aggregate complete first-vs-later deviations BY SAVED GIT PATH.
# This answers whether a path's anchor+severity-statement report profile
# stays different from the first chosen report, comes back to that profile,
# or never differs. It is intentionally not a chronology, fix, or risk rank.
# No new record/source reads: all groups came from the same verified selection.
function Test-CodeSequenceBaselinePersistenceRanksBefore {
    param([object] $Candidate, [object] $Existing)

    $left = [int]$Candidate.deviating_comparison_count
    $right = [int]$Existing.deviating_comparison_count
    if ($left -ne $right) { return ($left -gt $right) }
    $left = [int]$Candidate.cumulative_exact_anchor_symmetric_difference_count
    $right = [int]$Existing.cumulative_exact_anchor_symmetric_difference_count
    if ($left -ne $right) { return ($left -gt $right) }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

function Get-CodeSequenceBaselinePathPersistence {
    param([object[]] $States, [object[]] $Comparisons, [int] $Top)

    $count = $States.Count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        $Comparisons.Count -ne ($count - 1) -or $Top -lt 1 -or
        $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence baseline path persistence requires complete first-to-later comparisons and Top 1..20.'
    }

    $byPosition = [System.Collections.Generic.List[object]]::new()
    $paths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $byPosition.Add($byPath)
        foreach ($path in $byPath.Keys) { [void]$paths.Add($path) }
    }

    # Accumulate ALL paths before clipping previews, and reconcile every
    # later-position column against EC-027's independently computed totals.
    $totals = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $count; $i++) {
        $totals.Add([ordered]@{
            baseline_reported_path_count = 0
            compared_reported_path_count = 0
            retained_path_count = 0
            baseline_only_path_count = 0
            compared_only_path_count = 0
            retained_path_with_anchor_churn_count = 0
            retained_path_with_severity_distribution_change_count = 0
            changed_path_count = 0
            severity_histogram_only_changed_path_count = 0
            retained_exact_anchor_count = 0
            baseline_only_exact_anchor_count = 0
            compared_only_exact_anchor_count = 0
            retained_severity_distribution_changed_count = 0
            exact_anchor_symmetric_difference_count = 0
            baseline_finding_statement_count = 0
            compared_finding_statement_count = 0
        })
    }
    $bins = [int[]]::new($count)  # deviation counts 0..N-1, including zero.
    $hotspots = [System.Collections.Generic.List[object]]::new()
    $everDifferent = 0
    $multipleDifferent = 0
    $alwaysDifferent = 0
    $differentAtLast = 0
    $pathsWithReturn = 0
    $returnEvents = 0
    $pathsWithSeverityOnly = 0
    $severityOnlyOccurrences = 0
    $totalDeviatingPathPositions = 0
    $totalAnchorSymmetricDifference = 0

    foreach ($path in $paths) {
        $baselineReported = $byPosition[0].ContainsKey($path)
        $baselineGroups = if ($baselineReported) { $byPosition[0][$path] } else { $null }
        $baselineAnchors = if ($baselineReported) { $baselineGroups.Count } else { 0 }
        $baselineStatements = if ($baselineReported) {
            Get-CodeSequenceGroupStatementCount -Groups $baselineGroups
        } else { 0 }
        $deviationPattern = [System.Text.StringBuilder]::new('0')
        $reportingPattern = [System.Text.StringBuilder]::new($(if ($baselineReported) { '1' } else { '0' }))
        $observations = [System.Collections.Generic.List[object]]::new()
        $deviationCount = 0
        $currentRun = 0
        $longestRun = 0
        $returnsForPath = 0
        $previousDifferent = $false
        $firstDifferentPosition = $null
        $lastDifferentPosition = $null
        $severityOnlyCount = 0
        $cumulativeSymmetricDifference = 0

        for ($i = 1; $i -lt $count; $i++) {
            $comparedReported = $byPosition[$i].ContainsKey($path)
            $comparedGroups = if ($comparedReported) { $byPosition[$i][$path] } else { $null }
            $comparedAnchors = if ($comparedReported) { $comparedGroups.Count } else { 0 }
            $comparedStatements = if ($comparedReported) {
                Get-CodeSequenceGroupStatementCount -Groups $comparedGroups
            } else { 0 }
            [void]$reportingPattern.Append($(if ($comparedReported) { '1' } else { '0' }))

            $anchorKeys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
            if ($baselineReported) {
                foreach ($key in $baselineGroups.Keys) { [void]$anchorKeys.Add($key) }
            }
            if ($comparedReported) {
                foreach ($key in $comparedGroups.Keys) { [void]$anchorKeys.Add($key) }
            }
            $retained = 0
            $baselineOnly = 0
            $comparedOnly = 0
            $severityChanged = 0
            foreach ($key in $anchorKeys) {
                $wasReported = $baselineReported -and $baselineGroups.ContainsKey($key)
                $isReported = $comparedReported -and $comparedGroups.ContainsKey($key)
                if ($wasReported -and $isReported) {
                    $retained++
                    $beforeCounts = Get-CodeSequenceSeverities -Group $baselineGroups[$key]
                    $afterCounts = Get-CodeSequenceSeverities -Group $comparedGroups[$key]
                    foreach ($severity in @('critical','high','medium','low','info')) {
                        if ($beforeCounts[$severity] -ne $afterCounts[$severity]) {
                            $severityChanged++
                            break
                        }
                    }
                } elseif ($wasReported) { $baselineOnly++ }
                else { $comparedOnly++ }
            }
            if ($retained + $baselineOnly -ne $baselineAnchors -or
                $retained + $comparedOnly -ne $comparedAnchors) {
                throw 'Code Sequence baseline persistence lost a saved exact anchor.'
            }

            $symmetricDifference = $baselineOnly + $comparedOnly
            $different = ($symmetricDifference -gt 0 -or $severityChanged -gt 0)
            $severityOnly = ($different -and $symmetricDifference -eq 0)
            [void]$deviationPattern.Append($(if ($different) { '1' } else { '0' }))
            $column = $totals[$i - 1]
            if ($baselineReported) { $column['baseline_reported_path_count']++ }
            if ($comparedReported) { $column['compared_reported_path_count']++ }
            if ($baselineReported -and $comparedReported) {
                $column['retained_path_count']++
                if ($symmetricDifference -gt 0) { $column['retained_path_with_anchor_churn_count']++ }
                if ($severityChanged -gt 0) {
                    $column['retained_path_with_severity_distribution_change_count']++
                }
            } elseif ($baselineReported) { $column['baseline_only_path_count']++ }
            elseif ($comparedReported) { $column['compared_only_path_count']++ }
            $column['retained_exact_anchor_count'] += $retained
            $column['baseline_only_exact_anchor_count'] += $baselineOnly
            $column['compared_only_exact_anchor_count'] += $comparedOnly
            $column['retained_severity_distribution_changed_count'] += $severityChanged
            $column['exact_anchor_symmetric_difference_count'] += $symmetricDifference
            $column['baseline_finding_statement_count'] += $baselineStatements
            $column['compared_finding_statement_count'] += $comparedStatements

            if ($different) {
                $column['changed_path_count']++
                $deviationCount++
                $totalDeviatingPathPositions++
                $currentRun++
                if ($currentRun -gt $longestRun) { $longestRun = $currentRun }
                if ($null -eq $firstDifferentPosition) { $firstDifferentPosition = $i + 1 }
                $lastDifferentPosition = $i + 1
            } else {
                $currentRun = 0
                if ($previousDifferent) { $returnsForPath++; $returnEvents++ }
            }
            if ($severityOnly) {
                $column['severity_histogram_only_changed_path_count']++
                $severityOnlyCount++
                $severityOnlyOccurrences++
            }
            $totalAnchorSymmetricDifference += $symmetricDifference
            $cumulativeSymmetricDifference += $symmetricDifference
            $previousDifferent = $different
            $observations.Add([ordered]@{
                compared_position = $i + 1
                compared_record_id = $States[$i].checked.id
                compared_reported = $comparedReported
                compared_distinct_exact_anchor_count = $comparedAnchors
                profile_deviates_from_baseline = $different
                severity_histogram_only_deviation = $severityOnly
                exact_anchor_symmetric_difference_count = $symmetricDifference
                retained_severity_distribution_changed_count = $severityChanged
            })
        }

        $bins[$deviationCount]++
        if ($deviationCount -eq 0) { continue }
        $everDifferent++
        if ($deviationCount -ge 2) { $multipleDifferent++ }
        if ($deviationCount -eq ($count - 1)) { $alwaysDifferent++ }
        if ($previousDifferent) { $differentAtLast++ }
        if ($returnsForPath -gt 0) { $pathsWithReturn++ }
        if ($severityOnlyCount -gt 0) { $pathsWithSeverityOnly++ }

        $candidate = [ordered]@{
            path = $path
            baseline_reported = $baselineReported
            baseline_distinct_exact_anchor_count = $baselineAnchors
            baseline_finding_statement_count = $baselineStatements
            reporting_pattern = $reportingPattern.ToString()
            deviation_from_baseline_pattern = $deviationPattern.ToString()
            deviating_comparison_count = $deviationCount
            first_deviating_position = $firstDifferentPosition
            last_deviating_position = $lastDifferentPosition
            deviates_at_last_selected_position = $previousDifferent
            longest_consecutive_deviation_run = $longestRun
            returns_to_baseline_after_previous_difference_count = $returnsForPath
            severity_histogram_only_deviation_comparison_count = $severityOnlyCount
            cumulative_exact_anchor_symmetric_difference_count = $cumulativeSymmetricDifference
            compared_positions_in_caller_order = $observations.ToArray()
        }
        for ($position = 0; $position -lt $hotspots.Count; $position++) {
            if (Test-CodeSequenceBaselinePersistenceRanksBefore -Candidate $candidate -Existing $hotspots[$position]) { break }
        }
        if ($position -lt $Top) {
            $hotspots.Insert($position, $candidate)
            if ($hotspots.Count -gt $Top) { $hotspots.RemoveAt($Top) }
        }
    }

    $distribution = [System.Collections.Generic.List[object]]::new()
    $histogramTotal = 0
    $histogramWeighted = 0
    for ($n = 0; $n -lt $count; $n++) {
        $distribution.Add([ordered]@{
            deviating_comparison_count = $n
            saved_path_count = $bins[$n]
        })
        $histogramTotal += $bins[$n]
        $histogramWeighted += $n * $bins[$n]
    }
    $columnSummaries = [System.Collections.Generic.List[object]]::new()
    $columnDeviationSum = 0
    $columnSymmetricSum = 0
    $columnSeverityOnlySum = 0
    for ($i = 1; $i -lt $count; $i++) {
        $observed = $totals[$i - 1]
        $expectedPair = $Comparisons[$i - 1]
        if ($expectedPair.baseline_record_id -cne $States[0].checked.id -or
            $expectedPair.compared_record_id -cne $States[$i].checked.id -or
            $expectedPair.baseline_position -ne 1 -or
            $expectedPair.compared_position -ne ($i + 1)) {
            throw 'Code Sequence baseline persistence comparison positions or record IDs changed.'
        }
        foreach ($field in $observed.Keys) {
            if ($field -eq 'severity_histogram_only_changed_path_count') { continue }
            if (-not $expectedPair.counts.Contains($field) -or
                [int]$observed[$field] -ne [int]$expectedPair.counts[$field]) {
                throw 'Code Sequence baseline persistence path totals contradict complete first-to-later comparison.'
            }
        }
        if ([bool]$expectedPair.matches_baseline_profile -ne ([int]$observed['changed_path_count'] -eq 0) -or
            [int]$observed['severity_histogram_only_changed_path_count'] -gt [int]$observed['changed_path_count']) {
            throw 'Code Sequence baseline persistence differs from checked baseline profile equality.'
        }
        $columnDeviationSum += $observed['changed_path_count']
        $columnSymmetricSum += $observed['exact_anchor_symmetric_difference_count']
        $columnSeverityOnlySum += $observed['severity_histogram_only_changed_path_count']
        $columnSummaries.Add([ordered]@{
            compared_position = $i + 1
            compared_record_id = $States[$i].checked.id
            changed_path_count = $observed['changed_path_count']
            severity_histogram_only_changed_path_count = $observed['severity_histogram_only_changed_path_count']
            exact_anchor_symmetric_difference_count = $observed['exact_anchor_symmetric_difference_count']
        })
    }
    if ($histogramTotal -ne $paths.Count -or
        $histogramWeighted -ne $totalDeviatingPathPositions -or
        $columnDeviationSum -ne $totalDeviatingPathPositions -or
        $columnSymmetricSum -ne $totalAnchorSymmetricDifference -or
        $columnSeverityOnlySum -ne $severityOnlyOccurrences -or
        $everDifferent -ne ($paths.Count - $bins[0]) -or
        $pathsWithReturn -gt $everDifferent -or
        $alwaysDifferent -gt $everDifferent -or
        $differentAtLast -gt $everDifferent) {
        throw 'Code Sequence baseline persistence whole-selection totals do not reconcile.'
    }

    return [ordered]@{
        scope = 'exact_saved_path_profile_relative_to_first_selected_report_at_each_later_position_not_time'
        basis = 'exact_saved_quote_anchor_presence_plus_retained_anchor_five_severity_statement_histogram'
        ranking = 'deviating_comparison_count_desc_then_cumulative_anchor_symmetric_difference_desc_then_ordinal_path_asc_not_risk'
        selected_record_count = $count
        compared_position_count = $count - 1
        counts = [ordered]@{
            distinct_saved_path_union_count = $paths.Count
            paths_never_deviating_from_baseline_count = $bins[0]
            paths_ever_deviating_from_baseline_count = $everDifferent
            paths_deviating_in_multiple_comparisons_count = $multipleDifferent
            paths_deviating_in_every_comparison_count = $alwaysDifferent
            paths_deviating_at_last_selected_position_count = $differentAtLast
            paths_returning_to_baseline_after_previous_difference_count = $pathsWithReturn
            return_to_baseline_path_position_occurrences = $returnEvents
            paths_with_severity_histogram_only_deviation_count = $pathsWithSeverityOnly
            severity_histogram_only_deviation_path_position_occurrences = $severityOnlyOccurrences
            deviating_path_position_occurrences = $totalDeviatingPathPositions
            cumulative_exact_anchor_symmetric_difference_across_baseline_pairs_count = $totalAnchorSymmetricDifference
        }
        deviation_comparison_count_distribution = $distribution.ToArray()
        comparison_totals = $columnSummaries.ToArray()
        preview_top = $Top
        hotspots = $hotspots.ToArray()
        omitted_hotspots = $everDifferent - $hotspots.Count
        hotspots_truncated = ($everDifferent -gt $hotspots.Count)
        explanation = 'Each saved path is independently compared with the first caller-selected saved report, including paths first reported at a later position. A 1 in deviation_from_baseline_pattern means a changed exact anchor set or per-retained-anchor severity-statement histogram; 0 means the same reported profile, even if model prose differs. Return means the immediately previous selected path profile differed but the current one matches baseline. All paths and selected positions enter the totals, including never-changing paths and zero-Finding reports; only hotspot rows are clipped. Caller order is not authenticated time. Neither a returned path nor an absent reported anchor proves a source fix, a regression, a rollback or current code health.'
    }
}

# EC-030: attribute ALL EC-029 unordered-pair profile differences to exact
# saved paths, including a path missing from BOTH sides of a pair. The global
# path union is the same selection; absence of a reported path in two records
# counts as a matching PATH profile, not evidence about the business source.
# Only bounded hotspots are previewed; complete pair/path sums are independent
# of -SequenceTop and of any optional -SequencePath focus.
function Test-CodeSequencePairwisePathRanksBefore {
    param([object] $Candidate, [object] $Existing)
    $left = [int]$Candidate.differing_pair_count
    $right = [int]$Existing.differing_pair_count
    if ($left -ne $right) { return ($left -gt $right) }
    $left = [int]$Candidate.exact_anchor_symmetric_difference_pair_occurrences
    $right = [int]$Existing.exact_anchor_symmetric_difference_pair_occurrences
    if ($left -ne $right) { return ($left -gt $right) }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

function Get-CodeSequencePairwisePathDisagreement {
    param([object[]] $States, [object[]] $Pairs, [int] $Top)

    $count = $States.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        $Pairs.Count -ne $pairCount -or $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence pairwise path disagreement requires all checked pair rows and Top 1..20.'
    }

    # Build each path grouping ONCE from the already checked in-memory records.
    # Ordinal (case-sensitive) path identity is not a filesystem query.
    $byPosition = [System.Collections.Generic.List[object]]::new()
    $allPaths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $byPosition.Add($byPath)
        foreach ($path in $byPath.Keys) { [void]$allPaths.Add($path) }
    }
    $metrics = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    foreach ($path in $allPaths) {
        $reportedPositions = 0
        foreach ($byPath in $byPosition) { if ($byPath.ContainsKey($path)) { $reportedPositions++ } }
        $metrics.Add($path, [pscustomobject]@{
            path = $path
            reporting_position_count = $reportedPositions
            differing_pair_count = 0
            one_sided_path_pair_count = 0
            retained_path_anchor_churn_pair_count = 0
            retained_path_severity_change_pair_count = 0
            severity_histogram_only_difference_pair_count = 0
            exact_anchor_symmetric_difference_pair_occurrences = 0
            retained_severity_changed_anchor_pair_occurrences = 0
            differing_pairs = [System.Collections.Generic.List[object]]::new()
        })
    }

    $totalChangedPathPairOccurrences = 0
    $totalOneSidedPathPairs = 0
    $totalRetainedPathAnchorChurnPairs = 0
    $totalRetainedPathSeverityChangePairs = 0
    $totalSeverityOnlyPathPairs = 0
    $totalAnchorSymmetricDifferenceOccurrences = 0
    $totalRetainedSeverityChangedAnchorOccurrences = 0
    $pairIndex = 0
    for ($leftIndex = 0; $leftIndex -lt ($count - 1); $leftIndex++) {
        for ($rightIndex = $leftIndex + 1; $rightIndex -lt $count; $rightIndex++) {
            $expected = $Pairs[$pairIndex]
            if ($expected.left_position -ne ($leftIndex + 1) -or
                $expected.right_position -ne ($rightIndex + 1) -or
                $expected.left_record_id -cne $States[$leftIndex].checked.id -or
                $expected.right_record_id -cne $States[$rightIndex].checked.id) {
                throw 'Code Sequence path disagreement pair order or identity contradicts EC-029.'
            }
            $leftByPath = $byPosition[$leftIndex]
            $rightByPath = $byPosition[$rightIndex]
            $leftReported = 0; $rightReported = 0; $retainedPaths = 0
            $leftOnlyPaths = 0; $rightOnlyPaths = 0
            $retainedPathsWithChurn = 0; $retainedPathsWithSeverity = 0
            $changedPaths = 0; $severityOnlyChangedPaths = 0
            $retainedAnchors = 0; $leftOnlyAnchors = 0; $rightOnlyAnchors = 0
            $severityChangedAnchors = 0; $leftStatements = 0; $rightStatements = 0

            foreach ($path in $allPaths) {
                $hasLeft = $leftByPath.ContainsKey($path)
                $hasRight = $rightByPath.ContainsKey($path)
                if (-not $hasLeft -and -not $hasRight) { continue }
                $metric = $metrics[$path]
                if ($hasLeft) { $leftReported++ }
                if ($hasRight) { $rightReported++ }
                if ($hasLeft -and $hasRight) { $retainedPaths++ }
                elseif ($hasLeft) { $leftOnlyPaths++ }
                else { $rightOnlyPaths++ }
                $left = if ($hasLeft) { $leftByPath[$path] } else { $null }
                $right = if ($hasRight) { $rightByPath[$path] } else { $null }
                if ($hasLeft) { $leftStatements += Get-CodeSequenceGroupStatementCount -Groups $left }
                if ($hasRight) { $rightStatements += Get-CodeSequenceGroupStatementCount -Groups $right }
                $anchorKeys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
                if ($hasLeft) { foreach ($key in $left.Keys) { [void]$anchorKeys.Add($key) } }
                if ($hasRight) { foreach ($key in $right.Keys) { [void]$anchorKeys.Add($key) } }
                $oneSidedLeft = 0; $oneSidedRight = 0; $severityDifferent = 0
                foreach ($key in $anchorKeys) {
                    $anchorLeft = $hasLeft -and $left.ContainsKey($key)
                    $anchorRight = $hasRight -and $right.ContainsKey($key)
                    if ($anchorLeft -and $anchorRight) {
                        $retainedAnchors++
                        $leftHist = Get-CodeSequenceSeverities -Group $left[$key]
                        $rightHist = Get-CodeSequenceSeverities -Group $right[$key]
                        foreach ($severity in @('critical','high','medium','low','info')) {
                            if ($leftHist[$severity] -ne $rightHist[$severity]) {
                                $severityDifferent++
                                break
                            }
                        }
                    } elseif ($anchorLeft) { $oneSidedLeft++ }
                    else { $oneSidedRight++ }
                }
                $leftOnlyAnchors += $oneSidedLeft
                $rightOnlyAnchors += $oneSidedRight
                $severityChangedAnchors += $severityDifferent
                $anchorDifference = $oneSidedLeft + $oneSidedRight
                $changed = ($anchorDifference -gt 0 -or $severityDifferent -gt 0)
                if ($hasLeft -and $hasRight -and $anchorDifference -gt 0) {
                    $retainedPathsWithChurn++
                    $metric.retained_path_anchor_churn_pair_count++
                }
                if ($hasLeft -and $hasRight -and $severityDifferent -gt 0) {
                    $retainedPathsWithSeverity++
                    $metric.retained_path_severity_change_pair_count++
                }
                if ($hasLeft -xor $hasRight) { $metric.one_sided_path_pair_count++ }
                $metric.exact_anchor_symmetric_difference_pair_occurrences += $anchorDifference
                $metric.retained_severity_changed_anchor_pair_occurrences += $severityDifferent
                if ($changed) {
                    $changedPaths++
                    $metric.differing_pair_count++
                    $severityOnly = ($anchorDifference -eq 0)
                    if ($severityOnly) {
                        $metric.severity_histogram_only_difference_pair_count++
                        $severityOnlyChangedPaths++
                    }
                    $metric.differing_pairs.Add([ordered]@{
                        left_position = $leftIndex + 1
                        right_position = $rightIndex + 1
                        left_record_id = $States[$leftIndex].checked.id
                        right_record_id = $States[$rightIndex].checked.id
                        path_presence_difference = ($hasLeft -xor $hasRight)
                        exact_anchor_symmetric_difference_count = $anchorDifference
                        retained_severity_distribution_changed_count = $severityDifferent
                        severity_histogram_only_difference = $severityOnly
                    })
                }
            }
            $anchorDifferenceTotal = $leftOnlyAnchors + $rightOnlyAnchors
            $actualCounts = [ordered]@{
                left_reported_path_count = $leftReported
                right_reported_path_count = $rightReported
                retained_path_count = $retainedPaths
                left_only_path_count = $leftOnlyPaths
                right_only_path_count = $rightOnlyPaths
                retained_path_with_anchor_churn_count = $retainedPathsWithChurn
                retained_path_with_severity_distribution_change_count = $retainedPathsWithSeverity
                changed_path_count = $changedPaths
                retained_exact_anchor_count = $retainedAnchors
                left_only_exact_anchor_count = $leftOnlyAnchors
                right_only_exact_anchor_count = $rightOnlyAnchors
                retained_severity_distribution_changed_count = $severityChangedAnchors
                exact_anchor_symmetric_difference_count = $anchorDifferenceTotal
                left_finding_statement_count = $leftStatements
                right_finding_statement_count = $rightStatements
            }
            if ($expected.counts.Count -ne $actualCounts.Count -or
                [bool]$expected.matches_profile -ne ($changedPaths -eq 0) -or
                [bool]$expected.severity_histogram_only_difference -ne
                    ($changedPaths -gt 0 -and $anchorDifferenceTotal -eq 0)) {
                throw 'Code Sequence pairwise path disagreement contradicts EC-029 pair equality or counts.'
            }
            foreach ($field in $actualCounts.Keys) {
                if (-not $expected.counts.Contains($field) -or
                    [int]$expected.counts[$field] -ne [int]$actualCounts[$field]) {
                    throw 'Code Sequence pairwise path disagreement lost full pair path/anchor/statement attribution.'
                }
            }
            $totalChangedPathPairOccurrences += $changedPaths
            $totalOneSidedPathPairs += $leftOnlyPaths + $rightOnlyPaths
            $totalRetainedPathAnchorChurnPairs += $retainedPathsWithChurn
            $totalRetainedPathSeverityChangePairs += $retainedPathsWithSeverity
            # Per-path severity-only does not require the whole record pair
            # to be severity-only; unrelated paths may have anchor churn.
            $totalSeverityOnlyPathPairs += $severityOnlyChangedPaths
            $totalAnchorSymmetricDifferenceOccurrences += $anchorDifferenceTotal
            $totalRetainedSeverityChangedAnchorOccurrences += $severityChangedAnchors
            $pairIndex++
        }
    }
    if ($pairIndex -ne $pairCount) {
        throw 'Code Sequence pairwise path disagreement did not inspect every unordered pair.'
    }

    $bins = [int[]]::new($pairCount + 1)
    $hotspots = [System.Collections.Generic.List[object]]::new()
    $changedPathCount = 0; $unchangedPathCount = 0
    $sumChanged = 0; $sumOneSided = 0; $sumRetainedChurn = 0
    $sumRetainedSeverity = 0; $sumSeverityOnly = 0
    $sumAnchors = 0; $sumSeverityAnchors = 0
    foreach ($path in $allPaths) {
        $metric = $metrics[$path]
        $differing = [int]$metric.differing_pair_count
        if ($differing -gt $pairCount -or $metric.differing_pairs.Count -ne $differing -or
            $metric.one_sided_path_pair_count -ne
                ($metric.reporting_position_count * ($count - $metric.reporting_position_count)) -or
            $metric.severity_histogram_only_difference_pair_count -gt $differing -or
            $metric.retained_path_anchor_churn_pair_count -gt $differing -or
            $metric.retained_path_severity_change_pair_count -gt $differing) {
            throw 'Code Sequence pairwise path disagreement per-path pair coverage is inconsistent.'
        }
        $bins[$differing]++
        $sumChanged += $differing
        $sumOneSided += [int]$metric.one_sided_path_pair_count
        $sumRetainedChurn += [int]$metric.retained_path_anchor_churn_pair_count
        $sumRetainedSeverity += [int]$metric.retained_path_severity_change_pair_count
        $sumSeverityOnly += [int]$metric.severity_histogram_only_difference_pair_count
        $sumAnchors += [int]$metric.exact_anchor_symmetric_difference_pair_occurrences
        $sumSeverityAnchors += [int]$metric.retained_severity_changed_anchor_pair_occurrences
        if ($differing -eq 0) { $unchangedPathCount++; continue }
        $changedPathCount++
        $candidate = [ordered]@{
            path = $path
            reporting_position_count = [int]$metric.reporting_position_count
            differing_pair_count = $differing
            matching_pair_count = $pairCount - $differing
            one_sided_path_pair_count = [int]$metric.one_sided_path_pair_count
            retained_path_anchor_churn_pair_count = [int]$metric.retained_path_anchor_churn_pair_count
            retained_path_severity_change_pair_count = [int]$metric.retained_path_severity_change_pair_count
            severity_histogram_only_difference_pair_count = [int]$metric.severity_histogram_only_difference_pair_count
            exact_anchor_symmetric_difference_pair_occurrences = [int]$metric.exact_anchor_symmetric_difference_pair_occurrences
            retained_severity_changed_anchor_pair_occurrences = [int]$metric.retained_severity_changed_anchor_pair_occurrences
            differing_pairs = $metric.differing_pairs.ToArray()
        }
        for ($at = 0; $at -lt $hotspots.Count; $at++) {
            if (Test-CodeSequencePairwisePathRanksBefore -Candidate $candidate -Existing $hotspots[$at]) { break }
        }
        if ($at -lt $Top) {
            $hotspots.Insert($at, $candidate)
            if ($hotspots.Count -gt $Top) { $hotspots.RemoveAt($Top) }
        }
    }
    $distribution = [System.Collections.Generic.List[object]]::new()
    $distributionCount = 0; $distributionWeighted = 0
    for ($n = 0; $n -le $pairCount; $n++) {
        $distribution.Add([ordered]@{ differing_pair_count = $n; saved_path_count = $bins[$n] })
        $distributionCount += $bins[$n]
        $distributionWeighted += $n * $bins[$n]
    }
    if ($distributionCount -ne $allPaths.Count -or
        $distributionWeighted -ne $totalChangedPathPairOccurrences -or
        $sumChanged -ne $totalChangedPathPairOccurrences -or
        $sumOneSided -ne $totalOneSidedPathPairs -or
        $sumRetainedChurn -ne $totalRetainedPathAnchorChurnPairs -or
        $sumRetainedSeverity -ne $totalRetainedPathSeverityChangePairs -or
        $sumAnchors -ne $totalAnchorSymmetricDifferenceOccurrences -or
        $sumSeverityAnchors -ne $totalRetainedSeverityChangedAnchorOccurrences -or
        $changedPathCount + $unchangedPathCount -ne $allPaths.Count -or
        $hotspots.Count -ne [Math]::Min($Top, $changedPathCount)) {
        throw 'Code Sequence pairwise path disagreement histogram or pair/path totals do not reconcile.'
    }
    # Severity-only counts require two independent projections: per pair
    # and per path, not necessarily severity-only for the WHOLE record pair.
    if ($sumSeverityOnly -ne $totalSeverityOnlyPathPairs) {
        throw 'Code Sequence pairwise path disagreement severity-only totals do not reconcile.'
    }

    return [ordered]@{
        scope = 'exact_saved_path_union_by_every_unordered_selected_record_pair_not_chronology'
        basis = 'exact_six_field_anchor_membership_and_per_anchor_five_severity_statement_histogram'
        selected_record_count = $count
        pair_count = $pairCount
        counts = [ordered]@{
            distinct_saved_path_union_count = $allPaths.Count
            paths_differing_in_at_least_one_pair_count = $changedPathCount
            paths_matching_in_all_pairs_count = $unchangedPathCount
            changed_path_pair_occurrences = $totalChangedPathPairOccurrences
            matching_path_pair_occurrences = ($allPaths.Count * $pairCount - $totalChangedPathPairOccurrences)
            one_sided_path_pair_occurrences = $totalOneSidedPathPairs
            retained_path_anchor_churn_pair_occurrences = $totalRetainedPathAnchorChurnPairs
            retained_path_severity_change_pair_occurrences = $totalRetainedPathSeverityChangePairs
            severity_histogram_only_difference_path_pair_occurrences = $totalSeverityOnlyPathPairs
            exact_anchor_symmetric_difference_pair_occurrences = $totalAnchorSymmetricDifferenceOccurrences
            retained_severity_changed_anchor_pair_occurrences = $totalRetainedSeverityChangedAnchorOccurrences
        }
        differing_pair_count_distribution = $distribution.ToArray()
        preview_top = $Top
        hotspots = $hotspots.ToArray()
        omitted_hotspots = $changedPathCount - $hotspots.Count
        hotspots_truncated = ($changedPathCount -gt $hotspots.Count)
        explanation = 'Each exact case-sensitive saved path is compared in every unordered selected-report pair, including pairs where the path is absent on both sides (matching for that path). A changed path means different exact quote-anchor membership or a different retained-anchor five-severity Finding-statement histogram. One-sided path, retained anchor churn and retained severity changes are distinct counts and can overlap where specified. Full pair-path totals and the 0..pair-count path-frequency distribution are not clipped; only frequency-ranked path previews are capped by SequenceTop, and every displayed path includes ALL its differing pair positions. Rankings are navigation, not severity/risk. Caller order and missing saved reports do not prove time, actual source change, fixes, regressions or semantic issue identity; no new record/source read or writer is involved.'
    }
}

# EC-031: partition the SAME checked positions into exact profile classes
# independently for EACH saved path. An unreported path is one distinct
# profile, shared by every position that does not report that path; that
# absence is not a claim about source files. Only changing-path class
# previews are clipped; full partition counts and pair reconciliation are not.
function Test-CodeSequenceSavedPathProfilesEqual {
    param([AllowNull()][object] $Left, [AllowNull()][object] $Right)

    if ($null -eq $Left -or $null -eq $Right) {
        return ($null -eq $Left -and $null -eq $Right)
    }
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($key in $Left.Keys) {
        if (-not $Right.ContainsKey($key)) { return $false }
        $leftSeverity = Get-CodeSequenceSeverities -Group $Left[$key]
        $rightSeverity = Get-CodeSequenceSeverities -Group $Right[$key]
        foreach ($severity in @('critical','high','medium','low','info')) {
            if ([int]$leftSeverity[$severity] -ne [int]$rightSeverity[$severity]) {
                return $false
            }
        }
    }
    return $true
}

function Test-CodeSequencePathClassRanksBefore {
    param([object] $Candidate, [object] $Existing)
    if ([int]$Candidate.distinct_profile_class_count -ne [int]$Existing.distinct_profile_class_count) {
        return ([int]$Candidate.distinct_profile_class_count -gt [int]$Existing.distinct_profile_class_count)
    }
    if ([int]$Candidate.differing_pair_count -ne [int]$Existing.differing_pair_count) {
        return ([int]$Candidate.differing_pair_count -gt [int]$Existing.differing_pair_count)
    }
    return ([string]::Compare([string]$Candidate.path, [string]$Existing.path,
        [System.StringComparison]::Ordinal) -lt 0)
}

function Get-CodeSequencePathProfileClasses {
    param([object[]] $States, [object[]] $Pairs, [object] $PathDisagreement, [int] $Top)

    $count = $States.Count
    $pairCount = [int](($count * ($count - 1)) / 2)
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        $Pairs.Count -ne $pairCount -or $null -eq $PathDisagreement -or
        $Top -lt 1 -or $Top -gt $script:CodeShowSequenceMaxTop) {
        throw 'Code Sequence per-path profile classes require the complete checked pair/path result and Top 1..20.'
    }

    $byPosition = [System.Collections.Generic.List[object]]::new()
    $allPaths = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($state in $States) {
        $byPath = Get-CodeSequenceGroupsByPath -Groups $state.groups
        $byPosition.Add($byPath)
        foreach ($path in $byPath.Keys) { [void]$allPaths.Add($path) }
    }

    $pairChangedPathCounts = [int[]]::new($pairCount)
    $profileClassBins = [int[]]::new($count + 1)
    $differenceBins = [int[]]::new($pairCount + 1)
    $hotspots = [System.Collections.Generic.List[object]]::new()
    $unchangedPaths = 0; $changedPaths = 0; $allDistinctPaths = 0
    $pathsWithUnreported = 0; $pathsWithReusedReportedProfile = 0
    $totalClasses = 0; $reportedClasses = 0; $unreportedClasses = 0
    $totalClassMembers = 0; $totalMatchingPathPairs = 0; $totalDifferingPathPairs = 0

    foreach ($path in $allPaths) {
        # The class index is 1-based, allocated at the first caller position
        # for that exact saved-path profile. No synthetic hash is trusted as
        # a semantic/equality shortcut, and no model free text is inspected.
        $classes = [System.Collections.Generic.List[object]]::new()
        $positionClassIds = [int[]]::new($count)
        $positionReported = [bool[]]::new($count)
        for ($i = 0; $i -lt $count; $i++) {
            $hasPath = $byPosition[$i].ContainsKey($path)
            $positionReported[$i] = $hasPath
            $candidate = if ($hasPath) { $byPosition[$i][$path] } else { $null }
            $classIndex = -1
            for ($j = 0; $j -lt $classes.Count; $j++) {
                if (Test-CodeSequenceSavedPathProfilesEqual -Left $candidate `
                        -Right $classes[$j].representative_profile) {
                    $classIndex = $j
                    break
                }
            }
            if ($classIndex -lt 0) {
                $classIndex = $classes.Count
                $classes.Add([pscustomobject]@{
                    representative_profile = $candidate
                    path_reported = $hasPath
                    first_position = $i + 1
                    exact_anchor_count = if ($hasPath) { $candidate.Count } else { 0 }
                    finding_statement_count = if ($hasPath) {
                        Get-CodeSequenceGroupStatementCount -Groups $candidate
                    } else { 0 }
                    member_positions = [System.Collections.Generic.List[int]]::new()
                    member_record_ids = [System.Collections.Generic.List[string]]::new()
                })
            }
            $positionClassIds[$i] = $classIndex + 1
            $classes[$classIndex].member_positions.Add($i + 1)
            $classes[$classIndex].member_record_ids.Add([string]$States[$i].checked.id)
        }
        if ($classes.Count -lt 1 -or $classes.Count -gt $count) {
            throw 'Code Sequence saved-path profile class count is out of bounds.'
        }
        $profileClassBins[$classes.Count]++
        $totalClasses += $classes.Count
        $matching = 0
        $members = 0
        $hasUnreported = $false
        $reusedReported = $false
        foreach ($group in $classes) {
            $size = $group.member_positions.Count
            $members += $size
            $matching += [int](($size * ($size - 1)) / 2)
            if ($group.path_reported) {
                $reportedClasses++
                if ($size -ge 2) { $reusedReported = $true }
            } else {
                $unreportedClasses++
                if ($hasUnreported) {
                    throw 'Code Sequence has more than one unreported class for one saved path.'
                }
                $hasUnreported = $true
            }
        }
        if ($members -ne $count -or $matching -gt $pairCount) {
            throw 'Code Sequence saved-path profile class membership does not partition the selection.'
        }
        $totalClassMembers += $members
        if ($hasUnreported) { $pathsWithUnreported++ }
        if ($reusedReported) { $pathsWithReusedReportedProfile++ }
        $differing = $pairCount - $matching
        $differenceBins[$differing]++
        $totalMatchingPathPairs += $matching
        $totalDifferingPathPairs += $differing
        if ($classes.Count -eq 1) { $unchangedPaths++ } else { $changedPaths++ }
        if ($classes.Count -eq $count) { $allDistinctPaths++ }

        # Verify the partition directly against every unordered pair, not
        # merely against its representatives. This catches any nontransitive
        # grouping or silent loss of a retained-anchor severity histogram.
        $directDiffering = 0; $pairIndex = 0
        for ($left = 0; $left -lt ($count - 1); $left++) {
            for ($right = $left + 1; $right -lt $count; $right++) {
                $leftGroups = if ($positionReported[$left]) { $byPosition[$left][$path] } else { $null }
                $rightGroups = if ($positionReported[$right]) { $byPosition[$right][$path] } else { $null }
                $sameDirect = Test-CodeSequenceSavedPathProfilesEqual -Left $leftGroups -Right $rightGroups
                $sameClass = ($positionClassIds[$left] -eq $positionClassIds[$right])
                if ($sameDirect -ne $sameClass) {
                    throw 'Code Sequence saved-path partition contradicts a direct pair profile equality.'
                }
                if (-not $sameClass) {
                    $pairChangedPathCounts[$pairIndex]++
                    $directDiffering++
                }
                $pairIndex++
            }
        }
        if ($pairIndex -ne $pairCount -or $directDiffering -ne $differing) {
            throw 'Code Sequence saved-path classes do not reconcile to all pair comparisons.'
        }
        if ($classes.Count -eq 1) { continue }

        # Full class membership for each SHOWN path; neither class members
        # nor class positions are clipped. Top limits only path rows.
        $classRows = [System.Collections.Generic.List[object]]::new()
        foreach ($group in $classes) {
            $classRows.Add([ordered]@{
                profile_class = $classRows.Count + 1
                representative_position = [int]$group.first_position
                representative_record_id = [string]$group.member_record_ids[0]
                path_reported = [bool]$group.path_reported
                exact_anchor_count = [int]$group.exact_anchor_count
                finding_statement_count = [int]$group.finding_statement_count
                member_count = $group.member_positions.Count
                positions = $group.member_positions.ToArray()
                record_ids = $group.member_record_ids.ToArray()
            })
        }
        $positionRows = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            $positionRows.Add([ordered]@{
                position = $i + 1
                record_id = [string]$States[$i].checked.id
                profile_class = $positionClassIds[$i]
                path_reported = [bool]$positionReported[$i]
            })
        }
        $candidateRow = [ordered]@{
            path = $path
            distinct_profile_class_count = $classes.Count
            differing_pair_count = $differing
            matching_pair_count = $matching
            profile_classes = $classRows.ToArray()
            position_profile_classes = $positionRows.ToArray()
        }
        for ($at = 0; $at -lt $hotspots.Count; $at++) {
            if (Test-CodeSequencePathClassRanksBefore -Candidate $candidateRow -Existing $hotspots[$at]) {
                break
            }
        }
        if ($at -lt $Top) {
            $hotspots.Insert($at, $candidateRow)
            if ($hotspots.Count -gt $Top) { $hotspots.RemoveAt($Top) }
        }
    }

    # Reconcile the independent path-wise class partition with every EC-029
    # pair row, and with EC-030's untruncated per-path pair frequency bins.
    $pairTotal = 0
    for ($left = 0; $left -lt ($count - 1); $left++) {
        for ($right = $left + 1; $right -lt $count; $right++) {
            $expected = $Pairs[$pairTotal]
            if ([int]$expected.left_position -ne ($left + 1) -or
                [int]$expected.right_position -ne ($right + 1) -or
                [string]$expected.left_record_id -cne [string]$States[$left].checked.id -or
                [string]$expected.right_record_id -cne [string]$States[$right].checked.id -or
                [int]$expected.counts.changed_path_count -ne $pairChangedPathCounts[$pairTotal] -or
                [bool]$expected.matches_profile -ne ($pairChangedPathCounts[$pairTotal] -eq 0)) {
                throw 'Code Sequence saved-path classes contradict an EC-029 unordered pair.'
            }
            $pairTotal++
        }
    }
    $weightedClasses = 0; $binnedPaths = 0
    $distribution = [System.Collections.Generic.List[object]]::new()
    for ($n = 1; $n -le $count; $n++) {
        $distribution.Add([ordered]@{ distinct_profile_class_count = $n; saved_path_count = $profileClassBins[$n] })
        $binnedPaths += $profileClassBins[$n]
        $weightedClasses += $n * $profileClassBins[$n]
    }
    $binnedDifferences = 0; $weightedDifferences = 0
    for ($n = 0; $n -le $pairCount; $n++) {
        $expected = $PathDisagreement.differing_pair_count_distribution[$n]
        if ($null -eq $expected -or [int]$expected.differing_pair_count -ne $n -or
            [int]$expected.saved_path_count -ne $differenceBins[$n]) {
            throw 'Code Sequence saved-path classes contradict EC-030 complete pair-frequency bins.'
        }
        $binnedDifferences += $differenceBins[$n]
        $weightedDifferences += $n * $differenceBins[$n]
    }
    $old = $PathDisagreement.counts
    if ($pairTotal -ne $pairCount -or $binnedPaths -ne $allPaths.Count -or
        $binnedDifferences -ne $allPaths.Count -or $weightedClasses -ne $totalClasses -or
        $totalClasses -ne ($reportedClasses + $unreportedClasses) -or
        $totalClassMembers -ne ($allPaths.Count * $count) -or
        $totalMatchingPathPairs + $totalDifferingPathPairs -ne ($allPaths.Count * $pairCount) -or
        $totalDifferingPathPairs -ne $weightedDifferences -or
        $allPaths.Count -ne [int]$old.distinct_saved_path_union_count -or
        $unchangedPaths -ne [int]$old.paths_matching_in_all_pairs_count -or
        $changedPaths -ne [int]$old.paths_differing_in_at_least_one_pair_count -or
        $totalDifferingPathPairs -ne [int]$old.changed_path_pair_occurrences -or
        $totalMatchingPathPairs -ne [int]$old.matching_path_pair_occurrences -or
        $hotspots.Count -ne [Math]::Min($Top, $changedPaths)) {
        throw 'Code Sequence per-path profile classes failed complete EC-030/031 reconciliation.'
    }
    return [ordered]@{
        scope = 'exact_saved_path_profiles_partitioned_per_caller_position_not_chronology'
        basis = 'exact_six_field_anchor_membership_and_per_anchor_five_severity_statement_histogram'
        selected_record_count = $count
        pair_count = $pairCount
        counts = [ordered]@{
            distinct_saved_path_union_count = $allPaths.Count
            paths_with_single_profile_class_count = $unchangedPaths
            paths_with_multiple_profile_classes_count = $changedPaths
            paths_with_all_positions_distinct_profile_count = $allDistinctPaths
            paths_with_unreported_positions_count = $pathsWithUnreported
            paths_with_reused_reported_profile_count = $pathsWithReusedReportedProfile
            total_path_profile_class_count = $totalClasses
            reported_path_profile_class_count = $reportedClasses
            unreported_path_profile_class_count = $unreportedClasses
            matching_path_pair_occurrences = $totalMatchingPathPairs
            differing_path_pair_occurrences = $totalDifferingPathPairs
        }
        distinct_profile_class_count_distribution = $distribution.ToArray()
        preview_top = $Top
        hotspots = $hotspots.ToArray()
        omitted_hotspots = $changedPaths - $hotspots.Count
        hotspots_truncated = ($changedPaths -gt $hotspots.Count)
        explanation = 'For each exact case-sensitive historical saved Git path independently, divide every caller-selected report position into classes with identical six-field quote-anchor membership and per-anchor severity-statement histograms. A missing reported path belongs to one ordinary unreported class; that does not establish source absence or resolution. Class numbers follow first caller occurrence, not time, and each displayed changing path lists every class member and all caller positions. All counts and 1..N class-frequency bins cover the entire checked selection; SequenceTop clips only ranked changing-path hotspot rows. Results are reconciled with every EC-029 pair and EC-030 pair/path frequency bin. Ranking is profile diversity, not severity/risk; there are no further saved-record/source reads or writers.'
    }
}

# EC-029: compare EVERY unordered pair of the already checked selected saved
# reports. This closes the gap between adjacent-only and first-baseline-only
# views without opening another record or source file. Exact profile equality
# is the same anchor-set + per-anchor five-severity statement-histogram rule
# used by EC-027/028; caller position remains an order label, not time.
function Get-CodeSequencePairwiseProfile {
    param(
        [object[]] $States,
        [object[]] $ExpectedAdjacentPathDeltas,
        [object[]] $ExpectedBaselineComparisons,
        [int] $Top
    )

    $count = $States.Count
    if ($count -lt 2 -or $count -gt $script:CodeShowSequenceMaxRecords -or
        $ExpectedAdjacentPathDeltas.Count -ne ($count - 1) -or
        $ExpectedBaselineComparisons.Count -ne ($count - 1)) {
        throw 'Code Sequence pairwise profile requires complete adjacent and baseline comparisons for 2..12 selected records.'
    }

    $pairs = [System.Collections.Generic.List[object]]::new()
    $matches = [System.Collections.Generic.Dictionary[string,bool]]::new([System.StringComparer]::Ordinal)
    $matchingPairs = 0
    $differentPairs = 0
    $severityOnlyPairs = 0
    $pathPresenceDifferencePairs = 0
    $anchorPresenceDifferencePairs = 0
    $changedPathOccurrences = 0
    $anchorSymmetricDifferenceOccurrences = 0
    $severityChangedAnchorPairOccurrences = 0
    $maximumChangedPaths = 0
    $maximumAnchorSymmetricDifference = 0

    for ($leftIndex = 0; $leftIndex -lt ($count - 1); $leftIndex++) {
        for ($rightIndex = $leftIndex + 1; $rightIndex -lt $count; $rightIndex++) {
            $left = $States[$leftIndex]
            $right = $States[$rightIndex]
            $pairStates = @($left, $right)
            $anchorDelta = Get-CodeSequenceStep -Step 1 -Previous $left -Next $right -Top 1
            $pathDeltaRows = @(Get-CodeSequencePathStepDeltas -States $pairStates -ExpectedSteps @($anchorDelta) -Top 1)
            if ($pathDeltaRows.Count -ne 1) {
                throw 'Code Sequence pairwise profile did not produce exactly one complete path attribution.'
            }
            $pathDelta = $pathDeltaRows[0]
            $c = $pathDelta.counts
            $anchorSymmetricDifference = [int]$c.previous_only_exact_anchor_count + [int]$c.next_only_exact_anchor_count
            $changedPaths = [int]$c.changed_path_count
            $sameProfile = ($changedPaths -eq 0)
            $severityOnly = (-not $sameProfile -and $anchorSymmetricDifference -eq 0)
            $pathPresenceDifference = ([int]$c.previous_only_path_count + [int]$c.next_only_path_count -gt 0)
            $anchorPresenceDifference = ($anchorSymmetricDifference -gt 0)

            if (($sameProfile -and ($anchorSymmetricDifference -ne 0 -or
                        [int]$c.retained_severity_distribution_changed_count -ne 0)) -or
                (-not $sameProfile -and $anchorSymmetricDifference -eq 0 -and
                        [int]$c.retained_severity_distribution_changed_count -eq 0) -or
                [int]$c.retained_exact_anchor_count + [int]$c.previous_only_exact_anchor_count -ne $left.groups.Count -or
                [int]$c.retained_exact_anchor_count + [int]$c.next_only_exact_anchor_count -ne $right.groups.Count -or
                [int]$c.previous_finding_statement_count -ne (Get-CodeSequenceGroupStatementCount -Groups $left.groups) -or
                [int]$c.next_finding_statement_count -ne (Get-CodeSequenceGroupStatementCount -Groups $right.groups) -or
                $pathDelta.previous_record_id -cne $left.checked.id -or
                $pathDelta.next_record_id -cne $right.checked.id) {
                throw 'Code Sequence pairwise profile failed complete anchor/path/statement reconciliation.'
            }

            # Every adjacent all-pairs row must reproduce EC-025 exactly.
            if ($rightIndex -eq ($leftIndex + 1)) {
                $expectedAdjacent = $ExpectedAdjacentPathDeltas[$leftIndex]
                if ($expectedAdjacent.previous_record_id -cne $pathDelta.previous_record_id -or
                    $expectedAdjacent.next_record_id -cne $pathDelta.next_record_id -or
                    $expectedAdjacent.counts.Count -ne $c.Count) {
                    throw 'Code Sequence pairwise adjacent identity contradicts EC-025 attribution.'
                }
                foreach ($field in $c.Keys) {
                    if (-not $expectedAdjacent.counts.Contains($field) -or
                        [int]$expectedAdjacent.counts[$field] -ne [int]$c[$field]) {
                        throw 'Code Sequence pairwise adjacent counts contradict EC-025 attribution.'
                    }
                }
            }

            # Every first-vs-later row must reproduce EC-027's complete pair.
            if ($leftIndex -eq 0) {
                $expectedBaseline = $ExpectedBaselineComparisons[$rightIndex - 1]
                $baselineMapped = [ordered]@{
                    baseline_reported_path_count = $c.previous_reported_path_count
                    compared_reported_path_count = $c.next_reported_path_count
                    retained_path_count = $c.retained_path_count
                    baseline_only_path_count = $c.previous_only_path_count
                    compared_only_path_count = $c.next_only_path_count
                    retained_path_with_anchor_churn_count = $c.retained_path_with_anchor_churn_count
                    retained_path_with_severity_distribution_change_count = $c.retained_path_with_severity_distribution_change_count
                    changed_path_count = $c.changed_path_count
                    retained_exact_anchor_count = $c.retained_exact_anchor_count
                    baseline_only_exact_anchor_count = $c.previous_only_exact_anchor_count
                    compared_only_exact_anchor_count = $c.next_only_exact_anchor_count
                    retained_severity_distribution_changed_count = $c.retained_severity_distribution_changed_count
                    exact_anchor_symmetric_difference_count = $anchorSymmetricDifference
                    baseline_finding_statement_count = $c.previous_finding_statement_count
                    compared_finding_statement_count = $c.next_finding_statement_count
                }
                if ($expectedBaseline.baseline_position -ne 1 -or
                    $expectedBaseline.compared_position -ne ($rightIndex + 1) -or
                    $expectedBaseline.baseline_record_id -cne $left.checked.id -or
                    $expectedBaseline.compared_record_id -cne $right.checked.id -or
                    [bool]$expectedBaseline.matches_baseline_profile -ne $sameProfile -or
                    $expectedBaseline.counts.Count -ne $baselineMapped.Count) {
                    throw 'Code Sequence pairwise first-relative identity contradicts EC-027 baseline comparison.'
                }
                foreach ($field in $baselineMapped.Keys) {
                    if (-not $expectedBaseline.counts.Contains($field) -or
                        [int]$expectedBaseline.counts[$field] -ne [int]$baselineMapped[$field]) {
                        throw 'Code Sequence pairwise first-relative counts contradict EC-027 baseline comparison.'
                    }
                }
            }

            $key = ([string]$leftIndex + '|' + [string]$rightIndex)
            $matches.Add($key, $sameProfile)
            $pairs.Add([ordered]@{
                left_position = $leftIndex + 1
                right_position = $rightIndex + 1
                left_record_id = $left.checked.id
                right_record_id = $right.checked.id
                matches_profile = $sameProfile
                severity_histogram_only_difference = $severityOnly
                counts = [ordered]@{
                    left_reported_path_count = $c.previous_reported_path_count
                    right_reported_path_count = $c.next_reported_path_count
                    retained_path_count = $c.retained_path_count
                    left_only_path_count = $c.previous_only_path_count
                    right_only_path_count = $c.next_only_path_count
                    retained_path_with_anchor_churn_count = $c.retained_path_with_anchor_churn_count
                    retained_path_with_severity_distribution_change_count = $c.retained_path_with_severity_distribution_change_count
                    changed_path_count = $changedPaths
                    retained_exact_anchor_count = $c.retained_exact_anchor_count
                    left_only_exact_anchor_count = $c.previous_only_exact_anchor_count
                    right_only_exact_anchor_count = $c.next_only_exact_anchor_count
                    retained_severity_distribution_changed_count = $c.retained_severity_distribution_changed_count
                    exact_anchor_symmetric_difference_count = $anchorSymmetricDifference
                    left_finding_statement_count = $c.previous_finding_statement_count
                    right_finding_statement_count = $c.next_finding_statement_count
                }
            })

            if ($sameProfile) { $matchingPairs++ } else { $differentPairs++ }
            if ($severityOnly) { $severityOnlyPairs++ }
            if ($pathPresenceDifference) { $pathPresenceDifferencePairs++ }
            if ($anchorPresenceDifference) { $anchorPresenceDifferencePairs++ }
            $changedPathOccurrences += $changedPaths
            $anchorSymmetricDifferenceOccurrences += $anchorSymmetricDifference
            $severityChangedAnchorPairOccurrences += [int]$c.retained_severity_distribution_changed_count
            if ($changedPaths -gt $maximumChangedPaths) { $maximumChangedPaths = $changedPaths }
            if ($anchorSymmetricDifference -gt $maximumAnchorSymmetricDifference) {
                $maximumAnchorSymmetricDifference = $anchorSymmetricDifference
            }
        }
    }

    $expectedPairCount = [int](($count * ($count - 1)) / 2)
    if ($pairs.Count -ne $expectedPairCount -or
        $matchingPairs + $differentPairs -ne $expectedPairCount -or
        $severityOnlyPairs -gt $differentPairs -or
        $pathPresenceDifferencePairs -gt $differentPairs -or
        $anchorPresenceDifferencePairs -gt $differentPairs) {
        throw 'Code Sequence pairwise profile has inconsistent complete pair totals.'
    }

    # Partition selected positions into equivalence classes by the exact same
    # profile predicate used above. Earliest caller position is the stable
    # representative; no digest, prose or timestamp participates.
    $classBuilders = [System.Collections.Generic.List[object]]::new()
    for ($positionIndex = 0; $positionIndex -lt $count; $positionIndex++) {
        $matchedClass = -1
        for ($classIndex = 0; $classIndex -lt $classBuilders.Count; $classIndex++) {
            $representativeIndex = [int]$classBuilders[$classIndex].representative_index
            $sameAsRepresentative = $true
            if ($representativeIndex -ne $positionIndex) {
                $matchKey = ([string]$representativeIndex + '|' + [string]$positionIndex)
                if (-not $matches.ContainsKey($matchKey)) {
                    throw 'Code Sequence pairwise profile class lookup is missing a completed pair.'
                }
                $sameAsRepresentative = $matches[$matchKey]
            }
            if ($sameAsRepresentative) {
                if ($matchedClass -ne -1) {
                    throw 'Code Sequence pairwise profile equality relation produced overlapping classes.'
                }
                $matchedClass = $classIndex
            }
        }
        if ($matchedClass -eq -1) {
            $positions = [System.Collections.Generic.List[int]]::new()
            $recordIds = [System.Collections.Generic.List[string]]::new()
            $positions.Add($positionIndex + 1)
            $recordIds.Add([string]$States[$positionIndex].checked.id)
            $classBuilders.Add([pscustomobject]@{
                representative_index = $positionIndex
                positions = $positions
                record_ids = $recordIds
            })
        } else {
            $classBuilders[$matchedClass].positions.Add($positionIndex + 1)
            $classBuilders[$matchedClass].record_ids.Add([string]$States[$positionIndex].checked.id)
        }
    }

    $positionClasses = [int[]]::new($count)
    $profileClasses = [System.Collections.Generic.List[object]]::new()
    $repeatedClasses = 0
    $positionsInRepeatedClasses = 0
    $singletonClasses = 0
    $matchingPairsFromClasses = 0
    for ($classIndex = 0; $classIndex -lt $classBuilders.Count; $classIndex++) {
        $builder = $classBuilders[$classIndex]
        $classNumber = $classIndex + 1
        $memberCount = $builder.positions.Count
        foreach ($position in $builder.positions) { $positionClasses[$position - 1] = $classNumber }
        if ($memberCount -gt 1) {
            $repeatedClasses++
            $positionsInRepeatedClasses += $memberCount
        } else { $singletonClasses++ }
        $matchingPairsFromClasses += [int](($memberCount * ($memberCount - 1)) / 2)
        $profileClasses.Add([ordered]@{
            profile_class = $classNumber
            representative_position = [int]$builder.representative_index + 1
            representative_record_id = $States[[int]$builder.representative_index].checked.id
            member_count = $memberCount
            repeated = ($memberCount -gt 1)
            positions = $builder.positions.ToArray()
            record_ids = $builder.record_ids.ToArray()
        })
    }

    $positionClassRows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $count; $i++) {
        $positionClassRows.Add([ordered]@{
            position = $i + 1
            record_id = $States[$i].checked.id
            profile_class = $positionClasses[$i]
        })
    }

    # Equality classes must explain EVERY pair row; this also fail-closes any
    # accidental non-transitive result from future changes to the predicate.
    foreach ($pair in $pairs) {
        $sameClass = ($positionClasses[[int]$pair.left_position - 1] -eq
            $positionClasses[[int]$pair.right_position - 1])
        if ([bool]$pair.matches_profile -ne $sameClass) {
            throw 'Code Sequence pairwise profile classes contradict a complete pair comparison.'
        }
    }

    $distribution = [System.Collections.Generic.List[object]]::new()
    $bins = [int[]]::new($maximumChangedPaths + 1)
    foreach ($pair in $pairs) { $bins[[int]$pair.counts.changed_path_count]++ }
    $distributionTotal = 0
    $distributionWeighted = 0
    for ($n = 0; $n -lt $bins.Count; $n++) {
        $distribution.Add([ordered]@{
            changed_path_count = $n
            record_pair_count = $bins[$n]
        })
        $distributionTotal += $bins[$n]
        $distributionWeighted += $n * $bins[$n]
    }
    if ($matchingPairsFromClasses -ne $matchingPairs -or
        $classBuilders.Count -ne ($repeatedClasses + $singletonClasses) -or
        $distributionTotal -ne $expectedPairCount -or
        $distributionWeighted -ne $changedPathOccurrences -or
        $bins[0] -ne $matchingPairs) {
        throw 'Code Sequence pairwise profile class or distance distribution totals do not reconcile.'
    }

    $result = [ordered]@{
        scope = 'all_unordered_pairs_of_caller_selected_checked_saved_records_not_time'
        basis = 'exact_saved_six_field_quote_anchor_and_per_anchor_five_severity_statement_histogram'
        selected_record_count = $count
        pair_count = $expectedPairCount
        counts = [ordered]@{
            matching_profile_pair_count = $matchingPairs
            differing_profile_pair_count = $differentPairs
            severity_histogram_only_difference_pair_count = $severityOnlyPairs
            path_presence_difference_pair_count = $pathPresenceDifferencePairs
            exact_anchor_presence_difference_pair_count = $anchorPresenceDifferencePairs
            changed_path_pair_occurrences = $changedPathOccurrences
            exact_anchor_symmetric_difference_pair_occurrences = $anchorSymmetricDifferenceOccurrences
            retained_severity_distribution_changed_anchor_pair_occurrences = $severityChangedAnchorPairOccurrences
            maximum_changed_path_count = $maximumChangedPaths
            maximum_exact_anchor_symmetric_difference_count = $maximumAnchorSymmetricDifference
            distinct_profile_class_count = $classBuilders.Count
            repeated_profile_class_count = $repeatedClasses
            positions_in_repeated_profile_classes_count = $positionsInRepeatedClasses
            singleton_profile_class_count = $singletonClasses
        }
        changed_path_count_distribution = $distribution.ToArray()
        pairs = $pairs.ToArray()
        profile_classes = $profileClasses.ToArray()
        position_profile_classes = $positionClassRows.ToArray()
        explanation = 'Every unordered pair of the same fully checked selected saved reports is compared, including nonadjacent pairs that neither share the first baseline nor sit next to each other. Profile equality means exact saved quote-anchor membership plus the per-anchor five-severity Finding-statement histogram, not identical Finding IDs, summary prose, record bytes, source code, defect identity or verified chronology. Profile classes are exact equivalence classes over this comparison predicate and use earliest caller position only as a deterministic representative. No extra record, source file or writer is used.'
    }
    # EC-030: independently account for every changed path in every pair,
    # then require exact reconciliation with ALL the above full pair rows.
    $result['path_disagreement'] = Get-CodeSequencePairwisePathDisagreement -States $States `
        -Pairs ($pairs.ToArray()) -Top $Top
    if ($result.path_disagreement.counts.changed_path_pair_occurrences -ne $changedPathOccurrences -or
        $result.path_disagreement.counts.exact_anchor_symmetric_difference_pair_occurrences -ne $anchorSymmetricDifferenceOccurrences -or
        $result.path_disagreement.counts.retained_severity_changed_anchor_pair_occurrences -ne $severityChangedAnchorPairOccurrences) {
        throw 'Code Sequence pairwise path disagreement contradicts complete EC-029 totals.'
    }
    # EC-031: preserve the complete EC-029/030 results, then independently
    # partition caller positions for each saved path into exact local classes.
    $result['path_profile_classes'] = Get-CodeSequencePathProfileClasses -States $States `
        -Pairs ($pairs.ToArray()) -PathDisagreement $result.path_disagreement -Top $Top
    # EC-032: derive independently ranked path-local transitions/runs/returns
    # from the SAME already checked selection and exact EC-031 predicate.
    $result['path_profile_transitions'] = Get-CodeSequencePathProfileTransitions -States $States `
        -ExpectedAdjacentPathDeltas $ExpectedAdjacentPathDeltas -ExpectedAllPairs ($pairs.ToArray()) `
        -PathClasses $result.path_profile_classes -Top $Top
    return $result
}

function Get-CodeShowSequence {
    param(
        [string] $Directory,
        [string] $VerifiedRoot,
        [string[]] $RecordIds,
        [int] $Top,
        [AllowNull()][object] $Path = $null,
        [AllowNull()][object] $FindingRecordId = $null,
        [AllowNull()][object] $FindingId = $null,
        [AllowNull()][object] $AnchorIndex = $null,
        [AllowNull()][object] $PairIndex = $null,
        [AllowNull()][object] $PairOverviewIndex = $null,
        [AllowNull()][object] $PairPathIndex = $null,
        [AllowNull()][object] $PairPathAnchorIndex = $null,
        [AllowNull()][object] $PairPathAnchorFindingSide = $null,
        [AllowNull()][object] $PairPathAnchorFindingIndex = $null,
        [AllowNull()][object] $PairPathAnchorFindingCounterpartIndex = $null
    )

    # Preserve absent selectors as null; string binding converts null to ''.
    # Direct callers still must supply strings, with the original bounds below.
    foreach ($selector in @($Path, $FindingRecordId, $FindingId, $AnchorIndex, $PairIndex,
            $PairOverviewIndex, $PairPathIndex, $PairPathAnchorIndex,
            $PairPathAnchorFindingSide, $PairPathAnchorFindingIndex,
            $PairPathAnchorFindingCounterpartIndex)) {
        if ($null -ne $selector -and $selector -isnot [string]) {
            throw 'CODE_SHOW_SEQUENCE_SELECTOR_INVALID: optional selectors must be strings or null.'
        }
    }

    # EC-049: the fifth ordinal cannot be supplied without BOTH fourth-level
    # coordinates and all three parents, even by a direct module caller.
    # Canonical unsigned decimal 1..40; no implicit counterpart side or ID.
    if ($null -ne $PairPathAnchorFindingCounterpartIndex -and
        ($null -eq $PairOverviewIndex -or $null -eq $PairPathIndex -or
            $null -eq $PairPathAnchorIndex -or
            $null -eq $PairPathAnchorFindingSide -or
            $null -eq $PairPathAnchorFindingIndex -or
            $null -ne $Path -or $null -ne $PairIndex -or
            $null -ne $AnchorIndex -or $null -ne $FindingRecordId -or
            $null -ne $FindingId -or
            $PairPathAnchorFindingSide -cnotin @('left','right') -or
            $PairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$PairPathAnchorFindingIndex -gt 40 -or
            $PairPathAnchorFindingCounterpartIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$PairPathAnchorFindingCounterpartIndex -gt 40)) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_SELECTOR_INVALID: canonical 1..40 counterpart index requires complete four-level original Finding selection.'
    }
    # EC-048: a fourth-level Finding selection MUST carry both original
    # endpoint coordinates; reject direct module invocation before any body.
    if ($null -ne $PairPathAnchorFindingSide -or $null -ne $PairPathAnchorFindingIndex) {
        if ($null -eq $PairPathAnchorFindingSide -or $null -eq $PairPathAnchorFindingIndex -or
            $null -eq $PairOverviewIndex -or $null -eq $PairPathIndex -or
            $null -eq $PairPathAnchorIndex -or $null -ne $Path -or
            $null -ne $AnchorIndex -or $null -ne $PairIndex -or
            $null -ne $FindingRecordId -or $null -ne $FindingId -or
            $PairPathAnchorFindingSide -cnotin @('left','right') -or
            $PairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$PairPathAnchorFindingIndex -gt 40) {
            throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_SELECTOR_INVALID: canonical side and 1..40 ordinal require all three parent indices.'
        }
    }
    # EC-047: reject malformed direct module calls before even opening the
    # selected saved bodies; the two parent ordinals are both mandatory.
    if ($null -ne $PairPathAnchorIndex -and
        ($null -eq $PairOverviewIndex -or $null -eq $PairPathIndex -or
            $null -ne $Path -or $null -ne $AnchorIndex -or $null -ne $PairIndex -or
            $null -ne $FindingRecordId -or $null -ne $FindingId -or
            $PairPathAnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
            [int]$PairPathAnchorIndex -gt 480)) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_SELECTOR_INVALID: a valid exclusive indexed pair/path is required.'
    }

    # Membership-before-body invariant: verify the complete bounded store
    # filename inventory, then refuse if ANY selected ID is missing before
    # opening even the first selected record. No unselected body is opened.
    $beforeIds = @(Get-CodeShowRecordIds -Directory $Directory)
    foreach ($id in $RecordIds) {
        if (-not ($beforeIds -ccontains $id)) {
            throw 'CODE_SHOW_SEQUENCE_RECORD_NOT_FOUND: at least one selected record is missing.'
        }
    }

    $checked = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $RecordIds) {
        $checked.Add((Read-CodeShowRecord -Directory $Directory -Id $id -VerifiedRoot $VerifiedRoot))
    }

    # A cross-source-mode omission is not comparable. Nonetheless, every
    # chosen record was fully validated before checking compatibility.
    $sourceMode = [string]$checked[0].record.source_mode
    foreach ($item in $checked) {
        if ($item.record.source_mode -cne $sourceMode) {
            throw 'CODE_SHOW_SEQUENCE_SCOPE_MISMATCH: selected source modes differ.'
        }
    }

    $records = [System.Collections.Generic.List[object]]::new()
    $states = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $checked) {
        $groups = Get-CodeCompareGroups -Record $item.record
        $states.Add([pscustomobject]@{ checked = $item; groups = $groups })
        $records.Add([ordered]@{
            record_id = $item.id
            record_sha256 = $item.sha256
            source_mode = $sourceMode
            finding_statement_count = $item.record.finding_count
            distinct_exact_anchor_count = $groups.Count
            saved_collect_sha256 = $item.record.saved_collect_sha256
            packet_sha256 = $item.record.packet_sha256
        })
    }

    $steps = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $states.Count; $i++) {
        $steps.Add((Get-CodeSequenceStep -Step $i -Previous $states[$i-1] -Next $states[$i] -Top $Top))
    }

    # The trajectory and adjacent deltas share the same checked, grouped
    # selected bodies. Neither pass opens additional business/source files.
    $trajectory = Get-CodeSequenceTrajectory -States ($states.ToArray()) -Top $Top
    # EC-024: path discovery always covers the whole selected set, even when
    # EC-023 has an exact focus. It shares the validated groups and has no IO.
    $expectedFindingStatements = 0
    foreach ($item in $records) { $expectedFindingStatements += [int]$item.finding_statement_count }
    $pathIndex = Get-CodeSequencePathIndex -States ($states.ToArray()) -Top $Top `
        -ExpectedAnchorUnion $trajectory.counts.distinct_exact_anchor_union_count `
        -ExpectedAnchorTransitions $trajectory.counts.presence_transitions_across_adjacent_pairs_count `
        -ExpectedFindingStatements $expectedFindingStatements -ExpectedSteps ($steps.ToArray())
    # EC-027..028: all first-vs-later comparisons and path persistence reuse the checked selected
    # states. The complete first pair must match EC-025's adjacent totals.
    $baselineDrift = Get-CodeSequenceBaselineDrift -States ($states.ToArray()) `
        -ExpectedFirstAdjacentPathDelta $pathIndex.step_deltas[0] -Top $Top
    # EC-029: exhaustive all-pairs profile comparison reuses only the same
    # checked in-memory states, then cross-checks every adjacent and baseline
    # overlap before deriving exact profile-equivalence classes.
    $pairwiseProfile = Get-CodeSequencePairwiseProfile -States ($states.ToArray()) `
        -ExpectedAdjacentPathDeltas $pathIndex.step_deltas `
        -ExpectedBaselineComparisons $baselineDrift.comparisons -Top $Top
    # EC-046: index navigation cannot bypass the report pair overview or
    # combine with a caller literal path / another focused projection.
    if ($null -ne $PairPathIndex -and
        ($null -eq $PairOverviewIndex -or $null -ne $Path -or
            $null -ne $FindingRecordId -or $null -ne $FindingId -or
            $null -ne $AnchorIndex -or $null -ne $PairIndex -or
            $PairPathIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
            [int]$PairPathIndex -gt 480)) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_SELECTOR_INVALID: indexed path needs an exclusive pair overview.'
    }
    # EC-045: opt-in cross-path report-pair overview. It works without
    # requiring the caller to guess a path or disclosing any saved prose.
    $globalPairOverview = $null
    $selectedPairPathRow = $null
    $selectedPairPathSelection = $null
    $selectedPairPathAnchorSelection = $null
    $selectedPairPathAnchorFindingSelection = $null
    $selectedPairPathAnchorFindingCounterpartSelection = $null
    if ($null -ne $PairOverviewIndex) {
        if ($null -ne $Path -or $null -ne $FindingRecordId -or
            $null -ne $FindingId -or $null -ne $AnchorIndex -or
            $null -ne $PairIndex -or
            $PairOverviewIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$PairOverviewIndex -gt 66) {
            throw 'CODE_SHOW_SEQUENCE_PAIR_OVERVIEW_SELECTOR_INVALID: global pair overview must be exclusive.'
        }
        $globalPairOverview = Get-CodeSequenceGlobalPairOverview `
            -PairIndex ([int]$PairOverviewIndex) -States ($states.ToArray()) `
            -Pairwise $pairwiseProfile -PathIndex $pathIndex
        if ($null -ne $PairPathIndex) {
            $selectedPairPathRow = Resolve-CodeSequenceGlobalPairPath `
                -PairOverview $globalPairOverview -PathIndex ([int]$PairPathIndex)
            $Path = [string]$selectedPairPathRow.path
        }
    }
    $pathFocus = $null
    if ($null -ne $Path) {
        $pathFocus = Get-CodeSequencePathFocus -States ($states.ToArray()) -Path $Path -Top $Top
        # EC-033: unlike ranked global hotspots, an explicitly requested
        # literal saved path ALWAYS receives its complete local classes,
        # per-position statement histograms, runs and transition events.
        # The complete global profile remains unchanged by path focus.
        $pathFocus['profile_journey'] = Get-CodeSequenceFocusedPathProfileJourney `
            -States ($states.ToArray()) -Path $Path -ExistingFocus $pathFocus `
            -GlobalPathClasses $pairwiseProfile.path_profile_classes `
            -GlobalPathTransitions $pairwiseProfile.path_profile_transitions
        # EC-034: untruncated exact-anchor histories for this literal path,
        # distinct from EC-023's SequenceTop-limited trajectory previews.
        $pathFocus['anchor_journeys'] = Get-CodeSequenceFocusedAnchorJourneys `
            -States ($states.ToArray()) -Path $Path -ExistingFocus $pathFocus `
            -ExistingProfileJourney $pathFocus.profile_journey
        # EC-035: complete, ordinal 0/1 presence-pattern cohorts derived only
        # from the fully checked EC-034 anchor ledger, independent of Top.
        $pathFocus['anchor_cohorts'] = Get-CodeSequenceFocusedAnchorCohorts `
            -Journeys $pathFocus.anchor_journeys
        # EC-036: all unordered focused-path anchor comparisons, including
        # nonadjacent pairs and intermediate unreported positions. Reuses only
        # the complete and reconciled path-local journey and cohort ledgers.
        $pathFocus['anchor_pairwise'] = Get-CodeSequenceFocusedAnchorPairwise `
            -Journeys $pathFocus.anchor_journeys -Cohorts $pathFocus.anchor_cohorts `
            -ProfileJourney $pathFocus.profile_journey
        # EC-037: materialize complete navigable per-pair anchor index partitions
        # and signed saved-severity Finding-statement deltas. No extra IO.
        $pathFocus['anchor_pair_details'] = Get-CodeSequenceFocusedAnchorPairDetails `
            -Journeys $pathFocus.anchor_journeys -Pairwise $pathFocus.anchor_pairwise
        $pathFocus['anchor_pair_lookup'] = Get-CodeSequenceFocusedAnchorPairLookup `
            -Journeys $pathFocus.anchor_journeys -Pairwise $pathFocus.anchor_pairwise `
            -Details $pathFocus.anchor_pair_details
        # EC-039: exact saved (record_id, Finding ID) references in both
        # directions, joined only to already checked in-memory Finding groups.
        $pathFocus['anchor_finding_refs'] = Get-CodeSequenceFocusedAnchorFindingRefs `
            -States ($states.ToArray()) -Path $Path -Journeys $pathFocus.anchor_journeys
        # EC-040: every changed exact-anchor pair directly names the two
        # original record-scoped Finding ID sets, without matching Findings
        # or introducing an additional read, selector, writer or Top cap.
        $pathFocus['anchor_pair_finding_refs'] = Get-CodeSequenceFocusedAnchorPairFindingRefs `
            -Journeys $pathFocus.anchor_journeys `
            -Details $pathFocus.anchor_pair_details `
            -References $pathFocus.anchor_finding_refs
        # EC-041: invert complete saved pair classes back to EVERY original
        # record-scoped Finding ID, including retained same-histogram anchors.
        # No new selection, reads, writes, or cross-record Finding matching.
        $pathFocus['finding_pair_lookup'] = Get-CodeSequenceFocusedFindingPairLookup `
            -Journeys $pathFocus.anchor_journeys `
            -Details $pathFocus.anchor_pair_details `
            -References $pathFocus.anchor_finding_refs `
            -PairReferences $pathFocus.anchor_pair_finding_refs
    }

    # EC-042: one explicitly chosen original (record ID, Finding ID)
    # receives its complete direct quote-anchor journey and saved counterpart
    # references. The other path/global views are unchanged. No new I/O.
    if ($null -ne $FindingRecordId -or $null -ne $FindingId) {
        if ($null -eq $Path -or $null -eq $FindingRecordId -or $null -eq $FindingId -or
            -not ($RecordIds -ccontains $FindingRecordId)) {
            throw 'CODE_SHOW_SEQUENCE_FINDING_RECORD_NOT_SELECTED: selected original record and literal path are required.'
        }
        $pathFocus['selected_finding'] = Get-CodeSequenceFocusedSelectedFinding `
            -SeedRecordId $FindingRecordId -SeedFindingId $FindingId `
            -Journeys $pathFocus.anchor_journeys -Details $pathFocus.anchor_pair_details `
            -References $pathFocus.anchor_finding_refs `
            -PairReferences $pathFocus.anchor_pair_finding_refs `
            -FindingPairs $pathFocus.finding_pair_lookup
    }

    # EC-043: one explicit 1-based canonical quote-anchor index resolves
    # to all N report positions and all N*(N-1)/2 pairs, including the
    # both-unreported class omitted from original Finding seed navigation.
    # This remains an opt-in, read-only, Top-invariant in-memory projection.
    if ($null -ne $AnchorIndex) {
        if ($null -eq $Path -or $null -ne $FindingRecordId -or $null -ne $FindingId -or
            $AnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or [int]$AnchorIndex -gt 480) {
            throw 'CODE_SHOW_SEQUENCE_ANCHOR_SELECTOR_INVALID: a path and exclusive 1..480 anchor index are required.'
        }
        $pathFocus['selected_anchor'] = Get-CodeSequenceFocusedSelectedAnchor `
            -AnchorIndex ([int]$AnchorIndex) -Journeys $pathFocus.anchor_journeys `
            -Details $pathFocus.anchor_pair_details -Lookup $pathFocus.anchor_pair_lookup `
            -References $pathFocus.anchor_finding_refs `
            -PairReferences $pathFocus.anchor_pair_finding_refs
    }

    # EC-046 reuses the exact EC-044 path-and-pair projection after resolving
    # its literal path from the complete EC-045 ordinal path union.
    $effectivePairIndex = if ($null -ne $PairPathIndex) { $PairOverviewIndex } else { $PairIndex }
    # EC-044: one canonical unordered caller-position report pair directly
    # exposes ALL focused exact quote anchors and both original Finding sets,
    # including unchanged histograms and both-unreported anchor rows.
    if ($null -ne $effectivePairIndex) {
        if ($null -eq $Path -or $null -ne $FindingRecordId -or $null -ne $FindingId -or
            $null -ne $AnchorIndex -or $effectivePairIndex -cnotmatch '^[1-9][0-9]?$' -or
            [int]$effectivePairIndex -gt 66) {
            throw 'CODE_SHOW_SEQUENCE_PAIR_SELECTOR_INVALID: path and exclusive 1..66 report pair index required.'
        }
        $pathFocus['selected_pair'] = Get-CodeSequenceFocusedSelectedPair `
            -PairIndex ([int]$effectivePairIndex) -Journeys $pathFocus.anchor_journeys `
            -Details $pathFocus.anchor_pair_details -Lookup $pathFocus.anchor_pair_lookup `
            -References $pathFocus.anchor_finding_refs `
            -PairReferences $pathFocus.anchor_pair_finding_refs
    }
    if ($null -ne $PairPathIndex) {
        $selectedPairPathSelection = Get-CodeSequenceGlobalPairPathSelection `
            -PairOverview $globalPairOverview -SelectedPathRow $selectedPairPathRow `
            -SelectedPair $pathFocus.selected_pair -PathIndex ([int]$PairPathIndex)
    }

    # EC-047: third ordinal targets ONE exact anchor in the same complete
    # path-local all-N union used by EC-043/044. Reuse the existing detailed
    # all-positions/all-pairs anchor projection and join it with the full
    # EC-046 original-Finding-preserving two-sided pair/path row.
    if ($null -ne $PairPathAnchorIndex) {
        if ([int]$PairPathAnchorIndex -gt $pathFocus.selected_pair.anchors.Count) {
            throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_NOT_FOUND: anchor index is outside this indexed path.'
        }
        $pathFocus['selected_anchor'] = Get-CodeSequenceFocusedSelectedAnchor `
            -AnchorIndex ([int]$PairPathAnchorIndex) -Journeys $pathFocus.anchor_journeys `
            -Details $pathFocus.anchor_pair_details -Lookup $pathFocus.anchor_pair_lookup `
            -References $pathFocus.anchor_finding_refs `
            -PairReferences $pathFocus.anchor_pair_finding_refs
        $selectedPairPathAnchorSelection = Get-CodeSequenceGlobalPairPathAnchorSelection `
            -PairOverview $globalPairOverview -PathSelection $selectedPairPathSelection `
            -SelectedPair $pathFocus.selected_pair -SelectedAnchor $pathFocus.selected_anchor `
            -AnchorIndex ([int]$PairPathAnchorIndex)

        # EC-048: select the original Finding by endpoint and bounded ordinal,
        # then REUSE the independently checked EC-042 full N-position
        # original-ID journey. No inferred cross-report ID matching.
        if ($null -ne $PairPathAnchorFindingIndex) {
            $endpoint = $selectedPairPathAnchorSelection[$PairPathAnchorFindingSide]
            if ([int]$PairPathAnchorFindingIndex -gt $endpoint.original_record_scoped_finding_refs.Count) {
                throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_NOT_FOUND: no original Finding has that index at this endpoint anchor.'
            }
            $originalRef = $endpoint.original_record_scoped_finding_refs[[int]$PairPathAnchorFindingIndex - 1]
            $pathFocus['selected_finding'] = Get-CodeSequenceFocusedSelectedFinding `
                -SeedRecordId ([string]$endpoint.record_id) -SeedFindingId ([string]$originalRef.finding_id) `
                -Journeys $pathFocus.anchor_journeys -Details $pathFocus.anchor_pair_details `
                -References $pathFocus.anchor_finding_refs `
                -PairReferences $pathFocus.anchor_pair_finding_refs `
                -FindingPairs $pathFocus.finding_pair_lookup
            $selectedPairPathAnchorFindingSelection = Get-CodeSequenceGlobalPairPathAnchorFindingSelection `
                -AnchorSelection $selectedPairPathAnchorSelection -SelectedAnchor $pathFocus.selected_anchor `
                -SelectedFinding $pathFocus.selected_finding -FindingSide $PairPathAnchorFindingSide `
                -FindingIndex ([int]$PairPathAnchorFindingIndex)

            # EC-049: choose an independent ORIGINAL saved Finding on the
            # opposing endpoint; retain both unmodified EC-042 full journeys.
            # A missing opposite anchor/ordinal is NOT_FOUND, not a synthetic
            # correspondence. Reuse the same in-memory complete projections.
            if ($null -ne $PairPathAnchorFindingCounterpartIndex) {
                $counterpartSide = if ($PairPathAnchorFindingSide -ceq 'left') { 'right' } else { 'left' }
                $otherEndpoint = $selectedPairPathAnchorSelection[$counterpartSide]
                if ([int]$PairPathAnchorFindingCounterpartIndex -gt
                    $otherEndpoint.original_record_scoped_finding_refs.Count) {
                    throw 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_NOT_FOUND: opposite endpoint has no original Finding at that ordinal.'
                }
                $otherRef = $otherEndpoint.original_record_scoped_finding_refs[[int]$PairPathAnchorFindingCounterpartIndex - 1]
                $pathFocus['selected_counterpart_finding'] = Get-CodeSequenceFocusedSelectedFinding `
                    -SeedRecordId ([string]$otherEndpoint.record_id) -SeedFindingId ([string]$otherRef.finding_id) `
                    -Journeys $pathFocus.anchor_journeys -Details $pathFocus.anchor_pair_details `
                    -References $pathFocus.anchor_finding_refs `
                    -PairReferences $pathFocus.anchor_pair_finding_refs `
                    -FindingPairs $pathFocus.finding_pair_lookup
                $selectedPairPathAnchorFindingCounterpartSelection = Get-CodeSequenceGlobalPairPathAnchorFindingCounterpartSelection `
                    -AnchorSelection $selectedPairPathAnchorSelection `
                    -OriginalSelection $selectedPairPathAnchorFindingSelection `
                    -OriginalJourney $pathFocus.selected_finding `
                    -CounterpartJourney $pathFocus.selected_counterpart_finding `
                    -SelectedAnchor $pathFocus.selected_anchor `
                    -CounterpartIndex ([int]$PairPathAnchorFindingCounterpartIndex)
                # EC-050: add an exhaustive, five-bin SAVED REPORT PROFILE
                # cohort comparison only after both EC-042 journeys and the
                # fifth-level original endpoint pair have reconciled.
                $pathFocus['selected_original_finding_pair_profile_cohorts'] = `
                    Get-CodeSequenceOriginalFindingPairProfileCohorts `
                        -AnchorSelection $selectedPairPathAnchorSelection `
                        -CounterpartSelection $selectedPairPathAnchorFindingCounterpartSelection `
                        -SelectedAnchor $pathFocus.selected_anchor `
                        -OriginalJourney $pathFocus.selected_finding `
                        -CounterpartJourney $pathFocus.selected_counterpart_finding
                # EC-051: refine the verified five endpoint cohorts into
                # exact N-position histogram classes, all-pair-checked
                # adjacent transitions, runs and profile returns. There is
                # no new selector or independent saved-record/source read.
                $pathFocus['selected_original_finding_pair_profile_atlas'] = `
                    Get-CodeSequenceOriginalFindingPairProfileAtlas `
                        -Cohorts $pathFocus.selected_original_finding_pair_profile_cohorts `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-052: group ALL checked adjacent profile-class edges by
                # ordered class endpoints and expose complete prior-run
                # return walks, including their direct EC-043 pair witness.
                $pathFocus['selected_original_finding_pair_profile_transition_graph'] = `
                    Get-CodeSequenceOriginalFindingPairProfileTransitionGraph `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-053: partition ALL EC-043 caller-forward position pairs
                # into ordered class-passage groups. Shortest and longest
                # witnesses must each be a REAL contiguous selected span.
                $pathFocus['selected_original_finding_pair_profile_passages'] = `
                    Get-CodeSequenceOriginalFindingPairProfilePassages `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Graph $pathFocus.selected_original_finding_pair_profile_transition_graph `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-054: exhaustive ACTUAL contiguous whole-class-walk motifs
                # and exact repeat-overlap / maximum disjoint witnesses.
                # No invented graph route, sixth selector, or extra read.
                $pathFocus['selected_original_finding_pair_profile_motifs'] = `
                    Get-CodeSequenceOriginalFindingPairProfileMotifs `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Graph $pathFocus.selected_original_finding_pair_profile_transition_graph `
                        -Passages $pathFocus.selected_original_finding_pair_profile_passages `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-055: maximally extend only REAL equal-class repeat-pair
                # windows; enumerate ALL disjoint-limited maximal choices
                # separately so overlap does not erase independent evidence.
                $pathFocus['selected_original_finding_pair_profile_maximal_repeats'] = `
                    Get-CodeSequenceOriginalFindingPairProfileMaximalRepeats `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Graph $pathFocus.selected_original_finding_pair_profile_transition_graph `
                        -Motifs $pathFocus.selected_original_finding_pair_profile_motifs `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-056: lift every real pairwise maximal match to its
                # COMPLETE observed motif support, and retain ALL optimal
                # strictly nonoverlapping occurrence packs and coverage.
                $pathFocus['selected_original_finding_pair_profile_repeat_families'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRepeatFamilies `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Graph $pathFocus.selected_original_finding_pair_profile_transition_graph `
                        -Motifs $pathFocus.selected_original_finding_pair_profile_motifs `
                        -Maximal $pathFocus.selected_original_finding_pair_profile_maximal_repeats `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-057: a family's own independence is NOT proof that two
                # distinct families can use four mutually disjoint ORIGINAL
                # report intervals together. Count real joint witnesses and
                # test compatibility of both families' own local optima.
                $pathFocus['selected_original_finding_pair_profile_joint_support'] = `
                    Get-CodeSequenceOriginalFindingPairProfileJointSupport `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Motifs $pathFocus.selected_original_finding_pair_profile_motifs `
                        -Families $pathFocus.selected_original_finding_pair_profile_repeat_families `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-058: pairwise compatibility is necessary but NOT enough
                # for genuine 2+2+2 mutual support of three distinct real
                # repeat families. Reconcile every EC-057 pair before
                # enumerating six disjoint original EC-043 window witnesses.
                $pathFocus['selected_original_finding_pair_profile_triple_support'] = `
                    Get-CodeSequenceOriginalFindingPairProfileTripleSupport `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Motifs $pathFocus.selected_original_finding_pair_profile_motifs `
                        -Families $pathFocus.selected_original_finding_pair_profile_repeat_families `
                        -Joint $pathFocus.selected_original_finding_pair_profile_joint_support `
                        -SelectedAnchor $pathFocus.selected_anchor
                # EC-059: sensitivity to withholding EACH ORIGINAL caller position.
                # Discard existing windows crossing the withheld position,
                # NEVER stitch a new one or re-optimize original EC-056 maxima.
                $withholdingWitnessIndex = $null
                $pathFocus['selected_original_finding_pair_profile_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfilePositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Motifs $pathFocus.selected_original_finding_pair_profile_motifs `
                        -Families $pathFocus.selected_original_finding_pair_profile_repeat_families `
                        -Joint $pathFocus.selected_original_finding_pair_profile_joint_support `
                        -Triple $pathFocus.selected_original_finding_pair_profile_triple_support `
                        -SelectedAnchor $pathFocus.selected_anchor `
                        -WitnessMasksOut ([ref]$withholdingWitnessIndex)
                # EC-060: ALL unordered pairs of ORIGINAL position exclusions.
                # Use only the PRIVATE EC-059-conserved witness masks; never
                # reconstruct a shortened sequence or read records again.
                $privatePairWitnessAggregates = $null
                $pathFocus['selected_original_finding_pair_profile_pair_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfilePairPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -Triple $pathFocus.selected_original_finding_pair_profile_triple_support `
                        -Withholding $pathFocus.selected_original_finding_pair_profile_position_withholding `
                        -WitnessIndex $withholdingWitnessIndex `
                        -WitnessAggregatesOut ([ref]$privatePairWitnessAggregates)
                # EC-061: every original position TRIPLE, checking the full
                # EC-060 public pair projections before producing any new
                # projection from the private original witness histograms.
                $pathFocus['selected_original_finding_pair_profile_triple_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileTriplePositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-062: every original position QUARTET, only after the
                # entire EC-061 triple view and its original evidence checks.
                # Compare all preceding triple projections before extending
                # the unchanged private full-selection masks to 4-way loss.
                $pathFocus['selected_original_finding_pair_profile_quartet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileQuartetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-063: exhaustively exclude FIVE ORIGINAL positions,
                # only after EC-062 has checked all four-position evidence.
                # Exact five-way intersections use ONLY the preexisting
                # private full-selection masks; never stitch new windows.
                $pathFocus['selected_original_finding_pair_profile_quintet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileQuintetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-064: ALL SIX ORIGINAL report-position exclusions.
                # Recheck the FULL EC-063 parent output before reusing the
                # original, frozen private masks. Never splice newly adjacent
                # report positions or recompute an EC-056 optimum.
                $pathFocus['selected_original_finding_pair_profile_sextet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileSextetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-065: enumerate every SEVEN-position original exclusion
                # after reconstituting the full EC-064 sextet parent. All
                # evidence is the same original in-memory EC-060 mask ledger.
                $pathFocus['selected_original_finding_pair_profile_septet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileSeptetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-066: every EIGHT-position original exclusion, after
                # replaying all EC-065 septet evidence and ancestors. Original
                # masks/record positions are never regenerated or resequenced.
                $pathFocus['selected_original_finding_pair_profile_octet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileOctetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -SeptetWithholding $pathFocus.selected_original_finding_pair_profile_septet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-067: exhaustive ORIGINAL NINE-position exclusions.
                # Reconcile all EC-066 octet and earlier parent evidence;
                # remaining <=3 original positions cannot form two disjoint
                # true observed length-two windows. No new saved body access.
                $pathFocus['selected_original_finding_pair_profile_nonet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileNonetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -SeptetWithholding $pathFocus.selected_original_finding_pair_profile_septet_position_withholding `
                        -OctetWithholding $pathFocus.selected_original_finding_pair_profile_octet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-068: EVERY TEN original report-position exclusions, with
                # complete EC-067 nonet replay, exact tenth-order weighted
                # intersections and all nine original ancestor incidence levels.
                # No new user selector, saved-record reads or source mutation.
                $pathFocus['selected_original_finding_pair_profile_decet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileDecetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -SeptetWithholding $pathFocus.selected_original_finding_pair_profile_septet_position_withholding `
                        -OctetWithholding $pathFocus.selected_original_finding_pair_profile_octet_position_withholding `
                        -NonetWithholding $pathFocus.selected_original_finding_pair_profile_nonet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-069: EVERY ELEVEN original caller-position exclusions,
                # exact eleventh-order original-mask evidence and ALL ten
                # ancestor incidence levels. Replays complete EC-068 decet.
                # No selector, saved-record read or analyzed-source write.
                $pathFocus['selected_original_finding_pair_profile_undecet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileUndecetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -SeptetWithholding $pathFocus.selected_original_finding_pair_profile_septet_position_withholding `
                        -OctetWithholding $pathFocus.selected_original_finding_pair_profile_octet_position_withholding `
                        -NonetWithholding $pathFocus.selected_original_finding_pair_profile_nonet_position_withholding `
                        -DecetWithholding $pathFocus.selected_original_finding_pair_profile_decet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-070: complete TWELVE original report-position withholding.
                # At bounded N<=12 there is one whole-set exclusion only at N=12.
                # Replay the entire EC-069 parent before checking each actual
                # 12-way private weighted mask intersection and 11 ancestry levels.
                # No new selector, original record read or business source edit.
                $pathFocus['selected_original_finding_pair_profile_duodecet_position_withholding'] = `
                    Get-CodeSequenceOriginalFindingPairProfileDuodecetPositionWithholding `
                        -Atlas $pathFocus.selected_original_finding_pair_profile_atlas `
                        -PairWithholding $pathFocus.selected_original_finding_pair_profile_pair_position_withholding `
                        -TripleWithholding $pathFocus.selected_original_finding_pair_profile_triple_position_withholding `
                        -QuartetWithholding $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding `
                        -QuintetWithholding $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding `
                        -SextetWithholding $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding `
                        -SeptetWithholding $pathFocus.selected_original_finding_pair_profile_septet_position_withholding `
                        -OctetWithholding $pathFocus.selected_original_finding_pair_profile_octet_position_withholding `
                        -NonetWithholding $pathFocus.selected_original_finding_pair_profile_nonet_position_withholding `
                        -DecetWithholding $pathFocus.selected_original_finding_pair_profile_decet_position_withholding `
                        -UndecetWithholding $pathFocus.selected_original_finding_pair_profile_undecet_position_withholding `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-071: project the COMPLETE 0..N original withholding cube
                # and derive inclusion-minimal loss/extinction frontiers. One
                # evidence-backed subset-zeta projection across the EC-060
                # PRIVATE histograms independently checks EVERY EC-059..070 row.
                # No new selector, quote read, reordering, or source write.
                $originalWithholdingLayers = [object[]]@(
                    $pathFocus.selected_original_finding_pair_profile_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_pair_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_triple_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_quartet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_quintet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_sextet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_septet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_octet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_nonet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_decet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_undecet_position_withholding,
                    $pathFocus.selected_original_finding_pair_profile_duodecet_position_withholding
                )
                $pathFocus['selected_original_finding_pair_profile_resilience_frontier'] = `
                    Get-CodeSequenceOriginalFindingPairProfileResilienceFrontier `
                        -Layers $originalWithholdingLayers -WitnessAggregates $privatePairWitnessAggregates
                # EC-072: dualize every validated original loss frontier into
                # inclusion-minimal RETAINED witness bases. For every critical
                # excluded position, emit a concrete smallest-numbered ORIGINAL
                # basis re-enabled by restoring exactly that one position.
                # Only existing private histograms and EC-071 are consumed.
                $pathFocus['selected_original_finding_pair_profile_support_basis_duality'] = `
                    Get-CodeSequenceOriginalFindingPairProfileSupportBasisDuality `
                        -ResilienceFrontier $pathFocus.selected_original_finding_pair_profile_resilience_frontier `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-073: every retained-budget evidence-coverage count and
                # every directed one-original-position pivotal addition edge.
                # Reconcile REAL EC-060 mask support with EC-072 minimal bases
                # and exact Boolean-cube edge identities. No new selector/I/O.
                $pathFocus['selected_original_finding_pair_profile_retention_pivotality'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPivotality `
                        -ResilienceFrontier $pathFocus.selected_original_finding_pair_profile_resilience_frontier `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -WitnessAggregates $privatePairWitnessAggregates
                # EC-074: count every hypothetical permutation of ORIGINAL
                # reports exactly by its FIRST saved-evidence restoration step
                # and the original position that crossed the support boundary.
                # Each verified EC-073 edge contributes k!*(N-k-1)! orderings;
                # independent cumulative retained-budget evidence counts must
                # reconcile. No resequencing of private saved witnesses or I/O.
                $pathFocus['selected_original_finding_pair_profile_retention_order_attribution'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionOrderAttribution `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality
                # EC-075: condition the SAME complete hypothetical original
                # ordering universe on an exact original report at rank j.
                # Reconstruct independent support from verified EC-072 minimal
                # bases and reconcile all before/by/after/never partitions
                # against real EC-073 edges and EC-074 permutation margins.
                # No new selector, original witness read, I/O or reindexing.
                $pathFocus['selected_original_finding_pair_profile_retention_rank_conditioning'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionRankConditioning `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution
                # EC-076: condition all N! hypothetical permutations on
                # an ordered pair of DISTINCT ORIGINAL identities p before q.
                # Reconstruct original supported masks from checked EC-072
                # bases; compare 6-way pair precedences with EC-073 support,
                # EC-075 fixed-rank margins and EC-074 step totals. No new
                # saved evidence, selector, record reads or business writes.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_precedence'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairPrecedence `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning
                # EC-077: refine the same successful fifth-level ORIGINAL
                # pair to every directed IMMEDIATE adjacency p followed by q.
                # Five exact first-evidence states across (N-1)! original
                # full orderings; independently conserve EC-072/073 original
                # support, EC-075 fixed-rank margins, EC-074 first steps and
                # original EC-076 precedence subsets. No new selector or I/O.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_adjacency'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairAdjacency `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence
                # EC-078: condition p and q on having EXACTLY ONE intervening
                # ORIGINAL report r (p,r,q), independently of which r it is.
                # Exact six-state first-support attribution, with original r
                # bit contributions and independent EC-072/073/074/075/076/077
                # conservations. N2 has no such cases. No new selector or I/O.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_single_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairSingleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency
                # EC-079: constrain p/q to an original four-position block
                # p,r,s,q with exactly TWO separately identified middle
                # reports. Compute seven first-support stages using original
                # subset support frontiers and exact factorial weights,
                # reconciling EC-072..078 without reading new evidence.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_double_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairDoubleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening
                # EC-080: p,r,s,t,q is a hypothetical five-position block
                # with exactly THREE independent ORIGINAL intervening
                # identities. Eight first-support stages, three identity
                # ledgers and EC-072..079 exact conservation; no new
                # selector, evidence read, chronological assertion or write.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_triple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairTripleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening
                # EC-081: p,r,s,t,u,q has FOUR ordered, distinct ORIGINAL
                # intervening identities. Read-only nine-stage FIRST support,
                # four identity ledgers, and EC-072..080 full conservation.
                # No new selector, source read, risk claim or write.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_quadruple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairQuadrupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening
                # EC-082: read-only seven-report p,r,s,t,u,v,q hypothetical
                # blocks with five distinct ORIGINAL middle identities.
                # Ten FIRST evidence stages; checked EC-072..081 parents.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_quintuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairQuintupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening
                # EC-083: eight-report p,r,s,t,u,v,w,q blocks, six distinct
                # ORIGINAL intermediaries, eleven exclusive FIRST stages,
                # and independent checked EC-072..082 provenance ledgers.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_sextuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairSextupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening
                # EC-084: nine-report hypothetical p,r,s,t,u,v,w,z,q block,
                # SEVEN distinct ORIGINAL intermediaries, twelve FIRST stages.
                # Derive only from reconciled EC-072..083 public parents;
                # preserve fifth-level selection, original bits and read-only IO.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_septuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairSeptupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening `
                        -RetentionPairSextupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_sextuple_intervening
                # EC-085: ten-report hypothetical p,r,s,t,u,v,w,x,y,q,
                # eight distinct ordered ORIGINAL middle identities and 13
                # exclusive FIRST saved-support categories. Reuse checked
                # EC-072..084 parents without a new selector or source read.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_octuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairOctupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening `
                        -RetentionPairSextupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_sextuple_intervening `
                        -RetentionPairSeptupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_septuple_intervening
                # EC-086: eleven-report hypothetical p,r,s,t,u,v,w,x,y,z,q,
                # exactly NINE distinct ordered ORIGINAL intermediaries.
                # Preserve the successful EC-049 selector, parent evidence,
                # original identities and exclusively read-only projections.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_nonuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairNonupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening `
                        -RetentionPairSextupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_sextuple_intervening `
                        -RetentionPairSeptupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_septuple_intervening `
                        -RetentionPairOctupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_octuple_intervening
                # EC-087: N12's complete p,r,s,t,u,v,w,x,y,z,a,q original order,
                # with TEN distinct ordered middle identities and 15 exclusive
                # first-support stages. Only the existing successful EC-049
                # fifth-level selector gains this final, read-only gap projection.
                # Reconcile all 0..10 original distances to EC-076 precedence;
                # read neither source/saved bodies nor external Git/network.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_decuple_intervening'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairDecupleIntervening `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -SupportBasisDuality $pathFocus.selected_original_finding_pair_profile_support_basis_duality `
                        -RetentionOrderAttribution $pathFocus.selected_original_finding_pair_profile_retention_order_attribution `
                        -RetentionRankConditioning $pathFocus.selected_original_finding_pair_profile_retention_rank_conditioning `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening `
                        -RetentionPairSextupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_sextuple_intervening `
                        -RetentionPairSeptupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_septuple_intervening `
                        -RetentionPairOctupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_octuple_intervening `
                        -RetentionPairNonupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_nonuple_intervening
                # EC-088: materialize all exact ORIGINAL p-before-q report gap
                # distances 0..N-2, using only checked EC-076..087 results.
                # Preserve fifth-level selector success, original bits and
                # source/privacy boundary; no additional saved-record access.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_distance_spectrum'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairDistanceSpectrum `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairAdjacency $pathFocus.selected_original_finding_pair_profile_retention_pair_adjacency `
                        -RetentionPairSingleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_single_intervening `
                        -RetentionPairDoubleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_double_intervening `
                        -RetentionPairTripleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_triple_intervening `
                        -RetentionPairQuadrupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening `
                        -RetentionPairQuintupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening `
                        -RetentionPairSextupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_sextuple_intervening `
                        -RetentionPairSeptupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_septuple_intervening `
                        -RetentionPairOctupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_octuple_intervening `
                        -RetentionPairNonupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_nonuple_intervening `
                        -RetentionPairDecupleIntervening $pathFocus.selected_original_finding_pair_profile_retention_pair_decuple_intervening
                # EC-089: merge both disjoint directions of each ORIGINAL
                # unordered report pair at every checked EC-088 distance.
                # Retain exact original caller identities, signed direction
                # contrast and within-interval first-restorer attribution.
                $pathFocus['selected_original_finding_pair_profile_retention_pair_reciprocity'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionPairReciprocity `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionPairPrecedence $pathFocus.selected_original_finding_pair_profile_retention_pair_precedence `
                        -RetentionPairDistanceSpectrum $pathFocus.selected_original_finding_pair_profile_retention_pair_distance_spectrum
                # EC-090: project per-ORIGINAL-reporter hypothetical role exposure
                # and first-restorer counts, from checked EC-089 pair/gap identity
                # ledgers. Outside-pair restoration remains identity-unattributed.
                $pathFocus['selected_original_finding_pair_profile_retention_reporter_role_exposure'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionReporterRoleExposure `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionPairReciprocity $pathFocus.selected_original_finding_pair_profile_retention_pair_reciprocity
                # EC-091: fold genuine ORIGINAL endpoint identity with the
                # specific other report in each pair, preserving separately
                # exact r-before-partner / r-after-partner FIRST denominators.
                # Reconcile all partner cells against checked EC-090 roles.
                $pathFocus['selected_original_finding_pair_profile_retention_reporter_partner_matrix'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionReporterPartner `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionPairReciprocity $pathFocus.selected_original_finding_pair_profile_retention_pair_reciprocity `
                        -RetentionReporterRoleExposure $pathFocus.selected_original_finding_pair_profile_retention_reporter_role_exposure
                # EC-092: construct the unordered ORIGINAL endpoint-FIRST
                # comparison graph from both checked original subject views.
                # In each direction, explicitly retain the neither-endpoint
                # remainder; a conditional FIRST share is null if absent.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_credit_graph'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointCreditGraph `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionPairReciprocity $pathFocus.selected_original_finding_pair_profile_retention_pair_reciprocity `
                        -RetentionReporterPartner $pathFocus.selected_original_finding_pair_profile_retention_reporter_partner_matrix
                # EC-093: strict ORIGINAL endpoint-FIRST credit advantage arcs,
                # neutral equal pairs, directed cycles/SCCs and longest-path
                # condensation layers from EC-092 only. No tie is a strict path
                # and no layer is a chronological or priority ranking.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_topology'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDominanceTopology `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointCreditGraph $pathFocus.selected_original_finding_pair_profile_retention_endpoint_credit_graph
                # EC-094: keep precisely the necessary strict SCC links and
                # certify each redundant direct link with a shortest, lexical
                # path through retained links and actual EC-089 pair indices.
                # Equality/0-FIRST never become proof edges or real chronology.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_dominance_reduction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDominanceReduction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology
                # EC-095: single direct-SCC-link deletion on the FULL original
                # DAG, versus deletion from EC-094's retained-only DAG. All
                # lost reachable component pairs keep exact ORIGINAL reporter
                # multiplicity; redundant shortcuts are not discarded in the
                # full-graph scenario. Never infer empirical risk or priority.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_link_impact'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointLinkImpact `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction
                # EC-096: delete each pair of DISTINCT complete ORIGINAL SCC
                # direct links from the FULL graph (retain every other original
                # shortcut). Account for overlapping singleton loss and list
                # only additional reachability lost under joint deletion.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_pair_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointPairInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact
                # EC-097: exact strictly THIRD-order FULL SCC direct-link
                # reachability loss: combine all original EC-095 singleton and
                # EC-096 two-link FULL losses without double-counting, then
                # expose only paths lost after THREE distinct whole links.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_triple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTripleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction
                # EC-098: exact FOURTH-order FULL original condensed SCC-link
                # removal. Use small directed SCC vertex cuts to account for
                # all C(E,4) scenarios without 720,720 graph closures.
                # Parent EC-097 is regenerated and compared before use.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuadrupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction
                # EC-099: classify ALL five-whole-link deletions on the FULL
                # original condensed SCC DAG by directed edge-cut supersets.
                # Rebuild the complete EC-098 public projection first, then
                # preserve earlier-order loss tiers and disclose only genuine
                # strictly fifth-order reachability losses as bounded rows.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction
                # EC-100: classify ALL six-whole-original-SCC-link deletions
                # on the FULL condensation by bounded outgoing cuts. Authenticate
                # the ENTIRE EC-099 projection (and its earlier evidence chain)
                # before emitting the six disjoint lost-reachability tiers.
                # Only genuine strictly sixth-only cuts expand to sparse rows.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSextupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction
                # EC-101: exact SEVENTH-order FULL original SCC-link deletion.
                # Count all C(E,7) cases via memoized monotone minimal-cut DNF
                # cardinality, not a 778M-scenario scan/bitset. Rebuild the
                # complete EC-100 parent first; expand only strict seventh-only
                # seven-edge outgoing cuts as bounded sparse rows.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_septuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction
                # EC-102: exact EIGHTH-order FULL original SCC-link deletion.
                # Count all C(E,8) scenarios by exact memoized outgoing-cut
                # DNF cardinality, not a 5.74B-case scan or 685MiB bitmap.
                # Authenticate the entire EC-101 parent before deriving eight
                # minimum-cut tiers; expand only genuine strict eight-edge cuts.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_octuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction
                # EC-103: exact NINTH-order FULL original SCC reachability.
                # Authenticate the complete EC-102 parent before counting every
                # C(E,9) nine-link deletion with canonical memoized cut DNFs.
                # Only strict ninth-only-positive complete ORIGINAL nine-edge
                # outgoing directed cuts expand to bounded sparse rows.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointNonupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction
                # EC-104: tenth-order reachability from ten WHOLE original
                # FULL SCC direct-link deletions, exact C(E,10) cut-DNF count.
                # Authenticate the COMPLETE EC-103 public ninth-order parent;
                # preserve all original shortcuts not actually deleted and
                # expand only genuine ten-edge positive outgoing cut scenarios.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_decuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction
                # EC-105: exact ELEVENTH-order original FULL SCC direct-link
                # losses across all C(E,11) simultaneous eleven whole-link
                # deletions. Rebuild and whole-JSON-compare the complete EC-104
                # ten-link parent first; keep genuine shortcuts, original
                # caller bits and all prior target/selection semantics intact.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUndecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction
                # EC-106: exact TWELFTH-order loss across C(E,12) sets of
                # twelve distinct WHOLE ORIGINAL FULL SCC links. Regenerate and
                # whole-JSON-compare EC-105's entire eleven-link parent; retain
                # the original selector/caller/seed/Top and all real targets.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuodecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction
                # EC-107: one append-only ORIGINAL child, thirteen genuine FULL
                # direct-SCC edges removed simultaneously. Recompute and fully
                # authenticate the complete EC-106 twelfth-order parent.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTredecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction
                # EC-108: one append-only ORIGINAL child, fourteen genuine FULL
                # direct-SCC edges removed simultaneously. Recompute and fully
                # authenticate the complete EC-107 thirteenth-order parent.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuordecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction
                # EC-109: exact fifteenth-only ORIGINAL FULL SCC directed-link
                # deletion incidence by minimal outgoing cuts and memoized
                # cardinality-fifteen DNF. Recompute and completely authenticate
                # EC-108's fourteen-link parent before adding this child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuindecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction
                # EC-110: cardinality-sixteen strict original FULL SCC directed-cut
                # loss, with whole-value re-derivation of the EC-109 parent first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSexdecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction
                # EC-111: exact-cardinality seventeen original FULL SCC outgoing-cut
                # loss, after complete deterministic EC-110 parent regeneration.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptendecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction
                # EC-112: exact-cardinality eighteen WHOLE original FULL SCC
                # outgoing-cut loss. Regenerate and compare the entire EC-111
                # seventeenth-order parent (including real positive sparse rows)
                # before computing the eighteenth tier.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctodecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction
                # EC-113: exact nineteen distinct ORIGINAL FULL SCC link cuts;
                # regenerate and whole-JSON-authenticate the complete EC-112
                # eighteenth-order source before producing the new child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointNovemdecupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction
                # EC-114: exact twenty distinct ORIGINAL FULL SCC link cuts;
                # regenerate and whole-JSON-authenticate the complete EC-113
                # nineteenth-order source before producing the new child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointVigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction
                # EC-115: cardinality-21 complete ORIGINAL FULL SCC direct
                # link deletion. Re-derive and whole-JSON-verify the authentic
                # EC-114 twenty-link parent before any twenty-first counts.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUnvigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction
                # EC-116: cardinality-22 complete ORIGINAL FULL SCC direct
                # link deletion. Re-derive and whole-JSON-verify the authentic
                # EC-115 twenty-one-link parent before twenty-second counts.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuovigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction
                # EC-117: cardinality-23 WHOLE ORIGINAL FULL SCC link removal,
                # full rederivation and whole-public-JSON authentication of EC-116.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTrevigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction
                # EC-118: exactly 24 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-117 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuorvigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction
                # EC-119: exactly 25 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-118 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquevigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction
                # EC-120: exactly 26 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-119 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSexvigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction
                # EC-121: exactly 27 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-120 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptemvigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction
                # EC-122: exactly 28 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-121 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctovigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction
                # EC-123: exactly 29 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-122 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointNovemvigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction
                # EC-124: exactly 30 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-123 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction
                # EC-125: exactly 31 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-124 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUntrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction
                # EC-126: exactly 32 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-125 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuotrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction
                # EC-127: exactly 33 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-126 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_tretrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTretrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction `
                        -RetentionEndpointDuotrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction
                # EC-128: exactly 34 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-127 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuortrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuortrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction `
                        -RetentionEndpointDuotrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction `
                        -RetentionEndpointTretrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tretrigintuple_interaction
                # EC-129: exactly 35 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-128 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quinquetrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquetrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction `
                        -RetentionEndpointDuotrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction `
                        -RetentionEndpointTretrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tretrigintuple_interaction `
                        -RetentionEndpointQuattuortrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuortrigintuple_interaction
                # EC-130: exactly 36 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-129 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sextrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSextrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction `
                        -RetentionEndpointDuotrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction `
                        -RetentionEndpointTretrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tretrigintuple_interaction `
                        -RetentionEndpointQuattuortrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuortrigintuple_interaction `
                        -RetentionEndpointQuinquetrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquetrigintuple_interaction
                # EC-131: exactly 37 real WHOLE ORIGINAL FULL SCC direct-link
                # deletions; rederive and whole-JSON-authenticate EC-130 first.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_septemtrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptemtrigintupleInteraction `
                        -RetentionPivotality $pathFocus.selected_original_finding_pair_profile_retention_pivotality `
                        -RetentionEndpointDominanceTopology $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_topology `
                        -RetentionEndpointDominanceReduction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_dominance_reduction `
                        -RetentionEndpointLinkImpact $pathFocus.selected_original_finding_pair_profile_retention_endpoint_link_impact `
                        -RetentionEndpointPairInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_pair_interaction `
                        -RetentionEndpointTripleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_triple_interaction `
                        -RetentionEndpointQuadrupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quadruple_interaction `
                        -RetentionEndpointQuintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quintuple_interaction `
                        -RetentionEndpointSextupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextuple_interaction `
                        -RetentionEndpointSeptupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septuple_interaction `
                        -RetentionEndpointOctupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octuple_interaction `
                        -RetentionEndpointNonupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_nonuple_interaction `
                        -RetentionEndpointDecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_decuple_interaction `
                        -RetentionEndpointUndecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_undecuple_interaction `
                        -RetentionEndpointDuodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duodecuple_interaction `
                        -RetentionEndpointTredecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tredecuple_interaction `
                        -RetentionEndpointQuattuordecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuordecuple_interaction `
                        -RetentionEndpointQuindecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quindecuple_interaction `
                        -RetentionEndpointSexdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexdecuple_interaction `
                        -RetentionEndpointSeptendecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septendecuple_interaction `
                        -RetentionEndpointOctodecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octodecuple_interaction `
                        -RetentionEndpointNovemdecupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemdecuple_interaction `
                        -RetentionEndpointVigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_vigintuple_interaction `
                        -RetentionEndpointUnvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_unvigintuple_interaction `
                        -RetentionEndpointDuovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duovigintuple_interaction `
                        -RetentionEndpointTrevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trevigintuple_interaction `
                        -RetentionEndpointQuattuorvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuorvigintuple_interaction `
                        -RetentionEndpointQuinquevigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquevigintuple_interaction `
                        -RetentionEndpointSexvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sexvigintuple_interaction `
                        -RetentionEndpointSeptemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_septemvigintuple_interaction `
                        -RetentionEndpointOctovigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_octovigintuple_interaction `
                        -RetentionEndpointNovemvigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_novemvigintuple_interaction `
                        -RetentionEndpointTrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_trigintuple_interaction `
                        -RetentionEndpointUntrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_untrigintuple_interaction `
                        -RetentionEndpointDuotrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_duotrigintuple_interaction `
                        -RetentionEndpointTretrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_tretrigintuple_interaction `
                        -RetentionEndpointQuattuortrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quattuortrigintuple_interaction `
                        -RetentionEndpointQuinquetrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_quinquetrigintuple_interaction `
                        -RetentionEndpointSextrigintupleInteraction $pathFocus.selected_original_finding_pair_profile_retention_endpoint_sextrigintuple_interaction
                # EC-132: authenticate the ENTIRE EC-131 parent JSON first;
                # append exactly one selected original k38 SCC-reachability
                # projection, without touching the original selector/caller.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_octotrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctotrigintupleInteraction -PathFocus $pathFocus
                # EC-133: independently replay and compare the entire EC-132
                # public parent; append one original cardinality-39 child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_novemtrigintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointNovemtrigintupleInteraction -PathFocus $pathFocus
                # EC-134: verify the entire genuine EC-133 k39 public parent
                # before appending one cardinality-40 ORIGINAL FULL SCC child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuadragintupleInteraction -PathFocus $pathFocus
                # EC-135: authenticate all of EC-134's actual public k40 JSON;
                # append one read-only original k41 FULL SCC deletion child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_unquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUnquadragintupleInteraction -PathFocus $pathFocus
                # EC-136: replay the full authentic EC-135 k41 public JSON;
                # append exactly one read-only original k42 FULL SCC child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_duoquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuoquadragintupleInteraction -PathFocus $pathFocus
                # EC-137: rederive all of genuine EC-136 k42 public JSON first;
                # append one read-only original k43 FULL SCC deletion child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_trequadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTrequadragintupleInteraction -PathFocus $pathFocus
                # EC-138: authenticate EC-137 complete k43 public JSON first;
                # append one read-only exact k44 ORIGINAL FULL SCC child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuorquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuorquadragintupleInteraction -PathFocus $pathFocus
                # EC-139: authenticate the entire genuine EC-138 k44 parent;
                # add exact original 45-whole-link SCC reachability loss tiers.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quinquequadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquequadragintupleInteraction -PathFocus $pathFocus
                # EC-140: authenticate all EC-139 k45 original FIRST/SCC,
                # genuine/frozen/family and inherited tiers; append only k46.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sexquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSexquadragintupleInteraction -PathFocus $pathFocus
                # EC-141: rederive the complete authentic EC-140 k46 JSON
                # before appending one exact original k47 SCC deletion child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_septemquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSeptemquadragintupleInteraction -PathFocus $pathFocus
                # EC-142: authenticate all EC-141 k47 public JSON before adding
                # one selected read-only original k48 FULL SCC deletion child.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_octoquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointOctoquadragintupleInteraction -PathFocus $pathFocus
                # EC-143: first authenticate the real EC-142 k48 whole public JSON;
                # then append ONE original k49 FULL SCC deletion projection.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_novemquadragintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointNovemquadragintupleInteraction -PathFocus $pathFocus
                # EC-144: whole-public-JSON replay of actual EC143 k49, then
                # one exact original k50 SCC FULL-link deletion child only.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquagintupleInteraction -PathFocus $pathFocus
                # EC-145: independently replay and authenticate the entire EC144
                # k50 public parent before adding k51 FULL SCC link removals.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_unquinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointUnquinquagintupleInteraction -PathFocus $pathFocus
                # EC-146: whole-JSON rederive checked EC145 k51, then add k52
                # original SCC reachability (E63/eleven-kept index62 safe).
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_duoquinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointDuoquinquagintupleInteraction -PathFocus $pathFocus
                # EC-147: compare the full real EC146 k52 public JSON before
                # appending exact k53 original SCC loss (high-bit E64..66 CNF).
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_trequinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTrequinquagintupleInteraction -PathFocus $pathFocus
                # EC-148: reproduce and verify the complete real EC147 k53
                # public parent, then append exact original k54 SCC-link
                # loss tiers; the E64..66 high-edge decisions stay bounded.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quattuorquinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuattuorquinquagintupleInteraction -PathFocus $pathFocus
                # EC-149: replay and authenticate the complete EC148 k54
                # public parent before appending original k55 SCC link-loss
                # tiers. Real high edges 63..65 never enter signed-long masks.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_quinquequinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointQuinquequinquagintupleInteraction -PathFocus $pathFocus
                # EC-150: rederive and compare the COMPLETE EC149 k55 public
                # projection before appending exact k56 original FULL SCC
                # loss; high-index63..65 decisions retain true link provenance.
                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_sexquinquagintuple_interaction'] = `
                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointSexquinquagintupleInteraction -PathFocus $pathFocus
            }
        }
    }

    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)
    if (($beforeIds -join '|') -cne ($afterIds -join '|')) {
        throw 'CES record directory membership changed during selected Sequence.'
    }

    $result = [ordered]@{
        source_root = $VerifiedRoot
        mode = 'Sequence'
        selection_scope = 'caller_ordered_selected_record_ids'
        sequence_record_ids = @($RecordIds)
        selected_record_count = $RecordIds.Count
        record_count = $beforeIds.Count
        scanned_record_count = $checked.Count
        source_mode = $sourceMode
        comparison_basis = 'exact_saved_six_field_quote_anchor'
        sequence_top_per_category_per_step = $Top
        record_summaries = $records.ToArray()
        step_count = $steps.Count
        steps = $steps.ToArray()
        anchor_trajectory = $trajectory
        path_index = $pathIndex
        baseline_drift = $baselineDrift
        pairwise_profile = $pairwiseProfile
        selected_pair_overview = $globalPairOverview
        path_focus = $pathFocus
        record_integrity_verified = $true
        record_authorship_authenticated = $false
        source_revalidated = $false
        finding_semantics_verified = $false
        claimed_lines_verified = $false
        input_order_verified_as_chronology = $false
        absence_proves_resolution = $false
        snapshot_atomic = $false
        explanation = 'Caller order only, NOT verified time order. Anchor equality is exact saved source mode, layer, path, endpoint, quotation SHA-256 and quote proof category. Unreported in the next selected report is not a fix; counts describe saved model statements, not real defects. Preview caps never reduce full selected-record checks or exact counts.'
    }
    # No new field at all for an unfocused/pre-EC046 caller.
    if ($null -ne $selectedPairPathSelection) { $result['selected_pair_path_selection'] = $selectedPairPathSelection }
    if ($null -ne $selectedPairPathAnchorSelection) { $result['selected_pair_path_anchor_selection'] = $selectedPairPathAnchorSelection }
    if ($null -ne $selectedPairPathAnchorFindingSelection) { $result['selected_pair_path_anchor_finding_selection'] = $selectedPairPathAnchorFindingSelection }
    if ($null -ne $selectedPairPathAnchorFindingCounterpartSelection) { $result['selected_pair_path_anchor_finding_counterpart_selection'] = $selectedPairPathAnchorFindingCounterpartSelection }
    return $result
}

#requires -Version 7.0
<#
    EC-051: Complete histogram-equivalence classes and adjacent report-position
    transitions for ONE already selected pair/path/exact saved quote anchor and
    two INDEPENDENT original saved-record-scoped Findings.

    The EC-050 cohorts have already been checked against two full EC-042
    original Finding journeys and the full EC-043 anchor ledger. This module
    independently partitions the same N positions by EXACT five-bin saved
    MODEL statement counts (with absence a separate class), and checks EVERY
    unordered pair and five signed severity deltas against EC-043. It never
    matches Finding IDs across saved reports or reads source/records again.
#>
function Get-CodeSequenceOriginalFindingPairProfileAtlas {
    param(
        [object] $Cohorts,
        [object] $SelectedAnchor
    )

    $severities = @('critical', 'high', 'medium', 'low', 'info')
    $categories = @('absent_anchor', 'matches_left_only', 'matches_right_only',
                    'matches_both_endpoints', 'differs_from_both_endpoints')
    $pairCategories = @('left_only', 'right_only', 'retained_same_severity',
                        'retained_changed_severity', 'both_unreported')
    if ($null -eq $Cohorts -or $null -eq $SelectedAnchor) {
        throw 'Code Sequence original Finding pair profile atlas requires complete existing cohort/anchor views.'
    }
    $n = [int]$Cohorts.counts.selected_report_positions
    $pairCount = [int](($n * ($n - 1)) / 2)
    $leftPosition = [int]$Cohorts.left_endpoint.position
    $rightPosition = [int]$Cohorts.right_endpoint.position
    if ($Cohorts.scope -cne 'all_selected_report_saved_quote_anchor_severity_profile_cohorts_for_two_independent_original_Findings' -or
        -not [bool]$Cohorts.independent_of_sequence_top -or
        -not [bool]$Cohorts.complete_ec042_journeys_reused_unchanged -or
        -not [bool]$Cohorts.every_position_scoped_refs_and_five_severity_bins_reconciled -or
        -not [bool]$SelectedAnchor.independent_of_sequence_top -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        $leftPosition -lt 1 -or $leftPosition -ge $rightPosition -or $rightPosition -gt $n -or
        $Cohorts.positions.Count -ne $n -or $SelectedAnchor.positions.Count -ne $n -or
        $SelectedAnchor.compared_pairs.Count -ne $pairCount -or
        [int]$SelectedAnchor.selected_record_count -ne $n -or
        $Cohorts.path -cne $SelectedAnchor.path -or
        [int]$Cohorts.anchor_index_in_anchor_journeys -ne [int]$SelectedAnchor.anchor_index_in_anchor_journeys -or
        (Get-CodeCompareAnchorKey -Anchor $Cohorts.exact_saved_quote_anchor) -cne
            (Get-CodeCompareAnchorKey -Anchor $SelectedAnchor.anchor)) {
        throw 'Code Sequence original Finding pair profile atlas has inconsistent selected report/anchor scope.'
    }

    # Independently check that the EC-050 five cohorts are a disjoint,
    # complete, one-based partition in the caller's selected report order.
    $expectedBucketAtPosition = [string[]]::new($n)
    foreach ($category in $categories) {
        $members = $Cohorts.cohort_positions[$category]
        if ($null -eq $members -or $members.Count -ne [int]$Cohorts.counts[$category]) {
            throw 'Code Sequence original Finding pair profile atlas found an incomplete EC-050 cohort.'
        }
        $previous = 0
        foreach ($member in $members) {
            $position = [int]$member
            if ($position -lt 1 -or $position -gt $n -or $position -le $previous -or
                $null -ne $expectedBucketAtPosition[$position - 1]) {
                throw 'Code Sequence original Finding pair profile atlas found duplicate/unsorted cohort membership.'
            }
            $expectedBucketAtPosition[$position - 1] = $category
            $previous = $position
        }
    }
    for ($i = 0; $i -lt $n; $i++) {
        if ($null -eq $expectedBucketAtPosition[$i]) {
            throw 'Code Sequence original Finding pair profile atlas found an unclassified selected position.'
        }
    }

    # The position-specific key deliberately has no original Finding ID,
    # record digest, freeform text, or model-generated prose. An absent anchor
    # is NOT the five-zero histogram: a present anchor always has >=1 Finding.
    $indexByKey = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $classWork = [System.Collections.Generic.List[object]]::new()
    $positionWork = [System.Collections.Generic.List[object]]::new()
    $classByPosition = [int[]]::new($n)
    $reportedCount = 0
    $statementTotal = 0
    for ($i = 0; $i -lt $n; $i++) {
        $position = $i + 1
        $row = $Cohorts.positions[$i]
        $anchorRow = $SelectedAnchor.positions[$i]
        $reported = [bool]$row.reported_same_exact_saved_quote_anchor
        $count = [int]$row.saved_finding_statement_count_at_anchor
        if ([int]$row.position -ne $position -or [int]$anchorRow.position -ne $position -or
            $row.record_id -cne $anchorRow.record_id -or
            [bool]$anchorRow.reported_same_exact_saved_quote_anchor -ne $reported -or
            [int]$anchorRow.saved_finding_statement_count_at_anchor -ne $count -or
            $count -lt 0 -or $count -gt 40 -or
            $row.original_record_scoped_finding_refs.Count -ne $count -or
            $anchorRow.original_record_scoped_finding_refs.Count -ne $count -or
            ($reported -and $count -lt 1) -or
            (-not $reported -and $count -ne 0) -or
            (($null -eq $row.saved_severity_statement_counts) -eq $reported) -or
            -not (Test-CodeSequenceFocusedSeverityEqual -Left $row.saved_severity_statement_counts `
                -Right $anchorRow.saved_severity_statement_counts)) {
            throw 'Code Sequence original Finding pair profile atlas lost original report-position identity or absence.'
        }
        for ($r = 0; $r -lt $count; $r++) {
            $original = $row.original_record_scoped_finding_refs[$r]
            $checked = $anchorRow.original_record_scoped_finding_refs[$r]
            if ($original.finding_id -cne $checked.finding_id -or
                $original.severity -cne $checked.severity) {
                throw 'Code Sequence original Finding pair profile atlas diverges from original scoped ID/severity evidence.'
            }
        }
        $histogram = $null
        $key = 'ABSENT'
        if ($reported) {
            $digits = [System.Collections.Generic.List[string]]::new()
            $histogram = [ordered]@{}
            $sum = 0
            foreach ($severity in $severities) {
                $value = [int]$row.saved_severity_statement_counts[$severity]
                if ($value -lt 0 -or $value -gt 40) {
                    throw 'Code Sequence original Finding pair profile atlas found out-of-range saved histogram counts.'
                }
                $histogram[$severity] = $value
                $digits.Add([string]$value)
                $sum += $value
            }
            if ($sum -ne $count) {
                throw 'Code Sequence original Finding pair profile atlas histogram does not conserve original statement multiplicity.'
            }
            $key = 'P:' + ($digits.ToArray() -join ':')
            $reportedCount++
        }
        $statementTotal += $count
        $matchesLeft = $reported -and (Test-CodeSequenceFocusedSeverityEqual `
            -Left $histogram -Right $Cohorts.left_endpoint.saved_severity_statement_counts)
        $matchesRight = $reported -and (Test-CodeSequenceFocusedSeverityEqual `
            -Left $histogram -Right $Cohorts.right_endpoint.saved_severity_statement_counts)
        $bucket = if (-not $reported) { 'absent_anchor' }
            elseif ($matchesLeft -and $matchesRight) { 'matches_both_endpoints' }
            elseif ($matchesLeft) { 'matches_left_only' }
            elseif ($matchesRight) { 'matches_right_only' }
            else { 'differs_from_both_endpoints' }
        if ($bucket -cne $row.cohort -or $bucket -cne $expectedBucketAtPosition[$i] -or
            [bool]$row.matches_left_endpoint_saved_profile -ne [bool]$matchesLeft -or
            [bool]$row.matches_right_endpoint_saved_profile -ne [bool]$matchesRight) {
            throw 'Code Sequence original Finding pair profile atlas disagrees with the exhaustive EC-050 endpoint cohorts.'
        }
        if (-not $indexByKey.ContainsKey($key)) {
            $classIndex = $classWork.Count + 1
            $indexByKey.Add($key, $classIndex)
            $classWork.Add([ordered]@{
                class_index = $classIndex
                representative_position = $position
                representative_record_id = [string]$row.record_id
                reported_same_exact_saved_quote_anchor = $reported
                saved_finding_statement_count_at_anchor = $count
                saved_severity_statement_counts = $histogram
                position_indices = [System.Collections.Generic.List[int]]::new()
            })
        }
        $classIndex = $indexByKey[$key]
        $classWork[$classIndex - 1].position_indices.Add($position)
        $classByPosition[$i] = $classIndex
        $positionWork.Add([ordered]@{
            position = $position
            record_id = [string]$row.record_id
            profile_class_index = $classIndex
            ec050_endpoint_cohort = $bucket
            reported_same_exact_saved_quote_anchor = $reported
        })
    }
    if ($reportedCount -ne [int]$Cohorts.counts.reported_anchor_positions -or
        $n - $reportedCount -ne [int]$Cohorts.counts.unreported_anchor_positions -or
        $statementTotal -ne [int]$Cohorts.counts.saved_finding_statements_at_anchor_all_positions -or
        $classWork.Count -lt 1 -or $classWork.Count -gt $n) {
        throw 'Code Sequence original Finding pair profile atlas totals do not conserve EC-050.'
    }

    $leftClass = $classByPosition[$leftPosition - 1]
    $rightClass = $classByPosition[$rightPosition - 1]
    if ($Cohorts.positions[$leftPosition - 1].record_id -cne $Cohorts.left_endpoint.record_id -or
        $Cohorts.positions[$rightPosition - 1].record_id -cne $Cohorts.right_endpoint.record_id -or
        (($leftClass -eq $rightClass) -ne [bool]$Cohorts.endpoint_saved_severity_statement_profiles_equal) -or
        $Cohorts.anchor_pair_class -cne $(if ($leftClass -eq $rightClass) {
            'retained_same_severity'
        } else { 'retained_changed_severity' })) {
        throw 'Code Sequence original Finding pair profile atlas endpoint class membership differs from selected original Finding pair.'
    }

    # Exhaustively match all N*(N-1)/2 independent EC-043 pairs. A saved
    # absent anchor contributes numeric zero to signed deltas but still uses
    # NULL in every exposed profile to avoid claiming a zero-Finding report.
    $allPairCounts = [ordered]@{}
    foreach ($kind in $pairCategories) { $allPairCounts[$kind] = 0 }
    $adjacentByStep = [object[]]::new($n - 1)
    $pairIndex = 0
    for ($l = 0; $l -lt ($n - 1); $l++) {
        for ($r = $l + 1; $r -lt $n; $r++) {
            $pairIndex++
            $a = $Cohorts.positions[$l]
            $b = $Cohorts.positions[$r]
            $was = [bool]$a.reported_same_exact_saved_quote_anchor
            $now = [bool]$b.reported_same_exact_saved_quote_anchor
            $kind = if ($was -and $now) {
                if ($classByPosition[$l] -eq $classByPosition[$r]) {
                    'retained_same_severity'
                } else { 'retained_changed_severity' }
            } elseif ($was) { 'left_only' }
            elseif ($now) { 'right_only' }
            else { 'both_unreported' }
            $allPairCounts[$kind] = [int]$allPairCounts[$kind] + 1
            $pair = $SelectedAnchor.compared_pairs[$pairIndex - 1]
            $changed = ($kind -cin @('left_only','right_only','retained_changed_severity'))
            $gap = $false
            if ($was -and $now) {
                for ($middle = $l + 1; $middle -lt $r; $middle++) {
                    if (-not [bool]$Cohorts.positions[$middle].reported_same_exact_saved_quote_anchor) {
                        $gap = $true
                        break
                    }
                }
            }
            if ([int]$pair.pair_index -ne $pairIndex -or
                [int]$pair.left_position -ne ($l + 1) -or
                [int]$pair.right_position -ne ($r + 1) -or
                $pair.left_record_id -cne $a.record_id -or
                $pair.right_record_id -cne $b.record_id -or
                $pair.anchor_pair_class -cne $kind -or
                [bool]$pair.anchor_changed_in_pair -ne $changed -or
                [bool]$pair.shared_with_internal_unreported_position -ne $gap -or
                [int]$pair.left_saved_finding_statement_count_at_anchor -ne
                    [int]$a.saved_finding_statement_count_at_anchor -or
                [int]$pair.right_saved_finding_statement_count_at_anchor -ne
                    [int]$b.saved_finding_statement_count_at_anchor -or
                [int]$pair.saved_finding_statement_count_delta_right_minus_left -ne
                    ([int]$b.saved_finding_statement_count_at_anchor - [int]$a.saved_finding_statement_count_at_anchor)) {
                throw 'Code Sequence original Finding pair profile atlas disagrees with the complete EC-043 unordered-pair ledger.'
            }
            foreach ($severity in $severities) {
                $leftValue = if ($was) { [int]$a.saved_severity_statement_counts[$severity] } else { 0 }
                $rightValue = if ($now) { [int]$b.saved_severity_statement_counts[$severity] } else { 0 }
                if ([int]$pair.saved_severity_statement_delta_right_minus_left[$severity] -ne ($rightValue - $leftValue)) {
                    throw 'Code Sequence original Finding pair profile atlas severity-bin delta differs from EC-043.'
                }
            }
            if ($r -eq ($l + 1)) { $adjacentByStep[$l] = $pair }
        }
    }
    if ($pairIndex -ne $pairCount -or
        $allPairCounts.left_only -ne [int]$SelectedAnchor.counts.left_only_pair_count -or
        $allPairCounts.right_only -ne [int]$SelectedAnchor.counts.right_only_pair_count -or
        $allPairCounts.retained_same_severity -ne [int]$SelectedAnchor.counts.retained_same_severity_pair_count -or
        $allPairCounts.retained_changed_severity -ne [int]$SelectedAnchor.counts.retained_changed_severity_pair_count -or
        $allPairCounts.both_unreported -ne [int]$SelectedAnchor.counts.both_unreported_pair_count -or
        ($allPairCounts.left_only + $allPairCounts.right_only +
         $allPairCounts.retained_changed_severity) -ne [int]$SelectedAnchor.counts.changed_pair_count) {
        throw 'Code Sequence original Finding pair profile atlas cannot conserve complete EC-043 pair class totals.'
    }

    # Class runs and returns concern ONLY caller-supplied order. Unlike a
    # consecutive repeat (A,A), a return has at least one different class
    # since the class last appeared (A,B,A); it is not elapsed time or a fix.
    $adjacent = [System.Collections.Generic.List[object]]::new()
    $runs = [System.Collections.Generic.List[object]]::new()
    $adjacentCounts = [ordered]@{}
    foreach ($kind in $pairCategories) { $adjacentCounts[$kind] = 0 }
    $priorClasses = [System.Collections.Generic.HashSet[int]]::new()
    $returnClasses = [System.Collections.Generic.HashSet[int]]::new()
    [void]$priorClasses.Add($classByPosition[0])
    $returnCount = 0
    $runStart = 1
    for ($i = 1; $i -lt $n; $i++) {
        $pair = $adjacentByStep[$i - 1]
        if ($null -eq $pair) {
            throw 'Code Sequence original Finding pair profile atlas is missing an adjacent canonical pair.'
        }
        $fromClass = $classByPosition[$i - 1]
        $toClass = $classByPosition[$i]
        $different = ($fromClass -ne $toClass)
        $returned = $different -and $priorClasses.Contains($toClass)
        if ($returned) { $returnCount++; [void]$returnClasses.Add($toClass) }
        $kind = [string]$pair.anchor_pair_class
        if (-not ($pairCategories -ccontains $kind) -or
            ($different -ne ($kind -cin @('left_only','right_only','retained_changed_severity')))) {
            throw 'Code Sequence original Finding pair profile atlas class transitions disagree with EC-043.'
        }
        $adjacentCounts[$kind] = [int]$adjacentCounts[$kind] + 1
        $adjacent.Add([ordered]@{
            from_position = $i
            to_position = $i + 1
            from_record_id = [string]$Cohorts.positions[$i - 1].record_id
            to_record_id = [string]$Cohorts.positions[$i].record_id
            from_profile_class_index = $fromClass
            to_profile_class_index = $toClass
            ec043_pair_index = [int]$pair.pair_index
            saved_anchor_pair_class = $kind
            changed_saved_profile = $different
            returns_to_earlier_nonadjacent_profile_class = [bool]$returned
            saved_finding_statement_delta_right_minus_left =
                [int]$pair.saved_finding_statement_count_delta_right_minus_left
            saved_severity_statement_delta_right_minus_left =
                $pair.saved_severity_statement_delta_right_minus_left
        })
        if ($different) {
            $runs.Add([ordered]@{
                run_index = $runs.Count + 1
                profile_class_index = $fromClass
                start_position = $runStart
                end_position = $i
                selected_report_count = $i - $runStart + 1
            })
            $runStart = $i + 1
        }
        [void]$priorClasses.Add($toClass)
    }
    $runs.Add([ordered]@{
        run_index = $runs.Count + 1
        profile_class_index = $classByPosition[$n - 1]
        start_position = $runStart
        end_position = $n
        selected_report_count = $n - $runStart + 1
    })

    $classes = [System.Collections.Generic.List[object]]::new()
    $absentClasses = 0
    $classMemberTotal = 0
    foreach ($entry in $classWork) {
        $members = $entry.position_indices.ToArray()
        $classMemberTotal += $members.Count
        if (-not [bool]$entry.reported_same_exact_saved_quote_anchor) { $absentClasses++ }
        if ($members.Count -lt 1 -or $members[0] -ne [int]$entry.representative_position) {
            throw 'Code Sequence original Finding pair profile atlas class does not start at first caller appearance.'
        }
        $classes.Add([ordered]@{
            class_index = [int]$entry.class_index
            first_seen_position = [int]$entry.representative_position
            representative_record_id = [string]$entry.representative_record_id
            reported_same_exact_saved_quote_anchor = [bool]$entry.reported_same_exact_saved_quote_anchor
            saved_finding_statement_count_at_anchor = [int]$entry.saved_finding_statement_count_at_anchor
            saved_severity_statement_counts = $entry.saved_severity_statement_counts
            position_indices = $members
            position_count = $members.Count
            includes_left_endpoint = ($members -contains $leftPosition)
            includes_right_endpoint = ($members -contains $rightPosition)
        })
    }
    $changedAdjacent = $adjacentCounts.left_only + $adjacentCounts.right_only +
        $adjacentCounts.retained_changed_severity
    if ($classMemberTotal -ne $n -or $absentClasses -gt 1 -or
        $adjacent.Count -ne $n - 1 -or
        ($adjacentCounts.left_only + $adjacentCounts.right_only +
         $adjacentCounts.retained_same_severity + $adjacentCounts.retained_changed_severity +
         $adjacentCounts.both_unreported) -ne $n - 1 -or
        $runs.Count -ne $changedAdjacent + 1) {
        throw 'Code Sequence original Finding pair profile atlas class, transition or run counts are not conserved.'
    }

    return [ordered]@{
        scope = 'complete_saved_quote_anchor_five_severity_histogram_classes_adjacent_transitions_and_returns_for_two_independent_original_Findings'
        pair_index_in_pairwise_profile = [int]$Cohorts.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$Cohorts.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$Cohorts.anchor_index_in_anchor_journeys
        path = [string]$Cohorts.path
        exact_saved_quote_anchor = $Cohorts.exact_saved_quote_anchor
        left_endpoint_profile_class_index = $leftClass
        right_endpoint_profile_class_index = $rightClass
        counts = [ordered]@{
            selected_report_positions = $n
            distinct_saved_profile_class_count = $classes.Count
            reported_saved_profile_class_count = $classes.Count - $absentClasses
            absent_anchor_profile_class_count = $absentClasses
            reported_anchor_positions = $reportedCount
            saved_finding_statements_at_anchor_all_positions = $statementTotal
            all_unordered_pair_count = $pairCount
            adjacent_comparison_count = $adjacent.Count
            adjacent_changed_profile_count = $changedAdjacent
            adjacent_matching_profile_count = $adjacent.Count - $changedAdjacent
            contiguous_profile_run_count = $runs.Count
            return_to_prior_nonadjacent_profile_occurrence_count = $returnCount
            distinct_returned_profile_class_count = $returnClasses.Count
        }
        all_unordered_pair_class_counts = $allPairCounts
        adjacent_pair_class_counts = $adjacentCounts
        classes = $classes.ToArray()
        positions = $positionWork.ToArray()
        adjacent_comparisons = $adjacent.ToArray()
        profile_runs = $runs.ToArray()
        independent_of_sequence_top = $true
        complete_ec050_cohorts_and_ec043_all_pairs_reconciled = $true
        two_original_finding_journeys_remain_independent = $true
        explanation = 'Exact five-bin SAVED MODEL SEVERITY STATEMENT histogram classes include multiplicity; an absent quote anchor is a DISTINCT null-profile class. Classes are numbered by first appearance in caller-selected order, not time. Signed adjacent deltas treat absent as numeric zero ONLY for arithmetic. Returns are repetitions of an earlier histogram after intervening different class, NOT defect recurrence. The two original Finding IDs and all other saved Finding IDs remain in their independent saved-record scopes; matching quote, ID or profile never confirms identical real issues, risk, fix, regression, chronology or live source. Read-only in-memory view, untruncated by SequenceTop; no saved prose or quote/source/Git/network reads or writes.'
    }
}

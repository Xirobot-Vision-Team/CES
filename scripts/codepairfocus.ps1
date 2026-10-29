#requires -Version 7.0
<#
    EC-044: drill directly into ONE canonical selected report pair for ONE
    caller-explicit literal saved path. Return ALL canonical quote anchors,
    including retained-equal and both-unreported anchors, with both original
    report-scoped Finding ID/severity sets and right-minus-left differences.

    All inputs are prior, completely checked in-memory Sequence projections.
    No extra record, Git, source-file or network read, no write, no quote or
    model prose, no assertion of semantic Finding identity or chronology.
#>
function Get-CodeSequenceFocusedSelectedPairCell {
    param(
        [AllowNull()][object] $Source,
        [object] $Observation,
        [object] $OriginalPosition,
        [int] $ExpectedPosition,
        [string] $ExpectedRecordId,
        [int] $AnchorIndex
    )

    $present = ($null -ne $Source)
    $refs = [System.Collections.Generic.List[object]]::new()
    $severities = @('critical','high','medium','low','info')
    $hist = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
    if ([int]$Observation.position -ne $ExpectedPosition -or
        $Observation.record_id -cne $ExpectedRecordId -or
        [int]$OriginalPosition.position -ne $ExpectedPosition -or
        $OriginalPosition.record_id -cne $ExpectedRecordId -or
        [bool]$Observation.reported -ne $present) {
        throw 'Code Sequence selected pair has mismatched original report or anchor presence.'
    }
    if ($present) {
        if ([int]$Source.position -ne $ExpectedPosition -or
            $Source.record_id -cne $ExpectedRecordId -or
            $Source.finding_refs.Count -lt 1 -or $Source.finding_refs.Count -gt 40 -or
            [int]$Source.finding_statement_count -ne $Source.finding_refs.Count) {
            throw 'Code Sequence selected pair source Finding-reference cell is not bounded or correctly scoped.'
        }
        $previousId = $null
        foreach ($f in $Source.finding_refs) {
            $id = [string]$f.finding_id
            $severity = [string]$f.severity
            if ($id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
                ($null -ne $previousId -and [string]::CompareOrdinal($previousId, $id) -ge 0) -or
                -not ($severities -ccontains $severity)) {
                throw 'Code Sequence selected pair contains invalid original scoped Finding ID or severity.'
            }
            $matches = @($OriginalPosition.finding_refs | Where-Object { $_.finding_id -ceq $id })
            if ($matches.Count -ne 1 -or
                [int]$matches[0].anchor_index_in_anchor_journeys -ne $AnchorIndex -or
                $matches[0].severity -cne $severity) {
                throw 'Code Sequence selected pair original scoped Finding reference is bound to another anchor.'
            }
            $refs.Add([ordered]@{finding_id=$id; severity=$severity})
            $hist[$severity] = [int]$hist[$severity] + 1
            $previousId = $id
        }
    }
    if ([int]$Observation.finding_statement_count -ne $refs.Count -or
        (($null -eq $Observation.severity_statement_counts) -eq $present) -or
        ($present -and -not (Test-CodeSequenceFocusedSeverityEqual -Left $hist -Right $Observation.severity_statement_counts))) {
        throw 'Code Sequence selected pair original ID multiplicity differs from the saved severity observation.'
    }
    return [ordered]@{
        position = $ExpectedPosition
        record_id = $ExpectedRecordId
        reported_same_exact_saved_quote_anchor = $present
        saved_finding_statement_count_at_anchor = $refs.Count
        saved_severity_statement_counts = if ($present) { $hist } else { $null }
        original_record_scoped_finding_refs = $refs.ToArray()
    }
}

function Get-CodeSequenceFocusedSelectedPair {
    param(
        [int] $PairIndex,
        [object] $Journeys,
        [object] $Details,
        [object] $Lookup,
        [object] $References,
        [object] $PairReferences
    )

    if ($null -eq $Journeys -or $null -eq $Details -or $null -eq $Lookup -or
        $null -eq $References -or $null -eq $PairReferences) {
        throw 'Code Sequence selected pair requires five checked complete focused projections.'
    }
    $n = [int]$Journeys.selected_record_count
    $path = [string]$Journeys.path
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($path) -or $path.Length -gt 4096 -or
        $path.IndexOf([char]0) -ge 0 -or $anchorCount -gt ($n * 40) -or
        [int]$Journeys.counts.distinct_exact_anchor_union_count -ne $anchorCount -or
        $Journeys.position_totals.Count -ne $n -or
        $Details.path -cne $path -or $Lookup.path -cne $path -or
        $References.path -cne $path -or $PairReferences.path -cne $path -or
        [int]$Details.selected_record_count -ne $n -or
        [int]$Lookup.selected_record_count -ne $n -or
        [int]$References.selected_record_count -ne $n -or
        [int]$PairReferences.selected_record_count -ne $n -or
        [int]$Details.pair_count -ne $pairCount -or
        [int]$Lookup.pair_count -ne $pairCount -or
        [int]$PairReferences.pair_count -ne $pairCount -or
        $Details.pairs.Count -ne $pairCount -or
        $PairReferences.pairs.Count -ne $pairCount -or
        $Lookup.anchors.Count -ne $anchorCount -or
        $References.anchors.Count -ne $anchorCount -or
        $References.positions.Count -ne $n -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Details.independent_of_sequence_top -or
        -not [bool]$Lookup.independent_of_sequence_top -or
        -not [bool]$References.independent_of_sequence_top -or
        -not [bool]$PairReferences.independent_of_sequence_top) {
        throw 'Code Sequence selected pair requires matching, bounded, full-path saved-report ledgers.'
    }
    if ($PairIndex -lt 1 -or $PairIndex -gt $pairCount) {
        throw 'CODE_SHOW_SEQUENCE_PAIR_NOT_FOUND: the canonical report pair index is outside this caller selection.'
    }

    $expectedLeft = 0; $expectedRight = 0; $ordinal = 0
    for ($l = 1; $l -lt $n; $l++) {
        for ($r = $l + 1; $r -le $n; $r++) {
            $ordinal++
            if ($ordinal -eq $PairIndex) { $expectedLeft = $l; $expectedRight = $r }
        }
    }
    $detail = $Details.pairs[$PairIndex - 1]
    $witnessPair = $PairReferences.pairs[$PairIndex - 1]
    $leftId = [string]$Journeys.position_totals[$expectedLeft - 1].record_id
    $rightId = [string]$Journeys.position_totals[$expectedRight - 1].record_id
    if ($expectedLeft -lt 1 -or $expectedRight -le $expectedLeft -or
        [int]$detail.pair_index -ne $PairIndex -or
        [int]$witnessPair.pair_index -ne $PairIndex -or
        [int]$detail.left_position -ne $expectedLeft -or
        [int]$detail.right_position -ne $expectedRight -or
        [int]$witnessPair.left_position -ne $expectedLeft -or
        [int]$witnessPair.right_position -ne $expectedRight -or
        $detail.left_record_id -cne $leftId -or
        $detail.right_record_id -cne $rightId -or
        $witnessPair.left_record_id -cne $leftId -or
        $witnessPair.right_record_id -cne $rightId -or
        $References.positions[$expectedLeft - 1].record_id -cne $leftId -or
        $References.positions[$expectedRight - 1].record_id -cne $rightId) {
        throw 'Code Sequence selected pair order, endpoints or source record membership is inconsistent.'
    }

    # EC-040 emits witnesses ONLY for changed anchors. EC-037 records a
    # separate signed detail for retained-severity changes. Index both once,
    # then require exact exclusive membership for every canonical anchor.
    $changedWitnesses = [System.Collections.Generic.Dictionary[int,object]]::new()
    $previousIndex = 0
    foreach ($w in $witnessPair.changed_anchors) {
        $idx = [int]$w.anchor_index_in_anchor_journeys
        if ($idx -le $previousIndex -or $idx -gt $anchorCount -or
            $changedWitnesses.ContainsKey($idx)) {
            throw 'Code Sequence selected pair changed original Finding witnesses are malformed or unsorted.'
        }
        $changedWitnesses.Add($idx, $w)
        $previousIndex = $idx
    }
    $severityEvents = [System.Collections.Generic.Dictionary[int,object]]::new()
    $previousIndex = 0
    foreach ($event in $detail.retained_changed_severity_details) {
        $idx = [int]$event.anchor_index_in_anchor_journeys
        if ($idx -le $previousIndex -or $idx -gt $anchorCount -or
            $severityEvents.ContainsKey($idx)) {
            throw 'Code Sequence selected pair saved severity-change events are malformed or unsorted.'
        }
        $severityEvents.Add($idx, $event)
        $previousIndex = $idx
    }

    $classes = [ordered]@{
        left_only = 0
        right_only = 0
        retained_same_severity = 0
        retained_changed_severity = 0
        both_unreported = 0
    }
    $gaps = 0; $leftCount = 0; $rightCount = 0
    $leftChangedRefs = 0; $rightChangedRefs = 0
    $leftOnlyCount = 0; $rightOnlyCount = 0
    $retainedLeft = 0; $retainedRight = 0
    $severityNames = @('critical','high','medium','low','info')
    $allDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
    $retainedDelta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($a = 0; $a -lt $anchorCount; $a++) {
        $index = $a + 1
        $anchor = $Journeys.anchors[$a]
        $refAnchor = $References.anchors[$a]
        $inverse = $Lookup.anchors[$a]
        $pattern = [string]$anchor.presence_pattern
        if ($anchor.anchor.path -cne $path -or
            $pattern.Length -ne $n -or $pattern -match '[^01]' -or
            $anchor.observations_in_caller_order.Count -ne $n -or
            [int]$refAnchor.anchor_index_in_anchor_journeys -ne $index -or
            [int]$inverse.anchor_index_in_anchor_journeys -ne $index -or
            $refAnchor.presence_pattern -cne $pattern -or
            $inverse.presence_pattern -cne $pattern) {
            throw 'Code Sequence selected pair canonical quote-anchor identity changed.'
        }
        $sourceLeft = $null; $sourceRight = $null
        $lastSourcePosition = 0
        foreach ($ref in $refAnchor.references_in_caller_order) {
            $position = [int]$ref.position
            if ($position -le $lastSourcePosition -or $position -gt $n -or
                $ref.record_id -cne $Journeys.position_totals[$position - 1].record_id) {
                throw 'Code Sequence selected pair original Finding-reference positions are foreign or unsorted.'
            }
            if ($position -eq $expectedLeft) { $sourceLeft = $ref }
            if ($position -eq $expectedRight) { $sourceRight = $ref }
            $lastSourcePosition = $position
        }
        $left = Get-CodeSequenceFocusedSelectedPairCell -Source $sourceLeft `
            -Observation $anchor.observations_in_caller_order[$expectedLeft - 1] `
            -OriginalPosition $References.positions[$expectedLeft - 1] `
            -ExpectedPosition $expectedLeft -ExpectedRecordId $leftId -AnchorIndex $index
        $right = Get-CodeSequenceFocusedSelectedPairCell -Source $sourceRight `
            -Observation $anchor.observations_in_caller_order[$expectedRight - 1] `
            -OriginalPosition $References.positions[$expectedRight - 1] `
            -ExpectedPosition $expectedRight -ExpectedRecordId $rightId -AnchorIndex $index
        if (($pattern[$expectedLeft - 1] -eq [char]'1') -ne [bool]$left.reported_same_exact_saved_quote_anchor -or
            ($pattern[$expectedRight - 1] -eq [char]'1') -ne [bool]$right.reported_same_exact_saved_quote_anchor) {
            throw 'Code Sequence selected pair original IDs contradict anchor presence pattern.'
        }
        $was = [bool]$left.reported_same_exact_saved_quote_anchor
        $now = [bool]$right.reported_same_exact_saved_quote_anchor
        $kind = if ($was -and $now) {
            if (Test-CodeSequenceFocusedSeverityEqual -Left $left.saved_severity_statement_counts `
                    -Right $right.saved_severity_statement_counts) { 'retained_same_severity' }
            else { 'retained_changed_severity' }
        } elseif ($was) { 'left_only' }
        elseif ($now) { 'right_only' }
        else { 'both_unreported' }
        $parts = @(
            [pscustomobject]@{ name='left_only'; forward=$detail.left_only_anchor_indices; inverse=$inverse.left_only_pair_indices },
            [pscustomobject]@{ name='right_only'; forward=$detail.right_only_anchor_indices; inverse=$inverse.right_only_pair_indices },
            [pscustomobject]@{ name='retained_same_severity'; forward=$detail.retained_same_severity_anchor_indices; inverse=$inverse.retained_same_severity_pair_indices },
            [pscustomobject]@{ name='retained_changed_severity'; forward=$detail.retained_changed_severity_anchor_indices; inverse=$inverse.retained_changed_severity_pair_indices },
            [pscustomobject]@{ name='both_unreported'; forward=$detail.both_unreported_anchor_indices; inverse=$inverse.both_unreported_pair_indices }
        )
        foreach ($part in $parts) {
            $expected = ($part.name -ceq $kind)
            if (($part.forward -contains $index) -ne $expected -or
                ($part.inverse -contains $PairIndex) -ne $expected) {
                throw 'Code Sequence selected pair forward/inverse exact anchor partition disagrees.'
            }
        }
        $classes[$kind] = [int]$classes[$kind] + 1
        $gap = $false
        if ($was -and $now) {
            for ($m = $expectedLeft; $m -lt ($expectedRight - 1); $m++) {
                if ($pattern[$m] -eq [char]'0') { $gap = $true; break }
            }
        }
        if (($detail.shared_with_internal_unreported_position_anchor_indices -contains $index) -ne $gap -or
            ($inverse.shared_with_internal_unreported_position_pair_indices -contains $PairIndex) -ne $gap) {
            throw 'Code Sequence selected pair internal reporting gap contradicts checked forward/inverse evidence.'
        }
        if ($gap) { $gaps++ }

        $lCount = [int]$left.saved_finding_statement_count_at_anchor
        $rCount = [int]$right.saved_finding_statement_count_at_anchor
        $leftCount += $lCount; $rightCount += $rCount
        if ($kind -ceq 'left_only') { $leftOnlyCount += $lCount }
        if ($kind -ceq 'right_only') { $rightOnlyCount += $rCount }
        if ($was -and $now) { $retainedLeft += $lCount; $retainedRight += $rCount }
        $delta = [ordered]@{critical=0;high=0;medium=0;low=0;info=0}
        foreach ($severity in $severityNames) {
            $lv = if ($was) { [int]$left.saved_severity_statement_counts[$severity] } else { 0 }
            $rv = if ($now) { [int]$right.saved_severity_statement_counts[$severity] } else { 0 }
            $delta[$severity] = $rv - $lv
            $allDelta[$severity] = [int]$allDelta[$severity] + $rv - $lv
            if ($was -and $now) {
                $retainedDelta[$severity] = [int]$retainedDelta[$severity] + $rv - $lv
            }
        }
        $changed = $kind -in @('left_only','right_only','retained_changed_severity')
        if ($changedWitnesses.ContainsKey($index) -ne $changed) {
            throw 'Code Sequence selected pair missing or unexpected EC-040 changed Finding witness.'
        }
        if ($changed) {
            $w = $changedWitnesses[$index]
            if ($w.contrast_kind -cne $kind -or $w.left_record_id -cne $leftId -or
                $w.right_record_id -cne $rightId -or
                [int]$w.left_finding_statement_count -ne $lCount -or
                [int]$w.right_finding_statement_count -ne $rCount -or
                [int]$w.finding_statement_count_delta -ne ($rCount - $lCount) -or
                [bool]$w.shared_with_internal_unreported_position -ne $gap -or
                -not (Test-CodeSequenceFocusedSeverityEqual -Left $w.severity_statement_delta -Right $delta)) {
                throw 'Code Sequence selected pair original ID witness or saved severity delta changed.'
            }
            foreach ($side in @('left','right')) {
                $expectedRefs = if ($side -eq 'left') { $left.original_record_scoped_finding_refs } else { $right.original_record_scoped_finding_refs }
                $actualRefs = if ($side -eq 'left') { $w.left_finding_refs } else { $w.right_finding_refs }
                if ($expectedRefs.Count -ne $actualRefs.Count) {
                    throw 'Code Sequence selected pair changed Finding witness lost original statements.'
                }
                for ($j = 0; $j -lt $expectedRefs.Count; $j++) {
                    if ($actualRefs[$j].finding_id -cne $expectedRefs[$j].finding_id -or
                        $actualRefs[$j].severity -cne $expectedRefs[$j].severity) {
                        throw 'Code Sequence selected pair changed Finding witness differs from EC-039 original scope.'
                    }
                }
            }
            $leftChangedRefs += $lCount; $rightChangedRefs += $rCount
        }
        if ($severityEvents.ContainsKey($index) -ne ($kind -ceq 'retained_changed_severity')) {
            throw 'Code Sequence selected pair retained-severity witness mismatch.'
        }
        $inverseEvents = @($inverse.retained_changed_severity_events | Where-Object { [int]$_.pair_index -eq $PairIndex })
        if ($inverseEvents.Count -ne $(if ($kind -ceq 'retained_changed_severity') { 1 } else { 0 })) {
            throw 'Code Sequence selected pair inverse retained-severity event mismatch.'
        }
        if ($kind -ceq 'retained_changed_severity') {
            foreach ($ev in @($severityEvents[$index], $inverseEvents[0])) {
                if ([int]$ev.left_finding_statement_count -ne $lCount -or
                    [int]$ev.right_finding_statement_count -ne $rCount -or
                    [int]$ev.finding_statement_count_delta -ne ($rCount - $lCount) -or
                    [bool]$ev.shared_with_internal_unreported_position -ne $gap -or
                    -not (Test-CodeSequenceFocusedSeverityEqual -Left $ev.severity_statement_delta -Right $delta)) {
                    throw 'Code Sequence selected pair retained five-severity signed deltas changed.'
                }
            }
            if ([int]$inverseEvents[0].left_position -ne $expectedLeft -or
                [int]$inverseEvents[0].right_position -ne $expectedRight) {
                throw 'Code Sequence selected pair inverse severity event endpoints differ.'
            }
        }
        $rows.Add([ordered]@{
            anchor_index_in_anchor_journeys = $index
            anchor = $anchor.anchor
            anchor_presence_pattern_in_caller_order = $pattern
            anchor_pair_class = $kind
            anchor_changed_in_pair = $changed
            shared_with_internal_unreported_position = $gap
            left = $left
            right = $right
            saved_finding_statement_count_delta_right_minus_left = $rCount - $lCount
            saved_severity_statement_delta_right_minus_left = $delta
        })
    }
    if ($rows.Count -ne $anchorCount -or
        ($classes.left_only + $classes.right_only + $classes.retained_same_severity +
            $classes.retained_changed_severity + $classes.both_unreported) -ne $anchorCount -or
        $classes.left_only -ne $detail.left_only_anchor_indices.Count -or
        $classes.right_only -ne $detail.right_only_anchor_indices.Count -or
        $classes.retained_same_severity -ne $detail.retained_same_severity_anchor_indices.Count -or
        $classes.retained_changed_severity -ne $detail.retained_changed_severity_anchor_indices.Count -or
        $classes.both_unreported -ne $detail.both_unreported_anchor_indices.Count -or
        $gaps -ne $detail.shared_with_internal_unreported_position_anchor_indices.Count -or
        ($classes.left_only + $classes.right_only + $classes.retained_changed_severity) -ne [int]$detail.changed_exact_anchor_count -or
        $changedWitnesses.Count -ne [int]$detail.changed_exact_anchor_count -or
        $changedWitnesses.Count -ne [int]$witnessPair.changed_exact_anchor_count -or
        $severityEvents.Count -ne $classes.retained_changed_severity -or
        $leftCount -ne ([int]$detail.left_only_finding_statement_count + [int]$detail.retained_left_finding_statement_count) -or
        $rightCount -ne ([int]$detail.right_only_finding_statement_count + [int]$detail.retained_right_finding_statement_count) -or
        $leftOnlyCount -ne [int]$detail.left_only_finding_statement_count -or
        $rightOnlyCount -ne [int]$detail.right_only_finding_statement_count -or
        $retainedLeft -ne [int]$detail.retained_left_finding_statement_count -or
        $retainedRight -ne [int]$detail.retained_right_finding_statement_count -or
        ($rightCount - $leftCount) -ne [int]$detail.finding_statement_count_delta -or
        $leftCount -ne [int]$References.positions[$expectedLeft - 1].finding_statement_count -or
        $rightCount -ne [int]$References.positions[$expectedRight - 1].finding_statement_count -or
        $leftCount -ne [int]$Journeys.position_totals[$expectedLeft - 1].finding_statement_count -or
        $rightCount -ne [int]$Journeys.position_totals[$expectedRight - 1].finding_statement_count -or
        $leftChangedRefs -ne [int]$witnessPair.left_changed_finding_reference_occurrences -or
        $rightChangedRefs -ne [int]$witnessPair.right_changed_finding_reference_occurrences -or
        -not (Test-CodeSequenceFocusedSeverityEqual -Left $allDelta -Right $detail.severity_statement_delta_all_reported_anchors) -or
        -not (Test-CodeSequenceFocusedSeverityEqual -Left $retainedDelta -Right $detail.severity_statement_delta_retained_anchors)) {
        throw 'Code Sequence selected pair failed complete changed/stable/unreported anchor and original ID conservation.'
    }

    return [ordered]@{
        scope = 'one_explicit_canonical_report_pair_all_exact_saved_quote_anchors'
        path = $path
        pair_index_in_anchor_pair_details = $PairIndex
        selected_record_count = $n
        left_position = $expectedLeft
        right_position = $expectedRight
        left_record_id = $leftId
        right_record_id = $rightId
        independent_of_sequence_top = $true
        counts = [ordered]@{
            distinct_exact_anchor_union_count = $anchorCount
            left_only_anchor_count = [int]$classes.left_only
            right_only_anchor_count = [int]$classes.right_only
            retained_same_severity_anchor_count = [int]$classes.retained_same_severity
            retained_changed_severity_anchor_count = [int]$classes.retained_changed_severity
            both_unreported_anchor_count = [int]$classes.both_unreported
            changed_anchor_count = [int]($classes.left_only + $classes.right_only + $classes.retained_changed_severity)
            shared_with_internal_unreported_position_anchor_count = $gaps
            left_original_finding_statement_count = $leftCount
            right_original_finding_statement_count = $rightCount
            left_changed_anchor_original_finding_reference_occurrences = $leftChangedRefs
            right_changed_anchor_original_finding_reference_occurrences = $rightChangedRefs
        }
        saved_finding_statement_count_delta_right_minus_left = $rightCount - $leftCount
        saved_severity_statement_delta_right_minus_left = $allDelta
        saved_severity_statement_delta_retained_anchors_right_minus_left = $retainedDelta
        anchors = $rows.ToArray()
        explanation = 'Pair index is canonical ONLY for this selected report set and exact literal path. All exact saved quote anchors, including stable-histogram and neither-reported rows, are shown with separate ORIGINAL record-scoped Finding IDs on each endpoint. Each signed delta is a difference between SAVED model-statement histograms, never a matched Finding, verified defect, fix, severity progression, source freshness, risk or chronological change. No additional source/Git/stored-body read, quote/model prose, network access or write.'
    }
}

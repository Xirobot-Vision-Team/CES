#requires -Version 7.0
<#
    EC-042: user-selected original saved (record_id, Finding ID) -> one
    complete, direct, exact-quote-anchor report journey and counterpart view.

    This projection operates ONLY on previously checked, bounded EC-034,
    EC-037, EC-039, EC-040 and EC-041 in-memory views. Every counterpart
    Finding ID remains scoped to its own saved report. Neither matching an
    exact quote anchor nor matching an ID spelling establishes the identity,
    actual severity, existence, resolution or chronology of a real defect.
#>
function Get-CodeSequenceFocusedSelectedFinding {
    param(
        [string] $SeedRecordId,
        [string] $SeedFindingId,
        [object] $Journeys,
        [object] $Details,
        [object] $References,
        [object] $PairReferences,
        [object] $FindingPairs
    )

    $n = [int]$Journeys.selected_record_count
    $path = [string]$Journeys.path
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($SeedRecordId -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $SeedFindingId -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
        $n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($path) -or $path.Length -gt 4096 -or
        $path.IndexOf([char]0) -ge 0 -or
        $anchorCount -gt ($n * 40) -or
        $Details.path -cne $path -or $References.path -cne $path -or
        $PairReferences.path -cne $path -or $FindingPairs.path -cne $path -or
        [int]$Details.selected_record_count -ne $n -or
        [int]$References.selected_record_count -ne $n -or
        [int]$PairReferences.selected_record_count -ne $n -or
        [int]$FindingPairs.selected_record_count -ne $n -or
        $References.positions.Count -ne $n -or
        $FindingPairs.positions.Count -ne $n -or
        $References.anchors.Count -ne $anchorCount -or
        $Journeys.position_totals.Count -ne $n -or
        $Details.pairs.Count -ne $pairCount -or
        $PairReferences.pairs.Count -ne $pairCount -or
        [int]$FindingPairs.pair_count -ne $pairCount -or
        -not [bool]$Journeys.independent_of_sequence_top -or
        -not [bool]$Details.independent_of_sequence_top -or
        -not [bool]$References.independent_of_sequence_top -or
        -not [bool]$PairReferences.independent_of_sequence_top -or
        -not [bool]$FindingPairs.independent_of_sequence_top) {
        throw 'Code Sequence selected Finding requires five complete, mutually scoped, checked projections.'
    }

    $seedPosition = 0
    for ($p = 0; $p -lt $n; $p++) {
        if ([int]$References.positions[$p].position -ne ($p + 1) -or
            [int]$FindingPairs.positions[$p].position -ne ($p + 1) -or
            $References.positions[$p].record_id -cne $Journeys.position_totals[$p].record_id -or
            $FindingPairs.positions[$p].record_id -cne $Journeys.position_totals[$p].record_id -or
            $References.positions[$p].finding_refs.Count -ne $FindingPairs.positions[$p].finding_refs.Count) {
            throw 'Code Sequence selected Finding original positions do not conserve scoped saved records.'
        }
        if ($References.positions[$p].record_id -ceq $SeedRecordId) {
            if ($seedPosition -ne 0) { throw 'Code Sequence selected Finding selected record ID is duplicated.' }
            $seedPosition = $p + 1
        }
    }
    if ($seedPosition -eq 0) {
        throw 'CODE_SHOW_SEQUENCE_FINDING_RECORD_NOT_SELECTED: original saved record is not in caller selection.'
    }
    $seedRef = $null
    $seedPairs = $null
    foreach ($f in $References.positions[$seedPosition - 1].finding_refs) {
        if ($f.finding_id -ceq $SeedFindingId) { $seedRef = $f; break }
    }
    # The exact requested Finding may exist in the record at another path;
    # never silently use it or reinterpret a case-sensitive literal path.
    if ($null -eq $seedRef) {
        throw 'CODE_SHOW_SEQUENCE_FINDING_NOT_FOUND: exact original Finding ID is not reported at this literal saved path.'
    }
    foreach ($f in $FindingPairs.positions[$seedPosition - 1].finding_refs) {
        if ($f.finding_id -ceq $SeedFindingId) { $seedPairs = $f; break }
    }
    $anchorIndex = [int]$seedRef.anchor_index_in_anchor_journeys
    if ($null -eq $seedPairs -or $anchorIndex -lt 1 -or $anchorIndex -gt $anchorCount -or
        [int]$seedPairs.anchor_index_in_anchor_journeys -ne $anchorIndex -or
        $seedPairs.severity -cne $seedRef.severity -or
        [int]$seedPairs.pair_incidence_count -ne ($n - 1) -or
        $seedPairs.compared_pairs.Count -ne ($n - 1)) {
        throw 'Code Sequence selected Finding original saved ID, anchor or pair index contradicts checked views.'
    }

    $anchor = $Journeys.anchors[$anchorIndex - 1]
    $anchorRefs = $References.anchors[$anchorIndex - 1]
    $pattern = [string]$anchor.presence_pattern
    if ($anchor.anchor.path -cne $path -or
        $anchorRefs.anchor_index_in_anchor_journeys -ne $anchorIndex -or
        $anchorRefs.presence_pattern -cne $pattern -or
        $pattern.Length -ne $n -or $pattern -match '[^01]' -or
        $anchor.observations_in_caller_order.Count -ne $n -or
        $anchor.reporting_record_count -gt $n -or
        $anchorRefs.references_in_caller_order.Count -gt $n) {
        throw 'Code Sequence selected Finding canonical exact-anchor identity changed.'
    }

    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $positionRows = [System.Collections.Generic.List[object]]::new()
    $sourceCells = [object[]]::new($n)
    $reported = 0
    $statementSum = 0
    $counterpartRefs = 0
    $lastAnchorPosition = 0
    foreach ($r in $anchorRefs.references_in_caller_order) {
        $rPosition = [int]$r.position
        if ($rPosition -le $lastAnchorPosition -or $rPosition -gt $n -or
            $r.record_id -cne $Journeys.position_totals[$rPosition - 1].record_id) {
            throw 'Code Sequence selected Finding anchor references are not in checked caller position order.'
        }
        $sourceCells[$rPosition - 1] = $r
        $lastAnchorPosition = $rPosition
    }
    for ($p = 0; $p -lt $n; $p++) {
        $observation = $anchor.observations_in_caller_order[$p]
        $sourceCell = $sourceCells[$p]
        $isReported = ($null -ne $sourceCell)
        $severityCounts = [ordered]@{ critical=0; high=0; medium=0; low=0; info=0 }
        $refs = [System.Collections.Generic.List[object]]::new()
        if ($isReported) {
            if ($sourceCell.finding_refs.Count -lt 1 -or $sourceCell.finding_refs.Count -gt 40 -or
                [int]$sourceCell.finding_statement_count -ne $sourceCell.finding_refs.Count) {
                throw 'Code Sequence selected Finding counterpart reference count is invalid.'
            }
            $lastId = $null
            foreach ($f in $sourceCell.finding_refs) {
                $id = [string]$f.finding_id
                $severity = [string]$f.severity
                if ([string]::IsNullOrEmpty($id) -or
                    ($null -ne $lastId -and [string]::CompareOrdinal($lastId, $id) -ge 0) -or
                    -not ($severityNames -ccontains $severity)) {
                    throw 'Code Sequence selected Finding counterpart original ID or saved severity is invalid.'
                }
                $originalMatches = 0
                foreach ($orig in $References.positions[$p].finding_refs) {
                    if ($orig.finding_id -ceq $id) {
                        if ([int]$orig.anchor_index_in_anchor_journeys -ne $anchorIndex -or
                            $orig.severity -cne $severity) {
                            throw 'Code Sequence selected Finding counterpart maps to another saved quote anchor.'
                        }
                        $originalMatches++
                    }
                }
                if ($originalMatches -ne 1) {
                    throw 'Code Sequence selected Finding counterpart is not unique in its original record.'
                }
                $refs.Add([ordered]@{ finding_id=$id; severity=$severity })
                $severityCounts[$severity] = [int]$severityCounts[$severity] + 1
                $lastId = $id
            }
        }
        if ([int]$observation.position -ne ($p + 1) -or
            $observation.record_id -cne $Journeys.position_totals[$p].record_id -or
            [bool]$observation.reported -ne $isReported -or
            ([string]$pattern[$p] -ceq '1') -ne $isReported -or
            [int]$observation.finding_statement_count -ne $refs.Count -or
            (($null -eq $observation.severity_statement_counts) -eq $isReported) -or
            ($isReported -and -not (Test-CodeSequenceFocusedSeverityEqual `
                -Left $severityCounts -Right $observation.severity_statement_counts))) {
            throw 'Code Sequence selected Finding original IDs differ from complete anchor observations.'
        }
        if ($p + 1 -eq $seedPosition) {
            if (-not $isReported) { throw 'Code Sequence selected Finding seed anchor unexpectedly unreported.' }
            $matches = @($refs.ToArray() | Where-Object { $_.finding_id -ceq $SeedFindingId -and $_.severity -ceq $seedRef.severity })
            if ($matches.Count -ne 1) { throw 'Code Sequence selected Finding seed scoped reference differs from anchor observations.' }
        }
        if ($isReported) { $reported++ }
        $statementSum += $refs.Count
        if ($p + 1 -ne $seedPosition) { $counterpartRefs += $refs.Count }
        $positionRows.Add([ordered]@{
            position = $p + 1
            record_id = [string]$observation.record_id
            reported_same_exact_saved_quote_anchor = $isReported
            saved_finding_statement_count_at_anchor = $refs.Count
            saved_severity_statement_counts = if ($isReported) { $severityCounts } else { $null }
            original_record_scoped_finding_refs = $refs.ToArray()
            is_selected_finding_original_record = ($p + 1 -eq $seedPosition)
        })
    }
    if ($reported -ne [int]$anchor.reporting_record_count -or
        $statementSum -ne [int]$anchor.finding_statement_occurrences -or
        $statementSum -ne [int]$anchorRefs.finding_statement_occurrences -or
        $reported -ne $anchorRefs.reporting_record_count) {
        throw 'Code Sequence selected Finding lost source anchor occurrences.'
    }

    $compared = [System.Collections.Generic.List[object]]::new()
    $changed = 0; $stable = 0; $gapCount = 0
    $expectedPairIndex = 0
    foreach ($row in $seedPairs.compared_pairs) {
        $pairIndex = [int]$row.pair_index
        $otherPos = [int]$row.counterpart_position
        if ($pairIndex -le $expectedPairIndex -or $pairIndex -gt $pairCount -or
            $otherPos -lt 1 -or $otherPos -gt $n -or $otherPos -eq $seedPosition) {
            throw 'Code Sequence selected Finding compared pairs are not canonical.'
        }
        $pair = $Details.pairs[$pairIndex - 1]
        $onLeft = ([int]$pair.left_position -eq $seedPosition)
        $onRight = ([int]$pair.right_position -eq $seedPosition)
        if ($onLeft -eq $onRight -or
            [int]$pair.pair_index -ne $pairIndex -or
            [int]$pair.left_position -ge [int]$pair.right_position -or
            ($onLeft -and [int]$pair.right_position -ne $otherPos) -or
            ($onRight -and [int]$pair.left_position -ne $otherPos) -or
            $row.this_side -cne $(if ($onLeft) { 'left' } else { 'right' }) -or
            $row.counterpart_record_id -cne $positionRows[$otherPos - 1].record_id -or
            $row.counterpart_record_id -cne $(if ($onLeft) { $pair.right_record_id } else { $pair.left_record_id })) {
            throw 'Code Sequence selected Finding pair is not attached to the original saved record.'
        }
        $other = $positionRows[$otherPos - 1]
        $leftCell = $positionRows[([int]$pair.left_position - 1)]
        $rightCell = $positionRows[([int]$pair.right_position - 1)]
        $leftPresent = [bool]$leftCell.reported_same_exact_saved_quote_anchor
        $rightPresent = [bool]$rightCell.reported_same_exact_saved_quote_anchor
        $kind = if ($leftPresent -and $rightPresent) {
            if (Test-CodeSequenceFocusedSeverityEqual -Left $leftCell.saved_severity_statement_counts `
                    -Right $rightCell.saved_severity_statement_counts) {
                'retained_same_severity'
            } else { 'retained_changed_severity' }
        } elseif ($leftPresent) { 'left_only' }
        elseif ($rightPresent) { 'right_only' }
        else { 'both_unreported' }
        if ($kind -eq 'both_unreported' -or $kind -cne $row.anchor_pair_class -or
            [bool]$row.anchor_changed_in_pair -ne ($kind -ne 'retained_same_severity') -or
            [int]$row.counterpart_finding_statement_count -ne [int]$other.saved_finding_statement_count_at_anchor) {
            throw 'Code Sequence selected Finding pair classification changed or lost original counterpart counts.'
        }
        $member = switch ($kind) {
            'left_only' { $pair.left_only_anchor_indices }
            'right_only' { $pair.right_only_anchor_indices }
            'retained_same_severity' { $pair.retained_same_severity_anchor_indices }
            'retained_changed_severity' { $pair.retained_changed_severity_anchor_indices }
        }
        if (-not ($member -contains $anchorIndex)) {
            throw 'Code Sequence selected Finding contrast is absent from the checked pair partition.'
        }
        $gap = $false
        if ($leftPresent -and $rightPresent) {
            for ($p = [int]$pair.left_position; $p -lt ([int]$pair.right_position - 1); $p++) {
                if (-not [bool]$positionRows[$p].reported_same_exact_saved_quote_anchor) { $gap = $true; break }
            }
        }
        if ($gap -ne [bool]$row.shared_with_internal_unreported_position -or
            $gap -ne ($pair.shared_with_internal_unreported_position_anchor_indices -contains $anchorIndex)) {
            throw 'Code Sequence selected Finding internal unreported position differs from checked pairs.'
        }
        # For changed anchor pairs, EC-040's actual original-ID witness must
        # match BOTH endpoints. Stable anchors intentionally have no witness.
        $pairWitness = $PairReferences.pairs[$pairIndex - 1]
        if ([int]$pairWitness.pair_index -ne $pairIndex) {
            throw 'Code Sequence selected Finding changed-pair reference is not in pair order.'
        }
        $matches = @($pairWitness.changed_anchors | Where-Object { [int]$_.anchor_index_in_anchor_journeys -eq $anchorIndex })
        if ($kind -eq 'retained_same_severity') {
            if ($matches.Count -ne 0) { throw 'Code Sequence selected Finding stable anchor returned a changed witness.' }
            $stable++
        } else {
            if ($matches.Count -ne 1 -or $matches[0].contrast_kind -cne $kind) {
                throw 'Code Sequence selected Finding changed anchor lacks its original-ID witness.'
            }
            $witness = $matches[0]
            foreach ($side in @('left','right')) {
                $expected = if ($side -eq 'left') { $leftCell.original_record_scoped_finding_refs } else { $rightCell.original_record_scoped_finding_refs }
                $actual = if ($side -eq 'left') { $witness.left_finding_refs } else { $witness.right_finding_refs }
                if ($actual.Count -ne $expected.Count) {
                    throw 'Code Sequence selected Finding witness original scoped Finding counts differ.'
                }
                for ($i = 0; $i -lt $expected.Count; $i++) {
                    if ($actual[$i].finding_id -cne $expected[$i].finding_id -or
                        $actual[$i].severity -cne $expected[$i].severity) {
                        throw 'Code Sequence selected Finding witness original IDs or severities differ.'
                    }
                }
            }
            $changed++
        }
        if ($gap) { $gapCount++ }
        $compared.Add([ordered]@{
            pair_index = $pairIndex
            original_side = [string]$row.this_side
            counterpart_position = $otherPos
            counterpart_record_id = [string]$other.record_id
            counterpart_original_record_scoped_finding_refs = $other.original_record_scoped_finding_refs
            anchor_pair_class = $kind
            anchor_changed_in_pair = [bool]$row.anchor_changed_in_pair
            shared_with_internal_unreported_position = $gap
            left_saved_finding_statement_count_at_anchor = [int]$leftCell.saved_finding_statement_count_at_anchor
            right_saved_finding_statement_count_at_anchor = [int]$rightCell.saved_finding_statement_count_at_anchor
        })
        $expectedPairIndex = $pairIndex
    }
    if ($compared.Count -ne ($n - 1) -or
        $changed -ne [int]$seedPairs.changed_anchor_pair_incidence_count -or
        $stable -ne [int]$seedPairs.stable_anchor_pair_incidence_count -or
        $changed + $stable -ne ($n - 1)) {
        throw 'Code Sequence selected Finding pair navigation is not complete.'
    }
    return [ordered]@{
        scope = 'one_explicit_original_record_scoped_Finding_ID_exact_saved_quote_anchor'
        path = $path
        original_record_id = $SeedRecordId
        original_finding_id = $SeedFindingId
        original_position = $seedPosition
        original_saved_severity = [string]$seedRef.severity
        anchor_index_in_anchor_journeys = $anchorIndex
        anchor = $anchor.anchor
        anchor_presence_pattern_in_caller_order = $pattern
        anchor_first_reported_position = $anchor.first_reported_position
        anchor_last_reported_position = $anchor.last_reported_position
        anchor_presence_runs = $anchor.presence_runs
        anchor_adjacent_transition_events = $anchor.transition_events
        independent_of_sequence_top = $true
        selected_record_count = $n
        counts = [ordered]@{
            anchor_reported_position_count = $reported
            original_record_scoped_finding_statement_occurrences_at_anchor = $statementSum
            counterpart_record_scoped_finding_reference_appearances_at_other_positions = $counterpartRefs
            compared_pair_count = $compared.Count
            changed_anchor_pair_count = $changed
            stable_anchor_pair_count = $stable
            pairs_with_internal_unreported_position_count = $gapCount
        }
        positions = $positionRows.ToArray()
        compared_pairs = $compared.ToArray()
        explanation = 'An explicitly selected ORIGINAL (record_id, Finding ID) is resolved only within its saved record and exact literal path. All other IDs refer to their OWN reports and the SAME six-field quote anchor, not a matched Finding or defect. Pair stability compares saved severity STATEMENT histograms, not real severity, unchanged prose, fixes, regressions, verified chronology or source freshness. All selected reports were already validated; no extra saved-body, source, Git or network access, writer, original quote or free-form Finding text. Complete output ignores SequenceTop.'
    }
}

#requires -Version 7.0
<#
    EC-043: One explicitly selected, 1-based canonical exact quote-anchor
    within one literal saved path -> EVERY original saved-report position and
    EVERY unordered caller-position pair, including both-unreported pairs.

    Operates only on the already checked EC-034/037/038/039/040 in-memory
    projections; no extra saved-body, Git, business-file or network I/O.
    IDs and severities belong to each ORIGINAL report; matching quote anchors
    cannot prove semantic Finding continuity, risk, fixes or real chronology.
#>
function Get-CodeSequenceFocusedSelectedAnchor {
    param(
        [int] $AnchorIndex,
        [object] $Journeys,
        [object] $Details,
        [object] $Lookup,
        [object] $References,
        [object] $PairReferences
    )

    $n = [int]$Journeys.selected_record_count
    $path = [string]$Journeys.path
    $anchorCount = $Journeys.anchors.Count
    $pairCount = [int](($n * ($n - 1)) / 2)
    if ($n -lt 2 -or $n -gt $script:CodeShowSequenceMaxRecords -or
        [string]::IsNullOrEmpty($path) -or $path.Length -gt 4096 -or
        $path.IndexOf([char]0) -ge 0 -or $anchorCount -gt ($n * 40) -or
        $Details.path -cne $path -or $Lookup.path -cne $path -or
        $References.path -cne $path -or $PairReferences.path -cne $path -or
        [int]$Details.selected_record_count -ne $n -or
        [int]$Lookup.selected_record_count -ne $n -or
        [int]$References.selected_record_count -ne $n -or
        [int]$PairReferences.selected_record_count -ne $n -or
        $Journeys.position_totals.Count -ne $n -or
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
        throw 'Code Sequence selected anchor requires five complete, matching, checked focused projections.'
    }
    if ($AnchorIndex -lt 1 -or $AnchorIndex -gt $anchorCount) {
        throw 'CODE_SHOW_SEQUENCE_ANCHOR_NOT_FOUND: selected canonical anchor index does not exist at this literal path.'
    }

    $anchor = $Journeys.anchors[$AnchorIndex - 1]
    $lookup = $Lookup.anchors[$AnchorIndex - 1]
    $idAnchor = $References.anchors[$AnchorIndex - 1]
    $pattern = [string]$anchor.presence_pattern
    if ($anchor.anchor.path -cne $path -or
        $pattern.Length -ne $n -or $pattern -match '[^01]' -or
        $anchor.observations_in_caller_order.Count -ne $n -or
        [int]$lookup.anchor_index_in_anchor_journeys -ne $AnchorIndex -or
        [int]$idAnchor.anchor_index_in_anchor_journeys -ne $AnchorIndex -or
        $lookup.presence_pattern -cne $pattern -or
        $idAnchor.presence_pattern -cne $pattern -or
        $lookup.reporting_record_count -ne $anchor.reporting_record_count -or
        $idAnchor.reporting_record_count -ne $anchor.reporting_record_count -or
        $idAnchor.finding_statement_occurrences -ne $anchor.finding_statement_occurrences) {
        throw 'Code Sequence selected anchor canonical identity, support or original Finding references disagree.'
    }

    # The EC-039 anchor-centric reference view has only reporting positions;
    # expand it into N complete positions, keeping zero-Finding gaps explicit.
    $sourceRefs = [object[]]::new($n)
    $lastReportedPosition = 0
    foreach ($r in $idAnchor.references_in_caller_order) {
        $pos = [int]$r.position
        if ($pos -le $lastReportedPosition -or $pos -gt $n -or
            $r.record_id -cne $Journeys.position_totals[$pos - 1].record_id) {
            throw 'Code Sequence selected anchor original reference positions are unsorted or foreign.'
        }
        $sourceRefs[$pos - 1] = $r
        $lastReportedPosition = $pos
    }
    $severityNames = @('critical', 'high', 'medium', 'low', 'info')
    $positions = [System.Collections.Generic.List[object]]::new()
    $reported = 0; $statements = 0
    for ($i = 0; $i -lt $n; $i++) {
        $cell = $anchor.observations_in_caller_order[$i]
        $record = $Journeys.position_totals[$i]
        $origin = $References.positions[$i]
        $source = $sourceRefs[$i]
        $present = ($null -ne $source)
        $refs = [System.Collections.Generic.List[object]]::new()
        $severityCounts = [ordered]@{ critical=0; high=0; medium=0; low=0; info=0 }
        if ([int]$cell.position -ne ($i + 1) -or
            [int]$record.position -ne ($i + 1) -or
            [int]$origin.position -ne ($i + 1) -or
            $cell.record_id -cne $record.record_id -or
            $origin.record_id -cne $record.record_id -or
            [bool]$cell.reported -ne $present -or
            ($pattern[$i] -eq [char]'1') -ne $present) {
            throw 'Code Sequence selected anchor contains a contradictory saved report position.'
        }
        if ($present) {
            if ($source.finding_refs.Count -lt 1 -or $source.finding_refs.Count -gt 40 -or
                [int]$source.finding_statement_count -ne $source.finding_refs.Count) {
                throw 'Code Sequence selected anchor has invalid original scoped reference multiplicity.'
            }
            $lastId = $null
            foreach ($f in $source.finding_refs) {
                $id = [string]$f.finding_id
                $severity = [string]$f.severity
                if ($id -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$' -or
                    ($null -ne $lastId -and [string]::CompareOrdinal($lastId, $id) -ge 0) -or
                    -not ($severityNames -ccontains $severity)) {
                    throw 'Code Sequence selected anchor original reference is malformed or unsorted.'
                }
                $matches = @($origin.finding_refs | Where-Object { $_.finding_id -ceq $id })
                if ($matches.Count -ne 1 -or
                    [int]$matches[0].anchor_index_in_anchor_journeys -ne $AnchorIndex -or
                    $matches[0].severity -cne $severity) {
                    throw 'Code Sequence selected anchor original Finding ID is not bound to this anchor.'
                }
                $refs.Add([ordered]@{ finding_id=$id; severity=$severity })
                $severityCounts[$severity] = [int]$severityCounts[$severity] + 1
                $lastId = $id
            }
            $reported++
        }
        if ([int]$cell.finding_statement_count -ne $refs.Count -or
            (($null -eq $cell.severity_statement_counts) -eq $present) -or
            ($present -and -not (Test-CodeSequenceFocusedSeverityEqual `
                -Left $severityCounts -Right $cell.severity_statement_counts))) {
            throw 'Code Sequence selected anchor saved original ID totals contradict the checked severity ledger.'
        }
        $statements += $refs.Count
        $positions.Add([ordered]@{
            position = $i + 1
            record_id = [string]$record.record_id
            reported_same_exact_saved_quote_anchor = $present
            saved_finding_statement_count_at_anchor = $refs.Count
            saved_severity_statement_counts = if ($present) { $severityCounts } else { $null }
            original_record_scoped_finding_refs = $refs.ToArray()
        })
    }
    if ($reported -ne [int]$anchor.reporting_record_count -or
        $reported -ne $idAnchor.references_in_caller_order.Count -or
        $statements -ne [int]$anchor.finding_statement_occurrences) {
        throw 'Code Sequence selected anchor source reporting and Finding-statement totals differ.'
    }

    # All unordered position pairs, not just the N-1 pairs of one seed
    # Finding. Each pair class is independently recalculated and checked
    # against BOTH EC-037 forward partitions and EC-038 inverse buckets.
    $classCounts = [ordered]@{
        left_only=0; right_only=0; retained_same_severity=0
        retained_changed_severity=0; both_unreported=0
    }
    $gapCount = 0
    $pairs = [System.Collections.Generic.List[object]]::new()
    for ($left = 0; $left -lt ($n - 1); $left++) {
        for ($right = $left + 1; $right -lt $n; $right++) {
            $number = $pairs.Count + 1
            $detail = $Details.pairs[$number - 1]
            $witnessPair = $PairReferences.pairs[$number - 1]
            $l = $positions[$left]; $r = $positions[$right]
            if ([int]$detail.pair_index -ne $number -or
                [int]$witnessPair.pair_index -ne $number -or
                [int]$detail.left_position -ne ($left + 1) -or
                [int]$detail.right_position -ne ($right + 1) -or
                $detail.left_record_id -cne $l.record_id -or
                $detail.right_record_id -cne $r.record_id) {
                throw 'Code Sequence selected anchor pair order or report scope is not canonical.'
            }
            $was = [bool]$l.reported_same_exact_saved_quote_anchor
            $now = [bool]$r.reported_same_exact_saved_quote_anchor
            $kind = if ($was -and $now) {
                if (Test-CodeSequenceFocusedSeverityEqual -Left $l.saved_severity_statement_counts `
                        -Right $r.saved_severity_statement_counts) {
                    'retained_same_severity'
                } else { 'retained_changed_severity' }
            } elseif ($was) { 'left_only' }
            elseif ($now) { 'right_only' }
            else { 'both_unreported' }
            $partitions = @(
                [pscustomobject]@{ name='left_only'; d=$detail.left_only_anchor_indices; l=$lookup.left_only_pair_indices },
                [pscustomobject]@{ name='right_only'; d=$detail.right_only_anchor_indices; l=$lookup.right_only_pair_indices },
                [pscustomobject]@{ name='retained_same_severity'; d=$detail.retained_same_severity_anchor_indices; l=$lookup.retained_same_severity_pair_indices },
                [pscustomobject]@{ name='retained_changed_severity'; d=$detail.retained_changed_severity_anchor_indices; l=$lookup.retained_changed_severity_pair_indices },
                [pscustomobject]@{ name='both_unreported'; d=$detail.both_unreported_anchor_indices; l=$lookup.both_unreported_pair_indices }
            )
            foreach ($part in $partitions) {
                $expected = ($part.name -ceq $kind)
                if (($part.d -contains $AnchorIndex) -ne $expected -or
                    ($part.l -contains $number) -ne $expected) {
                    throw 'Code Sequence selected anchor pair does not match checked forward and inverse classes.'
                }
            }
            $gap = $false
            if ($was -and $now) {
                for ($middle = $left + 1; $middle -lt $right; $middle++) {
                    if (-not $positions[$middle].reported_same_exact_saved_quote_anchor) {
                        $gap = $true; break
                    }
                }
            }
            if (($detail.shared_with_internal_unreported_position_anchor_indices -contains $AnchorIndex) -ne $gap -or
                ($lookup.shared_with_internal_unreported_position_pair_indices -contains $number) -ne $gap) {
                throw 'Code Sequence selected anchor pair gap diverges from checked overlapping gap witnesses.'
            }
            if ($gap) { $gapCount++ }
            $classCounts[$kind] = [int]$classCounts[$kind] + 1

            $delta = [ordered]@{ critical=0; high=0; medium=0; low=0; info=0 }
            foreach ($severity in $severityNames) {
                $leftValue = if ($was) { [int]$l.saved_severity_statement_counts[$severity] } else { 0 }
                $rightValue = if ($now) { [int]$r.saved_severity_statement_counts[$severity] } else { 0 }
                $delta[$severity] = $rightValue - $leftValue
            }
            $witnesses = @($witnessPair.changed_anchors | Where-Object {
                [int]$_.anchor_index_in_anchor_journeys -eq $AnchorIndex
            })
            $changed = ($kind -in @('left_only','right_only','retained_changed_severity'))
            if ($witnesses.Count -ne $(if ($changed) { 1 } else { 0 })) {
                throw 'Code Sequence selected anchor changed-pair original ID witness is missing or unexpected.'
            }
            if ($changed) {
                $w = $witnesses[0]
                if ($w.contrast_kind -cne $kind) {
                    throw 'Code Sequence selected anchor changed-pair kind differs from original ID witness.'
                }
                foreach ($side in @('left','right')) {
                    $expected = if ($side -eq 'left') { $l.original_record_scoped_finding_refs } else { $r.original_record_scoped_finding_refs }
                    $actual = if ($side -eq 'left') { $w.left_finding_refs } else { $w.right_finding_refs }
                    if ($actual.Count -ne $expected.Count) {
                        throw 'Code Sequence selected anchor changed-pair original ID witness count differs.'
                    }
                    for ($j = 0; $j -lt $expected.Count; $j++) {
                        if ($actual[$j].finding_id -cne $expected[$j].finding_id -or
                            $actual[$j].severity -cne $expected[$j].severity) {
                            throw 'Code Sequence selected anchor changed-pair original ID witness differs.'
                        }
                    }
                }
            }
            $changeEvents = @($lookup.retained_changed_severity_events | Where-Object { [int]$_.pair_index -eq $number })
            if ($changeEvents.Count -ne $(if ($kind -ceq 'retained_changed_severity') { 1 } else { 0 })) {
                throw 'Code Sequence selected anchor severity change event membership differs from inverse pair history.'
            }
            if ($changeEvents.Count -eq 1) {
                $event = $changeEvents[0]
                if ([int]$event.left_position -ne ($left + 1) -or
                    [int]$event.right_position -ne ($right + 1) -or
                    [int]$event.finding_statement_count_delta -ne
                        ([int]$r.saved_finding_statement_count_at_anchor - [int]$l.saved_finding_statement_count_at_anchor) -or
                    [bool]$event.shared_with_internal_unreported_position -ne $gap) {
                    throw 'Code Sequence selected anchor saved-severity event positions or statement delta changed.'
                }
                foreach ($severity in $severityNames) {
                    if ([int]$event.severity_statement_delta[$severity] -ne [int]$delta[$severity]) {
                        throw 'Code Sequence selected anchor severity event signed delta changed.'
                    }
                }
            }
            $pairs.Add([ordered]@{
                pair_index = $number
                left_position = $left + 1
                right_position = $right + 1
                left_record_id = [string]$l.record_id
                right_record_id = [string]$r.record_id
                anchor_pair_class = $kind
                anchor_changed_in_pair = $changed
                shared_with_internal_unreported_position = $gap
                left_saved_finding_statement_count_at_anchor = [int]$l.saved_finding_statement_count_at_anchor
                right_saved_finding_statement_count_at_anchor = [int]$r.saved_finding_statement_count_at_anchor
                saved_finding_statement_count_delta_right_minus_left = [int]$r.saved_finding_statement_count_at_anchor - [int]$l.saved_finding_statement_count_at_anchor
                saved_severity_statement_delta_right_minus_left = $delta
                original_id_reference = 'positions[left_position-1/right_position-1].original_record_scoped_finding_refs'
            })
        }
    }
    if ($pairs.Count -ne $pairCount -or
        ($classCounts.left_only + $classCounts.right_only + $classCounts.retained_same_severity +
         $classCounts.retained_changed_severity + $classCounts.both_unreported) -ne $pairCount -or
        $classCounts.left_only -ne $lookup.left_only_pair_indices.Count -or
        $classCounts.right_only -ne $lookup.right_only_pair_indices.Count -or
        $classCounts.retained_same_severity -ne $lookup.retained_same_severity_pair_indices.Count -or
        $classCounts.retained_changed_severity -ne $lookup.retained_changed_severity_pair_indices.Count -or
        $classCounts.both_unreported -ne $lookup.both_unreported_pair_indices.Count -or
        $gapCount -ne $lookup.shared_with_internal_unreported_position_pair_indices.Count -or
        $classCounts.left_only + $classCounts.right_only + $classCounts.retained_changed_severity -ne [int]$lookup.changed_pair_count) {
        throw 'Code Sequence selected anchor failed complete all-pair classification conservation.'
    }

    return [ordered]@{
        scope = 'one_explicit_canonical_exact_saved_quote_anchor_all_selected_positions_and_all_pairs'
        path = $path
        anchor_index_in_anchor_journeys = $AnchorIndex
        anchor = $anchor.anchor
        anchor_presence_pattern_in_caller_order = $pattern
        anchor_first_reported_position = $anchor.first_reported_position
        anchor_last_reported_position = $anchor.last_reported_position
        anchor_presence_runs = $anchor.presence_runs
        anchor_adjacent_transition_events = $anchor.transition_events
        independent_of_sequence_top = $true
        selected_record_count = $n
        counts = [ordered]@{
            reported_position_count = $reported
            original_record_scoped_finding_statement_occurrences = $statements
            compared_pair_count = $pairCount
            left_only_pair_count = [int]$classCounts.left_only
            right_only_pair_count = [int]$classCounts.right_only
            retained_same_severity_pair_count = [int]$classCounts.retained_same_severity
            retained_changed_severity_pair_count = [int]$classCounts.retained_changed_severity
            both_unreported_pair_count = [int]$classCounts.both_unreported
            changed_pair_count = [int]($classCounts.left_only + $classCounts.right_only + $classCounts.retained_changed_severity)
            shared_with_internal_unreported_position_pair_count = $gapCount
        }
        positions = $positions.ToArray()
        compared_pairs = $pairs.ToArray()
        explanation = 'This canonical one-based anchor index is valid ONLY for this selected record set and literal saved path. Every unordered pair is returned, including pairs where neither selected report mentioned the anchor. Original Finding IDs and their saved severity labels are scoped to each record in positions; compare pairs by their position references, NOT matched IDs. Same saved quote anchor, equal saved severity-statement histogram, absent mentions and caller order cannot prove a real defect, its importance, a fix, regression, semantic continuity or chronology. Read only; no source file, Git, network, extra saved body, quotation or model prose.'
    }
}

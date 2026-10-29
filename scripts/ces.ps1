#requires -Version 7.0
<#
.SYNOPSIS
    CES 1.0 command-line entry point.
.DESCRIPTION
    Implements Inspect, Collect WorkingTree/DeliveredTarget, Reconcile Snapshot and
    read-only CodePrepare/CodeValidate Snapshot, explicit local CodeSave and
    read-only CodeShow List/Detail/Findings/Compare/Trace/Overview/Triage/Recurrence/Sequence. Other actions return NOT_IMPLEMENTED. Git
    reads never mutate source, index or branches; only authorized CodeSave
    writes CES-owned metadata.
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Inspect -RepoPath /path/to/repo -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Collect -Mode WorkingTree -RepoPath /path/to/repo -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Collect -Mode DeliveredTarget -RepoPath /path/to/repo -BaseSha <full> -TargetSha <full> -TargetRef refs/heads/main -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action Reconcile -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodePrepare -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeValidate -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -InputPath /path/to/review-draft.json -IncludePatches -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeSave -Mode Snapshot -RepoPath /path/to/repo -EvidencePath /path/to/saved-collect.json -InputPath /path/to/review-draft.json -IncludePatches -ApprovePersist -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode List -RepoPath /path/to/repo -Limit 50 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Detail -RepoPath /path/to/repo -RecordId ci-<sha256> -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Findings -RepoPath /path/to/repo -FindingSeverity high -Limit 25 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Findings -RepoPath /path/to/repo -FindingsRecordIds 'ci-<sha256>,ci-<sha256>' -FindingSeverity high -Limit 25 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Compare -RepoPath /path/to/repo -LeftRecordId ci-<sha256> -RightRecordId ci-<sha256> -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Trace -RepoPath /path/to/repo -RecordId ci-<sha256> -FindingId F1 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Trace -RepoPath /path/to/repo -RecordId ci-<sha256> -FindingId F1 -TraceRecordIds 'ci-<seed-sha256>,ci-<other-sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Overview -RepoPath /path/to/repo -OverviewSourceMode working_tree_diff -Limit 10 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Overview -RepoPath /path/to/repo -OverviewRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Triage -RepoPath /path/to/repo -TriageSourceMode working_tree_diff -TriageTop 15 -Limit 24 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Triage -RepoPath /path/to/repo -TriageRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Recurrence -RepoPath /path/to/repo -RecurrenceSourceMode working_tree_diff -RecurrenceMinRecords 2 -RecurrenceTop 15 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Recurrence -RepoPath /path/to/repo -RecurrenceRecordIds 'ci-<sha256>,ci-<sha256>' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequenceTop 10 -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -Json
.EXAMPLE
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequenceFindingRecordId ci-<first> -SequenceFindingId F1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequenceAnchorIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePath 'src/module.ps1' -SequencePairIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -SequencePairPathAnchorFindingSide left -SequencePairPathAnchorFindingIndex 1 -Json
    pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath /path/to/repo -SequenceRecordIds 'ci-<first>,ci-<second>' -SequencePairOverviewIndex 1 -SequencePairPathIndex 1 -SequencePairPathAnchorIndex 1 -SequencePairPathAnchorFindingSide left -SequencePairPathAnchorFindingIndex 1 -SequencePairPathAnchorFindingCounterpartIndex 1 -Json
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $Action = 'Inspect',

    [Parameter()]
    [AllowEmptyString()]
    [string] $RepoPath,

    [Parameter()]
    [switch] $Json,

    [Parameter()]
    [string] $Mode = 'WorkingTree',

    [Parameter()]
    [switch] $IncludePatches,

    [Parameter()]
    [switch] $IncludeUntrackedContent,

    [Parameter()]
    [AllowEmptyString()]
    [string] $BaseSha,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TargetSha,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TargetRef,

    [Parameter()]
    [AllowEmptyString()]
    [string] $EvidencePath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $InputPath,

    [Parameter()]
    [switch] $ApprovePersist,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterRecordId,

    [Parameter()]
    [int] $Limit = 50,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterFindingCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingSeverity,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingLayer,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingPath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingsRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $LeftRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RightRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $FindingId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterTraceCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TraceRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterOverviewCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $OverviewSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $OverviewRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterTriageCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TriageSourceMode,

    [Parameter()]
    [int] $TriageTop = 15,

    [Parameter()]
    [AllowEmptyString()]
    [string] $TriageRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $AfterRecurrenceCursor,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrenceSourceMode,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrencePath,

    [Parameter()]
    [int] $RecurrenceMinRecords = 2,

    [Parameter()]
    [int] $RecurrenceTop = 15,

    [Parameter()]
    [AllowEmptyString()]
    [string] $RecurrenceRecordIds,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceRecordIds,

    [Parameter()]
    [int] $SequenceTop = 10,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePath,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceFindingRecordId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceFindingId,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequenceAnchorIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairOverviewIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingSide,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingIndex,

    [Parameter()]
    [AllowEmptyString()]
    [string] $SequencePairPathAnchorFindingCounterpartIndex
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ProductVersion = '1.0.0'
$script:Build = '1.0.0'
$script:SchemaVersion = 'ces.cli.v1'
$script:GitTimeoutMilliseconds = 15000

function New-Envelope {
    param([string] $ActionName)

    return [ordered]@{
        schema_version = $script:SchemaVersion
        product_version = $script:ProductVersion
        build = $script:Build
        action = $ActionName
        status = 'unavailable'
        reason_code = 'UNINITIALIZED'
        next_step = 'none'
        message = ''
        supported_actions = @('Inspect', 'Collect', 'Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave', 'CodeShow')
        supported_collect_modes = @('WorkingTree', 'DeliveredTarget')
        supported_codeshow_modes = @('List', 'Detail', 'Findings', 'Compare', 'Trace', 'Overview', 'Triage', 'Recurrence', 'Sequence')
        read_only = $true
        data = $null
        coverage = [ordered]@{
            repository_checked = $false
            worktree_checked = $false
            stable_root_verified = $false
            head_checked = $false
            index_or_worktree_changes_checked = $false
            remote_or_ci_checked = $false
            staged_paths_checked = $false
            unstaged_paths_checked = $false
            untracked_paths_checked = $false
            staged_patch_checked = $false
            unstaged_patch_checked = $false
            untracked_content_checked = $false
            consistency_checked = $false
            target_ref_checked = $false
            base_commit_checked = $false
            target_commit_checked = $false
            ancestry_checked = $false
            delivered_paths_checked = $false
            delivered_patch_checked = $false
            snapshot_file_checked = $false
            snapshot_file_stable = $false
            source_bound = $false
            compared_inventory = $false
            compared_content = $false
            content_release_authorized = $false
            code_packet_built = $false
            code_draft_checked = $false
            code_findings_anchored = $false
            code_result_persisted = $false
            code_store_checked = $false
            code_records_integrity_checked = $false
        }
        warnings = @()
        evidence = @()
    }
}

function Finish {
    param(
        [System.Collections.IDictionary] $Envelope,
        [int] $ExitCode
    )

    if ($Json) {
        # An invocation with -Json emits exactly one JSON object on stdout.
        # EC-091 nests per-report, per-partner and per-gap exact fractions one
        # level deeper than EC-090. Keep those fractions as structured JSON
        # objects in successful Sequence envelopes; do not stringify them at
        # the default depth and do not alter unrelated action serialization.
        $jsonDepth = if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence') { 20 } else { 12 }
        Write-Output (ConvertTo-Json -InputObject $Envelope -Depth $jsonDepth -Compress)
    } else {
        Write-Output "CES $($Envelope.product_version) / $($Envelope.build) — $($Envelope.action)"
        Write-Output "Status: $($Envelope.status) ($($Envelope.reason_code))"
        if ($Envelope.message) { Write-Output $Envelope.message }
        if ($null -ne $Envelope.data) {
            $data = $Envelope.data
            # Not every action has Inspect's data shape. In strict mode,
            # reading a nonexistent nested key (for example CodeShow.head)
            # would turn a successful non-JSON result into a formatting error.
            if ($data -is [System.Collections.IDictionary]) {
                $displayLabels = [ordered]@{
                    source_root = 'Source root'
                    stable_project_root = 'Stable root'
                    stable_root_verified = 'Stable root verified'
                    worktree_kind = 'Worktree kind'
                }
                foreach ($field in $displayLabels.Keys) {
                    if ($data.Contains($field)) {
                        Write-Output ("{0}: {1}" -f $displayLabels[$field], $data[$field])
                    }
                }
                if ($data.Contains('head') -and $null -ne $data['head']) {
                    Write-Output "HEAD: $($data.head.sha) ($($data.head.state))"
                }
            }
            if ($Envelope.action -ieq 'CodePrepare' -and $data -is [System.Collections.IDictionary] -and $data.Contains('prepared')) {
                Write-Output "Prepared: $($data.prepared)"
                if ($data.Contains('scope')) { Write-Output "Source mode: $($data.scope.source_mode)" }
                if ($data.Contains('preparation')) {
                    Write-Output "Saved evidence SHA-256: $($data.preparation.saved_collect_sha256)"
                    foreach ($requirement in $data.preparation.missing_requirements) { Write-Output "Needs: $requirement" }
                }
            }
            if ($Envelope.action -ieq 'CodeShow' -and $data -is [System.Collections.IDictionary] -and $data.Contains('mode')) {
                Write-Output "Query mode: $($data.mode)"
                if ($data.mode -eq 'List') {
                    Write-Output "Records returned: $($data.returned_count) of $($data.record_count)"
                    Write-Output "More available: $($data.has_more)"
                    if ($data.next_after_record_id) { Write-Output "Next cursor: $($data.next_after_record_id)" }
                    foreach ($item in $data.records) { Write-Output "Record: $($item.record_id) ($($item.finding_count) findings)" }
                } elseif ($data.mode -eq 'Findings') {
                    Write-Output "Findings returned: $($data.returned_count)"
                    Write-Output "Records checked this page: $($data.scanned_record_count) of $($data.record_count)"
                    Write-Output "More candidate records/findings: $($data.has_more_candidates)"
                    if ($data.next_after_finding_cursor) { Write-Output "Next cursor: $($data.next_after_finding_cursor)" }
                    foreach ($item in $data.findings) {
                        Write-Output "Finding: $($item.record_id) / $($item.finding.id) [$($item.finding.severity)] $($item.finding.path)"
                    }
                } elseif ($data.mode -eq 'Overview') {
                    Write-Output "Evidence scope: $($data.selection_scope)"
                    if ($data.selection_scope -eq 'selected_record_ids') {
                        Write-Output "Explicit selected records: $($data.selected_record_count)"
                        foreach ($id in $data.selected_record_ids) { Write-Output "Selected record: $id" }
                    }
                    Write-Output "Included records in this scope: $($data.included_record_count)"
                    Write-Output "Finding statements in this scope: $($data.finding_statement_count)"
                    Write-Output "Distinct exact anchors in this scope: $($data.counts.distinct_exact_anchor_count)"
                    Write-Output "Cross-record repeated anchors in this scope: $($data.counts.cross_record_anchor_count)"
                    Write-Output "Scanned records: $($data.scanned_record_count) of $($data.record_count)"
                    Write-Output "More candidate records: $($data.has_more_candidates)"
                    if ($data.next_after_overview_cursor) { Write-Output "Next cursor: $($data.next_after_overview_cursor)" }
                    Write-Output $data.explanation
                } elseif ($data.mode -eq 'Triage') {
                    Write-Output "Included records in this page: $($data.included_record_count)"
                    Write-Output "Finding statements in this page: $($data.finding_statement_count)"
                    Write-Output "Path groups ranked: $($data.returned_group_count) of $($data.path_group_count)"
                    Write-Output "Scanned records: $($data.scanned_record_count) of $($data.record_count)"
                    Write-Output "More candidate records: $($data.has_more_candidates)"
                    if ($data.next_after_triage_cursor) { Write-Output "Next cursor: $($data.next_after_triage_cursor)" }
                    foreach ($item in $data.path_groups) {
                        Write-Output "Path: [$($item.highest_reported_severity)] $($item.source_mode) / $($item.path_exact) ($($item.path_endpoint); $($item.reporting_record_count) records, $($item.finding_statement_count) statements)"
                    }
                    Write-Output $data.explanation
                } elseif ($data.mode -eq 'Recurrence') {
                    Write-Output "Evidence scope: $($data.selection_scope)"
                    if ($data.selection_scope -eq 'selected_record_ids') {
                        Write-Output "Explicit selected records: $($data.selected_record_count)"
                        foreach ($id in $data.selected_record_ids) { Write-Output "Selected record: $id" }
                        Write-Output "Included selected records: $($data.included_record_count)"
                    } else {
                        Write-Output "Included records in this page: $($data.included_record_count)"
                    }
                    Write-Output "Finding statements matching filters: $($data.finding_statement_count)"
                    Write-Output "Repeated anchors returned: $($data.returned_anchor_count) of $($data.eligible_anchor_count)"
                    Write-Output "Scanned records: $($data.scanned_record_count) of $($data.record_count)"
                    Write-Output "More candidate records: $($data.has_more_candidates)"
                    if ($data.next_after_recurrence_cursor) { Write-Output "Next cursor: $($data.next_after_recurrence_cursor)" }
                    foreach ($item in $data.anchors) {
                        Write-Output "Anchor: $($item.anchor.path) [$($item.highest_reported_severity)] ($($item.reporting_record_count) records, $($item.finding_statement_count) statements)"
                    }
                    Write-Output $data.explanation
                } elseif ($data.mode -eq 'Sequence') {
                    Write-Output "Caller-ordered selected records: $($data.selected_record_count)"
                    Write-Output "Adjacent comparison steps: $($data.step_count)"
                    $trajectory = $data.anchor_trajectory
                    if ($null -ne $trajectory) {
                        Write-Output "Exact anchors across selection: $($trajectory.counts.distinct_exact_anchor_union_count)"
                        Write-Output "Reported in all / one / some records: $($trajectory.counts.reported_in_every_record_count) / $($trajectory.counts.reported_once_count) / $($trajectory.counts.reported_in_multiple_but_not_every_record_count)"
                        Write-Output "Reappeared after unreported position: $($trajectory.counts.reappeared_after_at_least_one_unreported_position_count)"
                        Write-Output "Reported severity distribution varied: $($trajectory.counts.severity_distribution_varied_across_reported_positions_count)"
                        Write-Output "Presence transitions over adjacent pairs: $($trajectory.counts.presence_transitions_across_adjacent_pairs_count)"
                        Write-Output "Trajectory previews truncated: $($trajectory.previews_truncated)"
                    }
                    if ($null -ne $data.path_index) {
                        $paths = $data.path_index
                        Write-Output "Historical saved paths: $($paths.counts.distinct_saved_path_count)"
                        Write-Output "Path reporting transitions / exact-anchor transitions: $($paths.counts.path_presence_transitions_across_adjacent_pairs_count) / $($paths.counts.exact_anchor_presence_transitions_across_adjacent_pairs_count)"
                        Write-Output "Path index previews omitted: $($paths.omitted_paths) (ranked by exact-anchor report churn, not risk)"
                        foreach ($entry in $paths.paths) {
                            Write-Output "Saved path: $($entry.path) [pattern=$($entry.presence_pattern), records=$($entry.reporting_record_count), anchor transitions=$($entry.exact_anchor_presence_transitions_across_adjacent_pairs_count)]"
                        }
                        if ($null -ne $paths.change_profile) {
                            $profile = $paths.change_profile
                            Write-Output "Saved paths changing in any / multiple adjacent steps: $($profile.counts.paths_with_any_changed_step_count) / $($profile.counts.paths_changed_in_multiple_steps_count)"
                            Write-Output "Historical changed-path step occurrences: $($profile.counts.changed_path_step_occurrences) (severity-only=$($profile.counts.retained_severity_only_path_step_occurrences))"
                            Write-Output "Cross-step hotspot previews omitted: $($profile.omitted_hotspots) (changed steps first, not risk)"
                            foreach ($hotspot in $profile.hotspots) {
                                Write-Output "  Repeated-change saved path: $($hotspot.path) [changed steps=$($hotspot.changed_step_count), longest run=$($hotspot.longest_consecutive_changed_step_run), anchor transitions=$($hotspot.exact_anchor_presence_transitions_across_adjacent_pairs_count)]"
                                foreach ($change in $hotspot.changes_in_caller_order) {
                                    Write-Output "    Step $($change.step): $($change.kind) [anchor transitions=$($change.exact_anchor_presence_transitions_count), retained severity changes=$($change.retained_severity_distribution_changed_count)]"
                                }
                            }
                        }
                        foreach ($delta in $paths.step_deltas) {
                            Write-Output "Path step $($delta.step): retained=$($delta.counts.retained_path_count), previous-only=$($delta.counts.previous_only_path_count), next-only=$($delta.counts.next_only_path_count), retained-with-anchor-churn=$($delta.counts.retained_path_with_anchor_churn_count), retained-with-severity-change=$($delta.counts.retained_path_with_severity_distribution_change_count)"
                            Write-Output "  Exact-anchor transitions=$($delta.counts.exact_anchor_presence_transitions_across_adjacent_pairs_count), changed paths=$($delta.counts.changed_path_count), preview omitted=$($delta.omitted_changed_paths)"
                            foreach ($change in $delta.changed_paths) {
                                Write-Output "  Changed saved path: $($change.path) [$($change.path_status); exact-anchor transitions=$($change.exact_anchor_presence_transitions_across_adjacent_pairs_count); retained severity changes=$($change.retained_severity_distribution_changed_count)]"
                            }
                        }
                    }
                    if ($null -ne $data.baseline_drift) {
                        $baseline = $data.baseline_drift
                        Write-Output "Baseline selected saved record: $($baseline.baseline_record_id) (caller position 1)"
                        Write-Output "Baseline profile matches / differences / returns: $($baseline.counts.matches_baseline_profile_position_count) / $($baseline.counts.differs_from_baseline_profile_position_count) / $($baseline.counts.returns_to_baseline_profile_after_previous_difference_position_count)"
                        Write-Output "Latest selected profile matches baseline: $($baseline.last_position_matches_baseline_profile)"
                        foreach ($comparison in $baseline.comparisons) {
                            Write-Output "Baseline vs selected position $($comparison.compared_position): $($comparison.compared_record_id) [matching profile=$($comparison.matches_baseline_profile), returned after prior difference=$($comparison.returns_to_baseline_profile_after_previous_difference)]"
                            Write-Output "  Changed saved paths=$($comparison.counts.changed_path_count), exact-anchor symmetric difference=$($comparison.counts.exact_anchor_symmetric_difference_count), changed retained severities=$($comparison.counts.retained_severity_distribution_changed_count), path previews omitted=$($comparison.omitted_changed_paths)"
                            foreach ($changed in $comparison.changed_paths) {
                                Write-Output "  Baseline-different path: $($changed.path) [$($changed.comparison_status), anchor symmetric difference=$($changed.exact_anchor_symmetric_difference_count), changed retained severities=$($changed.retained_severity_distribution_changed_count)]"
                            }
                        }
                    }
                    if ($null -ne $data.baseline_drift -and $null -ne $data.baseline_drift.path_persistence) {
                        $persistence = $data.baseline_drift.path_persistence
                        Write-Output "Saved paths deviating from first profile at least once / more than once: $($persistence.counts.paths_ever_deviating_from_baseline_count) / $($persistence.counts.paths_deviating_in_multiple_comparisons_count)"
                        Write-Output "Saved paths still different at last selected position: $($persistence.counts.paths_deviating_at_last_selected_position_count)"
                        Write-Output "Saved path-profile returns / severity-only deviation occurrences: $($persistence.counts.return_to_baseline_path_position_occurrences) / $($persistence.counts.severity_histogram_only_deviation_path_position_occurrences)"
                        Write-Output "Baseline path persistence hotspots omitted: $($persistence.omitted_hotspots) (frequency ranked; not defect or risk priority)"
                        foreach ($entry in $persistence.hotspots) {
                            Write-Output "  Baseline-persistent path: $($entry.path) [deviation pattern=$($entry.deviation_from_baseline_pattern), comparisons=$($entry.deviating_comparison_count), returns=$($entry.returns_to_baseline_after_previous_difference_count)]"
                        }
                    }
                    if ($null -ne $data.pairwise_profile) {
                        $pairs = $data.pairwise_profile
                        Write-Output "All unordered selected-report pairs: $($pairs.pair_count) (matching=$($pairs.counts.matching_profile_pair_count), differing=$($pairs.counts.differing_profile_pair_count), severity-only=$($pairs.counts.severity_histogram_only_difference_pair_count))"
                        Write-Output "Exact saved-report profile classes: $($pairs.counts.distinct_profile_class_count) (repeated=$($pairs.counts.repeated_profile_class_count), singleton=$($pairs.counts.singleton_profile_class_count))"
                        Write-Output "Pairwise changed-path / anchor-difference occurrences: $($pairs.counts.changed_path_pair_occurrences) / $($pairs.counts.exact_anchor_symmetric_difference_pair_occurrences)"
                        foreach ($profileClass in $pairs.profile_classes) {
                            if ($profileClass.repeated) {
                                Write-Output "  Repeated profile class $($profileClass.profile_class): positions=$($profileClass.positions -join ',') [members=$($profileClass.member_count)]"
                            }
                        }
                        if ($null -ne $pairs.path_profile_classes) {
                            $classesByPath = $pairs.path_profile_classes
                            Write-Output "Saved-path exact profile classes: $($classesByPath.counts.total_path_profile_class_count) (changing paths=$($classesByPath.counts.paths_with_multiple_profile_classes_count), matching paths=$($classesByPath.counts.paths_with_single_profile_class_count))"
                            Write-Output "Paths reusing a reported profile / with unreported positions: $($classesByPath.counts.paths_with_reused_reported_profile_count) / $($classesByPath.counts.paths_with_unreported_positions_count)"
                            Write-Output "Saved-path profile-class previews omitted: $($classesByPath.omitted_hotspots) (class-diversity ranked, not risk or verified chronology)"
                            foreach ($entry in $classesByPath.hotspots) {
                                $members = @($entry.profile_classes | ForEach-Object { "$($_.profile_class):$($_.positions -join ',')" }) -join '; '
                                Write-Output "  Diverse saved path: $($entry.path) [classes=$($entry.distinct_profile_class_count), differing pairs=$($entry.differing_pair_count), position classes=$members]"
                            }
                        }
                        if ($null -ne $pairs.path_profile_transitions) {
                            $journeys = $pairs.path_profile_transitions
                            Write-Output "Saved-path profile transitions: $($journeys.counts.adjacent_profile_transition_occurrences) across $($journeys.counts.paths_with_profile_transitions_count) paths; returns=$($journeys.counts.return_to_prior_profile_occurrences), reported-after-gap=$($journeys.counts.reported_again_after_unreported_gap_occurrences)"
                            Write-Output "Path transitions hotspots omitted: $($journeys.omitted_hotspots) (caller-selected position order, not verified chronology or risk)"
                            foreach ($entry in $journeys.hotspots) {
                                $classes = @($entry.position_profile_classes | ForEach-Object { $_.profile_class }) -join '>'
                                Write-Output "  Transition path: $($entry.path) [class positions=$classes, changes=$($entry.profile_transition_count), prior-class returns=$($entry.return_to_prior_profile_count), runs=$($entry.profile_runs.Count)]"
                            }
                        }
                        if ($null -ne $pairs.path_disagreement) {
                            $atlas = $pairs.path_disagreement
                            Write-Output "All-pairs saved paths: $($atlas.counts.distinct_saved_path_union_count) (different in at least one pair=$($atlas.counts.paths_differing_in_at_least_one_pair_count), always matching=$($atlas.counts.paths_matching_in_all_pairs_count))"
                            Write-Output "Path/pair changed / matching occurrences: $($atlas.counts.changed_path_pair_occurrences) / $($atlas.counts.matching_path_pair_occurrences) (severity-only path/pairs=$($atlas.counts.severity_histogram_only_difference_path_pair_occurrences))"
                            Write-Output "All-pairs path hotspots omitted: $($atlas.omitted_hotspots) (frequency-ranked, not risk or verified chronology)"
                            foreach ($entry in $atlas.hotspots) {
                                Write-Output "  All-pairs differing path: $($entry.path) [different pairs=$($entry.differing_pair_count), matching pairs=$($entry.matching_pair_count), anchor difference occurrences=$($entry.exact_anchor_symmetric_difference_pair_occurrences)]"
                            }
                        }
                    }
                    if ($null -ne $data.selected_pair_overview) {
                        $overview = $data.selected_pair_overview
                        Write-Output "Selected report pair (all saved paths): #$($overview.pair_index_in_pairwise_profile), positions $($overview.left_position)->$($overview.right_position), union paths=$($overview.counts.distinct_saved_path_union_count), changed=$($overview.counts.changed_path_count), matching=$($overview.counts.matching_path_count)"
                        Write-Output "Pair path classes: left-only=$($overview.counts.left_only_path_count), right-only=$($overview.counts.right_only_path_count), neither-reported=$($overview.counts.neither_reported_path_count), retained with changed severity=$($overview.counts.retained_path_with_severity_distribution_change_count)"
                        foreach ($changedIndex in @($overview.changed_path_indices | Select-Object -First 8)) {
                            $entry = $overview.paths[[int]$changedIndex - 1]
                            Write-Output "  Changed saved path: $($entry.path) [$($entry.pair_path_class); left anchors=$($entry.left.distinct_exact_anchor_count), right anchors=$($entry.right.distinct_exact_anchor_count)]"
                        }
                        Write-Output 'Complete ordinal paths, counts, signed saved-severity deltas and independently scoped original Finding IDs are available in JSON selected_pair_overview.'
                    }
                    if ($data.Contains('selected_pair_path_selection') -and $null -ne $data.selected_pair_path_selection) {
                        $navigation = $data.selected_pair_path_selection
                        Write-Output "Indexed pair path: pair #$($navigation.pair_index_in_pairwise_profile), path #$($navigation.path_index_in_selected_pair_overview): $($navigation.path) [$($navigation.pair_path_class)]"
                        Write-Output "Complete exact anchors=$($navigation.complete_anchor_union_count), both endpoints unreported=$($navigation.both_endpoints_unreported_anchor_count); see JSON path_focus.selected_pair for both original scoped ID sets."
                    }
                    if ($data.Contains('selected_pair_path_anchor_selection') -and $null -ne $data.selected_pair_path_anchor_selection) {
                        $choice = $data.selected_pair_path_anchor_selection
                        Write-Output "Indexed pair/path anchor: pair #$($choice.pair_index_in_pairwise_profile), path #$($choice.path_index_in_selected_pair_overview), anchor #$($choice.anchor_index_in_anchor_journeys) [$($choice.anchor_pair_class)]"
                        Write-Output "Original endpoint Finding IDs: left=$($choice.left.original_record_scoped_finding_refs.Count), right=$($choice.right.original_record_scoped_finding_refs.Count); complete all-position/all-pair evidence is in JSON path_focus.selected_anchor."
                    }
                    if ($data.Contains('selected_pair_path_anchor_finding_selection') -and $null -ne $data.selected_pair_path_anchor_finding_selection) {
                        $findingNavigation = $data.selected_pair_path_anchor_finding_selection
                        Write-Output "Indexed original Finding: pair #$($findingNavigation.pair_index_in_pairwise_profile), path #$($findingNavigation.path_index_in_selected_pair_overview), anchor #$($findingNavigation.anchor_index_in_anchor_journeys), $($findingNavigation.finding_side) #$($findingNavigation.finding_index_in_endpoint_anchor) of $($findingNavigation.finding_count_at_endpoint_anchor): $($findingNavigation.original_record_id)/$($findingNavigation.original_finding_id) [$($findingNavigation.original_saved_severity)]"
                        Write-Output 'Complete original Finding journey (all positions and seed-related pairs) is in JSON path_focus.selected_finding; exact-anchor all-pairs remains in selected_anchor.'
                    }
                    if ($data.Contains('selected_pair_path_anchor_finding_counterpart_selection') -and $null -ne $data.selected_pair_path_anchor_finding_counterpart_selection) {
                        $otherNavigation = $data.selected_pair_path_anchor_finding_counterpart_selection
                        Write-Output "Indexed independent counterpart Finding: $($otherNavigation.counterpart_finding_side) #$($otherNavigation.counterpart_finding_index_in_endpoint_anchor) of $($otherNavigation.counterpart_finding_count_at_opposite_endpoint_anchor): $($otherNavigation.counterpart_record_id)/$($otherNavigation.counterpart_finding_id) [$($otherNavigation.counterpart_saved_severity)]; original=$($otherNavigation.original_record_id)/$($otherNavigation.original_finding_id)"
                        Write-Output 'Both COMPLETE independent original-ID journeys are in JSON path_focus.selected_finding and selected_counterpart_finding; same anchor/ID spelling never asserts one defect.'
                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_cohorts) {
                            $cohorts = $data.path_focus.selected_original_finding_pair_profile_cohorts
                            Write-Output "Complete same-anchor SAVED severity-statement profile cohorts: absent=$($cohorts.counts.absent_anchor), left-only=$($cohorts.counts.matches_left_only), right-only=$($cohorts.counts.matches_right_only), both=$($cohorts.counts.matches_both_endpoints), neither=$($cohorts.counts.differs_from_both_endpoints); see JSON path_focus.selected_original_finding_pair_profile_cohorts."
                            Write-Output 'These are report histogram cohorts, NOT matched Findings, verified defects or severity histories.'
                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_atlas) {
                                $profileAtlas = $data.path_focus.selected_original_finding_pair_profile_atlas
                                Write-Output "Exact saved-profile classes=$($profileAtlas.counts.distinct_saved_profile_class_count), adjacent profile changes=$($profileAtlas.counts.adjacent_changed_profile_count), contiguous runs=$($profileAtlas.counts.contiguous_profile_run_count), nonadjacent profile returns=$($profileAtlas.counts.return_to_prior_nonadjacent_profile_occurrence_count)."
                                Write-Output 'Complete histogram class members, all-pair conservation, signed adjacent deltas and run spans: JSON path_focus.selected_original_finding_pair_profile_atlas. Caller order is not verified chronology.'
                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_transition_graph) {
                                    $profileGraph = $data.path_focus.selected_original_finding_pair_profile_transition_graph
                                    Write-Output "Saved-profile directed edges=$($profileGraph.counts.directed_edge_count) (reused=$($profileGraph.counts.reused_directed_edge_count), stable self-loops=$($profileGraph.counts.self_loop_directed_edge_count)); complete previous-run return witnesses=$($profileGraph.counts.return_to_previous_run_witness_count)."
                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_transition_graph for every directed edge, step linkage and exact closed return walk; caller order is NOT chronology or defect recurrence.'
                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_passages) {
                                        $passages = $data.path_focus.selected_original_finding_pair_profile_passages
                                        Write-Output "Observed caller-forward class passages=$($passages.counts.ordered_class_passage_group_count) across $($passages.counts.all_ec043_position_pair_count) exact saved-report pairs; nearest-run return links=$($passages.counts.closest_previous_run_return_link_count)."
                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_passages for complete ordered position pairs and shortest/longest ACTUAL contiguous class/edge walks; never inferred graph-path chronology.'
                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_motifs) {
                                            $motifs = $data.path_focus.selected_original_finding_pair_profile_motifs
                                            Write-Output "Actually observed full-class-walk motifs=$($motifs.counts.distinct_complete_class_walk_motif_count) across $($motifs.counts.observed_contiguous_window_count) real windows; repeated=$($motifs.counts.repeated_motif_count), strictly disjoint repeated=$($motifs.counts.motif_with_strictly_disjoint_repeat_count), longest repeat positions=$($motifs.counts.longest_repeated_motif_position_count)."
                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_motifs for each original contiguous walk, actual reused position intervals, overlaps and maximum disjoint witnesses. Similar saved profiles do NOT prove defect recurrence.'
                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_maximal_repeats) {
                                                $maximal = $data.path_focus.selected_original_finding_pair_profile_maximal_repeats
                                                Write-Output "Pairwise maximal actual repeat regions=$($maximal.counts.pairwise_maximal_repeat_region_count); strictly-disjoint maximal regions=$($maximal.counts.strictly_disjoint_maximal_repeat_region_count), longest disjoint maximal walk positions=$($maximal.counts.longest_strictly_disjoint_maximal_repeat_position_count)."
                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_maximal_repeats for exact synchronized extensions and ALL overlap-limited maxima; this is saved-profile repetition, NOT defect recurrence or verified chronology.'
                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_repeat_families) {
                                                    $families = $data.path_focus.selected_original_finding_pair_profile_repeat_families
                                                    Write-Output "Observed maximal-repeat class-walk families=$($families.counts.maximal_repeat_family_count), independently supported families=$($families.counts.family_with_two_or_more_strictly_disjoint_observed_occurrences_count), largest independent occurrence support=$($families.counts.largest_maximum_strictly_disjoint_occurrence_support), all optimal packs=$($families.counts.total_maximum_strictly_disjoint_occurrence_packings_across_families)."
                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_repeat_families for ALL original supporting occurrences, ALL optimum strictly disjoint packs and per-position always/sometimes/never coverage. Model-profile matches do NOT prove defect recurrence.'
                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_joint_support) {
                                                        $joint = $data.path_focus.selected_original_finding_pair_profile_joint_support
                                                        Write-Output "Distinct repeated-family pairs=$($joint.counts.distinct_maximal_repeat_family_pair_count); both independently supported=$($joint.counts.family_pairs_with_both_locally_independent_repeat_support); mutually compatible original support=$($joint.counts.family_pairs_with_joint_independent_repeat_support); both local maxima compatible=$($joint.counts.family_pairs_with_both_separate_local_maxima_jointly_compatible)."
                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_joint_support for EXACT genuine four-window combination counts, jointly feasible separate maxima, first original witnesses and per-position coverage. Competing caller positions invalidate simultaneous support, not the original separate observations.'
                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_triple_support) {
                                                            $triple = $data.path_focus.selected_original_finding_pair_profile_triple_support
                                                            Write-Output "Distinct repeated-family triples=$($triple.counts.distinct_maximal_repeat_family_triple_count); every pair jointly compatible=$($triple.counts.family_triples_where_every_pair_is_jointsupport_compatible); genuinely simultaneous six-window triples=$($triple.counts.family_triples_with_actual_three_family_joint_support); all three local maxima compatible=$($triple.counts.family_triples_with_compatible_three_local_maxima); global simultaneously independent family maximum=$($triple.counts.globally_maximum_simultaneously_independently_supported_distinct_family_count)."
                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_triple_support for ALL genuine three-family original witness combinations, distinct local-optimum compatibility, false pairwise-clique implications, record IDs, complete position coverage and all maximum family index sets. Saved profile matches do NOT prove historical defect recurrence.'
                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_position_withholding) {
                                                                $withholding = $data.path_focus.selected_original_finding_pair_profile_position_withholding
                                                                Write-Output "Single-position evidence withholding: $($withholding.counts.number_of_individual_positions_that_reduce_global_independent_family_maximum) of $($withholding.counts.selected_report_positions) caller positions reduce the distinct-family maximum; $($withholding.counts.number_of_individual_positions_that_reduce_global_original_local_optimum_maximum) reduce original local-optimum family capacity."
                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_position_withholding for EACH omitted original caller record, all genuinely surviving family/pair/triple witness totals, precise global maximum family sets and separately surviving FROZEN original local optima. This is not re-sequencing or removal of saved records.'
                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_pair_position_withholding) {
                                                                    $pairWithheld = $data.path_focus.selected_original_finding_pair_profile_pair_position_withholding
                                                                    Write-Output "Two-position evidence withholding: $($pairWithheld.counts.unordered_original_position_pair_count) exact ORIGINAL caller-position pairs; $($pairWithheld.counts.number_of_pairs_reducing_original_independent_maximum) reduce genuine family capacity, $($pairWithheld.counts.number_of_minimally_joint_critical_pairs_for_original_independent_maximum) are minimally jointly critical; frozen-original-optimum reductions=$($pairWithheld.counts.number_of_pairs_reducing_original_local_optimum_maximum)."
                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_pair_position_withholding for EVERY unordered original-position pair, genuine versus originally frozen-optimum witness counts, all global maximum family-index sets and pair-specific interaction beyond individual exclusions. No resequencing or semantic defect chronology is inferred.'
                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_triple_position_withholding) {
                                                                        $threeWithheld = $data.path_focus.selected_original_finding_pair_profile_triple_position_withholding
                                                                        Write-Output "Three-position evidence withholding: $($threeWithheld.counts.unordered_original_position_triple_count) exact ORIGINAL caller-position triples; $($threeWithheld.counts.number_of_triples_reducing_original_independent_maximum) reduce genuine family capacity, $($threeWithheld.counts.number_of_minimally_third_order_critical_triples_for_original_independent_maximum) are irreducibly third-order critical; originally frozen-optimum reductions=$($threeWithheld.counts.number_of_triples_reducing_original_local_optimum_maximum)."
                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_triple_position_withholding for all original triples, conserved two/four/six-window combinations, exact third-order interaction beyond every constituent pair, all maximum family sets and position/pair participation. This neither resequences saved records nor proves causal defect recurrence.'
                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_quartet_position_withholding) {
                                                                            $fourWithheld = $data.path_focus.selected_original_finding_pair_profile_quartet_position_withholding
                                                                            Write-Output "Four-position evidence withholding: $($fourWithheld.counts.unordered_original_position_quartet_count) exact ORIGINAL caller-position quartets; $($fourWithheld.counts.number_of_quartets_reducing_original_independent_maximum) reduce genuine family capacity, $($fourWithheld.counts.number_of_minimally_fourth_order_critical_quartets_for_original_independent_maximum) are irreducibly fourth-order critical; frozen full-selection optimum reductions=$($fourWithheld.counts.number_of_quartets_reducing_original_local_optimum_maximum)."
                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_quartet_position_withholding for original four-position records, independent and frozen original witness counts, fourth-order-only loss beyond each original constituent triple, all attaining family sets and complete original position/pair/triple incidence. No saved report is deleted or resequenced.'
                                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_quintet_position_withholding) {
                                                                                $fiveWithheld = $data.path_focus.selected_original_finding_pair_profile_quintet_position_withholding
                                                                                Write-Output "Five-position evidence withholding: $($fiveWithheld.counts.unordered_original_position_quintet_count) exact ORIGINAL quintets; $($fiveWithheld.counts.number_of_quintets_reducing_original_independent_maximum) reduce the global genuine maximum; $($fiveWithheld.counts.number_of_minimally_fifth_order_critical_quintets_for_original_independent_maximum) are globally fifth-order-only; $($fiveWithheld.counts.number_of_quintets_with_genuinely_fifth_order_only_original_family_loss) remove at least one particular original family only at the fifth exclusion; frozen-original-optimum global reductions=$($fiveWithheld.counts.number_of_quintets_reducing_original_local_optimum_maximum)."
                                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_quintet_position_withholding for all five-position sets, real surviving two-window witnesses, original frozen full-selection optima, exact fifth-order loss beyond every constituent quartet, all maximizing families and complete position/pair/triple/quartet incidence. No new adjacency, source change or real-defect claim.'
                                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_sextet_position_withholding) {
                                                                                    $sixWithheld = $data.path_focus.selected_original_finding_pair_profile_sextet_position_withholding
                                                                                    Write-Output "Six-position evidence withholding: $($sixWithheld.counts.unordered_original_position_sextet_count) original sextets; $($sixWithheld.counts.number_of_sextets_reducing_original_independent_maximum) reduce global independent capacity, $($sixWithheld.counts.number_of_minimally_sixth_order_critical_sextets_for_original_independent_maximum) are globally sixth-order-only; $($sixWithheld.counts.number_of_sextets_with_genuinely_sixth_order_only_original_family_loss) have specific original-family sixth-order-only loss. Frozen-original-optimum global reductions=$($sixWithheld.counts.number_of_sextets_reducing_original_local_optimum_maximum)."
                                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_sextet_position_withholding for ALL original six-position exclusions, exact sixth-order evidence survival, all maximizing sets, original constituent pair/triple/quartet/quintet identities and full 6/15/20/15/6 participation. No report is deleted, reindexed or made newly adjacent; no identical-defect or causal claim is made.'
                                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_septet_position_withholding) {
                                                                                        $sevenWithheld = $data.path_focus.selected_original_finding_pair_profile_septet_position_withholding
                                                                                        Write-Output "Seven-position evidence withholding: $($sevenWithheld.counts.unordered_original_position_septet_count) canonical original septets; $($sevenWithheld.counts.number_of_septets_reducing_original_independent_maximum) reduce the genuine global maximum, $($sevenWithheld.counts.number_of_minimally_seventh_order_critical_septets_for_original_independent_maximum) are globally seventh-order-only, and $($sevenWithheld.counts.number_of_septets_with_genuinely_seventh_order_only_original_family_loss) lose an individual family only at the seventh original exclusion. Frozen original-optimum reductions=$($sevenWithheld.counts.number_of_septets_reducing_original_local_optimum_maximum)."
                                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_septet_position_withholding for all original seven-position records, direct/exact seventh-order inclusion-exclusion survival, seven sextet ancestors, separately global versus particular-family loss, all attaining family sets and six-level 7/21/35/35/21/7 participation. No new adjacency, source reads, writes, defect identity or chronological claim.'
                                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_octet_position_withholding) {
                                                                                            $eightWithheld = $data.path_focus.selected_original_finding_pair_profile_octet_position_withholding
                                                                                            Write-Output "Eight-position evidence withholding: $($eightWithheld.counts.unordered_original_position_octet_count) original octets; $($eightWithheld.counts.number_of_octets_reducing_original_independent_maximum) reduce the original genuine global maximum, $($eightWithheld.counts.number_of_minimally_eighth_order_critical_octets_for_original_independent_maximum) are globally eighth-order-only, and $($eightWithheld.counts.number_of_octets_with_genuinely_eighth_order_only_original_family_loss) first lose a specific genuine family at the eighth exclusion. Frozen original-optimum global reductions=$($eightWithheld.counts.number_of_octets_reducing_original_local_optimum_maximum)."
                                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_octet_position_withholding for all eight-position source identities, direct and exact eighth-order weighted witness survival, eight septet parents, distinct global/family loss, original global maxima and seven-level 8/28/56/70/56/28/8 participation. Only original windows count; no business source changes or real-defect/causal claims.'
                                                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_nonet_position_withholding) {
                                                                                                $nineWithheld = $data.path_focus.selected_original_finding_pair_profile_nonet_position_withholding
                                                                                                Write-Output "Nine-position original evidence withholding: $($nineWithheld.counts.unordered_original_position_nonet_count) nonets; all genuine and original-frozen two-window survivors must be zero (at most three original positions remain). $($nineWithheld.counts.number_of_nonets_reducing_original_independent_maximum) reduce the original genuine global maximum, $($nineWithheld.counts.number_of_minimally_ninth_order_critical_nonets_for_original_independent_maximum) are globally ninth-order-only, and $($nineWithheld.counts.number_of_nonets_with_genuinely_ninth_order_only_original_family_loss) eliminate a specific family only after nine original exclusions."
                                                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_nonet_position_withholding for complete original identities, exact nine-way weighted inclusion/exclusion, all nine octet parents, separate global/family comparisons and eight-level 9/36/84/126/126/84/36/9 original incidence; no report resequencing, new source reads or writes.'
                                                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_decet_position_withholding) {
                                                                                                    $tenWithheld = $data.path_focus.selected_original_finding_pair_profile_decet_position_withholding
                                                                                                    Write-Output "Ten-position original evidence withholding: $($tenWithheld.counts.unordered_original_position_decet_count) decets; any original-frozen or genuine two-window survivor is impossible because only two original positions can remain. $($tenWithheld.counts.number_of_decets_reducing_original_independent_maximum) reduce the original global maximum; $($tenWithheld.counts.number_of_minimally_tenth_order_critical_decets_for_original_independent_maximum) first reduce it at tenth order."
                                                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_decet_position_withholding for survivor counts verified internally against 1023 ten-slot intersections, ten original nonet ancestors, separate global/family criticality and nine full incidence layers (10/45/120/210/252/210/120/45/10). All parent projections are preserved; original positions are never resequenced.'
                                                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_undecet_position_withholding) {
                                                                                                        $elevenWithheld = $data.path_focus.selected_original_finding_pair_profile_undecet_position_withholding
                                                                                                        Write-Output "Eleven-position original evidence withholding: $($elevenWithheld.counts.unordered_original_position_undecet_count) undecets; no genuine or original-frozen two-window survivors are possible with at most one original position remaining. $($elevenWithheld.counts.number_of_undecets_reducing_original_independent_maximum) reduce the original genuine maximum, while $($elevenWithheld.counts.number_of_minimally_eleventh_order_critical_undecets_for_original_independent_maximum) first reduce it at eleventh order."
                                                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_undecet_position_withholding for survivor totals checked against all 2047 original eleven-slot intersections and eleven fully replayed original decet parents, separate baseline/eleventh-only global and family effects, and ten original incidence levels (11/55/165/330/462/462/330/165/55/11). Report positions are never resequenced; no causal or real-defect conclusion follows.'
                                                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_duodecet_position_withholding) {
                                                                                                            $twelveWithheld = $data.path_focus.selected_original_finding_pair_profile_duodecet_position_withholding
                                                                                                            Write-Output "Twelve-position original evidence withholding: $($twelveWithheld.counts.unordered_original_position_duodecet_count) duodecets (one only for twelve original reports). $($twelveWithheld.counts.number_of_duodecets_reducing_original_independent_maximum) reduce the original genuine maximum; $($twelveWithheld.counts.number_of_minimally_twelfth_order_critical_duodecets_for_original_independent_maximum) introduce genuinely twelfth-only global loss."
                                                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_duodecet_position_withholding for exact 4095 nonempty twelve-slot weighted intersections, complete EC-069 replay, frozen/genuine zero survivors and all eleven original participation levels (12/66/220/495/792/924/792/495/220/66/12). No report resequencing, source edit or claim of real-world defect identity.'
                                                                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_resilience_frontier) {
                                                                                                                $frontier = $data.path_focus.selected_original_finding_pair_profile_resilience_frontier
                                                                                                                Write-Output "Complete original exclusion resilience: $($frontier.counts.nonempty_original_exclusion_sets) real subsets, checked across all 12 predecessor levels. Inclusion-minimal genuine/frozen first-loss cuts: $($frontier.counts.genuine_inclusion_minimal_global_first_loss_cut_count) / $($frontier.counts.frozen_inclusion_minimal_global_first_loss_cut_count); minimum omitted positions $($frontier.counts.genuine_minimum_positions_for_first_global_loss) / $($frontier.counts.frozen_minimum_positions_for_first_global_loss)."
                                                                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_resilience_frontier for exact original-position bit legend, global 3/2/1 capacity-loss frontiers, all family extinction frontiers, and zero-through-N cardinality summary. Cuts describe saved motif evidence only, not real-world defect identity or causation.'
                                                                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_support_basis_duality) {
                                                                                                                    $basisDuality = $data.path_focus.selected_original_finding_pair_profile_support_basis_duality
                                                                                                                    Write-Output "Original witness support-basis duality: $($basisDuality.counts.genuine_global_threshold_support_basis_frontiers) genuine and $($basisDuality.counts.frozen_global_threshold_support_basis_frontiers) frozen global thresholds, plus $($basisDuality.counts.individual_original_family_basis_frontiers) original family registries; each minimal evidence-loss cut includes exact one-position restoration certificates."
                                                                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_support_basis_duality for original kept-position witness bases, position involvement, and restoring each excluded position to regain a real basis. This is saved-evidence sensitivity only, not a causal repair, and original frozen optima are not reoptimized.'
                                                                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pivotality) {
                                                                                                                        $pivotal = $data.path_focus.selected_original_finding_pair_profile_retention_pivotality
                                                                                                                        Write-Output "Original retention-budget coverage and pivotal additions: $($pivotal.counts.exact_original_retained_masks_checked_per_target) retained subsets and $($pivotal.counts.exact_original_directed_position_additions_checked_per_target) directed edges per target; $($pivotal.counts.genuine_original_global_thresholds) genuine and $($pivotal.counts.frozen_original_global_thresholds) frozen global thresholds, plus $($pivotal.counts.original_individual_family_targets) original families."
                                                                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pivotality for exact supported/unsupported subset counts at each original retention budget, evidence-changing one-position additions by original report and budget, and checked real minimal-basis restoration examples. Original saved-evidence sensitivity is not causal defect importance or repair priority.'
                                                                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_order_attribution) {
                                                                                                                            $orders = $data.path_focus.selected_original_finding_pair_profile_retention_order_attribution
                                                                                                                            Write-Output "Exact hypothetical report-order first-evidence restoration: $($orders.counts.exact_original_distinct_permutations_per_target) original full permutations per target, $($orders.counts.genuine_original_global_thresholds) genuine and $($orders.counts.frozen_original_global_thresholds) frozen global thresholds, and $($orders.counts.individual_original_family_targets) separate families."
                                                                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_order_attribution for first support-restoration step counts, exact position-attributed permutation counts, reduced rational shares and certified EC-073 examples. Uniform enumerated permutations are mathematical hypothetical orderings, never observed report chronology, probabilities of real-world defects, or repair priority.'
                                                                                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_rank_conditioning) {
                                                                                                                                $rankCondition = $data.path_focus.selected_original_finding_pair_profile_retention_rank_conditioning
                                                                                                                                Write-Output "Fixed-rank original evidence conditioning: $($rankCondition.counts.fixed_rank_scenarios_per_target) report/rank combinations per target, each accounting for exactly $($rankCondition.counts.exact_permutations_given_one_original_position_at_one_fixed_rank) hypothetical complete orderings."
                                                                                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_rank_conditioning for the exact first-evidence-before/by/after/never partition for every original report fixed at every possible rank, with integer-reduced by-position fractions and independent EC-072/073/074 conservation. No real arrival-order, probability, defect or causal-repair claim is implied.'
                                                                                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_precedence) {
                                                                                                                                    $pairPrecedence = $data.path_focus.selected_original_finding_pair_profile_retention_pair_precedence
                                                                                                                                    Write-Output "Ordered original pair precedence: $($pairPrecedence.counts.ordered_original_report_pair_scenarios_per_target) distinct report-pair orientations per target, each comprising $($pairPrecedence.counts.exact_permutations_per_ordered_original_report_pair) hypothetical original complete orderings."
                                                                                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_precedence for first support before/by first report, strictly between, by/after second report, or never, with EC-072/073, EC-075 fixed-rank and EC-074 whole-permutation conservation. Relative order is hypothetical, not observed chronology or real-world probability.'
                                                                                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_adjacency) {
                                                                                                                                        $adjacency = $data.path_focus.selected_original_finding_pair_profile_retention_pair_adjacency
                                                                                                                                        Write-Output "Immediately adjacent original ordered report pairs: $($adjacency.counts.directed_original_report_adjacency_scenarios_per_target) directions per target, each with exactly $($adjacency.counts.exact_permutations_per_directed_immediate_original_pair) full hypothetical original orderings."
                                                                                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_adjacency for exact first support before/by first report, by/after its immediately following report, or never, reduced integer fractions and independent EC-072/073/074/075/076 conservation. Hypothetical adjacency does not establish arrival history, real-world probability, defect priority or causal repair.'
                                                                                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_single_intervening) {
                                                                                                                                            $singleGap = $data.path_focus.selected_original_finding_pair_profile_retention_pair_single_intervening
                                                                                                                                            Write-Output "Single-intervening ORIGINAL report-pair conditioning: $($singleGap.counts.directed_original_report_single_intervening_scenarios_per_target) directed p/r/q cases per target, with exactly $($singleGap.counts.exact_permutations_per_directed_original_pair_with_one_intervening_report) compatible full original orderings per p/q; N2 has none."
                                                                                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_single_intervening for exact first evidence before/by p, by the one ORIGINAL intervening report (including original-bit attribution), by/after q or never, with reduced integer fractions and checked independent EC-072/073/074/075 and EC-076/077 disjoint bounds. The gap is hypothetical, not a verified arrival order or causal repair.'
                                                                                                                                            if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_double_intervening) {
                                                                                                                                                $doubleGap = $data.path_focus.selected_original_finding_pair_profile_retention_pair_double_intervening
                                                                                                                                                Write-Output "Two-intervening ORIGINAL report-pair conditioning: $($doubleGap.counts.directed_original_report_double_intervening_scenarios_per_target) directed p/r/s/q cases per target, with $($doubleGap.counts.exact_permutations_per_directed_original_pair_with_two_intervening_reports) complete hypothetical orders per p/q. N2/N3 have none."
                                                                                                                                                Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_double_intervening for exact seven-stage first evidence, separate first- and second-intermediary ORIGINAL identity arrays, exact integer fractions and independent EC-072..078 conservation. Counterfactual gap positions do not attest chronology, defect identity or causal repair.'
                                                                                                                                                if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_triple_intervening) {
                                                                                                                                                    $tripleGap = $data.path_focus.selected_original_finding_pair_profile_retention_pair_triple_intervening
                                                                                                                                                    Write-Output "Three-intervening ORIGINAL report-pair conditioning: $($tripleGap.counts.directed_original_report_triple_intervening_scenarios_per_target) directed p/r/s/t/q cases per target, each with $($tripleGap.counts.exact_permutations_per_directed_original_pair_with_three_intervening_reports) compatible hypothetical orders. N2/N3/N4 have no eligible cases."
                                                                                                                                                    Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_triple_intervening for eight exact first-evidence stages, three separate ORIGINAL middle-position attribution vectors, reduced integer fractions and EC-072..079 preservation. These counterfactual placements do not authenticate chronology, real defect risk or causal repair.'
                                                                                                                                                    if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening) {
                                                                                                                                                        $quadGap = $data.path_focus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening
                                                                                                                                                        Write-Output "Four-intervening ORIGINAL report-pair conditioning: $($quadGap.counts.directed_original_report_quadruple_intervening_scenarios_per_target) directed p/r/s/t/u/q cases per target, each with $($quadGap.counts.exact_permutations_per_directed_original_pair_with_four_intervening_reports) compatible hypothetical orders. N2/N3/N4/N5 have no eligible cases."
                                                                                                                                                        Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_quadruple_intervening for nine exhaustive first-support stages, four independent ORIGINAL middle-identity attribution vectors, six exact integer fractions and EC-072..080 conservation. Hypothetical ordering does not attest chronology, severity, empirical probability or repair cause.'
                                                                                                                                                        if ($null -ne $data.path_focus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening) {
                                                                                                                                                            $quintGap = $data.path_focus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening
                                                                                                                                                            Write-Output "Five-intervening ORIGINAL report-pair conditioning: $($quintGap.counts.directed_original_report_quintuple_intervening_scenarios_per_target) directed p/r/s/t/u/v/q cases per target, each with $($quintGap.counts.exact_permutations_per_directed_original_pair_with_five_intervening_reports) compatible hypothetical orders. N2..N6 have no eligible cases."
                                                                                                                                                            Write-Output 'See JSON path_focus.selected_original_finding_pair_profile_retention_pair_quintuple_intervening for ten exhaustive first-support categories, five ORIGINAL intermediate identity-attribution arrays, seven exact reduced integer fractions and EC-072..081 conservation. No real chronology, statistical probability, severity or causal repair is inferred.'
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if ($null -ne $data.path_focus) {
                        Write-Output "Focused saved path: $($data.path_focus.path)"
                        Write-Output "Focused matching records / Finding statements: $($data.path_focus.matching_record_count) / $($data.path_focus.matching_finding_statement_count)"
                        Write-Output "Focused exact-anchor union: $($data.path_focus.anchor_trajectory.counts.distinct_exact_anchor_union_count)"
                        if ($null -ne $data.path_focus.profile_journey) {
                            $focusJourney = $data.path_focus.profile_journey
                            Write-Output "Focused saved-path profile classes / transitions / stable runs: $($focusJourney.counts.distinct_profile_class_count) / $($focusJourney.counts.profile_transition_count) / $($focusJourney.counts.profile_run_count)"
                            Write-Output "Focused prior-profile returns / reported-after-gap events: $($focusJourney.counts.return_to_prior_profile_count) / $($focusJourney.counts.reported_after_unreported_gap_count) (complete despite SequenceTop=$SequenceTop)"
                            foreach ($focusedRun in $focusJourney.profile_runs) {
                                Write-Output "  Focus run $($focusedRun.run_index): selected positions $($focusedRun.start_position)-$($focusedRun.end_position), class $($focusedRun.profile_class), reported=$($focusedRun.path_reported)"
                            }
                            foreach ($focusedEvent in $focusJourney.transition_events) {
                                Write-Output "  Focus profile transition $($focusedEvent.previous_position)->$($focusedEvent.next_position): $($focusedEvent.transition_kind), classes $($focusedEvent.from_profile_class)->$($focusedEvent.to_profile_class), exact-return=$($focusedEvent.returns_to_prior_profile), reported-after-gap=$($focusedEvent.reported_after_unreported_gap)"
                            }
                        }
                        if ($null -ne $data.path_focus.anchor_journeys) {
                            $anchorJourneys = $data.path_focus.anchor_journeys
                            Write-Output "Complete focused exact-anchor histories: $($anchorJourneys.counts.distinct_exact_anchor_union_count) anchors, $($anchorJourneys.counts.finding_statement_occurrences) Finding statements (not clipped by SequenceTop=$SequenceTop)"
                            Write-Output "Anchor presence / saved severity transitions: $($anchorJourneys.counts.presence_transitions_across_adjacent_pairs_count) / $($anchorJourneys.counts.retained_severity_histogram_transition_count); anchors reappearing after a reporting gap: $($anchorJourneys.counts.reappeared_after_at_least_one_unreported_position_count)"
                            Write-Output 'All exact anchors, every position, maximal presence runs and adjacent events are available in the JSON anchor_journeys result.'
                        }
                        if ($null -ne $data.path_focus.anchor_cohorts) {
                            $cohorts = $data.path_focus.anchor_cohorts
                            Write-Output "Focused exact-anchor presence cohorts: $($cohorts.counts.distinct_presence_pattern_cohort_count) groups; all-position / single-position / partial-contiguous / reappeared anchors: $($cohorts.counts.every_position_exact_anchor_count) / $($cohorts.counts.one_position_exact_anchor_count) / $($cohorts.counts.contiguous_partial_exact_anchor_count) / $($cohorts.counts.reappeared_after_gap_exact_anchor_count)"
                            Write-Output 'All cohort patterns, anchor indexes and per-position/per-step severity totals are available in JSON anchor_cohorts.'
                        }
                        if ($null -ne $data.path_focus.anchor_pairwise) {
                            $anchorPairs = $data.path_focus.anchor_pairwise
                            Write-Output "Focused exact-anchor all-pairs: $($anchorPairs.pair_count) checked caller-position pairs, $($anchorPairs.counts.identical_saved_path_profile_pair_count) equal saved path profiles, $($anchorPairs.counts.severity_only_difference_pair_count) severity-only differing pairs"
                            Write-Output "Pairwise shared-anchor reporting gaps / retained severity histogram differences: $($anchorPairs.counts.shared_anchor_with_internal_unreported_position_pair_occurrences) / $($anchorPairs.counts.retained_changed_severity_histogram_anchor_pair_occurrences)"
                            Write-Output 'Complete pair rows, canonical per-anchor pair frequencies and position-distance bins are available in JSON anchor_pairwise.'
                        }
                        if ($null -ne $data.path_focus.anchor_pair_details) {
                            $pairDetails = $data.path_focus.anchor_pair_details
                            Write-Output "Focused anchor pair drilldown: $($pairDetails.pair_count) complete index partitions; $($pairDetails.counts.left_only_anchor_pair_occurrences) left-only / $($pairDetails.counts.right_only_anchor_pair_occurrences) right-only / $($pairDetails.counts.retained_changed_severity_anchor_pair_occurrences) retained severity-changed pair occurrences"
                            if ($pairDetails.ranked_pairs.Count -gt 0) {
                                $peak = $pairDetails.ranked_pairs[0]
                                Write-Output "  Most different saved pair index: $($peak.pair_index), differing exact anchors=$($peak.changed_exact_anchor_count) (not risk or time ordering)"
                            }
                            Write-Output 'Every pair exact-anchor index partition, cross-gap overlap and signed five-severity saved Finding-statement delta are in JSON anchor_pair_details (not clipped).'
                        }
                        if ($null -ne $data.path_focus.anchor_pair_lookup) {
                            $lookup = $data.path_focus.anchor_pair_lookup
                            Write-Output "Focused anchor-to-pair lookup: $($lookup.anchors.Count) exact anchors, $($lookup.counts.anchors_differing_in_at_least_one_pair_count) differing in at least one selected pair; $($lookup.counts.changed_anchor_pair_occurrences) changed anchor/pair occurrences"
                            if ($lookup.ranked_anchors.Count -gt 0) {
                                $leading = $lookup.ranked_anchors[0]
                                Write-Output "  Most contrasting exact-anchor index: $($leading.anchor_index_in_anchor_journeys), changed in $($leading.changed_pair_count) pairs (not risk or time ranking)"
                            }
                            Write-Output 'All five exclusive pair-class lists, overlapping cross-gap pairs, and signed retained severity events are in JSON anchor_pair_lookup (not clipped).'
                        }
                        if ($null -ne $data.path_focus.anchor_finding_refs) {
                            $findingRefs = $data.path_focus.anchor_finding_refs
                            Write-Output "Focused Finding navigation: $($findingRefs.counts.finding_reference_occurrences) saved record-scoped IDs over $($findingRefs.counts.distinct_exact_anchor_union_count) exact anchors; $($findingRefs.counts.selected_positions_with_focused_findings_count) positions with reported Findings"
                            Write-Output 'Complete canonical anchor-to-(record ID, Finding ID) and per-record Finding-to-anchor references are in JSON anchor_finding_refs; no Finding text and no cross-record identity claim.'
                        }
                        if ($null -ne $data.path_focus.anchor_pair_finding_refs) {
                            $pairFindingRefs = $data.path_focus.anchor_pair_finding_refs
                            Write-Output "Focused changed-pair Finding witnesses: $($pairFindingRefs.counts.pairs_with_changed_exact_anchor_count) contrasting pairs, $($pairFindingRefs.counts.changed_exact_anchor_pair_occurrences) changed-anchor pair occurrences, $($pairFindingRefs.counts.changed_finding_reference_occurrences) record-scoped Finding reference appearances"
                            Write-Output 'JSON anchor_pair_finding_refs contains complete pair-indexed left/right Finding IDs for changed saved quote anchors only; equal histograms have no Finding-level match claim.'
                        }
                        if ($null -ne $data.path_focus.finding_pair_lookup) {
                            $findingPairs = $data.path_focus.finding_pair_lookup
                            Write-Output "Focused Finding-to-pair lookup: $($findingPairs.counts.original_finding_reference_count) original scoped Findings, $($findingPairs.counts.complete_finding_pair_incidence_count) pair appearances, $($findingPairs.counts.changed_anchor_finding_pair_incidence_count) changed / $($findingPairs.counts.stable_anchor_finding_pair_incidence_count) stable saved-anchor appearances"
                            Write-Output 'JSON finding_pair_lookup inverts every original scoped Finding into all pair indexes, including unchanged-histogram anchors; pair category is NOT per-Finding cross-record identity or a verified defect lifecycle.'
                        }
                        if ($null -ne $data.path_focus.selected_pair) {
                            $selectedPair = $data.path_focus.selected_pair
                            Write-Output "Selected saved report pair #$($selectedPair.pair_index_in_anchor_pair_details) at literal path $($selectedPair.path): caller positions $($selectedPair.left_position)/$($selectedPair.right_position), $($selectedPair.counts.distinct_exact_anchor_union_count) exact anchors"
                            Write-Output "  Left-only=$($selectedPair.counts.left_only_anchor_count), right-only=$($selectedPair.counts.right_only_anchor_count), retained-same=$($selectedPair.counts.retained_same_severity_anchor_count), retained-changed=$($selectedPair.counts.retained_changed_severity_anchor_count), both-unreported=$($selectedPair.counts.both_unreported_anchor_count), internal-gap=$($selectedPair.counts.shared_with_internal_unreported_position_anchor_count)."
                            Write-Output '  JSON selected_pair contains every canonical anchor and both separately scoped original saved Finding ID/severity sets; no cross-report issue match, chronology or verified risk claim.'
                        }
                        if ($null -ne $data.path_focus.selected_anchor) {
                            $selectedAnchor = $data.path_focus.selected_anchor
                            Write-Output "Selected exact quote anchor #$($selectedAnchor.anchor_index_in_anchor_journeys) at literal saved path $($selectedAnchor.path): $($selectedAnchor.counts.reported_position_count)/$($selectedAnchor.selected_record_count) reports, $($selectedAnchor.counts.original_record_scoped_finding_statement_occurrences) original saved statements"
                            Write-Output "  Every report pair: $($selectedAnchor.counts.compared_pair_count); left-only=$($selectedAnchor.counts.left_only_pair_count), right-only=$($selectedAnchor.counts.right_only_pair_count), retained-same=$($selectedAnchor.counts.retained_same_severity_pair_count), retained-changed=$($selectedAnchor.counts.retained_changed_severity_pair_count), both-unreported=$($selectedAnchor.counts.both_unreported_pair_count), internal-gap=$($selectedAnchor.counts.shared_with_internal_unreported_position_pair_count)."
                            Write-Output '  Complete original record-scoped IDs, saved severity histograms and every pair signed delta are in JSON selected_anchor; no semantic cross-report Finding identity or verified chronology.'
                        }
                        if ($null -ne $data.path_focus.selected_finding) {
                            $selectedFinding = $data.path_focus.selected_finding
                            Write-Output "Selected original Finding $($selectedFinding.original_finding_id) in $($selectedFinding.original_record_id): canonical exact quote anchor #$($selectedFinding.anchor_index_in_anchor_journeys), saved severity=$($selectedFinding.original_saved_severity)"
                            Write-Output "  Exact anchor reported in $($selectedFinding.counts.anchor_reported_position_count) selected reports; $($selectedFinding.counts.changed_anchor_pair_count) changed / $($selectedFinding.counts.stable_anchor_pair_count) unchanged saved-anchor comparisons involving the original report."
                            Write-Output '  JSON selected_finding includes complete position-scoped original counterpart IDs and direct pair/transition navigation; no cross-record Finding identity or verified defect lifecycle.'
                        }
                        Write-Output "Focused trajectory previews truncated: $($data.path_focus.anchor_trajectory.previews_truncated)"
                        foreach ($focusedStep in $data.path_focus.steps) {
                            Write-Output "Focused step $($focusedStep.step): retained=$($focusedStep.counts.retained_exact_anchor_count), previous-only=$($focusedStep.counts.previous_only_exact_anchor_count), next-only=$($focusedStep.counts.next_only_exact_anchor_count)"
                        }
                    }
                    foreach ($step in $data.steps) {
                        Write-Output "Step $($step.step): $($step.previous_record_id) -> $($step.next_record_id)"
                        Write-Output "  Retained exact anchors: $($step.counts.retained_exact_anchor_count)"
                        Write-Output "  Previous-only / next-only: $($step.counts.previous_only_exact_anchor_count) / $($step.counts.next_only_exact_anchor_count)"
                        Write-Output "  Retained with differing reported severities: $($step.counts.retained_severity_distribution_changed_count)"
                    }
                    Write-Output $data.explanation
                } elseif ($data.mode -eq 'Trace') {
                    Write-Output "Seed: $($data.seed.record_id) / $($data.seed.finding_id)"
                    Write-Output "Matching records in page: $($data.returned_record_count)"
                    if ($data.selection_scope -eq 'selected_record_ids') {
                        Write-Output "Selection: $($data.selected_record_count) explicitly selected saved records"
                    }
                    Write-Output "Records scanned: $($data.scanned_record_count) of $($data.record_count)"
                    Write-Output "More candidate records: $($data.has_more_candidates)"
                    if ($data.next_after_trace_cursor) { Write-Output "Next cursor: $($data.next_after_trace_cursor)" }
                    foreach ($item in $data.matches) {
                        Write-Output "Occurrence: $($item.record_id) ($($item.matching_finding_count) statements)"
                    }
                    Write-Output $data.explanation
                } elseif ($data.mode -eq 'Compare') {
                    Write-Output "Left record: $($data.left_record.record_id)"
                    Write-Output "Right record: $($data.right_record.record_id)"
                    Write-Output "Comparable source modes: $($data.comparable)"
                    if ($data.comparable) {
                        Write-Output "Shared quote anchors: $($data.counts.shared_anchor_count)"
                        Write-Output "Only in left record: $($data.counts.left_only_anchor_count)"
                        Write-Output "Only in right record: $($data.counts.right_only_anchor_count)"
                    }
                    Write-Output $data.explanation
                } else {
                    Write-Output "Record: $($data.record_id)"
                    Write-Output "SHA-256: $($data.record_sha256)"
                }
            }
            if ($Envelope.action -ieq 'CodeSave' -and $data -is [System.Collections.IDictionary] -and $data.Contains('persisted')) {
                Write-Output "Persisted: $($data.persisted)"
                if ($data.Contains('record_id')) { Write-Output "CES record: $($data.record_id)" }
                if ($data.Contains('record_path')) { Write-Output "Local file: $($data.record_path)" }
            }
            if ($Envelope.action -ieq 'CodeValidate' -and $data -is [System.Collections.IDictionary] -and $data.Contains('validated')) {
                Write-Output "Validated: $($data.validated)"
                if ($data.Contains('finding_count')) { Write-Output "Checked finding anchors: $($data.finding_count)" }
                if ($data.Contains('packet_sha256')) { Write-Output "Packet SHA-256: $($data.packet_sha256)" }
            }
            if ($Envelope.action -ieq 'Reconcile' -and $data -is [System.Collections.IDictionary] -and $data.Contains('verdict')) {
                Write-Output "Source mode: $($data.subject.source_mode)"
                Write-Output "Verdict: $($data.verdict)"
                Write-Output "Saved file SHA-256: $($data.previous_snapshot.snapshot_file_sha256)"
            }
            if ($Envelope.action -ieq 'Collect' -and $data -is [System.Collections.IDictionary] -and $data.Contains('subject')) {
                Write-Output "Source mode: $($data.subject.source_mode)"
                if ($data.Contains('changes')) {
                    Write-Output "Commit range: $($data.subject.base_sha) -> $($data.subject.target_sha)"
                    Write-Output "Local target ref: $($data.subject.target_ref)"
                    Write-Output "Changed paths: $($data.changes.count) ($($data.changes.state))"
                    Write-Output "Raw patch: $($data.changes.patch_state)"
                } elseif ($data.Contains('staged')) {
                    Write-Output "Staged: $($data.staged.count) ($($data.staged.state))"
                    Write-Output "Unstaged: $($data.unstaged.count) ($($data.unstaged.state))"
                    Write-Output "Untracked: $($data.untracked.count) ($($data.untracked.state))"
                }
                Write-Output "Consistency: $($data.snapshot.consistency)"
            }
        }
        foreach ($warning in $Envelope.warnings) {
            Write-Output "Warning: $warning"
        }
    }

    exit $ExitCode
}

function Limit-Text {
    param(
        [AllowNull()][string] $Value,
        [int] $MaxLength = 1000
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }
    # Keep diagnostic text printable; do not echo arbitrary terminal escapes.
    $clean = [regex]::Replace($Value, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x1B]', ' ')
    $clean = $clean.Trim()
    if ($clean.Length -gt $MaxLength) {
        return ($clean.Substring(0, $MaxLength) + '…')
    }
    return $clean
}

function Invoke-ReadOnlyGit {
    param(
        [Parameter(Mandatory)][string] $GitExecutable,
        [Parameter(Mandatory)][string[]] $GitArguments,
        [int] $MaxStdoutBytes = 1MB,
        [switch] $PreserveStdout
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $GitExecutable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $GitArguments) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    # Explicit RepoPath must win over inherited Git routing, config injections,
    # external filters and potentially network-fetching partial-clone behavior.
    foreach ($environmentName in @(
        'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
        'GIT_PREFIX', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY',
        'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_SUPER_PREFIX',
        'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_EXTERNAL_DIFF',
        'GIT_TRACE', 'GIT_TRACE_PACK_ACCESS', 'GIT_TRACE_PACKET',
        'GIT_TRACE_PERFORMANCE', 'GIT_TRACE_SETUP', 'GIT_TRACE2',
        'GIT_TRACE2_EVENT', 'GIT_TRACE2_PERF'
    )) {
        [void] $startInfo.Environment.Remove($environmentName)
    }
    # Also remove caller-controlled config-file locations, NOSYSTEM and
    # future GIT_CONFIG_* overlays. Keep Git's ordinary local configuration
    # available; this is not a sandbox against hostile repository config.
    foreach ($key in @($startInfo.Environment.Keys)) {
        if ($key -match '^GIT_CONFIG(?:_|$)') {
            [void] $startInfo.Environment.Remove($key)
        }
    }
    $startInfo.Environment['GIT_TERMINAL_PROMPT'] = '0'
    $startInfo.Environment['GIT_OPTIONAL_LOCKS'] = '0'
    $startInfo.Environment['GIT_NO_LAZY_FETCH'] = '1'
    $startInfo.Environment['GIT_NO_REPLACE_OBJECTS'] = '1'
    $startInfo.Environment['GIT_PAGER'] = 'cat'

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $output = [System.IO.MemoryStream]::new()
    try {
        [void] $process.Start()
        # Drain stderr concurrently while reading raw, NUL-safe stdout bytes.
        # Stop a runaway `git diff` before allocating an unbounded string.
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $buffer = [byte[]]::new(8192)
        $timedOut = $false
        $overLimit = $false
        while ($true) {
            $remaining = $script:GitTimeoutMilliseconds - [int]$watch.ElapsedMilliseconds
            if ($remaining -le 0) { $timedOut = $true; break }
            $task = $process.StandardOutput.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $task.Wait($remaining)) { $timedOut = $true; break }
            $count = $task.Result
            if ($count -eq 0) { break }
            if (($output.Length + $count) -gt $MaxStdoutBytes) { $overLimit = $true; break }
            $output.Write($buffer, 0, $count)
        }
        $remaining = [math]::Max(1, ($script:GitTimeoutMilliseconds - [int]$watch.ElapsedMilliseconds))
        if (-not ($timedOut -or $overLimit)) {
            if (-not $process.WaitForExit($remaining)) { $timedOut = $true }
        }
        if ($timedOut -or $overLimit) {
            try { $process.Kill($true) } catch { }
            try { [void] $process.WaitForExit(2000) } catch { }
            return [pscustomobject]@{
                ok = $false; exit_code = $null; stdout = ''
                stderr = if ($timedOut) { 'Git command timed out.' } else { 'Git output exceeded bounded capture limit.' }
                timed_out = $timedOut; over_limit = $overLimit
            }
        }
        # Reject invalid UTF-8 rather than quietly corrupting file names.
        $decoder = [System.Text.UTF8Encoding]::new($false, $true)
        $stdout = $decoder.GetString($output.ToArray())
        if (-not $PreserveStdout) { $stdout = $stdout.TrimEnd("`r", "`n") }
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ok = ($process.ExitCode -eq 0)
            exit_code = $process.ExitCode
            stdout = $stdout
            stderr = (Limit-Text -Value $stderr)
            timed_out = $false
            over_limit = $false
        }
    } catch {
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch { }
        return [pscustomobject]@{
            ok = $false; exit_code = $null; stdout = ''
            stderr = (Limit-Text -Value $_.Exception.Message)
            timed_out = $false; over_limit = $false
        }
    } finally {
        $output.Dispose()
        $process.Dispose()
    }
}

function Git-In {
    param(
        [Parameter(Mandatory)][string] $GitExecutable,
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][string[]] $Arguments,
        [int] $MaxStdoutBytes = 1MB,
        [switch] $PreserveStdout
    )

    # Disable configured fsmonitor and automatic maintenance. No hooks or
    # untrusted external commands are invoked for these read-only probes.
    $argv = @('-C', $Directory, '-c', 'core.fsmonitor=false', '-c', 'maintenance.auto=false', '-c', 'gc.auto=0') + $Arguments
    return Invoke-ReadOnlyGit -GitExecutable $GitExecutable -GitArguments $argv -MaxStdoutBytes $MaxStdoutBytes -PreserveStdout:$PreserveStdout
}

# EC-159: trusted common path, Git-root and actor identity helpers.
# Git-In remains the existing bounded, read-only Git child-process runner.
. (Join-Path $PSScriptRoot 'pathidentity.ps1')

function Inspect-Repository {
    param(
        [System.Collections.IDictionary] $Envelope,
        [string] $InputPath,
        [string] $GitExecutable
    )

    $evidence = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    $repoItem = $null
    try { $repoItem = Get-Item -LiteralPath $InputPath -ErrorAction Stop } catch {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'REPO_PATH_NOT_FOUND'
        $Envelope.message = 'The explicitly supplied repository path does not exist or cannot be read.'
        return 4
    }
    if (-not ($repoItem -is [System.IO.DirectoryInfo])) {
        $Envelope.status = 'invalid_input'
        $Envelope.reason_code = 'REPO_PATH_NOT_DIRECTORY'
        $Envelope.message = 'RepoPath must name a directory, not a file.'
        return 4
    }
    # Keep caller-selected RepoPath separate from its lexical absolute path.
    # Selection is not repository proof or authorization.
    $inputFullPath = (Resolve-CesUserPath -Path $repoItem.FullName -RelativeTo $repoItem.FullName).absolute_path

    $isBare = Git-In -GitExecutable $GitExecutable -Directory $inputFullPath -Arguments @('rev-parse', '--is-bare-repository')
    $evidence.Add([ordered]@{ check = 'git_is_bare_repository'; exit_code = $isBare.exit_code; output = (Limit-Text $isBare.stdout 100) })
    $Envelope.coverage.repository_checked = $true
    if (-not $isBare.ok -or $isBare.stdout -notin @('true', 'false')) {
        $Envelope.status = 'unavailable'
        $Envelope.reason_code = if ($isBare.timed_out) { 'GIT_TIMEOUT' }
                                elseif ($isBare.stderr -match 'not a git repository') { 'NOT_GIT_REPOSITORY' }
                                else { 'GIT_REPOSITORY_UNVERIFIED' }
        $Envelope.message = if ($isBare.timed_out) { 'Git did not respond before the read-only probe timed out.' } else { 'Git could not confirm a repository at RepoPath.' }
        if ($isBare.stderr) { $warnings.Add($isBare.stderr) }
        $Envelope.warnings = $warnings.ToArray()
        $Envelope.evidence = $evidence.ToArray()
        return 5
    }

    if ($isBare.stdout -eq 'true') {
        $Envelope.status = 'partial'
        $Envelope.reason_code = 'BARE_REPOSITORY'
        $Envelope.message = 'This is a bare Git repository; it has no verified worktree or stable CES project root.'
        $Envelope.data = [ordered]@{
            requested_path = $InputPath
            resolved_path = $inputFullPath
            source_root = $null
            stable_project_root = $null
            stable_root_verified = $false
            can_persist_ces_state = $false
            worktree_kind = 'bare'
            git_dir = $null
            git_common_dir = $null
            head = [ordered]@{ sha = $null; branch = $null; state = 'not_checked' }
        }
        $Envelope.evidence = $evidence.ToArray()
        return 2
    }

    $inside = Git-In -GitExecutable $GitExecutable -Directory $inputFullPath -Arguments @('rev-parse', '--is-inside-work-tree')
    $evidence.Add([ordered]@{ check = 'git_is_inside_work_tree'; exit_code = $inside.exit_code; output = (Limit-Text $inside.stdout 100) })
    if (-not $inside.ok -or $inside.stdout -ne 'true') {
        $Envelope.status = 'unavailable'
        $Envelope.reason_code = 'NOT_A_WORKTREE'
        $Envelope.message = 'The specified directory is not inside a Git working tree.'
        $Envelope.evidence = $evidence.ToArray()
        return 5
    }

    $top = Git-In -GitExecutable $GitExecutable -Directory $inputFullPath -Arguments @('rev-parse', '--show-toplevel')
    if (-not $top.ok -or [string]::IsNullOrWhiteSpace($top.stdout)) {
        $Envelope.status = 'unavailable'
        $Envelope.reason_code = if ($top.timed_out) { 'GIT_TIMEOUT' } else { 'GIT_TOPLEVEL_UNAVAILABLE' }
        $Envelope.message = 'Git could not resolve the working-tree root.'
        $Envelope.evidence = $evidence.ToArray()
        return 5
    }
    $sourceRoot = Normalize-FullPath -Path $top.stdout -RelativeTo $inputFullPath
    $Envelope.coverage.worktree_checked = $true
    $evidence.Add([ordered]@{ check = 'git_show_toplevel'; exit_code = $top.exit_code; output = $sourceRoot })

    $gitDirProbe = Git-In -GitExecutable $GitExecutable -Directory $sourceRoot -Arguments @('rev-parse', '--absolute-git-dir')
    $gitDir = if ($gitDirProbe.ok) { Normalize-FullPath -Path $gitDirProbe.stdout -RelativeTo $sourceRoot } else { $null }
    $evidence.Add([ordered]@{ check = 'git_absolute_git_dir'; exit_code = $gitDirProbe.exit_code; output = $gitDir })

    $commonProbe = Read-CommonGitDirectory -GitExecutable $GitExecutable -Directory $sourceRoot
    $commonDir = if ($commonProbe.ok) { $commonProbe.path } else { $null }
    $evidence.Add([ordered]@{ check = 'git_common_dir'; exit_code = $(if ($commonProbe.ok) { 0 } else { $null }); output = $commonDir })
    if ($commonProbe.fallback) {
        $warnings.Add('Git lacks --path-format=absolute; used and normalized --git-common-dir.')
    }

    $stableRoot = $null
    if ($gitDir -and $commonDir) {
        $stableRoot = Find-VerifiedStableRoot -GitExecutable $GitExecutable -CommonGitDir $commonDir
    }
    $stableVerified = ($null -ne $stableRoot)
    $Envelope.coverage.stable_root_verified = $stableVerified
    $kind = if (-not $stableVerified) { 'unverified' }
            elseif (Paths-Equal -First $sourceRoot -Second $stableRoot) { 'main' }
            else { 'linked' }

    $headCommit = Git-In -GitExecutable $GitExecutable -Directory $sourceRoot -Arguments @('rev-parse', '--verify', 'HEAD^{commit}')
    $symbolicHead = Git-In -GitExecutable $GitExecutable -Directory $sourceRoot -Arguments @('symbolic-ref', '--quiet', 'HEAD')
    $Envelope.coverage.head_checked = $true
    $headSha = if ($headCommit.ok -and $headCommit.stdout -match '^[0-9a-fA-F]{40,64}$') { $headCommit.stdout.ToLowerInvariant() } else { $null }
    $fullRef = if ($symbolicHead.ok -and $symbolicHead.stdout.StartsWith('refs/heads/', [System.StringComparison]::Ordinal)) {
        $symbolicHead.stdout
    } else { $null }
    $branchName = if ($fullRef) { $fullRef.Substring('refs/heads/'.Length) } else { $null }

    $missingHeadRef = $false
    if (-not $headSha -and $fullRef) {
        # A broken reference is not the same as an unborn branch. Only the
        # explicit 'ref does not exist' exit code permits 'unborn'.
        $refProbe = Git-In -GitExecutable $GitExecutable -Directory $sourceRoot -Arguments @('show-ref', '--verify', '--quiet', $fullRef)
        $missingHeadRef = ($refProbe.exit_code -eq 1)
        $evidence.Add([ordered]@{ check = 'git_show_ref_head'; exit_code = $refProbe.exit_code; output = $null })
    }
    $headState = if ($headSha -and $branchName) { 'attached' }
                 elseif ($headSha) { 'detached' }
                 elseif ($branchName -and $missingHeadRef) { 'unborn' }
                 else { 'unknown' }
    if ($headState -eq 'unborn') { $warnings.Add('HEAD is unborn; no commit SHA is available yet.') }
    if ($headState -eq 'unknown') { $warnings.Add('HEAD could not be verified; no commit SHA is asserted.') }
    $evidence.Add([ordered]@{ check = 'git_verify_head_commit'; exit_code = $headCommit.exit_code; output = $headSha })
    $evidence.Add([ordered]@{ check = 'git_symbolic_ref_head'; exit_code = $symbolicHead.exit_code; output = $fullRef })

    $Envelope.data = [ordered]@{
        requested_path = $InputPath
        resolved_path = $inputFullPath
        source_root = $sourceRoot
        stable_project_root = $stableRoot
        stable_root_verified = $stableVerified
        can_persist_ces_state = $false # Inspect is read-only; saving needs separate CodeSave authorization.
        worktree_kind = $kind
        git_dir = $gitDir
        git_common_dir = $commonDir
        head = [ordered]@{
            sha = $headSha
            branch = $branchName
            state = $headState
        }
    }
    $Envelope.warnings = $warnings.ToArray()
    $Envelope.evidence = $evidence.ToArray()

    if ($stableVerified -and $headState -eq 'unknown') {
        $Envelope.status = 'partial'
        $Envelope.reason_code = 'HEAD_UNVERIFIED'
        $Envelope.message = 'The stable project root is verified, but HEAD state could not be determined.'
        return 2
    }

    if ($stableVerified) {
        $Envelope.status = 'success'
        $Envelope.reason_code = 'INSPECT_OK'
        $Envelope.message = 'Read-only Git inspection completed; stable project root is verified.'
        return 0
    }

    $Envelope.status = 'partial'
    $Envelope.reason_code = 'STABLE_ROOT_UNVERIFIED'
    $Envelope.message = 'Worktree inspected, but a trusted persistent CES data root could not be proven. No location was guessed or written.'
    return 2
}

# This module comes from the trusted Skill directory, never from RepoPath.
. (Join-Path $PSScriptRoot 'collect.ps1')
. (Join-Path $PSScriptRoot 'delivered.ps1')
. (Join-Path $PSScriptRoot 'reconcile.ps1')
. (Join-Path $PSScriptRoot 'codeprepare.ps1')
. (Join-Path $PSScriptRoot 'codevalidate.ps1')
. (Join-Path $PSScriptRoot 'codesave.ps1')
. (Join-Path $PSScriptRoot 'codeshow.ps1')
. (Join-Path $PSScriptRoot 'codefindings.ps1')
. (Join-Path $PSScriptRoot 'codecompare.ps1')
. (Join-Path $PSScriptRoot 'codetrace.ps1')
. (Join-Path $PSScriptRoot 'codeoverview.ps1')
. (Join-Path $PSScriptRoot 'codetriage.ps1')
. (Join-Path $PSScriptRoot 'coderecurrence.ps1')
. (Join-Path $PSScriptRoot 'codesequence.ps1')
. (Join-Path $PSScriptRoot 'codepathtransitions.ps1')
. (Join-Path $PSScriptRoot 'codefocusjourney.ps1')
. (Join-Path $PSScriptRoot 'codefindingrefs.ps1')
. (Join-Path $PSScriptRoot 'codefindingpairrefs.ps1')
. (Join-Path $PSScriptRoot 'codefindingpairlookup.ps1')
. (Join-Path $PSScriptRoot 'codefindingfocus.ps1')
. (Join-Path $PSScriptRoot 'codeanchorfocus.ps1')
. (Join-Path $PSScriptRoot 'codepairfocus.ps1')
. (Join-Path $PSScriptRoot 'codepairoverview.ps1')
. (Join-Path $PSScriptRoot 'codeprofileatlas.ps1')
. (Join-Path $PSScriptRoot 'codeprofilegraph.ps1')
. (Join-Path $PSScriptRoot 'codeprofilepassages.ps1')
. (Join-Path $PSScriptRoot 'codeprofilemotifs.ps1')
. (Join-Path $PSScriptRoot 'codeprofilemaximal.ps1')
. (Join-Path $PSScriptRoot 'codeprofilefamilies.ps1')
. (Join-Path $PSScriptRoot 'codeprofilejoint.ps1')
. (Join-Path $PSScriptRoot 'codeprofiletriple.ps1')
. (Join-Path $PSScriptRoot 'codeprofilewithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofilepairwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofiletriplewithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofilequartetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofilequintetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofilesextetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofileseptetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofileoctetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofilenonetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofiledecetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofileundecetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofileduodecetwithholding.ps1')
. (Join-Path $PSScriptRoot 'codeprofileresiliencefrontier.ps1')
. (Join-Path $PSScriptRoot 'codeprofilesupportbasis.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpivotality.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionorders.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionrankconditioning.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairprecedence.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairadjacency.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairsingleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairdoubleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairtripleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairquadrupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairquintupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairsextupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairseptupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairoctupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairnonupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairdecupleintervening.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairdistancespectrum.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionpairreciprocity.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionreporterroleexposure.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionreporterpartner.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointcreditgraph.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointdominance.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointreduction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointlinkimpact.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointpairinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtripleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquadrupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsextupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointseptupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointoctupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointnonupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointdecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointundecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointduodecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtredecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquattuordecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquindecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsexdecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointseptendecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointoctodecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointnovemdecupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointunvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointduovigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtrevigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquattuorvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquinquevigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsexvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointseptemvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointoctovigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointnovemvigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointuntrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointduotrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtretrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquattuortrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquinquetrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsextrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointseptemtrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointoctotrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointnovemtrigintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointunquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointduoquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtrequadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquattuorquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquinquequadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsexquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointseptemquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointoctoquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointnovemquadragintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointunquinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointduoquinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointtrequinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquattuorquinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointquinquequinquagintupleinteraction.ps1')
. (Join-Path $PSScriptRoot 'codeprofileretentionendpointsexquinquagintupleinteraction.ps1')

$envelope = New-Envelope -ActionName $Action
if ($Action -ieq 'CodeSave') { $envelope.read_only = $false }
# EC-157: reject an unapproved write-capable action at the CLI boundary,
# before parameter-dependent Git discovery or ANY action handler. The
# CodeSave-Snapshot handler separately enforces the same gate in depth.
# -ApprovePersist:$false must NOT count as authorization.
if ($Action -ieq 'CodeSave' -and -not $ApprovePersist.IsPresent) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SAVE_AUTHORIZATION_REQUIRED'
    $envelope.message = 'CodeSave requires the explicit -ApprovePersist switch for local CES storage.'
    $envelope.data = [ordered]@{ persisted = $false; can_persist_ces_state = $false }
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -inotmatch '^(Inspect|Collect|Reconcile|CodePrepare|CodeValidate|CodeSave|CodeShow)$') {
    $envelope.status = 'not_implemented'
    $envelope.reason_code = 'NOT_IMPLEMENTED'
    $envelope.message = "Action '$Action' has no handler in this build. Implemented: Inspect, Collect WorkingTree/DeliveredTarget, Reconcile Snapshot, CodePrepare Snapshot, CodeValidate Snapshot, CodeSave Snapshot, CodeShow List/Detail/Findings/Compare/Trace/Overview/Triage/Recurrence/Sequence."
    Finish -Envelope $envelope -ExitCode 3
}
if ($Action -ieq 'Collect' -and $Mode -inotmatch '^(WorkingTree|DeliveredTarget)$') {
    $envelope.status = 'not_implemented'
    $envelope.reason_code = 'NOT_IMPLEMENTED'
    $envelope.message = "Collect Mode '$Mode' has no handler. Implemented: WorkingTree, DeliveredTarget."
    Finish -Envelope $envelope -ExitCode 3
}
if ($Action -in @('Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave') -and $PSBoundParameters.ContainsKey('Mode') -and $Mode -ine 'Snapshot') {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'SNAPSHOT_MODE_REQUIRED'
    $envelope.message = 'Reconcile, CodePrepare, CodeValidate and CodeSave support only -Mode Snapshot; source mode comes from saved evidence.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and (-not $PSBoundParameters.ContainsKey('Mode') -or $Mode -inotmatch '^(List|Detail|Findings|Compare|Trace|Overview|Triage|Recurrence|Sequence)$')) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_MODE_REQUIRED'
    $envelope.message = 'CodeShow requires explicit -Mode List, Detail, Findings, Compare, Trace, Overview, Triage, Recurrence or Sequence; it never uses the default Collect mode.'
    Finish -Envelope $envelope -ExitCode 4
}
# Never silently accept irrelevant selectors. Finding filters/cursor and
# left/right comparison IDs have disjoint CodeShow-only contracts.
$hasCompareSelector = ($PSBoundParameters.ContainsKey('LeftRecordId') -or
    $PSBoundParameters.ContainsKey('RightRecordId'))
$hasFindingSelector = ($PSBoundParameters.ContainsKey('AfterFindingCursor') -or
    $PSBoundParameters.ContainsKey('FindingSeverity') -or
    $PSBoundParameters.ContainsKey('FindingLayer') -or
    $PSBoundParameters.ContainsKey('FindingPath') -or
    $PSBoundParameters.ContainsKey('FindingSourceMode') -or
    $PSBoundParameters.ContainsKey('FindingsRecordIds'))
$hasTraceSelector = ($PSBoundParameters.ContainsKey('FindingId') -or
    $PSBoundParameters.ContainsKey('AfterTraceCursor') -or
    $PSBoundParameters.ContainsKey('TraceRecordIds'))
$hasOverviewSelector = ($PSBoundParameters.ContainsKey('AfterOverviewCursor') -or
    $PSBoundParameters.ContainsKey('OverviewSourceMode') -or
    $PSBoundParameters.ContainsKey('OverviewRecordIds'))
$hasTriageSelector = ($PSBoundParameters.ContainsKey('AfterTriageCursor') -or
    $PSBoundParameters.ContainsKey('TriageSourceMode') -or
    $PSBoundParameters.ContainsKey('TriageTop') -or
    $PSBoundParameters.ContainsKey('TriageRecordIds'))
$hasSequenceSelector = ($PSBoundParameters.ContainsKey('SequenceRecordIds') -or
    $PSBoundParameters.ContainsKey('SequenceTop') -or
    $PSBoundParameters.ContainsKey('SequencePath') -or
    $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
    $PSBoundParameters.ContainsKey('SequenceFindingId') -or
    $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairPathIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingSide') -or
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingIndex') -or
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingCounterpartIndex'))
$hasRecurrenceSelector = ($PSBoundParameters.ContainsKey('AfterRecurrenceCursor') -or
    $PSBoundParameters.ContainsKey('RecurrenceSourceMode') -or
    $PSBoundParameters.ContainsKey('RecurrencePath') -or
    $PSBoundParameters.ContainsKey('RecurrenceMinRecords') -or
    $PSBoundParameters.ContainsKey('RecurrenceTop') -or
    $PSBoundParameters.ContainsKey('RecurrenceRecordIds'))
if ($Action -ieq 'CodeShow' -and
    ($PSBoundParameters.ContainsKey('IncludePatches') -or
    $PSBoundParameters.ContainsKey('IncludeUntrackedContent') -or
    $PSBoundParameters.ContainsKey('BaseSha') -or $PSBoundParameters.ContainsKey('TargetSha') -or
    $PSBoundParameters.ContainsKey('TargetRef') -or $PSBoundParameters.ContainsKey('EvidencePath') -or
    $PSBoundParameters.ContainsKey('InputPath') -or $PSBoundParameters.ContainsKey('ApprovePersist') -or
    ($Mode -ieq 'List' -and ($PSBoundParameters.ContainsKey('RecordId') -or $hasFindingSelector)) -or
    ($Mode -ine 'Compare' -and $hasCompareSelector) -or
    ($Mode -ine 'Trace' -and $hasTraceSelector) -or
    ($Mode -ine 'Overview' -and $hasOverviewSelector) -or
    ($Mode -ine 'Triage' -and $hasTriageSelector) -or
    ($Mode -ine 'Recurrence' -and $hasRecurrenceSelector) -or
    ($Mode -ine 'Sequence' -and $hasSequenceSelector) -or
    ($Mode -ieq 'Detail' -and ($PSBoundParameters.ContainsKey('AfterRecordId') -or
        $PSBoundParameters.ContainsKey('Limit') -or $hasFindingSelector)) -or
    ($Mode -ieq 'Findings' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId'))) -or
    ($Mode -ieq 'Compare' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId') -or
        $PSBoundParameters.ContainsKey('Limit') -or $hasFindingSelector)) -or
    ($Mode -ieq 'Trace' -and ($PSBoundParameters.ContainsKey('AfterRecordId') -or
        $hasFindingSelector)) -or
    ($Mode -ieq 'Overview' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId') -or $hasFindingSelector)) -or
    ($Mode -ieq 'Triage' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId') -or $hasFindingSelector)) -or
    ($Mode -ieq 'Recurrence' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId') -or $hasFindingSelector)) -or
    ($Mode -ieq 'Sequence' -and ($PSBoundParameters.ContainsKey('RecordId') -or
        $PSBoundParameters.ContainsKey('AfterRecordId') -or $PSBoundParameters.ContainsKey('Limit') -or
        $hasFindingSelector -or $hasCompareSelector -or $hasTraceSelector -or
        $hasOverviewSelector -or $hasTriageSelector -or $hasRecurrenceSelector)))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
    $envelope.message = 'List, Detail, Findings, Compare, Trace, Overview, Triage, Recurrence and Sequence have separate read-only selector contracts; source and write switches are forbidden.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    (-not $PSBoundParameters.ContainsKey('SequenceRecordIds') -or
        [string]::IsNullOrEmpty($SequenceRecordIds))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_RECORD_IDS_INVALID'
    $envelope.message = 'Sequence requires 2..12 distinct, complete lowercase saved record IDs in caller order as one argument.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    ($SequenceTop -lt 1 -or $SequenceTop -gt 20)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_TOP_INVALID'
    $envelope.message = 'SequenceTop must be in 1..20 and caps adjacent, baseline, trajectory, focus and ranked saved-path previews, never full selected-record counts.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePath') -and
    ([string]::IsNullOrEmpty($SequencePath) -or $SequencePath.Length -gt 4096 -or
        $SequencePath.Contains([char]0))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PATH_INVALID'
    $envelope.message = 'SequencePath must be one nonempty literal case-sensitive saved Git path of at most 4096 characters without NUL; omit it for full-only Sequence output.'
    Finish -Envelope $envelope -ExitCode 4
}
# EC-049: a fifth-level original counterpart Finding is meaningful ONLY
# after all prior pair/path/anchor/original endpoint coordinates. Reject
# explicit empty, padded, zero, signed or out-of-range ordinals first.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingCounterpartIndex') -and
    (-not $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathAnchorIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingSide') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingIndex') -or
        $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequencePairIndex') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairPathAnchorFindingSide -cnotin @('left','right') -or
        $SequencePairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
        [int]$SequencePairPathAnchorFindingIndex -gt 40 -or
        $SequencePairPathAnchorFindingCounterpartIndex -cnotmatch '^[1-9][0-9]?$' -or
        [int]$SequencePairPathAnchorFindingCounterpartIndex -gt 40)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_COUNTERPART_SELECTOR_INVALID'
    $envelope.message = 'Opposite-endpoint original Finding ordinal 1..40 requires all five prior pair/path/anchor/side/Finding coordinates and no competing focus.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-048: fail closed on unpaired fourth-level selector fields BEFORE
# touching any store. The side is canonical lowercase to avoid accidental
# ambiguous output identity; all ordinals are query-local.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    ($PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingSide') -or
        $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingIndex')) -and
    (-not $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingSide') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequencePairIndex') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairPathAnchorFindingSide -cnotin @('left','right') -or
        $SequencePairPathAnchorFindingIndex -cnotmatch '^[1-9][0-9]?$' -or
        [int]$SequencePairPathAnchorFindingIndex -gt 40)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_FINDING_SELECTOR_INVALID'
    $envelope.message = 'Original Finding focus requires all three parent ordinals, canonical side left/right and one-based index 1..40, without a competing selector.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-047: the third ordinal must refer to a saved anchor inside the
# complete indexed pair/path. Explicit empty, padded or competing selectors
# fail BEFORE any storage work; the older two-index route remains valid.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePairPathAnchorIndex') -and
    (-not $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -or
        -not $PSBoundParameters.ContainsKey('SequencePairPathIndex') -or
        $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequencePairIndex') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairPathAnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
        [int]$SequencePairPathAnchorIndex -gt 480)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_ANCHOR_SELECTOR_INVALID'
    $envelope.message = 'SequencePairPathAnchorIndex requires both pair and path ordinals, canonical 1..480 and no other focus selector.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-046: path index is valid only in a report pair overview, never as a
# free-standing or literal-path/other-focus selector.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePairPathIndex') -and
    (-not $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -or
        $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequencePairIndex') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairPathIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
        [int]$SequencePairPathIndex -gt 480)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_PATH_SELECTOR_INVALID'
    $envelope.message = 'SequencePairPathIndex needs SequencePairOverviewIndex, canonical 1..480 and no other focus selector.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-042: a targeted saved Finding is always an ORIGINAL record-scoped ID,
# never an unscoped ID or an implicit path / cross-report identity match.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    ($PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId')) -and
    (-not $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        -not $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        -not $PSBoundParameters.ContainsKey('SequencePath') -or
        $SequenceFindingRecordId -cnotmatch '^ci-[0-9a-f]{64}$' -or
        $SequenceFindingId -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$')) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_FINDING_SELECTOR_INVALID'
    $envelope.message = 'Sequence Finding focus requires both -SequenceFindingRecordId (full lowercase selected record ID) and -SequenceFindingId (original case-sensitive Finding ID), plus an explicit literal -SequencePath.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-044: select precisely one canonical report pair at an explicit literal
# path. The one-based index is local to the current ordered record selection.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePairIndex') -and
    (-not $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairIndex -cnotmatch '^[1-9][0-9]?$' -or
        [int]$SequencePairIndex -gt 66)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_SELECTOR_INVALID'
    $envelope.message = 'SequencePairIndex requires -SequencePath and an exclusive canonical report-pair index 1..66; no anchor or original Finding selector may be combined.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-045: explicit global pair overview enumerates ALL saved paths and
# conflicts with every literal-path or other focused selector.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequencePairOverviewIndex') -and
    ($PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequencePairIndex') -or
        $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequencePairOverviewIndex -cnotmatch '^[1-9][0-9]?$' -or
        [int]$SequencePairOverviewIndex -gt 66)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_PAIR_OVERVIEW_SELECTOR_INVALID'
    $envelope.message = 'SequencePairOverviewIndex selects one global 1..66 report pair and must not be combined with a path or another focus selector.'
    Finish -Envelope $envelope -ExitCode 4
}

# EC-043: a canonical anchor index is one-based, applies ONLY to the current
# explicit literal path and caller selection, and cannot be mixed with the
# EC-042 original Finding seed selectors.
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence' -and
    $PSBoundParameters.ContainsKey('SequenceAnchorIndex') -and
    (-not $PSBoundParameters.ContainsKey('SequencePath') -or
        $PSBoundParameters.ContainsKey('SequenceFindingRecordId') -or
        $PSBoundParameters.ContainsKey('SequenceFindingId') -or
        $SequenceAnchorIndex -cnotmatch '^[1-9][0-9]{0,2}$' -or
        [int]$SequenceAnchorIndex -gt 480)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SEQUENCE_ANCHOR_SELECTOR_INVALID'
    $envelope.message = 'SequenceAnchorIndex requires -SequencePath and a canonical 1..480 integer index, and cannot be combined with original Finding selectors.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Findings' -and
    $PSBoundParameters.ContainsKey('FindingsRecordIds') -and
    $PSBoundParameters.ContainsKey('AfterFindingCursor')) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_FINDINGS_SELECTION_CONFLICT'
    $envelope.message = 'Selected Findings records cannot be combined with any Finding cursor; -Limit is a returned-row cap, not a selected-body scan bound.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Findings' -and
    $PSBoundParameters.ContainsKey('FindingsRecordIds') -and
    [string]::IsNullOrEmpty($FindingsRecordIds)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_FINDINGS_RECORD_IDS_INVALID'
    $envelope.message = 'FindingsRecordIds must contain 2..24 distinct full lowercase ci-SHA256 IDs in one comma-separated argument.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Findings' -and (
    ($PSBoundParameters.ContainsKey('FindingSeverity') -and [string]::IsNullOrEmpty($FindingSeverity)) -or
    ($PSBoundParameters.ContainsKey('FindingLayer') -and [string]::IsNullOrEmpty($FindingLayer)) -or
    ($PSBoundParameters.ContainsKey('FindingPath') -and [string]::IsNullOrEmpty($FindingPath)) -or
    ($PSBoundParameters.ContainsKey('FindingSourceMode') -and [string]::IsNullOrEmpty($FindingSourceMode)) -or
    ($PSBoundParameters.ContainsKey('AfterFindingCursor') -and [string]::IsNullOrEmpty($AfterFindingCursor)))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_FINDING_FILTER_INVALID'
    $envelope.message = 'Explicit Finding selector values must not be empty; omit a selector to disable it.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Overview' -and
    $PSBoundParameters.ContainsKey('OverviewRecordIds') -and
    ($PSBoundParameters.ContainsKey('AfterOverviewCursor') -or $PSBoundParameters.ContainsKey('Limit'))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_OVERVIEW_SELECTION_CONFLICT'
    $envelope.message = 'An explicit Overview record set cannot use a cursor or Limit, including an explicitly supplied default Limit.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Overview' -and
    $PSBoundParameters.ContainsKey('OverviewRecordIds') -and [string]::IsNullOrEmpty($OverviewRecordIds)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_OVERVIEW_RECORD_IDS_INVALID'
    $envelope.message = 'OverviewRecordIds must contain 2..24 comma-separated distinct ci-SHA256 IDs.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Overview' -and
    $PSBoundParameters.ContainsKey('AfterOverviewCursor') -and [string]::IsNullOrEmpty($AfterOverviewCursor)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_INVALID_OVERVIEW_CURSOR'
    $envelope.message = 'An explicitly supplied Overview cursor must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Overview' -and
    $PSBoundParameters.ContainsKey('OverviewSourceMode') -and [string]::IsNullOrEmpty($OverviewSourceMode)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_OVERVIEW_FILTER_INVALID'
    $envelope.message = 'An explicitly supplied Overview source-mode filter must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Triage' -and
    $PSBoundParameters.ContainsKey('TriageRecordIds') -and
    ($PSBoundParameters.ContainsKey('AfterTriageCursor') -or $PSBoundParameters.ContainsKey('Limit'))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_TRIAGE_SELECTION_CONFLICT'
    $envelope.message = 'A selected Triage record set cannot be combined with a cursor or Limit, even an explicitly supplied default Limit.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Triage' -and
    $PSBoundParameters.ContainsKey('AfterTriageCursor') -and [string]::IsNullOrEmpty($AfterTriageCursor)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_INVALID_TRIAGE_CURSOR'
    $envelope.message = 'An explicitly supplied Triage cursor must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Triage' -and
    $PSBoundParameters.ContainsKey('TriageSourceMode') -and [string]::IsNullOrEmpty($TriageSourceMode)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_TRIAGE_FILTER_INVALID'
    $envelope.message = 'An explicitly supplied Triage source-mode filter must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Triage' -and
    $PSBoundParameters.ContainsKey('TriageRecordIds') -and
    [string]::IsNullOrEmpty($TriageRecordIds)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_TRIAGE_RECORD_IDS_INVALID'
    $envelope.message = 'TriageRecordIds must contain 2..24 comma-separated distinct ci-SHA256 IDs.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Recurrence' -and
    $PSBoundParameters.ContainsKey('AfterRecurrenceCursor') -and [string]::IsNullOrEmpty($AfterRecurrenceCursor)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_INVALID_RECURRENCE_CURSOR'
    $envelope.message = 'An explicitly supplied Recurrence cursor must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Recurrence' -and
    ($PSBoundParameters.ContainsKey('RecurrenceSourceMode') -and [string]::IsNullOrEmpty($RecurrenceSourceMode) -or
     $PSBoundParameters.ContainsKey('RecurrencePath') -and [string]::IsNullOrEmpty($RecurrencePath))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_RECURRENCE_FILTER_INVALID'
    $envelope.message = 'An explicitly supplied Recurrence filter must not be empty.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Recurrence' -and
    $PSBoundParameters.ContainsKey('RecurrenceRecordIds') -and
    [string]::IsNullOrEmpty($RecurrenceRecordIds)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID'
    $envelope.message = 'RecurrenceRecordIds must contain 2..24 comma-separated distinct ci-SHA256 IDs.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Recurrence' -and
    $PSBoundParameters.ContainsKey('RecurrenceRecordIds') -and
    ($PSBoundParameters.ContainsKey('AfterRecurrenceCursor') -or $PSBoundParameters.ContainsKey('Limit'))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_RECURRENCE_SELECTION_CONFLICT'
    $envelope.message = 'An explicit record set cannot be combined with a pagination cursor or Limit; the 2..24 selected records are all checked.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Trace' -and
    $PSBoundParameters.ContainsKey('TraceRecordIds') -and
    ($PSBoundParameters.ContainsKey('AfterTraceCursor') -or $PSBoundParameters.ContainsKey('Limit'))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_TRACE_SELECTION_CONFLICT'
    $envelope.message = 'Explicitly selected Trace record IDs cannot be combined with a cursor or Limit, including explicit default values.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Trace' -and
    $PSBoundParameters.ContainsKey('TraceRecordIds') -and
    [string]::IsNullOrEmpty($TraceRecordIds)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_TRACE_RECORD_IDS_INVALID'
    $envelope.message = 'TraceRecordIds must contain 2..24 comma-separated distinct exact lowercase saved IDs, including RecordId.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Trace' -and
    $PSBoundParameters.ContainsKey('AfterTraceCursor') -and
    [string]::IsNullOrEmpty($AfterTraceCursor)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_INVALID_TRACE_CURSOR'
    $envelope.message = 'An explicitly supplied Trace cursor must not be empty; omit the parameter to start a new search.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ne 'CodeShow' -and ($PSBoundParameters.ContainsKey('RecordId') -or
    $PSBoundParameters.ContainsKey('AfterRecordId') -or $PSBoundParameters.ContainsKey('Limit') -or
    $hasFindingSelector -or $hasCompareSelector -or $hasTraceSelector -or $hasOverviewSelector -or
    $hasTriageSelector -or $hasRecurrenceSelector -or $hasSequenceSelector)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'CODE_SHOW_SELECTORS_NOT_APPLICABLE'
    $envelope.message = 'Record, Finding, Compare, Trace, Overview, Triage, Recurrence and Sequence selectors are only valid with CodeShow.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'Reconcile' -and ($IncludePatches.IsPresent -or $IncludeUntrackedContent.IsPresent -or
    -not [string]::IsNullOrEmpty($BaseSha) -or -not [string]::IsNullOrEmpty($TargetSha) -or -not [string]::IsNullOrEmpty($TargetRef))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'RECONCILE_SELECTORS_NOT_APPLICABLE'
    $envelope.message = 'Reconcile derives Git selectors and content depth from EvidencePath, not conflicting CLI switches.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -notin @('Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave') -and -not [string]::IsNullOrEmpty($EvidencePath)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'EVIDENCE_PATH_NOT_APPLICABLE'
    $envelope.message = 'EvidencePath is only valid with -Action Reconcile, CodePrepare, CodeValidate or CodeSave.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -in @('CodePrepare', 'CodeValidate', 'CodeSave') -and
    (-not [string]::IsNullOrEmpty($BaseSha) -or -not [string]::IsNullOrEmpty($TargetSha) -or -not [string]::IsNullOrEmpty($TargetRef))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = if ($Action -ieq 'CodePrepare') { 'CODE_PREPARE_SELECTORS_NOT_APPLICABLE' } elseif ($Action -ieq 'CodeSave') { 'CODE_SAVE_SELECTORS_NOT_APPLICABLE' } else { 'CODE_VALIDATE_SELECTORS_NOT_APPLICABLE' }
    $envelope.message = 'CodePrepare, CodeValidate and CodeSave derive selectors from the saved Collect observation; SHA/ref overrides are invalid.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -notin @('CodeValidate', 'CodeSave') -and $PSBoundParameters.ContainsKey('InputPath')) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'INPUT_PATH_NOT_APPLICABLE'
    $envelope.message = 'InputPath is only used by CodeValidate or CodeSave for the draft JSON file.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ine 'CodeSave' -and $PSBoundParameters.ContainsKey('ApprovePersist')) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'APPROVE_PERSIST_NOT_APPLICABLE'
    $envelope.message = 'Only CodeSave accepts -ApprovePersist.'
    Finish -Envelope $envelope -ExitCode 4
}
if ($Action -ieq 'Collect' -and $Mode -ieq 'WorkingTree' -and
    (-not [string]::IsNullOrEmpty($BaseSha) -or -not [string]::IsNullOrEmpty($TargetSha) -or -not [string]::IsNullOrEmpty($TargetRef))) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'SELECTORS_NOT_APPLICABLE'
    $envelope.message = 'Commit selectors belong to DeliveredTarget, not WorkingTree; no selector was silently ignored.'
    Finish -Envelope $envelope -ExitCode 4
}
if ([string]::IsNullOrWhiteSpace($RepoPath)) {
    $envelope.status = 'invalid_input'
    $envelope.reason_code = 'REPO_PATH_REQUIRED'
    $envelope.message = 'An explicit -RepoPath is required; CES never guesses a repository.'
    Finish -Envelope $envelope -ExitCode 4
}
$git = Get-Command -Name 'git' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $git) {
    $envelope.status = 'unavailable'
    $envelope.reason_code = 'GIT_UNAVAILABLE'
    $envelope.message = 'Git executable is not installed or not visible on PATH.'
    Finish -Envelope $envelope -ExitCode 5
}
try {
    if ($Action -ieq 'Inspect') {
        $resultCode = Inspect-Repository -Envelope $envelope -InputPath $RepoPath -GitExecutable $git.Source
    } elseif ($Action -ieq 'Reconcile') {
        $resultCode = Reconcile-Snapshot -Envelope $envelope -InputPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $git.Source
    } elseif ($Action -ieq 'CodePrepare') {
        $resultCode = CodePrepare-Snapshot -Envelope $envelope -InputPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $git.Source -RevealPatches $IncludePatches.IsPresent -RevealUntrackedContent $IncludeUntrackedContent.IsPresent
    } elseif ($Action -ieq 'CodeValidate') {
        $resultCode = CodeValidate-Snapshot -Envelope $envelope -InputPath $InputPath -RepoPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $git.Source -RevealPatches $IncludePatches.IsPresent -RevealUntrackedContent $IncludeUntrackedContent.IsPresent
    } elseif ($Action -ieq 'CodeShow') {
        $resultCode = CodeShow-Local -Envelope $envelope -RepoPath $RepoPath -GitExecutable $git.Source -Mode $Mode -RecordId $RecordId -AfterRecordId $AfterRecordId -Limit $Limit -AfterFindingCursor $AfterFindingCursor -FindingSeverity $FindingSeverity -FindingLayer $FindingLayer -FindingPath $FindingPath -FindingSourceMode $FindingSourceMode -FindingsRecordIds $FindingsRecordIds -FindingsRecordIdsExplicit ($PSBoundParameters.ContainsKey('FindingsRecordIds')) -AfterFindingCursorExplicit ($PSBoundParameters.ContainsKey('AfterFindingCursor')) -LeftRecordId $LeftRecordId -RightRecordId $RightRecordId -FindingId $FindingId -AfterTraceCursor $AfterTraceCursor -TraceRecordIds $TraceRecordIds -TraceRecordIdsExplicit ($PSBoundParameters.ContainsKey('TraceRecordIds')) -AfterOverviewCursor $AfterOverviewCursor -OverviewSourceMode $OverviewSourceMode -OverviewRecordIds $OverviewRecordIds -OverviewRecordIdsExplicit ($PSBoundParameters.ContainsKey('OverviewRecordIds')) -AfterTriageCursor $AfterTriageCursor -TriageSourceMode $TriageSourceMode -TriageTop $TriageTop -TriageRecordIds $TriageRecordIds -TriageRecordIdsExplicit ($PSBoundParameters.ContainsKey('TriageRecordIds')) -LimitExplicit ($PSBoundParameters.ContainsKey('Limit')) -AfterRecurrenceCursor $AfterRecurrenceCursor -RecurrenceSourceMode $RecurrenceSourceMode -RecurrencePath $RecurrencePath -RecurrenceMinRecords $RecurrenceMinRecords -RecurrenceTop $RecurrenceTop -RecurrenceRecordIds $RecurrenceRecordIds -SequenceRecordIds $SequenceRecordIds -SequenceTop $SequenceTop -SequencePath $SequencePath -SequencePathExplicit ($PSBoundParameters.ContainsKey('SequencePath')) -SequenceFindingRecordId $SequenceFindingRecordId -SequenceFindingId $SequenceFindingId -SequenceFindingRecordIdExplicit ($PSBoundParameters.ContainsKey('SequenceFindingRecordId')) -SequenceFindingIdExplicit ($PSBoundParameters.ContainsKey('SequenceFindingId')) -SequenceAnchorIndex $SequenceAnchorIndex -SequenceAnchorIndexExplicit ($PSBoundParameters.ContainsKey('SequenceAnchorIndex')) -SequencePairIndex $SequencePairIndex -SequencePairIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairIndex')) -SequencePairOverviewIndex $SequencePairOverviewIndex -SequencePairOverviewIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairOverviewIndex')) -SequencePairPathIndex $SequencePairPathIndex -SequencePairPathIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairPathIndex')) -SequencePairPathAnchorIndex $SequencePairPathAnchorIndex -SequencePairPathAnchorIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairPathAnchorIndex')) -SequencePairPathAnchorFindingSide $SequencePairPathAnchorFindingSide -SequencePairPathAnchorFindingSideExplicit ($PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingSide')) -SequencePairPathAnchorFindingIndex $SequencePairPathAnchorFindingIndex -SequencePairPathAnchorFindingIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingIndex')) -SequencePairPathAnchorFindingCounterpartIndex $SequencePairPathAnchorFindingCounterpartIndex -SequencePairPathAnchorFindingCounterpartIndexExplicit ($PSBoundParameters.ContainsKey('SequencePairPathAnchorFindingCounterpartIndex'))
    } elseif ($Action -ieq 'CodeSave') {
        $resultCode = CodeSave-Snapshot -Envelope $envelope -InputPath $InputPath -RepoPath $RepoPath -EvidencePath $EvidencePath -GitExecutable $git.Source -RevealPatches $IncludePatches.IsPresent -RevealUntrackedContent $IncludeUntrackedContent.IsPresent -ApprovePersist $ApprovePersist.IsPresent
    } elseif ($Mode -ieq 'WorkingTree') {
        $resultCode = Collect-WorkingTree -Envelope $envelope -InputPath $RepoPath -GitExecutable $git.Source -RequestPatches $IncludePatches.IsPresent -RequestUntrackedContent $IncludeUntrackedContent.IsPresent
    } else {
        $resultCode = Collect-DeliveredTarget -Envelope $envelope -InputPath $RepoPath -GitExecutable $git.Source -BaseSha $BaseSha -TargetSha $TargetSha -TargetRef $TargetRef -RequestPatches $IncludePatches.IsPresent -RequestUntrackedContent $IncludeUntrackedContent.IsPresent
    }
    Finish -Envelope $envelope -ExitCode $resultCode
} catch {
    $envelope.status = 'unavailable'
    if ($Action -ieq 'CodeSave') { $envelope.read_only = $false }
    $envelope.reason_code = switch ($Action.ToLowerInvariant()) { 'collect' { 'COLLECT_FAILED' } 'reconcile' { 'RECONCILE_FAILED' } 'codeprepare' { 'CODE_PREPARE_FAILED' } 'codevalidate' { 'CODE_VALIDATE_FAILED' } 'codesave' { 'CODE_SAVE_FAILED' } 'codeshow' { 'CODE_SHOW_FAILED' } default { 'INSPECT_FAILED' } }
    $envelope.message = if ($Action -ieq 'CodeSave') { 'The local CES save action terminated without a confirmed record.' } else { 'The requested read-only action terminated before completing its checks.' }
    $envelope.warnings = @((Limit-Text -Value $_.Exception.Message))
    Finish -Envelope $envelope -ExitCode 5
}

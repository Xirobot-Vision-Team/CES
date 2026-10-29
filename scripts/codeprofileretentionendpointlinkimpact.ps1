#requires -Version 7.0
<#
    EC-095: exact single-SCC-link deletion impact on ORIGINAL strict reachability.

    Scope is the checked EC-093 ORIGINAL endpoint-FIRST comparison SCC DAG and
    the unique EC-094 transitive reduction. For each ACTUAL direct condensed
    link, remove ALL of that link's constituent ORIGINAL strict comparisons
    from the FULL condensation graph, keeping every other direct link (even
    redundant shortcuts). Compare reachability before/after that deletion.

    For indispensable links separately delete the same link from the REDUCED
    DAG; the extra loss in that counterfactual is reported distinctly. These
    two experiments are NOT interchangeable: dropped redundant shortcuts can
    preserve a full-graph path that is absent after reduced-DAG link deletion.

    These are hypothetical comparison-graph interventions, not removal of
    real saved findings or historical observations, not repair proposals and
    not probabilities. No evidence, business source, Git, network or state read.
#>

function Get-CodeSequenceDominanceLinkImpactReachability {
    param(
        [int] $ComponentCount,
        [object[]] $DirectLinks,
        [bool] $RetainedOnly = $false,
        [int] $OmittedSourceComponent = 0,
        [int] $OmittedTargetComponent = 0
    )
    if ($ComponentCount -lt 1 -or $ComponentCount -gt 12 -or
        (($OmittedSourceComponent -eq 0) -ne ($OmittedTargetComponent -eq 0))) {
        throw 'Code Sequence link-impact received an invalid component graph/deletion selector.'
    }
    $reach = [bool[,]]::new($ComponentCount, $ComponentCount)
    for ($i = 0; $i -lt $ComponentCount; $i++) { $reach[$i, $i] = $true }
    foreach ($link in $DirectLinks) {
        if ($null -eq $link) { throw 'Code Sequence link-impact received a missing direct link.' }
        $from = [int]$link.dominant_component_index
        $to = [int]$link.subordinate_component_index
        if ($from -lt 1 -or $to -lt 1 -or $from -gt $ComponentCount -or
            $to -gt $ComponentCount -or $from -eq $to) {
            throw 'Code Sequence link-impact received a noncanonical SCC link.'
        }
        if ($RetainedOnly -and -not [bool]$link.indispensable_for_original_strict_component_reachability) {
            continue
        }
        if ($from -eq $OmittedSourceComponent -and $to -eq $OmittedTargetComponent) {
            continue
        }
        $reach[$from - 1, $to - 1] = $true
    }
    for ($k = 0; $k -lt $ComponentCount; $k++) {
        for ($i = 0; $i -lt $ComponentCount; $i++) {
            if (-not $reach[$i, $k]) { continue }
            for ($j = 0; $j -lt $ComponentCount; $j++) {
                if ($reach[$k, $j]) { $reach[$i, $j] = $true }
            }
        }
    }
    # A PSObject prevents the pipeline from unrolling the multidimensional
    # array, including the empty-link and singleton-SCC cases.
    return [pscustomobject]@{ Matrix = $reach }
}

function Get-CodeSequenceDominanceLinkImpactLostPairs {
    param(
        [bool[,]] $Before,
        [bool[,]] $After,
        [object[]] $Components
    )
    $componentCount = $Components.Length
    if ($Before.GetLength(0) -ne $componentCount -or
        $Before.GetLength(1) -ne $componentCount -or
        $After.GetLength(0) -ne $componentCount -or
        $After.GetLength(1) -ne $componentCount) {
        throw 'Code Sequence link-impact compared different SCC universes.'
    }
    $lost = [System.Collections.Generic.List[object]]::new()
    $reporterPairs = 0
    for ($i = 0; $i -lt $componentCount; $i++) {
        for ($j = 0; $j -lt $componentCount; $j++) {
            if ($After[$i, $j] -and -not $Before[$i, $j]) {
                throw 'Code Sequence link-impact fabricated a new strict path after deletion.'
            }
            if (-not $Before[$i, $j] -or $After[$i, $j]) { continue }
            if ($i -eq $j) { throw 'Code Sequence link-impact removed reflexive SCC identity.' }
            $membersFrom = [int[]]$Components[$i].original_member_caller_positions
            $membersTo = [int[]]$Components[$j].original_member_caller_positions
            if ($membersFrom.Length -lt 1 -or $membersTo.Length -lt 1) {
                throw 'Code Sequence link-impact found an SCC with no ORIGINAL reporters.'
            }
            $multiplicity = $membersFrom.Length * $membersTo.Length
            $reporterPairs += $multiplicity
            $lost.Add([ordered]@{
                from_strict_component_index = $i + 1
                to_strict_component_index = $j + 1
                exact_ordered_original_reporter_pair_multiplicity = $multiplicity
            })
        }
    }
    return [ordered]@{
        exact_lost_reachable_component_pair_count = $lost.Count
        exact_lost_reachable_original_reporter_pair_count = $reporterPairs
        lost_reachable_component_pairs_in_canonical_order = $lost.ToArray()
    }
}

function Get-CodeSequenceEndpointDominanceLinkImpactProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [int] $N
    )
    if ($null -eq $DominanceTopology -or $null -eq $DominanceReduction -or
        $N -lt 2 -or $N -gt 12 -or
        -not [bool]$DominanceReduction.every_original_strict_component_path_is_preserved -or
        -not [bool]$DominanceReduction.each_discarded_direct_link_has_shortest_deterministic_alternative_with_original_pair_witnesses -or
        -not [bool]$DominanceReduction.no_equal_pair_or_no_first_credit_is_used_as_a_strict_route -or
        -not [bool]$DominanceReduction.original_direct_credit_advantages_are_not_summed_along_alternative_paths -or
        -not [bool]$DominanceReduction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence link-impact requires checked EC-093/094 ORIGINAL graph and reduction.'
    }
    # Do not accept a predecessor's success flags as provenance. Rebuild the
    # ENTIRE EC-094 projection from the already-checked EC-093 source, then
    # compare its public contract and every underlying SCC, canonical pair,
    # credit margin and retained-only shortest witness. This is a pure graph
    # re-derivation, NOT re-reading evidence or enumerating saved orderings.
    $fresh = Get-CodeSequenceEndpointDominanceReductionProjection `
        -DominanceTopology $DominanceTopology -N $N
    $freshJson = ConvertTo-Json -InputObject $fresh -Depth 30 -Compress
    $givenJson = ConvertTo-Json -InputObject $DominanceReduction -Depth 30 -Compress
    if ($freshJson -cne $givenJson) {
        throw 'Code Sequence link-impact rejected modified EC-094 SCC reduction/route/credit evidence.'
    }
    $components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    $links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $componentCount = $components.Length
    if ($componentCount -ne [int]$DominanceReduction.exact_strongly_connected_component_count -or
        $links.Length -ne [int]$DominanceReduction.exact_original_condensed_direct_component_link_count) {
        throw 'Code Sequence link-impact changed ORIGINAL SCC/link counts.'
    }
    $fullMatrix = (Get-CodeSequenceDominanceLinkImpactReachability `
        -ComponentCount $componentCount -DirectLinks $links).Matrix
    $reducedMatrix = (Get-CodeSequenceDominanceLinkImpactReachability `
        -ComponentCount $componentCount -DirectLinks $links -RetainedOnly $true).Matrix
    $reachableComponentPairs = 0
    $reachableReporterPairs = 0
    for ($i = 0; $i -lt $componentCount; $i++) {
        $reported = [int[]]$components[$i].reachable_other_component_indices
        $expected = [System.Collections.Generic.List[int]]::new()
        for ($j = 0; $j -lt $componentCount; $j++) {
            if ($fullMatrix[$i, $j] -ne $reducedMatrix[$i, $j]) {
                throw 'Code Sequence link-impact found a changed baseline between full and reduced DAG.'
            }
            if ($i -eq $j -or -not $fullMatrix[$i, $j]) { continue }
            $expected.Add($j + 1)
            $reachableComponentPairs++
            $reachableReporterPairs += @($components[$i].original_member_caller_positions).Count *
                @($components[$j].original_member_caller_positions).Count
        }
        if (($expected.ToArray() -join ',') -cne ($reported -join ',')) {
            throw 'Code Sequence link-impact received mismatched SCC reachability.'
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $impactful = 0
    $redundant = 0
    $totalFullLosses = 0
    $totalFullReporterLosses = 0
    $totalReductionExtraLosses = 0
    $totalReductionExtraReporterLosses = 0
    for ($linkIndex = 0; $linkIndex -lt $links.Length; $linkIndex++) {
        $link = $links[$linkIndex]
        $from = [int]$link.dominant_component_index
        $to = [int]$link.subordinate_component_index
        $indispensable = [bool]$link.indispensable_for_original_strict_component_reachability
        $fullWithout = (Get-CodeSequenceDominanceLinkImpactReachability `
            -ComponentCount $componentCount -DirectLinks $links `
            -OmittedSourceComponent $from -OmittedTargetComponent $to).Matrix
        $fullLoss = Get-CodeSequenceDominanceLinkImpactLostPairs `
            -Before $fullMatrix -After $fullWithout -Components $components
        $fullPairCount = [int]$fullLoss.exact_lost_reachable_component_pair_count
        $fullReporterCount = [int]$fullLoss.exact_lost_reachable_original_reporter_pair_count
        $reducedWithoutView = $null
        $extraView = $null
        if ($indispensable) {
            $impactful++
            # Every indispensable edge must at least destroy its own u->v
            # reachability in the FULL direct graph. Otherwise EC-094's
            # uniqueness certificate has been violated.
            if ($fullPairCount -lt 1 -or $fullWithout[$from - 1, $to - 1]) {
                throw 'Code Sequence link-impact found a retained link with no full-graph endpoint loss.'
            }
            $reducedWithout = (Get-CodeSequenceDominanceLinkImpactReachability `
                -ComponentCount $componentCount -DirectLinks $links -RetainedOnly $true `
                -OmittedSourceComponent $from -OmittedTargetComponent $to).Matrix
            $reducedWithoutView = Get-CodeSequenceDominanceLinkImpactLostPairs `
                -Before $reducedMatrix -After $reducedWithout -Components $components
            $extraView = Get-CodeSequenceDominanceLinkImpactLostPairs `
                -Before $fullWithout -After $reducedWithout -Components $components
            if ([int]$reducedWithoutView.exact_lost_reachable_component_pair_count -ne
                    $fullPairCount + [int]$extraView.exact_lost_reachable_component_pair_count -or
                [int]$reducedWithoutView.exact_lost_reachable_original_reporter_pair_count -ne
                    $fullReporterCount + [int]$extraView.exact_lost_reachable_original_reporter_pair_count) {
                throw 'Code Sequence link-impact failed full-vs-reduced deletion loss conservation.'
            }
            $totalReductionExtraLosses += [int]$extraView.exact_lost_reachable_component_pair_count
            $totalReductionExtraReporterLosses += [int]$extraView.exact_lost_reachable_original_reporter_pair_count
        } else {
            $redundant++
            if ($fullPairCount -ne 0 -or $fullReporterCount -ne 0) {
                throw 'Code Sequence link-impact found lost full reachability after removing a redundant link.'
            }
        }
        $totalFullLosses += $fullPairCount
        $totalFullReporterLosses += $fullReporterCount
        $rows.Add([ordered]@{
            dominant_component_index = $from
            subordinate_component_index = $to
            original_direct_strict_comparison_count = [int]$link.original_direct_strict_comparison_count
            exact_sum_of_direct_strict_first_credit_advantages = [long]$link.exact_sum_of_direct_strict_first_credit_advantages
            original_ec089_unordered_pair_indices = [int[]]$link.original_ec089_unordered_pair_indices
            indispensable_for_original_strict_component_reachability = $indispensable
            # Remove the WHOLE direct SCC link (all contributing comparisons),
            # not just its first contributing EC-089 pair.
            if_entire_original_direct_component_link_removed_from_full_dag = $fullLoss
            if_same_indispensable_link_removed_from_reduced_dag = $reducedWithoutView
            extra_loss_only_because_redundant_shortcuts_are_absent_in_reduced_dag = $extraView
        })
    }
    if ($impactful -ne [int]$DominanceReduction.exact_indispensable_condensed_direct_component_link_count -or
        $redundant -ne [int]$DominanceReduction.exact_redundant_condensed_direct_component_link_count -or
        $impactful + $redundant -ne $links.Length) {
        throw 'Code Sequence link-impact lost a reduced or redundant direct SCC link.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $componentCount
        exact_original_direct_condensed_component_link_count = $links.Length
        exact_indispensable_component_link_count = $impactful
        exact_redundant_component_link_count_with_zero_full_removal_loss = $redundant
        exact_baseline_reachable_nonreflexive_component_pair_count = $reachableComponentPairs
        exact_baseline_reachable_cross_component_original_reporter_pair_count = $reachableReporterPairs
        # Totals are across DISTINCT ONE-LINK scenarios; they are NOT a union
        # of pairs lost under one combined deletion of multiple links.
        sum_of_component_pair_loss_incidences_across_separate_full_link_deletions = $totalFullLosses
        sum_of_original_reporter_pair_loss_incidences_across_separate_full_link_deletions = $totalFullReporterLosses
        sum_of_extra_component_pair_loss_incidences_across_separate_reduced_link_deletions = $totalReductionExtraLosses
        sum_of_extra_reporter_pair_loss_incidences_across_separate_reduced_link_deletions = $totalReductionExtraReporterLosses
        original_direct_component_link_single_deletion_impacts = $rows.ToArray()
        each_scenario_removes_one_entire_original_scc_link_only = $true
        reduced_graph_only_extra_losses_are_not_losses_in_the_full_original_graph = $true
        no_equal_pair_or_zero_credit_pair_is_a_strict_removal_target = $true
        impact_is_not_chronology_probability_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointLinkImpact {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        -not [bool]$RetentionEndpointDominanceReduction.only_consumed_checked_ec093_public_original_strict_topology -or
        -not [bool]$RetentionEndpointDominanceReduction.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionEndpointDominanceReduction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointDominanceReduction.component_route_witnesses_are_not_credit_addition_real_time_or_repair_priority -or
        -not [bool]$RetentionEndpointDominanceReduction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence link-impact requires the successful ORIGINAL selector and checked EC-094 reduction.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction)) {
        if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
            [int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence link-impact detected changed ORIGINAL caller/family/pair/anchor provenance.'
        }
    }
    $genuineTopology = [object[]]$RetentionEndpointDominanceTopology.genuine_global_threshold_endpoint_dominance_topology
    $frozenTopology = [object[]]$RetentionEndpointDominanceTopology.frozen_global_threshold_endpoint_dominance_topology
    $familyTopology = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    $genuineReduction = [object[]]$RetentionEndpointDominanceReduction.genuine_global_threshold_endpoint_dominance_reduction
    $frozenReduction = [object[]]$RetentionEndpointDominanceReduction.frozen_global_threshold_endpoint_dominance_reduction
    $familyReduction = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    if ($genuineTopology.Length -ne 3 -or $frozenTopology.Length -ne 3 -or
        $genuineReduction.Length -ne 3 -or $frozenReduction.Length -ne 3 -or
        $familyTopology.Length -ne $familyCount -or $familyReduction.Length -ne $familyCount) {
        throw 'Code Sequence link-impact lost a genuine/frozen threshold or actual ORIGINAL repeat family.'
    }
    $genuineOutput = [System.Collections.Generic.List[object]]::new()
    $frozenOutput = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $topTargets = if ($mode -eq 0) { $genuineTopology } else { $frozenTopology }
        $redTargets = if ($mode -eq 0) { $genuineReduction } else { $frozenReduction }
        $output = if ($mode -eq 0) { $genuineOutput } else { $frozenOutput }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $topTargets[$i]
            $red = $redTargets[$i]
            if ($null -eq $top -or $null -eq $red -or
                [int]$top.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$red.original_global_family_capacity_at_least -ne 3 - $i -or
                [int]$top.original_full_selection_global_family_capacity -ne
                    [int]$red.original_full_selection_global_family_capacity) {
                throw 'Code Sequence link-impact reindexed ORIGINAL threshold/support.'
            }
            $output.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_single_original_scc_link_removal_reachability_impact = `
                    (Get-CodeSequenceEndpointDominanceLinkImpactProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction -N $n)
            })
        }
    }
    $familyOutput = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $familyTopology[$i]
        $red = $familyReduction[$i]
        if ($null -eq $top -or $null -eq $red -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence link-impact reindexed an actual ORIGINAL repeat family.'
        }
        $familyOutput.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_single_original_scc_link_removal_reachability_impact = `
                (Get-CodeSequenceEndpointDominanceLinkImpactProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction -N $n)
            frozen_exact_single_original_scc_link_removal_reachability_impact = `
                (Get-CodeSequenceEndpointDominanceLinkImpactProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_one_original_scc_link_at_a_time_full_vs_reduced_strict_path_loss'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            genuine_original_global_thresholds = $genuineOutput.Count
            frozen_original_global_thresholds = $frozenOutput.Count
            individual_original_family_targets = $familyOutput.Count
        }
        genuine_global_threshold_endpoint_link_impact = $genuineOutput.ToArray()
        frozen_global_threshold_endpoint_link_impact = $frozenOutput.ToArray()
        individual_original_family_endpoint_link_impact = $familyOutput.ToArray()
        only_consumed_checked_ec093_and_ec094_original_graph_projections = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        single_link_deletion_cannot_attest_actual_faults_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

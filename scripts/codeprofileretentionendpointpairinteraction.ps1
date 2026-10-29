#requires -Version 7.0
<#
    EC-096: exact two-distinct-ORIGINAL-SCC-link co-deletion interactions.

    Each scenario removes exactly TWO whole existing direct component links
    from the FULL original condensation, preserving every other direct link,
    including the redundant shortcuts absent from the transitive reduction.
    A path lost by either one-link experiment cannot return after two deletions.
    Partition double-removal loss into first-only, second-only, shared
    single-link loss, and genuinely JOINT-ONLY loss absent from both singles.

    Keep all source SCCs fixed. These are graph counterfactuals over already
    checked ORIGINAL saved-witness credit comparisons, not historical facts,
    defects, empirical reliability, source edits, or repair priorities.
    No new saved data, Git, CI, network, permutation or business writes.
#>

function Get-CodeSequenceDominanceTwoLinkClosureBits {
    param(
        [int] $ComponentCount,
        [object[]] $DirectLinks,
        [int] $OmittedFirstLinkIndex = -1,
        [int] $OmittedSecondLinkIndex = -1
    )
    if ($ComponentCount -lt 1 -or $ComponentCount -gt 12 -or $null -eq $DirectLinks) {
        throw 'Code Sequence two-link impact received an invalid ORIGINAL SCC universe.'
    }
    $baseline = ($OmittedFirstLinkIndex -eq -1 -and $OmittedSecondLinkIndex -eq -1)
    $two = ($OmittedFirstLinkIndex -ge 0 -and
        $OmittedFirstLinkIndex -lt $OmittedSecondLinkIndex -and
        $OmittedSecondLinkIndex -lt $DirectLinks.Length)
    if (-not ($baseline -or $two)) {
        throw 'Code Sequence two-link impact requires either no deletion or two distinct ordered actual links.'
    }
    # N<=12: a single Int32 stores exact reachable SCC positions. Warshall
    # row unions avoid allocating a multidimensional matrix per link pair.
    [int[]]$rows = [int[]]::new($ComponentCount)
    for ($i = 0; $i -lt $ComponentCount; $i++) { $rows[$i] = 1 -shl $i }
    for ($edgeIndex = 0; $edgeIndex -lt $DirectLinks.Length; $edgeIndex++) {
        if ($edgeIndex -eq $OmittedFirstLinkIndex -or
            $edgeIndex -eq $OmittedSecondLinkIndex) { continue }
        $edge = $DirectLinks[$edgeIndex]
        if ($null -eq $edge) { throw 'Code Sequence two-link impact found a missing original direct link.' }
        $from = [int]$edge.dominant_component_index
        $to = [int]$edge.subordinate_component_index
        if ($from -lt 1 -or $to -lt 1 -or $from -gt $ComponentCount -or
            $to -gt $ComponentCount -or $from -eq $to) {
            throw 'Code Sequence two-link impact received an invalid original SCC direct link.'
        }
        $rows[$from - 1] = $rows[$from - 1] -bor (1 -shl ($to - 1))
    }
    for ($k = 0; $k -lt $ComponentCount; $k++) {
        $middleBit = 1 -shl $k
        for ($i = 0; $i -lt $ComponentCount; $i++) {
            if (($rows[$i] -band $middleBit) -ne 0) {
                $rows[$i] = $rows[$i] -bor $rows[$k]
            }
        }
    }
    # Do not enumerate the Int32[] into pipeline items.
    return [pscustomobject]@{ Rows = $rows }
}

function Get-CodeSequenceEndpointDominanceTwoLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        -not [bool]$SingleLinkImpact.each_scenario_removes_one_entire_original_scc_link_only -or
        -not [bool]$SingleLinkImpact.reduced_graph_only_extra_losses_are_not_losses_in_the_full_original_graph -or
        -not [bool]$SingleLinkImpact.no_equal_pair_or_zero_credit_pair_is_a_strict_removal_target -or
        -not [bool]$SingleLinkImpact.impact_is_not_chronology_probability_severity_causality_or_repair_priority -or
        -not [bool]$SingleLinkImpact.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence two-link impact requires checked EC-093/094/095 ORIGINAL source projections.'
    }
    # Not just validity flags: recompute EC-095 from EC-093 and EC-094,
    # including EC-094's own full SCC/topology/witness revalidation. Reject
    # modified single-link losses, identities, bits, credit, or prior summaries.
    $fresh = Get-CodeSequenceEndpointDominanceLinkImpactProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 32 -Compress) -cne
        (ConvertTo-Json -InputObject $SingleLinkImpact -Depth 32 -Compress)) {
        throw 'Code Sequence two-link impact rejected modified EC-095 ORIGINAL one-link evidence.'
    }

    $components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    $links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    $singles = [object[]]$SingleLinkImpact.original_direct_component_link_single_deletion_impacts
    $c = $components.Length
    $e = $links.Length
    if ($c -lt 1 -or $c -gt $N -or $e -gt [int]($c * ($c - 1) / 2) -or
        $e -ne $singles.Length -or
        $c -ne [int]$SingleLinkImpact.exact_strongly_connected_component_count -or
        $e -ne [int]$SingleLinkImpact.exact_original_direct_condensed_component_link_count) {
        throw 'Code Sequence two-link impact received an invalid checked SCC/link cardinality.'
    }

    $baseline = (Get-CodeSequenceDominanceTwoLinkClosureBits `
        -ComponentCount $c -DirectLinks $links).Rows
    $parentBaseline = (Get-CodeSequenceDominanceLinkImpactReachability `
        -ComponentCount $c -DirectLinks $links).Matrix
    for ($source = 0; $source -lt $c; $source++) {
        $expected = 0
        for ($target = 0; $target -lt $c; $target++) {
            if ($parentBaseline[$source, $target]) { $expected = $expected -bor (1 -shl $target) }
        }
        if ($baseline[$source] -ne $expected) {
            throw 'Code Sequence two-link impact did not reproduce original FULL graph reachability.'
        }
    }

    # Recover each checked full-graph one-link loss as compact bit masks.
    # All caller weights and the canonical underlying loss ledgers were
    # audited by the independently regenerated EC-095 projection above.
    [object[]]$oneMasks = [object[]]::new($e)
    for ($i = 0; $i -lt $e; $i++) {
        [int[]]$mask = [int[]]::new($c)
        $single = $singles[$i]
        $link = $links[$i]
        if ($null -eq $single -or
            [int]$single.dominant_component_index -ne [int]$link.dominant_component_index -or
            [int]$single.subordinate_component_index -ne [int]$link.subordinate_component_index) {
            throw 'Code Sequence two-link impact lost a canonical EC-095 single-link identity.'
        }
        $singleLoss = $single.if_entire_original_direct_component_link_removed_from_full_dag
        foreach ($lost in @($singleLoss.lost_reachable_component_pairs_in_canonical_order)) {
            $from = [int]$lost.from_strict_component_index - 1
            $to = [int]$lost.to_strict_component_index - 1
            if ($from -lt 0 -or $from -ge $c -or $to -lt 0 -or $to -ge $c -or
                $from -eq $to -or ($baseline[$from] -band (1 -shl $to)) -eq 0 -or
                ($mask[$from] -band (1 -shl $to)) -ne 0) {
                throw 'Code Sequence two-link impact received a noncanonical standalone lost SCC pair.'
            }
            $mask[$from] = $mask[$from] -bor (1 -shl $to)
        }
        $oneMasks[$i] = $mask
    }

    $scenarios = 0
    $withNewLoss = 0
    $summedShared = 0
    $summedSharedReporter = 0
    $summedUniqueSingles = 0
    $summedUniqueSinglesReporter = 0
    $summedJointOnly = 0
    $summedJointOnlyReporter = 0
    $summedCombined = 0
    $summedCombinedReporter = 0
    $jointlyFragile = [System.Collections.Generic.List[object]]::new()
    for ($firstIndex = 0; $firstIndex -lt $e; $firstIndex++) {
        [int[]]$aLoss = $oneMasks[$firstIndex]
        for ($secondIndex = $firstIndex + 1; $secondIndex -lt $e; $secondIndex++) {
            [int[]]$bLoss = $oneMasks[$secondIndex]
            $scenarios++
            $after = (Get-CodeSequenceDominanceTwoLinkClosureBits `
                -ComponentCount $c -DirectLinks $links `
                -OmittedFirstLinkIndex $firstIndex -OmittedSecondLinkIndex $secondIndex).Rows
            $aOnly = 0; $bOnly = 0; $shared = 0; $jointOnly = 0; $combined = 0
            $aOnlyWeight = 0; $bOnlyWeight = 0; $sharedWeight = 0
            $jointOnlyWeight = 0; $combinedWeight = 0
            $jointNewRows = [System.Collections.Generic.List[object]]::new()
            for ($source = 0; $source -lt $c; $source++) {
                if (($after[$source] -band (-bnot $baseline[$source])) -ne 0) {
                    throw 'Code Sequence two-link impact created a path by deleting strict links.'
                }
                $lostMask = $baseline[$source] -band (-bnot $after[$source])
                if ((($aLoss[$source] -bor $bLoss[$source]) -band (-bnot $lostMask)) -ne 0) {
                    throw 'Code Sequence two-link impact restored a path already lost by one deletion.'
                }
                $sourceWeight = @($components[$source].original_member_caller_positions).Count
                for ($target = 0; $target -lt $c; $target++) {
                    $bit = 1 -shl $target
                    if (($lostMask -band $bit) -eq 0) { continue }
                    if ($source -eq $target) {
                        throw 'Code Sequence two-link impact destroyed reflexive SCC identity.'
                    }
                    $weight = $sourceWeight * @($components[$target].original_member_caller_positions).Count
                    if ($weight -lt 1) { throw 'Code Sequence two-link impact has an empty original reporter SCC.' }
                    $combined++; $combinedWeight += $weight
                    $lostByA = ($aLoss[$source] -band $bit) -ne 0
                    $lostByB = ($bLoss[$source] -band $bit) -ne 0
                    if ($lostByA -and $lostByB) {
                        $shared++; $sharedWeight += $weight
                    } elseif ($lostByA) {
                        $aOnly++; $aOnlyWeight += $weight
                    } elseif ($lostByB) {
                        $bOnly++; $bOnlyWeight += $weight
                    } else {
                        $jointOnly++; $jointOnlyWeight += $weight
                        $jointNewRows.Add([ordered]@{
                            from_strict_component_index = $source + 1
                            to_strict_component_index = $target + 1
                            exact_ordered_original_reporter_pair_multiplicity = $weight
                        })
                    }
                }
            }
            $union = $aOnly + $bOnly + $shared
            $unionWeight = $aOnlyWeight + $bOnlyWeight + $sharedWeight
            $firstSingle = $singles[$firstIndex].if_entire_original_direct_component_link_removed_from_full_dag
            $secondSingle = $singles[$secondIndex].if_entire_original_direct_component_link_removed_from_full_dag
            if ($combined -ne $union + $jointOnly -or
                $combinedWeight -ne $unionWeight + $jointOnlyWeight -or
                [int]$firstSingle.exact_lost_reachable_component_pair_count -ne $aOnly + $shared -or
                [int]$secondSingle.exact_lost_reachable_component_pair_count -ne $bOnly + $shared -or
                [int]$firstSingle.exact_lost_reachable_original_reporter_pair_count -ne $aOnlyWeight + $sharedWeight -or
                [int]$secondSingle.exact_lost_reachable_original_reporter_pair_count -ne $bOnlyWeight + $sharedWeight) {
                throw 'Code Sequence two-link impact failed exact one-link union and joint-only conservation.'
            }
            $summedShared += $shared; $summedSharedReporter += $sharedWeight
            $summedUniqueSingles += $union; $summedUniqueSinglesReporter += $unionWeight
            $summedJointOnly += $jointOnly; $summedJointOnlyReporter += $jointOnlyWeight
            $summedCombined += $combined; $summedCombinedReporter += $combinedWeight
            # Sparse storage: only interactions whose second removal exposes
            # at least one NEW path loss. Pair cases without such loss are
            # still computed and included in exact total/zero-case counts.
            if ($jointOnly -eq 0) { continue }
            $withNewLoss++
            $a = $links[$firstIndex]
            $b = $links[$secondIndex]
            $jointlyFragile.Add([ordered]@{
                first_original_direct_link_index_in_ec095 = $firstIndex + 1
                second_original_direct_link_index_in_ec095 = $secondIndex + 1
                first_original_direct_link = [ordered]@{
                    dominant_component_index = [int]$a.dominant_component_index
                    subordinate_component_index = [int]$a.subordinate_component_index
                    indispensable_alone = [bool]$a.indispensable_for_original_strict_component_reachability
                    original_ec089_unordered_pair_indices = [int[]]$a.original_ec089_unordered_pair_indices
                    exact_sum_of_direct_strict_first_credit_advantages = [long]$a.exact_sum_of_direct_strict_first_credit_advantages
                }
                second_original_direct_link = [ordered]@{
                    dominant_component_index = [int]$b.dominant_component_index
                    subordinate_component_index = [int]$b.subordinate_component_index
                    indispensable_alone = [bool]$b.indispensable_for_original_strict_component_reachability
                    original_ec089_unordered_pair_indices = [int[]]$b.original_ec089_unordered_pair_indices
                    exact_sum_of_direct_strict_first_credit_advantages = [long]$b.exact_sum_of_direct_strict_first_credit_advantages
                }
                exact_lost_component_pairs_by_first_link_alone = [int]$firstSingle.exact_lost_reachable_component_pair_count
                exact_lost_component_pairs_by_second_link_alone = [int]$secondSingle.exact_lost_reachable_component_pair_count
                exact_loss_by_first_alone_not_second = $aOnly
                exact_loss_by_second_alone_not_first = $bOnly
                exact_loss_shared_by_both_individual_deletions = $shared
                exact_original_reporter_pair_loss_shared_by_both_individual_deletions = $sharedWeight
                exact_union_of_individual_component_pair_losses = $union
                exact_union_of_individual_original_reporter_pair_losses = $unionWeight
                exact_joint_full_graph_component_pair_losses = $combined
                exact_joint_full_graph_original_reporter_pair_losses = $combinedWeight
                new_loss_only_if_both_original_links_are_removed = [ordered]@{
                    exact_new_component_pair_count = $jointOnly
                    exact_new_original_reporter_pair_count = $jointOnlyWeight
                    newly_lost_component_pairs_in_canonical_order = $jointNewRows.ToArray()
                }
            })
        }
    }
    $expectedPairs = [int]($e * ($e - 1) / 2)
    if ($scenarios -ne $expectedPairs -or $withNewLoss -ne $jointlyFragile.Count -or
        $withNewLoss -gt $scenarios -or
        $summedCombined -ne $summedUniqueSingles + $summedJointOnly -or
        $summedCombinedReporter -ne $summedUniqueSinglesReporter + $summedJointOnlyReporter) {
        throw 'Code Sequence two-link impact did not conserve all unordered joint deletion scenarios.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $c
        exact_original_direct_component_link_count = $e
        exact_two_distinct_original_direct_link_removal_scenario_count = $scenarios
        exact_scenarios_with_joint_only_new_component_reachability_loss = $withNewLoss
        exact_scenarios_without_joint_only_new_component_reachability_loss = $scenarios - $withNewLoss
        sum_of_shared_single_loss_component_pair_incidences_across_joint_scenarios = $summedShared
        sum_of_shared_single_loss_original_reporter_pair_incidences_across_joint_scenarios = $summedSharedReporter
        sum_of_unique_single_loss_component_pair_incidences_across_joint_scenarios = $summedUniqueSingles
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_joint_scenarios = $summedUniqueSinglesReporter
        sum_of_joint_only_new_component_pair_incidences_across_joint_scenarios = $summedJointOnly
        sum_of_joint_only_new_original_reporter_pair_incidences_across_joint_scenarios = $summedJointOnlyReporter
        sum_of_combined_full_graph_component_pair_loss_incidences_across_joint_scenarios = $summedCombined
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_joint_scenarios = $summedCombinedReporter
        original_direct_link_pairs_with_joint_only_new_reachability_loss = $jointlyFragile.ToArray()
        omitted_zero_new_loss_cases_are_still_counted_in_scenario_totals = $true
        every_scenario_deletes_two_whole_original_scc_links_from_full_dag = $true
        single_loss_union_and_joint_only_new_loss_partition_combined_loss = $true
        original_scc_members_and_internal_cycles_are_held_fixed = $true
        no_reduced_dag_shortcut_deletion_is_used_in_this_full_graph_interaction = $true
        no_equal_pair_or_zero_endpoint_first_pair_is_a_strict_deletion_target = $true
        interaction_is_not_empirical_reliability_causality_severity_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointPairInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        [string]$RetentionEndpointLinkImpact.scope -cne 'exact_one_original_scc_link_at_a_time_full_vs_reduced_strict_path_loss' -or
        -not [bool]$RetentionEndpointLinkImpact.only_consumed_checked_ec093_and_ec094_original_graph_projections -or
        -not [bool]$RetentionEndpointLinkImpact.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionEndpointLinkImpact.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointLinkImpact.single_link_deletion_cannot_attest_actual_faults_or_repair_priority -or
        -not [bool]$RetentionEndpointLinkImpact.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence two-link interaction requires successful ORIGINAL selector and checked EC-095.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence two-link interaction received invalid ORIGINAL caller/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence two-link interaction detected changed ORIGINAL pair/path/anchor/caller provenance.'
        }
    }
    $topG = [object[]]$RetentionEndpointDominanceTopology.genuine_global_threshold_endpoint_dominance_topology
    $topF = [object[]]$RetentionEndpointDominanceTopology.frozen_global_threshold_endpoint_dominance_topology
    $topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    $redG = [object[]]$RetentionEndpointDominanceReduction.genuine_global_threshold_endpoint_dominance_reduction
    $redF = [object[]]$RetentionEndpointDominanceReduction.frozen_global_threshold_endpoint_dominance_reduction
    $redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    $oneG = [object[]]$RetentionEndpointLinkImpact.genuine_global_threshold_endpoint_link_impact
    $oneF = [object[]]$RetentionEndpointLinkImpact.frozen_global_threshold_endpoint_link_impact
    $oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    if ($topG.Length -ne 3 -or $topF.Length -ne 3 -or $redG.Length -ne 3 -or
        $redF.Length -ne 3 -or $oneG.Length -ne 3 -or $oneF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount) {
        throw 'Code Sequence two-link interaction lost a real ORIGINAL global or repeat-family target.'
    }
    $genuineOutput = [System.Collections.Generic.List[object]]::new()
    $frozenOutput = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $tops = if ($mode -eq 0) { $topG } else { $topF }
        $reds = if ($mode -eq 0) { $redG } else { $redF }
        $ones = if ($mode -eq 0) { $oneG } else { $oneF }
        $output = if ($mode -eq 0) { $genuineOutput } else { $frozenOutput }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
                [int]$top.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$red.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$one.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$top.original_full_selection_global_family_capacity -ne [int]$one.original_full_selection_global_family_capacity -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$one.original_full_selection_global_family_capacity) {
                throw 'Code Sequence two-link interaction reindexed ORIGINAL genuine/frozen global targets.'
            }
            $output.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_joint_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceTwoLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact -N $n)
            })
        }
    }
    $familyOutput = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]; $one = $oneFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence two-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $familyOutput.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_joint_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceTwoLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact -N $n)
            frozen_exact_joint_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceTwoLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_joint_two_distinct_original_scc_full_graph_link_removal_interaction'
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
        genuine_global_threshold_endpoint_pair_interaction = $genuineOutput.ToArray()
        frozen_global_threshold_endpoint_pair_interaction = $frozenOutput.ToArray()
        individual_original_family_endpoint_pair_interaction = $familyOutput.ToArray()
        only_consumed_checked_ec093_to_ec095_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_path_loss_is_interpreted_as_history_probability_defect_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

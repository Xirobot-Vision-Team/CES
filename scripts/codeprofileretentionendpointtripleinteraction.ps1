#requires -Version 7.0
<#
    EC-097: strictly THIRD-order reachability loss from simultaneously
    removing THREE distinct whole ORIGINAL direct SCC links.

    Source: ONLY fully checked EC-093/094/095/096 ORIGINAL public graph
    projections. EC-096 is regenerated and compared in full, transitively
    validating EC-095/094/093 source identities and genuine EC-089 pair IDs.
    Every original redundant direct shortcut remains unless explicitly among
    the three removed links. SCC membership never changes.

    Loss is partitioned into a unique union of one-link losses, losses present
    in at least one TWO-link deletion but no one-link deletion, and losses
    present only when all THREE links are removed. Count exact original
    reporter cross-SCC pairs, not link-credit margins or probabilities.

    This is a bounded hypothetical graph operation, NOT chronology, a real
    repository defect, empirical reliability, severity, causality, or advice
    to delete links. No reads, persistence, network, masks/permutations of
    ORIGINAL saved support, or analyzed business-source edits.
#>

function Get-CodeSequenceDominanceThreeLinkClosureBits {
    param(
        [int] $ComponentCount,
        [int[]] $FullDirectRows,
        [object[]] $DirectLinks,
        [int] $OmittedFirstLinkIndex = -1,
        [int] $OmittedSecondLinkIndex = -1,
        [int] $OmittedThirdLinkIndex = -1
    )
    if ($ComponentCount -lt 1 -or $ComponentCount -gt 12 -or
        $null -eq $FullDirectRows -or $FullDirectRows.Length -ne $ComponentCount -or
        $null -eq $DirectLinks) {
        throw 'Code Sequence three-link interaction received an invalid ORIGINAL SCC universe.'
    }
    $none = ($OmittedFirstLinkIndex -eq -1 -and
        $OmittedSecondLinkIndex -eq -1 -and $OmittedThirdLinkIndex -eq -1)
    $three = ($OmittedFirstLinkIndex -ge 0 -and
        $OmittedFirstLinkIndex -lt $OmittedSecondLinkIndex -and
        $OmittedSecondLinkIndex -lt $OmittedThirdLinkIndex -and
        $OmittedThirdLinkIndex -lt $DirectLinks.Length)
    if (-not ($none -or $three)) {
        throw 'Code Sequence three-link interaction requires no deletion or three distinct increasing real link indices.'
    }
    # Start from the complete ORIGINAL direct-link adjacency, not the
    # EC-094 reduced adjacency. Cloning Int32[<=12] per scenario avoids
    # repeated graph object construction and accidental caller mutation.
    [int[]]$rows = [int[]]$FullDirectRows.Clone()
    if ($three) {
        foreach ($linkIndex in @($OmittedFirstLinkIndex, $OmittedSecondLinkIndex,
            $OmittedThirdLinkIndex)) {
            $edge = $DirectLinks[$linkIndex]
            if ($null -eq $edge) { throw 'Code Sequence three-link interaction received a null original link.' }
            $from = [int]$edge.dominant_component_index - 1
            $to = [int]$edge.subordinate_component_index - 1
            if ($from -lt 0 -or $from -ge $ComponentCount -or
                $to -lt 0 -or $to -ge $ComponentCount -or $from -eq $to) {
                throw 'Code Sequence three-link interaction received an invalid direct SCC link.'
            }
            $toBit = 1 -shl $to
            if (($rows[$from] -band $toBit) -eq 0) {
                throw 'Code Sequence three-link interaction found an absent or duplicate full original link.'
            }
            $rows[$from] = $rows[$from] -band (-bnot $toBit)
        }
    }
    # Each SCC's own identity bit survives any direct-link deletion.
    for ($k = 0; $k -lt $ComponentCount; $k++) {
        $middle = 1 -shl $k
        for ($i = 0; $i -lt $ComponentCount; $i++) {
            if (($rows[$i] -band $middle) -ne 0) {
                $rows[$i] = $rows[$i] -bor $rows[$k]
            }
        }
    }
    return [pscustomobject]@{ Rows = $rows }
}

function Get-CodeSequenceOriginalDirectPairOffset {
    param([int] $First, [int] $Second, [int] $LinkCount)
    if ($LinkCount -lt 2 -or $LinkCount -gt 66 -or
        $First -lt 0 -or $First -ge $Second -or $Second -ge $LinkCount) {
        throw 'Code Sequence three-link interaction requires two distinct increasing original link indices.'
    }
    # Row-major enumeration (i,j), i<j, exactly as in EC-096.
    return [int](($First * (2 * $LinkCount - $First - 1)) / 2 + $Second - $First - 1)
}

function Get-CodeSequenceEndpointDominanceThreeLinkInteractionProjection {
    param(
        [object] $DominanceTopology,
        [object] $DominanceReduction,
        [object] $SingleLinkImpact,
        [object] $PairInteraction,
        [int] $N
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DominanceTopology -or
        $null -eq $DominanceReduction -or $null -eq $SingleLinkImpact -or
        $null -eq $PairInteraction -or
        -not [bool]$PairInteraction.every_scenario_deletes_two_whole_original_scc_links_from_full_dag -or
        -not [bool]$PairInteraction.single_loss_union_and_joint_only_new_loss_partition_combined_loss -or
        -not [bool]$PairInteraction.no_reduced_dag_shortcut_deletion_is_used_in_this_full_graph_interaction -or
        -not [bool]$PairInteraction.no_equal_pair_or_zero_endpoint_first_pair_is_a_strict_deletion_target -or
        -not [bool]$PairInteraction.no_new_evidence_read_permutation_mask_git_network_or_business_write) {
        throw 'Code Sequence three-link interaction requires checked EC-093/094/095/096 ORIGINAL sources.'
    }
    # Exact full parent re-derivation: checked EC-096 itself regenerates every
    # EC-095 full and reduced one-link loss, which in turn rechecks EC-094
    # reduction, original EC-089 pair witnesses and EC-093 SCC topology.
    $fresh = Get-CodeSequenceEndpointDominanceTwoLinkInteractionProjection `
        -DominanceTopology $DominanceTopology -DominanceReduction $DominanceReduction `
        -SingleLinkImpact $SingleLinkImpact -N $N
    if ((ConvertTo-Json -InputObject $fresh -Depth 40 -Compress) -cne
        (ConvertTo-Json -InputObject $PairInteraction -Depth 40 -Compress)) {
        throw 'Code Sequence three-link interaction rejected modified EC-096 original two-link evidence.'
    }

    [object[]]$components = [object[]]$DominanceReduction.original_component_reachability_after_reduction
    [object[]]$links = [object[]]$DominanceReduction.original_condensed_component_link_reduction
    [object[]]$singles = [object[]]$SingleLinkImpact.original_direct_component_link_single_deletion_impacts
    $c = $components.Length
    $e = $links.Length
    if ($c -lt 1 -or $c -gt $N -or $e -gt [int]($c * ($c - 1) / 2) -or
        $singles.Length -ne $e -or
        $c -ne [int]$PairInteraction.exact_strongly_connected_component_count -or
        $e -ne [int]$PairInteraction.exact_original_direct_component_link_count) {
        throw 'Code Sequence three-link interaction received changed original SCC/link counts.'
    }

    [int[]]$weights = [int[]]::new($c)
    [int[]]$directRows = [int[]]::new($c)
    for ($source = 0; $source -lt $c; $source++) {
        [int[]]$members = [int[]]$components[$source].original_member_caller_positions
        if ($null -eq $members -or $members.Length -lt 1) {
            throw 'Code Sequence three-link interaction found an empty original reporter SCC.'
        }
        $weights[$source] = $members.Length
        $directRows[$source] = 1 -shl $source
    }
    for ($linkIndex = 0; $linkIndex -lt $e; $linkIndex++) {
        $link = $links[$linkIndex]
        if ($null -eq $link) { throw 'Code Sequence three-link interaction found a missing original direct link.' }
        $from = [int]$link.dominant_component_index - 1
        $to = [int]$link.subordinate_component_index - 1
        if ($from -lt 0 -or $from -ge $c -or $to -lt 0 -or $to -ge $c -or
            $from -eq $to -or ($directRows[$from] -band (1 -shl $to)) -ne 0) {
            throw 'Code Sequence three-link interaction found an invalid or duplicate direct SCC link.'
        }
        $directRows[$from] = $directRows[$from] -bor (1 -shl $to)
    }
    [int[]]$baseline = (Get-CodeSequenceDominanceThreeLinkClosureBits `
        -ComponentCount $c -FullDirectRows $directRows -DirectLinks $links).Rows
    [int[]]$parentBaseline = (Get-CodeSequenceDominanceTwoLinkClosureBits `
        -ComponentCount $c -DirectLinks $links).Rows
    for ($source = 0; $source -lt $c; $source++) {
        if ($baseline[$source] -ne $parentBaseline[$source]) {
            throw 'Code Sequence three-link interaction changed original FULL SCC reachability.'
        }
    }

    # Reconstitute exact singleton loss masks from the verified EC-095 FULL
    # rows; never include EC-095 REDUCED-only extra losses.
    [object[]]$singleMasks = [object[]]::new($e)
    for ($i = 0; $i -lt $e; $i++) {
        [int[]]$mask = [int[]]::new($c)
        foreach ($lost in @($singles[$i].if_entire_original_direct_component_link_removed_from_full_dag.lost_reachable_component_pairs_in_canonical_order)) {
            $from = [int]$lost.from_strict_component_index - 1
            $to = [int]$lost.to_strict_component_index - 1
            if ($from -lt 0 -or $from -ge $c -or $to -lt 0 -or $to -ge $c -or
                $from -eq $to -or ($baseline[$from] -band (1 -shl $to)) -eq 0 -or
                ($mask[$from] -band (1 -shl $to)) -ne 0) {
                throw 'Code Sequence three-link interaction received invalid singleton FULL loss.'
            }
            $mask[$from] = $mask[$from] -bor (1 -shl $to)
        }
        $singleMasks[$i] = $mask
    }

    # EC-096 materializes only positive TWO-only interaction rows. Rebuild
    # the complete C(E,2) loss-mask table by unioning EC-095 singletons and
    # then inserting exactly the sparse two-only rows. This reconstruction
    # preserves every zero-two-only case without rerunning all pair closures.
    $expectedPairs = [int]($e * ($e - 1) / 2)
    [object[]]$pairMasks = [object[]]::new($expectedPairs)
    [int[,]]$pairOffsets = [int[,]]::new($e, $e)
    for ($i = 0; $i -lt $e; $i++) {
        [int[]]$a = $singleMasks[$i]
        for ($j = $i + 1; $j -lt $e; $j++) {
            [int[]]$b = $singleMasks[$j]
            [int[]]$joined = [int[]]::new($c)
            for ($from = 0; $from -lt $c; $from++) {
                $joined[$from] = $a[$from] -bor $b[$from]
            }
            $idx = Get-CodeSequenceOriginalDirectPairOffset -First $i -Second $j -LinkCount $e
            $pairOffsets[$i, $j] = $idx
            $pairMasks[$idx] = $joined
        }
    }
    $actualSparse = 0
    [long]$actualNovel = 0
    [long]$actualNovelWeight = 0
    [bool[]]$seen = [bool[]]::new($expectedPairs)
    foreach ($entry in @($PairInteraction.original_direct_link_pairs_with_joint_only_new_reachability_loss)) {
        $i = [int]$entry.first_original_direct_link_index_in_ec095 - 1
        $j = [int]$entry.second_original_direct_link_index_in_ec095 - 1
        $idx = Get-CodeSequenceOriginalDirectPairOffset -First $i -Second $j -LinkCount $e
        if ($seen[$idx]) { throw 'Code Sequence three-link interaction found duplicate sparse EC-096 link pair.' }
        $seen[$idx] = $true
        [int[]]$mask = $pairMasks[$idx]
        $novel = $entry.new_loss_only_if_both_original_links_are_removed
        $observed = 0
        $observedWeight = 0
        foreach ($lost in @($novel.newly_lost_component_pairs_in_canonical_order)) {
            $from = [int]$lost.from_strict_component_index - 1
            $to = [int]$lost.to_strict_component_index - 1
            if ($from -lt 0 -or $from -ge $c -or $to -lt 0 -or $to -ge $c -or
                $from -eq $to -or ($baseline[$from] -band (1 -shl $to)) -eq 0 -or
                ($mask[$from] -band (1 -shl $to)) -ne 0 -or
                [int]$lost.exact_ordered_original_reporter_pair_multiplicity -ne $weights[$from] * $weights[$to]) {
                throw 'Code Sequence three-link interaction found invalid joint-only EC-096 SCC loss.'
            }
            $mask[$from] = $mask[$from] -bor (1 -shl $to)
            $observed++
            $observedWeight += $weights[$from] * $weights[$to]
        }
        if ($observed -le 0 -or $observed -ne [int]$novel.exact_new_component_pair_count -or
            $observedWeight -ne [long]$novel.exact_new_original_reporter_pair_count) {
            throw 'Code Sequence three-link interaction lost a sparse EC-096 two-only certificate.'
        }
        $actualSparse++
        $actualNovel += $observed
        $actualNovelWeight += $observedWeight
    }
    if ($actualSparse -ne [int]$PairInteraction.exact_scenarios_with_joint_only_new_component_reachability_loss -or
        $expectedPairs - $actualSparse -ne [int]$PairInteraction.exact_scenarios_without_joint_only_new_component_reachability_loss -or
        $actualNovel -ne [long]$PairInteraction.sum_of_joint_only_new_component_pair_incidences_across_joint_scenarios -or
        $actualNovelWeight -ne [long]$PairInteraction.sum_of_joint_only_new_original_reporter_pair_incidences_across_joint_scenarios) {
        throw 'Code Sequence three-link interaction lost complete EC-096 sparse/full case conservation.'
    }

    $scenarios = 0
    $withTripleOnly = 0
    [long]$singleSum = 0; [long]$singleWeightSum = 0
    [long]$pairOnlySum = 0; [long]$pairOnlyWeightSum = 0
    [long]$tripleOnlySum = 0; [long]$tripleOnlyWeightSum = 0
    [long]$combinedSum = 0; [long]$combinedWeightSum = 0
    $positiveTriples = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $e; $i++) {
        [int[]]$singleI = $singleMasks[$i]
        for ($j = $i + 1; $j -lt $e; $j++) {
            [int[]]$singleJ = $singleMasks[$j]
            [int[]]$pairIJ = $pairMasks[$pairOffsets[$i, $j]]
            for ($k = $j + 1; $k -lt $e; $k++) {
                [int[]]$singleK = $singleMasks[$k]
                [int[]]$pairIK = $pairMasks[$pairOffsets[$i, $k]]
                [int[]]$pairJK = $pairMasks[$pairOffsets[$j, $k]]
                $scenarios++
                [int[]]$after = (Get-CodeSequenceDominanceThreeLinkClosureBits `
                    -ComponentCount $c -FullDirectRows $directRows -DirectLinks $links `
                    -OmittedFirstLinkIndex $i -OmittedSecondLinkIndex $j `
                    -OmittedThirdLinkIndex $k).Rows
                $singleCount = 0; $singleWeight = 0
                $pairOnlyCount = 0; $pairOnlyWeight = 0
                $tripleOnlyCount = 0; $tripleOnlyWeight = 0
                $combinedCount = 0; $combinedWeight = 0
                $tripleOnlyRows = $null
                for ($from = 0; $from -lt $c; $from++) {
                    $original = $baseline[$from]
                    if (($after[$from] -band (-bnot $original)) -ne 0) {
                        throw 'Code Sequence three-link deletion created new FULL graph reachability.'
                    }
                    $lost = $original -band (-bnot $after[$from])
                    if ($lost -eq 0) { continue }
                    $singleUnion = $singleI[$from] -bor $singleJ[$from] -bor $singleK[$from]
                    $pairUnion = $pairIJ[$from] -bor $pairIK[$from] -bor $pairJK[$from]
                    if (($singleUnion -band (-bnot $pairUnion)) -ne 0 -or
                        ($pairUnion -band (-bnot $lost)) -ne 0 -or
                        ($lost -band (1 -shl $from)) -ne 0) {
                        throw 'Code Sequence three-link interaction violated monotone singleton/pair/triple loss.'
                    }
                    $pairNew = $pairUnion -band (-bnot $singleUnion)
                    $tripleNew = $lost -band (-bnot $pairUnion)
                    for ($to = 0; $to -lt $c; $to++) {
                        $bit = 1 -shl $to
                        if (($lost -band $bit) -eq 0) { continue }
                        $weight = $weights[$from] * $weights[$to]
                        if ($weight -lt 1) {
                            throw 'Code Sequence three-link interaction found an invalid ORIGINAL SCC cross-product.'
                        }
                        $combinedCount++; $combinedWeight += $weight
                        if (($singleUnion -band $bit) -ne 0) {
                            $singleCount++; $singleWeight += $weight
                        } elseif (($pairNew -band $bit) -ne 0) {
                            $pairOnlyCount++; $pairOnlyWeight += $weight
                        } elseif (($tripleNew -band $bit) -ne 0) {
                            $tripleOnlyCount++; $tripleOnlyWeight += $weight
                            if ($null -eq $tripleOnlyRows) {
                                $tripleOnlyRows = [System.Collections.Generic.List[object]]::new()
                            }
                            $tripleOnlyRows.Add([ordered]@{
                                from_strict_component_index = $from + 1
                                to_strict_component_index = $to + 1
                                exact_ordered_original_reporter_pair_multiplicity = $weight
                            })
                        } else {
                            throw 'Code Sequence three-link interaction left a lost SCC pair unattributed.'
                        }
                    }
                }
                if ($combinedCount -ne $singleCount + $pairOnlyCount + $tripleOnlyCount -or
                    $combinedWeight -ne $singleWeight + $pairOnlyWeight + $tripleOnlyWeight) {
                    throw 'Code Sequence three-link interaction failed disjoint loss-partition conservation.'
                }
                $singleSum += $singleCount; $singleWeightSum += $singleWeight
                $pairOnlySum += $pairOnlyCount; $pairOnlyWeightSum += $pairOnlyWeight
                $tripleOnlySum += $tripleOnlyCount; $tripleOnlyWeightSum += $tripleOnlyWeight
                $combinedSum += $combinedCount; $combinedWeightSum += $combinedWeight
                # Every triple is counted. Detailed rows are sparse, and
                # contain ONLY genuinely third-order losses, never pair losses
                # already present after two removals.
                if ($tripleOnlyCount -eq 0) { continue }
                $withTripleOnly++
                $linkSummaries = [System.Collections.Generic.List[object]]::new()
                foreach ($linkIndex in @($i, $j, $k)) {
                    $link = $links[$linkIndex]
                    $linkSummaries.Add([ordered]@{
                        original_direct_link_index_in_ec095 = $linkIndex + 1
                        dominant_component_index = [int]$link.dominant_component_index
                        subordinate_component_index = [int]$link.subordinate_component_index
                        indispensable_alone = [bool]$link.indispensable_for_original_strict_component_reachability
                        original_ec089_unordered_pair_indices = [int[]]$link.original_ec089_unordered_pair_indices
                        exact_sum_of_direct_strict_first_credit_advantages = [long]$link.exact_sum_of_direct_strict_first_credit_advantages
                    })
                }
                $positiveTriples.Add([ordered]@{
                    first_original_direct_link_index_in_ec095 = $i + 1
                    second_original_direct_link_index_in_ec095 = $j + 1
                    third_original_direct_link_index_in_ec095 = $k + 1
                    three_whole_original_direct_links_in_canonical_order = $linkSummaries.ToArray()
                    exact_unique_single_link_loss_component_pairs = $singleCount
                    exact_unique_single_link_loss_original_reporter_pairs = $singleWeight
                    exact_additional_loss_by_some_pair_but_no_single_component_pairs = $pairOnlyCount
                    exact_additional_loss_by_some_pair_but_no_single_original_reporter_pairs = $pairOnlyWeight
                    exact_joint_three_link_full_component_pair_losses = $combinedCount
                    exact_joint_three_link_full_original_reporter_pair_losses = $combinedWeight
                    new_loss_only_if_all_three_original_links_are_removed = [ordered]@{
                        exact_new_component_pair_count = $tripleOnlyCount
                        exact_new_original_reporter_pair_count = $tripleOnlyWeight
                        newly_lost_component_pairs_in_canonical_order = $tripleOnlyRows.ToArray()
                    }
                })
            }
        }
    }
    $expectedTriples = [int]($e * ($e - 1) * ($e - 2) / 6)
    if ($scenarios -ne $expectedTriples -or $withTripleOnly -ne $positiveTriples.Count -or
        $withTripleOnly -gt $scenarios -or
        $combinedSum -ne $singleSum + $pairOnlySum + $tripleOnlySum -or
        $combinedWeightSum -ne $singleWeightSum + $pairOnlyWeightSum + $tripleOnlyWeightSum) {
        throw 'Code Sequence three-link interaction did not conserve full C(E,3) scenario totals.'
    }
    return [ordered]@{
        original_positions_in_impact_universe = $N
        exact_strongly_connected_component_count = $c
        exact_original_direct_component_link_count = $e
        exact_three_distinct_original_direct_link_removal_scenario_count = $scenarios
        exact_scenarios_with_strictly_triple_only_new_component_reachability_loss = $withTripleOnly
        exact_scenarios_without_strictly_triple_only_new_component_reachability_loss = $scenarios - $withTripleOnly
        sum_of_unique_single_loss_component_pair_incidences_across_triple_scenarios = $singleSum
        sum_of_unique_single_loss_original_reporter_pair_incidences_across_triple_scenarios = $singleWeightSum
        sum_of_pair_only_new_component_pair_incidences_across_triple_scenarios = $pairOnlySum
        sum_of_pair_only_new_original_reporter_pair_incidences_across_triple_scenarios = $pairOnlyWeightSum
        sum_of_strictly_triple_only_new_component_pair_incidences_across_triple_scenarios = $tripleOnlySum
        sum_of_strictly_triple_only_new_original_reporter_pair_incidences_across_triple_scenarios = $tripleOnlyWeightSum
        sum_of_combined_full_graph_component_pair_loss_incidences_across_triple_scenarios = $combinedSum
        sum_of_combined_full_graph_original_reporter_pair_loss_incidences_across_triple_scenarios = $combinedWeightSum
        original_direct_link_triples_with_strictly_triple_only_new_reachability_loss = $positiveTriples.ToArray()
        sparse_rows_omit_zero_third_order_cases_but_not_their_exact_aggregates = $true
        every_scenario_deletes_three_distinct_whole_original_direct_scc_links_from_full_dag = $true
        unique_single_plus_pair_only_plus_strictly_triple_only_partition_all_triple_loss = $true
        source_scc_members_and_internal_cycles_held_fixed = $true
        original_redundant_shortcuts_remain_unless_one_of_three_removed_links = $true
        positive_first_equality_and_zero_first_ties_never_become_strict_links = $true
        no_loss_is_empirical_reliability_chronology_severity_causality_or_repair_priority = $true
        no_new_evidence_read_permutation_mask_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointTripleInteraction {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionEndpointDominanceTopology,
        [object] $RetentionEndpointDominanceReduction,
        [object] $RetentionEndpointLinkImpact,
        [object] $RetentionEndpointPairInteraction
    )
    if ($null -eq $RetentionPivotality -or
        $null -eq $RetentionEndpointDominanceTopology -or
        $null -eq $RetentionEndpointDominanceReduction -or
        $null -eq $RetentionEndpointLinkImpact -or
        $null -eq $RetentionEndpointPairInteraction -or
        [string]$RetentionEndpointPairInteraction.scope -cne 'exact_joint_two_distinct_original_scc_full_graph_link_removal_interaction' -or
        -not [bool]$RetentionEndpointPairInteraction.only_consumed_checked_ec093_to_ec095_original_graph_projections -or
        -not [bool]$RetentionEndpointPairInteraction.original_ec071_caller_bits_and_all_actual_family_targets_unchanged -or
        -not [bool]$RetentionEndpointPairInteraction.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionEndpointPairInteraction.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence three-link interaction requires a successful ORIGINAL selector and checked EC-096.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66) {
        throw 'Code Sequence three-link interaction received invalid ORIGINAL reporter/family counts.'
    }
    foreach ($parent in @($RetentionEndpointDominanceTopology, $RetentionEndpointDominanceReduction,
        $RetentionEndpointLinkImpact, $RetentionEndpointPairInteraction)) {
        if ([int]$parent.counts.original_selected_report_positions -ne $n -or
            [int]$parent.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$parent.counts.original_unordered_pair_comparisons_per_target -ne [int]($n * ($n - 1) / 2) -or
            [int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence three-link interaction detected changed ORIGINAL caller/pair/path/anchor provenance.'
        }
    }
    [object[]]$topsG = [object[]]$RetentionEndpointDominanceTopology.genuine_global_threshold_endpoint_dominance_topology
    [object[]]$topsF = [object[]]$RetentionEndpointDominanceTopology.frozen_global_threshold_endpoint_dominance_topology
    [object[]]$redsG = [object[]]$RetentionEndpointDominanceReduction.genuine_global_threshold_endpoint_dominance_reduction
    [object[]]$redsF = [object[]]$RetentionEndpointDominanceReduction.frozen_global_threshold_endpoint_dominance_reduction
    [object[]]$onesG = [object[]]$RetentionEndpointLinkImpact.genuine_global_threshold_endpoint_link_impact
    [object[]]$onesF = [object[]]$RetentionEndpointLinkImpact.frozen_global_threshold_endpoint_link_impact
    [object[]]$twosG = [object[]]$RetentionEndpointPairInteraction.genuine_global_threshold_endpoint_pair_interaction
    [object[]]$twosF = [object[]]$RetentionEndpointPairInteraction.frozen_global_threshold_endpoint_pair_interaction
    [object[]]$topFamilies = [object[]]$RetentionEndpointDominanceTopology.individual_original_family_endpoint_dominance_topology
    [object[]]$redFamilies = [object[]]$RetentionEndpointDominanceReduction.individual_original_family_endpoint_dominance_reduction
    [object[]]$oneFamilies = [object[]]$RetentionEndpointLinkImpact.individual_original_family_endpoint_link_impact
    [object[]]$twoFamilies = [object[]]$RetentionEndpointPairInteraction.individual_original_family_endpoint_pair_interaction
    if ($topsG.Length -ne 3 -or $topsF.Length -ne 3 -or
        $redsG.Length -ne 3 -or $redsF.Length -ne 3 -or
        $onesG.Length -ne 3 -or $onesF.Length -ne 3 -or
        $twosG.Length -ne 3 -or $twosF.Length -ne 3 -or
        $topFamilies.Length -ne $familyCount -or $redFamilies.Length -ne $familyCount -or
        $oneFamilies.Length -ne $familyCount -or $twoFamilies.Length -ne $familyCount) {
        throw 'Code Sequence three-link interaction lost a real ORIGINAL global/family target.'
    }
    $genuine = [System.Collections.Generic.List[object]]::new()
    $frozen = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $tops = if ($mode -eq 0) { $topsG } else { $topsF }
        $reds = if ($mode -eq 0) { $redsG } else { $redsF }
        $ones = if ($mode -eq 0) { $onesG } else { $onesF }
        $twos = if ($mode -eq 0) { $twosG } else { $twosF }
        $out = if ($mode -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $top = $tops[$i]; $red = $reds[$i]; $one = $ones[$i]; $two = $twos[$i]
            if ($null -eq $top -or $null -eq $red -or $null -eq $one -or $null -eq $two -or
                [int]$top.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$red.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$one.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$two.original_global_family_capacity_at_least -ne (3 - $i) -or
                [int]$two.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$one.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity -or
                [int]$red.original_full_selection_global_family_capacity -ne [int]$top.original_full_selection_global_family_capacity) {
                throw 'Code Sequence three-link interaction reindexed an ORIGINAL genuine/frozen global threshold.'
            }
            $out.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$top.original_full_selection_global_family_capacity
                exact_strictly_triple_only_original_scc_link_removal_interaction = `
                    (Get-CodeSequenceEndpointDominanceThreeLinkInteractionProjection `
                        -DominanceTopology $top.exact_original_endpoint_first_credit_strict_dominance_topology `
                        -DominanceReduction $red.exact_original_strict_condensation_transitive_reduction `
                        -SingleLinkImpact $one.exact_single_original_scc_link_removal_reachability_impact `
                        -PairInteraction $two.exact_joint_original_scc_link_removal_interaction -N $n)
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        $top = $topFamilies[$i]; $red = $redFamilies[$i]
        $one = $oneFamilies[$i]; $two = $twoFamilies[$i]
        if ($null -eq $top -or $null -eq $red -or $null -eq $one -or $null -eq $two -or
            [int]$top.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$red.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$one.original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$two.original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence three-link interaction reindexed an actual ORIGINAL repeat family.'
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_exact_strictly_triple_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceThreeLinkInteractionProjection `
                    -DominanceTopology $top.genuine_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.genuine_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.genuine_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.genuine_exact_joint_original_scc_link_removal_interaction -N $n)
            frozen_exact_strictly_triple_only_original_scc_link_removal_interaction = `
                (Get-CodeSequenceEndpointDominanceThreeLinkInteractionProjection `
                    -DominanceTopology $top.frozen_original_endpoint_first_credit_strict_dominance_topology `
                    -DominanceReduction $red.frozen_original_strict_condensation_transitive_reduction `
                    -SingleLinkImpact $one.frozen_exact_single_original_scc_link_removal_reachability_impact `
                    -PairInteraction $two.frozen_exact_joint_original_scc_link_removal_interaction -N $n)
        })
    }
    return [ordered]@{
        scope = 'exact_strictly_third_order_three_distinct_original_scc_full_graph_link_removal_interaction'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_comparisons_per_target = [int]($n * ($n - 1) / 2)
            genuine_original_global_thresholds = $genuine.Count
            frozen_original_global_thresholds = $frozen.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_endpoint_triple_interaction = $genuine.ToArray()
        frozen_global_threshold_endpoint_triple_interaction = $frozen.ToArray()
        individual_original_family_endpoint_triple_interaction = $families.ToArray()
        only_consumed_checked_ec093_to_ec096_original_graph_projections = $true
        original_ec071_caller_bits_and_all_actual_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_reachability_loss_is_real_fault_probability_history_or_repair_priority = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

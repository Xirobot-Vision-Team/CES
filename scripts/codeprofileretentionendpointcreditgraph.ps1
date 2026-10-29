#requires -Version 7.0
<#
    EC-092: ORIGINAL unordered pair endpoint FIRST-credit comparison graph.

    Retain the two real original reporter identities in every unordered pair,
    distinguish the two disjoint direction universes at every eligible gap,
    and explicitly keep non-endpoint/never-FIRST cases as a residual rather
    than awarding them to either endpoint. Only when an endpoint receives
    FIRST credit, show the exact conditional allocation between a and b.

    Every edge is an incidence comparison of hypothetical complete ORIGINAL
    orderings under the existing saved-witness model, never a chronological
    head-to-head, quality ranking, empirical chance or causal diagnosis.
    This projection consumes checked EC-089 and EC-091 public values only;
    no record/Git/source/network read, no permutation enumeration, no writes.
#>

function Get-CodeSequenceEndpointCreditConditionalShare {
    param([long] $Credited, [long] $EndpointFirst)

    if ($Credited -lt 0 -or $EndpointFirst -lt 0 -or $Credited -gt $EndpointFirst) {
        throw 'Code Sequence endpoint credit graph received an invalid conditional FIRST share.'
    }
    # No eligible endpoint-FIRST events: undefined, never a manufactured 0/1.
    if ($EndpointFirst -eq 0) { return $null }
    return (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $Credited -Denominator $EndpointFirst)
}

function Get-CodeSequenceEndpointCreditRelation {
    param([long] $A, [long] $B)
    if ($A -lt 0 -or $B -lt 0) { throw 'Code Sequence endpoint credit comparison cannot be negative.' }
    if ($A -gt $B) { return 'a_more' }
    if ($B -gt $A) { return 'b_more' }
    return 'equal'
}

function Get-CodeSequenceEndpointCreditGraphProjection {
    param(
        [object] $PairReciprocity,
        [object] $ReporterPartnerMatrix,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $PairReciprocity -or
        $null -eq $ReporterPartnerMatrix -or
        -not [bool]$PairReciprocity.every_unordered_pair_has_both_disjoint_original_precedence_directions -or
        -not [bool]$PairReciprocity.every_bidirectional_gap_reconciles_independent_ec074_via_ec088 -or
        -not [bool]$PairReciprocity.every_original_endpoint_and_intermediary_identity_mass_is_conserved -or
        -not [bool]$PairReciprocity.all_six_global_first_support_categories_match_independent_ec074_and_ec076 -or
        -not [bool]$ReporterPartnerMatrix.every_original_report_partner_is_both_direction_complete_and_symmetric -or
        -not [bool]$ReporterPartnerMatrix.every_partner_gap_first_restorer_is_within_its_direction_denominator -or
        -not [bool]$ReporterPartnerMatrix.every_reporter_partner_gap_and_all_gap_matches_ec090_role_exposure -or
        -not [bool]$ReporterPartnerMatrix.all_partner_first_restorer_identity_totals_match_ec089_and_ec074_via_ec090 -or
        -not [bool]$ReporterPartnerMatrix.outside_interval_and_intervening_first_restorer_are_not_assigned_to_endpoints -or
        -not [bool]$ReporterPartnerMatrix.no_new_evidence_source_mask_enumeration_git_network_or_business_write) {
        throw 'Code Sequence endpoint credit graph requires fully checked EC-089 / EC-091 ORIGINAL views.'
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorials[$N]
    $half = [long]($full / 2)
    $pairCount = [int]($N * ($N - 1) / 2)
    $pairs = [object[]]$PairReciprocity.unordered_original_report_pair_reciprocities
    $reporters = [object[]]$ReporterPartnerMatrix.original_reporter_partner_endpoint_profiles
    $histograms = [object[]]$PairReciprocity.distance_histogram_across_unordered_original_pairs
    if ([int]$PairReciprocity.original_positions_in_reciprocity_universe -ne $N -or
        [int]$ReporterPartnerMatrix.original_positions_in_partner_universe -ne $N -or
        [int]$PairReciprocity.exact_unordered_original_pair_count -ne $pairCount -or
        [int]$ReporterPartnerMatrix.exact_unordered_original_pair_count -ne $pairCount -or
        [int]$ReporterPartnerMatrix.exact_directed_original_report_partner_count -ne $N * ($N - 1) -or
        [long]$PairReciprocity.total_distinct_full_original_permutations -ne $full -or
        [long]$ReporterPartnerMatrix.total_distinct_full_original_permutations -ne $full -or
        [long]$PairReciprocity.exact_full_orderings_per_unordered_original_pair -ne $full -or
        [bool]$PairReciprocity.full_original_selection_has_saved_witness_support -ne
            [bool]$ReporterPartnerMatrix.full_original_selection_has_saved_witness_support -or
        $pairs.Count -ne $pairCount -or $reporters.Count -ne $N -or $histograms.Count -ne $N - 1) {
        throw 'Code Sequence endpoint credit graph received mismatched original reporter/pair universes.'
    }

    # Index both EC-091 subject perspectives by ORIGINAL position, not by a
    # possibly reordered returned partner array. Enforce the public caller order.
    $slots = [object[]]::new($N)
    $reporterEarlier = [long[]]::new($N)
    $reporterLater = [long[]]::new($N)
    $nodeMore = [int[]]::new($N)
    $nodeLess = [int[]]::new($N)
    $nodeEqual = [int[]]::new($N)
    $nodeNoEndpoint = [int[]]::new($N)
    for ($r = 0; $r -lt $N; $r++) {
        $sourceReporter = $reporters[$r]
        if ($null -eq $sourceReporter -or
            [int]$sourceReporter.original_reporter_caller_position -ne $r + 1 -or
            [int]$sourceReporter.original_reporter_position_bit -ne (1 -shl $r) -or
            [int]$sourceReporter.original_distinct_endpoint_partner_count -ne $N - 1) {
            throw 'Code Sequence endpoint credit graph lost a true ORIGINAL subject identity.'
        }
        $sourcePartners = [object[]]$sourceReporter.partner_profiles_in_original_caller_order
        if ($sourcePartners.Count -ne $N - 1) {
            throw 'Code Sequence endpoint credit graph omitted an original partner.'
        }
        $slots[$r] = [object[]]::new($N)
        $i = 0
        for ($s = 0; $s -lt $N; $s++) {
            if ($r -eq $s) { continue }
            $p = $sourcePartners[$i]
            $i++
            if ($null -eq $p -or
                [int]$p.original_partner_caller_position -ne $s + 1 -or
                [int]$p.original_partner_position_bit -ne (1 -shl $s) -or
                [long]$p.exact_full_original_orderings_per_reporter_endpoint_direction -ne $half) {
                throw 'Code Sequence endpoint credit graph received reindexed or altered partner evidence.'
            }
            $slots[$r][$s] = $p
        }
    }

    $globalEndpoint = [long]0
    $globalResidual = [long]0
    $globalEarlier = [long]0
    $globalLater = [long]0
    $gapEarlier = [long[]]::new($N - 1)
    $gapLater = [long[]]::new($N - 1)
    $gapResidual = [long[]]::new($N - 1)
    $edges = [System.Collections.Generic.List[object]]::new()
    $pairIndex = 0
    for ($a = 0; $a -lt $N; $a++) {
        for ($b = $a + 1; $b -lt $N; $b++) {
            $source = $pairs[$pairIndex]
            $aPerspective = $slots[$a][$b]
            $bPerspective = $slots[$b][$a]
            $pairIndex++
            if ($null -eq $source -or $null -eq $aPerspective -or $null -eq $bPerspective -or
                [int]$source.original_report_a_caller_position -ne $a + 1 -or
                [int]$source.original_report_b_caller_position -ne $b + 1 -or
                [int]$source.original_report_a_position_bit -ne (1 -shl $a) -or
                [int]$source.original_report_b_position_bit -ne (1 -shl $b) -or
                [long]$source.exact_full_original_orderings_with_either_endpoint_direction -ne $full -or
                [int]$aPerspective.original_unordered_pair_index_in_ec089 -ne $pairIndex -or
                [int]$bPerspective.original_unordered_pair_index_in_ec089 -ne $pairIndex) {
                throw 'Code Sequence endpoint credit graph cannot join an original a/b pair by identity.'
            }
            $originalCases = [object[]]$source.distance_cases
            $aCases = [object[]]$aPerspective.distance_cases
            $bCases = [object[]]$bPerspective.distance_cases
            if ($originalCases.Count -ne $N - 1 -or $aCases.Count -ne $N - 1 -or
                $bCases.Count -ne $N - 1) {
                throw 'Code Sequence endpoint credit graph received an incomplete original gap spectrum.'
            }
            $edgeCases = [System.Collections.Generic.List[object]]::new()
            $totalA = [long]0
            $totalB = [long]0
            $totalResidual = [long]0
            $edgeEarlier = [long]0
            $edgeLater = [long]0
            $aEarlierTotal = [long]0
            $aLaterTotal = [long]0
            $bEarlierTotal = [long]0
            $bLaterTotal = [long]0
            $directionMass = [long]0
            for ($g = 0; $g -lt $N - 1; $g++) {
                $c = $originalCases[$g]
                $ar = $aCases[$g]
                $br = $bCases[$g]
                $d = [long]($N - $g - 1) * [long]$factorials[$N - 2]
                if ($null -eq $c -or $null -eq $ar -or $null -eq $br -or
                    [int]$c.number_of_original_reports_strictly_between_pair -ne $g -or
                    [int]$ar.number_of_original_reports_strictly_between_reporter_and_partner -ne $g -or
                    [int]$br.number_of_original_reports_strictly_between_reporter_and_partner -ne $g -or
                    [long]$c.exact_full_original_orderings_per_endpoint_direction -ne $d -or
                    [long]$c.exact_full_original_orderings_with_either_endpoint_direction -ne 2 * $d -or
                    [long]$ar.exact_full_original_orderings_with_reporter_earlier_than_partner -ne $d -or
                    [long]$ar.exact_full_original_orderings_with_reporter_later_than_partner -ne $d -or
                    [long]$br.exact_full_original_orderings_with_reporter_earlier_than_partner -ne $d -or
                    [long]$br.exact_full_original_orderings_with_reporter_later_than_partner -ne $d) {
                    throw 'Code Sequence endpoint credit graph received altered original direction/gap denominators.'
                }
                $aBeforeBByA = [long]$ar.first_restored_by_reporter_as_earlier_endpoint
                $aBeforeBByB = [long]$br.first_restored_by_reporter_as_later_endpoint
                $bBeforeAByA = [long]$ar.first_restored_by_reporter_as_later_endpoint
                $bBeforeAByB = [long]$br.first_restored_by_reporter_as_earlier_endpoint
                $aFirst = $aBeforeBByA + $bBeforeAByA
                $bFirst = $aBeforeBByB + $bBeforeAByB
                $earlier = $aBeforeBByA + $bBeforeAByB
                $later = $aBeforeBByB + $bBeforeAByA
                $forwardResidual = $d - $aBeforeBByA - $aBeforeBByB
                $reverseResidual = $d - $bBeforeAByA - $bBeforeAByB
                $residual = $forwardResidual + $reverseResidual
                $endpoint = $aFirst + $bFirst
                $before = [long]$c.first_restoring_before_either_first_endpoint
                $middle = [long]$c.first_restored_by_original_intervening_report
                $after = [long]$c.first_restoring_after_either_second_endpoint
                $never = [long]$c.never_restoring_saved_evidence
                $nonEndpointFromSource = $before + $middle + $after + $never
                if ($before -lt 0 -or $middle -lt 0 -or $after -lt 0 -or $never -lt 0 -or
                    $aBeforeBByA -lt 0 -or $aBeforeBByB -lt 0 -or
                    $bBeforeAByA -lt 0 -or $bBeforeAByB -lt 0 -or
                    $forwardResidual -lt 0 -or $reverseResidual -lt 0 -or
                    $nonEndpointFromSource -lt 0 -or
                    $residual -ne $nonEndpointFromSource -or
                    $aFirst -ne [long]$ar.first_restored_by_reporter_as_either_endpoint -or
                    $bFirst -ne [long]$br.first_restored_by_reporter_as_either_endpoint -or
                    $bBeforeAByA - $aBeforeBByA -ne [long]$ar.exact_signed_later_minus_earlier_first_restorer_count -or
                    $aBeforeBByB - $bBeforeAByB -ne [long]$br.exact_signed_later_minus_earlier_first_restorer_count -or
                    $aFirst -ne [long]$c.first_restored_by_original_report_a -or
                    $bFirst -ne [long]$c.first_restored_by_original_report_b -or
                    $aBeforeBByB -ne [long]$c.first_restored_when_later_in_a_before_b_direction -or
                    $bBeforeAByA -ne [long]$c.first_restored_when_later_in_b_before_a_direction -or
                    $aBeforeBByB - $bBeforeAByA -ne [long]$c.exact_signed_later_direction_contrast -or
                    $endpoint + $residual -ne 2 * $d) {
                    throw 'Code Sequence endpoint credit graph violates original pair direction FIRST conservation.'
                }
                if (-not [bool]$PairReciprocity.full_original_selection_has_saved_witness_support -and $endpoint -ne 0) {
                    throw 'Code Sequence endpoint credit graph invented FIRST credit for unsupported originals.'
                }
                $edgeCases.Add([ordered]@{
                    number_of_original_reports_strictly_between_pair = $g
                    exact_full_original_orderings_per_direction = $d
                    first_restored_by_a_when_a_before_b = $aBeforeBByA
                    first_restored_by_b_when_a_before_b = $aBeforeBByB
                    neither_endpoint_first_when_a_before_b = $forwardResidual
                    first_restored_by_a_when_b_before_a = $bBeforeAByA
                    first_restored_by_b_when_b_before_a = $bBeforeAByB
                    neither_endpoint_first_when_b_before_a = $reverseResidual
                    first_restored_by_original_a_in_either_direction = $aFirst
                    first_restored_by_original_b_in_either_direction = $bFirst
                    first_restored_by_either_endpoint = $endpoint
                    neither_endpoint_first_across_both_directions = $residual
                    original_a_vs_b_endpoint_credit_relation = (Get-CodeSequenceEndpointCreditRelation -A $aFirst -B $bFirst)
                    exact_signed_original_a_minus_b_first_credit_count = $aFirst - $bFirst
                    exact_reduced_signed_a_minus_b_credit_fraction_over_both_directions = `
                        (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($aFirst - $bFirst) -Denominator (2 * $d))
                    exact_reduced_a_share_given_either_endpoint_first = `
                        (Get-CodeSequenceEndpointCreditConditionalShare -Credited $aFirst -EndpointFirst $endpoint)
                    exact_reduced_b_share_given_either_endpoint_first = `
                        (Get-CodeSequenceEndpointCreditConditionalShare -Credited $bFirst -EndpointFirst $endpoint)
                })
                $totalA += $aFirst
                $totalB += $bFirst
                $totalResidual += $residual
                $edgeEarlier += $earlier
                $edgeLater += $later
                $aEarlierTotal += $aBeforeBByA
                $aLaterTotal += $bBeforeAByA
                $bEarlierTotal += $bBeforeAByB
                $bLaterTotal += $aBeforeBByB
                $gapEarlier[$g] += $earlier
                $gapLater[$g] += $later
                $gapResidual[$g] += $residual
                $reporterEarlier[$a] += $aBeforeBByA
                $reporterEarlier[$b] += $bBeforeAByB
                $reporterLater[$a] += $bBeforeAByA
                $reporterLater[$b] += $aBeforeBByB
                $directionMass += $d
            }
            $endpointTotal = $totalA + $totalB
            if ($directionMass -ne $half -or $endpointTotal + $totalResidual -ne $full -or
                $totalA -ne [long]$source.full_pair_first_restored_by_original_report_a -or
                $totalB -ne [long]$source.full_pair_first_restored_by_original_report_b -or
                $edgeEarlier -ne [long]$source.full_pair_first_restored_by_earlier_endpoint -or
                $edgeLater -ne [long]$source.full_pair_first_restored_by_later_endpoint -or
                $totalA -ne [long]$aPerspective.first_restored_by_reporter_as_either_endpoint_across_all_gaps -or
                $totalB -ne [long]$bPerspective.first_restored_by_reporter_as_either_endpoint_across_all_gaps -or
                $aEarlierTotal -ne [long]$aPerspective.first_restored_by_reporter_as_earlier_endpoint_across_all_gaps -or
                $aLaterTotal -ne [long]$aPerspective.first_restored_by_reporter_as_later_endpoint_across_all_gaps -or
                $bEarlierTotal -ne [long]$bPerspective.first_restored_by_reporter_as_earlier_endpoint_across_all_gaps -or
                $bLaterTotal -ne [long]$bPerspective.first_restored_by_reporter_as_later_endpoint_across_all_gaps -or
                $totalResidual -ne ([long]$source.full_pair_first_restoring_before_first_endpoint +
                    [long]$source.full_pair_first_restored_between_endpoints +
                    [long]$source.full_pair_first_restoring_after_later_endpoint +
                    [long]$source.full_pair_never_restoring_saved_evidence)) {
                throw 'Code Sequence endpoint credit graph contradicts EC-089/091 all-gap pair ledgers.'
            }
            $relation = Get-CodeSequenceEndpointCreditRelation -A $totalA -B $totalB
            if ($relation -ceq 'a_more') { $nodeMore[$a]++; $nodeLess[$b]++ }
            elseif ($relation -ceq 'b_more') { $nodeMore[$b]++; $nodeLess[$a]++ }
            else { $nodeEqual[$a]++; $nodeEqual[$b]++ }
            if ($endpointTotal -eq 0) { $nodeNoEndpoint[$a]++; $nodeNoEndpoint[$b]++ }
            $globalEndpoint += $endpointTotal
            $globalResidual += $totalResidual
            $globalEarlier += $edgeEarlier
            $globalLater += $edgeLater
            $edges.Add([ordered]@{
                original_unordered_pair_index_in_ec089 = $pairIndex
                original_report_a_caller_position = $a + 1
                original_report_b_caller_position = $b + 1
                original_report_a_position_bit = 1 -shl $a
                original_report_b_position_bit = 1 -shl $b
                exact_full_original_orderings_across_both_directions = $full
                distance_cases = $edgeCases.ToArray()
                first_restored_by_original_a_across_all_gaps = $totalA
                first_restored_by_original_b_across_all_gaps = $totalB
                first_restored_by_either_endpoint_across_all_gaps = $endpointTotal
                neither_endpoint_first_across_all_gaps = $totalResidual
                original_a_vs_b_endpoint_credit_relation = $relation
                exact_signed_original_a_minus_b_first_credit_count = $totalA - $totalB
                exact_reduced_signed_a_minus_b_credit_fraction_over_full_pair = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($totalA - $totalB) -Denominator $full)
                exact_reduced_a_share_given_either_endpoint_first = `
                    (Get-CodeSequenceEndpointCreditConditionalShare -Credited $totalA -EndpointFirst $endpointTotal)
                exact_reduced_b_share_given_either_endpoint_first = `
                    (Get-CodeSequenceEndpointCreditConditionalShare -Credited $totalB -EndpointFirst $endpointTotal)
            })
        }
    }
    if ($pairIndex -ne $pairCount -or $edges.Count -ne $pairCount) {
        throw 'Code Sequence endpoint credit graph lost a canonical original unordered edge.'
    }

    $nodes = [System.Collections.Generic.List[object]]::new()
    $nodeTotal = [long]0
    for ($r = 0; $r -lt $N; $r++) {
        $profile = $reporters[$r]
        $credit = $reporterEarlier[$r] + $reporterLater[$r]
        if ($reporterEarlier[$r] -ne [long]$profile.first_restored_as_earlier_endpoint_across_partners -or
            $reporterLater[$r] -ne [long]$profile.first_restored_as_later_endpoint_across_partners -or
            $credit -ne [long]$profile.first_restored_as_either_endpoint_across_partners -or
            $reporterEarlier[$r] -ne [long]$PairReciprocity.first_restored_by_original_caller_position_as_earlier_endpoint[$r] -or
            $reporterLater[$r] -ne [long]$PairReciprocity.first_restored_by_original_caller_position_as_later_endpoint[$r] -or
            $nodeMore[$r] + $nodeLess[$r] + $nodeEqual[$r] -ne $N - 1 -or
            $nodeNoEndpoint[$r] -gt $nodeEqual[$r]) {
            throw 'Code Sequence endpoint credit graph lost reporter-level EC-089/091 FIRST or pair-incidence conservation.'
        }
        $nodeTotal += $credit
        $nodes.Add([ordered]@{
            original_reporter_caller_position = $r + 1
            original_reporter_position_bit = 1 -shl $r
            original_distinct_endpoint_partner_count = $N - 1
            original_pairs_with_more_endpoint_first_credit_than_partner = $nodeMore[$r]
            original_pairs_with_less_endpoint_first_credit_than_partner = $nodeLess[$r]
            original_pairs_with_equal_endpoint_first_credit = $nodeEqual[$r]
            original_pairs_with_no_endpoint_first_credit = $nodeNoEndpoint[$r]
            first_restored_as_earlier_endpoint_across_partners = $reporterEarlier[$r]
            first_restored_as_later_endpoint_across_partners = $reporterLater[$r]
            first_restored_as_either_endpoint_across_partners = $credit
            exact_reduced_reporter_share_of_all_original_endpoint_first_credit = `
                (Get-CodeSequenceEndpointCreditConditionalShare -Credited $credit -EndpointFirst $globalEndpoint)
        })
    }
    $six = $PairReciprocity.original_global_six_first_support_categories
    if ($globalEndpoint -ne $nodeTotal -or $globalEndpoint + $globalResidual -ne [long]$pairCount * $full -or
        $globalEarlier -ne [long]$ReporterPartnerMatrix.first_restored_by_all_original_earlier_endpoint_roles -or
        $globalLater -ne [long]$ReporterPartnerMatrix.first_restored_by_all_original_later_endpoint_roles -or
        $globalEarlier -ne [long]$six.by_first -or $globalLater -ne [long]$six.by_second -or
        $globalEndpoint -ne [long]$six.by_first + [long]$six.by_second -or
        $globalResidual -ne ([long]$six.before_first + [long]$six.first_restored_between +
            [long]$six.after_second + [long]$six.never)) {
        throw 'Code Sequence endpoint credit graph contradicts independent EC-074/076/089/091 global FIRST mass.'
    }
    for ($g = 0; $g -lt $N - 1; $g++) {
        $hist = $histograms[$g]
        $expected = [long]$pairCount * 2 * ($N - $g - 1) * [long]$factorials[$N - 2]
        if ($null -eq $hist -or
            [int]$hist.number_of_original_reports_strictly_between_pair -ne $g -or
            $gapEarlier[$g] -ne [long]$hist.by_earlier_endpoint -or
            $gapLater[$g] -ne [long]$hist.by_later_endpoint -or
            $gapEarlier[$g] + $gapLater[$g] + $gapResidual[$g] -ne $expected -or
            $gapResidual[$g] -ne ([long]$hist.before_first_endpoint +
                [long]$hist.by_intervening_original_report + [long]$hist.after_later_endpoint +
                [long]$hist.never)) {
            throw 'Code Sequence endpoint credit graph contradicts EC-089 original gap FIRST histogram.'
        }
    }
    if (-not [bool]$PairReciprocity.full_original_selection_has_saved_witness_support -and $globalEndpoint -ne 0) {
        throw 'Code Sequence endpoint credit graph attributed unsupported original endpoint FIRST evidence.'
    }
    return [ordered]@{
        original_positions_in_credit_graph = $N
        exact_unordered_original_pair_edge_count = $pairCount
        exact_total_original_pair_ordering_incidences = [long]$pairCount * $full
        total_distinct_full_original_permutations = $full
        full_original_selection_has_saved_witness_support = [bool]$PairReciprocity.full_original_selection_has_saved_witness_support
        original_unordered_endpoint_credit_edges = $edges.ToArray()
        original_reporter_endpoint_credit_nodes = $nodes.ToArray()
        total_first_restored_by_any_original_pair_endpoint = $globalEndpoint
        total_neither_endpoint_first_ordering_incidences = $globalResidual
        every_original_pair_direction_and_gap_is_exhaustive_and_disjoint = $true
        every_reporter_first_credit_matches_ec089_and_ec091_original_identity = $true
        endpoint_first_only_conditional_shares_are_null_when_ineligible = $true
        all_first_restoration_mass_matches_independent_ec074_ec076_ec089 = $true
        nonendpoint_or_never_restoration_is_never_attributed_to_a_or_b = $true
        no_new_evidence_read_mask_enumeration_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointCreditGraph {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionPairReciprocity,
        [object] $RetentionReporterPartner
    )
    if ($null -eq $RetentionPivotality -or $null -eq $RetentionPairReciprocity -or
        $null -eq $RetentionReporterPartner -or
        -not [bool]$RetentionPairReciprocity.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairReciprocity.only_consumed_checked_ec088_and_independent_ec076_original_projections -or
        -not [bool]$RetentionReporterPartner.only_consumed_checked_ec089_and_ec090_public_original_projections -or
        -not [bool]$RetentionReporterPartner.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionReporterPartner.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionReporterPartner.outside_interval_first_restorer_identity_remains_unattributed -or
        -not [bool]$RetentionReporterPartner.no_new_evidence_read_reoptimization_git_network_or_business_write) {
        throw 'Code Sequence endpoint credit graph requires the unchanged fifth-level selector and checked ORIGINAL parents.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionPairReciprocity.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionReporterPartner.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairReciprocity.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionReporterPartner.counts.original_maximal_repeat_family_count -ne $familyCount) {
        throw 'Code Sequence endpoint credit graph received mismatched original selection dimensions.'
    }
    foreach ($parent in @($RetentionPairReciprocity, $RetentionReporterPartner)) {
        if ([int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence endpoint credit graph changed selected path/anchor provenance.'
        }
    }
    $gPairs = [object[]]$RetentionPairReciprocity.genuine_global_threshold_pair_reciprocity
    $fPairs = [object[]]$RetentionPairReciprocity.frozen_global_threshold_pair_reciprocity
    $gMatrix = [object[]]$RetentionReporterPartner.genuine_global_threshold_reporter_partner_endpoint_matrix
    $fMatrix = [object[]]$RetentionReporterPartner.frozen_global_threshold_reporter_partner_endpoint_matrix
    $pairFamilies = [object[]]$RetentionPairReciprocity.individual_original_family_pair_reciprocity
    $matrixFamilies = [object[]]$RetentionReporterPartner.individual_original_family_reporter_partner_endpoint_matrix
    if ($gPairs.Count -ne 3 -or $fPairs.Count -ne 3 -or
        $gMatrix.Count -ne 3 -or $fMatrix.Count -ne 3 -or
        $pairFamilies.Count -ne $familyCount -or $matrixFamilies.Count -ne $familyCount) {
        throw 'Code Sequence endpoint credit graph lost genuine/frozen targets or original families.'
    }
    $gOut = [System.Collections.Generic.List[object]]::new()
    $fOut = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $sourcePairs = if ($mode -eq 0) { $gPairs } else { $fPairs }
        $sourceMatrix = if ($mode -eq 0) { $gMatrix } else { $fMatrix }
        $target = if ($mode -eq 0) { $gOut } else { $fOut }
        for ($i = 0; $i -lt 3; $i++) {
            $threshold = 3 - $i
            if ([int]$sourcePairs[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$sourceMatrix[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$sourcePairs[$i].original_full_selection_global_family_capacity -ne
                    [int]$sourceMatrix[$i].original_full_selection_global_family_capacity) {
                throw 'Code Sequence endpoint credit graph changed an ORIGINAL global capacity threshold.'
            }
            $projection = Get-CodeSequenceEndpointCreditGraphProjection `
                -PairReciprocity $sourcePairs[$i].exact_first_support_pair_reciprocity `
                -ReporterPartnerMatrix $sourceMatrix[$i].exact_original_reporter_partner_endpoint_matrix -N $n
            $target.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = [int]$sourcePairs[$i].original_full_selection_global_family_capacity
                exact_original_endpoint_first_credit_comparison_graph = $projection
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        if ([int]$pairFamilies[$i].original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$matrixFamilies[$i].original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence endpoint credit graph reindexed original maximal repeat families.'
        }
        $g = Get-CodeSequenceEndpointCreditGraphProjection `
            -PairReciprocity $pairFamilies[$i].genuine_original_first_support_pair_reciprocity `
            -ReporterPartnerMatrix $matrixFamilies[$i].genuine_original_reporter_partner_endpoint_matrix -N $n
        $f = Get-CodeSequenceEndpointCreditGraphProjection `
            -PairReciprocity $pairFamilies[$i].frozen_original_first_support_pair_reciprocity `
            -ReporterPartnerMatrix $matrixFamilies[$i].frozen_original_reporter_partner_endpoint_matrix -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_endpoint_first_credit_comparison_graph = $g
            frozen_original_endpoint_first_credit_comparison_graph = $f
        })
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_endpoint_first_credit_comparison_graph'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_unordered_pair_edges_per_target = [int]($n * ($n - 1) / 2)
            original_reporter_credit_nodes_per_target = $n
            original_gap_cases_per_pair_edge = $n - 1
            hypothetical_full_original_orderings_per_unordered_pair = [long]$factorials[$n]
            genuine_original_global_thresholds = $gOut.Count
            frozen_original_global_thresholds = $fOut.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_endpoint_credit_graph = $gOut.ToArray()
        frozen_global_threshold_endpoint_credit_graph = $fOut.ToArray()
        individual_original_family_endpoint_credit_graph = $families.ToArray()
        only_consumed_checked_ec089_and_ec091_public_original_projections = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        endpoint_credit_is_hypothetical_incidence_not_real_time_or_probability = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

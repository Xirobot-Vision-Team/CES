#requires -Version 7.0
<#
    EC-091: ORIGINAL report-to-partner endpoint FIRST-restoration matrix.

    For each ORIGINAL reporter r and each other original partner s, preserve
    the exact disjoint r-before-s and s-before-r gap universes. Attribute
    FIRST restoration to r only when r is an endpoint, separately when r is
    earlier and later than this SPECIFIC partner. Fold EC-089's original
    report-a/b identity and genuine later-direction fields into EC-090's
    checked per-reporter, per-gap and all-gap endpoint role ledgers.

    All complete orderings are hypothetical, not authenticated report time.
    Neither outside-interval nor intermediary first restoration is assigned
    to an endpoint. This is a pure read-only public-projection fold, with no
    new saved records, support mask enumeration, Git, network or source I/O.
#>

function New-CodeSequenceRetentionReporterPartnerGapRow {
    param(
        [int] $Gap,
        [long] $DirectionDenominator,
        [long] $EarlierFirst,
        [long] $LaterFirst
    )

    if ($DirectionDenominator -le 0 -or $EarlierFirst -lt 0 -or $LaterFirst -lt 0 -or
        $EarlierFirst -gt $DirectionDenominator -or $LaterFirst -gt $DirectionDenominator) {
        throw 'Code Sequence reporter partner matrix received an ineligible or over-credited endpoint direction.'
    }
    $total = $EarlierFirst + $LaterFirst
    $signed = $LaterFirst - $EarlierFirst
    return [ordered]@{
        number_of_original_reports_strictly_between_reporter_and_partner = $Gap
        exact_full_original_orderings_with_reporter_earlier_than_partner = $DirectionDenominator
        exact_full_original_orderings_with_reporter_later_than_partner = $DirectionDenominator
        first_restored_by_reporter_as_earlier_endpoint = $EarlierFirst
        first_restored_by_reporter_as_later_endpoint = $LaterFirst
        first_restored_by_reporter_as_either_endpoint = $total
        exact_signed_later_minus_earlier_first_restorer_count = $signed
        exact_reduced_first_restorer_fraction_given_reporter_earlier = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $EarlierFirst -Denominator $DirectionDenominator)
        exact_reduced_first_restorer_fraction_given_reporter_later = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $LaterFirst -Denominator $DirectionDenominator)
        exact_reduced_first_restorer_fraction_given_either_direction = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $total -Denominator (2 * $DirectionDenominator))
        exact_reduced_signed_later_minus_earlier_fraction = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $signed -Denominator $DirectionDenominator)
    }
}

function New-CodeSequenceRetentionReporterPartnerRow {
    param(
        [int] $PairIndex,
        [int] $PartnerPosition,
        [long] $HalfFullOrderings,
        [object[]] $GapRows,
        [long] $FirstEarlier,
        [long] $FirstLater
    )

    $mass = [long]0
    foreach ($gap in $GapRows) {
        $mass += [long]$gap.exact_full_original_orderings_with_reporter_earlier_than_partner
    }
    if ($mass -ne $HalfFullOrderings -or $FirstEarlier -lt 0 -or $FirstLater -lt 0 -or
        $FirstEarlier -gt $HalfFullOrderings -or $FirstLater -gt $HalfFullOrderings) {
        throw 'Code Sequence reporter partner matrix lost the N!/2 endpoint direction universe.'
    }
    $first = $FirstEarlier + $FirstLater
    return [ordered]@{
        original_unordered_pair_index_in_ec089 = $PairIndex
        original_partner_caller_position = $PartnerPosition
        original_partner_position_bit = 1 -shl ($PartnerPosition - 1)
        exact_full_original_orderings_per_reporter_endpoint_direction = $HalfFullOrderings
        distance_cases = $GapRows
        first_restored_by_reporter_as_earlier_endpoint_across_all_gaps = $FirstEarlier
        first_restored_by_reporter_as_later_endpoint_across_all_gaps = $FirstLater
        first_restored_by_reporter_as_either_endpoint_across_all_gaps = $first
        exact_signed_later_minus_earlier_first_restorer_count = $FirstLater - $FirstEarlier
        exact_reduced_first_restorer_fraction_given_reporter_earlier = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $FirstEarlier -Denominator $HalfFullOrderings)
        exact_reduced_first_restorer_fraction_given_reporter_later = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $FirstLater -Denominator $HalfFullOrderings)
        exact_reduced_first_restorer_fraction_given_either_direction = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $first -Denominator (2 * $HalfFullOrderings))
        exact_reduced_signed_later_minus_earlier_fraction = `
            (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($FirstLater - $FirstEarlier) -Denominator $HalfFullOrderings)
    }
}

function Get-CodeSequenceRetentionReporterPartnerProjection {
    param(
        [object] $PairReciprocity,
        [object] $ReporterRoleExposure,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $PairReciprocity -or
        $null -eq $ReporterRoleExposure -or
        -not [bool]$PairReciprocity.every_unordered_pair_has_both_disjoint_original_precedence_directions -or
        -not [bool]$PairReciprocity.every_bidirectional_gap_reconciles_independent_ec074_via_ec088 -or
        -not [bool]$PairReciprocity.every_original_endpoint_and_intermediary_identity_mass_is_conserved -or
        -not [bool]$PairReciprocity.all_six_global_first_support_categories_match_independent_ec074_and_ec076 -or
        -not [bool]$ReporterRoleExposure.every_original_report_has_exact_pair_endpoint_and_nonendpoint_exposures -or
        -not [bool]$ReporterRoleExposure.every_original_gap_exposure_partitions_full_unordered_pair_universe -or
        -not [bool]$ReporterRoleExposure.every_original_role_first_restorer_count_is_within_exposure_denominator -or
        -not [bool]$ReporterRoleExposure.every_reporter_gap_first_restorer_reconciles_independent_ec089_pair_rows -or
        -not [bool]$ReporterRoleExposure.all_reporter_first_restorer_role_counts_match_independent_ec074_via_ec089 -or
        -not [bool]$ReporterRoleExposure.no_outside_first_restorer_identity_inferred -or
        -not [bool]$ReporterRoleExposure.no_new_evidence_source_read_or_business_write) {
        throw 'Code Sequence reporter partner matrix needs fully checked EC-089 and EC-090 ORIGINAL projections.'
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorials[$N]
    $half = [long]($full / 2)
    $pairCount = [int]($N * ($N - 1) / 2)
    $pairs = [object[]]$PairReciprocity.unordered_original_report_pair_reciprocities
    $histograms = [object[]]$PairReciprocity.distance_histogram_across_unordered_original_pairs
    $reporterRoles = [object[]]$ReporterRoleExposure.original_reporter_role_exposure_profiles
    if ([int]$PairReciprocity.original_positions_in_reciprocity_universe -ne $N -or
        [int]$ReporterRoleExposure.original_positions_in_reporter_role_atlas -ne $N -or
        [long]$PairReciprocity.total_distinct_full_original_permutations -ne $full -or
        [long]$ReporterRoleExposure.total_distinct_full_original_permutations -ne $full -or
        [int]$PairReciprocity.exact_unordered_original_pair_count -ne $pairCount -or
        [int]$ReporterRoleExposure.exact_unordered_original_pair_count -ne $pairCount -or
        [long]$PairReciprocity.exact_full_orderings_per_unordered_original_pair -ne $full -or
        [bool]$PairReciprocity.full_original_selection_has_saved_witness_support -ne
            [bool]$ReporterRoleExposure.full_original_selection_has_saved_witness_support -or
        $pairs.Count -ne $pairCount -or $histograms.Count -ne $N - 1 -or
        $reporterRoles.Count -ne $N) {
        throw 'Code Sequence reporter partner matrix received mismatched ORIGINAL report universes.'
    }

    # Symmetric off-diagonal matrix indexed by real ORIGINAL caller position.
    # A canonical unordered pair is visited exactly once; both reporter rows
    # are created from that same checked pair without inventing pair order.
    $partnerSlots = [object[]]::new($N)
    $firstEarlierByGap = [object[]]::new($N)
    $firstLaterByGap = [object[]]::new($N)
    for ($k = 0; $k -lt $N; $k++) {
        $partnerSlots[$k] = [object[]]::new($N)
        $firstEarlierByGap[$k] = [long[]]::new($N - 1)
        $firstLaterByGap[$k] = [long[]]::new($N - 1)
    }
    $gapTotalsEarlier = [long[]]::new($N - 1)
    $gapTotalsLater = [long[]]::new($N - 1)
    $pairIndex = 0
    for ($a = 0; $a -lt $N; $a++) {
        for ($b = $a + 1; $b -lt $N; $b++) {
            $pair = $pairs[$pairIndex]
            $pairIndex++
            if ($null -eq $pair -or
                [int]$pair.original_report_a_caller_position -ne $a + 1 -or
                [int]$pair.original_report_b_caller_position -ne $b + 1 -or
                [int]$pair.original_report_a_position_bit -ne (1 -shl $a) -or
                [int]$pair.original_report_b_position_bit -ne (1 -shl $b) -or
                [long]$pair.exact_full_original_orderings_with_either_endpoint_direction -ne $full) {
                throw 'Code Sequence reporter partner matrix lost a canonical ORIGINAL unordered pair.'
            }
            $cases = [object[]]$pair.distance_cases
            if ($cases.Count -ne $N - 1) {
                throw 'Code Sequence reporter partner matrix cannot omit or create original distance cases.'
            }
            $aRows = [System.Collections.Generic.List[object]]::new()
            $bRows = [System.Collections.Generic.List[object]]::new()
            $aEarlierSum = [long]0
            $aLaterSum = [long]0
            $bEarlierSum = [long]0
            $bLaterSum = [long]0
            for ($g = 0; $g -lt $N - 1; $g++) {
                $source = $cases[$g]
                $d = [long]($N - $g - 1) * [long]$factorials[$N - 2]
                if ($null -eq $source -or
                    [int]$source.number_of_original_reports_strictly_between_pair -ne $g -or
                    [long]$source.exact_full_original_orderings_per_endpoint_direction -ne $d -or
                    [long]$source.exact_full_original_orderings_with_either_endpoint_direction -ne 2 * $d) {
                    throw 'Code Sequence reporter partner matrix received an altered ORIGINAL pair-gap universe.'
                }
                # EC-089's ORIGINAL-a/b identity count includes both directions;
                # its by-later fields split the correct source orientation.
                $aLater = [long]$source.first_restored_when_later_in_b_before_a_direction
                $bLater = [long]$source.first_restored_when_later_in_a_before_b_direction
                $aEarlier = [long]$source.first_restored_by_original_report_a - $aLater
                $bEarlier = [long]$source.first_restored_by_original_report_b - $bLater
                if ($aLater -lt 0 -or $bLater -lt 0 -or $aEarlier -lt 0 -or $bEarlier -lt 0 -or
                    $aLater -gt $d -or $bLater -gt $d -or $aEarlier -gt $d -or $bEarlier -gt $d -or
                    [long]$source.exact_signed_later_direction_contrast -ne $bLater - $aLater) {
                    throw 'Code Sequence reporter partner matrix encountered inconsistent original endpoint directions.'
                }
                $aRows.Add((New-CodeSequenceRetentionReporterPartnerGapRow `
                    -Gap $g -DirectionDenominator $d -EarlierFirst $aEarlier -LaterFirst $aLater))
                $bRows.Add((New-CodeSequenceRetentionReporterPartnerGapRow `
                    -Gap $g -DirectionDenominator $d -EarlierFirst $bEarlier -LaterFirst $bLater))
                $aEarlierSum += $aEarlier
                $aLaterSum += $aLater
                $bEarlierSum += $bEarlier
                $bLaterSum += $bLater
                $firstEarlierByGap[$a][$g] += $aEarlier
                $firstEarlierByGap[$b][$g] += $bEarlier
                $firstLaterByGap[$a][$g] += $aLater
                $firstLaterByGap[$b][$g] += $bLater
                $gapTotalsEarlier[$g] += $aEarlier + $bEarlier
                $gapTotalsLater[$g] += $aLater + $bLater
                if (-not [bool]$PairReciprocity.full_original_selection_has_saved_witness_support -and
                    ($aEarlier + $aLater + $bEarlier + $bLater -ne 0)) {
                    throw 'Code Sequence reporter partner matrix invented FIRST restoration for unsupported original evidence.'
                }
            }
            if ($aEarlierSum + $aLaterSum -ne [long]$pair.full_pair_first_restored_by_original_report_a -or
                $bEarlierSum + $bLaterSum -ne [long]$pair.full_pair_first_restored_by_original_report_b -or
                $aEarlierSum + $bEarlierSum -ne [long]$pair.full_pair_first_restored_by_earlier_endpoint -or
                $aLaterSum + $bLaterSum -ne [long]$pair.full_pair_first_restored_by_later_endpoint) {
                throw 'Code Sequence reporter partner matrix contradicts EC-089 per-pair endpoint and role FIRST ledgers.'
            }
            $partnerSlots[$a][$b] = New-CodeSequenceRetentionReporterPartnerRow `
                -PairIndex $pairIndex -PartnerPosition ($b + 1) -HalfFullOrderings $half `
                -GapRows $aRows.ToArray() -FirstEarlier $aEarlierSum -FirstLater $aLaterSum
            $partnerSlots[$b][$a] = New-CodeSequenceRetentionReporterPartnerRow `
                -PairIndex $pairIndex -PartnerPosition ($a + 1) -HalfFullOrderings $half `
                -GapRows $bRows.ToArray() -FirstEarlier $bEarlierSum -FirstLater $bLaterSum
        }
    }
    if ($pairIndex -ne $pairCount) {
        throw 'Code Sequence reporter partner matrix lost a canonical unordered ORIGINAL pair.'
    }

    $firstEarlierGlobal = [long]0
    $firstLaterGlobal = [long]0
    $profiles = [System.Collections.Generic.List[object]]::new()
    for ($k = 0; $k -lt $N; $k++) {
        $parent = $reporterRoles[$k]
        if ($null -eq $parent -or
            [int]$parent.original_report_caller_position -ne $k + 1 -or
            [int]$parent.original_report_position_bit -ne (1 -shl $k) -or
            [int]$parent.original_unordered_endpoint_partners -ne $N - 1) {
            throw 'Code Sequence reporter partner matrix reindexed the EC-090 original reporter identity.'
        }
        $roleCases = [object[]]$parent.distance_cases
        if ($roleCases.Count -ne $N - 1) {
            throw 'Code Sequence reporter partner matrix lacks an EC-090 reporter-gap role ledger.'
        }
        $partners = [System.Collections.Generic.List[object]]::new()
        $reporterEarlier = [long]0
        $reporterLater = [long]0
        for ($s = 0; $s -lt $N; $s++) {
            $entry = $partnerSlots[$k][$s]
            if ($k -eq $s) {
                if ($null -ne $entry) {
                    throw 'Code Sequence reporter partner matrix cannot pair a report with itself.'
                }
                continue
            }
            $counterpart = $partnerSlots[$s][$k]
            if ($null -eq $entry -or $null -eq $counterpart -or
                [int]$entry.original_partner_caller_position -ne $s + 1 -or
                [int]$entry.original_partner_position_bit -ne (1 -shl $s) -or
                [int]$counterpart.original_partner_caller_position -ne $k + 1 -or
                [int]$entry.original_unordered_pair_index_in_ec089 -ne
                    [int]$counterpart.original_unordered_pair_index_in_ec089) {
                throw 'Code Sequence reporter partner matrix lost symmetric original endpoint partner identity.'
            }
            $partners.Add($entry)
            $reporterEarlier += [long]$entry.first_restored_by_reporter_as_earlier_endpoint_across_all_gaps
            $reporterLater += [long]$entry.first_restored_by_reporter_as_later_endpoint_across_all_gaps
        }
        if ($partners.Count -ne $N - 1) {
            throw 'Code Sequence reporter partner matrix lost a reporter/partner incidence.'
        }
        for ($g = 0; $g -lt $N - 1; $g++) {
            $source = $roleCases[$g]
            $hist = $histograms[$g]
            $d = [long]($N - $g - 1) * [long]$factorials[$N - 2]
            if ($null -eq $source -or $null -eq $hist -or
                [int]$source.number_of_original_reports_strictly_between_pair -ne $g -or
                [long]$source.exact_role_exposure_as_earlier_endpoint -ne [long]($N - 1) * $d -or
                [long]$source.exact_role_exposure_as_later_endpoint -ne [long]($N - 1) * $d -or
                [long]$firstEarlierByGap[$k][$g] -ne [long]$source.first_restored_as_earlier_endpoint -or
                [long]$firstLaterByGap[$k][$g] -ne [long]$source.first_restored_as_later_endpoint -or
                [long]$firstEarlierByGap[$k][$g] -ne
                    [long]$hist.by_original_caller_position_as_earlier_endpoint[$k] -or
                [long]$firstLaterByGap[$k][$g] -ne
                    [long]$hist.by_original_caller_position_as_later_endpoint[$k]) {
                throw 'Code Sequence reporter partner matrix contradicts EC-090 reporter-gap or EC-089 gap identity.'
            }
        }
        if ($reporterEarlier -ne [long]$parent.first_restored_as_earlier_endpoint_across_all_gaps -or
            $reporterLater -ne [long]$parent.first_restored_as_later_endpoint_across_all_gaps -or
            [long]$parent.full_original_ordering_role_exposure_as_earlier_endpoint -ne [long]($N - 1) * $half -or
            [long]$parent.full_original_ordering_role_exposure_as_later_endpoint -ne [long]($N - 1) * $half -or
            $reporterEarlier -gt [long]($N - 1) * $half -or
            $reporterLater -gt [long]($N - 1) * $half) {
            throw 'Code Sequence reporter partner matrix contradicts EC-090 full-gap reporter endpoint totals.'
        }
        $firstEarlierGlobal += $reporterEarlier
        $firstLaterGlobal += $reporterLater
        $profiles.Add([ordered]@{
            original_reporter_caller_position = $k + 1
            original_reporter_position_bit = 1 -shl $k
            original_distinct_endpoint_partner_count = $N - 1
            partner_profiles_in_original_caller_order = $partners.ToArray()
            exact_full_ordering_exposure_as_earlier_endpoint_across_partners = [long]($N - 1) * $half
            exact_full_ordering_exposure_as_later_endpoint_across_partners = [long]($N - 1) * $half
            first_restored_as_earlier_endpoint_across_partners = $reporterEarlier
            first_restored_as_later_endpoint_across_partners = $reporterLater
            first_restored_as_either_endpoint_across_partners = $reporterEarlier + $reporterLater
            exact_reduced_first_restorer_fraction_given_any_partner_earlier_role = `
                (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $reporterEarlier -Denominator ([long]($N - 1) * $half))
            exact_reduced_first_restorer_fraction_given_any_partner_later_role = `
                (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $reporterLater -Denominator ([long]($N - 1) * $half))
        })
    }
    for ($g = 0; $g -lt $N - 1; $g++) {
        $parentHist = $histograms[$g]
        if ([long]$gapTotalsEarlier[$g] -ne [long]$parentHist.by_earlier_endpoint -or
            [long]$gapTotalsLater[$g] -ne [long]$parentHist.by_later_endpoint) {
            throw 'Code Sequence reporter partner matrix contradicts EC-089 independent global gap role FIRST totals.'
        }
    }
    $globalSix = $PairReciprocity.original_global_six_first_support_categories
    if ($firstEarlierGlobal -ne [long]$ReporterRoleExposure.first_restored_by_all_original_earlier_endpoint_roles -or
        $firstLaterGlobal -ne [long]$ReporterRoleExposure.first_restored_by_all_original_later_endpoint_roles -or
        $firstEarlierGlobal -ne [long]$globalSix.by_first -or
        $firstLaterGlobal -ne [long]$globalSix.by_second) {
        throw 'Code Sequence reporter partner matrix contradicts EC-074/076-backed ORIGINAL global FIRST ledger.'
    }

    return [ordered]@{
        original_positions_in_partner_universe = $N
        exact_unordered_original_pair_count = $pairCount
        exact_directed_original_report_partner_count = $N * ($N - 1)
        total_distinct_full_original_permutations = $full
        full_original_selection_has_saved_witness_support = [bool]$PairReciprocity.full_original_selection_has_saved_witness_support
        original_reporter_partner_endpoint_profiles = $profiles.ToArray()
        first_restored_by_all_original_earlier_endpoint_roles = $firstEarlierGlobal
        first_restored_by_all_original_later_endpoint_roles = $firstLaterGlobal
        every_original_report_partner_is_both_direction_complete_and_symmetric = $true
        every_partner_gap_first_restorer_is_within_its_direction_denominator = $true
        every_reporter_partner_gap_and_all_gap_matches_ec090_role_exposure = $true
        all_partner_first_restorer_identity_totals_match_ec089_and_ec074_via_ec090 = $true
        outside_interval_and_intervening_first_restorer_are_not_assigned_to_endpoints = $true
        no_new_evidence_source_mask_enumeration_git_network_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionReporterPartner {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionPairReciprocity,
        [object] $RetentionReporterRoleExposure
    )

    if ($null -eq $RetentionPivotality -or $null -eq $RetentionPairReciprocity -or
        $null -eq $RetentionReporterRoleExposure -or
        -not [bool]$RetentionPairReciprocity.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairReciprocity.only_consumed_checked_ec088_and_independent_ec076_original_projections -or
        -not [bool]$RetentionPairReciprocity.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionReporterRoleExposure.only_consumed_checked_ec089_original_pair_reciprocity -or
        -not [bool]$RetentionReporterRoleExposure.original_ec071_caller_bits_and_family_targets_unchanged -or
        -not [bool]$RetentionReporterRoleExposure.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionReporterRoleExposure.outside_interval_first_restorer_identity_not_attributed -or
        -not [bool]$RetentionReporterRoleExposure.no_new_saved_evidence_source_git_network_or_business_write) {
        throw 'Code Sequence reporter partner matrix requires unchanged successful EC-049 original selector and checked EC-089/090 outputs.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionPairReciprocity.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionReporterRoleExposure.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairReciprocity.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionReporterRoleExposure.counts.original_maximal_repeat_family_count -ne $familyCount) {
        throw 'Code Sequence reporter partner matrix received mismatched ORIGINAL target dimensions.'
    }
    foreach ($parent in @($RetentionPairReciprocity, $RetentionReporterRoleExposure)) {
        if ([int]$parent.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$parent.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$parent.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$parent.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence reporter partner matrix changed the selected ORIGINAL path or anchor.'
        }
    }
    $gPairs = [object[]]$RetentionPairReciprocity.genuine_global_threshold_pair_reciprocity
    $fPairs = [object[]]$RetentionPairReciprocity.frozen_global_threshold_pair_reciprocity
    $gRoles = [object[]]$RetentionReporterRoleExposure.genuine_global_threshold_reporter_role_exposure
    $fRoles = [object[]]$RetentionReporterRoleExposure.frozen_global_threshold_reporter_role_exposure
    $pairFamilies = [object[]]$RetentionPairReciprocity.individual_original_family_pair_reciprocity
    $roleFamilies = [object[]]$RetentionReporterRoleExposure.individual_original_family_reporter_role_exposure
    if ($gPairs.Count -ne 3 -or $fPairs.Count -ne 3 -or
        $gRoles.Count -ne 3 -or $fRoles.Count -ne 3 -or
        $pairFamilies.Count -ne $familyCount -or $roleFamilies.Count -ne $familyCount) {
        throw 'Code Sequence reporter partner matrix lost genuine/frozen global thresholds or original family targets.'
    }
    $gOut = [System.Collections.Generic.List[object]]::new()
    $fOut = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $pairSources = if ($mode -eq 0) { $gPairs } else { $fPairs }
        $roleSources = if ($mode -eq 0) { $gRoles } else { $fRoles }
        $target = if ($mode -eq 0) { $gOut } else { $fOut }
        for ($i = 0; $i -lt 3; $i++) {
            $threshold = 3 - $i
            if ([int]$pairSources[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$roleSources[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$pairSources[$i].original_full_selection_global_family_capacity -ne
                    [int]$roleSources[$i].original_full_selection_global_family_capacity) {
                throw 'Code Sequence reporter partner matrix changed a genuine/frozen threshold or capacity.'
            }
            $projection = Get-CodeSequenceRetentionReporterPartnerProjection `
                -PairReciprocity $pairSources[$i].exact_first_support_pair_reciprocity `
                -ReporterRoleExposure $roleSources[$i].exact_original_reporter_role_exposure -N $n
            $target.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = [int]$pairSources[$i].original_full_selection_global_family_capacity
                exact_original_reporter_partner_endpoint_matrix = $projection
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        if ([int]$pairFamilies[$i].original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$roleFamilies[$i].original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence reporter partner matrix changed an original maximal-repeat family index.'
        }
        $g = Get-CodeSequenceRetentionReporterPartnerProjection `
            -PairReciprocity $pairFamilies[$i].genuine_original_first_support_pair_reciprocity `
            -ReporterRoleExposure $roleFamilies[$i].genuine_original_reporter_role_exposure -N $n
        $f = Get-CodeSequenceRetentionReporterPartnerProjection `
            -PairReciprocity $pairFamilies[$i].frozen_original_first_support_pair_reciprocity `
            -ReporterRoleExposure $roleFamilies[$i].frozen_original_reporter_role_exposure -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_reporter_partner_endpoint_matrix = $g
            frozen_original_reporter_partner_endpoint_matrix = $f
        })
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_reporter_partner_endpoint_first_restoration_matrix'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_reporter_partner_directed_cells_per_target = $n * ($n - 1)
            exact_original_unordered_pair_count_per_target = [int]($n * ($n - 1) / 2)
            gap_cases_per_directed_reporter_partner_cell = $n - 1
            hypothetical_full_original_orderings_per_unordered_pair = [long]$factorials[$n]
            genuine_original_global_thresholds = $gOut.Count
            frozen_original_global_thresholds = $fOut.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_reporter_partner_endpoint_matrix = $gOut.ToArray()
        frozen_global_threshold_reporter_partner_endpoint_matrix = $fOut.ToArray()
        individual_original_family_reporter_partner_endpoint_matrix = $families.ToArray()
        only_consumed_checked_ec089_and_ec090_public_original_projections = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        outside_interval_first_restorer_identity_remains_unattributed = $true
        exact_role_fractions_are_not_empirical_probabilities_or_chronology = $true
        no_new_evidence_read_reoptimization_git_network_or_business_write = $true
    }
}

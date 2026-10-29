#requires -Version 7.0
<#
    EC-089: An ORIGINAL unordered report-pair reciprocity view.

    Fold the checked EC-088 p-before-q and q-before-p distance spectra into
    disjoint, identity-preserving unordered pair universes. Each original
    permutation belongs to exactly one direction for each unordered pair;
    neither the pair nor its gaps represent authenticated time. Report exact
    directional first-by-later contrasts, endpoint-identity attribution,
    and strictly-intervening original-caller-position attribution.

    Only prevalidated EC-088 and independent EC-076 public projections are
    consumed. No saved-evidence read, new mask/order enumeration, or I/O.
#>

function Get-CodeSequenceRetentionPairReciprocityReducedFraction {
    param([long] $Numerator, [long] $Denominator)
    if ($Denominator -le 0) {
        throw 'Code Sequence pair reciprocity requires a positive exact denominator.'
    }
    $magnitude = if ($Numerator -lt 0) { -$Numerator } else { $Numerator }
    $divisor = Get-CodeSequenceRetentionOrderGcd -A $magnitude -B $Denominator
    if ($divisor -le 0) {
        throw 'Code Sequence pair reciprocity failed exact fraction reduction.'
    }
    return [ordered]@{
        numerator = [long]($Numerator / $divisor)
        denominator = [long]($Denominator / $divisor)
    }
}

function Get-CodeSequenceRetentionPairReciprocityProjection {
    param(
        [object] $DistanceSpectrum,
        [object] $PairPrecedence,
        [int] $N
    )

    $sixNames = [string[]]@('before_first', 'by_first', 'first_restored_between',
        'by_second', 'after_second', 'never')
    $precedenceNames = [string[]]@(
        'full_permutations_first_restoring_before_first_report',
        'full_permutations_first_restored_by_first_report',
        'full_permutations_first_restoring_strictly_between_reports',
        'full_permutations_first_restored_by_second_report',
        'full_permutations_first_restoring_after_second_report',
        'full_permutations_never_restoring_saved_evidence'
    )
    $spectrumPrecedenceNames = [string[]]@(
        'full_precedence_first_restoring_before_first_report',
        'full_precedence_first_restored_by_first_report',
        'full_precedence_first_restoring_between_reports',
        'full_precedence_first_restored_by_second_report',
        'full_precedence_first_restoring_after_second_report',
        'full_precedence_never_restoring_saved_evidence'
    )
    if ($N -lt 2 -or $N -gt 12 -or $null -eq $DistanceSpectrum -or
        $null -eq $PairPrecedence -or
        -not [bool]$DistanceSpectrum.every_original_directed_pair_gap_spectrum_partitions_ec076_precedence -or
        -not [bool]$DistanceSpectrum.all_original_middle_identity_attributions_preserve_caller_bits -or
        -not [bool]$DistanceSpectrum.every_distance_histogram_reconciles_independent_ec074_gap_ledger -or
        -not [bool]$DistanceSpectrum.all_six_global_precedence_categories_reconcile_independent_ec074_and_ec076 -or
        -not [bool]$PairPrecedence.every_ordered_report_pair_has_six_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairPrecedence.all_six_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence pair reciprocity requires complete checked EC-088 / independent EC-076 originals.'
    }

    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorial[$N]
    $half = [long]($full / 2)
    $pairCount = [int]($N * ($N - 1) / 2)
    $directedCount = 2 * $pairCount
    $distanceRows = [object[]]$DistanceSpectrum.directed_original_report_pair_distance_spectra
    $precedenceRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    $sourceHistogram = [object[]]$DistanceSpectrum.original_distance_histogram_across_all_directed_pairs
    if ($distanceRows.Count -ne $directedCount -or $precedenceRows.Count -ne $directedCount -or
        $sourceHistogram.Count -ne $N - 1 -or
        [int]$DistanceSpectrum.original_positions_in_distance_spectrum_universe -ne $N -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [long]$DistanceSpectrum.total_distinct_full_original_permutations -ne $full -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $full -or
        [long]$DistanceSpectrum.exactly_half_the_original_orderings_per_directed_pair -ne $half -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $half -or
        [bool]$DistanceSpectrum.full_original_selection_has_saved_witness_support -ne
            [bool]$PairPrecedence.full_original_selection_has_saved_witness_support) {
        throw 'Code Sequence pair reciprocity received a mismatched ORIGINAL precedence universe.'
    }

    $gapTotals = [object[]]::new($N - 1)
    $gapOriginalEndpointFirst = [object[]]::new($N - 1)
    $gapOriginalEndpointSecond = [object[]]::new($N - 1)
    $gapOriginalMiddle = [object[]]::new($N - 1)
    for ($g = 0; $g -lt $N - 1; $g++) {
        $gapTotals[$g] = [long[]]::new(6)
        $gapOriginalEndpointFirst[$g] = [long[]]::new($N)
        $gapOriginalEndpointSecond[$g] = [long[]]::new($N)
        $gapOriginalMiddle[$g] = [long[]]::new($N)
    }
    $globalTotals = [long[]]::new(6)
    $identityByEndpointFirst = [long[]]::new($N)
    $identityByEndpointSecond = [long[]]::new($N)
    $identityByMiddle = [long[]]::new($N)
    $unordered = [System.Collections.Generic.List[object]]::new()

    # Each original unordered a/b (a<b in caller positions) covers all N!
    # hypothetical complete orders: a->b and b->a are disjoint halves.
    for ($a = 0; $a -lt $N; $a++) {
        for ($b = $a + 1; $b -lt $N; $b++) {
            $forwardIndex = $a * ($N - 1) + ($b - 1)
            $reverseIndex = $b * ($N - 1) + $a
            $forward = $distanceRows[$forwardIndex]
            $reverse = $distanceRows[$reverseIndex]
            $forwardParent = $precedenceRows[$forwardIndex]
            $reverseParent = $precedenceRows[$reverseIndex]
            $aBit = 1 -shl $a
            $bBit = 1 -shl $b
            if ($null -eq $forward -or $null -eq $reverse -or
                [int]$forward.first_original_caller_position -ne $a + 1 -or
                [int]$forward.second_original_caller_position -ne $b + 1 -or
                [int]$reverse.first_original_caller_position -ne $b + 1 -or
                [int]$reverse.second_original_caller_position -ne $a + 1 -or
                [int]$forward.first_original_position_bit -ne $aBit -or
                [int]$forward.second_original_position_bit -ne $bBit -or
                [int]$reverse.first_original_position_bit -ne $bBit -or
                [int]$reverse.second_original_position_bit -ne $aBit -or
                [long]$forward.exact_orderings_with_first_report_before_second -ne $half -or
                [long]$reverse.exact_orderings_with_first_report_before_second -ne $half) {
                throw 'Code Sequence pair reciprocity lost an ORIGINAL caller identity in reciprocal directions.'
            }
            $pairStages = [long[]]::new(6)
            $parentStages = [long[]]::new(6)
            for ($stage = 0; $stage -lt 6; $stage++) {
                $sourceName = $precedenceNames[$stage]
                $fName = $spectrumPrecedenceNames[$stage]
                if ([long]$forward.$fName -ne [long]$forwardParent.$sourceName -or
                    [long]$reverse.$fName -ne [long]$reverseParent.$sourceName -or
                    [int]$forwardParent.first_original_caller_position -ne $a + 1 -or
                    [int]$forwardParent.second_original_caller_position -ne $b + 1 -or
                    [int]$reverseParent.first_original_caller_position -ne $b + 1 -or
                    [int]$reverseParent.second_original_caller_position -ne $a + 1 -or
                    [int]$forwardParent.first_original_position_bit -ne $aBit -or
                    [int]$forwardParent.second_original_position_bit -ne $bBit -or
                    [int]$reverseParent.first_original_position_bit -ne $bBit -or
                    [int]$reverseParent.second_original_position_bit -ne $aBit) {
                    throw 'Code Sequence pair reciprocity contradicts independent EC-076 original precedence.'
                }
                $parentStages[$stage] = [long]$forwardParent.$sourceName + [long]$reverseParent.$sourceName
            }

            $forwardCases = [object[]]$forward.exact_distance_cases
            $reverseCases = [object[]]$reverse.exact_distance_cases
            if ($forwardCases.Count -ne $N - 1 -or $reverseCases.Count -ne $N - 1) {
                throw 'Code Sequence pair reciprocity lost an eligible ORIGINAL distance.'
            }
            $byA = [long]0
            $byB = [long]0
            $pairMiddleByOriginal = [long[]]::new($N)
            $pairGapRows = [System.Collections.Generic.List[object]]::new()
            for ($g = 0; $g -lt $N - 1; $g++) {
                $fc = $forwardCases[$g]
                $rc = $reverseCases[$g]
                $d = [long]($N - $g - 1) * [long]$factorial[$N - 2]
                if ([int]$fc.number_of_original_reports_strictly_between_pair -ne $g -or
                    [int]$rc.number_of_original_reports_strictly_between_pair -ne $g -or
                    [long]$fc.exact_full_orderings_with_this_directed_gap -ne $d -or
                    [long]$rc.exact_full_orderings_with_this_directed_gap -ne $d) {
                    throw 'Code Sequence pair reciprocity received unequal or misplaced reciprocal gap universes.'
                }
                $forwardMass = [long]0
                $reverseMass = [long]0
                for ($stage = 0; $stage -lt 6; $stage++) {
                    $sourceName = $sixNames[$stage]
                    $fv = [long]$fc.$sourceName
                    $rv = [long]$rc.$sourceName
                    if ($fv -lt 0 -or $rv -lt 0) {
                        throw 'Code Sequence pair reciprocity received negative ORIGINAL FIRST evidence.'
                    }
                    $forwardMass += $fv
                    $reverseMass += $rv
                    $pairStages[$stage] += $fv + $rv
                    $gapTotals[$g][$stage] += $fv + $rv
                    $globalTotals[$stage] += $fv + $rv
                }
                if ($forwardMass -ne $d -or $reverseMass -ne $d) {
                    throw 'Code Sequence pair reciprocity lost its two disjoint exact gap halves.'
                }
                $forwardMiddle = [long[]]$fc.first_restored_between_by_original_caller_position
                $reverseMiddle = [long[]]$rc.first_restored_between_by_original_caller_position
                if ($forwardMiddle.Count -ne $N -or $reverseMiddle.Count -ne $N) {
                    throw 'Code Sequence pair reciprocity lost an ORIGINAL intermediary identity vector.'
                }
                $middle = [long[]]::new($N)
                $totalMiddle = [long]0
                for ($k = 0; $k -lt $N; $k++) {
                    $fValue = [long]$forwardMiddle[$k]
                    $rValue = [long]$reverseMiddle[$k]
                    if ($fValue -lt 0 -or $rValue -lt 0 -or
                        (($k -eq $a -or $k -eq $b) -and ($fValue -ne 0 -or $rValue -ne 0))) {
                        throw 'Code Sequence pair reciprocity credited an endpoint as an ORIGINAL intermediary.'
                    }
                    $middle[$k] = $fValue + $rValue
                    $totalMiddle += $middle[$k]
                    $pairMiddleByOriginal[$k] += $middle[$k]
                    $gapOriginalMiddle[$g][$k] += $middle[$k]
                    $identityByMiddle[$k] += $middle[$k]
                }
                if ($totalMiddle -ne [long]$fc.first_restored_between + [long]$rc.first_restored_between) {
                    throw 'Code Sequence pair reciprocity does not conserve real ORIGINAL intermediary attributions.'
                }
                $aRestored = [long]$fc.by_first + [long]$rc.by_second
                $bRestored = [long]$rc.by_first + [long]$fc.by_second
                $gapOriginalEndpointFirst[$g][$a] += [long]$fc.by_first
                $gapOriginalEndpointFirst[$g][$b] += [long]$rc.by_first
                $gapOriginalEndpointSecond[$g][$a] += [long]$rc.by_second
                $gapOriginalEndpointSecond[$g][$b] += [long]$fc.by_second
                $identityByEndpointFirst[$a] += [long]$fc.by_first
                $identityByEndpointFirst[$b] += [long]$rc.by_first
                $identityByEndpointSecond[$a] += [long]$rc.by_second
                $identityByEndpointSecond[$b] += [long]$fc.by_second
                $byA += $aRestored
                $byB += $bRestored
                $lateDelta = [long]$fc.by_second - [long]$rc.by_second
                $pairGapRows.Add([ordered]@{
                    number_of_original_reports_strictly_between_pair = $g
                    exact_full_original_orderings_with_either_endpoint_direction = 2 * $d
                    exact_full_original_orderings_per_endpoint_direction = $d
                    first_restoring_before_either_first_endpoint = [long]$fc.before_first + [long]$rc.before_first
                    first_restored_by_original_report_a = $aRestored
                    first_restored_by_original_report_b = $bRestored
                    first_restored_by_original_intervening_report = $totalMiddle
                    first_restoring_after_either_second_endpoint = [long]$fc.after_second + [long]$rc.after_second
                    never_restoring_saved_evidence = [long]$fc.never + [long]$rc.never
                    first_restored_by_intervening_original_caller_position = $middle
                    first_restored_when_later_in_a_before_b_direction = [long]$fc.by_second
                    first_restored_when_later_in_b_before_a_direction = [long]$rc.by_second
                    exact_signed_later_direction_contrast = $lateDelta
                    exact_reduced_signed_later_direction_contrast_fraction = `
                        (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $lateDelta -Denominator $d)
                    exact_reduced_either_original_endpoint_first_restorer_fraction = `
                        (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($aRestored + $bRestored) -Denominator (2 * $d))
                })
            }
            $pairMass = [long]0
            for ($stage = 0; $stage -lt 6; $stage++) {
                $pairMass += $pairStages[$stage]
                if ($pairStages[$stage] -ne $parentStages[$stage]) {
                    throw 'Code Sequence pair reciprocity fails independent EC-076 two-direction FIRST conservation.'
                }
            }
            if ($pairMass -ne $full -or $pairGapRows.Count -ne $N - 1 -or
                $byA + $byB -ne $pairStages[1] + $pairStages[3]) {
                throw 'Code Sequence pair reciprocity failed the full N! unordered pair partition.'
            }
            $sumPairMiddle = [long]0
            foreach ($value in $pairMiddleByOriginal) { $sumPairMiddle += $value }
            if ($sumPairMiddle -ne $pairStages[2] -or
                $pairMiddleByOriginal[$a] -ne 0 -or $pairMiddleByOriginal[$b] -ne 0) {
                throw 'Code Sequence pair reciprocity altered ORIGINAL cross-gap middle identities.'
            }
            $unordered.Add([ordered]@{
                original_report_a_caller_position = $a + 1
                original_report_b_caller_position = $b + 1
                original_report_a_position_bit = $aBit
                original_report_b_position_bit = $bBit
                exact_full_original_orderings_with_either_endpoint_direction = $full
                distance_cases = $pairGapRows.ToArray()
                full_pair_first_restoring_before_first_endpoint = $pairStages[0]
                full_pair_first_restored_by_earlier_endpoint = $pairStages[1]
                full_pair_first_restored_between_endpoints = $pairStages[2]
                full_pair_first_restored_by_later_endpoint = $pairStages[3]
                full_pair_first_restoring_after_later_endpoint = $pairStages[4]
                full_pair_never_restoring_saved_evidence = $pairStages[5]
                full_pair_first_restored_by_original_report_a = $byA
                full_pair_first_restored_by_original_report_b = $byB
                full_pair_first_restored_by_intervening_original_caller_position = $pairMiddleByOriginal
                exact_reduced_any_endpoint_first_restorer_fraction = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($byA + $byB) -Denominator $full)
            })
        }
    }
    if ($unordered.Count -ne $pairCount) {
        throw 'Code Sequence pair reciprocity omitted an ORIGINAL unordered pair.'
    }

    $histogram = [System.Collections.Generic.List[object]]::new()
    for ($g = 0; $g -lt $N - 1; $g++) {
        $source = $sourceHistogram[$g]
        $expected = [long]($N - $g - 1) * $full
        if ([int]$source.number_of_original_reports_strictly_between_pair -ne $g -or
            [long]$source.exact_directed_pair_occurrences_across_all_original_permutations -ne $expected) {
            throw 'Code Sequence pair reciprocity received an invalid independent EC-074 distance histogram.'
        }
        $sum = [long]0
        for ($stage = 0; $stage -lt 6; $stage++) {
            $sum += $gapTotals[$g][$stage]
            if ($gapTotals[$g][$stage] -ne [long]$source.($sixNames[$stage])) {
                throw 'Code Sequence pair reciprocity fails EC-088/074 gap FIRST conservation.'
            }
        }
        if ($sum -ne $expected) {
            throw 'Code Sequence pair reciprocity fails the (N-g-1)*N! gap incidence.'
        }
        $firstSum = [long]0
        $laterSum = [long]0
        $middleSum = [long]0
        for ($k = 0; $k -lt $N; $k++) {
            $firstSum += $gapOriginalEndpointFirst[$g][$k]
            $laterSum += $gapOriginalEndpointSecond[$g][$k]
            $middleSum += $gapOriginalMiddle[$g][$k]
        }
        if ($firstSum -ne $gapTotals[$g][1] -or
            $laterSum -ne $gapTotals[$g][3] -or
            $middleSum -ne $gapTotals[$g][2]) {
            throw 'Code Sequence pair reciprocity fails ORIGINAL endpoint/middle identity conservation.'
        }
        $histogram.Add([ordered]@{
            number_of_original_reports_strictly_between_pair = $g
            exact_pair_occurrences_across_all_original_permutations = $expected
            before_first_endpoint = $gapTotals[$g][0]
            by_earlier_endpoint = $gapTotals[$g][1]
            by_intervening_original_report = $gapTotals[$g][2]
            by_later_endpoint = $gapTotals[$g][3]
            after_later_endpoint = $gapTotals[$g][4]
            never = $gapTotals[$g][5]
            by_original_caller_position_as_earlier_endpoint = $gapOriginalEndpointFirst[$g]
            by_original_caller_position_as_later_endpoint = $gapOriginalEndpointSecond[$g]
            by_original_caller_position_as_intervening_report = $gapOriginalMiddle[$g]
        })
    }
    $independent = $PairPrecedence.independent_ec074_first_support_step_pair_precedence_ledger
    $globalSource = $DistanceSpectrum.total_first_restoration_by_six_precedence_categories
    $allMass = [long]0
    for ($stage = 0; $stage -lt 6; $stage++) {
        $value = $globalTotals[$stage]
        $allMass += $value
        if ($value -ne [long]$globalSource.($sixNames[$stage]) -or
            $value -ne [long]$independent.($precedenceNames[$stage])) {
            throw 'Code Sequence pair reciprocity contradicts the EC-074/076/088 global FIRST ledger.'
        }
    }
    $totalIncidence = [long]$pairCount * $full
    if ($allMass -ne $totalIncidence -or
        [long]$independent.expected_total_combinations_across_all_hypothetical_original_orderings -ne $totalIncidence) {
        throw 'Code Sequence pair reciprocity does not partition all unordered original pairs.'
    }
    $sumEarliest = [long]0
    $sumLater = [long]0
    $sumMiddle = [long]0
    $restorerByOriginalPosition = [long[]]::new($N)
    for ($k = 0; $k -lt $N; $k++) {
        $sumEarliest += $identityByEndpointFirst[$k]
        $sumLater += $identityByEndpointSecond[$k]
        $sumMiddle += $identityByMiddle[$k]
        $restorerByOriginalPosition[$k] = (
            $identityByEndpointFirst[$k] + $identityByEndpointSecond[$k] + $identityByMiddle[$k]
        )
    }
    if ($sumEarliest -ne $globalTotals[1] -or $sumLater -ne $globalTotals[3] -or
        $sumMiddle -ne $globalTotals[2]) {
        throw 'Code Sequence pair reciprocity lost ORIGINAL FIRST-restorer identity totals.'
    }

    return [ordered]@{
        original_positions_in_reciprocity_universe = $N
        total_distinct_full_original_permutations = $full
        exact_unordered_original_pair_count = $pairCount
        exact_full_orderings_per_unordered_original_pair = $full
        full_original_selection_has_saved_witness_support = [bool]$PairPrecedence.full_original_selection_has_saved_witness_support
        unordered_original_report_pair_reciprocities = $unordered.ToArray()
        distance_histogram_across_unordered_original_pairs = $histogram.ToArray()
        first_restored_by_original_caller_position_as_earlier_endpoint = $identityByEndpointFirst
        first_restored_by_original_caller_position_as_later_endpoint = $identityByEndpointSecond
        first_restored_by_original_caller_position_as_intervening_report = $identityByMiddle
        first_restored_by_original_caller_position_inside_pair_interval = $restorerByOriginalPosition
        original_global_six_first_support_categories = [ordered]@{
            before_first = $globalTotals[0]
            by_first = $globalTotals[1]
            first_restored_between = $globalTotals[2]
            by_second = $globalTotals[3]
            after_second = $globalTotals[4]
            never = $globalTotals[5]
        }
        every_unordered_pair_has_both_disjoint_original_precedence_directions = $true
        every_bidirectional_gap_reconciles_independent_ec074_via_ec088 = $true
        every_original_endpoint_and_intermediary_identity_mass_is_conserved = $true
        all_six_global_first_support_categories_match_independent_ec074_and_ec076 = $true
        original_directional_contrasts_are_exact_not_probabilistic_or_chronological = $true
        no_new_saved_record_evidence_or_external_access = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairReciprocity {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairDistanceSpectrum
    )

    if ($null -eq $RetentionPivotality -or $null -eq $RetentionPairPrecedence -or
        $null -eq $RetentionPairDistanceSpectrum -or
        -not [bool]$RetentionPairDistanceSpectrum.only_consumed_checked_ec076_to_ec087_original_projection_outputs -or
        -not [bool]$RetentionPairDistanceSpectrum.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairDistanceSpectrum.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairDistanceSpectrum.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairDistanceSpectrum.no_saved_quote_body_patch_git_network_or_business_source_access -or
        -not [bool]$RetentionPairPrecedence.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairPrecedence.no_new_selector_or_original_evidence_read_and_no_reoptimization) {
        throw 'Code Sequence pair reciprocity needs the checked successful EC-049 selector and EC-088 materialization.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionPairDistanceSpectrum.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairDistanceSpectrum.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairPrecedence.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
        [int]$RetentionPairPrecedence.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
        [int]$RetentionPairPrecedence.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
        [string]$RetentionPairPrecedence.path -cne [string]$RetentionPivotality.path -or
        [int]$RetentionPairDistanceSpectrum.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
        [int]$RetentionPairDistanceSpectrum.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
        [int]$RetentionPairDistanceSpectrum.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
        [string]$RetentionPairDistanceSpectrum.path -cne [string]$RetentionPivotality.path) {
        throw 'Code Sequence pair reciprocity changed the ORIGINAL pair target registry or selected path.'
    }
    $gSpectrum = [object[]]$RetentionPairDistanceSpectrum.genuine_global_threshold_pair_distance_spectrum
    $fSpectrum = [object[]]$RetentionPairDistanceSpectrum.frozen_global_threshold_pair_distance_spectrum
    $familySpectrum = [object[]]$RetentionPairDistanceSpectrum.individual_original_family_pair_distance_spectrum
    $gPrecedence = [object[]]$RetentionPairPrecedence.genuine_global_threshold_pair_precedence
    $fPrecedence = [object[]]$RetentionPairPrecedence.frozen_global_threshold_pair_precedence
    $familyPrecedence = [object[]]$RetentionPairPrecedence.individual_original_family_pair_precedence
    if ($gSpectrum.Count -ne 3 -or $fSpectrum.Count -ne 3 -or
        $gPrecedence.Count -ne 3 -or $fPrecedence.Count -ne 3 -or
        $familySpectrum.Count -ne $familyCount -or $familyPrecedence.Count -ne $familyCount) {
        throw 'Code Sequence pair reciprocity lost genuine/frozen original threshold or family targets.'
    }
    $genuine = [System.Collections.Generic.List[object]]::new()
    $frozen = [System.Collections.Generic.List[object]]::new()
    for ($kind = 0; $kind -lt 2; $kind++) {
        $source = if ($kind -eq 0) { $gSpectrum } else { $fSpectrum }
        $parent = if ($kind -eq 0) { $gPrecedence } else { $fPrecedence }
        $sink = if ($kind -eq 0) { $genuine } else { $frozen }
        for ($i = 0; $i -lt 3; $i++) {
            $threshold = 3 - $i
            if ([int]$source[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$parent[$i].original_global_family_capacity_at_least -ne $threshold -or
                [int]$source[$i].original_full_selection_global_family_capacity -ne
                    [int]$parent[$i].original_full_selection_global_family_capacity) {
                throw 'Code Sequence pair reciprocity changed an ORIGINAL genuine/frozen threshold.'
            }
            $projection = Get-CodeSequenceRetentionPairReciprocityProjection `
                -DistanceSpectrum $source[$i].exact_first_support_pair_distance_spectrum `
                -PairPrecedence $parent[$i].exact_first_support_pair_precedence -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = [int]$source[$i].original_full_selection_global_family_capacity
                exact_first_support_pair_reciprocity = $projection
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        if ([int]$familySpectrum[$i].original_maximal_repeat_family_index -ne $i + 1 -or
            [int]$familyPrecedence[$i].original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence pair reciprocity reindexed an ORIGINAL repeat family.'
        }
        $g = Get-CodeSequenceRetentionPairReciprocityProjection `
            -DistanceSpectrum $familySpectrum[$i].genuine_original_first_support_pair_distance_spectrum `
            -PairPrecedence $familyPrecedence[$i].genuine_original_first_support_pair_precedence -N $n
        $f = Get-CodeSequenceRetentionPairReciprocityProjection `
            -DistanceSpectrum $familySpectrum[$i].frozen_original_first_support_pair_distance_spectrum `
            -PairPrecedence $familyPrecedence[$i].frozen_original_first_support_pair_precedence -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_first_support_pair_reciprocity = $g
            frozen_original_first_support_pair_reciprocity = $f
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_unordered_report_pair_bidirectional_first_support_reciprocity'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            unordered_original_report_pairs_per_target = [int]($n * ($n - 1) / 2)
            exact_full_original_orderings_per_unordered_pair = [long]$factorial[$n]
            exact_unordered_pair_occurrences_across_all_full_original_permutations = `
                [long]($n * ($n - 1) / 2) * [long]$factorial[$n]
            eligible_distances_per_unordered_pair = $n - 1
            genuine_original_global_thresholds = $genuine.Count
            frozen_original_global_thresholds = $frozen.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_pair_reciprocity = $genuine.ToArray()
        frozen_global_threshold_pair_reciprocity = $frozen.ToArray()
        individual_original_family_pair_reciprocity = $families.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        only_consumed_checked_ec088_and_independent_ec076_original_projections = $true
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        original_directional_contrasts_are_hypothetical_not_observed_chronology = $true
        exact_incidence_fractions_are_not_empirical_probability_defect_priority_or_causal_repair = $true
    }
}

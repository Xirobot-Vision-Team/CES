#requires -Version 7.0
<#
    EC-090: Exact ORIGINAL reporter role/exposure/first-restorer atlas.

    A caller-position ORIGINAL report can be an earlier endpoint, later
    endpoint, strictly intervening nonendpoint, or outside the pair interval.
    Pair orientation is hypothetical, never authenticated chronology.
    All role exposure denominators are exact uniform *complete ordering*
    incidences. A first-restorer identity is available only for the first
    three roles in checked EC-089; do not invent an outside first-restorer.

    Consume only checked EC-089 public reciprocity projections. Do not read
    records, saved evidence, Git, network, business source, or recompute masks.
#>

function Get-CodeSequenceRetentionReporterRoleExposureProjection {
    param(
        [object] $PairReciprocity,
        [int] $N
    )

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $PairReciprocity -or
        -not [bool]$PairReciprocity.every_unordered_pair_has_both_disjoint_original_precedence_directions -or
        -not [bool]$PairReciprocity.every_bidirectional_gap_reconciles_independent_ec074_via_ec088 -or
        -not [bool]$PairReciprocity.every_original_endpoint_and_intermediary_identity_mass_is_conserved -or
        -not [bool]$PairReciprocity.all_six_global_first_support_categories_match_independent_ec074_and_ec076 -or
        -not [bool]$PairReciprocity.no_new_saved_record_evidence_or_external_access) {
        throw 'Code Sequence reporter role atlas requires completely checked EC-089 original reciprocity.'
    }

    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $N
    $full = [long]$factorials[$N]
    $half = [long]($full / 2)
    $pairCount = [int]($N * ($N - 1) / 2)
    $pairs = [object[]]$PairReciprocity.unordered_original_report_pair_reciprocities
    $histograms = [object[]]$PairReciprocity.distance_histogram_across_unordered_original_pairs
    if ([int]$PairReciprocity.original_positions_in_reciprocity_universe -ne $N -or
        [long]$PairReciprocity.total_distinct_full_original_permutations -ne $full -or
        [int]$PairReciprocity.exact_unordered_original_pair_count -ne $pairCount -or
        [long]$PairReciprocity.exact_full_orderings_per_unordered_original_pair -ne $full -or
        $pairs.Count -ne $pairCount -or $histograms.Count -ne $N - 1) {
        throw 'Code Sequence reporter role atlas received an altered ORIGINAL permutation universe.'
    }

    # Independently roll up identity totals from the a/b/g case rows, not
    # from the parent original-identity histograms alone. The pair rows
    # expose endpoint identity (a or b) but not which role that endpoint
    # occupied in the corresponding direction. EC-089 gap vectors supply
    # that split and must reconcile to these separately added totals.
    $endpointByGap = [object[]]::new($N - 1)
    $middleByGap = [object[]]::new($N - 1)
    $stageByGap = [object[]]::new($N - 1)
    for ($g = 0; $g -lt $N - 1; $g++) {
        $endpointByGap[$g] = [long[]]::new($N)
        $middleByGap[$g] = [long[]]::new($N)
        $stageByGap[$g] = [long[]]::new(6)
    }
    $pairAppearances = [int[]]::new($N)
    $index = 0
    for ($a = 0; $a -lt $N; $a++) {
        for ($b = $a + 1; $b -lt $N; $b++) {
            $pair = $pairs[$index]
            $index++
            if ($null -eq $pair -or
                [int]$pair.original_report_a_caller_position -ne $a + 1 -or
                [int]$pair.original_report_b_caller_position -ne $b + 1 -or
                [int]$pair.original_report_a_position_bit -ne (1 -shl $a) -or
                [int]$pair.original_report_b_position_bit -ne (1 -shl $b) -or
                [long]$pair.exact_full_original_orderings_with_either_endpoint_direction -ne $full) {
                throw 'Code Sequence reporter role atlas lost an ordered ORIGINAL unordered-pair identity.'
            }
            $pairAppearances[$a]++
            $pairAppearances[$b]++
            $cases = [object[]]$pair.distance_cases
            if ($cases.Count -ne $N - 1) {
                throw 'Code Sequence reporter role atlas received an ineligible or missing pair gap.'
            }
            $pairA = [long]0
            $pairB = [long]0
            $pairMiddle = [long[]]::new($N)
            $pairStages = [long[]]::new(6)
            for ($g = 0; $g -lt $N - 1; $g++) {
                $case = $cases[$g]
                $oneDirection = [long]($N - $g - 1) * [long]$factorials[$N - 2]
                $bothDirections = 2 * $oneDirection
                if ($null -eq $case -or
                    [int]$case.number_of_original_reports_strictly_between_pair -ne $g -or
                    [long]$case.exact_full_original_orderings_with_either_endpoint_direction -ne $bothDirections -or
                    [long]$case.exact_full_original_orderings_per_endpoint_direction -ne $oneDirection) {
                    throw 'Code Sequence reporter role atlas found an invalid complete gap denominator.'
                }
                $values = [long[]]@(
                    [long]$case.first_restoring_before_either_first_endpoint,
                    [long]$case.first_restored_by_original_report_a,
                    [long]$case.first_restored_by_original_intervening_report,
                    [long]$case.first_restored_by_original_report_b,
                    [long]$case.first_restoring_after_either_second_endpoint,
                    [long]$case.never_restoring_saved_evidence
                )
                $mass = [long]0
                for ($stage = 0; $stage -lt 6; $stage++) {
                    if ($values[$stage] -lt 0) {
                        throw 'Code Sequence reporter role atlas received negative FIRST evidence.'
                    }
                    $mass += $values[$stage]
                    $pairStages[$stage] += $values[$stage]
                    $stageByGap[$g][$stage] += $values[$stage]
                }
                if ($mass -ne $bothDirections) {
                    throw 'Code Sequence reporter role atlas does not partition a reciprocal pair gap.'
                }
                $endpointByGap[$g][$a] += $values[1]
                $endpointByGap[$g][$b] += $values[3]
                $pairA += $values[1]
                $pairB += $values[3]
                $mid = [long[]]$case.first_restored_by_intervening_original_caller_position
                if ($mid.Count -ne $N -or $mid[$a] -ne 0 -or $mid[$b] -ne 0) {
                    throw 'Code Sequence reporter role atlas would attribute an endpoint as an intermediary.'
                }
                $midSum = [long]0
                for ($k = 0; $k -lt $N; $k++) {
                    if ($mid[$k] -lt 0) {
                        throw 'Code Sequence reporter role atlas received negative ORIGINAL intermediary evidence.'
                    }
                    $midSum += $mid[$k]
                    $middleByGap[$g][$k] += $mid[$k]
                    $pairMiddle[$k] += $mid[$k]
                }
                if ($midSum -ne $values[2]) {
                    throw 'Code Sequence reporter role atlas lost the ORIGINAL middle FIRST-restorer total.'
                }
            }
            $sourceStageNames = [string[]]@(
                'full_pair_first_restoring_before_first_endpoint',
                'full_pair_first_restored_by_earlier_endpoint',
                'full_pair_first_restored_between_endpoints',
                'full_pair_first_restored_by_later_endpoint',
                'full_pair_first_restoring_after_later_endpoint',
                'full_pair_never_restoring_saved_evidence'
            )
            if ($pairA -ne [long]$pair.full_pair_first_restored_by_original_report_a -or
                $pairB -ne [long]$pair.full_pair_first_restored_by_original_report_b -or
                $pairA + $pairB -ne $pairStages[1] + $pairStages[3]) {
                throw 'Code Sequence reporter role atlas changed an endpoint first-restorer identity.'
            }
            $sourceMiddle = [long[]]$pair.full_pair_first_restored_by_intervening_original_caller_position
            if ($sourceMiddle.Count -ne $N) {
                throw 'Code Sequence reporter role atlas lost a full-gap middle original identity vector.'
            }
            for ($k = 0; $k -lt $N; $k++) {
                if ($sourceMiddle[$k] -ne $pairMiddle[$k]) {
                    throw 'Code Sequence reporter role atlas changed a full-pair original intermediary.'
                }
            }
            for ($stage = 0; $stage -lt 6; $stage++) {
                if ($stage -eq 1 -or $stage -eq 3) { continue }
                if ($pairStages[$stage] -ne [long]$pair.($sourceStageNames[$stage])) {
                    throw 'Code Sequence reporter role atlas changed the full-pair FIRST partition.'
                }
            }
        }
    }
    if ($index -ne $pairCount) {
        throw 'Code Sequence reporter role atlas omitted unordered report pairs.'
    }
    foreach ($count in $pairAppearances) {
        if ($count -ne $N - 1) {
            throw 'Code Sequence reporter role atlas lost an ORIGINAL endpoint pairing.'
        }
    }

    $totalByGap = [object[]]::new($N - 1)
    $globalByRole = [long[]]::new(3)
    $gapRoleTotals = [object[]]::new($N - 1)
    for ($g = 0; $g -lt $N - 1; $g++) {
        $hist = $histograms[$g]
        $oneDirection = [long]($N - $g - 1) * [long]$factorials[$N - 2]
        $expected = [long]$pairCount * 2 * $oneDirection
        $earlier = [long[]]$hist.by_original_caller_position_as_earlier_endpoint
        $later = [long[]]$hist.by_original_caller_position_as_later_endpoint
        $middle = [long[]]$hist.by_original_caller_position_as_intervening_report
        if ($null -eq $hist -or
            [int]$hist.number_of_original_reports_strictly_between_pair -ne $g -or
            [long]$hist.exact_pair_occurrences_across_all_original_permutations -ne $expected -or
            $earlier.Count -ne $N -or $later.Count -ne $N -or $middle.Count -ne $N) {
            throw 'Code Sequence reporter role atlas requires exact EC-089 original gap role histograms.'
        }
        $sourceStage = [long[]]@(
            [long]$hist.before_first_endpoint, [long]$hist.by_earlier_endpoint,
            [long]$hist.by_intervening_original_report, [long]$hist.by_later_endpoint,
            [long]$hist.after_later_endpoint, [long]$hist.never
        )
        $mass = [long]0
        for ($stage = 0; $stage -lt 6; $stage++) {
            $mass += $stageByGap[$g][$stage]
            if ($stage -eq 1 -or $stage -eq 3) { continue }
            if ($stageByGap[$g][$stage] -ne $sourceStage[$stage]) {
                throw 'Code Sequence reporter role atlas contradicts independently checked EC-089 gap stages.'
            }
        }
        if ($mass -ne $expected -or $sourceStage[0] + $sourceStage[1] +
            $sourceStage[2] + $sourceStage[3] + $sourceStage[4] + $sourceStage[5] -ne $expected) {
            throw 'Code Sequence reporter role atlas lost a complete gap FIRST partition.'
        }
        $sums = [long[]]::new(3)
        for ($k = 0; $k -lt $N; $k++) {
            if ($earlier[$k] -lt 0 -or $later[$k] -lt 0 -or $middle[$k] -lt 0 -or
                $earlier[$k] + $later[$k] -ne $endpointByGap[$g][$k] -or
                $middle[$k] -ne $middleByGap[$g][$k]) {
                throw 'Code Sequence reporter role atlas fails independent pair-row original attribution.'
            }
            $sums[0] += $earlier[$k]
            $sums[1] += $later[$k]
            $sums[2] += $middle[$k]
        }
        if ($sums[0] -ne $sourceStage[1] -or $sums[1] -ne $sourceStage[3] -or
            $sums[2] -ne $sourceStage[2]) {
            throw 'Code Sequence reporter role atlas changed the six-category ORIGINAL FIRST ledger.'
        }
        for ($role = 0; $role -lt 3; $role++) { $globalByRole[$role] += $sums[$role] }
        $totalByGap[$g] = [ordered]@{
            earlier = $earlier; later = $later; middle = $middle
            full_gap_pair_incidence = $expected
        }
        $gapRoleTotals[$g] = [ordered]@{
            number_of_original_reports_strictly_between_pair = $g
            exact_full_original_unordered_pair_gap_incidences = $expected
            first_restored_by_any_original_earlier_endpoint = $sums[0]
            first_restored_by_any_original_later_endpoint = $sums[1]
            first_restored_by_any_original_intervening_report = $sums[2]
        }
    }

    $reporters = [System.Collections.Generic.List[object]]::new()
    $expectedEndpointGap = [long[]]::new($N - 1)
    $expectedInterveningGap = [long[]]::new($N - 1)
    $expectedOutsideGap = [long[]]::new($N - 1)
    $nonEndpointPairsPerReporter = [int](($N - 1) * ($N - 2) / 2)
    for ($g = 0; $g -lt $N - 1; $g++) {
        $oneDirection = [long]($N - $g - 1) * [long]$factorials[$N - 2]
        $expectedEndpointGap[$g] = [long]($N - 1) * $oneDirection
        if ($N -gt 2) {
            # A fixed nonendpoint reporter has g/(N-2) of the two-orientation
            # gap orders inside the endpoints and (N-2-g)/(N-2) outside.
            # Write the integer formula with (N-3)! to avoid rounding.
            $unit = 2 * [long]($N - $g - 1) * [long]$factorials[$N - 3]
            $expectedInterveningGap[$g] = [long]$nonEndpointPairsPerReporter * $g * $unit
            $expectedOutsideGap[$g] = [long]$nonEndpointPairsPerReporter * ($N - 2 - $g) * $unit
        }
        if (2 * $expectedEndpointGap[$g] + $expectedInterveningGap[$g] +
            $expectedOutsideGap[$g] -ne $totalByGap[$g].full_gap_pair_incidence) {
            throw 'Code Sequence reporter role atlas cannot conserve exact gap role exposure.'
        }
    }

    $globalIdentityNames = [string[]]@(
        'first_restored_by_original_caller_position_as_earlier_endpoint',
        'first_restored_by_original_caller_position_as_later_endpoint',
        'first_restored_by_original_caller_position_as_intervening_report'
    )
    $globalParents = [object[]]::new(3)
    for ($role = 0; $role -lt 3; $role++) {
        $globalParents[$role] = [long[]]$PairReciprocity.($globalIdentityNames[$role])
        if ($globalParents[$role].Count -ne $N) {
            throw 'Code Sequence reporter role atlas requires an N-slot EC-089 global original identity ledger.'
        }
    }
    $globalInterval = [long[]]$PairReciprocity.first_restored_by_original_caller_position_inside_pair_interval
    if ($globalInterval.Count -ne $N) {
        throw 'Code Sequence reporter role atlas lost the all-gap ORIGINAL first-restorer vector.'
    }

    $reporterByRole = [long[]]::new(3)
    $allGapFirst = [long]0
    for ($k = 0; $k -lt $N; $k++) {
        $rows = [System.Collections.Generic.List[object]]::new()
        $first = [long[]]::new(3)
        $exposed = [long[]]::new(4)
        for ($g = 0; $g -lt $N - 1; $g++) {
            $v = $totalByGap[$g]
            $restored = [long[]]@([long]$v.earlier[$k], [long]$v.later[$k], [long]$v.middle[$k])
            $denominators = [long[]]@(
                $expectedEndpointGap[$g], $expectedEndpointGap[$g],
                $expectedInterveningGap[$g], $expectedOutsideGap[$g]
            )
            for ($role = 0; $role -lt 3; $role++) {
                if ($restored[$role] -lt 0 -or $restored[$role] -gt $denominators[$role]) {
                    throw 'Code Sequence reporter role atlas credited more FIRST events than eligible role exposures.'
                }
                $first[$role] += $restored[$role]
            }
            for ($role = 0; $role -lt 4; $role++) { $exposed[$role] += $denominators[$role] }
            $intervalRestored = $restored[0] + $restored[1] + $restored[2]
            $intervalExposure = $denominators[0] + $denominators[1] + $denominators[2]
            $rows.Add([ordered]@{
                number_of_original_reports_strictly_between_pair = $g
                exact_full_unordered_pair_gap_incidence_for_reporter = [long]$v.full_gap_pair_incidence
                exact_role_exposure_as_earlier_endpoint = $denominators[0]
                exact_role_exposure_as_later_endpoint = $denominators[1]
                exact_role_exposure_as_strictly_intervening_report = $denominators[2]
                exact_role_exposure_outside_pair_interval = $denominators[3]
                first_restored_as_earlier_endpoint = $restored[0]
                first_restored_as_later_endpoint = $restored[1]
                first_restored_as_strictly_intervening_report = $restored[2]
                first_restored_inside_pair_interval = $intervalRestored
                exact_reduced_first_restorer_fraction_given_earlier_endpoint = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $restored[0] -Denominator $denominators[0])
                exact_reduced_first_restorer_fraction_given_later_endpoint = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $restored[1] -Denominator $denominators[1])
                # Middle is impossible at g=0 or N2: null, never a fake 0/1.
                exact_reduced_first_restorer_fraction_given_intervening_role = if ($denominators[2] -eq 0) { $null } else {
                    Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $restored[2] -Denominator $denominators[2]
                }
                exact_reduced_first_restorer_fraction_given_any_endpoint = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator ($restored[0] + $restored[1]) -Denominator (2 * $denominators[0]))
                exact_reduced_first_restorer_fraction_given_inside_pair_interval = `
                    (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $intervalRestored -Denominator $intervalExposure)
            })
        }
        for ($role = 0; $role -lt 3; $role++) {
            if ($first[$role] -ne $globalParents[$role][$k]) {
                throw 'Code Sequence reporter role atlas contradicts the EC-089 global report identity ledger.'
            }
            $reporterByRole[$role] += $first[$role]
        }
        $insideFirst = $first[0] + $first[1] + $first[2]
        if ($insideFirst -ne $globalInterval[$k] -or
            $exposed[0] -ne [long]($N - 1) * $half -or
            $exposed[1] -ne [long]($N - 1) * $half -or
            $exposed[0] + $exposed[1] + $exposed[2] + $exposed[3] -ne [long]$pairCount * $full) {
            throw 'Code Sequence reporter role atlas fails whole-order exposure or FIRST totals.'
        }
        if ($N -gt 2 -and (3 * $exposed[2] -ne [long]$nonEndpointPairsPerReporter * $full -or
            $exposed[3] -ne 2 * $exposed[2])) {
            throw 'Code Sequence reporter role atlas fails original nonendpoint 1/3 vs 2/3 exposure partition.'
        }
        $allGapFirst += $insideFirst
        $reporters.Add([ordered]@{
            original_report_caller_position = $k + 1
            original_report_position_bit = 1 -shl $k
            original_unordered_endpoint_partners = $N - 1
            original_unordered_nonendpoint_pairs = $nonEndpointPairsPerReporter
            distance_cases = $rows.ToArray()
            full_original_ordering_role_exposure_as_earlier_endpoint = $exposed[0]
            full_original_ordering_role_exposure_as_later_endpoint = $exposed[1]
            full_original_ordering_role_exposure_as_strictly_intervening_report = $exposed[2]
            full_original_ordering_role_exposure_outside_pair_interval = $exposed[3]
            first_restored_as_earlier_endpoint_across_all_gaps = $first[0]
            first_restored_as_later_endpoint_across_all_gaps = $first[1]
            first_restored_as_intervening_report_across_all_gaps = $first[2]
            first_restored_inside_pair_interval_across_all_gaps = $insideFirst
            exact_reduced_first_restorer_fraction_given_earlier_endpoint = `
                (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $first[0] -Denominator $exposed[0])
            exact_reduced_first_restorer_fraction_given_later_endpoint = `
                (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $first[1] -Denominator $exposed[1])
            exact_reduced_first_restorer_fraction_given_intervening_role = if ($exposed[2] -eq 0) { $null } else {
                Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $first[2] -Denominator $exposed[2]
            }
            exact_reduced_first_restorer_fraction_given_inside_pair_interval = `
                (Get-CodeSequenceRetentionPairReciprocityReducedFraction -Numerator $insideFirst -Denominator ($exposed[0] + $exposed[1] + $exposed[2]))
        })
    }
    for ($role = 0; $role -lt 3; $role++) {
        if ($reporterByRole[$role] -ne $globalByRole[$role]) {
            throw 'Code Sequence reporter role atlas does not reconcile all original report identities.'
        }
    }
    $sourceGlobal = $PairReciprocity.original_global_six_first_support_categories
    if ($globalByRole[0] -ne [long]$sourceGlobal.by_first -or
        $globalByRole[1] -ne [long]$sourceGlobal.by_second -or
        $globalByRole[2] -ne [long]$sourceGlobal.first_restored_between -or
        $allGapFirst -ne $globalByRole[0] + $globalByRole[1] + $globalByRole[2]) {
        throw 'Code Sequence reporter role atlas contradicts EC-074/076-backed EC-089 global FIRST categories.'
    }

    return [ordered]@{
        original_positions_in_reporter_role_atlas = $N
        total_distinct_full_original_permutations = $full
        exact_unordered_original_pair_count = $pairCount
        full_original_selection_has_saved_witness_support = [bool]$PairReciprocity.full_original_selection_has_saved_witness_support
        original_reporter_role_exposure_profiles = $reporters.ToArray()
        distance_first_restorer_role_histogram = $gapRoleTotals
        first_restored_by_all_original_earlier_endpoint_roles = $globalByRole[0]
        first_restored_by_all_original_later_endpoint_roles = $globalByRole[1]
        first_restored_by_all_original_intervening_roles = $globalByRole[2]
        first_restored_by_all_original_reporters_inside_pair_interval = $allGapFirst
        every_original_report_has_exact_pair_endpoint_and_nonendpoint_exposures = $true
        every_original_gap_exposure_partitions_full_unordered_pair_universe = $true
        every_original_role_first_restorer_count_is_within_exposure_denominator = $true
        every_reporter_gap_first_restorer_reconciles_independent_ec089_pair_rows = $true
        all_reporter_first_restorer_role_counts_match_independent_ec074_via_ec089 = $true
        no_outside_first_restorer_identity_inferred = $true
        no_new_evidence_source_read_or_business_write = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionReporterRoleExposure {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionPairReciprocity
    )

    if ($null -eq $RetentionPivotality -or $null -eq $RetentionPairReciprocity -or
        -not [bool]$RetentionPairReciprocity.only_consumed_checked_ec088_and_independent_ec076_original_projections -or
        -not [bool]$RetentionPairReciprocity.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairReciprocity.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairReciprocity.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairReciprocity.no_saved_quote_body_patch_git_network_or_business_source_access) {
        throw 'Code Sequence reporter role atlas requires checked successful original selector and EC-089 reciprocity.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        [int]$RetentionPairReciprocity.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairReciprocity.counts.original_maximal_repeat_family_count -ne $familyCount -or
        [int]$RetentionPairReciprocity.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
        [int]$RetentionPairReciprocity.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
        [int]$RetentionPairReciprocity.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
        [string]$RetentionPairReciprocity.path -cne [string]$RetentionPivotality.path) {
        throw 'Code Sequence reporter role atlas changed the successful ORIGINAL selected pair target.'
    }
    $gSource = [object[]]$RetentionPairReciprocity.genuine_global_threshold_pair_reciprocity
    $fSource = [object[]]$RetentionPairReciprocity.frozen_global_threshold_pair_reciprocity
    $familySource = [object[]]$RetentionPairReciprocity.individual_original_family_pair_reciprocity
    if ($gSource.Count -ne 3 -or $fSource.Count -ne 3 -or $familySource.Count -ne $familyCount) {
        throw 'Code Sequence reporter role atlas lost genuine/frozen thresholds or original family targets.'
    }
    $gOut = [System.Collections.Generic.List[object]]::new()
    $fOut = [System.Collections.Generic.List[object]]::new()
    for ($mode = 0; $mode -lt 2; $mode++) {
        $sources = if ($mode -eq 0) { $gSource } else { $fSource }
        $destination = if ($mode -eq 0) { $gOut } else { $fOut }
        for ($i = 0; $i -lt 3; $i++) {
            if ([int]$sources[$i].original_global_family_capacity_at_least -ne (3 - $i)) {
                throw 'Code Sequence reporter role atlas changed a genuine/frozen ORIGINAL threshold.'
            }
            $target = Get-CodeSequenceRetentionReporterRoleExposureProjection `
                -PairReciprocity $sources[$i].exact_first_support_pair_reciprocity -N $n
            $destination.Add([ordered]@{
                original_global_family_capacity_at_least = 3 - $i
                original_full_selection_global_family_capacity = [int]$sources[$i].original_full_selection_global_family_capacity
                exact_original_reporter_role_exposure = $target
            })
        }
    }
    $families = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $familyCount; $i++) {
        if ([int]$familySource[$i].original_maximal_repeat_family_index -ne $i + 1) {
            throw 'Code Sequence reporter role atlas changed an ORIGINAL maximal-repeat family index.'
        }
        $genuine = Get-CodeSequenceRetentionReporterRoleExposureProjection `
            -PairReciprocity $familySource[$i].genuine_original_first_support_pair_reciprocity -N $n
        $frozen = Get-CodeSequenceRetentionReporterRoleExposureProjection `
            -PairReciprocity $familySource[$i].frozen_original_first_support_pair_reciprocity -N $n
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $i + 1
            genuine_original_reporter_role_exposure = $genuine
            frozen_original_reporter_role_exposure = $frozen
        })
    }
    $factorials = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_reporter_role_exposure_and_first_restoration_atlas'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            original_reporter_roles_per_target = $n
            disjoint_original_distance_cases_per_reporter = $n - 1
            hypothetical_full_original_orderings_per_unordered_pair = [long]$factorials[$n]
            genuine_original_global_thresholds = $gOut.Count
            frozen_original_global_thresholds = $fOut.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_reporter_role_exposure = $gOut.ToArray()
        frozen_global_threshold_reporter_role_exposure = $fOut.ToArray()
        individual_original_family_reporter_role_exposure = $families.ToArray()
        only_consumed_checked_ec089_original_pair_reciprocity = $true
        original_ec071_caller_bits_and_family_targets_unchanged = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        outside_interval_first_restorer_identity_not_attributed = $true
        hypothetical_role_exposure_not_empirical_probability_or_actual_chronology = $true
        no_new_saved_evidence_source_git_network_or_business_write = $true
    }
}

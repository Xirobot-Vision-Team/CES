#requires -Version 7.0
<#
    EC-088: Assemble already checked ORIGINAL ordered-pair gap projections
    (EC-077..087) into an exact, caller-identity-preserving distance spectrum.

    This is a read-only materialized view, NOT another support/original-record
    scan, permutation enumeration, chronological claim, or optimization.
    It rechecks each gap's six-state FIRST mass, original middle attributions,
    EC-074 global ledger, and the independent EC-076 directed precedence row.
#>

function Get-CodeSequenceRetentionPairDistanceSpectrumProjection {
    param(
        [object] $PairPrecedence,
        [object[]] $GapProjections,
        [int] $N
    )

    $suffixes = [string[]]@('adjacency', 'single_intervening', 'double_intervening',
        'triple_intervening', 'quadruple_intervening', 'quintuple_intervening',
        'sextuple_intervening', 'septuple_intervening', 'octuple_intervening',
        'nonuple_intervening', 'decuple_intervening')
    $distanceWords = [string[]]@('zero', 'one', 'two', 'three', 'four', 'five',
        'six', 'seven', 'eight', 'nine', 'ten')
    $ordinals = [string[]]@('first', 'second', 'third', 'fourth', 'fifth',
        'sixth', 'seventh', 'eighth', 'ninth', 'tenth')
    $sixNames = [string[]]@(
        'full_permutations_first_restoring_before_first_report',
        'full_permutations_first_restored_by_first_report',
        'full_permutations_first_restoring_strictly_between_reports',
        'full_permutations_first_restored_by_second_report',
        'full_permutations_first_restoring_after_second_report',
        'full_permutations_never_restoring_saved_evidence'
    )
    $gapUniverseNames = [string[]]@('exact_full_permutations_with_first_report_immediately_before_second')
    for ($g = 1; $g -le 10; $g++) {
        $gapUniverseNames += 'exact_full_permutations_with_exactly_' + $distanceWords[$g] + '_original_report' + $(if ($g -eq 1) { '' } else { 's' }) + '_between_pair'
    }
    $scenarioNames = [string[]]@('directed_immediate_original_report_pair_scenarios')
    for ($g = 1; $g -le 10; $g++) {
        $scenarioNames += 'directed_original_report_pair_' + $suffixes[$g] + '_scenarios'
    }
    $incidenceNames = [string[]]@('expected_total_adjacent_pairs_across_all_hypothetical_original_orderings',
        'expected_total_one_intervening_report_pair_occurrences_across_all_orderings')
    for ($g = 2; $g -le 10; $g++) {
        $incidenceNames += 'expected_total_' + $suffixes[$g] + '_pair_occurrences_across_all_orderings'
    }

    if ($N -lt 2 -or $N -gt 12 -or $null -eq $PairPrecedence -or
        $null -eq $GapProjections -or $GapProjections.Count -ne 11 -or
        -not [bool]$PairPrecedence.every_ordered_report_pair_has_six_disjoint_exhaustive_first_support_categories -or
        -not [bool]$PairPrecedence.all_six_first_support_categories_match_independent_ec074_step_counts) {
        throw 'Code Sequence distance spectrum requires complete checked EC-076..087 original pair projections.'
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $N
    $fullOrderings = [long]$factorial[$N]
    $perDirected = [long]($fullOrderings / 2)
    $directed = $N * ($N - 1)
    $parentRows = [object[]]$PairPrecedence.ordered_original_report_pair_precedence_scenarios
    if ($parentRows.Count -ne $directed -or
        [int]$PairPrecedence.original_positions_in_precedence_universe -ne $N -or
        [long]$PairPrecedence.total_distinct_full_original_permutations -ne $fullOrderings -or
        [long]$PairPrecedence.exactly_half_the_orderings_per_directed_report_pair -ne $perDirected) {
        throw 'Code Sequence distance spectrum received altered EC-076 original ordered-pair universe.'
    }

    $allRowsByGap = [object[]]::new($N - 1)
    $gapDenominators = [long[]]::new($N - 1)
    $sourceLedgers = [object[]]::new($N - 1)
    $gapLedgerSums = [object[]]::new($N - 1)
    for ($g = 0; $g -le 10; $g++) {
        $projection = $GapProjections[$g]
        if ($null -eq $projection) {
            throw 'Code Sequence distance spectrum is missing an ORIGINAL distance parent.'
        }
        if ([bool]$projection.full_original_selection_has_saved_witness_support -ne
            [bool]$PairPrecedence.full_original_selection_has_saved_witness_support -or
            [long]$projection.total_distinct_full_original_permutations -ne $fullOrderings) {
            throw 'Code Sequence distance spectrum changed an original supported/unsupported target.'
        }
        $scenarioField = $scenarioNames[$g]
        $rows = [object[]]$projection.$scenarioField
        $expectedRows = if ($g -le ($N - 2)) { $directed } else { 0 }
        if ($rows.Count -ne $expectedRows) {
            throw 'Code Sequence distance spectrum contains missing or ineligible directed gap cases.'
        }
        $ledgerField = 'independent_ec074_first_support_step_' + $suffixes[$g] + '_ledger'
        $ledger = $projection.$ledgerField
        if ($null -eq $ledger -or
            -not [bool]$projection.every_original_public_ec072_basis_reconciled_with_ec073_budget_coverage) {
            throw 'Code Sequence distance spectrum requires checked original support and EC-074 gap ledgers.'
        }
        $incidenceField = $incidenceNames[$g]
        $expectedIncidence = [long][Math]::Max(0, $N - $g - 1) * $fullOrderings
        if ([long]$ledger.$incidenceField -ne $expectedIncidence) {
            throw 'Code Sequence distance spectrum found a mismatched EC-074 ORIGINAL gap incidence.'
        }
        if ($g -le ($N - 2)) {
            $gapDenominators[$g] = if ($g -eq 0) { [long]$factorial[$N - 1] } else {
                [long]($N - $g - 1) * [long]$factorial[$N - 2]
            }
            if ($gapDenominators[$g] -le 0 -or
                [long]$rows[0].($gapUniverseNames[$g]) -ne $gapDenominators[$g]) {
                throw 'Code Sequence distance spectrum received an incorrect exact gap denominator.'
            }
            $allRowsByGap[$g] = $rows
            $sourceLedgers[$g] = $ledger
            $gapLedgerSums[$g] = [long[]]::new(6)
        }
    }
    $originalGapMass = [long]0
    foreach ($denominator in $gapDenominators) { $originalGapMass += $denominator }
    if ($originalGapMass -ne $perDirected) {
        throw 'Code Sequence distance spectrum does not partition the N!/2 directed ORIGINAL precedence universe.'
    }

    $spectra = [System.Collections.Generic.List[object]]::new()
    $allStageTotals = [long[]]::new(6)
    for ($p = 0; $p -lt $N; $p++) {
        for ($q = 0; $q -lt $N; $q++) {
            if ($p -eq $q) { continue }
            $index = $spectra.Count
            $parent = $parentRows[$index]
            $pBit = 1 -shl $p
            $qBit = 1 -shl $q
            if ([int]$parent.first_original_caller_position -ne ($p + 1) -or
                [int]$parent.second_original_caller_position -ne ($q + 1) -or
                [int]$parent.first_original_position_bit -ne $pBit -or
                [int]$parent.second_original_position_bit -ne $qBit -or
                [long]$parent.exact_complete_permutations_with_first_original_report_before_second -ne $perDirected) {
                throw 'Code Sequence distance spectrum lost original EC-076 directed report identities.'
            }
            $cumulative = [long[]]::new(6)
            $originalMiddleTotals = [long[]]::new($N)
            $distanceCases = [System.Collections.Generic.List[object]]::new()
            for ($g = 0; $g -le ($N - 2); $g++) {
                $row = $allRowsByGap[$g][$index]
                $denominator = $gapDenominators[$g]
                if ([int]$row.first_original_caller_position -ne ($p + 1) -or
                    [int]$row.second_original_caller_position -ne ($q + 1) -or
                    [int]$row.first_original_position_bit -ne $pBit -or
                    [int]$row.second_original_position_bit -ne $qBit -or
                    [long]$row.($gapUniverseNames[$g]) -ne $denominator) {
                    throw 'Code Sequence distance spectrum found a displaced ORIGINAL p/q in a gap.'
                }
                $current = [long[]]::new(6)
                $current[0] = [long]$row.full_permutations_first_restoring_before_first_report
                $current[1] = [long]$row.full_permutations_first_restored_by_first_report
                $current[3] = [long]$row.full_permutations_first_restored_by_second_report
                $current[4] = [long]$row.full_permutations_first_restoring_after_second_report
                $current[5] = [long]$row.full_permutations_never_restoring_saved_evidence
                $middleByPosition = [long[]]::new($N)
                for ($slot = 0; $slot -lt $g; $slot++) {
                    $stageName = if ($g -eq 1) {
                        'full_permutations_first_restored_by_single_intervening_original_report'
                    } else {
                        'full_permutations_first_restored_by_' + $ordinals[$slot] + '_intervening_original_report'
                    }
                    $vectorName = if ($g -eq 1) {
                        'first_restored_by_intervening_original_caller_position_counts'
                    } else {
                        'first_restored_by_' + $ordinals[$slot] + '_intervening_original_caller_position_counts'
                    }
                    $stage = [long]$row.$stageName
                    $originalVector = [long[]]$row.$vectorName
                    if ($stage -lt 0 -or $originalVector.Count -ne $N) {
                        throw 'Code Sequence distance spectrum lost a checked ORIGINAL middle stage or identity vector.'
                    }
                    $middleSlotMass = [long]0
                    for ($position = 0; $position -lt $N; $position++) {
                        $value = [long]$originalVector[$position]
                        if ($value -lt 0 -or (($position -eq $p -or $position -eq $q) -and $value -ne 0)) {
                            throw 'Code Sequence distance spectrum credited an ORIGINAL endpoint as a middle restorer.'
                        }
                        $middleByPosition[$position] += $value
                        $middleSlotMass += $value
                    }
                    if ($middleSlotMass -ne $stage) {
                        throw 'Code Sequence distance spectrum does not conserve one ORIGINAL middle identity slot.'
                    }
                    $current[2] += $stage
                }
                $mass = [long]0
                for ($stageIndex = 0; $stageIndex -lt 6; $stageIndex++) {
                    if ($current[$stageIndex] -lt 0) {
                        throw 'Code Sequence distance spectrum found a negative ORIGINAL saved-evidence stage.'
                    }
                    $mass += $current[$stageIndex]
                    $cumulative[$stageIndex] += $current[$stageIndex]
                    $gapLedgerSums[$g][$stageIndex] += $current[$stageIndex]
                }
                if ($mass -ne $denominator) {
                    throw 'Code Sequence distance spectrum failed a six-way ORIGINAL gap partition.'
                }
                for ($position = 0; $position -lt $N; $position++) {
                    $originalMiddleTotals[$position] += $middleByPosition[$position]
                }
                $bySecondGcd = Get-CodeSequenceRetentionOrderGcd -A $current[3] -B $denominator
                $betweenGcd = Get-CodeSequenceRetentionOrderGcd -A $current[2] -B $denominator
                $cumulativeMass = [long]0
                foreach ($v in $cumulative) { $cumulativeMass += $v }
                $distanceCases.Add([ordered]@{
                    number_of_original_reports_strictly_between_pair = $g
                    exact_full_orderings_with_this_directed_gap = $denominator
                    before_first = $current[0]
                    by_first = $current[1]
                    first_restored_between = $current[2]
                    by_second = $current[3]
                    after_second = $current[4]
                    never = $current[5]
                    first_restored_between_by_original_caller_position = $middleByPosition
                    exact_reduced_between_fraction_numerator = [long]($current[2] / $betweenGcd)
                    exact_reduced_between_fraction_denominator = [long]($denominator / $betweenGcd)
                    exact_reduced_by_second_fraction_numerator = [long]($current[3] / $bySecondGcd)
                    exact_reduced_by_second_fraction_denominator = [long]($denominator / $bySecondGcd)
                    cumulative_orderings_through_this_distance = $cumulativeMass
                    cumulative_before_first = $cumulative[0]
                    cumulative_by_first = $cumulative[1]
                    cumulative_first_restored_between = $cumulative[2]
                    cumulative_by_second = $cumulative[3]
                    cumulative_after_second = $cumulative[4]
                    cumulative_never = $cumulative[5]
                })
            }
            $middleSum = [long]0
            foreach ($v in $originalMiddleTotals) { $middleSum += $v }
            if ($middleSum -ne $cumulative[2] -or
                $originalMiddleTotals[$p] -ne 0 -or $originalMiddleTotals[$q] -ne 0) {
                throw 'Code Sequence distance spectrum misattributed an original cross-distance intermediary.'
            }
            $sixTotal = [long]0
            for ($i = 0; $i -lt 6; $i++) {
                if ($cumulative[$i] -ne [long]$parent.($sixNames[$i])) {
                    throw 'Code Sequence distance spectrum contradicts independent EC-076 ORIGINAL FIRST precedence.'
                }
                $sixTotal += $cumulative[$i]
                $allStageTotals[$i] += $cumulative[$i]
            }
            if ($sixTotal -ne $perDirected -or $distanceCases.Count -ne $N - 1) {
                throw 'Code Sequence distance spectrum lost a directed ORIGINAL gap or ordering.'
            }
            $allGcd = Get-CodeSequenceRetentionOrderGcd -A $cumulative[3] -B $perDirected
            if ([long]$parent.exact_reduced_by_second_report_fraction_numerator -ne
                    [long]($cumulative[3] / $allGcd) -or
                [long]$parent.exact_reduced_by_second_report_fraction_denominator -ne
                    [long]($perDirected / $allGcd)) {
                throw 'Code Sequence distance spectrum changed the exact EC-076 by-q fraction.'
            }
            $spectra.Add([ordered]@{
                first_original_caller_position = $p + 1
                second_original_caller_position = $q + 1
                first_original_position_bit = $pBit
                second_original_position_bit = $qBit
                exact_orderings_with_first_report_before_second = $perDirected
                exact_distance_cases = $distanceCases.ToArray()
                full_precedence_first_restoring_before_first_report = $cumulative[0]
                full_precedence_first_restored_by_first_report = $cumulative[1]
                full_precedence_first_restoring_between_reports = $cumulative[2]
                full_precedence_first_restored_by_second_report = $cumulative[3]
                full_precedence_first_restoring_after_second_report = $cumulative[4]
                full_precedence_never_restoring_saved_evidence = $cumulative[5]
                all_distances_first_restored_between_by_original_caller_position = $originalMiddleTotals
                exact_reduced_precedence_by_second_fraction_numerator = [long]($cumulative[3] / $allGcd)
                exact_reduced_precedence_by_second_fraction_denominator = [long]($perDirected / $allGcd)
            })
        }
    }
    if ($spectra.Count -ne $directed) {
        throw 'Code Sequence distance spectrum dropped a directed ORIGINAL report pair.'
    }

    # An independent margin exists for every gap: each original complete
    # order has exactly N-g-1 directed report pairs at that fixed distance.
    $distanceHistogram = [System.Collections.Generic.List[object]]::new()
    for ($g = 0; $g -le ($N - 2); $g++) {
        $ledger = $sourceLedgers[$g]
        $expected = [long]($N - $g - 1) * $fullOrderings
        $fromRows = [long]0
        foreach ($value in $gapLedgerSums[$g]) { $fromRows += $value }
        $fromLedger = [long[]]@(
            [long]$ledger.full_permutations_first_restoring_before_first_report,
            [long]$ledger.full_permutations_first_restored_by_first_report,
            [long]0,
            [long]$ledger.full_permutations_first_restored_by_second_report,
            [long]$ledger.full_permutations_first_restoring_after_second_report,
            [long]$ledger.full_permutations_never_restoring_saved_evidence
        )
        if ($g -eq 1) {
            $fromLedger[2] = [long]$ledger.full_permutations_first_restored_by_single_intervening_original_report
        }
        elseif ($g -ge 2) {
            for ($slot = 0; $slot -lt $g; $slot++) {
                $stageField = 'full_permutations_first_restored_by_' + $ordinals[$slot] + '_intervening_original_report'
                $fromLedger[2] += [long]$ledger.$stageField
            }
        }
        for ($i = 0; $i -lt 6; $i++) {
            if ($gapLedgerSums[$g][$i] -ne $fromLedger[$i]) {
                throw 'Code Sequence distance spectrum disagrees with independent EC-074 gap FIRST attribution.'
            }
        }
        if ($fromRows -ne $expected -or $fromRows -ne [long]$directed * $gapDenominators[$g]) {
            throw 'Code Sequence distance spectrum failed the N-g-1 original gap incidence identity.'
        }
        $distanceHistogram.Add([ordered]@{
            number_of_original_reports_strictly_between_pair = $g
            exact_directed_pair_occurrences_across_all_original_permutations = $expected
            before_first = $fromLedger[0]
            by_first = $fromLedger[1]
            first_restored_between = $fromLedger[2]
            by_second = $fromLedger[3]
            after_second = $fromLedger[4]
            never = $fromLedger[5]
        })
    }
    $independent = $PairPrecedence.independent_ec074_first_support_step_pair_precedence_ledger
    for ($i = 0; $i -lt 6; $i++) {
        if ($allStageTotals[$i] -ne [long]$independent.($sixNames[$i])) {
            throw 'Code Sequence distance spectrum failed independent EC-074/076 six-stage totals.'
        }
    }
    if ([long]$independent.expected_total_combinations_across_all_hypothetical_original_orderings -ne
            [long]($N * ($N - 1) / 2) * $fullOrderings) {
        throw 'Code Sequence distance spectrum received an altered independent precedence ledger.'
    }
    return [ordered]@{
        original_positions_in_distance_spectrum_universe = $N
        total_distinct_full_original_permutations = $fullOrderings
        exactly_half_the_original_orderings_per_directed_pair = $perDirected
        full_original_selection_has_saved_witness_support = [bool]$PairPrecedence.full_original_selection_has_saved_witness_support
        directed_original_report_pair_distance_spectra = $spectra.ToArray()
        original_distance_histogram_across_all_directed_pairs = $distanceHistogram.ToArray()
        total_first_restoration_by_six_precedence_categories = [ordered]@{
            before_first = $allStageTotals[0]
            by_first = $allStageTotals[1]
            first_restored_between = $allStageTotals[2]
            by_second = $allStageTotals[3]
            after_second = $allStageTotals[4]
            never = $allStageTotals[5]
        }
        every_original_directed_pair_gap_spectrum_partitions_ec076_precedence = $true
        all_original_middle_identity_attributions_preserve_caller_bits = $true
        every_distance_histogram_reconciles_independent_ec074_gap_ledger = $true
        all_six_global_precedence_categories_reconcile_independent_ec074_and_ec076 = $true
        no_new_saved_record_evidence_or_external_access = $true
        hypothetical_distance_spectrum_is_not_observed_chronology_or_empirical_probability = $true
    }
}

function Get-CodeSequenceOriginalFindingPairProfileRetentionPairDistanceSpectrum {
    param(
        [object] $RetentionPivotality,
        [object] $RetentionPairPrecedence,
        [object] $RetentionPairAdjacency,
        [object] $RetentionPairSingleIntervening,
        [object] $RetentionPairDoubleIntervening,
        [object] $RetentionPairTripleIntervening,
        [object] $RetentionPairQuadrupleIntervening,
        [object] $RetentionPairQuintupleIntervening,
        [object] $RetentionPairSextupleIntervening,
        [object] $RetentionPairSeptupleIntervening,
        [object] $RetentionPairOctupleIntervening,
        [object] $RetentionPairNonupleIntervening,
        [object] $RetentionPairDecupleIntervening
    )

    $suffixes = [string[]]@('adjacency', 'single_intervening', 'double_intervening',
        'triple_intervening', 'quadruple_intervening', 'quintuple_intervening',
        'sextuple_intervening', 'septuple_intervening', 'octuple_intervening',
        'nonuple_intervening', 'decuple_intervening')
    $gapWrappers = [object[]]@($RetentionPairAdjacency, $RetentionPairSingleIntervening,
        $RetentionPairDoubleIntervening, $RetentionPairTripleIntervening,
        $RetentionPairQuadrupleIntervening, $RetentionPairQuintupleIntervening,
        $RetentionPairSextupleIntervening, $RetentionPairSeptupleIntervening,
        $RetentionPairOctupleIntervening, $RetentionPairNonupleIntervening,
        $RetentionPairDecupleIntervening)
    if ($null -eq $RetentionPivotality -or $null -eq $RetentionPairPrecedence -or
        -not [bool]$RetentionPairDecupleIntervening.original_ec071_bit_legend_and_caller_order_unchanged -or
        -not [bool]$RetentionPairDecupleIntervening.no_new_selector_or_original_evidence_read_and_no_reoptimization -or
        -not [bool]$RetentionPairDecupleIntervening.independent_of_sequence_top_and_original_finding_seed_side -or
        -not [bool]$RetentionPairDecupleIntervening.no_saved_quote_body_patch_git_network_or_business_source_access) {
        throw 'Code Sequence distance spectrum requires completed read-only EC-087 and unchanged original selector.'
    }
    $n = [int]$RetentionPivotality.counts.original_selected_report_positions
    $familyCount = [int]$RetentionPivotality.counts.original_maximal_repeat_family_count
    $gParent = [object[]]$RetentionPairPrecedence.genuine_global_threshold_pair_precedence
    $fParent = [object[]]$RetentionPairPrecedence.frozen_global_threshold_pair_precedence
    $familyParent = [object[]]$RetentionPairPrecedence.individual_original_family_pair_precedence
    if ($n -lt 2 -or $n -gt 12 -or $familyCount -lt 0 -or $familyCount -gt 66 -or
        $gParent.Count -ne 3 -or $fParent.Count -ne 3 -or
        $familyParent.Count -ne $familyCount -or
        [int]$RetentionPairPrecedence.counts.original_selected_report_positions -ne $n -or
        [int]$RetentionPairPrecedence.counts.original_maximal_repeat_family_count -ne $familyCount) {
        throw 'Code Sequence distance spectrum received a changed original genuine/frozen/family target registry.'
    }
    foreach ($wrapper in $gapWrappers) {
        if ($null -eq $wrapper -or
            [int]$wrapper.counts.original_selected_report_positions -ne $n -or
            [int]$wrapper.counts.original_maximal_repeat_family_count -ne $familyCount -or
            [int]$wrapper.pair_index_in_pairwise_profile -ne [int]$RetentionPivotality.pair_index_in_pairwise_profile -or
            [int]$wrapper.path_index_in_selected_pair_overview -ne [int]$RetentionPivotality.path_index_in_selected_pair_overview -or
            [int]$wrapper.anchor_index_in_anchor_journeys -ne [int]$RetentionPivotality.anchor_index_in_anchor_journeys -or
            [string]$wrapper.path -cne [string]$RetentionPivotality.path) {
            throw 'Code Sequence distance spectrum mixed original selected paths or identity targets.'
        }
    }

    $gResult = [System.Collections.Generic.List[object]]::new()
    $fResult = [System.Collections.Generic.List[object]]::new()
    for ($kind = 0; $kind -lt 2; $kind++) {
        $mode = if ($kind -eq 0) { 'genuine' } else { 'frozen' }
        $parentItems = if ($kind -eq 0) { $gParent } else { $fParent }
        $sink = if ($kind -eq 0) { $gResult } else { $fResult }
        for ($i = 0; $i -lt 3; $i++) {
            $threshold = 3 - $i
            $parent = $parentItems[$i]
            $origCapacity = [int]$parent.original_full_selection_global_family_capacity
            if ([int]$parent.original_global_family_capacity_at_least -ne $threshold) {
                throw 'Code Sequence distance spectrum lost a genuine/frozen original capacity threshold.'
            }
            $projections = [object[]]::new(11)
            for ($g = 0; $g -le 10; $g++) {
                $field = $mode + '_global_threshold_pair_' + $suffixes[$g]
                $items = [object[]]$gapWrappers[$g].$field
                if ($items.Count -ne 3 -or
                    [int]$items[$i].original_global_family_capacity_at_least -ne $threshold -or
                    [int]$items[$i].original_full_selection_global_family_capacity -ne $origCapacity) {
                    throw 'Code Sequence distance spectrum changed the original global genuine/frozen threshold.'
                }
                $childField = 'exact_first_support_pair_' + $suffixes[$g]
                $projections[$g] = $items[$i].$childField
            }
            $projection = Get-CodeSequenceRetentionPairDistanceSpectrumProjection `
                -PairPrecedence $parent.exact_first_support_pair_precedence `
                -GapProjections $projections -N $n
            $sink.Add([ordered]@{
                original_global_family_capacity_at_least = $threshold
                original_full_selection_global_family_capacity = $origCapacity
                exact_first_support_pair_distance_spectrum = $projection
            })
        }
    }

    $families = [System.Collections.Generic.List[object]]::new()
    for ($fi = 0; $fi -lt $familyCount; $fi++) {
        $parent = $familyParent[$fi]
        if ([int]$parent.original_maximal_repeat_family_index -ne $fi + 1) {
            throw 'Code Sequence distance spectrum lost an ORIGINAL maximal-repeat family ID.'
        }
        $modeOutputs = [object[]]::new(2)
        for ($kind = 0; $kind -lt 2; $kind++) {
            $mode = if ($kind -eq 0) { 'genuine' } else { 'frozen' }
            $projections = [object[]]::new(11)
            for ($g = 0; $g -le 10; $g++) {
                $entryField = 'individual_original_family_pair_' + $suffixes[$g]
                $items = [object[]]$gapWrappers[$g].$entryField
                if ($items.Count -ne $familyCount -or
                    [int]$items[$fi].original_maximal_repeat_family_index -ne $fi + 1) {
                    throw 'Code Sequence distance spectrum mixed individual ORIGINAL family IDs.'
                }
                $targetField = $mode + '_original_first_support_pair_' + $suffixes[$g]
                $projections[$g] = $items[$fi].$targetField
            }
            $parentTargetField = $mode + '_original_first_support_pair_precedence'
            $modeOutputs[$kind] = Get-CodeSequenceRetentionPairDistanceSpectrumProjection `
                -PairPrecedence $parent.$parentTargetField -GapProjections $projections -N $n
        }
        $families.Add([ordered]@{
            original_maximal_repeat_family_index = $fi + 1
            genuine_original_first_support_pair_distance_spectrum = $modeOutputs[0]
            frozen_original_first_support_pair_distance_spectrum = $modeOutputs[1]
        })
    }
    $factorial = Get-CodeSequenceRetentionOrderFactorials -N $n
    return [ordered]@{
        scope = 'exact_original_directed_report_pair_saved_evidence_first_restoration_distance_spectrum'
        pair_index_in_pairwise_profile = [int]$RetentionPivotality.pair_index_in_pairwise_profile
        path_index_in_selected_pair_overview = [int]$RetentionPivotality.path_index_in_selected_pair_overview
        anchor_index_in_anchor_journeys = [int]$RetentionPivotality.anchor_index_in_anchor_journeys
        path = [string]$RetentionPivotality.path
        counts = [ordered]@{
            original_selected_report_positions = $n
            original_maximal_repeat_family_count = $familyCount
            exact_original_distinct_permutations_per_target = [long]$factorial[$n]
            directed_original_report_pair_spectra_per_target = $n * ($n - 1)
            disjoint_original_report_pair_distances_per_direction = $n - 1
            total_directed_original_pair_occurrences_across_all_permutations_per_target = [long]($n * ($n - 1) / 2) * [long]$factorial[$n]
            genuine_original_global_thresholds = $gResult.Count
            frozen_original_global_thresholds = $fResult.Count
            individual_original_family_targets = $families.Count
        }
        genuine_global_threshold_pair_distance_spectrum = $gResult.ToArray()
        frozen_global_threshold_pair_distance_spectrum = $fResult.ToArray()
        individual_original_family_pair_distance_spectrum = $families.ToArray()
        original_ec071_bit_legend_and_caller_order_unchanged = $true
        only_consumed_checked_ec076_to_ec087_original_projection_outputs = $true
        no_new_selector_or_original_evidence_read_and_no_reoptimization = $true
        independent_of_sequence_top_and_original_finding_seed_side = $true
        no_saved_quote_body_patch_git_network_or_business_source_access = $true
        hypothetical_distance_spectrum_is_not_authenticated_chronology_or_empirical_probability = $true
        conditional_distance_distribution_is_not_defect_severity_risk_priority_or_causal_repair = $true
    }
}

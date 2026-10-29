#!/usr/bin/env python3
"""EC332: compare two fully replayed, independently raw-SHA-pinned EC331 sets.

The only comparison unit is a finite LOCAL observation. A report or manifest
is UNSIGNED; a ninth receipt is counted once per genuine signed original SHA.
'Left'/'right' do not express timestamp, chronology, priority or CAS order.

Every EC331 manifest is validated and run through the *real* EC331 entrypoint,
which itself invokes EC330/329/328/.../294 actual original verification. The
result is then cross-checked against freshly read, pinned original ledger rows.
All inputs are repinned across both sets at the END to detect mutation during
comparison. No signer keys, writer, shell, network, remote CAS or store API.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hmac
from itertools import combinations
from typing import Any

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec329_offline_ledger_comparison import comparison
from ec330_replayable_comparison_report import report
from ec331_offline_report_set_crosscheck import crosscheck

RESULT_SCHEMA = 'ces.ec332.two_pinned_report_sets_local_delta.v1'
DENIAL_SCHEMA = 'ces.ec332.two_pinned_report_sets_local_delta_denial.v1'
MAX_RESULT_BYTES = 256_000
MAX_CROSS_ONLY_PAIR_EXAMPLES = 24
FALSE_FIELDS = tuple(dict.fromkeys((
    *crosscheck.FALSE_FIELDS,
    'two_unsigned_sets_prove_temporal_earlier_or_later',
    'locally_unobserved_signed_original_proves_remote_deletion_or_revocation',
    'cross_set_local_relationship_proves_transitive_global_signed_history',
    'source_pin_argument_proves_real_independent_custody',
)))
SHA_KEY = 'original_raw_sha256'
CATEGORIES = ('report', 'ledger', 'ninth_signed_receipt')


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC332_' + reason, status)


def _verified_view(manifest_file: str, expected_manifest_sha256: str) -> dict:
    """Construct one view *only after* the previous real EC331 full replay.

    Never reuse an unsigned EC331 JSON result as trust input: its job is to
    demonstrate what was recomputed just now, and the source digests remain
    independently required from the caller's pinned manifest.
    """
    result = crosscheck.cross_reference(
        manifest_file=manifest_file,
        expected_manifest_sha256=expected_manifest_sha256)
    need(type(result) is dict and result.get('schema') == crosscheck.RESULT_SCHEMA
         and result.get('exit_code') == 2
         and result.get('status') ==
             'finite_locally_observed_unsigned_report_set_cross_referenced_unresolved'
         and result.get('manifest_original_raw_sha256') == expected_manifest_sha256
         and result.get('every_listed_report_and_both_signed_histories_replayed') is True
         and result.get('all_original_source_sha_pins_rechecked_after_batch') is True
         and result.get('all_pins_require_separate_real_world_external_trust') is True
         and result.get('report_and_manifest_are_unsigned_local_observation_only') is True
         and all(result.get(name) is False for name in crosscheck.FALSE_FIELDS),
         'BOTH_SETS_REQUIRE_REAL_EC331_REPLAY_NOT_A_STORED_UNSIGNED_RESULT')
    manifest, raw = crosscheck._manifest(manifest_file, expected_manifest_sha256)
    rows = manifest['reports']
    report_shas = {item['expected_report_sha256'] for item in rows}
    ledgers = {}
    for item in rows:
        kw = item['comparison_inputs']
        # Old EC331 has already verified the entire original signature chain.
        # Reload canonical, independently SHA-pinned original rows for the
        # finite delta rather than trusting an unsigned summary's reported IDs.
        for side in ('a', 'b'):
            sha = kw[f'expected_branch_{side}_ledger_sha256']
            doc = comparison._load_snapshot(
                kw[f'branch_{side}_ledger_file'], sha,
                'EC332_RELOAD_VERIFIED_SIGNED_SOURCE_LEDGER_' + side.upper())
            if sha in ledgers:
                need(ledgers[sha] == doc,
                     'SAME_WHOLE_SHA_CANNOT_MAP_TO_DIFFERENT_SIGNED_SOURCE_ROWS')
            ledgers[sha] = doc
    receipt_shas = {entry['receipt_original_raw_sha256']
                    for doc in ledgers.values() for entry in doc['entries']}
    observed = result.get('observed_reports_not_new_signed_votes')
    nodes = result.get('verified_local_ledger_nodes')
    need(type(observed) is list and
         {r.get('report_original_raw_sha256') for r in observed
          if type(r) is dict} == report_shas and
         len(observed) == len(report_shas) and
         type(nodes) is list and
         {n.get('ledger_original_raw_sha256') for n in nodes
          if type(n) is dict} == set(ledgers) and
         len(nodes) == len(ledgers) and
         result.get('report_observation_count') == len(rows) and
         result.get('distinct_report_original_raw_sha_count') == len(report_shas) and
         result.get('distinct_verified_ledger_original_count') == len(ledgers) and
         result.get('deduplicated_unique_signed_ninth_receipt_original_count') ==
             len(receipt_shas) and
         type(result.get('shared_signed_request_context')) is dict,
         'REPLAY_RESULT_MUST_MATCH_RELOADED_SIGNED_ORIGINAL_OBSERVATIONS')
    context = result['shared_signed_request_context']
    need(set(context) == set((*crosscheck.SHARED_CONTEXT_FIELDS, 'request_id')) and
         all(all(doc.get(k) == context[k] for k in crosscheck.SHARED_CONTEXT_FIELDS)
             for doc in ledgers.values()),
         'VERIFIED_SIGNED_CONTEXT_MISMATCH', 'invalid_input')
    return {
        'manifest_file': manifest_file, 'manifest_sha': expected_manifest_sha256,
        'manifest_raw': raw, 'rows': rows, 'context': context,
        'report_shas': report_shas, 'ledgers': ledgers, 'receipt_shas': receipt_shas,
    }


def _three_way(a: set[str], b: set[str]) -> dict[str, list[str]]:
    return {
        'only_in_left_observation': sorted(a - b),
        'only_in_right_observation': sorted(b - a),
        'observed_in_both': sorted(a & b),
    }


def _cross_only_pairs(left: dict, right: dict) -> tuple[int, dict, list]:
    """Pairs visible *only after* uniting the two finite EC331 input sets.

    Do not infer a two-hop ancestor from a common signed prefix. The old
    EC331 _pair_relation only recognizes a direct append where a separate
    pinned immediate previous ledger was actually replayed by EC328.
    """
    exclusive_a = sorted(set(left['ledgers']) - set(right['ledgers']))
    exclusive_b = sorted(set(right['ledgers']) - set(left['ledgers']))
    all_ledgers = {**left['ledgers'], **right['ledgers']}
    count = 0
    classes: Counter[str] = Counter()
    examples = []
    for a in exclusive_a:
        for b in exclusive_b:
            x, y = sorted((a, b))
            pair = crosscheck._pair_relation(x, all_ledgers[x], y,
                                             all_ledgers[y], False)
            need(pair['new_pair_relationship_only_visible_across_reports'] is True
                 and pair['both_ledgers_coobserved_in_a_replayed_ec330_report'] is False
                 and pair['relationship'].endswith('_unresolved'),
                 'UNION_ONLY_PAIR_MUST_BE_LOCAL_AND_UNRESOLVED')
            count += 1
            classes[pair['relationship']] += 1
            if len(examples) < MAX_CROSS_ONLY_PAIR_EXAMPLES:
                examples.append(pair)
    return count, dict(sorted(classes.items())), examples


def _recheck_both(views: tuple[dict, dict]) -> None:
    """Late whole-byte source reads across BOTH views, not only the last view.

    The old EC330 recheck includes previous ledger, ninth originals, signed
    eighth request, dispute and all old signed registry/channel/capsule inputs.
    It does not claim concurrent remote atomicity or protection from ABA.
    """
    for view in views:
        for observation in view['rows']:
            kw = observation['comparison_inputs']
            report._recheck_all_pinned_inputs(kw)
            receipt._load(observation['report_file'],
                          observation['expected_report_sha256'],
                          report.MAX_REPORT_BYTES,
                          'EC332_LATE_EC330_ORIGINAL_REPORT_REPIN')
        fresh, raw = crosscheck._manifest(
            view['manifest_file'], view['manifest_sha'])
        need(hmac.compare_digest(raw, view['manifest_raw']) and
             fresh['reports'] == view['rows'],
             'BOTH_MANIFEST_ORIGINALS_MUST_REMAIN_IDENTICAL_AT_FINAL_RECHECK')


def compare(*, left_manifest_file: str, left_expected_manifest_sha256: str,
            right_manifest_file: str, right_expected_manifest_sha256: str) -> dict:
    """One finite difference operation; both independent real full replays.

    A whole raw SHA argument does not by itself prove an externally trusted
    source. Both expected SHAs must actually come from outside this tool.
    """
    need(type(left_manifest_file) is str and type(right_manifest_file) is str
         and left_manifest_file != right_manifest_file,
         'TWO_DISTINCT_MANIFEST_ORIGINAL_FILE_PATHS_REQUIRED', 'invalid_input')
    left = _verified_view(left_manifest_file, left_expected_manifest_sha256)
    right = _verified_view(right_manifest_file, right_expected_manifest_sha256)
    need(left['context'] == right['context'],
         'CROSS_SET_DIFFERENT_SIGNED_EIGHTH_REQUEST_OR_DISPUTE_CONTEXT',
         'invalid_input')
    for sha in set(left['ledgers']) & set(right['ledgers']):
        need(left['ledgers'][sha] == right['ledgers'][sha],
             'CROSS_SET_IDENTICAL_LEDGER_RAW_SHA_MUST_HAVE_IDENTICAL_ROWS')
    report_delta = _three_way(left['report_shas'], right['report_shas'])
    ledger_delta = _three_way(set(left['ledgers']), set(right['ledgers']))
    signed_delta = _three_way(left['receipt_shas'], right['receipt_shas'])
    combined = {**left['ledgers'], **right['ledgers']}
    origins = defaultdict(set)
    for name, view in (('left', left), ('right', right)):
        for sha in view['ledgers']:
            origins[sha].add(name)
    dispositions, collisions, collision_count, cross_only_collision_groups, \
        duplicate_signed_original_paths = crosscheck._receipt_reuse(combined, origins)
    union_signed = left['receipt_shas'] | right['receipt_shas']
    need(sum(dispositions.values()) == len(union_signed),
         'UNION_SIGNED_ORIGINAL_DEDUP_COUNT_INCONSISTENT')
    pair_count, class_counts, pair_examples = _cross_only_pairs(left, right)
    # Mutation during the second replay or during the difference computation
    # invalidates the *whole* operation, even if the earlier EC331 replay passed.
    _recheck_both((left, right))
    result = {
        'schema': RESULT_SCHEMA,
        'command': 'compare-report-set-observations',
        'status': 'two_finite_pinned_unsigned_observation_sets_compared_locally_unresolved',
        'exit_code': 2,
        'left_manifest_original_raw_sha256': left['manifest_sha'],
        'right_manifest_original_raw_sha256': right['manifest_sha'],
        'same_manifest_original_bytes_at_two_distinct_paths':
            left['manifest_sha'] == right['manifest_sha'],
        'shared_signed_request_context': left['context'],
        'left_observation_counts': {
            'report_rows': len(left['rows']),
            'distinct_report_originals': len(left['report_shas']),
            'distinct_ledger_originals': len(left['ledgers']),
            'distinct_signed_ninth_receipt_originals': len(left['receipt_shas']),
        },
        'right_observation_counts': {
            'report_rows': len(right['rows']),
            'distinct_report_originals': len(right['report_shas']),
            'distinct_ledger_originals': len(right['ledgers']),
            'distinct_signed_ninth_receipt_originals': len(right['receipt_shas']),
        },
        'report_original_observation_difference': report_delta,
        'ledger_original_observation_difference': ledger_delta,
        'signed_ninth_receipt_original_observation_difference': signed_delta,
        'combined_unique_report_original_count':
            len(left['report_shas'] | right['report_shas']),
        'combined_unique_ledger_original_count': len(combined),
        'combined_unique_signed_ninth_receipt_original_count': len(union_signed),
        'combined_deduplicated_signed_offline_disposition_counts': dispositions,
        'cross_input_only_ledger_pair_count': pair_count,
        'cross_input_only_ledger_pair_relationship_counts': class_counts,
        'cross_input_only_ledger_pair_examples': pair_examples,
        'cross_input_only_ledger_pair_examples_truncated':
            pair_count > len(pair_examples),
        'combined_distinct_signed_receipt_reused_ninth_role_groups': collision_count,
        'cross_input_only_ninth_role_reuse_groups': cross_only_collision_groups,
        'combined_ninth_role_reuse_group_examples': collisions,
        'combined_ninth_role_reuse_group_examples_truncated':
            collision_count > len(collisions),
        'same_signed_receipt_sha_seen_at_multiple_local_paths_count':
            duplicate_signed_original_paths,
        'both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed': True,
        'both_sets_original_source_report_and_manifest_pins_rechecked_after_union': True,
        'left_and_right_are_labels_not_temporal_claims_or_signed_precedence': True,
        'outputs_only_locally_observed_signed_sha_not_path_or_plaintext_identity': True,
        'external_trust_for_both_whole_original_manifest_shas_still_required': True,
        **{flag: False for flag in FALSE_FIELDS},
    }
    need(len(receipt._raw(result)) <= MAX_RESULT_BYTES,
         'TWO_SET_LOCAL_DELTA_OUTPUT_EXCEEDS_BOUND', 'invalid_input')
    return result

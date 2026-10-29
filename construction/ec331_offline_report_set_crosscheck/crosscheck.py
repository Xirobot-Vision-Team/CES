#!/usr/bin/env python3
"""EC331: independently full-replay 2-8 EC330 originals and cross-reference them.

All trust inputs are taken from an out-of-band, whole-original-SHA-pinned,
owner-private canonical manifest, NEVER copied from an EC330 report. Every
listed original goes through the production EC330 -> EC329 -> EC328 -> EC294
verification path, including historical real signature verification. Even an
identical report listed twice is verified twice: it is only *one* independent
set of signed evidence, not two votes.

The graph is an observed finite LOCAL set. No external CAS, real nonexecution,
remote latest, physical authority independence, or institution is attested.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import hmac
from itertools import combinations
from typing import Any

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec327_offline_hold_disposition import disposition as ninth
from ec328_offline_review_ledger import ledger
from ec329_offline_ledger_comparison import comparison
from ec330_replayable_comparison_report import report

MANIFEST_SCHEMA = 'ces.ec331.externally_pinned_offline_report_set_manifest.v1'
RESULT_SCHEMA = 'ces.ec331.offline_report_set_cross_reference.v1'
DENIAL_SCHEMA = 'ces.ec331.offline_report_set_cross_reference_denial.v1'
MAX_MANIFEST_BYTES = 140_000
MIN_REPORTS = 2
MAX_REPORTS = 8
MAX_OUTPUT_BYTES = 256_000
MAX_REUSE_GROUP_EXAMPLES = 24
MAX_PAIR_REORDER_EXAMPLES = 8
SHARED_CONTEXT_FIELDS = (
    'signed_request_original_raw_sha256', 'dispute_case_original_raw_sha256',
    'registry_id', 'sequence', 'expected_remote_parent_original_raw_sha256',
    'two_competing_heads_original_raw_sha256', 'target_store_namespace_id',
)
REQUIRED_COMPARE_KEYS = frozenset({
    'branch_a_ledger_file', 'expected_branch_a_ledger_sha256',
    'branch_b_ledger_file', 'expected_branch_b_ledger_sha256',
    'request_file', 'expected_request_sha256', 'case_file', 'expected_case_sha256',
    'left', 'right', 'registry_id', 'expected_sequence',
    'expected_prior_registry_sha256', 'request_id',
    'target_store_namespace_id', 'eighth_signer_id',
    'eighth_signer_public_hex', 'request_challenge_sha256',
})
OPTIONAL_COMPARE_KEYS = frozenset({
    'prior_registry_file', 'branch_a_prior_ledger_file',
    'expected_branch_a_prior_ledger_sha256',
    'branch_b_prior_ledger_file',
    'expected_branch_b_prior_ledger_sha256',
})
# Expose only signed-original SHA and role reuse, NOT filesystem paths.
REUSE_FIELDS = comparison.CROSS_ROLE_FIELDS
# A true here would be a fabricated success or trust escalation.
FALSE_FIELDS = (
    *report.REMOTE_FALSE_FIELDS,
    'manifest_externally_trusted_sha_custody_proven_by_this_tool',
    'physical_independence_or_real_institutional_authority_proven',
    'local_set_proven_to_be_globally_complete_or_latest',
    'a_signed_ec330_report_or_signed_manifest_was_created',
)


def need(condition: Any, reason: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise anchor.AnchorError('EC331_' + reason, status)


def _manifest(manifest_file: str, expected_manifest_sha256: str) -> tuple[dict, bytes]:
    need(type(manifest_file) is str and case.original._valid_path(manifest_file),
         'NORMALIZED_ABSOLUTE_PRIVATE_MANIFEST_PATH_REQUIRED', 'invalid_input')
    document, raw = receipt._load(
        manifest_file, expected_manifest_sha256, MAX_MANIFEST_BYTES,
        'EC331_SEPARATELY_PINNED_MANIFEST_ORIGINAL')
    need(type(document) is dict and set(document) == {'schema', 'reports'} and
         document['schema'] == MANIFEST_SCHEMA and
         type(document['reports']) is list and
         MIN_REPORTS <= len(document['reports']) <= MAX_REPORTS,
         'TWO_TO_EIGHT_EXACT_CANONICAL_REPORT_RECORDS_REQUIRED', 'invalid_input')
    report_files = []
    sources = {manifest_file}
    rows = []
    for observation in document['reports']:
        need(type(observation) is dict and
             set(observation) == {'report_file', 'expected_report_sha256',
                                   'comparison_inputs'} and
             type(observation['report_file']) is str and
             case.original._valid_path(observation['report_file']) and
             receipt._sha(observation['expected_report_sha256']),
             'REPORT_OR_EXTERNAL_WHOLE_SHA_RECORD_INVALID', 'invalid_input')
        kw = observation['comparison_inputs']
        need(type(kw) is dict and
             REQUIRED_COMPARE_KEYS <= set(kw) <=
                 REQUIRED_COMPARE_KEYS | OPTIONAL_COMPARE_KEYS and
             type(kw['expected_sequence']) is int and
             1 <= kw['expected_sequence'] <= 16 and
             all(type(kw[key]) is dict and
                 set(kw[key]) == set(report.SOURCE_SIDE_KEYS)
                 for key in ('left', 'right')),
             'EXACT_EC330_INDEPENDENT_REPLAY_INPUTS_REQUIRED', 'invalid_input')
        # EC330 validates all detailed source-pins. Reject any attempt to use
        # a manifest or report as one of the historical signed source paths.
        input_paths = report._paths(kw)
        need(all(type(path) is str and case.original._valid_path(path)
                 for path in input_paths),
             'HISTORICAL_SIGNED_INPUT_PATH_INVALID', 'invalid_input')
        sources.update(input_paths)
        report_files.append(observation['report_file'])
        rows.append(kw)
    need(len(set(report_files)) == len(report_files) and
         not set(report_files).intersection(sources),
         'SEPARATE_REPORT_FILES_MUST_NOT_ALIAS_MANIFEST_OR_SIGNED_ORIGINALS',
         'invalid_input')
    # Keep caller-specified trust claims: a valid manifest SHA is only useful
    # if the caller REALLY obtained it by a separate trusted channel.
    return document, raw


def _check_result(result: dict, observation: dict) -> None:
    kw = observation['comparison_inputs']
    need(type(result) is dict and
         result.get('schema') == report.RESULT_SCHEMA and
         result.get('status') ==
             'externally_pinned_original_report_replayed_unresolved' and
         result.get('exit_code') == 2 and
         result.get('report_original_raw_sha256') ==
             observation['expected_report_sha256'] and
         result.get('branch_a_ledger_original_raw_sha256') ==
             kw['expected_branch_a_ledger_sha256'] and
         result.get('branch_b_ledger_original_raw_sha256') ==
             kw['expected_branch_b_ledger_sha256'] and
         result.get('original_report_exactly_reconstructed_from_pinned_inputs') is True and
         result.get('all_current_signed_histories_genuinely_replayed_locally') is True and
         result.get('report_is_unsigned_local_result_only') is True and
         all(result.get(flag) is False for flag in report.REMOTE_FALSE_FIELDS),
         'EVERY_EC330_REPORT_MUST_HAVE_GENUINE_REPLAY_AND_UNRESOLVED_RESULT')


def _receipt_reuse(ledgers: dict[str, dict],
                   origins: dict[str, set[str]]) -> tuple[dict, list, int, int, int]:
    """Count each independently verified SIGNED receipt raw SHA only once.

    Identical signed original bytes legitimately copied to another local
    receipt path are *still one* signed opinion. Signed fields must agree;
    local receipt file paths may differ without being a forged signed claim.
    Any two DISTINCT signed receipts sharing a ninth identity/key/nonce/
    decision/path are disclosed but are NOT an external CAS decision.
    """
    unique: dict[str, dict] = {}
    seen_path: dict[str, set[str]] = defaultdict(set)
    seen_in_report: dict[str, set[str]] = defaultdict(set)
    by_role: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ledger_sha, doc in ledgers.items():
        for entry in doc['entries']:
            digest = entry['receipt_original_raw_sha256']
            values = {field: entry[field] for field in
                      (*[k for k in REUSE_FIELDS if k != 'receipt_file'],
                       'disposition', 'reason_code')}
            if digest in unique:
                need(unique[digest] == values,
                     'SAME_SIGNED_RECEIPT_SHA_MUST_HAVE_IDENTICAL_SIGNED_CLAIMS')
            else:
                unique[digest] = values
            seen_path[digest].add(entry['receipt_file'])
            seen_in_report[digest].update(origins[ledger_sha])
            for field in REUSE_FIELDS:
                by_role[field, entry[field]].add(digest)
    collisions = []
    collision_total = 0
    new_cross_report_collision_groups = 0
    for (field, val), receipts in sorted(by_role.items()):
        if len(receipts) <= 1:
            continue
        collision_total += 1
        # An earlier EC330 report already had both receipts iff at least one
        # of its own two verified ledgers saw both. Distinguish that from a
        # collision which only the cross-report union could expose.
        only_new = any(not (seen_in_report[a] & seen_in_report[b])
                       for a, b in combinations(sorted(receipts), 2))
        new_cross_report_collision_groups += bool(only_new)
        if len(collisions) < MAX_REUSE_GROUP_EXAMPLES:
            # Avoid echoing source filesystem paths or plaintext identities.
            fingerprint = hashlib.sha256(
                b'CES/EC331/reused-field/v1\0' + field.encode() + b'\0' +
                val.encode('utf-8')).hexdigest()
            collisions.append({
                'reused_field': field,
                'reused_value_domain_sha256': fingerprint,
                'distinct_signed_receipt_count': len(receipts),
                'sample_receipt_original_raw_sha256': sorted(receipts)[:8],
                'some_collision_pair_only_cross_observed_in_report_set': only_new,
            })
    return (
        {value: sum(row['disposition'] == value for row in unique.values())
         for value in sorted(ninth.DISPOSITIONS)},
        collisions, collision_total, new_cross_report_collision_groups,
        sum(len(paths) > 1 for paths in seen_path.values()),
    )


def _pair_relation(sha_a: str, a: dict, sha_b: str, b: dict,
                   coobserved: bool) -> dict:
    ar, br = a['entries'], b['entries']
    prefix = 0
    for ea, eb in zip(ar, br):
        if ea != eb:
            break
        prefix += 1
    a_receipts = {x['receipt_original_raw_sha256']: (i, x)
                  for i, x in enumerate(ar, 1)}
    b_receipts = {x['receipt_original_raw_sha256']: (i, x)
                  for i, x in enumerate(br, 1)}
    common = sorted(set(a_receipts) & set(b_receipts))
    reorders = [sha for sha in common
                if a_receipts[sha][0] != b_receipts[sha][0]]
    changed_unsigned_rows = [sha for sha in common
                             if a_receipts[sha][1] != b_receipts[sha][1]]
    a_prev, b_prev = (a['previous_ledger_original_raw_sha256'],
                      b['previous_ledger_original_raw_sha256'])
    # All direct predecessors were separately whole-SHA-pinned and actually
    # checked by EC328's real exact-one-row append verification. No inference
    # from row prefix alone can manufacture a missing intermediate snapshot.
    if (a_prev == sha_b and len(ar) == len(br) + 1 and ar[:-1] == br):
        classification = 'verified_direct_one_row_append_b_to_a_unresolved'
    elif (b_prev == sha_a and len(br) == len(ar) + 1 and br[:-1] == ar):
        classification = 'verified_direct_one_row_append_a_to_b_unresolved'
    elif (a_prev == b_prev != ledger.ZERO and len(ar) == len(br) and
          len(ar) > 1 and prefix == len(ar) - 1):
        classification = 'verified_two_distinct_one_row_appends_to_same_parent_unresolved'
    elif len(ar) == len(br) == prefix:
        classification = 'same_signed_rows_different_unsigned_snapshot_unresolved'
    elif prefix == min(len(ar), len(br)):
        classification = 'common_signed_row_prefix_unproven_indirect_ancestry_unresolved'
    elif common:
        classification = 'reordered_or_divergent_signed_receipts_unresolved'
    else:
        classification = 'no_shared_signed_receipt_and_no_proven_ancestry_unresolved'
    return {
        'ledger_a_original_raw_sha256': sha_a,
        'ledger_b_original_raw_sha256': sha_b,
        'relationship': classification,
        'previous_sha_equal_and_nonzero': a_prev == b_prev != ledger.ZERO,
        'common_exact_signed_row_prefix_length': prefix,
        'shared_distinct_signed_receipt_count': len(common),
        'same_signed_receipts_reordered_count': len(reorders),
        'same_signed_receipts_with_different_local_row_metadata_count':
            len(changed_unsigned_rows),
        'sample_reordered_original_receipt_raw_sha256': reorders[:MAX_PAIR_REORDER_EXAMPLES],
        'both_ledgers_coobserved_in_a_replayed_ec330_report': coobserved,
        'new_pair_relationship_only_visible_across_reports': not coobserved,
    }


def cross_reference(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    """Only read, fully replay, correlate and pin; output always unresolved.

    A supplied expected SHA is a CLAIM of an external trust anchor, not an
    independently trusted channel proven by this function. No network I/O.
    """
    manifest, original = _manifest(manifest_file, expected_manifest_sha256)
    items = manifest['reports']
    ledgers: dict[str, dict] = {}
    origins: dict[str, set[str]] = defaultdict(set)
    coobserved: set[tuple[str, str]] = set()
    context: dict | None = None
    report_tally: Counter[str] = Counter()
    original_report_bytes: dict[str, bytes] = {}
    all_source_paths = {manifest_file, *(row['report_file'] for row in items)}
    for observation in items:
        kw = observation['comparison_inputs']
        verified = report.verify_report(
            report_file=observation['report_file'],
            expected_report_sha256=observation['expected_report_sha256'], **kw)
        _check_result(verified, observation)
        pinned_doc, raw = receipt._load(
            observation['report_file'], observation['expected_report_sha256'],
            report.MAX_REPORT_BYTES, 'EC331_RECHECK_FULL_EC330_REPORT_ORIGINAL')
        need(pinned_doc.get('schema') == report.REPORT_SCHEMA and
             pinned_doc['recomputed_ec329_comparison']['relationship'] ==
                 verified['relationship'] and
             hmac.compare_digest(case.sha(raw), observation['expected_report_sha256']),
             'PINNED_EC330_REPORT_MUST_EQUAL_GENUINELY_REPLAYED_COMPARISON')
        original_report_bytes[observation['report_file']] = raw
        comparison_result = pinned_doc['recomputed_ec329_comparison']
        new_context = {key: comparison_result[key] for key in SHARED_CONTEXT_FIELDS}
        new_context['request_id'] = comparison_result['request_id']
        if context is None:
            context = new_context
        else:
            need(context == new_context,
                 'INDEPENDENT_REPORTS_HAVE_DIFFERENT_SIGNED_REQUEST_CONTEXT',
                 'invalid_input')
        report_sha = observation['expected_report_sha256']
        report_tally[report_sha] += 1
        for side in ('a', 'b'):
            sha = kw[f'expected_branch_{side}_ledger_sha256']
            doc = comparison._load_snapshot(
                kw[f'branch_{side}_ledger_file'], sha,
                f'EC331_RECHECK_EC328_LEDGER_{side.upper()}')
            for row in doc['entries']:
                need(row['receipt_file'] not in all_source_paths,
                     'SIGNED_RECEIPT_PATH_MUST_NOT_ALIAS_MANIFEST_OR_REPORT',
                     'invalid_input')
            if sha in ledgers:
                need(ledgers[sha] == doc,
                     'SAME_LEDGER_RAW_SHA_MUST_HAVE_IDENTICAL_CONTENT')
            else:
                ledgers[sha] = doc
            origins[sha].add(report_sha)
        current_pair = tuple(sorted((kw['expected_branch_a_ledger_sha256'],
                                     kw['expected_branch_b_ledger_sha256'])))
        if current_pair[0] != current_pair[1]:
            coobserved.add(current_pair)
    need(context is not None and len(ledgers) >= 1,
         'NO_VERIFIED_LOCAL_LEDGER_OBSERVATIONS', 'invalid_input')
    # EC330 replays force a shared old signed request; reject any attempt to
    # combine a different signed eighth context by accident or manipulation.
    for doc in ledgers.values():
        need(all(doc[field] == context[field]
                 for field in SHARED_CONTEXT_FIELDS),
             'LEDGER_CONTEXT_CONTRADICTS_SAME_SIGNED_EIGHTH_REQUEST')
    pairs = [_pair_relation(a, ledgers[a], b, ledgers[b], (a, b) in coobserved)
             for a, b in combinations(sorted(ledgers), 2)]
    (disposition_counts, collisions, collision_total,
     cross_only_collision_total, duplicate_signed_original_paths) = (
         _receipt_reuse(ledgers, origins))
    total_unique_receipts = sum(disposition_counts.values())
    nodes = [{
        'ledger_original_raw_sha256': sha,
        'immediate_predecessor_original_raw_sha256':
            ledgers[sha]['previous_ledger_original_raw_sha256'],
        'review_count': len(ledgers[sha]['entries']),
        'ledger_head_entry_commitment_sha256':
            ledgers[sha]['ledger_head_entry_commitment_sha256'],
        'seen_in_distinct_report_original_raw_sha256': sorted(origins[sha]),
    } for sha in sorted(ledgers)]
    # Final late whole-original reads: every report, every original signed
    # receipt, predecessor, request, dispute, channels, capsule, old parents,
    # and the manifest. This closes the entire bounded batch mutation window.
    for observation in items:
        kw = observation['comparison_inputs']
        report._recheck_all_pinned_inputs(kw)
        _, late = receipt._load(
            observation['report_file'], observation['expected_report_sha256'],
            report.MAX_REPORT_BYTES, 'EC331_FINAL_REPORT_ORIGINAL')
        need(hmac.compare_digest(late, original_report_bytes[observation['report_file']]),
             'REPORT_ORIGINAL_CHANGED_DURING_ALL_SIGNED_HISTORY_REPLAYS')
    _, late_manifest = _manifest(manifest_file, expected_manifest_sha256)
    need(hmac.compare_digest(late_manifest, original),
         'MANIFEST_ORIGINAL_CHANGED_DURING_FULL_SIGNED_HISTORY_REPLAYS')
    result = {
        'schema': RESULT_SCHEMA,
        'command': 'compare-report-set',
        'status': 'finite_locally_observed_unsigned_report_set_cross_referenced_unresolved',
        'exit_code': 2,
        'manifest_original_raw_sha256': expected_manifest_sha256,
        'manifest_original_byte_length': len(original),
        'report_observation_count': len(items),
        'distinct_report_original_raw_sha_count': len(report_tally),
        'duplicate_report_observation_count': len(items) - len(report_tally),
        'observed_reports_not_new_signed_votes': [
            {'report_original_raw_sha256': sha, 'observed_original_file_count': n}
            for sha, n in sorted(report_tally.items())],
        'shared_signed_request_context': context,
        'distinct_verified_ledger_original_count': len(ledgers),
        'verified_local_ledger_nodes': nodes,
        'ledger_pair_count': len(pairs),
        'new_cross_report_pair_count': sum(
            x['new_pair_relationship_only_visible_across_reports'] for x in pairs),
        'ledger_pair_relationships': pairs,
        'deduplicated_unique_signed_ninth_receipt_original_count':
            total_unique_receipts,
        'deduplicated_signed_offline_disposition_counts': disposition_counts,
        'different_offline_opinions_locally_observed':
            sum(v > 0 for v in disposition_counts.values()) > 1,
        'cross_report_distinct_signed_receipt_reused_ninth_role_groups':
            collision_total,
        'new_ninth_role_reuse_groups_only_revealed_across_reports':
            cross_only_collision_total,
        'same_signed_receipt_raw_sha_seen_at_multiple_local_paths_count':
            duplicate_signed_original_paths,
        'cross_report_ninth_role_reuse_group_examples': collisions,
        'cross_report_ninth_role_reuse_groups_truncated':
            collision_total > len(collisions),
        'every_listed_report_and_both_signed_histories_replayed': True,
        'all_original_source_sha_pins_rechecked_after_batch': True,
        'all_pins_require_separate_real_world_external_trust': True,
        'report_and_manifest_are_unsigned_local_observation_only': True,
        **{field: False for field in FALSE_FIELDS},
    }
    need(len(receipt._raw(result)) <= MAX_OUTPUT_BYTES,
         'CROSS_REPORT_LOCAL_OUTPUT_EXCEEDS_FIXED_BUDGET', 'invalid_input')
    return result

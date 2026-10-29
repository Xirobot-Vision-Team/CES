#!/usr/bin/env python3
"""EC329 read-only comparison of TWO independently pinned EC328 originals.

Both original ledgers (and each immediate predecessor, if present) are first
independently validated by the real EC328 -> EC327 -> EC326 -> EC325 -> EC294
production verification chain, including all ninth Ed25519 signatures. The
result describes locally OBSERVED relationship only: an unsigned hash link is
neither a remote CAS proof nor an externally complete or time-ordered history.

Do not infer a winner, organizational authority, actual nonexecution, or
remote latest state from even matching or direct-parent snapshots.
"""
from __future__ import annotations

from typing import Any

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt as r
from conditional_conflict_hold import hold
from offline_hold_disposition import disposition as ninth
from offline_review_ledger import ledger

RESULT_SCHEMA = 'ces.ec329.offline_review_dual_ledger_comparison.v1'
DENIAL_SCHEMA = 'ces.ec329.offline_review_dual_ledger_comparison_denial.v1'
ZERO = ledger.ZERO
FALSE_FIELDS = (
    'external_atomic_cas_or_worm_write_performed',
    'actual_external_nonexecution_or_hold_proven',
    'remote_global_latest_or_winner_proven',
    'organizational_identity_or_global_history_completeness_proven',
    'two_pins_alone_prove_global_uniqueness_or_authoritative_order',
    'business_or_external_store_writes_performed',
)
CROSS_ROLE_FIELDS = (
    'ninth_responder_id', 'ninth_responder_public_hex',
    'response_challenge_sha256', 'decision_id', 'receipt_file',
)


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC329_' + code, status)


def _load_snapshot(file: str, pinned_sha: str, label: str) -> dict:
    doc, _ = r._load(file, pinned_sha, ledger.MAX_LEDGER_BYTES, label)
    return ledger._validate_ledger(doc)


def _recheck_originals(*, snapshot_a: dict, snapshot_b: dict,
                       branch_a_file: str, expected_branch_a_sha256: str,
                       branch_b_file: str, expected_branch_b_sha256: str,
                       branch_a_prior_file: str | None,
                       expected_branch_a_prior_sha256: str,
                       branch_b_prior_file: str | None,
                       expected_branch_b_prior_sha256: str,
                       request_file: str, expected_request_sha256: str,
                       case_file: str, expected_case_sha256: str,
                       left: dict, right: dict,
                       expected_prior_registry_sha256: str,
                       prior_registry_file: str | None) -> None:
    """Close the cross-verification mutation window with original raw pins."""
    for doc, path, sha, label in (
        (snapshot_a, branch_a_file, expected_branch_a_sha256, 'EC329_FINAL_A_LEDGER'),
        (snapshot_b, branch_b_file, expected_branch_b_sha256, 'EC329_FINAL_B_LEDGER'),
    ):
        reread = _load_snapshot(path, sha, label)
        need(reread == doc, 'SIGNED_REVIEW_LEDGER_CHANGED_DURING_COMPARISON')
        for row in doc['entries']:
            r._load(row['receipt_file'], row['receipt_original_raw_sha256'],
                    ninth.MAX_RECEIPT_BYTES, 'EC329_FINAL_NINTH_ORIGINAL')
    for file, sha in ((branch_a_prior_file, expected_branch_a_prior_sha256),
                      (branch_b_prior_file, expected_branch_b_prior_sha256)):
        if file is not None:
            _load_snapshot(file, sha, 'EC329_FINAL_IMMEDIATE_PREDECESSOR')
    r._load(request_file, expected_request_sha256, hold.MAX_REQUEST_BYTES,
            'EC329_FINAL_EIGHTH_SIGNED_REQUEST')
    r._load(case_file, expected_case_sha256, hold.proof.MAX_CASE_BYTES,
            'EC329_FINAL_ORIGINAL_DISPUTE')
    for side in (left, right):
        r._load(side['registry_file'], side['expected_registry_sha256'],
                r.MAX_SNAPSHOT, 'EC329_FINAL_SIGNED_BRANCH_HEAD')
        origin, _ = r._load(side['origin_file'], side['expected_origin_sha256'],
                            r.MAX_CHANNEL, 'EC329_FINAL_ORIGINAL_CHANNEL')
        r._load(side['recipient_file'], side['expected_recipient_sha256'],
                r.MAX_CHANNEL, 'EC329_FINAL_RECIPIENT_CHANNEL')
        hold.capsule._file(side['capsule_file'], hold.capsule.MAX_ARCHIVE,
                           origin['capsule_original_raw_sha256'],
                           'EC329_FINAL_UNCHANGED_SIGNED_CAPSULE')
    if prior_registry_file is not None:
        r._load(prior_registry_file, expected_prior_registry_sha256,
                r.MAX_SNAPSHOT, 'EC329_FINAL_COMMON_SIGNED_PARENT')


def _compare_rows(a: dict, b: dict, a_sha: str, b_sha: str) -> dict:
    """Compare signed opinions, not fabricated timestamps or authoritative heads."""
    aa, bb = a['entries'], b['entries']
    common = 0
    for one, two in zip(aa, bb):
        if one != two:
            break
        common += 1
    a_pins = {x['receipt_original_raw_sha256'] for x in aa}
    b_pins = {x['receipt_original_raw_sha256'] for x in bb}
    common_pins = a_pins & b_pins
    conflict_rows = []
    misplaced = []
    for i, ea in enumerate(aa, 1):
        for j, eb in enumerate(bb, 1):
            if ea['receipt_original_raw_sha256'] == eb['receipt_original_raw_sha256']:
                if i != j or ea != eb:
                    misplaced.append({'branch_a_position': i, 'branch_b_position': j,
                                      'receipt_original_raw_sha256':
                                          ea['receipt_original_raw_sha256']})
                continue
            duplicated = [k for k in CROSS_ROLE_FIELDS if ea[k] == eb[k]]
            if duplicated:
                conflict_rows.append({
                    'branch_a_position': i, 'branch_b_position': j,
                    'branch_a_receipt_original_raw_sha256':
                        ea['receipt_original_raw_sha256'],
                    'branch_b_receipt_original_raw_sha256':
                        eb['receipt_original_raw_sha256'],
                    'reused_fields': duplicated,
                })
    if a_sha == b_sha:
        relation = 'same_pinned_original_bytes_unresolved'
        need(aa == bb and a == b,
             'IDENTICAL_WHOLE_SHA_CANNOT_HAVE_DIFFERENT_CANONICAL_LEDGER')
    elif common == len(aa) == len(bb):
        relation = 'same_signed_entries_different_unsigned_snapshot_metadata_unresolved'
    elif common == len(aa) and len(bb) == len(aa) + 1 and \
         b['previous_ledger_original_raw_sha256'] == a_sha:
        relation = 'verified_one_entry_append_from_a_to_b_unresolved'
    elif common == len(bb) and len(aa) == len(bb) + 1 and \
         a['previous_ledger_original_raw_sha256'] == b_sha:
        relation = 'verified_one_entry_append_from_b_to_a_unresolved'
    elif common == min(len(aa), len(bb)):
        # A locally equal row prefix does NOT prove missing intermediate
        # whole-ledger snapshots; no unproven transitive ancestry claim.
        relation = 'observed_common_row_prefix_unproven_snapshot_ancestry_unresolved'
    elif (len(aa) == len(bb) == common + 1 and
          a['previous_ledger_original_raw_sha256'] ==
          b['previous_ledger_original_raw_sha256'] != ZERO):
        # Both EC328 verifiers have separately checked the exact same
        # independently pinned predecessor and precisely one appended row.
        relation = 'different_one_row_appends_to_same_pinned_predecessor_unresolved'
    else:
        relation = 'divergent_locally_pinned_signed_review_lists_unresolved'
    all_unique = {row['receipt_original_raw_sha256']: row
                  for row in aa + bb}
    counts = {disposition: sum(row['disposition'] == disposition
                               for row in all_unique.values())
              for disposition in sorted(ninth.DISPOSITIONS)}
    return {
        'relationship': relation,
        'branch_a_review_count': len(aa), 'branch_b_review_count': len(bb),
        'common_exact_entry_prefix_length': common,
        'first_differing_position_if_both_have_an_entry':
            common + 1 if common < min(len(aa), len(bb)) else None,
        'branch_a_first_unshared_entry_receipt_sha256':
            aa[common]['receipt_original_raw_sha256'] if common < len(aa) else None,
        'branch_b_first_unshared_entry_receipt_sha256':
            bb[common]['receipt_original_raw_sha256'] if common < len(bb) else None,
        'common_signed_receipt_raw_sha_count': len(common_pins),
        'unique_signed_receipt_raw_sha_count': len(all_unique),
        'branch_a_only_signed_receipt_raw_sha256': sorted(a_pins - b_pins),
        'branch_b_only_signed_receipt_raw_sha256': sorted(b_pins - a_pins),
        'cross_snapshot_same_receipt_at_different_position_or_with_different_row': misplaced,
        'cross_snapshot_distinct_receipts_with_reused_role_nonce_decision_or_path':
            conflict_rows,
        'cross_snapshot_reused_role_or_nonce_detected': bool(conflict_rows),
        'unique_signed_offline_disposition_counts': counts,
        'distinct_signed_offline_dispositions_detected':
            sum(bool(v) for v in counts.values()) > 1,
        'both_snapshot_rows_equal_and_whole_original_sha_equal': a_sha == b_sha,
        'verified_direct_one_entry_append': relation.startswith('verified_one_entry_append_'),
        'same_independently_pinned_immediate_predecessor_on_both_sides':
            a['previous_ledger_original_raw_sha256'] ==
            b['previous_ledger_original_raw_sha256'] != ZERO,
    }


def compare_ledgers(*,
                    branch_a_ledger_file: str, expected_branch_a_ledger_sha256: str,
                    branch_b_ledger_file: str, expected_branch_b_ledger_sha256: str,
                    request_file: str, expected_request_sha256: str,
                    case_file: str, expected_case_sha256: str,
                    left: dict, right: dict, registry_id: str,
                    expected_sequence: int, expected_prior_registry_sha256: str,
                    request_id: str, target_store_namespace_id: str,
                    eighth_signer_id: str, eighth_signer_public_hex: str,
                    request_challenge_sha256: str,
                    prior_registry_file: str | None = None,
                    branch_a_prior_ledger_file: str | None = None,
                    expected_branch_a_prior_ledger_sha256: str = ZERO,
                    branch_b_prior_ledger_file: str | None = None,
                    expected_branch_b_prior_ledger_sha256: str = ZERO) -> dict:
    """Read-only two individually pinned originals and full REAL replay each.

    Both complete ledger pins and both sets of independently chosen ninth
    identity trust fields must have been authenticated OUTSIDE this process.
    Passing a freshly calculated local digest as the 'trusted pin' is not
    independent pin custody; cryptographic validity is not authorization.
    """
    paths = (branch_a_ledger_file, branch_b_ledger_file)
    need(all(case.original._valid_path(path) for path in paths) and
         paths[0] != paths[1] and
         r._sha(expected_branch_a_ledger_sha256) and
         r._sha(expected_branch_b_ledger_sha256),
         'TWO_SEPARATE_ORIGINAL_LEDGER_PATHS_AND_EXTERNAL_WHOLE_RAW_SHA_PINS_REQUIRED',
         'invalid_input')
    common = dict(request_file=request_file,
                  expected_request_sha256=expected_request_sha256,
                  case_file=case_file, expected_case_sha256=expected_case_sha256,
                  left=left, right=right, registry_id=registry_id,
                  expected_sequence=expected_sequence,
                  expected_prior_registry_sha256=expected_prior_registry_sha256,
                  prior_registry_file=prior_registry_file,
                  request_id=request_id,
                  target_store_namespace_id=target_store_namespace_id,
                  eighth_signer_id=eighth_signer_id,
                  eighth_signer_public_hex=eighth_signer_public_hex,
                  request_challenge_sha256=request_challenge_sha256)
    # Reject direct input aliasing (including ledger-to-ledger-prior) that
    # might turn a supposedly independent pin into a different original.
    # A current snapshot MAY legitimately be its sibling's exact immediate
    # predecessor, but the verifying EC328 append test must prove that fact.
    original_paths = {request_file, case_file}
    if prior_registry_file is not None:
        original_paths.add(prior_registry_file)
    for side in (left, right):
        original_paths.update(side[k] for k in (
            'registry_file', 'capsule_file', 'origin_file', 'recipient_file'))
    need(not set(paths).intersection(original_paths),
         'CURRENT_LEDGER_PATH_CANNOT_ALIAS_SIGNED_ORIGINAL', 'invalid_input')
    for file in (branch_a_prior_ledger_file, branch_b_prior_ledger_file):
        if file is not None:
            need(case.original._valid_path(file) and
                 file not in original_paths,
                 'PREDECESSOR_CANNOT_ALIAS_SIGNED_ORIGINAL', 'invalid_input')
    a = _load_snapshot(branch_a_ledger_file, expected_branch_a_ledger_sha256,
                       'EC329_EXTERNALLY_PINNED_BRANCH_A_LEDGER')
    b = _load_snapshot(branch_b_ledger_file, expected_branch_b_ledger_sha256,
                       'EC329_EXTERNALLY_PINNED_BRANCH_B_LEDGER')
    need(all(a[key] == b[key] for key in ledger.META_FIELDS
             if key != 'previous_ledger_original_raw_sha256'),
         'DIFFERENT_SIGNED_EIGHTH_REQUEST_OR_REGISTRY_PARENT_TWO_HEADS_NAMESPACE',
         'invalid_input')
    need(branch_a_prior_ledger_file != branch_a_ledger_file and
         branch_b_prior_ledger_file != branch_b_ledger_file,
         'LEDGER_CANNOT_BE_ITS_OWN_PREDECESSOR', 'invalid_input')
    a_result = ledger.verify_ledger(
        ledger_file=branch_a_ledger_file,
        expected_ledger_sha256=expected_branch_a_ledger_sha256,
        prior_ledger_file=branch_a_prior_ledger_file,
        expected_prior_ledger_sha256=expected_branch_a_prior_ledger_sha256,
        **common)
    b_result = ledger.verify_ledger(
        ledger_file=branch_b_ledger_file,
        expected_ledger_sha256=expected_branch_b_ledger_sha256,
        prior_ledger_file=branch_b_prior_ledger_file,
        expected_prior_ledger_sha256=expected_branch_b_prior_ledger_sha256,
        **common)
    for result, whole_sha, prior_sha in (
        (a_result, expected_branch_a_ledger_sha256,
         expected_branch_a_prior_ledger_sha256),
        (b_result, expected_branch_b_ledger_sha256,
         expected_branch_b_prior_ledger_sha256),
    ):
        need(result.get('exit_code') == 2 and
             result.get('ledger_original_raw_sha256') == whole_sha and
             result.get('previous_ledger_original_raw_sha256') == prior_sha and
             result.get('signed_request_original_raw_sha256') == expected_request_sha256 and
             result.get('dispute_case_original_raw_sha256') == expected_case_sha256 and
             result.get('all_ninth_signatures_eighth_signature_and_two_complete_original_histories_verified') is True and
             result.get('signed_offline_opinions_only_not_independent_external_nonexecution_proof') is True and
             all(result.get(k) is False for k in (
                 *ledger.EXPLICIT_FALSE_FIELDS,
                 'business_or_external_store_writes_performed')),
             'BOTH_EC328_VERIFICATIONS_MUST_BE_GENUINE_UNRESOLVED_AND_NO_REMOTE_SUCCESS')
    comparison = _compare_rows(a, b, expected_branch_a_ledger_sha256,
                               expected_branch_b_ledger_sha256)
    _recheck_originals(
        snapshot_a=a, snapshot_b=b,
        branch_a_file=branch_a_ledger_file,
        expected_branch_a_sha256=expected_branch_a_ledger_sha256,
        branch_b_file=branch_b_ledger_file,
        expected_branch_b_sha256=expected_branch_b_ledger_sha256,
        branch_a_prior_file=branch_a_prior_ledger_file,
        expected_branch_a_prior_sha256=expected_branch_a_prior_ledger_sha256,
        branch_b_prior_file=branch_b_prior_ledger_file,
        expected_branch_b_prior_sha256=expected_branch_b_prior_ledger_sha256,
        request_file=request_file, expected_request_sha256=expected_request_sha256,
        case_file=case_file, expected_case_sha256=expected_case_sha256,
        left=left, right=right,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file)
    return {
        'status': 'two_independently_pinned_offline_review_snapshots_compared_unresolved',
        'exit_code': 2,
        'branch_a_ledger_original_raw_sha256': expected_branch_a_ledger_sha256,
        'branch_b_ledger_original_raw_sha256': expected_branch_b_ledger_sha256,
        'branch_a_previous_ledger_original_raw_sha256':
            expected_branch_a_prior_ledger_sha256,
        'branch_b_previous_ledger_original_raw_sha256':
            expected_branch_b_prior_ledger_sha256,
        'branch_a_head_entry_commitment_sha256':
            a['ledger_head_entry_commitment_sha256'],
        'branch_b_head_entry_commitment_sha256':
            b['ledger_head_entry_commitment_sha256'],
        'signed_request_original_raw_sha256': expected_request_sha256,
        'dispute_case_original_raw_sha256': expected_case_sha256,
        'registry_id': registry_id, 'sequence': expected_sequence,
        'expected_remote_parent_original_raw_sha256':
            expected_prior_registry_sha256,
        'two_competing_heads_original_raw_sha256': sorted((
            left['expected_registry_sha256'], right['expected_registry_sha256'])),
        'request_id': request_id,
        'target_store_namespace_id': target_store_namespace_id,
        **comparison,
        'both_ledgers_all_ninth_signatures_and_eighth_two_original_histories_verified': True,
        'classification_is_local_unsigned_snapshot_relation_only': True,
        **{key: False for key in FALSE_FIELDS},
    }

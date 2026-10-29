#!/usr/bin/env python3
"""EC325: independently replay TWO EC324 local receipt children of one head.

A dispute case is an unsigned deterministic index of facts re-derived from two
externally pinned EC324 snapshots, their independently pinned channels and
their original EC323->EC294 signature chains. It cannot designate a winner,
linearize a concurrent write, or establish the world's latest CAS/WORM head.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt as r

CASE_SCHEMA = 'ces.ec325.offline_sibling_local_receipt_dispute_case.v1'
RESULT_SCHEMA = 'ces.ec325.offline_sibling_local_receipt_result.v1'
DENIAL_SCHEMA = 'ces.ec325.offline_sibling_local_receipt_denial.v1'
MAX_CASE_BYTES = 12_000
SIDE_FIELDS = frozenset((
    'registry_file', 'expected_registry_sha256', 'capsule_file',
    'origin_file', 'expected_origin_sha256', 'recipient_file',
    'expected_recipient_sha256',
))
CASE_FIELDS = frozenset((
    'schema', 'registry_id', 'sequence',
    'independently_pinned_common_parent_raw_sha256',
    'common_prefix_original_raw_sha256', 'proposals',
    'classification', 'two_ec324_current_rows_and_original_signed_histories_replayed',
    'external_linear_cas_worm_latest_or_fork_winner_proven',
    'independent_real_operators_or_trust_channels_authenticated',
    'business_or_external_store_writes_performed',
))
PROPOSAL_FIELDS = frozenset((
    'registry_snapshot_original_raw_sha256',
    'origin_channel_original_raw_sha256',
    'recipient_channel_original_raw_sha256',
    'capsule_original_raw_sha256', 'case_original_raw_sha256',
    'seventh_ack_original_raw_sha256', 'handoff_id', 'origin_operator_id',
    'recipient_operator_id', 'signed_registrar_fork_sequence',
    'last_record_canonical_sha256',
))
CLASSIFICATION = 'two_different_offline_receipt_children_of_one_pinned_parent_not_externally_resolved'


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise anchor.AnchorError('EC325_' + code, status)


def _valid_request(*, left: dict, right: dict, registry_id: str,
                   expected_sequence: int, expected_prior_registry_sha256: str,
                   prior_registry_file: str | None,
                   extra_file: str | None) -> tuple[dict, dict]:
    need(type(left) is dict and type(right) is dict and
         set(left) == SIDE_FIELDS and set(right) == SIDE_FIELDS,
         'EXACT_SEVEN_EXTERNAL_INPUT_FIELDS_PER_PROPOSAL', 'invalid_input')
    need(r._id(registry_id) and type(expected_sequence) is int and
         1 <= expected_sequence <= r.MAX_RECORDS and
         r._sha(expected_prior_registry_sha256, allow_zero=True) and
         ((expected_sequence == 1) ==
          (expected_prior_registry_sha256 == r.ZERO)),
         'REGISTRY_AND_BOUNDED_PARENT_ANCHOR_REQUIRED', 'invalid_input')
    need((prior_registry_file is None) == (expected_sequence == 1),
         'GENESIS_HAS_NO_PRIOR_FILE_NON_GENESIS_MUST_HAVE_ONE',
         'invalid_input')
    for side in (left, right):
        need(all(type(side[k]) is str for k in SIDE_FIELDS),
             'EXACT_FILE_PATHS_AND_SHA_ARGUMENT_TYPES', 'invalid_input')
        r._paths(*(side[k] for k in (
            'registry_file', 'capsule_file', 'origin_file', 'recipient_file')))
        need(all(r._sha(side[k]) for k in (
            'expected_registry_sha256', 'expected_origin_sha256',
            'expected_recipient_sha256')),
            'EVERY_PROPOSAL_HAS_THREE_EXTERNAL_WHOLE_SHA_PINS', 'invalid_input')
        need(len({side['expected_registry_sha256'],
                  side['expected_origin_sha256'],
                  side['expected_recipient_sha256']}) == 3,
             'THREE_DISTINCT_RAW_PINS_PER_PROPOSAL', 'invalid_input')
    need(left['expected_registry_sha256'] != right['expected_registry_sha256'],
         'SAME_RAW_RECEIPT_HEAD_IS_NOT_A_SIBLING_CONFLICT',
         'invalid_input')
    # Both proposals may refer to the SAME immutable original capsule or
    # channel (with valid source pins). Never require independent capsules:
    # two local writes of one original observation can still be a race.
    others = [
        side[k] for side in (left, right) for k in
        ('registry_file', 'capsule_file', 'origin_file', 'recipient_file')
    ]
    need(left['registry_file'] != right['registry_file'],
         'TWO_DISTINCT_SNAPSHOT_FILES_REQUIRED', 'invalid_input')
    if prior_registry_file is not None:
        r._paths(prior_registry_file)
        need(prior_registry_file not in others,
             'PRIOR_FILE_CANNOT_BE_A_CURRENT_INPUT', 'invalid_input')
        others.append(prior_registry_file)
    if extra_file is not None:
        r._paths(extra_file)
        need(extra_file not in others,
             'CASE_FILE_CANNOT_OVERLAP_ORIGINAL_INPUTS', 'invalid_input')
    return left, right


def _prefix(*, left: dict, right: dict, registry_id: str,
            expected_sequence: int, expected_prior_registry_sha256: str,
            prior_registry_file: str | None) -> tuple[dict, dict]:
    a = r._load_snapshot(left['registry_file'],
                         left['expected_registry_sha256'],
                         registry_id, expected_sequence)
    b = r._load_snapshot(right['registry_file'],
                         right['expected_registry_sha256'],
                         registry_id, expected_sequence)
    need(a['records'][-1] != b['records'][-1],
         'NO_DISTINCT_LATEST_RECORDS_ON_THE_TWO_CHILDREN',
         'invalid_input')
    need(a['records'][:-1] == b['records'][:-1],
         'DIFFERENT_LOCAL_ANCESTRY_NOT_SIBLING_CHILDREN',
         'permission_denied')
    if expected_sequence == 1:
        need(not a['records'][:-1] and
             a['records'][-1]['previous_snapshot_raw_sha256'] == r.ZERO and
             b['records'][-1]['previous_snapshot_raw_sha256'] == r.ZERO,
             'GENESIS_CHILDREN_NOT_BOTH_ATTACHED_TO_ZERO_PARENT')
    else:
        prior = r._load_snapshot(prior_registry_file,
                                 expected_prior_registry_sha256,
                                 registry_id, expected_sequence - 1)
        need(a['records'][:-1] == prior['records'] and
             b['records'][:-1] == prior['records'] and
             all(doc['records'][-1]['previous_snapshot_raw_sha256'] ==
                 expected_prior_registry_sha256 for doc in (a, b)),
             'SIBLINGS_NOT_ATTACHED_TO_EXACT_EXTERNAL_PRIOR_ORIGINAL')
    return a, b


def _check_actual_signed_history(side: dict, *, registry_id: str,
                                 expected_sequence: int,
                                 expected_prior_registry_sha256: str) -> dict:
    result = r.verify(**side, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    need(result.get('exit_code') == 2 and
         result.get('status') ==
         'independent_dual_channel_local_fork_receipt_and_all_signed_history_reverified' and
         result.get('registry_snapshot_original_raw_sha256') ==
         side['expected_registry_sha256'] and
         result.get('origin_channel_original_raw_sha256') ==
         side['expected_origin_sha256'] and
         result.get('recipient_channel_original_raw_sha256') ==
         side['expected_recipient_sha256'] and
         result.get('previous_snapshot_raw_sha256') ==
         expected_prior_registry_sha256 and
         result.get('registry_id') == registry_id and
         result.get('sequence') == expected_sequence and
         all(result.get(key) is True for key in (
             'both_external_raw_sha_pinned_channel_documents_agree',
             'seventh_signature_and_complete_original_case_history_reverified',
             'local_snapshot_append_only_and_prefix_sha_linked')) and
         all(result.get(key) is False for key in (
             'physical_independence_organizational_authority_external_worm_cas_latest_or_winner_proven',
             'registry_snapshot_is_an_external_cryptographic_signature',
             'business_or_external_cas_writes_performed')),
         'BOTH_CHILDREN_REQUIRE_INDEPENDENT_EC324_TRUE_SIGNATURE_REPLAYS')
    return result


def _proposal(snapshot: dict, head_sha: str) -> dict:
    row = snapshot['records'][-1]
    return {
        'registry_snapshot_original_raw_sha256': head_sha,
        'origin_channel_original_raw_sha256':
            row['origin_channel_original_raw_sha256'],
        'recipient_channel_original_raw_sha256':
            row['recipient_channel_original_raw_sha256'],
        'capsule_original_raw_sha256': row['capsule_original_raw_sha256'],
        'case_original_raw_sha256': row['case_original_raw_sha256'],
        'seventh_ack_original_raw_sha256':
            row['seventh_ack_original_raw_sha256'],
        'handoff_id': row['handoff_id'],
        'origin_operator_id': row['origin_operator_id'],
        'recipient_operator_id': row['recipient_operator_id'],
        'signed_registrar_fork_sequence': row['signed_registrar_fork_sequence'],
        'last_record_canonical_sha256': r._hash(row),
    }


def _document(*, a: dict, b: dict, left: dict, right: dict,
              registry_id: str, expected_sequence: int,
              expected_prior_registry_sha256: str) -> dict:
    proposals = sorted((
        _proposal(a, left['expected_registry_sha256']),
        _proposal(b, right['expected_registry_sha256']),
    ), key=lambda x: x['registry_snapshot_original_raw_sha256'])
    need(proposals[0]['registry_snapshot_original_raw_sha256'] !=
         proposals[1]['registry_snapshot_original_raw_sha256'],
         'NOT_TWO_DIFFERENT_HEADS', 'invalid_input')
    # r._verify_snapshot already reconstructs the canonical original SHA of
    # every cumulative prefix; compare exact records and external parent too.
    common_prefix_sha = (r.ZERO if expected_sequence == 1
                         else r._hash({**r._empty(registry_id),
                                       'records': a['records'][:-1]}))
    need(common_prefix_sha == expected_prior_registry_sha256,
         'SHARED_PREFIX_NOT_EQUAL_EXTERNAL_PARENT_RAW_SHA')
    return {
        'schema': CASE_SCHEMA,
        'registry_id': registry_id,
        'sequence': expected_sequence,
        'independently_pinned_common_parent_raw_sha256':
            expected_prior_registry_sha256,
        'common_prefix_original_raw_sha256': common_prefix_sha,
        'proposals': proposals,
        'classification': CLASSIFICATION,
        'two_ec324_current_rows_and_original_signed_histories_replayed': True,
        'external_linear_cas_worm_latest_or_fork_winner_proven': False,
        'independent_real_operators_or_trust_channels_authenticated': False,
        'business_or_external_store_writes_performed': False,
    }


def _recheck(*, left: dict, right: dict, registry_id: str,
             expected_sequence: int, expected_prior_registry_sha256: str,
             prior_registry_file: str | None,
             a: dict, b: dict) -> None:
    # Replay can be slow. Recheck every original SHA *after BOTH* replays,
    # including the first branch whose verification happened long ago.
    for side, initial in ((left, a), (right, b)):
        origin, _, _ = r._load_pair(
            origin_file=side['origin_file'],
            expected_origin_sha256=side['expected_origin_sha256'],
            recipient_file=side['recipient_file'],
            expected_recipient_sha256=side['expected_recipient_sha256'],
            registry_id=registry_id,
            expected_sequence=expected_sequence,
            expected_prior_registry_sha256=expected_prior_registry_sha256)
        r._check_again(
            capsule_file=side['capsule_file'],
            origin_file=side['origin_file'],
            expected_origin_sha256=side['expected_origin_sha256'],
            recipient_file=side['recipient_file'],
            expected_recipient_sha256=side['expected_recipient_sha256'],
            prior_registry_file=side['registry_file'],
            expected_prior_registry_sha256=side['expected_registry_sha256'],
            origin=origin)
        now = r._load_snapshot(
            side['registry_file'], side['expected_registry_sha256'],
            registry_id, expected_sequence)
        need(now == initial, 'SOURCE_ORIGINAL_CHANGED_AFTER_SIGNED_REPLAY')
    if prior_registry_file is not None:
        r._load_snapshot(prior_registry_file,
                         expected_prior_registry_sha256,
                         registry_id, expected_sequence - 1)


def derive(*, left: dict, right: dict, registry_id: str,
           expected_sequence: int, expected_prior_registry_sha256: str,
           prior_registry_file: str | None,
           extra_file: str | None = None) -> dict:
    """Derive without writes. Do not accept self-asserted report as evidence."""
    _valid_request(left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file, extra_file=extra_file)
    a, b = _prefix(left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file)
    _check_actual_signed_history(left, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    _check_actual_signed_history(right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    _recheck(left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file, a=a, b=b)
    result = _document(a=a, b=b, left=left, right=right,
        registry_id=registry_id, expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    need(len(r._raw(result)) <= MAX_CASE_BYTES,
         'DISPUTE_CASE_OUTSIDE_BOUNDED_BYTES', 'invalid_input')
    return result


def _result(document: dict, raw_sha: str, command: str) -> dict:
    return {
        'status': ('offline_sibling_local_receipt_dispute_case_created_no_cas'
                   if command == 'create-case' else
                   'offline_sibling_local_receipt_case_independently_reverified'),
        'exit_code': 2,
        'registry_id': document['registry_id'],
        'sequence': document['sequence'],
        'common_parent_original_raw_sha256':
            document['independently_pinned_common_parent_raw_sha256'],
        'dispute_case_original_raw_sha256': raw_sha,
        'proposal_head_original_raw_sha256': [
            x['registry_snapshot_original_raw_sha256']
            for x in document['proposals']],
        'classification': CLASSIFICATION,
        'both_children_current_complete_original_signed_histories_replayed': True,
        'case_is_a_new_signature_or_an_authoritative_cas_decision': False,
        'external_cas_worm_global_latest_or_fork_winner_proven': False,
        'physical_channel_or_operator_independence_proven': False,
        'business_or_external_cas_writes_performed': False,
    }


def create_case(*, out: str, left: dict, right: dict, registry_id: str,
                expected_sequence: int, expected_prior_registry_sha256: str,
                prior_registry_file: str | None = None) -> dict:
    """Create an exclusive owner-private unsigned case; never choose a child."""
    r._paths(out)
    r.bundle._private_parent(out)
    need(not os.path.lexists(out), 'OUTPUT_ALREADY_EXISTS', 'invalid_input')
    doc = derive(left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file, extra_file=out)
    raw = r._raw(doc)
    r._write_exclusive(out, raw)
    return _result(doc, case.sha(raw), 'create-case')


def verify_case(*, case_file: str, expected_case_sha256: str,
                left: dict, right: dict, registry_id: str,
                expected_sequence: int, expected_prior_registry_sha256: str,
                prior_registry_file: str | None = None) -> dict:
    """Independent verify *requires all originals and external raw SHA pins*."""
    r._paths(case_file)
    need(r._sha(expected_case_sha256),
         'INDEPENDENT_CASE_ORIGINAL_RAW_SHA_PIN_REQUIRED', 'invalid_input')
    stored, stored_raw = r._load(
        case_file, expected_case_sha256, MAX_CASE_BYTES, 'DISPUTE_CASE')
    anchor.exact(stored, CASE_FIELDS, 'EC325_CASE_EXACT_FIELDS')
    need(stored['schema'] == CASE_SCHEMA and
         type(stored['proposals']) is list and
         len(stored['proposals']) == 2 and
         all(type(p) is dict and set(p) == PROPOSAL_FIELDS
             for p in stored['proposals']),
         'CASE_SCHEMA_AND_TWO_EXACT_PROPOSALS_REQUIRED', 'invalid_input')
    rebuilt = derive(left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file, extra_file=case_file)
    need(hmac.compare_digest(stored_raw, r._raw(rebuilt)),
         'DISPUTE_CASE_NOT_EQUAL_TWO_REVERIFIED_ORIGINAL_CHILDREN',
         'permission_denied')
    # A case file replaced while old chains replayed cannot be accepted.
    r._load(case_file, expected_case_sha256, MAX_CASE_BYTES, 'RECHECKED_CASE')
    return _result(rebuilt, expected_case_sha256, 'verify-case')

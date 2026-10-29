#!/usr/bin/env python3
"""EC330 deterministic offline comparison report: create an unsigned candidate,
or verify an externally whole-raw-SHA pinned original by FULL EC329 replay.

The embedded JSON is a local, unsigned calculation, not a ninth signature or
independent observer. A separately trusted whole-file SHA and all externally
trusted EC329 material are required for independent verification. A report may
never be used to authenticate its own external pins, institution, or remote CAS.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec326_conditional_conflict_hold import hold
from ec327_offline_hold_disposition import disposition
from ec328_offline_review_ledger import ledger
from ec329_offline_ledger_comparison import comparison

REPORT_SCHEMA = 'ces.ec330.replayable_unsigned_offline_comparison_report.v1'
RESULT_SCHEMA = 'ces.ec330.offline_comparison_report_result.v1'
DENIAL_SCHEMA = 'ces.ec330.offline_comparison_report_denial.v1'
MAX_REPORT_BYTES = 256_000
SOURCE_SIDE_KEYS = (
    'registry_file', 'expected_registry_sha256', 'capsule_file',
    'origin_file', 'expected_origin_sha256', 'recipient_file',
    'expected_recipient_sha256',
)
REMOTE_FALSE_FIELDS = (*comparison.FALSE_FIELDS,
                       'report_proves_independent_external_sha_custody',
                       'report_is_signed_or_organizationally_authorized',
                       'report_itself_proves_full_global_history_or_fork_winner')
UNSIGNED_MEANING = (
    'locally_replayable_unsigned_comparison_only_not_independent_attestation'
)


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC330_' + code, status)


def _paths(kw: dict) -> list[str]:
    paths = [kw[name] for name in (
        'branch_a_ledger_file', 'branch_b_ledger_file', 'request_file', 'case_file')]
    paths += [kw[name] for name in (
        'branch_a_prior_ledger_file', 'branch_b_prior_ledger_file',
        'prior_registry_file') if kw.get(name) is not None]
    for side in (kw['left'], kw['right']):
        paths += [side[k] for k in (
            'registry_file', 'capsule_file', 'origin_file', 'recipient_file')]
    return paths


def _safe_report_path(path: str, kw: dict) -> None:
    need(type(path) is str and case.original._valid_path(path) and
         path not in _paths(kw),
         'REPORT_MUST_HAVE_A_DISTINCT_NORMALIZED_ABSOLUTE_PRIVATE_PATH',
         'invalid_input')


def _source_pin_claim(kw: dict) -> dict:
    """Paths are not embedded. Every claim still requires external custody.

    This is a comparison of externally SUPPLIED claims, not evidence that an
    independent channel ever supplied them. The side files carry actual
    original capsule SHAs and EC328 rows still carry original receipt paths.
    """
    side = {}
    for name in ('left', 'right'):
        item = kw[name]
        need(type(item) is dict and set(item) == set(SOURCE_SIDE_KEYS),
             'ORIGINAL_SIGNED_BRANCH_INPUTS_EXACT', 'invalid_input')
        side[name] = {
            'registry_original_raw_sha256': item['expected_registry_sha256'],
            'origin_channel_original_raw_sha256': item['expected_origin_sha256'],
            'recipient_channel_original_raw_sha256': item['expected_recipient_sha256'],
        }
    return {
        'branch_a_ledger_original_raw_sha256': kw['expected_branch_a_ledger_sha256'],
        'branch_b_ledger_original_raw_sha256': kw['expected_branch_b_ledger_sha256'],
        'branch_a_previous_ledger_original_raw_sha256':
            kw.get('expected_branch_a_prior_ledger_sha256', ledger.ZERO),
        'branch_b_previous_ledger_original_raw_sha256':
            kw.get('expected_branch_b_prior_ledger_sha256', ledger.ZERO),
        'signed_eighth_request_original_raw_sha256': kw['expected_request_sha256'],
        'dispute_case_original_raw_sha256': kw['expected_case_sha256'],
        'registry_id': kw['registry_id'],
        'sequence': kw['expected_sequence'],
        'expected_prior_registry_original_raw_sha256':
            kw['expected_prior_registry_sha256'],
        'request_id': kw['request_id'],
        'target_store_namespace_id': kw['target_store_namespace_id'],
        'eighth_signer_id': kw['eighth_signer_id'],
        'eighth_signer_public_hex': kw['eighth_signer_public_hex'],
        'request_challenge_sha256': kw['request_challenge_sha256'],
        'signed_original_branch_pin_claims': side,
    }


def _strict_comparison_result(result: dict) -> None:
    need(type(result) is dict and result.get('exit_code') == 2 and
         result.get('status') ==
             'two_independently_pinned_offline_review_snapshots_compared_unresolved' and
         result.get('both_ledgers_all_ninth_signatures_and_eighth_two_original_histories_verified') is True and
         result.get('classification_is_local_unsigned_snapshot_relation_only') is True and
         isinstance(result.get('relationship'), str) and
         result['relationship'].endswith('_unresolved') and
         all(result.get(field) is False for field in comparison.FALSE_FIELDS),
         'PARENT_EC329_MUST_HAVE_BOTH_GENUINE_REPLAYS_AND_REMAIN_UNRESOLVED')


def _replay(kw: dict) -> tuple[dict, bytes]:
    """This is the actual EC329 production path, not stored result trust."""
    result = comparison.compare_ledgers(**kw)
    _strict_comparison_result(result)
    document = {
        'schema': REPORT_SCHEMA,
        'interpretation': UNSIGNED_MEANING,
        'source_pin_claims_not_self_authenticating': _source_pin_claim(kw),
        'recomputed_ec329_comparison': {
            'schema': comparison.RESULT_SCHEMA,
            'command': 'compare-ledgers',
            **result,
        },
        'offline_unresolved_exit_code': 2,
        **{field: False for field in REMOTE_FALSE_FIELDS},
    }
    raw = receipt._raw(document)
    need(len(raw) <= MAX_REPORT_BYTES,
         'CANONICAL_REPORT_EXCEEDS_FIXED_LIMIT', 'invalid_input')
    return document, raw


def _recheck_all_pinned_inputs(kw: dict) -> None:
    """Late source pin check after report creation or after long full replay."""
    a = comparison._load_snapshot(
        kw['branch_a_ledger_file'], kw['expected_branch_a_ledger_sha256'],
        'EC330_FINAL_BRANCH_A_ORIGINAL')
    b = comparison._load_snapshot(
        kw['branch_b_ledger_file'], kw['expected_branch_b_ledger_sha256'],
        'EC330_FINAL_BRANCH_B_ORIGINAL')
    comparison._recheck_originals(
        snapshot_a=a, snapshot_b=b,
        branch_a_file=kw['branch_a_ledger_file'],
        expected_branch_a_sha256=kw['expected_branch_a_ledger_sha256'],
        branch_b_file=kw['branch_b_ledger_file'],
        expected_branch_b_sha256=kw['expected_branch_b_ledger_sha256'],
        branch_a_prior_file=kw.get('branch_a_prior_ledger_file'),
        expected_branch_a_prior_sha256=kw.get(
            'expected_branch_a_prior_ledger_sha256', ledger.ZERO),
        branch_b_prior_file=kw.get('branch_b_prior_ledger_file'),
        expected_branch_b_prior_sha256=kw.get(
            'expected_branch_b_prior_ledger_sha256', ledger.ZERO),
        request_file=kw['request_file'],
        expected_request_sha256=kw['expected_request_sha256'],
        case_file=kw['case_file'],
        expected_case_sha256=kw['expected_case_sha256'],
        left=kw['left'], right=kw['right'],
        expected_prior_registry_sha256=kw['expected_prior_registry_sha256'],
        prior_registry_file=kw.get('prior_registry_file'))


def _success(doc: dict, raw: bytes, *, verified: bool) -> dict:
    comparison_result = doc['recomputed_ec329_comparison']
    return {
        'schema': RESULT_SCHEMA,
        'status': ('externally_pinned_original_report_replayed_unresolved'
                   if verified else 'unsigned_candidate_report_created_unresolved'),
        'exit_code': 2,
        'report_original_raw_sha256': case.sha(raw),
        'report_original_byte_length': len(raw),
        'relationship': comparison_result['relationship'],
        'branch_a_ledger_original_raw_sha256':
            comparison_result['branch_a_ledger_original_raw_sha256'],
        'branch_b_ledger_original_raw_sha256':
            comparison_result['branch_b_ledger_original_raw_sha256'],
        'unique_signed_receipt_raw_sha_count':
            comparison_result['unique_signed_receipt_raw_sha_count'],
        'all_current_signed_histories_genuinely_replayed_locally': True,
        'original_report_exactly_reconstructed_from_pinned_inputs': verified,
        'report_is_unsigned_local_result_only': True,
        **{field: False for field in REMOTE_FALSE_FIELDS},
    }


def create_report(*, out: str, **kw: Any) -> dict:
    """Create only after genuine original replays, using 0600/O_EXCL/fsync.

    This does not create or authenticate the *external* expected SHA pin.
    """
    _safe_report_path(out, kw)
    need(not os.path.lexists(out), 'CANDIDATE_OUTPUT_ALREADY_EXISTS',
         'invalid_input')
    doc, raw = _replay(kw)
    # Re-pin immediately before the write, then once again afterwards.
    _recheck_all_pinned_inputs(kw)
    receipt._write_exclusive(out, raw)
    # Remember our own inode for best-effort cleanup. Replacement files must
    # never be unlinked as if they were our candidate.
    created = os.lstat(out)
    try:
        _, readback = receipt._load(
            out, case.sha(raw), MAX_REPORT_BYTES, 'EC330_LOCAL_CANDIDATE_READBACK')
        need(hmac.compare_digest(readback, raw),
             'CANDIDATE_ORIGINAL_CHANGED_ON_READBACK')
        _recheck_all_pinned_inputs(kw)
    except Exception:
        # Only unlink the exact inode that was created in this call. Never
        # remove an unknown replacement when a hostile concurrent actor races.
        try:
            import stat
            st_now = os.lstat(out)
            if (stat.S_ISREG(st_now.st_mode) and
                (st_now.st_dev, st_now.st_ino) == (created.st_dev, created.st_ino)):
                os.unlink(out)
        except OSError:
            pass
        raise
    return _success(doc, raw, verified=False)


def verify_report(*, report_file: str, expected_report_sha256: str,
                  **kw: Any) -> dict:
    """Require an independently trusted entire report SHA and original inputs.

    A signature, timestamp, path, or SHA included inside the report is never
    accepted as authority for any independent expected pin.
    """
    _safe_report_path(report_file, kw)
    need(receipt._sha(expected_report_sha256),
         'REPORT_EXTERNAL_WHOLE_RAW_SHA_REQUIRED', 'invalid_input')
    supplied, raw = receipt._load(
        report_file, expected_report_sha256, MAX_REPORT_BYTES,
        'EC330_EXTERNALLY_PINNED_REPORT')
    need(type(supplied) is dict and
         set(supplied) == {
             'schema', 'interpretation', 'source_pin_claims_not_self_authenticating',
             'recomputed_ec329_comparison', 'offline_unresolved_exit_code',
             *REMOTE_FALSE_FIELDS} and
         supplied.get('schema') == REPORT_SCHEMA and
         supplied.get('interpretation') == UNSIGNED_MEANING and
         type(supplied.get('offline_unresolved_exit_code')) is int and
         supplied['offline_unresolved_exit_code'] == 2 and
         all(supplied.get(field) is False for field in REMOTE_FALSE_FIELDS),
         'REPORT_SCHEMA_AND_UNRESOLVED_SAFETY_FLAGS_MUST_BE_EXACT',
         'invalid_input')
    need(supplied['source_pin_claims_not_self_authenticating'] ==
         _source_pin_claim(kw),
         'REPORT_PIN_CLAIMS_MUST_MATCH_SEPARATE_EXTERNAL_CALLER_INPUTS',
         'invalid_input')
    recomputed, canonical = _replay(kw)
    need(hmac.compare_digest(raw, canonical) and supplied == recomputed,
         'REPORT_NOT_EXACTLY_RECONSTRUCTED_FROM_TRUE_SIGNED_HISTORIES')
    # Another whole-file read and all source reads close the replay race.
    _, late_raw = receipt._load(
        report_file, expected_report_sha256, MAX_REPORT_BYTES,
        'EC330_FINAL_PINNED_REPORT')
    need(hmac.compare_digest(late_raw, canonical),
         'REPORT_MUTATED_DURING_SIGNED_HISTORY_REPLAY')
    _recheck_all_pinned_inputs(kw)
    return _success(recomputed, canonical, verified=True)

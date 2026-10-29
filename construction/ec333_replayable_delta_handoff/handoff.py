#!/usr/bin/env python3
"""EC333: create or independently reconstruct an unsigned EC332 delta original.

A handoff is a *portable file*, not a portable claim of trust: both EC331
manifests and every old signed source still have to be available at their
pinned paths on the verifier's machine. The file is not a signature or CAS
receipt. The producer cannot mint the independently entrusted SHA used by the
receiver; its printed local SHA must be transferred through another channel.

Creation and verification call EC332's actual production ``delta.compare``;
that path replays EC331 -> EC330 -> ... -> EC294 old original signatures for
BOTH manifests and repins inherited raw inputs. Never trust a stored EC332
console output as proof, and never use a digest in the handoff as its own pin.
"""
from __future__ import annotations

import hmac
import os
import stat
from typing import Any

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec330_replayable_comparison_report import report
from ec329_offline_ledger_comparison import comparison
from ec331_offline_report_set_crosscheck import crosscheck
from ec332_pinned_report_set_delta import delta

HANDOFF_SCHEMA = 'ces.ec333.replayable_unsigned_two_set_delta_handoff_original.v1'
RESULT_SCHEMA = 'ces.ec333.offline_delta_handoff_result.v1'
DENIAL_SCHEMA = 'ces.ec333.offline_delta_handoff_denial.v1'
MAX_HANDOFF_BYTES = 320_000
UNSIGNED_MEANING = (
    'unsigned_offline_finite_local_observation_only_requires_independent_'
    'whole_original_sha_and_replay_of_all_prior_signed_sources'
)
FALSE_FIELDS = tuple(dict.fromkeys((
    *delta.FALSE_FIELDS,
    'handoff_itself_is_signed_or_institutionally_authorized',
    'handoff_original_sha_argument_proves_independent_external_custody',
    'handoff_file_proves_signed_remote_cas_worm_or_actual_nonexecution',
    'handoff_can_be_verified_without_both_original_manifests_and_old_signatures',
    'handoff_proves_temporal_order_remote_deletion_or_globally_complete_history',
)))
HANDOFF_FIELDS = frozenset((
    'schema', 'interpretation', 'left_manifest_original_raw_sha256',
    'right_manifest_original_raw_sha256', 'recomputed_ec332_local_delta',
    'offline_unresolved_exit_code', *FALSE_FIELDS,
))


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC333_' + code, status)


def _inputs(*, left_manifest_file: str, left_expected_manifest_sha256: str,
            right_manifest_file: str, right_expected_manifest_sha256: str) -> dict:
    need(type(left_manifest_file) is str and type(right_manifest_file) is str
         and case.original._valid_path(left_manifest_file)
         and case.original._valid_path(right_manifest_file)
         and left_manifest_file != right_manifest_file,
         'TWO_DISTINCT_NORMALIZED_ABSOLUTE_PRIVATE_MANIFEST_PATHS_REQUIRED',
         'invalid_input')
    need(receipt._sha(left_expected_manifest_sha256) and
         receipt._sha(right_expected_manifest_sha256),
         'BOTH_INDEPENDENT_WHOLE_RAW_MANIFEST_SHA_PINS_REQUIRED', 'invalid_input')
    return dict(left_manifest_file=left_manifest_file,
                left_expected_manifest_sha256=left_expected_manifest_sha256,
                right_manifest_file=right_manifest_file,
                right_expected_manifest_sha256=right_expected_manifest_sha256)


def _source_paths(inputs: dict) -> set[str]:
    """Restrict handoff file aliasing, including ninth receipt and old sources.

    This preflight inspects the two independently pinned manifests, without
    granting them any authority. Authentic signature replay follows later.
    """
    paths = {inputs['left_manifest_file'], inputs['right_manifest_file']}
    for side in ('left', 'right'):
        manifest, _ = crosscheck._manifest(
            inputs[f'{side}_manifest_file'], inputs[f'{side}_expected_manifest_sha256'])
        for row in manifest['reports']:
            paths.add(row['report_file'])
            kw = row['comparison_inputs']
            paths.update(report._paths(kw))
            # Current ninth original paths are contained in independently
            # SHA-pinned, canonical EC328 snapshots, including receipt copies.
            for branch in ('a', 'b'):
                doc = comparison._load_snapshot(
                    kw[f'branch_{branch}_ledger_file'],
                    kw[f'expected_branch_{branch}_ledger_sha256'],
                    'EC333_ALIAS_CHECK_EC328_SIGNED_RECEIPT_ORIGINAL')
                paths.update(entry['receipt_file'] for entry in doc['entries'])
                prior_file = kw.get(f'branch_{branch}_prior_ledger_file')
                if prior_file is not None:
                    prior_doc = comparison._load_snapshot(
                        prior_file, kw[f'expected_branch_{branch}_prior_ledger_sha256'],
                        'EC333_ALIAS_CHECK_PREVIOUS_SIGNED_RECEIPT_ORIGINAL')
                    paths.update(entry['receipt_file']
                                 for entry in prior_doc['entries'])
    return paths


def _path_check(handoff_file: str, inputs: dict) -> None:
    need(type(handoff_file) is str and case.original._valid_path(handoff_file),
         'HANDOFF_MUST_USE_NORMALIZED_ABSOLUTE_PRIVATE_FILE_PATH', 'invalid_input')
    need(handoff_file not in _source_paths(inputs),
         'HANDOFF_PATH_MUST_BE_DISTINCT_FROM_ALL_PINNED_ORIGINALS',
         'invalid_input')


def _delta(inputs: dict) -> dict:
    result = delta.compare(**inputs)
    need(type(result) is dict and result.get('schema') == delta.RESULT_SCHEMA
         and result.get('command') == 'compare-report-set-observations'
         and result.get('status') ==
             'two_finite_pinned_unsigned_observation_sets_compared_locally_unresolved'
         and type(result.get('exit_code')) is int and result['exit_code'] == 2
         and result.get('left_manifest_original_raw_sha256') ==
             inputs['left_expected_manifest_sha256']
         and result.get('right_manifest_original_raw_sha256') ==
             inputs['right_expected_manifest_sha256']
         and result.get('both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed')
             is True
         and result.get('both_sets_original_source_report_and_manifest_pins_rechecked_after_union')
             is True
         and result.get('left_and_right_are_labels_not_temporal_claims_or_signed_precedence')
             is True
         and all(result.get(flag) is False for flag in delta.FALSE_FIELDS),
         'REQUIRE_BOTH_GENUINE_EC332_SIGNED_HISTORY_REPLAYS_NOT_UNSIGNED_CACHE')
    return result


def _build(inputs: dict) -> tuple[dict, bytes]:
    result = _delta(inputs)
    document = {
        'schema': HANDOFF_SCHEMA,
        'interpretation': UNSIGNED_MEANING,
        'left_manifest_original_raw_sha256': inputs['left_expected_manifest_sha256'],
        'right_manifest_original_raw_sha256': inputs['right_expected_manifest_sha256'],
        'recomputed_ec332_local_delta': result,
        'offline_unresolved_exit_code': 2,
        **{name: False for name in FALSE_FIELDS},
    }
    raw = receipt._raw(document)
    need(len(raw) <= MAX_HANDOFF_BYTES,
         'CANONICAL_HANDOFF_EXCEEDS_MAX_BYTES', 'invalid_input')
    return document, raw


def _late_repin(inputs: dict) -> None:
    """Repeat every inherited whole-SHA check *after* handling the handoff.

    EC332 already re-pins both manifests/sources after replay and delta
    construction. Repeat here to cover handoff file writing/reconstruction.
    This is non-atomic local observation; cannot prevent ABA or prove WORM.
    """
    for side in ('left', 'right'):
        mf = inputs[f'{side}_manifest_file']
        digest = inputs[f'{side}_expected_manifest_sha256']
        manifest, raw = crosscheck._manifest(mf, digest)
        for row in manifest['reports']:
            kw = row['comparison_inputs']
            report._recheck_all_pinned_inputs(kw)
            receipt._load(row['report_file'], row['expected_report_sha256'],
                          report.MAX_REPORT_BYTES,
                          'EC333_LATE_ORIGINAL_EC330_REPORT_REPIN')
        _, late = crosscheck._manifest(mf, digest)
        need(hmac.compare_digest(late, raw),
             'MANIFEST_CHANGED_BETWEEN_HANDOFF_RECHECKS')


def _summary(*, command: str, raw: bytes, verified: bool, inputs: dict,
             delta_result: dict) -> dict:
    return {
        'schema': RESULT_SCHEMA,
        'command': command,
        'status': ('unsigned_offline_delta_handoff_exactly_reconstructed_unresolved'
                   if verified else 'unsigned_offline_delta_handoff_candidate_created_unresolved'),
        'exit_code': 2,
        'handoff_original_raw_sha256': case.sha(raw),
        'handoff_original_byte_length': len(raw),
        'left_manifest_original_raw_sha256': inputs['left_expected_manifest_sha256'],
        'right_manifest_original_raw_sha256': inputs['right_expected_manifest_sha256'],
        'combined_unique_report_original_count':
            delta_result['combined_unique_report_original_count'],
        'combined_unique_ledger_original_count':
            delta_result['combined_unique_ledger_original_count'],
        'combined_unique_signed_ninth_receipt_original_count':
            delta_result['combined_unique_signed_ninth_receipt_original_count'],
        'handoff_original_exactly_reconstructed_from_both_original_signed_histories':
            verified,
        'both_ec331_manifests_and_all_inherited_old_signed_histories_replayed': True,
        'handoff_and_both_manifest_all_inherited_original_pins_late_rechecked': True,
        'handoff_is_unsigned_and_external_trust_remains_out_of_band': True,
        **{name: False for name in FALSE_FIELDS},
    }


def create_handoff(*, out: str, left_manifest_file: str,
                   left_expected_manifest_sha256: str,
                   right_manifest_file: str,
                   right_expected_manifest_sha256: str) -> dict:
    inputs = _inputs(left_manifest_file=left_manifest_file,
                     left_expected_manifest_sha256=left_expected_manifest_sha256,
                     right_manifest_file=right_manifest_file,
                     right_expected_manifest_sha256=right_expected_manifest_sha256)
    _path_check(out, inputs)
    need(not os.path.lexists(out), 'CANDIDATE_OUTPUT_ALREADY_EXISTS',
         'invalid_input')
    doc, raw = _build(inputs)
    _late_repin(inputs)
    receipt._write_exclusive(out, raw)
    # Readback + late repin; only attempt to unlink the inode we created.
    created = os.lstat(out)
    try:
        _, readback = receipt._load(out, case.sha(raw), MAX_HANDOFF_BYTES,
                                    'EC333_LOCAL_CANDIDATE_READBACK')
        need(hmac.compare_digest(readback, raw),
             'CANDIDATE_ORIGINAL_CHANGED_ON_READBACK')
        _late_repin(inputs)
        _, final_read = receipt._load(out, case.sha(raw), MAX_HANDOFF_BYTES,
                                      'EC333_FINAL_CANDIDATE_REPIN')
        need(hmac.compare_digest(final_read, raw),
             'CANDIDATE_MUTATED_AFTER_SOURCE_REPIN')
    except Exception:
        try:
            current = os.lstat(out)
            if (stat.S_ISREG(current.st_mode) and
                (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)):
                os.unlink(out)
        except OSError:
            pass
        raise
    return _summary(command='create-handoff', raw=raw, verified=False,
                    inputs=inputs, delta_result=doc['recomputed_ec332_local_delta'])


def verify_handoff(*, handoff_file: str, expected_handoff_sha256: str,
                   left_manifest_file: str, left_expected_manifest_sha256: str,
                   right_manifest_file: str,
                   right_expected_manifest_sha256: str) -> dict:
    inputs = _inputs(left_manifest_file=left_manifest_file,
                     left_expected_manifest_sha256=left_expected_manifest_sha256,
                     right_manifest_file=right_manifest_file,
                     right_expected_manifest_sha256=right_expected_manifest_sha256)
    _path_check(handoff_file, inputs)
    need(receipt._sha(expected_handoff_sha256),
         'HANDOFF_TRUSTED_WHOLE_RAW_SHA_FROM_INDEPENDENT_CHANNEL_REQUIRED',
         'invalid_input')
    saved, raw = receipt._load(handoff_file, expected_handoff_sha256,
                               MAX_HANDOFF_BYTES, 'EC333_EXTERNALLY_PINNED_HANDOFF')
    need(type(saved) is dict and set(saved) == HANDOFF_FIELDS
         and saved.get('schema') == HANDOFF_SCHEMA
         and saved.get('interpretation') == UNSIGNED_MEANING
         and type(saved.get('offline_unresolved_exit_code')) is int
         and saved['offline_unresolved_exit_code'] == 2
         and saved.get('left_manifest_original_raw_sha256') ==
             inputs['left_expected_manifest_sha256']
         and saved.get('right_manifest_original_raw_sha256') ==
             inputs['right_expected_manifest_sha256']
         and all(saved.get(name) is False for name in FALSE_FIELDS),
         'HANDOFF_SCHEMA_UNRESOLVED_FLAGS_AND_EXTERNAL_MANIFEST_PINS_EXACT',
         'invalid_input')
    # Never equate pinned unsigned bytes with a signed result: replay real
    # original signatures and reconstruct *every byte* of the entire report.
    rebuilt, canonical = _build(inputs)
    need(saved == rebuilt and hmac.compare_digest(raw, canonical),
         'HANDOFF_NOT_EXACTLY_RECONSTRUCTED_FROM_TWO_SIGNED_HISTORIES')
    _late_repin(inputs)
    _, late = receipt._load(handoff_file, expected_handoff_sha256,
                            MAX_HANDOFF_BYTES, 'EC333_FINAL_HANDOFF_ORIGINAL_REPIN')
    need(hmac.compare_digest(late, canonical),
         'HANDOFF_CHANGED_DURING_FULL_SIGNED_REPLAY')
    return _summary(command='verify-handoff', raw=canonical, verified=True,
                    inputs=inputs, delta_result=rebuilt['recomputed_ec332_local_delta'])

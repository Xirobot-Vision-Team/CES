#!/usr/bin/env python3
"""EC310: offline signature replay for a bounded EC309 observation window.

The current EC309 readback is *fully* reverified via the EC308->EC294
original evidence path, never via a cached audit boolean. Up to sixteen
previous EC309 files are each independently raw-SHA pinned, domain-signed,
nonce pinned and connected in strictly increasing observation sequence.

This is intentionally a SAME-decision SAME-observer SAME-namespace window.
A non-genesis boundary is a separately supplied *opaque* anchor, not a
verified signed history before the window. No actual CAS I/O, issuer,
organizational independence, trusted chronology or global tip is implied.
"""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from registrar_epochs import epochs
from cas_receipt import receipt as cas
from cas_readback import readback as rb

REPORT_SCHEMA = 'ces.ec310.bounded_signed_observer_history_audit.v1'
RESULT_SCHEMA = 'ces.ec310.bounded_signed_observer_history_result.v1'
DENIAL_SCHEMA = 'ces.ec310.bounded_signed_observer_history_denial.v1'
MAX_PREDECESSORS = 16
MAX_AUDIT_REPORT_BYTES = 36_000
PREDECESSOR_FIELDS = frozenset({'file', 'raw_sha256', 'request_nonce_sha256'})
BOUNDARY_FIELDS = frozenset({
    'sequence', 'raw_sha256', 'observed_revision',
})
HISTORY_OK = 'bounded_signed_history_contiguous_and_current_claims_compatible_not_store_proof'
HISTORY_ROLLBACK = 'signed_history_observer_revision_rollback_detected'
HISTORY_EQUIVOCATION = 'signed_history_same_revision_conflicting_heads_detected'
HISTORY_NO_CURRENT_CORROBORATION = 'bounded_signed_history_valid_current_decision_not_corroborated'


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC310_' + code, status)


def _boundary(trust: dict) -> None:
    a.exact(trust, BOUNDARY_FIELDS, 'EC310_BOUNDARY_EXTERNAL_TRUST_FIELDS_REQUIRED')
    seq, sha, revision = trust['sequence'], trust['raw_sha256'], trust['observed_revision']
    need(type(seq) is int and 0 <= seq < rb.MAX_OBSERVER_SEQUENCE,
         'BOUNDARY_SEQUENCE_INVALID')
    if seq == 0:
        need(sha == a.GENESIS and revision is None,
             'GENESIS_BOUNDARY_REQUIRES_ZERO_SHA_NULL_REVISION')
    else:
        need(rb._sha(sha) and sha != a.GENESIS and
             type(revision) is int and 0 <= revision <= cas.MAX_CAS_REVISION,
             'NON_GENESIS_BOUNDARY_REQUIRES_EXTERNAL_RAW_SHA_REVISION')


def _previous_inputs(predecessors: list, current_nonce: str,
                     issuer_nonce: str, latest_sha: str) -> None:
    need(type(predecessors) is list and
         1 <= len(predecessors) <= MAX_PREDECESSORS,
         'ONE_TO_SIXTEEN_INDEPENDENT_PREDECESSOR_RECORDS_REQUIRED', 'invalid_input')
    nonces = {current_nonce, issuer_nonce}
    shas = {latest_sha}
    for idx, item in enumerate(predecessors):
        a.exact(item, PREDECESSOR_FIELDS,
                'EC310_PREDECESSOR_PATH_RAW_SHA_AND_NONCE_REQUIRED')
        need(type(item['file']) is str and
             rb._sha(item['raw_sha256']) and
             item['raw_sha256'] != a.GENESIS and
             rb._sha(item['request_nonce_sha256']) and
             item['request_nonce_sha256'] != a.GENESIS,
             'PREDECESSOR_EXTERNAL_RAW_SHA_OR_NONCE_INVALID')
        need(item['raw_sha256'] not in shas,
             'REPLAYED_OR_DUPLICATED_SIGNED_OBSERVATION_IN_WINDOW')
        need(item['request_nonce_sha256'] not in nonces,
             'REUSED_REQUEST_NONCE_ACROSS_SIGNED_WINDOW')
        shas.add(item['raw_sha256'])
        nonces.add(item['request_nonce_sha256'])


def _previous_scope(claim: dict, latest: dict,
                    pinned_nonce: str) -> None:
    """Every historic signature must bind the same authenticated decision.

    This prevents splicing old observations from a different original CAS
    claim, fork, CAS authority, namespace, observer or original request.
    Historic decision inputs are NOT independently changed within this EC.
    """
    fields = (
        ('registry_id', 'registry_id'),
        ('cas_authority_id', 'cas_authority_id'),
        ('cas_authority_public_hex', 'cas_authority_public_hex'),
        ('cas_store_namespace_id', 'cas_store_namespace_id'),
        ('observer_id', 'observer_id'),
        ('observer_public_hex', 'observer_public_hex'),
        ('ec307_fork_case_raw_sha256', 'original_fork_case_raw_sha256'),
        ('ec307_fork_evidence_raw_sha256', 'original_fork_evidence_raw_sha256'),
        ('ec308_cas_receipt_raw_sha256', 'signed_cas_receipt_raw_sha256'),
        ('ec308_cas_claim_raw_sha256', 'signed_cas_claim_raw_sha256'),
        ('original_cas_request_nonce_sha256', 'original_request_nonce_sha256'),
        ('decision_signed_outcome', 'decision_signed_outcome'),
        ('decision_claimed_revision', 'decision_claimed_cas_revision'),
        ('decision_claimed_head_raw_sha256', 'decision_claimed_head_raw_sha256'),
    )
    need(all(type(claim[src]) is type(latest[dst]) and
             claim[src] == latest[dst] for src, dst in fields),
         'PREDECESSOR_SIGNED_DECISION_OBSERVER_OR_NAMESPACE_SCOPE_CHANGED')
    need(claim['readback_request_nonce_sha256'] == pinned_nonce,
         'PREDECESSOR_NONCE_NOT_INDEPENDENTLY_PINNED')
    need(type(claim['readback_sequence']) is int and
         1 <= claim['readback_sequence'] <= rb.MAX_OBSERVER_SEQUENCE and
         type(claim['observed_cas_revision']) is int and
         0 <= claim['observed_cas_revision'] <= cas.MAX_CAS_REVISION and
         rb._sha(claim['observed_head_chain_raw_sha256']) and
         (claim['previous_readback_observed_revision'] is None or
          (type(claim['previous_readback_observed_revision']) is int and
           0 <= claim['previous_readback_observed_revision'] <= cas.MAX_CAS_REVISION)),
         'PREDECESSOR_SIGNED_SEQUENCE_REVISION_OR_HEAD_INVALID')


def _link(claim: dict, prior: dict) -> None:
    need(claim['readback_sequence'] == prior['sequence'] + 1 and
         claim['previous_readback_raw_sha256'] == prior['raw_sha256'] and
         claim['previous_readback_observed_revision'] == prior['observed_revision'],
         'SIGNED_HISTORY_SEQUENCE_PREDECESSOR_SHA_OR_REVISION_DISCONTINUITY')


def _record(sha: str, claim: dict) -> dict:
    return {
        'sequence': claim['readback_sequence'],
        'raw_sha256': sha,
        'signed_claim_raw_sha256': b.digest(a.canonical(claim)),
        'request_nonce_sha256': claim['readback_request_nonce_sha256'],
        'observed_revision': claim['observed_cas_revision'],
        'observed_head_raw_sha256': claim['observed_head_chain_raw_sha256'],
    }


def evaluate(*, predecessors: list[dict], boundary_trust: dict,
             fork_case_file: str, expected_fork_case_sha256: str,
             fork_evidence_file: str, expected_fork_evidence_sha256: str,
             receipt_file: str, expected_receipt_sha256: str, cas_trust: dict,
             readback_file: str, expected_readback_sha256: str,
             observer_trust: dict) -> dict:
    """Replay the latest original decision and each predecessor's real bytes.

    Requiring explicit independent SHA *and nonce* for each supplied record
    protects the verifier from deriving a trusted history from the received
    JSON itself. A non-genesis boundary's existence is only an assumption.
    """
    _boundary(boundary_trust)
    # EC309 validates independent current pins and role-separated keys.
    # Validate the predecessor tuples before any expensive original replay.
    need(type(observer_trust) is dict and type(cas_trust) is dict,
         'LATEST_EXTERNAL_TRUST_REQUIRED', 'invalid_input')
    _previous_inputs(predecessors,
                     observer_trust.get('expected_readback_request_nonce_sha256'),
                     cas_trust.get('expected_request_nonce_sha256'),
                     expected_readback_sha256)
    initial = rb.evaluate(
        fork_case_file=fork_case_file,
        expected_fork_case_sha256=expected_fork_case_sha256,
        fork_evidence_file=fork_evidence_file,
        expected_fork_evidence_sha256=expected_fork_evidence_sha256,
        receipt_file=receipt_file, expected_receipt_sha256=expected_receipt_sha256,
        cas_trust=cas_trust, readback_file=readback_file,
        expected_readback_sha256=expected_readback_sha256,
        observer_trust=observer_trust)
    _, latest_claim = rb._parse_readback(
        readback_file, expected_readback_sha256)
    # Repeated read of latest uses the pinned raw SHA; no untrusted cache.
    _previous_scope(latest_claim, initial,
                    observer_trust['expected_readback_request_nonce_sha256'])
    items: list[dict] = []
    prior = boundary_trust.copy()
    all_revisions = []
    all_heads = []
    for item in predecessors:
        envelope, claim = rb._parse_readback(item['file'], item['raw_sha256'])
        _previous_scope(claim, initial, item['request_nonce_sha256'])
        _link(claim, prior)
        try:
            io.pub_from_hex(observer_trust['observer_public_hex']).verify(
                bytes.fromhex(envelope['observer_signature_ed25519']),
                rb.DOMAIN + a.canonical(claim))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise a.AnchorError('EC310_PREDECESSOR_OBSERVER_ED25519_SIGNATURE_INVALID',
                                'permission_denied') from exc
        current = _record(item['raw_sha256'], claim)
        items.append(current)
        all_revisions.append(current['observed_revision'])
        all_heads.append(current['observed_head_raw_sha256'])
        prior = {
            'sequence': current['sequence'],
            'raw_sha256': current['raw_sha256'],
            'observed_revision': current['observed_revision'],
        }
    need(prior['sequence'] == observer_trust['expected_previous_readback_sequence'] and
         prior['raw_sha256'] == observer_trust['expected_previous_readback_raw_sha256'] and
         prior['observed_revision'] == observer_trust['expected_previous_readback_observed_revision'],
         'LATEST_EXTERNAL_ANCHOR_MUST_EQUAL_LAST_AUTHENTIC_PREDECESSOR')
    _link(latest_claim, prior)
    latest_record = _record(expected_readback_sha256, latest_claim)
    all_revisions.append(latest_record['observed_revision'])
    all_heads.append(latest_record['observed_head_raw_sha256'])
    regression_pairs = []
    contradictory_pairs = []
    for idx in range(len(items) + 1):
        if idx == 0:
            previous_revision = boundary_trust['observed_revision']
            previous_head = None  # the opaque boundary does not pin a head
        else:
            previous_revision = all_revisions[idx - 1]
            previous_head = all_heads[idx - 1]
        current_revision = all_revisions[idx]
        current_head = all_heads[idx]
        current_sequence = boundary_trust['sequence'] + idx + 1
        if previous_revision is not None and current_revision < previous_revision:
            regression_pairs.append(current_sequence)
        if (previous_revision is not None and previous_head is not None and
                previous_revision == current_revision and previous_head != current_head):
            contradictory_pairs.append(current_sequence)

    if regression_pairs:
        status, exit_code = HISTORY_ROLLBACK, 2
    elif contradictory_pairs:
        status, exit_code = HISTORY_EQUIVOCATION, 2
    elif (initial['status'] == rb.SAME and
          initial['decision_signed_outcome'] == 'compare_exchange_committed_claim'):
        status, exit_code = HISTORY_OK, 0
    else:
        status, exit_code = HISTORY_NO_CURRENT_CORROBORATION, 2
    candidate = (initial['signed_claims_corroborate_selected_candidate_raw_sha256']
                 if exit_code == 0 else None)
    report = {
        'schema': REPORT_SCHEMA,
        'status': status,
        'exit_code': exit_code,
        'current_ec309_status': initial['status'],
        'registry_id': initial['registry_id'],
        'cas_store_namespace_id': initial['cas_store_namespace_id'],
        'observer_id': initial['observer_id'],
        'observer_public_hex': initial['observer_public_hex'],
        'cas_authority_id': initial['cas_authority_id'],
        'cas_authority_public_hex': initial['cas_authority_public_hex'],
        'signed_cas_receipt_raw_sha256': initial['signed_cas_receipt_raw_sha256'],
        'signed_current_readback_raw_sha256': expected_readback_sha256,
        'signed_original_claim_raw_sha256': initial['signed_cas_claim_raw_sha256'],
        'recomputed_ec309_audit_raw_sha256': b.digest(b.canonical(initial)),
        'history_window_boundary_sequence': boundary_trust['sequence'],
        'history_window_boundary_raw_sha256': boundary_trust['raw_sha256'],
        'history_window_boundary_observed_revision': boundary_trust['observed_revision'],
        'history_window_previous_count': len(items),
        'history_window_signed_records': items,
        'current_signed_record': latest_record,
        'history_from_genesis_to_current_included': boundary_trust['sequence'] == 0,
        'history_before_non_genesis_boundary_replayed': False,
        'history_window_revision_regression_at_sequences': regression_pairs,
        'history_window_same_revision_conflict_at_sequences': contradictory_pairs,
        'selected_candidate_corroborated_by_consistent_signed_window_raw_sha256': candidate,
        'each_predecessor_complete_raw_sha_independently_required': True,
        'each_predecessor_observer_ed25519_signature_verified': True,
        'each_predecessor_nonce_independently_required_and_unique_within_window': True,
        'same_observer_namespace_original_signed_decision_enforced': True,
        'original_ec294_through_ec309_current_decision_and_signature_replayed': True,
        'previous_physical_external_cas_reads_verified': False,
        'independent_organizational_authority_or_nonce_global_freshness_verified': False,
        'real_cas_commit_or_global_latest_proven': False,
        'business_or_external_cas_write_performed': False,
        'private_signing_key_loaded': False,
    }
    need(len(b.canonical(report)) + 1 <= MAX_AUDIT_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_PROTOCOL_BUDGET', 'invalid_input')
    return report


def result_from_report(report: dict) -> dict:
    return {
        'status': report['status'],
        'exit_code': report['exit_code'],
        'signed_current_readback_raw_sha256': report['signed_current_readback_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'history_window_previous_count': report['history_window_previous_count'],
        'history_from_genesis_to_current_included': report['history_from_genesis_to_current_included'],
        'history_window_revision_regression_at_sequences': report['history_window_revision_regression_at_sequences'],
        'history_window_same_revision_conflict_at_sequences': report['history_window_same_revision_conflict_at_sequences'],
        'current_ec309_status': report['current_ec309_status'],
        'selected_candidate_corroborated_by_consistent_signed_window_raw_sha256':
            report['selected_candidate_corroborated_by_consistent_signed_window_raw_sha256'],
        'original_signed_decision_and_current_observation_replayed': True,
        'bounded_predecessor_signatures_and_links_fully_replayed': True,
        'real_external_cas_read_or_global_latest_proven': False,
        'business_or_store_write_performed': False,
    }


def verify(*, out: str | None = None, **opts) -> dict:
    report = evaluate(**opts)
    if out is not None:
        store.store(out, report, MAX_AUDIT_REPORT_BYTES)
    result = result_from_report(report)
    result['audit_report_written'] = out is not None
    return result


def verify_report(*, audit_report_file: str,
                  expected_audit_report_sha256: str, **opts) -> dict:
    need(rb._sha(expected_audit_report_sha256) and
         expected_audit_report_sha256 != a.GENESIS,
         'AUDIT_RAW_SHA_MUST_BE_INDEPENDENTLY_PINNED')
    saved = epochs._owner_private_read(audit_report_file, expected_audit_report_sha256)
    need(len(b.canonical(saved)) + 1 <= MAX_AUDIT_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_PROTOCOL_BUDGET')
    fresh = evaluate(**opts)
    need(saved == fresh, 'SAVED_HISTORY_AUDIT_DIFFERS_FROM_ALL_SIGNATURE_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result

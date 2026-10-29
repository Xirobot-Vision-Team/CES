#!/usr/bin/env python3
"""EC311: verify 2-8 *different* EC308 decisions and their EC309 readbacks.

Each item owns an independently supplied original EC307 case/fork proof,
EC308 signed receipt, EC309 signed observation, all four raw byte digests,
CAS request nonce and independently specified precondition. The entire
operator manifest is independently raw-SHA pinned outside the manifest.

Unlike EC310, this code does not assume every observation refers to ONE
issuer decision. Each entry runs the UNMODIFIED EC309->EC308->EC307->EC294
cryptographic verifier. One observer namespace/key and CAS authority
must be consistent, and the original readback predecessor raw SHA/sequence/
revision as well as cross-issuer parent revision/head are connected.

This is evidence of mutually consistent *signed claims*, not independent
proof of a live linearizable CAS, global latest, real store, authority or time.
"""
from __future__ import annotations

import os
from typing import Any

from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec306_registrar_epochs import epochs
from ec308_cas_receipt import receipt as cas
from ec309_cas_readback import readback as rb

MANIFEST_SCHEMA = 'ces.ec311.cross_decision_signed_history_manifest.v1'
REPORT_SCHEMA = 'ces.ec311.cross_decision_signed_history_audit.v1'
RESULT_SCHEMA = 'ces.ec311.cross_decision_signed_history_result.v1'
DENIAL_SCHEMA = 'ces.ec311.cross_decision_signed_history_denial.v1'
MAX_DECISIONS = 8
MIN_DECISIONS = 2
MAX_MANIFEST_BYTES = 42_000
MAX_REPORT_BYTES = 45_000
MANIFEST_FIELDS = frozenset({
    'schema', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'observer_id', 'observer_public_hex',
    'boundary', 'decisions',
})
BOUNDARY_FIELDS = frozenset({
    'sequence', 'raw_sha256', 'observed_revision', 'observed_head_raw_sha256',
})
DECISION_FIELDS = frozenset({
    'fork_case_file', 'expected_fork_case_sha256',
    'fork_evidence_file', 'expected_fork_evidence_sha256',
    'receipt_file', 'expected_receipt_sha256',
    'expected_request_nonce_sha256', 'expected_parent_cas_revision',
    'expected_parent_cas_head_sha256', 'readback_file',
    'expected_readback_sha256', 'expected_readback_request_nonce_sha256',
})
GOOD = 'cross_decision_signed_claim_chain_compatible_not_actual_cas_proof'
OBSERVATION_ROLLBACK = 'cross_decision_signed_observer_revision_rollback'
OBSERVATION_EQUIVOCATION = 'cross_decision_same_revision_observer_head_conflict'
PARENT_DISCONTINUITY = 'cross_decision_signed_cas_parent_head_or_revision_discontinuous'
NOT_CORROBORATED = 'cross_decision_signed_issuer_or_observer_claim_not_corroborated'


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC311_' + code, status)


def _path(value: Any) -> bool:
    # Never make current working directory determine which evidence is read.
    return (type(value) is str and 0 < len(value) <= 4000 and
            '\x00' not in value and os.path.isabs(value))


def _external_boundary(value: dict) -> None:
    a.exact(value, BOUNDARY_FIELDS, 'EC311_BOUNDARY_FIELDS_INVALID')
    seq, sha, rev, head = (value[x] for x in (
        'sequence', 'raw_sha256', 'observed_revision',
        'observed_head_raw_sha256'))
    need(type(seq) is int and 0 <= seq <= rb.MAX_OBSERVER_SEQUENCE - MAX_DECISIONS,
         'BOUNDARY_SEQUENCE_MUST_LEAVE_BOUNDED_SEQUENCE_BUDGET', 'invalid_input')
    if seq == 0:
        need(sha == a.GENESIS and rev is None and head is None,
             'GENESIS_BOUNDARY_MUST_HAVE_NULL_REVISION_AND_HEAD')
    else:
        need(rb._sha(sha) and sha != a.GENESIS and
             type(rev) is int and 0 <= rev <= cas.MAX_CAS_REVISION and
             rb._sha(head),
             'NON_GENESIS_BOUNDARY_REQUIRES_INDEPENDENT_SHA_REVISION_AND_HEAD')


def _validate_manifest(manifest: dict) -> None:
    a.exact(manifest, MANIFEST_FIELDS, 'EC311_EXACT_MANIFEST_FIELDS_REQUIRED')
    need(manifest['schema'] == MANIFEST_SCHEMA, 'MANIFEST_SCHEMA_INVALID')
    decisions = manifest['decisions']
    need(type(decisions) is list and MIN_DECISIONS <= len(decisions) <= MAX_DECISIONS,
         'TWO_TO_EIGHT_INDEPENDENT_DECISIONS_REQUIRED', 'invalid_input')
    _external_boundary(manifest['boundary'])
    # Use unchanged original EC308/EC309 format and identity/role checking.
    cas._trust({
        'cas_authority_id': manifest['cas_authority_id'],
        'cas_authority_public_hex': manifest['cas_authority_public_hex'],
        'expected_request_nonce_sha256': 'f'*64,
        'expected_parent_cas_revision': 0,
        'expected_parent_cas_head_sha256': 'e'*64,
    })
    # No anonymous reuse of a public key between CAS issuer and observer.
    rb._validate_observer_trust({
        'cas_store_namespace_id': manifest['cas_store_namespace_id'],
        'observer_id': manifest['observer_id'],
        'observer_public_hex': manifest['observer_public_hex'],
        'expected_readback_request_nonce_sha256': 'f'*64,
        'expected_previous_readback_sequence': 0,
        'expected_previous_readback_raw_sha256': a.GENESIS,
        'expected_previous_readback_observed_revision': None,
    }, cas_nonce='e'*64, cas_public=manifest['cas_authority_public_hex'])
    all_nonces = set()
    cas_receipts = set()
    observer_readbacks = set()
    for entry in decisions:
        a.exact(entry, DECISION_FIELDS, 'EC311_EXACT_DECISION_FIELDS_REQUIRED')
        for name in ('fork_case_file', 'fork_evidence_file',
                     'receipt_file', 'readback_file'):
            need(_path(entry[name]), 'ALL_ORIGINAL_EVIDENCE_PATHS_MUST_BE_ABSOLUTE',
                 'invalid_input')
        for name in ('expected_fork_case_sha256',
                     'expected_fork_evidence_sha256', 'expected_receipt_sha256',
                     'expected_parent_cas_head_sha256',
                     'expected_readback_sha256', 'expected_request_nonce_sha256',
                     'expected_readback_request_nonce_sha256'):
            need(rb._sha(entry[name]), 'ALL_ORIGINAL_SHA_AND_NONCE_PINS_REQUIRED',
                 'invalid_input')
        need(type(entry['expected_parent_cas_revision']) is int and
             0 <= entry['expected_parent_cas_revision'] < cas.MAX_CAS_REVISION,
             'CAS_PARENT_REVISION_INTEGER_INVALID', 'invalid_input')
        cas_receipts.add(entry['expected_receipt_sha256'])
        observer_readbacks.add(entry['expected_readback_sha256'])
        for field in ('expected_request_nonce_sha256',
                      'expected_readback_request_nonce_sha256'):
            nonce = entry[field]
            need(nonce not in all_nonces,
                 'CAS_AND_OBSERVER_QUERY_NONCES_MUST_ALL_BE_UNIQUE')
            all_nonces.add(nonce)
    need(len(cas_receipts) == len(decisions) and
         len(observer_readbacks) == len(decisions),
         'DUPLICATE_SIGNED_CAS_DECISION_OR_READBACK')


def read_manifest(manifest_file: str, expected_manifest_sha256: str) -> dict:
    need(_path(manifest_file), 'ABSOLUTE_EXTERNAL_MANIFEST_PATH_REQUIRED',
         'invalid_input')
    need(rb._sha(expected_manifest_sha256),
         'INDEPENDENT_WHOLE_MANIFEST_RAW_SHA_PIN_REQUIRED', 'invalid_input')
    manifest = epochs._owner_private_read(manifest_file, expected_manifest_sha256)
    need(len(b.canonical(manifest)) + 1 <= MAX_MANIFEST_BYTES,
         'MANIFEST_TOO_LARGE', 'invalid_input')
    _validate_manifest(manifest)
    return manifest


def evaluate(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    """Do not trust a previous audit report: replay all signed original sources."""
    manifest = read_manifest(manifest_file, expected_manifest_sha256)
    boundary, decisions = manifest['boundary'], manifest['decisions']
    previous = {'sequence': boundary['sequence'],
                'raw_sha256': boundary['raw_sha256'],
                'observed_revision': boundary['observed_revision'],
                'observed_head_raw_sha256': boundary['observed_head_raw_sha256']}
    previous_decision: dict | None = None
    verified: list[dict] = []
    regression: list[int] = []
    conflicting_heads: list[int] = []
    broken_cas_parents: list[int] = []
    not_corroborated: list[int] = []
    registry = None
    cas_claims = set()
    for entry in decisions:
        issuer = {
            'cas_authority_id': manifest['cas_authority_id'],
            'cas_authority_public_hex': manifest['cas_authority_public_hex'],
            'expected_request_nonce_sha256': entry['expected_request_nonce_sha256'],
            'expected_parent_cas_revision': entry['expected_parent_cas_revision'],
            'expected_parent_cas_head_sha256': entry['expected_parent_cas_head_sha256'],
        }
        observer = {
            'cas_store_namespace_id': manifest['cas_store_namespace_id'],
            'observer_id': manifest['observer_id'],
            'observer_public_hex': manifest['observer_public_hex'],
            'expected_readback_request_nonce_sha256':
                entry['expected_readback_request_nonce_sha256'],
            'expected_previous_readback_sequence': previous['sequence'],
            'expected_previous_readback_raw_sha256': previous['raw_sha256'],
            'expected_previous_readback_observed_revision':
                previous['observed_revision'],
        }
        # EC309 re-evaluates EC308 -> EC307 -> EC306..EC294 original signatures
        # for EACH independently pinned decision, not just the latest.
        signed = rb.evaluate(
            fork_case_file=entry['fork_case_file'],
            expected_fork_case_sha256=entry['expected_fork_case_sha256'],
            fork_evidence_file=entry['fork_evidence_file'],
            expected_fork_evidence_sha256=entry['expected_fork_evidence_sha256'],
            receipt_file=entry['receipt_file'],
            expected_receipt_sha256=entry['expected_receipt_sha256'],
            cas_trust=issuer, readback_file=entry['readback_file'],
            expected_readback_sha256=entry['expected_readback_sha256'],
            observer_trust=observer)
        # Re-read original Ed25519 claim under the same full raw SHA; previous
        # semantic values are derived from a VERIFIED source, not audit JSON.
        _, claim = rb._parse_readback(entry['readback_file'],
                                      entry['expected_readback_sha256'])
        if registry is None:
            registry = signed['registry_id']
        else:
            need(signed['registry_id'] == registry,
                 'SIGNED_DECISIONS_CANNOT_CHANGE_REGISTRY_ID')
        need(signed['signed_cas_claim_raw_sha256'] not in cas_claims,
             'DUPLICATE_SIGNED_CAS_CLAIM_REPLAY')
        cas_claims.add(signed['signed_cas_claim_raw_sha256'])
        seq, rev, head = (claim[name] for name in (
            'readback_sequence', 'observed_cas_revision',
            'observed_head_chain_raw_sha256'))
        prior_rev, prior_head = (previous['observed_revision'],
                                 previous['observed_head_raw_sha256'])
        if prior_rev is not None:
            if rev < prior_rev:
                regression.append(seq)
            elif rev == prior_rev and prior_head is not None and head != prior_head:
                conflicting_heads.append(seq)
        if previous_decision is not None:
            prior_decision_revision = previous_decision['signed_decision_revision']
            prior_decision_head = previous_decision['signed_decision_head_raw_sha256']
            if (entry['expected_parent_cas_revision'] != prior_decision_revision or
                    entry['expected_parent_cas_head_sha256'] != prior_decision_head):
                broken_cas_parents.append(seq)
            # A signed old observer view is not a sufficient CAS parent to
            # backfill an unverified intervening issuer decision.
            if (previous['observed_revision'] != prior_decision_revision or
                    previous['observed_head_raw_sha256'] != prior_decision_head):
                broken_cas_parents.append(seq)
        elif boundary['sequence'] != 0:
            # For non-genesis windows, the operator's *opaque* external head
            # pin is REQUIRED to match the first issuer's signed precondition.
            if (entry['expected_parent_cas_revision'] != boundary['observed_revision'] or
                    entry['expected_parent_cas_head_sha256'] !=
                        boundary['observed_head_raw_sha256']):
                broken_cas_parents.append(seq)
        if (signed['status'] != rb.SAME or
                signed['decision_signed_outcome'] !=
                    'compare_exchange_committed_claim'):
            not_corroborated.append(seq)
        record = {
            'sequence': seq,
            'signed_readback_raw_sha256': entry['expected_readback_sha256'],
            'signed_readback_claim_raw_sha256': signed['signed_readback_claim_raw_sha256'],
            'signed_cas_receipt_raw_sha256': entry['expected_receipt_sha256'],
            'signed_cas_claim_raw_sha256': signed['signed_cas_claim_raw_sha256'],
            'original_fork_case_raw_sha256': entry['expected_fork_case_sha256'],
            'original_fork_evidence_raw_sha256': entry['expected_fork_evidence_sha256'],
            'original_request_nonce_sha256': entry['expected_request_nonce_sha256'],
            'readback_request_nonce_sha256': entry['expected_readback_request_nonce_sha256'],
            'parent_revision': entry['expected_parent_cas_revision'],
            'parent_head_raw_sha256': entry['expected_parent_cas_head_sha256'],
            'signed_decision_outcome': signed['decision_signed_outcome'],
            'signed_decision_revision': signed['decision_claimed_cas_revision'],
            'signed_decision_head_raw_sha256': signed['decision_claimed_head_raw_sha256'],
            'signed_observer_revision': rev,
            'signed_observer_head_raw_sha256': head,
            'signed_observer_vs_issuer_status': signed['status'],
            'recomputed_full_ec309_audit_sha256': b.digest(b.canonical(signed)),
        }
        verified.append(record)
        previous_decision = record
        previous = {'sequence': seq,
                    'raw_sha256': entry['expected_readback_sha256'],
                    'observed_revision': rev, 'observed_head_raw_sha256': head}

    # Detect all anomalies, with deterministic precedence and no winning
    # branch on any non-committed receipt, stale observation, or broken link.
    broken_cas_parents = sorted(set(broken_cas_parents))
    if regression:
        status, exit_code = OBSERVATION_ROLLBACK, 2
    elif conflicting_heads:
        status, exit_code = OBSERVATION_EQUIVOCATION, 2
    elif broken_cas_parents:
        status, exit_code = PARENT_DISCONTINUITY, 2
    elif not_corroborated:
        status, exit_code = NOT_CORROBORATED, 2
    else:
        status, exit_code = GOOD, 0
    # Never select a winner on ANY anomaly. The last candidate is a signed
    # source-only compatibility digest, not an actual CAS state assertion.
    candidate = (verified[-1]['signed_decision_head_raw_sha256']
                 if exit_code == 0 else None)
    report = {
        'schema': REPORT_SCHEMA,
        'status': status,
        'exit_code': exit_code,
        'manifest_raw_sha256': expected_manifest_sha256,
        'registry_id': registry,
        'cas_authority_id': manifest['cas_authority_id'],
        'cas_authority_public_hex': manifest['cas_authority_public_hex'],
        'cas_store_namespace_id': manifest['cas_store_namespace_id'],
        'observer_id': manifest['observer_id'],
        'observer_public_hex': manifest['observer_public_hex'],
        'boundary_sequence': boundary['sequence'],
        'boundary_raw_sha256': boundary['raw_sha256'],
        'boundary_observed_revision': boundary['observed_revision'],
        'boundary_observed_head_raw_sha256': boundary['observed_head_raw_sha256'],
        'observer_genesis_to_current_sequence_included': boundary['sequence'] == 0,
        'outside_window_earlier_cas_decisions_or_observations_replayed': False,
        'complete_decision_and_observation_count': len(verified),
        'signed_decision_observation_records': verified,
        'observer_revision_regression_at_sequences': regression,
        'observer_same_revision_conflicting_head_at_sequences': conflicting_heads,
        'cas_parent_discontinuity_at_sequences': broken_cas_parents,
        'issuer_decision_or_observer_not_corroborated_at_sequences': not_corroborated,
        'last_candidate_sha256_of_consistent_signed_claims_only': candidate,
        'each_decision_full_ec294_through_ec309_original_signatures_replayed': True,
        'each_decision_has_independent_raw_SHA_and_nonce_pins': True,
        'same_registry_namespace_cas_and_observer_signer_enforced': True,
        'signed_observer_full_original_raw_sha_sequence_revision_chain_enforced': True,
        'signed_cas_parent_revision_and_head_transition_compared': True,
        'external_manifest_original_bytes_independently_sha_pinned': True,
        'external_same_physical_cas_store_read_or_write_performed': False,
        'actual_cas_commit_or_global_latest_proven': False,
        'external_signer_organization_authorized_or_keys_custodied_proven': False,
        'nonce_global_freshness_or_trusted_chronology_proven': False,
        'business_or_external_storage_write_performed': False,
        'private_signing_key_loaded': False,
    }
    need(len(b.canonical(report)) + 1 <= MAX_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_BOUND', 'invalid_input')
    return report


def result_from_report(report: dict) -> dict:
    return {
        'status': report['status'],
        'exit_code': report['exit_code'],
        'manifest_raw_sha256': report['manifest_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'complete_decision_and_observation_count':
            report['complete_decision_and_observation_count'],
        'observer_genesis_to_current_sequence_included':
            report['observer_genesis_to_current_sequence_included'],
        'observer_revision_regression_at_sequences':
            report['observer_revision_regression_at_sequences'],
        'observer_same_revision_conflicting_head_at_sequences':
            report['observer_same_revision_conflicting_head_at_sequences'],
        'cas_parent_discontinuity_at_sequences':
            report['cas_parent_discontinuity_at_sequences'],
        'issuer_decision_or_observer_not_corroborated_at_sequences':
            report['issuer_decision_or_observer_not_corroborated_at_sequences'],
        'last_candidate_sha256_of_consistent_signed_claims_only':
            report['last_candidate_sha256_of_consistent_signed_claims_only'],
        'all_original_signed_decision_and_readback_cryptography_replayed': True,
        'real_external_cas_or_global_latest_proven': False,
        'business_or_store_write_performed': False,
    }


def verify(*, manifest_file: str, expected_manifest_sha256: str,
           out: str | None = None) -> dict:
    report = evaluate(manifest_file=manifest_file,
                      expected_manifest_sha256=expected_manifest_sha256)
    if out is not None:
        store.store(out, report, MAX_REPORT_BYTES)
    result = result_from_report(report)
    result['audit_report_written'] = out is not None
    return result


def verify_report(*, manifest_file: str, expected_manifest_sha256: str,
                  audit_report_file: str, expected_audit_report_sha256: str) -> dict:
    need(_path(audit_report_file) and rb._sha(expected_audit_report_sha256),
         'INDEPENDENT_PRIVATE_AUDIT_PATH_AND_RAW_SHA_REQUIRED', 'invalid_input')
    saved = epochs._owner_private_read(audit_report_file,
                                       expected_audit_report_sha256)
    need(len(b.canonical(saved)) + 1 <= MAX_REPORT_BYTES,
         'SAVED_AUDIT_TOO_LARGE', 'invalid_input')
    # Rerun ALL original EC294-309 verification; never trust a saved pass bool.
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256)
    need(saved == fresh,
         'SAVED_AUDIT_REPORT_DIFFERS_FROM_REPLAYED_ORIGINAL_SIGNED_EVIDENCE')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result

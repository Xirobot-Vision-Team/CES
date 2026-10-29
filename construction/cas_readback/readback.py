#!/usr/bin/env python3
"""EC309: independently signed, independently pinned *claimed* CAS readback.

Full EC308 signature/fork replay comes FIRST. Then verify a different
observer's domain-separated Ed25519 signature over a fresh query nonce,
CAS identity/namespace, exact earlier decision bytes, off-band previous
observer anchor and its claimed revision/head. A same-revision match is two
compatible *statements*, NOT proof either signer accessed the same store.

No network read, key loading, external CAS, signer, or business writer exists.
"""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as receiver
from registrar_epochs import epochs
from registrar_forks import operator as fork_operator
from cas_receipt import receipt as cas

READBACK_SCHEMA = 'ces.ec309.external_signed_cas_readback.v1'
CLAIM_SCHEMA = 'ces.ec309.external_cas_readback_claim.v1'
REPORT_SCHEMA = 'ces.ec309.independent_signed_cas_readback_audit.v1'
RESULT_SCHEMA = 'ces.ec309.cas_readback_audit_result.v1'
DENIAL_SCHEMA = 'ces.ec309.cas_readback_audit_denial.v1'
DOMAIN = b'CES/EC309/ExternalCAS/IndependentStateReadback/v1\0'
MAX_READBACK_BYTES = 10_000
MAX_AUDIT_REPORT_BYTES = 16_000
MAX_OBSERVER_SEQUENCE = 2**63 - 2
ENVELOPE_FIELDS = frozenset({'schema', 'claim', 'observer_signature_ed25519'})
CLAIM_FIELDS = frozenset({
    'schema', 'registry_id', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'observer_id', 'observer_public_hex',
    'ec307_fork_case_raw_sha256', 'ec307_fork_evidence_raw_sha256',
    'ec308_cas_receipt_raw_sha256',
    'ec308_cas_claim_raw_sha256', 'original_cas_request_nonce_sha256',
    'readback_request_nonce_sha256', 'decision_signed_outcome',
    'decision_claimed_revision', 'decision_claimed_head_raw_sha256',
    'readback_sequence', 'previous_readback_raw_sha256',
    'previous_readback_observed_revision', 'observed_cas_revision',
    'observed_head_chain_raw_sha256',
})
OBSERVER_TRUST_FIELDS = frozenset({
    'cas_store_namespace_id', 'observer_id', 'observer_public_hex',
    'expected_readback_request_nonce_sha256',
    'expected_previous_readback_sequence',
    'expected_previous_readback_raw_sha256',
    'expected_previous_readback_observed_revision',
})
SAME = 'two_signed_claims_same_revision_head_compatible_not_store_proof'
CONFLICT = 'two_signed_claims_same_revision_conflicting_heads'
LATER = 'signed_readback_claims_later_revision_intervening_history_unknown'
EARLIER = 'signed_readback_claims_earlier_revision_staleness_or_rollback_unknown'
REGRESSION = 'signed_readback_revision_regresses_below_external_observer_anchor'


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC309_' + code, status)


def _sha(value: Any) -> bool:
    return epochs._positive_sha(value)


def _validate_observer_trust(trust: dict, *, cas_nonce: str, cas_public: str) -> None:
    a.exact(trust, OBSERVER_TRUST_FIELDS, 'EC309_EXACT_EXTERNAL_OBSERVER_TRUST_REQUIRED')
    for name in ('cas_store_namespace_id', 'observer_id'):
        need(type(trust[name]) is str and receiver.ID.fullmatch(trust[name]) is not None,
             'INDEPENDENT_OBSERVER_ID_OR_STORE_NAMESPACE_INVALID')
    need(a.valid_pub(trust['observer_public_hex']) and
         trust['observer_public_hex'] != cas_public,
         'OBSERVER_KEY_MUST_BE_VALID_AND_DISTINCT_FROM_CAS_AUTHORITY')
    need(_sha(trust['expected_readback_request_nonce_sha256']) and
         trust['expected_readback_request_nonce_sha256'] != cas_nonce,
         'FRESH_DISTINCT_EXTERNALLY_PINNED_READBACK_NONCE_REQUIRED')
    seq = trust['expected_previous_readback_sequence']
    prev = trust['expected_previous_readback_raw_sha256']
    prev_revision = trust['expected_previous_readback_observed_revision']
    need(type(seq) is int and 0 <= seq < MAX_OBSERVER_SEQUENCE,
         'EXTERNAL_PREVIOUS_OBSERVER_SEQUENCE_INVALID')
    if seq == 0:
        need(prev == a.GENESIS and prev_revision is None,
             'FIRST_OBSERVATION_REQUIRES_GENESIS_AND_NULL_PREVIOUS_REVISION')
    else:
        need(_sha(prev) and type(prev_revision) is int and
             0 <= prev_revision <= cas.MAX_CAS_REVISION,
             'NONFIRST_OBSERVATION_REQUIRES_EXTERNAL_SHA_AND_REVISION_ANCHOR')


def _parse_readback(path: str, raw_sha: str) -> tuple[dict, dict]:
    need(_sha(raw_sha), 'INDEPENDENT_COMPLETE_READBACK_RAW_SHA_REQUIRED')
    # EC306 does 0600/single-link/O_NOFOLLOW, parent 0700, inode before/after,
    # and canonical JSON + LF + whole raw SHA checks. Never accept a self-pin.
    envelope = epochs._owner_private_read(path, raw_sha)
    need(len(b.canonical(envelope)) + 1 <= MAX_READBACK_BYTES,
         'READBACK_EXCEEDS_PROTOCOL_BUDGET')
    a.exact(envelope, ENVELOPE_FIELDS, 'EC309_READBACK_FIELDS_INVALID')
    need(envelope['schema'] == READBACK_SCHEMA, 'READBACK_SCHEMA_INVALID')
    claim = a.exact(envelope['claim'], CLAIM_FIELDS,
                    'EC309_SIGNED_READBACK_CLAIM_FIELDS_INVALID')
    need(claim['schema'] == CLAIM_SCHEMA, 'READBACK_CLAIM_SCHEMA_INVALID')
    signature = envelope['observer_signature_ed25519']
    need(type(signature) is str and a.SIG.fullmatch(signature) is not None,
         'READBACK_SIGNATURE_NOT_LOWERCASE_64_BYTE_HEX')
    return envelope, claim


def evaluate(*, fork_case_file: str, expected_fork_case_sha256: str,
             fork_evidence_file: str, expected_fork_evidence_sha256: str,
             receipt_file: str, expected_receipt_sha256: str,
             cas_trust: dict, readback_file: str, expected_readback_sha256: str,
             observer_trust: dict) -> dict:
    """Replay all real original signatures and compare two signed issuer claims.

    A proven signature is evidence of what a holder of a particular key signed.
    It cannot prove that either holder had access to a real, globally latest
    linearizable store or that the second signer is truly independent.
    """
    # Strict validation of trust pins is done BEFORE the expensive inherited
    # EC308 -> EC307 -> EC294 cryptographic and private original source replay.
    cas._trust(cas_trust)
    _validate_observer_trust(observer_trust,
        cas_nonce=cas_trust['expected_request_nonce_sha256'],
        cas_public=cas_trust['cas_authority_public_hex'])
    need(all(_sha(v) for v in (
        expected_fork_case_sha256, expected_fork_evidence_sha256,
        expected_receipt_sha256, expected_readback_sha256)),
        'FOUR_INDEPENDENT_COMPLETE_RAW_SHA_PINS_REQUIRED')

    verified_cas = cas.evaluate(
        fork_case_file=fork_case_file,
        expected_fork_case_sha256=expected_fork_case_sha256,
        fork_evidence_file=fork_evidence_file,
        expected_fork_evidence_sha256=expected_fork_evidence_sha256,
        receipt_file=receipt_file, expected_receipt_sha256=expected_receipt_sha256,
        trust=cas_trust)

    envelope, claim = _parse_readback(readback_file, expected_readback_sha256)
    need(type(claim['decision_claimed_revision']) is int and
         type(claim['readback_sequence']) is int and
         (claim['previous_readback_observed_revision'] is None if
          observer_trust['expected_previous_readback_observed_revision'] is None
          else type(claim['previous_readback_observed_revision']) is int),
         'SIGNED_READBACK_INTEGER_FIELDS_MUST_BE_STRICT_TYPES')
    need(
        claim['registry_id'] == verified_cas['registry_id'] and
        claim['cas_authority_id'] == cas_trust['cas_authority_id'] and
        claim['cas_authority_public_hex'] == cas_trust['cas_authority_public_hex'] and
        claim['cas_store_namespace_id'] == observer_trust['cas_store_namespace_id'] and
        claim['observer_id'] == observer_trust['observer_id'] and
        claim['observer_public_hex'] == observer_trust['observer_public_hex'] and
        claim['ec307_fork_case_raw_sha256'] == expected_fork_case_sha256 and
        claim['ec307_fork_evidence_raw_sha256'] == expected_fork_evidence_sha256 and
        claim['ec308_cas_receipt_raw_sha256'] == expected_receipt_sha256 and
        claim['ec308_cas_claim_raw_sha256'] ==
            verified_cas['signed_cas_claim_raw_sha256'] and
        claim['original_cas_request_nonce_sha256'] ==
            cas_trust['expected_request_nonce_sha256'] and
        claim['readback_request_nonce_sha256'] ==
            observer_trust['expected_readback_request_nonce_sha256'] and
        claim['decision_signed_outcome'] == verified_cas['issuer_signed_outcome'] and
        claim['decision_claimed_revision'] == verified_cas['observed_cas_revision'] and
        claim['decision_claimed_head_raw_sha256'] ==
            verified_cas['observed_head_chain_raw_sha256'] and
        claim['readback_sequence'] ==
            observer_trust['expected_previous_readback_sequence'] + 1 and
        claim['previous_readback_raw_sha256'] ==
            observer_trust['expected_previous_readback_raw_sha256'] and
        claim['previous_readback_observed_revision'] ==
            observer_trust['expected_previous_readback_observed_revision'],
        'SIGNED_READBACK_NOT_BOUND_TO_REPLAYED_DECISION_AND_EXTERNAL_PINS')

    case = fork_operator.read_case(fork_case_file, expected_fork_case_sha256)
    need(observer_trust['observer_public_hex'] not in cas._known_signer_keys(case),
         'OBSERVER_SIGNER_REUSES_KNOWN_ORIGINAL_SIGNING_ROLE')
    try:
        io.pub_from_hex(observer_trust['observer_public_hex']).verify(
            bytes.fromhex(envelope['observer_signature_ed25519']),
            DOMAIN + a.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise a.AnchorError('EC309_OBSERVER_ED25519_SIGNATURE_INVALID',
                            'permission_denied') from exc

    seq = claim['readback_sequence']
    observed_rev = claim['observed_cas_revision']
    observed_head = claim['observed_head_chain_raw_sha256']
    need(type(seq) is int and 1 <= seq <= MAX_OBSERVER_SEQUENCE and
         type(observed_rev) is int and
         0 <= observed_rev <= cas.MAX_CAS_REVISION and _sha(observed_head),
         'SIGNED_OBSERVER_SEQUENCE_REVISION_OR_HEAD_INVALID')
    decision_rev = verified_cas['observed_cas_revision']
    decision_head = verified_cas['observed_head_chain_raw_sha256']
    prev_rev = observer_trust['expected_previous_readback_observed_revision']
    if prev_rev is not None and observed_rev < prev_rev:
        relation = REGRESSION
    elif observed_rev == decision_rev:
        relation = SAME if observed_head == decision_head else CONFLICT
    elif observed_rev > decision_rev:
        relation = LATER
    else:
        relation = EARLIER

    # Neither a later revision nor a conflicting statement selects a winner.
    # A matching EC308 precondition-failure claim likewise has no winner.
    corroborated_candidate = (
        verified_cas['selected_candidate_chain_raw_sha256']
        if relation == SAME and
           verified_cas['issuer_signed_outcome'] ==
               'compare_exchange_committed_claim' else None)
    report = {
        'schema': REPORT_SCHEMA,
        'status': relation,
        'registry_id': verified_cas['registry_id'],
        'cas_store_namespace_id': observer_trust['cas_store_namespace_id'],
        'cas_authority_id': cas_trust['cas_authority_id'],
        'cas_authority_public_hex': cas_trust['cas_authority_public_hex'],
        'observer_id': observer_trust['observer_id'],
        'observer_public_hex': observer_trust['observer_public_hex'],
        'original_fork_case_raw_sha256': expected_fork_case_sha256,
        'original_fork_evidence_raw_sha256': expected_fork_evidence_sha256,
        'signed_cas_receipt_raw_sha256': expected_receipt_sha256,
        'signed_cas_claim_raw_sha256': verified_cas['signed_cas_claim_raw_sha256'],
        'recomputed_ec308_audit_raw_sha256': b.digest(b.canonical(verified_cas)),
        'signed_readback_raw_sha256': expected_readback_sha256,
        'signed_readback_claim_raw_sha256': b.digest(b.canonical(claim)),
        'original_request_nonce_sha256': cas_trust['expected_request_nonce_sha256'],
        'readback_request_nonce_sha256':
            observer_trust['expected_readback_request_nonce_sha256'],
        'previous_readback_sequence': observer_trust['expected_previous_readback_sequence'],
        'readback_sequence': seq,
        'previous_readback_raw_sha256':
            observer_trust['expected_previous_readback_raw_sha256'],
        'previous_readback_observed_revision': prev_rev,
        'decision_signed_outcome': verified_cas['issuer_signed_outcome'],
        'decision_claimed_cas_revision': decision_rev,
        'decision_claimed_head_raw_sha256': decision_head,
        'readback_claimed_cas_revision': observed_rev,
        'readback_claimed_head_raw_sha256': observed_head,
        'same_revision_and_head_signed_claims_compatible': relation == SAME,
        'same_revision_conflicting_signed_heads': relation == CONFLICT,
        'observer_revision_below_external_prior_anchor': relation == REGRESSION,
        'signed_claims_corroborate_selected_candidate_raw_sha256':
            corroborated_candidate,
        'original_ec294_through_ec308_signatures_and_claim_replayed': True,
        'distinct_known_observer_signing_key_verified': True,
        'observer_ed25519_signature_verified': True,
        'readback_observer_real_world_authorization_or_custody_proven': False,
        'observer_previous_signed_record_fully_replayed': False,
        'readback_nonce_global_uniqueness_or_real_freshness_proven': False,
        'actual_external_store_read_or_worm_performed': False,
        'actual_store_identity_or_linearizability_proven': False,
        'real_cas_commit_proven': False,
        'globally_current_head_or_cas_tip_proven': False,
        'business_or_external_store_write_performed': False,
        'private_signing_key_loaded': False,
    }
    need(len(b.canonical(report)) + 1 <= MAX_AUDIT_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_PROTOCOL_BUDGET')
    return report


def result_from_report(report: dict) -> dict:
    match = report['same_revision_and_head_signed_claims_compatible']
    committed = report['decision_signed_outcome'] == 'compare_exchange_committed_claim'
    return {
        'status': report['status'],
        'exit_code': 0 if match and committed else 2,
        'signed_readback_raw_sha256': report['signed_readback_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'original_signed_fork_and_cas_decision_replayed': True,
        'independent_observer_ed25519_signature_verified': True,
        'same_revision_and_head_signed_claims_compatible': match,
        'same_revision_conflicting_signed_heads':
            report['same_revision_conflicting_signed_heads'],
        'signed_claims_corroborate_selected_candidate_raw_sha256':
            report['signed_claims_corroborate_selected_candidate_raw_sha256'],
        'actual_external_cas_or_readback_proven': False,
        'world_authority_or_global_latest_proven': False,
        'business_or_store_write_performed': False,
    }


def verify(*, out: str | None = None, **options) -> dict:
    report = evaluate(**options)
    if out is not None:
        store.store(out, report, MAX_AUDIT_REPORT_BYTES)
    result = result_from_report(report)
    result['audit_report_written'] = out is not None
    return result


def verify_report(*, audit_report_file: str,
                  expected_audit_report_sha256: str, **options) -> dict:
    need(_sha(expected_audit_report_sha256),
         'INDEPENDENT_FULL_AUDIT_REPORT_SHA_REQUIRED')
    # Reuse the stronger EC306 private canonical raw-SHA-pinned file reader.
    saved = epochs._owner_private_read(audit_report_file, expected_audit_report_sha256)
    need(len(b.canonical(saved)) + 1 <= MAX_AUDIT_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_PROTOCOL_BUDGET')
    fresh = evaluate(**options)  # NOT a comparison of unsigned success booleans.
    need(saved == fresh, 'AUDIT_REPORT_DIFFERS_FROM_FULL_SIGNATURE_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    result['status'] = 'independently_pinned_signed_readback_audit_fully_reverified_' + fresh['status']
    return result

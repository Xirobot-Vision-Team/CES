#!/usr/bin/env python3
"""EC327 read-only verifier for *external* ninth-role NON-EXECUTION replies.

A canonical signed statement may report only an offline decision to defer or
reject an EC326 request. The signature authenticates a cryptographic statement,
not authority, delivery, atomic CAS, current remote head, or actual nonexecution.
This module has no signer, remote API, success/winner status, or output writer.
"""
from __future__ import annotations

import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt as r
from conditional_conflict_hold import hold

SCHEMA = 'ces.ec327.ninth_offline_no_execution_disposition_receipt.v1'
CLAIM_SCHEMA = 'ces.ec327.ninth_offline_no_execution_disposition_claim.v1'
RESULT_SCHEMA = 'ces.ec327.offline_no_execution_disposition_verification.v1'
DENIAL_SCHEMA = 'ces.ec327.offline_no_execution_disposition_denial.v1'
DOMAIN = b'CES/EC327/NinthOfflineNonExecutionDisposition/v1\0'
MAX_RECEIPT_BYTES = 12_000
DISPOSITIONS = frozenset(('deferred_without_submission',
                          'declined_without_submission'))
REASON_CODES = frozenset(('awaiting_authorized_external_executor',
                          'declined_by_local_reviewer',
                          'external_transaction_evidence_unavailable'))
RECEIPT_FIELDS = frozenset(('schema', 'claim', 'signature_ed25519'))
CLAIM_FIELDS = frozenset((
    'schema', 'decision_id', 'ninth_responder_id', 'ninth_responder_public_hex',
    'response_challenge_sha256', 'disposition', 'reason_code',
    'signed_request_original_raw_sha256', 'dispute_case_original_raw_sha256',
    'request_id', 'request_challenge_sha256', 'eighth_signer_id',
    'eighth_signer_public_hex', 'target_store_namespace_id',
    'registry_id', 'sequence', 'expected_remote_parent_original_raw_sha256',
    'proposed_competing_child_raw_sha256', 'offline_review_only',
    'external_store_contacted_or_atomic_cas_attempted',
    'actual_remote_hold_or_nonexecution_independently_proven',
    'remote_head_or_global_latest_verified',
    'any_child_winner_or_business_commit_proven',
    'organization_authority_or_cross_device_uniqueness_proven',
))


def need(ok: Any, code: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC327_' + code, status)


def _trust(*, decision_id: str, ninth_responder_id: str,
           ninth_responder_public_hex: str, response_challenge_sha256: str,
           expected_disposition: str, expected_reason_code: str) -> dict:
    need(r._id(decision_id) and r._id(ninth_responder_id) and
         anchor.valid_pub(ninth_responder_public_hex) and
         r._sha(response_challenge_sha256) and
         type(expected_disposition) is str and
         expected_disposition in DISPOSITIONS and
         type(expected_reason_code) is str and
         expected_reason_code in REASON_CODES,
         'EXTERNAL_NINTH_ID_PUBLIC_NONCE_DECISION_AND_DISPOSITION_REQUIRED',
         'invalid_input')
    return dict(decision_id=decision_id,
                ninth_responder_id=ninth_responder_id,
                ninth_responder_public_hex=ninth_responder_public_hex,
                response_challenge_sha256=response_challenge_sha256,
                disposition=expected_disposition,
                reason_code=expected_reason_code)


def _verify_signed_receipt(doc: dict, expected_public_hex: str) -> dict:
    anchor.exact(doc, RECEIPT_FIELDS, 'EC327_EXACT_SIGNED_REPLY_FIELDS')
    need(doc['schema'] == SCHEMA and
         type(doc['signature_ed25519']) is str and
         len(doc['signature_ed25519']) == 128 and
         all(c in '0123456789abcdef' for c in doc['signature_ed25519']),
         'SIGNED_REPLY_SCHEMA_OR_SIGNATURE_ENCODING_INVALID', 'invalid_input')
    claim = anchor.exact(doc['claim'], CLAIM_FIELDS,
                         'EC327_EXACT_NONEXECUTION_CLAIM_FIELDS')
    need(claim['schema'] == CLAIM_SCHEMA and
         claim['ninth_responder_public_hex'] == expected_public_hex and
         type(claim['disposition']) is str and
         claim['disposition'] in DISPOSITIONS and
         type(claim['reason_code']) is str and
         claim['reason_code'] in REASON_CODES and
         claim['offline_review_only'] is True and
         all(claim[key] is False for key in (
             'external_store_contacted_or_atomic_cas_attempted',
             'actual_remote_hold_or_nonexecution_independently_proven',
             'remote_head_or_global_latest_verified',
             'any_child_winner_or_business_commit_proven',
             'organization_authority_or_cross_device_uniqueness_proven')),
         'NO_FAKE_EXTERNAL_EXECUTION_READBACK_NONEXECUTION_PROOF_OR_WINNER',
         'invalid_input')
    # Authenticate with the *independently supplied* responder public key, not
    # an attacker-selected key taken from the signed document itself.
    try:
        io.pub_from_hex(expected_public_hex).verify(
            bytes.fromhex(doc['signature_ed25519']),
            DOMAIN + hold.reg.canonical(claim))
    except (InvalidSignature, ValueError, TypeError, io.HostError) as exc:
        raise anchor.AnchorError('EC327_NINTH_ED25519_REPLY_SIGNATURE_NOT_AUTHENTIC',
                                 'permission_denied') from exc
    return claim


def _binding_from_request(request_claim: dict, request_sha: str) -> dict:
    """Signed response projection: no remote head, success or time inference."""
    return dict(
        signed_request_original_raw_sha256=request_sha,
        dispute_case_original_raw_sha256=request_claim[
            'dispute_case_original_raw_sha256'],
        request_id=request_claim['request_id'],
        request_challenge_sha256=request_claim['request_challenge_sha256'],
        eighth_signer_id=request_claim['eighth_signer_id'],
        eighth_signer_public_hex=request_claim['eighth_signer_public_hex'],
        target_store_namespace_id=request_claim['target_store_namespace_id'],
        registry_id=request_claim['registry_id'],
        sequence=request_claim['sequence'],
        expected_remote_parent_original_raw_sha256=request_claim[
            'expected_remote_parent_original_raw_sha256'],
        proposed_competing_child_raw_sha256=request_claim[
            'proposed_competing_child_raw_sha256'])


def verify_nonexecution(*, receipt_file: str, expected_receipt_sha256: str,
                        request_file: str, expected_request_sha256: str,
                        case_file: str, expected_case_sha256: str,
                        left: dict, right: dict, registry_id: str,
                        expected_sequence: int,
                        expected_prior_registry_sha256: str,
                        request_id: str, target_store_namespace_id: str,
                        eighth_signer_id: str, eighth_signer_public_hex: str,
                        request_challenge_sha256: str,
                        decision_id: str, ninth_responder_id: str,
                        ninth_responder_public_hex: str,
                        response_challenge_sha256: str,
                        expected_disposition: str, expected_reason_code: str,
                        prior_registry_file: str | None = None) -> dict:
    """Verify a separately pinned external offline deferral/rejection reply.

    First authenticate the entire ninth signature and entire eighth request,
    then fully replay EC325->EC294 originals using production EC326 verifier,
    verify ninth's distinct visible identity/nonce, and finally SHA-recheck
    both untrusted documents and every bounded original path. Never writes.
    """
    hold._file_args(request_file=request_file, out=None, private_key_file=None,
                    case_file=case_file, prior_registry_file=prior_registry_file,
                    left=left, right=right)
    original_paths = [request_file, case_file]
    if prior_registry_file is not None:
        original_paths.append(prior_registry_file)
    for side in (left, right):
        original_paths.extend(side[k] for k in (
            'registry_file', 'capsule_file', 'origin_file', 'recipient_file'))
    need(case.original._valid_path(receipt_file) and
         receipt_file not in original_paths,
         'RECEIPT_PATH_MUST_BE_PRIVATE_ABSOLUTE_AND_SEPARATE', 'invalid_input')
    need(r._sha(expected_receipt_sha256) and
         r._sha(expected_request_sha256),
         'EXTERNAL_WHOLE_RAW_SHA_PINS_FOR_BOTH_SIGNED_DOCS_REQUIRED',
         'invalid_input')
    ninth = _trust(decision_id=decision_id,
        ninth_responder_id=ninth_responder_id,
        ninth_responder_public_hex=ninth_responder_public_hex,
        response_challenge_sha256=response_challenge_sha256,
        expected_disposition=expected_disposition,
        expected_reason_code=expected_reason_code)
    eighth = hold._actor(request_id=request_id,
        target_store_namespace_id=target_store_namespace_id,
        eighth_signer_id=eighth_signer_id,
        eighth_signer_public_hex=eighth_signer_public_hex,
        request_challenge_sha256=request_challenge_sha256)
    need(decision_id != request_id and
         ninth_responder_id != eighth_signer_id and
         ninth_responder_public_hex != eighth_signer_public_hex and
         response_challenge_sha256 != request_challenge_sha256,
         'NINTH_ROLE_DECISION_ID_AND_NONCE_MUST_DIFFER_FROM_EIGHTH',
         'invalid_input')
    response, raw_response = r._load(
        receipt_file, expected_receipt_sha256, MAX_RECEIPT_BYTES,
        'EC327_EXTERNAL_NINTH_NONEXECUTION_RESPONSE')
    receipt_claim = _verify_signed_receipt(response, ninth_responder_public_hex)
    need(all(receipt_claim.get(k) == v for k, v in ninth.items()),
         'SIGNED_REPLY_NOT_EQUAL_INDEPENDENT_NINTH_TRUST', 'invalid_input')
    request, raw_request = r._load(
        request_file, expected_request_sha256, hold.MAX_REQUEST_BYTES,
        'EC327_ORIGINAL_EIGHTH_SIGNED_REQUEST')
    request_claim = hold._signature(request, eighth_signer_public_hex)
    need(all(request_claim.get(k) == v for k, v in eighth.items()) and
         request_claim.get('registry_id') == registry_id and
         type(expected_sequence) is int and
         request_claim.get('sequence') == expected_sequence and
         request_claim.get('expected_remote_parent_original_raw_sha256') ==
             expected_prior_registry_sha256 and
         request_claim.get('dispute_case_original_raw_sha256') ==
             expected_case_sha256 and
         request_claim.get('proposed_competing_child_raw_sha256') ==
             sorted((left['expected_registry_sha256'],
                     right['expected_registry_sha256'])),
         'SIGNED_EIGHTH_REQUEST_NOT_EQUAL_OUTSIDE_TRUST', 'invalid_input')
    need(all(receipt_claim.get(k) == v for k, v in
             _binding_from_request(request_claim, expected_request_sha256).items()),
         'NINTH_REPLY_MUST_BIND_EXACT_EIGHTH_RAW_SHA_AND_BOTH_CHILDREN',
         'invalid_input')
    # The EC326 production verifier does its own eighth real signature and
    # two complete current EC325->EC294 historical replays, plus post-replay
    # source SHA pinning. An unsigned EC325 report is not accepted instead.
    outcome = hold.verify_request(
        request_file=request_file, expected_request_sha256=expected_request_sha256,
        case_file=case_file, expected_case_sha256=expected_case_sha256,
        left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        request_id=request_id,
        target_store_namespace_id=target_store_namespace_id,
        eighth_signer_id=eighth_signer_id,
        eighth_signer_public_hex=eighth_signer_public_hex,
        request_challenge_sha256=request_challenge_sha256,
        prior_registry_file=prior_registry_file)
    need(outcome.get('exit_code') == 2 and
         outcome.get('status') ==
             'eighth_signature_and_original_conflict_hold_request_reverified_no_cas' and
         outcome.get('eighth_ed25519_signature_and_both_ec325_signed_histories_verified') is True and
         outcome.get('external_cas_worm_global_latest_winner_or_commit_proven') is False,
         'FULL_EIGHTH_AND_TWO_EC325_ORIGINAL_SIGNED_REPLAYS_REQUIRED')
    old_ids, old_pubs, old_challenges = set(), set(), set()
    for side in (left, right):
        ids, pubs, nonces = hold._visible_roles_and_challenges(
            side=side, registry_id=registry_id,
            expected_sequence=expected_sequence,
            expected_prior_registry_sha256=expected_prior_registry_sha256)
        old_ids.update(ids)
        old_pubs.update(pubs)
        old_challenges.update(nonces)
    need(ninth_responder_id not in old_ids and
         ninth_responder_public_hex not in old_pubs,
         'NINTH_ROLE_REUSES_VISIBLE_PRIOR_SIGNATURE_OR_OPERATOR',
         'invalid_input')
    need(response_challenge_sha256 not in old_challenges and
         response_challenge_sha256 not in (
             request_challenge_sha256, expected_receipt_sha256,
             expected_request_sha256, expected_case_sha256,
             expected_prior_registry_sha256,
             left['expected_registry_sha256'],
             right['expected_registry_sha256']),
         'NINTH_CHALLENGE_REUSES_VISIBLE_HISTORY_OR_ORIGINAL',
         'invalid_input')
    need(hmac.compare_digest(raw_request, r._raw(request)) and
         hmac.compare_digest(raw_response, r._raw(response)) and
         set(receipt_claim) == CLAIM_FIELDS,
         'ORIGINAL_SIGNED_DOCUMENTS_CHANGED_OR_NONCANONICAL')
    # Detect changed reply/request while the deep EC317/318 replay is running.
    r._load(request_file, expected_request_sha256, hold.MAX_REQUEST_BYTES,
            'EC327_RECHECK_EIGHTH_SIGNED_REQUEST')
    r._load(receipt_file, expected_receipt_sha256, MAX_RECEIPT_BYTES,
            'EC327_RECHECK_NINTH_SIGNED_REPLY')
    # The whole original evidence is already re-pinned by EC326, but a final
    # check narrows a possible mutation window after EC327's role traversal.
    r._load(case_file, expected_case_sha256, hold.proof.MAX_CASE_BYTES,
            'EC327_RECHECK_DISPUTE_CASE')
    for side in (left, right):
        r._load(side['registry_file'], side['expected_registry_sha256'],
                r.MAX_SNAPSHOT, 'EC327_RECHECK_CHILD_REGISTRY')
        r._load(side['origin_file'], side['expected_origin_sha256'],
                r.MAX_CHANNEL, 'EC327_RECHECK_ORIGIN')
        r._load(side['recipient_file'], side['expected_recipient_sha256'],
                r.MAX_CHANNEL, 'EC327_RECHECK_RECIPIENT')
        origin, _ = r._load(side['origin_file'], side['expected_origin_sha256'],
                            r.MAX_CHANNEL, 'EC327_RECHECK_CAPSULE_SOURCE')
        hold.capsule._file(side['capsule_file'], hold.capsule.MAX_ARCHIVE,
                           origin['capsule_original_raw_sha256'],
                           'EC327_RECHECK_CAPSULE')
    if prior_registry_file is not None:
        r._load(prior_registry_file, expected_prior_registry_sha256,
                r.MAX_SNAPSHOT, 'EC327_RECHECK_SHARED_PARENT')
    return {
        'status': 'ninth_offline_nonexecution_statement_authentic_unresolved',
        'exit_code': 2,
        'receipt_original_raw_sha256': expected_receipt_sha256,
        'signed_request_original_raw_sha256': expected_request_sha256,
        'decision_id': decision_id,
        'disposition': expected_disposition,
        'reason_code': expected_reason_code,
        'ninth_responder_id': ninth_responder_id,
        'ninth_responder_public_hex': ninth_responder_public_hex,
        'request_id': request_id,
        'target_store_namespace_id': target_store_namespace_id,
        'dispute_case_original_raw_sha256': expected_case_sha256,
        'registry_id': registry_id,
        'sequence': expected_sequence,
        'expected_remote_parent_original_raw_sha256':
            expected_prior_registry_sha256,
        'two_competing_heads_original_raw_sha256': sorted((
            left['expected_registry_sha256'], right['expected_registry_sha256'])),
        'ninth_signature_eighth_signature_and_both_original_histories_verified': True,
        'offline_disposition_authenticity_only_not_remote_state': True,
        'external_atomic_cas_or_worm_write_performed': False,
        'actual_external_nonexecution_hold_or_remote_head_proven': False,
        'remote_global_latest_or_child_winner_proven': False,
        'organization_authorization_and_cross_device_nonce_uniqueness_proven': False,
        'business_or_external_store_writes_performed': False,
    }

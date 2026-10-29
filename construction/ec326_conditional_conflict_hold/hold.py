#!/usr/bin/env python3
"""EC326: eighth-role signed OFFLINE request to place a CAS conflict on hold.

The request authorizes no write by itself. It is *not* a provider receipt, an
observed CAS compare, an organizational authorization, a winning child, or a
remote state assertion. Both issuance and verification independently replay
EC325 -> EC324 -> EC323 -> original signed EC294 histories before accepting
any claim. Only the opaque, explicitly specified target namespace can later
be interpreted by a separately authorized external compare-and-set adapter.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import tempfile
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec322_receiver_fork_ack import ack
from ec323_composite_fork_capsule import capsule
from ec324_dual_channel_receipt import receipt as r
from ec325_offline_receipt_siblings import proof

SIGNED_SCHEMA = 'ces.ec326.eighth_signed_conditional_conflict_hold_request.v1'
CLAIM_SCHEMA = 'ces.ec326.conditional_external_conflict_hold_claim.v1'
RESULT_SCHEMA = 'ces.ec326.offline_conditional_conflict_hold_result.v1'
DENIAL_SCHEMA = 'ces.ec326.offline_conditional_conflict_hold_denial.v1'
SIGN_DOMAIN = b'CES/EC326/EighthIndependentOfflineConditionalConflictHoldRequest/v1\0'
OPERATION = 'request_conditional_dispute_hold_only_no_submission'
CONDITION = 'external_store_must_atomically_compare_its_current_head_to_expected_parent'
MAX_REQUEST_BYTES = 16_000
SIGNED_FIELDS = frozenset(('schema', 'claim', 'signature_ed25519'))
CLAIM_FIELDS = frozenset((
    'schema', 'request_id', 'target_store_namespace_id', 'eighth_signer_id',
    'eighth_signer_public_hex', 'request_challenge_sha256',
    'requested_operation', 'conditional_write_precondition',
    'registry_id', 'sequence', 'expected_remote_parent_original_raw_sha256',
    'dispute_case_original_raw_sha256', 'proposed_competing_child_raw_sha256',
    'both_ec325_original_current_signed_histories_replayed',
    'external_cas_read_compare_write_or_store_submission_occurred',
    'remote_latest_winner_or_commit_receipt_proven',
    'organization_signer_authorization_or_global_nonce_uniqueness_proven',
))
ACTOR_FIELDS = frozenset((
    'request_id', 'target_store_namespace_id', 'eighth_signer_id',
    'eighth_signer_public_hex', 'request_challenge_sha256',
))


def need(ok: Any, code: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC326_' + code, status)


def _actor(*, request_id: str, target_store_namespace_id: str,
           eighth_signer_id: str, eighth_signer_public_hex: str,
           request_challenge_sha256: str) -> dict:
    need(all(r._id(v) for v in (request_id, target_store_namespace_id,
                               eighth_signer_id)) and
         anchor.valid_pub(eighth_signer_public_hex) and
         r._sha(request_challenge_sha256),
         'INDEPENDENT_REQUEST_ID_TARGET_EIGHTH_ID_PUB_AND_NONCE_REQUIRED',
         'invalid_input')
    return dict(request_id=request_id,
                target_store_namespace_id=target_store_namespace_id,
                eighth_signer_id=eighth_signer_id,
                eighth_signer_public_hex=eighth_signer_public_hex,
                request_challenge_sha256=request_challenge_sha256)


def _file_args(*, request_file: str | None, out: str | None,
               private_key_file: str | None, case_file: str,
               prior_registry_file: str | None, left: dict,
               right: dict) -> None:
    control = [p for p in (request_file, out, private_key_file) if p is not None]
    originals = [p for p in (case_file, prior_registry_file) if p is not None]
    for side in (left, right):
        originals.extend(side[k] for k in (
            'registry_file', 'origin_file', 'recipient_file', 'capsule_file'))
    # One original case/capsule MAY be shared by both sides, while an output,
    # signed request or private signing key must not alias *any* original.
    need(all(case.original._valid_path(p) for p in control+originals),
         'ALL_SIGN_VERIFY_PATHS_MUST_BE_NORMALIZED_ABSOLUTE', 'invalid_input')
    need(len(set(control)) == len(control) and
         not set(control).intersection(originals),
         'SIGNING_REQUEST_AND_SECRET_PATHS_CANNOT_OVERLAP_ORIGINALS',
         'invalid_input')


def _visible_roles_and_challenges(*, side: dict, registry_id: str,
                                  expected_sequence: int,
                                  expected_prior_registry_sha256: str
                                  ) -> tuple[set[str], set[str], set[str]]:
    """Extract old roles only from *already fully replayed* original files.

    The EC321 original ZIP is rechecked with its external trust pins again;
    we never accept unsigned claims from a loosely decoded archive. Within
    the bounded historical signed records, include all first-six roles,
    historical challenges, then the separately authenticated seventh role.
    """
    origin, recipient, _ = r._load_pair(
        origin_file=side['origin_file'],
        expected_origin_sha256=side['expected_origin_sha256'],
        recipient_file=side['recipient_file'],
        expected_recipient_sha256=side['expected_recipient_sha256'],
        registry_id=registry_id, expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    pins = origin['historical_external_pins']
    seventh = origin['seventh_receiver_external_trust']
    raw = capsule._file(side['capsule_file'], capsule.MAX_ARCHIVE,
                        origin['capsule_original_raw_sha256'],
                        'EC326_ORIGINAL_PINNED_CAPSULE')
    case_raw, _ = capsule._validated_originals(
        raw, pins, seventh, origin['case_original_raw_sha256'],
        origin['seventh_ack_original_raw_sha256'])
    with tempfile.TemporaryDirectory(prefix='ces-ec326-roles-') as temp:
        path = case._temp_file(Path(temp)/'original-case.zip', case_raw)
        # EC336: exact newly created case.zip only; no generic /tmp allowance.
        with io._scoped_verified_local_import_reads(frozenset((path,))):
            manifest, blobs = case._load_case(
                path, origin['case_original_raw_sha256'], pins)
    left_snapshot = io.parse(blobs[pins['expected_left_sha256']],reg.MAX_SNAPSHOT)
    right_snapshot = io.parse(blobs[pins['expected_right_sha256']],reg.MAX_SNAPSHOT)
    genesis = left_snapshot['records'][0]['claim']
    root = genesis['original_source_root']['trust']
    ids = {pins['registrar_id'], pins['witness_id'],
           root['custodian_a_id'], root['custodian_b_id'],
           seventh['seventh_receiver_id'],
           origin['operator_id'], recipient['operator_id']}
    pubs = {pins['registrar_public_hex'], pins['witness_public_hex'],
            root['custodian_a_public_hex'], root['custodian_b_public_hex'],
            seventh['seventh_receiver_public_hex']}
    challenges = {pins['witness_challenge_sha256'],
                  genesis['registrar_epoch_challenge_sha256'],
                  genesis['original_source_root']['expected_latest_challenge_sha256'],
                  seventh['seventh_receiver_challenge_sha256'],
                  manifest['original_transfer_bundle_raw_sha256'],
                  origin['case_original_raw_sha256'],
                  origin['seventh_ack_original_raw_sha256'],
                  origin['capsule_original_raw_sha256']}
    challenges.update(pins[k] for k in (
        'expected_witness_sha256', 'expected_left_sha256',
        'expected_right_sha256', 'expected_genesis_raw_sha256',
        'expected_left_head_raw_sha256', 'expected_right_head_raw_sha256'))
    for snapshot in (left_snapshot, right_snapshot):
        for entry in snapshot['records'][1:]:
            claim = entry['claim']
            ids.update((claim['sender_id'], claim['receiver_id']))
            pubs.update((claim['sender_public_hex'],claim['receiver_public_hex']))
            challenges.update(claim[field] for field in (
                'sender_exchange_challenge_sha256',
                'receiver_exchange_challenge_sha256',
                'sender_confirmation_challenge_sha256',
                'registrar_entry_challenge_sha256'))
    return ids, pubs, challenges


def _claim_from_originals(*, case_file: str, expected_case_sha256: str,
                          left: dict, right: dict, registry_id: str,
                          expected_sequence: int,
                          expected_prior_registry_sha256: str,
                          prior_registry_file: str | None,
                          actor: dict) -> dict:
    """No private key, no output, no external write. Full EC325 replay first."""
    verified = proof.verify_case(
        case_file=case_file, expected_case_sha256=expected_case_sha256,
        left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file)
    need(verified.get('exit_code') == 2 and
         verified.get('status') ==
            'offline_sibling_local_receipt_case_independently_reverified' and
         verified.get('both_children_current_complete_original_signed_histories_replayed') is True and
         verified.get('case_is_a_new_signature_or_an_authoritative_cas_decision') is False and
         verified.get('external_cas_worm_global_latest_or_fork_winner_proven') is False,
         'WHOLE_EC325_CASE_AND_BOTH_ORIGINAL_SIGNATURE_CHAINS_REQUIRED')
    ids, pubs, challenges = set(), set(), set()
    for side in (left, right):
        side_ids, side_pubs, side_challenges = _visible_roles_and_challenges(
            side=side, registry_id=registry_id,
            expected_sequence=expected_sequence,
            expected_prior_registry_sha256=expected_prior_registry_sha256)
        ids.update(side_ids)
        pubs.update(side_pubs)
        challenges.update(side_challenges)
    need(actor['eighth_signer_id'] not in ids and
         actor['eighth_signer_public_hex'] not in pubs,
         'EIGHTH_SIGNER_MUST_NOT_REUSE_ANY_VISIBLE_OLD_ROLE',
         'invalid_input')
    heads = sorted((left['expected_registry_sha256'],
                    right['expected_registry_sha256']))
    need(actor['request_challenge_sha256'] not in challenges and
         actor['request_challenge_sha256'] not in (
             expected_case_sha256, expected_prior_registry_sha256, *heads),
         'EIGHTH_NONCE_MUST_NOT_REUSE_VISIBLE_HISTORY_OR_EVIDENCE',
         'invalid_input')
    # The entire existing case remains the subject: the signed request may
    # place the dispute on hold but may NEVER select either child as winner.
    claim = {
        'schema': CLAIM_SCHEMA, **actor,
        'requested_operation': OPERATION,
        'conditional_write_precondition': CONDITION,
        'registry_id': registry_id,
        'sequence': expected_sequence,
        'expected_remote_parent_original_raw_sha256':
            expected_prior_registry_sha256,
        'dispute_case_original_raw_sha256': expected_case_sha256,
        'proposed_competing_child_raw_sha256': heads,
        'both_ec325_original_current_signed_histories_replayed': True,
        'external_cas_read_compare_write_or_store_submission_occurred': False,
        'remote_latest_winner_or_commit_receipt_proven': False,
        'organization_signer_authorization_or_global_nonce_uniqueness_proven': False,
    }
    need(set(claim) == CLAIM_FIELDS and
         len(r._raw(claim)) <= MAX_REQUEST_BYTES-400,
         'CONDITIONAL_REQUEST_CLAIM_EXCEEDS_BUDGET', 'invalid_input')
    # Recheck every originally pinned input *after* role inspection too.
    for side in (left, right):
        r._load(side['registry_file'],side['expected_registry_sha256'],
                r.MAX_SNAPSHOT,'EC326_RECHECK_RECEIPT_HEAD')
        r._load(side['origin_file'],side['expected_origin_sha256'],
                r.MAX_CHANNEL,'EC326_RECHECK_ORIGIN_CHANNEL')
        r._load(side['recipient_file'],side['expected_recipient_sha256'],
                r.MAX_CHANNEL,'EC326_RECHECK_RECIPIENT_CHANNEL')
        capsule._file(side['capsule_file'],capsule.MAX_ARCHIVE,
                      r._load(side['origin_file'],side['expected_origin_sha256'],
                              r.MAX_CHANNEL,'EC326_RECHECK_CAPSULE_PIN')[0][
                              'capsule_original_raw_sha256'],
                      'EC326_RECHECK_CAPSULE')
    r._load(case_file, expected_case_sha256,
            proof.MAX_CASE_BYTES,'EC326_RECHECK_DISPUTE_CASE')
    if prior_registry_file is not None:
        r._load(prior_registry_file,expected_prior_registry_sha256,
                r.MAX_SNAPSHOT,'EC326_RECHECK_PARENT')
    return claim


def _signature(doc: dict, expected_public_hex: str) -> dict:
    anchor.exact(doc, SIGNED_FIELDS, 'EC326_EXACT_SIGNED_REQUEST_FIELDS')
    need(doc['schema'] == SIGNED_SCHEMA and
         type(doc['signature_ed25519']) is str and
         len(doc['signature_ed25519']) == 128 and
         all(c in '0123456789abcdef' for c in doc['signature_ed25519']),
         'SIGNED_REQUEST_SCHEMA_OR_SIGNATURE_ENCODING_INVALID', 'invalid_input')
    claim = anchor.exact(doc['claim'], CLAIM_FIELDS,
                         'EC326_EXACT_CONDITIONAL_REQUEST_CLAIM_FIELDS')
    need(claim['schema'] == CLAIM_SCHEMA and
         claim['requested_operation'] == OPERATION and
         claim['conditional_write_precondition'] == CONDITION and
         claim['eighth_signer_public_hex'] == expected_public_hex and
         claim['both_ec325_original_current_signed_histories_replayed'] is True and
         all(claim[k] is False for k in (
             'external_cas_read_compare_write_or_store_submission_occurred',
             'remote_latest_winner_or_commit_receipt_proven',
             'organization_signer_authorization_or_global_nonce_uniqueness_proven')),
         'NO_FAKE_REMOTE_SUCCESS_AUTHORIZATION_OR_WINNER', 'invalid_input')
    try:
        io.pub_from_hex(expected_public_hex).verify(
            bytes.fromhex(doc['signature_ed25519']),
            SIGN_DOMAIN + reg.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise anchor.AnchorError('EC326_ED25519_SIGNATURE_NOT_AUTHENTIC',
                                 'permission_denied') from exc
    return claim


def _result(*, status: str, claim: dict, request_sha: str) -> dict:
    return {
        'status': status, 'exit_code': 2,
        'request_id': claim['request_id'],
        'target_store_namespace_id': claim['target_store_namespace_id'],
        'eighth_signer_id': claim['eighth_signer_id'],
        'eighth_signer_public_hex': claim['eighth_signer_public_hex'],
        'signed_request_original_raw_sha256': request_sha,
        'dispute_case_original_raw_sha256':
            claim['dispute_case_original_raw_sha256'],
        'registry_id': claim['registry_id'], 'sequence': claim['sequence'],
        'expected_remote_parent_original_raw_sha256':
            claim['expected_remote_parent_original_raw_sha256'],
        'two_competing_heads_original_raw_sha256':
            claim['proposed_competing_child_raw_sha256'],
        'eighth_ed25519_signature_and_both_ec325_signed_histories_verified': True,
        'request_is_not_remote_authorization_or_actual_cas_transaction': True,
        'external_cas_worm_global_latest_winner_or_commit_proven': False,
        'organizational_approval_and_cross_device_nonce_uniqueness_proven': False,
        'business_or_external_store_writes_performed': False,
    }


def sign_request(*, out: str, private_key_file: str,
                 case_file: str, expected_case_sha256: str, left: dict,
                 right: dict, registry_id: str, expected_sequence: int,
                 expected_prior_registry_sha256: str,
                 request_id: str, target_store_namespace_id: str,
                 eighth_signer_id: str, eighth_signer_public_hex: str,
                 request_challenge_sha256: str,
                 prior_registry_file: str | None = None) -> dict:
    _file_args(request_file=None,out=out,private_key_file=private_key_file,
               case_file=case_file,prior_registry_file=prior_registry_file,
               left=left,right=right)
    r.bundle._private_parent(out)
    need(not os.path.lexists(out),'SIGNED_REQUEST_OUTPUT_EXISTS','invalid_input')
    actor = _actor(request_id=request_id,
        target_store_namespace_id=target_store_namespace_id,
        eighth_signer_id=eighth_signer_id,
        eighth_signer_public_hex=eighth_signer_public_hex,
        request_challenge_sha256=request_challenge_sha256)
    claim = _claim_from_originals(
        case_file=case_file, expected_case_sha256=expected_case_sha256,
        left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file, actor=actor)
    # The secret is read only after complete original replay and role checks.
    key = io.private_from_file(private_key_file)
    derived_pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(derived_pub,eighth_signer_public_hex),
         'PRIVATE_KEY_NOT_EQUAL_EXTERNALLY_SELECTED_EIGHTH_ROLE')
    doc = {'schema': SIGNED_SCHEMA,'claim':claim,
           'signature_ed25519':key.sign(SIGN_DOMAIN+reg.canonical(claim)).hex()}
    raw = r._raw(doc)
    need(len(raw) <= MAX_REQUEST_BYTES,
         'SIGNED_REQUEST_EXCEEDS_BUDGET', 'invalid_input')
    r._write_exclusive(out,raw)
    return _result(status='eighth_role_signed_offline_conditional_hold_request_only',
                   claim=claim,request_sha=case.sha(raw))


def verify_request(*, request_file: str, expected_request_sha256: str,
                   case_file: str, expected_case_sha256: str, left: dict,
                   right: dict, registry_id: str, expected_sequence: int,
                   expected_prior_registry_sha256: str,
                   request_id: str, target_store_namespace_id: str,
                   eighth_signer_id: str, eighth_signer_public_hex: str,
                   request_challenge_sha256: str,
                   prior_registry_file: str | None = None) -> dict:
    _file_args(request_file=request_file,out=None,private_key_file=None,
               case_file=case_file,prior_registry_file=prior_registry_file,
               left=left,right=right)
    need(r._sha(expected_request_sha256),
         'EXTERNALLY_PINNED_SIGNED_REQUEST_WHOLE_RAW_SHA_REQUIRED',
         'invalid_input')
    actor = _actor(request_id=request_id,
        target_store_namespace_id=target_store_namespace_id,
        eighth_signer_id=eighth_signer_id,
        eighth_signer_public_hex=eighth_signer_public_hex,
        request_challenge_sha256=request_challenge_sha256)
    doc,original = r._load(request_file,expected_request_sha256,
                           MAX_REQUEST_BYTES,'SIGNED_CONDITIONAL_HOLD_REQUEST')
    claim = _signature(doc,eighth_signer_public_hex)
    need(all(claim[k] == v for k,v in actor.items()) and
         claim['registry_id'] == registry_id and
         claim['sequence'] == expected_sequence and
         claim['expected_remote_parent_original_raw_sha256'] ==
             expected_prior_registry_sha256 and
         claim['dispute_case_original_raw_sha256'] == expected_case_sha256 and
         claim['proposed_competing_child_raw_sha256'] == sorted((
             left['expected_registry_sha256'],
             right['expected_registry_sha256'])),
         'SIGNED_REQUEST_NOT_EQUAL_EXPLICIT_OUTSIDE_TRUST_OR_BOTH_HEADS',
         'invalid_input')
    recreated = _claim_from_originals(
        case_file=case_file,expected_case_sha256=expected_case_sha256,
        left=left,right=right,registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file,actor=actor)
    need(claim == recreated and
         hmac.compare_digest(original,r._raw(doc)),
         'SIGNED_REQUEST_NOT_EQUAL_COMPLETE_REPLAYED_SOURCE_EVIDENCE')
    # Prevent a request being replaced while all the slow signing chains run.
    r._load(request_file,expected_request_sha256,MAX_REQUEST_BYTES,
            'EC326_RECHECK_SIGNED_REQUEST')
    return _result(status='eighth_signature_and_original_conflict_hold_request_reverified_no_cas',
                   claim=recreated,request_sha=expected_request_sha256)

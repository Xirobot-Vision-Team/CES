#!/usr/bin/env python3
"""EC322: sign/verify seventh-party acknowledgement ONLY after entire EC321 replay.

No portable ZIP metadata, unsigned PASS report, newly signed acknowledgement,
public key embedded in the acknowledgement, or original source path is a trust
anchor. The operator supplies independent whole-file pins and identity/key.
Both signing AND verifying replay EC321 -> EC320 -> EC319 -> EC318 -> EC294.
Acknowledging a demonstrably valid fork never chooses a winner (exit=2).
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec302_portable_bundle import bundle
from ec316_dual_custodian_checkpoint import checkpoint as custody
from ec319_offline_transfer_registry import registry as reg
from ec320_fork_witness import witness
from ec321_fork_case_transport import case

SIGNED_SCHEMA = 'ces.ec322.seventh_independent_receiver_signed_fork_case_ack.v1'
CLAIM_SCHEMA = 'ces.ec322.seventh_receiver_reverified_fork_claim.v1'
RESULT_SCHEMA = 'ces.ec322.seventh_receiver_fork_ack_result.v1'
DENIAL_SCHEMA = 'ces.ec322.seventh_receiver_fork_ack_denial.v1'
SIGN_DOMAIN = b'CES/EC322/SeventhIndependentReceiver/OriginalForkCaseAcknowledgement/v1\0'
OBSERVATION = 'portable_original_signed_fork_case_and_all_original_histories_reverified'
MAX_RECEIPT = 20_000
SIGNED_FIELDS = frozenset({'schema', 'claim', 'signature_ed25519'})
CLAIM_FIELDS = frozenset({
    'schema', 'ack_id', 'seventh_receiver_id', 'seventh_receiver_public_hex',
    'seventh_receiver_challenge_sha256', 'observation',
    'case_original_raw_sha256', 'ec321_independently_required_external_pins',
    'replayed_signed_fork_evidence', 'winner_selected',
    'global_latest_or_external_cas_proven',
    'receiver_physical_or_organizational_authorization_proven',
})
FORK_FIELDS = frozenset({
    'registry_id', 'fork_sequence', 'common_parent_signed_record_raw_sha256',
    'left_divergent_signed_record_raw_sha256',
    'right_divergent_signed_record_raw_sha256',
    'left_registration_count', 'right_registration_count',
    'source_object_count',
})
RECEIVER_FIELDS = frozenset({
    'ack_id', 'seventh_receiver_id', 'seventh_receiver_public_hex',
    'seventh_receiver_challenge_sha256',
})


def need(value: Any, reason: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC322_' + reason, status)


def _receiver(*, ack_id: str, seventh_receiver_id: str,
              seventh_receiver_public_hex: str,
              seventh_receiver_challenge_sha256: str) -> dict:
    need(custody._id(ack_id) and custody._id(seventh_receiver_id) and
         anchor.valid_pub(seventh_receiver_public_hex) and
         custody._sha(seventh_receiver_challenge_sha256),
         'EXTERNALLY_FIXED_ACK_ID_SEVENTH_ID_PUBLIC_KEY_AND_CHALLENGE_REQUIRED',
         'invalid_input')
    return dict(ack_id=ack_id, seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256)


def _no_reused_role(receiver: dict, manifest: dict, blobs: dict[str, bytes],
                    pins: dict, expected_bundle_sha256: str) -> dict:
    """Inspect verified, signed *both* original branches, not unsigned ZIP hints.

    Every original signed role and signed challenge is in the authenticated
    material (EC319 genesis + entry claims, EC320 sixth witness). This checks
    independence *within that bounded visible history*, not global uniqueness.
    """
    left = io.parse(blobs[pins['expected_left_sha256']], reg.MAX_SNAPSHOT)
    right = io.parse(blobs[pins['expected_right_sha256']], reg.MAX_SNAPSHOT)
    sixth = io.parse(blobs[pins['expected_witness_sha256']], witness.MAX_ATTESTATION)
    signed_fork = witness._verify_witness_signature(sixth,
        pins['witness_public_hex'])
    genesis = left['records'][0]['claim']
    root = genesis['original_source_root']['trust']
    identities = {pins['registrar_id'], pins['witness_id'],
                  root['custodian_a_id'], root['custodian_b_id']}
    public_keys = {pins['registrar_public_hex'], pins['witness_public_hex'],
                   root['custodian_a_public_hex'], root['custodian_b_public_hex']}
    challenges = {pins['witness_challenge_sha256'],
                  genesis['registrar_epoch_challenge_sha256'],
                  genesis['original_source_root']['expected_latest_challenge_sha256']}
    for snapshot in (left, right):
        for signed in snapshot['records'][1:]:
            claim = signed['claim']
            identities.update((claim['sender_id'], claim['receiver_id']))
            public_keys.update((claim['sender_public_hex'],
                                claim['receiver_public_hex']))
            challenges.update(claim[field] for field in (
                'sender_exchange_challenge_sha256',
                'receiver_exchange_challenge_sha256',
                'sender_confirmation_challenge_sha256',
                'registrar_entry_challenge_sha256'))
    need(receiver['seventh_receiver_id'] not in identities and
         receiver['seventh_receiver_public_hex'] not in public_keys,
         'SEVENTH_SIGNER_ID_AND_PUBLIC_KEY_MUST_NOT_REUSE_ANY_VISIBLE_ROLE',
         'invalid_input')
    need(receiver['seventh_receiver_challenge_sha256'] not in challenges and
         receiver['seventh_receiver_challenge_sha256'] not in (
             manifest['original_transfer_bundle_raw_sha256'],
             pins['expected_witness_sha256'],
             pins['expected_left_sha256'], pins['expected_right_sha256'],
             expected_bundle_sha256),
         'SEVENTH_RECEIPT_CHALLENGE_REUSES_VISIBLE_SIGNED_NONCE_OR_EVIDENCE',
         'invalid_input')
    return signed_fork


def _claimed_observation(*, bundle_file: str, expected_bundle_sha256: str,
                         receiver: dict, pins: dict) -> tuple[dict, dict]:
    # THIS is the authoritative operation: recipient rebinds and individually
    # re-verifies all original signed EC320->EC294 evidence from the ZIP.
    replay = case.verify(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, **pins)
    need(replay.get('exit_code') == 2 and
         replay.get('status') ==
            'independent_receiver_verified_unmodified_original_fork_after_pathless_import' and
         replay.get('ec320_sixth_signature_and_both_complete_original_forks_replayed') is True and
         replay.get('lossless_exact_original_bytes_rebound_without_source_paths') is True and
         replay.get('external_latest_winner_or_atomic_cas_proven') is False and
         replay.get('new_receiver_signature_or_organizational_authority_proven') is False,
         'WHOLE_ORIGINAL_CASE_MUST_BE_AUTHENTICALLY_REPLAYED_BEFORE_ACK')
    # A second independently SHA-pinned read supplies ONLY verified signed
    # claims for the role exclusion check and reconstruction of the new claim.
    # Any concurrent alteration fails the external raw ZIP SHA requirement.
    manifest, blobs = case._load_case(bundle_file, expected_bundle_sha256, pins)
    fork = _no_reused_role(receiver, manifest, blobs, pins,
                            expected_bundle_sha256)
    need(fork['fork_sequence'] == replay['fork_sequence'] and
         fork['left_registration_count'] == replay['left_transfer_count'] and
         fork['right_registration_count'] == replay['right_transfer_count'] and
         fork['left_snapshot_original_raw_sha256'] == pins['expected_left_sha256'] and
         fork['right_snapshot_original_raw_sha256'] == pins['expected_right_sha256'] and
         fork['genesis_signed_original_raw_sha256'] ==
              pins['expected_genesis_raw_sha256'],
         'REPLAY_RESULT_NOT_EQUAL_SIGNED_SIXTH_FORK_EVIDENCE', 'unavailable')
    signed_fork = {k:fork[k] for k in (
        'registry_id', 'fork_sequence',
        'common_parent_signed_record_raw_sha256',
        'left_divergent_signed_record_raw_sha256',
        'right_divergent_signed_record_raw_sha256',
        'left_registration_count', 'right_registration_count')}
    signed_fork['source_object_count'] = replay['source_object_count']
    need(set(signed_fork) == FORK_FIELDS,
         'FORK_EVIDENCE_FIELDS_INCONSISTENT', 'unavailable')
    claim = {
        'schema': CLAIM_SCHEMA,
        **receiver,
        'observation': OBSERVATION,
        'case_original_raw_sha256': expected_bundle_sha256,
        'ec321_independently_required_external_pins': dict(pins),
        'replayed_signed_fork_evidence': signed_fork,
        'winner_selected': False,
        'global_latest_or_external_cas_proven': False,
        'receiver_physical_or_organizational_authorization_proven': False,
    }
    need(set(claim) == CLAIM_FIELDS and len(reg.raw_doc(claim)) < MAX_RECEIPT,
         'RECEIPT_CLAIM_EXCEEDS_EXACT_BUDGET', 'invalid_input')
    return claim, replay


def _signed_document(claim: dict, private_key_file: str,
                     expected_public_hex: str) -> dict:
    # Deliberately never read the private key before the original full replay.
    key = io.private_from_file(private_key_file)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(pub, expected_public_hex),
         'SEVENTH_PRIVATE_KEY_NOT_MATCH_EXTERNALLY_FIXED_PUBLIC_IDENTITY')
    document = {'schema': SIGNED_SCHEMA, 'claim': claim,
                'signature_ed25519':key.sign(SIGN_DOMAIN+reg.canonical(claim)).hex()}
    need(len(reg.raw_doc(document)) <= MAX_RECEIPT,
         'SEVENTH_SIGNED_RECEIPT_OVERSIZED', 'invalid_input')
    return document


def _verify_signature(doc: dict, expected_public_hex: str) -> dict:
    anchor.exact(doc, SIGNED_FIELDS, 'EC322_SIGNED_ACK_EXACT_FIELDS')
    need(doc['schema'] == SIGNED_SCHEMA and
         type(doc['signature_ed25519']) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None and
         anchor.valid_pub(expected_public_hex),
         'SEVENTH_SIGNATURE_SCHEMA_FORMAT_OR_EXTERNAL_KEY_INVALID',
         'invalid_input')
    claim = anchor.exact(doc['claim'], CLAIM_FIELDS,
                         'EC322_ACK_CLAIM_EXACT_FIELDS')
    need(claim['schema'] == CLAIM_SCHEMA and claim['observation'] == OBSERVATION and
         claim['seventh_receiver_public_hex'] == expected_public_hex and
         claim['winner_selected'] is False and
         claim['global_latest_or_external_cas_proven'] is False and
         claim['receiver_physical_or_organizational_authorization_proven'] is False,
         'SEVENTH_CLAIM_SCOPE_MUST_NOT_PRETEND_CAS_OR_AUTHORITY',
         'invalid_input')
    anchor.exact(claim['ec321_independently_required_external_pins'],
                 case.PIN_FIELDS, 'EC322_ORIGINAL_CASE_PIN_SHAPE')
    anchor.exact(claim['replayed_signed_fork_evidence'], FORK_FIELDS,
                 'EC322_OBSERVED_SIGNED_FORK_SHAPE')
    try:
        io.pub_from_hex(expected_public_hex).verify(
            bytes.fromhex(doc['signature_ed25519']),
            SIGN_DOMAIN + reg.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise anchor.AnchorError('EC322_SEVENTH_RECEIVER_ED25519_SIGNATURE_NOT_AUTHENTIC',
                                 'permission_denied') from exc
    return claim


def _exclusive_write(path: str, raw: bytes) -> None:
    parent = bundle._private_parent(path)
    need(not os.path.lexists(parent),
         'ACK_OUTPUT_MUST_NOT_ALREADY_EXIST_OR_OVERWRITE', 'invalid_input')
    fd = -1
    completed = False
    created = False
    try:
        fd = os.open(parent, os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        created = True
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        dirfd = os.open(parent.parent, os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        completed = True
    except FileExistsError as exc:
        raise anchor.AnchorError('EC322_ACK_OUTPUT_EXISTS_NO_OVERWRITE',
                                 'invalid_input') from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if not completed:
            # A prior file cannot be deleted: O_EXCL only grants ownership if
            # this invocation successfully created this path.
            # Existing-file failure is checked before any fd is opened.
            if created:
                try: os.unlink(parent)
                except FileNotFoundError: pass


def _result(receiver: dict, claim: dict, ack_sha: str, status: str) -> dict:
    return {
        'status': status, 'exit_code': 2,
        'ack_id': receiver['ack_id'],
        'case_id': claim['ec321_independently_required_external_pins']['case_id'],
        'seventh_receiver_id': receiver['seventh_receiver_id'],
        'seventh_receiver_public_hex': receiver['seventh_receiver_public_hex'],
        'case_bundle_original_raw_sha256': claim['case_original_raw_sha256'],
        'signed_receiver_ack_original_raw_sha256': ack_sha,
        'original_sixth_witness_raw_sha256':
            claim['ec321_independently_required_external_pins']['expected_witness_sha256'],
        'fork_sequence': claim['replayed_signed_fork_evidence']['fork_sequence'],
        'seventh_receiver_ed25519_signature_verified': True,
        'ec321_case_and_complete_ec320_to_ec294_original_forks_reverified': True,
        'all_visible_original_roles_and_challenges_distinct_from_seventh': True,
        'external_cas_latest_or_fork_winner_proven': False,
        'receiver_physical_or_organizational_authority_proven': False,
        'business_or_external_store_writes_performed': False,
    }


def attest(*, out: str, private_key_file: str,
           bundle_file: str, expected_bundle_sha256: str,
           ack_id: str, seventh_receiver_id: str,
           seventh_receiver_public_hex: str,
           seventh_receiver_challenge_sha256: str,
           **external_pins: str) -> dict:
    receiver = _receiver(ack_id=ack_id,seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256)
    pins = case._pins(**external_pins)
    need(all(reg.original._valid_path(p) for p in
             (out, private_key_file, bundle_file)) and
         len({out,private_key_file,bundle_file}) == 3,
         'ACK_SIGN_OUTPUT_PRIVATE_KEY_AND_ORIGINAL_CASE_PATHS_DISTINCT',
         'invalid_input')
    bundle._private_parent(out)
    need(not os.path.lexists(out),
         'ACK_OUTPUT_MUST_NOT_ALREADY_EXIST_OR_OVERWRITE', 'invalid_input')
    claim,_ = _claimed_observation(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, receiver=receiver,pins=pins)
    document = _signed_document(claim,private_key_file,
                                receiver['seventh_receiver_public_hex'])
    raw = reg.raw_doc(document)
    _exclusive_write(out,raw)
    return _result(receiver,claim,case.sha(raw),
        'seventh_receiver_signed_authentic_offline_fork_case_reverification')


def verify(*, ack_file: str, expected_ack_sha256: str,
           bundle_file: str, expected_bundle_sha256: str,
           ack_id: str, seventh_receiver_id: str,
           seventh_receiver_public_hex: str,
           seventh_receiver_challenge_sha256: str,
           **external_pins: str) -> dict:
    receiver = _receiver(ack_id=ack_id,seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256)
    pins = case._pins(**external_pins)
    need(reg.original._valid_path(ack_file) and
         reg.original._valid_path(bundle_file) and ack_file != bundle_file and
         custody._sha(expected_ack_sha256) and
         custody._sha(expected_bundle_sha256),
         'DISTINCT_PRIVATE_ACK_CASE_AND_WHOLE_RAW_SHA_PINS_REQUIRED',
         'invalid_input')
    signed = reg._load(ack_file,expected_ack_sha256,MAX_RECEIPT,
                       'SEVENTH_RECEIVER_ACK')
    claim = _verify_signature(signed,receiver['seventh_receiver_public_hex'])
    need(all(claim[name] == value for name,value in receiver.items()) and
         claim['case_original_raw_sha256'] == expected_bundle_sha256 and
         claim['ec321_independently_required_external_pins'] == pins,
         'ACK_NOT_EQUAL_EXTERNALLY_SELECTED_ID_CHALLENGE_OR_CASE_PINS',
         'invalid_input')
    reconstructed,_ = _claimed_observation(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256,receiver=receiver,pins=pins)
    need(claim == reconstructed,
         'SEVENTH_SIGNED_ACK_NOT_EQUAL_FULLY_REPLAYED_ORIGINAL_EVIDENCE')
    return _result(receiver,reconstructed,expected_ack_sha256,
        'independent_seventh_signature_and_entire_original_fork_case_reverified')

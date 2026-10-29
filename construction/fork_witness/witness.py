#!/usr/bin/env python3
"""EC320: independent signed custody observation of a REAL EC319 registrar fork.

A sixth Ed25519 signer attests ONLY that both externally pinned offline
registrar histories contained two authentic sibling records, each with its
entire EC318->EC294 signed source closure independently replayed. Signing is
forbidden for identical/prefix histories or when the witness is any observed
custodian, sender, receiver or registrar. An independent reviewer must provide
ALL original SHA pins, path maps, witness ID/key and the attestation's full SHA;
it never promotes signed source paths or a previously generated PASS report to
authority. An offline witness cannot decide which branch won, establish
enterprise authority, freshness, revocation, globally spent challenges or CAS.
"""
from __future__ import annotations

import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature

from delivery_anchor import anchor as anchor
from finding_query_host import protocol as io
from dual_custodian_checkpoint import checkpoint as custody
from offline_transfer_registry import registry as reg

SIGNED_SCHEMA = 'ces.ec320.sixth_independent_signed_fork_attestation.v1'
CLAIM_SCHEMA = 'ces.ec320.genuinely_replayed_registrar_sibling_fork_claim.v1'
RESULT_SCHEMA = 'ces.ec320.independent_fork_witness_result.v1'
DENIAL_SCHEMA = 'ces.ec320.independent_fork_witness_denial.v1'
SIGN_DOMAIN = b'CES/EC320/SixthIndependentSignedRegistrarForkObservation/v1\0'
MAX_ATTESTATION = 16_000
MAX_CASE_ID = 32
OBSERVATION = 'both_original_signed_registrar_siblings_and_ec318_to_ec294_fully_replayed'
SIGNED_FIELDS = frozenset({'schema', 'claim', 'signature_ed25519'})
CLAIM_FIELDS = frozenset({
    'schema', 'case_id', 'witness_id', 'witness_public_hex',
    'witness_challenge_sha256', 'observation',
    'registry_id', 'registrar_id', 'registrar_public_hex',
    'genesis_signed_original_raw_sha256',
    'original_bundle_raw_sha256', 'original_replay_result_sha256',
    'source_reference_count', 'fork_sequence',
    'common_parent_signed_record_raw_sha256',
    'left_divergent_signed_record_raw_sha256',
    'right_divergent_signed_record_raw_sha256',
    'left_snapshot_original_raw_sha256',
    'right_snapshot_original_raw_sha256',
    'left_head_signed_original_raw_sha256',
    'right_head_signed_original_raw_sha256',
    'left_registration_count', 'right_registration_count',
})


def require(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC320_' + reason, status)


def _sha(value: Any) -> bool:
    return custody._sha(value)


def _external(*, case_id: str, witness_id: str, witness_public_hex: str,
              witness_challenge_sha256: str, registrar_id: str,
              registrar_public_hex: str, expected_genesis_raw_sha256: str,
              expected_left_sha256: str, expected_right_sha256: str,
              expected_left_head_raw_sha256: str,
              expected_right_head_raw_sha256: str) -> None:
    require(custody._id(case_id) and len(case_id) <= MAX_CASE_ID and
            custody._id(witness_id) and anchor.valid_pub(witness_public_hex) and
            custody._id(registrar_id) and anchor.valid_pub(registrar_public_hex) and
            _sha(witness_challenge_sha256) and
            all(_sha(value) for value in (
                expected_genesis_raw_sha256, expected_left_sha256,
                expected_right_sha256, expected_left_head_raw_sha256,
                expected_right_head_raw_sha256)) and
            not hmac.compare_digest(expected_left_sha256, expected_right_sha256),
            'INDEPENDENT_CASE_IDS_PUBKEYS_CHALLENGE_AND_TWO_BRANCH_PINS_REQUIRED',
            'invalid_input')


def _witness_is_independent(left: dict, right: dict, witness_id: str,
                            witness_public_hex: str,
                            witness_challenge_sha256: str) -> None:
    """Avoid key/ID overlap with every signer SEEN in EITHER fork branch.

    A fork's two tips may use different EC318 sender/receiver pairs. Counting
    only the first branch or only its tip would incorrectly admit a reused
    historical signer as a seemingly new sixth witness.
    """
    genesis = left['records'][0]['claim']
    trust = genesis['original_source_root']['trust']
    identities = {genesis['registrar_id'], trust['custodian_a_id'],
                  trust['custodian_b_id']}
    public_keys = {genesis['registrar_public_hex'],
                   trust['custodian_a_public_hex'],
                   trust['custodian_b_public_hex']}
    challenges = {genesis['registrar_epoch_challenge_sha256'],
                  genesis['original_source_root']['expected_latest_challenge_sha256']}
    # Both branches are already independently authenticated by EC319.compare.
    for snapshot in (left, right):
        for signed in snapshot['records'][1:]:
            c = signed['claim']
            identities.update((c['sender_id'], c['receiver_id']))
            public_keys.update((c['sender_public_hex'], c['receiver_public_hex']))
            challenges.update(c[name] for name in (
                'sender_exchange_challenge_sha256',
                'receiver_exchange_challenge_sha256',
                'sender_confirmation_challenge_sha256',
                'registrar_entry_challenge_sha256'))
    require(witness_id not in identities and witness_public_hex not in public_keys,
            'SIXTH_WITNESS_MUST_HAVE_NEW_ID_AND_ED25519_KEY_ACROSS_BOTH_BRANCHES',
            'invalid_input')
    require(witness_challenge_sha256 not in challenges,
            'WITNESS_CHALLENGE_REUSES_VISIBLE_HISTORICAL_CHALLENGE',
            'invalid_input')


def _compare_full_originals(*, left_file: str, expected_left_sha256: str,
                            left_materials_file: str,
                            expected_left_head_raw_sha256: str,
                            right_file: str, expected_right_sha256: str,
                            right_materials_file: str,
                            expected_right_head_raw_sha256: str,
                            expected_genesis_raw_sha256: str,
                            registrar_id: str, registrar_public_hex: str,
                            case_id: str, witness_id: str,
                            witness_public_hex: str,
                            witness_challenge_sha256: str) -> dict:
    _external(case_id=case_id, witness_id=witness_id,
        witness_public_hex=witness_public_hex,
        witness_challenge_sha256=witness_challenge_sha256,
        registrar_id=registrar_id, registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_left_sha256=expected_left_sha256,
        expected_right_sha256=expected_right_sha256,
        expected_left_head_raw_sha256=expected_left_head_raw_sha256,
        expected_right_head_raw_sha256=expected_right_head_raw_sha256)
    paths = (left_file, left_materials_file, right_file, right_materials_file)
    require(all(reg.original._valid_path(p) for p in paths) and
            left_file != right_file and
            left_file not in (left_materials_file, right_materials_file) and
            right_file not in (left_materials_file, right_materials_file),
            'TWO_DISTINCT_PRIVATE_SNAPSHOT_FILES_AND_LOCAL_MATERIALS_REQUIRED',
            'invalid_input')
    # Mandatory genuine independent branch-by-branch replay, never just
    # signature verification of the two top-level EC319 registrar records.
    compared = reg.compare(left_file=left_file,
        expected_left_sha256=expected_left_sha256,
        left_materials_file=left_materials_file,
        expected_left_head_raw_sha256=expected_left_head_raw_sha256,
        right_file=right_file, expected_right_sha256=expected_right_sha256,
        right_materials_file=right_materials_file,
        expected_right_head_raw_sha256=expected_right_head_raw_sha256,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        registrar_id=registrar_id, registrar_public_hex=registrar_public_hex)
    require(compared.get('exit_code') == 2 and
            compared.get('status') ==
                'two_authentic_registrar_branches_from_same_signed_parent' and
            compared.get('both_forks_full_ec318_to_ec294_replayed') is True and
            compared.get('left_snapshot_original_raw_sha256') ==
                expected_left_sha256 and
            compared.get('right_snapshot_original_raw_sha256') ==
                expected_right_sha256,
            'CANNOT_ATTEST_IDENTICAL_PREFIX_OR_UNVERIFIED_REGISTRAR_BRANCHES',
            'invalid_input')
    # Exact SHA pins make the second read equivalent to the independently
    # authenticated snapshot reads despite untrusted file paths. No persisted
    # or unsigned previous 'PASS' report is consulted.
    left = reg._load(left_file, expected_left_sha256, reg.MAX_SNAPSHOT,
                     'LEFT_WITNESS_SNAPSHOT')
    right = reg._load(right_file, expected_right_sha256, reg.MAX_SNAPSHOT,
                      'RIGHT_WITNESS_SNAPSHOT')
    _witness_is_independent(left, right, witness_id, witness_public_hex,
                            witness_challenge_sha256)
    genesis = left['records'][0]['claim']
    sequence = compared['divergent_sequence']
    require(type(sequence) is int and 1 <= sequence <= reg.MAX_ENTRIES and
            right['records'][0] == left['records'][0] and
            sequence < len(left['records']) and
            sequence < len(right['records']) and
            reg.digest(reg.raw_doc(left['records'][sequence - 1])) ==
                compared['shared_previous_signed_record_raw_sha256'] and
            reg.digest(reg.raw_doc(right['records'][sequence - 1])) ==
                compared['shared_previous_signed_record_raw_sha256'] and
            reg.digest(reg.raw_doc(left['records'][sequence])) ==
                compared['left_divergent_signed_record_raw_sha256'] and
            reg.digest(reg.raw_doc(right['records'][sequence])) ==
                compared['right_divergent_signed_record_raw_sha256'],
            'COMPARE_PROOF_DOES_NOT_MATCH_ACTUAL_SIBLING_SIGNED_RECORD_BYTES',
            'unavailable')
    claim = {
        'schema': CLAIM_SCHEMA,
        'case_id': case_id,
        'witness_id': witness_id,
        'witness_public_hex': witness_public_hex,
        'witness_challenge_sha256': witness_challenge_sha256,
        'observation': OBSERVATION,
        'registry_id': genesis['registry_id'],
        'registrar_id': registrar_id,
        'registrar_public_hex': registrar_public_hex,
        'genesis_signed_original_raw_sha256': expected_genesis_raw_sha256,
        'original_bundle_raw_sha256': genesis['transfer_bundle_raw_sha256'],
        'original_replay_result_sha256': genesis['original_replay_result_sha256'],
        'source_reference_count': genesis['source_reference_count'],
        'fork_sequence': sequence,
        'common_parent_signed_record_raw_sha256':
            compared['shared_previous_signed_record_raw_sha256'],
        'left_divergent_signed_record_raw_sha256':
            compared['left_divergent_signed_record_raw_sha256'],
        'right_divergent_signed_record_raw_sha256':
            compared['right_divergent_signed_record_raw_sha256'],
        'left_snapshot_original_raw_sha256': expected_left_sha256,
        'right_snapshot_original_raw_sha256': expected_right_sha256,
        'left_head_signed_original_raw_sha256': expected_left_head_raw_sha256,
        'right_head_signed_original_raw_sha256': expected_right_head_raw_sha256,
        'left_registration_count': len(left['records'])-1,
        'right_registration_count': len(right['records'])-1,
    }
    require(set(claim) == CLAIM_FIELDS, 'WITNESS_CLAIM_INTERNAL_FIELDS_INVALID',
            'unavailable')
    return claim


def _verify_witness_signature(signed: dict, public_hex: str) -> dict:
    anchor.exact(signed, SIGNED_FIELDS, 'EC320_ATTESTATION_EXACT_FIELDS_REQUIRED')
    require(signed['schema'] == SIGNED_SCHEMA and
            type(signed['signature_ed25519']) is str and
            anchor.SIG.fullmatch(signed['signature_ed25519']) is not None and
            anchor.valid_pub(public_hex),
            'SIXTH_SIGNATURE_FORMAT_OR_PUBLIC_KEY_INVALID', 'invalid_input')
    claim = anchor.exact(signed['claim'], CLAIM_FIELDS,
                         'EC320_WITNESS_CLAIM_EXACT_FIELDS_REQUIRED')
    require(claim['schema'] == CLAIM_SCHEMA and
            claim['observation'] == OBSERVATION and
            claim['witness_public_hex'] == public_hex,
            'SIXTH_SIGNATURE_CLAIM_DOMAIN_OR_PUBLIC_KEY_INVALID',
            'invalid_input')
    try:
        io.pub_from_hex(public_hex).verify(
            bytes.fromhex(signed['signature_ed25519']),
            SIGN_DOMAIN + reg.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise anchor.AnchorError('EC320_SIXTH_ED25519_SIGNATURE_NOT_AUTHENTIC',
                                 'permission_denied') from exc
    return claim


def _result(claim: dict, *, signed_raw_sha256: str, status: str) -> dict:
    return {
        'status': status,
        'exit_code': 2,  # A proven fork is not a healthy single registry head.
        'case_id': claim['case_id'],
        'witness_id': claim['witness_id'],
        'registry_id': claim['registry_id'],
        'registrar_id': claim['registrar_id'],
        'fork_sequence': claim['fork_sequence'],
        'common_parent_signed_record_raw_sha256':
            claim['common_parent_signed_record_raw_sha256'],
        'left_divergent_signed_record_raw_sha256':
            claim['left_divergent_signed_record_raw_sha256'],
        'right_divergent_signed_record_raw_sha256':
            claim['right_divergent_signed_record_raw_sha256'],
        'left_snapshot_original_raw_sha256':
            claim['left_snapshot_original_raw_sha256'],
        'right_snapshot_original_raw_sha256':
            claim['right_snapshot_original_raw_sha256'],
        'attestation_original_raw_sha256': signed_raw_sha256,
        'sixth_witness_ed25519_signature_verified': True,
        'both_registrar_siblings_and_all_originals_replayed': True,
        'external_global_latest_or_winner_proven': False,
        'six_independent_authorized_human_signers_proven': False,
        'offline_witness_challenge_globally_unique_proven': False,
        'original_business_or_remote_cas_writes_performed': False,
    }


def attest(*, case_id: str, witness_id: str, witness_public_hex: str,
           witness_challenge_sha256: str, private_key_file: str, out: str,
           **branches: str) -> dict:
    sources = tuple(branches[k] for k in (
        'left_file', 'right_file', 'left_materials_file',
        'right_materials_file')) + (private_key_file,)
    reg._out(out, sources)  # Exclusive new owner-private file, not a source.
    require(reg.original._valid_path(private_key_file),
            'SIXTH_SIGNING_KEY_MUST_BE_OWNER_PRIVATE_ABSOLUTE_FILE',
            'invalid_input')
    claim = _compare_full_originals(case_id=case_id, witness_id=witness_id,
        witness_public_hex=witness_public_hex,
        witness_challenge_sha256=witness_challenge_sha256, **branches)
    # No key file is read UNTIL two full original independent replays, genuine
    # sibling fork verification, and six-way key/ID separation all succeeded.
    key = io.private_from_file(private_key_file)
    require(hmac.compare_digest(reg._public(key), witness_public_hex),
            'SIXTH_SIGNING_PRIVATE_KEY_NOT_EXTERNALLY_SELECTED_PUBLIC_KEY')
    signed = {'schema': SIGNED_SCHEMA, 'claim': claim,
              'signature_ed25519':key.sign(SIGN_DOMAIN + reg.canonical(claim)).hex()}
    require(len(reg.raw_doc(signed)) <= MAX_ATTESTATION,
            'SIGNED_ATTESTATION_EXCEEDS_BOUNDED_SIZE', 'invalid_input')
    _verify_witness_signature(signed, witness_public_hex)
    signed_sha = reg.digest(reg.raw_doc(signed))
    reg.store.store(out, signed, MAX_ATTESTATION)
    return _result(claim, signed_raw_sha256=signed_sha,
        status='independent_sixth_witness_signed_genuine_registrar_fork')


def verify(*, witness_file: str, expected_witness_sha256: str,
           case_id: str, witness_id: str, witness_public_hex: str,
           witness_challenge_sha256: str, **branches: str) -> dict:
    require(witness_file not in {branches['left_file'], branches['right_file'],
                branches['left_materials_file'], branches['right_materials_file']},
            'ATTESTATION_MUST_BE_DISTINCT_FROM_BOTH_BRANCHES_AND_MAPS',
            'invalid_input')
    require(_sha(expected_witness_sha256),
            'WITNESS_ATTESTATION_EXTERNAL_WHOLE_RAW_SHA_REQUIRED', 'invalid_input')
    signed = reg._load(witness_file, expected_witness_sha256,
                       MAX_ATTESTATION, 'SIGNED_WITNESS_ATTESTATION')
    claim = _verify_witness_signature(signed, witness_public_hex)
    require(claim['case_id'] == case_id and
            claim['witness_id'] == witness_id and
            claim['witness_challenge_sha256'] == witness_challenge_sha256,
            'WITNESS_CASE_ID_CHALLENGE_OR_TRUST_ID_NOT_EXTERNALLY_PINNED',
            'invalid_input')
    # Don't get ANY source path/pin/authority from the signed claim. Require
    # separately caller-supplied branch SHA pins and independently re-run the
    # two full original EC319->EC318->EC294 cryptographic histories.
    rebuilt = _compare_full_originals(case_id=case_id, witness_id=witness_id,
        witness_public_hex=witness_public_hex,
        witness_challenge_sha256=witness_challenge_sha256, **branches)
    require(hmac.compare_digest(reg.canonical(claim), reg.canonical(rebuilt)),
            'SIXTH_SIGNED_FORK_EVIDENCE_NOT_EQUAL_FRESH_FULL_ORIGINAL_REPLAY')
    return _result(rebuilt, signed_raw_sha256=expected_witness_sha256,
        status='independent_sixth_signature_and_both_complete_original_forks_reverified')

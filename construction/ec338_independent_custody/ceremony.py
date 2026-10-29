#!/usr/bin/env python3
"""EC338 offline cryptographic custody ceremony around EC337 ORIGINAL bytes.

A bounded, EXTERNALLY PINNED roster binds exactly seven independent EC337
whole-original SHA roots, four different public keys and claimed organizations.
Each actor signs a role-specific Ed25519 claim chained to the PREVIOUS signed
receipt's complete LF JSON raw SHA. All four receipt raw SHAs are also independently
supplied by the receiver, not taken from receipt content or the unsigned ZIP.

The verifier always re-runs real EC337 complete ZIP/member/nested-member checks.
It verifies signed *statements*, not the truth of physical observations, credential
issuance, organizational authority, revocation, timestamps, actual physical device
independence, EC336 full old signed history, or external CAS/WORM state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hmac
import os
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt as prior
from ec337_airgap_transport import transport

POLICY_SCHEMA = 'ces.ec338.externally_pinned_four_role_airgap_custody_roster.v1'
CLAIM_SCHEMA = 'ces.ec338.role_bound_offline_custody_observation_claim.v1'
SIGNED_SCHEMA = 'ces.ec338.ed25519_role_bound_offline_custody_receipt.v1'
RESULT_SCHEMA = 'ces.ec338.four_role_custody_cryptographic_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec338.custody_chain_denial.v1'
ROLES = ('sender', 'carrier', 'receiver', 'witness')
EVENTS = ('sender_declares_sealed_original_bundle',
          'carrier_declares_accepted_same_sealed_medium',
          'receiver_declares_received_same_sealed_medium',
          'independent_witness_declares_observed_receipt_chain')
ROOT_MAP = (
    ('bundle_original_raw_sha256', 'expected_bundle_sha256'),
    ('plan_original_raw_sha256', 'expected_first_hop_plan_sha256'),
    ('closure_original_raw_sha256', 'expected_closure_sha256'),
    ('map_original_raw_sha256', 'expected_map_sha256'),
    ('handoff_original_raw_sha256', 'expected_handoff_sha256'),
    ('left_manifest_original_raw_sha256', 'left_expected_manifest_sha256'),
    ('right_manifest_original_raw_sha256', 'right_expected_manifest_sha256'),
)
POLICY_FIELDS = frozenset({'schema', 'transfer_id', 'medium_identifier_sha256',
                           'original_roots', 'actors',
                           'authority_and_revocation_require_external_verification'})
ACTOR_FIELDS = frozenset({'role', 'actor_id', 'organization_id',
                          'public_hex', 'authorization_reference_sha256'})
CLAIM_FIELDS = frozenset({'schema', 'transfer_id', 'medium_identifier_sha256',
                          'role', 'event', 'sequence', 'actor_id', 'organization_id',
                          'signer_public_hex', 'authorization_reference_sha256',
                          'policy_original_raw_sha256', 'bundle_original_raw_sha256',
                          'previous_receipt_original_raw_sha256', 'nonce_sha256',
                          'signer_reported_utc',
                          'physical_independence_or_institutional_authority_proven_by_software'})
SIGNED_FIELDS = frozenset({'schema', 'claim', 'signature_ed25519'})
MAX_POLICY = 12_000
MAX_RECEIPT = 12_000
ZERO = '0' * 64
ID = re.compile(r'[a-z][a-z0-9_-]{2,63}\Z')
STAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
FALSE_FIELDS = (
    'policy_whole_sha_or_public_keys_self_certify_real_institutional_authority',
    'authorization_reference_sha_proves_authority_or_current_revocation_status',
    'signatures_prove_physical_handoff_or_two_separate_real_devices',
    'signer_reported_utc_is_a_trusted_clock_attestation',
    'ec336_entire_unmocked_old_signed_history_replayed_by_this_audit',
    'old_absolute_signature_paths_or_original_source_bytes_rewritten',
    'remote_cas_worm_actual_nonexecution_latest_winner_or_delivery_proven',
    'network_business_provider_or_remote_cas_write_performed',
)


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC338_' + reason, status)


def _sha(v: Any, *, zero: bool = False) -> bool:
    return prior._sha(v, allow_zero=zero)


def _id(v: Any) -> bool:
    return type(v) is str and ID.fullmatch(v) is not None


def _utc(value: Any) -> bool:
    if type(value) is not str or STAMP.fullmatch(value) is None:
        return False
    try:
        stamp = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return stamp.strftime('%Y-%m-%dT%H:%M:%SZ') == value


def _domain(role: str) -> bytes:
    need(role in ROLES, 'ONLY_FIXED_CUSTODY_ROLES', 'invalid_input')
    return b'CES/EC338/IndependentAirgapCustodyReceipt/' + role.encode('ascii') + b'/v1\0'


def _roots(pins: dict[str, str]) -> dict[str, str]:
    roots = {}
    for original_key, arg_key in ROOT_MAP:
        value = pins.get(arg_key)
        need(_sha(value), 'SEVEN_EXPLICIT_INDEPENDENT_WHOLE_SHA_ROOTS_REQUIRED',
             'invalid_input')
        roots[original_key] = value
    return roots


def _policy_validate(value: Any, roots: dict) -> dict:
    need(type(value) is dict and set(value) == POLICY_FIELDS and
         value.get('schema') == POLICY_SCHEMA and
         _id(value.get('transfer_id')) and
         _sha(value.get('medium_identifier_sha256')) and
         type(value.get('original_roots')) is dict and
         value['original_roots'] == roots and
         value.get('authority_and_revocation_require_external_verification') is True,
         'PINNED_POLICY_ROOTS_AND_UNPROVEN_AUTHORITY_BOUNDARIES_INVALID', 'invalid_input')
    actors = value.get('actors')
    need(type(actors) is list and len(actors) == 4,
         'EXACT_FOUR_POLICY_ACTORS_REQUIRED', 'invalid_input')
    for actor, role in zip(actors, ROLES):
        need(type(actor) is dict and set(actor) == ACTOR_FIELDS and
             actor.get('role') == role and _id(actor.get('actor_id')) and
             _id(actor.get('organization_id')) and
             anchor.valid_pub(actor.get('public_hex')) and
             _sha(actor.get('authorization_reference_sha256')),
             'FOUR_ORDERED_EXTERNALLY_AUTHORIZED_IDENTITIES_REQUIRED', 'invalid_input')
    need(all(len({actor[key] for actor in actors}) == 4 for key in
             ('actor_id', 'public_hex', 'authorization_reference_sha256')) and
         actors[0]['organization_id'] != actors[2]['organization_id'] and
         actors[3]['organization_id'] not in {
            a['organization_id'] for a in actors[:3]},
         'WITNESS_ORG_MUST_BE_DISTINCT_AND_SENDER_RECEIVER_ORGS_DIFFER',
         'invalid_input')
    return value


def _load_policy(policy_file: str, expected_policy_sha256: str,
                 roots: dict) -> tuple[dict, bytes]:
    need(_sha(expected_policy_sha256),
         'INDEPENDENT_WHOLE_POLICY_SHA_REQUIRED', 'invalid_input')
    raw = reg._private_read(policy_file, MAX_POLICY, 'EC338_POLICY')
    need(hmac.compare_digest(case.sha(raw), expected_policy_sha256),
         'POLICY_NOT_EQUAL_EXTERNALLY_TRUSTED_ORIGINAL_SHA')
    doc = io.parse(raw, MAX_POLICY)
    need(raw == reg.raw_doc(doc), 'NONCANONICAL_POLICY_LF_JSON', 'invalid_input')
    return _policy_validate(doc, roots), raw


def _expected_claim(policy: dict, policy_sha: str, index: int,
                    previous_sha: str, claim: dict) -> None:
    actor = policy['actors'][index]
    need(type(claim) is dict and set(claim) == CLAIM_FIELDS and
         claim.get('schema') == CLAIM_SCHEMA and
         claim.get('transfer_id') == policy['transfer_id'] and
         claim.get('medium_identifier_sha256') == policy['medium_identifier_sha256'] and
         claim.get('role') == ROLES[index] and
         claim.get('event') == EVENTS[index] and
         type(claim.get('sequence')) is int and claim['sequence'] == index + 1 and
         claim.get('actor_id') == actor['actor_id'] and
         claim.get('organization_id') == actor['organization_id'] and
         claim.get('signer_public_hex') == actor['public_hex'] and
         claim.get('authorization_reference_sha256') == actor['authorization_reference_sha256'] and
         claim.get('policy_original_raw_sha256') == policy_sha and
         claim.get('bundle_original_raw_sha256') == policy['original_roots']['bundle_original_raw_sha256'] and
         claim.get('previous_receipt_original_raw_sha256') == previous_sha and
         _sha(claim.get('nonce_sha256')) and
         _utc(claim.get('signer_reported_utc')) and
         claim.get('physical_independence_or_institutional_authority_proven_by_software') is False,
         'SIGNED_ROLE_EVENT_ACTOR_ROOT_PREVIOUS_OR_NONCE_MISMATCH', 'invalid_input')


def _load_receipt(path: str, expected_sha: str, policy: dict,
                  policy_sha: str, index: int, previous_sha: str) -> tuple[dict, bytes]:
    need(_sha(expected_sha), 'INDEPENDENT_RECEIPT_WHOLE_SHA_REQUIRED','invalid_input')
    raw = reg._private_read(path, MAX_RECEIPT, 'EC338_' + ROLES[index].upper())
    need(hmac.compare_digest(case.sha(raw), expected_sha),
         'SIGNED_RECEIPT_NOT_EQUAL_INDEPENDENT_WHOLE_SHA')
    doc = io.parse(raw, MAX_RECEIPT)
    need(raw == reg.raw_doc(doc) and type(doc) is dict and
         set(doc) == SIGNED_FIELDS and doc.get('schema') == SIGNED_SCHEMA and
         type(doc.get('signature_ed25519')) is str and
         anchor.SIG.fullmatch(doc['signature_ed25519']) is not None,
         'SIGNED_RECEIPT_MUST_BE_CANONICAL_EXACT_ED25519_JSON', 'invalid_input')
    claim = doc['claim']
    _expected_claim(policy, policy_sha, index, previous_sha, claim)
    try:
        io.pub_from_hex(policy['actors'][index]['public_hex']).verify(
            bytes.fromhex(doc['signature_ed25519']),
            _domain(ROLES[index]) + reg.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise anchor.AnchorError('EC338_INDEPENDENT_ROLE_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc, raw


def _read_chain(policy: dict, policy_sha: str,
                receipt_paths: list[str], receipt_shas: list[str]) -> list[dict]:
    need(len(receipt_paths) == len(receipt_shas) and
         0 <= len(receipt_paths) <= 4 and
         all(type(p) is str for p in receipt_paths) and
         len(set(receipt_paths)) == len(receipt_paths) and
         all(_sha(s) for s in receipt_shas),
         'DISTINCT_ORDERED_RECEIPTS_AND_EACH_INDEPENDENT_SHA_REQUIRED',
         'invalid_input')
    previous = ZERO
    observed_nonces = set()
    docs = []
    for index, (path, pinned) in enumerate(zip(receipt_paths, receipt_shas)):
        doc, raw = _load_receipt(path,pinned,policy,policy_sha,index,previous)
        nonce = doc['claim']['nonce_sha256']
        need(nonce not in observed_nonces,
             'SIGNED_CUSTODY_NONCE_REUSED_WITHIN_TRANSFER', 'invalid_input')
        observed_nonces.add(nonce)
        previous = case.sha(raw)
        docs.append(doc)
    return docs


def _inputs_distinct(policy_file: str, bundle_file: str,
                     receipt_paths: list[str], extra: list[str] | None = None) -> None:
    paths=[policy_file,bundle_file,*receipt_paths,*(extra or [])]
    need(all(reg.original._valid_path(p) for p in paths) and
         len(set(paths)) == len(paths),
         'ALL_CANONICAL_INPUTS_SEPARATE_NO_ALIAS_PATHS_REQUIRED',
         'invalid_input')


def _inspect_archive(bundle_file: str, pins: dict) -> dict:
    observed = transport.inspect_bundle(bundle_file=bundle_file, **pins)
    need(observed.get('exit_code') == 2 and
         observed.get('command') == 'inspect-bundle' and
         observed.get('all_archive_members_whole_sha_verified') is True and
         observed.get('blank_external_custody_worksheet_byte_verified') is True and
         observed.get('offline_unresolved_exit_code') == 2 and
         all(observed.get(k) is False for k in transport.FALSE_FIELDS),
         'INHERITED_EC337_COMPLETE_BYTE_AUDIT_UNAVAILABLE')
    return observed


def _late_repin(policy_file: str, policy_sha: str,
                receipt_paths: list[str], receipt_shas: list[str],
                bundle_file: str, bundle_sha: str) -> None:
    for path, sha, limit, label in [
        (policy_file,policy_sha,MAX_POLICY,'LATE_POLICY'),
        *[(path,sha,MAX_RECEIPT,'LATE_'+ROLES[i].upper()) for i,(path,sha) in
          enumerate(zip(receipt_paths,receipt_shas))]]:
        need(hmac.compare_digest(case.sha(reg._private_read(path,limit,'EC338_'+label)),sha),
             label+'_WHOLE_RAW_BYTES_CHANGED_AFTER_AUDIT')
    need(transport._sha_path(bundle_file) == bundle_sha,
         'LATE_TRANSPORT_WHOLE_RAW_BYTES_CHANGED_AFTER_SIGNATURE_AUDIT')


def verify_chain(*, policy_file: str, expected_policy_sha256: str,
                 bundle_file: str, sender_receipt_file: str,
                 expected_sender_receipt_sha256: str,
                 carrier_receipt_file: str, expected_carrier_receipt_sha256: str,
                 receiver_receipt_file: str, expected_receiver_receipt_sha256: str,
                 witness_receipt_file: str, expected_witness_receipt_sha256: str,
                 **pins: str) -> dict:
    """Read-only: seven archive/controls + policy + FOUR receipt external pins.

    Exit 2 means four role-key signatures and all observed original bytes were
    locally checked. It NEVER means true external custody or organizational
    authority was independently established by this software.
    """
    roots=_roots(pins)
    paths=[sender_receipt_file,carrier_receipt_file,
           receiver_receipt_file,witness_receipt_file]
    shas=[expected_sender_receipt_sha256,expected_carrier_receipt_sha256,
          expected_receiver_receipt_sha256,expected_witness_receipt_sha256]
    _inputs_distinct(policy_file,bundle_file,paths)
    policy, _=_load_policy(policy_file,expected_policy_sha256,roots)
    documents=_read_chain(policy,expected_policy_sha256,paths,shas)
    need(len(documents) == 4,
         'FOUR_SIGNED_ROLE_RECEIPTS_REQUIRED', 'invalid_input')
    archive=_inspect_archive(bundle_file,pins)
    _late_repin(policy_file,expected_policy_sha256,paths,shas,bundle_file,
                pins['expected_bundle_sha256'])
    return {
        'schema':RESULT_SCHEMA,'command':'verify-chain',
        'status':'four_role_pinned_local_signature_and_original_bytes_verified_unresolved',
        'exit_code':2,'transfer_id':policy['transfer_id'],
        'medium_identifier_sha256':policy['medium_identifier_sha256'],
        'policy_original_raw_sha256':expected_policy_sha256,
        'original_roots':roots,
        'receipt_original_raw_sha256s':dict(zip(ROLES,shas)),
        'receipt_roles_verified_in_order':list(ROLES),
        'signature_count_verified':4,
        'whole_receipt_external_sha_and_previous_raw_sha_chain_verified':True,
        'ed25519_role_scoped_independent_public_keys_verified':True,
        'declared_witness_organization_distinct_in_trusted_policy':True,
        'ec337_complete_archive_and_nested_originals_verified':True,
        'ec337_persistent_original_source_count':archive['persistent_original_source_count'],
        'ec337_verified_nested_member_count':archive['nested_zip_member_identity_verified_count'],
        'caller_must_entrust_all_twelve_raw_sha_values_outside_local_untrusted_files':True,
        'ec336_old_signed_history_must_run_separately':True,
        'offline_unresolved_exit_code':2,
        **{field:False for field in FALSE_FIELDS},
    }


def sign_receipt(*, role: str, out: str, private_key_file: str,
                 nonce_sha256: str, signer_reported_utc: str,
                 policy_file: str, expected_policy_sha256: str,
                 bundle_file: str, prior_receipt_files: list[str],
                 prior_receipt_shas: list[str], **pins: str) -> dict:
    """Create ONE locally signed declaration, never an external trust root.

    Each participant must separately receive the authenticated policy and all
    original SHA pins; an operator holding all keys can produce syntactically
    valid statements but this cannot establish independent real people/devices.
    """
    need(role in ROLES and _sha(nonce_sha256) and _utc(signer_reported_utc),
         'KNOWN_ROLE_FRESH_NONCE_AND_STRICT_SELF_REPORTED_UTC_REQUIRED',
         'invalid_input')
    index=ROLES.index(role)
    need(len(prior_receipt_files)==index and len(prior_receipt_shas)==index,
         'SIGNER_REQUIRES_ALL_PINNED_PREVIOUS_ROLE_RECEIPTS', 'invalid_input')
    _inputs_distinct(policy_file,bundle_file,prior_receipt_files,
                     [out,private_key_file])
    roots=_roots(pins)
    policy,_=_load_policy(policy_file,expected_policy_sha256,roots)
    earlier=_read_chain(policy,expected_policy_sha256,
                        prior_receipt_files,prior_receipt_shas)
    need(nonce_sha256 not in {doc['claim']['nonce_sha256'] for doc in earlier},
         'SIGNER_NONCE_MUST_NOT_REUSE_ANY_PREVIOUS_TRANSFER_ROLE')
    _inspect_archive(bundle_file,pins)  # Read every byte and nested old ZIP member BEFORE key access.
    previous=prior_receipt_shas[-1] if index else ZERO
    actor=policy['actors'][index]
    claim={
        'schema':CLAIM_SCHEMA,'transfer_id':policy['transfer_id'],
        'medium_identifier_sha256':policy['medium_identifier_sha256'],
        'role':role,'event':EVENTS[index], 'sequence':index+1,
        'actor_id':actor['actor_id'], 'organization_id':actor['organization_id'],
        'signer_public_hex':actor['public_hex'],
        'authorization_reference_sha256':actor['authorization_reference_sha256'],
        'policy_original_raw_sha256':expected_policy_sha256,
        'bundle_original_raw_sha256':pins['expected_bundle_sha256'],
        'previous_receipt_original_raw_sha256':previous,
        'nonce_sha256':nonce_sha256, 'signer_reported_utc':signer_reported_utc,
        'physical_independence_or_institutional_authority_proven_by_software':False,
    }
    _expected_claim(policy,expected_policy_sha256,index,previous,claim)
    # The old EC322 operator only accepts a private owner-secured local key.
    key=io.private_from_file(private_key_file)
    pub=key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(pub,actor['public_hex']),
         'LOCAL_SECRET_KEY_DOES_NOT_MATCH_SEPARATELY_AUTHORIZED_ROLE_KEY')
    signed={'schema':SIGNED_SCHEMA,'claim':claim,
            'signature_ed25519':key.sign(_domain(role)+reg.canonical(claim)).hex()}
    raw=reg.raw_doc(signed)
    need(len(raw)<=MAX_RECEIPT,'SIGNED_CUSTODY_RECEIPT_EXCEEDS_BUDGET','invalid_input')
    # Prevent TOCTOU between lengthy archive inspection and writing any newly
    # signed statement; no output is created on changed source inputs.
    _late_repin(policy_file,expected_policy_sha256,prior_receipt_files,
                prior_receipt_shas,bundle_file,pins['expected_bundle_sha256'])
    prior._write_exclusive(out,raw)
    # In case of a later check failure, attempt to remove only this new inode;
    # do not unlink a different inode supplied by a concurrent actor.
    created_stat = os.lstat(out)
    try:
        actual = reg._private_read(out,MAX_RECEIPT,'EC338_SIGNED_OUTPUT')
        need(actual == raw,'SIGNED_OUTPUT_BYTES_CHANGED_AFTER_WRITE')
        _load_receipt(out,case.sha(raw),policy,expected_policy_sha256,index,previous)
        _late_repin(policy_file,expected_policy_sha256,prior_receipt_files,
                    prior_receipt_shas,bundle_file,pins['expected_bundle_sha256'])
        # The local SHA is OUTPUT METADATA ONLY, never a new externally trusted pin.
        return {
            'schema':RESULT_SCHEMA,'command':'sign-receipt',
            'status':'locally_signed_candidate_untrusted_until_independent_custody',
            'exit_code':2,'role':role,'transfer_id':policy['transfer_id'],
            'receipt_original_raw_sha256_local_untrusted':case.sha(raw),
            'policy_original_raw_sha256':expected_policy_sha256,
            'separately_trusted_receipt_sha_required_by_receiver':True,
            'ec337_complete_archive_and_nested_originals_verified':True,
            'no_claim_of_institutional_trust_or_real_custody':True,
            'offline_unresolved_exit_code':2,
            **{field:False for field in FALSE_FIELDS},
        }
    except Exception:
        # Best effort only; not an atomic transaction against concurrent writers.
        try:
            now=os.lstat(out)
            if (stat.S_ISREG(now.st_mode) and now.st_dev == created_stat.st_dev and
                now.st_ino == created_stat.st_ino and now.st_nlink == 1 and
                reg._private_read(out,MAX_RECEIPT,'EC338_FAILED_OUTPUT') == raw):
                os.unlink(out)
        except (OSError, ValueError, anchor.AnchorError, io.HostError):
            pass
        raise

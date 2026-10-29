#!/usr/bin/env python3
"""EC319 offline, fifth-key, signed registry of *fully replayed* EC318 receipts.

An immutable new snapshot is written for every extension; an original snapshot
is never overwritten. Every stored event is a domain-separated Ed25519 signature
of its own bounded claim and the preceding signed event's EXACT stored bytes.
Each audit independently replays EC318->317->316->294 signed originals, checks
all five roles and prevents challenge/receipt reuse *inside the supplied history*.
Different valid siblings can be compared to expose independently verifiable
registrar equivocation. Without an external non-rollback head/atomic CAS, no
single view can prove globally unique issuance or "latest".
"""
from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from dual_custodian_checkpoint import checkpoint as custody
from original_rebinding import rebinding as original
from bilateral_transfer_receipt import receipt as receipt

SNAPSHOT_SCHEMA = 'ces.ec319.offline_signed_transfer_registry_snapshot.v1'
SIGNED_SCHEMA = 'ces.ec319.domain_separated_registrar_signed_record.v1'
GENESIS_SCHEMA = 'ces.ec319.offline_registry_genesis_claim.v1'
ENTRY_SCHEMA = 'ces.ec319.offline_registered_transfer_claim.v1'
MATERIALS_SCHEMA = 'ces.ec319.local_unsigned_material_path_map.v1'
RESULT_SCHEMA = 'ces.ec319.offline_registrar_result.v1'
DENIAL_SCHEMA = 'ces.ec319.offline_registrar_denial.v1'
GENESIS_DOMAIN = b'CES/EC319/OfflineOriginalSHARegistrar/Genesis/v1\0'
ENTRY_DOMAIN = b'CES/EC319/OfflineOriginalSHARegistrar/UniqueTransfer/v1\0'
MAX_ENTRIES = 4
MAX_SNAPSHOT = 250_000
MAX_MATERIALS = 18_000
MAX_SIGNED_RECORD = 18_000
GENESIS_FIELDS = frozenset({
    'schema','registry_id','registrar_id','registrar_public_hex',
    'registrar_epoch_challenge_sha256','original_source_root',
    'transfer_bundle_raw_sha256','original_replay_result_sha256',
    'source_reference_count',
})
ENTRY_FIELDS = frozenset({
    'schema','registry_id','registry_genesis_raw_sha256','sequence',
    'previous_signed_record_raw_sha256','transfer_bundle_raw_sha256',
    'offer_original_raw_sha256','ack_original_raw_sha256',
    'closure_original_raw_sha256','sender_id','sender_public_hex',
    'receiver_id','receiver_public_hex',
    'sender_exchange_challenge_sha256',
    'receiver_exchange_challenge_sha256',
    'sender_confirmation_challenge_sha256',
    'registrar_entry_challenge_sha256',
    'original_replay_result_sha256','binding_canonical_sha256',
    'source_reference_count',
})
NEW_FIELDS = frozenset(ENTRY_FIELDS - {
    'schema','registry_id','registry_genesis_raw_sha256','sequence',
    'previous_signed_record_raw_sha256','transfer_bundle_raw_sha256',
    'original_replay_result_sha256','binding_canonical_sha256',
    'source_reference_count',
})
SIGNED_FIELDS = frozenset({'schema','claim','signature_ed25519'})
SNAPSHOT_FIELDS = frozenset({'schema','records'})
MATERIALS_FIELDS = frozenset({'schema','genesis_bundle_file','receipts'})
PATH_FIELDS = frozenset({'sequence','bundle_file','offer_file','ack_file','closure_file'})
ROOT_FIELDS = frozenset({
    'chain_file','expected_chain_sha256','ledger_manifest_file',
    'expected_ledger_manifest_sha256','expected_latest_certificate_sha256',
    'expected_latest_challenge_sha256','trust',
})


def require(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise a.AnchorError('EC319_' + code, status)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(doc: Any) -> bytes:
    return a.canonical(doc)


def raw_doc(doc: dict) -> bytes:
    return canonical(doc) + b'\n'


def _fields(doc: Any, fields: frozenset, name: str) -> dict:
    return a.exact(doc, fields, 'EC319_' + name + '_EXACT_FIELDS_REQUIRED')


def _private_read(path: str, limit: int, label: str) -> bytes:
    require(original._valid_path(path), label + '_ABSOLUTE_PATH_REQUIRED', 'invalid_input')
    # EC336: signed logical path is preserved for claim verification, but the
    # already-allowlisted physical destination needs the SAME pre/post inode
    # security checks as the bytes read by EC317's guarded ORIGINAL bridge.
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                label + '_OWNER_0600_ONE_REGULAR_LINK_REQUIRED')
        result = io._open_regular(path, limit, private=True)
        after = os.lstat(target)
        require(tuple(getattr(before, key) for key in (
                'st_dev','st_ino','st_size','st_ctime_ns','st_mtime_ns')) ==
                tuple(getattr(after, key) for key in (
                'st_dev','st_ino','st_size','st_ctime_ns','st_mtime_ns')),
                label + '_CHANGED_DURING_READ', 'unavailable')
        return result
    except OSError as exc:
        raise a.AnchorError('EC319_' + label + '_MISSING_OR_INACCESSIBLE',
                            'unavailable') from exc


def _load(path: str, expected_sha256: str, limit: int, label: str) -> dict:
    require(custody._sha(expected_sha256), label + '_EXTERNAL_RAW_SHA_REQUIRED',
            'invalid_input')
    data = _private_read(path, limit, label)
    require(hmac.compare_digest(digest(data), expected_sha256),
            label + '_RAW_BYTES_DIFFER_FROM_EXTERNAL_PIN')
    doc = io.parse(data, limit)
    require(hmac.compare_digest(data, raw_doc(doc)),
            label + '_NOT_EXACT_CANONICAL_LF_JSON')
    return doc


def _materials(path: str) -> dict:
    data = _private_read(path, MAX_MATERIALS, 'MATERIALS_MAP')
    doc = io.parse(data, MAX_MATERIALS)
    require(hmac.compare_digest(data, raw_doc(doc)),
            'MATERIALS_MAP_MUST_BE_CANONICAL_LF_JSON')
    _fields(doc, MATERIALS_FIELDS, 'MATERIALS_MAP')
    require(doc['schema'] == MATERIALS_SCHEMA and
            original._valid_path(doc['genesis_bundle_file']) and
            type(doc['receipts']) is list and len(doc['receipts']) <= MAX_ENTRIES,
            'MATERIALS_MAP_SCHEMA_OR_BOUNDS', 'invalid_input')
    for i, item in enumerate(doc['receipts'], 1):
        _fields(item, PATH_FIELDS, 'MATERIALS_RECEIPT')
        paths = [item[k] for k in ('bundle_file','offer_file','ack_file','closure_file')]
        require(type(item['sequence']) is int and item['sequence'] == i and
                all(original._valid_path(p) for p in paths) and
                len(set(paths)) == 4,
                'MATERIALS_MUST_MAP_EXACT_ORDERED_DISTINCT_RECEIPT_PATHS',
                'invalid_input')
    return doc


def _public(private: Any) -> str:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def _sign(claim: dict, domain: bytes, private_key_file: str, expected_pub: str) -> dict:
    key = io.private_from_file(private_key_file)
    require(hmac.compare_digest(_public(key), expected_pub),
            'REGISTRAR_PRIVATE_KEY_NOT_THE_EXTERNALLY_SELECTED_PUBLIC_KEY')
    doc = {'schema': SIGNED_SCHEMA, 'claim': claim,
           'signature_ed25519': key.sign(domain + canonical(claim)).hex()}
    require(len(raw_doc(doc)) <= MAX_SIGNED_RECORD,
            'SIGNED_RECORD_EXCEEDS_BUDGET', 'invalid_input')
    return doc


def _signature(document: dict, domain: bytes, expected_pub: str) -> None:
    _fields(document, SIGNED_FIELDS, 'SIGNED_RECORD')
    require(len(raw_doc(document)) <= MAX_SIGNED_RECORD,
            'SIGNED_RECORD_EXCEEDS_BUDGET', 'invalid_input')
    require(document['schema'] == SIGNED_SCHEMA and
            type(document['signature_ed25519']) is str and
            a.SIG.fullmatch(document['signature_ed25519']) is not None and
            a.valid_pub(expected_pub),
            'REGISTRAR_SIGNATURE_FORMAT_OR_PUBLIC_KEY_INVALID', 'invalid_input')
    try:
        io.pub_from_hex(expected_pub).verify(
            bytes.fromhex(document['signature_ed25519']),
            domain + canonical(document['claim']))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise a.AnchorError('EC319_REGISTRAR_ED25519_SIGNATURE_NOT_AUTHENTIC',
                            'permission_denied') from exc


def _genesis_claim(claim: dict, expected_id: str, expected_pub: str) -> dict:
    _fields(claim, GENESIS_FIELDS, 'GENESIS_CLAIM')
    root = _fields(claim['original_source_root'], ROOT_FIELDS, 'SOURCE_ROOT')
    # This validates the original EXACT two external custodian role identities.
    rebuilt = original._root(**root)
    require(rebuilt == root and claim['schema'] == GENESIS_SCHEMA and
            custody._id(claim['registry_id']) and
            custody._id(claim['registrar_id']) and
            claim['registrar_id'] == expected_id and
            claim['registrar_public_hex'] == expected_pub and
            a.valid_pub(expected_pub),
            'GENESIS_SCHEMA_REGISTRAR_OR_TRUST_ROOT_INVALID', 'invalid_input')
    two_ids = [root['trust']['custodian_a_id'], root['trust']['custodian_b_id']]
    two_keys = [root['trust']['custodian_a_public_hex'],
                root['trust']['custodian_b_public_hex']]
    require(expected_id not in two_ids and expected_pub not in two_keys and
            custody._sha(claim['transfer_bundle_raw_sha256']) and
            custody._sha(claim['original_replay_result_sha256']) and
            custody._sha(claim['registrar_epoch_challenge_sha256']) and
            claim['registrar_epoch_challenge_sha256'] !=
                root['expected_latest_challenge_sha256'] and
            type(claim['source_reference_count']) is int and
            1 <= claim['source_reference_count'] <= original.MAX_SOURCES,
            'REGISTRAR_IS_INDEPENDENT_AND_GENESIS_PINS_ARE_VALID', 'invalid_input')
    return root


def _genuine_original(genesis: dict, bundle_file: str) -> dict:
    require(original._valid_path(bundle_file),
            'GENESIS_REPLAY_BUNDLE_PATH_REQUIRED', 'invalid_input')
    report = original.verify(bundle_file=bundle_file,
        expected_bundle_sha256=genesis['transfer_bundle_raw_sha256'],
        **genesis['original_source_root'])
    require(report['exit_code'] == 0 and report['status'] ==
            'relocated_original_bytes_fully_reverified_without_original_paths' and
            report['every_original_ec316_to_ec294_signature_replayed'] is True and
            report['old_signed_original_bytes_rewritten'] is False and
            report['external_business_writes_performed'] is False and
            report['replayed_result_original_sha256'] ==
                genesis['original_replay_result_sha256'] and
            report['source_reference_count'] ==
                genesis['source_reference_count'],
            'GENESIS_REAL_ORIGINAL_REPLAY_NOT_EQUAL_SIGNED_PROJECTION')
    return report


def _trust_roles(genesis: dict, claim: dict) -> None:
    trust = genesis['original_source_root']['trust']
    identities = [trust['custodian_a_id'], trust['custodian_b_id'],
                  genesis['registrar_id'], claim['sender_id'], claim['receiver_id']]
    keys = [trust['custodian_a_public_hex'], trust['custodian_b_public_hex'],
            genesis['registrar_public_hex'], claim['sender_public_hex'],
            claim['receiver_public_hex']]
    require(all(custody._id(value) for value in identities) and
            len(set(identities)) == 5 and
            all(a.valid_pub(value) for value in keys) and len(set(keys)) == 5,
            'FIVE_DISTINCT_REAL_ED25519_ROLE_IDENTITIES_AND_PUBLIC_KEYS_REQUIRED',
            'invalid_input')


def _transfer_context(genesis: dict, claim: dict, material: dict) -> dict:
    root = genesis['original_source_root']
    return dict(bundle_file=material['bundle_file'],
        expected_bundle_sha256=genesis['transfer_bundle_raw_sha256'],
        **root, sender_id=claim['sender_id'],
        sender_public_hex=claim['sender_public_hex'],
        receiver_id=claim['receiver_id'],
        receiver_public_hex=claim['receiver_public_hex'],
        sender_exchange_challenge_sha256=claim['sender_exchange_challenge_sha256'],
        receiver_exchange_challenge_sha256=claim['receiver_exchange_challenge_sha256'])


def _genuine_transfer(genesis: dict, claim: dict, material: dict,
                      *, check_binding: bool = True) -> dict:
    result = receipt.verify(
        offer_file=material['offer_file'],
        expected_offer_sha256=claim['offer_original_raw_sha256'],
        ack_file=material['ack_file'],
        expected_ack_sha256=claim['ack_original_raw_sha256'],
        closure_file=material['closure_file'],
        expected_closure_sha256=claim['closure_original_raw_sha256'],
        sender_confirmation_challenge_sha256=
            claim['sender_confirmation_challenge_sha256'],
        **_transfer_context(genesis, claim, material))
    require(result['exit_code'] == 0 and result['status'] ==
            'three_authentic_bilateral_signatures_and_every_original_replay_valid' and
            result['original_ec316_to_ec294_signatures_fully_replayed'] is True and
            result['original_full_replay_result_sha256'] ==
                genesis['original_replay_result_sha256'] and
            result['original_full_replay_result_sha256'] ==
                claim['original_replay_result_sha256'] and
            (not check_binding or result['binding_canonical_sha256'] ==
                claim['binding_canonical_sha256']) and
            result['source_reference_count'] == claim['source_reference_count'] and
            all(result[field] is False for field in (
                'independent_sender_and_receiver_human_custody_proven',
                'physical_transfer_or_external_durable_receipt_proven',
                'global_latest_or_business_write_proven')),
            'TRIPLE_SIGNED_TRANSFER_NOT_EQUAL_FRESH_COMPLETE_REPLAY')
    return result


def _validate_records(snapshot: dict, *, registrar_id: str,
                      registrar_public_hex: str,
                      expected_genesis_raw_sha256: str,
                      expected_head_raw_sha256: str) -> dict:
    _fields(snapshot, SNAPSHOT_FIELDS, 'SNAPSHOT')
    records = snapshot['records']
    require(snapshot['schema'] == SNAPSHOT_SCHEMA and
            type(records) is list and 1 <= len(records) <= MAX_ENTRIES + 1,
            'SNAPSHOT_SCHEMA_OR_ENTRY_COUNT_INVALID', 'invalid_input')
    genesis_doc = records[0]
    require(type(genesis_doc) is dict and
            custody._id(registrar_id) and a.valid_pub(registrar_public_hex),
            'INDEPENDENT_REGISTRAR_ID_AND_ED25519_KEY_REQUIRED', 'invalid_input')
    _signature(genesis_doc, GENESIS_DOMAIN, registrar_public_hex)
    genesis = genesis_doc['claim']
    _genesis_claim(genesis, registrar_id, registrar_public_hex)
    require(custody._sha(expected_genesis_raw_sha256) and
            custody._sha(expected_head_raw_sha256) and
            hmac.compare_digest(digest(raw_doc(genesis_doc)),
                                expected_genesis_raw_sha256) and
            hmac.compare_digest(digest(raw_doc(records[-1])),
                                expected_head_raw_sha256),
            'GENESIS_OR_HEAD_SIGNED_RECORD_DIFFERS_FROM_INDEPENDENT_PIN')
    prev_raw = digest(raw_doc(genesis_doc))
    used = {genesis['registrar_epoch_challenge_sha256'],
            genesis['original_source_root']['expected_latest_challenge_sha256']}
    # All three receipt raw artifact SHA must be distinct across the entire
    # submitted registry. Each event uses four single-use challenge SHAs.
    receipt_pins = set()
    for number, signed in enumerate(records[1:], 1):
        require(type(signed) is dict, 'REGISTRATION_RECORD_MUST_BE_OBJECT',
                'invalid_input')
        _signature(signed, ENTRY_DOMAIN, registrar_public_hex)
        claim = _fields(signed['claim'], ENTRY_FIELDS, 'TRANSFER_CLAIM')
        require(claim['schema'] == ENTRY_SCHEMA and
                claim['registry_id'] == genesis['registry_id'] and
                claim['registry_genesis_raw_sha256'] ==
                    expected_genesis_raw_sha256 and
                type(claim['sequence']) is int and claim['sequence'] == number and
                claim['previous_signed_record_raw_sha256'] == prev_raw and
                claim['transfer_bundle_raw_sha256'] ==
                    genesis['transfer_bundle_raw_sha256'] and
                claim['original_replay_result_sha256'] ==
                    genesis['original_replay_result_sha256'] and
                type(claim['source_reference_count']) is int and
                claim['source_reference_count'] == genesis['source_reference_count'] and
                custody._sha(claim['binding_canonical_sha256']),
                'REGISTRY_SIGNED_SEQUENCE_PARENT_OR_ROOT_NOT_EXACT',
                'invalid_input')
        _trust_roles(genesis, claim)
        pins = [claim[k] for k in ('offer_original_raw_sha256',
                'ack_original_raw_sha256','closure_original_raw_sha256')]
        require(all(custody._sha(p) for p in pins) and
                all(p not in receipt_pins for p in pins) and len(set(pins)) == 3,
                'DUPLICATE_OR_INVALID_OFFER_ACK_CLOSURE_RECEIPT_RAW_SHA')
        receipt_pins.update(pins)
        challenges = [claim[k] for k in (
            'sender_exchange_challenge_sha256',
            'receiver_exchange_challenge_sha256',
            'sender_confirmation_challenge_sha256',
            'registrar_entry_challenge_sha256')]
        require(all(custody._sha(c) for c in challenges) and
                len(set(challenges)) == 4 and
                not any(c in used for c in challenges),
                'REGISTRY_HISTORICAL_CHALLENGE_REUSED_OR_INVALID')
        used.update(challenges)
        prev_raw = digest(raw_doc(signed))
    return genesis


def _replay_snapshot(snapshot: dict, materials: dict, **pins: str) -> dict:
    genesis = _validate_records(snapshot, **pins)
    require(len(materials['receipts']) == len(snapshot['records']) - 1,
            'EXACT_ONE_MATERIAL_RECORD_PER_REGISTERED_RECEIPT_REQUIRED',
            'invalid_input')
    _genuine_original(genesis, materials['genesis_bundle_file'])
    for signed, material in zip(snapshot['records'][1:], materials['receipts']):
        _genuine_transfer(genesis, signed['claim'], material)
    return genesis


def _out(path: str, existing: tuple[str, ...]) -> None:
    require(original._valid_path(path),
            'NEW_SNAPSHOT_DESTINATION_MUST_BE_NORMALIZED_ABSOLUTE_FILE',
            'invalid_input')
    b._private_parent(path)
    require(path not in existing and not os.path.lexists(path),
            'SNAPSHOT_OUTPUT_MUST_BE_FRESH_AND_NOT_A_SOURCE')


def _persist(path: str, snapshot: dict) -> str:
    data = raw_doc(snapshot)
    require(len(data) <= MAX_SNAPSHOT, 'NEW_SNAPSHOT_EXCEEDS_BUDGET',
            'invalid_input')
    store.store(path, snapshot, MAX_SNAPSHOT)
    return digest(data)


def _output(snapshot: dict, file_sha: str, status: str) -> dict:
    events = snapshot['records']
    return {'status': status, 'exit_code': 0,
        'registry_id': events[0]['claim']['registry_id'],
        'registrar_id': events[0]['claim']['registrar_id'],
        'registration_count': len(events) - 1,
        'snapshot_original_raw_sha256': file_sha,
        'genesis_signed_original_raw_sha256': digest(raw_doc(events[0])),
        'head_signed_original_raw_sha256': digest(raw_doc(events[-1])),
        'genuine_ec318_to_ec294_historical_signatures_replayed': True,
        'same_history_duplicate_receipts_and_challenges_denied': True,
        'physical_worm_or_global_latest_proven': False,
        'external_identity_authorization_or_revocation_proven': False,
        'production_business_writes_performed': False}


def bootstrap(*, registry_id: str, registrar_id: str,
              registrar_public_hex: str, registrar_epoch_challenge_sha256: str,
              bundle_file: str, expected_bundle_sha256: str,
              chain_file: str, expected_chain_sha256: str,
              ledger_manifest_file: str, expected_ledger_manifest_sha256: str,
              expected_latest_certificate_sha256: str,
              expected_latest_challenge_sha256: str, trust: dict,
              private_key_file: str, out: str) -> dict:
    _out(out, (bundle_file, chain_file, ledger_manifest_file,
               private_key_file))
    root = original._root(chain_file=chain_file,
        expected_chain_sha256=expected_chain_sha256,
        ledger_manifest_file=ledger_manifest_file,
        expected_ledger_manifest_sha256=expected_ledger_manifest_sha256,
        expected_latest_certificate_sha256=expected_latest_certificate_sha256,
        expected_latest_challenge_sha256=expected_latest_challenge_sha256,
        trust=trust)
    require(custody._id(registry_id) and custody._id(registrar_id) and
            a.valid_pub(registrar_public_hex) and
            custody._sha(expected_bundle_sha256),
            'GENESIS_ID_PUBLIC_KEY_AND_ORIGINAL_BUNDLE_PIN_REQUIRED',
            'invalid_input')
    claim = {'schema': GENESIS_SCHEMA, 'registry_id': registry_id,
             'registrar_id': registrar_id,
             'registrar_public_hex': registrar_public_hex,
             'registrar_epoch_challenge_sha256': registrar_epoch_challenge_sha256,
             'original_source_root': root,
             'transfer_bundle_raw_sha256': expected_bundle_sha256,
             'original_replay_result_sha256': '1'*64, # replaced before signing
             'source_reference_count': 1}  # replaced before signing
    # Run actual original EC317 full historical Ed25519 replay before opening
    # the fifth role's private key. No unsigned reports may bootstrap a log.
    replay = original.verify(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, **root)
    require(replay['exit_code'] == 0 and
            replay['every_original_ec316_to_ec294_signature_replayed'] is True and
            replay['old_signed_original_bytes_rewritten'] is False and
            replay['external_business_writes_performed'] is False,
            'BOOTSTRAP_GENUINE_ORIGINAL_SIGNATURE_REPLAY_REQUIRED')
    claim['original_replay_result_sha256'] = replay['replayed_result_original_sha256']
    claim['source_reference_count'] = replay['source_reference_count']
    _genesis_claim(claim, registrar_id, registrar_public_hex)
    first = _sign(claim, GENESIS_DOMAIN, private_key_file, registrar_public_hex)
    snapshot = {'schema': SNAPSHOT_SCHEMA, 'records': [first]}
    sha = _persist(out, snapshot)
    return _output(snapshot, sha, 'fresh_signed_registrar_genesis_after_full_original_replay')


def verify(*, registry_file: str, expected_registry_sha256: str,
           materials_file: str, expected_genesis_raw_sha256: str,
           expected_head_raw_sha256: str, registrar_id: str,
           registrar_public_hex: str) -> dict:
    require(registry_file != materials_file,
            'SNAPSHOT_AND_LOCAL_MATERIALS_CANNOT_BE_SAME_FILE', 'invalid_input')
    snapshot = _load(registry_file, expected_registry_sha256, MAX_SNAPSHOT, 'SNAPSHOT')
    materials = _materials(materials_file)
    _replay_snapshot(snapshot, materials, registrar_id=registrar_id,
        registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_head_raw_sha256=expected_head_raw_sha256)
    return _output(snapshot, expected_registry_sha256,
                   'signed_registrar_history_and_every_original_receipt_reverified')


def append(*, registry_file: str, expected_registry_sha256: str,
           materials_file: str, expected_genesis_raw_sha256: str,
           expected_head_raw_sha256: str, registrar_id: str,
           registrar_public_hex: str, new_claim_fields: dict,
           private_key_file: str, out: str) -> dict:
    _out(out, (registry_file, materials_file, private_key_file))
    require(out != registry_file and out != materials_file,
            'MUST_CREATE_NEW_IMMUTABLE_SNAPSHOT')
    snapshot = _load(registry_file, expected_registry_sha256, MAX_SNAPSHOT, 'PRIOR_SNAPSHOT')
    _fields(snapshot, SNAPSHOT_FIELDS, 'PRIOR_SNAPSHOT')
    require(snapshot['schema'] == SNAPSHOT_SCHEMA and
            type(snapshot['records']) is list and
            1 <= len(snapshot['records']) <= MAX_ENTRIES,
            'MAX_FOUR_ORIGINAL_REGISTRATIONS_PER_EPOCH', 'invalid_input')
    materials = _materials(materials_file)
    require(len(materials['receipts']) == len(snapshot['records']),
            'APPEND_NEEDS_PREVIOUS_MATERIALS_PLUS_EXACT_ONE_NEW_RECEIPT',
            'invalid_input')
    prev_materials = dict(materials, receipts=materials['receipts'][:-1])
    genesis = _replay_snapshot(snapshot, prev_materials,
        registrar_id=registrar_id, registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_head_raw_sha256=expected_head_raw_sha256)
    _fields(new_claim_fields, NEW_FIELDS, 'NEW_REGISTERED_TRANSFER')
    claim = {'schema': ENTRY_SCHEMA,'registry_id': genesis['registry_id'],
             'registry_genesis_raw_sha256':expected_genesis_raw_sha256,
             'sequence':len(snapshot['records']),
             'previous_signed_record_raw_sha256':expected_head_raw_sha256,
             'transfer_bundle_raw_sha256':genesis['transfer_bundle_raw_sha256'],
             'original_replay_result_sha256':genesis['original_replay_result_sha256'],
             'source_reference_count':genesis['source_reference_count'],
             'binding_canonical_sha256':'1'*64, **new_claim_fields}
    # Detect anti-replay/nonce and receipt reuse on the full candidate history
    # BEFORE expensive fresh replay or accessing the registrar's private key.
    # Check signed previous history and the new unsigned claim's invariants.
    _check_candidate(snapshot, genesis, claim, expected_genesis_raw_sha256)
    # Binding SHA is obtained from the real EC318 verification, not from the
    # unsigned caller; it becomes mandatory on every later signed replay.
    result = _genuine_transfer(genesis, claim, materials['receipts'][-1],
                               check_binding=False)
    claim['binding_canonical_sha256'] = result['binding_canonical_sha256']
    # Re-check shape, links and challenge reuse with the authentic bound digest.
    _check_candidate(snapshot, genesis, claim, expected_genesis_raw_sha256)
    new_record = _sign(claim, ENTRY_DOMAIN, private_key_file, registrar_public_hex)
    ready = {'schema': SNAPSHOT_SCHEMA, 'records': snapshot['records'] + [new_record]}
    # Revalidate all cryptographic record signatures before producing bytes.
    _validate_records(ready, registrar_id=registrar_id,
        registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_head_raw_sha256=digest(raw_doc(new_record)))
    result_sha = _persist(out, ready)
    return _output(ready, result_sha,
                   'new_fifth_role_signed_registration_after_all_prior_and_new_replay')


def _check_candidate(snapshot: dict, genesis: dict, claim: dict,
                     genesis_sha: str) -> None:
    _fields(claim, ENTRY_FIELDS, 'CANDIDATE')
    require(claim['registry_id'] == genesis['registry_id'] and
            claim['registry_genesis_raw_sha256'] == genesis_sha and
            claim['sequence'] == len(snapshot['records']) and
            claim['previous_signed_record_raw_sha256'] ==
                digest(raw_doc(snapshot['records'][-1])) and
            claim['transfer_bundle_raw_sha256'] == genesis['transfer_bundle_raw_sha256'],
            'CANDIDATE_PARENT_AND_GENESIS_BINDING_INVALID', 'invalid_input')
    _trust_roles(genesis, claim)
    used_challenges = {genesis['registrar_epoch_challenge_sha256'],
        genesis['original_source_root']['expected_latest_challenge_sha256']}
    used_receipts = set()
    for signed in snapshot['records'][1:]:
        old = signed['claim']
        used_receipts.update(old[k] for k in (
            'offer_original_raw_sha256','ack_original_raw_sha256',
            'closure_original_raw_sha256'))
        used_challenges.update(old[k] for k in (
            'sender_exchange_challenge_sha256',
            'receiver_exchange_challenge_sha256',
            'sender_confirmation_challenge_sha256',
            'registrar_entry_challenge_sha256'))
    fresh_receipts = [claim[k] for k in (
        'offer_original_raw_sha256','ack_original_raw_sha256',
        'closure_original_raw_sha256')]
    challenges = [claim[k] for k in (
        'sender_exchange_challenge_sha256',
        'receiver_exchange_challenge_sha256',
        'sender_confirmation_challenge_sha256',
        'registrar_entry_challenge_sha256')]
    require(all(custody._sha(value) for value in fresh_receipts) and
            len(set(fresh_receipts)) == 3 and
            not set(fresh_receipts).intersection(used_receipts),
            'DUPLICATE_TRANSFER_OR_RECEIPT_REJECTED')
    require(all(custody._sha(value) for value in challenges) and
            len(set(challenges)) == 4 and
            not set(challenges).intersection(used_challenges),
            'REPLAYED_HISTORICAL_OR_CURRENT_CHALLENGE_REJECTED')
    require(claim['original_replay_result_sha256'] ==
                genesis['original_replay_result_sha256'] and
            claim['source_reference_count'] == genesis['source_reference_count'] and
            custody._sha(claim['binding_canonical_sha256']),
            'NEW_TRANSFER_REPLAY_RESULT_BINDING_NOT_VALID', 'invalid_input')


def compare(*, left_file: str, expected_left_sha256: str,
            left_materials_file: str, expected_left_head_raw_sha256: str,
            right_file: str, expected_right_sha256: str,
            right_materials_file: str, expected_right_head_raw_sha256: str,
            expected_genesis_raw_sha256: str, registrar_id: str,
            registrar_public_hex: str) -> dict:
    left = _load(left_file, expected_left_sha256, MAX_SNAPSHOT, 'LEFT_SNAPSHOT')
    right = _load(right_file, expected_right_sha256, MAX_SNAPSHOT, 'RIGHT_SNAPSHOT')
    lmaterials = _materials(left_materials_file)
    rmaterials = _materials(right_materials_file)
    gl = _replay_snapshot(left, lmaterials, registrar_id=registrar_id,
        registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_head_raw_sha256=expected_left_head_raw_sha256)
    gr = _replay_snapshot(right, rmaterials, registrar_id=registrar_id,
        registrar_public_hex=registrar_public_hex,
        expected_genesis_raw_sha256=expected_genesis_raw_sha256,
        expected_head_raw_sha256=expected_right_head_raw_sha256)
    require(gl == gr and left['records'][0] == right['records'][0],
            'COMPARED_SNAPSHOTS_NOT_FROM_ONE_SIGNED_ROOT', 'invalid_input')
    la = [digest(raw_doc(item)) for item in left['records']]
    ra = [digest(raw_doc(item)) for item in right['records']]
    common = next((i for i in range(min(len(la),len(ra))) if la[i] != ra[i]),
                  min(len(la),len(ra)))
    if common < min(len(la), len(ra)):
        # The first divergence is proof of *two different genuine registrar
        # signatures* at the same logical sequence from the same signed parent.
        a1 = left['records'][common]['claim']
        a2 = right['records'][common]['claim']
        require(common >= 1 and
                a1['previous_signed_record_raw_sha256'] ==
                    a2['previous_signed_record_raw_sha256'] == la[common-1],
                'FORK_PROOF_SIGNED_PARENT_NOT_EQUAL', 'invalid_input')
        return {'status':'two_authentic_registrar_branches_from_same_signed_parent',
            'exit_code':2,'registry_id':gl['registry_id'],
            'registrar_id':registrar_id,'divergent_sequence':common,
            'shared_previous_signed_record_raw_sha256':la[common-1],
            'left_divergent_signed_record_raw_sha256':la[common],
            'right_divergent_signed_record_raw_sha256':ra[common],
            'left_snapshot_original_raw_sha256':expected_left_sha256,
            'right_snapshot_original_raw_sha256':expected_right_sha256,
            'both_forks_full_ec318_to_ec294_replayed':True,
            'third_party_atomic_worm_or_global_latest_proven':False,
            'registrar_identity_authority_proven':False}
    return {'status': ('identical_signed_snapshot' if la == ra else
            'one_valid_signed_registry_prefix_of_the_other'),
            'exit_code':0,'registry_id':gl['registry_id'],
            'registrar_id':registrar_id,
            'shared_signed_record_count':common,
            'left_registration_count':len(la)-1,
            'right_registration_count':len(ra)-1,
            'both_snapshots_fully_replayed':True,
            'no_unseen_branch_or_global_latest_proven':False}

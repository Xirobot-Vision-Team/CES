#!/usr/bin/env python3
"""EC318 original-SHA transfer: sender offer -> receiver ACK -> sender closure.

Each signing operation independently verifies EC317's *whole original evidence
bundle*, which itself replays the original EC316->EC294 Ed25519 history. No
previous unsigned success report is accepted as a substitute. Offer, ACK and
closure are three separate owner-private, raw-SHA-pinned signed JSON files.

This is a cryptographic record of what two supplied keys asserted. It cannot
prove that the keys are held by two humans or organizations, that media
physically moved, that the external challenges are unique, or that anyone
maintains an immutable/global/latest receipt registry.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec303_receiver_ack import ack as old_ack
from ec316_dual_custodian_checkpoint import checkpoint as custody
from ec317_original_rebinding import rebinding as original

BINDING_SCHEMA = 'ces.ec318.original_sha_transfer_binding.v1'
OFFER_SCHEMA = 'ces.ec318.sender_signed_original_sha_transfer_offer.v1'
ACK_CLAIM_SCHEMA = 'ces.ec318.receiver_accepted_original_sha_transfer_claim.v1'
ACK_SCHEMA = 'ces.ec318.receiver_signed_original_sha_transfer_ack.v1'
CLOSE_CLAIM_SCHEMA = 'ces.ec318.sender_confirmed_receiver_ack_claim.v1'
CLOSE_SCHEMA = 'ces.ec318.sender_signed_original_sha_transfer_closure.v1'
RESULT_SCHEMA = 'ces.ec318.bilateral_original_sha_transfer_result.v1'
DENIAL_SCHEMA = 'ces.ec318.bilateral_original_sha_transfer_denial.v1'
DOMAINS = {
    'offer': b'CES/EC318/OriginalSHA/TransferSenderOffer/v1\0',
    'ack': b'CES/EC318/OriginalSHA/TransferReceiverAck/v1\0',
    'close': b'CES/EC318/OriginalSHA/TransferSenderConfirmation/v1\0',
}
MAX_SIGNED_DOCUMENT = 20_000
BINDING_FIELDS = frozenset({
    'schema', 'original_source_root', 'transfer_bundle_raw_sha256',
    'sender_id', 'sender_public_hex', 'receiver_id', 'receiver_public_hex',
    'sender_exchange_challenge_sha256', 'receiver_exchange_challenge_sha256',
    'verified_original_replay_result_sha256', 'source_reference_count',
    'distinct_original_object_count',
})
OFFER_FIELDS = frozenset({'schema', 'binding', 'sender_signature_ed25519'})
ACK_CLAIM_FIELDS = frozenset({
    'schema', 'offer_original_raw_sha256', 'binding_canonical_sha256',
    'transfer_bundle_raw_sha256', 'verified_original_replay_result_sha256',
    'receiver_id', 'receiver_public_hex', 'receiver_exchange_challenge_sha256',
    'receiver_replayed_every_original_signature',
})
ACK_FIELDS = frozenset({'schema', 'claim', 'receiver_signature_ed25519'})
CLOSE_CLAIM_FIELDS = frozenset({
    'schema', 'offer_original_raw_sha256', 'ack_original_raw_sha256',
    'binding_canonical_sha256', 'transfer_bundle_raw_sha256',
    'verified_original_replay_result_sha256', 'sender_id', 'sender_public_hex',
    'sender_confirmation_challenge_sha256',
    'sender_verified_ack_signature_and_every_original_signature',
})
CLOSE_FIELDS = frozenset({'schema', 'claim', 'sender_signature_ed25519'})


def require(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise a.AnchorError('EC318_' + reason, status)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(doc: dict) -> bytes:
    # Signature and binding digest use canonical JSON without an LF; persisted
    # documents are that exact JSON plus one final LF.
    return a.canonical(doc)


def _exact(document: Any, fields: frozenset, name: str) -> dict:
    return a.exact(document, fields, 'EC318_' + name + '_EXACT_FIELDS_REQUIRED')


def _public(key: Any) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def _signed(role: str, subject: dict, private_key_file: str,
            expected_public_hex: str) -> str:
    # Verify all original signed evidence *before* opening the signing key.
    # Caller must ensure it has already run the complete EC317 replay.
    key = io.private_from_file(private_key_file)
    require(hmac.compare_digest(_public(key), expected_public_hex),
            'PRIVATE_KEY_NOT_EQUAL_EXPLICITLY_PINNED_' + role.upper() + '_KEY')
    return key.sign(DOMAINS[role] + canonical(subject)).hex()


def _check_sig(role: str, subject: dict, signature: Any, public_hex: str) -> None:
    require(type(signature) is str and a.SIG.fullmatch(signature) is not None,
            role.upper() + '_SIGNATURE_FORMAT_INVALID', 'invalid_input')
    try:
        io.pub_from_hex(public_hex).verify(bytes.fromhex(signature),
            DOMAINS[role] + canonical(subject))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise a.AnchorError('EC318_' + role.upper() + '_SIGNATURE_NOT_AUTHENTIC',
                            'permission_denied') from exc


def _context(*, bundle_file: str, expected_bundle_sha256: str,
             chain_file: str, expected_chain_sha256: str,
             ledger_manifest_file: str, expected_ledger_manifest_sha256: str,
             expected_latest_certificate_sha256: str,
             expected_latest_challenge_sha256: str, trust: dict,
             sender_id: str, sender_public_hex: str,
             receiver_id: str, receiver_public_hex: str,
             sender_exchange_challenge_sha256: str,
             receiver_exchange_challenge_sha256: str) -> tuple[dict, str]:
    root = original._root(chain_file=chain_file,
        expected_chain_sha256=expected_chain_sha256,
        ledger_manifest_file=ledger_manifest_file,
        expected_ledger_manifest_sha256=expected_ledger_manifest_sha256,
        expected_latest_certificate_sha256=expected_latest_certificate_sha256,
        expected_latest_challenge_sha256=expected_latest_challenge_sha256,
        trust=trust)
    require(original._valid_path(bundle_file) and custody._sha(expected_bundle_sha256),
            'WHOLE_ZIP_PATH_AND_INDEPENDENT_RAW_SHA_REQUIRED', 'invalid_input')
    ids = [trust['custodian_a_id'], trust['custodian_b_id'],
           sender_id, receiver_id]
    keys = [trust['custodian_a_public_hex'], trust['custodian_b_public_hex'],
            sender_public_hex, receiver_public_hex]
    require(all(custody._id(x) for x in ids) and len(set(ids)) == len(ids),
            'FOUR_DISTINCT_ROLE_IDENTITIES_REQUIRED', 'invalid_input')
    require(all(a.valid_pub(x) for x in keys) and len(set(keys)) == len(keys),
            'FOUR_DISTINCT_VALID_ED25519_ROLE_PUBLIC_KEYS_REQUIRED', 'invalid_input')
    challenges = [expected_latest_challenge_sha256,
                  sender_exchange_challenge_sha256,
                  receiver_exchange_challenge_sha256]
    require(all(custody._sha(x) for x in challenges) and
            len(set(challenges)) == len(challenges),
            'THREE_DISTINCT_OFF_BUNDLE_NONZERO_CHALLENGE_PINS_REQUIRED',
            'invalid_input')
    return root, bundle_file


def _binding(*, result: dict, root: dict, expected_bundle_sha256: str,
             sender_id: str, sender_public_hex: str,
             receiver_id: str, receiver_public_hex: str,
             sender_exchange_challenge_sha256: str,
             receiver_exchange_challenge_sha256: str) -> dict:
    require(result['exit_code'] == 0 and
            result['status'] ==
                'relocated_original_bytes_fully_reverified_without_original_paths' and
            result['every_original_ec316_to_ec294_signature_replayed'] is True and
            result['old_signed_original_bytes_rewritten'] is False and
            result['external_business_writes_performed'] is False and
            result['bundle_original_raw_sha256'] == expected_bundle_sha256 and
            result['latest_certificate_original_raw_sha256'] ==
                root['expected_latest_certificate_sha256'],
            'ORIGINAL_FULL_HISTORY_NOT_AUTHENTICALLY_REPLAYED')
    require(type(result['source_reference_count']) is int and
            1 <= result['source_reference_count'] <= original.MAX_SOURCES and
            type(result['distinct_byte_object_count']) is int and
            1 <= result['distinct_byte_object_count'] <= result['source_reference_count'] and
            custody._sha(result['replayed_result_original_sha256']),
            'ORIGINAL_REPLAY_RESULT_PROJECTION_INVALID', 'invalid_input')
    return {
        'schema': BINDING_SCHEMA,
        'original_source_root': root,
        'transfer_bundle_raw_sha256': expected_bundle_sha256,
        'sender_id': sender_id, 'sender_public_hex': sender_public_hex,
        'receiver_id': receiver_id, 'receiver_public_hex': receiver_public_hex,
        'sender_exchange_challenge_sha256': sender_exchange_challenge_sha256,
        'receiver_exchange_challenge_sha256': receiver_exchange_challenge_sha256,
        'verified_original_replay_result_sha256':
            result['replayed_result_original_sha256'],
        'source_reference_count': result['source_reference_count'],
        'distinct_original_object_count': result['distinct_byte_object_count'],
    }


def _replayed_binding(bundle_file: str, expected_bundle_sha256: str,
                      root: dict, **transfer: Any) -> dict:
    # Replays all previous signatures for each stage independently. Neither
    # an unsigned EC317 PASS report nor a previous stage's stored claim can
    # authorize any subsequent signature.
    result = original.verify(bundle_file=bundle_file,
                             expected_bundle_sha256=expected_bundle_sha256, **root)
    return _binding(result=result, root=root,
                    expected_bundle_sha256=expected_bundle_sha256, **transfer)


def _file(path: str, expected_sha256: str, label: str) -> dict:
    require(original._valid_path(path) and custody._sha(expected_sha256),
            label + '_PRIVATE_FILE_AND_OUTSIDE_WHOLE_SHA_REQUIRED', 'invalid_input')
    target = b._private_parent(path)
    try:
        first = os.lstat(target)
        require(stat.S_ISREG(first.st_mode) and first.st_uid == os.geteuid() and
                stat.S_IMODE(first.st_mode) == 0o600 and first.st_nlink == 1,
                label + '_OWNER_PRIVATE_0600_SINGLE_LINK_REQUIRED')
        raw = io._open_regular(path, MAX_SIGNED_DOCUMENT, private=True)
        last = os.lstat(target)
        require(tuple(getattr(first, x) for x in (
                'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')) ==
                tuple(getattr(last, x) for x in (
                'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),
                label + '_SOURCE_CHANGED_DURING_READ', 'unavailable')
    except FileNotFoundError as exc:
        raise a.AnchorError('EC318_'+label+'_SOURCE_NOT_PRESENT',
                            'unavailable') from exc
    require(hmac.compare_digest(sha(raw), expected_sha256),
            label + '_WHOLE_RAW_SHA_DIFFERS_FROM_EXTERNAL_PIN')
    document = io.parse(raw, MAX_SIGNED_DOCUMENT)
    require(hmac.compare_digest(raw, canonical(document) + b'\n'),
            label + '_MUST_BE_EXACT_CANONICAL_LF_JSON')
    return document


def _destination(path: str, reserved: tuple[str, ...]) -> None:
    require(original._valid_path(path),
            'OUTPUT_MUST_BE_NORMALIZED_ABSOLUTE_FILE', 'invalid_input')
    b._private_parent(path)
    require(path not in reserved and not os.path.lexists(path),
            'OUTPUT_MUST_BE_NEW_AND_NOT_A_TRANSFER_SOURCE')


def _store(path: str, doc: dict) -> str:
    return store.store(path, doc, MAX_SIGNED_DOCUMENT)  # 0600 O_EXCL + fsync


def _verify_offer(offer_file: str, expected_offer_sha256: str,
                  binding: dict) -> dict:
    offer = _file(offer_file, expected_offer_sha256, 'OFFER')
    _exact(offer, OFFER_FIELDS, 'OFFER')
    require(offer['schema'] == OFFER_SCHEMA, 'OFFER_SCHEMA_INVALID', 'invalid_input')
    _exact(offer['binding'], BINDING_FIELDS, 'TRANSFER_BINDING')
    require(offer['binding']['schema'] == BINDING_SCHEMA and
            offer['binding'] == binding,
            'SIGNED_OFFER_NOT_EQUAL_CURRENT_INDEPENDENT_REPLAY_AND_PINS')
    _check_sig('offer', binding, offer['sender_signature_ed25519'],
               binding['sender_public_hex'])
    return offer


def _ack_claim(binding: dict, offer_sha: str) -> dict:
    return {
        'schema': ACK_CLAIM_SCHEMA,
        'offer_original_raw_sha256': offer_sha,
        'binding_canonical_sha256': sha(canonical(binding)),
        'transfer_bundle_raw_sha256': binding['transfer_bundle_raw_sha256'],
        'verified_original_replay_result_sha256':
            binding['verified_original_replay_result_sha256'],
        'receiver_id': binding['receiver_id'],
        'receiver_public_hex': binding['receiver_public_hex'],
        'receiver_exchange_challenge_sha256':
            binding['receiver_exchange_challenge_sha256'],
        'receiver_replayed_every_original_signature': True,
    }


def _verify_ack(ack_file: str, expected_ack_sha256: str,
                binding: dict, offer_sha: str) -> dict:
    ack = _file(ack_file, expected_ack_sha256, 'ACK')
    _exact(ack, ACK_FIELDS, 'ACK')
    require(ack['schema'] == ACK_SCHEMA, 'ACK_SCHEMA_INVALID', 'invalid_input')
    _exact(ack['claim'], ACK_CLAIM_FIELDS, 'ACK_CLAIM')
    require(ack['claim'] == _ack_claim(binding, offer_sha),
            'RECEIVER_ACK_DOES_NOT_REFERENCE_EXACT_SIGNED_OFFER_AND_REPLAY')
    _check_sig('ack', ack['claim'], ack['receiver_signature_ed25519'],
               binding['receiver_public_hex'])
    return ack


def _fresh_confirmation_challenge(challenge: str, binding: dict) -> None:
    require(custody._sha(challenge) and challenge not in (
        binding['sender_exchange_challenge_sha256'],
        binding['receiver_exchange_challenge_sha256'],
        binding['original_source_root']['expected_latest_challenge_sha256']),
        'FOURTH_DISTINCT_EXTERNALLY_PINNED_CONFIRMATION_CHALLENGE_REQUIRED',
        'invalid_input')


def _close_claim(binding: dict, offer_sha: str, ack_sha: str,
                 sender_confirmation_challenge_sha256: str) -> dict:
    _fresh_confirmation_challenge(sender_confirmation_challenge_sha256, binding)
    return {
        'schema': CLOSE_CLAIM_SCHEMA,
        'offer_original_raw_sha256': offer_sha,
        'ack_original_raw_sha256': ack_sha,
        'binding_canonical_sha256': sha(canonical(binding)),
        'transfer_bundle_raw_sha256': binding['transfer_bundle_raw_sha256'],
        'verified_original_replay_result_sha256':
            binding['verified_original_replay_result_sha256'],
        'sender_id': binding['sender_id'],
        'sender_public_hex': binding['sender_public_hex'],
        'sender_confirmation_challenge_sha256':
            sender_confirmation_challenge_sha256,
        'sender_verified_ack_signature_and_every_original_signature': True,
    }


def _verify_close(close_file: str, expected_close_sha256: str,
                  binding: dict, offer_sha: str, ack_sha: str,
                  sender_confirmation_challenge_sha256: str) -> dict:
    close = _file(close_file, expected_close_sha256, 'CLOSURE')
    _exact(close, CLOSE_FIELDS, 'CLOSURE')
    require(close['schema'] == CLOSE_SCHEMA,
            'CLOSURE_SCHEMA_INVALID', 'invalid_input')
    _exact(close['claim'], CLOSE_CLAIM_FIELDS, 'CLOSURE_CLAIM')
    require(close['claim'] == _close_claim(binding, offer_sha, ack_sha,
                   sender_confirmation_challenge_sha256),
            'SENDER_CLOSURE_NOT_EQUAL_EXACT_RECEIVER_ACK_AND_PINS')
    _check_sig('close', close['claim'], close['sender_signature_ed25519'],
               binding['sender_public_hex'])
    return close


def _context_and_binding(context: dict) -> tuple[dict, dict]:
    root, bundle_file = _context(**context)
    binding = _replayed_binding(bundle_file, context['expected_bundle_sha256'], root,
        sender_id=context['sender_id'],
        sender_public_hex=context['sender_public_hex'],
        receiver_id=context['receiver_id'],
        receiver_public_hex=context['receiver_public_hex'],
        sender_exchange_challenge_sha256=context['sender_exchange_challenge_sha256'],
        receiver_exchange_challenge_sha256=context['receiver_exchange_challenge_sha256'])
    return root, binding


def _result(status: str, binding: dict, **refs: str) -> dict:
    return {
        'status': status, 'exit_code': 0,
        'transfer_bundle_original_raw_sha256':
            binding['transfer_bundle_raw_sha256'],
        'original_full_replay_result_sha256':
            binding['verified_original_replay_result_sha256'],
        'binding_canonical_sha256': sha(canonical(binding)),
        'source_reference_count': binding['source_reference_count'],
        'sender_id': binding['sender_id'], 'receiver_id': binding['receiver_id'],
        'original_ec316_to_ec294_signatures_fully_replayed': True,
        'independent_sender_and_receiver_human_custody_proven': False,
        'physical_transfer_or_external_durable_receipt_proven': False,
        'global_latest_or_business_write_proven': False,
        **refs,
    }


def sender_offer(*, private_key_file: str, out: str, **context: Any) -> dict:
    _destination(out, (context['bundle_file'],))
    _, binding = _context_and_binding(context)
    doc = {'schema': OFFER_SCHEMA, 'binding': binding,
           'sender_signature_ed25519': _signed('offer', binding,
                private_key_file, binding['sender_public_hex'])}
    _store(out, doc)
    return _result('sender_signed_offer_after_genuine_original_replay', binding,
                   offer_original_raw_sha256=sha(canonical(doc) + b'\n'))


def receiver_ack(*, offer_file: str, expected_offer_sha256: str,
                 private_key_file: str, out: str, **context: Any) -> dict:
    _destination(out, (context['bundle_file'], offer_file))
    _, binding = _context_and_binding(context)
    _verify_offer(offer_file, expected_offer_sha256, binding)
    claim = _ack_claim(binding, expected_offer_sha256)
    doc = {'schema': ACK_SCHEMA, 'claim': claim,
           'receiver_signature_ed25519': _signed('ack', claim,
                private_key_file, binding['receiver_public_hex'])}
    _store(out, doc)
    return _result('receiver_signed_ack_after_offer_and_original_replay', binding,
                   offer_original_raw_sha256=expected_offer_sha256,
                   ack_original_raw_sha256=sha(canonical(doc) + b'\n'))


def sender_confirm(*, offer_file: str, expected_offer_sha256: str,
                   ack_file: str, expected_ack_sha256: str,
                   sender_confirmation_challenge_sha256: str,
                   private_key_file: str, out: str, **context: Any) -> dict:
    _destination(out, (context['bundle_file'], offer_file, ack_file))
    require(offer_file != ack_file,
            'SIGNED_OFFER_AND_RECEIVER_ACK_MUST_BE_DISTINCT_FILES', 'invalid_input')
    _, binding = _context_and_binding(context)
    _verify_offer(offer_file, expected_offer_sha256, binding)
    _verify_ack(ack_file, expected_ack_sha256, binding, expected_offer_sha256)
    claim = _close_claim(binding, expected_offer_sha256, expected_ack_sha256,
                         sender_confirmation_challenge_sha256)
    doc = {'schema': CLOSE_SCHEMA, 'claim': claim,
           'sender_signature_ed25519': _signed('close', claim,
                private_key_file, binding['sender_public_hex'])}
    _store(out, doc)
    return _result('sender_confirmed_receivers_authentic_ack_after_original_replay',
                   binding, offer_original_raw_sha256=expected_offer_sha256,
                   ack_original_raw_sha256=expected_ack_sha256,
                   closure_original_raw_sha256=sha(canonical(doc) + b'\n'))


def verify(*, offer_file: str, expected_offer_sha256: str,
           ack_file: str, expected_ack_sha256: str,
           closure_file: str, expected_closure_sha256: str,
           sender_confirmation_challenge_sha256: str,
           **context: Any) -> dict:
    paths = [context['bundle_file'], offer_file, ack_file, closure_file]
    require(all(original._valid_path(p) for p in paths) and
            len(set(paths)) == 4,
            'FOUR_INDEPENDENT_SOURCE_FILE_PATHS_REQUIRED', 'invalid_input')
    _, binding = _context_and_binding(context)
    _verify_offer(offer_file, expected_offer_sha256, binding)
    _verify_ack(ack_file, expected_ack_sha256, binding, expected_offer_sha256)
    _verify_close(closure_file, expected_closure_sha256, binding,
                  expected_offer_sha256, expected_ack_sha256,
                  sender_confirmation_challenge_sha256)
    return _result('three_authentic_bilateral_signatures_and_every_original_replay_valid',
                   binding, offer_original_raw_sha256=expected_offer_sha256,
                   ack_original_raw_sha256=expected_ack_sha256,
                   closure_original_raw_sha256=expected_closure_sha256)

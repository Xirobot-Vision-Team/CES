#!/usr/bin/env python3
"""EC304: signed, externally checkpointed spent-challenge ledger for EC303 ACKs.

Each new snapshot is written to a NEW owner-private file. A fourth, separate
Ed25519 registrar signs the exact prior *whole-ledger raw SHA*, the sequence,
and the EC303 acknowledgement that was freshly reverified from its original
EC302 -> EC294 cryptographic evidence. Verification checks ALL previous
registrar signatures and the full latest EC303 evidence chain.

This is NOT a globally serialized database, trusted challenge issuer, key
revocation service, immutable off-host store, or proof of independent people.
An external custodian MUST atomically retain and compare the latest raw
ledger SHA and sequence. Two writers given the same external predecessor can
produce competing valid signed successors: neither is automatically final.
"""
from __future__ import annotations

import hmac
import os
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as r

DOMAIN = b'CES/EC304/DeliveryAudit/IndependentSpentChallengeRegistry/v1\0'
LEDGER_SCHEMA = 'ces.ec304.offline_signed_challenge_registry.v1'
RECORD_SCHEMA = 'ces.ec304.registrar_signed_challenge_record.v1'
CLAIM_SCHEMA = 'ces.ec304.verified_ack_challenge_consumption_claim.v1'
RESULT_SCHEMA = 'ces.ec304.challenge_registry_operation_result.v1'
DENIAL_SCHEMA = 'ces.ec304.challenge_registry_denial.v1'
MAX_ENTRIES = 256
MAX_LEDGER_BYTES = 1_500_000
RECORD_FIELDS = frozenset({'schema', 'claim', 'registrar_signature_ed25519'})
LEDGER_FIELDS = frozenset({'schema', 'registry_id', 'registrar_public_hex', 'records'})
CLAIM_FIELDS = frozenset({
    'schema', 'registry_id', 'registrar_public_hex', 'sequence',
    'previous_ledger_raw_sha256', 'previous_record_sha256',
    'sender_id', 'receiver_id', 'receiver_public_hex',
    'external_exchange_challenge_sha256', 'bundle_sha256',
    'acknowledgement_sha256', 'independently_pinned_original_chain',
    'original_ec301_report_sha256', 'original_evidence_document_count',
    'acknowledgement_reverified_at_recording',
})


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC304_' + code, status)


def _identity(registry_id: str, registrar_public_hex: str) -> None:
    need(type(registry_id) is str and r.ID.fullmatch(registry_id) is not None,
         'INDEPENDENT_REGISTRY_ID_REQUIRED')
    need(type(registrar_public_hex) is str and a.valid_pub(registrar_public_hex),
         'INDEPENDENT_REGISTRAR_PUBLIC_KEY_REQUIRED')


def _ledger(registry_id: str, registrar_public_hex: str, records: list) -> dict:
    return {'schema': LEDGER_SCHEMA, 'registry_id': registry_id,
            'registrar_public_hex': registrar_public_hex, 'records': records}


def _signed_record_sha(record: dict | None) -> str:
    return a.GENESIS if record is None else b.digest(b.canonical(record))


def _claim(*, registry_id: str, registrar_public_hex: str, sequence: int,
           previous_ledger_raw_sha256: str, previous_record_sha256: str,
           sender_id: str, receiver_id: str, receiver_public_hex: str,
           challenge_sha256: str, expected_bundle_sha256: str,
           expected_acknowledgement_sha256: str, pins: dict,
           proof: dict) -> dict:
    need(proof['exit_code'] == 0 and
         proof['status'] == 'receiver_signature_and_original_pinned_bundle_reverified',
         'LATEST_ORIGINAL_ACK_CANNOT_AUTHORIZE_POSITIVE_REGISTRATION')
    return {'schema': CLAIM_SCHEMA, 'registry_id': registry_id,
            'registrar_public_hex': registrar_public_hex, 'sequence': sequence,
            'previous_ledger_raw_sha256': previous_ledger_raw_sha256,
            'previous_record_sha256': previous_record_sha256,
            'sender_id': sender_id, 'receiver_id': receiver_id,
            'receiver_public_hex': receiver_public_hex,
            'external_exchange_challenge_sha256': challenge_sha256,
            'bundle_sha256': expected_bundle_sha256,
            'acknowledgement_sha256': expected_acknowledgement_sha256,
            'independently_pinned_original_chain': dict(pins),
            'original_ec301_report_sha256': proof['report_sha256'],
            'original_evidence_document_count': proof['evidence_document_count'],
            'acknowledgement_reverified_at_recording': True}


def _validate_context(*, registry_id: str, registrar_public_hex: str,
                      expected_bundle_sha256: str, pins: dict,
                      sender_id: str, receiver_id: str, receiver_public_hex: str,
                      challenge_sha256: str, expected_acknowledgement_sha256: str) -> dict:
    _identity(registry_id, registrar_public_hex)
    pins = r._context(pins, expected_bundle_sha256, sender_id=sender_id,
                      receiver_id=receiver_id,
                      receiver_public_hex=receiver_public_hex,
                      challenge_sha256=challenge_sha256)
    need(registrar_public_hex not in
         (pins['a_public_hex'], pins['b_public_hex'], receiver_public_hex),
         'FOURTH_DISTINCT_REGISTRAR_ED25519_KEY_REQUIRED')
    need(type(expected_acknowledgement_sha256) is str and
         b.HEX64.fullmatch(expected_acknowledgement_sha256) is not None and
         expected_acknowledgement_sha256 != a.GENESIS,
         'EXTERNAL_ACK_RAW_SHA_REQUIRED')
    return pins


def _read_ledger(path: str, expected_raw_sha256: str) -> dict:
    need(type(expected_raw_sha256) is str and
         b.HEX64.fullmatch(expected_raw_sha256) is not None and
         expected_raw_sha256 != a.GENESIS,
         'INDEPENDENT_WHOLE_LEDGER_RAW_SHA_REQUIRED')
    # Enforces regular, private, bounded, no-follow, stable read; no trust in the
    # file until its full bytes equal a SHA obtained outside this file.
    target = b._private_parent(path)  # private directory, no symlink ancestors
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC304_LEDGER_FILE_UNAVAILABLE','unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'LEDGER_FILE_MUST_BE_EXCLUSIVE_OWNER_0600_REGULAR')
    raw = io._open_regular(path, MAX_LEDGER_BYTES, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'LEDGER_FILE_CHANGED_DURING_VERIFICATION', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), expected_raw_sha256),
         'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN')
    doc = io.parse(raw, MAX_LEDGER_BYTES)
    need(hmac.compare_digest(raw, b.canonical(doc)),
         'LEDGER_NOT_EXACT_CANONICAL_BYTES')
    return doc


def _verify_history(doc: dict, registry_id: str,
                    registrar_public_hex: str) -> list[dict]:
    """Verify complete historic sign/chain, NOT missing old ZIPs/ACKs.

    Each historic prefix SHA recomputes the exact previously issued file bytes
    (canonical JSON + newline); links cannot be satisfied by an arbitrary
    subset, an unsigned mutable index, or a repackaged intermediate record.
    """
    a.exact(doc, LEDGER_FIELDS, 'LEDGER_FIELDS_INVALID')
    need(doc['schema'] == LEDGER_SCHEMA and
         doc['registry_id'] == registry_id and
         doc['registrar_public_hex'] == registrar_public_hex,
         'LEDGER_REGISTRY_OR_EXTERNAL_KEY_IDENTITY_MISMATCH')
    records = doc['records']
    need(type(records) is list and 1 <= len(records) <= MAX_ENTRIES,
         'LEDGER_RECORD_COUNT_OUTSIDE_BUDGET')
    seen_challenges: set[str] = set()
    seen_acknowledgements: set[str] = set()
    previous_file_hash = a.GENESIS
    previous_record_hash = a.GENESIS
    pub = io.pub_from_hex(registrar_public_hex)
    for seq, record in enumerate(records, start=1):
        a.exact(record, RECORD_FIELDS, 'REGISTRAR_RECORD_FIELDS_INVALID')
        need(record['schema'] == RECORD_SCHEMA,
             'REGISTRAR_RECORD_SCHEMA_INVALID')
        claim = a.exact(record['claim'], CLAIM_FIELDS, 'RECORD_CLAIM_FIELDS_INVALID')
        need(claim['schema'] == CLAIM_SCHEMA and
             claim['registry_id'] == registry_id and
             claim['registrar_public_hex'] == registrar_public_hex and
             type(claim['sequence']) is int and claim['sequence'] == seq,
             'SIGNED_RECORD_SEQUENCE_OR_REGISTRY_IDENTITY_MISMATCH')
        need(claim['previous_ledger_raw_sha256'] == previous_file_hash and
             claim['previous_record_sha256'] == previous_record_hash,
             'SIGNED_RECORD_CHAIN_OR_PREFIX_SHA_INVALID')
        pins = _validate_context(registry_id=registry_id,
              registrar_public_hex=registrar_public_hex,
              expected_bundle_sha256=claim['bundle_sha256'],
              pins=claim['independently_pinned_original_chain'],
              sender_id=claim['sender_id'], receiver_id=claim['receiver_id'],
              receiver_public_hex=claim['receiver_public_hex'],
              challenge_sha256=claim['external_exchange_challenge_sha256'],
              expected_acknowledgement_sha256=claim['acknowledgement_sha256'])
        need(type(claim['original_ec301_report_sha256']) is str and
             b.HEX64.fullmatch(claim['original_ec301_report_sha256']) is not None and
             claim['original_ec301_report_sha256'] != a.GENESIS and
             type(claim['original_evidence_document_count']) is int and
             1 <= claim['original_evidence_document_count'] <= b.MAX_DOCUMENTS and
             claim['acknowledgement_reverified_at_recording'] is True,
             'SIGNED_ORIGINAL_REPORT_FIELDS_OR_ATTESTATION_INVALID')
        challenge = claim['external_exchange_challenge_sha256']
        receipt = claim['acknowledgement_sha256']
        need(challenge not in seen_challenges,
             'REUSED_EXCHANGE_CHALLENGE_ACROSS_ENTIRE_REGISTRY')
        need(receipt not in seen_acknowledgements,
             'REPLAYED_ACKNOWLEDGEMENT_ACROSS_ENTIRE_REGISTRY')
        sig = record['registrar_signature_ed25519']
        need(type(sig) is str and a.SIG.fullmatch(sig) is not None,
             'REGISTRAR_SIGNATURE_FORMAT_INVALID')
        try:
            pub.verify(bytes.fromhex(sig), DOMAIN + a.canonical(claim))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise a.AnchorError('EC304_REGISTRAR_SIGNATURE_INVALID',
                                'permission_denied') from exc
        seen_challenges.add(challenge)
        seen_acknowledgements.add(receipt)
        previous_record_hash = _signed_record_sha(record)
        # Recreate exact historic prefix snapshot bytes, rather than trusting
        # a hash field supplied by the current signed record.
        previous_file_hash = b.digest(b.canonical(_ledger(
            registry_id, registrar_public_hex, records[:seq])))
    return records


def _latest_binding(*, records: list[dict], registry_id: str,
                    registrar_public_hex: str, expected_bundle_sha256: str,
                    expected_acknowledgement_sha256: str, pins: dict,
                    sender_id: str, receiver_id: str, receiver_public_hex: str,
                    challenge_sha256: str, proof: dict) -> None:
    sequence = len(records)
    previous = (a.GENESIS if sequence == 1 else b.digest(b.canonical(_ledger(
        registry_id, registrar_public_hex, records[:-1]))))
    previous_record = _signed_record_sha(records[-2] if sequence > 1 else None)
    expected = _claim(registry_id=registry_id,
        registrar_public_hex=registrar_public_hex, sequence=sequence,
        previous_ledger_raw_sha256=previous,
        previous_record_sha256=previous_record,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        pins=pins, proof=proof)
    need(hmac.compare_digest(a.canonical(records[-1]['claim']), a.canonical(expected)),
         'LATEST_SIGNED_RECORD_NOT_EQUAL_FULLY_REVERIFIED_EC303_ACK')


def register(*, bundle_file: str, expected_bundle_sha256: str, pins: dict,
             acknowledgement_file: str, expected_acknowledgement_sha256: str,
             sender_id: str, receiver_id: str, receiver_public_hex: str,
             challenge_sha256: str, registry_id: str, registrar_public_hex: str,
             registrar_private_key_file: str, previous_ledger_file: str | None,
             expected_previous_ledger_sha256: str,
             expected_previous_sequence: int, out: str) -> dict:
    """Create next immutable snapshot only after verifying prior pin and EC303.

    The external custodian, NOT this process, must compare-and-swap the next
    raw SHA/sequence into independent durable custody to prevent fork/rollback.
    """
    pins = _validate_context(registry_id=registry_id,
        registrar_public_hex=registrar_public_hex,
        expected_bundle_sha256=expected_bundle_sha256, pins=pins,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256)
    need(type(expected_previous_sequence) is int and
         0 <= expected_previous_sequence < MAX_ENTRIES,
         'EXTERNAL_PREVIOUS_SEQUENCE_OUTSIDE_BUDGET')
    if previous_ledger_file is None:
        need(expected_previous_sequence == 0 and
             expected_previous_ledger_sha256 == a.GENESIS,
             'GENESIS_REQUIRES_EXPLICIT_EXTERNAL_EMPTY_LEDGER_PIN')
        records = []
    else:
        need(expected_previous_sequence >= 1,
             'NONEMPTY_PREDECESSOR_SEQUENCE_REQUIRED')
        prior = _read_ledger(previous_ledger_file, expected_previous_ledger_sha256)
        records = _verify_history(prior, registry_id, registrar_public_hex)
        need(len(records) == expected_previous_sequence,
             'EXTERNAL_PREVIOUS_SEQUENCE_NOT_EQUAL_PINNED_HISTORY')
    need(not any(c['claim']['external_exchange_challenge_sha256'] == challenge_sha256
                 for c in records), 'EXCHANGE_CHALLENGE_ALREADY_CONSUMED')
    need(not any(c['claim']['acknowledgement_sha256'] == expected_acknowledgement_sha256
                 for c in records), 'ACK_ALREADY_RECORDED')
    output = b._private_parent(out)
    need(not output.exists() and not output.is_symlink(),
         'LEDGER_SNAPSHOT_OUTPUT_MUST_BE_NEW')
    # Full EC303 verification replays EC302 ZIP and all original EC301->294
    # signatures. No signer key is read before the entire proof passes.
    proof = r.verify_ack(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, pins=pins,
        acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256)
    key = io.private_from_file(registrar_private_key_file)
    actual_pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(actual_pub, registrar_public_hex),
         'REGISTRAR_PRIVATE_KEY_NOT_EQUAL_INDEPENDENT_PUBLIC_PIN')
    claim = _claim(registry_id=registry_id,
        registrar_public_hex=registrar_public_hex,
        sequence=len(records) + 1,
        previous_ledger_raw_sha256=(a.GENESIS if not records else
                                    expected_previous_ledger_sha256),
        previous_record_sha256=_signed_record_sha(records[-1] if records else None),
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        pins=pins, proof=proof)
    record = {'schema': RECORD_SCHEMA, 'claim': claim,
              'registrar_signature_ed25519': key.sign(
                  DOMAIN + a.canonical(claim)).hex()}
    new = _ledger(registry_id, registrar_public_hex, [*records, record])
    need(len(b.canonical(new)) <= MAX_LEDGER_BYTES,
         'LEDGER_STORAGE_BUDGET_EXCEEDED')
    # Defense in depth: verify freshly assembled full record chain before
    # writing, without re-executing old physical evidence transfers.
    _verify_history(new, registry_id, registrar_public_hex)
    store.store(str(output), new, MAX_LEDGER_BYTES)
    return {'status': 'signed_unique_challenge_after_verified_receiver_ack',
            'registry_id': registry_id, 'sequence': len(new['records']),
            'previous_ledger_raw_sha256':claim['previous_ledger_raw_sha256'],
            'ledger_raw_sha256':b.digest(b.canonical(new)),
            'acknowledgement_sha256':expected_acknowledgement_sha256,
            'bundle_sha256':expected_bundle_sha256,
            'report_sha256':proof['report_sha256'], 'exit_code':0}


def verify(*, ledger_file: str, expected_ledger_sha256: str,
           expected_sequence: int, registry_id: str, registrar_public_hex: str,
           bundle_file: str, expected_bundle_sha256: str, pins: dict,
           acknowledgement_file: str, expected_acknowledgement_sha256: str,
           sender_id: str, receiver_id: str, receiver_public_hex: str,
           challenge_sha256: str) -> dict:
    """Check independently pinned *latest* ledger and its real EC303 ACK.

    Old record signatures and the exact hash chain are checked in full. Only
    the latest EC303 ZIP/ACK is supplied and fully replayed by this API.
    """
    pins = _validate_context(registry_id=registry_id,
        registrar_public_hex=registrar_public_hex,
        expected_bundle_sha256=expected_bundle_sha256, pins=pins,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256)
    need(type(expected_sequence) is int and 1 <= expected_sequence <= MAX_ENTRIES,
         'EXTERNAL_LATEST_SEQUENCE_OUTSIDE_BUDGET')
    ledger = _read_ledger(ledger_file, expected_ledger_sha256)
    records = _verify_history(ledger, registry_id, registrar_public_hex)
    need(len(records) == expected_sequence,
         'EXTERNAL_LATEST_SEQUENCE_NOT_EQUAL_SIGNED_HISTORY')
    proof = r.verify_ack(bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, pins=pins,
        acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256)
    _latest_binding(records=records, registry_id=registry_id,
        registrar_public_hex=registrar_public_hex,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        pins=pins, sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256,
        proof=proof)
    return {'status': 'externally_pinned_signed_history_and_latest_ack_reverified',
            'registry_id': registry_id, 'sequence': expected_sequence,
            'ledger_raw_sha256':expected_ledger_sha256,
            'acknowledgement_sha256':expected_acknowledgement_sha256,
            'bundle_sha256':expected_bundle_sha256,
            'report_sha256':proof['report_sha256'], 'exit_code':0}

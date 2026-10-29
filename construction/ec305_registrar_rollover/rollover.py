#!/usr/bin/env python3
"""EC305 independently signed *one-step* EC304 registrar key cutover.

An immutable EC304 old ledger is frozen at an externally pinned (raw SHA, seq).
A separately pre-trusted governance key and the activating registrar sign a
domain-separated cutover; planned cutovers also require retiring registrar
consent, while emergency cutovers explicitly require NO compromised old key.
The rotated registrar starts a *new EC304 ledger*; this wrapper cross-checks
both ledgers for reused challenge and ACK values before original EC304 writes
and on every full read-only verification.

A signer/ledger is NOT globally revoked by this local process. Only external
latest-certificate/raw-tip pinning and governance-aware verifiers enforce
cutover; CAS/WORM, role independence and global freshness are external.
"""
from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec304_challenge_registry import registry as old

INTENT_SCHEMA = 'ces.ec305.registrar_cutover_intent.v1'
VOTE_SCHEMA = 'ces.ec305.registrar_cutover_vote.v1'
CERT_SCHEMA = 'ces.ec305.registrar_cutover_certificate.v1'
RESULT_SCHEMA = 'ces.ec305.registrar_rollover_result.v1'
DENIAL_SCHEMA = 'ces.ec305.registrar_rollover_denial.v1'
VOTE_FIELDS = frozenset({'schema', 'role', 'intent_raw_sha256',
                         'public_hex', 'signature_ed25519'})
CERT_FIELDS = frozenset({'schema', 'intent', 'votes'})
TRUST_FIELDS = frozenset({
    'registry_id', 'retiring_registrar_public_hex',
    'activating_registrar_public_hex', 'governor_public_hex',
    'old_ledger_raw_sha256', 'old_ledger_sequence',
    'cutover_nonce_sha256', 'governance_decision_sha256', 'cutover_mode'})
DOMAINS = {
    'retiring': b'CES/EC305/RegistrarCutover/RetiringConsent/v1\0',
    'activating': b'CES/EC305/RegistrarCutover/ActivatingProof/v1\0',
    'governance': b'CES/EC305/RegistrarCutover/GovernanceAuthority/v1\0',
}
ROLE_PUB = {
    'retiring': 'retiring_registrar_public_hex',
    'activating': 'activating_registrar_public_hex',
    'governance': 'governor_public_hex'}
MAX_DOCUMENT = 16_384


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC305_' + code, status)


def _sha(value: Any) -> bool:
    return type(value) is str and b.HEX64.fullmatch(value) is not None and value != a.GENESIS


def validate_trust(trust: dict) -> dict:
    a.exact(trust, TRUST_FIELDS, 'EC305_EXPLICIT_EXTERNAL_CUTOVER_PINS_REQUIRED')
    need(type(trust['registry_id']) is str and
         old.r.ID.fullmatch(trust['registry_id']) is not None,
         'REGISTRY_ID_INVALID')
    keys = [trust[k] for k in ('retiring_registrar_public_hex',
                              'activating_registrar_public_hex',
                              'governor_public_hex')]
    need(all(a.valid_pub(key) for key in keys) and len(set(keys)) == 3,
         'THREE_DISTINCT_RETIRED_NEW_GOVERNOR_KEYS_REQUIRED')
    need(all(_sha(trust[k]) for k in ('old_ledger_raw_sha256',
                                    'cutover_nonce_sha256',
                                    'governance_decision_sha256')),
         'OLD_RAW_SHA_NONCE_AND_EXTERNAL_GOVERNANCE_DECISION_REQUIRED')
    need(type(trust['old_ledger_sequence']) is int and
         1 <= trust['old_ledger_sequence'] <= old.MAX_ENTRIES,
         'EXTERNAL_OLD_SEQUENCE_INVALID')
    need(trust['cutover_mode'] in ('planned', 'emergency_compromised'),
         'CUTOVER_MODE_NOT_EXPLICIT')
    return dict(trust)


def _read_doc(path: str, expected_raw_sha256: str) -> dict:
    need(_sha(expected_raw_sha256), 'INDEPENDENT_RAW_SHA_REQUIRED')
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC305_PRIVATE_DOCUMENT_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'OWNER_0600_REGULAR_SINGLE_LINK_REQUIRED')
    raw = io._open_regular(path, MAX_DOCUMENT, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'DOCUMENT_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), expected_raw_sha256),
         'DOCUMENT_NOT_EQUAL_INDEPENDENT_RAW_SHA_PIN')
    doc = io.parse(raw, MAX_DOCUMENT)
    need(hmac.compare_digest(raw, b.canonical(doc)),
         'DOCUMENT_NOT_CANONICAL_EXACT_BYTES')
    return doc


def _read_unpinned_vote(path: str) -> dict:
    """Untrusted vote file: signature verification against pinned intent follows.

    No vote file SHA is needed from outside because the signed message and
    signer identity are both validated and the final cert SHA is independent.
    """
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC305_VOTE_FILE_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'VOTE_OWNER_0600_REQUIRED')
    raw = io._open_regular(path, MAX_DOCUMENT, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'VOTE_FILE_CHANGED_DURING_READ', 'unavailable')
    doc = io.parse(raw, MAX_DOCUMENT)
    need(raw == b.canonical(doc), 'VOTE_NOT_EXACT_CANONICAL_BYTES')
    return doc


def _old_history(trust: dict, old_ledger_file: str) -> list[dict]:
    ledger = old._read_ledger(old_ledger_file, trust['old_ledger_raw_sha256'])
    records = old._verify_history(ledger, trust['registry_id'],
                                  trust['retiring_registrar_public_hex'])
    need(len(records) == trust['old_ledger_sequence'],
         'FROZEN_OLD_LEDGER_SEQUENCE_DIFFERS_FROM_EXTERNAL_PIN')
    new_keys = (trust['activating_registrar_public_hex'],
                trust['governor_public_hex'])
    for record in records:
        claim = record['claim']
        original = claim['independently_pinned_original_chain']
        already = (claim['receiver_public_hex'],
                   original['a_public_hex'], original['b_public_hex'])
        need(all(k not in already for k in new_keys),
             'GOVERNOR_OR_NEW_REGISTRAR_REUSES_HISTORIC_ORIGINAL_ROLE')
    return records


def _intent(trust: dict) -> dict:
    return {'schema': INTENT_SCHEMA, **trust}


def _validate_intent(intent: dict, trust: dict) -> None:
    a.exact(intent, {'schema', *TRUST_FIELDS}, 'EC305_INTENT_FIELDS_INVALID')
    need(intent == _intent(trust), 'CUTOVER_INTENT_MISMATCH_WITH_INDEPENDENT_PINS')


def _vote(role: str, intent: dict, private_key_file: str) -> dict:
    need(role in DOMAINS, 'SIGNATURE_ROLE_NOT_RECOGNIZED')
    need(role != 'retiring' or intent['cutover_mode'] == 'planned',
         'RETIRED_KEY_MUST_NOT_SIGN_EMERGENCY_REVOCATION')
    key = io.private_from_file(private_key_file)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    need(hmac.compare_digest(pub, intent[ROLE_PUB[role]]),
         'ROLE_PRIVATE_KEY_DIFFERS_FROM_EXTERNAL_PUBLIC_PIN')
    return {'schema': VOTE_SCHEMA, 'role': role,
            'intent_raw_sha256': b.digest(b.canonical(intent)),
            'public_hex': pub,
            'signature_ed25519': key.sign(DOMAINS[role] + a.canonical(intent)).hex()}


def _verify_vote(value: dict, role: str, intent: dict) -> None:
    a.exact(value, VOTE_FIELDS, 'EC305_SIGNED_VOTE_FIELDS_INVALID')
    need(value['schema'] == VOTE_SCHEMA and value['role'] == role and
         value['intent_raw_sha256'] == b.digest(b.canonical(intent)) and
         value['public_hex'] == intent[ROLE_PUB[role]],
         'VOTE_ROLE_KEY_OR_INTENT_HASH_MISMATCH')
    signature = value['signature_ed25519']
    need(type(signature) is str and a.SIG.fullmatch(signature) is not None,
         'VOTE_SIGNATURE_FORMAT_INVALID')
    try:
        io.pub_from_hex(value['public_hex']).verify(
            bytes.fromhex(signature), DOMAINS[role] + a.canonical(intent))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise a.AnchorError('EC305_'+role.upper()+'_SIGNATURE_INVALID',
                            'permission_denied') from exc


def _check_cert_fields(cert: dict, trust: dict) -> None:
    a.exact(cert, CERT_FIELDS, 'EC305_CERTIFICATE_FIELDS_INVALID')
    need(cert['schema'] == CERT_SCHEMA, 'CERTIFICATE_SCHEMA_INVALID')
    intent = cert['intent']
    _validate_intent(intent, trust)
    votes = a.exact(cert['votes'], set(DOMAINS), 'EC305_VOTES_FIELDS_INVALID')
    for role in DOMAINS:
        value = votes[role]
        if role == 'retiring' and trust['cutover_mode'] == 'emergency_compromised':
            need(value is None, 'OLD_KEY_MUST_NOT_AUTHORIZE_EMERGENCY')
        else:
            need(type(value) is dict, 'MISSING_MANDATORY_INDEPENDENT_'+role.upper()+'_VOTE')
            _verify_vote(value, role, intent)


def _check_certificate(*, trust: dict, old_ledger_file: str,
                       certificate_file: str,
                       expected_certificate_sha256: str) -> tuple[dict, list[dict]]:
    trust = validate_trust(trust)
    old_records = _old_history(trust, old_ledger_file)
    cert = _read_doc(certificate_file, expected_certificate_sha256)
    _check_cert_fields(cert, trust)
    return cert, old_records


def _new_history(trust: dict, old_records: list[dict],
                 new_ledger_file: str | None,
                 expected_new_ledger_sha256: str,
                 expected_new_sequence: int, *, allow_empty: bool) -> list[dict]:
    need(type(expected_new_sequence) is int and
         (0 if allow_empty else 1) <= expected_new_sequence <= old.MAX_ENTRIES,
         'INDEPENDENT_NEW_EPOCH_SEQUENCE_INVALID')
    if new_ledger_file is None:
        need(allow_empty and expected_new_sequence == 0 and
             expected_new_ledger_sha256 == a.GENESIS,
             'NEW_EPOCH_GENESIS_REQUIRES_EXPLICIT_ZERO_EXTERNAL_PIN')
        return []
    need(expected_new_sequence >= 1, 'NEW_LEDGER_FILE_REQUIRES_NONZERO_PIN')
    new_ledger = old._read_ledger(new_ledger_file, expected_new_ledger_sha256)
    newer = old._verify_history(new_ledger, trust['registry_id'],
                                trust['activating_registrar_public_hex'])
    need(len(newer) == expected_new_sequence,
         'NEW_EPOCH_SEQUENCE_MISMATCH_WITH_INDEPENDENT_PIN')
    prior_challenges = {rec['claim']['external_exchange_challenge_sha256']
                        for rec in old_records}
    prior_acks = {rec['claim']['acknowledgement_sha256'] for rec in old_records}
    for record in newer:
        claim = record['claim']
        need(claim['external_exchange_challenge_sha256'] not in prior_challenges,
             'CROSS_EPOCH_CHALLENGE_REUSE_FORBIDDEN')
        need(claim['acknowledgement_sha256'] not in prior_acks,
             'CROSS_EPOCH_ACK_REPLAY_FORBIDDEN')
        pins = claim['independently_pinned_original_chain']
        need(all(k not in (trust['governor_public_hex'],
                           trust['retiring_registrar_public_hex'])
                 for k in (claim['receiver_public_hex'],
                           pins['a_public_hex'], pins['b_public_hex'])),
             'OLD_REGISTRAR_OR_GOVERNOR_REUSED_AS_NEW_ORIGINAL_ROLE')
    return newer


def _check_new_context(trust: dict, pins: dict, receiver_public_hex: str) -> None:
    need(type(pins) is dict and
         all(k in pins for k in ('a_public_hex','b_public_hex')) and
         all(k not in (trust['governor_public_hex'],
                       trust['retiring_registrar_public_hex'])
             for k in (receiver_public_hex, pins['a_public_hex'],pins['b_public_hex'])),
         'OLD_REGISTRAR_OR_GOVERNOR_CANNOT_BE_NEW_ORIGINAL_ROLE')


def prepare(*, trust: dict, old_ledger_file: str, out: str) -> dict:
    trust = validate_trust(trust)
    _old_history(trust, old_ledger_file)
    intent = _intent(trust)
    store.store(out, intent, MAX_DOCUMENT)
    return {'status':'independently_pinned_cutover_intent_prepared',
            'intent_raw_sha256':b.digest(b.canonical(intent)),
            'cutover_mode':trust['cutover_mode'], 'exit_code':0}


def sign(*, trust: dict, old_ledger_file: str, intent_file: str,
         expected_intent_sha256: str, role: str,
         private_key_file: str, out: str) -> dict:
    trust = validate_trust(trust)
    _old_history(trust, old_ledger_file)
    intent = _read_doc(intent_file, expected_intent_sha256)
    _validate_intent(intent, trust)
    vote = _vote(role, intent, private_key_file)
    store.store(out, vote, MAX_DOCUMENT)
    return {'status':'cutover_role_signed_after_old_history_recheck',
            'role':role, 'vote_raw_sha256':b.digest(b.canonical(vote)),
            'intent_raw_sha256':expected_intent_sha256, 'exit_code':0}


def assemble(*, trust: dict, old_ledger_file: str, intent_file: str,
             expected_intent_sha256: str, retiring_vote_file: str | None,
             activating_vote_file: str, governance_vote_file: str,
             out: str) -> dict:
    trust = validate_trust(trust)
    _old_history(trust, old_ledger_file)
    intent = _read_doc(intent_file, expected_intent_sha256)
    _validate_intent(intent, trust)
    votes = {
        'retiring': (_read_unpinned_vote(retiring_vote_file)
                     if retiring_vote_file is not None else None),
        'activating':_read_unpinned_vote(activating_vote_file),
        'governance':_read_unpinned_vote(governance_vote_file)}
    cert = {'schema': CERT_SCHEMA, 'intent':intent, 'votes': votes}
    _check_cert_fields(cert, trust)
    store.store(out, cert, MAX_DOCUMENT)
    return {'status':'independent_governance_and_activation_cutover_signed',
            'certificate_raw_sha256':b.digest(b.canonical(cert)),
            'old_ledger_raw_sha256':trust['old_ledger_raw_sha256'],
            'old_ledger_sequence':trust['old_ledger_sequence'],
            'cutover_mode':trust['cutover_mode'], 'exit_code':0}


def verify_certificate(*, trust: dict, old_ledger_file: str,
                       certificate_file: str,
                       expected_certificate_sha256: str) -> dict:
    cert, records = _check_certificate(
        trust=trust, old_ledger_file=old_ledger_file,
        certificate_file=certificate_file,
        expected_certificate_sha256=expected_certificate_sha256)
    return {'status':'pinned_frozen_old_history_and_independent_cutover_signatures_reverified',
            'certificate_raw_sha256':expected_certificate_sha256,
            'old_ledger_raw_sha256':trust['old_ledger_raw_sha256'],
            'old_ledger_sequence':len(records),
            'cutover_mode':cert['intent']['cutover_mode'],
            'new_ledger_accepted_as_latest':False,
            'exit_code':0}


def _before_append(*, trust: dict, old_ledger_file: str,
                   certificate_file: str, expected_certificate_sha256: str,
                   previous_new_ledger_file: str | None,
                   expected_previous_new_ledger_sha256: str,
                   expected_previous_new_sequence: int,
                   expected_challenge_sha256: str,
                   expected_acknowledgement_sha256: str,
                   pins: dict, receiver_public_hex: str) -> tuple[list[dict], list[dict]]:
    _, old_records = _check_certificate(
        trust=trust, old_ledger_file=old_ledger_file,
        certificate_file=certificate_file,
        expected_certificate_sha256=expected_certificate_sha256)
    new_records = _new_history(
        trust, old_records, previous_new_ledger_file,
        expected_previous_new_ledger_sha256,
        expected_previous_new_sequence, allow_empty=True)
    _check_new_context(trust, pins, receiver_public_hex)
    need(not any(rec['claim']['external_exchange_challenge_sha256'] ==
                 expected_challenge_sha256 for rec in old_records),
         'CUTOVER_CANNOT_REUSE_RETIRED_EPOCH_CHALLENGE')
    need(not any(rec['claim']['acknowledgement_sha256'] ==
                 expected_acknowledgement_sha256 for rec in old_records),
         'CUTOVER_CANNOT_REUSE_RETIRED_EPOCH_ACK')
    return old_records, new_records


def register(*, trust: dict, old_ledger_file: str,
             certificate_file: str, expected_certificate_sha256: str,
             previous_new_ledger_file: str | None,
             expected_previous_new_ledger_sha256: str,
             expected_previous_new_sequence: int,
             activating_private_key_file: str, out: str,
             bundle_file: str, expected_bundle_sha256: str, pins: dict,
             acknowledgement_file: str, expected_acknowledgement_sha256: str,
             sender_id: str, receiver_id: str, receiver_public_hex: str,
             challenge_sha256: str) -> dict:
    trust = validate_trust(trust)
    _before_append(
        trust=trust, old_ledger_file=old_ledger_file,
        certificate_file=certificate_file,
        expected_certificate_sha256=expected_certificate_sha256,
        previous_new_ledger_file=previous_new_ledger_file,
        expected_previous_new_ledger_sha256=expected_previous_new_ledger_sha256,
        expected_previous_new_sequence=expected_previous_new_sequence,
        expected_challenge_sha256=challenge_sha256,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        pins=pins, receiver_public_hex=receiver_public_hex)
    # The ORIGINAL EC304 checks all new-epoch prior signatures and consumes
    # the genuinely reverified newest EC303 -> EC294 ACK BEFORE signing.
    result = old.register(
        registry_id=trust['registry_id'],
        registrar_public_hex=trust['activating_registrar_public_hex'],
        registrar_private_key_file=activating_private_key_file,
        previous_ledger_file=previous_new_ledger_file,
        expected_previous_ledger_sha256=expected_previous_new_ledger_sha256,
        expected_previous_sequence=expected_previous_new_sequence,
        out=out, bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256,pins=pins,
        acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex,
        challenge_sha256=challenge_sha256)
    return {**result,
            'status':'governed_new_registrar_signed_unique_cross_epoch_ack',
            'certificate_raw_sha256':expected_certificate_sha256,
            'retired_ledger_raw_sha256':trust['old_ledger_raw_sha256'],
            'new_epoch_sequence':result['sequence'],
            'old_key_authorizes_new_epoch':False,
            'external_cas_or_revocation_distribution_proven':False}


def verify(*, trust: dict, old_ledger_file: str,
           certificate_file: str, expected_certificate_sha256: str,
           new_ledger_file: str, expected_new_ledger_sha256: str,
           expected_new_sequence: int,
           bundle_file: str, expected_bundle_sha256: str, pins: dict,
           acknowledgement_file: str, expected_acknowledgement_sha256: str,
           sender_id: str, receiver_id: str, receiver_public_hex: str,
           challenge_sha256: str) -> dict:
    trust = validate_trust(trust)
    _, old_records = _check_certificate(
        trust=trust, old_ledger_file=old_ledger_file,
        certificate_file=certificate_file,
        expected_certificate_sha256=expected_certificate_sha256)
    new_records = _new_history(trust, old_records,
                               new_ledger_file, expected_new_ledger_sha256,
                               expected_new_sequence, allow_empty=False)
    _check_new_context(trust, pins, receiver_public_hex)
    proof = old.verify(
        registry_id=trust['registry_id'],
        registrar_public_hex=trust['activating_registrar_public_hex'],
        ledger_file=new_ledger_file,
        expected_ledger_sha256=expected_new_ledger_sha256,
        expected_sequence=expected_new_sequence,
        bundle_file=bundle_file,expected_bundle_sha256=expected_bundle_sha256,
        pins=pins,acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id,receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex,challenge_sha256=challenge_sha256)
    need(len(new_records) == expected_new_sequence and proof['exit_code'] == 0,
         'LATEST_ACTIVATING_EPOCH_NOT_VERIFIED')
    return {'status':'externally_pinned_governed_rollover_and_latest_original_ack_reverified',
            'registry_id':trust['registry_id'],
            'cutover_mode':trust['cutover_mode'],
            'certificate_raw_sha256':expected_certificate_sha256,
            'old_ledger_raw_sha256':trust['old_ledger_raw_sha256'],
            'old_ledger_sequence':len(old_records),
            'new_ledger_raw_sha256':expected_new_ledger_sha256,
            'new_ledger_sequence':len(new_records),
            'acknowledgement_sha256':expected_acknowledgement_sha256,
            'bundle_sha256':expected_bundle_sha256,
            'report_sha256':proof['report_sha256'],
            'old_key_authorizes_new_epoch':False,
            'historical_old_zip_ack_contents_replayed':False,
            'external_global_revocation_cas_worm_proven':False,
            'exit_code':0}

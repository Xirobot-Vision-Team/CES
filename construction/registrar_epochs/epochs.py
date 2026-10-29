#!/usr/bin/env python3
"""EC306: multi-epoch EC304 signed registries linked by original EC305 votes.

The raw-SHA-pinned chain is an *index*, NOT a new trust root. Every audit reads
all epoch ledgers and all EC305 certificates, verifies their real Ed25519
signatures, and enforces global spent challenge/ACK and registrar key exclusion.
Only the current epoch may grow. Cutover freezes the last independently pinned
ledger of its predecessor and creates an empty new EC304 epoch. Signing a new
EC304 ledger and publishing the new chain pin are deliberately separate steps:
external durable CAS/WORM must decide which candidate is authoritative.
"""
from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from challenge_registry import registry as registry
from registrar_rollover import rollover as rollover

SCHEMA = 'ces.ec306.registrar_epoch_chain.v1'
RESULT_SCHEMA = 'ces.ec306.registrar_epoch_result.v1'
DENIAL_SCHEMA = 'ces.ec306.registrar_epoch_denial.v1'
CHAIN_FIELDS = frozenset({
    'schema', 'registry_id', 'governor_public_hex',
    'initial_registrar_public_hex', 'previous_chain_raw_sha256', 'epochs'})
EPOCH_FIELDS = frozenset({
    'ordinal', 'registrar_public_hex', 'ledger_raw_sha256', 'ledger_sequence',
    'cutover_certificate_raw_sha256', 'cutover_nonce_sha256',
    'governance_decision_sha256', 'cutover_mode'})
EXTERNAL_FIELDS = frozenset({
    'registry_id', 'governor_public_hex', 'initial_registrar_public_hex',
    'chain_raw_sha256', 'epoch_count', 'active_registrar_public_hex',
    'active_ledger_raw_sha256', 'active_ledger_sequence'})
MAX_EPOCHS = 8
MAX_CHAIN_BYTES = 32_768


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise a.AnchorError('EC306_' + code, status)


def _positive_sha(value: Any) -> bool:
    return a.valid_sha(value) and value != a.GENESIS


def _owner_private_read(path: str, pinned_raw_sha: str) -> dict:
    """Read one canonical 0600 JSON snapshot under an external raw SHA pin."""
    need(_positive_sha(pinned_raw_sha), 'INDEPENDENT_CHAIN_SHA_REQUIRED')
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC306_CHAIN_FILE_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'CHAIN_FILE_OWNER_0600_SINGLE_LINK_REQUIRED')
    raw = io._open_regular(path, MAX_CHAIN_BYTES, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
          before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
          after.st_ctime_ns), 'CHAIN_FILE_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), pinned_raw_sha),
         'CHAIN_BYTES_DIFFER_FROM_INDEPENDENT_RAW_SHA')
    doc = io.parse(raw, MAX_CHAIN_BYTES)
    need(hmac.compare_digest(raw, b.canonical(doc)),
         'CHAIN_NOT_CANONICAL_EXACT_BYTES')
    return doc


def _epoch(ordinal: int, public_hex: str, ledger_sha: str, sequence: int,
           certificate_sha: str | None = None,
           nonce_sha: str | None = None, decision_sha: str | None = None,
           mode: str | None = None) -> dict:
    return {'ordinal': ordinal, 'registrar_public_hex': public_hex,
            'ledger_raw_sha256': ledger_sha, 'ledger_sequence': sequence,
            'cutover_certificate_raw_sha256': certificate_sha,
            'cutover_nonce_sha256': nonce_sha,
            'governance_decision_sha256': decision_sha, 'cutover_mode': mode}


def _chain(registry_id: str, governor_pub: str, initial_pub: str,
           previous_chain_sha: str, epochs: list[dict]) -> dict:
    return {'schema': SCHEMA, 'registry_id': registry_id,
            'governor_public_hex': governor_pub,
            'initial_registrar_public_hex': initial_pub,
            'previous_chain_raw_sha256': previous_chain_sha,
            'epochs': epochs}


def _check_structure(doc: dict) -> None:
    a.exact(doc, CHAIN_FIELDS, 'EC306_CHAIN_FIELDS_INVALID')
    need(doc['schema'] == SCHEMA, 'CHAIN_SCHEMA_INVALID')
    need(type(doc['registry_id']) is str and
         registry.r.ID.fullmatch(doc['registry_id']) is not None,
         'REGISTRY_ID_INVALID')
    need(a.valid_pub(doc['governor_public_hex']) and
         a.valid_pub(doc['initial_registrar_public_hex']) and
         doc['governor_public_hex'] != doc['initial_registrar_public_hex'],
         'ROOT_GOVERNANCE_KEY_SEPARATION_REQUIRED')
    need(a.valid_sha(doc['previous_chain_raw_sha256']),
         'PREDECESSOR_SNAPSHOT_SHA_FORMAT_INVALID')
    # The first snapshot uses GENESIS. Every later revision must name an
    # independently externally pinnable previous snapshot, not fake GENESIS.
    need(doc['previous_chain_raw_sha256'] == a.GENESIS or
         _positive_sha(doc['previous_chain_raw_sha256']),
         'PREVIOUS_CHAIN_SHA_MUST_BE_EXPLICIT')
    epochs = doc['epochs']
    need(type(epochs) is list and 1 <= len(epochs) <= MAX_EPOCHS,
         'EPOCH_COUNT_OUTSIDE_BOUNDED_HISTORY')
    need(len(epochs) == 1 or doc['previous_chain_raw_sha256'] != a.GENESIS,
         'MULTI_EPOCH_CHAIN_CANNOT_CLAIM_GENESIS_PARENT')
    pubkeys = [doc['governor_public_hex']]
    nonces: set[str] = set()
    certs: set[str] = set()
    for i, e in enumerate(epochs):
        a.exact(e, EPOCH_FIELDS, 'EC306_EPOCH_FIELDS_INVALID')
        need(type(e['ordinal']) is int and e['ordinal'] == i,
             'EPOCH_ORDINAL_MUST_BE_CONTIGUOUS')
        key = e['registrar_public_hex']
        need(a.valid_pub(key) and key not in pubkeys,
             'REGISTRAR_KEY_REUSED_OR_NOT_VALID')
        pubkeys.append(key)
        seq = e['ledger_sequence']
        need(type(seq) is int and 0 <= seq <= registry.MAX_ENTRIES and
             (seq > 0 or (i > 0 and i == len(epochs) - 1)),
             'ONLY_ACTIVE_EPOCH_MAY_BE_EMPTY')
        sha = e['ledger_raw_sha256']
        need((sha == a.GENESIS) if seq == 0 else _positive_sha(sha),
             'LEDGER_SHA_AND_SEQUENCE_GENESIS_INCONSISTENT')
        if i == 0:
            need(key == doc['initial_registrar_public_hex'] and
                 all(e[f] is None for f in (
                     'cutover_certificate_raw_sha256',
                     'cutover_nonce_sha256', 'governance_decision_sha256',
                     'cutover_mode')),
                 'ROOT_MUST_HAVE_NO_CUTOVER_CERTIFICATE')
        else:
            cert = e['cutover_certificate_raw_sha256']
            nonce = e['cutover_nonce_sha256']
            decision = e['governance_decision_sha256']
            need(all(_positive_sha(x) for x in (cert, nonce, decision)) and
                 e['cutover_mode'] in ('planned', 'emergency_compromised'),
                 'EPOCH_MISSING_SIGNED_GOVERNANCE_CUTOVER_PINS')
            need(nonce not in nonces and cert not in certs,
                 'CUTOVER_NONCE_OR_CERTIFICATE_REUSED')
            nonces.add(nonce)
            certs.add(cert)



def _check_external(doc: dict, external: dict) -> None:
    a.exact(external, EXTERNAL_FIELDS,
            'EC306_EIGHT_INDEPENDENT_EXTERNAL_PINS_REQUIRED')
    _check_structure(doc)
    active = doc['epochs'][-1]
    expected = {
        'registry_id': doc['registry_id'],
        'governor_public_hex': doc['governor_public_hex'],
        'initial_registrar_public_hex': doc['initial_registrar_public_hex'],
        'epoch_count': len(doc['epochs']),
        'active_registrar_public_hex': active['registrar_public_hex'],
        'active_ledger_raw_sha256': active['ledger_raw_sha256'],
        'active_ledger_sequence': active['ledger_sequence'],
    }
    need(all(type(external[k]) is type(v) and external[k] == v
             for k, v in expected.items()),
         'EXPLICIT_EXTERNAL_ROOT_EPOCH_ACTIVE_TIP_OR_SEQUENCE_MISMATCH')
    need(_positive_sha(external['chain_raw_sha256']),
         'CURRENT_CHAIN_RAW_SHA_MUST_BE_INDEPENDENTLY_ANCHORED')


def _read_active_chain(*, chain_file: str, external: dict,
                       ledger_files: list[str],
                       certificate_files: list[str]) -> tuple[dict, list[list[dict]]]:
    doc = _owner_private_read(chain_file, external['chain_raw_sha256'])
    _check_external(doc, external)
    histories = _verify_all_epochs(doc, ledger_files, certificate_files)
    return doc, histories


def _trust(doc: dict, old_epoch: dict, new_epoch: dict) -> dict:
    return {
        'registry_id': doc['registry_id'],
        'retiring_registrar_public_hex': old_epoch['registrar_public_hex'],
        'activating_registrar_public_hex': new_epoch['registrar_public_hex'],
        'governor_public_hex': doc['governor_public_hex'],
        'old_ledger_raw_sha256': old_epoch['ledger_raw_sha256'],
        'old_ledger_sequence': old_epoch['ledger_sequence'],
        'cutover_nonce_sha256': new_epoch['cutover_nonce_sha256'],
        'governance_decision_sha256': new_epoch['governance_decision_sha256'],
        'cutover_mode': new_epoch['cutover_mode']}


def _verify_all_epochs(doc: dict, ledger_files: list[str],
                       certificate_files: list[str]) -> list[list[dict]]:
    """All signed histories/certificates + global role/consumption invariants.

    Files are separate *untrusted locators*, in ordinal order for every
    nonempty ledger, and in transition order for each EC305 certificate.
    Hashes, sequence numbers, public keys and roles come from externally
    raw-SHA-pinned chain and are never taken from those file locators.
    """
    _check_structure(doc)
    need(type(ledger_files) is list and
         all(type(x) is str for x in ledger_files) and
         len(ledger_files) == sum(e['ledger_sequence'] > 0 for e in doc['epochs']),
         'ALL_NONEMPTY_EPOCH_LEDGER_FILES_REQUIRED')
    need(type(certificate_files) is list and
         all(type(x) is str for x in certificate_files) and
         len(certificate_files) == len(doc['epochs']) - 1,
         'ALL_CUTOVER_CERTIFICATE_FILES_REQUIRED')
    need(len(set(ledger_files + certificate_files)) ==
         len(ledger_files) + len(certificate_files),
         'DUPLICATE_HISTORY_FILE_LOCATOR')
    all_pub = {doc['governor_public_hex']} | {
        e['registrar_public_hex'] for e in doc['epochs']}
    seen_challenges: set[str] = set()
    seen_acks: set[str] = set()
    histories: list[list[dict]] = []
    ledger_by_epoch: dict[int, str] = {}
    ledger_iter = iter(ledger_files)
    for i, e in enumerate(doc['epochs']):
        if e['ledger_sequence'] == 0:
            histories.append([])
            continue
        file = next(ledger_iter)
        ledger_by_epoch[i] = file
        signed_ledger = registry._read_ledger(file, e['ledger_raw_sha256'])
        records = registry._verify_history(
            signed_ledger, doc['registry_id'], e['registrar_public_hex'])
        need(len(records) == e['ledger_sequence'],
             'SIGNED_EPOCH_SEQUENCE_NOT_EQUAL_EXTERNALLY_PINNED_SEQUENCE')
        for record in records:
            claim = record['claim']
            pins = claim['independently_pinned_original_chain']
            need(not ({claim['receiver_public_hex'], pins['a_public_hex'],
                       pins['b_public_hex']} & all_pub),
                 'GOVERNANCE_OR_ANY_PAST_FUTURE_REGISTRAR_REUSED_AS_ORIGINAL_ROLE')
            challenge = claim['external_exchange_challenge_sha256']
            ack = claim['acknowledgement_sha256']
            need(challenge not in seen_challenges,
                 'CHALLENGE_REPLAY_ACROSS_ANY_HISTORIC_EPOCH')
            need(ack not in seen_acks,
                 'ACK_REPLAY_ACROSS_ANY_HISTORIC_EPOCH')
            seen_challenges.add(challenge)
            seen_acks.add(ack)
        histories.append(records)
    for i in range(1, len(doc['epochs'])):
        old_epoch, new_epoch = doc['epochs'][i-1:i+1]
        # The original EC305 checks exact old ledger raw SHA/sequence and
        # *all* old EC304 signatures before verifying role-separated votes.
        cert, frozen = rollover._check_certificate(
            trust=_trust(doc, old_epoch, new_epoch),
            old_ledger_file=ledger_by_epoch[i-1],
            certificate_file=certificate_files[i-1],
            expected_certificate_sha256=new_epoch['cutover_certificate_raw_sha256'])
        need(len(frozen) == len(histories[i-1]) and
             cert['intent']['activating_registrar_public_hex'] ==
             new_epoch['registrar_public_hex'],
             'CERTIFICATE_CANNOT_CHANGE_FROZEN_EPOCH')
    return histories


def _spent(histories: list[list[dict]]) -> tuple[set[str], set[str]]:
    challenges = set()
    receipts = set()
    for records in histories:
        for record in records:
            challenges.add(record['claim']['external_exchange_challenge_sha256'])
            receipts.add(record['claim']['acknowledgement_sha256'])
    return challenges, receipts


def _latest_roles(doc: dict, pins: dict, receiver_public_hex: str) -> None:
    need(type(pins) is dict and
         all(k in pins for k in ('a_public_hex', 'b_public_hex')),
         'ORIGINAL_WITNESS_PUBLIC_PINS_REQUIRED')
    forbidden = {doc['governor_public_hex']} | {
        e['registrar_public_hex'] for e in doc['epochs']}
    need(not (forbidden & {receiver_public_hex, pins['a_public_hex'],
                            pins['b_public_hex']}),
         'REGISTRAR_OF_ANY_EPOCH_OR_GOVERNOR_REUSED_FOR_ORIGINAL_ACK_ROLE')


def _save_snapshot(out: str, doc: dict, *, status: str) -> dict:
    _check_structure(doc)
    store.store(out, doc, MAX_CHAIN_BYTES)
    active = doc['epochs'][-1]
    return {'status': status,
            'registry_id': doc['registry_id'],
            'chain_raw_sha256': b.digest(b.canonical(doc)),
            'epoch_count': len(doc['epochs']),
            'active_registrar_public_hex': active['registrar_public_hex'],
            'active_ledger_raw_sha256': active['ledger_raw_sha256'],
            'active_ledger_sequence': active['ledger_sequence'],
            'previous_chain_raw_sha256': doc['previous_chain_raw_sha256'],
            'external_latest_cas_worm_proven': False,
            'exit_code': 0}


def start(*, registry_id: str, governor_public_hex: str,
          initial_registrar_public_hex: str, initial_ledger_file: str,
          expected_initial_ledger_sha256: str, expected_initial_sequence: int,
          out: str) -> dict:
    """Create the first full chain index over an existing signed EC304 ledger."""
    doc = _chain(registry_id, governor_public_hex,
        initial_registrar_public_hex, a.GENESIS,
        [_epoch(0, initial_registrar_public_hex,
                expected_initial_ledger_sha256, expected_initial_sequence)])
    need(type(expected_initial_sequence) is int and
         expected_initial_sequence >= 1, 'INITIAL_SIGNED_LEDGER_REQUIRED')
    _verify_all_epochs(doc, [initial_ledger_file], [])
    return _save_snapshot(out, doc, status='initial_ec304_signed_epoch_indexed')


def rotate(*, chain_file: str, external: dict, ledger_files: list[str],
           certificate_files: list[str], new_registrar_public_hex: str,
           new_certificate_file: str, expected_new_certificate_sha256: str,
           cutover_nonce_sha256: str, governance_decision_sha256: str,
           cutover_mode: str, out: str) -> dict:
    """Verify every previous epoch and an original EC305 independent cutover.

    The active ledger tip becomes frozen. New epoch starts at (GENESIS, 0).
    Never use the generic EC305 one-step wrapper after this: EC306 checks all
    prior epochs, not just the most recent retired epoch.
    """
    doc, _ = _read_active_chain(
        chain_file=chain_file, external=external, ledger_files=ledger_files,
        certificate_files=certificate_files)
    need(len(doc['epochs']) < MAX_EPOCHS, 'MAX_EPOCHS_REACHED')
    retiring = doc['epochs'][-1]
    need(retiring['ledger_sequence'] >= 1,
         'CANNOT_ROTATE_UNINITIALIZED_EMPTY_REGISTRAR_EPOCH')
    new = _epoch(len(doc['epochs']), new_registrar_public_hex, a.GENESIS, 0,
                 expected_new_certificate_sha256, cutover_nonce_sha256,
                 governance_decision_sha256, cutover_mode)
    candidate = _chain(doc['registry_id'], doc['governor_public_hex'],
                       doc['initial_registrar_public_hex'],
                       external['chain_raw_sha256'], doc['epochs'] + [new])
    _check_structure(candidate)
    # Full verifier detects the newly activated key in *all* historic original
    # receiver/witness roles; this closes key reuse before creating the index.
    _verify_all_epochs(candidate, ledger_files,
                       certificate_files + [new_certificate_file])
    return _save_snapshot(out, candidate,
                          status='original_ec305_signed_cutover_appended_new_epoch')


def register(*, chain_file: str, external: dict, ledger_files: list[str],
             certificate_files: list[str], active_private_key_file: str,
             out: str, bundle_file: str, expected_bundle_sha256: str,
             pins: dict, acknowledgement_file: str,
             expected_acknowledgement_sha256: str, sender_id: str,
             receiver_id: str, receiver_public_hex: str,
             challenge_sha256: str) -> dict:
    """Sign an EC304 candidate only after global spent/role/cert verification.

    Does NOT publish a new latest chain: caller must explicitly commit its
    signed ledger under a new immutable chain snapshot and external CAS.
    """
    doc, histories = _read_active_chain(
        chain_file=chain_file, external=external, ledger_files=ledger_files,
        certificate_files=certificate_files)
    active = doc['epochs'][-1]
    _latest_roles(doc, pins, receiver_public_hex)
    challenges, acks = _spent(histories)
    need(challenge_sha256 not in challenges,
         'NEW_CHALLENGE_ALREADY_SPENT_IN_ANY_EPOCH')
    need(expected_acknowledgement_sha256 not in acks,
         'NEW_ACK_ALREADY_SPENT_IN_ANY_EPOCH')
    prior = (ledger_files[-1] if active['ledger_sequence'] else None)
    signed = registry.register(
        registry_id=doc['registry_id'],
        registrar_public_hex=active['registrar_public_hex'],
        registrar_private_key_file=active_private_key_file,
        previous_ledger_file=prior,
        expected_previous_ledger_sha256=active['ledger_raw_sha256'],
        expected_previous_sequence=active['ledger_sequence'],
        out=out, bundle_file=bundle_file,
        expected_bundle_sha256=expected_bundle_sha256, pins=pins,
        acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex,
        challenge_sha256=challenge_sha256)
    return {**signed, 'status': 'ec304_signed_candidate_rechecked_across_all_epochs',
            'pinned_prior_chain_sha256': external['chain_raw_sha256'],
            'registered_epoch': len(doc['epochs'])-1,
            'candidate_committed_to_chain': False,
            'external_latest_cas_worm_proven': False}


def _verify_latest_ack(*, doc: dict, ledger_file: str,
                       bundle_file: str, expected_bundle_sha256: str,
                       pins: dict, acknowledgement_file: str,
                       expected_acknowledgement_sha256: str,
                       sender_id: str, receiver_id: str,
                       receiver_public_hex: str,
                       challenge_sha256: str) -> dict:
    active = doc['epochs'][-1]
    need(active['ledger_sequence'] >= 1,
         'NEWEST_EPOCH_HAS_NO_ACK_YET')
    _latest_roles(doc, pins, receiver_public_hex)
    return registry.verify(
        registry_id=doc['registry_id'],
        registrar_public_hex=active['registrar_public_hex'],
        ledger_file=ledger_file,
        expected_ledger_sha256=active['ledger_raw_sha256'],
        expected_sequence=active['ledger_sequence'],
        bundle_file=bundle_file, expected_bundle_sha256=expected_bundle_sha256,
        pins=pins, acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex,
        challenge_sha256=challenge_sha256)


def commit(*, chain_file: str, external: dict, ledger_files: list[str],
           certificate_files: list[str], candidate_ledger_file: str,
           expected_candidate_ledger_sha256: str,
           expected_candidate_sequence: int, out: str,
           bundle_file: str, expected_bundle_sha256: str, pins: dict,
           acknowledgement_file: str, expected_acknowledgement_sha256: str,
           sender_id: str, receiver_id: str, receiver_public_hex: str,
           challenge_sha256: str) -> dict:
    """Promote one signed EC304 ledger candidate into a new pinned index.

    Recompute exact old prefix, never accept a replaced or truncated prior
    snapshot. Latest ACK is truly rechecked against EC303->EC294 prior to
    writing the next immutable chain index. External CAS remains mandatory.
    """
    doc, histories = _read_active_chain(
        chain_file=chain_file, external=external, ledger_files=ledger_files,
        certificate_files=certificate_files)
    active = doc['epochs'][-1]
    need(type(expected_candidate_sequence) is int and
         expected_candidate_sequence == active['ledger_sequence'] + 1,
         'CANDIDATE_MUST_ADVANCE_ACTIVE_EPOCH_BY_EXACTLY_ONE')
    signed_candidate = registry._read_ledger(
        candidate_ledger_file, expected_candidate_ledger_sha256)
    records = registry._verify_history(signed_candidate,
        doc['registry_id'], active['registrar_public_hex'])
    need(len(records) == expected_candidate_sequence,
         'CANDIDATE_SEQUENCE_DIFFERS_FROM_INDEPENDENT_PIN')
    prior_records = histories[-1]
    need(records[:-1] == prior_records, 'CANDIDATE_NOT_EXACT_SIGNED_PREFIX_EXTENSION')
    # EC304 signed claims cryptographically bind the entire previous snapshot.
    need(records[-1]['claim']['previous_ledger_raw_sha256'] ==
         active['ledger_raw_sha256'],
         'CANDIDATE_PREVIOUS_RAW_LEDGER_HASH_NOT_PINNED_ACTIVE_TIP')
    # Read against all previous epochs and original EC305 certificate history,
    # including the proposed candidate, before any chain output is created.
    new = dict(active, ledger_raw_sha256=expected_candidate_ledger_sha256,
               ledger_sequence=expected_candidate_sequence)
    candidate_index = _chain(
        doc['registry_id'], doc['governor_public_hex'],
        doc['initial_registrar_public_hex'], external['chain_raw_sha256'],
        doc['epochs'][:-1] + [new])
    candidate_files = (ledger_files[:-1] + [candidate_ledger_file]
                       if active['ledger_sequence'] else ledger_files + [candidate_ledger_file])
    _verify_all_epochs(candidate_index, candidate_files, certificate_files)
    verified = _verify_latest_ack(
        doc=candidate_index, ledger_file=candidate_ledger_file,
        bundle_file=bundle_file, expected_bundle_sha256=expected_bundle_sha256,
        pins=pins, acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex,
        challenge_sha256=challenge_sha256)
    need(verified['exit_code'] == 0, 'ORIGINAL_NEWEST_ACK_NOT_VERIFIED')
    saved = _save_snapshot(out, candidate_index,
                status='single_signed_ack_promoted_into_new_pinned_chain_candidate')
    return {**saved, 'report_sha256': verified['report_sha256'],
            'acknowledgement_sha256': expected_acknowledgement_sha256,
            'bundle_sha256': expected_bundle_sha256,
            'latest_original_ec303_ack_replayed': True}


def verify_history(*, chain_file: str, external: dict,
                   ledger_files: list[str],
                   certificate_files: list[str]) -> dict:
    doc, histories = _read_active_chain(
        chain_file=chain_file, external=external, ledger_files=ledger_files,
        certificate_files=certificate_files)
    return {'status': 'all_epochs_signed_histories_and_original_cutovers_verified',
            'registry_id': doc['registry_id'],
            'chain_raw_sha256': external['chain_raw_sha256'],
            'epoch_count': len(histories),
            'active_ledger_sequence': doc['epochs'][-1]['ledger_sequence'],
            'total_signed_ack_records': sum(map(len, histories)),
            'old_zip_ack_payloads_replayed': False,
            'latest_original_ec303_ack_replayed': False,
            'external_latest_cas_worm_proven': False,
            'exit_code': 0}


def verify_latest(*, chain_file: str, external: dict,
                  ledger_files: list[str], certificate_files: list[str],
                  bundle_file: str, expected_bundle_sha256: str, pins: dict,
                  acknowledgement_file: str,
                  expected_acknowledgement_sha256: str,
                  sender_id: str, receiver_id: str, receiver_public_hex: str,
                  challenge_sha256: str) -> dict:
    doc, histories = _read_active_chain(
        chain_file=chain_file, external=external, ledger_files=ledger_files,
        certificate_files=certificate_files)
    active = doc['epochs'][-1]
    need(active['ledger_sequence'] > 0, 'ACTIVE_EPOCH_EMPTY_NEEDS_FIRST_ACK')
    proof = _verify_latest_ack(
        doc=doc, ledger_file=ledger_files[-1],
        bundle_file=bundle_file, expected_bundle_sha256=expected_bundle_sha256,
        pins=pins, acknowledgement_file=acknowledgement_file,
        expected_acknowledgement_sha256=expected_acknowledgement_sha256,
        sender_id=sender_id, receiver_id=receiver_id,
        receiver_public_hex=receiver_public_hex, challenge_sha256=challenge_sha256)
    need(proof['exit_code'] == 0, 'ACTIVE_ORIGINAL_LATEST_ACK_NOT_VERIFIED')
    return {'status': 'all_registrar_epochs_governance_and_latest_original_ack_reverified',
            'registry_id': doc['registry_id'],
            'chain_raw_sha256': external['chain_raw_sha256'],
            'initial_registrar_public_hex': doc['initial_registrar_public_hex'],
            'governor_public_hex': doc['governor_public_hex'],
            'epoch_count': len(histories),
            'active_registrar_public_hex': active['registrar_public_hex'],
            'active_ledger_raw_sha256': active['ledger_raw_sha256'],
            'active_ledger_sequence': active['ledger_sequence'],
            'total_signed_ack_records': sum(map(len, histories)),
            'acknowledgement_sha256': expected_acknowledgement_sha256,
            'bundle_sha256': expected_bundle_sha256,
            'report_sha256': proof['report_sha256'],
            'old_zip_ack_payloads_replayed': False,
            'latest_original_ec303_ack_replayed': True,
            'external_latest_cas_worm_proven': False,
            'exit_code': 0}

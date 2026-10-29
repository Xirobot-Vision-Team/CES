#!/usr/bin/env python3
"""EC324 offline dual-channel original-fork-capsule receiving ceremony.

Two separately transported, independently whole-SHA-pinned canonical pin
statements must agree on every pre-existing original trust anchor and the
explicit prior local receipt SHA. Only after a genuine EC323->EC294 full
signature replay may the receiver create a new, immutable local snapshot.
A receiving snapshot is NOT signed, external WORM, global CAS, global latest,
physical device independence, authorized human identity, or a fork winner.
"""
from __future__ import annotations

import hmac
import os
import re
from typing import Any

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec302_portable_bundle import bundle
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec322_receiver_fork_ack import ack
from ec323_composite_fork_capsule import capsule

CHANNEL_SCHEMA = 'ces.ec324.two_channel_offline_original_fork_pin_statement.v1'
REGISTRY_SCHEMA = 'ces.ec324.local_immutable_dual_channel_fork_receipt_snapshots.v1'
RESULT_SCHEMA = 'ces.ec324.local_dual_channel_fork_receipt_result.v1'
DENIAL_SCHEMA = 'ces.ec324.local_dual_channel_fork_receipt_denial.v1'
ZERO = '0' * 64
MAX_CHANNEL = 16_000
MAX_SNAPSHOT = 80_000
MAX_RECORDS = 16
ID = re.compile(r'[a-z][a-z0-9_-]{1,31}\Z')
ROLES = ('origin', 'recipient')
CHANNEL_FIELDS = frozenset({
    'schema', 'channel_role', 'operator_id', 'handoff_id', 'registry_id',
    'expected_sequence', 'expected_prior_registry_raw_sha256',
    'capsule_original_raw_sha256', 'case_original_raw_sha256',
    'seventh_ack_original_raw_sha256', 'historical_external_pins',
    'seventh_receiver_external_trust',
    'physical_channel_independence_or_organization_authority_proven',
})
SNAPSHOT_FIELDS = frozenset({'schema', 'registry_id', 'records'})
RECORD_FIELDS = frozenset({
    'sequence', 'handoff_id', 'previous_snapshot_raw_sha256',
    'origin_channel_original_raw_sha256',
    'recipient_channel_original_raw_sha256',
    'origin_operator_id', 'recipient_operator_id',
    'capsule_original_raw_sha256', 'case_original_raw_sha256',
    'seventh_ack_original_raw_sha256', 'common_pins_canonical_sha256',
    'signed_registrar_fork_sequence',
    'external_cas_latest_worm_organizational_authority_or_winner_proven',
})
COMMON_FIELDS = frozenset(CHANNEL_FIELDS - {
    'schema', 'channel_role', 'operator_id',
    'physical_channel_independence_or_organization_authority_proven',
})


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC324_' + code, status)


def _id(v: Any) -> bool:
    return type(v) is str and ID.fullmatch(v) is not None


def _sha(v: Any, allow_zero: bool = False) -> bool:
    return (type(v) is str and re.fullmatch(r'[0-9a-f]{64}', v) is not None
            and (allow_zero or v != ZERO))


def _raw(doc: dict) -> bytes:
    return reg.raw_doc(doc)


def _hash(doc: dict) -> str:
    return case.sha(_raw(doc))


def _paths(*paths: str) -> None:
    need(all(type(p) is str and case.original._valid_path(p) for p in paths)
         and len(set(paths)) == len(paths),
         'ALL_INPUT_OUTPUT_PATHS_NORMALIZED_ABSOLUTE_AND_DISTINCT_REQUIRED',
         'invalid_input')


def _load(path: str, expected_sha: str, limit: int, label: str) -> tuple[dict, bytes]:
    need(_sha(expected_sha), label + '_EXTERNAL_WHOLE_SHA_REQUIRED', 'invalid_input')
    data = reg._private_read(path, limit, label)
    need(hmac.compare_digest(case.sha(data), expected_sha),
         label + '_NOT_EQUAL_INDEPENDENT_RAW_SHA')
    doc = io.parse(data, limit)
    need(hmac.compare_digest(data, _raw(doc)),
         label + '_NONCANONICAL_OR_NOT_LF_JSON', 'invalid_input')
    return doc, data


def _write_exclusive(out: str, raw: bytes) -> None:
    """No overwrites; a failed write never leaves a partially accepted head."""
    target = bundle._private_parent(out)
    need(not os.path.lexists(target), 'OUTPUT_ALREADY_EXISTS', 'invalid_input')
    fd = -1
    created = False
    finished = False
    try:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        created = True
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(target.parent, os.O_RDONLY |
                               getattr(os, 'O_DIRECTORY', 0) |
                               getattr(os, 'O_NOFOLLOW', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        finished = True
    except FileExistsError as exc:
        raise anchor.AnchorError('EC324_OUTPUT_ALREADY_EXISTS', 'invalid_input') from exc
    except OSError as exc:
        raise anchor.AnchorError('EC324_EXCLUSIVE_PRIVATE_WRITE_UNAVAILABLE',
                                 'unavailable') from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if created and not finished:
            try:
                os.unlink(target)
            except OSError:
                pass


def _channel(*, channel_role: str, operator_id: str,
             handoff_id: str, registry_id: str, expected_sequence: int,
             expected_prior_registry_raw_sha256: str,
             expected_capsule_sha256: str,
             expected_bundle_sha256: str, expected_ack_sha256: str,
             ack_id: str, seventh_receiver_id: str,
             seventh_receiver_public_hex: str,
             seventh_receiver_challenge_sha256: str,
             external_pins: dict) -> dict:
    need(channel_role in ROLES and all(_id(v) for v in
         (operator_id, handoff_id, registry_id)),
         'EXACT_ROLE_AND_OPERATOR_HANDOFF_REGISTRY_IDS_REQUIRED', 'invalid_input')
    need(type(expected_sequence) is int and 1 <= expected_sequence <= MAX_RECORDS,
         'SEQUENCE_OUTSIDE_BOUNDED_RANGE', 'invalid_input')
    need(_sha(expected_prior_registry_raw_sha256, allow_zero=True) and
         ((expected_sequence == 1) ==
          (expected_prior_registry_raw_sha256 == ZERO)),
         'GENESIS_ZERO_OR_NONZERO_PRIOR_SHA_CONTINUITY_REQUIRED', 'invalid_input')
    need(all(_sha(s) for s in (expected_capsule_sha256,
                               expected_bundle_sha256, expected_ack_sha256)) and
         len({expected_capsule_sha256, expected_bundle_sha256,
              expected_ack_sha256}) == 3,
         'THREE_DIFFERENT_WHOLE_ORIGINAL_SHAS_REQUIRED', 'invalid_input')
    receiver, pins = capsule._trust(ack_id=ack_id,
        seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256,
        external_pins=external_pins)
    return {
        'schema': CHANNEL_SCHEMA,
        'channel_role': channel_role,
        'operator_id': operator_id,
        'handoff_id': handoff_id,
        'registry_id': registry_id,
        'expected_sequence': expected_sequence,
        'expected_prior_registry_raw_sha256': expected_prior_registry_raw_sha256,
        'capsule_original_raw_sha256': expected_capsule_sha256,
        'case_original_raw_sha256': expected_bundle_sha256,
        'seventh_ack_original_raw_sha256': expected_ack_sha256,
        'historical_external_pins': pins,
        'seventh_receiver_external_trust': receiver,
        'physical_channel_independence_or_organization_authority_proven': False,
    }


def prepare_channel(*, out: str, channel_role: str, operator_id: str,
                    handoff_id: str, registry_id: str, expected_sequence: int,
                    expected_prior_registry_raw_sha256: str,
                    expected_capsule_sha256: str,
                    expected_bundle_sha256: str, expected_ack_sha256: str,
                    ack_id: str, seventh_receiver_id: str,
                    seventh_receiver_public_hex: str,
                    seventh_receiver_challenge_sha256: str,
                    **external_pins: str) -> dict:
    """Generate only an UNSIGNED pin statement on one operator's own device.

    The resulting whole raw SHA must be fixed via an independently trustworthy
    channel; running this command twice on one machine proves no independence.
    """
    _paths(out)
    doc = _channel(channel_role=channel_role, operator_id=operator_id,
        handoff_id=handoff_id, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_raw_sha256=expected_prior_registry_raw_sha256,
        expected_capsule_sha256=expected_capsule_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_ack_sha256=expected_ack_sha256,
        ack_id=ack_id, seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256,
        external_pins=external_pins)
    raw = _raw(doc)
    need(len(raw) <= MAX_CHANNEL, 'CHANNEL_RAW_BYTE_LIMIT', 'invalid_input')
    _write_exclusive(out, raw)
    return {
        'status': 'unsigned_channel_pin_document_prepared_only',
        'exit_code': 0, 'channel_role': channel_role,
        'operator_id': operator_id, 'handoff_id': handoff_id,
        'registry_id': registry_id, 'expected_sequence': expected_sequence,
        'channel_original_raw_sha256': case.sha(raw),
        'original_signature_or_external_channel_authentication_proven': False,
        'real_independent_channel_or_custody_established': False,
        'business_writes_performed': False,
    }


def _parse_channel(doc: Any, role: str) -> dict:
    anchor.exact(doc, CHANNEL_FIELDS, 'EC324_CHANNEL_EXACT_FIELDS')
    need(doc['schema'] == CHANNEL_SCHEMA and doc['channel_role'] == role and
         doc['physical_channel_independence_or_organization_authority_proven'] is False,
         'CHANNEL_ROLE_SCHEMA_OR_UNSUPPORTED_AUTHORITY_CLAIM', 'invalid_input')
    # Reconstruct all known fields through prior EC321/322 trust validators;
    # a valid SHA by itself cannot make an arbitrary claim well typed.
    pins = doc['historical_external_pins']
    anchor.exact(pins, case.PIN_FIELDS, 'EC324_TWELVE_OLD_PIN_FIELDS')
    receiver = doc['seventh_receiver_external_trust']
    anchor.exact(receiver, ack.RECEIVER_FIELDS, 'EC324_SEVENTH_TRUST_FIELDS')
    expected = _channel(channel_role=role, operator_id=doc['operator_id'],
        handoff_id=doc['handoff_id'], registry_id=doc['registry_id'],
        expected_sequence=doc['expected_sequence'],
        expected_prior_registry_raw_sha256=doc['expected_prior_registry_raw_sha256'],
        expected_capsule_sha256=doc['capsule_original_raw_sha256'],
        expected_bundle_sha256=doc['case_original_raw_sha256'],
        expected_ack_sha256=doc['seventh_ack_original_raw_sha256'],
        external_pins=pins, **receiver)
    need(doc == expected, 'CHANNEL_RECONSTRUCTION_MISMATCH', 'invalid_input')
    return doc


def _load_pair(*, origin_file: str, expected_origin_sha256: str,
               recipient_file: str, expected_recipient_sha256: str,
               registry_id: str, expected_sequence: int,
               expected_prior_registry_sha256: str) -> tuple[dict, dict, str]:
    need(_sha(expected_origin_sha256) and _sha(expected_recipient_sha256) and
         expected_origin_sha256 != expected_recipient_sha256,
         'TWO_DIFFERENT_EXTERNAL_CHANNEL_RAW_SHA_PINS_REQUIRED',
         'invalid_input')
    left, _ = _load(origin_file, expected_origin_sha256,
                    MAX_CHANNEL, 'ORIGIN_CHANNEL')
    right, _ = _load(recipient_file, expected_recipient_sha256,
                     MAX_CHANNEL, 'RECIPIENT_CHANNEL')
    _parse_channel(left, 'origin')
    _parse_channel(right, 'recipient')
    need(left['operator_id'] != right['operator_id'],
         'TWO_DIFFERENT_OPERATOR_IDENTITIES_REQUIRED', 'invalid_input')
    need(all(left[k] == right[k] for k in COMMON_FIELDS),
         'CHANNELS_DISAGREE_ON_ANY_HISTORICAL_PIN_OR_HANDOFF_HEAD',
         'permission_denied')
    need(left['registry_id'] == registry_id and
         left['expected_sequence'] == expected_sequence and
         left['expected_prior_registry_raw_sha256'] ==
            expected_prior_registry_sha256,
         'CHANNELS_NOT_BOUND_TO_INDEPENDENT_EXPECTED_REGISTRY_HEAD',
         'permission_denied')
    common = {k: left[k] for k in COMMON_FIELDS}
    return left, right, _hash(common)


def _empty(registry_id: str) -> dict:
    return {'schema': REGISTRY_SCHEMA, 'registry_id': registry_id,
            'records': []}


def _verify_snapshot(doc: Any, registry_id: str,
                     sequence: int | None = None) -> dict:
    anchor.exact(doc, SNAPSHOT_FIELDS, 'EC324_SNAPSHOT_EXACT_FIELDS')
    need(doc['schema'] == REGISTRY_SCHEMA and _id(doc['registry_id']) and
         doc['registry_id'] == registry_id and
         type(doc['records']) is list and
         1 <= len(doc['records']) <= MAX_RECORDS,
         'SNAPSHOT_SCHEMA_REGISTRY_OR_BOUNDED_LENGTH', 'invalid_input')
    if sequence is not None:
        need(type(sequence) is int and len(doc['records']) == sequence,
             'SNAPSHOT_NOT_THE_EXPECTED_SEQUENCE_HEAD', 'permission_denied')
    seen_handoff, seen_capsule, seen_docs = set(), set(), set()
    for i, row in enumerate(doc['records'], 1):
        anchor.exact(row, RECORD_FIELDS, 'EC324_RECORD_EXACT_FIELDS')
        previous_sha = ZERO if i == 1 else _hash({
            **_empty(registry_id), 'records': doc['records'][:i-1]})
        need(type(row['sequence']) is int and row['sequence'] == i and
             _id(row['handoff_id']) and
             _id(row['origin_operator_id']) and
             _id(row['recipient_operator_id']) and
             row['origin_operator_id'] != row['recipient_operator_id'] and
             row['previous_snapshot_raw_sha256'] == previous_sha and
             all(_sha(row[key]) for key in (
                 'origin_channel_original_raw_sha256',
                 'recipient_channel_original_raw_sha256',
                 'capsule_original_raw_sha256', 'case_original_raw_sha256',
                 'seventh_ack_original_raw_sha256',
                 'common_pins_canonical_sha256')) and
             len({row['origin_channel_original_raw_sha256'],
                  row['recipient_channel_original_raw_sha256']}) == 2 and
             len({row['capsule_original_raw_sha256'],
                  row['case_original_raw_sha256'],
                  row['seventh_ack_original_raw_sha256']}) == 3 and
             type(row['signed_registrar_fork_sequence']) is int and
             1 <= row['signed_registrar_fork_sequence'] <= 4 and
             row['external_cas_latest_worm_organizational_authority_or_winner_proven']
                is False,
             'RECORD_SHAPE_LINKAGE_AND_NO_FALSE_AUTHORITY', 'invalid_input')
        need(row['handoff_id'] not in seen_handoff and
             row['capsule_original_raw_sha256'] not in seen_capsule and
             row['origin_channel_original_raw_sha256'] not in seen_docs and
             row['recipient_channel_original_raw_sha256'] not in seen_docs,
             'REPLAYED_HANDOFF_CAPSULE_OR_CHANNEL_DOCUMENT_IN_LOCAL_LINEAGE',
             'permission_denied')
        seen_handoff.add(row['handoff_id'])
        seen_capsule.add(row['capsule_original_raw_sha256'])
        seen_docs.update((row['origin_channel_original_raw_sha256'],
                          row['recipient_channel_original_raw_sha256']))
    return doc


def _load_snapshot(file: str, expected_sha: str, registry_id: str,
                   sequence: int | None = None) -> dict:
    doc, _ = _load(file, expected_sha, MAX_SNAPSHOT, 'LOCAL_RECEIPT_SNAPSHOT')
    return _verify_snapshot(doc, registry_id, sequence)


def _event(origin: dict, recipient: dict, origin_sha: str,
           recipient_sha: str, common_sha: str, observed: dict) -> dict:
    return {
        'sequence': origin['expected_sequence'],
        'handoff_id': origin['handoff_id'],
        'previous_snapshot_raw_sha256': origin['expected_prior_registry_raw_sha256'],
        'origin_channel_original_raw_sha256': origin_sha,
        'recipient_channel_original_raw_sha256': recipient_sha,
        'origin_operator_id': origin['operator_id'],
        'recipient_operator_id': recipient['operator_id'],
        'capsule_original_raw_sha256': origin['capsule_original_raw_sha256'],
        'case_original_raw_sha256': origin['case_original_raw_sha256'],
        'seventh_ack_original_raw_sha256': origin['seventh_ack_original_raw_sha256'],
        'common_pins_canonical_sha256': common_sha,
        'signed_registrar_fork_sequence': observed['fork_sequence'],
        'external_cas_latest_worm_organizational_authority_or_winner_proven': False,
    }


def _replay(capsule_file: str, doc: dict) -> dict:
    result = capsule.verify(
        capsule_file=capsule_file,
        expected_capsule_sha256=doc['capsule_original_raw_sha256'],
        expected_bundle_sha256=doc['case_original_raw_sha256'],
        expected_ack_sha256=doc['seventh_ack_original_raw_sha256'],
        **doc['historical_external_pins'],
        **doc['seventh_receiver_external_trust'])
    need(result.get('exit_code') == 2 and
         result.get('status') ==
           'independent_portable_original_case_seventh_ack_and_all_histories_reverified' and
         result.get('capsule_original_raw_sha256') == doc['capsule_original_raw_sha256'] and
         result.get('case_bundle_original_raw_sha256') == doc['case_original_raw_sha256'] and
         result.get('signed_receiver_ack_original_raw_sha256') ==
           doc['seventh_ack_original_raw_sha256'] and
         result.get('seventh_ed25519_and_entire_original_signed_history_reverified') is True and
         result.get('both_original_member_raw_sha256_preserved') is True and
         result.get('portable_capsule_itself_is_a_new_signature') is False and
         result.get('external_latest_winner_cas_or_organizational_authority_proven') is False and
         result.get('business_or_external_store_writes_performed') is False and
         type(result.get('fork_sequence')) is int and
         1 <= result['fork_sequence'] <= 4,
         'PREVIOUS_SIGNED_HISTORY_MUST_REPLAY_NOT_CACHED_UNSIGNED_RESULT')
    return result


def _check_again(*, capsule_file: str, origin_file: str,
                 expected_origin_sha256: str, recipient_file: str,
                 expected_recipient_sha256: str, prior_registry_file: str | None,
                 expected_prior_registry_sha256: str, origin: dict) -> None:
    # Close the common time-of-check/time-of-use window after expensive old
    # signature replay: no changed originals/anchors are admitted at commit.
    capsule._file(capsule_file, capsule.MAX_ARCHIVE,
                  origin['capsule_original_raw_sha256'],
                  'EC324_RECHECKED_ORIGINAL_CAPSULE')
    _load(origin_file, expected_origin_sha256, MAX_CHANNEL,
          'RECHECKED_ORIGIN_CHANNEL')
    _load(recipient_file, expected_recipient_sha256, MAX_CHANNEL,
          'RECHECKED_RECIPIENT_CHANNEL')
    if prior_registry_file is not None:
        _load(prior_registry_file, expected_prior_registry_sha256,
              MAX_SNAPSHOT, 'RECHECKED_PRIOR_SNAPSHOT')


def _result(*, command: str, origin: dict, recipient: dict,
            origin_sha: str, recipient_sha: str, head_sha: str,
            observed: dict) -> dict:
    return {
        'status': ('local_offline_dual_channel_fork_receipt_recorded_no_external_cas'
                   if command == 'receive' else
                   'independent_dual_channel_local_fork_receipt_and_all_signed_history_reverified'),
        'exit_code': 2,
        'registry_id': origin['registry_id'],
        'handoff_id': origin['handoff_id'],
        'sequence': origin['expected_sequence'],
        'previous_snapshot_raw_sha256': origin['expected_prior_registry_raw_sha256'],
        'registry_snapshot_original_raw_sha256': head_sha,
        'origin_channel_original_raw_sha256': origin_sha,
        'recipient_channel_original_raw_sha256': recipient_sha,
        'capsule_original_raw_sha256': origin['capsule_original_raw_sha256'],
        'case_original_raw_sha256': origin['case_original_raw_sha256'],
        'seventh_ack_original_raw_sha256': origin['seventh_ack_original_raw_sha256'],
        'origin_operator_id': origin['operator_id'],
        'recipient_operator_id': recipient['operator_id'],
        'signed_registrar_fork_sequence': observed['fork_sequence'],
        'both_external_raw_sha_pinned_channel_documents_agree': True,
        'seventh_signature_and_complete_original_case_history_reverified': True,
        'local_snapshot_append_only_and_prefix_sha_linked': True,
        'physical_independence_organizational_authority_external_worm_cas_latest_or_winner_proven': False,
        'registry_snapshot_is_an_external_cryptographic_signature': False,
        'business_or_external_cas_writes_performed': False,
    }


def receive(*, out: str, capsule_file: str,
            origin_file: str, expected_origin_sha256: str,
            recipient_file: str, expected_recipient_sha256: str,
            registry_id: str, expected_sequence: int,
            expected_prior_registry_sha256: str,
            prior_registry_file: str | None = None) -> dict:
    """Commit a *new* local bounded snapshot after all historical proof checks.

    Because independent atomic CAS/latest is unavailable, simultaneous writers
    can create sibling receipts from the same predecessor. A trusted external
    witness must resolve that, not this append-only local snapshot format.
    """
    locations = [out, capsule_file, origin_file, recipient_file]
    if prior_registry_file is not None:
        locations.append(prior_registry_file)
    _paths(*locations)
    bundle._private_parent(out)
    need(not os.path.lexists(out), 'OUTPUT_ALREADY_EXISTS', 'invalid_input')
    origin, recipient, common_sha = _load_pair(
        origin_file=origin_file, expected_origin_sha256=expected_origin_sha256,
        recipient_file=recipient_file,
        expected_recipient_sha256=expected_recipient_sha256,
        registry_id=registry_id, expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    if expected_sequence == 1:
        need(prior_registry_file is None and expected_prior_registry_sha256 == ZERO,
             'GENESIS_MUST_HAVE_NO_PREVIOUS_FILE_AND_ZERO_SHA', 'invalid_input')
        current = _empty(registry_id)
    else:
        need(prior_registry_file is not None and
             _sha(expected_prior_registry_sha256),
             'APPEND_REQUIRES_PRIOR_ORIGINAL_FILE_AND_EXTERNAL_SHA',
             'invalid_input')
        current = _load_snapshot(prior_registry_file,
                                  expected_prior_registry_sha256,
                                  registry_id, expected_sequence - 1)
    # A last-record duplicate is rejected before expensive signature replay.
    need(all(row['handoff_id'] != origin['handoff_id'] and
             row['capsule_original_raw_sha256'] != origin['capsule_original_raw_sha256']
             for row in current['records']),
         'DUPLICATE_HANDOFF_OR_ORIGINAL_CAPSULE_IN_RECEIPT_LINEAGE')
    observed = _replay(capsule_file, origin)
    row = _event(origin, recipient, expected_origin_sha256,
                 expected_recipient_sha256, common_sha, observed)
    next_snapshot = {**_empty(registry_id),
                     'records': current['records'] + [row]}
    _verify_snapshot(next_snapshot, registry_id, expected_sequence)
    raw = _raw(next_snapshot)
    need(0 < len(raw) <= MAX_SNAPSHOT,
         'BOUNDED_LOCAL_RECEIPT_SNAPSHOT_SIZE_REQUIRED', 'invalid_input')
    _check_again(capsule_file=capsule_file,
        origin_file=origin_file, expected_origin_sha256=expected_origin_sha256,
        recipient_file=recipient_file,
        expected_recipient_sha256=expected_recipient_sha256,
        prior_registry_file=prior_registry_file,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        origin=origin)
    _write_exclusive(out, raw)
    return _result(command='receive', origin=origin, recipient=recipient,
                   origin_sha=expected_origin_sha256,
                   recipient_sha=expected_recipient_sha256,
                   head_sha=case.sha(raw), observed=observed)


def verify(*, registry_file: str, expected_registry_sha256: str,
           capsule_file: str, origin_file: str,
           expected_origin_sha256: str, recipient_file: str,
           expected_recipient_sha256: str, registry_id: str,
           expected_sequence: int, expected_prior_registry_sha256: str) -> dict:
    """Independently SHA pin this local head, compare both operator statements,
    and replay the current capsule's real Ed25519 originals again (exit 2).
    Earlier rows' snapshots are structurally hash-linked, not re-cryptoverified
    here unless separately supplied to individual verify calls.
    """
    _paths(registry_file, capsule_file, origin_file, recipient_file)
    origin, recipient, common_sha = _load_pair(
        origin_file=origin_file, expected_origin_sha256=expected_origin_sha256,
        recipient_file=recipient_file,
        expected_recipient_sha256=expected_recipient_sha256,
        registry_id=registry_id, expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256)
    current = _load_snapshot(registry_file, expected_registry_sha256,
                              registry_id, expected_sequence)
    last = current['records'][-1]
    expected_fields = _event(origin, recipient, expected_origin_sha256,
        expected_recipient_sha256, common_sha,
        {'fork_sequence': last['signed_registrar_fork_sequence']})
    need(last == expected_fields,
         'LATEST_RECORD_NOT_BOUND_EXACTLY_TO_BOTH_EXTERNAL_CHANNELS',
         'permission_denied')
    observed = _replay(capsule_file, origin)
    need(observed['fork_sequence'] == last['signed_registrar_fork_sequence'],
         'LATEST_RECORD_NOT_EQUAL_ACTUAL_GENUINE_SIGNED_FORK',
         'permission_denied')
    # Read originals once more after all deep historical replay; if another
    # process replaces any source, never accept the stale verification result.
    _check_again(capsule_file=capsule_file,
        origin_file=origin_file, expected_origin_sha256=expected_origin_sha256,
        recipient_file=recipient_file,
        expected_recipient_sha256=expected_recipient_sha256,
        prior_registry_file=registry_file,
        expected_prior_registry_sha256=expected_registry_sha256,
        origin=origin)
    return _result(command='verify', origin=origin, recipient=recipient,
                   origin_sha=expected_origin_sha256,
                   recipient_sha=expected_recipient_sha256,
                   head_sha=expected_registry_sha256, observed=observed)

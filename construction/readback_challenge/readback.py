#!/usr/bin/env python3
"""EC347: genuinely re-read receiver bytes only on explicit signed re-measurement.

This protocol makes temporal and signer claims auditable, but never equates a
self-reported clock / host label / Ed25519 signature with an independently
controlled machine, durable medium, trusted UTC or physical custody.

All inherited EC345/EC346 originals MUST be individually whole-SHA-pinned.
The separate read-only audit never follows a signed path to byte-copy content
unless an auditor explicitly presents that pair for *this* invocation.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from independent_custody import ceremony
from offline_authority import authority as old
from issuer_root_rotation import rotation
from hold_receipts import timeline as prior
from disclosure_custody import custody as previous

CHALLENGE_SCHEMA = 'ces.ec347.ed25519_independent_copy_readback_challenge.v1'
CHALLENGE_CLAIM = 'ces.ec347.independent_copy_readback_challenge_claim.v1'
RESPONSE_SCHEMA = 'ces.ec347.ed25519_receiver_remeasure_reply.v1'
RESPONSE_CLAIM = 'ces.ec347.receiver_remeasure_reply_claim.v1'
RESULT_SCHEMA = 'ces.ec347.bounded_challenged_copy_readback_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec347.bounded_challenged_copy_readback_audit_denial.v1'
D_CHALLENGE = b'CES/EC347/IndependentReReadChallenge/v1\0'
D_RESPONSE = b'CES/EC347/ReceiverReReadResponse/v1\0'
MEASURED = 'measured_readback'
UNAVAILABLE = 'unavailable_claim'
MAX_ROUNDS = 3
MAX_RESPONSES = MAX_ROUNDS * prior.MAX_RECEIVERS
PARENT_KEYS = previous.BASELINE_KEYS | {
    'item_id', 'custody_evaluation_utc', 'observation_files', 'observation_shas'
}
C_FIELDS = frozenset({
    'schema', 'case_id', 'target_item_id', 'target_slot_id',
    'ec346_audit_inputs_canonical_sha256',
    'ec346_observation_original_raw_sha256s',
    'source_snapshot_original_raw_sha256', 'source_ack_set_original_raw_sha256',
    'challenge_signer_id', 'challenge_signer_public_hex',
    'challenge_signer_organization_id', 'audience_receiver_ids',
    'receiver_latest_signed_observations', 'round_number',
    'previous_challenge_file', 'previous_challenge_original_raw_sha256',
    'challenge_nonce_sha256', 'issued_utc', 'scope', 'no_remote_authority',
})
R_FIELDS = frozenset({
    'schema', 'case_id', 'target_item_id', 'target_slot_id',
    'ec346_audit_inputs_canonical_sha256',
    'challenge_file', 'challenge_original_raw_sha256',
    'challenge_nonce_sha256', 'round_number',
    'receiver_id', 'receiver_public_hex', 'receiver_organization_id',
    'copy_id', 'claimed_storage_id',
    'ec346_latest_signed_event_original_raw_sha256',
    'copy_snapshot_file', 'copy_ack_set_file',
    'response_kind', 'copy_snapshot_original_raw_sha256',
    'copy_snapshot_byte_length', 'copy_ack_set_original_raw_sha256',
    'copy_ack_set_byte_length', 'matches_ec346_signed_bytes',
    'matches_ec345_verified_source', 'bytes_reopened_after_challenge',
    'response_nonce_sha256', 'reported_utc', 'scope', 'no_remote_authority',
})
NEGATIVES = (
    'signed_challenge_proves_external_institutional_or_site_identity',
    'separate_ed25519_keys_prove_different_physical_machines',
    'claimed_storage_label_proves_independent_hardware_or_geography',
    'self_reported_challenge_and_response_utc_are_trusted_time',
    'unchanged_repeated_reads_prove_future_physical_durability',
    'unavailable_claim_or_unanswered_challenge_proves_global_loss',
    'readback_claim_executes_remote_cas_worm_provider_actions',
    'signed_transcript_proves_hidden_forks_global_latest_or_winner',
    'fully_unmocked_ec317_ec318_or_final_acceptance_proven',
)
KINDS = (MEASURED, UNAVAILABLE)
OUTCOMES = (
    'signed_readback_matches_prior_and_verified_source',
    'signed_readback_changed_from_ec346_observation',
    'signed_readback_differs_from_verified_source',
    'signed_unavailable_claim_without_byte_read',
    'challenged_receiver_did_not_reply',
    'later_explicitly_presented_bytes_changed_after_signed_readback',
)
STATUS_ORDER = (
    'explicitly_presented_bytes_changed_after_response_unresolved',
    'challenged_remeasurement_changed_from_ec346_unresolved',
    'challenged_remeasurement_differs_from_source_unresolved',
    'signed_unavailable_claim_unresolved',
    'challenged_receiver_unanswered_unresolved',
    'local_challenged_remeasurements_match_unresolved',
)


def need(ok: Any, name: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC347_' + name, status)


def _candidate(command: str, sha: str) -> dict:
    return {'schema': RESULT_SCHEMA, 'command': command,
            'status': 'private_signed_candidate_requires_independent_whole_sha_pin',
            'exit_code': 2, 'candidate_original_raw_sha256': sha,
            'offline_unresolved_exit_code': 2,
            **{k: False for k in NEGATIVES}}


def _parent(source: dict):
    """Full EC346 -> EC345 -> EC337 real history, without reading copy paths."""
    need(set(source) == PARENT_KEYS, 'EXACT_PINNED_EC346_PARENT_ARGUMENTS_REQUIRED')
    need(type(source['observation_files']) is list and
         type(source['observation_shas']) is list and
         len(source['observation_files']) == len(source['observation_shas']),
         'PARENT_OBSERVATION_PATHS_AND_HASHES_REQUIRED')
    full = previous.audit_copies(**source,
        presented_receiver_ids=[], presented_snapshot_files=[], presented_ack_set_files=[])
    need(full['exit_code'] == 2 and
         full['verified_disclosed_source_replayed_ec345_through_ec337'] is True,
         'EC346_REAL_RECEIVER_SIGNED_HISTORY_MUST_REPLAY', 'permission_denied')
    baseline = {k: source[k] for k in previous.BASELINE_KEYS}
    roster, item, _, _, pins = previous._basis(source['item_id'], baseline)
    rows = {}
    for path, sha in zip(source['observation_files'], source['observation_shas'], strict=True):
        claim, _ = previous._load_event(path, sha, r=roster, item=item,
                                         baseline=baseline, pins=pins)
        rows[claim['receiver_id']] = (path, sha, claim)
    need(set(rows) == {r['receiver_id'] for r in full['receiver_copies']},
         'REPLAYED_RECEIVER_SET_MUST_AGREE')
    # A change to any pinned original cannot be hidden after the replay.
    prior.late(pins)
    return roster, item, pins, rows


def _history_row(sha: str, claim: dict) -> dict:
    return {
        'receiver_id': claim['receiver_id'],
        'organization_id': claim['receiver_organization_id'],
        'claimed_storage_id': claim['claimed_storage_id'],
        'copy_id': claim['copy_id'],
        'ec346_latest_event_original_raw_sha256': sha,
        'ec346_latest_event_kind': claim['event_kind'],
        'copy_snapshot_original_raw_sha256': claim['copy_snapshot_original_raw_sha256'],
        'copy_snapshot_byte_length': claim['copy_snapshot_byte_length'],
        'copy_ack_set_original_raw_sha256': claim['copy_ack_set_original_raw_sha256'],
        'copy_ack_set_byte_length': claim['copy_ack_set_byte_length'],
    }


def _context(source: dict, roster: dict, item: dict, rows: dict) -> dict:
    order = [a['signer_id'] for a in roster['receivers']]
    return {'case_id': roster['case_id'], 'target_item_id': item['item_id'],
            'target_slot_id': item['slot_id'],
            'ec346_audit_inputs_canonical_sha256': case.sha(reg.canonical(source)),
            'ec346_observation_original_raw_sha256s': source['observation_shas'],
            'source_snapshot_original_raw_sha256': item['expected_snapshot_sha256'],
            'source_ack_set_original_raw_sha256': item['expected_ack_set_sha256'],
            'challenge_signer_id': roster['change_proposer']['signer_id'],
            'challenge_signer_public_hex': roster['change_proposer']['public_hex'],
            'challenge_signer_organization_id': roster['change_proposer']['organization_id'],
            'receiver_latest_signed_observations': [
                _history_row(rows[rid][1], rows[rid][2]) for rid in order if rid in rows],
            }


def _parent_nonces(source: dict, rows: dict) -> set[str]:
    baseline = {k: source[k] for k in previous.BASELINE_KEYS}
    result = previous._ec345_nonces(baseline)
    for path, sha in zip(source['observation_files'], source['observation_shas'], strict=True):
        doc = prior.read(path, sha, 'EC347_INHERITED_OBSERVATION_NONCE')
        result.add(doc['claim']['event_nonce_sha256'])
    return result


def _challenge_claim(source: dict, roster: dict, item: dict, rows: dict,
        *, audience_receiver_ids: list[str], round_number: int,
        previous_challenge_file: str | None, previous_challenge_sha: str | None,
        challenge_nonce_sha256: str, issued_utc: str) -> dict:
    return {'schema': CHALLENGE_CLAIM,
            **_context(source, roster, item, rows),
            'audience_receiver_ids': audience_receiver_ids,
            'round_number': round_number,
            'previous_challenge_file': previous_challenge_file,
            'previous_challenge_original_raw_sha256': previous_challenge_sha,
            'challenge_nonce_sha256': challenge_nonce_sha256,
            'issued_utc': issued_utc,
            'scope': 'request_new_local_byte_reopening_without_remote_rights',
            'no_remote_authority': True}


def _load_challenge(path: str, sha: str, *, source: dict, roster: dict,
                    item: dict, rows: dict, pins: dict, depth: int = 1):
    need(depth <= MAX_ROUNDS, 'SIGNED_CHALLENGE_HISTORY_TOO_DEEP')
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'EC347_SIGNED_INDEPENDENT_CHALLENGE')
    c = doc.get('claim') if type(doc) is dict else None
    need(type(c) is dict and set(c) == C_FIELDS and
         c.get('schema') == CHALLENGE_CLAIM and
         all(c.get(k) == v for k, v in _context(source, roster, item, rows).items()),
         'CHALLENGE_MUST_BIND_REPLAYED_EC346_HISTORY')
    canonical = [a['signer_id'] for a in roster['receivers'] if a['signer_id'] in rows]
    audience = c.get('audience_receiver_ids')
    need(type(audience) is list and 2 <= len(audience) <= prior.MAX_RECEIVERS and
         audience == [r for r in canonical if r in audience] and
         all(rows[r][2]['event_kind'] != previous.REVOCATION for r in audience),
         'CHALLENGE_NEEDS_TWO_DISTINCT_ACTIVE_REGISTERED_RECEIVERS')
    need(type(c.get('round_number')) is int and
         1 <= c['round_number'] <= MAX_ROUNDS and
         ceremony._sha(c.get('challenge_nonce_sha256')) and
         ceremony._utc(c.get('issued_utc')) and
         old._time(c['issued_utc']) >= old._time(source['custody_evaluation_utc']) and
         c.get('scope') == 'request_new_local_byte_reopening_without_remote_rights' and
         c.get('no_remote_authority') is True,
         'CHALLENGE_NONCE_ROUND_TIME_AND_SCOPE_INVALID')
    prior._signed(doc, CHALLENGE_SCHEMA, D_CHALLENGE,
                  roster['change_proposer']['public_hex'], 'EC347_CHALLENGE')
    if c['round_number'] == 1:
        need(c['previous_challenge_file'] is None and
             c['previous_challenge_original_raw_sha256'] is None,
             'FIRST_CHALLENGE_MUST_HAVE_NO_PREDECESSOR')
        chain = [(path, sha, c)]
    else:
        need(type(c['previous_challenge_file']) is str and
             ceremony._sha(c['previous_challenge_original_raw_sha256']) and
             c['previous_challenge_file'] != path,
             'SUCCESSOR_CHALLENGE_NEEDS_EXTERNAL_PREDECESSOR_SHA')
        older = _load_challenge(c['previous_challenge_file'],
            c['previous_challenge_original_raw_sha256'], source=source,
            roster=roster, item=item, rows=rows, pins=pins, depth=depth+1)
        head = older[-1][2]
        need(head['round_number'] + 1 == c['round_number'] and
             head['audience_receiver_ids'] == audience and
             old._time(head['issued_utc']) <= old._time(c['issued_utc']) and
             c['challenge_nonce_sha256'] not in
                 {x[2]['challenge_nonce_sha256'] for x in older},
             'CHALLENGE_CHAIN_MUST_BE_CONTIGUOUS_SAME_AUDIENCE_AND_FRESH_NONCE')
        chain = [*older, (path, sha, c)]
    need(c['challenge_nonce_sha256'] not in _parent_nonces(source, rows),
         'CHALLENGE_NONCE_MUST_BE_NEW_RELATIVE_TO_EC345_EC346')
    return chain


def issue_challenge(*, out: str, private_key_file: str,
                    audience_receiver_ids: list[str], round_number: int,
                    challenge_nonce_sha256: str, issued_utc: str,
                    previous_challenge_file: str | None = None,
                    expected_previous_challenge_sha256: str | None = None,
                    **source) -> dict:
    roster, item, pins, rows = _parent(source)
    _, pub = rotation._private_key_public(private_key_file)
    need(prior.same(pub, roster['change_proposer']['public_hex']),
         'ONLY_INDEPENDENT_EC343_CHANGE_PROPOSER_CAN_ISSUE_CHALLENGE',
         'permission_denied')
    need(type(audience_receiver_ids) is list and
         type(round_number) is int and 1 <= round_number <= MAX_ROUNDS and
         ceremony._sha(challenge_nonce_sha256) and ceremony._utc(issued_utc),
         'CHALLENGE_INPUT_TYPES_INVALID')
    claim = _challenge_claim(source, roster, item, rows,
         audience_receiver_ids=audience_receiver_ids, round_number=round_number,
         previous_challenge_file=previous_challenge_file,
         previous_challenge_sha=expected_previous_challenge_sha256,
         challenge_nonce_sha256=challenge_nonce_sha256, issued_utc=issued_utc)
    # Validate the complete prospective claim with its actual signature before
    # releasing a candidate. Existing challenge predecessors must remain pinned.
    key, _ = rotation._private_key_public(private_key_file)
    doc = {'schema': CHALLENGE_SCHEMA, 'claim': claim,
           'signature_ed25519': key.sign(D_CHALLENGE + reg.canonical(claim)).hex()}
    prior._signed(doc, CHALLENGE_SCHEMA, D_CHALLENGE,
                  roster['change_proposer']['public_hex'], 'EC347_NEW_CHALLENGE')
    # Validate all structure and intended ordering without writing a transient
    # candidate to a source directory or trusting user-supplied labels.
    need(old._time(issued_utc) >= old._time(source['custody_evaluation_utc']) and
         audience_receiver_ids == [a['signer_id'] for a in roster['receivers']
             if a['signer_id'] in audience_receiver_ids and a['signer_id'] in rows] and
         2 <= len(audience_receiver_ids) <= prior.MAX_RECEIVERS and
         all(rows[r][2]['event_kind'] != previous.REVOCATION
             for r in audience_receiver_ids) and
         challenge_nonce_sha256 not in _parent_nonces(source, rows),
         'AUDIENCE_MUST_BE_ACTIVE_CANONICAL_AND_NONCE_NEW')
    if round_number == 1:
        need(previous_challenge_file is None and
             expected_previous_challenge_sha256 is None,
             'FIRST_CHALLENGE_CANNOT_REFERENCE_PREDECESSOR')
    else:
        need(type(previous_challenge_file) is str and
             ceremony._sha(expected_previous_challenge_sha256),
             'SUCCESSOR_NEEDS_EXISTING_SIGNED_CHALLENGE')
        older = _load_challenge(previous_challenge_file,
            expected_previous_challenge_sha256, source=source,
            roster=roster, item=item, rows=rows, pins=pins)
        need(older[-1][2]['round_number'] + 1 == round_number and
             older[-1][2]['audience_receiver_ids'] == audience_receiver_ids and
             old._time(older[-1][2]['issued_utc']) <= old._time(issued_utc) and
             challenge_nonce_sha256 not in
                 {x[2]['challenge_nonce_sha256'] for x in older},
             'SUCCESSOR_CHALLENGE_CHAIN_ROUND_AUDIENCE_OR_NONCE_INVALID')
    need(out not in set(source['observation_files'] +
         source['challenge_files'] + source['response_files'] +
         source['view_files']), 'OUTPUT_CANNOT_ALIAS_PREVIOUS_SIGNED_ORIGINALS')
    return _candidate('issue-challenge', prior._write(out, doc, pins, private_key_file))


def _receiver_fields(actor: dict, row: tuple) -> dict:
    claim = row[2]
    return {'receiver_id': actor['signer_id'],
            'receiver_public_hex': actor['public_hex'],
            'receiver_organization_id': actor['organization_id'],
            'copy_id': claim['copy_id'],
            'claimed_storage_id': claim['claimed_storage_id'],
            'ec346_latest_signed_event_original_raw_sha256': row[1],
            'copy_snapshot_file': claim['copy_snapshot_file'],
            'copy_ack_set_file': claim['copy_ack_set_file']}


def _response_claim(*, c: dict, challenge_file: str, challenge_sha: str,
                    actor: dict, row: tuple, response_kind: str,
                    measurements: dict, response_nonce_sha256: str,
                    reported_utc: str) -> dict:
    return {'schema': RESPONSE_CLAIM, 'case_id': c['case_id'],
            'target_item_id': c['target_item_id'],
            'target_slot_id': c['target_slot_id'],
            'ec346_audit_inputs_canonical_sha256': c['ec346_audit_inputs_canonical_sha256'],
            'challenge_file': challenge_file,
            'challenge_original_raw_sha256': challenge_sha,
            'challenge_nonce_sha256': c['challenge_nonce_sha256'],
            'round_number': c['round_number'],
            **_receiver_fields(actor, row), 'response_kind': response_kind,
            **measurements, 'response_nonce_sha256': response_nonce_sha256,
            'reported_utc': reported_utc,
            'scope': 'local_reopen_claim_not_physical_site_independence',
            'no_remote_authority': True}


def _measurement(copy: dict | None, row: tuple, item: dict) -> dict:
    if copy is None:
        return {k: None for k in (
            'copy_snapshot_original_raw_sha256', 'copy_snapshot_byte_length',
            'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length',
            'matches_ec346_signed_bytes', 'matches_ec345_verified_source')} | {
            'bytes_reopened_after_challenge': False}
    signed = row[2]
    return {
        'copy_snapshot_original_raw_sha256': copy['copy_snapshot_original_raw_sha256'],
        'copy_snapshot_byte_length': copy['copy_snapshot_byte_length'],
        'copy_ack_set_original_raw_sha256': copy['copy_ack_set_original_raw_sha256'],
        'copy_ack_set_byte_length': copy['copy_ack_set_byte_length'],
        'matches_ec346_signed_bytes': all(copy[k] == signed[k] for k in (
            'copy_snapshot_original_raw_sha256', 'copy_snapshot_byte_length',
            'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length')),
        'matches_ec345_verified_source': previous._matching(copy, item),
        'bytes_reopened_after_challenge': True,
    }


def sign_readback(*, out: str, private_key_file: str,
                  challenge_file: str, expected_challenge_sha256: str,
                  response_kind: str, response_nonce_sha256: str, reported_utc: str,
                  copy_snapshot_file: str | None = None,
                  copy_ack_set_file: str | None = None, **source) -> dict:
    roster, item, pins, rows = _parent(source)
    chain = _load_challenge(challenge_file, expected_challenge_sha256,
        source=source, roster=roster, item=item, rows=rows, pins=pins)
    c = chain[-1][2]
    key, pub = rotation._private_key_public(private_key_file)
    actor = next((a for a in roster['receivers'] if prior.same(a['public_hex'], pub)), None)
    need(actor is not None and actor['signer_id'] in c['audience_receiver_ids'],
         'ONLY_CHALLENGED_ORIGINAL_RECEIVER_CAN_SIGN_REPLY', 'permission_denied')
    need(response_kind in KINDS and ceremony._sha(response_nonce_sha256) and
         ceremony._utc(reported_utc) and
         old._time(c['issued_utc']) <= old._time(reported_utc),
         'REPLY_KIND_NONCE_AND_POST_CHALLENGE_CLAIMED_TIME_REQUIRED')
    used = _parent_nonces(source, rows) | {
        x[2]['challenge_nonce_sha256'] for x in chain}
    need(response_nonce_sha256 not in used, 'REPLY_NONCE_MUST_BE_NEW')
    row = rows[actor['signer_id']]
    if response_kind == MEASURED:
        need((copy_snapshot_file, copy_ack_set_file) ==
             (row[2]['copy_snapshot_file'], row[2]['copy_ack_set_file']),
             'REMEASUREMENT_EXACT_TWO_EXPLICIT_EC346_COPY_PATHS_REQUIRED')
        copy = previous._copy_fields(copy_snapshot_file, copy_ack_set_file,
            allow_source=(item['snapshot_file'], item['ack_set_file']))
        need(not ({copy_snapshot_file, copy_ack_set_file} & set(pins)),
             'REMEASURED_BYTES_CANNOT_ALIAS_PINNED_SIGNED_ORIGINALS')
        for p, sha in ((copy_snapshot_file, copy['copy_snapshot_original_raw_sha256']),
                       (copy_ack_set_file, copy['copy_ack_set_original_raw_sha256'])):
            prior.pin(pins, p, sha)
    else:
        need(copy_snapshot_file is None and copy_ack_set_file is None,
             'UNAVAILABLE_CLAIM_MUST_NOT_ACCESS_ANY_COPY_PATHS')
        copy = None
    claim = _response_claim(c=c, challenge_file=challenge_file,
        challenge_sha=expected_challenge_sha256, actor=actor, row=row,
        response_kind=response_kind, measurements=_measurement(copy, row, item),
        response_nonce_sha256=response_nonce_sha256, reported_utc=reported_utc)
    need(out not in {challenge_file, row[2]['copy_snapshot_file'],
                     row[2]['copy_ack_set_file']},
         'REPLY_OUTPUT_CANNOT_ALIAS_CHALLENGE_OR_SOURCE_BYTES')
    doc = {'schema': RESPONSE_SCHEMA, 'claim': claim,
           'signature_ed25519': key.sign(D_RESPONSE + reg.canonical(claim)).hex()}
    prior._signed(doc, RESPONSE_SCHEMA, D_RESPONSE, actor['public_hex'],
                  'EC347_NEW_SIGNED_REPLY')
    return _candidate('sign-readback', prior._write(out, doc, pins, private_key_file))


def _load_response(path: str, sha: str, *, challenge: tuple,
                   roster: dict, item: dict, rows: dict, pins: dict):
    cpath, csha, c = challenge
    prior.pin(pins, path, sha)
    need(path != cpath, 'REPLY_CANNOT_ALIAS_CHALLENGE')
    doc = prior.read(path, sha, 'EC347_PINNED_SIGNED_READBACK')
    r = doc.get('claim') if type(doc) is dict else None
    need(type(r) is dict and set(r) == R_FIELDS and
         r.get('schema') == RESPONSE_CLAIM and
         r.get('case_id') == c['case_id'] and
         r.get('target_item_id') == c['target_item_id'] and
         r.get('target_slot_id') == c['target_slot_id'] and
         r.get('ec346_audit_inputs_canonical_sha256') ==
             c['ec346_audit_inputs_canonical_sha256'] and
         r.get('challenge_file') == cpath and
         r.get('challenge_original_raw_sha256') == csha and
         r.get('challenge_nonce_sha256') == c['challenge_nonce_sha256'] and
         r.get('round_number') == c['round_number'],
         'REPLY_MUST_BIND_PRECISE_SIGNED_CHALLENGE_AND_EC346_HISTORY')
    actor = next((a for a in roster['receivers'] if a['signer_id'] == r.get('receiver_id')), None)
    need(actor is not None and actor['signer_id'] in c['audience_receiver_ids'] and
         actor['signer_id'] in rows and
         all(r.get(k) == v for k, v in _receiver_fields(actor, rows[actor['signer_id']]).items()),
         'REPLY_MUST_BIND_ORIGINAL_REGISTERED_RECEIVER_AND_COPY_VERSION')
    need(r.get('response_kind') in KINDS and
         ceremony._sha(r.get('response_nonce_sha256')) and
         ceremony._utc(r.get('reported_utc')) and
         old._time(r['reported_utc']) >= old._time(c['issued_utc']) and
         r.get('scope') == 'local_reopen_claim_not_physical_site_independence' and
         r.get('no_remote_authority') is True,
         'REPLY_POST_CHALLENGE_TIME_NONCE_KIND_OR_SCOPE_INVALID')
    keys = ('copy_snapshot_original_raw_sha256', 'copy_snapshot_byte_length',
            'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length')
    if r['response_kind'] == MEASURED:
        need(all(ceremony._sha(r[k]) for k in keys if k.endswith('sha256')) and
             all(type(r[k]) is int and 0 < r[k] <= previous.MAX_COPY_BYTES
                 for k in keys if k.endswith('length')) and
             r.get('bytes_reopened_after_challenge') is True,
             'MEASURED_REPLY_NEEDS_TWO_COMPLETE_BYTES_SHA_AND_LENGTHS')
        signed = rows[actor['signer_id']][2]
        matches_old = all(r[k] == signed[k] for k in keys)
        matches_source = (r['copy_snapshot_original_raw_sha256'] == item['expected_snapshot_sha256'] and
                          r['copy_ack_set_original_raw_sha256'] == item['expected_ack_set_sha256'])
        need(r['matches_ec346_signed_bytes'] is matches_old and
             r['matches_ec345_verified_source'] is matches_source,
             'SIGNED_COPY_COMPARISONS_MUST_BE_DERIVED_FROM_PINNED_BYTES')
    else:
        need(all(r.get(k) is None for k in (*keys,
            'matches_ec346_signed_bytes', 'matches_ec345_verified_source')) and
            r.get('bytes_reopened_after_challenge') is False,
            'UNAVAILABLE_CLAIM_MAY_NOT_PRETEND_TO_HAVE_READ_BYTES')
    prior._signed(doc, RESPONSE_SCHEMA, D_RESPONSE, actor['public_hex'],
                  'EC347_SIGNED_RECEIVER_READBACK')
    return r


def audit_readbacks(*, readback_evaluation_utc: str,
                    readback_challenge_files: list[str],
                    readback_challenge_shas: list[str],
                    readback_response_files: list[str],
                    readback_response_shas: list[str],
                    presented_receiver_ids: list[str],
                    presented_snapshot_files: list[str],
                    presented_ack_set_files: list[str], **source) -> dict:
    """Whole-original audit; only caller-presented *last-round* copies re-open."""
    need(ceremony._utc(readback_evaluation_utc) and
         old._time(readback_evaluation_utc) >= old._time(source['custody_evaluation_utc']),
         'EVALUATION_CLAIMED_UTC_MUST_FOLLOW_EC346')
    lists = (readback_challenge_files, readback_challenge_shas,
             readback_response_files, readback_response_shas,
             presented_receiver_ids, presented_snapshot_files,
             presented_ack_set_files)
    need(all(type(x) is list for x in lists) and
         1 <= len(readback_challenge_files) <= MAX_ROUNDS and
         len(readback_challenge_files) == len(readback_challenge_shas) and
         len(readback_response_files) == len(readback_response_shas) and
         len(readback_response_files) <= MAX_RESPONSES and
         len(presented_receiver_ids) == len(presented_snapshot_files) ==
             len(presented_ack_set_files) <= prior.MAX_RECEIVERS and
         all(len(set(x)) == len(x) for x in (
             readback_challenge_files, readback_response_files,
             presented_receiver_ids)) and
         not (set(readback_challenge_files) & set(readback_response_files)),
         'BOUNDED_DISTINCT_CHALLENGES_RESPONSES_AND_PRESENTATIONS_REQUIRED')
    roster, item, pins, rows = _parent(source)
    ordered_receivers = [a['signer_id'] for a in roster['receivers'] if a['signer_id'] in rows]
    all_nonces = _parent_nonces(source, rows)
    challenges = []
    for idx, (path, sha) in enumerate(zip(readback_challenge_files,
                                         readback_challenge_shas, strict=True)):
        chain = _load_challenge(path, sha, source=source, roster=roster,
                                item=item, rows=rows, pins=pins)
        c = chain[-1][2]
        need(c['round_number'] == idx+1 and
             len(chain) == idx+1 and
             [(x[0], x[1]) for x in chain] == list(zip(
                readback_challenge_files[:idx+1],
                readback_challenge_shas[:idx+1], strict=True)) and
             old._time(c['issued_utc']) <= old._time(readback_evaluation_utc) and
             c['challenge_nonce_sha256'] not in all_nonces,
             'EVERY_SIGNED_CHALLENGE_ROUND_NEEDS_ITS_EXPLICIT_PREDECESSOR')
        all_nonces.add(c['challenge_nonce_sha256'])
        challenges.append((path, sha, c))
    responses: dict[tuple[int, str], tuple[str, str, dict]] = {}
    last_sort = (-1, -1)
    for path, sha in zip(readback_response_files, readback_response_shas, strict=True):
        # Without looking at signed copy paths, inspect only the explicitly
        # pinned response's challenge SHA to find its signed challenge.
        prior.pin(pins, path, sha)
        pre = prior.read(path, sha, 'EC347_RESPONSE_ROUTING')
        cc = pre.get('claim') if type(pre) is dict else None
        need(type(cc) is dict and
             type(cc.get('round_number')) is int and
             1 <= cc['round_number'] <= len(challenges),
             'RESPONSE_MUST_TARGET_A_PRESENTED_CHALLENGE')
        ch = challenges[cc['round_number']-1]
        claim = _load_response(path, sha, challenge=ch, roster=roster,
                               item=item, rows=rows, pins=pins)
        index = (claim['round_number'], ordered_receivers.index(claim['receiver_id']))
        key = (claim['round_number'], claim['receiver_id'])
        need(index > last_sort and key not in responses and
             claim['response_nonce_sha256'] not in all_nonces and
             old._time(claim['reported_utc']) <= old._time(readback_evaluation_utc),
             'REPLIES_MUST_BE_CANONICAL_UNIQUE_NO_NONCE_REUSE_NO_FUTURE_CLAIM')
        all_nonces.add(claim['response_nonce_sha256'])
        last_sort = index
        responses[key] = (path, sha, claim)
    latest = challenges[-1][2]
    need(presented_receiver_ids == [r for r in ordered_receivers if r in presented_receiver_ids] and
         len(presented_receiver_ids) <= len(latest['audience_receiver_ids']),
         'PRESENTED_RECEIVERS_CANONICAL')
    provided = dict(zip(presented_receiver_ids, zip(
        presented_snapshot_files, presented_ack_set_files, strict=True), strict=True))
    present_paths = [p for pair in provided.values() for p in pair]
    need(len(present_paths) == len(set(present_paths)) and
         not (set(present_paths) & set(pins)),
         'EXPLICIT_PRESENTED_PAIRS_MUST_NOT_ALIAS_OTHER_ORIGINALS')
    for rid, pair in provided.items():
        need((len(pair) == 2 and pair[0] != pair[1] and
              rid in latest['audience_receiver_ids'] and
              (len(challenges), rid) in responses and
              responses[(len(challenges), rid)][2]['response_kind'] == MEASURED and
              pair == (rows[rid][2]['copy_snapshot_file'],
                       rows[rid][2]['copy_ack_set_file'])),
             'ONLY_LATEST_MEASURED_SIGNER_EXPLICIT_COPY_PATHS_CAN_BE_REOPENED')
    report = []
    for round_no, ch in enumerate(challenges, start=1):
        for rid in ch[2]['audience_receiver_ids']:
            signed = responses.get((round_no, rid))
            r = signed[2] if signed else None
            outcome = ('challenged_receiver_did_not_reply' if r is None else
                'signed_unavailable_claim_without_byte_read'
                    if r['response_kind'] == UNAVAILABLE else
                'signed_readback_changed_from_ec346_observation'
                    if not r['matches_ec346_signed_bytes'] else
                'signed_readback_differs_from_verified_source'
                    if not r['matches_ec345_verified_source'] else
                'signed_readback_matches_prior_and_verified_source')
            measured_now = None
            if round_no == len(challenges) and rid in provided:
                copy = previous._copy_fields(*provided[rid], allow_source=(
                    item['snapshot_file'], item['ack_set_file']))
                for k, value in ((provided[rid][0], copy['copy_snapshot_original_raw_sha256']),
                                 (provided[rid][1], copy['copy_ack_set_original_raw_sha256'])):
                    prior.pin(pins, k, value)
                matches_response = all(copy[k] == r[k] for k in (
                    'copy_snapshot_original_raw_sha256', 'copy_snapshot_byte_length',
                    'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length'))
                measured_now = {'snapshot_original_raw_sha256':
                                    copy['copy_snapshot_original_raw_sha256'],
                                'ack_set_original_raw_sha256': copy['copy_ack_set_original_raw_sha256'],
                                'snapshot_byte_length': copy['copy_snapshot_byte_length'],
                                'ack_set_byte_length': copy['copy_ack_set_byte_length'],
                                'matches_signed_remeasurement': matches_response,
                                'matches_verified_source': previous._matching(copy, item)}
                if not matches_response:
                    outcome = 'later_explicitly_presented_bytes_changed_after_signed_readback'
            report.append({
                'round_number': round_no, 'challenge_original_raw_sha256': ch[1],
                'receiver_id': rid, 'receiver_organization_id': rows[rid][2]['receiver_organization_id'],
                'claimed_storage_id_unverified': rows[rid][2]['claimed_storage_id'],
                'ec346_latest_signed_event_original_raw_sha256': rows[rid][1],
                'responded': r is not None,
                'response_original_raw_sha256': signed[1] if signed else None,
                'response_kind': r['response_kind'] if r else None,
                'response_reported_utc': r['reported_utc'] if r else None,
                'signed_snapshot_raw_sha256': r['copy_snapshot_original_raw_sha256'] if r else None,
                'signed_ack_set_raw_sha256': r['copy_ack_set_original_raw_sha256'] if r else None,
                'signed_bytes_match_prior': r['matches_ec346_signed_bytes'] if r else None,
                'signed_bytes_match_source': r['matches_ec345_verified_source'] if r else None,
                'copy_explicitly_reopened_by_auditor': measured_now is not None,
                'auditor_actual_byte_measurement': measured_now,
                'outcome': outcome,
            })
    prior.late(pins)
    counts = {k: sum(row['outcome'] == k for row in report) for k in OUTCOMES}
    priority = (OUTCOMES[5], OUTCOMES[1], OUTCOMES[2],
                OUTCOMES[3], OUTCOMES[4], OUTCOMES[0])
    chosen = next(i for i,k in enumerate(priority) if counts[k])
    status = STATUS_ORDER[chosen]
    repeated = []
    for rid in ordered_receivers:
        events = [responses.get((j, rid)) for j in range(1, len(challenges)+1)]
        measured = [x[2] for x in events if x is not None and x[2]['response_kind'] == MEASURED]
        if len(measured) >= 2 and all(x['matches_ec346_signed_bytes'] and
            x['matches_ec345_verified_source'] and
            (x['copy_snapshot_original_raw_sha256'],x['copy_ack_set_original_raw_sha256']) ==
            (measured[0]['copy_snapshot_original_raw_sha256'],
             measured[0]['copy_ack_set_original_raw_sha256']) for x in measured):
            repeated.append(rid)
    return {'schema': RESULT_SCHEMA, 'command': 'audit-readbacks',
            'status': status, 'exit_code': 2, 'case_id': roster['case_id'],
            'target_item_id': item['item_id'], 'target_slot_id': item['slot_id'],
            'ec346_audit_inputs_canonical_sha256': case.sha(reg.canonical(source)),
            'source_snapshot_original_raw_sha256': item['expected_snapshot_sha256'],
            'source_ack_set_original_raw_sha256': item['expected_ack_set_sha256'],
            'independent_proposer_key_distinct_from_receiver_keys_by_ec343_roster': True,
            'ec345_through_ec346_original_signed_history_replayed': True,
            'challenge_round_count': len(challenges),
            'signed_response_count': len(responses),
            'latest_challenge_audience_receiver_ids': latest['audience_receiver_ids'],
            'explicitly_presented_latest_round_copy_count': len(provided),
            'claimed_same_bytes_on_two_or_more_distinct_signed_rounds_receiver_ids': repeated,
            'per_receiver_round_outcomes': report, 'outcome_counts': counts,
            'readback_evaluation_utc': readback_evaluation_utc,
            'all_actual_byte_checks_are_local_and_explicit_only': True,
            'offline_unresolved_exit_code': 2,
            **{k: False for k in NEGATIVES}}

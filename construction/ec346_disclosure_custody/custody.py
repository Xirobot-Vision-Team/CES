#!/usr/bin/env python3
"""EC346: Ed25519 receiver observations of actually read offline copy bytes.

An EC345 verified disclosed snapshot/ack pair is the *only* acceptable source.
The receiving signer measures the destination bytes before signing; later audits
replay all EC345 original signatures and require the auditor to explicitly name
which copies are presented for a fresh comparison. Revocation is a statement,
not deletion; claimed storage ids are not proof of separate physical machines.
"""
from __future__ import annotations

import inspect
from collections import defaultdict
from typing import Any

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec338_independent_custody import ceremony
from ec339_offline_authority import authority as old
from ec340_issuer_root_rotation import rotation
from ec343_hold_receipts import timeline as prior
from ec344_receiver_visibility import visibility as vis
from ec345_disclosure_challenge import challenge as previous

EVENT_SCHEMA = 'ces.ec346.ed25519_offline_receiver_copy_event.v1'
CLAIM_SCHEMA = 'ces.ec346.offline_receiver_copy_event_claim.v1'
RESULT_SCHEMA = 'ces.ec346.post_disclosure_copy_custody_audit_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec346.post_disclosure_copy_custody_audit_denial.v1'
EVENT_DOMAIN = b'CES/EC346/OfflineReceiverCopyObservation/v1\0'
RECEIPT = 'receipt'
REPLACEMENT = 'replacement_claim'
REVOCATION = 'revocation_claim'
KINDS = (RECEIPT, REPLACEMENT, REVOCATION)
MAX_EVENTS_PER_RECEIVER = 3
MAX_EVENTS = prior.MAX_RECEIVERS * MAX_EVENTS_PER_RECEIVER
MAX_COPY_BYTES = prior.LIMIT
OUTCOMES = (
    'presented_copy_changed_since_signed_observation',
    'presented_copy_differs_from_verified_source',
    'signed_copy_not_presented_in_this_audit',
    'presented_copy_matches_verified_source',
)
STATUSES = (
    'presented_copy_changed_since_signed_observation_unresolved',
    'presented_copy_differs_from_verified_source_unresolved',
    'revocation_or_replacement_claim_unresolved',
    'signed_copy_not_presented_in_this_audit_unresolved',
    'multiple_identical_local_copies_unresolved',
)
NEGATIVES = (
    'signed_receipt_alone_proves_physical_inter_machine_transfer',
    'claimed_storage_id_proves_distinct_machine_or_organization',
    'signed_revocation_claim_deletes_or_erases_any_original',
    'signed_replacement_claim_modifies_prior_original',
    'self_reported_utc_is_independently_trusted',
    'all_receivers_or_global_forks_latest_or_winner_known',
    'remote_provider_cas_worm_freeze_release_readback_nonexecution_proven',
    'fully_unmocked_legacy_history_or_final_acceptance_proven',
)
FIELDS = frozenset({
    'schema', 'case_id', 'ec343_roster_original_raw_sha256',
    'ec344_directory_original_raw_sha256', 'ec344_checkpoint_original_raw_sha256',
    'ec345_full_audit_arguments_canonical_sha256',
    'ec345_signed_challenge_original_raw_sha256s',
    'ec345_signed_response_original_raw_sha256s',
    'disclosure_evaluation_utc', 'target_item_id', 'target_slot_id',
    'source_snapshot_file', 'source_snapshot_original_raw_sha256',
    'source_ack_set_file', 'source_ack_set_original_raw_sha256',
    'receiver_id', 'receiver_public_hex', 'receiver_organization_id',
    'copy_id', 'claimed_storage_id', 'event_kind', 'sequence',
    'previous_event_file', 'previous_event_original_raw_sha256',
    'copy_snapshot_file', 'copy_snapshot_original_raw_sha256',
    'copy_snapshot_byte_length', 'copy_ack_set_file',
    'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length',
    'bytes_measured_this_event', 'copy_bytes_match_delivered_source',
    'event_nonce_sha256', 'reported_utc', 'scope',
    'no_remote_transfer_revocation_or_winner_authority',
})
BASELINE_KEYS = frozenset(inspect.signature(vis.audit_views).parameters) | {
    'challenge_files', 'challenge_shas', 'response_files', 'response_shas',
    'disclosed_item_ids', 'disclosure_evaluation_utc'
}


def need(condition: Any, code: str, status: str = 'invalid_input') -> None:
    if condition is not True:
        raise anchor.AnchorError('EC346_' + code, status)


def _candidate(command: str, sha: str) -> dict:
    return {'schema': RESULT_SCHEMA, 'command': command,
            'status': 'private_signed_observation_candidate_requires_external_sha_pin',
            'exit_code': 2, 'candidate_original_raw_sha256': sha,
            'offline_unresolved_exit_code': 2,
            **{key: False for key in NEGATIVES}}


def _basis(item_id: str, baseline: dict) -> tuple[dict, dict, dict, dict, dict[str, str]]:
    """Real full EC345->EC337 replay, even if EC345's top outcome is conflict."""
    need(set(baseline) == BASELINE_KEYS, 'EXACT_FULL_EC345_TRUST_ARGUMENTS_REQUIRED')
    need(ceremony._id(item_id) and item_id in baseline['disclosed_item_ids'],
         'SOURCE_MUST_BE_EXPLICITLY_FURNISHED_IN_EC345')
    audit = previous.audit_disclosures(**baseline)
    need(audit['exit_code'] == 2 and
         audit['true_ec342_signed_fork_and_old_originals_replayed'] is True and
         item_id in audit['verified_furnished_item_ids'],
         'ONLY_ACTUALLY_FULL_SHA_VERIFIED_DISCLOSURE_CAN_BE_A_COPY_SOURCE',
         'permission_denied')
    row = next(x for x in audit['item_outcomes'] if x['item_id'] == item_id)
    need(row['verified_furnished_originals'] is True and
         row['verified_original_detail'] is not None,
         'FULLY_REPLAYED_PAIR_AND_GENUINE_SIGNED_OFFER_REQUIRED')
    r, d, c, pins = vis._prepared(
        roster_file=baseline['roster_file'],
        expected_roster_sha256=baseline['expected_roster_sha256'],
        directory_file=baseline['directory_file'],
        expected_directory_sha256=baseline['expected_directory_sha256'],
        checkpoint_file=baseline['checkpoint_file'],
        expected_checkpoint_sha256=baseline['expected_checkpoint_sha256'])
    items = [x for x in c['announcements'] if x['item_id'] == item_id]
    need(len(items) == 1, 'EXACT_ONE_CHECKPOINT_SOURCE_ITEM_REQUIRED')
    item = items[0]
    need(row['verified_original_detail']['snapshot_original_raw_sha256'] ==
         item['expected_snapshot_sha256'] and
         row['verified_original_detail']['ack_set_original_raw_sha256'] ==
         item['expected_ack_set_sha256'], 'EC345_RESULT_MUST_BIND_EXACT_SOURCE_SHA')
    # The material must remain accessible and pinned for the EC346 operation.
    prior.pin(pins, item['snapshot_file'], item['expected_snapshot_sha256'])
    prior.pin(pins, item['ack_set_file'], item['expected_ack_set_sha256'])
    for path_key, sha_key in (
        ('manifest_file', 'expected_manifest_sha256'),
        ('governance_roster_file', 'expected_governance_roster_sha256'),
        ('review_manifest_file', 'expected_review_manifest_sha256'),
        ('approval_file', 'expected_approval_sha256'),
        ('roster_file', 'expected_roster_sha256'),
        ('head_snapshot_file', 'expected_head_snapshot_sha256'),
        ('head_ack_set_file', 'expected_head_ack_set_sha256'),
        ('directory_file', 'expected_directory_sha256'),
        ('checkpoint_file', 'expected_checkpoint_sha256'),
    ):
        prior.pin(pins, baseline[path_key], baseline[sha_key])
    for paths, shas in (('challenge_files', 'challenge_shas'),
                        ('response_files', 'response_shas'),
                        ('view_files', 'view_shas')):
        for path, sha in zip(baseline[paths], baseline[shas], strict=True):
            prior.pin(pins, path, sha)
    return r, item, audit, _basis_claim(baseline), pins


def _basis_claim(baseline: dict) -> dict:
    return {
        'ec343_roster_original_raw_sha256': baseline['expected_roster_sha256'],
        'ec344_directory_original_raw_sha256': baseline['expected_directory_sha256'],
        'ec344_checkpoint_original_raw_sha256': baseline['expected_checkpoint_sha256'],
        'ec345_full_audit_arguments_canonical_sha256': case.sha(reg.canonical(baseline)),
        'ec345_signed_challenge_original_raw_sha256s': baseline['challenge_shas'],
        'ec345_signed_response_original_raw_sha256s': baseline['response_shas'],
        'disclosure_evaluation_utc': baseline['disclosure_evaluation_utc'],
    }


def _source_fields(item: dict) -> dict:
    return {
        'target_item_id': item['item_id'], 'target_slot_id': item['slot_id'],
        'source_snapshot_file': item['snapshot_file'],
        'source_snapshot_original_raw_sha256': item['expected_snapshot_sha256'],
        'source_ack_set_file': item['ack_set_file'],
        'source_ack_set_original_raw_sha256': item['expected_ack_set_sha256'],
    }


def _actor_fields(actor: dict) -> dict:
    return {'receiver_id': actor['signer_id'],
            'receiver_public_hex': actor['public_hex'],
            'receiver_organization_id': actor['organization_id']}


def _copy_fields(snapshot_file: str, ack_set_file: str,
                 *, allow_source: tuple[str, str]) -> dict:
    rotation._paths(snapshot_file, ack_set_file, *allow_source)
    raw1 = reg._private_read(snapshot_file, MAX_COPY_BYTES, 'EC346_SNAPSHOT_COPY')
    raw2 = reg._private_read(ack_set_file, MAX_COPY_BYTES, 'EC346_ACK_SET_COPY')
    need(len(raw1) > 0 and len(raw2) > 0, 'COPY_BYTES_MUST_BE_NONEMPTY')
    return {
        'copy_snapshot_file': snapshot_file,
        'copy_snapshot_original_raw_sha256': case.sha(raw1),
        'copy_snapshot_byte_length': len(raw1),
        'copy_ack_set_file': ack_set_file,
        'copy_ack_set_original_raw_sha256': case.sha(raw2),
        'copy_ack_set_byte_length': len(raw2),
    }


def _matching(fields: dict, item: dict) -> bool:
    return (fields['copy_snapshot_original_raw_sha256'] == item['expected_snapshot_sha256'] and
            fields['copy_ack_set_original_raw_sha256'] == item['expected_ack_set_sha256'])


def _context(claim: dict) -> tuple:
    return tuple(claim[k] if type(claim[k]) is not list else tuple(claim[k]) for k in (
        'case_id', 'ec343_roster_original_raw_sha256',
        'ec344_directory_original_raw_sha256', 'ec344_checkpoint_original_raw_sha256',
        'ec345_full_audit_arguments_canonical_sha256',
        'ec345_signed_challenge_original_raw_sha256s',
        'ec345_signed_response_original_raw_sha256s', 'disclosure_evaluation_utc',
        'target_item_id', 'target_slot_id', 'source_snapshot_file',
        'source_snapshot_original_raw_sha256', 'source_ack_set_file',
        'source_ack_set_original_raw_sha256', 'receiver_id',
        'receiver_public_hex', 'receiver_organization_id', 'copy_id',
        'claimed_storage_id',
    ))


def _load_event(path: str, sha: str, *, r: dict, item: dict,
                baseline: dict, pins: dict[str, str]) -> tuple[dict, list[tuple[str, dict]]]:
    """Validate one complete signed predecessor chain, up to three links."""
    prior.pin(pins, path, sha)
    doc = prior.read(path, sha, 'EC346_SIGNED_CUSTODY_EVENT')
    claim = doc.get('claim') if type(doc) is dict else None
    need(type(claim) is dict and set(claim) == FIELDS and
         claim.get('schema') == CLAIM_SCHEMA and
         claim.get('case_id') == r['case_id'] and
         all(claim.get(k) == v for k, v in _basis_claim(baseline).items()) and
         all(claim.get(k) == v for k, v in _source_fields(item).items()),
         'SIGNED_EVENT_MUST_BIND_VERIFIED_EC345_DISCLOSURE_AND_SOURCE')
    actor = next((a for a in r['receivers']
                  if a['signer_id'] == claim.get('receiver_id')), None)
    need(actor is not None and
         all(claim.get(k) == v for k, v in _actor_fields(actor).items()),
         'ONLY_GENUINE_REGISTERED_RECEIVER_MAY_CLAIM_CUSTODY')
    need(ceremony._id(claim.get('copy_id')) and
         ceremony._id(claim.get('claimed_storage_id')) and
         claim.get('event_kind') in KINDS and
         type(claim.get('sequence')) is int and
         1 <= claim['sequence'] <= MAX_EVENTS_PER_RECEIVER and
         ceremony._sha(claim.get('event_nonce_sha256')) and
         ceremony._utc(claim.get('reported_utc')) and
         old._time(claim['reported_utc']) >=
             old._time(baseline['disclosure_evaluation_utc']) and
         claim.get('scope') == 'receiver_claim_about_measured_local_bytes_only' and
         claim.get('no_remote_transfer_revocation_or_winner_authority') is True,
         'EVENT_ID_KIND_NONCE_TIME_AND_SCOPE_INVALID')
    # Prior EC345 challenges were addressed to a fixed set of actual receivers.
    audience = _audience(baseline, item['item_id'])
    need(actor['signer_id'] in audience,
         'RECEIVER_NOT_IN_EC345_CHALLENGE_AUDIENCE')
    for key in ('copy_snapshot_file', 'copy_ack_set_file'):
        need(type(claim.get(key)) is str,
             'MEASURED_COPY_PATHS_ARE_MANDATORY')
    rotation._paths(claim['copy_snapshot_file'], claim['copy_ack_set_file'],
                    item['snapshot_file'], item['ack_set_file'])
    need(all(ceremony._sha(claim.get(k)) for k in (
        'copy_snapshot_original_raw_sha256', 'copy_ack_set_original_raw_sha256')) and
        all(type(claim.get(k)) is int and 0 < claim[k] <= MAX_COPY_BYTES for k in (
            'copy_snapshot_byte_length', 'copy_ack_set_byte_length')) and
        type(claim.get('copy_bytes_match_delivered_source')) is bool,
        'MEASURED_COPY_HASHES_LENGTHS_AND_MATCH_FLAG_REQUIRED')
    match = (claim['copy_snapshot_original_raw_sha256'] == item['expected_snapshot_sha256'] and
             claim['copy_ack_set_original_raw_sha256'] == item['expected_ack_set_sha256'])
    need(claim['copy_bytes_match_delivered_source'] is match,
         'MATCH_FLAG_MUST_BE_DERIVED_FROM_ACTUAL_SIGNED_HASHES')
    if claim['sequence'] == 1:
        need(claim['event_kind'] == RECEIPT and
             claim.get('previous_event_file') is None and
             claim.get('previous_event_original_raw_sha256') is None and
             claim.get('bytes_measured_this_event') is True,
             'FIRST_EVENT_MUST_BE_MEASURED_RECEIPT')
        history: list[tuple[str, dict]] = []
    else:
        need(claim['event_kind'] in (REPLACEMENT, REVOCATION) and
             claim.get('bytes_measured_this_event') is (claim['event_kind'] == REPLACEMENT) and
             ceremony._sha(claim.get('previous_event_original_raw_sha256')) and
             type(claim.get('previous_event_file')) is str and
             path != claim['previous_event_file'],
             'SUCCESSOR_NEEDS_SIGNED_PREVIOUS_EVENT_AND_KIND')
        parent, history = _load_event(
            claim['previous_event_file'], claim['previous_event_original_raw_sha256'],
            r=r, item=item, baseline=baseline, pins=pins)
        need(_context(parent) == _context(claim) and
             parent['sequence'] + 1 == claim['sequence'] and
             parent['event_kind'] != REVOCATION and
             old._time(parent['reported_utc']) <= old._time(claim['reported_utc']) and
             all(oldrow['event_nonce_sha256'] != claim['event_nonce_sha256']
                 for _, oldrow in history),
             'EXACT_CONTIGUOUS_NONREVOKED_SAME_RECEIVER_EVENT_CHAIN_REQUIRED')
        if claim['event_kind'] == REVOCATION:
            need(all(claim[k] == parent[k] for k in (
                'copy_snapshot_file', 'copy_snapshot_original_raw_sha256',
                'copy_snapshot_byte_length', 'copy_ack_set_file',
                'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length')),
                'REVOCATION_ONLY_REFERENCES_PREVIOUS_MEASURED_COPY_NO_NEW_BYTES')
    prior._signed(doc, EVENT_SCHEMA, EVENT_DOMAIN,
                  actor['public_hex'], 'EC346_RECEIVER_COPY_EVENT')
    return claim, [*history, (sha, claim)]


def _ec345_nonces(baseline: dict) -> set[str]:
    """EC346 nonces are never reused across any pinned EC345 request or reply."""
    used = set()
    for paths, shas, field in (
        ('challenge_files', 'challenge_shas', 'challenge_nonce_sha256'),
        ('response_files', 'response_shas', 'response_nonce_sha256'),
    ):
        for path, sha in zip(baseline[paths], baseline[shas], strict=True):
            claim = prior.read(path, sha, 'EC346_PINNED_PREVIOUS_NONCE')['claim']
            used.add(claim[field])
    return used


def _audience(baseline: dict, item_id: str) -> set[str]:
    """Signed EC345 challenge audience is re-read, not inferred from directory."""
    audience: set[str] = set()
    for path, sha in zip(baseline['challenge_files'], baseline['challenge_shas'], strict=True):
        doc = prior.read(path, sha, 'EC346_PINNED_CHALLENGE_AUDIENCE')
        if doc['claim']['target_item_id'] == item_id:
            audience.update(doc['claim']['audience_receiver_ids'])
    return audience


def _event_claim(*, r: dict, actor: dict, item: dict, baseline: dict,
                 copy_id: str, claimed_storage_id: str, event_kind: str,
                 sequence: int, previous_event_file: str | None,
                 previous_event_sha: str | None, copy_fields: dict,
                 event_nonce_sha256: str, reported_utc: str) -> dict:
    return {'schema': CLAIM_SCHEMA, 'case_id': r['case_id'],
            **_basis_claim(baseline), **_source_fields(item), **_actor_fields(actor),
            'copy_id': copy_id, 'claimed_storage_id': claimed_storage_id,
            'event_kind': event_kind, 'sequence': sequence,
            'previous_event_file': previous_event_file,
            'previous_event_original_raw_sha256': previous_event_sha,
            **copy_fields,
            'bytes_measured_this_event': event_kind != REVOCATION,
            'copy_bytes_match_delivered_source': _matching(copy_fields, item),
            'event_nonce_sha256': event_nonce_sha256, 'reported_utc': reported_utc,
            'scope': 'receiver_claim_about_measured_local_bytes_only',
            'no_remote_transfer_revocation_or_winner_authority': True}


def sign_observation(*, out: str, private_key_file: str, item_id: str,
                     copy_id: str, claimed_storage_id: str, event_kind: str,
                     sequence: int, event_nonce_sha256: str, reported_utc: str,
                     copy_snapshot_file: str | None = None,
                     copy_ack_set_file: str | None = None,
                     previous_event_file: str | None = None,
                     expected_previous_event_sha256: str | None = None,
                     **baseline) -> dict:
    r, item, _, _, pins = _basis(item_id, baseline)
    need(ceremony._id(copy_id) and ceremony._id(claimed_storage_id) and
         event_kind in KINDS and type(sequence) is int and
         1 <= sequence <= MAX_EVENTS_PER_RECEIVER and
         ceremony._sha(event_nonce_sha256) and ceremony._utc(reported_utc) and
         old._time(reported_utc) >=
             old._time(baseline['disclosure_evaluation_utc']),
         'EVENT_ARGS_AND_SELF_REPORTED_TIME_INVALID')
    key, pub = rotation._private_key_public(private_key_file)
    actors = [a for a in r['receivers'] if prior.same(a['public_hex'], pub)]
    need(len(actors) == 1, 'ONLY_EC343_REGISTERED_RECEIVER_CAN_SIGN', 'permission_denied')
    actor = actors[0]
    need(actor['signer_id'] in _audience(baseline, item_id),
         'RECEIVER_MUST_BE_LISTED_IN_REAL_EC345_CHALLENGE_AUDIENCE',
         'permission_denied')
    if sequence == 1:
        need(event_kind == RECEIPT and previous_event_file is None and
             expected_previous_event_sha256 is None,
             'FIRST_EVENT_CANNOT_REPLACE_OR_REVOKE')
        parent = None
    else:
        need(event_kind in (REPLACEMENT, REVOCATION) and
             previous_event_file is not None and
             expected_previous_event_sha256 is not None,
             'SUCCESSOR_MUST_PIN_REAL_PREDECESSOR')
        parent, _ = _load_event(previous_event_file,
            expected_previous_event_sha256, r=r, item=item,
            baseline=baseline, pins=pins)
        need(parent['receiver_id'] == actor['signer_id'] and
             parent['copy_id'] == copy_id and
             parent['claimed_storage_id'] == claimed_storage_id and
             parent['sequence'] + 1 == sequence and
             parent['event_kind'] != REVOCATION and
             old._time(parent['reported_utc']) <= old._time(reported_utc),
             'SUCCESSOR_MUST_MATCH_OWN_NONREVOKED_SAME_COPY_CHAIN')
    if event_kind == REVOCATION:
        need(copy_snapshot_file is None and copy_ack_set_file is None and
             parent is not None,
             'REVOCATION_IS_CLAIM_ONLY_WITHOUT_NEW_COPY_READ')
        fields = {k: parent[k] for k in (
            'copy_snapshot_file', 'copy_snapshot_original_raw_sha256',
            'copy_snapshot_byte_length', 'copy_ack_set_file',
            'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length')}
    else:
        need(copy_snapshot_file is not None and copy_ack_set_file is not None,
             'MEASURED_RECEIPT_OR_REPLACEMENT_REQUIRES_TWO_COPY_FILES')
        fields = _copy_fields(copy_snapshot_file, copy_ack_set_file,
                              allow_source=(item['snapshot_file'], item['ack_set_file']))
        need(not ({copy_snapshot_file, copy_ack_set_file} & set(pins)),
             'MEASURED_COPY_CANNOT_ALIAS_ANY_PINNED_SOURCE_EVIDENCE')
        for path, sha in ((copy_snapshot_file, fields['copy_snapshot_original_raw_sha256']),
                          (copy_ack_set_file, fields['copy_ack_set_original_raw_sha256'])):
            prior.pin(pins, path, sha)
    claim = _event_claim(r=r, actor=actor, item=item, baseline=baseline,
        copy_id=copy_id, claimed_storage_id=claimed_storage_id,
        event_kind=event_kind, sequence=sequence,
        previous_event_file=previous_event_file,
        previous_event_sha=expected_previous_event_sha256,
        copy_fields=fields, event_nonce_sha256=event_nonce_sha256,
        reported_utc=reported_utc)
    need(event_nonce_sha256 not in _ec345_nonces(baseline),
         'EC346_EVENT_NONCE_MUST_NOT_REUSE_EC345_NONCE')
    if parent is not None:
        _, history = _load_event(previous_event_file, expected_previous_event_sha256,
            r=r, item=item, baseline=baseline, pins=pins)
        need(all(oldrow['event_nonce_sha256'] != event_nonce_sha256 for _, oldrow in history),
             'EVENT_NONCE_MUST_NOT_REPEAT_PREVIOUS_SIGNED_CHAIN')
    need(out not in {item['snapshot_file'], item['ack_set_file'],
                     fields['copy_snapshot_file'], fields['copy_ack_set_file']},
         'SIGNATURE_OUTPUT_MUST_NOT_OVERWRITE_SOURCE_OR_DESTINATION')
    doc = {'schema': EVENT_SCHEMA, 'claim': claim,
           'signature_ed25519': key.sign(EVENT_DOMAIN + reg.canonical(claim)).hex()}
    return _candidate('sign-observation', prior._write(out, doc, pins, private_key_file))


def audit_copies(*, item_id: str, custody_evaluation_utc: str,
                 observation_files: list[str], observation_shas: list[str],
                 presented_receiver_ids: list[str],
                 presented_snapshot_files: list[str],
                 presented_ack_set_files: list[str], **baseline) -> dict:
    """Replay whole signed history; only caller-named destination paths are opened."""
    need(ceremony._utc(custody_evaluation_utc) and
         old._time(custody_evaluation_utc) >=
             old._time(baseline['disclosure_evaluation_utc']),
         'CUSTODY_EVALUATION_UTC_MUST_FOLLOW_DISCLOSURE')
    need(type(observation_files) is list and type(observation_shas) is list and
         2 <= len(observation_files) <= MAX_EVENTS and
         len(observation_files) == len(observation_shas) and
         len(set(observation_files)) == len(observation_files) and
         type(presented_receiver_ids) is list and
         type(presented_snapshot_files) is list and
         type(presented_ack_set_files) is list and
         0 <= len(presented_receiver_ids) <= prior.MAX_RECEIVERS and
         len(presented_receiver_ids) == len(presented_snapshot_files) ==
             len(presented_ack_set_files) and
         len(set(presented_receiver_ids)) == len(presented_receiver_ids),
         'BOUNDED_ORIGINAL_EVENTS_AND_EXPLICIT_PRESENTATION_PAIRS_REQUIRED')
    r, item, audit, _, pins = _basis(item_id, baseline)
    receivers = [a['signer_id'] for a in r['receivers']]
    claims: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
    nonces = _ec345_nonces(baseline)
    already = set()
    for path, sha in zip(observation_files, observation_shas, strict=True):
        need(path not in set(baseline['challenge_files']+baseline['response_files']+
                             baseline['view_files']),
             'SIGNED_EVENT_CANNOT_ALIAS_EC345_OR_EC344_INPUT')
        claim, chain = _load_event(path, sha, r=r, item=item,
                                   baseline=baseline, pins=pins)
        signer = claim['receiver_id']
        previous_event = claims[signer][-1] if claims[signer] else None
        need((previous_event is None and claim['sequence'] == 1) or
             (previous_event is not None and
              claim['sequence'] == previous_event[2]['sequence']+1 and
              claim['previous_event_file'] == previous_event[0] and
              claim['previous_event_original_raw_sha256'] == previous_event[1]),
             'ALL_SIGNED_PREDECESSOR_EVENTS_MUST_BE_EXPLICITLY_PRESENTED')
        need(len(claims[signer]) < MAX_EVENTS_PER_RECEIVER and
             claim['event_nonce_sha256'] not in nonces and sha not in already and
             old._time(claim['reported_utc']) <= old._time(custody_evaluation_utc),
             'REUSED_NONCE_DUPLICATE_EVENT_OR_FUTURE_SIGNED_TIME')
        nonces.add(claim['event_nonce_sha256']); already.add(sha)
        claims[signer].append((path, sha, claim))
    need(2 <= len(claims) <= prior.MAX_RECEIVERS,
         'AT_LEAST_TWO_DISTINCT_EC343_RECEIVER_SIGNATURES_REQUIRED')
    expected_order = [(receivers.index(signer), seq[2]['sequence'])
                      for path, sha in zip(observation_files, observation_shas, strict=True)
                      for signer, seqs in claims.items() for seq in seqs if seq[0] == path]
    need(expected_order == sorted(expected_order) and
         len(expected_order) == len(observation_files),
         'EVENTS_MUST_BE_GROUPED_BY_REGISTERED_RECEIVER_AND_SEQUENCE')
    need(all(signer in claims for signer in presented_receiver_ids) and
         presented_receiver_ids == [s for s in receivers if s in presented_receiver_ids],
         'PRESENTED_RECEIVERS_MUST_BE_UNIQUE_REGISTERED_CANONICAL_ORDER')
    provided = dict(zip(presented_receiver_ids,
        zip(presented_snapshot_files, presented_ack_set_files, strict=True), strict=True))
    need(all(pair[0] != pair[1] for pair in provided.values()),
         'PRESENTED_COPY_PATH_PAIR_MUST_BE_DISTINCT')
    # The path is *both* a user explicitly presented input and the latest
    # signed file reference. There is no implicit opening of signed missing paths.
    presented_paths = [path for pair in provided.values() for path in pair]
    need(len(set(presented_paths)) == len(presented_paths) and
         not (set(presented_paths) & set(pins)),
         'PRESENTED_COPY_CANNOT_ALIAS_SOURCE_OR_SIGNED_EVIDENCE')
    rows = []
    for signer in receivers:
        if signer not in claims:
            continue
        history = claims[signer]
        last_path, last_sha, latest = history[-1]
        path_pair = (latest['copy_snapshot_file'], latest['copy_ack_set_file'])
        signed_match = latest['copy_bytes_match_delivered_source']
        presented = signer in provided
        measured = None
        if presented:
            need(provided[signer] == path_pair,
                 'EXPLICIT_COPY_PATHS_MUST_MATCH_LATEST_SIGNED_OBSERVATION')
            copy = _copy_fields(*path_pair,
                      allow_source=(item['snapshot_file'],item['ack_set_file']))
            for path, sha in ((path_pair[0], copy['copy_snapshot_original_raw_sha256']),
                              (path_pair[1], copy['copy_ack_set_original_raw_sha256'])):
                prior.pin(pins, path, sha)
            matches_signed = all(copy[k] == latest[k] for k in (
                'copy_snapshot_original_raw_sha256', 'copy_snapshot_byte_length',
                'copy_ack_set_original_raw_sha256', 'copy_ack_set_byte_length'))
            matches_source = _matching(copy, item)
            outcome = ('presented_copy_changed_since_signed_observation' if not matches_signed
                       else 'presented_copy_matches_verified_source' if matches_source
                       else 'presented_copy_differs_from_verified_source')
            measured = {
                'snapshot_original_raw_sha256': copy['copy_snapshot_original_raw_sha256'],
                'ack_set_original_raw_sha256': copy['copy_ack_set_original_raw_sha256'],
                'snapshot_byte_length': copy['copy_snapshot_byte_length'],
                'ack_set_byte_length': copy['copy_ack_set_byte_length'],
                'matches_signed_observation': matches_signed,
                'matches_verified_disclosed_source': matches_source,
            }
        else:
            outcome = 'signed_copy_not_presented_in_this_audit'
        rows.append({
            'receiver_id': signer, 'receiver_organization_id': latest['receiver_organization_id'],
            'copy_id': latest['copy_id'], 'claimed_storage_id': latest['claimed_storage_id'],
            'signed_event_count': len(history),
            'signed_event_original_raw_sha256s': [e[1] for e in history],
            'signed_event_kinds': [e[2]['event_kind'] for e in history],
            'signed_event_history': [{
                'sequence': e[2]['sequence'],
                'event_original_raw_sha256': e[1],
                'event_kind': e[2]['event_kind'],
                'previous_event_original_raw_sha256':
                    e[2]['previous_event_original_raw_sha256'],
                'reported_utc': e[2]['reported_utc'],
                'copy_snapshot_original_raw_sha256':
                    e[2]['copy_snapshot_original_raw_sha256'],
                'copy_ack_set_original_raw_sha256':
                    e[2]['copy_ack_set_original_raw_sha256'],
                'copy_bytes_match_delivered_source':
                    e[2]['copy_bytes_match_delivered_source'],
                'bytes_measured_this_event':
                    e[2]['bytes_measured_this_event'],
            } for e in history],
            'latest_reported_utc': latest['reported_utc'],
            'latest_event_kind': latest['event_kind'],
            'latest_copy_snapshot_original_raw_sha256':
                latest['copy_snapshot_original_raw_sha256'],
            'latest_copy_ack_set_original_raw_sha256':
                latest['copy_ack_set_original_raw_sha256'],
            'latest_signed_copy_matches_source': signed_match,
            'copy_explicitly_presented': presented,
            'presented_copy_measurement': measured,
            'copy_outcome': outcome,
            'revocation_is_claim_only_not_physical_deletion':
                latest['event_kind'] == REVOCATION,
            'replacement_is_claim_only_not_change_to_prior_original':
                REPLACEMENT in [e[2]['event_kind'] for e in history],
        })
    need(len(rows) >= 2, 'TWO_REAL_SIGNED_RECEIVER_COPIES_REQUIRED')
    prior.late(pins)
    differences = [[a['receiver_id'], b['receiver_id']]
        for i, a in enumerate(rows) for b in rows[i+1:]
        if (a['latest_copy_snapshot_original_raw_sha256'],
            a['latest_copy_ack_set_original_raw_sha256']) !=
           (b['latest_copy_snapshot_original_raw_sha256'],
            b['latest_copy_ack_set_original_raw_sha256'])]
    claimed_storage_label_collisions = [[a['receiver_id'], b['receiver_id']]
        for i, a in enumerate(rows) for b in rows[i+1:]
        if a['claimed_storage_id'] == b['claimed_storage_id']]
    present_differences = [[a['receiver_id'], b['receiver_id']]
        for i, a in enumerate(rows) for b in rows[i+1:]
        if a['presented_copy_measurement'] is not None and
           b['presented_copy_measurement'] is not None and
           (a['presented_copy_measurement']['snapshot_original_raw_sha256'],
            a['presented_copy_measurement']['ack_set_original_raw_sha256']) !=
           (b['presented_copy_measurement']['snapshot_original_raw_sha256'],
            b['presented_copy_measurement']['ack_set_original_raw_sha256'])]
    counts = {outcome: sum(x['copy_outcome'] == outcome for x in rows)
              for outcome in OUTCOMES}
    status = (STATUSES[0] if counts[OUTCOMES[0]] else
        STATUSES[1] if counts[OUTCOMES[1]] else
        STATUSES[2] if any(x['latest_event_kind'] != RECEIPT for x in rows) else
        STATUSES[3] if counts[OUTCOMES[2]] else STATUSES[4])
    return {
        'schema': RESULT_SCHEMA, 'command': 'audit-copies',
        'status': status, 'exit_code': 2, 'case_id': r['case_id'],
        'target_item_id': item_id, 'target_slot_id': item['slot_id'],
        'source_snapshot_original_raw_sha256': item['expected_snapshot_sha256'],
        'source_ack_set_original_raw_sha256': item['expected_ack_set_sha256'],
        'ec343_roster_original_raw_sha256': baseline['expected_roster_sha256'],
        'ec344_checkpoint_original_raw_sha256': baseline['expected_checkpoint_sha256'],
        'ec345_full_audit_arguments_canonical_sha256': case.sha(reg.canonical(baseline)),
        'ec345_signed_challenge_original_raw_sha256s': baseline['challenge_shas'],
        'ec345_signed_response_original_raw_sha256s': baseline['response_shas'],
        'disclosure_evaluation_utc': baseline['disclosure_evaluation_utc'],
        'custody_evaluation_utc': custody_evaluation_utc,
        'verified_disclosed_source_replayed_ec345_through_ec337': True,
        'distinct_registered_receiver_signatures': len(rows),
        'signed_event_count': len(observation_files),
        'explicitly_presented_copy_count': len(provided),
        'receiver_copies': rows, 'copy_outcome_counts': counts,
        'signed_copy_sha_difference_receiver_pairs': differences,
        'explicitly_measured_copy_sha_difference_receiver_pairs': present_differences,
        'claimed_storage_ids_are_unverified_labels_only': True,
        'same_claimed_storage_label_receiver_pairs': claimed_storage_label_collisions,
        'revocation_and_replacement_are_not_remote_side_effects': True,
        'offline_unresolved_exit_code': 2,
        **{key: False for key in NEGATIVES},
    }

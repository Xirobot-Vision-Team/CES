#!/usr/bin/env python3
"""EC328 offline *multi-receipt* audit for an unchanged EC326 conflict.

The ledger is UNSIGNED and is not a remote append-only log. An independently
trusted whole-file SHA must pin it and (for extensions) its previous snapshot.
Every listed EC327 statement is separately SHA-pinned and Ed25519-verified.
Only a signed offline opinion is observable; ordering, actual nonexecution,
remote CAS status, institutional authorization and global completeness are not.

No remote API, signer, private key or business writer exists in this module.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt as r
from conditional_conflict_hold import hold
from offline_hold_disposition import disposition as ninth

DRAFT_SCHEMA = 'ces.ec328.offline_nonexecution_review_draft.v1'
LEDGER_SCHEMA = 'ces.ec328.offline_nonexecution_review_ledger.v1'
RESULT_SCHEMA = 'ces.ec328.offline_nonexecution_review_ledger_verification.v1'
DENIAL_SCHEMA = 'ces.ec328.offline_nonexecution_review_ledger_denial.v1'
ENTRY_DOMAIN = b'CES/EC328/OfflineReviewEntry/v1\0'
ZERO = '0' * 64
MAX_ENTRIES = 16
MAX_DRAFT_BYTES = 48_000
MAX_LEDGER_BYTES = 56_000
META_FIELDS = frozenset({
    'signed_request_original_raw_sha256', 'dispute_case_original_raw_sha256',
    'registry_id', 'sequence', 'expected_remote_parent_original_raw_sha256',
    'two_competing_heads_original_raw_sha256', 'target_store_namespace_id',
    'previous_ledger_original_raw_sha256',
})
ENTRY_FIELDS = frozenset({
    'position', 'receipt_file', 'receipt_original_raw_sha256', 'decision_id',
    'ninth_responder_id', 'ninth_responder_public_hex',
    'response_challenge_sha256', 'disposition', 'reason_code',
})
LINK_FIELDS = frozenset({'previous_entry_commitment_sha256',
                         'entry_commitment_sha256'})
DRAFT_FIELDS = META_FIELDS | {'schema', 'entries'}
LEDGER_FIELDS = DRAFT_FIELDS | {'ledger_head_entry_commitment_sha256',
    'external_store_write_or_actual_nonexecution_proven',
    'remote_global_latest_or_winner_proven',
    'organizational_identity_or_complete_global_history_proven'}
EXPLICIT_FALSE_FIELDS = (
    'external_store_write_or_actual_nonexecution_proven',
    'remote_global_latest_or_winner_proven',
    'organizational_identity_or_complete_global_history_proven',
)


def need(ok: Any, code: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC328_' + code, status)


def _entry_hash(entry: dict) -> str:
    """Locally computed link, not a signature or external timestamp."""
    plain = {key: value for key, value in entry.items()
             if key != 'entry_commitment_sha256'}
    return hashlib.sha256(ENTRY_DOMAIN + r._raw(plain)).hexdigest()


def _validate_meta(doc: dict) -> None:
    need(r._sha(doc['signed_request_original_raw_sha256']) and
         r._sha(doc['dispute_case_original_raw_sha256']) and
         r._id(doc['registry_id']) and
         type(doc['sequence']) is int and 1 <= doc['sequence'] <= 16 and
         r._sha(doc['expected_remote_parent_original_raw_sha256'], allow_zero=True) and
         (doc['sequence'] == 1) ==
             (doc['expected_remote_parent_original_raw_sha256'] == ZERO) and
         type(doc['two_competing_heads_original_raw_sha256']) is list and
         len(doc['two_competing_heads_original_raw_sha256']) == 2 and
         all(r._sha(v) for v in doc['two_competing_heads_original_raw_sha256']) and
         doc['two_competing_heads_original_raw_sha256'] ==
             sorted(set(doc['two_competing_heads_original_raw_sha256'])) and
         r._id(doc['target_store_namespace_id']) and
         r._sha(doc['previous_ledger_original_raw_sha256'], allow_zero=True),
         'LEDGER_BOUND_REQUEST_PARENT_TWO_HEADS_OR_NAMESPACE_INVALID',
         'invalid_input')


def _validate_entries(entries: Any, *, linked: bool) -> list[dict]:
    need(type(entries) is list and 1 <= len(entries) <= MAX_ENTRIES,
         'BOUNDED_NONEMPTY_REVIEW_ENTRIES_REQUIRED', 'invalid_input')
    paths: set[str] = set()
    signatures: set[str] = set()
    decisions: set[str] = set()
    ids: set[str] = set()
    pubs: set[str] = set()
    nonces: set[str] = set()
    prev = ZERO
    for position, row in enumerate(entries, 1):
        anchor.exact(row, ENTRY_FIELDS | (LINK_FIELDS if linked else frozenset()),
                     'EC328_EXACT_REVIEW_ENTRY_FIELDS')
        need(type(row['position']) is int and row['position'] == position and
             case.original._valid_path(row['receipt_file']) and
             r._sha(row['receipt_original_raw_sha256']) and
             r._id(row['decision_id']) and
             r._id(row['ninth_responder_id']) and
             anchor.valid_pub(row['ninth_responder_public_hex']) and
             r._sha(row['response_challenge_sha256']) and
             type(row['disposition']) is str and
             row['disposition'] in ninth.DISPOSITIONS and
             type(row['reason_code']) is str and
             row['reason_code'] in ninth.REASON_CODES,
             'REVIEW_ROW_MISSING_EXTERNAL_RAW_SHA_SIGNER_AND_DECISION_TRUST',
             'invalid_input')
        # A repeated public key or nonce cannot be presented as a new
        # independent signer or new review. Distinct opinions require distinct
        # evidence; no implicit deduplication or "last write wins".
        need(row['receipt_file'] not in paths and
             row['receipt_original_raw_sha256'] not in signatures and
             row['decision_id'] not in decisions and
             row['ninth_responder_id'] not in ids and
             row['ninth_responder_public_hex'] not in pubs and
             row['response_challenge_sha256'] not in nonces,
             'DUPLICATE_RECEIPT_ROLE_DECISION_OR_CHALLENGE_ACROSS_REVIEWS',
             'invalid_input')
        paths.add(row['receipt_file'])
        signatures.add(row['receipt_original_raw_sha256'])
        decisions.add(row['decision_id'])
        ids.add(row['ninth_responder_id'])
        pubs.add(row['ninth_responder_public_hex'])
        nonces.add(row['response_challenge_sha256'])
        if linked:
            need(row['previous_entry_commitment_sha256'] == prev and
                 r._sha(row['entry_commitment_sha256']) and
                 hmac.compare_digest(row['entry_commitment_sha256'],
                                     _entry_hash(row)),
                 'REVIEW_ENTRY_CHAIN_LINK_OR_DOMAIN_HASH_INVALID',
                 'invalid_input')
            prev = row['entry_commitment_sha256']
    return entries


def prepare_unsigned_ledger(*, draft_file: str, out: str) -> dict:
    """Produce a local UNTRUSTED unsigned candidate; never attest its contents.

    The draft may contain operator-selected key/identities. The candidate is
    not admissible until an independent authority pins its complete original
    SHA and actual verification later checks each signature + originals.
    """
    need(case.original._valid_path(draft_file) and
         case.original._valid_path(out) and draft_file != out,
         'PRIVATE_DISTINCT_DRAFT_AND_OUTPUT_PATHS_REQUIRED', 'invalid_input')
    draft_raw = hold.reg._private_read(draft_file, MAX_DRAFT_BYTES,
                                       'EC328_UNSIGNED_DRAFT')
    draft = hold.io.parse(draft_raw, MAX_DRAFT_BYTES)
    need(hmac.compare_digest(draft_raw, r._raw(draft)),
         'UNSIGNED_DRAFT_MUST_BE_CANONICAL_LF_JSON', 'invalid_input')
    anchor.exact(draft, DRAFT_FIELDS, 'EC328_EXACT_DRAFT_FIELDS')
    need(draft['schema'] == DRAFT_SCHEMA, 'DRAFT_SCHEMA_INVALID', 'invalid_input')
    _validate_meta(draft)
    _validate_entries(draft['entries'], linked=False)
    entries = []
    previous = ZERO
    for row in draft['entries']:
        next_row = {**row, 'previous_entry_commitment_sha256': previous}
        next_row['entry_commitment_sha256'] = _entry_hash(next_row)
        previous = next_row['entry_commitment_sha256']
        entries.append(next_row)
    doc = {'schema': LEDGER_SCHEMA, **{k: draft[k] for k in META_FIELDS},
           'entries': entries, 'ledger_head_entry_commitment_sha256': previous,
           **{key: False for key in EXPLICIT_FALSE_FIELDS}}
    _validate_ledger(doc)
    raw = r._raw(doc)
    need(len(raw) <= MAX_LEDGER_BYTES, 'LEDGER_EXCEEDS_BYTE_BUDGET', 'invalid_input')
    need(out not in {row['receipt_file'] for row in entries},
         'OUTPUT_CANNOT_OVERWRITE_SIGNED_ORIGINAL', 'invalid_input')
    r._write_exclusive(out, raw)
    return {
        'status': 'unsigned_candidate_only_independent_whole_sha_pin_still_required',
        'exit_code': 2,
        'candidate_ledger_original_raw_sha256': case.sha(raw),
        'review_count': len(entries),
        'ledger_head_entry_commitment_sha256': previous,
        'all_signatures_or_original_histories_verified': False,
        'independent_ledger_sha_trust_established': False,
        **{key: False for key in EXPLICIT_FALSE_FIELDS},
        'business_or_external_store_writes_performed': False,
    }


def _validate_ledger(doc: Any) -> dict:
    anchor.exact(doc, LEDGER_FIELDS, 'EC328_EXACT_LEDGER_FIELDS')
    need(doc['schema'] == LEDGER_SCHEMA and
         all(doc[key] is False for key in EXPLICIT_FALSE_FIELDS),
         'LEDGER_CANNOT_ASSERT_EXTERNAL_SUCCESS_NONEXECUTION_OR_AUTHORITY',
         'invalid_input')
    _validate_meta(doc)
    _validate_entries(doc['entries'], linked=True)
    need(doc['ledger_head_entry_commitment_sha256'] ==
         doc['entries'][-1]['entry_commitment_sha256'],
         'HEAD_COMMITMENT_MUST_EQUAL_LAST_ENTRY', 'invalid_input')
    return doc


def _verify_incremental_append(*, current: dict, expected_prior_sha: str,
                               prior_file: str | None,
                               forbidden_paths: set[str]) -> None:
    prior_sha = current['previous_ledger_original_raw_sha256']
    need(r._sha(expected_prior_sha, allow_zero=True) and
         prior_sha == expected_prior_sha,
         'INDEPENDENT_PRIOR_LEDGER_RAW_SHA_NOT_EQUAL_CURRENT_PARENT',
         'invalid_input')
    need((prior_sha == ZERO) == (prior_file is None),
         'PRIOR_LEDGER_WHOLE_ORIGINAL_REQUIRED_FOR_NON_GENESIS',
         'invalid_input')
    if prior_file is None:
        return
    need(case.original._valid_path(prior_file) and
         prior_file not in forbidden_paths,
         'PRIOR_LEDGER_MUST_BE_DISTINCT_NORMALIZED_PRIVATE_ORIGINAL',
         'invalid_input')
    prior, _ = r._load(prior_file, prior_sha, MAX_LEDGER_BYTES,
                       'EC328_INDEPENDENT_PRIOR_LEDGER')
    _validate_ledger(prior)
    need(all(prior[k] == current[k] for k in META_FIELDS
             if k != 'previous_ledger_original_raw_sha256') and
         len(current['entries']) == len(prior['entries']) + 1 and
         current['entries'][:-1] == prior['entries'] and
         current['entries'][-1]['previous_entry_commitment_sha256'] ==
             prior['ledger_head_entry_commitment_sha256'],
         'CURRENT_LEDGER_NOT_AN_EXACT_SINGLE_ENTRY_APPEND_TO_PREDECESSOR',
         'invalid_input')


def verify_ledger(*, ledger_file: str, expected_ledger_sha256: str,
                  request_file: str, expected_request_sha256: str,
                  case_file: str, expected_case_sha256: str,
                  left: dict, right: dict, registry_id: str,
                  expected_sequence: int, expected_prior_registry_sha256: str,
                  request_id: str, target_store_namespace_id: str,
                  eighth_signer_id: str, eighth_signer_public_hex: str,
                  request_challenge_sha256: str,
                  prior_registry_file: str | None = None,
                  prior_ledger_file: str | None = None,
                  expected_prior_ledger_sha256: str = ZERO) -> dict:
    """Read only: genuine ninth signatures for EVERY row + full original replay.

    The final (newest in locally declared order, NOT trusted time) receipt goes
    through production EC327 -> EC326 -> two EC325 -> EC294, while all other
    receipts receive the same strict standalone EC327 claim/signature/trust
    checks and cross-history role challenges. Recheck every raw pin at exit.
    """
    hold._file_args(request_file=request_file, out=None, private_key_file=None,
                    case_file=case_file, prior_registry_file=prior_registry_file,
                    left=left, right=right)
    original_paths = {request_file, case_file}
    if prior_registry_file is not None:
        original_paths.add(prior_registry_file)
    for side in (left, right):
        original_paths.update(side[k] for k in (
            'registry_file', 'capsule_file', 'origin_file', 'recipient_file'))
    need(case.original._valid_path(ledger_file) and
         ledger_file not in original_paths and
         r._sha(expected_ledger_sha256) and
         r._sha(expected_request_sha256),
         'SEPARATE_PRIVATE_LEDGER_AND_BOTH_INDEPENDENT_WHOLE_SHA_PINS_REQUIRED',
         'invalid_input')
    ledger, _ = r._load(ledger_file, expected_ledger_sha256, MAX_LEDGER_BYTES,
                        'EC328_EXTERNALLY_PINNED_REVIEW_LEDGER')
    _validate_ledger(ledger)
    needed = {
        'signed_request_original_raw_sha256': expected_request_sha256,
        'dispute_case_original_raw_sha256': expected_case_sha256,
        'registry_id': registry_id, 'sequence': expected_sequence,
        'expected_remote_parent_original_raw_sha256': expected_prior_registry_sha256,
        'two_competing_heads_original_raw_sha256': sorted((
            left['expected_registry_sha256'], right['expected_registry_sha256'])),
        'target_store_namespace_id': target_store_namespace_id,
    }
    need(all(ledger[k] == v for k, v in needed.items()),
         'LEDGER_NOT_EQUAL_INDEPENDENT_EIGHTH_REQUEST_PARENT_AND_BOTH_HEADS',
         'invalid_input')
    receipt_paths = {e['receipt_file'] for e in ledger['entries']}
    need(not receipt_paths.intersection(original_paths | {ledger_file}) and
         (prior_ledger_file is None or prior_ledger_file not in receipt_paths),
         'LEDGER_INPUT_PATH_ALIASES_ANOTHER_SIGNED_ORIGINAL', 'invalid_input')
    _verify_incremental_append(current=ledger,
         expected_prior_sha=expected_prior_ledger_sha256,
         prior_file=prior_ledger_file,
         forbidden_paths=original_paths | receipt_paths | {ledger_file})
    # Independently pinned manifest, not the receipt itself, supplies all
    # ninth ID/public key/challenge/decision/disposition/reason trust choices.
    # Validate the EC326 eighth signature BEFORE long original signed replay.
    request, _ = r._load(request_file, expected_request_sha256,
                          hold.MAX_REQUEST_BYTES, 'EC328_EIGHTH_REQUEST')
    actor = hold._actor(request_id=request_id,
         target_store_namespace_id=target_store_namespace_id,
         eighth_signer_id=eighth_signer_id,
         eighth_signer_public_hex=eighth_signer_public_hex,
         request_challenge_sha256=request_challenge_sha256)
    signed_request = hold._signature(request, eighth_signer_public_hex)
    need(all(signed_request[k] == v for k,v in actor.items()) and
         all(signed_request[k] == v for k,v in needed.items()
             if k != 'signed_request_original_raw_sha256' and
                k != 'two_competing_heads_original_raw_sha256') and
         signed_request['proposed_competing_child_raw_sha256'] ==
             needed['two_competing_heads_original_raw_sha256'],
         'EIGHTH_SIGNATURE_AND_LEDGER_REQUEST_SCOPE_DISAGREE',
         'invalid_input')
    binding = ninth._binding_from_request(signed_request, expected_request_sha256)
    rows = ledger['entries']
    for row in rows:
        ninth_trust = ninth._trust(
            decision_id=row['decision_id'],
            ninth_responder_id=row['ninth_responder_id'],
            ninth_responder_public_hex=row['ninth_responder_public_hex'],
            response_challenge_sha256=row['response_challenge_sha256'],
            expected_disposition=row['disposition'],
            expected_reason_code=row['reason_code'])
        need(row['decision_id'] != request_id and
             row['ninth_responder_id'] != eighth_signer_id and
             row['ninth_responder_public_hex'] != eighth_signer_public_hex and
             row['response_challenge_sha256'] != request_challenge_sha256,
             'REVIEW_ROLE_DECISION_OR_CHALLENGE_REUSES_EIGHTH_REQUEST',
             'invalid_input')
        doc, _ = r._load(row['receipt_file'], row['receipt_original_raw_sha256'],
                         ninth.MAX_RECEIPT_BYTES,
                         'EC328_NINTH_SIGNED_OFFLINE_REVIEW')
        claim = ninth._verify_signed_receipt(doc, row['ninth_responder_public_hex'])
        need(all(claim[k] == value for k,value in
                 {**ninth_trust, **binding}.items()),
             'REVIEW_SIGNATURE_NOT_BOUND_TO_PINNED_LEDGER_AND_EIGHTH_REQUEST',
             'invalid_input')
    # EC327 performs the real two-branch full historical signed replay and
    # post-verification re-pinning. A fast-only signature check is inadequate.
    last = rows[-1]
    outcome = ninth.verify_nonexecution(
        receipt_file=last['receipt_file'],
        expected_receipt_sha256=last['receipt_original_raw_sha256'],
        request_file=request_file, expected_request_sha256=expected_request_sha256,
        case_file=case_file, expected_case_sha256=expected_case_sha256,
        left=left, right=right, registry_id=registry_id,
        expected_sequence=expected_sequence,
        expected_prior_registry_sha256=expected_prior_registry_sha256,
        prior_registry_file=prior_registry_file,
        request_id=request_id,
        target_store_namespace_id=target_store_namespace_id,
        eighth_signer_id=eighth_signer_id,
        eighth_signer_public_hex=eighth_signer_public_hex,
        request_challenge_sha256=request_challenge_sha256,
        decision_id=last['decision_id'],
        ninth_responder_id=last['ninth_responder_id'],
        ninth_responder_public_hex=last['ninth_responder_public_hex'],
        response_challenge_sha256=last['response_challenge_sha256'],
        expected_disposition=last['disposition'],
        expected_reason_code=last['reason_code'])
    need(outcome.get('exit_code') == 2 and
         outcome.get('status') ==
             'ninth_offline_nonexecution_statement_authentic_unresolved' and
         outcome.get('ninth_signature_eighth_signature_and_both_original_histories_verified') is True and
         all(outcome.get(k) is False for k in (
             'actual_external_nonexecution_hold_or_remote_head_proven',
             'external_atomic_cas_or_worm_write_performed',
             'remote_global_latest_or_child_winner_proven')),
         'PRODUCTION_EC327_AND_BOTH_GENUINE_ORIGINAL_HISTORIES_REQUIRED')
    historical_ids: set[str] = {eighth_signer_id, request_id}
    historical_pubs: set[str] = {eighth_signer_public_hex}
    historical_nonces: set[str] = {request_challenge_sha256,
        expected_request_sha256, expected_case_sha256,
        expected_prior_registry_sha256, expected_ledger_sha256,
        expected_prior_ledger_sha256, ledger['ledger_head_entry_commitment_sha256']}
    historical_nonces.update(e['receipt_original_raw_sha256'] for e in rows)
    historical_nonces.update(e['entry_commitment_sha256'] for e in rows)
    for side in (left, right):
        ids, pubs, nonces = hold._visible_roles_and_challenges(
            side=side, registry_id=registry_id,
            expected_sequence=expected_sequence,
            expected_prior_registry_sha256=expected_prior_registry_sha256)
        historical_ids.update(ids)
        historical_pubs.update(pubs)
        historical_nonces.update(nonces)
    historical_nonces.update((left['expected_registry_sha256'],
                              right['expected_registry_sha256']))
    for row in rows:
        need(row['decision_id'] not in historical_ids and
             row['ninth_responder_id'] not in historical_ids and
             row['ninth_responder_public_hex'] not in historical_pubs and
             row['response_challenge_sha256'] not in historical_nonces,
             'REVIEW_REUSES_VISIBLE_SIGNER_ID_ORIGINAL_SHA_OR_NONCE',
             'invalid_input')
    # Narrow the mutation window after all signatures, history reads and
    # cross-role comparisons. No unsigned earlier row can slip through. The
    # extra EC328 historical-role traversal runs AFTER EC327's last repin,
    # so it must finish with another read of the two signed original branches.
    for row in rows:
        r._load(row['receipt_file'], row['receipt_original_raw_sha256'],
                ninth.MAX_RECEIPT_BYTES, 'EC328_FINAL_SIGNED_RECEIPT_REPIN')
    r._load(ledger_file, expected_ledger_sha256, MAX_LEDGER_BYTES,
            'EC328_FINAL_SIGNED_LEDGER_REPIN')
    if prior_ledger_file is not None:
        r._load(prior_ledger_file, expected_prior_ledger_sha256,
                MAX_LEDGER_BYTES, 'EC328_FINAL_PRIOR_LEDGER_REPIN')
    r._load(request_file, expected_request_sha256, hold.MAX_REQUEST_BYTES,
            'EC328_FINAL_EIGHTH_REQUEST_REPIN')
    r._load(case_file, expected_case_sha256, hold.proof.MAX_CASE_BYTES,
            'EC328_FINAL_EC325_CASE_REPIN')
    for side in (left, right):
        r._load(side['registry_file'], side['expected_registry_sha256'],
                r.MAX_SNAPSHOT, 'EC328_FINAL_CHILD_HEAD_REPIN')
        origin, _ = r._load(side['origin_file'],side['expected_origin_sha256'],
                            r.MAX_CHANNEL, 'EC328_FINAL_ORIGIN_REPIN')
        r._load(side['recipient_file'],side['expected_recipient_sha256'],
                r.MAX_CHANNEL, 'EC328_FINAL_RECIPIENT_REPIN')
        hold.capsule._file(side['capsule_file'],hold.capsule.MAX_ARCHIVE,
                           origin['capsule_original_raw_sha256'],
                           'EC328_FINAL_ORIGINAL_CAPSULE_REPIN')
    if prior_registry_file is not None:
        r._load(prior_registry_file,expected_prior_registry_sha256,
                r.MAX_SNAPSHOT,'EC328_FINAL_COMMON_PARENT_REPIN')
    # All old signatures are verified by the actual production EC327 verifier,
    # never by treating a prior report as evidence of historical authenticity.
    counts = {name: sum(e['disposition'] == name for e in rows)
              for name in sorted(ninth.DISPOSITIONS)}
    diverged = len([n for n in counts.values() if n]) > 1
    return {
        'status': ('multiple_offline_review_dispositions_diverge_unresolved'
                   if diverged else 'offline_review_dispositions_consistent_unresolved'),
        'exit_code': 2,
        'ledger_original_raw_sha256': expected_ledger_sha256,
        'previous_ledger_original_raw_sha256': expected_prior_ledger_sha256,
        'ledger_head_entry_commitment_sha256':
            ledger['ledger_head_entry_commitment_sha256'],
        'signed_request_original_raw_sha256': expected_request_sha256,
        'dispute_case_original_raw_sha256': expected_case_sha256,
        'registry_id': registry_id, 'sequence': expected_sequence,
        'expected_remote_parent_original_raw_sha256':
            expected_prior_registry_sha256,
        'two_competing_heads_original_raw_sha256':
            needed['two_competing_heads_original_raw_sha256'],
        'request_id': request_id,
        'target_store_namespace_id': target_store_namespace_id,
        'review_count': len(rows),
        'disposition_counts': counts,
        'offline_disposition_disagreement_detected': diverged,
        'verified_review_receipt_original_raw_sha256':
            [e['receipt_original_raw_sha256'] for e in rows],
        'all_ninth_signatures_eighth_signature_and_two_complete_original_histories_verified': True,
        'signed_offline_opinions_only_not_independent_external_nonexecution_proof': True,
        **{key: False for key in EXPLICIT_FALSE_FIELDS},
        'business_or_external_store_writes_performed': False,
    }

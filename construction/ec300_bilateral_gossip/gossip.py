#!/usr/bin/env python3
"""EC300 offline bilateral witness gossip: authenticated snapshots and continuity.

The two EC299 witness keys sign ONE identical, fully reverified historical
comparison snapshot, with role-separated EC300 signatures. Each later session
must include the complete source history of all earlier sessions and extend
both immutable witness-receipt prefixes (at least one strictly). Original
EC294--299 evidence is replayed for EVERY historical session. The session
hash is only an out-of-band comparison anchor; it is NOT a clock, WORM store,
remote transport, organizational identity or globally preferred fork.
"""
from __future__ import annotations

import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec297_anchor_lineage import lineage as l
from ec299_witness_consistency import witness as w

DOMAIN = b'CES/EC300/DeliveryAudit/BilateralWitnessGossip/v1\0'
CLAIM_SCHEMA = 'ces.ec300.bilateral_snapshot_claim.v1'
PROPOSAL_SCHEMA = 'ces.ec300.bilateral_session_proposal.v1'
VOTE_SCHEMA = 'ces.ec300.bilateral_session_vote.v1'
SESSION_SCHEMA = 'ces.ec300.bilateral_signed_gossip_session.v1'
HISTORY_SCHEMA = 'ces.ec300.bilateral_gossip_full_history.v1'
REPORT_SCHEMA = 'ces.ec300.bilateral_gossip_verification_report.v1'
RESULT_SCHEMA = 'ces.ec300.bilateral_gossip_verification_result.v1'
DENIAL_SCHEMA = 'ces.ec300.bilateral_gossip_denial.v1'
MAX_SESSIONS = 8
MAX_PROPOSAL_BYTES = 6500
MAX_VOTE_BYTES = 1000
MAX_SESSION_BYTES = 8500
MAX_HISTORY_BYTES = 96_000
MAX_REPORT_BYTES = 40_000
ID_FIELDS = ('operation_id','job_sha256','ec294_policy_sha256',
             'ec294_host_code_sha256','original_ec227_code_sha256')
ROLE_FIELDS = frozenset({'witness_id','witness_public_hex',
                         'latest_observation_sha256',
                         'signed_observation_sha256_chain'})
CLAIM_FIELDS = frozenset({'schema','sequence','previous_session_sha256',
    'independent_challenge_sha256','original_audit_identity',
    'a','b','comparison_report_sha256','comparison_status',
    'comparison_exit_code'})
PROPOSAL_FIELDS = frozenset({'schema','claim'})
VOTE_FIELDS = frozenset({'schema','role','claim_sha256',
                         'signer_public_hex','signature_ed25519'})
SESSION_FIELDS = frozenset({'schema','claim','vote_a','vote_b'})
HISTORY_FIELDS = frozenset({'schema','a_id','a_public_hex','b_id',
                            'b_public_hex','sessions'})
ENTRY_FIELDS = frozenset({'signed_session_file','expected_session_sha256',
                          'witness_manifest_file','expected_a_tip','expected_b_tip'})


def _same(left: str, right: str) -> bool:
    return type(left) is str and type(right) is str and hmac.compare_digest(left, right)


def check_identities(a_id: str, a_public_hex: str, b_id: str,
                     b_public_hex: str) -> None:
    l.require(w.valid_id(a_id) and w.valid_id(b_id) and a_id != b_id and
              w.valid_pub(a_public_hex) and w.valid_pub(b_public_hex) and
              a_public_hex != b_public_hex,
              'EC300_TWO_DISTINCT_PINNED_WITNESS_IDENTITIES_KEYS_REQUIRED',
              'permission_denied')


def verified_snapshot(manifest_file: str, *, a_id: str, a_public_hex: str,
                      a_tip: str, b_id: str, b_public_hex: str,
                      b_tip: str) -> dict:
    check_identities(a_id, a_public_hex, b_id, b_public_hex)
    l.require(l.absolute_file(manifest_file) and l.sha_pin(a_tip) and
              l.sha_pin(b_tip),
              'EC300_EXPLICIT_ORIGINAL_WITNESS_MANIFEST_AND_TWO_TIPS_REQUIRED',
              'permission_denied')
    doc = io.read_doc(manifest_file, w.MAX_MANIFEST_BYTES)
    # Calls unchanged EC299 full signature and all-pair signed-fork replay.
    return w.compare_witnesses(manifest=doc,
        a_id=a_id, a_public_hex=a_public_hex, a_tip=a_tip,
        b_id=b_id, b_public_hex=b_public_hex, b_tip=b_tip)


def role_claim(report: dict, role: str) -> dict:
    base = report['witness_' + role]
    return {
        'witness_id': base['witness_id'],
        'witness_public_hex': base['witness_public_hex'],
        'latest_observation_sha256': base['externally_pinned_latest_observation_sha256'],
        'signed_observation_sha256_chain': list(base['signed_observation_sha256_chain']),
    }


def claim_for(report: dict, *, sequence: int,
              previous_session_sha256: str,
              independent_challenge_sha256: str) -> dict:
    l.require(type(sequence) is int and 1 <= sequence <= MAX_SESSIONS and
        a.valid_sha(previous_session_sha256) and
        (sequence == 1) == (previous_session_sha256 == a.GENESIS) and
        l.sha_pin(independent_challenge_sha256),
        'EC300_SEQUENCE_PREDECESSOR_OR_OUT_OF_BAND_CHALLENGE_INVALID',
        'permission_denied')
    return {
        'schema': CLAIM_SCHEMA, 'sequence': sequence,
        'previous_session_sha256': previous_session_sha256,
        'independent_challenge_sha256': independent_challenge_sha256,
        'original_audit_identity': {k: report[k] for k in ID_FIELDS},
        'a': role_claim(report, 'a'), 'b': role_claim(report, 'b'),
        'comparison_report_sha256': a.sha(report),
        'comparison_status': report['status'],
        'comparison_exit_code': report['exit_code'],
    }


def _vote_bytes(claim: dict, role: str) -> bytes:
    l.require(role in ('a', 'b'), 'EC300_SIGNER_ROLE_NOT_A_OR_B')
    return DOMAIN + role.encode('ascii') + b'\0' + a.canonical(claim)


def sign_vote(claim: dict, role: str, private_key: Ed25519PrivateKey) -> dict:
    l.exact(claim, CLAIM_FIELDS, 'EC300_SIGNING_CLAIM_FIELDS_INVALID')
    return {
        'schema': VOTE_SCHEMA, 'role': role,
        'claim_sha256': a.sha(claim),
        'signer_public_hex': claim[role]['witness_public_hex'],
        'signature_ed25519': private_key.sign(_vote_bytes(claim, role)).hex(),
    }


def verify_vote(vote: Any, claim: dict, role: str) -> None:
    l.exact(vote, VOTE_FIELDS, 'EC300_VOTE_FIELDS_INVALID')
    l.require(vote['schema'] == VOTE_SCHEMA and vote['role'] == role and
              _same(vote['claim_sha256'], a.sha(claim)) and
              _same(vote['signer_public_hex'], claim[role]['witness_public_hex']) and
              type(vote['signature_ed25519']) is str and
              a.SIG.fullmatch(vote['signature_ed25519']) is not None,
              'EC300_VOTE_ROLE_SIGNER_CLAIM_OR_ENCODING_MISMATCH',
              'permission_denied')
    try:
        io.pub_from_hex(vote['signer_public_hex']).verify(
            bytes.fromhex(vote['signature_ed25519']), _vote_bytes(claim, role))
    except (InvalidSignature, ValueError, TypeError, io.HostError) as exc:
        raise a.AnchorError('EC300_ED25519_BILATERAL_SIGNATURE_INVALID',
                            'permission_denied') from exc


def verify_session(session: Any, *, expected_sha256: str,
                   rebuilt_claim: dict) -> None:
    l.exact(session, SESSION_FIELDS, 'EC300_SIGNED_SESSION_FIELDS_INVALID')
    l.require(session['schema'] == SESSION_SCHEMA and
              len(a.canonical(session)) + 1 <= MAX_SESSION_BYTES and
              l.sha_pin(expected_sha256) and
              _same(a.sha(session), expected_sha256),
              'EC300_EXTERNALLY_PINNED_SESSION_SHA_OR_SCHEMA_MISMATCH',
              'permission_denied')
    claim = l.exact(session['claim'], CLAIM_FIELDS,
                    'EC300_SIGNED_SESSION_CLAIM_FIELDS_INVALID')
    # Canonical-byte equality, not Python dict equality (True == 1).
    l.require(a.canonical(claim) == a.canonical(rebuilt_claim),
              'EC300_SIGNED_SESSION_NOT_EQUAL_FULLY_REPLAYED_ORIGINAL_EVIDENCE',
              'permission_denied')
    verify_vote(session['vote_a'], claim, 'a')
    verify_vote(session['vote_b'], claim, 'b')


def validate_history(doc: Any) -> dict:
    l.exact(doc, HISTORY_FIELDS, 'EC300_HISTORY_FIELDS_INVALID')
    l.require(doc['schema'] == HISTORY_SCHEMA and
              len(a.canonical(doc)) + 1 <= MAX_HISTORY_BYTES,
              'EC300_HISTORY_SCHEMA_OR_SIZE_INVALID')
    check_identities(doc['a_id'], doc['a_public_hex'],
                     doc['b_id'], doc['b_public_hex'])
    entries = doc['sessions']
    l.require(type(entries) is list and 1 <= len(entries) <= MAX_SESSIONS,
              'EC300_HISTORY_MUST_CONTAIN_ONE_TO_EIGHT_SESSIONS')
    for entry in entries:
        l.exact(entry, ENTRY_FIELDS, 'EC300_HISTORY_ENTRY_FIELDS_INVALID')
        l.require(l.absolute_file(entry['signed_session_file']) and
                  l.absolute_file(entry['witness_manifest_file']) and
                  all(l.sha_pin(entry[k]) for k in (
                      'expected_session_sha256','expected_a_tip','expected_b_tip')),
                  'EC300_HISTORY_REQUIRES_ABSOLUTE_FILES_AND_INDEPENDENT_PINS',
                  'permission_denied')
    return doc


def _transition(old: dict, new: dict) -> None:
    l.require(old['original_audit_identity'] == new['original_audit_identity'] and
              all(old[role]['witness_id'] == new[role]['witness_id'] and
                  old[role]['witness_public_hex'] == new[role]['witness_public_hex']
                  for role in ('a', 'b')),
              'EC300_AUDIT_TASK_OR_ORIGINAL_WITNESS_IDENTITY_CHANGED',
              'permission_denied')
    progressed = False
    for role in ('a', 'b'):
        before = old[role]['signed_observation_sha256_chain']
        after = new[role]['signed_observation_sha256_chain']
        l.require(type(before) is list and type(after) is list and
                  len(before) <= len(after) and after[:len(before)] == before and
                  old[role]['latest_observation_sha256'] == before[-1] and
                  new[role]['latest_observation_sha256'] == after[-1],
                  'EC300_WITNESS_RECEIPT_HISTORY_ROLLBACK_REPLACEMENT_OR_REORDER',
                  'permission_denied')
        progressed |= len(after) > len(before)
    l.require(progressed,
              'EC300_NEW_SESSION_MUST_CONTAIN_AUTHENTIC_NEW_SIGNED_OBSERVATION',
              'permission_denied')


def verify_full_history(doc: dict, *, a_id: str, a_public_hex: str,
                        a_tip: str, b_id: str, b_public_hex: str,
                        b_tip: str, expected_session_tip: str) -> tuple[dict, list[dict]]:
    """Replay *every* original source & signature; trust only caller pins.

    Return path-free report and fully verified ordered session claims.
    Caller-provided session SHA is mandatory to prevent silent file rollback.
    """
    validate_history(doc)
    check_identities(a_id, a_public_hex, b_id, b_public_hex)
    l.require(_same(doc['a_id'], a_id) and
              _same(doc['a_public_hex'], a_public_hex) and
              _same(doc['b_id'], b_id) and
              _same(doc['b_public_hex'], b_public_hex) and
              l.sha_pin(a_tip) and l.sha_pin(b_tip) and
              l.sha_pin(expected_session_tip) and
              _same(expected_session_tip, doc['sessions'][-1]['expected_session_sha256']) and
              _same(a_tip, doc['sessions'][-1]['expected_a_tip']) and
              _same(b_tip, doc['sessions'][-1]['expected_b_tip']),
              'EC300_LATEST_SESSION_AND_BOTH_WITNESS_TIPS_NOT_EXTERNALLY_PINNED',
              'permission_denied')
    predecessor = a.GENESIS
    seen_challenges: set[str] = set()
    accepted: list[dict] = []
    reports: list[dict] = []
    for i, entry in enumerate(doc['sessions'], 1):
        snapshot = verified_snapshot(entry['witness_manifest_file'],
            a_id=a_id, a_public_hex=a_public_hex, a_tip=entry['expected_a_tip'],
            b_id=b_id, b_public_hex=b_public_hex, b_tip=entry['expected_b_tip'])
        session = io.read_doc(entry['signed_session_file'], MAX_SESSION_BYTES)
        l.exact(session, SESSION_FIELDS, 'EC300_SIGNED_SESSION_FIELDS_INVALID')
        raw_claim = l.exact(session['claim'], CLAIM_FIELDS,
                            'EC300_SIGNED_SESSION_CLAIM_FIELDS_INVALID')
        fresh_challenge = raw_claim['independent_challenge_sha256']
        rebuilt = claim_for(snapshot, sequence=i,
            previous_session_sha256=predecessor,
            independent_challenge_sha256=fresh_challenge)
        verify_session(session,
            expected_sha256=entry['expected_session_sha256'],
            rebuilt_claim=rebuilt)
        l.require(fresh_challenge not in seen_challenges,
                  'EC300_OUT_OF_BAND_CHALLENGE_REUSED_IN_SESSION_HISTORY',
                  'permission_denied')
        if accepted:
            _transition(accepted[-1], rebuilt)
        seen_challenges.add(fresh_challenge)
        accepted.append(rebuilt)
        reports.append(snapshot)
        predecessor = entry['expected_session_sha256']
    # A later comparison must never erase an earlier verified fork or an
    # inconclusive episode from the publicly reported overall status.
    observed = [r['status'] for r in reports]
    if 'signed_competing_evidence_between_supplied_witnesses' in observed:
        status, exit_code = 'signed_competing_evidence_between_supplied_witnesses', 2
    elif 'witness_histories_inconclusive' in observed:
        status, exit_code = 'witness_histories_inconclusive', 2
    else:
        status, exit_code = 'supplied_signed_witness_observations_compatible', 0
    report = {
        'schema': REPORT_SCHEMA,
        'status': status, 'exit_code': exit_code,
        'original_audit_identity': accepted[0]['original_audit_identity'],
        'witness_a': {'witness_id': a_id, 'witness_public_hex': a_public_hex,
                      'externally_pinned_latest_observation_sha256': a_tip,
                      'verified_observation_receipt_sha256_chain':
                          accepted[-1]['a']['signed_observation_sha256_chain']},
        'witness_b': {'witness_id': b_id, 'witness_public_hex': b_public_hex,
                      'externally_pinned_latest_observation_sha256': b_tip,
                      'verified_observation_receipt_sha256_chain':
                          accepted[-1]['b']['signed_observation_sha256_chain']},
        'externally_pinned_latest_bilateral_session_sha256': expected_session_tip,
        'full_signed_bilateral_session_sha256_chain':
            [e['expected_session_sha256'] for e in doc['sessions']],
        'fully_recomputed_original_ec299_comparison_sha256_per_session':
            [a.sha(report) for report in reports],
        'session_comparison_statuses': [r['status'] for r in reports],
        'history_session_count': len(accepted),
        'ever_observed_signed_competing_evidence': any(
            r['status'] == 'signed_competing_evidence_between_supplied_witnesses'
            for r in reports),
        'ever_observed_inconclusive_histories': any(
            r['status'] == 'witness_histories_inconclusive' for r in reports),
        'both_separate_keys_signed_every_snapshot_of_the_same_comparison': True,
        'all_sessions_previous_sha_linked_and_challenges_unique': True,
        'each_progression_preserved_both_old_signed_observation_prefixes': True,
        'all_ec294_to_ec299_original_evidence_replayed_each_session': True,
        'physical_independent_humans_or_off_host_worm_proven': False,
        'challenge_source_freshness_or_trusted_time_proven': False,
        'globally_unique_latest_or_absence_of_unknown_forks_proven': False,
        'provider_inbox_or_original_send_executed': False,
    }
    l.require(len(a.canonical(report)) + 1 <= MAX_REPORT_BYTES,
              'EC300_HISTORY_REPORT_TOO_LARGE')
    return report, accepted


def build_next_claim(*, witness_manifest_file: str,
                     a_id: str, a_public_hex: str, a_tip: str,
                     b_id: str, b_public_hex: str, b_tip: str,
                     sequence: int, independent_challenge_sha256: str,
                     prior_history_file: str | None = None,
                     expected_previous_session_sha256: str | None = None) -> dict:
    """Sign ceremony always replays the ENTIRE old signed session history."""
    check_identities(a_id, a_public_hex, b_id, b_public_hex)
    l.require(type(sequence) is int and 1 <= sequence <= MAX_SESSIONS and
              l.sha_pin(independent_challenge_sha256),
              'EC300_SESSION_INDEX_OR_EXTERNAL_CHALLENGE_INVALID',
              'permission_denied')
    previous = a.GENESIS
    old_claims: list[dict] = []
    if sequence == 1:
        l.require(prior_history_file is None and
                  expected_previous_session_sha256 is None,
                  'EC300_GENESIS_MUST_NOT_ACCEPT_PRIOR_HISTORY')
    else:
        l.require(l.absolute_file(prior_history_file) and
                  l.sha_pin(expected_previous_session_sha256),
                  'EC300_NON_GENESIS_REQUIRES_FULL_PREVIOUS_HISTORY_AND_EXTERNAL_TIP',
                  'permission_denied')
        history = io.read_doc(prior_history_file, MAX_HISTORY_BYTES)
        validate_history(history)
        l.require(len(history['sessions']) == sequence - 1,
                  'EC300_PREVIOUS_COMPLETE_HISTORY_LENGTH_INVALID',
                  'permission_denied')
        last = history['sessions'][-1]
        _, old_claims = verify_full_history(history,
            a_id=a_id, a_public_hex=a_public_hex,
            a_tip=last['expected_a_tip'], b_id=b_id,
            b_public_hex=b_public_hex, b_tip=last['expected_b_tip'],
            expected_session_tip=expected_previous_session_sha256)
        previous = expected_previous_session_sha256
        l.require(independent_challenge_sha256 not in
                  {x['independent_challenge_sha256'] for x in old_claims},
                  'EC300_NEW_SESSION_CHALLENGE_WAS_PREVIOUSLY_SIGNED',
                  'permission_denied')
    comparison = verified_snapshot(witness_manifest_file,
        a_id=a_id, a_public_hex=a_public_hex, a_tip=a_tip,
        b_id=b_id, b_public_hex=b_public_hex, b_tip=b_tip)
    claim = claim_for(comparison, sequence=sequence,
        previous_session_sha256=previous,
        independent_challenge_sha256=independent_challenge_sha256)
    if old_claims:
        _transition(old_claims[-1], claim)
    return claim

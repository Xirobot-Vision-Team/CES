#!/usr/bin/env python3
"""EC296 offline EC295 signer rotation with explicit two-epoch continuity.

This is a four-signature handover, NOT an external immutable pin store:
old keeper/witness release one exact old tip to a new keeper/witness and
all four sign one exact pair of complete, Ed25519-verified EC295 histories.
No socket, Provider call, HMAC key, remote auth or original send is used.
"""
from __future__ import annotations

import hmac
from typing import Any

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a

CLAIM_SCHEMA = 'ces.ec296.delivery_anchor_rotation_claim.v1'
PREPARED_SCHEMA = 'ces.ec296.delivery_anchor_rotation_prepared.v1'
VOTE_SCHEMA = 'ces.ec296.delivery_anchor_rotation_vote.v1'
BRIDGE_SCHEMA = 'ces.ec296.four_party_delivery_anchor_rotation.v1'
RESULT_SCHEMA = 'ces.ec296.delivery_anchor_rotation_verified.v1'
DENIAL_SCHEMA = 'ces.ec296.delivery_anchor_rotation_denial.v1'
ROLES = ('old_keeper', 'old_witness', 'new_keeper', 'new_witness')
DOMAINS = {role: (f'CES/EC296/DeliveryAudit/Rotation/{role}/v1\0').encode('ascii')
           for role in ROLES}
POLICY_CONTINUITY = frozenset({
    'ec294_policy_sha256', 'ec294_server_public_hex',
    'ec294_custodian_public_hex', 'ec294_auditor_public_hex',
    'ec294_host_code_sha256', 'original_ec227_code_sha256',
    'operation_id', 'job_sha256',
})
CLAIM_FIELDS = frozenset({
    'schema', 'old_policy_sha256', 'new_policy_sha256',
    'old_checkpoint_tip_sha256', 'new_checkpoint_tip_sha256',
    'old_checkpoint_count', 'new_checkpoint_count',
    'operation_id', 'job_sha256', 'ec294_policy_sha256',
    'old_last_event_count', 'new_first_event_count', 'new_last_event_count',
    'old_last_hmac_head_sha256', 'new_first_hmac_head_sha256',
    'new_last_hmac_head_sha256',
    'old_last_receipt_sha256', 'new_first_receipt_sha256',
    'old_last_reply_unix', 'new_first_reply_unix',
    'handover_observation_mode', 'minimum_fresh_readback_unix',
})
PREPARED_FIELDS = frozenset({'schema', 'claim'})
VOTE_FIELDS = frozenset({'schema', 'role', 'prepared_sha256',
                         'signature_ed25519'})
BRIDGE_FIELDS = frozenset({'schema', 'claim'}) | frozenset(
    role + '_signature_ed25519' for role in ROLES)
MAX_PREPARED_BYTES = 6000
MAX_BRIDGE_BYTES = 7500
MAX_VOTE_BYTES = 3000
GENESIS = a.GENESIS


def require(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise a.AnchorError(code, status)


def exact(doc: Any, fields: frozenset[str], code: str) -> dict:
    require(type(doc) is dict and set(doc) == fields, code)
    return doc


def policy_continuity(old_policy: dict, new_policy: dict,
                      old_sha: str, new_sha: str) -> None:
    a.validate_policy(old_policy)
    a.validate_policy(new_policy)
    require(a.valid_sha(old_sha) and a.valid_sha(new_sha) and old_sha != new_sha,
            'EC296_DISTINCT_PINNED_POLICY_FILES_REQUIRED', 'permission_denied')
    require(all(old_policy[key] == new_policy[key] for key in POLICY_CONTINUITY),
            'EC296_ORIGINAL_EC294_AUDIT_IDENTITY_OR_CODE_CHANGED',
            'permission_denied')
    pubs = [pol[role + '_public_hex'] for pol in (old_policy, new_policy)
            for role in ('keeper', 'witness')]
    require(len(set(pubs)) == 4,
            'EC296_ALL_FOUR_OLD_AND_NEW_ROLE_KEYS_MUST_DIFFER',
            'permission_denied')
    # Both independently checked EC295 policies already forbid their signer
    # keys from overlapping the three original EC294 server/grant keys.


def sign(role: str, claim: dict, key: Any) -> str:
    require(role in DOMAINS, 'EC296_SIGNING_ROLE_INVALID')
    return key.sign(DOMAINS[role] + a.canonical(claim)).hex()


def verify_vote_signature(role: str, claim: dict,
                          signature: Any, public_hex: str) -> None:
    require(role in DOMAINS and type(signature) is str and
            a.SIG.fullmatch(signature) is not None,
            'EC296_ROTATION_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(public_hex).verify(
            bytes.fromhex(signature), DOMAINS[role] + a.canonical(claim))
    except Exception as exc:
        raise a.AnchorError('EC296_ROTATION_FOUR_PARTY_SIGNATURE_INVALID',
                            'permission_denied') from exc


def role_pub(role: str, old_policy: dict, new_policy: dict) -> str:
    require(role in ROLES, 'EC296_SIGNING_ROLE_INVALID')
    epoch, kind = role.split('_', 1)
    return (old_policy if epoch == 'old' else new_policy)[kind + '_public_hex']


def claim_from_histories(*, old_policy: dict, old_policy_sha: str,
                         old_checkpoints: list[dict], old_expected_tip: str,
                         new_policy: dict, new_policy_sha: str,
                         new_checkpoints: list[dict], new_proposed_tip: str,
                         minimum_fresh_readback_unix: int | None = None) -> dict:
    """All historical original EC294 signatures and EC295 seals are rechecked.

    The old tip is necessarily independently trusted; the proposed new tip
    must be explicit, but does NOT become independently trusted by appearing
    in this function. Caller must externally retain the resulting bridge SHA.
    """
    policy_continuity(old_policy, new_policy, old_policy_sha, new_policy_sha)
    require(a.valid_sha(old_expected_tip) and old_expected_tip != GENESIS,
            'EC296_EXTERNALLY_RETAINED_OLD_TIP_REQUIRED', 'permission_denied')
    require(a.valid_sha(new_proposed_tip) and new_proposed_tip != GENESIS,
            'EC296_EXPLICIT_NEW_EPOCH_TIP_REQUIRED', 'permission_denied')
    # The existing verifier also checks genesis, every single ancestor,
    # original EC294 nonce/grants/reply + signatures, count, and both seals.
    a.verify_chain(old_checkpoints, old_policy, old_policy_sha,
                   old_expected_tip)
    a.verify_chain(new_checkpoints, new_policy, new_policy_sha,
                   new_proposed_tip)
    before = old_checkpoints[-1]['claim']
    first = new_checkpoints[0]['claim']
    last = new_checkpoints[-1]['claim']
    # Two well-separated forward-safe paths:
    # 1. A separately approved Record actually extends EC227 HMAC history.
    # 2. A separately approved local-only EC294 Readback confirms unchanged
    #    EC227 head without ANY fresh Provider status lookup. This latter
    #    path additionally requires a separately recorded minimum reply time.
    #    An old Record must never be passed off as a fresh Readback.
    handover_mode = first['ec294_operation_mode']
    if handover_mode == 'record':
        require(minimum_fresh_readback_unix is None,
                'EC296_RECORD_HANDOVER_MUST_NOT_CLAIM_READBACK_FRESHNESS')
        forward = (first['audit_event_count'] > before['audit_event_count'] and
                   first['audit_head_hmac_sha256'] != before['audit_head_hmac_sha256'] and
                   first['ec294_reply_issued_at_unix'] >= before['ec294_reply_issued_at_unix'])
    elif handover_mode == 'readback':
        require(type(minimum_fresh_readback_unix) is int and
                946684800 <= minimum_fresh_readback_unix <= 4102444800,
                'EC296_INDEPENDENT_FRESH_READBACK_TIME_REQUIRED',
                'permission_denied')
        forward = (first['audit_event_count'] == before['audit_event_count'] and
                   first['audit_head_hmac_sha256'] == before['audit_head_hmac_sha256'] and
                   first['ec294_reply_issued_at_unix'] > before['ec294_reply_issued_at_unix'] and
                   first['ec294_reply_issued_at_unix'] >= minimum_fresh_readback_unix and
                   new_checkpoints[0]['evidence']['grant']['subject'][
                       'expected_head_hmac_sha256'] == before['audit_head_hmac_sha256'])
    else:
        forward = False
    require(first['sequence'] == 1 and
            first['previous_checkpoint_sha256'] == GENESIS and
            first['ec294_signed_reply_sha256'] != before['ec294_signed_reply_sha256'] and
            forward,
            'EC296_NEW_EPOCH_MUST_FOLLOW_AUTHENTICATED_OLD_AUDIT_HEAD',
            'permission_denied')
    return {
        'schema': CLAIM_SCHEMA,
        'old_policy_sha256': old_policy_sha,
        'new_policy_sha256': new_policy_sha,
        'old_checkpoint_tip_sha256': old_expected_tip,
        'new_checkpoint_tip_sha256': new_proposed_tip,
        'old_checkpoint_count': len(old_checkpoints),
        'new_checkpoint_count': len(new_checkpoints),
        'operation_id': old_policy['operation_id'],
        'job_sha256': old_policy['job_sha256'],
        'ec294_policy_sha256': old_policy['ec294_policy_sha256'],
        'old_last_event_count': before['audit_event_count'],
        'new_first_event_count': first['audit_event_count'],
        'new_last_event_count': last['audit_event_count'],
        'old_last_hmac_head_sha256': before['audit_head_hmac_sha256'],
        'new_first_hmac_head_sha256': first['audit_head_hmac_sha256'],
        'new_last_hmac_head_sha256': last['audit_head_hmac_sha256'],
        'old_last_receipt_sha256': before['ec294_signed_reply_sha256'],
        'new_first_receipt_sha256': first['ec294_signed_reply_sha256'],
        'old_last_reply_unix': before['ec294_reply_issued_at_unix'],
        'new_first_reply_unix': first['ec294_reply_issued_at_unix'],
        'handover_observation_mode': handover_mode,
        'minimum_fresh_readback_unix': minimum_fresh_readback_unix,
    }


def prepare(claim: dict) -> dict:
    exact(claim, CLAIM_FIELDS, 'EC296_ROTATION_CLAIM_FIELDS_INVALID')
    require(claim['schema'] == CLAIM_SCHEMA and
            len(a.canonical(claim)) <= MAX_PREPARED_BYTES,
            'EC296_ROTATION_CLAIM_SCHEMA_OR_SIZE_INVALID')
    return {'schema': PREPARED_SCHEMA, 'claim': claim}


def check_prepared(prepared: Any, expected_claim: dict) -> dict:
    exact(prepared, PREPARED_FIELDS, 'EC296_PREPARED_FIELDS_INVALID')
    require(prepared['schema'] == PREPARED_SCHEMA and
            len(a.canonical(prepared)) <= MAX_PREPARED_BYTES and
            type(prepared['claim']) is dict and
            prepared['claim'] == expected_claim,
            'EC296_PREPARED_NOT_EXACT_VERIFIED_TWO_EPOCH_HISTORY',
            'permission_denied')
    return expected_claim


def verify_bridge(bridge: Any, expected_claim: dict, old_policy: dict,
                  new_policy: dict, *, externally_pinned_bridge_sha: str) -> dict:
    exact(bridge, BRIDGE_FIELDS, 'EC296_SIGNED_ROTATION_BRIDGE_FIELDS_INVALID')
    require(bridge['schema'] == BRIDGE_SCHEMA and
            len(a.canonical(bridge)) <= MAX_BRIDGE_BYTES and
            type(bridge['claim']) is dict and bridge['claim'] == expected_claim,
            'EC296_BRIDGE_DOES_NOT_MATCH_THE_TWO_COMPLETE_EPOCHS',
            'permission_denied')
    require(a.valid_sha(externally_pinned_bridge_sha) and
            externally_pinned_bridge_sha != GENESIS,
            'EC296_EXTERNALLY_PINNED_BRIDGE_DIGEST_REQUIRED',
            'permission_denied')
    for role in ROLES:
        verify_vote_signature(role, expected_claim,
                              bridge[role + '_signature_ed25519'],
                              role_pub(role, old_policy, new_policy))
    bridge_sha = a.sha(bridge)
    require(hmac.compare_digest(bridge_sha, externally_pinned_bridge_sha),
            'EC296_EXTERNAL_ROTATION_BRIDGE_PIN_MISMATCH_OR_ROLLBACK',
            'permission_denied')
    return {
        'schema': RESULT_SCHEMA,
        'status': 'verified_offline_two_epoch_rotation',
        'exit_code': 0,
        'old_checkpoint_tip_sha256': expected_claim['old_checkpoint_tip_sha256'],
        'new_checkpoint_tip_sha256': expected_claim['new_checkpoint_tip_sha256'],
        'rotation_bridge_sha256': bridge_sha,
        'old_checkpoint_count': expected_claim['old_checkpoint_count'],
        'new_checkpoint_count': expected_claim['new_checkpoint_count'],
        'old_last_event_count': expected_claim['old_last_event_count'],
        'new_first_event_count': expected_claim['new_first_event_count'],
        'new_last_event_count': expected_claim['new_last_event_count'],
        'handover_observation_mode': expected_claim['handover_observation_mode'],
        'original_ec294_signatures_and_both_ec295_epoch_chains_verified': True,
        'all_four_distinct_rotation_role_signatures_verified': True,
        'independent_off_host_latest_pin_and_real_people_proven': False,
        'current_original_ec227_disk_state_rechecked': False,
        'production_delivery_proven': False,
        'new_provider_status_query_or_original_submit_executed': False,
        'security_of_any_later_rotation_or_fork_without_external_pin_proven': False,
    }

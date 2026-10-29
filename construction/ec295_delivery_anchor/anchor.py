#!/usr/bin/env python3
"""EC295: portable EC294 HMAC audit checkpoint attestation (no Provider, HMAC key, or socket).

One already *verified* EC294 signed reply is reconstructed from its original
signed grant, optional EC226 read grant, and original server response. A pair
of NEW offline authorities countersigns the exact evidence and monotonic
checkpoint predecessor. The external custodian MUST separately pin/retain
its latest signed checkpoint SHA; an on-host chain alone is rollbackable.

This module never sends, re-reads status, checks the network, or writes EC227.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import re
from typing import Any

from ec279_finding_query_host import protocol as io
from ec294_delivery_reconcile_host import protocol as old

POLICY_SCHEMA = 'ces.ec295.external_delivery_audit_anchor_policy.v1'
PREPARED_SCHEMA = 'ces.ec295.delivery_anchor_prepared.v1'
VOTE_SCHEMA = 'ces.ec295.delivery_anchor_vote.v1'
CHECKPOINT_SCHEMA = 'ces.ec295.portable_delivery_audit_checkpoint.v1'
CLAIM_SCHEMA = 'ces.ec295.delivery_audit_anchor_claim.v1'
EVIDENCE_SCHEMA = 'ces.ec295.original_ec294_signed_evidence.v1'
RESULT_SCHEMA = 'ces.ec295.offline_chain_verification.v1'
DOMAINS = {
    'keeper': b'CES/EC295/DeliveryAudit/OffHostKeeper/v1\0',
    'witness': b'CES/EC295/DeliveryAudit/IndependentWitness/v1\0',
}
POLICY_KEYS = {
    'schema', 'ec294_policy_sha256', 'ec294_server_public_hex',
    'ec294_custodian_public_hex', 'ec294_auditor_public_hex',
    'ec294_host_code_sha256', 'original_ec227_code_sha256',
    'operation_id', 'job_sha256', 'keeper_public_hex', 'witness_public_hex',
}
CLAIM_KEYS = {
    'schema', 'policy_sha256', 'sequence', 'previous_checkpoint_sha256',
    'evidence_sha256', 'operation_id', 'job_sha256', 'audit_event_count',
    'audit_head_hmac_sha256', 'ec294_signed_reply_sha256', 'ec294_reply_issued_at_unix',
    'ec294_operation_mode', 'historical_delivery_state',
}
PREPARED_KEYS = {'schema', 'claim', 'evidence'}
EVIDENCE_KEYS = {'schema', 'response', 'grant', 'read_grant'}
CHECKPOINT_KEYS = PREPARED_KEYS | {'keeper_signature_ed25519',
                                      'witness_signature_ed25519'}
VOTE_KEYS = {'schema', 'role', 'prepared_sha256', 'signature_ed25519'}
MAX_POLICY_BYTES = 12000
MAX_EVIDENCE_BYTES = 45000
MAX_PREPARED_BYTES = 55000
MAX_CHECKPOINT_BYTES = 56000
MAX_CHECKPOINTS = 64
HASH = re.compile(r'[0-9a-f]{64}\Z')
SIG = re.compile(r'[0-9a-f]{128}\Z')
GENESIS = '0' * 64


class AnchorError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input'):
        super().__init__(code)
        self.code, self.status = code, status


def need(value: bool, code: str, status: str = 'invalid_input') -> None:
    if value is not True:
        raise AnchorError(code, status)


def exact(obj: Any, fields: set[str], code: str) -> dict:
    need(type(obj) is dict and set(obj) == fields, code)
    return obj


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def sha(doc: Any) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def valid_sha(value: Any) -> bool:
    return type(value) is str and HASH.fullmatch(value) is not None


def valid_pub(pub: Any) -> bool:
    try:
        io.pub_from_hex(pub)
        return True
    except (ValueError, TypeError, io.HostError):
        return False


def validate_policy(policy: Any) -> dict:
    exact(policy, POLICY_KEYS, 'EC295_ANCHOR_POLICY_FIELDS_INVALID')
    need(policy['schema'] == POLICY_SCHEMA, 'EC295_ANCHOR_POLICY_SCHEMA_INVALID')
    for field in ('ec294_policy_sha256', 'ec294_host_code_sha256',
                  'original_ec227_code_sha256', 'operation_id', 'job_sha256'):
        need(valid_sha(policy[field]), 'EC295_POLICY_BOUND_SHA_INVALID')
    pubs = [policy[field] for field in ('ec294_server_public_hex',
        'ec294_custodian_public_hex', 'ec294_auditor_public_hex',
        'keeper_public_hex', 'witness_public_hex')]
    need(all(valid_pub(pub) for pub in pubs) and len(set(pubs)) == len(pubs),
         'EC295_FIVE_DISTINCT_ED25519_ROLES_REQUIRED')
    return policy


def load_policy(path: str, pinned_sha256: str) -> dict:
    need(valid_sha(pinned_sha256), 'EC295_EXTERNALLY_PINNED_POLICY_SHA_REQUIRED')
    raw = io._open_regular(path, MAX_POLICY_BYTES)
    need(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), pinned_sha256),
         'EC295_ANCHOR_POLICY_RAW_BYTES_CHANGED', 'permission_denied')
    return validate_policy(io.parse(raw, MAX_POLICY_BYTES))


def make_policy(ec294_policy_file: str, ec294_policy_sha256: str,
                operation_id: str, job_sha256: str,
                keeper_public_hex: str, witness_public_hex: str) -> dict:
    """Only EC294 public policy metadata is imported; no audit key or token opened."""
    need(valid_sha(ec294_policy_sha256), 'EC295_ORIGINAL_POLICY_PIN_REQUIRED')
    raw = io._open_regular(ec294_policy_file, MAX_POLICY_BYTES)
    need(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), ec294_policy_sha256),
         'EC295_ORIGINAL_POLICY_PIN_MISMATCH', 'permission_denied')
    prior = io.parse(raw, MAX_POLICY_BYTES)
    exact(prior, old.POLICY_KEYS, 'EC295_EC294_POLICY_SHAPE_INVALID')
    need(prior['schema'] == old.POLICY_SCHEMA and
         prior['enable_private_reconciliation'] is True,
         'EC295_ORIGINAL_EC294_OPT_IN_NOT_PINNED')
    policy = {'schema': POLICY_SCHEMA, 'ec294_policy_sha256': ec294_policy_sha256,
      'ec294_server_public_hex': prior['server_public_hex'],
      'ec294_custodian_public_hex': prior['custodian_public_hex'],
      'ec294_auditor_public_hex': prior['auditor_public_hex'],
      'ec294_host_code_sha256': prior['host_code_sha256'],
      'original_ec227_code_sha256': prior['original_ec227_code_sha256'],
      'operation_id': operation_id, 'job_sha256': job_sha256,
      'keeper_public_hex': keeper_public_hex,
      'witness_public_hex': witness_public_hex}
    return validate_policy(policy)


def verify_evidence(evidence: Any, policy: dict) -> dict:
    """Recreate original signed EC294 RPC from original grant + nonce in its ACK.

    The sealed response alone is NOT sufficient, since its signed request hash
    includes a nonce and signed grant. No live EC294 Host is contacted.
    """
    exact(evidence, EVIDENCE_KEYS, 'EC295_EVIDENCE_FIELDS_INVALID')
    need(evidence['schema'] == EVIDENCE_SCHEMA and
         len(canonical(evidence)) <= MAX_EVIDENCE_BYTES,
         'EC295_EVIDENCE_SCHEMA_OR_LENGTH_INVALID')
    response = evidence['response']
    grant = evidence['grant']
    read = evidence['read_grant']
    need(type(response) is dict and type(grant) is dict and
         (read is None or type(read) is dict),
         'EC295_SIGNED_EVIDENCE_OBJECT_INVALID')
    exact(grant, {'schema','subject','custodian_signature_ed25519',
                  'auditor_signature_ed25519'}, 'EC295_EC294_SIGNED_GRANT_FIELDS_INVALID')
    need(grant['schema'] == old.GRANT_SCHEMA, 'EC295_EC294_GRANT_SCHEMA_INVALID')
    try:
        sub = old.validate_subject(grant['subject'])
    except Exception as exc:
        raise AnchorError('EC295_ORIGINAL_EC294_SUBJECT_MALFORMED',
                          'permission_denied') from exc
    need(sub['policy_sha256'] == policy['ec294_policy_sha256'] and
         sub['host_code_sha256'] == policy['ec294_host_code_sha256'] and
         sub['original_ec227_code_sha256'] == policy['original_ec227_code_sha256'] and
         sub['job_sha256'] == policy['job_sha256'] and
         sub['operation_id'] == policy['operation_id'],
         'EC295_EC294_GRANT_NOT_IN_ANCHOR_SCOPE', 'permission_denied')
    for role in ('custodian', 'auditor'):
        try:
            old.verify(role, sub, grant[role+'_signature_ed25519'],
                       policy['ec294_'+role+'_public_hex'])
        except (old.HostError, ValueError) as exc:
            raise AnchorError('EC295_EC294_ORIGINAL_OFFLINE_VOTE_INVALID',
                              'permission_denied') from exc
    need((sub['mode'] == 'record') == (read is not None) and
         sub['read_grant_sha256'] == (sha(read) if read is not None else old.NO_READ_SHA),
         'EC295_ORIGINAL_READ_GRANT_SCOPE_INVALID')
    if read is not None:
        # Check its strict envelope, not just the untrusted file/hash shape;
        # its source issuer's online authorization was checked by EC294 Host.
        try:
            old.prev.read_envelope(read)
        except Exception as exc:
            raise AnchorError('EC295_ORIGINAL_READ_GRANT_MALFORMED') from exc
    exact(response,{'schema','verified_server_signature','mode','result',
        'signed_reply','audit_head_hmac_sha256',
        'audit_head_requires_independent_external_anchoring',
        'fresh_attested_delivery_state_this_call','original_ec225_submit_retried',
        'original_ec225_send_token_loaded_by_host',
        'automatic_status_query_or_send_retry_allowed',
        'production_inbox_delivery_proven','real_world_signer_independence_proven',
        'raw_hmac_secret_or_private_payload_returned'},
        'EC295_EC294_RESULT_WRAPPER_FIELDS_INVALID')
    need(response.get('schema') == old.RESULT_SCHEMA and
         response.get('verified_server_signature') is True and
         response.get('mode') == sub['mode'] and
         response.get('audit_head_requires_independent_external_anchoring') is True and
         all(response.get(k) is False for k in (
             'original_ec225_submit_retried',
             'original_ec225_send_token_loaded_by_host',
             'automatic_status_query_or_send_retry_allowed',
             'production_inbox_delivery_proven',
             'real_world_signer_independence_proven',
             'raw_hmac_secret_or_private_payload_returned')),
         'EC295_EC294_RESULT_WRAPPER_INVALID')
    reply = response.get('signed_reply')
    need(type(reply) is dict and len(canonical(reply)) <= old.MAX_REPLY,
         'EC295_ORIGINAL_SIGNED_REPLY_REQUIRED')
    nonce = reply.get('nonce')
    need(type(nonce) is str and old.HEX32.fullmatch(nonce) is not None,
         'EC295_REPLY_NONCE_INVALID')
    request = {'schema':old.REQUEST_SCHEMA, 'nonce':nonce,
               'grant':grant, 'read_grant':read}
    issued = reply.get('issued_at_unix')
    need(type(issued) is int and
         sub['issued_at_unix'] - old.CLOCK_SKEW <= issued <=
         sub['expires_at_unix'] + 90,
         'EC295_EC294_ACK_NOT_IN_AUTHORITATIVE_GRANT_WINDOW')
    try:
        # Explicit archived timestamp: verifies the original Ed25519 signature,
        # exact nonce + request hash + pins and original EC227 result semantics;
        # does NOT assert that a historical approval is valid "now".
        result = old.verify_reply(reply, request,
            policy['ec294_server_public_hex'],policy['ec294_policy_sha256'], issued)
    except Exception as exc:
        raise AnchorError('EC295_ORIGINAL_EC294_SIGNED_RECEIPT_INVALID',
                          'permission_denied') from exc
    need(response.get('result') == result and
         response.get('audit_head_hmac_sha256') == result.get('audit_head_hmac_sha256') and
         response.get('fresh_attested_delivery_state_this_call') is (
             sub['mode'] == 'record' and
             result.get('fresh_independent_status_evidence_verified') is True and
             result.get('delivery_state') in old.dr.KNOWN_STATES),
         'EC295_EC294_RESPONSE_FIELDS_CONTRADICT_SIGNED_REPLY')
    need(result['schema'] == old.dr.SCHEMA and result['status'] == 'partial' and
         result['exit_code'] == 2 and result['audit_chain_verified'] is True and
         type(result['audit_event_count']) is int and
         1 <= result['audit_event_count'] <= 64 and
         valid_sha(result['audit_head_hmac_sha256']) and
         result['audit_head_hmac_sha256'] != GENESIS,
         'EC295_NO_POSITIVE_AUTHENTICATED_AUDIT_HEAD_TO_ANCHOR')
    return {'operation_id':sub['operation_id'],
        'job_sha256':sub['job_sha256'], 'audit_event_count':result['audit_event_count'],
        'audit_head_hmac_sha256':result['audit_head_hmac_sha256'],
        'ec294_signed_reply_sha256':sha(reply), 'ec294_reply_issued_at_unix':issued,
        'ec294_operation_mode':sub['mode'],
        # HISTORICAL reference only, NEVER a new or production delivery claim.
        'historical_delivery_state':(result['delivery_state'] if sub['mode']=='record'
             else result['last_historical_attested_state'] or 'UNKNOWN_UNCONFIRMED')}


def sign(role: str, claim: dict, key) -> str:
    need(role in DOMAINS, 'EC295_OFFLINE_SIGNER_ROLE_INVALID')
    return key.sign(DOMAINS[role] + canonical(claim)).hex()


def verify_signature(role: str, claim: dict, signature: Any, public_hex: str) -> None:
    need(role in DOMAINS and type(signature) is str and
         SIG.fullmatch(signature) is not None,
         'EC295_OFFLINE_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(public_hex).verify(bytes.fromhex(signature),
            DOMAINS[role] + canonical(claim))
    except Exception as exc:
        raise AnchorError('EC295_INDEPENDENT_ANCHOR_SIGNATURE_INVALID',
                          'permission_denied') from exc


def claim_from_evidence(evidence: dict, policy: dict, policy_sha: str,
                        sequence: int, predecessor: str) -> dict:
    fields = verify_evidence(evidence, policy)
    need(valid_sha(policy_sha) and type(sequence) is int and
         1 <= sequence <= MAX_CHECKPOINTS and valid_sha(predecessor),
         'EC295_CHECKPOINT_SEQUENCE_OR_PIN_INVALID')
    return {'schema':CLAIM_SCHEMA,'policy_sha256':policy_sha,
            'sequence':sequence,'previous_checkpoint_sha256':predecessor,
            'evidence_sha256':sha(evidence), **fields}


def prepared_from_evidence(evidence: dict, policy: dict, policy_sha: str,
                           predecessor: dict | None) -> dict:
    if predecessor is not None:
        prev = verify_checkpoint(predecessor, policy, policy_sha)
        sequence, prev_sha = prev['sequence']+1, sha(predecessor)
    else:
        sequence, prev_sha = 1, GENESIS
    need(sequence <= MAX_CHECKPOINTS, 'EC295_MAXIMUM_CHECKPOINT_COUNT_REACHED')
    claim = claim_from_evidence(evidence, policy, policy_sha,sequence,prev_sha)
    if predecessor is not None:
        check_progress(predecessor['claim'],claim)
    return {'schema':PREPARED_SCHEMA,'claim':claim,'evidence':evidence}


def validate_prepared(prepared: Any, policy: dict, policy_sha: str) -> dict:
    exact(prepared, PREPARED_KEYS, 'EC295_PREPARED_FIELDS_INVALID')
    need(prepared['schema'] == PREPARED_SCHEMA and
         len(canonical(prepared)) <= MAX_PREPARED_BYTES,
         'EC295_PREPARED_SCHEMA_OR_LENGTH_INVALID')
    claim = exact(prepared['claim'],CLAIM_KEYS,'EC295_CLAIM_FIELDS_INVALID')
    need(claim['schema'] == CLAIM_SCHEMA and
         claim['policy_sha256'] == policy_sha and
         type(claim['sequence']) is int and 1 <= claim['sequence'] <= MAX_CHECKPOINTS and
         valid_sha(claim['previous_checkpoint_sha256']) and
         ((claim['sequence'] == 1) == (claim['previous_checkpoint_sha256'] == GENESIS)) and
         valid_sha(claim['evidence_sha256']) and
         claim['evidence_sha256'] == sha(prepared['evidence']),
         'EC295_CLAIM_SEQUENCE_OR_EVIDENCE_DIGEST_INVALID')
    expected = claim_from_evidence(prepared['evidence'],policy,policy_sha,
                  claim['sequence'],claim['previous_checkpoint_sha256'])
    need(claim == expected,'EC295_CLAIM_NOT_EXACT_EC294_SIGNED_EVIDENCE')
    return claim


def verify_checkpoint(doc: Any, policy: dict, policy_sha: str) -> dict:
    exact(doc,CHECKPOINT_KEYS,'EC295_SIGNED_CHECKPOINT_FIELDS_INVALID')
    need(doc['schema'] == CHECKPOINT_SCHEMA and
         len(canonical(doc)) <= MAX_CHECKPOINT_BYTES,
         'EC295_CHECKPOINT_SCHEMA_OR_SIZE_INVALID')
    prepared = {key:doc[key] for key in PREPARED_KEYS}
    prepared['schema'] = PREPARED_SCHEMA
    claim = validate_prepared(prepared,policy,policy_sha)
    for role in ('keeper','witness'):
        verify_signature(role,claim,doc[role+'_signature_ed25519'],
                         policy[role+'_public_hex'])
    return claim


def check_progress(before: dict, after: dict) -> None:
    need(after['sequence'] == before['sequence'] + 1 and
         after['audit_event_count'] > before['audit_event_count'] and
         after['audit_head_hmac_sha256'] != before['audit_head_hmac_sha256'] and
         after['ec294_reply_issued_at_unix'] >= before['ec294_reply_issued_at_unix'] and
         after['ec294_signed_reply_sha256'] != before['ec294_signed_reply_sha256'],
         'EC295_AUDIT_HISTORY_REGRESSED_OR_NOT_ADVANCED','permission_denied')


def verify_chain(checkpoints: list[dict], policy: dict, policy_sha: str,
                 expected_tip: str) -> dict:
    """Requires a separately trusted tip. No trusted tip = no antirollback claim."""
    need(type(checkpoints) is list and 1 <= len(checkpoints) <= MAX_CHECKPOINTS and
         valid_sha(expected_tip) and expected_tip != GENESIS,
         'EC295_EXTERNALLY_PINNED_TIP_AND_CHAIN_REQUIRED')
    prev = None
    for doc in checkpoints:
        claim = verify_checkpoint(doc,policy,policy_sha)
        need(claim['previous_checkpoint_sha256'] ==
             (sha(prev) if prev is not None else GENESIS),
             'EC295_ANCHOR_CHAIN_PREDECESSOR_MISMATCH','permission_denied')
        need(claim['sequence'] == (prev['claim']['sequence']+1 if prev is not None else 1),
             'EC295_NONCONTIGUOUS_ANCHOR_SEQUENCE','permission_denied')
        if prev is not None:
            check_progress(prev['claim'],claim)
        prev = doc
    tip = sha(prev)
    need(hmac.compare_digest(tip,expected_tip),
         'EC295_EXTERNALLY_ANCHORED_TIP_MISMATCH_OR_ROLLBACK','permission_denied')
    claim = prev['claim']
    return {'schema':RESULT_SCHEMA,'status':'verified_offline_local_history_only',
        'exit_code':0,'checkpoints_verified':len(checkpoints),
        'operation_id':policy['operation_id'],'job_sha256':policy['job_sha256'],
        'audit_event_count':claim['audit_event_count'],
        'audit_head_hmac_sha256':claim['audit_head_hmac_sha256'],
        'signed_checkpoint_tip_sha256':tip,
        'historical_delivery_state':claim['historical_delivery_state'],
        'original_ec294_server_signature_verified':True,
        'two_new_independent_key_signatures_verified':True,
        'original_ec227_hmac_audit_was_verified_by_original_ec294_host':True,
        'current_original_ec227_audit_storage_checked':False,
        'new_status_query_or_original_send_requested':False,
        'production_delivery_proven':False,
        'off_host_tip_actually_retained_or_immutable_proven':False,
        'organizational_signer_independence_proven':False,
        'real_world_final_acceptance_proven':False}

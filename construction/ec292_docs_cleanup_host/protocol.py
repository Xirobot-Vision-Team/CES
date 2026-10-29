#!/usr/bin/env python3
"""EC292 exact cleanup authorization, linked to a signed EC291 positive readback.

Only the unchanged EC230 cleanup_docs may remove an EC229 disposable linked
worktree. The host cannot alter a bare ref, source checkout, history, provider
or original write journals. The EC291 proof is read from a private host file,
not trusted on the socket. Every cleanup approval binds the observed commit,
worktree device/inode, original operation, previous read receipt and exact
code/policy bytes. A missing acknowledgement must be reconciled, not retried.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import secrets
from typing import Any

from ec279_finding_query_host import protocol as io
from ec285_docs_sandbox_host import protocol as old
from ec291_docs_receipt_host import protocol as prior
import delivery_authorization as da
import delivery_preview as dp
import publication_receipts as rec

POLICY_SCHEMA = 'ces.ec292.docs_cleanup_policy.v1'
TEMPLATE_SCHEMA = 'ces.ec292.original_ec230_cleanup_template.v1'
SUBJECT_SCHEMA = 'ces.ec292.exact_worktree_cleanup_subject.v1'
VOTE_SCHEMA = 'ces.ec292.cleanup_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec292.cleanup_two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec292.docs_cleanup_request.v1'
REPLY_SCHEMA = 'ces.ec292.signed_cleanup_reply.v1'
RESULT_SCHEMA = 'ces.ec292.verified_original_cleanup_result.v1'
DENIAL_SCHEMA = 'ces.ec292.cleanup_denial.v1'
DOMAINS = {
    'custodian': b'CES/EC292/WorktreeCleanup/Custodian/v1\0',
    'reviewer': b'CES/EC292/WorktreeCleanup/IndependentReviewer/v1\0',
    'server': b'CES/EC292/WorktreeCleanup/SignedReply/v1\0',
}
MAX_POLICY, MAX_RPC, MAX_REPLY, MAX_PROOF, MAX_TTL = 12000, 14000, 18000, 22000, 25
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
HEX_NONCE = io.HEX_NONCE
PINS = ('ec291_policy_sha256', 'job_sha256', 'original_receipt_code_sha256',
        'original_docs_code_sha256', 'ec291_host_code_sha256', 'host_code_sha256')
POLICY_KEYS = {'schema', 'ec291_policy_file', 'ec291_policy_sha256',
               'readback_result_file', 'admission_root', 'allowed_uids',
               'cleanup_custodian_public_hex', 'independent_reviewer_public_hex',
               'server_public_hex', 'enable_one_clean_linked_worktree', *PINS}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256',
                'cleanup_grant_sha256', 'readback_sha256', 'operation_sha256',
                'target_sha256', 'original_grant_sha256', 'inspection_id',
                'observation_sha256', 'candidate_commit_sha', 'worktree_inode',
                'issued_at_unix', 'expires_at_unix', *PINS}
RESULT_KEYS = prior.RESULT_KEYS


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable'):
        super().__init__(code)
        self.code, self.status = code, status


def need(value: bool, code: str, status: str = 'unavailable') -> None:
    if value is not True:
        raise HostError(code, status)


def fields(obj: Any, names: set, code: str) -> dict:
    need(type(obj) is dict and set(obj) == names, code, 'invalid_input')
    return obj


def canonical(obj: Any) -> bytes:
    return io.canonical(obj)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def host_sha() -> str:
    return prior.code_sha(b'CES/EC292/Independent-Cleanup-Host/v1\0',
        Path(__file__).resolve().parent, ('protocol.py', 'daemon.py', 'operator.py'))


def parent_policy(pol: dict) -> dict:
    previous = prior.load_policy(pol['ec291_policy_file'],
                                 pol['ec291_policy_sha256'])
    need(previous['job_sha256'] == pol['job_sha256'] and
         previous['original_receipt_code_sha256'] == pol['original_receipt_code_sha256'] and
         previous['original_docs_code_sha256'] == pol['original_docs_code_sha256'] and
         previous['host_code_sha256'] == pol['ec291_host_code_sha256'],
         'EC292_ORIGINAL_AND_EC291_CODE_OR_JOB_DRIFT')
    return previous


def validate_policy(doc: Any) -> dict:
    pol = fields(doc, POLICY_KEYS, 'EC292_POLICY_EXACT_FIELDS_REQUIRED')
    need(pol['schema'] == POLICY_SCHEMA and
         pol['enable_one_clean_linked_worktree'] is True,
         'EC292_OWNER_EXPLICIT_CLEANUP_OPT_IN_REQUIRED', 'permission_denied')
    need(all(old.plain_abs(pol[k]) for k in (
            'ec291_policy_file', 'readback_result_file', 'admission_root')),
         'EC292_OWNER_PRIVATE_ABSOLUTE_PATHS_REQUIRED')
    need(all(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None
             for k in PINS) and
         pol['original_receipt_code_sha256'] == rec.ACTIVE_CODE_SHA256 == rec._code_hash() and
         pol['original_docs_code_sha256'] == prior.original_sha() and
         pol['ec291_host_code_sha256'] == prior.host_sha() and
         pol['host_code_sha256'] == host_sha(),
         'EC292_ALL_ORIGINAL_EC291_AND_NEW_CODE_PINS_REQUIRED')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(x) is int and 0 <= x <= 2**31-1 for x in uids) and
         uids == sorted(set(uids)), 'EC292_KERNEL_UID_ALLOWLIST_INVALID')
    keys = [pol[k] for k in ('cleanup_custodian_public_hex',
                             'independent_reviewer_public_hex', 'server_public_hex')]
    try:
        for key in keys:
            io.pub_from_hex(key)
    except (ValueError, TypeError) as exc:
        raise HostError('EC292_NEW_PUBLIC_KEYS_INVALID') from exc
    need(len(set(keys)) == 3, 'EC292_THREE_NEW_ROOTS_MUST_BE_DISTINCT')
    prev = parent_policy(pol)
    originals = prior.load_job(prev)['access']
    inherited_keys = [originals[k] for k in ('policy_public_hex',
        'reviewer_public_hex', 'revocation_public_hex', 'side_effect_public_hex')]
    inherited_keys += [prev[k] for k in ('read_public_hex', 'cleanup_public_hex',
        'custodian_public_hex', 'inspector_public_hex', 'server_public_hex')]
    need(len(set(inherited_keys + keys)) == 12,
         'EC292_TWELVE_SEPARATE_ORIGINAL_AND_HOST_KEYS_REQUIRED')
    disallowed = [prev[k] for k in ('job_file', 'audit_root', 'admission_root',
                                    'ec291_policy_file') if k in prev]
    disallowed += [pol['ec291_policy_file']]
    disallowed += [originals[k] for k in ('repository_root', 'journal_root',
                                           'worktree_root', 'sandbox_bare_root')]
    # Owner-private file and one-shot admission must be distinct from existing
    # operation data and journals. A proof file may share a private parent.
    for new in (pol['readback_result_file'], pol['admission_root']):
        for existing in disallowed:
            need(not (new == existing or new.startswith(existing + '/') or
                      existing.startswith(new + '/')),
                 'EC292_CLEANUP_PROOF_OR_ADMISSION_OVERLAPS_PROTECTED_DATA')
    need(not (pol['readback_result_file'] == pol['admission_root'] or
              pol['readback_result_file'].startswith(pol['admission_root'] + '/') or
              pol['admission_root'].startswith(pol['readback_result_file'] + '/')),
         'EC292_PROOF_AND_ADMISSION_MUST_BE_SEPARATE')
    rec._safe_private_dir(pol['admission_root'])
    return pol


def load_policy(path: str, digest: str) -> dict:
    need(type(digest) is str and HEX.fullmatch(digest) is not None,
         'EC292_PINNED_POLICY_SHA_REQUIRED')
    raw = old.private_file(path, MAX_POLICY)
    need(sha(raw) == digest, 'EC292_POLICY_RAW_BYTES_CHANGED')
    return validate_policy(io.parse(raw, MAX_POLICY))


def service(pol: dict):
    prev = parent_policy(pol)
    _old, access, original = prior.service(prev)
    roots = rec.ReceiptRoots(bytes.fromhex(prev['read_public_hex']),
        bytes.fromhex(prev['cleanup_public_hex']), prev['receipt_epoch'])
    # Readback disabled. Original cleanup_docs is the only local worktree writer.
    scope = rec.HostReceiptScope(roots, prev['audit_root'], False, True, False, '')
    svc = rec.PublicationReceiptService(scope)
    need(svc.host.enable_readback is False and
         svc.host.enable_clean_linked_worktree is True and
         svc.host.provider_read_credential == '' and
         svc.host.allow_synthetic_receipt_reader_for_development is False,
         'EC292_CLEANUP_ONLY_NO_READ_NO_PROVIDER')
    return svc, access, original


def _positive_proof(pol: dict, op: str, job_sha: str) -> tuple[dict, str]:
    prev = parent_policy(pol)
    raw = old.private_file(pol['readback_result_file'], MAX_PROOF)
    wrapper = io.parse(raw, MAX_PROOF)
    # Verify *original EC291 host signature*, not an unauthenticated stdout flag.
    fields(wrapper, {'schema', 'verified_server_signature', 'result', 'signed_reply',
        'verified_private_local_git_ref_observed',
        'private_git_only_not_production_publication',
        'public_or_production_published', 'original_docs_publish_retried',
        'worktree_cleanup_attempted', 'private_document_bytes_or_paths_returned',
        'automatic_git_read_or_publish_retry_allowed',
        'organization_signer_independence_verified'},
        'EC292_EC291_COMPLETE_SIGNED_PROOF_REQUIRED')
    need(wrapper['schema'] == prior.RESULT_SCHEMA and
         wrapper['verified_server_signature'] is True and
         wrapper['verified_private_local_git_ref_observed'] is True and
         wrapper['private_git_only_not_production_publication'] is True and
         all(wrapper[k] is False for k in (
             'public_or_production_published', 'original_docs_publish_retried',
             'worktree_cleanup_attempted', 'private_document_bytes_or_paths_returned',
             'automatic_git_read_or_publish_retry_allowed',
             'organization_signer_independence_verified')),
         'EC292_ONLY_POSITIVE_EC291_PRIVATE_GIT_PROOF_ALLOWED')
    reply = fields(wrapper['signed_reply'], {'schema', 'nonce', 'request_sha256',
        'policy_sha256', 'job_sha256', 'issued_at_unix', 'result',
        'signature_ed25519'}, 'EC292_EC291_SIGNED_REPLY_FIELDS_REQUIRED')
    need(reply['schema'] == prior.REPLY_SCHEMA and
         type(reply['nonce']) is str and HEX_NONCE.fullmatch(reply['nonce']) is not None and
         type(reply['request_sha256']) is str and HEX.fullmatch(reply['request_sha256']) is not None and
         reply['policy_sha256'] == pol['ec291_policy_sha256'] and
         reply['job_sha256'] == job_sha and
         type(reply['issued_at_unix']) is int and
         reply['result'] == wrapper['result'],
         'EC292_EC291_REPLY_NOT_BOUND_TO_THIS_ORIGINAL_JOB')
    prior.verify('server', {k: v for k, v in reply.items()
                            if k != 'signature_ed25519'},
                 reply['signature_ed25519'], prev['server_public_hex'])
    result = prior.validate_backend(wrapper['result'], op)
    need(result['status'] == 'partial' and result['exit_code'] == 2 and
         result['reason_code'] == 'PUBLICATION_RECEIPT_VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
         result['receipt_state'] == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
         result['inspection_id'] is not None and
         result['observation_sha256'] is not None and
         result['operation_id'] == op,
         'EC292_ONLY_EC291_POSITIVE_INSPECTION_CAN_AUTHORIZE_CLEANUP')
    return result, sha(canonical(wrapper))


def exact_snapshot(pol: dict, *, require_worktree: bool = True) -> dict:
    """Check the positive EC291 result, EC230 audit and live exact Git identity.

    No new EC230 read nonce is spent; only the already-audited observation is
    consumed. The original cleanup_docs will independently repeat the checks.
    """
    prev = parent_policy(pol)
    svc, access, req = service(pol)
    pub, op, target, original_grant, journal, pins = svc._base(
        rec.MODE_DOCS, req, access)
    original_scope = prior.operation_scope(prev)
    need(original_scope == {'operation_sha256': op, 'target_sha256': target,
                            'original_grant_sha256': original_grant},
         'EC292_ORIGINAL_OPERATION_PINS_DRIFT')
    proof, proof_sha = _positive_proof(pol, op, prev['job_sha256'])
    inspection_id = proof['inspection_id']
    audit = rec._read_observation(svc.audit, inspection_id)
    claim, attempt, obs = [audit[x] for x in ('00_CLAIM', '01_ATTEMPT', '02_OBSERVATION')]
    now = rec._time()
    need(claim == {'mode': rec.MODE_DOCS, 'operation_id': op,
                   'original_grant_sha256': original_grant,
                   'target_sha256': target,
                   'inspection_nonce': claim.get('inspection_nonce')} and
         type(claim.get('inspection_nonce')) is str and
         HEX_NONCE.fullmatch(claim['inspection_nonce']) is not None and
         inspection_id == dp.sha(rec.READ_ID_DOMAIN, {
             'mode': rec.MODE_DOCS, 'operation_id': op,
             'inspection_nonce': claim['inspection_nonce'],
             'target_sha256': target}) and
         attempt.get('kind') == 'LOCAL_PRIVATE_GIT_READ_ONLY' and
         obs.get('inspection_id') == inspection_id and
         obs.get('mode') == rec.MODE_DOCS and
         obs.get('operation_id') == op and
         obs.get('original_grant_sha256') == original_grant and
         obs.get('target_sha256') == target and
         obs.get('state') == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
         dp.sha(rec.OBS_DOMAIN, obs) == proof['observation_sha256'] and
         type(obs.get('observed_at')) is int and
         0 <= now - obs['observed_at'] <= rec.MAX_OBSERVATION_AGE,
         'EC292_EC230_SIGNED_POSITIVE_READ_OBSERVATION_MUST_BE_RECENT')
    markers, payloads, journal_sha = rec._view_markers(
        journal, 'ec229-' + op, '00_CLAIM_DURABLE', rec._ALLOWED_DOCS,
        frozenset(('05_COMMIT_CREATED', '07_SANDBOX_REF_OBSERVED')))
    need(journal_sha == obs.get('journal_sha256') == attempt.get('journal_sha256') and
         {'05_COMMIT_CREATED', '06_PUSH_ATTEMPTED'}.issubset(markers),
         'EC292_ORIGINAL_GIT_JOURNAL_CHANGED_OR_INCOMPLETE')
    state, candidate = svc._observe_ref(pub, op, pins['contents'], markers, payloads)
    need(state == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
         candidate == obs.get('candidate_commit') and candidate is not None,
         'EC292_PRIVATE_REF_NOT_IDENTICAL_TO_EC291_OBSERVATION')
    pub._source_ready(pins['contents'])
    if require_worktree:
        _, inode = svc._eligible_worktree(pub, op, candidate, pins['contents'])
    else:
        inode = (0, 0)
    return {'operation_sha256': op, 'target_sha256': target,
            'original_grant_sha256': original_grant,
            'inspection_id': inspection_id,
            'observation_sha256': proof['observation_sha256'],
            'candidate_commit_sha': candidate, 'worktree_inode': list(inode),
            'readback_sha256': proof_sha}


def cleanup_statement(doc: Any, public_hex: str, snapshot: dict,
                      receipt_epoch: int) -> da.SignedAuthorizationStatement:
    try:
        fields(doc, {'statement', 'signature_hex'},
               'EC292_ORIGINAL_EC230_CLEANUP_SIGNATURE_ENVELOPE_REQUIRED')
        signed = da.SignedAuthorizationStatement(doc['statement'], doc['signature_hex'])
        body = rec._signed(signed, bytes.fromhex(public_hex), rec.CLEAN_DOMAIN, {
            'schema', 'mode', 'operation_id', 'target_sha256',
            'original_grant_sha256', 'inspection_id', 'observation_sha256',
            'candidate_commit_sha', 'worktree_inode', 'cleanup_epoch',
            'permission', 'code_revision_sha256', 'issued_at', 'expires_at'},
            'CLEANUP_GRANT')
        rec._window(body, rec._time())
        mapping = {'operation_sha256': 'operation_id', 'target_sha256': 'target_sha256',
            'original_grant_sha256': 'original_grant_sha256',
            'inspection_id': 'inspection_id', 'observation_sha256': 'observation_sha256',
            'candidate_commit_sha': 'candidate_commit_sha',
            'worktree_inode': 'worktree_inode'}
        need(body['schema'] == rec.CLEAN_SCHEMA and body['mode'] == rec.MODE_DOCS and
             body['permission'] == rec.CLEAN_PERMISSION and
             body['code_revision_sha256'] == rec.ACTIVE_CODE_SHA256 and
             body['cleanup_epoch'] >= receipt_epoch and
             body['expires_at'] - body['issued_at'] <= 36 and
             all(body[side] == snapshot[own] for own, side in mapping.items()),
             'EC292_ORIGINAL_CLEANUP_NOT_EXACTLY_BOUND_TO_OBSERVATION',
             'permission_denied')
        return signed
    except (rec.ReceiptDenied, da.AuthorizationDenied, ValueError,
            TypeError, KeyError) as exc:
        raise HostError('EC292_ORIGINAL_EC230_CLEANUP_GRANT_INVALID',
                        'permission_denied') from exc


def new_subject(pol: dict, policy_sha: str, cleanup: dict,
                uid: int, ttl: int) -> dict:
    need(type(uid) is int and uid in pol['allowed_uids'] and
         type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC292_UID_OR_SHORT_HOST_TTL_INVALID', 'permission_denied')
    snap = exact_snapshot(pol)
    prev = parent_policy(pol)
    cleanup_statement(cleanup, prev['cleanup_public_hex'], snap, prev['receipt_epoch'])
    now = rec._time()
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, **{k: pol[k] for k in PINS},
        **snap, 'cleanup_grant_sha256': sha(canonical(cleanup)),
        'issued_at_unix': now, 'expires_at_unix': now + ttl})


def validate_subject(obj: Any) -> dict:
    s = fields(obj, SUBJECT_KEYS, 'EC292_HOST_SUBJECT_EXACT_FIELDS_REQUIRED')
    hashes = SUBJECT_KEYS - {'schema', 'grant_id', 'uid', 'worktree_inode',
                             'candidate_commit_sha',
                             'issued_at_unix', 'expires_at_unix'}
    need(s['schema'] == SUBJECT_SCHEMA and
         type(s['grant_id']) is str and HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s['uid']) is int and 0 <= s['uid'] <= 2**31 - 1 and
         all(type(s[k]) is str and HEX.fullmatch(s[k]) is not None for k in hashes) and
         type(s['candidate_commit_sha']) is str and
         rec.gitp.GIT_SHA.fullmatch(s['candidate_commit_sha']) is not None and
         type(s['worktree_inode']) is list and len(s['worktree_inode']) == 2 and
         all(type(n) is int and 0 <= n < 2**64 for n in s['worktree_inode']) and
         type(s['issued_at_unix']) is int and type(s['expires_at_unix']) is int and
         946684800 <= s['issued_at_unix'] < s['expires_at_unix'] <= 4102444800 and
         s['expires_at_unix'] - s['issued_at_unix'] <= MAX_TTL,
         'EC292_SHORT_EXACT_OPERATION_WORKTREE_SUBJECT_INVALID')
    return s


def sign(role: str, body: dict, key) -> str:
    return key.sign(DOMAINS[role] + canonical(body)).hex()


def verify(role: str, body: dict, signature: Any, public_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC292_OFFLINE_SIGNATURE_SHAPE_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(public_hex).verify(bytes.fromhex(signature),
                                           DOMAINS[role] + canonical(body))
    except Exception as exc:
        raise HostError('EC292_INDEPENDENT_SIGNATURE_INVALID',
                        'permission_denied') from exc


def validate_grant(grant: Any, pol: dict, cleanup: dict, uid: int,
                   policy_sha: str, now: int) -> dict:
    fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                   'reviewer_signature_ed25519'},
           'EC292_TWO_NEW_INDEPENDENT_HOST_VOTES_REQUIRED')
    need(grant['schema'] == GRANT_SCHEMA,
         'EC292_HOST_VOTE_GRANT_SCHEMA_INVALID', 'permission_denied')
    s = validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and s['uid'] == uid and
         s['policy_sha256'] == policy_sha and
         all(s[k] == pol[k] for k in PINS) and
         s['cleanup_grant_sha256'] == sha(canonical(cleanup)) and
         s['issued_at_unix'] <= now + 5 and now < s['expires_at_unix'],
         'EC292_PEER_UID_OR_SHORT_VOTE_OR_PIN_CHANGED', 'permission_denied')
    # Verify the new role signatures BEFORE touching the live repository.
    # A client cannot force expensive Git reads using an unsigned request.
    verify('custodian', s, grant['custodian_signature_ed25519'],
           pol['cleanup_custodian_public_hex'])
    verify('reviewer', s, grant['reviewer_signature_ed25519'],
           pol['independent_reviewer_public_hex'])
    snap = exact_snapshot(pol)
    need(all(s[k] == v for k, v in snap.items()),
         'EC292_LIVE_READBACK_REF_WORKTREE_OR_INODE_CHANGED', 'permission_denied')
    prev = parent_policy(pol)
    cleanup_statement(cleanup, prev['cleanup_public_hex'], snap, prev['receipt_epoch'])
    return s


def validate_backend(result: Any, operation: str | None = None) -> dict:
    fields(result, RESULT_KEYS, 'EC292_ORIGINAL_EC230_RESULT_SHAPE_DRIFT')
    need(result['schema'] == rec.SCHEMA and result['mode'] == rec.MODE_DOCS and
         (result['status'], result['exit_code']) in (
             ('partial', 2), ('blocked', 4), ('invalid_input', 4),
             ('unavailable', 5)) and
         type(result['reason_code']) is str and re.fullmatch(
             r'PUBLICATION_RECEIPT_[A-Z0-9_]{1,150}', result['reason_code']) is not None and
         (operation is None or result['operation_id'] in (None, operation)) and
         all(type(result[k]) is bool for k in (
             'historical_journal_present', 'provider_receipt_read_attempted',
             'cleanup_attempted', 'local_worktree_cleanup_confirmed',
             'public_or_production_published', 'external_publication_confirmed',
             'original_post_or_push_retried', 'remote_ref_or_provider_content_deleted',
             'original_journal_deleted', 'original_source_or_index_modified')) and
         all(result[k] is False for k in (
             'provider_receipt_read_attempted', 'public_or_production_published',
             'external_publication_confirmed', 'original_post_or_push_retried',
             'remote_ref_or_provider_content_deleted', 'original_journal_deleted',
             'original_source_or_index_modified')) and
         all(v is None or (type(v) is str and HEX.fullmatch(v) is not None)
             for v in (result['operation_id'], result['inspection_id'],
                       result['observation_sha256'])) and
         type(result['receipt_state']) is str and type(result['evidence_kind']) is str,
         'EC292_UNSAFE_OR_MALFORMED_ORIGINAL_CLEANUP_ENVELOPE')
    if result['status'] == 'partial':
        need(result['reason_code'] ==
             'PUBLICATION_RECEIPT_VERIFIED_LOCAL_WORKTREE_REMOVED_KEEP_REF_AND_JOURNALS' and
             result['operation_id'] == operation and
             result['receipt_state'] == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
             result['historical_journal_present'] is True and
             result['evidence_kind'] == 'LOCAL_GIT_PRIVATE_BARE_READBACK' and
             result['inspection_id'] is not None and
             result['observation_sha256'] is not None and
             result['cleanup_attempted'] is True and
             result['local_worktree_cleanup_confirmed'] is True,
             'EC292_ONLY_VERIFIED_LINKED_WORKTREE_REMOVAL_IS_PARTIAL')
    else:
        need(result['local_worktree_cleanup_confirmed'] is False and
             result['evidence_kind'] == 'NONE' and
             result['observation_sha256'] is None,
             'EC292_FAILED_ORIGINAL_CLEANUP_CANNOT_CLAIM_SUCCESS')
    return result


def denial(code: str, status: str = 'unavailable', *, attempted: bool = False) -> dict:
    need(status in ('unavailable', 'permission_denied', 'invalid_input'),
         'EC292_INTERNAL_DENIAL_STATUS_INVALID')
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'unavailable': 5, 'permission_denied': 3,
                          'invalid_input': 4}[status], 'reason_code': code,
            'cleanup_may_have_been_attempted': attempted,
            'cleanup_confirmed': False, 'git_ref_deleted': False,
            'original_docs_published_again': False, 'source_or_index_modified': False,
            'automatic_cleanup_or_publish_retry_allowed': False}


def signed_reply(request: dict, result: dict, policy_sha: str, job_sha: str,
                 signer, now: int) -> dict:
    body = {'schema': REPLY_SCHEMA, 'nonce': request['nonce'],
            'request_sha256': sha(canonical(request)), 'policy_sha256': policy_sha,
            'job_sha256': job_sha, 'issued_at_unix': now, 'result': result}
    return {**body, 'signature_ed25519': sign('server', body, signer)}


def verify_reply(reply: Any, request: dict, public_hex: str,
                 policy_sha: str, now: int) -> dict:
    fields(reply, {'schema', 'nonce', 'request_sha256', 'policy_sha256',
                   'job_sha256', 'issued_at_unix', 'result', 'signature_ed25519'},
           'EC292_EXACT_SERVER_REPLY_FIELDS_REQUIRED')
    subject = validate_subject(request['grant']['subject'])
    need(reply['schema'] == REPLY_SCHEMA and reply['nonce'] == request['nonce'] and
         reply['request_sha256'] == sha(canonical(request)) and
         reply['policy_sha256'] == subject['policy_sha256'] == policy_sha and
         reply['job_sha256'] == subject['job_sha256'] and
         type(reply['issued_at_unix']) is int and abs(now - reply['issued_at_unix']) <= 90,
         'EC292_SIGNED_RESULT_NONCE_OR_AUTHORITY_MISMATCH')
    verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
           reply['signature_ed25519'], public_hex)
    result = reply['result']
    if type(result) is dict and result.get('schema') == rec.SCHEMA:
        return validate_backend(result, subject['operation_sha256'])
    fields(result, set(denial('EC292_PLACEHOLDER')),
           'EC292_SIGNED_DENIAL_FIELDS_REQUIRED')
    need(result['schema'] == DENIAL_SCHEMA and
         (result['status'], result['exit_code']) in (
             ('permission_denied', 3), ('invalid_input', 4), ('unavailable', 5)) and
         type(result['reason_code']) is str and re.fullmatch(
             r'EC292_[A-Z0-9_]{1,150}', result['reason_code']) is not None and
         type(result['cleanup_may_have_been_attempted']) is bool and
         all(result[k] is False for k in (
             'cleanup_confirmed', 'git_ref_deleted', 'original_docs_published_again',
             'source_or_index_modified', 'automatic_cleanup_or_publish_retry_allowed')),
         'EC292_SIGNED_HOST_DENIAL_INVALID')
    return result

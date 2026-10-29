#!/usr/bin/env python3
"""EC283 exact chapter query: private job, two offline grants, signed response.

The server fixes the complete EC206/208/210 store selection and EC202 read
permissions. A socket client supplies only two signatures and a nonce, never
paths, query terms, source text, permissions, executable code or a callback.
Separate EC283 Ed25519 domains cannot be replayed against EC279-282 hosts.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
import knowledge_boundary as kb
import knowledge_bootstrap as bootstrap
import knowledge_candidate_store as kc
import knowledge_lifecycle as lifecycle
import knowledge_version_save as vs

POLICY_SCHEMA = 'ces.ec283.knowledge_chapters_host_policy.v1'
JOB_SCHEMA = 'ces.ec283.knowledge_chapters_exact_job.v1'
SUBJECT_SCHEMA = 'ces.ec283.knowledge_chapters_grant_subject.v1'
VOTE_SCHEMA = 'ces.ec283.knowledge_chapters_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec283.knowledge_chapters_dual_grant.v1'
REQUEST_SCHEMA = 'ces.ec283.knowledge_chapters_request.v1'
REPLY_SCHEMA = 'ces.ec283.knowledge_chapters_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec283.knowledge_chapters_denial.v1'
RESULT_SCHEMA = 'ces.ec283.verified_knowledge_chapters_result.v1'
DOMAINS = {
    'custodian': b'CES/EC283/KnowledgeQuery.Chapters/StoreCustodian/v1\0',
    'reader': b'CES/EC283/KnowledgeQuery.Chapters/ReadGrant/v1\0',
    'server': b'CES/EC283/KnowledgeQuery.Chapters/SignedReply/v1\0',
}
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'allowed_uids',
               'custodian_issuer_public_hex', 'reader_issuer_public_hex',
               'server_public_hex'}
JOB_KEYS = {'schema', 'repository_root', 'knowledge_root', 'candidate_root',
            'version_root', 'candidate_store_id', 'version_store_id',
            'repository_ref', 'knowledge_space_key', 'period_id',
            'source_policy_revision', 'chapter_path', 'trusted_approvers',
            'revoked_approvers', 'query_request', 'query_policy',
            'bootstrap_request', 'bootstrap_read_policy', 'version_evidence'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'job_sha256',
                'repository_ref', 'query_view', 'projection',
                'query_request_sha256', 'issued_at_unix', 'expires_at_unix'}
MAX_POLICY = 16_384
MAX_JOB = 768 * 1024
MAX_RPC = 16_384
MAX_REPLY = 1_200_000
MAX_TTL = 300
CLOCK_SKEW = 30
MAX_VISIBLE_SECTION_BYTES = 256 * 1024


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(obj: Any) -> bytes:
    return io.canonical(obj)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(role: str, obj: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(obj)).hex()


def verify(role: str, obj: dict, signature: Any, pub_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC283_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub_hex).verify(bytes.fromhex(signature),
                                      DOMAINS[role] + canonical(obj))
    except Exception as exc:
        raise HostError('EC283_SIGNATURE_INVALID', 'permission_denied') from exc


def validate_policy(pol: Any) -> dict:
    need(type(pol) is dict and set(pol) == POLICY_KEYS and
         pol.get('schema') == POLICY_SCHEMA,
         'EC283_PRIVATE_POLICY_FIELDS_INVALID', 'unavailable')
    need(type(pol['job_file']) is str and os.path.isabs(pol['job_file']) and
         len(pol['job_file']) <= 4096 and '\x00' not in pol['job_file'] and
         type(pol['job_sha256']) is str and
         io.HASH.fullmatch(pol['job_sha256']) is not None,
         'EC283_PRIVATE_JOB_PIN_REQUIRED', 'unavailable')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         len(set(uids)) == len(uids) and
         all(type(x) is int and 0 <= x <= 2**31-1 for x in uids),
         'EC283_ALLOWED_KERNEL_UIDS_INVALID', 'unavailable')
    keys = [pol[f'{r}_issuer_public_hex'] for r in ('custodian', 'reader')]
    keys.append(pol['server_public_hex'])
    try:
        for key in keys:
            io.pub_from_hex(key)
    except (ValueError, TypeError) as exc:
        raise HostError('EC283_HOST_SIGNERS_INVALID', 'unavailable') from exc
    need(len(set(keys)) == 3,
         'EC283_THREE_DISTINCT_SIGNER_KEYS_REQUIRED', 'unavailable')
    return pol


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC283_HOST_POLICY_SHA_REQUIRED', 'unavailable')
    raw = io._open_regular(path, MAX_POLICY, private=True)
    need(hmac.compare_digest(sha(raw), expected_sha),
         'EC283_PRIVATE_POLICY_CHANGED', 'unavailable')
    return validate_policy(io.parse(raw, MAX_POLICY))


def _plain_abs(path: Any) -> bool:
    return (type(path) is str and os.path.isabs(path) and
            path != '/' and len(path) <= 4096 and '\x00' not in path and
            os.path.normpath(path) == path and not path.startswith('//'))


def validate_job(job: Any) -> dict:
    need(type(job) is dict and set(job) == JOB_KEYS and
         job.get('schema') == JOB_SCHEMA,
         'EC283_PRIVATE_JOB_FIELDS_INVALID', 'unavailable')
    roots = [job[k] for k in ('repository_root', 'knowledge_root',
                              'candidate_root', 'version_root')]
    need(all(_plain_abs(x) for x in roots) and len(set(roots)) == 4,
         'EC283_PRIVATE_ROOTS_INVALID', 'unavailable')
    # These stores MUST already exist with their original private POSIX
    # manifests. Validate separation before any original backend opens them.
    for i, left in enumerate(roots):
        for right in roots[i + 1:]:
            one, two = os.path.realpath(left), os.path.realpath(right)
            need(os.path.commonpath((one, two)) not in (one, two),
                 'EC283_STORE_ROOTS_OVERLAP', 'unavailable')
    need(all(type(job[k]) is str and kc.STORE_ID.fullmatch(job[k]) is not None
             for k in ('candidate_store_id', 'version_store_id')),
         'EC283_STORE_IDS_INVALID', 'unavailable')
    need(type(job['repository_ref']) is str and
         kb.REPO.fullmatch(job['repository_ref']) is not None and
         all(kb.key(job[k]) for k in ('knowledge_space_key', 'period_id',
                                      'source_policy_revision')),
         'EC283_SCOPE_FIELDS_INVALID', 'unavailable')
    try:
        vs._path(job['chapter_path'])
        # This is exactly the original EC210 parser, not a hand-authored
        # replacement query language.
        req = lifecycle._query_request(kb.canonical(job['query_request']), None)
    except (vs.SaveError, lifecycle.LifecycleError, ValueError, TypeError) as exc:
        raise HostError('EC283_QUERY_REQUEST_INVALID', 'unavailable') from exc
    need(type(job['query_policy']) is dict and
         set(job['query_policy']) == {'schema', 'purpose', 'store_instance_id',
             'store_scope_binding_sha256', 'query_authorization_scope_sha256',
             'permission_receipt_sha256', 'permit_query_metadata',
             'permit_source_snapshot_text', 'permit_private_version_text',
             'permit_restricted_private_version_text', 'permit_term_search',
             'permit_full_section_return', *lifecycle.QUERY_DENIED} and
         job['query_policy'].get('schema') == lifecycle.QUERY_POLICY_SCHEMA and
         job['query_policy'].get('purpose') == lifecycle.QUERY_PURPOSE and
         all(job['query_policy'].get(k) is False for k in lifecycle.QUERY_DENIED) and
         job['query_policy'].get('permit_query_metadata') is True,
         'EC283_QUERY_POLICY_WRITE_ESCALATION_OR_FIELDS', 'unavailable')
    approved = job['trusted_approvers']
    need(type(approved) is dict and 2 <= len(approved) <= 32,
         'EC283_APPROVER_REGISTRY_MISSING', 'unavailable')
    role_keys = set()
    key_material = set()
    for name, row in approved.items():
        need(kb.key(name) and type(row) is dict and
             set(row) == {'role', 'public_hex'} and
             row['role'] in vs.ROLES and type(row['public_hex']) is str,
             'EC283_APPROVER_INVALID', 'unavailable')
        try:
            io.pub_from_hex(row['public_hex'])
        except (ValueError, TypeError) as exc:
            raise HostError('EC283_APPROVER_PUBLIC_KEY_INVALID', 'unavailable') from exc
        role_keys.add(row['role'])
        need(row['public_hex'] not in key_material,
             'EC283_APPROVER_SIGNER_DUPLICATE', 'unavailable')
        key_material.add(row['public_hex'])
    need(role_keys == set(vs.ROLES) and
         type(job['revoked_approvers']) is list and
         job['revoked_approvers'] == sorted(set(job['revoked_approvers'])) and
         all(type(k) is str and k in approved for k in job['revoked_approvers']) and
         all(any(x['role'] == r and name not in job['revoked_approvers']
                 for name, x in approved.items()) for r in vs.ROLES),
         'EC283_APPROVER_ROLES_OR_REVOCATION_INVALID', 'unavailable')
    need(req['projection'] == 'hashes_only' or
         (job['query_policy'].get('permit_source_snapshot_text') is True and
          type(job['bootstrap_request']) is dict and
          type(job['bootstrap_read_policy']) is dict),
         'EC283_FULL_TEXT_NEEDS_SEPARATE_SOURCE_AUTHORIZATION', 'unavailable')
    if req['projection'] == 'hashes_only':
        need(job['bootstrap_request'] is None and
             job['bootstrap_read_policy'] is None and
             job['version_evidence'] is None,
             'EC283_HASH_ONLY_JOB_CANNOT_CARRY_TEXT_GRANTS', 'unavailable')
    elif req['view'] == 'source_snapshot':
        need(job['version_evidence'] is None,
             'EC283_SOURCE_VIEW_CANNOT_CARRY_PRIVATE_VERSION_EVIDENCE', 'unavailable')
    elif job['version_evidence'] is not None:
        need(type(job['version_evidence']) is dict and
             job['version_evidence'].get('schema') == lifecycle.EVIDENCE_SCHEMA and
             type(job['version_evidence'].get('versions')) is list,
             'EC283_VERSION_EVIDENCE_BUNDLE_INVALID', 'unavailable')
    if job['bootstrap_request'] is not None:
        try:
            breq = bootstrap._request(job['bootstrap_request'])
        except (bootstrap.BootstrapError, ValueError, TypeError) as exc:
            raise HostError('EC283_EC202_READ_REQUEST_INVALID', 'unavailable') from exc
        need(breq['scope']['repository_ref'] == job['repository_ref'] and
             breq['scope']['knowledge_space_key'] == job['knowledge_space_key'] and
             breq['scope']['period']['period_id'] == job['period_id'] and
             breq['scope']['source_policy_revision'] == job['source_policy_revision'],
             'EC283_EC202_SOURCE_SCOPE_INVALID', 'unavailable')
    need(all(type(job[k]) is dict for k in ('query_request', 'query_policy')),
         'EC283_QUERY_JOB_INCOMPLETE', 'unavailable')
    return job


def load_job(pol: dict) -> dict:
    raw = io._open_regular(pol['job_file'], MAX_JOB, private=True)
    need(hmac.compare_digest(sha(raw), pol['job_sha256']),
         'EC283_PRIVATE_JOB_CHANGED', 'unavailable')
    return validate_job(io.parse(raw, MAX_JOB))


def validate_subject(s: Any) -> dict:
    need(type(s) is dict and set(s) == SUBJECT_KEYS and
         s.get('schema') == SUBJECT_SCHEMA and
         type(s.get('grant_id')) is str and
         io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s.get('uid')) is int and 0 <= s['uid'] <= 2**31-1,
         'EC283_OFFLINE_SUBJECT_FIELDS_INVALID')
    need(all(type(s[k]) is str and io.HASH.fullmatch(s[k]) is not None for k in
             ('policy_sha256', 'job_sha256', 'query_request_sha256')),
         'EC283_OFFLINE_SUBJECT_SHA_INVALID')
    need(type(s['repository_ref']) is str and
         kb.REPO.fullmatch(s['repository_ref']) is not None and
         s['query_view'] in ('source_snapshot', 'local_metadata_version') and
         type(s['query_view']) is str and
         s['projection'] in ('hashes_only', 'match_snippets', 'full_sections') and
         type(s['projection']) is str,
         'EC283_OFFLINE_SUBJECT_QUERY_INVALID')
    a, b = s['issued_at_unix'], s['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and
         b-a <= MAX_TTL, 'EC283_OFFLINE_SUBJECT_TTL_INVALID')
    return s


def new_subject(*, uid: int, policy_sha: str, job_sha: str, repository_ref: str,
                query_view: str, projection: str, query_sha: str,
                ttl: int, now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC283_SIGNED_GRANT_TTL_OUT_OF_RANGE')
    t = int(time.time()) if now is None else now
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, 'job_sha256': job_sha,
        'repository_ref': repository_ref, 'query_view': query_view,
        'projection': projection, 'query_request_sha256': query_sha,
        'issued_at_unix': t, 'expires_at_unix': t+ttl})


def validate_grant(grant: Any, pol: dict, job: dict, *, uid: int,
                   now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
        'schema', 'subject', 'custodian_signature_ed25519',
        'reader_signature_ed25519'} and grant['schema'] == GRANT_SCHEMA,
        'EC283_DUAL_OFFLINE_GRANT_FIELDS_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (HostError, TypeError, KeyError, ValueError) as exc:
        raise HostError('EC283_OFFLINE_SUBJECT_INVALID', 'permission_denied') from exc
    original = job['query_request']
    need(uid in pol['allowed_uids'] and uid == s['uid'] and
         hmac.compare_digest(s['policy_sha256'], policy_sha) and
         hmac.compare_digest(s['job_sha256'], pol['job_sha256']) and
         s['repository_ref'] == job['repository_ref'] and
         s['query_view'] == original['view'] and
         s['projection'] == original['projection'] and
         hmac.compare_digest(s['query_request_sha256'], sha(canonical(original))),
         'EC283_UID_OR_PINNED_QUERY_NOT_AUTHORIZED', 'permission_denied')
    need(s['issued_at_unix'] <= now+CLOCK_SKEW and now < s['expires_at_unix'],
         'EC283_OFFLINE_GRANT_EXPIRED_OR_FUTURE', 'permission_denied')
    for role in ('custodian', 'reader'):
        verify(role, s, grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return s


def denial(reason: str, status: str = 'permission_denied',
           *, backend_invoked: bool | None = False) -> dict:
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': reason, 'handler_invoked': backend_invoked,
            'data_disclosed': False, 'repository_written': False,
            'knowledge_written': False, 'private_metadata_written': False,
            'business_effect_verified': False}


def safe_backend_result(result: Any, *, projection: str, view: str,
                        section_indices: list[int] | None = None) -> bool:
    """Reject original partial results that cannot support an exact disclosure.

    Caller-provided business claims are never deemed organizational truth.
    Read the original EC210 selected section hashes and verify decoded text
    matches those exact fingerprints, not just a successful JSON status.
    """
    if (type(result) is not dict or result.get('schema') != lifecycle.SCHEMA or
        result.get('status') != 'partial' or result.get('exit_code') != 2 or
        result.get('reason_code') !=
            'KNOWLEDGE_LIFECYCLE_EXACT_LOCAL_KNOWLEDGE_QUERY_NOT_PUBLISHED' or
        any(result.get(k) is not False for k in (
            'candidate_metadata_written', 'local_version_metadata_written',
            'local_write_outcome_unknown', 'source_knowledge_file_written',
            'business_repository_written', 'issue_or_provider_written',
            'docs_only_publish_invoked', 'published',
            'candidate_promoted_to_verified_fact',
            'organizational_authority_authenticated',
            'live_git_delivery_currentness_proven',
            'native_knowledge_route_registered'))):
        return False
    s = result.get('subject')
    if (type(s) is not dict or s.get('view') != view or
        s.get('projection') != projection or
        s.get('metadata_only_without_query_grants') is not False or
        s.get('source_snapshot_is_not_verified_current_architecture') is not True or
        s.get('private_versions_not_authoritative_or_published') is not True or
        s.get('external_or_native_actions_performed') is not False or
        type(s.get('selected_sections')) is not list or
        type(s.get('section_fingerprints')) is not list):
        return False
    selections = s['selected_sections']
    pins = s['section_fingerprints']
    if len(selections) != len(pins) or not 1 <= len(selections) <= lifecycle.MAX_SECTIONS:
        return False
    if section_indices is not None and section_indices != [x.get('ordinal') for x in pins]:
        return False
    total = 0
    for entry, pin in zip(selections, pins):
        if type(entry) is not dict or type(pin) is not dict or \
                entry.get('ordinal') != pin.get('ordinal') or \
                type(pin.get('sha256')) is not str or \
                io.HASH.fullmatch(pin['sha256']) is None or \
                entry.get('section_sha256') != pin['sha256'] or \
                type(pin.get('length_bytes')) is not int or \
                not 0 <= pin['length_bytes'] <= MAX_VISIBLE_SECTION_BYTES:
            return False
        if projection == 'hashes_only':
            if set(entry) != {'ordinal', 'section_sha256'}:
                return False
        elif projection == 'match_snippets':
            if set(entry) != {'ordinal', 'section_sha256', 'matching_lines'} or \
                    type(entry['matching_lines']) is not list or \
                    len(entry['matching_lines']) > lifecycle.MAX_MATCHES:
                return False
            for line in entry['matching_lines']:
                if (type(line) is not dict or set(line) != {
                    'line_number_in_section', 'excerpt',
                    'excerpt_truncated_left', 'excerpt_truncated_right'} or
                    type(line['line_number_in_section']) is not int or
                    line['line_number_in_section'] < 1 or
                    type(line['excerpt']) is not str or
                    len(line['excerpt']) > lifecycle.MAX_SNIPPET_CHARS or
                    type(line['excerpt_truncated_left']) is not bool or
                    type(line['excerpt_truncated_right']) is not bool):
                    return False
        else:
            if set(entry) != {'ordinal', 'section_sha256',
                              'section_content_base64'}:
                return False
            try:
                raw = base64.b64decode(entry['section_content_base64'], validate=True)
            except (ValueError, TypeError, binascii.Error):
                return False
            if (base64.b64encode(raw).decode('ascii') != entry['section_content_base64'] or
                len(raw) != pin['length_bytes'] or
                not hmac.compare_digest(sha(raw), pin['sha256'])):
                return False
            total += len(raw)
    return total <= MAX_VISIBLE_SECTION_BYTES


def signed_reply(req: dict, result: dict, policy_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    payload = {'schema': REPLY_SCHEMA, 'request_sha256': sha(canonical(req)),
               'nonce': req['nonce'], 'policy_sha256': policy_sha,
               'job_sha256': job_sha, 'issued_at_unix': now, 'result': result}
    return {**payload, 'signature_ed25519': sign('server', payload, key)}


def verify_reply(reply: Any, request: dict, *, server_public_hex: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {'schema', 'request_sha256',
        'nonce', 'policy_sha256', 'job_sha256', 'issued_at_unix', 'result',
        'signature_ed25519'} and reply.get('schema') == REPLY_SCHEMA,
        'EC283_SIGNED_REPLY_FIELDS_INVALID', 'unavailable')
    s = validate_subject(request['grant']['subject'])
    need(all(type(reply[k]) is str and io.HASH.fullmatch(reply[k]) is not None
             for k in ('request_sha256', 'policy_sha256', 'job_sha256')) and
         type(reply['nonce']) is str and
         type(reply['issued_at_unix']) is int,
         'EC283_SIGNED_REPLY_PINS_INVALID', 'unavailable')
    need(reply['nonce'] == request['nonce'] and
         hmac.compare_digest(reply['request_sha256'], sha(canonical(request))) and
         hmac.compare_digest(reply['policy_sha256'], policy_sha) and
         reply['policy_sha256'] == s['policy_sha256'] and
         reply['job_sha256'] == s['job_sha256'] and
         abs(now-reply['issued_at_unix']) <= 180,
         'EC283_SIGNED_REPLY_SCOPE_OR_TIME_MISMATCH', 'unavailable')
    try:
        verify('server', {k: v for k, v in reply.items()
                          if k != 'signature_ed25519'},
               reply['signature_ed25519'], server_public_hex)
    except HostError as exc:
        raise HostError('EC283_SIGNED_REPLY_SERVER_SIGNATURE_INVALID',
                        'unavailable') from exc
    res = reply['result']
    if type(res) is not dict:
        raise HostError('EC283_SIGNED_REPLY_RESULT_INVALID', 'unavailable')
    if res.get('status') == 'partial':
        need(safe_backend_result(res, projection=s['projection'],
                                 view=s['query_view']),
             'EC283_SIGNED_REPLY_UNSUPPORTED_PROJECTION', 'unavailable')
    else:
        need(res.get('schema') == DENIAL_SCHEMA and
             (res.get('status'), res.get('exit_code')) in (
                 ('permission_denied', 3), ('invalid_input', 4),
                 ('unavailable', 5)) and
             all(res.get(k) is False for k in ('data_disclosed',
                 'repository_written', 'knowledge_written',
                 'private_metadata_written', 'business_effect_verified')),
             'EC283_SIGNED_REPLY_DENIAL_INVALID', 'unavailable')
    return res

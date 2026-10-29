#!/usr/bin/env python3
"""EC287 exact IssueCreate.Create: private evidence + original EC217/218, signed wire.

No caller-provided tokens, business text, authority registry, repository path, or
HTTP URL crosses the socket. Only two domain-separated offline votes for one
private pinned job can invoke the unchanged original EC218 create operation.
A host reply authenticates a *provider claim*, not an independent remote read.
"""
from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import time
import types
from typing import Any, get_args, get_origin, get_type_hints, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
import issue_provider as ip
import issue_eligibility as ie
import issue_match as im
import issue_plan as plan
import issue_create_grant as cg
import issue_create_write as cw

POLICY_SCHEMA = 'ces.ec287.issue_create_host_policy.v1'
JOB_SCHEMA = 'ces.ec287.issue_create_private_job.v1'
TRUST_SCHEMA = 'ces.ec287.issue_create_host_trust.v1'
ACCESS_SCHEMA = 'ces.ec287.issue_create_host_access.v1'
SUBJECT_SCHEMA = 'ces.ec287.issue_create_offline_subject.v1'
VOTE_SCHEMA = 'ces.ec287.issue_create_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec287.issue_create_two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec287.issue_create_request.v1'
REPLY_SCHEMA = 'ces.ec287.issue_create_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec287.issue_create_host_denial.v1'
RESULT_SCHEMA = 'ces.ec287.verified_issue_create_result.v1'
DOMAINS = {
    'custodian': b'CES/EC287/IssueCreate/Create/PrivateEvidenceCustodian/v1\0',
    'authorizer': b'CES/EC287/IssueCreate/Create/RemoteWriteAuthorizer/v1\0',
    'server': b'CES/EC287/IssueCreate/Create/SignedHostReply/v1\0',
}
MAX_POLICY = 12000
MAX_JOB = 250000
MAX_TRUST = 40000
MAX_ACCESS = 8192
MAX_TOKEN = 4200
MAX_RPC = 8192
MAX_REPLY = 13000
MAX_TTL = 30
CLOCK_SKEW = 5
CODE_FILES = ('issue_provider.py', 'issue_existing_readonly.py',
              'issue_eligibility.py', 'issue_match.py', 'issue_plan.py',
              'issue_create_grant.py', 'issue_create_write.py')
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'trust_file', 'trust_sha256',
               'access_file', 'access_sha256', 'token_file', 'reservation_db',
               'attempt_db', 'host_grant_db', 'allowed_uids',
               'custodian_issuer_public_hex', 'authorizer_issuer_public_hex',
               'server_public_hex', 'enable_exact_remote_create'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'job_sha256',
                'trust_sha256', 'access_sha256', 'backend_sha256',
                'operation_sha256', 'approval_sha256',
                'issued_at_unix', 'expires_at_unix'}
BACKEND_KEYS = {'schema', 'status', 'exit_code', 'reason_code', 'create_state',
                'operation_sha256', 'provider_issue_identity_sha256',
                'synthetic', 'ec217_original_reservation_confirmed',
                'durable_attempt_barrier_recorded', 'provider_post_invoked',
                'same_request_replay_blocked', 'provider_reported_created',
                'issue_created', 'remote_creation_independently_reread',
                'provider_write_may_have_occurred',
                'external_final_text_may_have_been_disclosed',
                'permission_to_modify_existing_issues', 'issue_edited',
                'issue_closed', 'comment_created', 'business_repository_written',
                'git_or_knowledge_written', 'external_ai_called',
                'published_or_delivered', 'native_issue_action_registered',
                'all_existing_issues_enumerated', 'duplicate_absence_proven',
                'organizational_authority_independently_authenticated_by_ces',
                'safe_next_step'}


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input'):
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


def sign(role: str, payload: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(payload)).hex()


def verify(role: str, payload: dict, sig: Any, pub: str) -> None:
    need(type(sig) is str and io.HEX_SIG.fullmatch(sig) is not None,
         'EC287_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(sig),
                                    DOMAINS[role] + canonical(payload))
    except Exception as exc:
        raise HostError('EC287_SIGNATURE_INVALID', 'permission_denied') from exc


def plain_abs(s: Any) -> bool:
    return (type(s) is str and s.startswith('/') and s != '/' and
            not s.startswith('//') and '\x00' not in s and len(s) < 2048 and
            os.path.normpath(s) == s)


def private_parent(path: str) -> None:
    need(plain_abs(path), 'EC287_PRIVATE_ABSOLUTE_PATH_REQUIRED', 'unavailable')
    try:
        target = Path(path)
        need(not any(p.is_symlink() for p in (target, *target.parents)),
             'EC287_PRIVATE_PATH_SYMLINK_REJECTED', 'unavailable')
        st = os.lstat(target.parent)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) & 0o077 == 0,
             'EC287_PRIVATE_PARENT_MUST_BE_OWNER_ONLY', 'unavailable')
    except OSError as exc:
        raise HostError('EC287_PRIVATE_PARENT_UNAVAILABLE', 'unavailable') from exc


def private_file(path: str, limit: int) -> bytes:
    private_parent(path)
    try:
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) & 0o077 == 0 and st.st_nlink == 1,
             'EC287_PRIVATE_FILE_IDENTITY_OR_PERMISSIONS_INVALID', 'unavailable')
        return io._open_regular(path, limit, private=True)
    except OSError as exc:
        raise HostError('EC287_PRIVATE_FILE_UNAVAILABLE', 'unavailable') from exc


def pinned_doc(path: str, pin: str, limit: int) -> dict:
    raw = private_file(path, limit)
    need(hmac.compare_digest(sha(raw), pin),
         'EC287_OWNER_PRIVATE_RAW_BYTES_CHANGED', 'unavailable')
    return io.parse(raw, limit)


def code_sha256() -> str:
    """Bind original code bytes, not merely the new bridge's source tree."""
    root = Path(__file__).resolve().parents[1]
    h = hashlib.sha256(b'CES/EC287/ORIGINAL-EC211-220-CREATE-CODE/v1\0')
    for name in CODE_FILES:
        path = root / name
        need(not path.is_symlink() and path.is_file(),
             'EC287_ORIGINAL_BACKEND_SOURCE_MISSING', 'unavailable')
        raw = path.read_bytes()
        h.update(name.encode('ascii') + b'\0' + len(raw).to_bytes(8, 'big') + raw)
    return h.hexdigest()


def _decode_type(kind: Any, value: Any) -> Any:
    if kind is Any:
        return value  # strict JSON parsing and raw job byte limit already applied
    if kind is type(None):
        need(value is None, 'EC287_ORIGINAL_DATA_NONE_REQUIRED')
        return None
    if kind in (str, int, bool):
        need(type(value) is kind, 'EC287_ORIGINAL_DATA_SCALAR_TYPE_INVALID')
        return value
    origin = get_origin(kind)
    args = get_args(kind)
    if origin in (Union, types.UnionType):
        failures = []
        for item in args:
            try:
                return _decode_type(item, value)
            except HostError as exc:
                failures.append(exc)
        raise HostError('EC287_ORIGINAL_DATA_UNION_TYPE_INVALID')
    if origin is tuple:
        need(type(value) in (tuple, list), 'EC287_ORIGINAL_DATA_SEQUENCE_INVALID')
        if len(args) == 2 and args[-1] is Ellipsis:
            need(len(value) <= 64, 'EC287_ORIGINAL_DATA_SEQUENCE_TOO_LONG')
            return tuple(_decode_type(args[0], item) for item in value)
        need(len(value) == len(args), 'EC287_ORIGINAL_DATA_TUPLE_LENGTH_INVALID')
        return tuple(_decode_type(item, value[i]) for i, item in enumerate(args))
    if origin is dict:
        need(type(value) is dict, 'EC287_ORIGINAL_DATA_MAPPING_INVALID')
        return {_decode_type(args[0], k): _decode_type(args[1], v)
                for k, v in value.items()}
    need(is_dataclass(kind) and kind in SAFE_TYPES,
         'EC287_ORIGINAL_DATA_CLASS_NOT_ALLOWED')
    need(type(value) is dict, 'EC287_ORIGINAL_DATA_CLASS_NOT_OBJECT')
    hints = get_type_hints(kind)
    entries = fields(kind)
    need(set(value) == {f.name for f in entries},
         'EC287_ORIGINAL_DATA_CLASS_FIELDS_INVALID')
    return kind(**{f.name: _decode_type(hints[f.name], value[f.name]) for f in entries})


SAFE_TYPES = frozenset((ip.ProviderContext, im.EvidenceAnchor, im.MatchCandidate,
                        im.IssueMatchRequest, ie.FindingBasis, ie.PrivacyScope,
                        ie.EligibilityRequest, ie.HumanReviewReceipt,
                        plan.SelectedSourceRef, plan.IssuePlanRequest,
                        cg.Citation, cg.FinalIssueContent, cg.IssueCreateIntent,
                        cg.PlanEvidence, cg.HumanCreateApproval))


def validate_job(job: Any) -> dict:
    need(type(job) is dict and set(job) == {
         'schema', 'evidence', 'intent', 'content', 'approval'} and
         job.get('schema') == JOB_SCHEMA,
         'EC287_EXACT_PRIVATE_JOB_FIELDS_INVALID', 'unavailable')
    values = {k: _decode_type(cls, job[k]) for k, cls in (
        ('evidence', cg.PlanEvidence), ('intent', cg.IssueCreateIntent),
        ('content', cg.FinalIssueContent), ('approval', cg.HumanCreateApproval))}
    evidence, intent, content, approval = (values[k] for k in
                                         ('evidence', 'intent', 'content', 'approval'))
    need(intent.action == cg.ACTION and
         (intent.provider, intent.api_host, intent.account_ref) ==
         (evidence.context.provider, evidence.context.api_host,
          evidence.context.account_ref) and
         intent.expected_final_content_sha256 == cg.final_content_sha256(content) and
         intent.expected_plan_result_sha256 == cg.plan_result_sha256(evidence.plan_result) and
         intent.audience == approval.audience and
         intent.policy_revision_sha256 == approval.policy_revision_sha256,
         'EC287_ORIGINAL_JOB_INTENT_APPROVAL_MISMATCH', 'unavailable')
    return values


def load_job(pol: dict) -> dict:
    return validate_job(pinned_doc(pol['job_file'], pol['job_sha256'], MAX_JOB))


def validate_trust(doc: Any) -> dict:
    need(type(doc) is dict and set(doc) == {'schema', 'eligibility_review_keys_hex',
                                           'issuers'} and doc.get('schema') == TRUST_SCHEMA and
         type(doc['eligibility_review_keys_hex']) is dict and
         type(doc['issuers']) is dict and
         1 <= len(doc['eligibility_review_keys_hex']) <= 16 and
         1 <= len(doc['issuers']) <= 32,
         'EC287_TRUST_REGISTRY_FIELDS_INVALID', 'unavailable')
    for name, key in doc['eligibility_review_keys_hex'].items():
        need(type(name) is str and 1 <= len(name) <= 128 and
             type(key) is str and len(key) == 64,
             'EC287_REVIEW_KEY_INVALID', 'unavailable')
        io.pub_from_hex(key)
    fields_ = {f.name for f in fields(cg.IssuerAuthority)} - {'public_key'}
    for name, entry in doc['issuers'].items():
        need(type(name) is str and len(name) <= 128 and
             type(entry) is dict and set(entry) == fields_ | {'public_key_hex'},
             'EC287_ISSUER_AUTHORITY_FIELDS_INVALID', 'unavailable')
        io.pub_from_hex(entry['public_key_hex'])
        need(type(entry['revoked']) is bool and
             all(type(entry[f.name]) is str for f in fields(cg.IssuerAuthority)
                 if f.name not in ('public_key', 'revoked')),
             'EC287_ISSUER_AUTHORITY_TYPES_INVALID', 'unavailable')
    return doc


def load_trust(pol: dict) -> dict:
    return validate_trust(pinned_doc(pol['trust_file'], pol['trust_sha256'], MAX_TRUST))


def build_trust(doc: dict) -> tuple[dict[str, bytes], dict[str, cg.IssuerAuthority]]:
    return ({k: bytes.fromhex(v) for k, v in doc['eligibility_review_keys_hex'].items()},
            {k: cg.IssuerAuthority(public_key=bytes.fromhex(v['public_key_hex']),
                                   **{f.name: v[f.name] for f in fields(cg.IssuerAuthority)
                                      if f.name != 'public_key'})
             for k, v in doc['issuers'].items()})


def validate_access(doc: Any) -> cw.HostCreateAccess:
    entries = {f.name for f in fields(cw.HostCreateAccess)}
    need(type(doc) is dict and set(doc) == entries | {'schema'} and
         doc.get('schema') == ACCESS_SCHEMA,
         'EC287_ACCESS_FIELDS_INVALID', 'unavailable')
    data = {k: v for k, v in doc.items() if k != 'schema'}
    types_ = get_type_hints(cw.HostCreateAccess)
    for k, v in data.items():
        need(type(v) is types_[k], 'EC287_ACCESS_FIELD_TYPE_INVALID', 'unavailable')
    need(all(data[k] is True for k in ('network_opt_in', 'create_new_issue_opt_in',
                                      'current_provider_credentials_attested_by_host')),
         'EC287_HOST_EXPLICIT_NETWORK_AND_CREATE_OPT_INS_REQUIRED', 'unavailable')
    return cw.HostCreateAccess(**data)


def load_access(pol: dict) -> cw.HostCreateAccess:
    return validate_access(pinned_doc(pol['access_file'],pol['access_sha256'],MAX_ACCESS))


def validate_policy(pol: Any) -> dict:
    need(type(pol) is dict and set(pol) == POLICY_KEYS and
         pol.get('schema') == POLICY_SCHEMA and
         pol.get('enable_exact_remote_create') is True,
         'EC287_PRIVATE_POLICY_INVALID', 'unavailable')
    for k in ('job_file', 'trust_file', 'access_file', 'token_file',
              'reservation_db', 'attempt_db', 'host_grant_db'):
        need(plain_abs(pol[k]), 'EC287_POLICY_PRIVATE_PATH_INVALID', 'unavailable')
    need(len({pol[k] for k in ('job_file', 'trust_file', 'access_file',
          'token_file', 'reservation_db', 'attempt_db', 'host_grant_db')}) == 7,
         'EC287_PRIVATE_FILE_PATH_COLLISION', 'unavailable')
    for k in ('job_sha256','trust_sha256','access_sha256'):
        need(type(pol[k]) is str and io.HASH.fullmatch(pol[k]) is not None,
             'EC287_PRIVATE_PIN_INVALID', 'unavailable')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(n) is int and 0 <= n <= 2**31-1 for n in uids) and
         uids == sorted(set(uids)), 'EC287_PEER_UID_ALLOWLIST_INVALID', 'unavailable')
    keys = [pol[k] for k in ('custodian_issuer_public_hex',
                            'authorizer_issuer_public_hex','server_public_hex')]
    for key in keys:
        io.pub_from_hex(key)
    need(len(set(keys)) == 3, 'EC287_THREE_DISTINCT_SIGNERS_REQUIRED', 'unavailable')
    return pol


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC287_POLICY_SHA_REQUIRED', 'unavailable')
    return validate_policy(pinned_doc(path, expected_sha, MAX_POLICY))


def job_pins(pol: dict, job: dict) -> dict:
    return {'job_sha256': pol['job_sha256'],
            'trust_sha256': pol['trust_sha256'],
            'access_sha256': pol['access_sha256'],
            'backend_sha256': code_sha256(),
            'operation_sha256': cw.operation_sha256(job['intent']),
            'approval_sha256': sha(canonical(job['approval'].__dict__))}


def validate_subject(s: Any) -> dict:
    need(type(s) is dict and set(s) == SUBJECT_KEYS and
         s.get('schema') == SUBJECT_SCHEMA and
         type(s.get('grant_id')) is str and
         io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s.get('uid')) is int and 0 <= s['uid'] <= 2**31-1 and
         all(type(s.get(k)) is str and io.HASH.fullmatch(s[k]) is not None for k in
             ('policy_sha256','job_sha256','trust_sha256','access_sha256',
              'backend_sha256','operation_sha256','approval_sha256')),
         'EC287_SUBJECT_FIELDS_INVALID')
    t, end = s['issued_at_unix'], s['expires_at_unix']
    need(type(t) is int and type(end) is int and 0 < t < end and
         end-t <= MAX_TTL, 'EC287_SUBJECT_TTL_INVALID')
    return s


def new_subject(uid: int, policy_sha: str, pins: dict, ttl: int) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL, 'EC287_TTL_OUT_OF_RANGE')
    t = int(time.time())
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, **pins,
        'issued_at_unix': t, 'expires_at_unix': t+ttl})


def validate_grant(grant: Any, pol: dict, job: dict, *,
                   uid: int, now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
         'schema','subject','custodian_signature_ed25519',
         'authorizer_signature_ed25519'} and grant.get('schema') == GRANT_SCHEMA,
         'EC287_TWO_OFFLINE_SIGNATURES_REQUIRED', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (HostError,ValueError,KeyError,TypeError) as exc:
        raise HostError('EC287_SIGNED_SUBJECT_INVALID','permission_denied') from exc
    need(uid in pol['allowed_uids'] and s['uid'] == uid and
         s['policy_sha256'] == policy_sha and
         all(s[k] == v for k, v in job_pins(pol,job).items()) and
         s['issued_at_unix'] <= now + CLOCK_SKEW and
         now < s['expires_at_unix'],
         'EC287_PEER_SCOPE_PRIVATE_PIN_OR_TIME_CHANGED', 'permission_denied')
    for role in ('custodian','authorizer'):
        verify(role,s,grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return s


def validate_backend(result: Any, operation_sha: str) -> dict:
    need(type(result) is dict and set(result) == BACKEND_KEYS and
         result.get('schema') == cw.SCHEMA and
         (result.get('status'),result.get('exit_code')) in (
             ('partial',2),('invalid_input',4),('unavailable',5)) and
         type(result.get('reason_code')) is str and
         result['reason_code'].startswith('ISSUE_CREATE_WRITE_') and
         len(result['reason_code']) <= 190 and
         result['reason_code'].replace('_','').isalnum() and
         type(result.get('create_state')) is str and
         type(result.get('synthetic')) is bool and
         result.get('synthetic') is False and
         result.get('remote_creation_independently_reread') is False and
         result.get('permission_to_modify_existing_issues') is False and
         result.get('issue_edited') is False and
         result.get('issue_closed') is False and
         result.get('comment_created') is False and
         result.get('business_repository_written') is False and
         result.get('git_or_knowledge_written') is False and
         result.get('external_ai_called') is False and
         result.get('published_or_delivered') is False and
         result.get('native_issue_action_registered') is False and
         result.get('all_existing_issues_enumerated') is False and
         result.get('duplicate_absence_proven') is False and
         result.get('organizational_authority_independently_authenticated_by_ces') is False,
         'EC287_ORIGINAL_EC218_RESULT_NOT_ACCEPTABLE', 'unavailable')
    for field in ('ec217_original_reservation_confirmed',
                  'durable_attempt_barrier_recorded','provider_post_invoked',
                  'same_request_replay_blocked','provider_reported_created',
                  'issue_created','provider_write_may_have_occurred',
                  'external_final_text_may_have_been_disclosed'):
        need(type(result.get(field)) is bool,
             'EC287_ORIGINAL_RESULT_BOOLEAN_INVALID','unavailable')
    op = result['operation_sha256']
    need(op is None or (type(op) is str and op == operation_sha),
         'EC287_ORIGINAL_OPERATION_PIN_MISMATCH','unavailable')
    identity = result['provider_issue_identity_sha256']
    need(identity is None or (type(identity) is str and
         io.HASH.fullmatch(identity) is not None),
         'EC287_ORIGINAL_IDENTITY_DIGEST_INVALID','unavailable')
    # Enforce the original EC218 monotone, one-use operation state machine.
    # A forged or future incompatible backend state MUST NOT be promoted into
    # a signed proof of creation or an authorization to issue a second POST.
    if result['durable_attempt_barrier_recorded']:
        need(result['ec217_original_reservation_confirmed'] is True and
             op == operation_sha,
             'EC287_ATTEMPT_WITHOUT_ORIGINAL_RESERVATION_OR_OPERATION','unavailable')
    if result['provider_post_invoked']:
        need(result['durable_attempt_barrier_recorded'] is True and
             result['provider_write_may_have_occurred'] is True and
             result['external_final_text_may_have_been_disclosed'] is True,
             'EC287_POST_WITHOUT_DURABLE_BARRIER_OR_RISK_ACK','unavailable')
    else:
        need(result['provider_write_may_have_occurred'] is False and
             result['external_final_text_may_have_been_disclosed'] is False,
             'EC287_PROVIDER_RISK_WITHOUT_POST_INCONSISTENT','unavailable')
    if result['same_request_replay_blocked']:
        need(result['create_state'] == 'BLOCKED' and
             result['provider_post_invoked'] is False and
             result['durable_attempt_barrier_recorded'] is False,
             'EC287_REPLAY_BARRIER_REPORT_INCONSISTENT','unavailable')
    # A 201 response is the provider's claim, not CES independent observation.
    if result['provider_reported_created']:
        need(result['create_state'] == 'PROVIDER_REPORTED_CREATED' and
             result['issue_created'] is True and
             result['provider_post_invoked'] is True and
             result['durable_attempt_barrier_recorded'] is True and
             result['provider_write_may_have_occurred'] is True and
             identity is not None and op == operation_sha,
             'EC287_ORIGINAL_REMOTE_CLAIM_INCONSISTENT','unavailable')
    else:
        need(result['issue_created'] is False and identity is None,
             'EC287_ORIGINAL_FAILED_OUTCOME_CANNOT_CLAIM_CREATION','unavailable')
    need(type(result.get('safe_next_step')) is str and
         result['safe_next_step'] in ('NO_AUTOMATIC_SECOND_POST',
                                      'EC219_REMOTE_UNKNOWN_RECONCILIATION_NO_POST_RETRY'),
         'EC287_ORIGINAL_RETRY_POLICY_INVALID','unavailable')
    return result


def denial(code: str, status: str = 'unavailable', *,
           handler_invoked: bool = False,
           remote_effect_outcome_unknown: bool = False) -> dict:
    need(status in ('unavailable','invalid_input','permission_denied'),
         'EC287_DENIAL_STATUS_INVALID')
    return {'schema':DENIAL_SCHEMA,'status':status,
            'exit_code': {'unavailable':5,'invalid_input':4,'permission_denied':3}[status],
            'reason_code':code,'handler_invoked':handler_invoked,
            'remote_effect_outcome_unknown':remote_effect_outcome_unknown,
            'provider_reported_created':False,
            'business_repository_written':False,
            'remote_creation_independently_verified':False,
            'private_issue_content_returned':False,
            'automatic_retry_allowed':False}


def signed_reply(req: dict, result: dict, policy_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    body = {'schema':REPLY_SCHEMA,'nonce':req['nonce'],
            'request_sha256':sha(canonical(req)),
            'policy_sha256':policy_sha,'job_sha256':job_sha,
            'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}


def verify_reply(reply: Any, req: dict, pub: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {
         'schema','nonce','request_sha256','policy_sha256','job_sha256',
         'issued_at_unix','result','signature_ed25519'} and
         reply.get('schema') == REPLY_SCHEMA,
         'EC287_SIGNED_REPLY_FIELDS_INVALID','unavailable')
    s = validate_subject(req['grant']['subject'])
    need(reply['nonce'] == req['nonce'] and
         reply['request_sha256'] == sha(canonical(req)) and
         reply['policy_sha256'] == policy_sha == s['policy_sha256'] and
         reply['job_sha256'] == s['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now-reply['issued_at_unix']) <= 90,
         'EC287_REPLY_NONCE_PRIVATE_PIN_OR_TIME_MISMATCH','unavailable')
    verify('server',{k:v for k,v in reply.items() if k != 'signature_ed25519'},
           reply['signature_ed25519'],pub)
    result = reply['result']
    if type(result) is dict and result.get('schema') == cw.SCHEMA:
        return validate_backend(result,s['operation_sha256'])
    need(type(result) is dict and set(result) == {
         'schema','status','exit_code','reason_code','handler_invoked',
         'remote_effect_outcome_unknown','provider_reported_created',
         'business_repository_written','remote_creation_independently_verified',
         'private_issue_content_returned','automatic_retry_allowed'} and
         result['schema'] == DENIAL_SCHEMA and
         (result['status'],result['exit_code']) in (
             ('unavailable',5),('invalid_input',4),('permission_denied',3)) and
         type(result['reason_code']) is str and
         len(result['reason_code']) <= 190 and
         result['reason_code'].startswith('EC287_') and
         all(type(result[k]) is bool for k in (
             'handler_invoked','remote_effect_outcome_unknown')) and
         all(result[k] is False for k in (
             'provider_reported_created','business_repository_written',
             'remote_creation_independently_verified','private_issue_content_returned',
             'automatic_retry_allowed')),
         'EC287_SIGNED_DENIAL_INCONSISTENT','unavailable')
    return result

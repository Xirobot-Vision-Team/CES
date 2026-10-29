#!/usr/bin/env python3
"""EC286 exact QualityRun.Execute authorization and independently signed receipts.

The original EC186/187 + EC253/259 gates remain authoritative. EC286 grants
neither container execution privileges nor quality PASS. It authenticates a
single policy-owned profile/source/session and two offline operator votes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ec279_finding_query_host import protocol as io
from ec281_quality_preflight_host import protocol as pre
from ec253_lease_host import broker as lease
from ec252_quality_run_host import broker as runner
import quality_run_budget as budget
import quality_run_guard as guard

POLICY_SCHEMA='ces.ec286.execute_host_policy.v1'
SUBJECT_SCHEMA='ces.ec286.execute_offline_subject.v1'
VOTE_SCHEMA='ces.ec286.execute_offline_vote.v1'
GRANT_SCHEMA='ces.ec286.execute_two_vote_grant.v1'
REQUEST_SCHEMA='ces.ec286.execute_request.v1'
REPLY_SCHEMA='ces.ec286.execute_signed_reply.v1'
DENIAL_SCHEMA='ces.ec286.execute_denial.v1'
RESULT_SCHEMA='ces.ec286.verified_quality_execute_result.v1'
DOMAINS={
    'custodian':b'CES/EC286/QualityRun/SourceCustodian/v1\0',
    'executor':b'CES/EC286/QualityRun/ExecutionAuthorizer/v1\0',
    'server':b'CES/EC286/QualityRun/ServerExecutionReceipt/v1\0',
}
POLICY_KEYS={'schema','preflight_policy_file','preflight_policy_sha256',
             'lease_policy_file','lease_policy_sha256',
             'git_repo','allowlist_file','allowlist_sha256',
             'receipt_file','receipt_sha256','session_socket','session_service_uid',
             'scope_id','profile_id','allowed_uids','custodian_issuer_public_hex',
             'executor_issuer_public_hex','server_public_hex',
             'source_tar_sha256','backend_code_sha256'}
SUBJECT_KEYS={'schema','grant_id','uid','policy_sha256','preflight_policy_sha256',
              'lease_policy_sha256','source_tar_sha256','backend_code_sha256',
              'source_pin_sha256','profile_sha256','scope_id','profile_id',
              'issued_at_unix','expires_at_unix'}
MAX_POLICY=16384
MAX_RPC=10000
MAX_REPLY=108000
MAX_TTL=45
CLOCK_SKEW=5
CODE_PATHS=('quality_run_guard.py','quality_run_budget.py','quality_detect.py',
            'ec253_lease_host/broker.py','ec254_session_host/broker.py',
            'ec259_custody_gated_host/gate.py','ec259_custody_gated_host/serve.py',
            'ec258_git_tar_custody/custody.py','ec252_quality_run_host/broker.py',
            'ec256_cgroup_reaper/supervisor.py','ec257_cgroup_metrics/metrics.py',
            'ec286_quality_execute_host/protocol.py',
            'ec286_quality_execute_host/daemon.py',
            'ec286_quality_execute_host/operator.py',
            '../scripts/ces_quality_execute_host.py')


class HostError(ValueError):
    def __init__(self, code: str, status: str='unavailable'):
        super().__init__(code)
        self.code=code
        self.status=status


def need(ok: Any, code: str, status: str='unavailable') -> None:
    if ok is not True:
        raise HostError(code,status)


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def backend_code_sha() -> str:
    base=Path(__file__).resolve().parents[1]
    try:
        sources={name:sha((base/name).read_bytes()) for name in CODE_PATHS}
        return sha(b'CES/EC286/EXECUTION-SOURCE-CODE/v1\0'+canonical(sources))
    except OSError as exc:
        raise HostError('EC286_FIXED_BACKEND_CODE_UNAVAILABLE') from exc


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


def sign(role: str, data: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role]+canonical(data)).hex()


def verify(role: str, data: dict, signature: Any, pub: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC286_SIGNATURE_FORMAT_INVALID','permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(signature),
                                     DOMAINS[role]+canonical(data))
    except Exception as exc:
        raise HostError('EC286_SIGNATURE_INVALID','permission_denied') from exc


def plain_abs(path: Any) -> bool:
    return (type(path) is str and path.startswith('/') and
            not path.startswith('//') and path!='/' and
            len(path.encode('utf-8')) <= 4096 and '\0' not in path and
            os.path.normpath(path)==path)


def private_file(path: str, limit: int) -> bytes:
    """Read owner-private regular files, rejecting all symlink ancestors.

    This is a local operator trust boundary, NOT a defense against a malicious
    administrator using the same UID or concurrent inode substitution.
    """
    need(plain_abs(path),'EC286_PRIVATE_ABSOLUTE_PATH_REQUIRED')
    try:
        for part in (Path(path),*Path(path).parents):
            need(not part.is_symlink(),'EC286_PRIVATE_PATH_SYMLINK')
        parent=os.lstat(Path(path).parent)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and
             stat.S_IMODE(parent.st_mode)&0o077==0,
             'EC286_PRIVATE_PARENT_OWNER_ONLY_REQUIRED')
        st=os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
             stat.S_IMODE(st.st_mode)&0o077==0,
             'EC286_PRIVATE_FILE_OWNER_ONLY_REQUIRED')
        return io._open_regular(path,limit,private=True)
    except OSError as exc:
        raise HostError('EC286_PRIVATE_INPUT_UNAVAILABLE') from exc


def validate_policy(obj: Any) -> dict:
    need(type(obj) is dict and set(obj)==POLICY_KEYS and
         obj.get('schema')==POLICY_SCHEMA,
         'EC286_POLICY_FIELDS_INVALID')
    for k in ('preflight_policy_file','lease_policy_file','git_repo','allowlist_file',
              'receipt_file','session_socket'):
        need(plain_abs(obj[k]),'EC286_OPERATOR_PATH_INVALID')
    paths=[obj[k] for k in ('preflight_policy_file','lease_policy_file',
                             'git_repo','allowlist_file','receipt_file','session_socket')]
    need(len(set(paths))==len(paths),'EC286_OPERATOR_PATHS_OVERLAP')
    for k in ('preflight_policy_sha256','lease_policy_sha256','allowlist_sha256',
              'receipt_sha256','source_tar_sha256','backend_code_sha256'):
        need(type(obj[k]) is str and io.HASH.fullmatch(obj[k]) is not None,
             'EC286_OPERATOR_SHA_INVALID')
    need(type(obj['scope_id']) is str and runner.SCOPE.fullmatch(obj['scope_id']) is not None and
         type(obj['profile_id']) is str and obj['profile_id'] in runner.PROFILE_IDS,
         'EC286_EXACT_SCOPE_PROFILE_INVALID')
    need(type(obj['session_service_uid']) is int and
         1<=obj['session_service_uid']<=runner.UID_MAX,
         'EC286_ROOTLESS_SERVICE_UID_REQUIRED')
    ids=obj['allowed_uids']
    need(type(ids) is list and 1<=len(ids)<=32 and
         ids==sorted(set(ids)) and all(type(x) is int and 0<=x<=2**31-1 for x in ids),
         'EC286_ALLOWED_PEER_UIDS_INVALID')
    keys=[obj[f'{role}_issuer_public_hex'] for role in ('custodian','executor')]
    keys += [obj['server_public_hex']]
    try:
        for key in keys: io.pub_from_hex(key)
    except (TypeError,ValueError) as exc:
        raise HostError('EC286_PUBLIC_KEY_INVALID') from exc
    need(len(set(keys))==3,'EC286_THREE_DISTINCT_ED25519_KEYS_REQUIRED')
    return obj


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC286_POLICY_SHA_REQUIRED')
    raw=private_file(path,MAX_POLICY)
    need(hmac.compare_digest(sha(raw),expected_sha),
         'EC286_POLICY_RAW_BYTES_CHANGED')
    return validate_policy(io.parse(raw,MAX_POLICY))


def pinned_source(policy: dict, filename: str, digest_field: str,
                  bound: int) -> bytes:
    raw=private_file(policy[filename],bound)
    need(hmac.compare_digest(sha(raw),policy[digest_field]),
         'EC286_PRIVATE_INPUT_SHA_CHANGED')
    return raw


def load_dependencies(pol: dict, *, verify_tickets: bool=False) -> tuple[dict, dict, dict, dict, dict, bytes, bytes]:
    """All substantive source/ticket checks remain in original EC281/253.

    Returned tuple: preflight policy, lease policy, pin, approval, lease, HMAC
    profile key and HMAC broker key. No secrets cross the AF_UNIX request.
    """
    need(hmac.compare_digest(backend_code_sha(),pol['backend_code_sha256']),
         'EC286_BACKEND_CODE_SHA_CHANGED')
    pref_raw=pinned_source(pol,'preflight_policy_file','preflight_policy_sha256',
                           pre.MAX_POLICY)
    pref=pre.validate_policy(io.parse(pref_raw,pre.MAX_POLICY))
    pin,approval,ticket,policy_key,broker_key=pre.load_material(pref)
    need(pref['repo_root']==pin.get('repo_root') and
         pol['profile_id'] in pref['allowed_profiles'],
         'EC286_PREFLIGHT_SCOPE_MISMATCH')
    lease_raw=pinned_source(pol,'lease_policy_file','lease_policy_sha256',
                            lease.MAX_POLICY)
    lease_pol, observed_sha=lease._policy(pol['lease_policy_file'])
    need(hmac.compare_digest(observed_sha,pol['lease_policy_sha256']) and
         lease_pol.get('source_tar_path') and
         lease_pol['expected_source_tar_sha256']==pol['source_tar_sha256'] and
         lease_pol['authorized_source_pin_sha256']==guard._digest(
            __import__('quality_detect').DOMAIN_PIN,pin),
         'EC286_EC253_SOURCE_PIN_OR_TAR_MISMATCH')
    need(any(g['uid']==os.geteuid() and g['scope_id']==pol['scope_id'] and
             pol['profile_id'] in g['profile_ids'] for g in lease_pol['grants']),
         'EC286_ORIGINAL_SESSION_POLICY_SCOPE_UID_DENIED')
    if verify_tickets:
        other=lease._tickets(lease_pol,pol['profile_id'])
        need(other['approval']==approval and other['lease']==ticket and
             hmac.compare_digest(lease._key(lease_pol['approval_hmac_key_path']),
                                 policy_key) and
             hmac.compare_digest(lease._key(lease_pol['broker_hmac_key_path']),
                                 broker_key),
             'EC286_ORIGINAL_EC186_EC253_HMAC_TICKETS_DIFFER')
    return pref,lease_pol,pin,approval,ticket,policy_key,broker_key


def validate_subject(value: Any) -> dict:
    need(type(value) is dict and set(value)==SUBJECT_KEYS and
         value.get('schema')==SUBJECT_SCHEMA,
         'EC286_SUBJECT_FIELDS_INVALID','invalid_input')
    need(type(value['grant_id']) is str and io.HEX_NONCE.fullmatch(value['grant_id']) is not None and
         type(value['uid']) is int and 0<=value['uid']<=2**31-1 and
         type(value['scope_id']) is str and runner.SCOPE.fullmatch(value['scope_id']) is not None and
         type(value['profile_id']) is str and value['profile_id'] in runner.PROFILE_IDS,
         'EC286_SUBJECT_ID_SCOPE_INVALID','invalid_input')
    for key in ('policy_sha256','preflight_policy_sha256','lease_policy_sha256',
                'source_tar_sha256','backend_code_sha256','source_pin_sha256','profile_sha256'):
        need(type(value[key]) is str and io.HASH.fullmatch(value[key]) is not None,
             'EC286_SUBJECT_SHA_INVALID','invalid_input')
    a,b=value['issued_at_unix'],value['expires_at_unix']
    need(type(a) is int and type(b) is int and a>0 and a<b and b-a<=MAX_TTL,
         'EC286_SUBJECT_TTL_INVALID','invalid_input')
    return value


def new_subject(pol: dict, policy_sha: str, *, uid: int, ttl: int=40,
                now: int | None=None) -> dict:
    need(type(ttl) is int and 1<=ttl<=MAX_TTL,'EC286_TTL_OUT_OF_RANGE','invalid_input')
    need(type(uid) is int and 0<=uid<=2**31-1,'EC286_UID_INVALID','invalid_input')
    _,_,pin,_,_,_,_=load_dependencies(pol,verify_tickets=True)
    import quality_detect as detect
    current=int(time.time()) if now is None else now
    return validate_subject({'schema':SUBJECT_SCHEMA,
         'grant_id':secrets.token_hex(16),'uid':uid,'policy_sha256':policy_sha,
         'preflight_policy_sha256':pol['preflight_policy_sha256'],
         'lease_policy_sha256':pol['lease_policy_sha256'],
         'source_tar_sha256':pol['source_tar_sha256'],
         'backend_code_sha256':pol['backend_code_sha256'],
         'source_pin_sha256':guard._digest(detect.DOMAIN_PIN,pin),
         'profile_sha256':guard.catalog_entry(pol['profile_id'])['profile_sha256'],
         'scope_id':pol['scope_id'],'profile_id':pol['profile_id'],
         'issued_at_unix':current,
         'expires_at_unix':current+ttl})


def validate_grant(value: Any, pol: dict, *, uid: int, now: int,
                   policy_sha: str) -> dict:
    need(type(value) is dict and set(value)=={
        'schema','subject','custodian_signature_ed25519',
        'executor_signature_ed25519'} and value.get('schema')==GRANT_SCHEMA,
        'EC286_TWO_ROLE_SIGNATURES_REQUIRED','permission_denied')
    try: subject=validate_subject(value['subject'])
    except (ValueError,KeyError,TypeError) as exc:
        raise HostError('EC286_SUBJECT_INVALID','permission_denied') from exc
    need(uid in pol['allowed_uids'] and uid==subject['uid'] and
         subject['scope_id']==pol['scope_id'] and
         subject['profile_id']==pol['profile_id'] and
         subject['policy_sha256']==policy_sha and
         all(subject[k]==pol[k] for k in ('preflight_policy_sha256',
            'lease_policy_sha256','source_tar_sha256','backend_code_sha256')) and
         subject['profile_sha256']==guard.catalog_entry(pol['profile_id'])['profile_sha256'] and
         subject['issued_at_unix']<=now+CLOCK_SKEW and now<subject['expires_at_unix'],
         'EC286_GRANT_UID_SCOPE_OR_FRESHNESS_INVALID','permission_denied')
    for role in ('custodian','executor'):
        verify(role,subject,value[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return subject


def safe_backend_result(result: Any) -> bool:
    """Accept only the *redacted*, original EC187 report shape.

    Never allow new fields in the signed result; otherwise an adapter could
    slip private test output or an invented PASS claim past the console.
    This is schema hygiene, NOT proof of real OCI execution or trusted code.
    """
    if type(result) is not dict or set(result)!={
       'schema','status','exit_code','reason_code','profile_id','limits',
       'execution','resources','output','proof','effects','trust_boundary'} or\
       result['schema']!=budget.SCHEMA or\
       (result['status'],result['exit_code']) not in (
         ('partial',2),('unavailable',5)) or\
       type(result['reason_code']) is not str or\
       not result['reason_code'].startswith(budget.PREFIX):
        return False
    effects=result['effects']
    original_effects=budget._effects()
    if type(effects) is not dict or set(effects)!=set(original_effects):
        return False
    for k,default in original_effects.items():
        v=effects[k]
        if type(v) is not type(default) or\
           (type(v) is int and not 0<=v<=2**63-1):
            return False
    if (effects['tests_verified_by_ces'] is not False or
        effects['writes_performed_by_ces'] is not False or
        effects['real_kernel_isolation_verified_by_ces'] is not False or
        effects['commands_launched_by_ces'] is not False):
        return False
    if result['execution'] is None:
        return (result['profile_id'] is None and result['limits'] is None and
                result['resources'] is None and result['output'] is None and
                result['proof'] is None and
                result['trust_boundary']=='NO_RUNNER_RESULT_AND_NO_QUALITY_PASS' and
                effects['external_broker_begin_called'] is False)
    proof=result['proof']; execution=result['execution']
    resources=result['resources']; output=result['output']
    limits=result['limits']
    if (result['status']!='partial' or
        (result['profile_id'] is not None and
         (type(result['profile_id']) is not str or
          result['profile_id'] not in runner.PROFILE_IDS)) or
        limits!=budget.HARD_CEILINGS or
        type(limits) is not dict or
        result['trust_boundary']!='HOST_SESSION_REPORT_ONLY_NO_ATTESTED_QUALITY_PASS' or
        not effects['external_broker_begin_called']):
        return False
    if type(proof) is not dict or set(proof)!={
      'source_contents_independently_verified',
      'kernel_isolation_independently_verified',
      'broker_identity_independently_authenticated',
      'test_execution_verified_by_ces','quality_pass_verified',
      'budget_enforcement_guaranteed_by_ces','host_claims_only'} or\
      any(proof[k] is not (k=='host_claims_only') for k in proof):
        return False
    if type(execution) is not dict or set(execution)!={
      'state','host_reported_exit_code','elapsed_ms_observed_locally',
      'source_snapshot_sha256_host_claim','lease_consumption_only_host_reported',
      'actual_process_exit_independently_verified','overall_pass_verified'} or\
      execution['actual_process_exit_independently_verified'] is not False or\
      execution['overall_pass_verified'] is not False or\
      type(execution['lease_consumption_only_host_reported']) is not bool or\
      type(execution['elapsed_ms_observed_locally']) is not int or\
      execution['elapsed_ms_observed_locally']<0 or\
      execution['state'] not in ('exited_host_reported','interrupted_or_unverified'):
        return False
    if (execution['host_reported_exit_code'] is not None and
        (type(execution['host_reported_exit_code']) is not int or
         not 0<=execution['host_reported_exit_code']<=255)):
        return False
    if (execution['source_snapshot_sha256_host_claim'] is not None and
        (type(execution['source_snapshot_sha256_host_claim']) is not str or
         io.HASH.fullmatch(execution['source_snapshot_sha256_host_claim']) is None)):
        return False
    if (type(resources) is not dict or set(resources)!=set(budget.RESOURCE_KEYS)|
        {'telemetry_host_reported_only'} or
        resources['telemetry_host_reported_only'] is not True or
        any(type(resources[k]) is not int or resources[k]<0
            for k in budget.RESOURCE_KEYS)):
        return False
    if (type(output) is not dict or set(output)!={
        'stdout_preview','stderr_preview','captured_bytes','observed_bytes',
        'discarded_bytes','truncated','observed_content_sha256','complete'} or
        output['stdout_preview'] is not None or output['stderr_preview'] is not None or
        type(output['truncated']) is not bool or type(output['complete']) is not bool or
        type(output['observed_content_sha256']) is not str or
        io.HASH.fullmatch(output['observed_content_sha256']) is None or
        any(type(output[k]) is not int or output[k]<0 for k in (
            'captured_bytes','observed_bytes','discarded_bytes')) or
        output['captured_bytes']>budget.HARD_CEILINGS['capture_bytes']):
        return False
    return True


def denial(reason: str, status: str='unavailable', *,
           backend_invoked: bool=False, effects_unknown: bool=False) -> dict:
    need(status in ('permission_denied','invalid_input','unavailable'),
         'EC286_DENIAL_STATUS_INVALID')
    return {'schema':DENIAL_SCHEMA,'status':status,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}[status],
            'reason_code':reason,'backend_invoked':backend_invoked,
            'lease_or_container_effect_unknown':effects_unknown,
            'quality_pass_verified':False,'business_repository_written':False,
            'remote_ci_verified':False,'private_output_disclosed':False}


def signed_reply(request: dict,result: dict,pol_sha: str,
                 key: Ed25519PrivateKey,now: int) -> dict:
    body={'schema':REPLY_SCHEMA,'nonce':request['nonce'],
          'request_sha256':sha(canonical(request)),
          'policy_sha256':pol_sha,'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}


def verify_reply(reply: Any,request: dict,server_pub: str,policy_sha: str,
                 now: int) -> dict:
    need(type(reply) is dict and set(reply)=={'schema','nonce','request_sha256',
         'policy_sha256','issued_at_unix','result','signature_ed25519'} and
         reply.get('schema')==REPLY_SCHEMA,
         'EC286_REPLY_FIELDS_INVALID')
    need(reply['nonce']==request['nonce'] and
         reply['request_sha256']==sha(canonical(request)) and
         reply['policy_sha256']==policy_sha==request['grant']['subject']['policy_sha256'] and
         type(reply['issued_at_unix']) is int and abs(now-reply['issued_at_unix'])<=150,
         'EC286_REPLY_NONCE_SCOPE_OR_TIME_INVALID')
    verify('server',{k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'],server_pub)
    result=reply['result']
    need(type(result) is dict,'EC286_SIGNED_RESULT_TYPE_INVALID')
    if result.get('schema')==budget.SCHEMA:
        need(safe_backend_result(result),'EC286_ORIGINAL_EC187_RESULT_INVALID')
    else:
        need(result.get('schema')==DENIAL_SCHEMA and
             (result.get('status'),result.get('exit_code')) in (
               ('permission_denied',3),('invalid_input',4),('unavailable',5)) and
             result.get('quality_pass_verified') is False and
             result.get('business_repository_written') is False and
             result.get('remote_ci_verified') is False and
             result.get('private_output_disclosed') is False and
             type(result.get('lease_or_container_effect_unknown')) is bool,
             'EC286_SIGNED_DENIAL_INVALID')
    return result

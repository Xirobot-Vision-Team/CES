#!/usr/bin/env python3
"""EC294 one-operation, private, independent ORIGINAL EC227 audit host protocol.

Never sends EC225 messages. 'record' delegates to original EC227, which uses
original EC226 for a STATUS-only query; 'readback' has no network credentials.
Signer domains are distinct from original send/status and EC293. No audit key,
payload, endpoint, credential or private key is accepted over the socket.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any

from ec279_finding_query_host import protocol as io
from ec293_delivery_status_host import protocol as prev
import delivery_reconcile as dr
import delivery_status as st

POLICY_SCHEMA='ces.ec294.private_delivery_reconcile_policy.v1'
SUBJECT_SCHEMA='ces.ec294.private_reconcile_offline_subject.v1'
VOTE_SCHEMA='ces.ec294.private_reconcile_offline_vote.v1'
GRANT_SCHEMA='ces.ec294.private_reconcile_two_vote_grant.v1'
REQUEST_SCHEMA='ces.ec294.private_reconcile_host_request.v1'
REPLY_SCHEMA='ces.ec294.private_reconcile_signed_reply.v1'
DENIAL_SCHEMA='ces.ec294.private_reconcile_denial.v1'
RESULT_SCHEMA='ces.ec294.verified_private_delivery_reconciliation.v1'
DOMAINS={
 'custodian':b'CES/EC294/DeliveryReconcile/IndependentCustodian/v1\x00',
 'auditor':b'CES/EC294/DeliveryReconcile/IndependentAuditAuthorizer/v1\x00',
 'server':b'CES/EC294/DeliveryReconcile/SignedHostAck/v1\x00',
}
POLICY_KEYS={'schema','ec293_policy_file','ec293_policy_sha256',
 'audit_hmac_file','audit_hmac_sha256','admission_root','allowed_uids',
 'custodian_public_hex','auditor_public_hex','server_public_hex',
 'original_ec227_code_sha256','parent_ec293_host_code_sha256',
 'host_code_sha256','enable_private_reconciliation'}
SUBJECT_KEYS={'schema','mode','grant_id','uid','policy_sha256',
 'ec293_policy_sha256','ec288_policy_sha256','job_sha256','trust_sha256',
 'status_trust_sha256','read_credential_sha256','original_approval_sha256',
 'operation_id','original_ec226_code_sha256','parent_ec293_host_code_sha256',
 'audit_hmac_sha256','original_ec227_code_sha256','host_code_sha256',
 'read_grant_sha256','expected_head_hmac_sha256','issued_at_unix','expires_at_unix'}
RESULT_KEYS={'schema','status','exit_code','reason_code','operation_id',
 'delivery_state','last_historical_attested_state','last_provider_state',
 'audit_event_count','audit_head_hmac_sha256','audit_chain_verified',
 'status_network_requested','fresh_independent_status_evidence_verified',
 'conflicting_historical_evidence','incomplete_prior_observation',
 'original_operation_retry_allowed','new_delivery_authorized','resent','published','effects'}
EFFECT_KEYS={'provider_submit_requested','external_status_network_requested',
 'recipient_contacted_by_reconciler','git_or_business_files_written',
 'ces_business_records_written','local_audit_records_written'}
HEX=prev.HEX
HEX32=prev.HEX32
GENESIS=dr.GENESIS
NO_READ_SHA='0'*64
MAX_POLICY=12000
MAX_RPC=18000
MAX_REPLY=19000
MAX_TTL=25
CLOCK_SKEW=5
ORIGINAL_FILES=('delivery_reconcile.py',)
HOST_FILES=('protocol.py','daemon.py','operator.py')

class HostError(ValueError):
    def __init__(self,code:str,status:str='unavailable'):
        super().__init__(code)
        self.code,self.status=code,status

def need(ok:bool,code:str,status:str='unavailable')->None:
    if ok is not True:raise HostError(code,status)

def canonical(doc:Any)->bytes:
    return io.canonical(doc)

def digest(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def keys(doc:Any,wanted:set[str],code:str)->dict:
    need(type(doc) is dict and set(doc)==wanted,code)
    return doc

def original_sha()->str:
    src=Path(dr.__file__).resolve()
    need(src.name=='delivery_reconcile.py' and src.is_file() and not src.is_symlink(),
         'EC294_ORIGINAL_EC227_SOURCE_UNAVAILABLE')
    return digest(src.read_bytes())

def host_sha()->str:
    h=hashlib.sha256(b'CES/EC294/INDEPENDENT-ORIGINAL-EC227-HOST/v1\x00')
    for name in HOST_FILES:
        src=Path(__file__).resolve().parent/name
        need(src.is_file() and not src.is_symlink(),'EC294_HOST_CODE_FILE_MISSING')
        raw=src.read_bytes()
        h.update(name.encode()+b'\x00'+len(raw).to_bytes(8,'big')+raw)
    return h.hexdigest()

def sign(role:str,sub:dict,key)->str:
    need(role in DOMAINS,'EC294_ROLE_INVALID')
    return key.sign(DOMAINS[role]+canonical(sub)).hex()

def verify(role:str,sub:dict,sig:Any,pub:str)->None:
    need(role in DOMAINS and type(sig) is str and io.HEX_SIG.fullmatch(sig) is not None,
         'EC294_SIGNED_VOTE_INVALID','permission_denied')
    try:io.pub_from_hex(pub).verify(bytes.fromhex(sig),DOMAINS[role]+canonical(sub))
    except Exception as exc:
        raise HostError('EC294_VOTE_SIGNATURE_INVALID','permission_denied') from exc

def validate_policy(pol:Any)->dict:
    keys(pol,POLICY_KEYS,'EC294_POLICY_FIELDS_INVALID')
    need(pol['schema']==POLICY_SCHEMA and pol['enable_private_reconciliation'] is True,
         'EC294_EXPLICIT_PRIVATE_AUDIT_OPT_IN_REQUIRED','permission_denied')
    for k in ('ec293_policy_file','audit_hmac_file','admission_root'):
        need(prev.previous.absolute(pol[k]),'EC294_ABSOLUTE_OWNER_PATH_REQUIRED')
    need(len({pol[k] for k in ('ec293_policy_file','audit_hmac_file','admission_root')})==3,
         'EC294_PRIVATE_PATH_COLLISION')
    for k in ('ec293_policy_sha256','audit_hmac_sha256','original_ec227_code_sha256',
              'parent_ec293_host_code_sha256','host_code_sha256'):
        need(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None,
             'EC294_PINNED_SHA_INVALID')
    need(pol['original_ec227_code_sha256']==original_sha() and
         pol['parent_ec293_host_code_sha256']==prev.host_sha() and
         pol['host_code_sha256']==host_sha(),
         'EC294_ORIGINAL_PARENT_OR_HOST_CODE_DRIFT')
    allow=pol['allowed_uids']
    need(type(allow) is list and 1<=len(allow)<=32 and
         all(type(uid) is int and 0<=uid<=2**31-1 for uid in allow) and
         allow==sorted(set(allow)),'EC294_KERNEL_UID_ALLOWLIST_INVALID')
    for k in ('custodian_public_hex','auditor_public_hex','server_public_hex'):
        io.pub_from_hex(pol[k])
    need(len({pol[k] for k in ('custodian_public_hex','auditor_public_hex',
                               'server_public_hex')})==3,
         'EC294_NEW_ROLE_KEYS_MUST_BE_DISTINCT')
    return pol

def load_policy(path:str,expected:str)->dict:
    need(type(expected) is str and HEX.fullmatch(expected) is not None,
         'EC294_PINNED_POLICY_SHA_REQUIRED')
    return validate_policy(prev.previous.pinned(path,expected,MAX_POLICY))

def parent_policy(pol:dict)->dict:
    return prev.load_policy(pol['ec293_policy_file'],pol['ec293_policy_sha256'])

def audit_secret(pol:dict)->bytes:
    raw=prev.previous.private_file(pol['audit_hmac_file'],64)
    need(type(raw) is bytes and len(raw)==32 and raw!=b'\0'*32 and
         hmac.compare_digest(digest(raw),pol['audit_hmac_sha256']),
         'EC294_AUDIT_HMAC_KEY_SIZE_OR_SHA_CHANGED')
    return raw

def build_context(pol:dict,*,credential:bool=False):
    par=parent_policy(pol)
    reader,job,prior=prev.build_reader(par,credential=credential)
    oldpol,_,trust=prev.load_previous(par)
    status_trust=prev.load_trust(par)
    allkeys=(prev.previous.trust_keys(trust)+
             [oldpol[k] for k in ('custodian_issuer_public_hex',
                                    'authorizer_issuer_public_hex','server_public_hex')]+
             [status_trust[k] for k in ('status_read_public_hex',
                                       'inbox_observation_public_hex')]+
             [par[k] for k in ('custodian_public_hex','reviewer_public_hex',
                               'server_public_hex')]+
             [pol[k] for k in ('custodian_public_hex','auditor_public_hex',
                               'server_public_hex')])
    need(len(allkeys)==19 and len(set(allkeys))==19,
         'EC294_NINETEEN_DISTINCT_SIGNING_KEYS_REQUIRED')
    need(pol['admission_root']!=oldpol['outbox_root'] and
         pol['admission_root']!=par['admission_root'] and
         pol['audit_hmac_file'] not in (
             oldpol['credential_file'],par['read_credential_file'],
             pol['ec293_policy_file']),
         'EC294_NEW_AUDIT_KEY_OR_ADMISSION_PATH_NOT_SEPARATE')
    return reader,job,par,prior

def pins(pol:dict,reader:st.DeliveryStatusReader,job)->dict:
    par=parent_policy(pol)
    return {**prev.operation_pins(par,reader,job),
     'ec293_policy_sha256':pol['ec293_policy_sha256'],
     'parent_ec293_host_code_sha256':pol['parent_ec293_host_code_sha256'],
     'original_ec227_code_sha256':pol['original_ec227_code_sha256'],
     'audit_hmac_sha256':pol['audit_hmac_sha256'],
     'host_code_sha256':pol['host_code_sha256']}

def validate_subject(sub:Any)->dict:
    keys(sub,SUBJECT_KEYS,'EC294_SUBJECT_FIELDS_INVALID')
    need(sub['schema']==SUBJECT_SCHEMA and sub['mode'] in ('record','readback') and
         type(sub['grant_id']) is str and HEX32.fullmatch(sub['grant_id']) is not None and
         type(sub['uid']) is int and 0<=sub['uid']<=2**31-1 and
         all(type(sub[k]) is str and HEX.fullmatch(sub[k]) is not None for k in (
         'policy_sha256','ec293_policy_sha256','ec288_policy_sha256',
         'job_sha256','trust_sha256','status_trust_sha256','read_credential_sha256',
         'original_approval_sha256','operation_id','original_ec226_code_sha256',
         'parent_ec293_host_code_sha256','audit_hmac_sha256','original_ec227_code_sha256',
         'host_code_sha256','read_grant_sha256','expected_head_hmac_sha256')) and
         (sub['mode']=='record' and sub['read_grant_sha256']!=NO_READ_SHA or
          sub['mode']=='readback' and sub['read_grant_sha256']==NO_READ_SHA) and
         type(sub['issued_at_unix']) is int and type(sub['expires_at_unix']) is int and
         946684800<=sub['issued_at_unix']<sub['expires_at_unix']<=4102444800 and
         sub['expires_at_unix']-sub['issued_at_unix']<=MAX_TTL,
         'EC294_SIGNED_SUBJECT_SHAPE_INVALID')
    return sub

def new_subject(pol:dict,policy_sha:str,context:dict,uid:int,mode:str,
                expected_head:str,read_grant:dict|None,ttl:int)->dict:
    need(type(ttl) is int and 1<=ttl<=MAX_TTL,'EC294_TTL_MAX_25_SECONDS')
    need(type(expected_head) is str and HEX.fullmatch(expected_head) is not None,
         'EC294_EXTERNAL_HEAD_MUST_BE_EXPLICIT_SHA','invalid_input')
    need(mode in ('record','readback') and
         ((mode=='record' and type(read_grant) is dict) or
          (mode=='readback' and read_grant is None)),
         'EC294_MODE_OR_ORIGINAL_READ_GRANT_MISMATCH','invalid_input')
    now=int(time.time())
    return validate_subject({'schema':SUBJECT_SCHEMA,'mode':mode,
       'grant_id':secrets.token_hex(16),'uid':uid,'policy_sha256':policy_sha,
       **context,'expected_head_hmac_sha256':expected_head,
       'read_grant_sha256':digest(canonical(read_grant)) if read_grant is not None
             else NO_READ_SHA,'issued_at_unix':now,'expires_at_unix':now+ttl})

def validate_grant(grant:Any,pol:dict,policy_sha:str,reader,job,uid:int,
                   now:int,read_grant:dict|None)->dict:
    keys(grant,{'schema','subject','custodian_signature_ed25519',
                'auditor_signature_ed25519'},'EC294_TWO_OFFLINE_VOTES_REQUIRED')
    need(grant['schema']==GRANT_SCHEMA,'EC294_SIGNED_GRANT_SCHEMA_INVALID')
    sub=validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and uid==sub['uid'] and
         sub['policy_sha256']==policy_sha and
         sub['read_grant_sha256']==(digest(canonical(read_grant)) if
             read_grant is not None else NO_READ_SHA) and
         (sub['mode']=='record')==(read_grant is not None) and
         all(sub.get(k)==value for k,value in pins(pol,reader,job).items()) and
         sub['issued_at_unix']<=now+CLOCK_SKEW and now<sub['expires_at_unix'],
         'EC294_EXACT_OPERATION_UID_MODE_OR_FRESHNESS_MISMATCH','permission_denied')
    for role in ('custodian','auditor'):
        verify(role,sub,grant[role+'_signature_ed25519'],pol[role+'_public_hex'])
    return sub

def validate_original_read(read:dict,reader:st.DeliveryStatusReader,job,now:int)->dict:
    # The original EC226 signer is NOT one of the two new EC294 votes.
    try:return prev.validate_read(read,reader,job,now)
    except Exception as exc:
        raise HostError('EC294_ORIGINAL_EC226_READ_SIGNATURE_OR_CONTEXT_DENIED',
                        'permission_denied') from exc

def reconciler(reader,secret:bytes)->dr.DeliveryReconciler:
    return dr.DeliveryReconciler(reader,dr.HostAuditAccess(secret,True))

def preflight_head(rec:dr.DeliveryReconciler,job,expected:str)->dict:
    """Fail closed BEFORE spending Host grant; independent head is client-signed.

    The GENESIS sentinel means NO existing audit, not a caller-controlled
    deletion of an existing authenticated history. No automatic recovery.
    """
    if expected==GENESIS:
        result=rec.readback(job)
        need((result['reason_code']=='DELIVERY_RECONCILE_AUDIT_NOT_YET_RECORDED'
             or (result['status']=='partial' and result['audit_chain_verified'] is True
                 and result['audit_event_count']==0 and
                 result['audit_head_hmac_sha256'] is None)),
             'EC294_EXPECTED_EMPTY_AUDIT_BUT_LOG_PRESENT_OR_UNVERIFIABLE',
             'permission_denied')
    else:
        result=rec.readback(job,expected_head_hmac_sha256=expected)
        need(result['status']=='partial' and result['audit_chain_verified'] is True and
             result['audit_head_hmac_sha256']==expected,
             'EC294_EXTERNAL_CHECKPOINT_MISMATCH_OR_AUDIT_UNVERIFIABLE',
             'permission_denied')
    return result

def validate_backend(res:Any,mode:str,operation:str,expected_head:str)->dict:
    keys(res,RESULT_KEYS,'EC294_ORIGINAL_EC227_RESULT_FIELDS_INVALID')
    need(res['schema']==dr.SCHEMA and type(res['status']) is str and
         (res['exit_code']==2 if res['status']=='partial' else
          res['exit_code']==4 if res['status']=='invalid_input' else
          res['exit_code']==5) and
         type(res['reason_code']) is str and
         re.fullmatch('DELIVERY_RECONCILE_[A-Z0-9_]{1,150}',res['reason_code']) is not None and
         res['operation_id'] in (None,operation) and
         type(res['audit_event_count']) is int and 0<=res['audit_event_count']<=64 and
         (res['audit_head_hmac_sha256'] is None or
          type(res['audit_head_hmac_sha256']) is str and
          HEX.fullmatch(res['audit_head_hmac_sha256']) is not None) and
         res['delivery_state'] in dr.FINAL_STATES and
         res['last_historical_attested_state'] in (None,*dr.KNOWN_STATES) and
         res['last_provider_state'] in (None,*dr.PROVIDER_STATES) and
         all(type(res[k]) is bool for k in ('audit_chain_verified',
             'status_network_requested','fresh_independent_status_evidence_verified',
             'conflicting_historical_evidence','incomplete_prior_observation',
             'original_operation_retry_allowed','new_delivery_authorized',
             'resent','published')) and
         all(res[k] is False for k in ('original_operation_retry_allowed',
             'new_delivery_authorized','resent','published')),
         'EC294_ORIGINAL_EC227_FALSE_RECONCILIATION_REPORT')
    effects=keys(res['effects'],EFFECT_KEYS,'EC294_EC227_EFFECT_FIELDS_INVALID')
    need(all(type(val) is bool for val in effects.values()) and
         all(effects[k] is False for k in ('provider_submit_requested',
             'recipient_contacted_by_reconciler','git_or_business_files_written',
             'ces_business_records_written')) and
         effects['external_status_network_requested']==res['status_network_requested'],
         'EC294_ORIGINAL_EC227_FORBIDDEN_EFFECT')
    if mode=='readback':
        need(not res['status_network_requested'] and not effects['local_audit_records_written']
             and not res['fresh_independent_status_evidence_verified'] and
             res['delivery_state']=='UNKNOWN_UNCONFIRMED' and
             (res['status']!='partial' or (
                 res['reason_code']=='DELIVERY_RECONCILE_LOCAL_AUDIT_READBACK_NOT_CURRENT_DELIVERY_PROOF'
                 and res['audit_chain_verified'] and
                 res['audit_head_hmac_sha256']==expected_head)),
             'EC294_READBACK_ATTEMPTED_SIDE_EFFECT_OR_PROMOTED_HISTORY')
    else:
        need(res['status']!='partial' or (
              res['audit_chain_verified'] and res['audit_event_count']>=2 and
              res['audit_event_count']%2==0 and
              res['audit_head_hmac_sha256'] not in (None,expected_head) and
              effects['local_audit_records_written'] and
              (res['status_network_requested'] or (
                res['delivery_state']=='UNKNOWN_UNCONFIRMED' and
                not res['fresh_independent_status_evidence_verified']))),
              'EC294_RECORD_MISSING_NEW_DURABLE_AUDIT')
        need(not res['fresh_independent_status_evidence_verified'] or (
              res['status']=='partial' and not res['conflicting_historical_evidence'] and
              res['delivery_state'] in dr.FINAL_STATES),
              'EC294_UNPROVEN_FRESH_STATUS_PROMOTION')
        need(res['delivery_state']!='DELIVERED_INBOX_OBSERVED' or (
             res['fresh_independent_status_evidence_verified'] and
             res['last_provider_state']=='DELIVERED'),
             'EC294_INBOX_DELIVERY_WITHOUT_INDEPENDENT_PROOF')
    return res

def denial(code:str,status:str='unavailable',*,admission_uncertain:bool=False)->dict:
    need(status in ('permission_denied','invalid_input','unavailable'),
         'EC294_DENIAL_STATUS_INVALID')
    return {'schema':DENIAL_SCHEMA,'status':status,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}[status],
      'reason_code':code,'audit_or_status_outcome_unknown':admission_uncertain,
      'provider_submit_requested':False,'original_send_retried':False,
      'automatic_read_or_send_retry_allowed':False,
      'production_delivery_claimed':False}

def signed_reply(req:dict,result:dict,policy_sha:str,job_sha:str,key,now:int)->dict:
    body={'schema':REPLY_SCHEMA,'nonce':req['nonce'],
          'request_sha256':digest(canonical(req)),'policy_sha256':policy_sha,
          'job_sha256':job_sha,'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}

def verify_reply(reply:Any,req:dict,server_pub:str,policy_sha:str,now:int)->dict:
    keys(reply,{'schema','nonce','request_sha256','policy_sha256','job_sha256',
                'issued_at_unix','result','signature_ed25519'},
         'EC294_SIGNED_ACK_FIELDS_INVALID')
    sub=validate_subject(req['grant']['subject'])
    need(reply['schema']==REPLY_SCHEMA and reply['nonce']==req['nonce'] and
         reply['request_sha256']==digest(canonical(req)) and
         reply['policy_sha256']==policy_sha==sub['policy_sha256'] and
         reply['job_sha256']==sub['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(reply['issued_at_unix']-now)<=90,
         'EC294_SIGNED_ACK_NONCE_JOB_SHA_OR_TIME_MISMATCH')
    verify('server',{k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'],server_pub)
    result=reply['result']
    need(type(result) is dict,'EC294_SIGNED_RESULT_NOT_OBJECT')
    if result.get('schema')==dr.SCHEMA:
        return validate_backend(result,sub['mode'],sub['operation_id'],
                                sub['expected_head_hmac_sha256'])
    keys(result,{'schema','status','exit_code','reason_code',
                 'audit_or_status_outcome_unknown','provider_submit_requested',
                 'original_send_retried','automatic_read_or_send_retry_allowed',
                 'production_delivery_claimed'},'EC294_SIGNED_DENIAL_FIELDS_INVALID')
    need(result['schema']==DENIAL_SCHEMA and
         (result['status'],result['exit_code']) in (
           ('permission_denied',3),('invalid_input',4),('unavailable',5)) and
         type(result['reason_code']) is str and
         re.fullmatch('EC294_[A-Z0-9_]{1,160}',result['reason_code']) is not None and
         type(result['audit_or_status_outcome_unknown']) is bool and
         all(result[k] is False for k in ('provider_submit_requested',
            'original_send_retried','automatic_read_or_send_retry_allowed',
            'production_delivery_claimed')),'EC294_FALSE_SIGNED_DENIAL')
    return result

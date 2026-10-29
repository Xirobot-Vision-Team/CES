#!/usr/bin/env python3
"""EC293 private EC225 -> ORIGINAL EC226 status-only readback protocol.

This Host never opens the EC288 send credential, never calls EC225.send_once,
never takes a provider endpoint or payload from a socket, and never authorizes
another submission. It delegates signed provider/inbox verification to EC226.
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
from ec288_delivery_send_host import protocol as previous
import delivery_authorization as da
import delivery_preview as dp
import delivery_send as ds
import delivery_status as st

POLICY_SCHEMA = 'ces.ec293.private_delivery_status_policy.v1'
TRUST_SCHEMA = 'ces.ec293.private_delivery_status_trust.v1'
SUBJECT_SCHEMA = 'ces.ec293.private_status_offline_subject.v1'
VOTE_SCHEMA = 'ces.ec293.private_status_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec293.private_status_two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec293.private_status_host_request.v1'
REPLY_SCHEMA = 'ces.ec293.private_status_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec293.private_status_denial.v1'
RESULT_SCHEMA = 'ces.ec293.verified_private_delivery_status.v1'
DOMAINS = {
    'custodian': b'CES/EC293/DeliveryStatus/SourceCustodian/v1\x00',
    'reviewer': b'CES/EC293/DeliveryStatus/IndependentStatusReviewer/v1\x00',
    'server': b'CES/EC293/DeliveryStatus/SignedHostAck/v1\x00',
}
POLICY_KEYS = {'schema','ec288_policy_file','ec288_policy_sha256',
               'status_trust_file','status_trust_sha256',
               'read_credential_file','read_credential_sha256',
               'admission_root','allowed_uids','custodian_public_hex',
               'reviewer_public_hex','server_public_hex',
               'original_ec226_code_sha256','host_code_sha256',
               'enable_one_private_status_read'}
TRUST_KEYS = {'schema','issuer_id','reader_id','inbox_observer_id',
              'status_read_public_hex','inbox_observation_public_hex',
              'minimum_read_epoch','enable_private_status_read'}
SUBJECT_KEYS = {'schema','grant_id','uid','policy_sha256',
                'ec288_policy_sha256','job_sha256','trust_sha256',
                'status_trust_sha256','read_credential_sha256',
                'original_approval_sha256','operation_id','read_grant_sha256',
                'original_ec226_code_sha256','host_code_sha256',
                'issued_at_unix','expires_at_unix'}
RESULT_KEYS = {'schema','status','exit_code','reason_code','operation_id',
               'provider_state','delivery_state','provider_message_id_sha256',
               'read_grant_verified','submit_attempt_marker_verified',
               'status_network_requested','provider_evidence_verified',
               'inbox_evidence_verified','provider_accepted',
               'recipient_delivery_observed','message_sent_by_status_read',
               'resent','published','effects'}
MAX_POLICY, MAX_TRUST, MAX_CREDENTIAL = 12000, 10000, 4096
MAX_RPC, MAX_REPLY = 16000, 18000
MAX_TTL, CLOCK_SKEW = 25, 5
HEX = re.compile('[0-9a-f]{64}\\Z', re.ASCII)
HEX32 = re.compile('[0-9a-f]{32}\\Z', re.ASCII)
HOST_FILES = ('protocol.py','daemon.py','operator.py')
# The ORIGINAL EC225/226 and EC288 sources must not be edited to install EC293.
ORIGINAL_FILES = ('delivery_status.py','delivery_send.py','delivery_authorization.py',
                  'delivery_identity.py','delivery_preview.py',
                  'ec288_delivery_send_host/protocol.py')


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable'):
        super().__init__(code)
        self.code, self.status = code, status


def need(condition: bool, code: str, status: str = 'unavailable') -> None:
    if condition is not True:
        raise HostError(code, status)


def canonical(item: Any) -> bytes:
    return io.canonical(item)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def keys(item: Any, wanted: set[str], code: str) -> dict:
    need(type(item) is dict and set(item) == wanted, code)
    return item


def original_sha() -> str:
    h = hashlib.sha256(b'CES/EC293/ORIGINAL-EC225-226-AND-EC288-CODE/v1\x00')
    root = Path(__file__).resolve().parents[1]
    for name in ORIGINAL_FILES:
        source = root / name
        need(source.is_file() and not source.is_symlink(), 'EC293_ORIGINAL_SOURCE_UNAVAILABLE')
        raw = source.read_bytes()
        h.update(name.encode()+b'\x00'+len(raw).to_bytes(8,'big')+raw)
    return h.hexdigest()


def host_sha() -> str:
    h = hashlib.sha256(b'CES/EC293/HOST-BRIDGE/v1\x00')
    for name in HOST_FILES:
        source = Path(__file__).resolve().parent / name
        need(source.is_file() and not source.is_symlink(), 'EC293_HOST_SOURCE_UNAVAILABLE')
        raw = source.read_bytes()
        h.update(name.encode()+b'\x00'+len(raw).to_bytes(8,'big')+raw)
    return h.hexdigest()


def public_hex(key) -> str:
    return previous.public_hex(key)


def sign(role: str, body: dict, key) -> str:
    need(role in DOMAINS, 'EC293_SIGNER_ROLE_INVALID')
    return key.sign(DOMAINS[role]+canonical(body)).hex()


def verify(role: str, body: dict, signature: Any, pub: str) -> None:
    need(role in DOMAINS and type(signature) is str and
         io.HEX_SIG.fullmatch(signature) is not None,
         'EC293_SIGNATURE_SHAPE_INVALID','permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(signature),
                                    DOMAINS[role]+canonical(body))
    except Exception as exc:
        raise HostError('EC293_SIGNATURE_INVALID','permission_denied') from exc


def validate_trust(doc: Any) -> dict:
    keys(doc, TRUST_KEYS, 'EC293_STATUS_TRUST_FIELDS_INVALID')
    need(doc['schema']==TRUST_SCHEMA and doc['enable_private_status_read'] is True,
         'EC293_PRIVATE_STATUS_TRUST_DISABLED','permission_denied')
    for label in ('issuer_id','reader_id','inbox_observer_id'):
        need(type(doc[label]) is str and 1<=len(doc[label])<=128 and
             re.fullmatch('[A-Za-z0-9_.:-]{1,128}',doc[label]) is not None,
             'EC293_STATUS_TRUST_ROLE_ID_INVALID')
    need(len({doc[k] for k in ('issuer_id','reader_id','inbox_observer_id')})==3,
         'EC293_READ_ROLES_MUST_BE_DISTINCT')
    for label in ('status_read_public_hex','inbox_observation_public_hex'):
        io.pub_from_hex(doc[label])
    need(doc['status_read_public_hex']!=doc['inbox_observation_public_hex'] and
         type(doc['minimum_read_epoch']) is int and
         1<=doc['minimum_read_epoch']<=2**63-1,
         'EC293_STATUS_KEY_OR_EPOCH_INVALID')
    return doc


def load_previous(pol: dict) -> tuple[dict, ds.DeliverySendRequest, dict]:
    prior=previous.load_policy(pol['ec288_policy_file'],pol['ec288_policy_sha256'])
    job=previous.load_job(prior)
    trust=previous.load_trust(prior)
    # We intentionally do NOT call previous.load_credential(prior).
    return prior,job,trust


def validate_policy(pol: Any) -> dict:
    keys(pol,POLICY_KEYS,'EC293_POLICY_FIELDS_INVALID')
    need(pol['schema']==POLICY_SCHEMA and pol['enable_one_private_status_read'] is True,
         'EC293_EXPLICIT_STATUS_READ_OPT_IN_REQUIRED','permission_denied')
    for name in ('ec288_policy_file','status_trust_file','read_credential_file','admission_root'):
        need(previous.absolute(pol[name]),'EC293_OWNER_ABSOLUTE_PATH_REQUIRED')
    need(len({pol[n] for n in ('ec288_policy_file','status_trust_file',
          'read_credential_file','admission_root')})==4,
         'EC293_PRIVATE_PATH_COLLISION')
    for name in ('ec288_policy_sha256','status_trust_sha256',
                 'read_credential_sha256','original_ec226_code_sha256','host_code_sha256'):
        need(type(pol[name]) is str and HEX.fullmatch(pol[name]) is not None,
             'EC293_RAW_SHA_PIN_INVALID')
    need(pol['original_ec226_code_sha256']==original_sha() and
         pol['host_code_sha256']==host_sha(),
         'EC293_ORIGINAL_OR_HOST_CODE_CHANGED')
    allow=pol['allowed_uids']
    need(type(allow) is list and 1<=len(allow)<=32 and
         all(type(x) is int and 0<=x<=2**31-1 for x in allow) and
         allow==sorted(set(allow)), 'EC293_PEER_UID_ALLOWLIST_INVALID')
    for name in ('custodian_public_hex','reviewer_public_hex','server_public_hex'):
        io.pub_from_hex(pol[name])
    need(len({pol[n] for n in ('custodian_public_hex','reviewer_public_hex',
                                'server_public_hex')})==3,
         'EC293_THREE_INDEPENDENT_HOST_KEYS_REQUIRED')
    return pol


def load_policy(path: str, expected: str) -> dict:
    need(type(expected) is str and HEX.fullmatch(expected) is not None,
         'EC293_PINNED_POLICY_SHA_REQUIRED')
    return validate_policy(previous.pinned(path,expected,MAX_POLICY))


def load_trust(pol: dict) -> dict:
    return validate_trust(previous.pinned(pol['status_trust_file'],
                                          pol['status_trust_sha256'],MAX_TRUST))


def read_credential(pol: dict, prior: dict) -> str:
    # The original EC288 POST credential is pinned by hash but never loaded.
    need(pol['read_credential_sha256']!=prior['credential_sha256'],
         'EC293_READ_AND_SEND_CREDENTIAL_MUST_DIFFER')
    raw=previous.private_file(pol['read_credential_file'],MAX_CREDENTIAL)
    need(hmac.compare_digest(digest(raw),pol['read_credential_sha256']),
         'EC293_READ_CREDENTIAL_BYTES_CHANGED')
    try: token=raw.decode('ascii','strict')
    except UnicodeError as exc: raise HostError('EC293_READ_TOKEN_NOT_ASCII') from exc
    need(token.strip()==token and 16<=len(token)<=2048 and
         all(33<=ord(ch)<=126 for ch in token),
         'EC293_READ_ONLY_TOKEN_INVALID')
    return token


def build_reader(pol: dict, *, credential: bool = True) -> tuple[st.DeliveryStatusReader, ds.DeliverySendRequest,dict]:
    prior, request, trust=load_previous(pol)
    status_trust=load_trust(pol)
    # Build original EC225 business types using a deliberately unusable dummy
    # for SEND. Never pass or load the EC288 provider submit credential.
    sender=previous.build_sender(trust,'EC293_NO_SEND_CREDENTIAL_000000',prior['outbox_root'])
    roots=st.TrustedStatusRoots(status_trust['issuer_id'],status_trust['reader_id'],
            status_trust['inbox_observer_id'],
            bytes.fromhex(status_trust['status_read_public_hex']),
            bytes.fromhex(status_trust['inbox_observation_public_hex']),
            status_trust['minimum_read_epoch'])
    token=read_credential(pol,prior) if credential else 'EC293_STATUS_READ_NOT_ENABLED'
    access=st.HostStatusAccess(roots,token,True,False)
    reader=st.DeliveryStatusReader(sender,access,transport=None)
    # previous EC288: eight original + three Host; original EC226: two more;
    # this Host adds its own three. No shared public keys across all 16.
    allkeys=previous.trust_keys(trust)+[
       prior[k] for k in ('custodian_issuer_public_hex',
                         'authorizer_issuer_public_hex','server_public_hex')]+[
       status_trust[k] for k in ('status_read_public_hex','inbox_observation_public_hex')]+[
       pol[k] for k in ('custodian_public_hex','reviewer_public_hex','server_public_hex')]
    need(len(allkeys)==16 and len(set(allkeys))==16,
         'EC293_SIXTEEN_DISTINCT_ORIGINAL_AND_HOST_KEYS_REQUIRED')
    return reader,request,prior


def operation_pins(pol: dict,reader: st.DeliveryStatusReader,
                   request: ds.DeliverySendRequest) -> dict:
    # Fully verify historical ORIGINAL EC221-225 Ed25519 signatures, not just
    # parse user-controlled JSON. Historical signatures do not grant a NEW send.
    try: history=reader._historical(request)
    except Exception as exc: raise HostError('EC293_ORIGINAL_SEND_HISTORY_NOT_VERIFIABLE') from exc
    return {'ec288_policy_sha256':pol['ec288_policy_sha256'],
            'job_sha256':reader_job_sha(pol),'trust_sha256':reader_trust_sha(pol),
            'status_trust_sha256':pol['status_trust_sha256'],
            'read_credential_sha256':pol['read_credential_sha256'],
            'original_approval_sha256':history['approver_exact_grant_sha256'],
            'operation_id':history['operation_id'],
            'original_ec226_code_sha256':pol['original_ec226_code_sha256'],
            'host_code_sha256':pol['host_code_sha256']}


def reader_job_sha(pol: dict) -> str:
    return previous.load_policy(pol['ec288_policy_file'],pol['ec288_policy_sha256'])['job_sha256']


def reader_trust_sha(pol: dict) -> str:
    return previous.load_policy(pol['ec288_policy_file'],pol['ec288_policy_sha256'])['trust_sha256']


def original_read_template(pol: dict, reader: st.DeliveryStatusReader,
                           request: ds.DeliverySendRequest, ttl: int) -> dict:
    need(type(ttl) is int and 1<=ttl<=35,'EC293_ORIGINAL_EC226_TTL_MAX_35_SECONDS')
    history=reader._historical(request)
    roots=reader.access.roots
    target=reader.sender.access.target
    now=int(time.time())
    return {'schema':st.READ_SCHEMA,'issuer_id':roots.issuer_id,
       'reader_id':roots.reader_id,'purpose':st.READ_PURPOSE,
       'send_trust_anchor_binding_sha256':reader.sender._roots_pin,
       'status_trust_anchor_binding_sha256':reader._root_pin,
       'provider_target_binding_sha256':reader.sender._target_pin,
       **{key:history[key] for key in (
           'authorization_receipt_id','approver_exact_grant_sha256',
           'side_effect_permit_sha256','payload_sha256','source_set_sha256',
           'operation_id')},
       **{key:getattr(target,key) for key in (
           'provider_id','account_id','project_id','recipient_id',
           'channel_id','audience_id','recipient_identity_sha256')},
       'read_nonce':secrets.token_hex(16),'permission_epoch':roots.minimum_read_epoch,
       'sandbox_only':True,'issued_at':now,'expires_at':now+ttl}


def read_envelope(raw: Any) -> da.SignedAuthorizationStatement:
    doc=keys(raw,{'statement','signature_hex'},'EC293_ORIGINAL_READ_ENVELOPE_INVALID')
    need(type(doc['statement']) is dict and type(doc['signature_hex']) is str and
         io.HEX_SIG.fullmatch(doc['signature_hex']) is not None,
         'EC293_ORIGINAL_SIGNED_READ_DOCUMENT_REQUIRED')
    return da.SignedAuthorizationStatement(doc['statement'],doc['signature_hex'])


def validate_read(raw: Any,reader:st.DeliveryStatusReader,
                  request:ds.DeliverySendRequest,now:int) -> dict:
    signed=read_envelope(raw)
    try:
        history=reader._historical(request)
        statement,_=reader._read_grant(signed,history,now)
        return statement
    except Exception as exc:
        raise HostError('EC293_ORIGINAL_EC226_STATUS_READ_GRANT_NOT_AUTHORIZED',
                        'permission_denied') from exc


def new_subject(pol:dict,policy_sha:str,pins:dict,read_grant:dict,uid:int,ttl:int)->dict:
    need(type(ttl) is int and 1<=ttl<=MAX_TTL,'EC293_HOST_TTL_MAX_25_SECONDS')
    now=int(time.time())
    return validate_subject({'schema':SUBJECT_SCHEMA,'grant_id':secrets.token_hex(16),
        'uid':uid,'policy_sha256':policy_sha,**pins,
        'read_grant_sha256':digest(canonical(read_grant)),
        'issued_at_unix':now,'expires_at_unix':now+ttl})


def validate_subject(sub: Any) -> dict:
    keys(sub,SUBJECT_KEYS,'EC293_HOST_SUBJECT_FIELDS_INVALID')
    need(sub['schema']==SUBJECT_SCHEMA and
         type(sub['grant_id']) is str and HEX32.fullmatch(sub['grant_id']) is not None and
         type(sub['uid']) is int and 0<=sub['uid']<=2**31-1 and
         all(type(sub[k]) is str and HEX.fullmatch(sub[k]) is not None for k in (
             'policy_sha256','ec288_policy_sha256','job_sha256','trust_sha256',
             'status_trust_sha256','read_credential_sha256','original_approval_sha256',
             'operation_id','read_grant_sha256','original_ec226_code_sha256','host_code_sha256')) and
         type(sub['issued_at_unix']) is int and type(sub['expires_at_unix']) is int and
         946684800<=sub['issued_at_unix']<sub['expires_at_unix']<=4102444800 and
         sub['expires_at_unix']-sub['issued_at_unix']<=MAX_TTL,
         'EC293_HOST_OFFLINE_SUBJECT_INVALID')
    return sub


def validate_grant(grant: Any,read_grant:dict,pol:dict,reader:st.DeliveryStatusReader,
                   request:ds.DeliverySendRequest,uid:int,now:int,policy_sha:str)->dict:
    keys(grant,{'schema','subject','custodian_signature_ed25519',
                'reviewer_signature_ed25519'},'EC293_HOST_TWO_VOTES_REQUIRED')
    need(grant['schema']==GRANT_SCHEMA,'EC293_HOST_GRANT_SCHEMA_INVALID')
    sub=validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and uid==sub['uid'] and
         sub['policy_sha256']==policy_sha and
         sub['read_grant_sha256']==digest(canonical(read_grant)) and
         all(sub[k]==v for k,v in operation_pins(pol,reader,request).items()) and
         sub['issued_at_unix']<=now+CLOCK_SKEW and now<sub['expires_at_unix'],
         'EC293_UID_READ_GRANT_CONTEXT_OR_FRESHNESS_MISMATCH','permission_denied')
    for role in ('custodian','reviewer'):
        verify(role,sub,grant[role+'_signature_ed25519'],
               pol[role+'_public_hex'])
    return sub


def validate_backend(result:Any)->dict:
    keys(result,RESULT_KEYS,'EC293_ORIGINAL_EC226_RESULT_FIELDS_INVALID')
    need(result['schema']==st.SCHEMA and
         (result['status'],result['exit_code']) in (
             ('partial',2),('unavailable',5),('blocked',5),('invalid_input',4)) and
         type(result['reason_code']) is str and
         re.fullmatch('DELIVERY_STATUS_[A-Z0-9_]{1,160}',result['reason_code']) is not None and
         type(result['effects']) is dict and
         set(result['effects'])=={
             'external_network_requested','provider_submit_requested',
             'recipient_contacted_by_status_read',
             'git_or_business_files_written','ces_business_records_written'},
         'EC293_ORIGINAL_STATUS_RESULT_INVALID')
    for name in ('read_grant_verified','submit_attempt_marker_verified',
                 'status_network_requested','provider_evidence_verified',
                 'inbox_evidence_verified','provider_accepted','recipient_delivery_observed',
                 'message_sent_by_status_read','resent','published'):
        need(type(result[name]) is bool,'EC293_ORIGINAL_STATUS_FLAG_NOT_BOOL')
    need(all(type(x) is bool for x in result['effects'].values()) and
         not any(result[name] for name in ('message_sent_by_status_read','resent','published')) and
         not any(result['effects'][k] for k in (
             'provider_submit_requested','recipient_contacted_by_status_read',
             'git_or_business_files_written','ces_business_records_written')) and
         result['effects']['external_network_requested']==result['status_network_requested'],
         'EC293_STATUS_REPORT_CLAIMS_PROHIBITED_EFFECT')
    need(result['provider_state'] in (None,'UNKNOWN','PENDING','ACCEPTED',
             'DELIVERED','REJECTED','FAILED') and
         result['delivery_state'] in ('UNKNOWN_UNCONFIRMED','ACCEPTED_PROVIDER_ATTESTED',
              'DELIVERED_INBOX_OBSERVED','PROVIDER_REJECTION_ATTESTED',
              'PROVIDER_FAILURE_ATTESTED'),
         'EC293_PROVIDER_OR_DELIVERY_STATE_INVALID')
    need(result['operation_id'] is None or
         (type(result['operation_id']) is str and HEX.fullmatch(result['operation_id']) is not None),
         'EC293_OPERATION_INVALID')
    need(result['provider_message_id_sha256'] is None or
         (type(result['provider_message_id_sha256']) is str and
          HEX.fullmatch(result['provider_message_id_sha256']) is not None),
         'EC293_PROVIDER_MESSAGE_HASH_INVALID')
    if result['status']=='partial':
        need(result['reason_code']=='DELIVERY_STATUS_SIGNED_READ_ONLY_OBSERVATION' and
             all(result[k] for k in ('read_grant_verified','submit_attempt_marker_verified',
                    'status_network_requested','provider_evidence_verified')) and
             result['operation_id'] is not None and
             result['provider_state'] is not None,
             'EC293_FALSE_ORIGINAL_POSITIVE_STATUS')
        expected={'DELIVERED_INBOX_OBSERVED':('DELIVERED',True,True),
                  'ACCEPTED_PROVIDER_ATTESTED':(None,True,False),
                  'PROVIDER_REJECTION_ATTESTED':('REJECTED',False,False),
                  'PROVIDER_FAILURE_ATTESTED':('FAILED',False,False),
                  'UNKNOWN_UNCONFIRMED':(None,False,False)}
        need(result['delivery_state'] in expected,'EC293_UNKNOWN_DELIVERY_STATE')
        _, accepted, delivered=expected[result['delivery_state']]
        need(result['provider_accepted'] is accepted and
             result['recipient_delivery_observed'] is delivered and
             result['inbox_evidence_verified'] is delivered and
             (not delivered or result['provider_state']=='DELIVERED') and
             (not accepted or result['provider_state'] in ('ACCEPTED','DELIVERED')) and
             (result['provider_state'] not in ('ACCEPTED','DELIVERED') or accepted) and
             (result['provider_state']!='REJECTED' or result['delivery_state']=='PROVIDER_REJECTION_ATTESTED') and
             (result['provider_state']!='FAILED' or result['delivery_state']=='PROVIDER_FAILURE_ATTESTED') and
             (result['provider_message_id_sha256'] is not None)==accepted,
             'EC293_DELIVERY_EVIDENCE_CONTRADICTION')
    else:
        need(result['delivery_state']=='UNKNOWN_UNCONFIRMED' and
             result['provider_state'] is None and
             result['provider_message_id_sha256'] is None and
             not result['provider_evidence_verified'] and
             not result['inbox_evidence_verified'] and
             not result['provider_accepted'] and
             not result['recipient_delivery_observed'],
             'EC293_FAILED_STATUS_CANNOT_CLAIM_PROOF')
    return result


def denial(code:str,status:str='unavailable',*,invoked:bool=False,
           read_outcome_unknown:bool=False)->dict:
    need(status in ('unavailable','invalid_input','permission_denied'),
         'EC293_DENIAL_STATUS_INVALID')
    return {'schema':DENIAL_SCHEMA,'status':status,
        'exit_code':{'unavailable':5,'invalid_input':4,'permission_denied':3}[status],
        'reason_code':code,'handler_invoked':invoked,
        'read_outcome_unknown':read_outcome_unknown,
        'provider_accepted':False,'recipient_delivery_observed':False,
        'message_sent_by_status_read':False,'automatic_read_or_send_retry_allowed':False}


def signed_reply(req:dict,result:dict,policy_sha:str,job_sha:str,key,now:int)->dict:
    body={'schema':REPLY_SCHEMA,'nonce':req['nonce'],
          'request_sha256':digest(canonical(req)),
          'policy_sha256':policy_sha,'job_sha256':job_sha,
          'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}


def verify_reply(reply:Any,req:dict,server_pub:str,policy_sha:str,now:int)->dict:
    keys(reply,{'schema','nonce','request_sha256','policy_sha256','job_sha256',
                'issued_at_unix','result','signature_ed25519'},
         'EC293_SERVER_REPLY_FIELDS_INVALID')
    sub=validate_subject(req['grant']['subject'])
    need(reply['schema']==REPLY_SCHEMA and reply['nonce']==req['nonce'] and
         reply['request_sha256']==digest(canonical(req)) and
         reply['policy_sha256']==policy_sha==sub['policy_sha256'] and
         reply['job_sha256']==sub['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(reply['issued_at_unix']-now)<=90,
         'EC293_SERVER_REPLY_NONCE_SCOPE_OR_TIME_MISMATCH')
    verify('server',{k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'],server_pub)
    result=reply['result']
    need(type(result) is dict,'EC293_SERVER_SIGNED_RESULT_MISSING')
    if result.get('schema')==st.SCHEMA:
        value=validate_backend(result)
        need(value['operation_id']==sub['operation_id'] or
             (value['status']!='partial' and value['operation_id'] is None),
             'EC293_WRONG_OPERATION_IN_SIGNED_EC226_REPLY')
        return value
    keys(result,{'schema','status','exit_code','reason_code','handler_invoked',
                 'read_outcome_unknown','provider_accepted','recipient_delivery_observed',
                 'message_sent_by_status_read','automatic_read_or_send_retry_allowed'},
         'EC293_SIGNED_DENIAL_FIELDS_INVALID')
    need(result['schema']==DENIAL_SCHEMA and
         (result['status'],result['exit_code']) in (
             ('unavailable',5),('invalid_input',4),('permission_denied',3)) and
         type(result['reason_code']) is str and
         re.fullmatch('EC293_[A-Z0-9_]{1,160}',result['reason_code']) is not None and
         type(result['handler_invoked']) is bool and
         type(result['read_outcome_unknown']) is bool and
         all(result[name] is False for name in (
           'provider_accepted','recipient_delivery_observed',
           'message_sent_by_status_read','automatic_read_or_send_retry_allowed')),
         'EC293_FALSE_SIGNED_DENIAL')
    return result

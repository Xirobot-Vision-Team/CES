#!/usr/bin/env python3
"""EC288: independently gated ORIGINAL EC221-225 one-use sandbox submission.

The exact private JSON job and all original trust roots are HOST-owned and SHA-pinned;
the socket receives only a nonce and two independently signed, short-lived votes.
Only the original EC225 DeliverySender performs provider probe/submit. A returned
202 means SUBMISSION_UNCONFIRMED, not delivered; an untrusted reply is UNKNOWN.
"""
from __future__ import annotations

import base64
from dataclasses import fields, is_dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finding_query_host import protocol as io
import delivery_preview as dp
import delivery_redaction as dr
import delivery_identity as di
import delivery_authorization as da
import delivery_send as ds
import report_history as rh
import finding_show as fshow

POLICY_SCHEMA = 'ces.ec288.delivery_send_policy.v1'
JOB_SCHEMA = 'ces.ec288.exact_private_delivery_job.v1'
TRUST_SCHEMA = 'ces.ec288.delivery_send_trust.v1'
SUBJECT_SCHEMA = 'ces.ec288.delivery_offline_subject.v1'
VOTE_SCHEMA = 'ces.ec288.delivery_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec288.delivery_two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec288.delivery_host_request.v1'
REPLY_SCHEMA = 'ces.ec288.delivery_host_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec288.delivery_host_denial.v1'
RESULT_SCHEMA = 'ces.ec288.verified_delivery_send_result.v1'
DOMAINS = {
    'custodian': b'CES/EC288/DeliverySend/SourceCustodian/v1\x00',
    'authorizer': b'CES/EC288/DeliverySend/ExternalSideEffectAuthorizer/v1\x00',
    'server': b'CES/EC288/DeliverySend/SignedHostReply/v1\x00',
}
MAX_POLICY, MAX_TRUST, MAX_JOB = 16000, 20000, 450000
MAX_TOKEN, MAX_RPC, MAX_REPLY = 4096, 8192, 14000
MAX_TTL, CLOCK_SKEW = 25, 5
HOST_FILES = ('protocol.py','daemon.py','operator.py')
SOURCE_FILES = ('report_history.py','finding_show.py','finding_save.py',
                'delivery_preview.py','delivery_redaction.py','delivery_identity.py',
                'delivery_authorization.py','delivery_send.py')
POLICY_KEYS = {'schema','job_file','job_sha256','trust_file','trust_sha256',
               'credential_file','credential_sha256','outbox_root','admission_root',
               'allowed_uids','custodian_issuer_public_hex',
               'authorizer_issuer_public_hex','server_public_hex',
               'original_backend_sha256','host_backend_sha256','enable_single_sandbox_delivery'}
SUBJECT_KEYS = {'schema','grant_id','uid','policy_sha256','job_sha256',
                'trust_sha256','credential_sha256','original_backend_sha256','host_backend_sha256',
                'original_approval_sha256','payload_sha256',
                'issued_at_unix','expires_at_unix'}
RESULT_KEYS = {'schema','status','exit_code','reason_code','operation_id',
               'submission_receipt_id','submission_state','claim_committed',
               'provider_sandbox_capability_verified','provider_probe_requested',
               'submission_post_attempted','ready_to_send','message_sent',
               'delivery_accepted','delivered','published','effects'}
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
B64 = re.compile(r'[A-Za-z0-9+/]*={0,2}\Z', re.ASCII)


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(value: Any) -> bytes:
    return io.canonical(value)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(role: str, doc: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(doc)).hex()


def verify(role: str, doc: dict, signature: Any, pub: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC288_SIGNATURE_SHAPE_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(signature),
                                    DOMAINS[role] + canonical(doc))
    except Exception as exc:
        raise HostError('EC288_SIGNATURE_NOT_AUTHORIZED', 'permission_denied') from exc


def absolute(path: Any) -> bool:
    return (type(path) is str and 1 < len(path) < 2048 and path.startswith('/') and
            not path.startswith('//') and '\x00' not in path and
            os.path.normpath(path) == path)


def private_parent(path: str) -> None:
    need(absolute(path), 'EC288_ABSOLUTE_PRIVATE_PATH_REQUIRED')
    try:
        parent = Path(path).parent
        need(not any(p.is_symlink() for p in (Path(path), *Path(path).parents)),
             'EC288_SYMLINK_PATH_FORBIDDEN')
        st = os.lstat(parent)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
             not stat.S_IMODE(st.st_mode) & 0o077,
             'EC288_PRIVATE_PARENT_OWNER_MODE_REQUIRED')
    except OSError as exc:
        raise HostError('EC288_PRIVATE_PARENT_UNAVAILABLE') from exc


def private_file(path: str, limit: int) -> bytes:
    private_parent(path)
    try:
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
             not stat.S_IMODE(st.st_mode) & 0o077 and st.st_nlink == 1 and
             0 < st.st_size <= limit, 'EC288_PRIVATE_FILE_OWNER_MODE_SIZE_INVALID')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            f = os.fstat(fd)
            need((f.st_dev,f.st_ino)==(st.st_dev,st.st_ino) and
                 f.st_uid==st.st_uid and f.st_size==st.st_size,
                 'EC288_PRIVATE_FILE_RACE_DETECTED')
            raw = os.read(fd, limit+1)
            need(len(raw)==st.st_size, 'EC288_PRIVATE_FILE_UNSTABLE')
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise HostError('EC288_PRIVATE_FILE_UNAVAILABLE') from exc


def pinned(path: str, sha256: str, limit: int) -> dict:
    raw = private_file(path,limit)
    need(hmac.compare_digest(digest(raw), sha256),
         'EC288_OWNER_PRIVATE_BYTES_CHANGED')
    return io.parse(raw,limit)


def backend_sha() -> str:
    h=hashlib.sha256(b'CES/EC288/ORIGINAL-EC221-225-CODE/v1\x00')
    root=Path(__file__).resolve().parents[1]
    for name in SOURCE_FILES:
        p=root/name
        need(p.is_file() and not p.is_symlink(),
             'EC288_ORIGINAL_SOURCE_MISSING')
        raw=p.read_bytes()
        h.update(name.encode()+b'\x00'+len(raw).to_bytes(8,'big')+raw)
    return h.hexdigest()



def host_code_sha() -> str:
    # New bridge is pinned independently of untouched original EC221-225.
    h=hashlib.sha256(b'CES/EC288/PRIVILEGED-HOST-CODE/v1\x00')
    for name in HOST_FILES:
        path=Path(__file__).resolve().parent/name
        need(path.is_file() and not path.is_symlink(),
             'EC288_PRIVILEGED_HOST_SOURCE_MISSING')
        raw=path.read_bytes()
        h.update(name.encode()+b'\x00'+len(raw).to_bytes(8,'big')+raw)
    return h.hexdigest()

def keys(doc: Any, expected: set, code: str) -> dict:
    need(type(doc) is dict and set(doc)==expected, code)
    return doc


def typed(cls: type, doc: Any, *, except_fields: tuple[str,...] = ()) -> dict:
    entries={f.name for f in fields(cls)}-set(except_fields)
    keys(doc,entries,'EC288_ORIGINAL_DATACLASS_FIELDS_INVALID')
    for f in fields(cls):
        if f.name in except_fields: continue
        v=doc[f.name]
        # These fields are then *also* validated by the unchanged original
        # business methods. Reject JSON values with the wrong broad type here.
        need(type(v) not in (float,type(None)) or cls is dp.Destination,
             'EC288_ORIGINAL_DATA_SCALAR_INVALID')
    return doc


def signed(doc: Any, cls: type):
    keys(doc,{'statement','signature_hex'},'EC288_SIGNED_STATEMENT_FIELDS_INVALID')
    need(type(doc['statement']) is dict and
         len(canonical(doc['statement']))<=da.MAX_SIGNED_JSON_BYTES and
         type(doc['signature_hex']) is str and
         io.HEX_SIG.fullmatch(doc['signature_hex']) is not None,
         'EC288_ORIGINAL_SIGNED_STATEMENT_INVALID')
    return cls(doc['statement'],doc['signature_hex'])


def source(doc: Any):
    need(type(doc) is dict and 'kind' in doc,'EC288_SOURCE_KIND_REQUIRED')
    kind=doc['kind']
    if kind=='REPORT':
        fields_={f.name for f in fields(dp.ReportSelection)}-{'reader'}
        keys(doc,fields_|{'kind'},'EC288_REPORT_SOURCE_FIELDS_INVALID')
        arg={k:doc[k] for k in fields_}
        need(absolute(arg['storage_root']) and
             type(arg['slot_members']) is list and
             type(arg['read_policy']) is dict,
             'EC288_REPORT_SOURCE_PRIVATE_SCOPE_INVALID')
        return dp.ReportSelection(reader=rh.ReportHistory(),**arg)
    if kind=='FINDING':
        fields_={f.name for f in fields(dp.FindingSelection)}-{'reader'}
        keys(doc,fields_|{'kind','reader_roots'},'EC288_FINDING_SOURCE_FIELDS_INVALID')
        roots=keys(doc['reader_roots'],
                   {'stage_root','business_repo_root','finding_store_root','codesave_root'},
                   'EC288_FINDING_READER_ROOTS_INVALID')
        need(all(absolute(v) for k,v in roots.items() if k!='codesave_root' or v is not None),
             'EC288_FINDING_READER_PATH_INVALID')
        obj=fshow.FindingShower(roots['stage_root'],roots['business_repo_root'],
                               roots['finding_store_root'],codesave_root=roots['codesave_root'])
        return dp.FindingSelection(reader=obj,**{k:doc[k] for k in fields_})
    raise HostError('EC288_SOURCE_KIND_NOT_SUPPORTED','invalid_input')



def encode_original_request(request: ds.DeliverySendRequest) -> dict:
    """Trusted operator-side serializer for a REAL original EC225 request.

    Never export a client-claim as an "approval": the returned owner-private job
    still requires the original EC221-224 signatures/stores to validate at send.
    Source reader objects become *fixed constructor data*, never pickle/import.
    """
    need(type(request) is ds.DeliverySendRequest,
         'EC288_ORIGINAL_DELIVERY_REQUEST_OBJECT_REQUIRED')
    allowed={ds.DeliverySendRequest,da.DeliveryAuthorizationRequest,
             da.SignedAuthorizationStatement,di.DeliveryIdentityRequest,
             di.SignedIdentityStatement,dr.SensitiveReviewRequest,
             dr.FindingTextWitness,dp.DeliveryPreviewRequest,dp.Destination}

    def convert(value):
        if type(value) is bytes:
            return base64.b64encode(value).decode('ascii')
        if type(value) is dp.ReportSelection:
            return {'kind':'REPORT',**{
                f.name:convert(getattr(value,f.name))
                for f in fields(value) if f.name!='reader'}}
        if type(value) is dp.FindingSelection:
            reader=value.reader
            need(type(reader) is fshow.FindingShower and
                 reader.clock is None and reader.ledger.clock is None,
                 'EC288_CUSTOM_FINDING_READER_CLOCK_NOT_SERIALIZABLE')
            ledger=reader.ledger
            return {'kind':'FINDING','reader_roots':{
                k:getattr(ledger,k) for k in (
                'stage_root','business_repo_root','finding_store_root','codesave_root')},
                **{f.name:convert(getattr(value,f.name))
                   for f in fields(value) if f.name!='reader'}}
        if is_dataclass(value):
            need(type(value) in allowed,
                 'EC288_ORIGINAL_UNAPPROVED_DATACLASS_TYPE')
            return {('exact_payload_b64' if f.name=='exact_payload_bytes' else f.name):
                    convert(getattr(value,f.name)) for f in fields(value)}
        if type(value) in (tuple,list):
            return [convert(x) for x in value]
        if type(value) is dict:
            need(all(type(k) is str for k in value),
                 'EC288_ORIGINAL_JSON_KEY_TYPE_INVALID')
            return {k:convert(v) for k,v in value.items()}
        need(value is None or type(value) in (str,int,bool),
             'EC288_ORIGINAL_JSON_VALUE_TYPE_INVALID')
        return value

    job={'schema':JOB_SCHEMA,'send_request':convert(request)}
    need(len(canonical(job))<=MAX_JOB,'EC288_ORIGINAL_EXACT_JOB_TOO_LARGE')
    validate_job(job)
    return job


def decode_job(doc: Any) -> ds.DeliverySendRequest:
    keys(doc,{'schema','send_request'},'EC288_EXACT_JOB_SHAPE_INVALID')
    need(doc['schema']==JOB_SCHEMA,'EC288_JOB_SCHEMA_INVALID')
    obj=keys(doc['send_request'],{'authorization_request','exact_side_effect_grant',
         'permit_single_sandbox_external_side_effect','permit_provider_network_egress'},
         'EC288_SEND_REQUEST_FIELDS_INVALID')
    ar=keys(obj['authorization_request'],{'identity_request',
         'expected_identity_verification_id','exact_payload_b64',
         'organization_entitlement','exact_delivery_grant',
         'organization_revocation_checkpoint',
         'permit_independent_delivery_authorization'},
         'EC288_EC224_REQUEST_FIELDS_INVALID')
    ir=keys(ar['identity_request'],{'sensitive_review_request','expected_review_id',
         'expected_redacted_markdown_sha256','project_id','directory_route',
         'revocation_checkpoint','verification_permit',
         'permit_independent_identity_verification'},
         'EC288_EC223_REQUEST_FIELDS_INVALID')
    review=keys(ir['sensitive_review_request'],{'preview_request',
         'expected_preview_id','expected_policy_sha256',
         'permit_independent_sensitive_policy_review',
         'permit_exact_report_plaintext_review','permit_exact_finding_plaintext_review',
         'finding_text_witnesses'},'EC288_EC222_REQUEST_FIELDS_INVALID')
    preview=keys(review['preview_request'],{'sources','destination',
         'policy_revision_sha256','requested_privacy_floor','permit_local_preview',
         'permit_private_source_metadata_read','permit_report_content_read_in_process',
         'permit_finding_digest_details_read'},'EC288_EC221_REQUEST_FIELDS_INVALID')
    need(type(preview['sources']) is list and 1<=len(preview['sources'])<=4 and
         type(review['finding_text_witnesses']) is list and
         len(review['finding_text_witnesses'])<=4,
         'EC288_BOUNDED_PRIVATE_SOURCE_SELECTION_REQUIRED')
    dest=dp.Destination(**typed(dp.Destination,preview['destination']))
    pre=dp.DeliveryPreviewRequest(
        tuple(source(s) for s in preview['sources']),dest,
        **{k:v for k,v in preview.items() if k not in ('sources','destination')})
    witnesses=tuple(dr.FindingTextWitness(**typed(dr.FindingTextWitness,w))
                    for w in review['finding_text_witnesses'])
    rev=dr.SensitiveReviewRequest(pre,finding_text_witnesses=witnesses,**{
        k:v for k,v in review.items() if k not in ('preview_request','finding_text_witnesses')})
    ident=di.DeliveryIdentityRequest(rev,
        **{k:(signed(v,di.SignedIdentityStatement) if k in (
             'directory_route','revocation_checkpoint','verification_permit') else v)
           for k,v in ir.items() if k!='sensitive_review_request'})
    b64=ar['exact_payload_b64']
    need(type(b64) is str and 0<len(b64)<=24000 and B64.fullmatch(b64) is not None,
         'EC288_EXACT_PAYLOAD_BASE64_INVALID')
    try:
        payload=base64.b64decode(b64,validate=True)
        need(base64.b64encode(payload).decode('ascii')==b64 and
             0<len(payload)<=dr.MAX_SUMMARY_BYTES,
             'EC288_EXACT_PAYLOAD_NOT_BOUNDED')
    except (ValueError,base64.binascii.Error) as exc:
        raise HostError('EC288_PAYLOAD_BASE64_NOT_CANONICAL') from exc
    auth=da.DeliveryAuthorizationRequest(
        ident,ar['expected_identity_verification_id'],payload,
        signed(ar['organization_entitlement'],da.SignedAuthorizationStatement),
        signed(ar['exact_delivery_grant'],da.SignedAuthorizationStatement),
        signed(ar['organization_revocation_checkpoint'],da.SignedAuthorizationStatement),
        ar['permit_independent_delivery_authorization'])
    return ds.DeliverySendRequest(auth,
       signed(obj['exact_side_effect_grant'],da.SignedAuthorizationStatement),
       obj['permit_single_sandbox_external_side_effect'],
       obj['permit_provider_network_egress'])


def validate_job(doc: Any) -> ds.DeliverySendRequest:
    try:
        req=decode_job(doc)
    except (HostError,):
        raise
    except (TypeError,ValueError,KeyError,AttributeError,RecursionError) as exc:
        raise HostError('EC288_ORIGINAL_PRIVATE_JOB_INVALID') from exc
    need(all(type(v) is bool and v is True for v in (
         req.permit_single_sandbox_external_side_effect,
         req.permit_provider_network_egress,
         req.authorization_request.permit_independent_delivery_authorization,
         req.authorization_request.identity_request.permit_independent_identity_verification)),
         'EC288_ALL_EXPLICIT_APPROVAL_FLAGS_REQUIRED')
    # Both original EC221 and EC222 policies must be present; their full checks
    # execute inside EC225 before any network call, against the real private store.
    pre=req.authorization_request.identity_request.sensitive_review_request.preview_request
    need(pre.policy_revision_sha256 == dr.ACTIVE_POLICY_SHA256 and
         pre.requested_privacy_floor in ('PUBLIC','INTERNAL'),
         'EC288_INTERNAL_ONLY_POLICY_REQUIRED')
    return req


def load_job(pol: dict) -> ds.DeliverySendRequest:
    return validate_job(pinned(pol['job_file'],pol['job_sha256'],MAX_JOB))


def validate_trust(doc: Any) -> dict:
    keys(doc,{'schema','identity','authorization','send','target',
              'enable_live_sandbox_send'},'EC288_HOST_TRUST_FIELDS_INVALID')
    need(doc['schema']==TRUST_SCHEMA and doc['enable_live_sandbox_send'] is True,
         'EC288_EXPLICIT_HOST_SIDE_SANDBOX_OPT_IN_MISSING')
    keys(doc['identity'],{'issuer_id','directory_public_hex','revocation_public_hex',
                         'verification_public_hex'},'EC288_IDENTITY_TRUST_FIELDS_INVALID')
    keys(doc['authorization'],{'issuer_id','organization_id','approver_id',
         'approval_public_hex','entitlement_public_hex','revocation_public_hex',
         'minimum_revocation_epoch'},'EC288_APPROVAL_TRUST_FIELDS_INVALID')
    keys(doc['send'],{'issuer_id','operator_id','side_effect_public_hex',
                      'provider_capability_public_hex','minimum_send_epoch'},
         'EC288_SIDE_EFFECT_TRUST_FIELDS_INVALID')
    typed(ds.HostTestProvider,doc['target'])
    for k in ('directory_public_hex','revocation_public_hex','verification_public_hex'):
        io.pub_from_hex(doc['identity'][k])
    for k in ('approval_public_hex','entitlement_public_hex','revocation_public_hex'):
        io.pub_from_hex(doc['authorization'][k])
    for k in ('side_effect_public_hex','provider_capability_public_hex'):
        io.pub_from_hex(doc['send'][k])
    need(doc['target']['user_controlled_sandbox'] is True,
         'EC288_NON_SANDBOX_TARGET_FORBIDDEN')
    return doc


def trust_keys(trust: dict) -> list[str]:
    return ([trust['identity'][k] for k in (
                'directory_public_hex','revocation_public_hex','verification_public_hex')] +
            [trust['authorization'][k] for k in (
                'approval_public_hex','entitlement_public_hex','revocation_public_hex')] +
            [trust['send'][k] for k in (
                'side_effect_public_hex','provider_capability_public_hex')])


def load_trust(pol: dict) -> dict:
    return validate_trust(pinned(pol['trust_file'],pol['trust_sha256'],MAX_TRUST))


def build_sender(trust: dict, credential: str, outbox_root: str) -> ds.DeliverySender:
    d,a,s=trust['identity'],trust['authorization'],trust['send']
    roots_i=di.TrustedIdentityRoots(d['issuer_id'],*(bytes.fromhex(d[k]) for k in (
        'directory_public_hex','revocation_public_hex','verification_public_hex')))
    roots_a=da.TrustedAuthorizationRoots(
        a['issuer_id'],a['organization_id'],a['approver_id'],
        *(bytes.fromhex(a[k]) for k in (
          'approval_public_hex','entitlement_public_hex','revocation_public_hex')),
        a['minimum_revocation_epoch'])
    roots_s=ds.TrustedSideEffectRoots(
        s['issuer_id'],s['operator_id'],
        bytes.fromhex(s['side_effect_public_hex']),
        bytes.fromhex(s['provider_capability_public_hex']),s['minimum_send_epoch'])
    target=ds.HostTestProvider(**trust['target'])
    access=ds.HostSendAccess(roots_s,target,credential,outbox_root,True,False)
    return ds.DeliverySender(access,
              da.DeliveryAuthorizer(roots_a,di.DeliveryIdentityVerifier(roots_i)),
              transport=None)


def load_credential(pol: dict) -> str:
    raw=private_file(pol['credential_file'],MAX_TOKEN)
    need(hmac.compare_digest(digest(raw),pol['credential_sha256']),
         'EC288_PRIVATE_CREDENTIAL_CHANGED')
    try:
        cred=raw.decode('ascii')
    except UnicodeError as exc:
        raise HostError('EC288_CREDENTIAL_NOT_ASCII') from exc
    need(cred.strip()==cred and 16<=len(cred)<=2048 and
         all(33<=ord(c)<=126 for c in cred),
         'EC288_HOST_SCOPED_CREDENTIAL_INVALID')
    return cred


def private_directory(path: str) -> None:
    private_parent(path)
    try:
        st=os.lstat(path)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
             stat.S_IMODE(st.st_mode)&0o077==0,
             'EC288_OWNER_ONLY_DURABLE_DIRECTORY_REQUIRED')
    except OSError as exc:
        raise HostError('EC288_DURABLE_DIRECTORY_MISSING') from exc


def validate_policy(pol: Any) -> dict:
    keys(pol,POLICY_KEYS,'EC288_HOST_POLICY_FIELDS_INVALID')
    need(pol['schema']==POLICY_SCHEMA and pol['enable_single_sandbox_delivery'] is True,
         'EC288_HOST_LIVE_SEND_NOT_ENABLED')
    for k in ('job_file','trust_file','credential_file','outbox_root','admission_root'):
        need(absolute(pol[k]),'EC288_HOST_PRIVATE_ABSOLUTE_PATH_REQUIRED')
    need(len({pol[k] for k in ('job_file','trust_file','credential_file',
                             'outbox_root','admission_root')})==5,
         'EC288_HOST_PRIVATE_PATH_COLLISION')
    for k in ('job_sha256','trust_sha256','credential_sha256','original_backend_sha256','host_backend_sha256'):
        need(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None,
             'EC288_HOST_RAW_SHA_PIN_INVALID')
    need(pol['original_backend_sha256']==backend_sha(),
         'EC288_ORIGINAL_BACKEND_BYTES_CHANGED')
    need(pol['host_backend_sha256']==host_code_sha(),
         'EC288_PRIVILEGED_BRIDGE_BYTES_CHANGED')
    uids=pol['allowed_uids']
    need(type(uids) is list and 1<=len(uids)<=32 and
         all(type(i) is int and 0<=i<=2**31-1 for i in uids) and
         uids==sorted(set(uids)),'EC288_HOST_PEER_UID_ALLOWLIST_INVALID')
    rolekeys=[pol[k] for k in ('custodian_issuer_public_hex',
                    'authorizer_issuer_public_hex','server_public_hex')]
    for key in rolekeys: io.pub_from_hex(key)
    need(len(set(rolekeys))==3,'EC288_THREE_DISTINCT_HOST_KEYS_REQUIRED')
    return pol


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and HEX.fullmatch(expected_sha) is not None,
         'EC288_EXPECTED_POLICY_SHA_REQUIRED')
    return validate_policy(pinned(path,expected_sha,MAX_POLICY))


def job_pins(pol: dict, req: ds.DeliverySendRequest) -> dict:
    return {'job_sha256':pol['job_sha256'],'trust_sha256':pol['trust_sha256'],
            'credential_sha256':pol['credential_sha256'],
            'original_backend_sha256':pol['original_backend_sha256'],
            'host_backend_sha256':pol['host_backend_sha256'],
            'original_approval_sha256':digest(canonical(
                req.authorization_request.exact_delivery_grant.__dict__)),
            'payload_sha256':digest(req.authorization_request.exact_payload_bytes)}


def validate_subject(s: Any) -> dict:
    keys(s,SUBJECT_KEYS,'EC288_OFFLINE_SUBJECT_FIELDS_INVALID')
    need(s['schema']==SUBJECT_SCHEMA and
         type(s['grant_id']) is str and io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s['uid']) is int and 0<=s['uid']<=2**31-1 and
         all(type(s[k]) is str and HEX.fullmatch(s[k]) is not None for k in (
             'policy_sha256','job_sha256','trust_sha256','credential_sha256',
             'original_backend_sha256','host_backend_sha256','original_approval_sha256','payload_sha256')) and
         type(s['issued_at_unix']) is int and type(s['expires_at_unix']) is int and
         0<s['issued_at_unix']<s['expires_at_unix'] and
         s['expires_at_unix']-s['issued_at_unix']<=MAX_TTL,
         'EC288_OFFLINE_SUBJECT_SCOPE_INVALID')
    return s


def new_subject(uid: int, policy_sha: str, pins: dict, ttl: int) -> dict:
    need(type(ttl) is int and 1<=ttl<=MAX_TTL,'EC288_TTL_EXCEEDS_CEILING')
    now=int(time.time())
    return validate_subject({'schema':SUBJECT_SCHEMA,'grant_id':secrets.token_hex(16),
      'uid':uid,'policy_sha256':policy_sha,**pins,
      'issued_at_unix':now,'expires_at_unix':now+ttl})


def validate_grant(grant: Any, pol: dict, req: ds.DeliverySendRequest, *,
                   uid: int, now: int, policy_sha: str) -> dict:
    keys(grant,{'schema','subject','custodian_signature_ed25519',
                'authorizer_signature_ed25519'},
         'EC288_TWO_OFFLINE_VOTES_REQUIRED')
    need(grant['schema']==GRANT_SCHEMA,'EC288_OFFLINE_GRANT_SCHEMA_INVALID')
    sub=validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and uid==sub['uid'] and
         sub['policy_sha256']==policy_sha and
         all(sub[k]==v for k,v in job_pins(pol,req).items()) and
         sub['issued_at_unix']<=now+CLOCK_SKEW and
         now<sub['expires_at_unix'],
         'EC288_KERNEL_UID_PRIVATE_PIN_OR_TIME_MISMATCH','permission_denied')
    for role in ('custodian','authorizer'):
        verify(role,sub,grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return sub


def validate_backend(result: Any) -> dict:
    keys(result,RESULT_KEYS,'EC288_ORIGINAL_RESULT_FIELDS_UNEXPECTED')
    need(result['schema']==ds.SCHEMA and
         (result['status'],result['exit_code']) in (
             ('partial',2),('blocked',5),('unavailable',5),('invalid_input',4)) and
         type(result['reason_code']) is str and
         re.fullmatch(r'DELIVERY_SEND_[A-Z0-9_]{1,150}',result['reason_code']) is not None and
         type(result['effects']) is dict and
         set(result['effects'])==set(dp.effects()) and
         all(type(x) is bool for x in result['effects'].values()),
         'EC288_ORIGINAL_EC225_RESULT_NOT_RECOGNIZED')
    for k in ('claim_committed','provider_sandbox_capability_verified',
        'provider_probe_requested','submission_post_attempted','ready_to_send',
        'message_sent','delivery_accepted','delivered','published'):
        need(type(result[k]) is bool,'EC288_ORIGINAL_RESULT_BOOLEAN_INVALID')
    need(all(result[k] is False for k in (
        'ready_to_send','message_sent','delivery_accepted','delivered','published')) and
        all(result['effects'][k] is False for k in (
        'message_sent','delivery_accepted','delivered','published',
        'recipient_contacted','git_or_business_files_written',
        'ces_records_written','issue_or_pr_created_or_modified','external_ai_invoked')),
        'EC288_FALSE_DELIVERY_OR_FORBIDDEN_SIDE_EFFECT_CLAIM')
    for k in ('operation_id','submission_receipt_id'):
        v=result[k]
        need(v is None or (type(v) is str and
             re.fullmatch(r'(?:cesds1:)?[a-f0-9]{64}',v) is not None),
             'EC288_OPERATION_OR_RECEIPT_INVALID')
    need(type(result['submission_state']) is str and
         result['submission_state'] in (
         'SUBMISSION_UNCONFIRMED','UNKNOWN_UNCONFIRMED','NO_SUBMISSION_ATTEMPT'),
         'EC288_SUBMISSION_STATE_INVALID')
    need(not result['submission_post_attempted'] or (
        result['claim_committed'] and result['provider_sandbox_capability_verified'] and
        result['provider_probe_requested']),
         'EC288_POST_WITHOUT_ORIGINAL_DURABLE_BARRIER')
    if result['status']=='partial':
        need(result['submission_post_attempted'] and
             result['submission_state']=='SUBMISSION_UNCONFIRMED' and
             result['operation_id'] is not None and
             result['submission_receipt_id'] is not None,
             'EC288_PARTIAL_CANNOT_CLAIM_DELIVERY')
    else:
        need(result['submission_receipt_id'] is None and
             result['submission_state']!='SUBMISSION_UNCONFIRMED',
             'EC288_FAILURE_CANNOT_CLAIM_SUBMISSION_RECEIPT')
    return result


def denial(code: str, status: str = 'unavailable', *,
           handler_invoked: bool = False, send_outcome_unknown: bool = False) -> dict:
    need(status in ('unavailable','invalid_input','permission_denied'),
         'EC288_DENIAL_STATUS_UNSUPPORTED')
    return {'schema':DENIAL_SCHEMA,'status':status,
            'exit_code':{'unavailable':5,'invalid_input':4,'permission_denied':3}[status],
            'reason_code':code,'handler_invoked':handler_invoked,
            'send_outcome_unknown':send_outcome_unknown,
            'delivered':False,'external_content_returned':False,
            'automatic_retry_allowed':False}


def signed_reply(req: dict, result: dict, policy_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    body={'schema':REPLY_SCHEMA,'nonce':req['nonce'],
          'request_sha256':digest(canonical(req)),
          'policy_sha256':policy_sha,'job_sha256':job_sha,
          'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}


def verify_reply(reply: Any, req: dict, pub: str,
                 policy_sha: str, now: int) -> dict:
    keys(reply,{'schema','nonce','request_sha256','policy_sha256','job_sha256',
                'issued_at_unix','result','signature_ed25519'},
         'EC288_SIGNED_REPLY_FIELDS_INVALID')
    sub=validate_subject(req['grant']['subject'])
    need(reply['schema']==REPLY_SCHEMA and reply['nonce']==req['nonce'] and
         reply['request_sha256']==digest(canonical(req)) and
         reply['policy_sha256']==policy_sha==sub['policy_sha256'] and
         reply['job_sha256']==sub['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now-reply['issued_at_unix'])<=90,
         'EC288_SIGNED_REPLY_PIN_NONCE_OR_TIME_MISMATCH')
    verify('server',{k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'],pub)
    r=reply['result']
    need(type(r) is dict,'EC288_SIGNED_RESULT_NOT_OBJECT')
    if r.get('schema')==ds.SCHEMA:
        return validate_backend(r)
    keys(r,{'schema','status','exit_code','reason_code','handler_invoked',
            'send_outcome_unknown','delivered','external_content_returned',
            'automatic_retry_allowed'},'EC288_SIGNED_DENIAL_INVALID')
    need(r['schema']==DENIAL_SCHEMA and
         (r['status'],r['exit_code']) in (
         ('unavailable',5),('invalid_input',4),('permission_denied',3)) and
         type(r['reason_code']) is str and
         re.fullmatch(r'EC288_[A-Z0-9_]{1,150}',r['reason_code']) is not None and
         type(r['handler_invoked']) is bool and
         type(r['send_outcome_unknown']) is bool and
         all(r[k] is False for k in (
         'delivered','external_content_returned','automatic_retry_allowed')),
         'EC288_SIGNED_DENIAL_SEMANTICS_INVALID')
    return r

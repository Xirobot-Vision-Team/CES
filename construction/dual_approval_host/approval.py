#!/usr/bin/env python3
"""EC276: two offline operator approvals bind an exact EC275 CAS and site roster.

This is an additional, opt-in authorization layer, NOT a new authority for
witness/TSA/governance evidence. Private approver keys are read ONLY by the
explicit offline sign command; neither the strict host nor the remote escrow
services require or accept them. Revalidation of the pinned file, signatures,
site identities and expiry is necessary on every protected host guard.
"""
from __future__ import annotations

import hmac
import secrets
import time
from typing import Any

from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from remote_escrow_host import escrow as esc
from dual_escrow_host.quorum import DualEscrow

INTENT_SCHEMA = 'ces.ec276.dual_escrow_operator_intent.v1'
APPROVAL_SCHEMA = 'ces.ec276.dual_escrow_operator_approval.v1'
DOMAIN = b'CES/EC276/two-person-dual-escrow-intent/v1\x00'
INTENT_FIELDS = frozenset({
    'schema','nonce','namespace','record','record_sha256',
    'previous_record_sha256','record_index','recovered_root_public_sha256',
    'closure_sha256','witness_public_sha256','approver_public_sha256',
    'primary','secondary','not_before_unix','expires_at_unix',
})
SITE_FIELDS = frozenset({
    'host','port','tls_ca_sha256','tls_leaf_sha256','escrow_public_sha256',
})
VOTE_FIELDS = frozenset({'public_sha256','signature_ed25519'})
APPROVAL_FIELDS = frozenset({'schema','intent','approvals'})
MAX_INTENT = 8500
MAX_APPROVAL = 10500
MAX_VOTE = 1024
MAX_LIFETIME = 72 * 3600
MIN_EPOCH = 1
MAX_EPOCH = 2**40


class ApprovalError(esc.EscrowError):
    """Fixed error codes; never return secret bytes, paths or untrusted JSON."""


def deny(code: str) -> None:
    raise ApprovalError(code)


def _sha(value: Any) -> str:
    try:
        return esc._sha(value)
    except (rec.RecoveryError, esc.EscrowError, ValueError, TypeError) as exc:
        raise ApprovalError('EC276_HASH_NOT_CANONICAL') from exc


def _document(path: str, pin: str, limit: int, code: str) -> dict:
    raw = prov._bytes(path, limit)
    if not hmac.compare_digest(esc.sha(raw), _sha(pin)):
        deny('EC276_FILE_SHA256_PIN_MISMATCH')
    return esc._parse(raw, limit, code)


def _read_intent(path: str, pin: str) -> dict:
    return _document(path, pin, MAX_INTENT, 'EC276_INTENT_NONCANONICAL')


def read_approval(path: str, pin: str) -> dict:
    return _document(path, pin, MAX_APPROVAL, 'EC276_APPROVAL_NONCANONICAL')


def approver_keys(pairs: list[tuple[str,str]], duo: DualEscrow) -> dict[str,bytes]:
    """Require three pinned, unique offline signers with no other service role."""
    if type(pairs) is not list or len(pairs) != 3:
        deny('EC276_EXACTLY_THREE_APPROVER_PUBLIC_KEYS_REQUIRED')
    paths=[]
    keys={}
    for path,pin in pairs:
        keypin=_sha(pin)
        private_path=prov._path(path)
        if private_path in paths or keypin in keys:
            deny('EC276_DUPLICATE_APPROVER_IDENTITY_OR_PATH')
        try:
            key=rec._public(private_path,keypin)
        except (rec.RecoveryError,prov.ProvenanceError) as exc:
            raise ApprovalError('EC276_APPROVER_PUBLIC_KEY_UNAVAILABLE') from exc
        paths.append(private_path)
        keys[keypin]=key
    forbidden=set(duo.keys) | {duo.primary.escrow_pin,duo.secondary.escrow_pin,duo.root}
    if set(keys)&forbidden:
        deny('EC276_APPROVER_MUST_NOT_REUSE_WITNESS_ESCROW_OR_ROOT')
    if set(paths)&set(duo.authority_paths()):
        deny('EC276_APPROVER_FILE_COLLIDES_WITH_ESCROW_TRUST')
    return keys


def site_identity(client: esc.RemoteClient) -> dict[str,Any]:
    return {'host':client.host,'port':client.port,
        'tls_ca_sha256':client.ca_pin,'tls_leaf_sha256':client.leaf_pin,
        'escrow_public_sha256':client.escrow_pin}


def _record_votes(record: Any, duo: DualEscrow) -> dict:
    if type(record) is not dict or set(record)!=esc.RECORD_FIELDS or \
            record.get('schema')!=esc.RECORD_SCHEMA:
        deny('EC276_WITNESS_RECORD_SCHEMA_INVALID')
    proposal=record.get('proposal')
    esc._proposal(proposal,namespace=duo.namespace,witnesses=sorted(duo.keys),
                  root=duo.root,closure=duo.closure)
    votes=record.get('approvals')
    if type(votes) is not list or len(votes)!=2 or any(type(v) is not dict or
            set(v)!=esc.VOTE_FIELDS for v in votes):
        deny('EC276_TWO_WITNESS_VOTES_REQUIRED')
    ordered=[v.get('public_sha256') for v in votes]
    if any(type(x) is not str for x in ordered) or ordered!=sorted(set(ordered)):
        deny('EC276_WITNESS_VOTES_NOT_DISTINCT_AND_ORDERED')
    for vote in votes:
        esc._verify_vote(proposal,vote,duo.keys)
    if len(esc.canonical(record))>esc.MAX_RECORD:
        deny('EC276_WITNESS_RECORD_TOO_LARGE')
    return proposal


def validate_intent(intent: Any, duo: DualEscrow,
                    keys: dict[str,bytes], *, now: int|None=None,
                    check_time: bool=True) -> dict:
    """Exact binding of signed authorization, full witness record and sites.

    The *separate* EC275 CAS inspector validates predecessor and transition
    against both authenticated current histories before any write. This check
    never mistakes an approval for a distributed commit.
    """
    if type(intent) is not dict or set(intent)!=INTENT_FIELDS or \
            intent.get('schema')!=INTENT_SCHEMA:
        deny('EC276_INTENT_FIELDS_INVALID')
    if type(intent['nonce']) is not str or esc.NONCE.fullmatch(intent['nonce']) is None:
        deny('EC276_INTENT_NONCE_INVALID')
    start=esc.integer(intent['not_before_unix'],MIN_EPOCH,MAX_EPOCH,
                      'EC276_NOT_BEFORE_INVALID')
    end=esc.integer(intent['expires_at_unix'],MIN_EPOCH,MAX_EPOCH,
                    'EC276_EXPIRES_INVALID')
    if end<=start or end-start>MAX_LIFETIME:
        deny('EC276_LIFETIME_TOO_LONG_OR_INVERTED')
    if check_time:
        observed=int(time.time()) if now is None else esc.integer(now,0,MAX_EPOCH,
            'EC276_OBSERVED_TIME_INVALID')
        if not start<=observed<=end:
            deny('EC276_APPROVAL_NOT_YET_VALID_OR_EXPIRED')
    if (intent['namespace']!=duo.namespace or
        intent['recovered_root_public_sha256']!=duo.root or
        intent['closure_sha256']!=duo.closure or
        intent['witness_public_sha256']!=sorted(duo.keys) or
        intent['approver_public_sha256']!=sorted(keys)):
        deny('EC276_INTENT_NAMESPACE_CUSTODY_OR_APPROVERS_CHANGED')
    for name,client in (('primary',duo.primary),('secondary',duo.secondary)):
        slot=intent[name]
        if type(slot) is not dict or set(slot)!=SITE_FIELDS or \
                slot!=site_identity(client):
            deny('EC276_SIGNED_REMOTE_SITE_IDENTITY_MISMATCH')
    rec_data=intent['record']
    proposal=_record_votes(rec_data,duo)
    new_head=esc.sha(esc.canonical(rec_data))
    if (intent['record_sha256']!=new_head or
        intent['previous_record_sha256']!=proposal['previous_record_sha256'] or
        intent['record_index']!=proposal['record_index']):
        deny('EC276_APPROVED_RECORD_OR_PREDECESSOR_MISMATCH')
    if len(esc.canonical(intent))>MAX_INTENT:
        deny('EC276_INTENT_TOO_LARGE')
    return intent


def prepare_intent(duo: DualEscrow,keys:dict[str,bytes],record:dict, *,
                   previous_sha256:str,not_before_unix:int,
                   expires_at_unix:int,output:str) -> dict:
    proposal=_record_votes(record,duo)
    prev=_sha(previous_sha256)
    if proposal['previous_record_sha256']!=prev:
        deny('EC276_PREPARE_PREVIOUS_NOT_SIGNED_RECORD_PREDECESSOR')
    intent={'schema':INTENT_SCHEMA,'nonce':secrets.token_hex(16),
        'namespace':duo.namespace,'record':record,
        'record_sha256':esc.sha(esc.canonical(record)),
        'previous_record_sha256':prev,'record_index':proposal['record_index'],
        'recovered_root_public_sha256':duo.root,'closure_sha256':duo.closure,
        'witness_public_sha256':sorted(duo.keys),
        'approver_public_sha256':sorted(keys),
        'primary':site_identity(duo.primary),'secondary':site_identity(duo.secondary),
        'not_before_unix':not_before_unix,'expires_at_unix':expires_at_unix}
    validate_intent(intent,duo,keys,check_time=False)
    raw=esc.canonical(intent)
    prov._new(output,raw)
    return {'status':'partial','exit_code':2,
        'reason_code':'EC276_OFFLINE_TWO_PERSON_REVIEW_REQUIRED',
        'intent_sha256':esc.sha(raw),
        'approved_record_sha256':intent['record_sha256'],
        'record_index':intent['record_index'],
        'offline_approver_private_keys_required_on_isolated_devices':True}


def _offline_intent_shape(intent: Any) -> dict:
    """Offline signer has no remote dependency; strictly validate what it signs."""
    if type(intent) is not dict or set(intent)!=INTENT_FIELDS or \
            intent.get('schema')!=INTENT_SCHEMA:
        deny('EC276_OFFLINE_INTENT_SCHEMA_INVALID')
    if (type(intent['nonce']) is not str or esc.NONCE.fullmatch(intent['nonce']) is None or
            type(intent['approver_public_sha256']) is not list or
            len(intent['approver_public_sha256'])!=3 or
            any(type(x) is not str or _sha(x)!=x for x in intent['approver_public_sha256']) or
            intent['approver_public_sha256']!=sorted(set(intent['approver_public_sha256']))):
        deny('EC276_OFFLINE_INTENT_APPROVER_ROSTER_INVALID')
    for field in ('record_sha256','previous_record_sha256',
                  'recovered_root_public_sha256','closure_sha256'):
        _sha(intent[field])
    if (type(intent['record']) is not dict or
        esc.sha(esc.canonical(intent['record']))!=intent['record_sha256'] or
        type(intent['record'].get('proposal')) is not dict or
        intent['record']['proposal'].get('previous_record_sha256')!=intent['previous_record_sha256'] or
        intent['record']['proposal'].get('record_index')!=intent['record_index']):
        deny('EC276_OFFLINE_RECORD_PIN_OR_ANCESTRY_INVALID')
    for field in ('primary','secondary'):
        site=intent[field]
        if (type(site) is not dict or set(site)!=SITE_FIELDS or
                type(site['host']) is not str or not site['host'] or
                type(site['port']) is not int or not 1<=site['port']<=65535):
            deny('EC276_OFFLINE_SITE_FIELDS_INVALID')
        for key in ('tls_ca_sha256','tls_leaf_sha256','escrow_public_sha256'):
            _sha(site[key])
    if intent['primary']==intent['secondary']:
        deny('EC276_OFFLINE_DUPLICATE_ESCROW_SITES')
    start=esc.integer(intent['not_before_unix'],MIN_EPOCH,MAX_EPOCH,
                      'EC276_NOT_BEFORE_INVALID')
    end=esc.integer(intent['expires_at_unix'],MIN_EPOCH,MAX_EPOCH,
                    'EC276_EXPIRES_INVALID')
    if end<=start or end-start>MAX_LIFETIME:
        deny('EC276_LIFETIME_TOO_LONG_OR_INVERTED')
    if len(esc.canonical(intent))>MAX_INTENT:
        deny('EC276_OFFLINE_INTENT_TOO_LARGE')
    return intent


def sign_intent(*,intent_path:str,intent_sha256:str,secret_path:str,
                signer_sha256:str,output:str) -> dict:
    """Explicit offline command. Never invoked from the serve/remote paths."""
    cp._need_crypto()
    intent=_offline_intent_shape(_read_intent(intent_path,intent_sha256))
    signer=_sha(signer_sha256)
    if signer not in intent['approver_public_sha256']:
        deny('EC276_OFFLINE_SIGNER_NOT_ON_APPROVER_ROSTER')
    secret=prov._bytes(secret_path,32)
    if len(secret)!=32 or esc.sha(cp.public_bytes_from_signing_key(secret))!=signer:
        deny('EC276_OFFLINE_PRIVATE_APPROVER_MISMATCH')
    vote={'public_sha256':signer,
        'signature_ed25519':cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
            DOMAIN+esc.canonical(intent)).hex()}
    raw=esc.canonical(vote)
    prov._new(output,raw)
    return {'status':'partial','exit_code':2,
        'reason_code':'EC276_OFFLINE_APPROVER_SIGNATURE_CREATED',
        'approval_vote_sha256':esc.sha(raw),'approver_public_sha256':signer,
        'independent_human_review_not_cryptographically_proven':True}


def verify_approval(doc:Any,duo:DualEscrow,keys:dict[str,bytes], *,
                    now:int|None=None,check_time:bool=True) -> dict:
    if type(doc) is not dict or set(doc)!=APPROVAL_FIELDS or \
            doc.get('schema')!=APPROVAL_SCHEMA:
        deny('EC276_APPROVAL_FIELDS_INVALID')
    intent=validate_intent(doc['intent'],duo,keys,now=now,check_time=check_time)
    votes=doc['approvals']
    if type(votes) is not list or len(votes)!=2 or any(type(v) is not dict or
            set(v)!=VOTE_FIELDS for v in votes):
        deny('EC276_EXACTLY_TWO_OFFLINE_APPROVALS_REQUIRED')
    pins=[v.get('public_sha256') for v in votes]
    if any(type(p) is not str for p in pins) or pins!=sorted(set(pins)):
        deny('EC276_DUPLICATE_OR_UNORDERED_APPROVER_VOTES')
    message=DOMAIN+esc.canonical(intent)
    for vote in votes:
        pin=_sha(vote['public_sha256'])
        if pin not in keys:
            deny('EC276_UNTRUSTED_APPROVER_VOTE')
        try:
            rec._signature(keys[pin],message,vote['signature_ed25519'],
                           'EC276_OFFLINE_APPROVER_SIGNATURE_INVALID')
        except (rec.RecoveryError,ValueError,TypeError) as exc:
            raise ApprovalError('EC276_OFFLINE_APPROVER_SIGNATURE_INVALID') from exc
    if len(esc.canonical(doc))>MAX_APPROVAL:
        deny('EC276_APPROVAL_TOO_LARGE')
    return intent


def assemble_approval(*,intent_path:str,intent_sha256:str,
                      vote_paths:list[tuple[str,str]],duo:DualEscrow,
                      keys:dict[str,bytes],output:str) -> dict:
    intent=_read_intent(intent_path,intent_sha256)
    if type(vote_paths) is not list or len(vote_paths)!=2:
        deny('EC276_TWO_PINNED_VOTE_FILES_REQUIRED')
    votes=[]
    for path,pin in vote_paths:
        votes.append(_document(path,pin,MAX_VOTE,'EC276_VOTE_NOT_CANONICAL'))
    votes.sort(key=lambda item:item.get('public_sha256','') if type(item) is dict else '')
    approved={'schema':APPROVAL_SCHEMA,'intent':intent,'approvals':votes}
    verify_approval(approved,duo,keys)
    raw=esc.canonical(approved)
    prov._new(output,raw)
    return {'status':'partial','exit_code':2,
        'reason_code':'EC276_TWO_OFFLINE_APPROVERS_VERIFIED',
        'approval_sha256':esc.sha(raw),
        'record_sha256':intent['record_sha256'],
        'record_index':intent['record_index'],
        'physical_separation_of_approvers_verified':False}


def verified_file(path:str,pin:str,duo:DualEscrow,
                  keys:dict[str,bytes], *,now:int|None=None) -> dict:
    return verify_approval(read_approval(path,pin),duo,keys,now=now)

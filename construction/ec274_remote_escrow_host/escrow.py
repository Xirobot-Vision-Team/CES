#!/usr/bin/env python3
"""EC274 independently operated, TLS+Ed25519 remote monotonic escrow.

The dedicated daemon persists a strict witness-quorum CAS journal and signs
fresh nonce-bound reads. The protected host never holds escrow or witness
private keys and never trusts an unsigned local 'last seen' file. True
hardware/WORM rollback resistance of the *remote* machine is an external
operator requirement, not something a local file can prove.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from typing import Any

from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec269_emergency_recovery_host import recovery as rec
from ec271_freshness_quorum_host import freshness as fresh
from ec272_freshness_rollover_host import rollover as roll
from ec273_rfc3161_timestamp_host import timeproof as tsa

PROPOSAL_SCHEMA = 'ces.ec274.remote_escrow_proposal.v1'
RECORD_SCHEMA = 'ces.ec274.remote_escrow_record.v1'
REPLY_SCHEMA = 'ces.ec274.remote_escrow_nonce_reply.v1'
PROPOSAL_DOMAIN = b'CES/EC274/remote-escrow-proposal/v1\x00'
REPLY_DOMAIN = b'CES/EC274/remote-escrow-nonce-reply/v1\x00'
ZERO = '0' * 64
NAMESPACE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{3,63}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')
MAX_PROPOSAL = 3000
MAX_RECORD = 4200
MAX_RPC = 8192
MAX_REPLY = 10000
MAX_LEDGER = 32 * 1024 * 1024
MAX_RECORDS = 32768
FIELDS = frozenset({
    'schema','namespace','nonce','record_index','previous_record_sha256',
    'checkpoint_number','checkpoint_sha256','segment_sha256',
    'freshness_sequence','latest_receipt_sha256','previous_receipt_sha256',
    'governance_epoch','governance_sha256','recovered_root_public_sha256',
    'closure_sha256','tsa_request_sha256','tsa_response_sha256',
    'tsa_statement_sha256','tsa_gen_time_microseconds','witness_public_sha256',
})
VOTE_FIELDS = frozenset({'public_sha256','signature_ed25519'})
RECORD_FIELDS = frozenset({'schema','proposal','approvals'})
REPLY_FIELDS = frozenset({'schema','namespace','nonce','head_sha256',
                          'record','record_index','escrow_public_sha256',
                          'signature_ed25519'})


class EscrowError(tsa.TimestampError):
    """Denial code only, no secret or untrusted service text."""


def deny(code: str) -> None:
    raise EscrowError(code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: dict) -> bytes:
    return prov._canonical(obj)


def validate_namespace(value: Any) -> str:
    if type(value) is not str or NAMESPACE.fullmatch(value) is None:
        deny('EC274_NAMESPACE_INVALID')
    return value


def integer(value: Any, low: int, high: int, code: str) -> int:
    if type(value) is not int or not low <= value <= high:
        deny(code)
    return value


def _parse(raw: bytes, limit: int, error: str) -> dict:
    if not raw or len(raw) > limit or not raw.endswith(b'\n'):
        deny(error)
    try:
        doc = json.loads(raw)
        if type(doc) is not dict or canonical(doc) != raw:
            deny(error)
        return doc
    except (UnicodeError, ValueError, TypeError, OverflowError) as exc:
        raise EscrowError(error) from exc


def _sha(value: Any) -> str:
    try:
        return rec._sha(value)
    except (ValueError, TypeError, rec.RecoveryError) as exc:
        raise EscrowError('EC274_SHA256_FIELD_INVALID') from exc


def _proposal(obj: Any, *, namespace: str, witnesses: list[str],
              root: str, closure: str) -> dict:
    if type(obj) is not dict or set(obj) != FIELDS or obj.get('schema') != PROPOSAL_SCHEMA:
        deny('EC274_PROPOSAL_SCHEMA_INVALID')
    if obj['namespace'] != namespace or obj['witness_public_sha256'] != witnesses or \
            obj['recovered_root_public_sha256'] != root or obj['closure_sha256'] != closure:
        deny('EC274_UNTRUSTED_NAMESPACE_OR_AUTHORITY')
    if type(obj['nonce']) is not str or NONCE.fullmatch(obj['nonce']) is None:
        deny('EC274_PROPOSAL_NONCE_INVALID')
    for field in ('previous_record_sha256','checkpoint_sha256','segment_sha256',
                  'latest_receipt_sha256','previous_receipt_sha256',
                  'governance_sha256','recovered_root_public_sha256','closure_sha256',
                  'tsa_request_sha256','tsa_response_sha256','tsa_statement_sha256'):
        _sha(obj[field])
    integer(obj['record_index'],1,MAX_RECORDS,'EC274_RECORD_INDEX_INVALID')
    integer(obj['checkpoint_number'],1,roll.MAX_CHECKPOINTS,'EC274_CHECKPOINT_NUMBER_INVALID')
    integer(obj['freshness_sequence'],1,2**31-1,'EC274_SEQUENCE_INVALID')
    integer(obj['governance_epoch'],1,2**31-1,'EC274_EPOCH_INVALID')
    integer(obj['tsa_gen_time_microseconds'],1,2**60,'EC274_TIMESTAMP_INVALID')
    if len(canonical(obj)) > MAX_PROPOSAL:
        deny('EC274_PROPOSAL_OVERSIZE')
    return obj


def _verify_vote(proposal: dict, vote: Any, keys: dict[str,bytes]) -> None:
    if type(vote) is not dict or set(vote) != VOTE_FIELDS:
        deny('EC274_WITNESS_VOTE_FIELDS_INVALID')
    signer = _sha(vote['public_sha256'])
    if signer not in keys:
        deny('EC274_UNRECOGNIZED_WITNESS')
    try:
        rec._signature(keys[signer],PROPOSAL_DOMAIN+canonical(proposal),
                       vote['signature_ed25519'],'EC274_WITNESS_SIGNATURE_INVALID')
    except (rec.RecoveryError, ValueError, TypeError) as exc:
        raise EscrowError('EC274_WITNESS_SIGNATURE_INVALID') from exc


def _check_transition(proposal: dict, previous: dict|None, *,
                      minimum_bootstrap_sequence: int = 1,
                      minimum_bootstrap_epoch: int = 1) -> None:
    """Validate monotonic ledger policy before witnessing and at remote CAS."""
    if previous is None:
        if (proposal['record_index'] != 1 or proposal['previous_record_sha256'] != ZERO or
                proposal['freshness_sequence'] < minimum_bootstrap_sequence or
                proposal['governance_epoch'] < minimum_bootstrap_epoch):
            deny('EC274_GENESIS_MISSING_OR_BELOW_INDEPENDENT_FLOOR')
    else:
        old=previous['proposal']
        if (proposal['record_index'] != old['record_index']+1 or
                proposal['previous_record_sha256'] != sha(canonical(previous))):
            deny('EC274_PREDECESSOR_CAS_FAILED')
        if proposal['freshness_sequence'] != old['freshness_sequence']+1:
            deny('EC274_SEQUENCE_MUST_ADVANCE_BY_EXACTLY_ONE')
        if proposal['previous_receipt_sha256'] != old['latest_receipt_sha256']:
            deny('EC274_SIGNED_RECEIPT_ANCESTRY_DISCONTINUITY')
        if not old['checkpoint_number'] <= proposal['checkpoint_number'] <= old['checkpoint_number']+1:
            deny('EC274_CHECKPOINT_NONMONOTONIC_OR_SKIPPED')
        if (proposal['checkpoint_number'] == old['checkpoint_number']) == \
                (proposal['checkpoint_sha256'] != old['checkpoint_sha256']):
            deny('EC274_CHECKPOINT_IDENTITY_NOT_CONTINUOUS')
        if proposal['governance_epoch'] < old['governance_epoch'] or (
                proposal['governance_epoch']==old['governance_epoch'] and
                proposal['governance_sha256'] != old['governance_sha256']):
            deny('EC274_GOVERNANCE_EPOCH_ROLLBACK_OR_FORK')
        if proposal['tsa_gen_time_microseconds'] < old['tsa_gen_time_microseconds']:
            deny('EC274_SIGNED_TIMESTAMP_MOVED_BACKWARD')
        if (proposal['tsa_request_sha256']==old['tsa_request_sha256'] or
                proposal['tsa_response_sha256']==old['tsa_response_sha256'] or
                proposal['tsa_statement_sha256']==old['tsa_statement_sha256']):
            deny('EC274_TIMESTAMP_OR_STATEMENT_REUSED')
        if (proposal['latest_receipt_sha256']==old['latest_receipt_sha256'] or
                proposal['segment_sha256']==old['segment_sha256']):
            deny('EC274_LIVE_TAIL_NOT_ADVANCED')


def _record(obj: Any, *, namespace: str, keys: dict[str,bytes],
            root: str, closure: str, previous: dict|None,
            minimum_bootstrap_sequence: int = 1,
            minimum_bootstrap_epoch: int = 1) -> str:
    if type(obj) is not dict or set(obj) != RECORD_FIELDS or obj.get('schema') != RECORD_SCHEMA:
        deny('EC274_RECORD_SCHEMA_INVALID')
    proposal = _proposal(obj['proposal'],namespace=namespace,witnesses=sorted(keys),
                         root=root,closure=closure)
    votes=obj['approvals']
    if type(votes) is not list or len(votes)!=2:
        deny('EC274_EXACTLY_TWO_INDEPENDENT_VOTES_REQUIRED')
    voters=[x.get('public_sha256') if type(x) is dict else None for x in votes]
    if voters != sorted(set(voters)):
        deny('EC274_DUPLICATE_OR_UNORDERED_VOTES')
    for vote in votes:
        _verify_vote(proposal,vote,keys)
    _check_transition(proposal,previous,
        minimum_bootstrap_sequence=minimum_bootstrap_sequence,
        minimum_bootstrap_epoch=minimum_bootstrap_epoch)
    raw=canonical(obj)
    if len(raw)>MAX_RECORD:
        deny('EC274_RECORD_OVERSIZE')
    return sha(raw)


def witness_keys(pairs: list[tuple[str,str]]|tuple[tuple[str,str],...],
                 escrow_public_sha256: str|None=None) -> dict[str, bytes]:
    try:
        keys=fresh._witness_keys(pairs,())
        if escrow_public_sha256 is not None and rec._sha(escrow_public_sha256) in keys:
            deny('EC274_ESCROW_SIGNER_CANNOT_BE_WITNESS')
        return keys
    except (fresh.FreshnessError, rec.RecoveryError, prov.ProvenanceError) as exc:
        raise EscrowError('EC274_WITNESS_TRUST_UNAVAILABLE') from exc


def sign_proposal(proposal_path: str, proposal_pin: str, witness_secret: str,
                  witness_public_sha256: str, output: str) -> dict:
    """Offline-only witness utility. A witness must independently review inputs."""
    cp._need_crypto()
    raw=prov._bytes(proposal_path,MAX_PROPOSAL)
    if sha(raw)!=_sha(proposal_pin):
        deny('EC274_OFFLINE_PROPOSAL_PIN_MISMATCH')
    proposal=_parse(raw,MAX_PROPOSAL,'EC274_OFFLINE_PROPOSAL_NOT_CANONICAL')
    pins=proposal.get('witness_public_sha256')
    signer=_sha(witness_public_sha256)
    if type(pins) is not list or len(pins)!=3 or pins!=sorted(set(pins)) or signer not in pins:
        deny('EC274_WITNESS_ROSTER_MISMATCH')
    secret=prov._bytes(witness_secret,32)
    if len(secret)!=32 or sha(cp.public_bytes_from_signing_key(secret))!=signer:
        deny('EC274_OFFLINE_PRIVATE_WITNESS_MISMATCH')
    vote={'public_sha256':signer,
          'signature_ed25519':cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
              PROPOSAL_DOMAIN+raw).hex()}
    prov._new(output,canonical(vote))
    return {'status':'partial','exit_code':2,'vote_sha256':sha(canonical(vote)),
            'witness_public_sha256':signer,'independent_review_by_operator_required':True}


def assemble(proposal_path: str,proposal_pin: str,
             vote_paths: list[tuple[str,str]],
             keys: dict[str,bytes], namespace: str, root: str, closure: str,
             output: str) -> dict:
    raw=prov._bytes(proposal_path,MAX_PROPOSAL)
    if sha(raw)!=_sha(proposal_pin):
        deny('EC274_PROPOSAL_PIN_MISMATCH')
    core=_parse(raw,MAX_PROPOSAL,'EC274_PROPOSAL_INVALID')
    _proposal(core,namespace=namespace,witnesses=sorted(keys),root=root,closure=closure)
    if len(vote_paths)!=2:
        deny('EC274_TWO_PINNED_OFFLINE_VOTES_REQUIRED')
    votes=[]
    for path,pin in vote_paths:
        rawvote=prov._bytes(path,1024)
        if sha(rawvote)!=_sha(pin):
            deny('EC274_VOTE_PIN_MISMATCH')
        votes.append(_parse(rawvote,1024,'EC274_VOTE_NONCANONICAL'))
    votes.sort(key=lambda v: v.get('public_sha256','') if type(v) is dict else '')
    record={'schema':RECORD_SCHEMA,'proposal':core,'approvals':votes}
    # Verify signatures and schema independently without advancing any state.
    for vote in votes:
        _verify_vote(core,vote,keys)
    if votes[0]['public_sha256']==votes[1]['public_sha256']:
        deny('EC274_DUPLICATE_WITNESS_VOTES')
    raw=canonical(record)
    if len(raw)>MAX_RECORD:
        deny('EC274_RECORD_OVERSIZE')
    prov._new(output,raw)
    return {'status':'partial','exit_code':2,'record_sha256':sha(raw),
            'requires_atomic_remote_acceptance':True}


def progress(*, namespace: str, checkpoint_sha256: str,
             segment_sha256: str, latest_receipt_sha256: str,
             newest: dict, report: dict, timestamp: dict, checkpoint_number: int,
             witness_pins: list[str]) -> dict:
    """Derive expected escrow subject from *already verified* EC272+273 gate."""
    fresh._fields(newest)
    if (report['freshness_sequence'] != newest['sequence'] or
            report['sealed_checkpoint_number'] != checkpoint_number or
            timestamp['timestamp_bound_to_latest_receipt_sha256'] != latest_receipt_sha256 or
            timestamp['timestamp_request_sha256'] is None):
        deny('EC274_PARENT_EVIDENCE_DISAGREES')
    if sorted(witness_pins) != newest['witness_public_sha256']:
        deny('EC274_WITNESS_ROSTER_NOT_CURRENT')
    return {'namespace':validate_namespace(namespace),
        'checkpoint_number':checkpoint_number,
        'checkpoint_sha256':_sha(checkpoint_sha256),
        'segment_sha256':_sha(segment_sha256),
        'freshness_sequence':newest['sequence'],
        'latest_receipt_sha256':_sha(latest_receipt_sha256),
        'previous_receipt_sha256':_sha(newest['previous_receipt_sha256']),
        'governance_epoch':newest['governance_epoch'],
        'governance_sha256':_sha(newest['governance_sha256']),
        'recovered_root_public_sha256':_sha(newest['recovered_root_public_sha256']),
        'closure_sha256':_sha(newest['closure_sha256']),
        'tsa_request_sha256':_sha(timestamp['timestamp_request_sha256']),
        'tsa_response_sha256':_sha(timestamp['timestamp_response_sha256']),
        'tsa_statement_sha256':_sha(timestamp['timestamp_message_sha256']),
        'tsa_gen_time_microseconds':round(timestamp['timestamp_gen_time_unix']*1_000_000),
        'witness_public_sha256':list(newest['witness_public_sha256'])}


def prepare_proposal(subject: dict, previous: dict|None,
                     *, output: str) -> dict:
    nonce=secrets.token_hex(16)
    previous_pin=ZERO if previous is None else sha(canonical(previous))
    count=1 if previous is None else previous['proposal']['record_index']+1
    proposal={'schema':PROPOSAL_SCHEMA,'nonce':nonce,'record_index':count,
              'previous_record_sha256':previous_pin,**subject}
    _proposal(proposal,namespace=subject['namespace'],
        witnesses=sorted(subject['witness_public_sha256']),
        root=subject['recovered_root_public_sha256'],
        closure=subject['closure_sha256'])
    raw=canonical(proposal)
    prov._new(output,raw)
    return {'status':'partial','exit_code':2,'proposal_sha256':sha(raw),
        'record_index':count,'remote_previous_record_sha256':previous_pin,
        'requires_two_independent_witness_approvals':True}


def _sign_reply(secret: bytes, *, namespace: str, nonce: str,
               record: dict|None, escrow_pub: str) -> dict:
    body={'schema':REPLY_SCHEMA,'namespace':namespace,'nonce':nonce,
          'head_sha256':ZERO if record is None else sha(canonical(record)),
          'record':record,'record_index':0 if record is None else record['proposal']['record_index'],
          'escrow_public_sha256':escrow_pub}
    signature=cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
        REPLY_DOMAIN+canonical(body)).hex()
    return {**body,'signature_ed25519':signature}


def _verify_reply(doc: Any, *, namespace: str, nonce: str,
                  escrow_key: bytes, escrow_pin: str,
                  witness_keys_map: dict[str,bytes],root: str,closure: str,
                  minimum_index: int = 0) -> tuple[dict|None,str]:
    if type(doc) is not dict or set(doc)!=REPLY_FIELDS or doc.get('schema')!=REPLY_SCHEMA:
        deny('EC274_SIGNED_REPLY_SCHEMA_INVALID')
    if doc['namespace'] != namespace or doc['nonce'] != nonce or \
            doc['escrow_public_sha256'] != escrow_pin:
        deny('EC274_REMOTE_REPLY_NONCE_OR_IDENTITY_MISMATCH')
    unsigned={k:v for k,v in doc.items() if k!='signature_ed25519'}
    try:
        rec._signature(escrow_key,REPLY_DOMAIN+canonical(unsigned),
                       doc['signature_ed25519'],'EC274_REMOTE_REPLY_SIGNATURE_INVALID')
    except (rec.RecoveryError,ValueError,TypeError) as exc:
        raise EscrowError('EC274_REMOTE_REPLY_SIGNATURE_INVALID') from exc
    head=_sha(doc['head_sha256'])
    record=doc['record']
    if record is None:
        if head!=ZERO or doc['record_index']!=0 or minimum_index>0:
            deny('EC274_REMOTE_ESCROW_NOT_BOOTSTRAPPED')
    else:
        # The client checks the current quorum and record digest. The off-host
        # service alone has custody of the complete append-only history and
        # strictly replays it before replying to every request.
        core=record.get('proposal')
        if type(core) is not dict:
            deny('EC274_REMOTE_RECORD_INVALID')
        _proposal(core,namespace=namespace,witnesses=sorted(witness_keys_map),
                  root=root,closure=closure)
        votes=record.get('approvals')
        if (set(record)!=RECORD_FIELDS or record.get('schema')!=RECORD_SCHEMA or
                type(votes) is not list or len(votes)!=2 or
                any(type(v) is not dict or set(v)!=VOTE_FIELDS for v in votes)):
            deny('EC274_REMOTE_RECORD_VOTES_INVALID')
        pins=[v['public_sha256'] for v in votes]
        if any(type(p) is not str for p in pins) or pins!=sorted(set(pins)):
            deny('EC274_REMOTE_RECORD_VOTES_INVALID')
        for vote in votes:
            _verify_vote(core,vote,witness_keys_map)
        if (head != sha(canonical(record)) or
                type(doc['record_index']) is not int or
                doc['record_index']!=core['record_index'] or
                doc['record_index']<minimum_index):
            deny('EC274_REMOTE_RECORD_HEAD_OR_FLOOR_MISMATCH')
    return record,head


class RemoteClient:
    """Pinned CA + exact TLS leaf DER + signed fresh reply; no HTTP fallback."""

    def __init__(self, *, host: str, port: int, ca_path: str, ca_pin: str,
                 leaf_pin: str, escrow_public_path: str, escrow_public_pin: str,
                 namespace: str, witness_keys_map: dict[str,bytes],
                 root: str, closure: str):
        if (type(host) is not str or not host or len(host)>253 or '/' in host or
                '\x00' in host or '@' in host or ':' in host):
            deny('EC274_ESCROW_TLS_HOSTNAME_INVALID')
        self.host=host
        self.port=integer(port,1,65535,'EC274_ESCROW_PORT_INVALID')
        self.ca_path=prov._path(ca_path)
        self.ca_pin=_sha(ca_pin)
        self.leaf_pin=_sha(leaf_pin)
        self.escrow_public_path=prov._path(escrow_public_path)
        self.escrow_pin=_sha(escrow_public_pin)
        self.namespace=validate_namespace(namespace)
        self.keys=dict(witness_keys_map)
        self.root=_sha(root)
        self.closure=_sha(closure)
        self._last_read:dict|None=None

    def authority_paths(self)->list[str]:
        return [self.ca_path,self.escrow_public_path]

    def _request(self, route: str, body: dict, nonce: str) -> tuple[dict|None,str]:
        root=prov._bytes(self.ca_path,65536)
        if sha(root)!=self.ca_pin:
            deny('EC274_TLS_ROOT_PIN_CHANGED')
        try:
            public=rec._public(self.escrow_public_path,self.escrow_pin)
        except (rec.RecoveryError,prov.ProvenanceError) as exc:
            raise EscrowError('EC274_REMOTE_SIGNING_PUBLIC_PIN_MISMATCH') from exc
        try:
            ctx=ssl.create_default_context(cadata=root.decode('ascii'))
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.check_hostname=True
            ctx.verify_mode=ssl.CERT_REQUIRED
            conn=http.client.HTTPSConnection(self.host,self.port,context=ctx,timeout=4)
            try:
                conn.connect()
                cert=conn.sock.getpeercert(binary_form=True)
                if sha(cert)!=self.leaf_pin:
                    deny('EC274_EXACT_TLS_LEAF_CERT_PIN_MISMATCH')
                data=canonical(body)
                if len(data)>MAX_RPC:
                    deny('EC274_REMOTE_REQUEST_OVERSIZE')
                conn.request('POST',route,body=data,
                    headers={'Content-Type':'application/json','Content-Length':str(len(data))})
                response=conn.getresponse()
                if response.status!=200:
                    deny('EC274_REMOTE_ESCROW_DENIED')
                if response.getheader('Content-Length') and int(response.getheader('Content-Length'))>MAX_REPLY:
                    deny('EC274_REMOTE_REPLY_OVERSIZE')
                raw=response.read(MAX_REPLY+1)
                if len(raw)>MAX_REPLY:
                    deny('EC274_REMOTE_REPLY_OVERSIZE')
                doc=_parse(raw,MAX_REPLY,'EC274_REMOTE_REPLY_NOT_CANONICAL')
            finally:
                conn.close()
        except EscrowError:
            raise
        except (OSError,ValueError,UnicodeError,ssl.SSLError,http.client.HTTPException) as exc:
            raise EscrowError('EC274_REMOTE_ESCROW_TLS_OR_NETWORK_UNAVAILABLE') from exc
        return _verify_reply(doc,namespace=self.namespace,nonce=nonce,
            escrow_key=public,escrow_pin=self.escrow_pin,
            witness_keys_map=self.keys,root=self.root,closure=self.closure)

    def read(self, minimum_index: int = 0) -> tuple[dict|None,str]:
        nonce=secrets.token_hex(16)
        record,head=self._request('/v1/read',{'namespace':self.namespace,
                                            'nonce':nonce},nonce)
        if record is None and minimum_index>0 or record is not None and \
                record['proposal']['record_index']<minimum_index:
            deny('EC274_INDEPENDENT_ESCROW_INDEX_FLOOR_NOT_MET')
        return record,head

    def advance(self, record: dict) -> tuple[dict|None,str]:
        nonce=secrets.token_hex(16)
        return self._request('/v1/advance',{'namespace':self.namespace,
                                           'nonce':nonce,'record':record},nonce)

    def verify_current(self, expected: dict, *, expected_head: str,
                       minimum_index: int) -> dict:
        record,head=self.read(minimum_index)
        if head != _sha(expected_head) or record is None:
            deny('EC274_REMOTE_HEAD_DIFFERS_FROM_OPERATOR_PIN')
        subject={k:v for k,v in record['proposal'].items()
                 if k not in ('schema','nonce','record_index','previous_record_sha256')}
        if subject != expected:
            deny('EC274_REMOTE_CURRENT_TAIL_OR_EPOCH_DIFFERS')
        return {'status':'partial','exit_code':2,
                'reason_code':'EC274_PINNED_LIVE_REMOTE_ESCROW_VERIFIED',
                'escrow_record_sha256':head,
                'escrow_record_index':record['proposal']['record_index'],
                'escrow_freshness_sequence':expected['freshness_sequence'],
                'escrow_governance_epoch':expected['governance_epoch'],
                'escrow_checkpoint_number':expected['checkpoint_number'],
                'escrow_nonce_bound_signed_remote_reply_verified':True,
                'off_host_live_escrow_verified_under_operator_trust':True,
                'physical_remote_worm_or_hardware_monotonic_verified':False}


class EscrowLedger:
    """One independently hosted private fd, locked for the whole process.

    A torn append or inaccessible journal denies service until separately
    reviewed recovery. No silent truncation, overwrite, compaction or reset.
    """

    def __init__(self, path: str, *, namespace: str,keys: dict[str,bytes],
                 root: str, closure: str, escrow_secret_path: str,
                 escrow_pin: str, minimum_bootstrap_sequence: int = 1,
                 minimum_bootstrap_epoch: int = 1):
        self.namespace=validate_namespace(namespace)
        self.keys=dict(keys)
        self.root=_sha(root)
        self.closure=_sha(closure)
        self.escrow_pin=_sha(escrow_pin)
        if self.escrow_pin in self.keys:
            deny('EC274_ESCROW_SIGNER_MUST_BE_DISTINCT')
        self.minimum_bootstrap_sequence=integer(minimum_bootstrap_sequence,1,2**31-1,
            'EC274_BOOTSTRAP_SEQUENCE_FLOOR_INVALID')
        self.minimum_bootstrap_epoch=integer(minimum_bootstrap_epoch,1,2**31-1,
            'EC274_BOOTSTRAP_EPOCH_FLOOR_INVALID')
        secret=prov._bytes(escrow_secret_path,32)
        if len(secret)!=32 or sha(cp.public_bytes_from_signing_key(secret))!=self.escrow_pin:
            deny('EC274_REMOTE_SIGNING_KEY_PIN_MISMATCH')
        self.secret=secret
        self.path=prov._path(path)
        parent=str(Path(self.path).parent)
        from ec252_quality_run_host import broker as runner
        runner._private_dir(parent)
        self.fd=None
        self.current=None
        self.size=0
        self.count=0
        self._verified_prefix_sha256=sha(b'')
        self.broken=False
        flags=os.O_RDWR|os.O_APPEND|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_CREAT
        try:
            self.fd=os.open(self.path,flags,0o600)
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            s=os.fstat(self.fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or \
                    stat.S_IMODE(s.st_mode)!=0o600:
                deny('EC274_REMOTE_JOURNAL_PRIVATE_REGULAR_REQUIRED')
            self._reload()
            dirfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
        except BaseException:
            self.close()
            raise

    def _reload(self) -> None:
        statfd=os.fstat(self.fd)
        statpath=os.stat(self.path,follow_symlinks=False)
        if statfd.st_ino!=statpath.st_ino or statfd.st_dev!=statpath.st_dev or \
                statfd.st_size>MAX_LEDGER:
            deny('EC274_REMOTE_JOURNAL_REPLACED_OR_OVERSIZE')
        os.lseek(self.fd,0,os.SEEK_SET)
        raw=bytearray()
        while len(raw)<=MAX_LEDGER:
            data=os.read(self.fd,min(65536,MAX_LEDGER+1-len(raw)))
            if not data: break
            raw.extend(data)
        if len(raw)>MAX_LEDGER or len(raw)!=statfd.st_size:
            deny('EC274_REMOTE_JOURNAL_SIZE_CHANGED')
        # The full historical quorum journal was verified at startup. On a
        # long-running daemon, always hash the complete old prefix to detect
        # even same-size in-place rewrites, but validate Ed25519 only for newly
        # appended records. This keeps guarded remote reads affordable at the
        # bounded 32 MiB limit without weakening live prefix integrity.
        if len(raw)<self.size or (self.size and
                sha(bytes(raw[:self.size]))!=self._verified_prefix_sha256):
            deny('EC274_REMOTE_JOURNAL_ROLLED_BACK_OR_REWRITTEN')
        previous=self.current
        count=self.count
        suffix=bytes(raw[self.size:])
        if suffix:
            if suffix[-1]!=10:
                deny('EC274_REMOTE_JOURNAL_TORN_WRITE')
            for line in suffix.splitlines(keepends=True):
                count+=1
                if count>MAX_RECORDS: deny('EC274_REMOTE_JOURNAL_RECORD_LIMIT')
                record=_parse(line,MAX_RECORD,'EC274_REMOTE_JOURNAL_RECORD_NONCANONICAL')
                _record(record,namespace=self.namespace,keys=self.keys,
                    root=self.root,closure=self.closure,previous=previous,
                    minimum_bootstrap_sequence=self.minimum_bootstrap_sequence,
                    minimum_bootstrap_epoch=self.minimum_bootstrap_epoch)
                previous=record
        self.current=previous
        self.size=len(raw)
        self.count=count
        self._verified_prefix_sha256=sha(bytes(raw))

    def read(self, nonce: str) -> dict:
        if self.broken: deny('EC274_REMOTE_JOURNAL_LATCHED_FAILURE')
        self._reload()  # revalidate all history, not only cached head
        return _sign_reply(self.secret,namespace=self.namespace,nonce=nonce,
                           record=self.current,escrow_pub=self.escrow_pin)

    def advance(self, record: dict, nonce: str) -> dict:
        if self.broken: deny('EC274_REMOTE_JOURNAL_LATCHED_FAILURE')
        # Unauthenticated/incomplete quorum requests MUST NOT permanently
        # latch the service: no untrusted caller gets to trigger a DoS.
        self._reload()
        _record(record,namespace=self.namespace,keys=self.keys,
            root=self.root,closure=self.closure,previous=self.current,
            minimum_bootstrap_sequence=self.minimum_bootstrap_sequence,
            minimum_bootstrap_epoch=self.minimum_bootstrap_epoch)
        raw=canonical(record)
        if self.size+len(raw)>MAX_LEDGER:
            deny('EC274_REMOTE_JOURNAL_FULL')
        # Once the durable append begins, any write/fsync/readback uncertainty
        # is terminal until independent operator review of the whole journal.
        self.broken=True
        view=memoryview(raw)
        while view:
            written=os.write(self.fd,view)
            if written<=0: deny('EC274_JOURNAL_WRITE_FAILED')
            view=view[written:]
        os.fsync(self.fd)
        self._reload()
        if self.current!=record:
            deny('EC274_JOURNAL_READBACK_MISMATCH')
        self.broken=False
        return _sign_reply(self.secret,namespace=self.namespace,
            nonce=nonce,record=self.current,escrow_pub=self.escrow_pin)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd=None

    def __enter__(self): return self
    def __exit__(self,*_): self.close()

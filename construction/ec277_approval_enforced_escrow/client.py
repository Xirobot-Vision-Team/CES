#!/usr/bin/env python3
"""EC277 signed server-enforced approval receipts and resumable two-site CAS.

The old EC275 dual CAS algorithm is preserved as a separate entrypoint. This
client sends the COMPLETE EC276 two-person authorization to BOTH strictly
configured EC277 daemons, checks each separate escrow signer, then obtains
two independently signed nonce readbacks before claiming completion.
"""
from __future__ import annotations

import hmac
import http.client
import secrets
import ssl
import time
from typing import Any

from ec266_source_provenance_host import provenance as prov
from ec269_emergency_recovery_host import recovery as rec
from ec274_remote_escrow_host import escrow as esc
from ec275_dual_escrow_host.quorum import DualEscrow
from ec276_dual_approval_host import approval as auth
from ec277_approval_enforced_escrow import daemon as service
from ec277_approval_enforced_escrow.policy import TrustPolicy


class EnforcedEscrowError(auth.ApprovalError):
    """Never include incoming network bytes or private path in denial codes."""


def deny(code:str)->None:
    raise EnforcedEscrowError(code)


class ApprovedClient(esc.RemoteClient):
    def __init__(self, source:esc.RemoteClient, role:str):
        super().__init__(host=source.host,port=source.port,ca_path=source.ca_path,
            ca_pin=source.ca_pin,leaf_pin=source.leaf_pin,
            escrow_public_path=source.escrow_public_path,
            escrow_public_pin=source.escrow_pin,namespace=source.namespace,
            witness_keys_map=source.keys,root=source.root,closure=source.closure)
        if role not in ('primary','secondary'):
            deny('EC277_INVALID_CLIENT_SITE_ROLE')
        self.role=role

    def advance_approved(self, approval:dict, *, intent:dict)->tuple[dict,str,dict]:
        """Only this route can advance a correctly deployed EC277 server."""
        nonce=secrets.token_hex(16)
        doc={'namespace':self.namespace,'nonce':nonce,'approval':approval}
        request=esc.canonical(doc)
        if len(request)>service.MAX_RPC:
            deny('EC277_APPROVED_RPC_TOO_LARGE')
        ca=prov._bytes(self.ca_path,65536)
        if not hmac.compare_digest(esc.sha(ca),self.ca_pin):
            deny('EC277_TLS_CA_PIN_CHANGED')
        try:
            public=rec._public(self.escrow_public_path,self.escrow_pin)
            context=ssl.create_default_context(cadata=ca.decode('ascii'))
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            conn=http.client.HTTPSConnection(self.host,self.port,context=context,timeout=4)
            try:
                conn.connect()
                cert=conn.sock.getpeercert(binary_form=True)
                if not hmac.compare_digest(esc.sha(cert),self.leaf_pin):
                    deny('EC277_TLS_LEAF_PIN_CHANGED')
                conn.request('POST','/v1/advance-approved',body=request,
                    headers={'Content-Type':'application/json'})
                response=conn.getresponse()
                if response.status!=200:
                    deny('EC277_REMOTE_DID_NOT_AUTHORIZE_APPROVED_CAS')
                lengths=response.headers.get_all('Content-Length',[])
                if (len(lengths)!=1 or not lengths[0].isdecimal() or
                        int(lengths[0])>service.MAX_REPLY or
                        response.getheader('Content-Type')!='application/json'):
                    deny('EC277_REMOTE_COMMIT_REPLY_HEADERS_INVALID')
                raw=response.read(service.MAX_REPLY+1)
                if len(raw)>service.MAX_REPLY or len(raw)!=int(lengths[0]):
                    deny('EC277_REMOTE_COMMIT_REPLY_LENGTH_INVALID')
            finally:
                conn.close()
        except esc.EscrowError:
            raise
        except (OSError,ValueError,UnicodeError,ssl.SSLError,
                http.client.HTTPException) as exc:
            raise EnforcedEscrowError('EC277_REMOTE_TLS_OR_SIGNED_REPLY_UNAVAILABLE') from exc
        reply=esc._parse(raw,service.MAX_REPLY,'EC277_REMOTE_COMMIT_NOT_CANONICAL')
        if (set(reply)!=service.COMMIT_FIELDS or
                reply.get('schema')!=service.COMMIT_SCHEMA or
                reply.get('namespace')!=self.namespace or
                reply.get('nonce')!=nonce or reply.get('site_role')!=self.role or
                reply.get('approval_sha256')!=esc.sha(esc.canonical(approval)) or
                reply.get('record_sha256')!=intent['record_sha256'] or
                reply.get('record_index')!=intent['record_index']):
            deny('EC277_SIGNED_COMMIT_IDENTITY_OR_APPROVAL_MISMATCH')
        at=esc.integer(reply['admitted_at_unix'],1,auth.MAX_EPOCH,
            'EC277_SIGNED_ADMISSION_TIME_INVALID')
        if not intent['not_before_unix']<=at<=intent['expires_at_unix']:
            deny('EC277_COMMIT_ADMITTED_OUTSIDE_APPROVAL_WINDOW')
        core={key:value for key,value in reply.items() if key!='signature_ed25519'}
        try:
            rec._signature(public,service.COMMIT_DOMAIN+esc.canonical(core),
                reply['signature_ed25519'],'EC277_SIGNED_COMMIT_SIGNATURE_INVALID')
        except (ValueError,TypeError,rec.RecoveryError) as exc:
            raise EnforcedEscrowError('EC277_SIGNED_COMMIT_SIGNATURE_INVALID') from exc
        record,head=esc._verify_reply(reply['signed_head'],
            namespace=self.namespace,nonce=nonce,escrow_key=public,
            escrow_pin=self.escrow_pin,witness_keys_map=self.keys,
            root=self.root,closure=self.closure,
            minimum_index=intent['record_index'])
        if head!=intent['record_sha256'] or record!=intent['record']:
            deny('EC277_SIGNED_COMMIT_HEAD_NOT_APPROVED_RECORD')
        return record,head,reply


class ApprovedDualEscrow(DualEscrow):
    def __init__(self,policy:TrustPolicy):
        super().__init__(ApprovedClient(policy.dual.primary,'primary'),
                         ApprovedClient(policy.dual.secondary,'secondary'))
        self.policy=policy

    def authorized(self,approval:dict)->dict:
        # No signer secret is ever held online. Exact canonical EC276 approval
        # is rechecked before all writes and again before final signoff.
        return self.policy.verify(approval,now=int(time.time()))

    def inspect_approved(self, approval:dict)->dict[str,Any]:
        intent=self.authorized(approval)
        record,head=self.read_pair(minimum_index=intent['record_index'])
        if head!=intent['record_sha256'] or record!=intent['record']:
            deny('EC277_REMOTE_HEADS_NOT_AT_TWO_PERSON_APPROVED_RECORD')
        return {'status':'partial','exit_code':2,
            'reason_code':'EC277_BOTH_APPROVED_DURABLE_HEADS_SIGNED',
            'record_sha256':head,'record_index':intent['record_index'],
            'two_fresh_independent_read_signatures_verified':True,
            'ec277_daemon_policy_proven_from_read_alone':False}

    def inspect_advance_approved(self, approval:dict)->dict[str,Any]:
        intent=self.authorized(approval)
        result=self.inspect_advance(intent['record'],
            record_sha256=intent['record_sha256'],
            previous_sha256=intent['previous_record_sha256'])
        result['ec277_both_servers_must_enforce_signatures']=True
        result['ec277_approval_sha256']=esc.sha(esc.canonical(approval))
        return result

    def advance_approved(self,approval:dict)->dict[str,Any]:
        intent=self.authorized(approval)
        # Invariant: only two known states (predecessor / exact target)
        # before sending any write, retained from unchanged EC275 inspection.
        state=self.inspect_advance(intent['record'],
            record_sha256=intent['record_sha256'],
            previous_sha256=intent['previous_record_sha256'])
        receipts={'primary':None,'secondary':None}
        for role,client in (('primary',self.primary),('secondary',self.secondary)):
            if state[role]=='advanced':
                continue
            try:
                # Both remote daemons will also independently verify the full
                # approval using their OWN pinned public keys and live clock.
                new_intent=self.authorized(approval)
                if new_intent!=intent:
                    deny('EC277_APPROVED_INTENT_CHANGED')
                record,head,receipt=client.advance_approved(approval,intent=intent)
                if record!=intent['record'] or head!=intent['record_sha256']:
                    deny('EC277_WRITTEN_HEAD_NOT_APPROVED')
                receipts[role]=receipt
                stored,read_head=client.read(minimum_index=intent['record_index'])
                if stored!=record or read_head!=head:
                    deny('EC277_JOURNAL_READBACK_NOT_APPROVED')
            except (esc.EscrowError,OSError,ValueError,TypeError) as exc:
                raise EnforcedEscrowError(
                    'EC277_PARTIAL_OR_UNCERTAIN_COMMIT_INSPECT_AND_RESUME_SAME_RECORD') from exc
        current,head=self.read_pair(minimum_index=intent['record_index'])
        if head!=intent['record_sha256'] or current!=intent['record']:
            deny('EC277_FINAL_INDEPENDENT_DUAL_READBACK_FAILED')
        self.authorized(approval)
        fresh_count=sum(value is not None for value in receipts.values())
        # A live read proves the current signed head, NOT that an already-
        # committed record was admitted through this particular approval
        # endpoint. Report exactly which signed admissions we observed.
        return {'status':'partial','exit_code':2,
            'reason_code':('EC277_BOTH_APPROVED_HEADS_READBACK_NO_NEW_WRITE'
                if fresh_count==0 else
                'EC277_SERVER_APPROVED_CAS_AND_DUAL_SIGNED_READBACK_COMPLETE'),
            'record_sha256':head,'record_index':intent['record_index'],
            'approval_sha256':esc.sha(esc.canonical(approval)),
            'primary_was_previously_advanced':state['primary']=='advanced',
            'secondary_was_previously_advanced':state['secondary']=='advanced',
            'new_server_signed_commit_receipts':receipts,
            'new_server_signed_commit_receipt_count':fresh_count,
            'both_server_enforcements_attested_in_this_operation':fresh_count==2,
            'both_independent_signed_readbacks_verified':True,
            'distributed_atomic_commit_claimed':False,
            'physical_operator_site_independence_verified':False}

#!/usr/bin/env python3
"""EC275: two *different* EC274 authorities must attest the same pinned head.

There is deliberately no distributed atomic commit claim. Both servers enforce
independent EC274 witness-approved CAS histories. A signed record can be sent
to each in turn; uncertain or single-sided outcomes stay unavailable until an
operator rereads both and resumes the EXACT SAME, already approved record.
The protected service only reads and never advances either ledger.
"""
from __future__ import annotations

from typing import Any

from remote_escrow_host import escrow as esc


class DualEscrowError(esc.EscrowError):
    """Fail-closed reason code with no remote response or secret included."""


def deny(code: str) -> None:
    raise DualEscrowError(code)


class DualEscrow:
    """Independent signers, CA bundles and TLS leafs; same signed subject.

    Both upstream daemon processes must be separately operated, with distinct
    escrow signing keys, independent CAs, and separately durable journals.
    Distinct configured endpoint IDs cannot establish real physical separation.
    """

    def __init__(self, primary: esc.RemoteClient, secondary: esc.RemoteClient):
        if not isinstance(primary, esc.RemoteClient) or not isinstance(secondary, esc.RemoteClient):
            deny('EC275_BOTH_PINNED_REMOTE_CLIENTS_REQUIRED')
        if (primary.namespace != secondary.namespace or primary.keys != secondary.keys or
                primary.root != secondary.root or primary.closure != secondary.closure):
            deny('EC275_AUTHORITIES_DISAGREE_ON_SIGNED_SUBJECT_OR_WITNESSES')
        if primary.escrow_pin in primary.keys or secondary.escrow_pin in primary.keys:
            deny('EC275_AUTHORITY_SIGNING_KEYS_CANNOT_BE_WITNESS_KEYS')
        if (primary.escrow_pin == secondary.escrow_pin or
                primary.leaf_pin == secondary.leaf_pin or
                primary.ca_pin == secondary.ca_pin):
            deny('EC275_TWO_DISTINCT_SIGNERS_CA_AND_TLS_LEAF_PINS_REQUIRED')
        if (primary.host,primary.port)==(secondary.host,secondary.port):
            deny('EC275_TWO_DISTINCT_TLS_ENDPOINTS_REQUIRED')
        if set(primary.authority_paths()) & set(secondary.authority_paths()):
            deny('EC275_AUTHORITIES_MUST_USE_SEPARATE_PINNED_FILES')
        self.primary=primary
        self.secondary=secondary
        self.namespace=primary.namespace
        self.keys=primary.keys
        self.root=primary.root
        self.closure=primary.closure

    def authority_paths(self) -> list[str]:
        return [*self.primary.authority_paths(),*self.secondary.authority_paths()]

    def read_pair(self, *, minimum_index: int = 0) -> tuple[dict|None,str]:
        """Two separate nonce challenges; neither read is an unsigned cache."""
        esc.integer(minimum_index,0,esc.MAX_RECORDS,'EC275_READ_FLOOR_INVALID')
        first,first_head=self.primary.read(minimum_index=minimum_index)
        second,second_head=self.secondary.read(minimum_index=minimum_index)
        if first_head!=second_head or first!=second:
            deny('EC275_SIGNED_REMOTE_HEADS_DIVERGED')
        return first,first_head

    def verify_current(self, expected: dict, *, expected_head: str,
                       minimum_index: int) -> dict[str,Any]:
        pin=esc._sha(expected_head)
        esc.integer(minimum_index,1,esc.MAX_RECORDS,'EC275_OPERATOR_INDEX_FLOOR_INVALID')
        record,head=self.read_pair(minimum_index=minimum_index)
        if record is None or head!=pin:
            deny('EC275_DUAL_HEAD_NOT_EQUAL_TO_OPERATOR_PIN')
        subject={k:v for k,v in record['proposal'].items()
                 if k not in ('schema','nonce','record_index','previous_record_sha256')}
        if subject != expected:
            deny('EC275_DUAL_HEAD_NOT_CURRENT_VERIFIED_SIGNED_TAIL')
        return {
            'status':'partial','exit_code':2,
            'reason_code':'EC275_TWO_DISTINCT_SIGNED_HEADS_AND_TAIL_VERIFIED',
            'escrow_record_sha256':head,
            'escrow_record_index':record['proposal']['record_index'],
            'escrow_freshness_sequence':expected['freshness_sequence'],
            'escrow_governance_epoch':expected['governance_epoch'],
            'escrow_checkpoint_number':expected['checkpoint_number'],
            'ec275_both_nonce_bound_remote_signatures_verified':True,
            'ec275_both_remote_heads_equal_operator_pin':True,
            'ec275_physically_independent_storage_or_worm_verified':False,
        }

    def _classify(self, client:esc.RemoteClient, record:dict, previous_pin:str,
                  desired_pin:str) -> tuple[str,dict|None]:
        """Only two authorized states: *exact* previous head or *exact* new head."""
        current,head=client.read()
        if head==desired_pin:
            if current!=record:
                deny('EC275_DESIRED_HEAD_BYTES_NOT_IDENTICAL')
            return 'advanced',current
        if head!=previous_pin:
            deny('EC275_REMOTE_HEAD_NOT_AN_APPROVED_PREDECESSOR_OR_TARGET')
        prior_index=record['proposal']['record_index']-1
        if ((current is None and prior_index!=0) or
                (current is not None and current['proposal']['record_index']!=prior_index)):
            deny('EC275_PREDECESSOR_INDEX_WRONG')
        # Check signed two-witness votes and the *actual* ledger transition,
        # not just the new SHA, before attempting any network state change.
        esc._record(record,namespace=self.namespace,keys=self.keys,
            root=self.root,closure=self.closure,previous=current)
        return 'pending',current

    def inspect_advance(self, record:dict, *, record_sha256:str,
                        previous_sha256:str) -> dict[str,Any]:
        """Non-mutating rehearsal; can report partial prior completion."""
        desired=esc._sha(record_sha256)
        previous=esc._sha(previous_sha256)
        if esc.sha(esc.canonical(record))!=desired:
            deny('EC275_PINNED_APPROVED_RECORD_SHA_MISMATCH')
        if type(record) is not dict or set(record)!=esc.RECORD_FIELDS:
            deny('EC275_RECORD_SCHEMA_INVALID')
        core=record.get('proposal')
        if (type(core) is not dict or core.get('previous_record_sha256')!=previous or
                core.get('namespace')!=self.namespace):
            deny('EC275_OPERATOR_PREDECESSOR_OR_NAMESPACE_MISMATCH')
        # Before making either write, both remote authorities must be live,
        # authentic, and known to be at one of these TWO strictly pinned heads.
        first,_=self._classify(self.primary,record,previous,desired)
        second,_=self._classify(self.secondary,record,previous,desired)
        return {'status':'partial','exit_code':2,
            'reason_code':'EC275_DUAL_CAS_RECONCILED_NO_WRITE',
            'record_sha256':desired,'previous_sha256':previous,
            'record_index':core['record_index'],
            'primary':first,'secondary':second,
            'dual_commit_complete':first=='advanced' and second=='advanced',
            'may_resume_exact_signed_record':True}

    def advance(self, record:dict, *, record_sha256:str,
                previous_sha256:str) -> dict[str,Any]:
        """Resumable two-site CAS, never falsely represented as atomic.

        If any attempted advance/ack/readback is ambiguous, raise rather than
        returning success; the same pinned record may be retried after recovery.
        Different successors or signers demand a separately authorized ceremony.
        """
        state=self.inspect_advance(record,record_sha256=record_sha256,
                                  previous_sha256=previous_sha256)
        desired=state['record_sha256']
        for label,client in (('primary',self.primary),('secondary',self.secondary)):
            if state[label]=='advanced':
                continue
            try:
                confirmed,head=client.advance(record)
                if head!=desired or confirmed!=record:
                    deny('EC275_REMOTE_ADVANCE_ACK_NOT_THE_APPROVED_RECORD')
                stored,read_head=client.read(minimum_index=record['proposal']['record_index'])
                if read_head!=desired or stored!=record:
                    deny('EC275_REMOTE_DURABLE_READBACK_NOT_APPROVED_RECORD')
            except (esc.EscrowError,OSError,ValueError,TypeError) as exc:
                raise DualEscrowError('EC275_PARTIAL_OR_UNCERTAIN_ADVANCE_REREAD_AND_RESUME') from exc
        # Always perform TWO more independent signed nonce reads, including
        # previously-committed sites; no success from HTTP advance acks alone.
        final,head=self.read_pair(minimum_index=record['proposal']['record_index'])
        if head!=desired or final!=record:
            deny('EC275_FINAL_DUAL_READBACK_NOT_THE_APPROVED_RECORD')
        return {'status':'partial','exit_code':2,
            'reason_code':'EC275_DUAL_CAS_ADVANCE_AND_SIGNED_READBACK_COMPLETE',
            'record_sha256':desired,'record_index':record['proposal']['record_index'],
            'both_independently_signed_nonce_readbacks_verified':True,
            'distributed_atomic_commit_claimed':False,
            'physical_cross_site_worm_or_hsm_verified':False}

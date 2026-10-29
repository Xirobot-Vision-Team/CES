#!/usr/bin/env python3
"""EC275 opt-in strict host: inherited EC274 gate plus second live authority.

The protected host NEVER advances either EC274 ledger. All previous
recovery/governance/EC272/EC273 proofs, session lease and active recall remain
mandatory. Before each guarded operation both independent escrows must
answer fresh signed nonce reads for the *same operator-pinned* current tail.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from finding_host import broker as fio
from quality_run_host import broker as runner
from lease_host import broker as lease
from session_host import broker as session
from active_recall_host.serve import _recover_prior
from signed_audit_host.serve import _check_placement
from signed_audit_host.audit import _reason
from segmented_audit_host.segment import _read_config
from custody_receipt_host.custody import CustodyAudit
from source_provenance_host.serve import _open_preflight, _ensure_gate_outside_audits
from source_provenance_host.provenance import ProvenanceError
from governed_source_host.governance import GovernanceError
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as old_cli
from recovery_closure_host.closure import ClosureError
from freshness_quorum_host import serve as fresh_cli
from rfc3161_timestamp_host import timeproof as tsa
from remote_escrow_host import escrow as esc
from remote_escrow_host import serve as parent
from dual_escrow_host.quorum import DualEscrow, DualEscrowError, deny


class DualEscrowGate(parent.RemoteEscrowGate):
    """Second signed remote read is mandatory throughout the active session."""

    def __init__(self,*args:Any,secondary_escrow_host:str,
                 secondary_escrow_port:int,secondary_escrow_tls_ca:str,
                 secondary_escrow_tls_ca_sha256:str,
                 secondary_escrow_tls_leaf_sha256:str,
                 secondary_escrow_public:str,
                 secondary_escrow_public_sha256:str,
                 secondary_escrow_minimum_index:int,**kwargs:Any):
        # Base EC269's constructor calls virtual authority_paths(), so
        # secondary trust paths MUST exist before invoking the parent chain.
        self.secondary_floor=esc.integer(secondary_escrow_minimum_index,
            1,esc.MAX_RECORDS,'EC275_SECONDARY_MINIMUM_INDEX_INVALID')
        keys=esc.witness_keys(kwargs['freshness_witness_public_keys'],
                              kwargs['escrow_public_sha256'])
        self.secondary_client=esc.RemoteClient(host=secondary_escrow_host,
            port=secondary_escrow_port,namespace=kwargs['escrow_namespace'],
            ca_path=secondary_escrow_tls_ca,
            ca_pin=secondary_escrow_tls_ca_sha256,
            leaf_pin=secondary_escrow_tls_leaf_sha256,
            escrow_public_path=secondary_escrow_public,
            escrow_public_pin=secondary_escrow_public_sha256,
            witness_keys_map=keys,
            root=kwargs['governance_public_sha256'],
            closure=kwargs['closure_certificate_sha256'])
        # Parent records all EC274 pins and invokes the EC273->EC272 chain.
        super().__init__(*args,**kwargs)
        self.dual=DualEscrow(self.escrow_client,self.secondary_client)
        self._dual_verified:dict|None=None

    def authority_paths(self) -> list[str]:
        return [*super().authority_paths(),*self.secondary_client.authority_paths()]

    def _check_freshness(self) -> None:
        # Parent first verifies every historical and live check, including an
        # authenticated current primary remote read. Never substitute a local
        # snapshot, nor allow a secondary read to mask primary failure.
        super()._check_freshness()
        if self._freshness_verified is None or self._timestamp_verified is None or \
                self._escrow_verified is None:
            deny('EC275_COMPLETE_EC274_PARENT_PROOFS_REQUIRED')
        _,newest,latest=tsa._tail(segment=self.freshness_chain,
            segment_sha256=self.freshness_pin,checkpoint_sha256=self.checkpoint_pin)
        expected=esc.progress(namespace=self.dual.namespace,
            checkpoint_sha256=self.checkpoint_pin,segment_sha256=self.freshness_pin,
            latest_receipt_sha256=latest,newest=newest,
            report=self._freshness_verified,timestamp=self._timestamp_verified,
            checkpoint_number=self._freshness_verified['sealed_checkpoint_number'],
            witness_pins=sorted(self.dual.keys))
        # Parent already proved primary with a fresh nonce in THIS gate check.
        # A new, separately signed secondary nonce must independently agree
        # with the same immutable, operator-pinned EC274 head and full subject.
        verified=self.dual.secondary.verify_current(expected,
            expected_head=self.escrow_expected_head,
            minimum_index=self.secondary_floor)
        if (verified['escrow_record_sha256']!=self._escrow_verified['escrow_record_sha256'] or
                verified['escrow_record_index']!=self._escrow_verified['escrow_record_index']):
            deny('EC275_PRIMARY_SECONDARY_VERIFIED_HEADS_DISAGREE')
        report={'ec275_dual_escrow_opt_in':True,
            'ec275_two_distinct_remote_signers_and_ca_pins':True,
            'ec275_primary_secondary_signed_live_read_verified':True,
            'ec275_record_sha256':verified['escrow_record_sha256'],
            'ec275_record_index':verified['escrow_record_index'],
            'ec275_physical_independence_or_worm_verified':False}
        if self._dual_verified is not None and report!=self._dual_verified:
            deny('EC275_DUAL_REMOTE_STATE_CHANGED_DURING_SESSION')
        self._dual_verified=report

    def summary(self) -> dict[str,Any]:
        if self._dual_verified is None:
            deny('EC275_DUAL_REMOTE_NOT_YET_VERIFIED')
        result=super().summary()
        result.update(self._dual_verified)
        return result


def _gate(args:argparse.Namespace,audit:CustodyAudit)->DualEscrowGate:
    # Keep an explicit, reviewable wiring of the EC274 contract. The prior
    # optional EC274 host itself is untouched and remains independently usable.
    return DualEscrowGate(
        policy_path=args.policy,repo=args.repo,allowlist=args.allowlist,
        receipt=args.receipt,profile_id=args.profile_id,
        provenance_gate=args.provenance_gate,
        provenance_gate_sha256=args.provenance_gate_sha256,
        governance_policy=args.governance_policy,
        governance_policy_sha256=args.governance_policy_sha256,
        governance_public=args.governance_public,
        governance_public_sha256=args.governance_public_sha256,
        minimum_epoch=args.minimum_governance_epoch,
        expected_previous_governance_sha256=args.expected_previous_governance_sha256,
        old_governance=args.old_governance,
        old_governance_sha256=args.old_governance_sha256,
        old_root_public=args.old_root_public,
        old_root_public_sha256=args.old_root_public_sha256,
        charter=args.charter,charter_sha256=args.charter_sha256,
        council_public_keys=old_cli._council(args),
        recovery_certificate=args.recovery_certificate,
        recovery_certificate_sha256=args.recovery_certificate_sha256,
        anchor_governance=args.anchor_governance,
        anchor_governance_sha256=args.anchor_governance_sha256,
        continuation_chain=args.continuation_chain,
        continuation_chain_sha256=args.continuation_chain_sha256,
        closure_certificate=args.closure_certificate,
        closure_certificate_sha256=args.closure_certificate_sha256,
        witness_public=args.witness_public,
        witness_public_sha256=args.witness_public_sha256,
        minimum_witness_observed_at_unix=args.minimum_closure_observed_at_unix,
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
        freshness_chain=args.freshness_chain,
        freshness_chain_sha256=args.freshness_chain_sha256,
        freshness_witness_public_keys=fresh_cli._witnesses(args),
        minimum_freshness_sequence=args.minimum_freshness_sequence,
        expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
        checkpoint=args.checkpoint,checkpoint_sha256=args.checkpoint_sha256,
        minimum_checkpoint_number=args.minimum_checkpoint_number,
        tsa_request=args.tsa_request,tsa_request_sha256=args.tsa_request_sha256,
        tsa_response=args.tsa_response,tsa_response_sha256=args.tsa_response_sha256,
        tsa_ca_bundle=args.tsa_ca_bundle,tsa_ca_bundle_sha256=args.tsa_ca_bundle_sha256,
        tsa_leaf_cert_sha256=args.tsa_leaf_cert_sha256,
        tsa_policy_oid=args.tsa_policy_oid,
        tsa_openssl_binary=args.tsa_openssl_binary,
        tsa_openssl_binary_sha256=args.tsa_openssl_binary_sha256,
        tsa_max_age_seconds=args.tsa_max_age_seconds,
        tsa_minimum_time_unix=args.tsa_minimum_time_unix,
        tsa_intermediates=args.tsa_intermediates,
        tsa_intermediates_sha256=args.tsa_intermediates_sha256,
        escrow_host=args.escrow_host,escrow_port=args.escrow_port,
        escrow_namespace=args.escrow_namespace,
        escrow_tls_ca=args.escrow_tls_ca,
        escrow_tls_ca_sha256=args.escrow_tls_ca_sha256,
        escrow_tls_leaf_sha256=args.escrow_tls_leaf_sha256,
        escrow_public=args.escrow_public,
        escrow_public_sha256=args.escrow_public_sha256,
        escrow_record_sha256=args.escrow_record_sha256,
        escrow_minimum_index=args.escrow_minimum_index,
        secondary_escrow_host=args.secondary_escrow_host,
        secondary_escrow_port=args.secondary_escrow_port,
        secondary_escrow_tls_ca=args.secondary_escrow_tls_ca,
        secondary_escrow_tls_ca_sha256=args.secondary_escrow_tls_ca_sha256,
        secondary_escrow_tls_leaf_sha256=args.secondary_escrow_tls_leaf_sha256,
        secondary_escrow_public=args.secondary_escrow_public,
        secondary_escrow_public_sha256=args.secondary_escrow_public_sha256,
        secondary_escrow_minimum_index=args.secondary_escrow_minimum_index)


def _preflight(args:argparse.Namespace,audit:CustodyAudit) -> DualEscrowGate:
    gate=_gate(args,audit)
    _ensure_gate_outside_audits(args,audit,gate)
    cfg=gate._read_config()
    protected=[gate.gate_path,cfg['subject']]
    for authority in cfg['authorities']:
        protected.extend(authority[key] for key in ('public_key','assertion','evidence'))
    roots=[gate.repo,*[x['audit_root'] for x in audit.config['archives']],
           audit.config['active']['audit_root']]
    authorities=gate.authority_paths()
    if len(authorities)!=len(set(authorities)):
        deny('EC275_AUTHORITY_PIN_FILE_COLLISION')
    for path in authorities:
        if path in protected:
            deny('EC275_TRUST_FILE_COLLIDES_WITH_PROTECTED_SOURCE')
        for root in roots:
            if os.path.commonpath((path,root))==root:
                deny('EC275_TRUST_OR_PUBLIC_KEYS_INSIDE_UNTRUSTED_TREE')
    if gate.tsa_openssl_binary in authorities or gate.tsa_openssl_binary in protected:
        deny('EC275_OPENSSL_BINARY_PATH_COLLISION')
    return gate


def verify_gate(args:argparse.Namespace) -> dict:
    with _open_preflight(args,writable=False) as audit:
        gate=_preflight(args,audit)
        policy,pin=lease._policy(args.policy)
        gate.startup(policy,pin)
        report=gate.summary()
        report['custody_receipts_verified']=audit.summary()['custody_receipts_verified']
        return report


def run_serve(args:argparse.Namespace) -> None:
    cfg=_read_config(args.chain,args.chain_sha256)
    for item in cfg['archives']+[cfg['active']]:
        placement=argparse.Namespace(**vars(args))
        placement.audit_root=item['audit_root']
        placement.audit_key=item['audit_key']
        _check_placement(placement)
    _recover_prior(args.policy)
    with _open_preflight(args,writable=True) as audit:
        gate=_preflight(args,audit)
        policy,pin=lease._policy(args.policy)
        gate.startup(policy,pin)  # signed reads from BOTH before socket/lease
        audit.record('service_start')
        try:
            audit.record('service_recovery_complete')
            session.serve(args.policy,args.socket,
                max_sessions=args.max_sessions,accept_timeout=args.accept_timeout,
                require_cgroup=True,require_kernel_metrics=True,
                startup_guard=gate.recheck_startup,
                before_begin_guard=gate.before_begin,
                during_session_guard=gate.before_begin,
                audit_event=audit.record)
        except BaseException as exc:
            try:
                audit.record('service_failed',reason_code=_reason(
                    getattr(exc,'code','EC275_DUAL_REMOTE_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def build_parser() -> argparse.ArgumentParser:
    p=parent.build_parser()
    p.description='EC275 strict dual independent remote escrow protected EC273 host'
    sub=next(x for x in p._actions if isinstance(x,argparse._SubParsersAction))
    options=('secondary_escrow_host','secondary_escrow_port',
        'secondary_escrow_tls_ca','secondary_escrow_tls_ca_sha256',
        'secondary_escrow_tls_leaf_sha256','secondary_escrow_public',
        'secondary_escrow_public_sha256','secondary_escrow_minimum_index')
    for cmd in sub.choices.values():
        old_cli._required(cmd,options)
    return p


def main(argv:list[str]|None=None) -> int:
    args=build_parser().parse_args(argv)
    try:
        for name in ('minimum_governance_epoch','minimum_closure_observed_at_unix',
            'minimum_freshness_sequence','minimum_checkpoint_number',
            'tsa_max_age_seconds','tsa_minimum_time_unix','escrow_port',
            'escrow_minimum_index','secondary_escrow_port',
            'secondary_escrow_minimum_index'):
            setattr(args,name,int(getattr(args,name)))
        if args.action=='serve':
            run_serve(args)
            return 0
        print(json.dumps(verify_gate(args),sort_keys=True))
        return 2
    except (runner.HostRunError,fio.HostError,rec.RecoveryError,
            GovernanceError,ProvenanceError,ClosureError,OSError,
            ValueError,TypeError) as exc:
        print(json.dumps(session._reply('unavailable',_reason(
            getattr(exc,'code','EC275_DUAL_REMOTE_HOST_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

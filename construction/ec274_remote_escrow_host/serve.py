#!/usr/bin/env python3
"""EC274 strict opt-in EC273 host with remote quorum CAS escrow admission.

Every active guarded operation requires a fresh signed nonce response from an
independently reachable TLS authority, with exact operator-pinned head.
This host never advances remote escrow state and never holds private witness
or remote escrow signing keys. Prior EC273 services are unchanged.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec250_finding_host import broker as fio
from ec252_quality_run_host import broker as runner
from ec253_lease_host import broker as lease
from ec254_session_host import broker as session
from ec260_active_recall_host.serve import _recover_prior
from ec262_signed_audit_host.serve import _check_placement
from ec262_signed_audit_host.audit import _reason
from ec264_segmented_audit_host.segment import _read_config
from ec265_custody_receipt_host.custody import CustodyAudit
from ec266_source_provenance_host.serve import _open_preflight, _ensure_gate_outside_audits
from ec266_source_provenance_host import provenance as prov
from ec266_source_provenance_host.provenance import ProvenanceError
from ec267_governed_source_host import governance as gov
from ec267_governed_source_host.governance import GovernanceError
from ec269_emergency_recovery_host import recovery as rec
from ec269_emergency_recovery_host import serve as old_cli
from ec270_recovery_closure_host.closure import ClosureError
from ec271_freshness_quorum_host import serve as fresh_cli
from ec273_rfc3161_timestamp_host import serve as timestamp_host
from ec273_rfc3161_timestamp_host import timeproof as tsa
from ec274_remote_escrow_host import escrow as esc


class RemoteEscrowGate(timestamp_host.TrustedTimestampGate):
    """Add an off-host, signed fresh read after all EC273 inheritance checks."""

    def __init__(self,*args:Any,escrow_host:str,escrow_port:int,
                 escrow_namespace:str,escrow_tls_ca:str,escrow_tls_ca_sha256:str,
                 escrow_tls_leaf_sha256:str,escrow_public:str,
                 escrow_public_sha256:str,escrow_record_sha256:str,
                 escrow_minimum_index:int,**kwargs:Any):
        self.escrow_expected_head=esc._sha(escrow_record_sha256)
        self.escrow_floor=esc.integer(escrow_minimum_index,1,esc.MAX_RECORDS,
            'EC274_ESCROW_OPERATOR_MINIMUM_INDEX_INVALID')
        keys=esc.witness_keys(kwargs['freshness_witness_public_keys'],
                              escrow_public_sha256)
        self.escrow_client=esc.RemoteClient(
            host=escrow_host,port=escrow_port,namespace=escrow_namespace,
            ca_path=escrow_tls_ca,ca_pin=escrow_tls_ca_sha256,
            leaf_pin=escrow_tls_leaf_sha256,
            escrow_public_path=escrow_public,
            escrow_public_pin=escrow_public_sha256,
            witness_keys_map=keys,
            root=kwargs['governance_public_sha256'],
            closure=kwargs['closure_certificate_sha256'])
        self._escrow_verified:dict|None=None
        super().__init__(*args,**kwargs)

    def authority_paths(self)->list[str]:
        return [*super().authority_paths(),*self.escrow_client.authority_paths()]

    def _check_freshness(self)->None:
        # Parent performs full signed root, governance, custody, live chain,
        # TSA request/response and timestamp freshness verification first.
        super()._check_freshness()
        if self._freshness_verified is None or self._timestamp_verified is None:
            esc.deny('EC274_PARENT_EC272_EC273_VERIFICATION_REQUIRED')
        _, newest, latest=tsa._tail(segment=self.freshness_chain,
            segment_sha256=self.freshness_pin,checkpoint_sha256=self.checkpoint_pin)
        expected=esc.progress(namespace=self.escrow_client.namespace,
            checkpoint_sha256=self.checkpoint_pin,segment_sha256=self.freshness_pin,
            latest_receipt_sha256=latest,newest=newest,
            report=self._freshness_verified,timestamp=self._timestamp_verified,
            checkpoint_number=self._freshness_verified['sealed_checkpoint_number'],
            witness_pins=sorted(self.escrow_client.keys))
        report=self.escrow_client.verify_current(expected,
            expected_head=self.escrow_expected_head,minimum_index=self.escrow_floor)
        if self._escrow_verified is not None and report != self._escrow_verified:
            esc.deny('EC274_REMOTE_ESCROW_CHANGED_DURING_ACTIVE_SESSION')
        self._escrow_verified=report

    def summary(self)->dict[str,Any]:
        if self._escrow_verified is None:
            esc.deny('EC274_REMOTE_ESCROW_NOT_YET_VERIFIED')
        report=super().summary()
        report.update(self._escrow_verified)
        report['ec274_independent_remote_escrow_opt_in']=True
        report['remote_custody_hardware_nonrollbackable_verified']=False
        return report


def _gate(args:argparse.Namespace,audit:CustodyAudit)->RemoteEscrowGate:
    return RemoteEscrowGate(
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
        tsa_ca_bundle=args.tsa_ca_bundle,
        tsa_ca_bundle_sha256=args.tsa_ca_bundle_sha256,
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
        escrow_minimum_index=args.escrow_minimum_index)


def _preflight(args:argparse.Namespace,audit:CustodyAudit)->RemoteEscrowGate:
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
        esc.deny('EC274_AUTHORITY_FILE_COLLISION')
    for authority in authorities:
        if authority in protected:
            esc.deny('EC274_REMOTE_ESCROW_AUTHORITY_COLLIDES_WITH_SOURCE')
        for root in roots:
            if os.path.commonpath((authority,root))==root:
                esc.deny('EC274_ESCROW_KEYS_OR_TRUST_INSIDE_UNTRUSTED_TREE')
    if gate.tsa_openssl_binary in authorities or gate.tsa_openssl_binary in protected:
        esc.deny('EC274_OPENSSL_PATH_COLLISION')
    return gate


def verify_gate(args:argparse.Namespace)->dict:
    with _open_preflight(args,writable=False) as audit:
        gate=_preflight(args,audit)
        policy,pin=lease._policy(args.policy)
        gate.startup(policy,pin)
        report=gate.summary()
        report['custody_receipts_verified']=audit.summary()['custody_receipts_verified']
        return report


def run_serve(args:argparse.Namespace)->None:
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
        gate.startup(policy,pin)  # includes live remote check BEFORE socket or lease
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
                    getattr(exc,'code','EC274_REMOTE_ESCROW_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def build_parser()->argparse.ArgumentParser:
    parser=argparse.ArgumentParser(description='EC274 remote escrow protected EC273 host')
    sub=parser.add_subparsers(dest='action',required=True)
    original=('old_governance','old_governance_sha256','old_root_public',
        'old_root_public_sha256','charter','charter_sha256',
        'anchor_governance','anchor_governance_sha256',
        'governance_public','governance_public_sha256',
        'recovery_certificate','recovery_certificate_sha256',
        'witness_public','witness_public_sha256',
        'closure_certificate','closure_certificate_sha256',
        'governance_policy','governance_policy_sha256')
    host_extra=('provenance_gate','provenance_gate_sha256',
        'minimum_closure_observed_at_unix','chain','chain_sha256',
        'custody_gate','custody_gate_sha256','policy','repo','allowlist',
        'receipt','profile_id','minimum_governance_epoch',
        'expected_previous_governance_sha256')
    tail=('checkpoint','checkpoint_sha256','freshness_chain',
        'freshness_chain_sha256','minimum_freshness_sequence',
        'expected_previous_receipt_sha256','minimum_checkpoint_number')
    proof=('tsa_request','tsa_request_sha256','tsa_response','tsa_response_sha256',
        'tsa_ca_bundle','tsa_ca_bundle_sha256','tsa_leaf_cert_sha256',
        'tsa_openssl_binary','tsa_openssl_binary_sha256',
        'tsa_max_age_seconds','tsa_minimum_time_unix','tsa_policy_oid')
    remote=('escrow_host','escrow_port','escrow_namespace','escrow_tls_ca',
        'escrow_tls_ca_sha256','escrow_tls_leaf_sha256','escrow_public',
        'escrow_public_sha256','escrow_record_sha256','escrow_minimum_index')
    for action in ('verify-gate','serve'):
        cmd=sub.add_parser(action)
        old_cli._required(cmd,original+host_extra+tail+proof+remote)
        old_cli._council_args(cmd)
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        cmd.add_argument('--tsa-intermediates')
        cmd.add_argument('--tsa-intermediates-sha256')
        if action=='serve':
            cmd.add_argument('--socket',required=True)
            cmd.add_argument('--max-sessions',type=int,default=1)
            cmd.add_argument('--accept-timeout',type=float,default=60.)
    return parser


def main(argv:list[str]|None=None)->int:
    args=build_parser().parse_args(argv)
    try:
        for name in ('minimum_governance_epoch','minimum_closure_observed_at_unix',
            'minimum_freshness_sequence','minimum_checkpoint_number',
            'tsa_max_age_seconds','tsa_minimum_time_unix','escrow_port',
            'escrow_minimum_index'):
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
            getattr(exc,'code','EC274_REMOTE_ESCROW_HOST_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

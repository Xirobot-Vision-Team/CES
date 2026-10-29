#!/usr/bin/env python3
"""EC273 standalone opt-in RFC3161-gated strict EC272 service and offline CLI.

Verify the external timestamp BEFORE opening any socket or lease, then again
through inherited startup, begin, and continuous guarded-egress checks. Old
EC272/271 entrypoints and all native CLI/Router host-required denials remain.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
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
from source_provenance_host import provenance as prov
from governed_source_host import governance as gov
from governed_source_host.governance import GovernanceError
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as old_cli
from recovery_closure_host.closure import ClosureError
from freshness_quorum_host import serve as fresh_cli
from freshness_rollover_host import rollover as roll
from freshness_rollover_host import serve as parent
from rfc3161_timestamp_host import timeproof as tsa


class TrustedTimestampGate(parent.SignedRolloverGate):
    """Add an external pinned TSA to all mandatory, inherited EC272 checks."""

    def __init__(self,*args:Any,tsa_request:str,tsa_request_sha256:str,
                 tsa_response:str,tsa_response_sha256:str,
                 tsa_ca_bundle:str,tsa_ca_bundle_sha256:str,
                 tsa_leaf_cert_sha256:str,tsa_policy_oid:str,
                 tsa_openssl_binary:str,tsa_openssl_binary_sha256:str,
                 tsa_max_age_seconds:int,tsa_minimum_time_unix:int,
                 tsa_intermediates:str|None=None,
                 tsa_intermediates_sha256:str|None=None,**kwargs:Any):
        self.tsa_request=prov._path(tsa_request)
        self.tsa_request_pin=rec._sha(tsa_request_sha256)
        self.tsa_response=prov._path(tsa_response)
        self.tsa_response_pin=rec._sha(tsa_response_sha256)
        self.tsa_ca=prov._path(tsa_ca_bundle)
        self.tsa_ca_pin=rec._sha(tsa_ca_bundle_sha256)
        self.tsa_leaf_pin=rec._sha(tsa_leaf_cert_sha256)
        tsa._oid(tsa_policy_oid)
        self.tsa_policy_oid=tsa_policy_oid
        self.tsa_openssl_binary=tsa_openssl_binary
        self.tsa_openssl_pin=rec._sha(tsa_openssl_binary_sha256)
        self.tsa_max_age=rec._integer(tsa_max_age_seconds,1,tsa.MAX_AGE,
                                      'EC273_MAX_TIMESTAMP_AGE_INVALID')
        self.tsa_floor=rec._integer(tsa_minimum_time_unix,1,2**40,
                                    'EC273_TIMESTAMP_FLOOR_INVALID')
        if (tsa_intermediates is None)!=(tsa_intermediates_sha256 is None):
            tsa.deny('EC273_INTERMEDIATE_CERTIFICATE_PIN_PAIR_REQUIRED')
        self.tsa_intermediates=None if tsa_intermediates is None else prov._path(tsa_intermediates)
        self.tsa_intermediates_pin=None if tsa_intermediates is None else rec._sha(tsa_intermediates_sha256)
        self._timestamp_verified:dict|None=None
        super().__init__(*args,**kwargs)

    def authority_paths(self)->list[str]:
        return [*super().authority_paths(),self.tsa_request,self.tsa_response,
                self.tsa_ca,*([self.tsa_intermediates] if self.tsa_intermediates else [])]

    def _check_freshness(self)->None:
        # No caller may replace/avoid the parent EC270/271/272 authorization.
        super()._check_freshness()
        if self._clock_anchor is None or self._freshness_verified is None:
            tsa.deny('EC273_PARENT_RECOVERY_AND_SIGNED_TAIL_REQUIRED')
        wall,mono=gov._now()
        first_wall,first_mono=self._clock_anchor
        effective=max(wall,first_wall+mono-first_mono,self._max_wall_seen or 0)
        report=tsa.verify_timestamp(
            segment=self.freshness_chain,segment_sha256=self.freshness_pin,
            checkpoint_sha256=self.checkpoint_pin,
            request=self.tsa_request,request_sha256=self.tsa_request_pin,
            response=self.tsa_response,response_sha256=self.tsa_response_pin,
            ca_bundle=self.tsa_ca,ca_bundle_sha256=self.tsa_ca_pin,
            leaf_cert_sha256=self.tsa_leaf_pin,policy_oid=self.tsa_policy_oid,
            openssl_binary=self.tsa_openssl_binary,
            openssl_binary_sha256=self.tsa_openssl_pin,
            effective_now=effective,maximum_age_seconds=self.tsa_max_age,
            minimum_time_unix=self.tsa_floor,
            intermediates=self.tsa_intermediates,
            intermediates_sha256=self.tsa_intermediates_pin)
        if self._timestamp_verified is not None and report != self._timestamp_verified:
            tsa.deny('EC273_TIMESTAMP_AUTHORITY_CHANGED_DURING_SESSION')
        self._timestamp_verified=report

    def summary(self)->dict[str,Any]:
        if self._timestamp_verified is None:
            tsa.deny('EC273_TIMESTAMP_NOT_VERIFIED')
        result=super().summary()
        result.update(self._timestamp_verified)
        result['ec273_external_tsa_opt_in']=True
        result['independent_external_time_or_off_host_escrow_proven']=False
        return result


def _gate(args:argparse.Namespace,audit:CustodyAudit)->TrustedTimestampGate:
    return TrustedTimestampGate(
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
        tsa_intermediates_sha256=args.tsa_intermediates_sha256)


def _preflight(args:argparse.Namespace,audit:CustodyAudit)->TrustedTimestampGate:
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
        tsa.deny('EC273_AUTHORITY_PATH_COLLISION')
    for authority in authorities:
        if authority in protected:
            tsa.deny('EC273_AUTHORITY_COLLIDES_WITH_SOURCE_EVIDENCE')
        for root in roots:
            if os.path.commonpath((authority,root))==root:
                tsa.deny('EC273_AUTHORITY_INSIDE_SOURCE_OR_AUDIT_TREE')
    if gate.tsa_openssl_binary in authorities or gate.tsa_openssl_binary in protected:
        tsa.deny('EC273_OPENSSL_BINARY_PATH_COLLISION')
    return gate


def verify_gate(args:argparse.Namespace)->dict:
    with _open_preflight(args,writable=False) as audit:
        gate=_preflight(args,audit)
        policy,sha=lease._policy(args.policy)
        gate.startup(policy,sha)
        summary=gate.summary()
        summary['custody_receipts_verified']=audit.summary()['custody_receipts_verified']
        return summary


def run_serve(args:argparse.Namespace)->None:
    cfg=_read_config(args.chain,args.chain_sha256)
    for entry in cfg['archives']+[cfg['active']]:
        placement=argparse.Namespace(**vars(args))
        placement.audit_root=entry['audit_root']
        placement.audit_key=entry['audit_key']
        _check_placement(placement)
    _recover_prior(args.policy)
    with _open_preflight(args,writable=True) as audit:
        gate=_preflight(args,audit)
        policy,sha=lease._policy(args.policy)
        gate.startup(policy,sha)  # MUST precede lease, socket and service event
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
                    getattr(exc,'code','EC273_TIMESTAMP_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def _tail_verified(args:argparse.Namespace)->dict:
    base,epochs,_=parent._offline(args)
    current,_,_=roll._authority(**base)
    result,_=roll.verify_tail(checkpoint=args.checkpoint,
        checkpoint_sha256=args.checkpoint_sha256,
        segment=args.freshness_chain,segment_sha256=args.freshness_chain_sha256,
        witness_public_keys=base['witness_public_keys'],
        closure_sha256=base['historic']['closure_certificate_sha256'],
        recovered_root_public_sha256=base['historic']['recovered_root_public_sha256'],
        allowed_governance_epochs=epochs,
        current_governance_sha256=base['governance_policy_sha256'],
        current_governance_epoch=current['epoch'],
        minimum_sequence=int(args.minimum_freshness_sequence),
        expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
        minimum_checkpoint_number=int(args.minimum_checkpoint_number),
        effective_now=gov._now()[0],forbidden_signers=base['forbidden_signers'])
    return result


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description='EC273 signed RFC3161 timestamp for EC272 strict host')
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
    tail=('checkpoint','checkpoint_sha256','freshness_chain','freshness_chain_sha256',
          'minimum_freshness_sequence','expected_previous_receipt_sha256',
          'minimum_checkpoint_number')
    proof=('tsa_request','tsa_request_sha256','tsa_response','tsa_response_sha256',
          'tsa_ca_bundle','tsa_ca_bundle_sha256','tsa_leaf_cert_sha256',
          'tsa_openssl_binary','tsa_openssl_binary_sha256',
          'tsa_max_age_seconds','tsa_minimum_time_unix')
    for action in ('prepare-request','verify-proof','verify-gate','serve'):
        cmd=sub.add_parser(action)
        host=action in ('verify-gate','serve')
        old_cli._required(cmd,original+tail+(host_extra if host else ()))
        old_cli._council_args(cmd)
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        if action=='prepare-request':
            old_cli._required(cmd,('output','tsa_policy_oid'))
        else:
            old_cli._required(cmd,proof+('tsa_policy_oid',))
            cmd.add_argument('--tsa-intermediates')
            cmd.add_argument('--tsa-intermediates-sha256')
        if not host:
            cmd.add_argument('--forbidden-public-sha256',action='append',default=[])
        if action=='serve':
            cmd.add_argument('--socket',required=True)
            cmd.add_argument('--max-sessions',type=int,default=1)
            cmd.add_argument('--accept-timeout',type=float,default=60.)
    args=parser.parse_args(argv)
    try:
        for name in ('minimum_freshness_sequence','minimum_checkpoint_number'):
            setattr(args,name,int(getattr(args,name)))
        if args.action in ('verify-gate','serve'):
            for name in ('minimum_governance_epoch','minimum_closure_observed_at_unix'):
                setattr(args,name,int(getattr(args,name)))
        if args.action!='prepare-request':
            args.tsa_max_age_seconds=int(args.tsa_max_age_seconds)
            args.tsa_minimum_time_unix=int(args.tsa_minimum_time_unix)
        if args.action=='serve':
            run_serve(args)
            return 0
        if args.action=='verify-gate':
            result=verify_gate(args)
        else:
            tail_report=_tail_verified(args)
            if args.action=='prepare-request':
                result=tsa.prepare_request(segment=args.freshness_chain,
                    segment_sha256=args.freshness_chain_sha256,
                    checkpoint_sha256=args.checkpoint_sha256,
                    policy_oid=args.tsa_policy_oid,output=args.output)
            else:
                result=tsa.verify_timestamp(
                    segment=args.freshness_chain,segment_sha256=args.freshness_chain_sha256,
                    checkpoint_sha256=args.checkpoint_sha256,
                    request=args.tsa_request,request_sha256=args.tsa_request_sha256,
                    response=args.tsa_response,response_sha256=args.tsa_response_sha256,
                    ca_bundle=args.tsa_ca_bundle,ca_bundle_sha256=args.tsa_ca_bundle_sha256,
                    leaf_cert_sha256=args.tsa_leaf_cert_sha256,
                    policy_oid=args.tsa_policy_oid,
                    openssl_binary=args.tsa_openssl_binary,
                    openssl_binary_sha256=args.tsa_openssl_binary_sha256,
                    effective_now=gov._now()[0],
                    maximum_age_seconds=args.tsa_max_age_seconds,
                    minimum_time_unix=args.tsa_minimum_time_unix,
                    intermediates=args.tsa_intermediates,
                    intermediates_sha256=args.tsa_intermediates_sha256)
            result.update({'ec272_full_live_segment_verified':True,
                           'ec272_freshness_sequence':tail_report['freshness_sequence']})
        print(json.dumps(result,sort_keys=True))
        return 2
    except (runner.HostRunError,fio.HostError,rec.RecoveryError,
            GovernanceError,ProvenanceError,ClosureError,OSError,ValueError,
            TypeError) as exc:
        print(json.dumps(session._reply('unavailable',_reason(
            getattr(exc,'code','EC273_TIMESTAMP_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

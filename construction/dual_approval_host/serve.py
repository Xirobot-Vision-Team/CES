#!/usr/bin/env python3
"""EC276 opt-in strict EC275 host plus dual offline-signed CAS intent.

All existing strict host duties remain delegated to EC275 unmodified: live
source provenance, governance/recovery, EC272/273, two nonce-signed remote
readbacks, active recall, custody, audit, cgroup and lease. On *every* startup
and guarded operation the signed offline approval is checked both before and
after the full parent check. This process never reads approver private keys.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import sys
import time
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
from source_provenance_host.serve import _open_preflight
from source_provenance_host import provenance as prov
from source_provenance_host.provenance import ProvenanceError
from governed_source_host.governance import GovernanceError
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as old_cli
from recovery_closure_host.closure import ClosureError
from remote_escrow_host import escrow as esc
from dual_escrow_host import serve as parent
from dual_approval_host import approval as auth


class ApprovedDualEscrowGuard:
    """Composition preserves exact EC275 parent wiring and protected checks."""

    def __init__(self,gate:parent.DualEscrowGate, *,approval_path:str,
                 approval_pin:str,approver_pairs:list[tuple[str,str]]):
        self.base=gate
        self.approval_path=prov._path(approval_path)
        self.approval_pin=esc._sha(approval_pin)
        self.approver_paths=[prov._path(path) for path,_ in approver_pairs]
        if len(set([self.approval_path,*self.approver_paths,
                    *gate.authority_paths()]))!=1+len(self.approver_paths)+len(gate.authority_paths()):
            auth.deny('EC276_APPROVAL_FILE_OR_TRUST_PATH_COLLISION')
        self.approvers=auth.approver_keys(approver_pairs,gate.dual)
        self._clock_wall=time.time()
        self._clock_mono=time.monotonic()
        self._highest_now=math.floor(self._clock_wall)
        self._receipt:dict[str,Any]|None=None

    def authority_paths(self) -> list[str]:
        return [*self.base.authority_paths(),self.approval_path,*self.approver_paths]

    def _now(self) -> int:
        # In-process monotonic anchor prevents trivial wall-clock rewind after
        # startup. A trusted monotonic clock across restarts remains external.
        observed=max(time.time(),self._clock_wall+(time.monotonic()-self._clock_mono))
        self._highest_now=max(self._highest_now,math.ceil(observed))
        return self._highest_now

    def _authorize(self) -> None:
        intent=auth.verified_file(self.approval_path,self.approval_pin,
            self.base.dual,self.approvers,now=self._now())
        if (intent['record_sha256']!=self.base.escrow_expected_head or
                intent['record_index']!=self.base.escrow_floor or
                intent['record_index']!=self.base.secondary_floor):
            auth.deny('EC276_SIGNED_INTENT_NOT_EXACTLY_HOST_OPERATOR_HEAD_AND_FLOORS')
        report={'ec276_offline_two_person_approval_required':True,
            'ec276_approval_sha256':self.approval_pin,
            'ec276_record_sha256':intent['record_sha256'],
            'ec276_record_index':intent['record_index'],
            'ec276_approval_expires_at_unix':intent['expires_at_unix'],
            'ec276_offline_approver_signatures_verified':2,
            'ec276_remote_sites_and_tls_pins_bound_to_approval':True,
            'ec276_trusted_external_wall_clock_verified':False,
            'ec276_physical_approver_independence_verified':False}
        if self._receipt is not None and report!=self._receipt:
            auth.deny('EC276_APPROVED_INTENT_CHANGED_IN_ACTIVE_SESSION')
        self._receipt=report

    def startup(self,policy:dict,policy_sha:str)->None:
        self._authorize()
        self.base.startup(policy,policy_sha)
        self._authorize()

    def recheck_startup(self,policy:dict,policy_sha:str)->None:
        self._authorize()
        self.base.recheck_startup(policy,policy_sha)
        self._authorize()

    def before_begin(self,policy:dict,policy_sha:str,request:dict)->None:
        self._authorize()
        self.base.before_begin(policy,policy_sha,request)
        self._authorize()

    def summary(self) -> dict:
        if self._receipt is None:
            auth.deny('EC276_OFFLINE_APPROVAL_NOT_VERIFIED')
        report=self.base.summary()
        report.update(self._receipt)
        return report


def _approver_pairs(args:argparse.Namespace)->list[tuple[str,str]]:
    if len(args.approver_public)!=len(args.approver_public_sha256):
        auth.deny('EC276_APPROVER_PUBLIC_PIN_PAIRS_REQUIRED')
    return list(zip(args.approver_public,args.approver_public_sha256))


def _preflight(args:argparse.Namespace,audit:CustodyAudit)->ApprovedDualEscrowGuard:
    # Full EC275 trust/source/audit validation is mandatory; no reimplementation
    # or reduction of its inherited policy, governance, timestamp or session.
    base=parent._preflight(args,audit)
    gate=ApprovedDualEscrowGuard(base,approval_path=args.approval,
        approval_pin=args.approval_sha256,approver_pairs=_approver_pairs(args))
    config=base._read_config()
    protected=[base.gate_path,config['subject']]
    for authority in config['authorities']:
        protected.extend(authority[k] for k in ('public_key','assertion','evidence'))
    forbidden=[base.repo,*[a['audit_root'] for a in audit.config['archives']],
               audit.config['active']['audit_root']]
    for path in [gate.approval_path,*gate.approver_paths]:
        if path in protected or path==base.tsa_openssl_binary:
            auth.deny('EC276_APPROVAL_TRUST_COLLIDES_WITH_SOURCE_OR_EXECUTABLE')
        if any(os.path.commonpath((path,root))==root for root in forbidden):
            auth.deny('EC276_APPROVAL_FILES_INSIDE_UNTRUSTED_SOURCE_OR_AUDIT')
    forbidden_roles={audit.config['signer_public_sha256'],
                     audit.gate_config['custody_public_sha256']}
    if set(gate.approvers)&forbidden_roles:
        auth.deny('EC276_OFFLINE_APPROVER_MUST_NOT_BE_ACTIVE_AUDIT_OR_CUSTODY_SIGNER')
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
        gate.startup(policy,pin)  # BEFORE socket / lease / first audit event
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
                    getattr(exc,'code','EC276_APPROVED_DUAL_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def build_parser()->argparse.ArgumentParser:
    p=parent.build_parser()
    p.description='EC276 strict dual escrow host requiring offline 2-of-3 operator authorization'
    sub=next(x for x in p._actions if isinstance(x,argparse._SubParsersAction))
    for cmd in sub.choices.values():
        old_cli._required(cmd,('approval','approval_sha256'))
        cmd.add_argument('--approver-public',action='append',required=True)
        cmd.add_argument('--approver-public-sha256',action='append',required=True)
    return p


def main(argv:list[str]|None=None)->int:
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
            getattr(exc,'code','EC276_APPROVED_DUAL_HOST_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

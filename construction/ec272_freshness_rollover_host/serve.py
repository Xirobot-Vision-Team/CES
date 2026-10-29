#!/usr/bin/env python3
"""EC272 stand-alone opt-in strict host and offline signed rollover CLI.

The old EC271 host retains its original complete 256-receipt verification.
Only the new EC272 host may admit a SHA pinned, independently 2-signed
checkpoint and a subsequent live segment. No private signing key is loaded by
verify/serve paths, and no client payload can select an authority file.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
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
from ec266_source_provenance_host.provenance import ProvenanceError
from ec266_source_provenance_host import provenance as prov
from ec267_governed_source_host import governance as gov
from ec267_governed_source_host.governance import GovernanceError
from ec268_root_handover_host import handover as rot
from ec269_emergency_recovery_host import recovery as rec
from ec269_emergency_recovery_host import serve as old_cli
from ec270_recovery_closure_host.closure import ClosureError
from ec271_freshness_quorum_host import freshness as fresh
from ec271_freshness_quorum_host import serve as parent
from ec272_freshness_rollover_host import rollover as roll


class SignedRolloverGate(parent.QuorumFreshnessGate):
    """Preserve every EC270/EC271 parent safety gate; override only chain proof."""

    def __init__(self,*args:Any,checkpoint:str,checkpoint_sha256:str,
                 minimum_checkpoint_number:int,**kwargs:Any):
        self.checkpoint=prov._path(checkpoint)
        self.checkpoint_pin=rec._sha(checkpoint_sha256)
        self.minimum_checkpoint_number=rec._integer(minimum_checkpoint_number,1,
            roll.MAX_CHECKPOINTS,'EC272_CHECKPOINT_FLOOR_INVALID')
        super().__init__(*args,**kwargs)

    def authority_paths(self)->list[str]:
        return [*super().authority_paths(),
            *roll.referenced_checkpoint_paths(checkpoint=self.checkpoint,
                checkpoint_sha256=self.checkpoint_pin,
                witness_public_keys=self.freshness_witnesses)]

    def _check_freshness(self)->None:
        if self._closure_seen is None or self._governance_seen is None:
            roll.deny('EC272_PARENT_RECOVERY_MUST_VERIFY_FIRST')
        root=rec._public(self.governance_public,self.governance_public_pin)
        anchor=rot._signed_governance(self.anchor_governance,self.anchor_pin,root)
        history={anchor['epoch']:self.anchor_pin}
        disallowed=set(self._forbidden)|{
            self.old_root_pin,self.governance_public_pin,self.witness_pin,
            *[pin for _,pin in self.council_keys]}
        old=rot._signed_governance(self.old_governance,self.old_sha,
            rec._public(self.old_root,self.old_root_pin))
        for policy in (old,anchor):
            disallowed.update(policy['role_public_sha256'].values())
            disallowed.update(policy['revoked_public_sha256'])
        for part in self._continuations():
            nxt=rot._signed_governance(part['governance_policy'],
                                      part['governance_policy_sha256'],root)
            history[nxt['epoch']]=part['governance_policy_sha256']
            disallowed.update(nxt['role_public_sha256'].values())
            disallowed.update(nxt['revoked_public_sha256'])
        if history.get(self._governance_seen['epoch'])!=self.governance_policy_pin:
            roll.deny('EC272_CURRENT_GOVERNANCE_HISTORY_MISMATCH')
        if self._clock_anchor is None:
            roll.deny('EC272_GOVERNANCE_CLOCK_ANCHOR_MISSING')
        wall,mono=gov._now()
        first_wall,first_mono=self._clock_anchor
        effective=max(wall,first_wall+mono-first_mono,self._max_wall_seen or 0)
        result,_=roll.verify_tail(checkpoint=self.checkpoint,
            checkpoint_sha256=self.checkpoint_pin,
            segment=self.freshness_chain,segment_sha256=self.freshness_pin,
            witness_public_keys=self.freshness_witnesses,
            closure_sha256=self.closure_pin,
            recovered_root_public_sha256=self.governance_public_pin,
            allowed_governance_epochs=history,
            current_governance_sha256=self.governance_policy_pin,
            current_governance_epoch=self._governance_seen['epoch'],
            minimum_sequence=self.minimum_freshness_sequence,
            expected_previous_receipt_sha256=self.expected_previous_receipt_sha256,
            minimum_checkpoint_number=self.minimum_checkpoint_number,
            effective_now=effective,forbidden_signers=tuple(disallowed))
        if self._freshness_verified is not None and result!=self._freshness_verified:
            roll.deny('EC272_LIVE_CHAIN_CHANGED_DURING_RUNNING_HOST')
        self._freshness_verified=result

    def summary(self)->dict[str,Any]:
        result=super().summary()
        result['ec272_signed_rollover_opt_in']=True
        result['full_old_member_replay_after_checkpoint']=False
        return result


def _gate(args:argparse.Namespace,audit:CustodyAudit)->SignedRolloverGate:
    return SignedRolloverGate(
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
        freshness_witness_public_keys=parent._witnesses(args),
        minimum_freshness_sequence=args.minimum_freshness_sequence,
        expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
        checkpoint=args.checkpoint,checkpoint_sha256=args.checkpoint_sha256,
        minimum_checkpoint_number=args.minimum_checkpoint_number)


def _preflight(args:argparse.Namespace,audit:CustodyAudit)->SignedRolloverGate:
    gate=_gate(args,audit)
    _ensure_gate_outside_audits(args,audit,gate)
    cfg=gate._read_config()
    protected=[gate.gate_path,cfg['subject']]
    for authority in cfg['authorities']:
        protected.extend(authority[key] for key in ('public_key','assertion','evidence'))
    roots=[gate.repo,*[item['audit_root'] for item in audit.config['archives']],
           audit.config['active']['audit_root']]
    authorities=gate.authority_paths()
    if len(authorities)!=len(set(authorities)):
        roll.deny('EC272_AUTHORITY_PATH_COLLISION')
    for authority in authorities:
        if authority in protected:
            roll.deny('EC272_AUTHORITY_COLLIDES_WITH_SOURCE_EVIDENCE')
        for root in roots:
            if os.path.commonpath((authority,root))==root:
                roll.deny('EC272_AUTHORITY_INSIDE_SOURCE_OR_AUDIT_TREE')
    return gate


def verify_gate(args:argparse.Namespace)->dict:
    with _open_preflight(args,writable=False) as audit:
        gate=_preflight(args,audit)
        policy,sha=lease._policy(args.policy)
        gate.startup(policy,sha)
        result=gate.summary()
        result['custody_receipts_verified']=audit.summary()['custody_receipts_verified']
        return result


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
        gate.startup(policy,sha)  # before event, socket or new lease
        audit.record('service_start')
        try:
            audit.record('service_recovery_complete')
            session.serve(args.policy,args.socket,max_sessions=args.max_sessions,
                accept_timeout=args.accept_timeout,
                require_cgroup=True,require_kernel_metrics=True,
                startup_guard=gate.recheck_startup,
                before_begin_guard=gate.before_begin,
                during_session_guard=gate.before_begin,
                audit_event=audit.record)
        except BaseException as exc:
            try:
                audit.record('service_failed',reason_code=_reason(
                    getattr(exc,'code','EC272_ROLLOVER_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def _basis(args:argparse.Namespace)->dict[str,Any]:
    return parent._historic(args)


def _forbidden(args:argparse.Namespace)->tuple[str,...]:
    return tuple(getattr(args,'forbidden_public_sha256',[]) or [])


def _offline(args:argparse.Namespace)->tuple[dict,dict,dict]:
    historic=_basis(args)
    base=dict(historic=historic,governance_policy=args.governance_policy,
        governance_policy_sha256=args.governance_policy_sha256,
        continuation_chain=args.continuation_chain,
        continuation_chain_sha256=args.continuation_chain_sha256,
        witness_public_keys=parent._witnesses(args),
        forbidden_signers=_forbidden(args))
    current,epochs,keys=roll._authority(**base)
    return base,epochs,keys


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description='EC272 signed EC271 segment rollover and strict host')
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
    for action in ('prepare-checkpoint','sign-checkpoint','append-segment',
                   'verify-segment','verify-gate','serve'):
        cmd=sub.add_parser(action)
        old_cli._required(cmd,original + (host_extra if action in ('verify-gate','serve') else ()))
        old_cli._council_args(cmd)
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        if action in ('prepare-checkpoint','sign-checkpoint','append-segment'):
            cmd.add_argument('--forbidden-public-sha256',action='append',default=[])
        if action=='prepare-checkpoint':
            old_cli._required(cmd,('segment','segment_sha256','output'))
            cmd.add_argument('--previous-checkpoint')
            cmd.add_argument('--previous-checkpoint-sha256')
        if action=='sign-checkpoint':
            old_cli._required(cmd,('input_path','input_sha256','signing_key',
                                   'expected_public_sha256','output'))
        if action=='append-segment':
            old_cli._required(cmd,('checkpoint','checkpoint_sha256',
                'segment_receipt','segment_receipt_sha256','output'))
            cmd.add_argument('--previous-segment')
            cmd.add_argument('--previous-segment-sha256')
        if action in ('verify-segment','verify-gate','serve'):
            old_cli._required(cmd,('checkpoint','checkpoint_sha256',
                 'freshness_chain','freshness_chain_sha256',
                 'minimum_freshness_sequence','expected_previous_receipt_sha256',
                 'minimum_checkpoint_number'))
        if action=='serve':
            cmd.add_argument('--socket',required=True)
            cmd.add_argument('--max-sessions',type=int,default=1)
            cmd.add_argument('--accept-timeout',type=float,default=60.0)
    args=parser.parse_args(argv)
    try:
        if args.action in ('verify-gate','serve'):
            for key in ('minimum_governance_epoch',
                        'minimum_closure_observed_at_unix',
                        'minimum_freshness_sequence','minimum_checkpoint_number'):
                setattr(args,key,int(getattr(args,key)))
            if args.action=='serve':
                run_serve(args)
                return 0
            output=verify_gate(args)
        else:
            base,epochs,_keys=_offline(args)
            if args.action=='prepare-checkpoint':
                output=roll.prepare_checkpoint(**base,
                    segment=args.segment,segment_sha256=args.segment_sha256,
                    previous_checkpoint=args.previous_checkpoint,
                    previous_checkpoint_sha256=args.previous_checkpoint_sha256,
                    output=args.output)
            elif args.action=='sign-checkpoint':
                output=roll.sign_checkpoint(**base,input_path=args.input_path,
                    input_sha256=args.input_sha256,signing_key=args.signing_key,
                    expected_public_sha256=args.expected_public_sha256,
                    output=args.output)
            elif args.action=='append-segment':
                output=roll.append_segment(checkpoint=args.checkpoint,
                    checkpoint_sha256=args.checkpoint_sha256,
                    segment_receipt=args.segment_receipt,
                    segment_receipt_sha256=args.segment_receipt_sha256,
                    witness_public_keys=base['witness_public_keys'],
                    closure_sha256=base['historic']['closure_certificate_sha256'],
                    recovered_root_public_sha256=base['historic']['recovered_root_public_sha256'],
                    allowed_governance_epochs=epochs,output=args.output,
                    previous_segment=args.previous_segment,
                    previous_segment_sha256=args.previous_segment_sha256,
                    forbidden_signers=base['forbidden_signers'])
            else:
                current,_,_=roll._authority(**base)
                output,_paths=roll.verify_tail(checkpoint=args.checkpoint,
                    checkpoint_sha256=args.checkpoint_sha256,
                    segment=args.freshness_chain,
                    segment_sha256=args.freshness_chain_sha256,
                    witness_public_keys=base['witness_public_keys'],
                    closure_sha256=base['historic']['closure_certificate_sha256'],
                    recovered_root_public_sha256=base['historic']['recovered_root_public_sha256'],
                    allowed_governance_epochs=epochs,
                    current_governance_sha256=base['governance_policy_sha256'],
                    current_governance_epoch=current['epoch'],
                    minimum_sequence=int(args.minimum_freshness_sequence),
                    expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
                    minimum_checkpoint_number=int(args.minimum_checkpoint_number),
                    effective_now=gov._now()[0],
                    forbidden_signers=base['forbidden_signers'])
        print(json.dumps(output,sort_keys=True))
        return 2
    except (runner.HostRunError,fio.HostError,rec.RecoveryError,
            GovernanceError,ProvenanceError,ClosureError,OSError,ValueError,
            TypeError) as exc:
        print(json.dumps(session._reply('unavailable',_reason(
            getattr(exc,'code','EC272_ROLLOVER_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

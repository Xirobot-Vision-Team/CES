#!/usr/bin/env python3
"""EC271 offline two-of-three signer CLI and separate strict active-recall host.

Host routes accept ONLY public keys and exact digest-pinned signed documents.
No new routes to the existing PowerShell, Router, EC269 or EC270 services.
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
from ec263_offline_anchor_host import checkpoint as cp
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
from ec270_recovery_closure_host import serve as parent_cli
from ec270_recovery_closure_host.closure import ClosureError, RatifiedRecoveryGate
from ec271_freshness_quorum_host import freshness as fresh


def _witnesses(args: argparse.Namespace) -> tuple[tuple[str,str], ...]:
    paths = getattr(args, 'freshness_witness_public', None) or []
    pins = getattr(args, 'freshness_witness_public_sha256', None) or []
    if len(paths) != 3 or len(pins) != 3:
        fresh.deny('EC271_THREE_INDEPENDENT_WITNESS_PINS_REQUIRED')
    return tuple(zip(paths, pins))


def _historic(args: argparse.Namespace) -> dict[str, Any]:
    return {
        **parent_cli._basis(args),
        'closure_certificate':args.closure_certificate,
        'closure_certificate_sha256':args.closure_certificate_sha256,
    }


class QuorumFreshnessGate(RatifiedRecoveryGate):
    """Adds a mandatory short-lived signed 2-of-3 chain to EC270 guards.

    The chain is validated afresh on startup and *every* session guard call,
    including the inherited active-recall/guarded-egress checks.
    """

    def __init__(self, *args: Any, freshness_chain: str,
                 freshness_chain_sha256: str,
                 freshness_witness_public_keys: tuple[tuple[str,str], ...],
                 minimum_freshness_sequence: int,
                 expected_previous_receipt_sha256: str,
                 **kwargs: Any):
        self.freshness_chain = prov._path(freshness_chain)
        self.freshness_pin = rec._sha(freshness_chain_sha256)
        self.freshness_witnesses = tuple((prov._path(p),rec._sha(pin))
                                         for p,pin in freshness_witness_public_keys)
        self.minimum_freshness_sequence = minimum_freshness_sequence
        self.expected_previous_receipt_sha256 = rec._sha(expected_previous_receipt_sha256)
        self.freshness_entries = fresh._chain_entries(self.freshness_chain,self.freshness_pin)
        self._freshness_verified: dict | None = None
        super().__init__(*args, **kwargs)
        if len(set(self.authority_paths())) != len(self.authority_paths()):
            fresh.deny('EC271_AUTHORITY_PATH_COLLISION')

    def authority_paths(self) -> list[str]:
        return [*super().authority_paths(), self.freshness_chain,
                *(p for p,_ in self.freshness_witnesses),
                *(x['receipt_path'] for x in self.freshness_entries)]

    def _check_freshness(self) -> None:
        if self._closure_seen is None or self._governance_seen is None:
            fresh.deny('EC271_PARENT_RECOVERY_MUST_VERIFY_FIRST')
        root = rec._public(self.governance_public,self.governance_public_pin)
        anchor = rot._signed_governance(self.anchor_governance,self.anchor_pin,root)
        history = {anchor['epoch']:self.anchor_pin}
        disallowed = set(self._forbidden) | {
            self.old_root_pin,self.governance_public_pin,self.witness_pin,
            *[pin for _,pin in self.council_keys],
        }
        old = rot._signed_governance(self.old_governance,self.old_sha,
            rec._public(self.old_root,self.old_root_pin))
        for policy in (old,anchor):
            disallowed.update(policy['role_public_sha256'].values())
            disallowed.update(policy['revoked_public_sha256'])
        for part in self._continuations():
            nxt = rot._signed_governance(part['governance_policy'],
                                        part['governance_policy_sha256'],root)
            history[nxt['epoch']] = part['governance_policy_sha256']
            disallowed.update(nxt['role_public_sha256'].values())
            disallowed.update(nxt['revoked_public_sha256'])
        if history[self._governance_seen['epoch']] != self.governance_policy_pin:
            fresh.deny('EC271_CURRENT_GOVERNANCE_HISTORY_MISMATCH')
        if self._clock_anchor is None:
            fresh.deny('EC271_GOVERNANCE_CLOCK_ANCHOR_MISSING')
        wall,mono = gov._now()
        first_wall,first_mono = self._clock_anchor
        effective = max(wall, first_wall + mono - first_mono,
                        self._max_wall_seen or 0)
        result = fresh.verify_chain(
            chain=self.freshness_chain, chain_sha256=self.freshness_pin,
            witness_public_keys=self.freshness_witnesses,
            closure_sha256=self.closure_pin,
            recovered_root_public_sha256=self.governance_public_pin,
            allowed_governance_epochs=history,
            current_governance_sha256=self.governance_policy_pin,
            current_governance_epoch=self._governance_seen['epoch'],
            minimum_sequence=self.minimum_freshness_sequence,
            expected_previous_receipt_sha256=self.expected_previous_receipt_sha256,
            effective_now=effective,forbidden_signers=tuple(disallowed))
        if self._freshness_verified is not None and result != self._freshness_verified:
            fresh.deny('EC271_FRESHNESS_CHANGED_DURING_RUNNING_HOST')
        self._freshness_verified = result

    def _check_recovery(self) -> None:
        super()._check_recovery()
        self._check_freshness()

    def summary(self) -> dict[str, Any]:
        if self._freshness_verified is None:
            fresh.deny('EC271_FRESHNESS_NOT_VERIFIED')
        result = super().summary()
        result.update(self._freshness_verified)
        result['independent_external_time_or_off_host_escrow_proven'] = False
        return result


def _gate(args: argparse.Namespace, audit: CustodyAudit) -> QuorumFreshnessGate:
    # Extend the original EC270 parent, never weaken its parameters or guards.
    kw = {
        'policy_path':args.policy, 'repo':args.repo, 'allowlist':args.allowlist,
        'receipt':args.receipt, 'profile_id':args.profile_id,
        'provenance_gate':args.provenance_gate,
        'provenance_gate_sha256':args.provenance_gate_sha256,
        'governance_policy':args.governance_policy,
        'governance_policy_sha256':args.governance_policy_sha256,
        'governance_public':args.governance_public,
        'governance_public_sha256':args.governance_public_sha256,
        'minimum_epoch':args.minimum_governance_epoch,
        'expected_previous_governance_sha256':args.expected_previous_governance_sha256,
        'old_governance':args.old_governance,
        'old_governance_sha256':args.old_governance_sha256,
        'old_root_public':args.old_root_public,
        'old_root_public_sha256':args.old_root_public_sha256,
        'charter':args.charter, 'charter_sha256':args.charter_sha256,
        'council_public_keys':old_cli._council(args),
        'recovery_certificate':args.recovery_certificate,
        'recovery_certificate_sha256':args.recovery_certificate_sha256,
        'anchor_governance':args.anchor_governance,
        'anchor_governance_sha256':args.anchor_governance_sha256,
        'continuation_chain':args.continuation_chain,
        'continuation_chain_sha256':args.continuation_chain_sha256,
        'closure_certificate':args.closure_certificate,
        'closure_certificate_sha256':args.closure_certificate_sha256,
        'witness_public':args.witness_public,
        'witness_public_sha256':args.witness_public_sha256,
        'minimum_witness_observed_at_unix':args.minimum_closure_observed_at_unix,
        'forbidden_signers':(audit.config['signer_public_sha256'],
                             audit.gate_config['custody_public_sha256']),
        'freshness_chain':args.freshness_chain,
        'freshness_chain_sha256':args.freshness_chain_sha256,
        'freshness_witness_public_keys':_witnesses(args),
        'minimum_freshness_sequence':args.minimum_freshness_sequence,
        'expected_previous_receipt_sha256':args.expected_previous_receipt_sha256,
    }
    return QuorumFreshnessGate(**kw)


def _preflight(args: argparse.Namespace, audit: CustodyAudit) -> QuorumFreshnessGate:
    gate = _gate(args, audit)
    _ensure_gate_outside_audits(args, audit, gate)
    cfg = gate._read_config()
    protected = [gate.gate_path, cfg['subject']]
    for a in cfg['authorities']:
        protected.extend(a[n] for n in ('public_key','assertion','evidence'))
    roots = [gate.repo, *[v['audit_root'] for v in audit.config['archives']],
             audit.config['active']['audit_root']]
    for authority in gate.authority_paths():
        if authority in protected:
            fresh.deny('EC271_AUTHORITY_COLLIDES_WITH_SOURCE_EVIDENCE')
        for root in roots:
            if os.path.commonpath((authority,root)) == root:
                fresh.deny('EC271_AUTHORITY_INSIDE_SOURCE_OR_AUDIT_TREE')
    return gate


def verify_gate(args: argparse.Namespace) -> dict:
    with _open_preflight(args,writable=False) as audit:
        gate = _preflight(args,audit)
        policy, sha = lease._policy(args.policy)
        gate.startup(policy,sha)
        result=gate.summary()
        result['custody_receipts_verified']=audit.summary()['custody_receipts_verified']
        return result


def run_serve(args: argparse.Namespace) -> None:
    cfg = _read_config(args.chain,args.chain_sha256)
    for entry in cfg['archives']+[cfg['active']]:
        placement=argparse.Namespace(**vars(args))
        placement.audit_root=entry['audit_root']
        placement.audit_key=entry['audit_key']
        _check_placement(placement)
    _recover_prior(args.policy)
    with _open_preflight(args,writable=True) as audit:
        gate = _preflight(args,audit)
        policy,sha=lease._policy(args.policy)
        gate.startup(policy,sha)  # MUST precede socket, event, new lease
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
                    getattr(exc,'code','EC271_FRESHNESS_HOST_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def _epochs(historic: dict, chain: str | None, sha: str | None) -> dict[int,str]:
    root = rec._public(historic['recovered_root_public'],
                       historic['recovered_root_public_sha256'])
    anchor = rot._signed_governance(historic['anchor_governance'],
                                    historic['anchor_governance_sha256'],root)
    result={anchor['epoch']:historic['anchor_governance_sha256']}
    for entry in ([] if chain is None else rot._read_continuation(chain,sha)):
        signed=rot._signed_governance(entry['governance_policy'],
                                     entry['governance_policy_sha256'],root)
        result[signed['epoch']]=entry['governance_policy_sha256']
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC271 signed quorum freshness, separate strict host')
    sub = parser.add_subparsers(dest='action',required=True)
    offline = ('old_governance','old_governance_sha256','old_root_public',
               'old_root_public_sha256','charter','charter_sha256',
               'anchor_governance','anchor_governance_sha256','governance_public',
               'governance_public_sha256','recovery_certificate',
               'recovery_certificate_sha256','witness_public','witness_public_sha256',
               'closure_certificate','closure_certificate_sha256',
               'governance_policy','governance_policy_sha256')
    for action in ('prepare-freshness','sign-freshness','append-chain',
                   'verify-chain','verify-gate','serve'):
        cmd=sub.add_parser(action)
        if action != 'append-chain':
            mandatory = offline if action in ('prepare-freshness','sign-freshness','verify-chain') else (
                'old_governance','old_governance_sha256','old_root_public',
                'old_root_public_sha256','charter','charter_sha256',
                'anchor_governance','anchor_governance_sha256',
                'governance_public','governance_public_sha256',
                'recovery_certificate','recovery_certificate_sha256',
                'witness_public','witness_public_sha256',
                'closure_certificate','closure_certificate_sha256',
                'governance_policy','governance_policy_sha256',
                'provenance_gate','provenance_gate_sha256',
                'minimum_closure_observed_at_unix',
                'chain','chain_sha256','custody_gate','custody_gate_sha256',
                'policy','repo','allowlist','receipt','profile_id',
                'minimum_governance_epoch','expected_previous_governance_sha256')
            old_cli._required(cmd,mandatory)
            old_cli._council_args(cmd)
            cmd.add_argument('--continuation-chain')
            cmd.add_argument('--continuation-chain-sha256')
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        if action == 'prepare-freshness':
            old_cli._required(cmd,('output',))
            cmd.add_argument('--sequence',type=int,required=True)
            cmd.add_argument('--not-before-unix',type=int,required=True)
            cmd.add_argument('--expires-at-unix',type=int,required=True)
        if action == 'sign-freshness':
            old_cli._required(cmd,('input_path','input_sha256','signing_key',
                                    'expected_public_sha256','output'))
        if action in ('prepare-freshness','sign-freshness'):
            cmd.add_argument('--previous-receipt')
            cmd.add_argument('--previous-receipt-sha256')
            cmd.add_argument('--forbidden-public-sha256',action='append',default=[])
        if action == 'append-chain':
            old_cli._required(cmd,('receipt','receipt_sha256','output'))
            cmd.add_argument('--previous-chain')
            cmd.add_argument('--previous-chain-sha256')
        if action in ('verify-chain','verify-gate','serve'):
            old_cli._required(cmd,('freshness_chain','freshness_chain_sha256',
                                    'minimum_freshness_sequence',
                                    'expected_previous_receipt_sha256'))
        if action == 'serve':
            cmd.add_argument('--socket',required=True)
            cmd.add_argument('--max-sessions',type=int,default=1)
            cmd.add_argument('--accept-timeout',type=float,default=60.0)
    args=parser.parse_args(argv)
    try:
        keys=_witnesses(args)
        if args.action in ('prepare-freshness','sign-freshness'):
            opts=dict(
                historic=_historic(args),governance_policy=args.governance_policy,
                governance_policy_sha256=args.governance_policy_sha256,
                witness_public_keys=keys,
                continuation_chain=args.continuation_chain,
                continuation_chain_sha256=args.continuation_chain_sha256,
                previous_receipt=args.previous_receipt,
                previous_receipt_sha256=args.previous_receipt_sha256,
                forbidden_signers=tuple(args.forbidden_public_sha256),
                output=args.output)
            if args.action=='prepare-freshness':
                result=fresh.prepare_freshness(**opts,sequence=args.sequence,
                    not_before_unix=args.not_before_unix,
                    expires_at_unix=args.expires_at_unix)
            else:
                result=fresh.sign_freshness(**opts,input_path=args.input_path,
                    input_sha256=args.input_sha256,signing_key=args.signing_key,
                    expected_public_sha256=args.expected_public_sha256)
        elif args.action=='append-chain':
            result=fresh.append_chain(receipt=args.receipt,
                receipt_sha256=args.receipt_sha256,witness_public_keys=keys,
                previous_chain=args.previous_chain,
                previous_chain_sha256=args.previous_chain_sha256,output=args.output)
        elif args.action=='verify-chain':
            historic=_historic(args)
            current,_=fresh._authority(historic=historic,
                governance_policy=args.governance_policy,
                governance_policy_sha256=args.governance_policy_sha256,
                continuation_chain=args.continuation_chain,
                continuation_chain_sha256=args.continuation_chain_sha256,
                witness_public_keys=keys,forbidden_signers=())
            result=fresh.verify_chain(chain=args.freshness_chain,
                chain_sha256=args.freshness_chain_sha256,witness_public_keys=keys,
                closure_sha256=historic['closure_certificate_sha256'],
                recovered_root_public_sha256=historic['recovered_root_public_sha256'],
                allowed_governance_epochs=_epochs(historic,args.continuation_chain,
                                                  args.continuation_chain_sha256),
                current_governance_sha256=args.governance_policy_sha256,
                current_governance_epoch=current['epoch'],
                minimum_sequence=int(args.minimum_freshness_sequence),
                expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
                effective_now=gov._now()[0])
        elif args.action=='verify-gate':
            args.minimum_governance_epoch=int(args.minimum_governance_epoch)
            args.minimum_closure_observed_at_unix=int(args.minimum_closure_observed_at_unix)
            args.minimum_freshness_sequence=int(args.minimum_freshness_sequence)
            result=verify_gate(args)
        else:
            args.minimum_governance_epoch=int(args.minimum_governance_epoch)
            args.minimum_closure_observed_at_unix=int(args.minimum_closure_observed_at_unix)
            args.minimum_freshness_sequence=int(args.minimum_freshness_sequence)
            run_serve(args)
            return 0
        print(json.dumps(result,sort_keys=True))
        return 2
    except (runner.HostRunError,fio.HostError,rec.RecoveryError,
            rot.HandoverError,GovernanceError,ProvenanceError,
            cp.AnchorError,OSError,ValueError,TypeError) as exc:
        print(json.dumps(session._reply('unavailable',_reason(
            getattr(exc,'code','EC271_FRESHNESS_UNAVAILABLE'))),sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())

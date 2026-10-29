#!/usr/bin/env python3
"""EC306 offline epoch-client; console integration is verify-latest ONLY."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec302_portable_bundle import bundle as b
from . import epochs as e


def _base(p: argparse.ArgumentParser) -> None:
    p.add_argument('--chain-file', required=True)
    for key in sorted(e.EXTERNAL_FIELDS):
        p.add_argument('--expected-' + key.replace('_','-'),required=True,
                       type=int if key in ('epoch_count','active_ledger_sequence') else str)
    p.add_argument('--epoch-ledger-file',action='append',default=[],
                   help='repeat for every NONEMPTY epoch, oldest to newest')
    p.add_argument('--cutover-certificate-file',action='append',default=[],
                   help='repeat for each epoch transition, oldest to newest')


def _external(args: argparse.Namespace) -> dict:
    return {k:getattr(args,'expected_'+k) for k in e.EXTERNAL_FIELDS}


def _chain_args(args: argparse.Namespace) -> dict:
    return {'chain_file':args.chain_file, 'external':_external(args),
            'ledger_files':args.epoch_ledger_file,
            'certificate_files':args.cutover_certificate_file}


def _ack(p: argparse.ArgumentParser) -> None:
    p.add_argument('--bundle-file',required=True)
    p.add_argument('--expected-bundle-sha256',required=True)
    p.add_argument('--acknowledgement-file',required=True)
    p.add_argument('--expected-acknowledgement-sha256',required=True)
    for field in b.PINS:
        p.add_argument('--expected-'+field.replace('_','-'),required=True)
    for field in ('sender-id','receiver-id','receiver-public-hex',
                  'exchange-challenge-sha256'):
        p.add_argument('--expected-'+field,required=True)


def _ack_args(args: argparse.Namespace) -> dict:
    return {'bundle_file':args.bundle_file,
            'expected_bundle_sha256':args.expected_bundle_sha256,
            'acknowledgement_file':args.acknowledgement_file,
            'expected_acknowledgement_sha256':args.expected_acknowledgement_sha256,
            'pins':{name:getattr(args,'expected_'+name) for name in b.PINS},
            'sender_id':args.expected_sender_id,
            'receiver_id':args.expected_receiver_id,
            'receiver_public_hex':args.expected_receiver_public_hex,
            'challenge_sha256':args.expected_exchange_challenge_sha256}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC306: bounded signed EC304 registrar epochs, ORIGINAL EC305 governance '
        'certificates, mandatory outside-index SHA and all-epoch spent checks; '
        'never substitutes for trusted external CAS/WORM'))
    sub=p.add_subparsers(dest='command',required=True)

    init=sub.add_parser('start',help='create immutable first signed-epoch index')
    for field in ('registry-id','governor-public-hex','initial-registrar-public-hex',
                  'initial-ledger-sha256','initial-sequence'):
        init.add_argument('--expected-'+field,required=True,
                          type=int if field=='initial-sequence' else str)
    init.add_argument('--initial-ledger-file',required=True)
    init.add_argument('--out',required=True)

    rotate=sub.add_parser('rotate',help='verify original EC305 cert and freeze old tip')
    _base(rotate)
    for field in ('new-registrar-public-hex','new-certificate-sha256',
                  'cutover-nonce-sha256','governance-decision-sha256'):
        rotate.add_argument('--expected-'+field,required=True)
    rotate.add_argument('--new-certificate-file',required=True)
    rotate.add_argument('--cutover-mode',choices=('planned','emergency_compromised'),
                        required=True)
    rotate.add_argument('--out',required=True)

    reg=sub.add_parser('register',help='sign ONE new candidate with original EC304')
    _base(reg); _ack(reg)
    reg.add_argument('--active-private-key-file',required=True)
    reg.add_argument('--out',required=True)

    commit=sub.add_parser('commit',help='verify candidate ACK and write new index; CAS external')
    _base(commit); _ack(commit)
    commit.add_argument('--candidate-ledger-file',required=True)
    commit.add_argument('--expected-candidate-ledger-sha256',required=True)
    commit.add_argument('--expected-candidate-sequence',type=int,required=True)
    commit.add_argument('--out',required=True)

    hist=sub.add_parser('verify-history',help='read-only all epoch signed ledgers and votes')
    _base(hist)

    latest=sub.add_parser('verify-latest',help='read-only all history plus latest real EC303 proof')
    _base(latest); _ack(latest)
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    try:
        if args.command=='start':
            result=e.start(
                registry_id=args.expected_registry_id,
                governor_public_hex=args.expected_governor_public_hex,
                initial_registrar_public_hex=args.expected_initial_registrar_public_hex,
                initial_ledger_file=args.initial_ledger_file,
                expected_initial_ledger_sha256=args.expected_initial_ledger_sha256,
                expected_initial_sequence=args.expected_initial_sequence,
                out=args.out)
        elif args.command=='rotate':
            result=e.rotate(**_chain_args(args),
                new_registrar_public_hex=args.expected_new_registrar_public_hex,
                new_certificate_file=args.new_certificate_file,
                expected_new_certificate_sha256=args.expected_new_certificate_sha256,
                cutover_nonce_sha256=args.expected_cutover_nonce_sha256,
                governance_decision_sha256=args.expected_governance_decision_sha256,
                cutover_mode=args.cutover_mode,out=args.out)
        elif args.command=='register':
            result=e.register(**_chain_args(args),**_ack_args(args),
                active_private_key_file=args.active_private_key_file,out=args.out)
        elif args.command=='commit':
            result=e.commit(**_chain_args(args),**_ack_args(args),
                candidate_ledger_file=args.candidate_ledger_file,
                expected_candidate_ledger_sha256=args.expected_candidate_ledger_sha256,
                expected_candidate_sequence=args.expected_candidate_sequence,
                out=args.out)
        elif args.command=='verify-history':
            result=e.verify_history(**_chain_args(args))
        elif args.command=='verify-latest':
            result=e.verify_latest(**_chain_args(args),**_ack_args(args))
        else:
            raise AssertionError('unknown command')
        print(json.dumps({
            'schema':e.RESULT_SCHEMA,'command':args.command,**result,
            'real_organizational_governance_authority_proven':False,
            'physically_independent_signer_custody_proven':False,
            'global_revocation_and_external_latest_cas_worm_proven':False,
            'original_business_provider_write_performed':False},
            sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status = exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        code = exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC306_LOCAL_OPERATION_UNAVAILABLE'
        rc = {'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({
            'schema':e.DENIAL_SCHEMA,'status':status,'reason_code':code,
            'exit_code':rc,'epoch_history_or_registration_success_claimed':False,
            'original_provider_access_performed':False},
            sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

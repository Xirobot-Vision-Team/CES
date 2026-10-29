#!/usr/bin/env python3
"""EC305 standalone offline cutover client; signing/writing are NOT console routes."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from . import rollover as r


def _base(p: argparse.ArgumentParser) -> None:
    for field in ('registry-id','retiring-registrar-public-hex',
                  'activating-registrar-public-hex','governor-public-hex',
                  'old-ledger-raw-sha256','old-ledger-sequence',
                  'cutover-nonce-sha256','governance-decision-sha256',
                  'cutover-mode'):
        p.add_argument('--expected-'+field, required=True,
                       type=int if field=='old-ledger-sequence' else str)
    p.add_argument('--old-ledger-file',required=True)


def _trust(args: argparse.Namespace) -> dict:
    return {field:getattr(args,'expected_'+field)
            for field in r.TRUST_FIELDS}


def _certificate(p: argparse.ArgumentParser) -> None:
    p.add_argument('--certificate-file',required=True)
    p.add_argument('--expected-certificate-sha256',required=True)


def _latest_ack(p: argparse.ArgumentParser) -> None:
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
            'pins':{n:getattr(args,'expected_'+n) for n in b.PINS},
            'sender_id':args.expected_sender_id,
            'receiver_id':args.expected_receiver_id,
            'receiver_public_hex':args.expected_receiver_public_hex,
            'challenge_sha256':args.expected_exchange_challenge_sha256}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC305 planned/emergency offline registrar handoff: '
        'independent governor + activating signer, frozen old EC304 history, '
        'externally pinned certificate and both latest ledgers; no global revocation.'))
    sub=p.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare',help='create unsigned owner-private cutover intent')
    _base(prep)
    prep.add_argument('--out',required=True)

    sign=sub.add_parser('sign',help='offline domain-separated role vote; no full cert')
    _base(sign)
    sign.add_argument('--intent-file',required=True)
    sign.add_argument('--expected-intent-sha256',required=True)
    sign.add_argument('--role',required=True,choices=tuple(r.DOMAINS))
    sign.add_argument('--private-key-file',required=True)
    sign.add_argument('--out',required=True)

    ass=sub.add_parser('assemble',help='verify separate signed votes and write certificate')
    _base(ass)
    ass.add_argument('--intent-file',required=True)
    ass.add_argument('--expected-intent-sha256',required=True)
    ass.add_argument('--retiring-vote-file',help='required for planned; forbidden in emergency')
    ass.add_argument('--activating-vote-file',required=True)
    ass.add_argument('--governance-vote-file',required=True)
    ass.add_argument('--out',required=True)

    vc=sub.add_parser('verify-certificate',help='read-only frozen ledger + cutover certificate')
    _base(vc); _certificate(vc)

    reg=sub.add_parser('register',help='cross-epoch spent-check + real EC304 ACK registration')
    _base(reg); _certificate(reg); _latest_ack(reg)
    reg.add_argument('--previous-new-ledger-file')
    reg.add_argument('--expected-previous-new-ledger-sha256',required=True)
    reg.add_argument('--expected-previous-new-sequence',type=int,required=True)
    reg.add_argument('--activating-private-key-file',required=True)
    reg.add_argument('--out',required=True)

    ver=sub.add_parser('verify',help='read-only full old and new signed ledgers and newest EC303')
    _base(ver); _certificate(ver); _latest_ack(ver)
    ver.add_argument('--new-ledger-file',required=True)
    ver.add_argument('--expected-new-ledger-sha256',required=True)
    ver.add_argument('--expected-new-sequence',type=int,required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    common={'trust':_trust(args),'old_ledger_file':args.old_ledger_file}
    try:
        if args.command=='prepare':
            result=r.prepare(**common,out=args.out)
        elif args.command=='sign':
            result=r.sign(**common,intent_file=args.intent_file,
                expected_intent_sha256=args.expected_intent_sha256,
                role=args.role,private_key_file=args.private_key_file,out=args.out)
        elif args.command=='assemble':
            result=r.assemble(**common,intent_file=args.intent_file,
                expected_intent_sha256=args.expected_intent_sha256,
                retiring_vote_file=args.retiring_vote_file,
                activating_vote_file=args.activating_vote_file,
                governance_vote_file=args.governance_vote_file,out=args.out)
        elif args.command=='verify-certificate':
            result=r.verify_certificate(**common,
                certificate_file=args.certificate_file,
                expected_certificate_sha256=args.expected_certificate_sha256)
        elif args.command=='register':
            result=r.register(**common,
                certificate_file=args.certificate_file,
                expected_certificate_sha256=args.expected_certificate_sha256,
                previous_new_ledger_file=args.previous_new_ledger_file,
                expected_previous_new_ledger_sha256=args.expected_previous_new_ledger_sha256,
                expected_previous_new_sequence=args.expected_previous_new_sequence,
                activating_private_key_file=args.activating_private_key_file,
                out=args.out,**_ack_args(args))
        elif args.command=='verify':
            result=r.verify(**common,
                certificate_file=args.certificate_file,
                expected_certificate_sha256=args.expected_certificate_sha256,
                new_ledger_file=args.new_ledger_file,
                expected_new_ledger_sha256=args.expected_new_ledger_sha256,
                expected_new_sequence=args.expected_new_sequence,
                **_ack_args(args))
        else:
            raise AssertionError('unreachable command')
        print(json.dumps({
            'schema':r.RESULT_SCHEMA,'command':args.command,**result,
            'external_governance_trust_and_latest_cas_worm_proven':False,
            'real_independent_key_custody_proven':False,
            'original_provider_business_write_performed':False},
            sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        code=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC305_LOCAL_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({
            'schema':r.DENIAL_SCHEMA,'status':status,
            'reason_code':code,'exit_code':rc,
            'cutover_or_registry_success_claimed':False,
            'original_provider_access_performed':False},
            sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

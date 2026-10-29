#!/usr/bin/env python3
"""EC318 offline sender/receiver signing CLI; protected unified console is verify-only."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import receipt as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC318 sender-signed offer, independently verified receiver ACK and '
        'sender countersigned confirmation of original EC317 ZIP. '
        'All historical EC316->294 signatures are replayed at each stage. '
        'No Provider/CAS/Host writes or proof of off-host custody.'))
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('sender-offer', 'receiver-ack', 'sender-confirm', 'verify'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--bundle-file', required=True)
        cmd.add_argument('--expected-bundle-sha256', required=True)
        cmd.add_argument('--chain-file', required=True,
                         help='original absolute path string, not receiver local path')
        cmd.add_argument('--expected-chain-sha256', required=True)
        cmd.add_argument('--ledger-manifest-file', required=True)
        cmd.add_argument('--expected-ledger-manifest-sha256', required=True)
        cmd.add_argument('--expected-latest-certificate-sha256', required=True)
        cmd.add_argument('--expected-latest-challenge-sha256', required=True)
        for role in ('a', 'b'):
            cmd.add_argument('--custodian-'+role+'-id', required=True)
            cmd.add_argument('--custodian-'+role+'-public-hex', required=True)
        cmd.add_argument('--sender-id', required=True)
        cmd.add_argument('--sender-public-hex', required=True)
        cmd.add_argument('--receiver-id', required=True)
        cmd.add_argument('--receiver-public-hex', required=True)
        cmd.add_argument('--sender-exchange-challenge-sha256', required=True)
        cmd.add_argument('--receiver-exchange-challenge-sha256', required=True)
        if name != 'sender-offer':
            cmd.add_argument('--offer-file', required=True)
            cmd.add_argument('--expected-offer-sha256', required=True)
        if name in ('sender-confirm','verify'):
            cmd.add_argument('--ack-file', required=True)
            cmd.add_argument('--expected-ack-sha256', required=True)
            cmd.add_argument('--sender-confirmation-challenge-sha256', required=True)
        if name == 'verify':
            cmd.add_argument('--closure-file', required=True)
            cmd.add_argument('--expected-closure-sha256', required=True)
        else:
            cmd.add_argument('--private-key-file', required=True,
                help='role-specific owner-private Ed25519 32-byte key; never returned')
            cmd.add_argument('--out', required=True,
                help='fresh exclusive 0600 JSON receipt under private 0700 parent')
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    context = dict(bundle_file=args.bundle_file,
        expected_bundle_sha256=args.expected_bundle_sha256,
        chain_file=args.chain_file,
        expected_chain_sha256=args.expected_chain_sha256,
        ledger_manifest_file=args.ledger_manifest_file,
        expected_ledger_manifest_sha256=args.expected_ledger_manifest_sha256,
        expected_latest_certificate_sha256=args.expected_latest_certificate_sha256,
        expected_latest_challenge_sha256=args.expected_latest_challenge_sha256,
        trust={key: vars(args)[key] for key in (
            'custodian_a_id','custodian_a_public_hex',
            'custodian_b_id','custodian_b_public_hex')},
        sender_id=args.sender_id, sender_public_hex=args.sender_public_hex,
        receiver_id=args.receiver_id, receiver_public_hex=args.receiver_public_hex,
        sender_exchange_challenge_sha256=args.sender_exchange_challenge_sha256,
        receiver_exchange_challenge_sha256=args.receiver_exchange_challenge_sha256)
    try:
        if args.command == 'sender-offer':
            result = r.sender_offer(private_key_file=args.private_key_file,
                                    out=args.out, **context)
        elif args.command == 'receiver-ack':
            result = r.receiver_ack(offer_file=args.offer_file,
                expected_offer_sha256=args.expected_offer_sha256,
                private_key_file=args.private_key_file, out=args.out, **context)
        elif args.command == 'sender-confirm':
            result = r.sender_confirm(offer_file=args.offer_file,
                expected_offer_sha256=args.expected_offer_sha256,
                ack_file=args.ack_file, expected_ack_sha256=args.expected_ack_sha256,
                sender_confirmation_challenge_sha256=
                    args.sender_confirmation_challenge_sha256,
                private_key_file=args.private_key_file, out=args.out, **context)
        else:
            result = r.verify(offer_file=args.offer_file,
                expected_offer_sha256=args.expected_offer_sha256,
                ack_file=args.ack_file, expected_ack_sha256=args.expected_ack_sha256,
                closure_file=args.closure_file,
                expected_closure_sha256=args.expected_closure_sha256,
                sender_confirmation_challenge_sha256=
                    args.sender_confirmation_challenge_sha256, **context)
        print(json.dumps({'schema':r.RESULT_SCHEMA,'command':args.command,**result},
            sort_keys=True, separators=(',', ':')))
        return 0
    except Exception as exc:
        status = (exc.status if isinstance(exc, (a.AnchorError,io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (a.AnchorError,io.HostError))
                  else 'EC318_BILATERAL_TRANSFER_UNAVAILABLE')
        rc = {'permission_denied':3, 'invalid_input':4, 'unavailable':5}.get(status,5)
        print(json.dumps({'schema':r.DENIAL_SCHEMA,'command':args.command,
            'status':status, 'reason_code':reason, 'exit_code':rc,
            'bilateral_signatures_and_original_replay_accepted':False,
            'physical_or_global_latest_proven':False,
            'business_writes_performed':False},sort_keys=True,separators=(',',':')))
        return rc

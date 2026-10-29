#!/usr/bin/env python3
"""EC303 recipient-only signing and untrusted-source offline receipt verification."""
from __future__ import annotations

import argparse
import json
from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from . import ack as r
from portable_bundle import bundle as b


def _add_pins(parser: argparse.ArgumentParser) -> None:
    for name in b.PINS:
        parser.add_argument('--expected-'+name.replace('_','-'),required=True)
    parser.add_argument('--bundle-file',required=True)
    parser.add_argument('--expected-bundle-sha256',required=True)
    parser.add_argument('--expected-sender-id',required=True)
    parser.add_argument('--expected-receiver-id',required=True)
    parser.add_argument('--expected-receiver-public-hex',required=True)
    parser.add_argument('--expected-exchange-challenge-sha256',required=True)


def _pins(args: argparse.Namespace) -> dict:
    return {k:getattr(args,'expected_'+k) for k in b.PINS}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC303 offline recipient receipt; independent pins and fresh off-band '
        'challenge required; signed claim is NOT proof of physical delivery.'))
    subs=p.add_subparsers(dest='command',required=True)
    issue=subs.add_parser('issue',help='sign only AFTER byte-exact EC302 private import and complete signature replay')
    _add_pins(issue)
    issue.add_argument('--imported-dir',required=True)
    issue.add_argument('--receiver-private-key-file',required=True,help='owner-private raw 32-byte Ed25519 key; NOT a PEM')
    issue.add_argument('--out',required=True,help='new exclusive acknowledgement JSON in owner-private parent, OUTSIDE imported tree')
    verify=subs.add_parser('verify',help='read-only verify independent receiver signature, pins and original signed archive')
    _add_pins(verify)
    verify.add_argument('--acknowledgement-file',required=True)
    verify.add_argument('--expected-acknowledgement-sha256',required=True,
                        help='independently pinned SHA256 of complete raw acknowledgement JSON bytes')
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    kwargs={'bundle_file':args.bundle_file,
            'expected_bundle_sha256':args.expected_bundle_sha256,
            'pins':_pins(args),
            'sender_id':args.expected_sender_id,
            'receiver_id':args.expected_receiver_id,
            'receiver_public_hex':args.expected_receiver_public_hex,
            'challenge_sha256':args.expected_exchange_challenge_sha256}
    try:
        if args.command=='issue':
            doc=r.issue_ack(**kwargs, imported_dir=args.imported_dir,
                            receiver_private_key_file=args.receiver_private_key_file,
                            out=args.out)
        else:
            doc=r.verify_ack(**kwargs,acknowledgement_file=args.acknowledgement_file,
                             expected_acknowledgement_sha256=args.expected_acknowledgement_sha256)
        print(json.dumps({'schema':r.RESULT_SCHEMA,'command':args.command,**doc,
                          'original_ec301_to_ec294_signatures_reverified':True,
                          'signer_private_key_returned':False,
                          'cross_site_transport_or_human_independence_proven':False,
                          'external_challenge_freshness_or_immutable_custody_proven':False,
                          'original_provider_inbox_or_business_write_performed':False},
                         sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        code=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC303_LOCAL_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':r.DENIAL_SCHEMA,'status':status,
                          'reason_code':code,'exit_code':rc,
                          'no_receipt_acceptance_or_business_success_claimed':True,
                          'original_provider_inbox_or_business_write_performed':False},
                         sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

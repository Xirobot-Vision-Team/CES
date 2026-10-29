#!/usr/bin/env python3
"""EC302 portable evidence export, temporary read-only verify, secure import."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import bundle as b


def _add_pins(parser: argparse.ArgumentParser) -> None:
    for flag in ('expected-a-id','expected-a-public-hex','expected-a-tip',
                 'expected-b-id','expected-b-public-hex','expected-b-tip',
                 'expected-session-tip','expected-receipt-tip'):
        parser.add_argument('--'+flag,required=True)


def _pins(args: argparse.Namespace) -> dict:
    return {k:getattr(args,'expected_'+k) for k in b.PINS}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC302 offline full evidence bundle. Never fetch network, copy keys, '
        'discover trust pins or attest real delivery.'))
    subs=p.add_subparsers(dest='command',required=True)
    export=subs.add_parser('export',help='replay EC301, bundle exactly referenced public evidence')
    _add_pins(export)
    export.add_argument('--journal-file',required=True)
    export.add_argument('--out',required=True,help='new .zip in existing private parent; never overwrite')
    for command in ('verify','import'):
        q=subs.add_parser(command,help=(
            'verify in temporary private snapshot' if command=='verify' else
            'verify ZIP and pin, materialize in NEW private directory, replay proof'))
        _add_pins(q)
        q.add_argument('--bundle-file',required=True)
        q.add_argument('--expected-bundle-sha256',required=True,
                       help='must be independently received, not copied from bundle manifest')
        if command=='import':
            q.add_argument('--dest-dir',required=True,
                           help='new non-existing directory with owner-private parent')
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    try:
        pins=_pins(args)
        if args.command=='export':
            result=b.build_bundle(args.journal_file,pins,args.out)
        else:
            result=b.verify_bundle(args.bundle_file,args.expected_bundle_sha256,pins,
                                   destination=args.dest_dir if args.command=='import' else None)
        rc=result['exit_code']
        assert rc in (0,2)
        response={'schema':b.RESULT_SCHEMA,'command':args.command,
                  **result,
                  'bundle_verification_and_complete_original_signature_replay':True,
                  'external_latest_pins_proven_immutable':False,
                  'actual_cross_machine_transfer_or_independent_humans_proven':False,
                  'private_keys_or_hmac_secrets_packed':False,
                  'production_provider_inbox_or_original_business_write_performed':False}
        print(json.dumps(response,sort_keys=True,separators=(',',':')))
        return rc
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        reason=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC302_LOCAL_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':b.DENIAL_SCHEMA,'status':status,
                          'reason_code':reason,'exit_code':rc,
                          'any_independent_custody_or_business_success_claimed':False,
                          'production_provider_inbox_or_original_business_write_performed':False},
                         sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

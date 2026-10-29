#!/usr/bin/env python3
"""EC317 independent sender export and strictly read-only receiver verify."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from . import rebinding as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC317 lossless original-SHA portable EC316/315->294 replay. No signer, '
        'CAS/Provider/Host write, original rewrite, or global latest proof.'))
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('export', 'verify'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--chain-file', required=True,
                         help='original absolute source-side path, not relocated path')
        cmd.add_argument('--expected-chain-sha256', required=True)
        cmd.add_argument('--ledger-manifest-file', required=True)
        cmd.add_argument('--expected-ledger-manifest-sha256', required=True)
        cmd.add_argument('--expected-latest-certificate-sha256', required=True)
        cmd.add_argument('--expected-latest-challenge-sha256', required=True)
        for role in ('a','b'):
            cmd.add_argument('--custodian-' + role + '-id', required=True)
            cmd.add_argument('--custodian-' + role + '-public-hex', required=True)
        if name == 'export':
            cmd.add_argument('--out', required=True,
                             help='new exclusive 0600 zip under private 0700 parent')
        else:
            cmd.add_argument('--bundle-file', required=True,
                             help='locally relocated 0600 ZIP under private 0700 parent')
            cmd.add_argument('--expected-bundle-sha256', required=True,
                             help='independently supplied entire ZIP raw SHA')
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    context = dict(
        chain_file=args.chain_file,
        expected_chain_sha256=args.expected_chain_sha256,
        ledger_manifest_file=args.ledger_manifest_file,
        expected_ledger_manifest_sha256=args.expected_ledger_manifest_sha256,
        expected_latest_certificate_sha256=args.expected_latest_certificate_sha256,
        expected_latest_challenge_sha256=args.expected_latest_challenge_sha256,
        trust={key:vars(args)[key] for key in (
            'custodian_a_id','custodian_a_public_hex',
            'custodian_b_id','custodian_b_public_hex')})
    try:
        if args.command == 'export':
            result = r.export(out=args.out, **context)
        else:
            result = r.verify(bundle_file=args.bundle_file,
                              expected_bundle_sha256=args.expected_bundle_sha256,
                              **context)
        print(json.dumps({'schema':r.RESULT_SCHEMA,'command':args.command,**result},
                         sort_keys=True,separators=(',', ':')))
        return 0
    except Exception as exc:
        status = (exc.status if isinstance(exc, (a.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                  else 'EC317_ORIGINAL_REBINDING_UNAVAILABLE')
        rc = {'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':r.DENIAL_SCHEMA,'command':args.command,
            'status':status,'reason_code':reason,'exit_code':rc,
            'original_signature_replay_accepted':False,
            'external_global_latest_or_physical_cas_proven':False,
            'external_business_writes_performed':False},
            sort_keys=True,separators=(',', ':')))
        return rc

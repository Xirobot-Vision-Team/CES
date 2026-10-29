#!/usr/bin/env python3
"""EC338 standalone offline custody signer or rigorous receiver verifier."""
from __future__ import annotations
import argparse
import json
from typing import Any

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import ceremony


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC338 four externally pinned role-separated Ed25519 offline custody '
        'statements. Signatures do not certify real physical custody/authority.'))
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('sign-receipt','verify-chain'):
        item=sub.add_parser(name,help=(
            'Create ONE local signed role claim; must independently entrust its SHA'
            if name=='sign-receipt' else
            'READ ONLY: validate all four externally SHA-pinned receipts and '
            'the complete EC337 archive/nested originals'))
        item.add_argument('--policy-file',required=True)
        item.add_argument('--expected-policy-sha256',required=True)
        item.add_argument('--bundle-file',required=True)
        for _,flag in ceremony.ROOT_MAP:
            item.add_argument('--'+flag.replace('_','-'),required=True)
        if name=='sign-receipt':
            item.add_argument('--role',required=True,choices=ceremony.ROLES)
            item.add_argument('--out',required=True)
            item.add_argument('--private-key-file',required=True)
            item.add_argument('--nonce-sha256',required=True)
            item.add_argument('--signer-reported-utc',required=True)
            item.add_argument('--prior-receipt-file',dest='prior_receipt_files',
                              action='append',default=[])
            item.add_argument('--prior-receipt-sha256',dest='prior_receipt_shas',
                              action='append',default=[])
        else:
            for role in ceremony.ROLES:
                item.add_argument('--'+role+'-receipt-file',required=True)
                item.add_argument('--expected-'+role+'-receipt-sha256',required=True)
    return p


def _denial(command: str, status: str, reason: str, code: int) -> dict[str, Any]:
    return {
        'schema':ceremony.DENIAL_SCHEMA,'command':command,
        'status':status,'reason_code':reason,'exit_code':code,
        'whole_receipt_external_sha_and_previous_raw_sha_chain_verified':False,
        'ed25519_role_scoped_independent_public_keys_verified':False,
        'declared_witness_organization_distinct_in_trusted_policy':False,
        'ec337_complete_archive_and_nested_originals_verified':False,
        'caller_must_entrust_all_twelve_raw_sha_values_outside_local_untrusted_files':True,
        'ec336_old_signed_history_must_run_separately':True,
        **{field:False for field in ceremony.FALSE_FIELDS},
    }


def main(argv: list[str] | None = None) -> int:
    args=vars(parser().parse_args(argv))
    command=args.pop('command')
    try:
        if command=='sign-receipt':
            output=ceremony.sign_receipt(**args)
        else:
            output=ceremony.verify_chain(**args)
        code=output['exit_code']
    except Exception as exc:
        status=(exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'unavailable')
        reason=(exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC338_LOCAL_OR_INHERITED_IO_UNAVAILABLE')
        code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        output=_denial(command,status,reason,code)
    print(json.dumps(output,sort_keys=True,separators=(',',':'),
                     ensure_ascii=True,allow_nan=False))
    return code

if __name__=='__main__':
    raise SystemExit(main())

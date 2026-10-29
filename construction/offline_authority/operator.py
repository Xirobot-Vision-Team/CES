#!/usr/bin/env python3
"""Isolated EC339 local issuer writer and complete read-only receiver."""
from __future__ import annotations

import argparse
import json
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor
from independent_custody import ceremony
from . import authority as a


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC339: external-issuer-signed grants and challenged status assertions. '
        'No command proves legal authority, true clock or latest revocation.'))
    sub=p.add_subparsers(dest='command',required=True)
    grant=sub.add_parser('issue-grant',help='Issuer writes one future EC338 policy grant, no overwrite')
    for k in ('out','private-key-file','role','issuer-id','grant-id',
              'transfer-id','bundle-original-raw-sha256','actor-id',
              'organization-id','subject-public-hex','issued-utc',
              'not-before-utc','not-after-utc'):
        grant.add_argument('--'+k,required=True)
    status=sub.add_parser('issue-status',help='Issuer writes challenge-bound revocation status, no overwrite')
    for k in ('out','private-key-file','role','policy-file',
              'expected-policy-sha256','authority-roster-file',
              'expected-authority-roster-sha256','grant-file','expected-grant-sha256',
              'verifier-challenge-sha256','state','as-of-utc','expires-utc'):
        status.add_argument('--'+k,required=True)
    status.add_argument('--revoked-effective-utc')
    verify=sub.add_parser('verify-authority',help='READ ONLY real EC338->EC337 plus all issuer signatures')
    for k in ('policy-file','expected-policy-sha256','bundle-file',
              *(flag.replace('_','-') for _,flag in ceremony.ROOT_MAP),
              *(v for role in a.ROLES for v in
                (role+'-receipt-file','expected-'+role+'-receipt-sha256')),
              'authority-roster-file','expected-authority-roster-sha256',
              *(v for role in a.ROLES for v in
                (role+'-grant-file','expected-'+role+'-grant-sha256')),
              *(v for role in a.ROLES for v in
                (role+'-status-file','expected-'+role+'-status-sha256')),
              'evaluation-utc','verifier-challenge-sha256'):
        verify.add_argument('--'+k,required=True)
    return p


def _denial(command: str, status: str, reason: str, code: int) -> dict[str,Any]:
    return {'schema':a.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':reason,'exit_code':code,
            'issuer_sig_and_grant_actor_role_key_bound':False,
            'signed_status_challenge_and_time_window_verified':False,
            'ec338_four_signed_receipts_verified':False,
            'ec337_complete_archive_and_nested_originals_verified':False,
            'external_custody_of_all_twenty_one_raw_sha_pins_required':True,
            'ec336_old_signed_history_must_run_separately':True,
            **{field:False for field in a.FALSE_FIELDS}}


def main(argv: list[str]|None=None) -> int:
    args=vars(parser().parse_args(argv))
    cmd=args.pop('command')
    try:
        output={'issue-grant':a.issue_grant,
                'issue-status':a.issue_status,
                'verify-authority':a.verify_authority}[cmd](**args)
        rc=output['exit_code']
    except Exception as exc:
        status=exc.status if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'unavailable'
        reason=exc.code if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'EC339_LOCAL_OR_INHERITED_IO_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        output=_denial(cmd,status,reason,rc)
    print(json.dumps(output,sort_keys=True,separators=(',',':'),
                     ensure_ascii=True,allow_nan=False))
    return rc

if __name__=='__main__':
    raise SystemExit(main())

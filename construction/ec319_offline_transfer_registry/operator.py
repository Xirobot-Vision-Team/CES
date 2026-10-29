#!/usr/bin/env python3
"""Independent EC319 registrar CLI. The unified CES console only exposes verify."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import registry as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC319 fifth-role Ed25519 offline signed original-SHA transfer registry: '
        'bootstrap / append new immutable snapshots / reverify / compare signed '
        'forks; no globally authoritative CAS, WORM, key revocation or Host write.'))
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('bootstrap')
    for field in ('registry-id','registrar-id','registrar-public-hex',
                  'registrar-epoch-challenge-sha256','bundle-file',
                  'expected-bundle-sha256','chain-file','expected-chain-sha256',
                  'ledger-manifest-file','expected-ledger-manifest-sha256',
                  'expected-latest-certificate-sha256',
                  'expected-latest-challenge-sha256',
                  'custodian-a-id','custodian-a-public-hex',
                  'custodian-b-id','custodian-b-public-hex',
                  'private-key-file','out'):
        c.add_argument('--'+field, required=True)
    for command in ('append','verify','compare'):
        c = sub.add_parser(command)
        c.add_argument('--registrar-id', required=True)
        c.add_argument('--registrar-public-hex', required=True)
        c.add_argument('--expected-genesis-raw-sha256', required=True)
        if command != 'compare':
            for field in ('registry-file','expected-registry-sha256',
                          'materials-file','expected-head-raw-sha256'):
                c.add_argument('--'+field, required=True)
        else:
            for field in ('left-file','expected-left-sha256',
                          'left-materials-file','expected-left-head-raw-sha256',
                          'right-file','expected-right-sha256',
                          'right-materials-file','expected-right-head-raw-sha256'):
                c.add_argument('--'+field, required=True)
        if command == 'append':
            for field in sorted(r.NEW_FIELDS):
                c.add_argument('--'+field.replace('_','-'), required=True)
            c.add_argument('--private-key-file', required=True)
            c.add_argument('--out', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    kwargs = vars(args).copy()
    command = kwargs.pop('command')
    if command == 'bootstrap':
        trust = {f'custodian_{role}_{field}':kwargs.pop(f'custodian_{role}_{field}')
                 for role in ('a','b') for field in ('id','public_hex')}
        kwargs['trust'] = trust
    if command == 'append':
        kwargs['new_claim_fields'] = {k:kwargs.pop(k) for k in r.NEW_FIELDS}
    try:
        action = {'bootstrap':r.bootstrap, 'append':r.append,
                  'verify':r.verify, 'compare':r.compare}[command]
        result = action(**kwargs)
        print(json.dumps({'schema':r.RESULT_SCHEMA,'command':command,**result},
            sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError,io.HostError)) else 'unavailable'
        reason = exc.code if isinstance(exc, (a.AnchorError,io.HostError)) else 'EC319_OFFLINE_REGISTRAR_UNAVAILABLE'
        rc = {'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':r.DENIAL_SCHEMA,'command':command,
            'status':status,'reason_code':reason,'exit_code':rc,
            'registrar_signature_or_history_accepted':False,
            'global_latest_or_external_immutable_cas_proven':False,
            'business_writes_performed':False},sort_keys=True,separators=(',',':')))
        return rc

#!/usr/bin/env python3
"""Standalone offline EC304 registrar; registration is never a console route."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from . import registry as r


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument('--bundle-file',required=True)
    p.add_argument('--expected-bundle-sha256',required=True)
    p.add_argument('--acknowledgement-file',required=True)
    p.add_argument('--expected-acknowledgement-sha256',required=True)
    for name in b.PINS:
        p.add_argument('--expected-'+name.replace('_','-'),required=True)
    for name in ('sender-id','receiver-id','receiver-public-hex',
                 'exchange-challenge-sha256','registry-id','registrar-public-hex'):
        p.add_argument('--expected-'+name,required=True)


def _context(args: argparse.Namespace) -> dict:
    return {'bundle_file':args.bundle_file,
            'expected_bundle_sha256':args.expected_bundle_sha256,
            'acknowledgement_file':args.acknowledgement_file,
            'expected_acknowledgement_sha256':args.expected_acknowledgement_sha256,
            'pins':{n:getattr(args,'expected_'+n) for n in b.PINS},
            'sender_id':args.expected_sender_id,
            'receiver_id':args.expected_receiver_id,
            'receiver_public_hex':args.expected_receiver_public_hex,
            'challenge_sha256':args.expected_exchange_challenge_sha256,
            'registry_id':args.expected_registry_id,
            'registrar_public_hex':args.expected_registrar_public_hex}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC304 signed one-time challenge registry; ALWAYS pin prior/latest '
        'raw ledger SHA + sequence independently; no global CAS/WORM claims.'))
    sub=p.add_subparsers(dest='command',required=True)
    register=sub.add_parser('register',help='verify genuine EC303 ACK and sign new owner-private ledger snapshot')
    _common(register)
    register.add_argument('--previous-ledger-file',help='omit only for externally authorized empty genesis')
    register.add_argument('--expected-previous-ledger-sha256',required=True)
    register.add_argument('--expected-previous-sequence',required=True,type=int)
    register.add_argument('--registrar-private-key-file',required=True,
                          help='owner-private raw 32-byte FOURTH role Ed25519 key')
    register.add_argument('--out',required=True,help='new O_EXCL 0600 ledger snapshot; never overwrite')
    verify=sub.add_parser('verify',help='read-only full registrar history + exact newest original EC303 ACK')
    _common(verify)
    verify.add_argument('--ledger-file',required=True)
    verify.add_argument('--expected-ledger-sha256',required=True)
    verify.add_argument('--expected-sequence',required=True,type=int)
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    context=_context(args)
    try:
        if args.command=='register':
            result=r.register(**context,
                previous_ledger_file=args.previous_ledger_file,
                expected_previous_ledger_sha256=args.expected_previous_ledger_sha256,
                expected_previous_sequence=args.expected_previous_sequence,
                registrar_private_key_file=args.registrar_private_key_file,
                out=args.out)
        else:
            result=r.verify(**context,ledger_file=args.ledger_file,
                expected_ledger_sha256=args.expected_ledger_sha256,
                expected_sequence=args.expected_sequence)
        print(json.dumps({'schema':r.RESULT_SCHEMA, 'command':args.command,**result,
                          'complete_registrar_history_signatures_verified':True,
                          'latest_original_ec303_to_ec294_signatures_reverified':True,
                          'older_zip_and_ack_material_replayed':False,
                          'external_latest_compare_and_swap_or_worm_proven':False,
                          'registrar_key_custody_or_challenge_issuance_proven':False,
                          'business_send_or_original_provider_access_performed':False},
                         sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        code=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC304_LOCAL_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':r.DENIAL_SCHEMA,'status':status,
                          'reason_code':code,'exit_code':rc,
                          'ledger_or_business_success_claimed':False,
                          'original_provider_access_performed':False},
                         sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

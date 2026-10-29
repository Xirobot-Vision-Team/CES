#!/usr/bin/env python3
"""EC351 standalone offline import. Read-only; no signer, network or output file."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec350_tsa_timestamp import operator as old_cli
from . import provenance as core

SCALARS=old_cli.SCALARS
NEW_REPEATS=(
    ('authority_channel_ids','authority_channel_id'),
    ('authority_statement_files','authority_statement_file'),
    ('authority_statement_shas','expected_authority_statement_sha256'),
    ('authority_key_files','authority_public_key_file'),
    ('authority_key_shas','expected_authority_public_key_sha256'),
    ('authority_source_files','authority_source_document_file'),
    ('authority_source_shas','expected_authority_source_document_sha256'),
    ('ocsp_files','ocsp_response_file'),
    ('ocsp_shas','expected_ocsp_response_sha256'),
    ('ocsp_expected_nonces','ocsp_precommitted_request_nonce_hex'),
)


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC351 bounded offline source provenance and signed OCSP/CRL comparison')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('derive-provenance-handoff','audit-provenance-evidence'):
        s=sub.add_parser(name,help='actually replay complete EC350 through EC337 signed originals')
        old_cli.old_cli.old_cli.old_cli._scalars(s,SCALARS)
        old_cli.old_cli.old_cli.old_cli._repeats(s,old_cli.old_cli.old_cli.PARENT_REPEATS)
        for k in old_cli.old_cli.old_cli.EXTRA_REPEATS:
            s.add_argument('--'+old_cli.old_cli.old_cli.FLAGS[k].replace('_','-'),
                           action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for field,flag in old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for field,flag in old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        if name=='audit-provenance-evidence':
            s.add_argument('--provenance-evaluation-utc',required=True)
            for field,flag in NEW_REPEATS:
                s.add_argument('--'+flag.replace('_','-'),dest=field,
                               action='append',default=[])
    return p


def denial(command:str,exc:Exception)->dict:
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:status,code='unavailable','EC351_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{'permission_denied':3,
                'invalid_input':4,'unavailable':5}.get(status,5),
            'ec350_to_ec337_actual_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*old_cli.old_cli.old_cli.PARENT_REPEATS,
              *old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        doc=(core.checklist(**args) if command=='derive-provenance-handoff'
             else core.audit(**args))
    except Exception as exc:
        doc=denial(command,exc)
    print(json.dumps(doc,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':
    raise SystemExit(main())

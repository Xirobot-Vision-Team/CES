#!/usr/bin/env python3
"""EC348 isolated, no-key imported Ed25519 external custodian audit."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from readback_challenge import operator as old_cli
from . import custody as c

SCALARS = (*old_cli.SCALARS, 'readback_evaluation_utc')
PARENT_REPEATS = (*old_cli.PARENT_REPEATS, *old_cli.AUDIT_REPEATS)
EXTRA_SCALARS = ('external_evaluation_utc', 'keeper_directory_file',
                 'expected_keeper_directory_sha256',
                 'expected_directory_root_public_hex')
EXTRA_REPEATS = (
    'keeper_receipt_files', 'keeper_receipt_shas',
    'presented_keeper_ids', 'presented_ledger_files',
    'presented_ledger_shas', 'presented_copy_snapshot_files',
    'presented_copy_ack_set_files'
)
FLAGS = {**{k: old_cli.FLAGS[k] for k in PARENT_REPEATS},
    'keeper_receipt_files':'keeper_receipt_file',
    'keeper_receipt_shas':'expected_keeper_receipt_sha256',
    'presented_keeper_ids':'presented_keeper_id',
    'presented_ledger_files':'presented_ledger_file',
    'presented_ledger_shas':'expected_presented_ledger_sha256',
    'presented_copy_snapshot_files':'presented_copy_snapshot_file',
    'presented_copy_ack_set_files':'presented_copy_ack_set_file'}


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC348 externally furnished signed SHA inventories; NO external custody proof')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('derive-checklist','audit-external-custody'):
        s=sub.add_parser(name,help='read-only original replay and public checklist' if name=='derive-checklist' else 'read-only external SHA-pinned signer/expiry/fork/retest audit')
        old_cli._scalars(s,SCALARS)
        old_cli._repeats(s,PARENT_REPEATS)
        if name=='audit-external-custody':
            old_cli._scalars(s,EXTRA_SCALARS)
            for k in EXTRA_REPEATS:
                s.add_argument('--'+FLAGS[k].replace('_','-'),action='append',default=[])
    return p


def denial(command: str, exc: Exception) -> dict:
    if isinstance(exc,(anchor.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:
        status,code='unavailable','EC348_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':c.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':rc,
            'ec347_full_signed_source_and_readback_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in c.NEGATIVES}}


def main(argv=None) -> int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in EXTRA_REPEATS:
        args[k]=args.pop(FLAGS[k]) if FLAGS[k] in args else args[k]
    # All old flags have already been assigned their old_cli dest names.
    for k in PARENT_REPEATS:
        if FLAGS[k] != k and FLAGS[k] in args:
            args[k]=args.pop(FLAGS[k])
    try:
        result=(c.derive_checklist if command=='derive-checklist' else
                c.audit_external_custody)(**args)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())

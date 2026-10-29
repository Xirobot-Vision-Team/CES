#!/usr/bin/env python3
"""EC371 fixed read-only original-archive CLI, no private signing/network."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from ec370_publication_accountability import accountability as inherited
from . import archive as core


def parser():
    p=argparse.ArgumentParser(description='EC371 receiver-only historical directory original SHA/signature verifier; always exit2 unresolved')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('audit-historical-directory-archive','derive-historical-directory-inventory'):
        q=sub.add_parser(command,help='live EC370 replay, caller-pinned historical originals, never prove complete old history')
        fields=(*inherited.prior.SCALARS,*inherited.NEW_SCALARS,*core.NEW_SCALARS)
        if command=='audit-historical-directory-archive':fields+=core.AUDIT_ONLY
        for name in fields:
            q.add_argument('--'+name.replace('_','-'),required=True,
                           **({'type':int} if name.startswith('minimum_') else {}))
        for name,flag in (*inherited.prior.REPEATS,*inherited.NEW_REPEATS,
                          *core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
                           **({'required':True} if name not in
                                  ('historical_dual_handoff_shas',) else {'default':[]}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code.upper()
    else:status,code='unavailable','EC371_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{
                'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'offline_unresolved_exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec365_to_ec337_full_parent_original_replay_performed':False,
            **{x:False for x in core.NEGATIVES}}


def main(argv=None):
    inp=vars(parser().parse_args(argv));command=inp.pop('command')
    inp['expected_source_attestation_head_shas']=[
        None if s=='none' else s for s in inp['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**inp) if
             command=='derive-historical-directory-inventory' else core.audit(**inp))
    except Exception as exc:doc=denial(command,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())

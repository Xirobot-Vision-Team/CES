#!/usr/bin/env python3
"""EC344 standalone owner-private declaration/signing and read-only comparison."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec343_hold_receipts import operator as previous_cli
from . import visibility as v

ROSTER=('roster_file','expected_roster_sha256')
DIRECTORY=('directory_file','expected_directory_sha256')
CHECKPOINT=('checkpoint_file','expected_checkpoint_sha256')
VERIFY=(*previous_cli.VERIFY,*DIRECTORY,*CHECKPOINT,'anchor_item_id')


def add(p,keys,required=True):
    for key in keys:
        p.add_argument('--'+key.replace('_','-'),required=required,
            **({'type':int} if key in
               ('expected_current_root_epoch','minimum_acceptable_epoch') else {}))


def parser():
    p=argparse.ArgumentParser(description='EC344 signed bounded visibility sample: '
        'offline-only; no global recipient census, missing-file proof, winner or remote write')
    subs=p.add_subparsers(dest='command',required=True)
    x=subs.add_parser('assemble-directory')
    add(x,('out',*ROSTER,'round_nonce_sha256'))
    for key in ('receiver_id','receiver_public_hex','receiver_organization_id'):
        x.add_argument('--'+key.replace('_','-'),action='append',default=[])
    x=subs.add_parser('assemble-checkpoint')
    add(x,('out',*ROSTER,*DIRECTORY))
    for key in ('item_id','slot_id','snapshot_file','expected_snapshot_sha256',
                'ack_set_file','expected_ack_set_sha256'):
        x.add_argument('--'+key.replace('_','-'),action='append',default=[])
    x=subs.add_parser('sign-view')
    add(x,('out','private_key_file',*ROSTER,*DIRECTORY,*CHECKPOINT,
           'view_nonce_sha256','reported_utc'))
    x.add_argument('--observed-item-id',action='append',default=[])
    x=subs.add_parser('audit-views')
    add(x,VERIFY)
    x.add_argument('--view-file',action='append',default=[])
    x.add_argument('--expected-view-sha256',action='append',default=[])
    x.add_argument('--presented-item-id',action='append',default=[])
    return p


def denial(command:str,ex:Exception)->dict:
    if isinstance(ex,(anchor.AnchorError,io.HostError)):
        status,reason=ex.status,ex.code
    else:
        status,reason='unavailable','EC344_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':v.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':reason,'exit_code':code,
            'true_ec342_signed_fork_and_old_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in v.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv)); command=args.pop('command')
    if command=='assemble-directory':
        ids=args.pop('receiver_id')
        pubs=args.pop('receiver_public_hex')
        orgs=args.pop('receiver_organization_id')
        if len(ids)!=len(pubs) or len(ids)!=len(orgs):
            print(json.dumps(denial(command,anchor.AnchorError(
                'EC344_DIRECTORY_RECEIVER_TRIPLETS_REQUIRED','invalid_input')),
                sort_keys=True,separators=(',',':')))
            return 4
        args['receivers']=[{'signer_id':a,'public_hex':b,'organization_id':c}
                           for a,b,c in zip(ids,pubs,orgs,strict=True)]
    elif command=='assemble-checkpoint':
        names=('item_id','slot_id','snapshot_file','expected_snapshot_sha256',
               'ack_set_file','expected_ack_set_sha256')
        cols=[args.pop(k) for k in names]
        if any(len(c)!=len(cols[0]) for c in cols):
            print(json.dumps(denial(command,anchor.AnchorError(
                'EC344_CHECKPOINT_ANNOUNCEMENT_SEXTUPLETS_REQUIRED','invalid_input')),
                sort_keys=True,separators=(',',':')))
            return 4
        args['announcements']=[dict(zip(names,x,strict=True)) for x in zip(*cols)]
    elif command=='sign-view':
        args['observed_item_ids']=args.pop('observed_item_id')
    elif command=='audit-views':
        args['view_files']=args.pop('view_file')
        args['view_shas']=args.pop('expected_view_sha256')
        args['presented_item_ids']=args.pop('presented_item_id')
    fn={'assemble-directory':v.assemble_directory,
        'assemble-checkpoint':v.assemble_checkpoint,
        'sign-view':v.sign_view,'audit-views':v.audit_views}[command]
    try:
        result=fn(**args)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())

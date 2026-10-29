#!/usr/bin/env python3
"""EC343 role-private signer/assembler and independent read-only timeline."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import timeline as t

ROSTER=('roster_file','expected_roster_sha256')
BASE=('governance_roster_file','hold_file','review_manifest_file','approval_file')
SNAPSHOT=('snapshot_file','expected_snapshot_sha256')
PREV=('previous_snapshot_file','expected_previous_snapshot_sha256',
      'previous_ack_set_file','expected_previous_ack_set_sha256')
CHANGE=('change_file','expected_change_sha256')
RECEIPTS=('receipt_file','expected_receipt_sha256')
VERIFY=(*t.oldhold.LINEAGE_KEYS,
        'governance_roster_file','expected_governance_roster_sha256',
        'review_manifest_file','expected_review_manifest_sha256',
        'approval_file','expected_approval_sha256','hold_evaluation_utc',
        *ROSTER,'head_snapshot_file','expected_head_snapshot_sha256',
        'head_ack_set_file','expected_head_ack_set_sha256','timeline_evaluation_utc')
OPTIONAL=('competing_snapshot_file','expected_competing_snapshot_sha256',
          'competing_ack_set_file','expected_competing_ack_set_sha256')


def add(p,keys,required=True):
    for key in keys:
        p.add_argument('--'+key.replace('_','-'),required=required,
             **({'type':int} if key in ('expected_current_root_epoch',
                                        'minimum_acceptable_epoch') else {}))


def parser():
    p=argparse.ArgumentParser(description='EC343 offline signed receiver receipts '
       'and conflict-preserving requested revisions. No remote freeze, release or winner.')
    sub=p.add_subparsers(dest='command',required=True)
    x=sub.add_parser('assemble-base');add(x,('out',*ROSTER,*BASE))
    x=sub.add_parser('sign-ack');add(x,('out','private_key_file',*ROSTER,
                                        *SNAPSHOT,'received_utc'))
    x=sub.add_parser('assemble-ack-set');add(x,('out',*ROSTER,*SNAPSHOT))
    x.add_argument('--receipt-file',action='append',default=[])
    x.add_argument('--expected-receipt-sha256',action='append',default=[])
    x=sub.add_parser('issue-change');add(x,('out','private_key_file',*ROSTER,*PREV,
         'change_summary_sha256','change_nonce_sha256','issued_utc'))
    x.add_argument('--request-kind',required=True,choices=t.ACTIONS)
    x.add_argument('--requested-successor-case-id',default='',
        help='Required to name a different case for request_supersession; omit otherwise')
    x=sub.add_parser('approve-change');add(x,('out','private_key_file',*ROSTER,
         *PREV,*CHANGE,'approval_reported_utc'))
    x=sub.add_parser('assemble-snapshot');add(x,('out',*ROSTER,*PREV,*CHANGE,
                           'change_approval_file','expected_change_approval_sha256'))
    x=sub.add_parser('verify-timeline');add(x,VERIFY);add(x,OPTIONAL,False)
    return p


def denial(command:str,ex:Exception)->dict:
    if isinstance(ex,(anchor.AnchorError,io.HostError)):
        status,reason=ex.status,ex.code
    else:
        status,reason='unavailable','EC343_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':t.DENIAL_SCHEMA,'command':command,'status':status,
        'reason_code':reason,'exit_code':code,
        'true_ec342_sibling_fork_and_old_originals_replayed':False,
        'offline_unresolved_exit_code':2,
        **{k:False for k in t.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    if command=='assemble-ack-set':
        args['receipt_files']=args.pop('receipt_file')
        args['receipt_shas']=args.pop('expected_receipt_sha256')
    fn={'assemble-base':t.assemble_base,'sign-ack':t.sign_ack,
        'assemble-ack-set':t.assemble_ack_set,'issue-change':t.issue_change,
        'approve-change':t.approve_change,'assemble-snapshot':t.assemble_snapshot,
        'verify-timeline':t.verify_timeline}[command]
    try:
        result=fn(**args)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())

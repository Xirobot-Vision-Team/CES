#!/usr/bin/env python3
"""EC345 standalone signer and fixed read-only audit CLI. All writes are explicit."""
from __future__ import annotations
import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from receiver_visibility import operator as prev
from . import challenge as c

COMMON=(*prev.ROSTER,*prev.DIRECTORY,*prev.CHECKPOINT)
BASELINE=prev.VERIFY
COLLECTIONS={
    'view_files':'view_file','view_shas':'expected_view_sha256',
    'presented_item_ids':'presented_item_id',
    'challenge_files':'challenge_file',
    'challenge_shas':'expected_challenge_sha256',
    'response_files':'response_file',
    'response_shas':'expected_response_sha256',
    'disclosed_item_ids':'disclosed_item_id',
    'baseline_presented_item_ids':'baseline_presented_item_id',
    'audience_receiver_ids':'audience_receiver_id'}


def add(p,keys,required=True):
    for key in keys:
        p.add_argument('--'+key.replace('_','-'),required=required,
            **({'type':int} if key in (
               'expected_current_root_epoch','minimum_acceptable_epoch',
               'attempt_number') else {}))


def repeated(p,keys):
    for key in keys:
        p.add_argument('--'+COLLECTIONS[key].replace('_','-'),
                       action='append',default=[])


def parser():
    p=argparse.ArgumentParser(description='EC345 bounded real Ed25519 challenge/'
        'response with independently SHA-pinned files: NOT global delivery or absence')
    sub=p.add_subparsers(dest='command',required=True)
    x=sub.add_parser('issue-challenge')
    add(x,('out','private_key_file',*COMMON,'anchor_item_id','item_id',
           'attempt_number','challenge_nonce_sha256','issued_utc'))
    add(x,('previous_challenge_file','expected_previous_challenge_sha256'),
        required=False)
    repeated(x,('view_files','view_shas','baseline_presented_item_ids',
                'audience_receiver_ids'))
    x=sub.add_parser('sign-response')
    add(x,('out','private_key_file',*COMMON,'challenge_file',
           'expected_challenge_sha256','response_kind','response_nonce_sha256',
           'reported_utc'))
    x=sub.add_parser('audit-disclosures')
    add(x,(*BASELINE,'disclosure_evaluation_utc'))
    repeated(x,('view_files','view_shas','presented_item_ids',
                'challenge_files','challenge_shas','response_files',
                'response_shas','disclosed_item_ids'))
    return p


def denial(command:str,exc:Exception)->dict:
    if isinstance(exc,(anchor.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC345_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':c.DENIAL_SCHEMA,'command':command,
            'status':status,'reason_code':reason,'exit_code':code,
            'true_ec342_signed_fork_and_old_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in c.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv)); command=args.pop('command')
    for key,flag in COLLECTIONS.items():
        if flag in args: # no internal key spellings collide with public switches
            args[key]=args.pop(flag)
    fn={'issue-challenge':c.issue_challenge,
        'sign-response':c.sign_response,
        'audit-disclosures':c.audit_disclosures}[command]
    try:
        result=fn(**args)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']


if __name__=='__main__':
    raise SystemExit(main())

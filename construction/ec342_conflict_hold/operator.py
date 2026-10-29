#!/usr/bin/env python3
"""EC342 standalone offline role-separated signer and read-only hold auditor."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import hold

GOV=('governance_roster_file','expected_governance_roster_sha256')
LINEAGE=hold.LINEAGE_KEYS
HOLD=('hold_file','expected_hold_sha256')
REVIEW=('review_manifest_file','expected_review_manifest_sha256')
VERIFY=(*LINEAGE,*GOV,*REVIEW,'hold_evaluation_utc')


def _add(parser,keys,*,required=True):
    for key in keys:
        parser.add_argument('--'+key.replace('_','-'),required=required,
            **({'type':int} if key in ('expected_current_root_epoch',
                                        'minimum_acceptable_epoch') else {}))


def parser():
    p=argparse.ArgumentParser(description=(
      'EC342 offline-only signed sibling hold: role-separated one-key candidates, '
      'or externally pinned read-only evidence replay. Never remote freeze/winner.'))
    commands=p.add_subparsers(dest='command',required=True)
    s=commands.add_parser('issue-hold',help='one initiator private key; verified EC341 signed fork')
    _add(s,('out','private_key_file',*GOV,*LINEAGE,
            'hold_challenge_sha256','issued_utc','expires_utc'))
    s=commands.add_parser('sign-review',help='one independent reviewer private key')
    _add(s,('out','private_key_file',*GOV,*HOLD,'reviewer_reported_utc'))
    s.add_argument('--decision',choices=('support_hold','object_to_hold'),required=True)
    s=commands.add_parser('assemble-review',help='exclusive canonical reviewed witness index')
    _add(s,('out',*GOV,*HOLD))
    s.add_argument('--attestation-file',action='append',default=[])
    s.add_argument('--expected-attestation-sha256',action='append',default=[])
    s=commands.add_parser('issue-approval',help='one separate approver key signs exact witnessed review set')
    _add(s,('out','private_key_file',*GOV,*REVIEW,'approval_reported_utc'))
    s=commands.add_parser('verify-hold',help='READ ONLY actual signed EC341 fork and hold/quorum')
    _add(s,VERIFY)
    _add(s,('approval_file','expected_approval_sha256'),required=False)
    return p


def _denial(command,exc):
    if isinstance(exc,(anchor.AnchorError,io.HostError)):
        status=exc.status;reason=exc.code
    else:
        status='unavailable';reason='EC342_LOCAL_OR_INHERITED_IO_UNAVAILABLE'
    exit_code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':hold.DENIAL_SCHEMA,'command':command,
        'status':status,'reason_code':reason,'exit_code':exit_code,
        'signed_sibling_fork_and_historical_full_replay_verified':False,
        'initiator_signature_verified':False,
        'reviewer_signatures_verified':False,
        'separate_approver_signature_verified':False,
        'offline_unresolved_exit_code':2,
        **{key:False for key in hold.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv))
    command=args.pop('command')
    if command=='assemble-review':
        args['attestation_files']=args.pop('attestation_file')
        args['attestation_shas']=args.pop('expected_attestation_sha256')
    callback={'issue-hold':hold.issue_hold,
        'sign-review':hold.sign_review,
        'assemble-review':hold.assemble_review,
        'issue-approval':hold.issue_approval,
        'verify-hold':hold.verify_hold}[command]
    try:
        result=callback(**args)
    except Exception as exc:
        result=_denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']


if __name__=='__main__':
    raise SystemExit(main())

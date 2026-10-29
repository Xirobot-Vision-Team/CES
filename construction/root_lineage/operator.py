#!/usr/bin/env python3
"""EC341 isolated bounded issuer lineage CLI; only verify-lineage is unified."""
from __future__ import annotations
import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from issuer_root_rotation import rotation as one
from . import lineage as r

CONTEXT=('policy_file','expected_policy_sha256')
PAIR=('predecessor_roster_file','expected_predecessor_roster_sha256',
      'successor_roster_file','expected_successor_roster_sha256')
EDGE_KEYS=tuple(k for side,role in one.EDGE_KEYS for k in
   (side+'_'+role+'_edge_file','expected_'+side+'_'+role+'_edge_sha256'))
VERIFY_KEYS=('manifest_file','expected_manifest_sha256',
             'expected_current_root_sha256','expected_current_root_epoch',
             'minimum_acceptable_epoch','current_root_evaluation_utc')


def _add(p,keys):
    for k in keys:
        kw={'type':int} if k in ('expected_current_root_epoch',
                                'minimum_acceptable_epoch') else {}
        p.add_argument('--'+k.replace('_','-'),required=True,**kw)


def parser():
    p=argparse.ArgumentParser(description=(
      'EC341 bounded true Ed25519 lineage; untrusted local candidates and '
      'read-only manifest-pinned receiver; never legal/global latest trust.'))
    s=p.add_subparsers(dest='command',required=True)
    q=s.add_parser('create-roster',help='owner-private candidate epoch>=3 roster')
    _add(q,('out',*CONTEXT,PAIR[0],PAIR[1],
            'issuer_config_file','expected_issuer_config_sha256',
            'rotation_id','rotation_nonce_sha256','effective_utc'))
    q=s.add_parser('sign-edge',help='sign exactly one role and side with one key')
    _add(q,('out','private_key_file','side','role',*CONTEXT,*PAIR))
    q=s.add_parser('issue-observation',help='sign eight pinned edges and challenge')
    _add(q,('out','private_key_file',*CONTEXT,*PAIR,
            'observer_roster_file','expected_observer_roster_sha256',
            *EDGE_KEYS,'verifier_challenge_sha256','observed_utc','expires_utc'))
    q=s.add_parser('verify-lineage',help='READ ONLY historical replay + 1..7 hops + signed forks')
    _add(q,VERIFY_KEYS)
    return p


def _denial(cmd,exc):
    status=exc.status if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'unavailable'
    reason=exc.code if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'EC341_LOCAL_OR_INHERITED_IO_UNAVAILABLE'
    code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
    return {'schema':r.DENIAL_SCHEMA,'command':cmd,'exit_code':code,
            'status':status,'reason_code':reason,
            'historical_ec340_to_ec337_real_original_replay_verified':False,
            'old_grants_not_new_epoch_authorizations':True,
            'only_supplied_externally_pinned_forks_examined':True,
            **{k:False for k in r.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv))
    cmd=args.pop('command')
    try:
        if cmd=='issue-observation':
            files={};shas={}
            for side,role in one.EDGE_KEYS:
                files[(side,role)]=args.pop(side+'_'+role+'_edge_file')
                shas[(side,role)]=args.pop('expected_'+side+'_'+role+'_edge_sha256')
            args['edge_files']=files;args['edge_shas']=shas
        fun={'create-roster':r.create_roster,'sign-edge':r.sign_edge,
             'issue-observation':r.issue_observation,
             'verify-lineage':r.verify_lineage}[cmd]
        result=fun(**args)
    except Exception as exc:
        result=_denial(cmd,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     separators=(',',':'),allow_nan=False))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())

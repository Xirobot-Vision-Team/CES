#!/usr/bin/env python3
"""EC340 candidate roster/edge/witness tools and independent receiver auditor."""
from __future__ import annotations

import argparse
import json
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_authority import authority as old
from . import rotation as r

CONTEXT_KEYS = ('policy_file','expected_policy_sha256',
                'authority_roster_file','expected_authority_roster_sha256')
SUCCESSOR_KEYS = ('successor_roster_file','expected_successor_roster_sha256')
OBSERVER_KEYS = ('observer_roster_file','expected_observer_roster_sha256')
EDGE_ARG_KEYS = tuple(x for side,role in r.EDGE_KEYS for x in (
    side+'_'+role+'_edge_file','expected_'+side+'_'+role+'_edge_sha256'))
BASE_KEYS = ('policy_file','expected_policy_sha256','bundle_file',
    'expected_bundle_sha256','expected_first_hop_plan_sha256',
    'expected_closure_sha256','expected_map_sha256','expected_handoff_sha256',
    'left_expected_manifest_sha256','right_expected_manifest_sha256',
    *(v for role in r.ROLES for v in
      (role+'_receipt_file','expected_'+role+'_receipt_sha256')),
    'authority_roster_file','expected_authority_roster_sha256',
    *(v for role in r.ROLES for v in
      (role+'_grant_file','expected_'+role+'_grant_sha256')),
    *(v for role in r.ROLES for v in
      (role+'_status_file','expected_'+role+'_status_sha256')),
    'evaluation_utc','verifier_challenge_sha256')
VERIFY_KEYS = (*BASE_KEYS,*SUCCESSOR_KEYS,'expected_current_root_sha256',
               'expected_current_root_epoch',*OBSERVER_KEYS,
               'root_observation_file','expected_root_observation_sha256',
               *EDGE_ARG_KEYS,'root_evaluation_utc')


def _add(p: argparse.ArgumentParser, keys: tuple[str,...]) -> None:
    for key in keys:
        kw={'type':int} if key=='expected_current_root_epoch' else {}
        p.add_argument('--'+key.replace('_','-'),required=True,**kw)


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
       'EC340 ONE-HOP root rotation. Local original signatures are not '
       'legal issuer authorization, trusted time, or global latest epoch.'))
    subs=p.add_subparsers(dest='command',required=True)
    q=subs.add_parser('create-roster',help='Create only a candidate successor root, no key')
    _add(q,('out',*CONTEXT_KEYS,'issuer_config_file',
            'expected_issuer_config_sha256','rotation_id',
            'rotation_nonce_sha256','effective_utc'))
    q=subs.add_parser('sign-edge',help='One genuine role/side signer, private O_EXCL')
    _add(q,('out','private_key_file','side','role',*CONTEXT_KEYS,*SUCCESSOR_KEYS))
    q=subs.add_parser('issue-observation',help='Independent observer signs retired/active claim')
    _add(q,('out','private_key_file',*CONTEXT_KEYS,*SUCCESSOR_KEYS,
            *OBSERVER_KEYS,*EDGE_ARG_KEYS,'verifier_challenge_sha256',
            'observed_utc','expires_utc'))
    q=subs.add_parser('verify-rotation',help='READ ONLY full EC339->337 plus eight edges and observer')
    _add(q,VERIFY_KEYS)
    return p


def _edges(kwargs: dict) -> tuple[dict,dict]:
    paths={};pins={}
    for side,role in r.EDGE_KEYS:
        paths[(side,role)]=kwargs.pop(side+'_'+role+'_edge_file')
        pins[(side,role)]=kwargs.pop('expected_'+side+'_'+role+'_edge_sha256')
    return paths,pins


def _denial(command: str, code: int, status: str, reason: str) -> dict[str,Any]:
    return {'schema':r.DENIAL_SCHEMA,'command':command,'exit_code':code,
            'status':status,'reason_code':reason,
            'eight_separate_old_new_ed25519_signatures_verified':False,
            'independent_observer_challenged_signed_retirement_verified':False,
            'root_epoch_and_current_sha_external_rollback_floor_checked':False,
            'historical_ec339_to_ec337_original_full_replay_verified':False,
            'historical_ec339_not_accepted_as_new_epoch_authorization':True,
            'new_eleven_original_sha_pins_plus_21_old_sha_required':True,
            **{f:False for f in r.NEGATIVES}}


def main(argv: list[str]|None=None) -> int:
    args=vars(parser().parse_args(argv))
    cmd=args.pop('command')
    try:
        if cmd in ('issue-observation','verify-rotation'):
            args['edge_files'],args['edge_shas']=_edges(args)
        if cmd=='verify-rotation':
            old_base={key:args.pop(key) for key in BASE_KEYS if key not in
                    (*CONTEXT_KEYS,'verifier_challenge_sha256')}
            result=r.verify_rotation(**args,**old_base)
        else:
            result={'create-roster':r.create_successor_roster,
                    'sign-edge':r.sign_edge,
                    'issue-observation':r.issue_observation}[cmd](**args)
        code=result['exit_code']
    except Exception as exc:
        status=exc.status if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'unavailable'
        reason=exc.code if isinstance(exc,(anchor.AnchorError,io.HostError)) else 'EC340_LOCAL_OR_INHERITED_IO_UNAVAILABLE'
        code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        result=_denial(cmd,code,status,reason)
    print(json.dumps(result,ensure_ascii=True,allow_nan=False,sort_keys=True,
                     separators=(',',':')))
    return code

if __name__=='__main__':
    raise SystemExit(main())

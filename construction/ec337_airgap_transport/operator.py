#!/usr/bin/env python3
"""EC337 standalone offline transfer. Install is explicitly authorized ONLY here."""
from __future__ import annotations
import argparse
import json
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import transport


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC337 private, unsigned, whole-original airgap transport. '
        'Never treats its self-reported SHA as outside custody.'))
    subs=p.add_subparsers(dest='command',required=True)
    for command in ('create-bundle','inspect-bundle','install-bundle'):
        a=subs.add_parser(command,help={
            'create-bundle':'SOURCE only: make owner-private non-overwriting archive',
            'inspect-bundle':'RECEIVER read-only whole archive and all member SHA audit',
            'install-bundle':'RECEIVER explicitly install no-overwrite originals and controls',
        }[command])
        if command=='create-bundle':
            a.add_argument('--out',required=True)
            for k in ('first-hop-plan-file','closure-file','map-file'):
                a.add_argument('--'+k,required=True)
        else:
            a.add_argument('--bundle-file',required=True)
            a.add_argument('--expected-bundle-sha256',required=True)
        for k in ('expected-first-hop-plan-sha256','expected-closure-sha256',
                  'expected-map-sha256','expected-handoff-sha256',
                  'left-expected-manifest-sha256','right-expected-manifest-sha256'):
            a.add_argument('--'+k,required=True)
        if command=='install-bundle':
            a.add_argument('--control-root',required=True)
            a.add_argument('--destination-root',required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    options=vars(parser().parse_args(argv))
    command=options.pop('command')
    try:
        if command=='create-bundle':
            result=transport.create_bundle(**options)
        elif command=='inspect-bundle':
            result=transport.inspect_bundle(**options)
        else:
            result=transport.install_bundle(**options)
        code=result['exit_code']
    except Exception as exc:
        status=(exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'unavailable')
        reason=(exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC337_LOCAL_OR_INHERITED_SOURCE_UNAVAILABLE')
        code={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        result={
            'schema':transport.DENIAL_SCHEMA,'command':command,
            'status':status,'reason_code':reason,'exit_code':code,
            'all_archive_members_whole_sha_verified':False,
            'blank_external_custody_worksheet_byte_verified':False,
            'receiver_installed_sources_and_controls_byte_rechecked':False,
            'full_ec336_signed_history_receiver_replay_must_be_run_separately':True,
            'caller_supplied_sha_is_not_independently_custodied_by_implementation':True,
            **{k:False for k in transport.FALSE_FIELDS},
        }
    print(json.dumps(result,sort_keys=True,separators=(',',':'),
                     ensure_ascii=True,allow_nan=False))
    return code

if __name__=='__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""EC307 portable fork evidence client: pin a private local case file externally.

The case JSON is only an input locator/expected-pin manifest, not signed
authority. Operators must preserve its raw SHA out of band before verification.
The report contains no file paths, private key, token, HMAC or approval.
"""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec306_registrar_epochs import epochs as e
from . import forks as f

CASE_SCHEMA = 'ces.ec307.local_case_manifest.v1'
CASE_FIELDS = frozenset({'schema', 'parent', 'candidate_a', 'candidate_b'})
PARENT_FIELDS = frozenset({
    'chain_file', 'external', 'ledger_files', 'certificate_files'})


def read_case(file: str, expected_sha: str) -> dict:
    # Uses EC306's own strict 0600 single-link/parent-owner/open/no-follow
    # and exact externally anchored file SHA + canonical trailing-newline IO.
    case = e._owner_private_read(file, expected_sha)
    a.exact(case, CASE_FIELDS, 'EC307_CASE_FIELDS_INVALID')
    f.need(case['schema'] == CASE_SCHEMA, 'CASE_SCHEMA_INVALID')
    a.exact(case['parent'], PARENT_FIELDS,
            'EC307_PARENT_CASE_FIELDS_INVALID')
    a.exact(case['parent']['external'], e.EXTERNAL_FIELDS,
            'EC307_EIGHT_PARENT_EXTERNAL_FIELDS_REQUIRED')
    for branch in ('candidate_a','candidate_b'):
        f._branch_input(case[branch])
    return case


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC307 fully signed same-parent conflict evidence, no CAS/no winner. '
        'Each local case file has its own independent full raw-SHA pin.'))
    s=p.add_subparsers(dest='command',required=True)
    for name in ('compare','verify-report'):
        q=s.add_parser(name,help=(
            'replay and optionally privately write deterministic conflict evidence'
            if name == 'compare' else
            'independently revalidate original signed sources against a pinned report'))
        q.add_argument('--case-file',required=True)
        q.add_argument('--expected-case-raw-sha256',required=True)
        if name=='compare':
            q.add_argument('--out',help='optional owner-private non-overwrite report path')
        else:
            q.add_argument('--evidence-file',required=True)
            q.add_argument('--expected-evidence-report-sha256',required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args=parser().parse_args(argv)
    try:
        case=read_case(args.case_file,args.expected_case_raw_sha256)
        options={'parent_chain_file':case['parent']['chain_file'],
                 'parent_external':case['parent']['external'],
                 'parent_ledger_files':case['parent']['ledger_files'],
                 'parent_certificate_files':case['parent']['certificate_files'],
                 'candidate_a':case['candidate_a'],
                 'candidate_b':case['candidate_b']}
        if args.command=='compare':
            result=f.compare(**options,out=args.out)
        else:
            result=f.verify_report(**options,
                evidence_file=args.evidence_file,
                expected_evidence_report_sha256=args.expected_evidence_report_sha256)
        print(json.dumps({
            'schema':f.RESULT_SCHEMA,'command':args.command,**result,
            'external_pin_source_immutability_proven':False,
            'real_governance_decision_proven':False,
            'external_global_latest_or_revocation_proven':False},
            sort_keys=True,separators=(',',':')))
        return result['exit_code']
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        code=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC307_LOCAL_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({
            'schema':f.DENIAL_SCHEMA,'command':args.command,
            'status':status,'reason_code':code,'exit_code':rc,
            'signed_competing_successor_claimed':False,
            'externally_authorized_winner_claimed':False,
            'external_cas_or_provider_write_performed':False},
            sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':
    raise SystemExit(main())

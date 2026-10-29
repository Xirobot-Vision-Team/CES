#!/usr/bin/env python3
"""EC298 operator: two fully pinned EC297 histories, offline conflict report.

The eight per-lane digest arguments must originate outside the local inputs;
this code cannot prove independence, immutability or which fork is newest.
"""
from __future__ import annotations

import argparse
import hmac
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as storage
from . import conflicts as c


LANE_FLAGS = ('inputs-file', 'commitment-file', 'expected-commitment-sha256',
              'expected-root-tip', 'expected-latest-tip',
              'expected-latest-bridge-sha256')


def compare(*, a_lane: dict, b_lane: dict, out: str | None = None,
            report_file: str | None = None,
            expected_report_sha256: str | None = None) -> dict:
    if report_file is not None or expected_report_sha256 is not None:
        c.l.require(out is None and c.l.absolute_file(report_file) and
                    c.l.sha_pin(expected_report_sha256),
                    'EC298_REPORT_REVERIFICATION_REQUIRES_EXTERNAL_REPORT_SHA',
                    'permission_denied')
        # Validate the supplied report SHA *before* doing the expensive replay.
        old = io.read_doc(report_file, c.MAX_REPORT_BYTES)
        c.l.require(hmac.compare_digest(a.sha(old), expected_report_sha256),
                    'EC298_EXTERNALLY_PINNED_REPORT_SHA_MISMATCH',
                    'permission_denied')
    else:
        old = None
    first, a_snap = c.verify_lane(a_lane)
    second, b_snap = c.verify_lane(b_lane)
    report = c.compare_verified(first, a_snap, second, b_snap)
    if old is not None:
        c.l.require(old == report,
                    'EC298_REPORT_NOT_EQUAL_TO_CURRENT_REVERIFIED_SIGNED_EVIDENCE',
                    'permission_denied')
    if out is not None:
        # Offline proposal only: exclusive private 0600 + fsync, never overwrite.
        storage.store(out, report, c.MAX_REPORT_BYTES)
    return report


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='EC298: offline signed fork evidence, not an adjudicator')
    subs = p.add_subparsers(dest='command', required=True)
    for name in ('compare-lineages', 'verify-report'):
        sub = subs.add_parser(name,
            help='full 2x EC297 signed verification and exact shared-parent comparison')
        for lane in ('a', 'b'):
            for flag in LANE_FLAGS:
                sub.add_argument('--'+lane+'-'+flag, required=True)
        if name == 'compare-lineages':
            sub.add_argument('--out', help='exclusive private portable report proposal')
        else:
            sub.add_argument('--report-file', required=True)
            sub.add_argument('--expected-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        lanes = [{flag.replace('-', '_'): getattr(args, lane+'_'+flag.replace('-','_'))
                  for flag in LANE_FLAGS} for lane in ('a', 'b')]
        report = compare(a_lane=lanes[0], b_lane=lanes[1],
            out=args.out if args.command == 'compare-lineages' else None,
            report_file=args.report_file if args.command == 'verify-report' else None,
            expected_report_sha256=(args.expected_report_sha256
                                   if args.command == 'verify-report' else None))
        print(json.dumps({'schema': c.RESULT_SCHEMA,
            'status': report['status'], 'exit_code': report['exit_code'],
            'comparison': report['comparison'],
            'report_sha256': a.sha(report),
            'report': report,
            'out_of_band_report_pin_stored_or_authenticated': False,
            'verified_against_explicit_report_sha': args.command == 'verify-report',
            'external_custody_or_unique_latest_proven': False,
            'original_send_or_network_executed': False,
        }, sort_keys=True, separators=(',', ':')))
        return report['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, a.AnchorError) else 'unavailable'
        reason = exc.code if isinstance(exc, a.AnchorError) else 'EC298_OFFLINE_COMPARISON_UNAVAILABLE'
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}[status]
        print(json.dumps({'schema': c.DENIAL_SCHEMA,
            'status': status, 'exit_code': rc, 'reason_code': reason,
            'either_lineage_claimed_verified_on_failure': False,
            'original_send_or_network_executed': False,
            'external_custody_or_unique_latest_proven': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())

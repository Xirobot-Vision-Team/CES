#!/usr/bin/env python3
"""EC331 standalone read-only pinned-manifest report cross-check CLI."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import crosscheck


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC331: read-only 2-8 EC330 signed-history replay and unsigned local '
        'cross-reference. Require externally trusted manifest whole original SHA; '
        'never infer remote CAS, institutional authority, global latest or winner.'))
    subs = p.add_subparsers(dest='command', required=True)
    check = subs.add_parser('compare-report-set', help=(
        'check each EC330 pinned original and all inherited Ed25519 originals'))
    check.add_argument('--manifest-file', required=True)
    check.add_argument('--expected-manifest-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        doc = crosscheck.cross_reference(**args)
        print(json.dumps(doc, sort_keys=True, separators=(',', ':'),
                         allow_nan=False, ensure_ascii=True))
        return 2
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC331_BATCH_OR_ORIGINAL_REPLAY_ENVIRONMENT_UNAVAILABLE')
        code = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(
            status, 5)
        print(json.dumps({
            'schema': crosscheck.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': code,
            'every_listed_report_and_both_signed_histories_replayed': False,
            **{field: False for field in crosscheck.FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())

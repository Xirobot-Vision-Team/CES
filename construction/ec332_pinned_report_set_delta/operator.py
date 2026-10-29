#!/usr/bin/env python3
"""EC332 standalone two pinned EC331 sets real replay read-only CLI."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import delta


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC332: compare two independently whole-SHA-pinned EC331 manifests; '
        'replay all prior originals, local observation deltas only, no remote CAS.'))
    sub = p.add_subparsers(dest='command', required=True)
    cmd = sub.add_parser('compare-report-set-observations')
    cmd.add_argument('--left-manifest-file', required=True)
    cmd.add_argument('--left-expected-manifest-sha256', required=True)
    cmd.add_argument('--right-manifest-file', required=True)
    cmd.add_argument('--right-expected-manifest-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        result = delta.compare(**args)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'), allow_nan=False))
        return 2
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC332_TWO_SET_SIGNED_REPLAY_OR_ENVIRONMENT_UNAVAILABLE')
        code = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(
            status, 5)
        print(json.dumps({
            'schema': delta.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': code,
            'both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed': False,
            'both_sets_original_source_report_and_manifest_pins_rechecked_after_union': False,
            **{flag: False for flag in delta.FALSE_FIELDS},
        }, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())

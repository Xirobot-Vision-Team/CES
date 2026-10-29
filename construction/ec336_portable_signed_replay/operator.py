#!/usr/bin/env python3
"""EC336 standalone strictly read-only receiver signed-history replay."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import replay


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC336 exact old-path scoped ORIGINAL cryptographic history replay at a '
        'relocated receiver. READ ONLY. Full outside SHA trust is mandatory.'))
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('verify-signed-replay', help=(
        'Recheck all EC335 copies, then actually replay EC333->EC294 history under '
        'an exact path-to-private-byte read binding; exit2 is unresolved.'))
    for key in (
        'first-hop-plan-file', 'expected-first-hop-plan-sha256',
        'closure-file', 'expected-closure-sha256', 'map-file',
        'expected-map-sha256', 'expected-handoff-sha256',
        'left-expected-manifest-sha256', 'right-expected-manifest-sha256',
    ):
        a.add_argument('--'+key, required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    opts = vars(parser().parse_args(argv))
    command = opts.pop('command')
    try:
        result = replay.verify_relocated_history(**opts)
        rc = result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC336_REAL_HISTORICAL_SIGNATURE_SOURCE_REPLAY_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4,
              'unavailable': 5}.get(status, 5)
        result = {
            'schema': replay.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': rc,
            'ec333_to_ec294_inherited_original_signatures_replayed_locally': False,
            'every_ec335_source_was_guarded_replayed_under_its_unchanged_old_path': False,
            'all_receiver_destination_and_control_originals_late_rechecked': False,
            'independent_sha_trust_and_real_source_authority_remain_external': True,
            **{field: False for field in replay.FALSE_FIELDS},
        }
    print(json.dumps(result, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False))
    return rc


if __name__ == '__main__':
    raise SystemExit(main())

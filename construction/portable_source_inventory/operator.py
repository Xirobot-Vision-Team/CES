#!/usr/bin/env python3
"""EC334 offline private source inventory CLI; only verify-copies is unified."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from . import inventory


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC334 unsigned first-hop source inventory + private copy comparison. '
        'No signature path rebinding, remote CAS, business write or global authority.'))
    sub = p.add_subparsers(dest='command', required=True)
    make = sub.add_parser('create-plan', help='source side, after real EC333 signed replay')
    make.add_argument('--out', required=True)
    make.add_argument('--handoff-file', required=True)
    make.add_argument('--expected-handoff-sha256', required=True)
    for side in ('left', 'right'):
        make.add_argument(f'--{side}-manifest-file', required=True)
        make.add_argument(f'--{side}-expected-manifest-sha256', required=True)
    mapping = sub.add_parser('prepare-map', help='write candidate explicit prefix translation')
    mapping.add_argument('--out', required=True)
    mapping.add_argument('--plan-file', required=True)
    mapping.add_argument('--expected-plan-sha256', required=True)
    mapping.add_argument('--source-root', required=True)
    mapping.add_argument('--destination-root', required=True)
    audit = sub.add_parser('verify-copies', help='receive side, read-only exact byte audit')
    audit.add_argument('--plan-file', required=True)
    audit.add_argument('--expected-plan-sha256', required=True)
    audit.add_argument('--map-file', required=True)
    audit.add_argument('--expected-map-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        if command == 'create-plan':
            result = inventory.create_plan(**args)
        elif command == 'prepare-map':
            result = inventory.prepare_map(**args)
        else:
            result = inventory.verify_copies(**args)
        print(json.dumps(result, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC334_SOURCE_COPY_OR_INHERITED_SIGNED_HISTORY_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(
            status, 5)
        print(json.dumps({
            'schema': inventory.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': rc,
            'destination_bytes_match_every_first_hop_original': False,
            'source_side_full_signed_original_replay_required_for_plan_creation': True,
            'copy_check_is_first_hop_only_and_never_signature_rebinding': True,
            **{key: False for key in inventory.FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())

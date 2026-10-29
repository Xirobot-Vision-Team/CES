#!/usr/bin/env python3
"""EC335 bounded nested original closure: source writers are standalone only."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from . import closure


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC335 signed-replay guarded-read nested source closure and offline private '
        'byte verification. No signing, path rebinding, networking, or CAS.'))
    sub = p.add_subparsers(dest='command', required=True)
    create = sub.add_parser('create-closure', help='source-side genuine signed replay')
    create.add_argument('--out', required=True)
    create.add_argument('--source-root', required=True)
    create.add_argument('--first-hop-plan-file', required=True)
    create.add_argument('--expected-first-hop-plan-sha256', required=True)
    create.add_argument('--handoff-file', required=True)
    create.add_argument('--expected-handoff-sha256', required=True)
    for side in ('left', 'right'):
        create.add_argument(f'--{side}-manifest-file', required=True)
        create.add_argument(f'--{side}-expected-manifest-sha256', required=True)
    mapping = sub.add_parser('prepare-map', help='source-side prefix map, no copying')
    mapping.add_argument('--out', required=True)
    for subcommand in (mapping,):
        subcommand.add_argument('--first-hop-plan-file', required=True)
        subcommand.add_argument('--expected-first-hop-plan-sha256', required=True)
        subcommand.add_argument('--closure-file', required=True)
        subcommand.add_argument('--expected-closure-sha256', required=True)
    mapping.add_argument('--source-root', required=True)
    mapping.add_argument('--destination-root', required=True)
    audit = sub.add_parser('verify-copies', help='read-only receiver, no source root required')
    audit.add_argument('--first-hop-plan-file', required=True)
    audit.add_argument('--expected-first-hop-plan-sha256', required=True)
    audit.add_argument('--closure-file', required=True)
    audit.add_argument('--expected-closure-sha256', required=True)
    audit.add_argument('--map-file', required=True)
    audit.add_argument('--expected-map-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    data = vars(parser().parse_args(argv))
    command = data.pop('command')
    try:
        if command == 'create-closure':
            result = closure.create_closure(**data)
        elif command == 'prepare-map':
            result = closure.prepare_map(**data)
        else:
            result = closure.verify_copies(**data)
        print(json.dumps(result, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC335_NESTED_CLOSURE_OR_INHERITED_SOURCE_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4,
              'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': closure.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': rc,
            'destination_all_observed_copy_bytes_verified': False,
            'full_signed_source_replay_required_on_origin': True,
            'destination_replay_not_performed': True,
            **{k: False for k in closure.FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())

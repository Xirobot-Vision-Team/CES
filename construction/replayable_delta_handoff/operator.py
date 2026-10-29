#!/usr/bin/env python3
"""EC333 standalone candidate-writer and completely read-only verifier CLI."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from . import handoff


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC333 unsigned handoff: create owner-private immutable local candidate '
        'or independently pin and replay both EC331->EC294 histories. '
        'Never attests real-world external SHA custody or CAS/nonexecution.'))
    subs = p.add_subparsers(dest='command', required=True)
    for command in ('create-handoff', 'verify-handoff'):
        sub = subs.add_parser(command)
        if command == 'create-handoff':
            sub.add_argument('--out', required=True)
        else:
            sub.add_argument('--handoff-file', required=True)
            sub.add_argument('--expected-handoff-sha256', required=True)
        for side in ('left', 'right'):
            sub.add_argument(f'--{side}-manifest-file', required=True)
            sub.add_argument(f'--{side}-expected-manifest-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        result = (handoff.create_handoff(**args) if command == 'create-handoff'
                  else handoff.verify_handoff(**args))
        print(json.dumps(result, sort_keys=True, separators=(',', ':'),
                         allow_nan=False, ensure_ascii=True))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC333_HANDOFF_OR_INHERITED_SIGNED_HISTORY_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(
            status, 5)
        print(json.dumps({
            'schema': handoff.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': rc,
            'handoff_original_exactly_reconstructed_from_both_original_signed_histories': False,
            'both_ec331_manifests_and_all_inherited_old_signed_histories_replayed': False,
            'handoff_and_both_manifest_all_inherited_original_pins_late_rechecked': False,
            **{name: False for name in handoff.FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())

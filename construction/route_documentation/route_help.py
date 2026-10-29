#!/usr/bin/env python3
"""EC246: read-only, source-bound help for the *existing* unified router.

No handler is dispatched here. The on-disk catalog is matched to the real
router inventory before exposing examples; a stale publication fails closed.
This tool is independent of (and does not modify) the frozen R243 router CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'references' / 'route-catalog.json'
MATRIX = ROOT / 'construction' / 'CAPABILITY_MATRIX.json'
sys.path.insert(0, str(ROOT / 'construction'))
from unified_action_router import inventory  # noqa: E402; imports no business handlers


def _key(row: dict[str, Any]) -> tuple[str, str | None]:
    mode = row['mode']
    return row['action'].casefold(), mode.casefold() if mode is not None else None


def _read_json(path: Path) -> dict[str, Any]:
    # Packaged files only; no user path, URL, arbitrary module or handler input.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 300_000:
        raise ValueError('PACKAGED_HELP_SOURCE_UNAVAILABLE')
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, value in pairs:
            if k in obj:
                raise ValueError('PACKAGED_HELP_DUPLICATE_KEY')
            obj[k] = value
        return obj
    data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(data) is not dict:
        raise ValueError('PACKAGED_HELP_NOT_OBJECT')
    return data


def _load() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    catalog, matrix, live = _read_json(CATALOG), _read_json(MATRIX), inventory()
    rows = catalog.get('routes')
    matrix_rows = matrix.get('unified_v5_routes')
    if (catalog.get('schema') != 'ces.ec246.route_catalog.v1' or
            catalog.get('package_version') != 'V5.56/R246' or
            catalog.get('wire_schema') != live.get('schema') or
            catalog.get('wire_version') != live.get('version') or
            catalog.get('wire_build') != live.get('build') or
            type(rows) is not list or type(matrix_rows) is not list or
            len(rows) != live.get('route_count') or len(matrix_rows) != len(rows) or
            len(rows) != 74):
        raise ValueError('PACKAGED_HELP_CATALOG_METADATA_DRIFT')
    fields = ('action', 'mode', 'route_kind', 'effect', 'handler', 'invokable_by_new_router')
    # Compare order as well as identity: the published 74 rows must be the same
    # real source inventory, not a hand-waved count or a merged Action family.
    for actual, published, product in zip(live['routes'], rows, matrix_rows):
        if any(actual.get(f) != published.get(f) or
               actual.get(f) != product.get(f) for f in fields):
            raise ValueError('PACKAGED_HELP_ROUTE_DRIFT')
        if published != product:
            raise ValueError('PACKAGED_HELP_PRODUCT_MATRIX_DRIFT')
    if len({_key(r) for r in rows}) != 74:
        raise ValueError('PACKAGED_HELP_DUPLICATE_ROUTE')
    # Published examples are an explicitly reviewed *subset*, not a generator
    # for arbitrary handler requests. Reject unexpected or unbound templates.
    samples = catalog.get('examples')
    approved = {('due', 'evaluate'), ('schemareview', 'inventory'),
                ('schemareview', 'audit'), ('issuecreate', 'create'),
                ('docsonlypublish', 'localsandbox')}
    if (type(samples) is not list or len(samples) != len(approved) or
            {_key(e) for e in samples if type(e) is dict and
             'action' in e and 'mode' in e} != approved):
        raise ValueError('PACKAGED_HELP_EXAMPLES_DRIFT')
    for ex in samples:
        req = ex.get('request')
        if (type(req) is not dict or req.get('schema') != catalog['request_schema'] or
                (req.get('action'), req.get('mode')) != (ex['action'], ex['mode']) or
                _key(ex) not in {_key(r) for r in rows} or
                type(ex.get('purpose')) is not str or
                type(ex.get('expected_result')) is not str):
            raise ValueError('PACKAGED_HELP_EXAMPLES_DRIFT')
        if ex['action'] in ('IssueCreate', 'DocsOnlyPublish') and set(req) != {
                'schema', 'action', 'mode'}:
            raise ValueError('PACKAGED_HELP_EXAMPLES_DRIFT')
        if ex['action'] == 'SchemaReview' and (set(req) != {
                'schema', 'action', 'mode', 'argv'} or req['argv'] != []):
            raise ValueError('PACKAGED_HELP_EXAMPLES_DRIFT')
        if ex['action'] == 'Due' and (set(req) != {
                'schema', 'action', 'mode', 'parameters'} or
                type(req['parameters']) is not dict or
                set(req['parameters']) != {
                    'project_timezone', 'cadence', 'observed_at', 'never_processed'}):
            raise ValueError('PACKAGED_HELP_EXAMPLES_DRIFT')
    return catalog, rows


def _describe(row: dict[str, Any]) -> str:
    kind = row['route_kind']
    if kind == 'LEGACY_NATIVE_R150':
        return 'Legacy PowerShell only; new JSON dispatcher cannot execute it; native validation pending.'
    if kind == 'HOST_REQUIRED':
        return 'Registered for visibility; standalone dispatcher refuses; no host bridge or grant.'
    if row['action'] == 'Cycle' and row['mode'] == 'BusinessWriteAttempt':
        return 'Real local handler always denies attempted business writes.'
    if row['effect'] == 'PRIVATE_CES_METADATA_WRITE_OPT_IN':
        return 'Requires explicit private CES metadata opt-in and handler-local checks; not a business grant.'
    return 'Existing handler path only; partial/error possible, no attested business completion.'


def _table(rows: list[dict[str, Any]]) -> str:
    lines = ['| Action | Mode | Kind | Effect / help |', '|---|---|---|---|']
    for r in rows:
        mode = r['mode'] if r['mode'] is not None else '(no fixed mode)'
        lines.append(f"| `{r['action']}` | `{mode}` | `{r['route_kind']}` | {_describe(r)} |")
    return '\n'.join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC246 read-only route/help catalog (no dispatch, no authentication)')
    parser.add_argument('--action', help='exact Action; omission lists all 74 routes')
    parser.add_argument('--mode', help='exact Mode, requires --action')
    parser.add_argument('--example', action='store_true',
                        help='show a vetted fixed request JSON where one exists, never call it')
    parser.add_argument('--json', action='store_true', help='emit JSON instead of Markdown')
    parser.add_argument('--list-examples', action='store_true',
                        help='list Action/Mode pairs with a vetted example')
    args = parser.parse_args(argv)
    if args.mode and not args.action:
        parser.error('--mode requires --action')
    if args.example and (not args.mode or not args.action):
        parser.error('--example requires --action and --mode')
    if args.list_examples and (args.action or args.mode or args.example):
        parser.error('--list-examples is standalone')
    try:
        catalog, all_rows = _load()
        if args.list_examples:
            output = catalog['examples']
            if args.json:
                print(json.dumps(output, ensure_ascii=False, indent=2))
            else:
                for item in output:
                    print(f"{item['action']}/{item['mode']}: {item['purpose']}")
            return 0
        rows = [r for r in all_rows if
                (not args.action or r['action'].casefold() == args.action.casefold()) and
                (not args.mode or (r['mode'] is not None and
                                   r['mode'].casefold() == args.mode.casefold()))]
        if not rows:
            raise ValueError('ROUTE_NOT_IN_FIXED_CATALOG')
        if args.example:
            examples = [e for e in catalog['examples'] if
                        _key(e) == _key(rows[0])]
            if not examples:
                raise ValueError('NO_VETTED_EXAMPLE_FOR_THIS_ROUTE')
            ex = examples[0]
            print(json.dumps({'request': ex['request'], 'note': ex['purpose'],
                              'expected_result': ex['expected_result'],
                              'caution': catalog['acceptance_limit']},
                             ensure_ascii=False, indent=2))
        elif args.json:
            print(json.dumps({'schema': 'ces.ec246.route_help.v1',
                              'router_wire': catalog['wire_schema'],
                              'package_version': catalog['package_version'],
                              'count': len(rows), 'routes': rows,
                              'acceptance_limit': catalog['acceptance_limit']},
                             ensure_ascii=False, indent=2))
        else:
            print(f"CES routes: {len(rows)} shown; router wire {catalog['wire_schema']} "
                  f"({catalog['wire_version']}/{catalog['wire_build']}).")
            print(_table(rows))
            print('\n' + catalog['acceptance_limit'])
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Fixed reason codes only; do not echo stack, paths or local secrets.
        allowed = {'PACKAGED_HELP_SOURCE_UNAVAILABLE', 'PACKAGED_HELP_DUPLICATE_KEY',
                   'PACKAGED_HELP_NOT_OBJECT', 'PACKAGED_HELP_CATALOG_METADATA_DRIFT',
                   'PACKAGED_HELP_ROUTE_DRIFT', 'PACKAGED_HELP_PRODUCT_MATRIX_DRIFT',
                   'PACKAGED_HELP_DUPLICATE_ROUTE', 'ROUTE_NOT_IN_FIXED_CATALOG',
                   'NO_VETTED_EXAMPLE_FOR_THIS_ROUTE',
                   'PACKAGED_HELP_EXAMPLES_DRIFT'}
        reason = str(exc) if str(exc) in allowed else 'PACKAGED_HELP_INVALID'
        print(json.dumps({'schema': 'ces.ec246.route_help.v1', 'status': 'invalid',
                          'reason_code': reason}), file=sys.stdout)
        return 4


if __name__ == '__main__':
    sys.exit(main())

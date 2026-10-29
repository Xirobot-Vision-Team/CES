#!/usr/bin/env python3
"""EC-152: read-only source trace for the seven authored CES CLI actions.

Reads the frozen ACTION_TRACE.json and its referenced local source paths.
This is NOT a PowerShell runner, a runtime router, or a permission grant. It
must never inspect a user Git repository or mutate a project file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
TRACE = ROOT / 'construction' / 'ACTION_TRACE.json'
EXPECTED = {
    'Inspect': (None,),
    'Collect': ('WorkingTree', 'DeliveredTarget'),
    'Reconcile': ('Snapshot',),
    'CodePrepare': ('Snapshot',),
    'CodeValidate': ('Snapshot',),
    'CodeSave': ('Snapshot',),
    'CodeShow': ('List', 'Detail', 'Findings', 'Compare', 'Trace',
                 'Overview', 'Triage', 'Recurrence', 'Sequence'),
}


def read_trace() -> dict:
    return json.loads(TRACE.read_text(encoding='utf-8'))


def safe_source(relative: str) -> Path:
    """Reject absolute paths, traversal and symlinks before looking at source."""
    if not isinstance(relative, str) or not re.fullmatch(r'(?:scripts|tests)/[A-Za-z0-9._/-]+\.ps1', relative):
        raise ValueError('unexpected source-relative path: ' + repr(relative))
    if any(part in ('.', '..', '') for part in relative.split('/')):
        raise ValueError('unsafe relative source path: ' + relative)
    node = ROOT
    for part in relative.split('/'):
        node = node / part
        if node.is_symlink():
            raise ValueError('symlink source path: ' + relative)
    if not node.is_file():
        raise ValueError('missing source file: ' + relative)
    return node


def line_of_symbol(source: str, symbol: str) -> int | None:
    """Find a literal top-level function signature; NOT a PS language parser."""
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]+', symbol):
        return None
    lines = safe_source(source).read_text(encoding='utf-8-sig').splitlines()
    hits = [n for n, line in enumerate(lines, 1)
            if re.match(r'^function\s+' + re.escape(symbol) + r'\s*\{\s*$', line, flags=re.I)]
    return hits[0] if len(hits) == 1 else None


def line_of_invocation(source: str, callee: str, is_dispatch: bool) -> int | None:
    """Locate exactly one direct invocation after assignment; do not execute it."""
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]+', callee):
        return None
    assignment = r'\$resultCode\s*=\s*' if is_dispatch else r'\$Envelope\.data\s*=\s*'
    pattern = re.compile(assignment + re.escape(callee) + r'(?:\s|$)', flags=re.I)
    lines = safe_source(source).read_text(encoding='utf-8-sig').splitlines()
    hits = [n for n, line in enumerate(lines, 1) if pattern.search(line)]
    return hits[0] if len(hits) == 1 else None


def check_trace(data: dict) -> dict:
    problems: list[str] = []
    warnings: list[str] = []
    rows = data.get('routes', [])
    if data.get('schema_version') != 'ces.ec152.action_trace.v1':
        problems.append('unexpected trace schema')
    if not isinstance(rows, list) or len(rows) != 16:
        problems.append('expected exactly 16 source-traced routes')
        rows = [] if not isinstance(rows, list) else rows
    seen: set[tuple[str, str | None]] = set()
    by_action: dict[str, set[str | None]] = {a: set() for a in EXPECTED}
    smoke: set[str] = set()
    for row in rows:
        ident = str(row.get('id', '?'))
        act, mode = row.get('action'), row.get('mode')
        key = (act, mode)
        if key in seen:
            problems.append(f'duplicate route: {ident}')
        seen.add(key)
        if act not in EXPECTED:
            problems.append(f'unlisted action: {ident}')
        else:
            by_action[act].add(mode)
        if row.get('evidence_confidence') != 'STATIC_SOURCE_AND_EXISTING_SMOKE_REFERENCES_ONLY':
            problems.append(f'unwarranted evidence grade: {ident}')
        try:
            source = row['handler']
            found = line_of_symbol(source['file'], source['symbol'])
            if found is None:
                problems.append(f'handler not found exactly once: {ident}')
            elif found != source['line']:
                warnings.append(f'handler moved from line {source["line"]} to {found}: {ident}')
            dispatcher = row['dispatcher']
            found = line_of_invocation(dispatcher['file'], dispatcher['callee'], True)
            if dispatcher['file'] != 'scripts/ces.ps1' or found is None or dispatcher['callee'] != source['symbol']:
                problems.append(f'dispatch not anchored: {ident}')
            elif found != dispatcher['line']:
                warnings.append(f'dispatch moved from line {dispatcher["line"]} to {found}: {ident}')
            if act == 'CodeShow' and mode not in ('List', 'Detail'):
                sub = row['submode_handler']
                call, definition = sub['invocation'], sub['definition']
                found = line_of_invocation(call['file'], call['callee'], False)
                if call['file'] != 'scripts/codeshow.ps1' or found is None or call['callee'] != definition['symbol']:
                    problems.append(f'CodeShow submode call not anchored: {ident}')
                elif found != call['line']:
                    warnings.append(f'submode dispatch moved: {ident} line {call["line"]} -> {found}')
                found = line_of_symbol(definition['file'], definition['symbol'])
                if found is None:
                    problems.append(f'CodeShow submode implementation missing: {ident}')
                elif found != definition['line']:
                    warnings.append(f'submode implementation moved: {ident} line {definition["line"]} -> {found}')
                imported = "Join-Path $PSScriptRoot '" + Path(definition['file']).name + "'"
                if imported not in (ROOT / 'scripts/ces.ps1').read_text(encoding='utf-8-sig'):
                    problems.append(f'CodeShow module not dot-sourced by CLI: {ident}')
            elif act == 'CodeShow' and row.get('submode_handler'):
                problems.append(f'List/Detail are inline and must not claim an external callee: {ident}')
            for dep in row['cross_module_calls']:
                if line_of_symbol(dep['file'], dep['symbol']) is None:
                    problems.append(f'cross-module implementation absent: {ident}/{dep["symbol"]}')
                if not re.search(r'\b'+re.escape(dep['symbol'])+r'\b', safe_source(source['file']).read_text(encoding='utf-8-sig')):
                    problems.append(f'cross-module call absent: {ident}/{dep["symbol"]}')
            smoke_path = row['tests']['primary_smoke']
            safe_source(smoke_path)
            if row['tests']['status'] != 'PRESENT_NOT_RUN':
                problems.append(f'smoke improperly marked as tested: {ident}')
            smoke.add(smoke_path)
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f'invalid route evidence {ident}: {exc}')
    for action, modes in EXPECTED.items():
        if by_action[action] != set(modes):
            problems.append(f'missing or extra modes for {action}: {sorted(map(str, by_action[action]))}')
    expected_tests = {f'tests/{p.name}' for p in (ROOT / 'tests').glob('*.Smoke.ps1')}
    if smoke != expected_tests or len(smoke) != 15:
        problems.append('15 primary Smoke suites not mapped one-to-many: absent='+str(sorted(expected_tests - smoke)))
    for src, expected_hash in data.get('source_fingerprints', {}).items():
        try:
            actual = hashlib.sha256(safe_source(src).read_bytes()).hexdigest()
            if actual != expected_hash:
                warnings.append(f'R150 source changed since trace snapshot; review mapping: {src}')
        except ValueError as exc:
            problems.append(str(exc))
    try:
        cli = safe_source('scripts/ces.ps1').read_text(encoding='utf-8-sig')
        for term in ("$script:ProductVersion = '1.0.0'", "$script:Build = '1.0.0'",
                     "'NOT_IMPLEMENTED'", 'CODE_SHOW_MODE_REQUIRED',
                     "if ($Action -ieq 'CodeSave') { $envelope.read_only = $false }"):
            if term not in cli:
                warnings.append('CLI boundary contract may have changed: ' + term)
        if "if ($Action -ieq 'Collect' -and $Mode -inotmatch '^(WorkingTree|DeliveredTarget)$')" not in cli:
            warnings.append('Collect accepted-mode guard moved/changed')
    except ValueError as exc:
        problems.append(str(exc))
    return {
        'verdict': 'STATIC_TRACE_PASS' if not problems else 'STATIC_TRACE_FAIL',
        'native_runtime_validation': 'NOT_RUN',
        'route_count': len(rows), 'action_families': len(EXPECTED),
        'primary_smoke_suites': len(smoke),
        'problems': problems, 'warnings': warnings,
    }


def find_route(data: dict, action: str, mode: str | None) -> dict:
    action = next((a for a in EXPECTED if a.casefold() == action.casefold()), '')
    if not action:
        raise ValueError('No traced handler for action; see --list (unknown actions remain NOT_IMPLEMENTED in CES).')
    if mode is None:
        if action == 'CodeShow':
            raise ValueError('CodeShow requires an explicit --mode; choose from: ' + ', '.join(m for m in EXPECTED[action] if m))
        mode = 'WorkingTree' if action == 'Collect' else ('Snapshot' if action != 'Inspect' else None)
    else:
        normalized = next((m for m in EXPECTED[action] if m is not None and m.casefold() == mode.casefold()), None)
        if normalized is None:
            raise ValueError('No mapped mode for ' + action + ': ' + mode + '; see --list.')
        mode = normalized
    return next(row for row in data['routes'] if row['action'] == action and row['mode'] == mode)


def main() -> int:
    parser = argparse.ArgumentParser(description='Inspect EC-152 authored CLI routes without running PowerShell or Git.')
    parser.add_argument('--list', action='store_true', help='Show all seven action families and authored modes.')
    parser.add_argument('--action', help='Show source/input/JSON/Smoke trace for this authored action.')
    parser.add_argument('--mode', help='Optional mode. Required for CodeShow; omitted Collect defaults to WorkingTree.')
    parser.add_argument('--check', action='store_true', help='Read-only static route/source presence check (not runtime tests).')
    parser.add_argument('--json', action='store_true', help='Emit selected trace or static-check output as JSON.')
    args = parser.parse_args()
    if args.mode and not args.action:
        parser.error('--mode requires --action')
    if args.check and (args.action or args.list):
        parser.error('--check cannot be combined with --list or --action')
    try:
        data = read_trace()
        if args.check:
            result = check_trace(data)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f'{result["verdict"]}: {result["action_families"]} families / {result["route_count"]} source routes / {result["primary_smoke_suites"]} Smoke files referenced')
                for item in result['problems']:
                    print('ERROR:', item)
                for item in result['warnings']:
                    print('WARN:', item)
                print('PowerShell/Git/Smoke runtime validation: NOT_RUN')
            return 0 if not result['problems'] else 1
        if args.action:
            item = find_route(data, args.action, args.mode)
            if args.json:
                print(json.dumps(item, ensure_ascii=False, indent=2))
            else:
                print(item['id'], '—', item['source_scope'])
                print('Entry:', item['dispatcher']['file']+':'+str(item['dispatcher']['line']),
                      '→',item['handler']['file']+'::'+item['handler']['symbol'])
                if 'submode_handler' in item:
                    sub = item['submode_handler']['definition']
                    print('Mode:', sub['file']+'::'+sub['symbol'])
                print('Required:', ', '.join(item['inputs']['required']))
                print('Optional:', ', '.join(item['inputs']['optional']) or 'none')
                print('Success reason codes:', ', '.join(item['success_reason_codes']))
                print('JSON data fields (examples):', ', '.join(item['example_payload_fields']))
                print('Effect:', item['effect'])
                print('Smoke:', item['tests']['primary_smoke'], '(NOT_RUN)')
                print('Command example:', item['example_powershell'])
                for note in item['limitations']:
                    print('Limit:', note)
                print('STATIC SOURCE TRACE ONLY; not a runtime assertion.')
            return 0
        if args.json:
            print(json.dumps({'baseline': data['source_baseline'],
                              'source_baseline': data['source_baseline'],
                              'routes': [{'action': row['action'], 'mode': row['mode'],
                                          'handler': row['handler'], 'smoke':row['tests']['primary_smoke']}
                                         for row in data['routes']]}, ensure_ascii=False, indent=2))
        else:
            print(f'CES {data["source_baseline"]} source trace')
            for action, modes in EXPECTED.items():
                print(' ', action+':', ', '.join(mode for mode in modes if mode) if modes[0] else '(no mode)')
            print('Use --action Name [--mode Mode] for code, parameters, JSON fields and existing Smoke.')
            print('Source authored only; native PowerShell/Smoke verification NOT_RUN.')
        return 0
    except (OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError) as exc:
        print('Trace lookup failed:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

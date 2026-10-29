#!/usr/bin/env python3
"""EC-154: read-only, source-derived CodeShow Sequence k1..56 dependency/contract audit.

This is a narrow PowerShell *lexical* auditor, not a PowerShell interpreter or
an AST/reachability/performance proof. It reads only shipped CES sources and
existing EC-151/152 evidence; it never invokes Git, PowerShell, or CES actions.
Its compatibility snapshot is reviewable JSON, NOT an alternative R150 baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = 'construction/SEQUENCE_SOURCE_AUDIT.json'
PREFIX = 'Get-CodeSequenceOriginalFindingPairProfileRetentionEndpoint'
FIELD_PREFIX = 'selected_original_finding_pair_profile_retention_endpoint_'
EXPECTED_K = 56
CORE = ('scripts/ces.ps1', 'scripts/codeshow.ps1', 'scripts/codesequence.ps1')
# These three are graph prerequisites, not cardinality-k children.
NON_K_ENDPOINT_MODULES = {
    'codeprofileretentionendpointcreditgraph.ps1',
    'codeprofileretentionendpointdominance.ps1',
    'codeprofileretentionendpointreduction.ps1',
}
IMPORT = re.compile(r"(?m)^\s*\.\s*\(Join-Path\s+\$PSScriptRoot\s+'([^']+\.ps1)'\s*\)")
DEFINITION = re.compile(r'(?im)^\s*function\s+([\w-]+)\s*\{')
CHILD = re.compile(
    r"(?im)^\s*\$pathFocus\['(?P<key>" + FIELD_PREFIX + r"[a-z0-9_]+)'\]\s*=\s*`?\s*"
    r'(?P<symbol>' + PREFIX + r'[a-z0-9]+)\b'
)
CALL = re.compile(r'(?i)\b(' + PREFIX + r'[a-z0-9]+)\s+(?:-|`|@|\()')
PARENT_REPLAY = re.compile(r'(?im)^\s*\$freshParent\s*=\s*(' + PREFIX + r'\w+)\b')
TOP_FIELD = re.compile(r'(?m)^\s{8}([a-z][a-z_0-9]+)\s*=')
CONDITIONAL_FIELD = re.compile(r"(?m)^\s*if\s*\(\$null\s+-ne\s+\$\w+\)\s*\{\s*\$result\['([^']+)'\]")
R150_SHA = 'construction/SOURCE_BASELINE.json'


class AuditError(Exception):
    """Invalid/ambiguous source input: no success-shaped result is returned."""


def source_bytes(root: Path, relative: str) -> bytes:
    # Fixed, repo-relative paths; forbid linked source files and absolute imports.
    if not re.fullmatch(r'[a-zA-Z0-9_./-]+', relative) or '..' in Path(relative).parts or relative.startswith('/'):
        raise AuditError(f'unsafe source locator: {relative!r}')
    file = root / relative
    if not file.is_file() or file.is_symlink() or file.stat().st_size > 2_000_000:
        raise AuditError(f'missing, symlink or oversized source: {relative}')
    return file.read_bytes()


def text_of(raw: bytes, relative: str) -> str:
    try:
        return raw.decode('utf-8-sig')
    except UnicodeError as exc:
        raise AuditError(f'not UTF-8: {relative}') from exc


def line_of(text: str, start: int) -> int:
    return text.count('\n', 0, start) + 1


def loc(path: str, line: int) -> dict:
    return {'file': path, 'line': line}


def source_lines_without_comments(code: str) -> list[tuple[int, str]]:
    """Ignore block/line comments for *call-like* scanning; preserve line numbers.

    Not a PowerShell tokenizer: multiline strings/dynamic invocations are not
    classified as calls. This deliberately under-claims full call coverage.
    """
    in_block = False
    lines = []
    for no, original in enumerate(code.splitlines(), 1):
        line = original
        while True:
            if in_block:
                close = line.find('#>')
                if close == -1:
                    line = ''
                    break
                line = line[close + 2:]
                in_block = False
            start = line.find('<#')
            if start == -1:
                break
            close = line.find('#>', start + 2)
            if close == -1:
                line = line[:start]
                in_block = True
                break
            line = line[:start] + line[close + 2:]
        # A full-line comment never contains an executable invocation.
        if line.lstrip().startswith('#'):
            continue
        lines.append((no, line))
    return lines


def get_functions(code: str) -> dict[str, tuple[int, str]]:
    """Find top-level lexical declarations and their line ranges."""
    defs = list(DEFINITION.finditer(code))
    found = {}
    for i, match in enumerate(defs):
        name = match.group(1)
        key = name.casefold()
        if key in found:
            raise AuditError(f'duplicate function declaration: {name}')
        stop = defs[i + 1].start() if i + 1 < len(defs) else len(code)
        found[key] = (line_of(code, match.start()), code[match.end():stop])
    return found


def scan_direct_calls(body: str, symbol_by_fold: dict[str, int]) -> list[dict]:
    found = []
    for line, code in source_lines_without_comments(body):
        if re.match(r'^\s*function\s+', code, re.I):
            continue
        for match in CALL.finditer(code):
            target = symbol_by_fold.get(match.group(1).casefold())
            if target is not None:
                found.append({'to_k': target, 'body_relative_line': line, 'symbol': match.group(1)})
    return found


def find_result_keys(sequence: str) -> list[str]:
    """Extract only the PUBLIC end-of-function ordered result, not helper maps."""
    marker = sequence.rfind('$result = [ordered]@{')
    if marker < 0:
        raise AuditError('Sequence public ordered result missing')
    # Last result literal is at four-space indentation; its immediate children
    # appear at eight spaces. The closing brace is a four-space-only line.
    end = re.search(r'(?m)^    \}\s*$', sequence[marker:])
    if end is None:
        raise AuditError('Sequence public ordered result closing brace missing')
    block = sequence[marker:marker + end.start()]
    return TOP_FIELD.findall(block)


def final_child_fields(body: str) -> tuple[list[str], list[str]]:
    """Conservative last-return ordered-map signature for one k projection.

    This intentionally does not claim to parse arbitrary dynamic map writes,
    item arrays, conditional extensions or PowerShell object semantics.
    """
    returns = list(re.finditer(r'(?m)^    return \[ordered\]@\{\s*$', body))
    if not returns:
        raise AuditError('k handler has no four-space final ordered return')
    ending = body[returns[-1].end():]
    closing = re.search(r'(?m)^    \}\s*$', ending)
    if not closing:
        raise AuditError('k handler final ordered return is not closed at four spaces')
    segment = ending[:closing.start()]
    outer = re.findall(r'(?m)^ {8}([a-z][a-z0-9_]+)\s*=', segment)
    if not outer or len(set(outer)) != len(outer):
        raise AuditError('k handler final public fields are missing or duplicated')
    counts = re.search(r'(?m)^ {8}counts\s*=\s*\[ordered\]@\{\s*$', segment)
    if not counts:
        raise AuditError('k handler counts map missing')
    sub = segment[counts.end():]
    close = re.search(r'(?m)^ {8}\}\s*$', sub)
    if not close:
        raise AuditError('k handler counts map is not closed at eight spaces')
    count_fields = re.findall(r'(?m)^ {12}([a-z][a-z0-9_]+)\s*=', sub[:close.start()])
    if not count_fields or len(set(count_fields)) != len(count_fields):
        raise AuditError('k handler count fields are missing or duplicated')
    return outer, count_fields


def build_audit(root: Path = ROOT) -> dict:
    root = Path(root)
    cli = text_of(source_bytes(root, CORE[0]), CORE[0])
    show = text_of(source_bytes(root, CORE[1]), CORE[1])
    sequence = text_of(source_bytes(root, CORE[2]), CORE[2])
    original_imports = IMPORT.findall(cli)
    if len(original_imports) != len(set(x.casefold() for x in original_imports)):
        raise AuditError('duplicate case-insensitive PowerShell dot-source import')
    imported = {'scripts/' + name.casefold(): line_of(cli, match.start())
                for match in IMPORT.finditer(cli) for name in [match.group(1)]}
    for name in original_imports:
        source_bytes(root, 'scripts/' + name)

    # Refuse a private, self-proclaimed source inventory as authoritative:
    # cross-check both previous rounds' independently recorded facts.
    dep = json.loads(source_bytes(root, 'construction/NATIVE_DEPENDENCIES.json'))
    trace = json.loads(source_bytes(root, 'construction/ACTION_TRACE.json'))
    # EC-151 is a frozen R150 observation, not a veto against later planned
    # Action/Mode additions. Keep deviations visible without forcing future
    # EC-155 changes to rewrite historical evidence or break k1..56 queries.
    known_edges = {e['to'].casefold() for e in dep['edges'] if e['from'] == CORE[0]}
    old_count = dep.get('counts', {}).get('cli_imported_modules')
    if len(known_edges) != old_count:
        raise AuditError('EC-151 internal CLI import count conflicts with its own edges')
    added_imports = sorted(set(imported) - known_edges)
    removed_imports = sorted(known_edges - set(imported))
    routes = [r for r in trace['routes'] if r.get('id') == 'CodeShow:Sequence']
    if len(routes) != 1 or routes[0]['handler']['symbol'] != 'CodeShow-Local':
        # EC152 describes dispatcher in handler and underlying Sequence function
        # in a separate subhandler field; inspect rather than assume schema.
        if len(routes) != 1:
            raise AuditError('EC-152 CodeShow:Sequence route missing or duplicated')
    if not re.search(r'(?im)^\s*\$Envelope\.data\s*=\s*Get-CodeShowSequence\s+-Directory\b', show):
        raise AuditError('CodeShow Sequence route to Get-CodeShowSequence absent')
    if not re.search(r'(?im)^\s*function\s+Get-CodeShowSequence\s*\{', sequence):
        raise AuditError('Sequence entry function absent')

    # Every potential cardinality module (including a new k57 file) must be
    # accounted for; no inference from the Latin spelling of k is necessary.
    prefix = 'codeprofileretentionendpoint'
    candidates = sorted(p.name for p in (root / 'scripts').glob(prefix + '*.ps1'))
    candidates = [p for p in candidates if p not in NON_K_ENDPOINT_MODULES]
    k_definitions: dict[str, dict] = {}
    module_by_symbol = {}
    modules = []
    for name in candidates:
        relative = 'scripts/' + name
        raw = source_bytes(root, relative)
        code = text_of(raw, relative)
        defs = get_functions(code)
        handlers = [(symbol, start, body) for symbol, (start, body) in defs.items()
                    if symbol.startswith(PREFIX.casefold())]
        if len(handlers) != 1:
            raise AuditError(f'cardinality module must declare one endpoint projection: {relative} ({len(handlers)})')
        symbol, start, body = handlers[0]
        if symbol in k_definitions:
            raise AuditError(f'projection symbol defined in two modules: {symbol}')
        k_definitions[symbol] = {'source': relative, 'definition_line': start, 'body': body,
                                  'source_lines': code.splitlines(),
                                  'sha256': hashlib.sha256(raw).hexdigest()}
        module_by_symbol[symbol] = relative
        modules.append(relative)

    # Three prerequisite endpoint projections share the same naming prefix
    # but are not k=1..56 deletion cardinalities.
    non_k_outputs = {FIELD_PREFIX + slug for slug in (
        'credit_graph', 'dominance_topology', 'dominance_reduction')}
    all_entries = list(CHILD.finditer(sequence))
    extras = [m.group('key') for m in all_entries
              if m.group('symbol').casefold() not in k_definitions and
              m.group('key') not in non_k_outputs]
    if extras:
        raise AuditError('new/unclassified endpoint projections: ' + ', '.join(extras))
    entries = [m for m in all_entries if m.group('symbol').casefold() in k_definitions]
    scope_guard = re.search(r'(?m)^\s*if \(\$null -ne \$PairPathAnchorFindingCounterpartIndex\) \{', sequence)
    if not scope_guard or (entries and scope_guard.start() > entries[0].start()):
        raise AuditError('k deletion branches lost the expected counterpart selection guard (static locator)')
    if len(entries) != EXPECTED_K:
        raise AuditError(f'expected {EXPECTED_K} Sequence direct cardinality outputs; found {len(entries)}')
    if len(candidates) != EXPECTED_K:
        raise AuditError(f'expected {EXPECTED_K} k projection modules; found {len(candidates)}')
    table = []
    observed = set()
    for k, assignment in enumerate(entries, 1):
        symbol = assignment.group('symbol')
        key = symbol.casefold()
        field = assignment.group('key')
        if field in observed or key not in k_definitions:
            raise AuditError(f'duplicate/missing cardinality output or function: {field} -> {symbol}')
        observed.add(field)
        definition = k_definitions[key]
        module = definition['source']
        if module.casefold() not in imported:
            raise AuditError(f'k{k} module not loaded by CLI: {module}')
        if module not in modules:
            raise AuditError(f'k{k} non-cardinality module projection: {module}')
        body = definition['body']
        replay = list(PARENT_REPLAY.finditer(body))
        child_fields, child_count_fields = final_child_fields(body)
        top_line = line_of(sequence, assignment.start())
        table.append({
            'k': k,
            'output_key': field,
            'invocation': symbol,
            'sequence_call': loc(CORE[2], top_line),
            'module': module,
            'cli_import': loc(CORE[0], imported[module.casefold()]),
            'function_definition': loc(module, definition['definition_line']),
            'baseline_sha256': definition['sha256'],
            'direct_k_calls': [],
            'final_child_public_fields': child_fields,
            'final_child_counts_fields': child_count_fields,
            'direct_parent_replay': bool(replay),
            'parent_replay_symbol': replay[0].group(1) if replay else None,
            'parent_replay_line': (loc(module, definition['definition_line'] +
                body[:replay[0].start()].count('\n')) if replay else None),
            'full_json_parent_comparison': bool(re.search(
                r'ConvertTo-Json\s+-InputObject\s+\$freshParent', body, re.I)),
            'path_focus_input_fields': sorted(set(re.findall(
                r'\$PathFocus\.(selected_[a-z0-9_]+)', body, re.I))),
        })
    if len(set(t['module'] for t in table)) != EXPECTED_K:
        raise AuditError('not a bijection: multiple k outputs reuse a module')
    if set(t['module'] for t in table) != set(modules):
        raise AuditError('one or more imported cardinality modules are not exposed as Sequence outputs')

    by_symbol = {row['invocation'].casefold(): row['k'] for row in table}
    for item in table:
        body = k_definitions[item['invocation'].casefold()]['body']
        calls = scan_direct_calls(body, by_symbol)
        item['direct_k_calls'] = sorted(set(call['to_k'] for call in calls))
        item['direct_k_call_sites'] = [loc(item['module'], item['function_definition']['line'] +
                                   # Body begins on the same physical line as '{';
                                   # counted body-relative lines are 1-based.
                                   call['body_relative_line'] - 1) | {'to_k': call['to_k']}
                                   for call in calls]
        if item['k'] in item['direct_k_calls']:
            raise AuditError(f'k{item["k"]} calls itself, audit as recursion before releasing')
        if any(k >= item['k'] for k in item['direct_k_calls']):
            raise AuditError(f'k{item["k"]} has a forward/cyclic dependency')
        if item['direct_parent_replay']:
            replay_k = by_symbol.get(item['parent_replay_symbol'].casefold())
            if replay_k is None or replay_k not in item['direct_k_calls']:
                raise AuditError(f'k{item["k"]} parent replay is not a recorded k call')
            item['parent_replay_k'] = replay_k
        else:
            item['parent_replay_k'] = None
    transitive = {}
    for item in table:
        reach = set(item['direct_k_calls'])
        for p in item['direct_k_calls']:
            reach.update(transitive[p])  # topologically ordered invariant above
        transitive[item['k']] = reach
        item['transitive_k_dependencies'] = sorted(reach)

    public_keys = find_result_keys(sequence)
    if not public_keys or len(public_keys) != len(set(public_keys)):
        raise AuditError('Sequence final JSON keys missing or duplicated')
    conditional = CONDITIONAL_FIELD.findall(sequence[sequence.rfind('$result = [ordered]@{'):])
    if len(conditional) != len(set(conditional)):
        raise AuditError('duplicate conditional public Sequence result keys')
    settings = {}
    for name in ('MaxRecords', 'DefaultTop', 'MaxTop'):
        match = re.search(r'(?m)^\$script:CodeShowSequence' + name + r'\s*=\s*(\d+)\s*$', sequence)
        if not match:
            raise AuditError(f'CodeShow Sequence {name} bound unavailable')
        settings[name] = {'value': int(match.group(1)), 'source': loc(CORE[2], line_of(sequence, match.start()))}
    if [settings[n]['value'] for n in ('MaxRecords', 'DefaultTop', 'MaxTop')] != [12, 10, 20]:
        raise AuditError('Sequence selector bounds changed; compatibility re-review required')
    if not re.search(r'\$parts.Count\s+-lt\s+2', sequence) or not re.search(r'\$seen\.Add\(\$part\)', sequence):
        raise AuditError('Sequence input lower-bound / distinct-ID validation removed')
    if not re.search(r'\$beforeIds\s+-join\s+[\'\"]\|', sequence) or not re.search(r'\$afterIds\s*=\s*@\(Get-CodeShowRecordIds', sequence):
        raise AuditError('Sequence store-membership drift check removed')
    if not re.search(r"\$Envelope\.data\s*=\s*Get-CodeShowSequence", show):
        raise AuditError('Sequence dispatcher lost its structured data return')
    original_fingerprints = json.loads(source_bytes(root, R150_SHA))['fingerprints']
    source_drift = sorted(set(CORE + tuple(modules)) & set(original_fingerprints) -
                          {p for p in CORE + tuple(modules) if
                           hashlib.sha256(source_bytes(root, p)).hexdigest() == original_fingerprints.get(p)})
    relevant_modules = sorted(set(CORE + tuple(modules)))
    hashes = {p: hashlib.sha256(source_bytes(root, p)).hexdigest() for p in relevant_modules}
    # Static hotspots indicate review/test priorities, NOT demonstrated slowdowns.
    replay = [x for x in table if x['direct_parent_replay']]
    evidence = {
        'COMPAT-PUBLIC-JSON': {
            'classification': 'compatibility_review',
            'basis': 'Source-level public JSON keys, 56 path_focus child keys, and each k handler last-return ordered-map/counts keys. Dynamic and array-element shapes not fully parsed.',
            'evidence': [loc(CORE[2], line_of(sequence, sequence.rfind('$result = [ordered]@{'))), table[-1]['sequence_call']],
            'verification_needed': 'Native CodeSequence Smoke with representative focused/unfocused selections and JSON snapshot comparison.'
        },
        'COMPAT-SELECTORS': {
            'classification': 'compatibility_review',
            'basis': '2..12 distinct record IDs, default preview Top 10, max Top 20 and route selectors must remain stable.',
            'evidence': [settings['MaxRecords']['source'], settings['MaxTop']['source'], loc(CORE[1],
                line_of(show, show.index('$Envelope.data = Get-CodeShowSequence')))],
            'verification_needed': 'Boundary selectors, missing IDs, duplicate IDs, focus hierarchy and truncation behavior under PowerShell.'
        },
        'PERF-EAGER-LOAD': {
            'classification': 'potential_workload_risk_not_measured',
            'basis': f'{len(imported)} literal modules are dot-sourced in ces.ps1 before per-Action dispatch; static import count, not latency.',
            'evidence': [loc(CORE[0], min(imported.values()))],
            'verification_needed': 'PowerShell startup time and process memory on representative platform; avoid changing load semantics during EC-154.'
        },
        'PERF-PARENT-REPLAY': {
            'classification': 'potential_workload_risk_not_measured',
            'basis': f'{len(replay)} of 56 children contain a freshParent re-invocation; {sum(x["full_json_parent_comparison"] for x in replay)} compare serialized parent JSON. Parent replays can amplify deep focused requests.',
            'evidence': [x['parent_replay_line'] for x in replay[:2]] + ([replay[-1]['parent_replay_line']] if replay else []),
            'verification_needed': 'Profile focused k1..56 work and serialized JSON volume; never infer exponential runtime from syntax alone.'
        },
        'PERF-HIGH-EDGE-CNF': {
            'classification': 'potential_workload_risk_not_measured',
            'basis': 'k56 contains bounded high-edge E64..E66 assignment enumeration and polynomial/CNF counting; no elapsed time or memory budget proven.',
            'evidence': [table[-1]['function_definition']],
            'verification_needed': 'E63, E64, E65, E66 native throughput/memory and correctness fixtures with genuine directed SCC links.'
        },
    }
    # Freeze semantic shape, not a performance number: hashes remain immutable R150
    # comparison facts, and legitimate future edits require explicit drift review.
    invariants = {
        'sequence_route': 'scripts/codeshow.ps1::Get-CodeShowSequence',
        'selector_bounds': {k: v['value'] for k, v in settings.items()},
        'public_json_fields': public_keys,
        'optional_public_json_fields': conditional,
        'k_outputs_in_order': [{'k': x['k'], 'key': x['output_key'], 'symbol': x['invocation'],
                                'module': x['module'],
                                'public_fields': x['final_child_public_fields'],
                                'counts_fields': x['final_child_counts_fields'],
                                'direct_k_calls': x['direct_k_calls'],
                                'parent_replay_k': x['parent_replay_k']} for x in table],
    }
    return {
        'schema_version': 'ces.ec154.sequence_audit.v1',
        'ec': 'EC-154',
        'baseline': 'V4.60/R150',
        'claim_level': 'LEXICAL_STATIC_SOURCE_AUDIT_ONLY_NO_RUNTIME_OR_BENCHMARK',
        'limits': [
            'PowerShell syntax is not parsed by an AST: dynamic invocation, string-built paths, conditional execution and true reachability are not proven.',
            'The k1..56 order is sourced from CodeShow Sequence field assignments; parent calls are a conservative lexical subset, not full function-call coverage.',
            'Conditional outputs and nested JSON shapes may depend on runtime data; values, content and performance are not certified.',
            'CodeSequence Smoke presence does not imply it was run, and no source code is executed or modified.',
        ],
        'source_evidence': {
            'ec151_map': 'construction/NATIVE_DEPENDENCIES.json',
            'ec152_trace': 'construction/ACTION_TRACE.json',
            'r150_sha256_register': R150_SHA,
            'existing_smoke': 'tests/CodeSequence.Smoke.ps1',
            'cli_dot_source_modules': len(imported),
            'ec151_cli_dot_source_modules': old_count,
            'ec151_cli_imports_match_current': not added_imports and not removed_imports,
            'cli_imports_added_since_ec151': added_imports,
            'cli_imports_removed_since_ec151': removed_imports,
            'k_modules': len(table),
            'k_highest': EXPECTED_K,
            'record_count_bounds': [2, settings['MaxRecords']['value']],
            'top_bounds': [1, settings['MaxTop']['value']],
            'original_sha_mismatches': source_drift,
            'source_sha256': hashes,
            'counterpart_focus_guard': loc(CORE[2], line_of(sequence, scope_guard.start())),
        },
        'contract': {
            'entrypoint': CORE[0],
            'dispatcher': CORE[1],
            'handler': CORE[2] + '::Get-CodeShowSequence',
            'path_focus_condition': 'selected PairPathAnchorFindingCounterpartIndex is present; other focus routes may not expose k children',
            'public_json_fields': public_keys,
            'conditional_public_json_fields': conditional,
            'sequence_selector_settings': settings,
            'k_key_path': 'data.path_focus.<child_key> (only if corresponding selected focus was built)',
        },
        'k_chain': table,
        'dependency_profile': {
            'explicit_direct_k_edges': sum(len(x['direct_k_calls']) for x in table),
            'direct_parent_replay_count': len(replay),
            'whole_public_json_parent_comparisons': sum(x['full_json_parent_comparison'] for x in replay),
            'max_transitive_k_dependencies': max(len(x['transitive_k_dependencies']) for x in table),
            'k56_transitive_depends_on': table[-1]['transitive_k_dependencies'],
            'unresolved_runtime_dynamic_calls': 'NOT_ANALYZED',
            'code_sequence_smoke': 'PRESENT_NOT_RUN',
        },
        'risk_register': evidence,
        'compatibility_invariants': invariants,
        'runtime_validation': {
            'powershell7': 'NOT_RUN', 'existing_15_smoke': 'NOT_RUN',
            'windows_git': 'NOT_RUN', 'performance_E63_E66': 'NOT_RUN',
            'final_user_assisted': 'NOT_STARTED',
        },
    }


def check_snapshot(current: dict, expected: dict) -> list[str]:
    problems = []
    if expected.get('schema_version') != current.get('schema_version'):
        problems.append('snapshot_schema_mismatch')
    baseline = expected.get('compatibility_invariants')
    if not isinstance(baseline, dict):
        return problems + ['missing_snapshot_compatibility_invariants']
    for key in ('sequence_route', 'selector_bounds', 'public_json_fields',
                'optional_public_json_fields', 'k_outputs_in_order'):
        if baseline.get(key) != current['compatibility_invariants'].get(key):
            problems.append('contract_drift:' + key)
    # A byte-level change may preserve lexical JSON signatures while changing
    # numerical semantics. Require explicit human review/re-baselining of the
    # frozen Sequence/k modules, not an automatic semantic approval.
    old_hashes = expected.get('source_evidence', {}).get('source_sha256', {})
    new_hashes = current['source_evidence']['source_sha256']
    protected = {'scripts/codesequence.ps1', 'scripts/codeshow.ps1'}
    protected.update(r['module'] for r in current['k_chain'])
    for name in sorted(protected):
        if old_hashes.get(name) != new_hashes.get(name):
            problems.append('source_sha_drift_requires_review:' + name)
    return problems


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='one JSON report, no source changes')
    parser.add_argument('--list', action='store_true', help='list k1..56 links')
    parser.add_argument('--k', type=int, metavar='1..56', help='query one k entry')
    parser.add_argument('--risk', metavar='RISK-ID', help='query a risk record')
    parser.add_argument('--check', action='store_true', help='compare live structure with immutable EC-154 snapshot')
    args = parser.parse_args(argv)
    try:
        result = build_audit(root)
        problems = []
        if args.check:
            snapshot = json.loads(source_bytes(Path(root), EVIDENCE))
            problems = check_snapshot(result, snapshot)
        if args.k is not None and not (1 <= args.k <= EXPECTED_K):
            raise AuditError('k must be between 1 and 56; no k57+ has been authorized')
        if args.risk and args.risk not in result['risk_register']:
            raise AuditError('unknown risk id: ' + args.risk)
        view = result
        if args.k is not None:
            view = {'k': result['k_chain'][args.k - 1], 'claim_level': result['claim_level']}
        elif args.risk:
            view = {'id': args.risk, **result['risk_register'][args.risk]}
        elif args.list:
            view = [{'k': x['k'], 'module': x['module'], 'output_key': x['output_key'],
                     'direct_k_calls': x['direct_k_calls']} for x in result['k_chain']]
        if args.json:
            if args.check:
                view = {'status': 'STATIC_CONTRACT_MATCH' if not problems else 'STATIC_CONTRACT_DRIFT',
                        'issues': problems, 'result': view}
            print(json.dumps(view, ensure_ascii=False, indent=2))
        else:
            if args.k is not None or args.risk or args.list:
                print(json.dumps(view, ensure_ascii=False, indent=2))
            else:
                counts = result['dependency_profile']
                print('EC-154 | CodeShow Sequence static k1..56 audit')
                print('k modules:', len(result['k_chain']), 'CLI dot-source modules:',
                      result['source_evidence']['cli_dot_source_modules'])
                print('direct k-call edges:', counts['explicit_direct_k_edges'],
                      '| parent replays:', counts['direct_parent_replay_count'],
                      '| parent JSON compares:', counts['whole_public_json_parent_comparisons'])
                print('public data fields:', len(result['contract']['public_json_fields']),
                      '| source R150 SHA drift:', len(result['source_evidence']['original_sha_mismatches']))
                print('Static source only. PowerShell, Smoke and E63..66 resources: NOT_RUN')
            if args.check:
                print('STATIC SNAPSHOT:', 'MATCH' if not problems else 'DRIFT (' + ', '.join(problems) + ')')
        return 1 if problems else 0
    except (AuditError, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print('SEQUENCE_AUDIT_UNAVAILABLE: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

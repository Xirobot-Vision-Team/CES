#!/usr/bin/env python3
"""EC-155: read-only CES Action/Mode registry, lookup and routing policy.

The PowerShell `scripts/ces.ps1` dispatcher remains the runtime authority.
This module NEVER dispatches a CES handler, runs PowerShell/Git, writes a Git
repository, or upgrades an unimplemented planned capability to implemented.
It resolves only the Action/Mode preflight behavior visible in the R150 source;
all other parameter binding/validation and handler outcomes remain out of scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_RELATIVE = 'references/cli-action-mode-registry.json'
TRACE_RELATIVE = 'construction/ACTION_TRACE.json'
MATRIX_RELATIVE = 'construction/CAPABILITY_MATRIX.json'
BASELINE_RELATIVE = 'construction/SOURCE_BASELINE.json'
CLI_RELATIVE = 'scripts/ces.ps1'
SCHEMA = 'ces.cli.action_mode_registry.v1'
STATE_AUTHORED = 'SOURCE_AUTHORED_RUNTIME_UNVERIFIED'
POLICY_RULES = frozenset({'IGNORE_MODE', 'DEFAULT_OR_SELECT', 'IMPLICIT_SNAPSHOT', 'EXPLICIT_REQUIRED'})
ROUTABLE = 'routable_unverified'
# Accept the current R414 299 KB capability matrix while retaining a bounded metadata read.
MAX_JSON_BYTES = 400_000


class RegistryError(ValueError):
    """A registry that cannot be trusted for safe lookup. No routes returned."""


def _load_json(root: Path, relative: str) -> dict[str, Any]:
    """Read fixed package-relative metadata; reject linked files and oversized data."""
    path = root
    for item in relative.split('/'):
        if not re.fullmatch(r'[A-Za-z0-9._-]+', item) or item in {'.', '..'}:
            raise RegistryError('unsafe package-relative metadata path')
        path = path / item
        if path.is_symlink():
            raise RegistryError('linked metadata path is not trusted: ' + relative)
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise RegistryError('missing or oversized metadata file: ' + relative)
    try:
        value = json.loads(path.read_text(encoding='utf-8-sig'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError('malformed metadata: ' + relative) from exc
    if not isinstance(value, dict):
        raise RegistryError('metadata root must be an object: ' + relative)
    return value


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _fold(value: str) -> str:
    # The registry contains ASCII Action/Mode tokens; PowerShell dispatch is
    # case-insensitive. Never trim or normalize input to a different token.
    return value.casefold()


def validate_registry(data: dict) -> None:
    """Fail closed on malformed/contradictory registry structure.

    The optional `check_registry` additionally compares against actual source,
    EC-152 provenance and the capability matrix. No check implies runtime PASS.
    """
    if data.get('schema_version') != SCHEMA:
        raise RegistryError('unexpected registry schema')
    defaults = data.get('cli_defaults')
    actions = data.get('supported_actions')
    policies = data.get('action_modes')
    routes = data.get('routes')
    plans = data.get('planned_capabilities')
    if not isinstance(defaults, dict) or not isinstance(actions, list) or not isinstance(policies, dict) or not isinstance(routes, list) or not isinstance(plans, list):
        raise RegistryError('missing Action/Mode/route/plan collections')
    if not actions or any(not _nonempty(a) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', a) for a in actions):
        raise RegistryError('invalid supported Action tokens')
    if len(set(map(_fold, actions))) != len(actions) or set(policies) != set(actions):
        raise RegistryError('Action names duplicated or lack a mode policy')
    if defaults.get('action') not in actions or defaults.get('mode') != 'WorkingTree':
        raise RegistryError('unrecognized Action/Mode defaults')
    if defaults.get('mode_explicitness') != 'PSBoundParameters.ContainsKey(Mode)' or defaults.get('match') != 'case_insensitive_no_trimming':
        raise RegistryError('mode explicitness or case matching semantics drifted')
    rejection = defaults.get('unknown_action')
    if rejection != {'status': 'not_implemented', 'reason_code': 'NOT_IMPLEMENTED', 'exit_code': 3}:
        raise RegistryError('unknown Action policy must fail closed as NOT_IMPLEMENTED/3')
    required_rules = {'Inspect': 'IGNORE_MODE', 'Collect': 'DEFAULT_OR_SELECT',
                      'CodeShow': 'EXPLICIT_REQUIRED'}
    required_rules.update({name: 'IMPLICIT_SNAPSHOT' for name in
                           ('Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave')})
    if set(required_rules) != set(actions):
        raise RegistryError('registry must enumerate exactly the seven source-authored Action families')
    seen: set[tuple[str, str | None]] = set()
    by_action: dict[str, list[str | None]] = {a: [] for a in actions}
    route_ids: set[str] = set()
    for action, policy in policies.items():
        if not isinstance(policy, dict) or policy.get('rule') not in POLICY_RULES or policy['rule'] != required_rules[action]:
            raise RegistryError('incorrect mode policy: ' + action)
        modes = policy.get('modes')
        if not isinstance(modes, list) or any(not _nonempty(m) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', m) for m in modes):
            raise RegistryError('invalid declared modes: ' + action)
        if len(set(map(_fold, modes))) != len(modes):
            raise RegistryError('duplicate case-insensitive Mode: ' + action)
        if action == 'Inspect':
            if modes or policy.get('omitted_mode') != 'NO_MODE' or policy.get('explicit_mode') != 'ANY_VALUE_IGNORED' or 'reject' in policy:
                raise RegistryError('Inspect must ignore Mode and have only one route')
        else:
            required_modes = (['WorkingTree', 'DeliveredTarget'] if action == 'Collect'
                              else ['List', 'Detail', 'Findings', 'Compare', 'Trace', 'Overview', 'Triage', 'Recurrence', 'Sequence'] if action == 'CodeShow'
                              else ['Snapshot'])
            if modes != required_modes:
                raise RegistryError('mode order or supported mode tokens drifted: ' + action)
            expected_default = 'WorkingTree' if action == 'Collect' else 'REJECT' if action == 'CodeShow' else 'Snapshot'
            if policy.get('omitted_mode') != expected_default:
                raise RegistryError('mode-omission policy drifted: ' + action)
            expected_explicit = 'SELECT_CASE_INSENSITIVE' if action in ('Collect', 'CodeShow') else 'SNAPSHOT_ONLY_CASE_INSENSITIVE'
            if policy.get('explicit_mode') != expected_explicit:
                raise RegistryError('explicit mode-selection policy drifted: ' + action)
            expected_rejection = ({'status': 'not_implemented', 'reason_code': 'NOT_IMPLEMENTED', 'exit_code': 3}
                                  if action == 'Collect' else
                                  {'status': 'invalid_input', 'reason_code': 'CODE_SHOW_MODE_REQUIRED', 'exit_code': 4}
                                  if action == 'CodeShow' else
                                  {'status': 'invalid_input', 'reason_code': 'SNAPSHOT_MODE_REQUIRED', 'exit_code': 4})
            if policy.get('reject') != expected_rejection:
                raise RegistryError('unsafe rejection status or exit code for ' + action)
    for route in routes:
        if not isinstance(route, dict):
            raise RegistryError('route entry is not an object')
        act, mode, ident = route.get('action'), route.get('mode'), route.get('id')
        if act not in actions or (mode is not None and not _nonempty(mode)):
            raise RegistryError('route references nonexistent Action or invalid Mode')
        if mode not in policies[act]['modes'] and not (act == 'Inspect' and mode is None):
            raise RegistryError('route declares unregistered Mode: ' + str(ident))
        if ident != (act if mode is None else act + ':' + mode) or ident in route_ids:
            raise RegistryError('route ID mismatch or duplicate: ' + str(ident))
        if route.get('implementation_state') != STATE_AUTHORED or route.get('source_trace_route_id') != ident:
            raise RegistryError('route state/provenance mismatch: ' + ident)
        handler = route.get('handler')
        dispatcher = route.get('dispatcher')
        if not isinstance(handler, dict) or not isinstance(dispatcher, dict):
            raise RegistryError('route must bind existing handler and dispatcher: ' + ident)
        for binding in (handler, dispatcher):
            if not _nonempty(binding.get('file')) or not re.fullmatch(r'scripts/[a-zA-Z0-9_-]+\.ps1', binding['file']):
                raise RegistryError('unsafe handler/dispatcher source path: ' + ident)
            if not _nonempty(binding.get('symbol')) and not _nonempty(binding.get('callee')):
                raise RegistryError('missing handler/dispatcher symbol: ' + ident)
        if not isinstance(route.get('inputs'), dict) or not isinstance(route.get('primary_smoke'), str):
            raise RegistryError('missing route inputs or primary Smoke reference: ' + ident)
        inputs = route['inputs']
        if (not isinstance(inputs.get('required'), list) or not isinstance(inputs.get('optional'), list)
            or any(not _nonempty(arg) for arg in inputs['required'] + inputs['optional'])):
            raise RegistryError('malformed route input requirements: ' + ident)
        if not re.fullmatch(r'tests/[A-Za-z0-9._-]+\.Smoke\.ps1', route['primary_smoke']):
            raise RegistryError('unsafe/missing primary Smoke reference: ' + ident)
        effect = ('LOCAL_CES_METADATA_WRITE_WITH_EXPLICIT_AUTHORIZATION' if ident == 'CodeSave:Snapshot' else 'READ_ONLY')
        if route.get('effect') != effect:
            raise RegistryError('permission/effect mismatch: ' + ident)
        route_ids.add(ident)
        key = (act, mode)
        if key in seen:
            raise RegistryError('duplicate Action+Mode route: ' + ident)
        seen.add(key)
        by_action[act].append(mode)
    if len(routes) != 16:
        raise RegistryError('expected 16 authored source routes')
    for act, policy in policies.items():
        if by_action[act] != ([None] if act == 'Inspect' else policy['modes']):
            raise RegistryError('route enumeration/order does not match policy: ' + act)
    names = set()
    for plan in plans:
        if not isinstance(plan, dict) or not _nonempty(plan.get('name')):
            raise RegistryError('malformed planned capability')
        name = plan['name']
        if _fold(name) in names or plan.get('status') != 'NOT_IMPLEMENTED' or plan.get('cli_handler_registered') is not False:
            raise RegistryError('planned capability duplicated or spuriously marked executable: ' + name)
        if any(k in plan for k in ('handler', 'route_id', 'dispatcher')):
            raise RegistryError('planned-only capability cannot contain a handler: ' + name)
        names.add(_fold(name))
    if not plans:
        raise RegistryError('planned/unimplemented registry cannot be empty')
    safety = data.get('safety')
    if (not isinstance(safety, dict) or safety.get('planned_never_callable') is not True
        or safety.get('routing_performs_no_actions') is not True
        or safety.get('runtime_only_authorized_write') != {
            'route': 'CodeSave:Snapshot', 'requires_explicit_parameter': 'ApprovePersist',
            'destination': 'CES_OWNED_METADATA_ONLY'}):
        raise RegistryError('registry safety claims inconsistent or unapproved')


def read_registry(root: Path = ROOT) -> dict:
    data = _load_json(Path(root), REGISTRY_RELATIVE)
    validate_registry(data)
    return data


def _route(data: dict, action: str, mode: str | None) -> dict:
    matches = [r for r in data['routes'] if r['action'] == action and r['mode'] == mode]
    if len(matches) != 1:
        raise RegistryError('route missing/ambiguous: ' + action + ':' + str(mode))
    return matches[0]


def _find_planned(data: dict, token: str) -> dict | None:
    return next((p for p in data['planned_capabilities'] if _fold(p['name']) == _fold(token)), None)


def _planned_hint(data: dict, action: str, mode: str | None) -> dict | None:
    # Only exact spelled capability tokens are suggestions; never turn one
    # into a callable route or guess synonyms for combined project names.
    return _find_planned(data, action + ':' + mode) if mode is not None else _find_planned(data, action)


def resolve(data: dict, *, action: str | None = None, mode: str | None = None) -> dict:
    """Resolve only existing R150 Action/Mode gates, without invoking handlers.

    `None` means parameter omitted. `''` means explicitly supplied empty token.
    For a valid route the PowerShell *runtime* exit code remains unknown.
    Negative decisions carry the existing PowerShell rejection exit code.
    """
    validate_registry(data)
    if action is not None and not isinstance(action, str):
        raise RegistryError('action must be a string or None')
    if mode is not None and not isinstance(mode, str):
        raise RegistryError('mode must be a string or None')
    supplied = action is not None
    requested = data['cli_defaults']['action'] if action is None else action
    selected = next((a for a in data['supported_actions'] if _fold(a) == _fold(requested)), None)
    base = {
        'schema_version': 'ces.action_mode_decision.v1',
        'validation_scope': 'ACTION_MODE_PREFLIGHT_ONLY_NOT_ARGUMENT_BINDING_OR_HANDLER_EXECUTION',
        'action_was_explicit': supplied,
        'mode_was_explicit': mode is not None,
        'requested_action': requested,
        'requested_mode': mode,
        'handler_invoked': False,
        'native_runtime_validation': 'NOT_RUN',
    }
    if selected is None:
        base.update({
            'decision': 'not_implemented', 'route': None,
            'reason_code': 'NOT_IMPLEMENTED', 'cli_rejection_exit_code': 3,
            'planned_capability': _planned_hint(data, requested, mode),
            'message': 'Unknown Action has no handler, even when mentioned in the construction plan.',
        })
        return base
    policy = data['action_modes'][selected]
    requested_mode = mode if mode is not None else data['cli_defaults']['mode']
    if policy['rule'] == 'IGNORE_MODE':
        actual_mode = None
        effective_note = 'Inspect ignores Mode in its dispatch; explicit Mode does not create an Inspect submode.'
    elif policy['rule'] == 'IMPLICIT_SNAPSHOT' and mode is None:
        actual_mode = 'Snapshot'
        effective_note = 'Omitted Mode selects the Snapshot handler despite global WorkingTree parameter default.'
    elif policy['rule'] == 'EXPLICIT_REQUIRED' and mode is None:
        actual_mode = None
        effective_note = None
    else:
        actual_mode = next((m for m in policy['modes'] if _fold(m) == _fold(requested_mode)), None)
        effective_note = None
    if actual_mode is None and policy['rule'] != 'IGNORE_MODE':
        refusal = policy['reject']
        base.update({
            'decision': refusal['status'], 'route': None,
            'canonical_action': selected, 'effective_mode': None,
            'reason_code': refusal['reason_code'],
            'cli_rejection_exit_code': refusal['exit_code'],
            'planned_capability': _planned_hint(data, selected, mode),
            'message': 'Mode absent or unsupported by the existing ' + selected + ' dispatch.',
        })
        return base
    route = _route(data, selected, actual_mode)
    base.update({
        'decision': ROUTABLE,
        'canonical_action': selected,
        'effective_mode': actual_mode,
        'route': route,
        'cli_rejection_exit_code': None,
        'runtime_exit_code': 'UNKNOWN_UNTIL_NATIVE_EXECUTION',
        'read_only': route['effect'] == 'READ_ONLY',
        'requires_explicit_persist_authorization': route['id'] == 'CodeSave:Snapshot',
        'no_execution_or_permission_grant': True,
        'message': effective_note or 'Source-authored route only; additional CLI validation and handler outcome not verified.',
    })
    return base


def describe(data: dict, token: str) -> dict:
    """Return an Action's registered modes or a planned capability's blocker."""
    validate_registry(data)
    if not isinstance(token, str):
        raise RegistryError('show token must be a string')
    action = next((a for a in data['supported_actions'] if _fold(a) == _fold(token)), None)
    if action:
        return {
            'query': token, 'kind': 'source_authored_action',
            'runtime_state': STATE_AUTHORED, 'action': action,
            'mode_policy': data['action_modes'][action],
            'routes': [r for r in data['routes'] if r['action'] == action],
            'planned_capabilities': [p for p in data['planned_capabilities']
                                     if _fold(p['name']).startswith(_fold(action) + ':')],
            'no_handler_invoked': True,
        }
    plan = _find_planned(data, token)
    if plan:
        return {
            'query': token, 'kind': 'planned_capability',
            'runtime_state': 'NOT_IMPLEMENTED', 'capability': plan,
            'registered_handler': False,
        }
    return {'query': token, 'kind': 'unknown_action_or_capability',
            'runtime_state': 'NOT_IMPLEMENTED', 'registered_handler': False}


def _parse_literal_ps_array(source: str, name: str) -> list[str] | None:
    match = re.search(r'(?m)^\s*' + re.escape(name) + r'\s*=\s*@\(([^\r\n)]*)\)', source)
    if not match:
        return None
    values = re.findall(r"'([^']+)'", match.group(1))
    if not values:
        return None
    if not re.fullmatch(r"(?:\s*'[^']+'\s*,?)*\s*", match.group(1)):
        return None
    return values


def _source_gates(cli: str) -> tuple[dict[str, object], list[str]]:
    """Lexical evidence only: anchors the four fail-closed Action/Mode gates."""
    errors: list[str] = []
    defs = {}
    for param in ('Action', 'Mode'):
        match = re.search(r'(?im)^\s*\[string\]\s+\$' + param + r"\s*=\s*'([^']+)'", cli)
        defs[param] = match.group(1) if match else None
        if defs[param] is None:
            errors.append('PowerShell parameter default missing: ' + param)
    action_gate = re.search(r"(?i)if\s*\(\$Action\s+-inotmatch\s+'\^\(([^']+)\)\$'\)\s*\{(.*?)\n\}", cli, re.S)
    collect_gate = re.search(r"(?i)if\s*\(\$Action\s+-ieq\s+'Collect'\s+-and\s+\$Mode\s+-inotmatch\s+'\^\(([^']+)\)\$'\)\s*\{(.*?)\n\}", cli, re.S)
    snap_gate = re.search(r"(?i)if\s*\(\$Action\s+-in\s+@\(([^)]+)\)\s+-and\s+\$PSBoundParameters\.ContainsKey\('Mode'\)\s+-and\s+\$Mode\s+-ine\s+'Snapshot'\)\s*\{(.*?)\n\}", cli, re.S)
    show_gate = re.search(r"(?i)if\s*\(\$Action\s+-ieq\s+'CodeShow'\s+-and\s+\(-not\s+\$PSBoundParameters\.ContainsKey\('Mode'\)\s+-or\s+\$Mode\s+-inotmatch\s+'\^\(([^']+)\)\$'\)\)\s*\{(.*?)\n\}", cli, re.S)
    def check_body(kind: str, match: re.Match | None, reason: str, status: str, exit_code: int):
        if match is None:
            errors.append(kind + ' preflight rejection gate missing')
        else:
            text = match.group(match.lastindex)
            if not all(part in text for part in ["$envelope.status = '" + status + "'",
                                                       "$envelope.reason_code = '" + reason + "'",
                                                       'Finish -Envelope $envelope -ExitCode ' + str(exit_code)]):
                errors.append(kind + ' rejection status/reason/exit semantics drifted')
    check_body('unknown Action', action_gate, 'NOT_IMPLEMENTED', 'not_implemented', 3)
    check_body('Collect Mode', collect_gate, 'NOT_IMPLEMENTED', 'not_implemented', 3)
    check_body('Snapshot Mode', snap_gate, 'SNAPSHOT_MODE_REQUIRED', 'invalid_input', 4)
    check_body('CodeShow Mode', show_gate, 'CODE_SHOW_MODE_REQUIRED', 'invalid_input', 4)
    defs['action_list'] = action_gate.group(1).split('|') if action_gate else None
    defs['collect_modes'] = collect_gate.group(1).split('|') if collect_gate else None
    defs['snapshot_actions'] = re.findall(r"'([^']+)'", snap_gate.group(1)) if snap_gate else None
    defs['codeshow_modes'] = show_gate.group(1).split('|') if show_gate else None
    for array in ('supported_actions', 'supported_collect_modes', 'supported_codeshow_modes'):
        defs[array] = _parse_literal_ps_array(cli, array)
        if defs[array] is None:
            errors.append('envelope advertised modes not statically readable: ' + array)
    return defs, errors


def _ec157_reviewed_drift(root: Path, relative: str,
                           baseline_sha: str | None, observed_sha: str) -> bool:
    """Accept only the EXACT, explicitly recorded EC-157 source delta.

    The ledger is a build-review receipt, not a security authorization or
    third-party authentication. Frozen R150 evidence remains untouched.
    """
    ledger_path = root / 'construction/LEGACY_SECURITY_DRIFT.json'
    if not ledger_path.is_file() or ledger_path.is_symlink():
        return False
    try:
        ledger = json.loads(ledger_path.read_text(encoding='utf-8'))
        item = ledger['changed_powershell_sources'][relative]
        return (ledger.get('ec') == 'EC-157'
                and ledger.get('source_baseline') == 'R150'
                and isinstance(baseline_sha, str)
                and item.get('r150_sha256') == baseline_sha
                and item.get('current_sha256') == observed_sha
                and observed_sha != baseline_sha)
    except (OSError, KeyError, ValueError, TypeError):
        return False



def _ec159_reviewed_drift(root: Path, relative: str,
                           baseline_sha: str | None, observed_sha: str) -> bool:
    """Accept only a fully chained, explicit EC-159 native source delta.

    EC-157 review remains frozen as a HISTORICAL receipt, not rewritten to
    describe newer bytes. EC-159 chains from those reviewed bytes or from R150.
    A receipt is source-review metadata, NEVER a security attestation.
    """
    ledger_path = root / 'construction/LEGACY_PATH_DRIFT.json'
    if not ledger_path.is_file() or ledger_path.is_symlink():
        return False
    try:
        doc = json.loads(ledger_path.read_text(encoding='utf-8'))
        item = doc['changed_powershell_sources'][relative]
        if doc.get('ec') != 'EC-159' or doc.get('source_baseline') != 'R150':
            return False
        if not isinstance(baseline_sha, str) or item.get('r150_sha256') != baseline_sha:
            return False
        previous = item.get('previous_sha256')
        if not isinstance(previous, str):
            return False
        if relative in ('scripts/ces.ps1', 'scripts/codesave.ps1'):
            old_review = json.loads((root / 'construction/LEGACY_SECURITY_DRIFT.json').read_text(encoding='utf-8'))
            if old_review.get('ec') != 'EC-157':
                return False
            if previous != old_review['changed_powershell_sources'][relative]['current_sha256']:
                return False
        elif previous != baseline_sha:
            return False
        return (item.get('current_sha256') == observed_sha
                and observed_sha != previous
                and item.get('wire_contract_changed') is False)
    except (OSError, KeyError, ValueError, TypeError):
        return False


def check_registry(data: dict, root: Path = ROOT) -> dict:
    """Compare registry to R150 lexical CLI gates and previous static evidence.

    `check` is intentionally not a test of real PowerShell semantics or outputs.
    It should reject drift needing explicit review rather than rewrite R150 SHA.
    """
    problems: list[str] = []
    details: dict = {}
    try:
        validate_registry(data)
    except RegistryError as exc:
        return {'verdict': 'STATIC_CONTRACT_MISMATCH', 'problems': [str(exc)],
                'scope': 'STATIC_PROVENANCE_AND_SOURCE_SHAPE_NOT_RUNTIME_VALIDATION'}
    root = Path(root)
    trace = _load_json(root, TRACE_RELATIVE)
    matrix = _load_json(root, MATRIX_RELATIVE)
    baseline = _load_json(root, BASELINE_RELATIVE)
    entry = root / CLI_RELATIVE
    if not entry.is_file() or entry.is_symlink():
        raise RegistryError('missing/symlink CLI entrypoint')
    raw = entry.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    details['cli_sha256'] = digest
    details['baseline_cli_sha256'] = baseline.get('fingerprints', {}).get(CLI_RELATIVE)
    reviewed_159 = _ec159_reviewed_drift(root, CLI_RELATIVE,
                                         details['baseline_cli_sha256'], digest)
    reviewed = reviewed_159 or _ec157_reviewed_drift(
        root, CLI_RELATIVE, details['baseline_cli_sha256'], digest)
    details['cli_source_provenance'] = (
        'REVIEWED_EC159_DRIFT_WITH_PRESERVED_EC157' if reviewed_159
        else ('REVIEWED_EC157_DRIFT_FROM_R150' if reviewed
              else ('UNCHANGED_BASELINE' if digest == details['baseline_cli_sha256']
              else 'UNREVIEWED_SOURCE_DRIFT'))
    )
    if digest != details['baseline_cli_sha256'] and not reviewed:
        problems.append('PowerShell CLI differs from its reviewed source baseline')
    if digest != trace.get('source_fingerprints', {}).get(CLI_RELATIVE) and not reviewed:
        problems.append('CLI hash differs from the reviewed action trace')
    try:
        cli = raw.decode('utf-8-sig')
    except UnicodeError as exc:
        raise RegistryError('CLI source cannot be decoded as UTF-8') from exc
    gates, errors = _source_gates(cli)
    problems.extend(errors)
    expected_modes = data['action_modes']
    expected = {
        'Action': data['cli_defaults']['action'], 'Mode': data['cli_defaults']['mode'],
        'action_list': data['supported_actions'],
        'collect_modes': expected_modes['Collect']['modes'],
        'snapshot_actions': ['Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave'],
        'codeshow_modes': expected_modes['CodeShow']['modes'],
        'supported_actions': data['supported_actions'],
        'supported_collect_modes': expected_modes['Collect']['modes'],
        'supported_codeshow_modes': expected_modes['CodeShow']['modes'],
    }
    for key, want in expected.items():
        if gates.get(key) != want:
            problems.append('PowerShell action/mode selector divergence: ' + key)
    # Authorization is a handler gate, not a registry permission grant.
    # This literal check is useful for source drift; native runtime is still NOT_RUN.
    store_source = root / 'scripts/codesave.ps1'
    if not store_source.is_file() or store_source.is_symlink():
        raise RegistryError('CodeSave authorization handler is missing/linked')
    try:
        store_code = store_source.read_text(encoding='utf-8-sig')
    except UnicodeError as exc:
        raise RegistryError('CodeSave source is not UTF-8') from exc
    current_store_sha = hashlib.sha256(store_source.read_bytes()).hexdigest()
    baseline_store_sha = baseline.get('fingerprints', {}).get('scripts/codesave.ps1')
    reviewed_store_159 = _ec159_reviewed_drift(
        root, 'scripts/codesave.ps1', baseline_store_sha, current_store_sha)
    reviewed_store = reviewed_store_159 or _ec157_reviewed_drift(
        root, 'scripts/codesave.ps1', baseline_store_sha, current_store_sha)
    details['codesave_source_provenance'] = (
        'REVIEWED_EC159_DRIFT_WITH_PRESERVED_EC157' if reviewed_store_159
        else ('REVIEWED_EC157_DRIFT_FROM_R150' if reviewed_store
              else ('UNCHANGED_BASELINE' if current_store_sha == baseline_store_sha
              else 'UNREVIEWED_SOURCE_DRIFT'))
    )
    if current_store_sha != baseline_store_sha and not reviewed_store:
        problems.append('CodeSave source differs from its reviewed source baseline')
    if reviewed and not re.search(
        r"if\s*\(\$Action\s+-ieq\s+'CodeSave'\s+-and\s+-not\s+\$ApprovePersist\.IsPresent\)", cli
    ):
        problems.append('EC-157 CLI authorization preflight missing')
    if not re.search(r'if\s*\(-not\s+\$ApprovePersist\)\s*\{(?:(?!\n\s*\}).)*CODE_SAVE_AUTHORIZATION_REQUIRED', store_code, re.S):
        problems.append('CodeSave explicit ApprovePersist denial gate not found')
    if not re.search(r'CodeSave-Snapshot\s+-Envelope\s+\$envelope[^\r\n]*-ApprovePersist\s+\$ApprovePersist\.IsPresent', cli, re.I):
        problems.append('CodeSave call no longer forwards explicit ApprovePersist switch')
    original_routes = trace.get('routes', [])
    original = {r['id']: r for r in original_routes if isinstance(r, dict) and 'id' in r}
    if len(original) != len(original_routes) or set(original) != {r['id'] for r in data['routes']}:
        problems.append('EC-152 16 source route IDs differ from registry')
    for route in data['routes']:
        evidence = original.get(route['id'])
        if not evidence:
            continue
        for field, orig in [('action', evidence.get('action')), ('mode', evidence.get('mode')),
                            ('handler', evidence.get('handler')), ('dispatcher', evidence.get('dispatcher')),
                            ('submode_handler', evidence.get('submode_handler')),
                            ('inputs', evidence.get('inputs')), ('effect', evidence.get('effect')),
                            ('primary_smoke', evidence.get('tests', {}).get('primary_smoke'))]:
            if route.get(field) != orig:
                problems.append('EC-152 route evidence divergence: ' + route['id'] + ' ' + field)
    from trace_actions import check_trace
    trace_result = check_trace(trace)
    if trace_result['problems']:
        problems.extend('EC-152 existing handler/source evidence: ' + p for p in trace_result['problems'])
    details['trace_warnings'] = trace_result['warnings']
    expected_plan = [
        {'name': item['name'], 'status': 'NOT_IMPLEMENTED',
         'planned_range': item.get('planned_range'), 'cli_handler_registered': False}
        for item in matrix.get('actions', []) if item.get('status') == 'NOT_IMPLEMENTED'
    ]
    # Native planned modes are distinct from later Python standalone routes.
    expected_plan = matrix.get('native_planned_capabilities', expected_plan)
    if data['planned_capabilities'] != expected_plan:
        problems.append('planned capability names/states/ranges differ from capability matrix')
    implemented_in_matrix = [x for x in matrix.get('actions', []) if x.get('status') == 'IMPLEMENTED_UNVERIFIED']
    if len(implemented_in_matrix) != 8:
        problems.append('capability matrix no longer represents the original 7 families/8 baseline rows')
    details['authored_route_count'] = len(data['routes'])
    details['planned_capability_count'] = len(data['planned_capabilities'])
    details['native_powershell'] = 'NOT_RUN'
    return {'verdict': 'STATIC_CONTRACT_MATCH' if not problems else 'STATIC_CONTRACT_MISMATCH',
            'problems': problems, 'details': details,
            'scope': 'STATIC_PROVENANCE_AND_SOURCE_SHAPE_NOT_RUNTIME_VALIDATION'}


def _print(value: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return
    if 'decision' in value:
        print(f"{value['decision']}: {value['requested_action']} (Mode={value['requested_mode']!r})")
        if value.get('route'):
            r = value['route']
            print(f"  route {r['id']} -> {r['handler']['file']}::{r['handler']['symbol']}")
            print('  effect ' + r['effect'] + '; runtime unverified, no handler invoked')
        else:
            print('  rejection: ' + value['reason_code'] + f" (PowerShell exit {value['cli_rejection_exit_code']})")
        print('  ' + value['message'])
    elif 'verdict' in value:
        print(value['verdict'])
        for p in value['problems']:
            print('  - ' + p)
        print('  Not a PowerShell/Smoke acceptance result.')
    elif 'routes' in value and 'kind' in value:
        print(value['action'] + ': ' + value['runtime_state'] + ' / ' + value['mode_policy']['rule'])
        for r in value['routes']:
            print('  ' + r['id'] + ' -> ' + r['handler']['symbol'])
    elif 'kind' in value:
        print(value['query'] + ': ' + value['runtime_state'] + ' / ' + value['kind'])
    else:
        print('Authored Action routes (source only; PowerShell runtime unverified):')
        for a in value['supported_actions']:
            policy = value['action_modes'][a]
            print('  ' + a + ': ' + (', '.join(policy['modes']) or '(Mode ignored)'))
        print('Planned, NOT_IMPLEMENTED (no handlers):')
        for p in value['planned_capabilities']:
            print('  ' + p['name'])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Read-only CES Action/Mode contract; not an action runner')
    commands = parser.add_subparsers(dest='command', required=True)
    list_cmd = commands.add_parser('list', help='List authored routes and blocked planned capabilities')
    list_cmd.add_argument('--json', action='store_true')
    show_cmd = commands.add_parser('show', help='Inspect one authored Action or one planned capability')
    show_cmd.add_argument('name')
    show_cmd.add_argument('--json', action='store_true')
    resolve_cmd = commands.add_parser('resolve', help='Resolve Action/Mode only; does not execute CES')
    resolve_cmd.add_argument('--action', help='Omitted means default Inspect')
    resolve_cmd.add_argument('--mode', help='Omitted is distinct from explicit Mode')
    resolve_cmd.add_argument('--json', action='store_true')
    check_cmd = commands.add_parser('check', help='Compare contract against source and provenance')
    check_cmd.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        data = read_registry()
        if args.command == 'resolve':
            value = resolve(data, action=args.action, mode=args.mode)
            code = value.get('cli_rejection_exit_code') or 0
        elif args.command == 'show':
            value = describe(data, args.name)
            code = 3 if value['kind'] == 'unknown_action_or_capability' else 0
        elif args.command == 'check':
            value = check_registry(data)
            code = 0 if not value['problems'] else 1
        else:
            value = {
                'schema_version': data['schema_version'],
                'claim_level': data['claim_level'],
                'supported_actions': data['supported_actions'],
                'action_modes': data['action_modes'],
                'authored_route_count': len(data['routes']),
                'planned_capabilities': data['planned_capabilities'],
                'no_handler_invoked': True,
            }
            code = 0
    except (RegistryError, OSError, KeyError, TypeError) as exc:
        print('REGISTRY_UNAVAILABLE: ' + str(exc), file=sys.stderr)
        return 2
    _print(value, args.json)
    return code


if __name__ == '__main__':
    sys.exit(main())

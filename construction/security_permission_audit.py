#!/usr/bin/env python3
"""EC244: offline, source-bound CES action/permission review.

No application handler, Git command, provider, broker, or PowerShell process is
invoked. Registry inspection uses AST, not importing the business router.
A PASS_STATIC finding is a checked property of pinned *local source text*,
not execution reachability, authority, filesystem isolation or business safety.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
CONSTRUCTION = Path('construction')
ROUTER = 'construction/unified_action_router.py'
LOCK = 'construction/SECURITY_SOURCE_LOCK.json'
SCHEMA = 'ces.security_permission_audit.v1'
LOCK_SCHEMA = 'ces.ec244.source_lock.v1'
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 512 * 1024
EXPECTED_NATIVE = 16
EXPECTED_NEW = 58
EXPECTED_HOST = 11
EXPECTED_TOTAL = EXPECTED_NATIVE + EXPECTED_NEW
EFFECTS = frozenset({'READ_ONLY_OR_LOCAL_PROPOSAL',
                     'PRIVATE_CES_METADATA_WRITE_OPT_IN',
                     'INDEPENDENT_HOST_BRIDGE_REQUIRED'})
MODES = {'CLI', 'API', 'PREVIEW', 'HOST_REQUIRED', 'LEGACY_NATIVE_ONLY'}
# Review of a direct Python module does not cover unprivileged callers outside
# the router.  In particular POST/PRIVATE Git publication are stand-alone, HOST.
ISSUE_READ_MODULES = ('issue_sync', 'issue_show', 'issue_match',
                      'issue_eligibility', 'issue_existing_readonly',
                      'issue_provider', 'issue_unknown_recheck')
CRITICAL_EXTRA = (
    'construction/issue_existing_readonly.py',
    'construction/issue_create_write.py',
    'construction/issue_create_grant.py',
    'construction/issue_unknown_recheck.py',
    'construction/issue_provider.py',
    'construction/docs_only_publish.py',
    'construction/delivery_authorization.py',
    'construction/delivery_send.py',
    'construction/report_publish.py',
    'construction/knowledge_target_binding.py',
    'construction/knowledge_version_save.py',
    'construction/quality_run_guard.py',
    'construction/quality_run_budget.py',
    'construction/proposed_pr_source.py',
    'construction/security_permission_audit.py',
    'scripts/ces.ps1', 'scripts/codesave.ps1',
    'scripts/ces-v5.ps1', 'scripts/ces_router.py', 'scripts/pathidentity.ps1',
)
FORBIDDEN_HTTP = frozenset({'PATCH', 'PUT', 'DELETE', 'MERGE'})
SINK_METHODS = frozenset({'write_text', 'write_bytes', 'mkdir', 'rmdir', 'unlink',
                          'replace', 'rename', 'post_create', 'push', 'run',
                          'Popen', 'put', 'patch', 'delete', 'submit', 'publish'})


class ReviewError(ValueError):
    pass


class Probe(NamedTuple):
    id: str
    domain: str
    file: str
    symbol: str
    required: tuple[str, ...]


# AST fragments are deliberately scoped to the executable function bodies,
# not comments or unrelated files. A reviewed SHA lock is the companion guard.
PROBES = (
    Probe('ROUTER_LEGACY_OWNED', 'routing', ROUTER, 'dispatch',
          ('ROUTER_LEGACY_POWERSHELL_REQUIRED', 'LEGACY', 'REGISTRY')),
    Probe('ROUTER_HOST_DENIED_FIRST', 'routing', ROUTER, 'dispatch',
          ("route.kind == 'HOST_REQUIRED'", 'ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED',
           '_run_cli', '_run_api', '_run_preview')),
    Probe('ROUTER_LOCAL_WRITE_EXPLICIT', 'routing', ROUTER, '_request',
          ('route.effect == LOCAL', 'acknowledge_private_ces_write', 'is True',
           'ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED')),
    Probe('ROUTER_HOST_INPUT_NOT_CREDENTIALS', 'routing', ROUTER, '_request',
          ('ROUTER_HOST_ONLY_CANNOT_ACCEPT_FAKE_CREDENTIAL_INPUT', 'stdin_json')),
    Probe('ROUTER_FIXED_SOURCE_FILES', 'routing', ROUTER, '_regular_module',
          ('MODULE_ROOT', 'route.module', 'stat.S_ISREG', 'is_symlink')),
    Probe('ROUTER_CHILD_ISOLATED', 'routing', ROUTER, '_run_cli',
          ('sys.executable', "'-I'", 'subprocess.run', 'TIMEOUT_SECONDS')),
    Probe('ROUTER_API_IMPORT_PIN', 'routing', ROUTER, '_run_api',
          ('_regular_module', 'importlib.import_module', '__file__',
           'ROUTER_IMPORTED_HANDLER_ORIGIN_MISMATCH')),
    Probe('ROUTER_PREVIEW_FIXED_CONSTRUCTORS', 'routing', ROUTER, '_run_preview',
          ('delivery_preview', 'report_history', 'finding_show',
           'ROUTER_DELIVERY_PREVIEW_FIELDS_INVALID')),
    Probe('ROUTER_RESULT_CANONICAL', 'routing', ROUTER, 'dispatch',
          ('normalize_handler', 'handler_invoked=True', 'outcome=normalized')),
    Probe('ISSUE_GET_ONLY_SELECTED', 'existing_issue',
          'construction/issue_existing_readonly.py', 'issue_http_route',
          ("method == 'GET'", "'EC220_SELECTED'", "'EC219_RECHECK'",
           'READ_ROUTE_NOT_AUTHORIZED')),
    Probe('ISSUE_NEW_COLLECTION_ONLY', 'existing_issue',
          'construction/issue_existing_readonly.py', 'issue_http_route',
          ("method in ('GET', 'POST')", "kind == 'CREATE_NEW_COLLECTION'",
           'NEW_CREATE_ONLY_ROUTE')),
    Probe('ISSUE_READ_INDEPENDENT_ACCESS', 'existing_issue',
          'construction/issue_existing_readonly.py', 'read_existing_issue',
          ('_access_ok', "issue_http_route('GET'", 'REPOSITORY_CHANGED_DURING_READ')),
    Probe('ISSUE_CREATE_ONCE_LEDGER_BEFORE_POST', 'existing_issue',
          'construction/issue_create_write.py', 'create_new_issue_once',
          ('_permit', '_reservation', 'attempt_ledger.atomic_start',
           'ALREADY_RECORDED', 'er.allow_issue_http', 'active.post_create')),
    Probe('ISSUE_CREATE_TRANSPORT_ONLY_NEW', 'existing_issue',
          'construction/issue_create_write.py', 'StrictHTTPSIssueCreateTransport.post_create',
          ("self._request('POST'",)),
    Probe('ISSUE_UNKNOWN_ONLY_GET', 'existing_issue',
          'construction/issue_unknown_recheck.py', 'recheck_unknown_issue',
          ('_permit', 'get_json', 'record_candidate')),
    Probe('DOCS_EXACT_SAFE_PATH', 'docs_publication',
          'construction/docs_only_publish.py', '_safe_path',
          ('DOC_PATH', '.md', 'fullmatch')),
    Probe('DOCS_FOUR_SEPARATE_SIGNERS', 'docs_publication',
          'construction/docs_only_publish.py', 'DocsOnlyPublisher._verify',
          ('repository_policy', 'content_review', 'current_revocation',
           'one_use_grant', 'ACTIVE_CODE_SHA256')),
    Probe('DOCS_DISJOINT_ROOTS', 'docs_publication',
          'construction/docs_only_publish.py', 'DocsOnlyPublisher.__init__',
          ('GIT_PUBLICATION_SANDBOX_NOT_ISOLATED', 'self.workroot',
           'self.journalroot', 'self.bare')),
    Probe('DOCS_STAGING_NEW_DOCS_ONLY', 'docs_publication',
          'construction/docs_only_publish.py', 'DocsOnlyPublisher.publish_once',
          ('NON_DOC_PATH_STAGED', "'add'", "'--'", 'self._verify_isolated_commit')),
    Probe('DOCS_PRIVATE_NEW_REF_ONLY', 'docs_publication',
          'construction/docs_only_publish.py', 'DocsOnlyPublisher.publish_once',
          ('self._reference_absent', 'OnceOnlyDocsJournal', "'push'",
           "'--force-with-lease='", 'self.bare', 'PRIVATE_SANDBOX_REF_NOT_OBSERVED')),
    Probe('DOCS_NO_AUTORETRY', 'docs_publication',
          'construction/docs_only_publish.py', 'DocsOnlyPublisher.publish_once',
          ('journal.claim', 'GIT_LOCAL_EFFECT_OR_HOST_STATE_UNKNOWN_NO_RETRY')),
    Probe('DOCS_GIT_PROTOCOL_LIMITED', 'docs_publication',
          'construction/docs_only_publish.py', 'RestrictedGit.run',
          ('protocol.allow=never', 'protocol.file.allow=always',
           'GIT_CONFIG_NOSYSTEM', 'subprocess.run', 'env=env')),
    Probe('QUALITY_RUN_HOST_POLICY', 'independent_authority',
          'construction/quality_run_guard.py', 'QualityRunSafetyGate.prepare',
          ('_verify_ticket', '_host_grant', '_checked_root')),
    Probe('QUALITY_RUN_BROKER', 'independent_authority',
          'construction/quality_run_budget.py', 'QualityRunBudgetController.run',
          ('security_gate', '_run_grant', 'broker')),
    Probe('KNOWLEDGE_SAVE_INDEPENDENT_APPROVAL', 'independent_authority',
          'construction/knowledge_version_save.py', 'KnowledgeVersionSave.save',
          ('_verify_approvals', '_open', 'write=True')),
    Probe('DELIVERY_INDEPENDENT_GRANT', 'independent_authority',
          'construction/delivery_send.py', 'DeliverySender.send_once',
          ('self._permit', 'DurableGrantOutbox', 'submit')),
    Probe('REPORT_PUBLISH_INDEPENDENT_GRANT', 'independent_authority',
          'construction/report_publish.py', 'ReportPublisher.publish_once',
          ('self._verify', 'PrivatePublishOutbox', 'publish')),
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(root: Path, relative: str) -> bytes:
    if not re.fullmatch(r'[a-zA-Z0-9_./-]{1,160}', relative) or '\\' in relative or '..' in relative.split('/'):
        raise ReviewError('INVALID_RELATIVE_SOURCE_PATH')
    path = root / relative
    try:
        if any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents):
            raise ReviewError('SOURCE_SYMLINK_NOT_ADMITTED:' + relative)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SOURCE_BYTES:
            raise ReviewError('SOURCE_NOT_REGULAR_OR_BOUNDED:' + relative)
        raw = path.read_bytes()
    except OSError as exc:
        raise ReviewError('SOURCE_UNAVAILABLE:' + relative) from exc
    if len(raw) != info.st_size or not raw:
        raise ReviewError('SOURCE_CHANGED_DURING_READ:' + relative)
    return raw


@lru_cache(maxsize=512)
def _parse_bytes(raw: bytes, relative: str) -> ast.Module:
    try:
        return ast.parse(raw.decode('utf-8', 'strict'), filename=relative)
    except (SyntaxError, UnicodeError, RecursionError, ValueError) as exc:
        raise ReviewError('SOURCE_PYTHON_PARSE_FAILED:' + relative) from exc


def _source(root: Path, relative: str) -> tuple[ast.Module, bytes]:
    raw = _read(root, relative)
    return _parse_bytes(raw, relative), raw


@lru_cache(maxsize=512)
def _unparse(node: ast.AST) -> str:
    return ast.unparse(node)


def _value(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, RecursionError, MemoryError) as exc:
        raise ReviewError('REGISTRY_NOT_LITERAL_AND_REVIEWABLE') from exc


def _named_assignment(tree: ast.Module, key: str) -> ast.AST:
    matches: list[ast.AST] = []
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == key for t in n.targets):
            matches.append(n.value)
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == key:
            matches.append(n.value)
    if len(matches) != 1 or matches[0] is None:
        raise ReviewError('REGISTRY_BINDING_NOT_UNIQUE:' + key)
    return matches[0]


def _route_call(node: ast.AST) -> dict[str, Any]:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        raise ReviewError('UNREVIEWED_ROUTE_EXPRESSION')
    builder = node.func.id
    if builder not in ('C', 'A', 'H', 'Route'):
        raise ReviewError('UNREVIEWED_ROUTE_BUILDER')
    args = [_value(a) for a in node.args]
    kwargs = {}
    for kw in node.keywords:
        if kw.arg is None or kw.arg in kwargs:
            raise ReviewError('ROUTE_KEYWORD_EXPANSION_FORBIDDEN')
        if isinstance(kw.value, ast.Name) and kw.value.id in ('READ', 'LOCAL', 'HOST'):
            kwargs[kw.arg] = {'READ': 'READ_ONLY_OR_LOCAL_PROPOSAL',
                              'LOCAL': 'PRIVATE_CES_METADATA_WRITE_OPT_IN',
                              'HOST': 'INDEPENDENT_HOST_BRIDGE_REQUIRED'}[kw.value.id]
        else:
            kwargs[kw.arg] = _value(kw.value)
    if builder in ('C', 'A', 'H'):
        action, mode, module = args[:3]
        symbol = 'main' if builder == 'C' else args[3]
        kind = {'C': 'CLI', 'A': 'API', 'H': 'HOST_REQUIRED'}[builder]
        effect = kwargs.get('effect', 'READ_ONLY_OR_LOCAL_PROPOSAL')
        if builder == 'H':
            effect = 'INDEPENDENT_HOST_BRIDGE_REQUIRED'
        prefix = list(kwargs.get('prefix', ()))
    else:
        if len(args) < 5:
            raise ReviewError('ROUTE_POSITIONAL_FIELDS_MISSING')
        action, mode, kind, module, symbol = args[:5]
        effect = args[5] if len(args) > 5 else kwargs.get('effect', 'READ_ONLY_OR_LOCAL_PROPOSAL')
        prefix = list(kwargs.get('prefix', ()))
    if (not all(type(x) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,47}', x)
                for x in (action, mode)) or
        type(module) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', module) or
        type(symbol) is not str or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.]{0,100}', symbol) or
        kind not in MODES or kind == 'LEGACY_NATIVE_ONLY' or effect not in EFFECTS or
        any(type(s) is not str or len(s) > 100 for s in prefix)):
        raise ReviewError('ROUTE_SHAPE_INVALID')
    if (kind == 'HOST_REQUIRED') != (effect == 'INDEPENDENT_HOST_BRIDGE_REQUIRED'):
        raise ReviewError('HOST_EFFECT_MISMATCH')
    return {'action': action, 'mode': mode, 'kind': kind, 'module': module,
            'symbol': symbol, 'effect': effect, 'prefix': prefix}


def extract_routes(root: Path) -> list[dict[str, Any]]:
    tree, _ = _source(root, ROUTER)
    legacy = _value(_named_assignment(tree, 'LEGACY'))
    route_expr = _named_assignment(tree, 'ROUTES')
    if type(legacy) is not dict or not isinstance(route_expr, (ast.Tuple, ast.List)):
        raise ReviewError('REGISTRY_LAYOUT_INVALID')
    routes: list[dict[str, Any]] = []
    for action, modes in legacy.items():
        if (type(action) is not str or type(modes) is not tuple or
            not modes or any(m is not None and type(m) is not str for m in modes)):
            raise ReviewError('LEGACY_ROUTE_SHAPE_INVALID')
        for m in modes:
            routes.append({'action': action, 'mode': m,
                           'kind': 'LEGACY_NATIVE_ONLY', 'module': 'ces',
                           'symbol': 'scripts/ces.ps1',
                           'effect': ('PRIVATE_CES_METADATA_WRITE_OPT_IN'
                                      if action.casefold() == 'codesave'
                                      else 'READ_ONLY_OR_LOCAL_PROPOSAL'),
                           'prefix': []})
    routes.extend(_route_call(n) for n in route_expr.elts)
    if (len(routes) != EXPECTED_TOTAL or len(routes) - sum(x['kind'] == 'LEGACY_NATIVE_ONLY'
            for x in routes) != EXPECTED_NEW or
        sum(x['kind'] == 'LEGACY_NATIVE_ONLY' for x in routes) != EXPECTED_NATIVE or
        sum(x['kind'] == 'HOST_REQUIRED' for x in routes) != EXPECTED_HOST):
        raise ReviewError('ROUTER_COUNT_DRIFT')
    keys = [(x['action'].casefold(), str(x['mode']).casefold()) for x in routes]
    if len(set(keys)) != len(keys):
        raise ReviewError('ROUTE_ACTION_MODE_COLLISION')
    return routes


def _symbol(tree: ast.Module, path: str) -> ast.AST | None:
    parts = path.split('.')
    current: list[ast.AST] = tree.body
    result: ast.AST | None = None
    for part in parts:
        matches = [n for n in current
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                   and n.name == part]
        if len(matches) != 1:
            return None
        result = matches[0]
        current = result.body
    return result


def _candidate_sinks(node: ast.AST) -> list[str]:
    names: set[str] = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            f = call.func
            if isinstance(f, ast.Attribute) and f.attr in SINK_METHODS:
                names.add(f.attr)
            elif isinstance(f, ast.Name) and f.id in {'open', 'exec', 'eval', 'compile'}:
                names.add(f.id)
    return sorted(names)


def _local_imports(tree: ast.Module, root: Path) -> list[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                names.update(a.name for a in node.names)
            else:
                names.add(node.module.rsplit('.', 1)[-1])
        elif isinstance(node, ast.Import):
            names.update(a.name.split('.')[0] for a in node.names)
    return sorted(n for n in names if (root / CONSTRUCTION / (n + '.py')).is_file())


def _route_info(root: Path, record: dict[str, Any], cache: dict[str, tuple[ast.Module, bytes]]) -> dict[str, Any]:
    record = dict(record)
    if record['kind'] == 'LEGACY_NATIVE_ONLY':
        record.update(source='scripts/ces.ps1', entry_line=None,
                      source_sha256=_sha(_read(root, 'scripts/ces.ps1')),
                      direct_local_imports=[], potential_module_sinks=[],
                      boundary='Legacy PowerShell R150 owner; per-route handler not executed')
        record['entry_chain'] = ['scripts/ces-v5.ps1', 'scripts/ces.ps1']
        return record
    source = f"construction/{record['module']}.py"
    if source not in cache:
        cache[source] = _source(root, source)
    tree, raw = cache[source]
    node = _symbol(tree, record['symbol'])
    if node is None:
        raise ReviewError('ROUTE_HANDLER_SYMBOL_MISSING:' + record['action'] + '/' + record['mode'])
    # Module-level method calls are only candidates: direct and transitive
    # execution, imported functions and dynamic callbacks need final review.
    record.update(entry_chain=['scripts/ces-v5.ps1', 'scripts/ces_router.py', ROUTER,
                               source + ':' + record['symbol']],
                  source=source, entry_line=node.lineno, source_sha256=_sha(raw),
                  direct_local_imports=_local_imports(tree, root),
                  potential_module_sinks=_candidate_sinks(tree),
                  boundary=('Independent host required; target symbol exists, not invoked'
                            if record['kind'] == 'HOST_REQUIRED' else
                            'AST-mapped entry; transitive authority not proven'))
    return record


def _probes(root: Path, cache: dict[str, tuple[ast.Module, bytes]]) -> list[dict[str, Any]]:
    output = []
    for p in PROBES:
        if p.file not in cache:
            cache[p.file] = _source(root, p.file)
        tree = cache[p.file][0]
        node = _symbol(tree, p.symbol)
        if node is None:
            output.append({'id': p.id, 'domain': p.domain, 'source': p.file,
                           'symbol': p.symbol, 'line': None, 'status': 'BLOCKED',
                           'missing': ['SYMBOL_MISSING']})
            continue
        code = _unparse(node)
        missing = [item for item in p.required if item not in code]
        output.append({'id': p.id, 'domain': p.domain, 'source': p.file,
                       'symbol': p.symbol, 'line': node.lineno,
                       'status': 'PASS_STATIC' if not missing else 'BLOCKED',
                       'missing': missing})
    return output


def _structural_guards(root: Path, cache: dict[str, tuple[ast.Module, bytes]]) -> list[dict[str, Any]]:
    """Semantic AST guards where text-fragment probes would be insufficient."""
    result: list[dict[str, Any]] = []
    router = cache[ROUTER][0]
    dispatch = _symbol(router, 'dispatch')
    if dispatch is None:
        raise ReviewError('ROUTER_DISPATCH_MISSING')
    code = _unparse(dispatch)
    host = code.find("route.kind == 'HOST_REQUIRED'")
    cli = code.find("route.kind == 'CLI'")
    api = code.find("route.kind == 'API'")
    result.append({'id': 'HOST_DENIAL_PRECEDES_ANY_HANDLER', 'domain': 'routing',
                   'status': 'PASS_STATIC' if -1 not in (host, cli, api)
                   and host < cli < api else 'BLOCKED',
                   'source': ROUTER, 'line': dispatch.lineno})
    method = _symbol(router, '_result')
    if method is None:
        raise ReviewError('ROUTER_RESULT_MISSING')
    flags = ('business_effect_verified', 'permissions_granted_by_router',
             'external_identity_authenticated_by_router', 'tasks_advanced_by_router',
             'native_powershell_runtime_tested')
    returned: list[ast.Dict] = []
    for n in ast.walk(method):
        if isinstance(n, ast.Dict):
            keys = {k.value: v for k, v in zip(n.keys, n.values)
                    if isinstance(k, ast.Constant) and type(k.value) is str}
            if all(k in keys for k in flags):
                returned.append(n)
                if all(isinstance(keys[k], ast.Constant) and keys[k].value is False for k in flags):
                    break
    good = any(all(isinstance(values[f], ast.Constant) and values[f].value is False
                   for f in flags) for values in (
        {k.value: v for k, v in zip(n.keys, n.values)
         if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        for n in returned))
    result.append({'id': 'RESULT_NEVER_GRANTS_BUSINESS_AUTHORITY', 'domain': 'routing',
                   'status': 'PASS_STATIC' if good else 'BLOCKED',
                   'source': ROUTER, 'line': method.lineno})
    # Ensure no direct issue read CLI adds a network write primitive, even if
    # a malicious function is unreachable in a normal CLI path.
    for name in ISSUE_READ_MODULES:
        path = f'construction/{name}.py'
        if path not in cache:
            cache[path] = _source(root, path)
        tree = cache[path][0]
        unsafe: list[str] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr in ('post_create', 'patch', 'put', 'delete', 'submit'):
                    unsafe.append(f'{n.func.attr}@{n.lineno}')
            if isinstance(n, ast.Constant) and n.value in FORBIDDEN_HTTP:
                unsafe.append(f'forbidden_http_verb@{n.lineno}')
        result.append({'id': 'ISSUE_NONMUTATING_MODULE_' + name.upper(),
                       'domain': 'existing_issue', 'source': path,
                       'status': 'PASS_STATIC' if not unsafe else 'BLOCKED',
                       'details': unsafe})
    # Only the explicitly reviewed private DocsOnly entry may run Git push;
    # changing a dispatch to a direct source-branch push must fail this guard.
    docs = cache['construction/docs_only_publish.py'][0]
    pushes = []
    for n in ast.walk(docs):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and
            n.func.attr == 'run' and n.args and isinstance(n.args[1] if len(n.args) > 1 else None,
                                                        ast.Constant) and
            n.args[1].value == 'push'):
            pushes.append(n.lineno)
    publish = _symbol(docs, 'DocsOnlyPublisher.publish_once')
    result.append({'id': 'DOCS_ONLY_ONE_PRIVATE_PUSH_SITE', 'domain': 'docs_publication',
                   'source': 'construction/docs_only_publish.py',
                   'status': ('PASS_STATIC' if publish is not None and len(pushes) == 1
                              and publish.lineno <= pushes[0] <= publish.end_lineno
                              else 'BLOCKED'), 'details': pushes})
    # Bridge and original native CodeSave authority must be present at the
    # actual source entrypoints; PowerShell is NOT parsed or run here.
    bridges = {
        'LEGACY_NATIVE_CODE_SAVE_OPTIN': (
            'scripts/ces.ps1',
            ("if ($Action -ieq 'CodeSave' -and -not $ApprovePersist.IsPresent)",
             'CODE_SAVE_AUTHORIZATION_REQUIRED',
             'CodeSave-Snapshot', '-ApprovePersist $ApprovePersist.IsPresent')),
        'V5_POWERSHELL_LEGACY_DELEGATION': (
            'scripts/ces-v5.ps1',
            ("if (-not $PSBoundParameters.ContainsKey('RequestPath'))",
             "Join-Path $PSScriptRoot 'ces.ps1'", 'exit $LASTEXITCODE')),
        'V5_POWERSHELL_PYTHON_BRIDGE': (
            'scripts/ces-v5.ps1',
            ("$bridgeAllowed = @('Action', 'Mode', 'RequestPath', 'Json')",
             "Join-Path $PSScriptRoot 'ces_router.py'", '-I $bridgeScript',
             '$proofFieldsAreFalse', '$resultIsCoherent')),
    }
    for check_id, (path, anchors) in bridges.items():
        code = _read(root, path).decode('utf-8', 'strict')
        # Only strip full-line PowerShell comments; inline comments are not
        # used as evidence. SHA lock remains necessary, not sufficient.
        code = '\n'.join(line for line in code.splitlines()
                         if not line.lstrip().startswith('#'))
        missing = [x for x in anchors if x not in code]
        result.append({'id': check_id, 'domain': 'native_bridge', 'source': path,
                       'status': 'PASS_STATIC' if not missing else 'BLOCKED',
                       'missing': missing})
    wrapper, _ = _source(root, 'scripts/ces_router.py')
    direct = _unparse(wrapper)
    result.append({'id': 'PY_WRAPPER_FIXED_ROUTER_IMPORT', 'domain': 'routing',
                   'source': 'scripts/ces_router.py',
                   'status': ('PASS_STATIC' if 'from unified_action_router import main' in direct
                              and 'sys.exit(main())' in direct and
                              'sys.path.insert' in direct else 'BLOCKED')})
    return result


@lru_cache(maxsize=12)
def _entrypoints_from_snapshot(root_text: str,
                               snapshot: tuple[tuple[str, int, int], ...]) -> tuple[str, ...]:
    root = Path(root_text)
    entries: list[str] = []
    for relative, _, _ in snapshot:
        raw = _read(root, relative)
        if b'__main__' not in raw:  # conservative fast prefilter only
            continue
        tree = _parse_bytes(raw, relative)
        for n in tree.body:
            if isinstance(n, ast.If) and isinstance(n.test, ast.Compare):
                test = _unparse(n.test)
                if test in ("__name__ == '__main__'", "'__main__' == __name__"):
                    entries.append(relative)
                    break
    return tuple(sorted(entries))


def _direct_entrypoints(root: Path) -> list[str]:
    # Paths/sizes/mtime capture newly introduced entrypoints without rescanning
    # every Python AST on every individual gate. Hash pins still read bytes.
    snapshot = []
    for folder in ('construction', 'scripts'):
        for p in sorted((root / folder).glob('*.py')):
            info = p.lstat()
            snapshot.append((str(p.relative_to(root)), info.st_size, info.st_mtime_ns))
    return list(_entrypoints_from_snapshot(str(root), tuple(snapshot)))


def _lock_paths(root: Path, routes: list[dict[str, Any]]) -> list[str]:
    return sorted({ROUTER, *CRITICAL_EXTRA, *_direct_entrypoints(root),
                   *(str(p.relative_to(root)) for d in ('scripts', 'tests')
                     for p in (root / d).glob('*.ps1') if p.is_file()),
                   *(f"construction/{x['module']}.py" for x in routes
                     if x['kind'] != 'LEGACY_NATIVE_ONLY')})


def generate_lock(root: Path) -> dict[str, Any]:
    """Build-time only: review and commit; NOT offered by the audit CLI."""
    routes = extract_routes(root)
    return {'schema': LOCK_SCHEMA, 'reviewed_ec': 'EC-244',
            'security_claim': 'PINNED_SOURCE_AND_PATTERNS_ONLY_NOT_PROOF',
            'route_count': len(routes), 'route_registry': routes,
            'direct_entrypoints': _direct_entrypoints(root),
            'source_sha256': {f: _sha(_read(root, f)) for f in _lock_paths(root, routes)}}


def _check_lock(root: Path, routes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    try:
        raw = _read(root, LOCK)
        if len(raw) > MAX_JSON_BYTES:
            raise ReviewError('LOCK_TOO_LARGE')
        lock = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate)
        if (type(lock) is not dict or lock.get('schema') != LOCK_SCHEMA or
            lock.get('route_count') != EXPECTED_TOTAL or lock.get('route_registry') != routes or
            lock.get('direct_entrypoints') != _direct_entrypoints(root) or
            type(lock.get('source_sha256')) is not dict or
            set(lock['source_sha256']) != set(_lock_paths(root, routes))):
            raise ReviewError('REVIEWED_ROUTE_OR_SOURCE_LOCK_MISMATCH')
        rows = []
        for path, expected in sorted(lock['source_sha256'].items()):
            actual = _sha(_read(root, path))
            rows.append({'source': path, 'match': actual == expected})
        return rows, lock
    except (ReviewError, UnicodeError, ValueError, TypeError, OSError, RecursionError) as exc:
        return [{'source': LOCK, 'match': False, 'reason': str(exc)[:100]}], None


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d = {}
    for k, v in pairs:
        if k.casefold() in {x.casefold() for x in d}:
            raise ReviewError('DUPLICATE_LOCK_KEY')
        d[k] = v
    return d


def audit(root: Path = ROOT, *, include_routes: bool = True) -> dict[str, Any]:
    cache: dict[str, tuple[ast.Module, bytes]] = {}
    try:
        routes = extract_routes(root)
        described = [_route_info(root, r, cache) for r in routes]
        probes = _probes(root, cache)
        checks = _structural_guards(root, cache)
        hashes, lock = _check_lock(root, routes)
        violations = [x['id'] for x in (*probes, *checks) if x['status'] != 'PASS_STATIC']
        violations += ['SOURCE_HASH_DRIFT:' + x['source'] for x in hashes if not x['match']]
        result: dict[str, Any] = {
            'schema': SCHEMA, 'package_version': 'V5.54', 'build': 'R244',
            'status': 'BLOCKED_STATIC_REVIEW' if violations else 'PASS_STATIC_SOURCE_ONLY',
            'exit_code': 2 if violations else 0,
            'route_count': len(routes), 'native_route_count': EXPECTED_NATIVE,
            'new_route_count': EXPECTED_NEW, 'host_denied_routes': EXPECTED_HOST,
            'local_opt_in_routes': sum(r['effect'] == 'PRIVATE_CES_METADATA_WRITE_OPT_IN'
                                       for r in routes),
            'route_kinds': dict(sorted(Counter(x['kind'] for x in routes).items())),
            'direct_python_entrypoints': (_direct_entrypoints(root) if include_routes else []),
            'direct_python_entrypoint_count': len(_direct_entrypoints(root)),
            'router_does_not_govern_direct_entrypoints': True,
            'gate_count': len(probes) + len(checks),
            'pass_static_gates': sum(c['status'] == 'PASS_STATIC' for c in (*probes, *checks)),
            'source_pin_count': len(hashes),
            'source_pin_matched': sum(x['match'] for x in hashes),
            'reviewed_source_lock': lock is not None,
            'checks': probes + checks, 'source_pins': hashes,
            'violations': violations,
            'source_authority_authenticated': False, 'actor_authenticated': False,
            'permission_granted': False, 'broker_or_host_attested': False,
            'business_repository_mutation_absence_proven': False,
            'existing_issue_live_nonmutation_proven': False,
            'docs_publication_live_isolation_proven': False,
            'real_network_and_native_runtime_tested': False,
            'limitations': [
                'AST/source SHA and patterns are necessary local review signals, NOT semantic proof of a closed transitive call graph',
                'Direct standalone Python modules bypass the V5 router; only separately authorized hosts may execute side effects',
                'DocsOnly uses source Git administrative worktree metadata; original worktree/index/content isolation not independently observed',
                'Independent signed policy, current actor, source trust, provider credentials, broker and revocation require final host attestations',
                'Python import callbacks/dynamic calls, PowerShell semantics, OS race/symlink/multihost/NFS and network cannot be statically verified',
                'B001 missing frozen source plan remains OPEN; E63-E66, native 15 smoke, final user-assisted acceptance NOT_RUN',
            ],
        }
        if include_routes:
            result['routes'] = described
        return result
    except (ReviewError, OSError, UnicodeError, SyntaxError, TypeError, ValueError,
            MemoryError, RecursionError) as exc:
        return {'schema': SCHEMA, 'package_version': 'V5.54', 'build': 'R244',
                'status': 'BLOCKED_STATIC_REVIEW', 'exit_code': 2,
                'route_count': None, 'violations': [str(exc)[:160]],
                'source_authority_authenticated': False, 'actor_authenticated': False,
                'permission_granted': False, 'business_repository_mutation_absence_proven': False,
                'real_network_and_native_runtime_tested': False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='CES EC244 offline source/permission audit; never grants authority')
    p.add_argument('--summary', action='store_true', help='omit detailed route trace (no business execution)')
    p.add_argument('--route', help='case-insensitive action:mode, one source trace')
    args = p.parse_args(argv)
    result = audit()
    if args.route and 'routes' in result:
        key = args.route.casefold()
        matches = [x for x in result['routes'] if (x['action'] + ':' + str(x['mode'])).casefold() == key]
        if not matches:
            result['status'] = 'BLOCKED_STATIC_REVIEW'
            result['exit_code'] = 2
            result['violations'].append('ROUTE_NOT_FOUND')
        else:
            result['routes'] = matches
    if args.summary:
        result.pop('routes', None)
        result.pop('checks', None)
        result.pop('source_pins', None)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())

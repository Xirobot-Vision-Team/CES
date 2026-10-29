#!/usr/bin/env python3
"""EC241: bounded Action/Mode dispatch into *existing* CES handlers.

This is an actual unified caller boundary, not an executor/authorizer. The R150
PowerShell actions retain their original dispatcher and parameter semantics.
Independent Python CLI modules are invoked in fixed, allowlisted subprocesses;
read-only Python APIs without an argparse entrypoint are called through explicit
method bindings. Host-owned credential/approval/broker providers are never
constructed from request JSON: those actions are registered as HOST_REQUIRED
but cannot be executed by this unprivileged CLI.

A routed result (even a provider or module exit 0) is NOT proof of a successful
business task. EC243 normalizes negative/partial outcomes and retains raw child
claims separately. No auto-retry, DAG advancement or permission grant occurs here.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

from outcome_consistency import (Outcome, normalize_handler,
                                 normalize_router_rejection)

SCHEMA = 'ces.unified_action_router.v2'
REQUEST_SCHEMA = 'ces.unified_action_router.request.v1'
ROOT = Path(__file__).resolve().parent.parent
MODULE_ROOT = ROOT / 'construction'
MAX_REQUEST = 262_144
MAX_RESULT = 262_144
MAX_ARGV = 96
MAX_ARG = 4096
TIMEOUT_SECONDS = 45
# Python's module API and subprocess returns are *not* attested business effects.
LEGACY = {
    'inspect': (None,),
    'collect': ('workingtree', 'deliveredtarget'),
    'reconcile': ('snapshot',),
    'codeprepare': ('snapshot',),
    'codevalidate': ('snapshot',),
    'codesave': ('snapshot',),
    'codeshow': ('list', 'detail', 'findings', 'compare', 'trace', 'overview',
                 'triage', 'recurrence', 'sequence'),
}
READ = 'READ_ONLY_OR_LOCAL_PROPOSAL'
LOCAL = 'PRIVATE_CES_METADATA_WRITE_OPT_IN'
HOST = 'INDEPENDENT_HOST_BRIDGE_REQUIRED'


@dataclass(frozen=True)
class Route:
    action: str
    mode: str
    kind: str  # CLI, API, PREVIEW or HOST_REQUIRED
    module: str
    symbol: str
    effect: str = READ
    prefix: tuple[str, ...] = ()
    initializer_keys: tuple[str, ...] = ()
    initializer_bytes: tuple[str, ...] = ()
    description: str = ''


def C(action: str, mode: str, module: str, *, prefix: tuple[str, ...] = (),
      effect: str = READ, description: str = '') -> Route:
    return Route(action, mode, 'CLI', module, 'main', effect, prefix,
                 description=description)


def A(action: str, mode: str, module: str, symbol: str, *,
      keys: tuple[str, ...] = (), byte_keys: tuple[str, ...] = (),
      effect: str = READ, description: str = '') -> Route:
    return Route(action, mode, 'API', module, symbol, effect,
                 initializer_keys=keys, initializer_bytes=byte_keys,
                 description=description)


def H(action: str, mode: str, module: str, symbol: str, description: str) -> Route:
    return Route(action, mode, 'HOST_REQUIRED', module, symbol, HOST,
                 description=description)


# Fixed, reviewed target identities. Request JSON cannot specify a path, module,
# symbol, Python code, callback, trust root, outbound transport or broker.
ROUTES: tuple[Route, ...] = (
    C('Collect', 'ProposedPR', 'proposed_pr_snapshot'),
    C('Reconcile', 'Remote', 'proposed_pr_reconcile'),
    C('Reconcile', 'DeliveryAssociation', 'proposed_pr_merge'),
    C('CodePrepare', 'MultiSource', 'codeprepare_multisource'),
    C('AIHandoff', 'Lifecycle', 'handoff_lifecycle'),
    C('AIHandoff', 'Stage', 'task_staging', effect=LOCAL),
    C('AIHandoff', 'Input', 'handoff_input'),
    C('AIHandoff', 'Route', 'ai_handoff_router'),
    C('CodeValidate', 'Staged', 'codevalidate_staged'),
    C('CodeSave', 'Staged', 'codesave_staged', effect=LOCAL),
    C('FindingSave', 'Local', 'finding_save', effect=LOCAL),
    H('FindingShow', 'Query', 'finding_show', 'FindingShower.query',
      'Reading HMAC-backed Finding records needs independent host-issued per-store and per-query grants'),
    C('QualityDetect', 'Observe', 'quality_detect'),
    C('QualityReadCI', 'Metadata', 'quality_read_ci'),
    C('QualityReadCI', 'SHABinding', 'quality_sha_bind'),
    C('QualityReadCI', 'Evidence', 'quality_ci_evidence'),
    H('QualityRun', 'Preflight', 'quality_run_guard', 'QualityRunSafetyGate.prepare',
      'Requires independently provisioned policy and isolation broker HMAC verification keys'),
    H('QualityRun', 'Execute', 'quality_run_budget', 'QualityRunBudgetController.run',
      'Actual execution requires host-owned isolated broker and reserved lease'),
    H('QualityShow', 'Query', 'quality_show', 'QualityShow.query',
      'Receipt visibility and cursor key require independent host-scoped authorization callbacks'),
    A('Due', 'Evaluate', 'due_calendar', 'DueCalendar.evaluate'),
    A('ReportPrepare', 'Prepare', 'report_prepare', 'ReportPrepare.bind'),
    A('ReportRender', 'Render', 'report_render', 'ReportRender.render'),
    A('ReportRender', 'SaveLocal', 'report_render', 'ReportRender.save', effect=LOCAL),
    A('ReportShow', 'History', 'report_history', 'ReportHistory.show'),
    A('KnowledgeBootstrap', 'Preview', 'knowledge_bootstrap', 'KnowledgeBootstrap.binding_preview',
      keys=('repository_root', 'knowledge_root')),
    A('KnowledgeBootstrap', 'Read', 'knowledge_bootstrap', 'KnowledgeBootstrap.read',
      keys=('repository_root', 'knowledge_root')),
    H('KnowledgeImpact', 'Analyze', 'knowledge_impact', 'KnowledgeImpact.analyze',
      'Requires independent EC203 target and baseline trust-key configuration'),
    H('KnowledgeSave', 'SaveLocal', 'knowledge_version_save', 'KnowledgeVersionSave.save',
      'Requires separately configured candidate store and two independent signature key roles'),
    H('KnowledgeQuery', 'Chapters', 'knowledge_chapters', 'KnowledgeChapters.map_chapters',
      'Requires independent trusted target/baseline verification keys and read policies'),
    C('IssueSync', 'Read', 'issue_sync'),
    C('IssueShow', 'Read', 'issue_show'),
    C('IssueMatch', 'Match', 'issue_match'),
    C('IssueCreate', 'Eligibility', 'issue_eligibility', prefix=('--stdin-json',)),
    H('IssueCreate', 'Create', 'issue_create_write', 'create_new_issue_once',
      'POST requires host-owned credential, signed one-use grant, durable claim ledger and independent authorization'),
    Route('DeliveryPreview', 'Preview', 'PREVIEW', 'delivery_preview', 'preview_delivery'),
    H('DeliverySend', 'Send', 'delivery_send', 'DeliverySender.send_once',
      'External sending requires host-provided independent roots, credential, provider and durable outbox'),
    H('ReportPublish', 'PrivateTest', 'report_publish', 'ReportPublisher.publish_once',
      'External publication requires private host target, trusted keys and a durable outbox'),
    H('DocsOnlyPublish', 'LocalSandbox', 'docs_only_publish', 'DocsOnlyPublisher.publish_once',
      'Git publication requires independently pinned host policy, reviewer, revocation and sandbox'),
    C('Cycle', 'Create', 'cycle_run_metadata', prefix=('create',), effect=LOCAL),
    C('Cycle', 'Inspect', 'cycle_run_metadata', prefix=('inspect',)),
    C('Cycle', 'DAG', 'cycle_dag', prefix=('check',)),
    C('Cycle', 'Next', 'cycle_next', prefix=('next',)),
    C('Cycle', 'Budget', 'cycle_budget', prefix=('inspect',)),
    C('Cycle', 'Pause', 'cycle_permission_pause', prefix=('pause',), effect=LOCAL),
    C('Cycle', 'PauseInspect', 'cycle_permission_pause', prefix=('inspect',)),
    C('Resume', 'Restore', 'cycle_resume', prefix=('restore',)),
    C('Cycle', 'Summary', 'cycle_summary', prefix=('summary',)),
    C('Cycle', 'CrossLink', 'cycle_cross_action', prefix=('link',), effect=LOCAL,
      description='EC238 link is an unguarded local metadata operation; not an execution transaction'),
    C('Cycle', 'CrossCheck', 'cycle_cross_action', prefix=('check',)),
    C('Cycle', 'CrossAttachGuarded', 'cycle_conflict_guard',
      prefix=('artifact_attach',), effect=LOCAL),
    C('Cycle', 'SchedulePlan', 'cycle_external_scheduler', prefix=('plan',)),
    C('Cycle', 'ScheduledSummaryGuarded', 'cycle_conflict_guard',
      prefix=('scheduled_summary',), effect=LOCAL,
      description='Real read-only EC237 Summary, but EC240 reserves a durable local operation slot'),
    C('Cycle', 'GuardInspect', 'cycle_conflict_guard', prefix=('inspect',)),
    C('Cycle', 'BusinessWriteAttempt', 'cycle_conflict_guard',
      prefix=('business_write_attempt',), description='Existing EC240 handler always denies business writes'),
    C('SchemaReview', 'Inventory', 'schema_migration_review', prefix=('inventory',),
      description='EC242 pinned local catalog, no data or business admission'),
    C('SchemaReview', 'Audit', 'schema_migration_review', prefix=('audit',),
      description='EC242 audit schema IDs, root version markers and exact byte pins'),
    C('SchemaReview', 'Inspect', 'schema_migration_review', prefix=('inspect',),
      description='EC242 read-only versioned per-domain schema validation'),
    C('SchemaReview', 'Plan', 'schema_migration_review', prefix=('plan',),
      description='EC242 read-only migration refusal/reissue path, no mutation'),
)
REGISTRY = {(r.action.casefold(), r.mode.casefold()): r for r in ROUTES}
assert len(REGISTRY) == len(ROUTES) and len(ROUTES) >= 45


class RouterError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input',
                 *, attempted: bool = False) -> None:
        super().__init__(code)
        self.code, self.status, self.attempted = code, status, attempted


def _need(test: bool, code: str, status: str = 'invalid_input') -> None:
    if not test:
        raise RouterError(code, status)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for k, v in pairs:
        key = k.casefold()
        if key in seen:
            raise RouterError('ROUTER_DUPLICATE_OR_CASE_COLLIDING_JSON_KEY')
        seen.add(key)
        result[k] = v
    return result


def _decode_json(raw: bytes) -> dict[str, Any]:
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST,
          'ROUTER_REQUEST_SIZE_INVALID')
    _need(not raw.startswith(b'\xef\xbb\xbf'), 'ROUTER_BOM_FORBIDDEN')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_strict_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except RouterError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise RouterError('ROUTER_REQUEST_JSON_INVALID') from exc
    _need(type(obj) is dict, 'ROUTER_REQUEST_OBJECT_REQUIRED')
    return obj


def _file_bytes(path: str) -> bytes:
    _need(type(path) is str and 1 <= len(path) <= 4096 and os.path.isabs(path),
          'ROUTER_ABSOLUTE_REQUEST_FILE_REQUIRED')
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_REQUEST,
              'ROUTER_REQUEST_FILE_NOT_REGULAR_OR_TOO_LARGE')
        content = os.read(fd, MAX_REQUEST + 1)
        after = os.fstat(fd)
        _need(before.st_dev == after.st_dev and before.st_ino == after.st_ino and
              before.st_size == after.st_size == len(content) and
              before.st_mtime_ns == after.st_mtime_ns and
              before.st_ctime_ns == after.st_ctime_ns,
              'ROUTER_REQUEST_CHANGED_DURING_READ', 'unavailable')
        return content
    except RouterError:
        raise
    except OSError as exc:
        raise RouterError('ROUTER_REQUEST_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _valid_token(s: Any) -> bool:
    return type(s) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,47}', s) is not None


def _api_data(value: Any, code: str) -> dict[str, Any]:
    _need(type(value) is dict and len(value) <= 64 and
          all(type(k) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}', k) for k in value), code)
    return value


def _request(request: dict[str, Any], action: str, mode: str, route: Route) -> dict[str, Any]:
    _need(request.get('schema') == REQUEST_SCHEMA, 'ROUTER_REQUEST_SCHEMA_INVALID')
    _need(request.get('action') == action and request.get('mode') == mode,
          'ROUTER_ACTION_MODE_BINDING_MISMATCH')
    _need(set(request).issubset({'schema', 'action', 'mode', 'argv', 'init', 'parameters',
                                 'acknowledge_private_ces_write', 'allow_network_read', 'stdin_json'}) and
          type(request.get('acknowledge_private_ces_write', False)) is bool and
          type(request.get('allow_network_read', False)) is bool,
          'ROUTER_REQUEST_FIELDS_INVALID')
    if route.effect == LOCAL:
        _need(request.get('acknowledge_private_ces_write') is True,
              'ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED', 'permission_denied')
    else:
        _need(request.get('acknowledge_private_ces_write') is not True,
              'ROUTER_WRITE_OPT_IN_ON_NONWRITE_ACTION')
    if route.kind == 'CLI':
        _need('init' not in request and 'parameters' not in request and 'argv' in request,
              'ROUTER_CLI_ARGV_REQUIRED')
        if route.module == 'issue_eligibility':
            _need('stdin_json' in request and type(request['stdin_json']) is dict and
                  not request['argv'], 'ROUTER_ELIGIBILITY_STDIN_OBJECT_REQUIRED')
        else:
            _need('stdin_json' not in request, 'ROUTER_STDIN_ONLY_FOR_ELIGIBILITY')
        args = request['argv']
        _need(type(args) is list and len(args) <= MAX_ARGV and
              all(type(a) is str and 0 < len(a) <= MAX_ARG and '\x00' not in a for a in args),
              'ROUTER_CLI_ARGV_INVALID')
        # A missing explicit network opt-in is not an implicit egress grant.
        _need(not any(a in ('--allow-network', '--permit-provider-network-egress')
                      for a in args) or request.get('allow_network_read') is True,
              'ROUTER_NETWORK_OPT_IN_REQUIRED', 'permission_denied')
        _need(not request.get('allow_network_read') or
              any(a in ('--allow-network', '--permit-provider-network-egress') for a in args),
              'ROUTER_NETWORK_OPT_IN_UNUSED')
    elif route.kind in ('API', 'PREVIEW'):
        _need('argv' not in request and 'stdin_json' not in request and
              request.get('allow_network_read', False) is False,
              'ROUTER_API_NO_CLI_OR_NETWORK_FLAGS')
        _api_data(request.get('init', {}), 'ROUTER_INITIALIZER_INVALID')
        _api_data(request.get('parameters', {}), 'ROUTER_PARAMETERS_INVALID')
    else:
        _need('argv' not in request and 'init' not in request and
              'parameters' not in request and 'stdin_json' not in request,
              'ROUTER_HOST_ONLY_CANNOT_ACCEPT_FAKE_CREDENTIAL_INPUT')
    return request


def _result(action: str | None, mode: str | None, *, status: str, reason: str,
            route: Route | None = None, handler_invoked: bool = False,
            handler_attempted: bool = False,
            handler_result: Any = None, handler_exit_code: int | None = None,
            handler_status: str | None = None, outcome: Outcome | None = None) -> dict[str, Any]:
    # Only a normalized, fixed status leaves this Action boundary. Historical
    # raw handler status/exit/result are preserved separately for diagnostics.
    if outcome is None:
        outcome = normalize_router_rejection(status=status, reason_code=reason,
                                            handler_attempted=handler_attempted)
    result = {
        'schema': SCHEMA, 'version': '1.0.0', 'build': '1.0.0',
        'action': action, 'mode': mode,
        'status': outcome.status, 'reason_code': outcome.reason_code,
        'normalized_exit_code': outcome.exit_code,
        'outcome_basis': outcome.basis,
        'handler_outcome_consistent': outcome.handler_outcome_consistent,
        'coverage_assessment': outcome.coverage_assessment,
        'coverage_missing_claims': list(outcome.coverage_missing_claims),
        'route_kind': route.kind if route else None,
        'handler': (route.module + ':' + route.symbol) if route else None,
        'effect_class': route.effect if route else None,
        # Historical meaning: the handler returned a valid JSON object.
        # `handler_attempted` records a subprocess/method call even if no
        # valid bounded result could be kept after a timeout/parse failure.
        'handler_invoked': handler_invoked,
        'handler_attempted': handler_attempted or handler_invoked,
        'handler_exit_code': handler_exit_code, 'handler_status': handler_status,
        'handler_result': handler_result,
        'business_effect_verified': False, 'external_identity_authenticated_by_router': False,
        'permissions_granted_by_router': False, 'tasks_advanced_by_router': False,
        'native_powershell_runtime_tested': False,
        'limitations': 'CES 1.0: normalized outcomes are not actor/permission/source or business-effect proof',
    }
    return result


def _regular_module(route: Route) -> Path:
    _need(re.fullmatch(r'[a-z][a-z0-9_]{0,63}', route.module) is not None,
          'ROUTER_MODULE_NOT_ALLOWLISTED', 'unavailable')
    p = MODULE_ROOT / (route.module + '.py')
    try:
        _need(not p.is_symlink() and p.is_file() and stat.S_ISREG(p.stat().st_mode),
              'ROUTER_HANDLER_SOURCE_NOT_REGULAR', 'unavailable')
        return p
    except OSError as exc:
        raise RouterError('ROUTER_HANDLER_SOURCE_UNAVAILABLE', 'unavailable') from exc


def _run_cli(route: Route, req: dict[str, Any]) -> tuple[Any, int, str | None]:
    module = _regular_module(route)
    args = list(route.prefix) + req['argv']
    # Isolated Python prevents PYTHONPATH/user-site from overriding dependencies;
    # inject ONLY the fixed package directory for existing module sibling imports.
    worker = ('import runpy,sys;sys.path.insert(0,sys.argv[1]);'
              'p=sys.argv[2];sys.argv=[p]+sys.argv[3:];runpy.run_path(p,run_name="__main__")')
    cmd = [sys.executable, '-I', '-B', '-c', worker, str(MODULE_ROOT), str(module), *args]
    stdin_data = None
    if route.module == 'issue_eligibility':
        try:
            stdin_data = json.dumps(req['stdin_json'], ensure_ascii=True, allow_nan=False,
                                    separators=(',', ':')).encode('utf-8')
        except (TypeError, ValueError, RecursionError, OverflowError) as exc:
            raise RouterError('ROUTER_ELIGIBILITY_STDIN_INVALID') from exc
        _need(len(stdin_data) <= 65536, 'ROUTER_ELIGIBILITY_STDIN_TOO_LARGE')
    completed = False
    try:
        with tempfile.TemporaryFile(mode='w+b') as output:
            stdin_kwargs = ({'input': stdin_data} if stdin_data is not None else
                            {'stdin': subprocess.DEVNULL})
            proc = subprocess.run(cmd, stdout=output, stderr=subprocess.DEVNULL,
                                  timeout=TIMEOUT_SECONDS, cwd=ROOT,
                                  check=False, **stdin_kwargs)
            completed = True
            _need(0 <= output.tell() <= MAX_RESULT, 'ROUTER_HANDLER_OUTPUT_TOO_LARGE', 'unavailable')
            output.seek(0)
            raw = output.read(MAX_RESULT + 1)
        _need(len(raw) <= MAX_RESULT, 'ROUTER_HANDLER_OUTPUT_TOO_LARGE', 'unavailable')
        if not raw or raw[:1] != b'{':
            raise RouterError('ROUTER_HANDLER_NONJSON_OUTPUT', 'unavailable')
        try:
            result = json.loads(raw.decode('utf-8', 'strict'),
                                object_pairs_hook=_strict_pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (RouterError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
            raise RouterError('ROUTER_HANDLER_NONJSON_OUTPUT', 'unavailable') from exc
        _need(type(result) is dict, 'ROUTER_HANDLER_OBJECT_REQUIRED', 'unavailable')
        if 'status' in result:
            _need(type(result['status']) is str and len(result['status']) <= 160,
                  'ROUTER_HANDLER_STATUS_INVALID', 'unavailable')
        status = result.get('status')
        return result, proc.returncode, status
    except RouterError as exc:
        exc.attempted = exc.attempted or completed
        raise
    except subprocess.TimeoutExpired as exc:
        raise RouterError('ROUTER_HANDLER_TIMEOUT_OUTCOME_UNKNOWN', 'unavailable',
                          attempted=True) from exc
    except OSError as exc:
        raise RouterError('ROUTER_HANDLER_START_UNAVAILABLE', 'unavailable',
                          attempted=completed) from exc


def _encoded_key(text: Any) -> bytes:
    _need(type(text) is str and re.fullmatch(r'[A-Za-z0-9+/]{40,4096}={0,2}', text) is not None,
          'ROUTER_KEY_BASE64_REQUIRED')
    try:
        value = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RouterError('ROUTER_KEY_BASE64_INVALID') from exc
    _need(32 <= len(value) <= 3072, 'ROUTER_KEY_LENGTH_INVALID')
    return value


def _run_api(route: Route, req: dict[str, Any]) -> tuple[Any, int | None, str | None]:
    _regular_module(route)
    init = dict(req.get('init', {}))
    parameters = dict(req.get('parameters', {}))
    allowed_init = set(route.initializer_keys) | set(route.initializer_bytes)
    _need(set(init).issubset(allowed_init), 'ROUTER_API_INITIALIZER_FIELD_UNEXPECTED')
    for key in route.initializer_bytes:
        _need(key in init, 'ROUTER_API_HOST_CURSOR_KEY_REQUIRED')
        init[key] = _encoded_key(init[key])
    attempted = False
    try:
        # Verify the actual imported target, not just an existing same-name
        # module from a caller-influenced sys.path/sys.modules.
        original = _regular_module(route)
        module = importlib.import_module(route.module)
        _need(Path(getattr(module, '__file__', '')).resolve() == original.resolve(),
              'ROUTER_IMPORTED_HANDLER_ORIGIN_MISMATCH', 'unavailable')
        cls_name, method_name = route.symbol.split('.', 1)
        cls = getattr(module, cls_name)
        owner = cls(**init)
        method = getattr(owner, method_name)
        attempted = True
        result = method(**parameters)
        # No implicit conversion of arbitrary objects/bytes, no plugin dispatch.
        _need(type(result) is dict, 'ROUTER_API_RESULT_NOT_JSON_OBJECT', 'unavailable')
        status = result.get('status')
        _need('status' not in result or (type(status) is str and len(status) <= 160),
              'ROUTER_API_STATUS_INVALID', 'unavailable')
        code = result.get('exit_code')
        _need('exit_code' not in result or type(code) is int,
              'ROUTER_API_EXIT_INVALID', 'unavailable')
        return result, code if type(code) is int else None, status
    except RouterError as exc:
        exc.attempted = exc.attempted or attempted
        raise
    except (TypeError, ValueError, KeyError, OSError, RuntimeError, AttributeError, ImportError) as exc:
        # Exception content may include private source paths or credentials.
        raise RouterError('ROUTER_HANDLER_REJECTED_OR_UNAVAILABLE', 'unavailable',
                          attempted=attempted) from exc


def _run_preview(route: Route, req: dict[str, Any]) -> tuple[Any, int | None, str | None]:
    # EC221 typed objects are assembled ONLY from the known dataclasses; never
    # deserialize arbitrary classes or allow a request to choose a reader.
    _regular_module(route)
    try:
        mod = importlib.import_module('delivery_preview')
        history = importlib.import_module('report_history')
        findings = importlib.import_module('finding_show')
        params = req.get('parameters', {})
        _need(set(params) == {'sources', 'destination', 'policy_revision_sha256',
                              'requested_privacy_floor', 'permit_local_preview',
                              'permit_private_source_metadata_read',
                              'permit_report_content_read_in_process',
                              'permit_finding_digest_details_read'},
              'ROUTER_DELIVERY_PREVIEW_FIELDS_INVALID')
        _need(not req.get('init'), 'ROUTER_DELIVERY_PREVIEW_INIT_FORBIDDEN')
        dest = _api_data(params['destination'], 'ROUTER_DESTINATION_INVALID')
        _need(set(dest) == set(mod.Destination.__dataclass_fields__),
              'ROUTER_DESTINATION_FIELDS_INVALID')
        obj_dest = mod.Destination(**dest)
        sources = params['sources']
        _need(type(sources) is list and 1 <= len(sources) <= 32,
              'ROUTER_SOURCES_INVALID')
        built = []
        for item in sources:
            _need(type(item) is dict and item.get('kind') in ('report', 'finding'),
                  'ROUTER_SOURCE_KIND_INVALID')
            body = {k: v for k, v in item.items() if k != 'kind'}
            if item['kind'] == 'report':
                _need(set(body) == set(mod.ReportSelection.__dataclass_fields__) - {'reader'},
                      'ROUTER_REPORT_SOURCE_FIELDS_INVALID')
                built.append(mod.ReportSelection(reader=history.ReportHistory(), **body))
            else:
                _need(set(body) == set(mod.FindingSelection.__dataclass_fields__) - {'reader'} | {'reader_roots'},
                      'ROUTER_FINDING_SOURCE_FIELDS_INVALID')
                roots = body.pop('reader_roots')
                roots = _api_data(roots, 'ROUTER_FINDING_READER_ROOTS_INVALID')
                _need(set(roots) == {'stage_root', 'business_repo_root', 'finding_store_root'},
                      'ROUTER_FINDING_READER_ROOTS_INVALID')
                built.append(mod.FindingSelection(reader=findings.FindingShower(**roots), **body))
        request = mod.DeliveryPreviewRequest(
            sources=tuple(built), destination=obj_dest,
            **{k: v for k, v in params.items() if k not in ('sources', 'destination')})
        result = mod.preview_delivery(request)
        _need(type(result) is dict, 'ROUTER_PREVIEW_RESULT_NOT_OBJECT', 'unavailable')
        return result, result.get('exit_code') if type(result.get('exit_code')) is int else None, result.get('status')
    except RouterError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OSError, ImportError) as exc:
        raise RouterError('ROUTER_PREVIEW_REJECTED_OR_UNAVAILABLE', 'unavailable') from exc


def inventory() -> dict[str, Any]:
    entries = []
    for name, modes in LEGACY.items():
        for mode in modes:
            entries.append({'action': name, 'mode': mode, 'route_kind': 'LEGACY_NATIVE_R150',
                            'effect': 'PRESERVE_EXISTING_NATIVE_PERMISSION_GATES',
                            'handler': 'scripts/ces.ps1', 'invokable_by_new_router': False})
    for r in ROUTES:
        entries.append({'action': r.action, 'mode': r.mode,
                        'route_kind': r.kind, 'effect': r.effect,
                        'handler': r.module + ':' + r.symbol,
                        'invokable_by_new_router': r.kind != 'HOST_REQUIRED'})
    return {'schema': SCHEMA, 'version': '1.0.0', 'build': '1.0.0',
            'status': 'route_inventory_only_not_business_execution',
            'routes': entries, 'route_count': len(entries),
            'legacy_native_runtime_tested': False,
            'host_only_routes_execute_without_host_bridge': False}


def dispatch(action: str, mode: str, request: dict[str, Any]) -> tuple[dict[str, Any], int]:
    route: Route | None = None
    try:
        _need(_valid_token(action) and _valid_token(mode), 'ROUTER_ACTION_MODE_INVALID')
        key = (action.casefold(), mode.casefold())
        # Legacy source must remain the owner of old CodeSave permission gates.
        if action.casefold() in LEGACY and (
                mode.casefold() in LEGACY[action.casefold()] or
                action.casefold() == 'inspect'):
            return _result(action, mode, status='legacy_native_only',
                           reason='ROUTER_LEGACY_POWERSHELL_REQUIRED'), 3
        route = REGISTRY.get(key)
        _need(route is not None, 'ROUTER_ACTION_OR_MODE_UNREGISTERED', 'not_implemented')
        _request(request, action, mode, route)
        if route.kind == 'HOST_REQUIRED':
            return _result(action, mode, status='permission_denied',
                           reason='ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED', route=route), 3
        if route.kind == 'CLI':
            result, code, status = _run_cli(route, request)
        elif route.kind == 'API':
            result, code, status = _run_api(route, request)
        else:
            result, code, status = _run_preview(route, request)
        # Source/module exit 0 or `status: success` never means business
        # completion. Normalize all handler states before emitting a result.
        normalized = normalize_handler(result, exit_code=code,
                                       handler_status=status)
        payload = _result(action, mode, status=normalized.status,
                          reason=normalized.reason_code,
                          route=route, handler_invoked=True, handler_attempted=True,
                          handler_result=result, handler_exit_code=code,
                          handler_status=status, outcome=normalized)
        raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        _need(len(raw.encode('utf-8')) <= MAX_RESULT,
              'ROUTER_COMBINED_RESULT_TOO_LARGE', 'unavailable')
        return payload, normalized.exit_code
    except RouterError as exc:
        payload = _result(action if _valid_token(action) else None,
                          mode if _valid_token(mode) else None, status=exc.status,
                          reason=exc.code, route=route,
                          handler_attempted=exc.attempted)
        return payload, payload['normalized_exit_code']
    except Exception:
        # Never echo exceptions from upstream handlers: they can include a
        # private path, token or source content. No partial result is retained.
        return _result(action if _valid_token(action) else None,
                       mode if _valid_token(mode) else None, status='unavailable',
                       reason='ROUTER_HANDLER_UNEXPECTED_FAILURE', route=route), 5


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='CES unified routing through EC243, no authorization upgrades')
    p.add_argument('-Action', '--action', help='CES Action exact token')
    p.add_argument('-Mode', '--mode', help='explicit mode exact token')
    p.add_argument('-RequestPath', '--request-path', help='absolute UTF-8 JSON request file')
    p.add_argument('--list-routes', action='store_true', help='read-only Action/Mode inventory')
    args = p.parse_args(argv)
    if args.list_routes:
        out, exit_code = inventory(), 0
    elif not all((args.action, args.mode, args.request_path)):
        out = _result(args.action, args.mode, status='invalid_input',
                      reason='ROUTER_ACTION_MODE_AND_REQUEST_REQUIRED')
        exit_code = 4
    else:
        try:
            request = _decode_json(_file_bytes(args.request_path))
            out, exit_code = dispatch(args.action, args.mode, request)
        except RouterError as exc:
            out = _result(args.action, args.mode, status=exc.status, reason=exc.code,
                          handler_attempted=exc.attempted)
            exit_code = out['normalized_exit_code']
    print(json.dumps(out, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""EC247: reproducible LOCAL cross-module regression data and scenario runner.

Never runs any original PowerShell Smoke, reads user repositories, installs
credentials, enables network, or exercises a host-owned external write bridge.
The one positive metadata write is explicit and confined to a disposable
private temporary directory. Result reports intentionally contain only tested
route IDs and fixed state names, not raw handler data, paths or secrets.

This is developer feedback, NOT native/enterprise/OS/final acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any, Callable

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CONSTRUCTION = ROOT / 'construction'
FIX = CONSTRUCTION / 'fixtures/ec247'
MANIFEST = FIX / 'manifest.json'
MAX_MANIFEST = 48 * 1024
MAX_FIXTURE = 64 * 1024
SCHEMA = 'ces.ec247.regression_report.v1'
FLOW_IDS = (
    'schema_admission', 'calendar_period', 'cycle_source_chain',
    'code_save_gates', 'issue_creation_boundary',
    'delivery_publication_boundary', 'provider_network_boundary',
)
FIXTURE_NAMES = ('schema-cycle-example.json', 'cycle-actions.json',
                 'cycle-input.txt', 'offline-requests.json')
SMOKE_NAMES = (
    'CodeCompare.Smoke.ps1', 'CodeFindings.Smoke.ps1',
    'CodeOverview.Smoke.ps1', 'CodePrepare.Smoke.ps1',
    'CodeRecurrence.Smoke.ps1', 'CodeSave.Smoke.ps1',
    'CodeSequence.Smoke.ps1', 'CodeShow.Smoke.ps1',
    'CodeTrace.Smoke.ps1', 'CodeTriage.Smoke.ps1',
    'CodeValidate.Smoke.ps1', 'Collect.Smoke.ps1',
    'DeliveredTarget.Smoke.ps1', 'Inspect.Smoke.ps1', 'Reconcile.Smoke.ps1',
)
# Deliberately fixed action/mode choices; no fixture can choose an import,
# executable, command, subprocess parameter, provider, destination or root.
FLOW_ROUTES = {
    'schema_admission': ('SchemaReview:Inventory', 'SchemaReview:Audit',
                         'SchemaReview:Inspect', 'SchemaReview:Plan'),
    'calendar_period': ('Due:Evaluate', 'NaturalPeriod:from_instant'),
    'cycle_source_chain': ('Cycle:Create', 'Cycle:Inspect', 'Cycle:Next',
                           'Cycle:Summary', 'Cycle:BusinessWriteAttempt'),
    'code_save_gates': ('CodePrepare:MultiSource', 'CodeSave:Staged',
                        'CodeSave:Snapshot'),
    'issue_creation_boundary': ('IssueCreate:Eligibility', 'IssueCreate:Create'),
    'delivery_publication_boundary': ('DeliveryPreview:Preview', 'DeliverySend:Send',
                                      'DocsOnlyPublish:LocalSandbox',
                                      'ReportPublish:PrivateTest'),
    'provider_network_boundary': ('Collect:ProposedPR',),
}
REQUEST_KEYS = (
    ('Due', 'Evaluate'), ('SchemaReview', 'Inventory'), ('SchemaReview', 'Audit'),
    ('IssueCreate', 'Eligibility'), ('IssueCreate', 'Create'),
    ('DeliveryPreview', 'Preview'), ('DeliverySend', 'Send'),
    ('DocsOnlyPublish', 'LocalSandbox'), ('Collect', 'ProposedPR'),
    ('CodePrepare', 'MultiSource'), ('CodeSave', 'Staged'),
    ('CodeSave', 'Snapshot'), ('ReportPublish', 'PrivateTest'),
)


class RegressionError(Exception):
    """All displayed errors are static reason codes, never input content."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise RegressionError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path: Path, maximum: int) -> bytes:
    """Read an exact small regular file, never follow the final symlink."""
    try:
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
             'FIXTURE_NOT_REGULAR_OR_SIZE_INVALID')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(path, flags)
        try:
            st0 = os.fstat(fd)
            need(stat.S_ISREG(st0.st_mode) and (st0.st_dev, st0.st_ino) ==
                 (before.st_dev, before.st_ino), 'FIXTURE_REPLACED_BEFORE_READ')
            raw = os.read(fd, maximum + 1)
            st1 = os.fstat(fd)
            need(len(raw) == st0.st_size == st1.st_size and
                 st0.st_mtime_ns == st1.st_mtime_ns and
                 st0.st_ctime_ns == st1.st_ctime_ns,
                 'FIXTURE_CHANGED_DURING_READ')
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise RegressionError('FIXTURE_READ_FAILED') from exc


def strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            need(key not in obj, 'FIXTURE_DUPLICATE_JSON_KEY')
            obj[key] = value
        return obj
    def no_constants(_: str) -> None:
        raise RegressionError('FIXTURE_NONFINITE_JSON_NUMBER')
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                          parse_constant=no_constants)
    except RegressionError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RegressionError('FIXTURE_JSON_INVALID') from exc


def load_plan() -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    plan = strict_json(regular_bytes(MANIFEST, MAX_MANIFEST))
    need(type(plan) is dict and plan.get('schema') == 'ces.ec247.regression_manifest.v1'
         and plan.get('ec') == 'EC-247' and plan.get('version') == 'V5.57',
         'REGRESSION_MANIFEST_VERSION_INVALID')
    flows = plan.get('flows')
    need(type(flows) is list and len(flows) == len(FLOW_IDS) and
         tuple(e.get('id') for e in flows if type(e) is dict) == FLOW_IDS,
         'REGRESSION_FLOW_SET_DRIFT')
    for item in flows:
        need(item.get('route_chain') == list(FLOW_ROUTES[item['id']]) and
             item.get('type') == 'LOCAL_SYNTHETIC_ONLY',
             'REGRESSION_FLOW_BINDING_DRIFT')
    native = plan.get('native_smokes')
    need(type(native) is list and len(native) == 15 and
         tuple(Path(e['file']).name for e in native) == SMOKE_NAMES,
         'REGRESSION_NATIVE_15_SET_DRIFT')
    for item in native:
        name = item['file']
        need(name == 'tests/' + Path(name).name and
             item['execution'] == 'NOT_RUN_NATIVE_PWSH7_GIT' and
             re.fullmatch(r'[a-f0-9]{64}', item['sha256']) is not None,
             'REGRESSION_SMOKE_ENTRY_INVALID')
        need(sha(regular_bytes(ROOT / name, 4_194_304)) == item['sha256'],
             'REGRESSION_ORIGINAL_SMOKE_CHANGED')
    pins = plan.get('fixtures_sha256')
    need(type(pins) is dict and set(pins) == set(FIXTURE_NAMES),
         'REGRESSION_FIXTURE_SET_DRIFT')
    for name in FIXTURE_NAMES:
        need(type(pins[name]) is str and sha(regular_bytes(FIX / name, MAX_FIXTURE))
             == pins[name], 'REGRESSION_FIXTURE_PIN_DRIFT')
    requests = strict_json(regular_bytes(FIX / 'offline-requests.json', MAX_FIXTURE))
    need(type(requests) is dict and requests.get('schema') == 'ces.ec247.fixed_requests.v1',
         'REGRESSION_REQUESTS_FORMAT_INVALID')
    rows = requests.get('requests')
    need(type(rows) is list and len(rows) == len(REQUEST_KEYS) and
         tuple((e.get('action'), e.get('mode')) for e in rows if type(e) is dict)
         == REQUEST_KEYS, 'REGRESSION_REQUEST_SET_DRIFT')
    for r in rows:
        need(r.get('schema') == 'ces.unified_action_router.request.v1' and
             not r.get('allow_network_read', False) and
             not r.get('acknowledge_private_ces_write', False) and
             set(r).issubset({'schema', 'action', 'mode', 'argv', 'parameters', 'stdin_json'}),
             'REGRESSION_UNSAFE_REQUEST_FIELD')
    need(plan.get('constraints') == {
        'business_repository_writes': False, 'network_egress_requested': False,
        'host_credentials_included': False, 'native_smokes_executed': False,
        'legacy_15_smokes_rewritten': False, 'real_provider_or_user_approval': False,
        'final_acceptance_started': False}, 'REGRESSION_SAFETY_SCOPE_CHANGED')
    return plan, {(r['action'], r['mode']): r for r in rows}


def _router() -> Any:
    if str(CONSTRUCTION) not in sys.path:
        sys.path.insert(0, str(CONSTRUCTION))
    import unified_action_router as router
    need(Path(router.__file__).resolve() == CONSTRUCTION / 'unified_action_router.py',
         'ROUTER_SOURCE_ORIGIN_MISMATCH')
    need(router.SCHEMA == 'ces.unified_action_router.v2' and
         router.REQUEST_SCHEMA == 'ces.unified_action_router.request.v1' and
         router.inventory()['route_count'] == 74,
         'ROUTER_ROUTE_OR_WIRE_DRIFT')
    return router


class Scenario:
    def __init__(self, router: Any, requests: dict[tuple[str, str], dict[str, Any]]):
        self.router = router
        self.requests = requests
        self.observed: list[dict[str, Any]] = []

    def call(self, action: str, mode: str, *, request: dict[str, Any] | None = None,
             code: int, status: str, invoked: bool | None = None,
             reason: str | None = None) -> dict[str, Any]:
        if request is None:
            request = self.requests[(action, mode)]
        need(request.get('action') == action and request.get('mode') == mode and
             request.get('schema') == self.router.REQUEST_SCHEMA,
             'SCENARIO_REQUEST_BINDING_INVALID')
        out, rc = self.router.dispatch(action, mode, request)
        need(type(out) is dict and rc == out.get('normalized_exit_code') and
             out.get('schema') == 'ces.unified_action_router.v2',
             'SCENARIO_NORMALIZED_WIRE_INVALID')
        need(rc == code and out['status'] == status and
             (reason is None or out['reason_code'] == reason) and
             (invoked is None or out['handler_invoked'] is invoked),
             'SCENARIO_UNEXPECTED_ROUTE_OUTCOME')
        need(all(out.get(key) is False for key in (
            'business_effect_verified', 'permissions_granted_by_router',
            'tasks_advanced_by_router', 'native_powershell_runtime_tested',
            'external_identity_authenticated_by_router')),
            'SCENARIO_FALSE_BUSINESS_ATTESTATION')
        self.observed.append({'route': action + ':' + mode,
                              'normalized_status': out['status'],
                              'normalized_exit': rc,
                              'handler_invoked': out['handler_invoked']})
        return out

    def local(self, ident: str, state: str) -> None:
        """Record an in-process API call (not a Router route)."""
        self.observed.append({'route': ident, 'normalized_status': state,
                              'normalized_exit': 2, 'handler_invoked': True})


def example_request(router: Any, action: str, mode: str, **kwargs: Any) -> dict[str, Any]:
    return {'schema': router.REQUEST_SCHEMA, 'action': action, 'mode': mode, **kwargs}


def schema_admission(s: Scenario, base: Path) -> None:
    inv = s.call('SchemaReview', 'Inventory', code=2, status='partial', invoked=True)
    need(inv['handler_result']['data']['registered_json_schema_contracts'] == 112,
         'SCHEMA_PINNED_112_CATALOG_CHANGED')
    audit = s.call('SchemaReview', 'Audit', code=2, status='partial', invoked=True)
    need(audit['handler_result']['migration_executed'] is False,
         'SCHEMA_AUDIT_REPORTED_MIGRATION')
    original = regular_bytes(FIX / 'schema-cycle-example.json', MAX_FIXTURE)
    path = base / 'schema-example.json'
    path.write_bytes(original)
    read = s.call('SchemaReview', 'Inspect', request=example_request(
        s.router, 'SchemaReview', 'Inspect', argv=[
            '--domain', 'Cycle', '--input', str(path)]),
        code=2, status='partial', invoked=True)
    need(read['handler_result']['structural_validation'] is True and
         read['handler_result']['observed_content_sha256'] == sha(original),
         'SCHEMA_SYNTHETIC_INSTANCE_NOT_RECOGNIZED')
    planned = s.call('SchemaReview', 'Plan', request=example_request(
        s.router, 'SchemaReview', 'Plan', argv=[
            '--domain', 'Cycle', '--input', str(path),
            '--target-contract', 'cycle-cross-action-snapshot.v1']),
        code=2, status='partial', invoked=True)
    need(planned['handler_result']['disposition'] == 'NOOP_KEEP_EXACT_ORIGINAL_BYTES'
         and planned['handler_result']['migration_executed'] is False and
         regular_bytes(path, MAX_FIXTURE) == original,
         'SCHEMA_PLAN_DID_NOT_PRESERVE_BYTES')


def calendar_period(s: Scenario, base: Path) -> None:
    due = s.call('Due', 'Evaluate', code=2, status='partial', invoked=True)
    observation = s.requests[('Due', 'Evaluate')]['parameters']
    need(due['handler_result']['decision']['state'] == 'DUE',
         'DUE_SYNTHETIC_HISTORY_NOT_OBSERVED')
    from natural_period import NaturalPeriod
    result = NaturalPeriod().from_instant(
        project_timezone=observation['project_timezone'],
        cadence=observation['cadence'], observed_at=observation['observed_at'])
    need(result['status'] == 'partial' and result['exit_code'] == 2,
         'NATURAL_PERIOD_NOT_COMPUTED')
    period = result['period']
    current = due['handler_result']['calendar']['current_period']
    need(current['start_local'] == period['start_local'] and
         current['end_exclusive_local'] == period['end_exclusive_local'] and
         current['elapsed_seconds'] == period['elapsed_seconds'] and
         result['limitations']['scheduler_report_or_publishing_executed'] is False,
         'DUE_NATURAL_PERIOD_BOUNDARY_MISMATCH')
    replay = NaturalPeriod().from_id(period_id=period['period_id'])
    need(replay['period'] == period, 'NATURAL_PERIOD_ID_REPLAY_CHANGED')
    s.local('NaturalPeriod:from_instant', 'partial')


def cycle_source_chain(s: Scenario, base: Path) -> None:
    need(os.name == 'posix', 'CYCLE_POSIX_LOCAL_STORE_UNAVAILABLE')
    store = base / 'private-store'
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    snapshot = base / 'cycle-input.txt'
    actions = base / 'cycle-actions.json'
    snapshot.write_bytes(regular_bytes(FIX / 'cycle-input.txt', MAX_FIXTURE))
    actions.write_bytes(regular_bytes(FIX / 'cycle-actions.json', MAX_FIXTURE))
    args = ['--store', str(store), '--snapshot-file', str(snapshot),
            '--source-ref', 'synthetic:ec247-offline', '--actor-origin', 'human',
            '--actor-subject', 'ec247-test-operator-not-verified',
            '--actions-json', str(actions)]
    create_req = example_request(s.router, 'Cycle', 'Create', argv=args)
    # First refuse write *without* the explicit private scratch opt-in.
    denied = s.call('Cycle', 'Create', request=create_req, code=3, status='denied',
                    invoked=False, reason='ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED')
    need(list(store.iterdir()) == [] and denied['handler_attempted'] is False,
         'CYCLE_DENIED_CREATE_TOUCHED_STORE')
    create_req['acknowledge_private_ces_write'] = True
    created = s.call('Cycle', 'Create', request=create_req,
                     code=2, status='partial', invoked=True)
    result = created['handler_result']
    need(result['status'] == 'metadata_created_not_started' and
         result['execution_proven'] is False,
         'CYCLE_PRIVATE_FIXTURE_INCOMPLETE')
    run_id = result['run_id']
    record_path = store / (run_id + '.cycle.json')
    need(record_path.exists() and not record_path.is_symlink(),
         'CYCLE_PRIVATE_STORE_MISSING')
    before = sha(regular_bytes(record_path, MAX_FIXTURE))
    inspected = s.call('Cycle', 'Inspect', request=example_request(
        s.router, 'Cycle', 'Inspect', argv=['--store', str(store), '--run-id', run_id]),
        code=2, status='partial', invoked=True)
    record = inspected['handler_result']['record']
    need(inspected['handler_result']['metadata_valid'] is True and
         record['run_state'] == 'NOT_STARTED', 'CYCLE_INSPECT_INCORRECT')
    pins = ['--expected-record-sha256', record['record_sha256'],
            '--expected-action-set-sha256', record['action_set_sha256'],
            '--expected-input-sha256', record['input']['sha256']]
    argbase = ['--store', str(store), '--run-id', run_id, *pins]
    next_result = s.call('Cycle', 'Next', request=example_request(
        s.router, 'Cycle', 'Next', argv=argbase),
        code=2, status='partial', invoked=True)
    proposal = next_result['handler_result']
    need(proposal['status'] == 'NEXT_PROPOSED_NO_EXECUTION' and
         proposal['next_step']['step_id'] == 'step_prepare' and
         proposal['next_step']['handler']['entrypoint'] == 'scripts/ces.ps1' and
         proposal['next_step']['handler']['runtime_verified'] is False,
         'CYCLE_NEXT_DID_NOT_BIND_LEGACY_SOURCE')
    summary = s.call('Cycle', 'Summary', request=example_request(
        s.router, 'Cycle', 'Summary', argv=argbase),
        code=2, status='partial', invoked=True)
    need(summary['handler_result']['status'] == 'NOT_STARTED' and
         summary['handler_result']['counts']['verified_success'] == 0 and
         summary['handler_result']['overall_success_proven'] is False,
         'CYCLE_SUMMARY_PROMOTED_UNEXECUTED_STEPS')
    write = s.call('Cycle', 'BusinessWriteAttempt', request=example_request(
        s.router, 'Cycle', 'BusinessWriteAttempt', argv=argbase),
        code=3, status='denied', invoked=True)
    need(write['handler_result']['reason_code'] ==
         'CONFLICT_BUSINESS_WRITE_REQUIRES_NATIVE_INDEPENDENT_APPROVAL',
         'CYCLE_BUSINESS_WRITE_NOT_REJECTED')
    need(sha(regular_bytes(record_path, MAX_FIXTURE)) == before,
         'CYCLE_SOURCE_RECORD_MODIFIED_DURING_READS')


def code_save_gates(s: Scenario, base: Path) -> None:
    source = s.call('CodePrepare', 'MultiSource', code=4, status='invalid', invoked=True)
    need(source['handler_result']['context'] is None,
         'CODEPREPARE_INVALID_INPUT_EXPOSED_CONTEXT')
    save = s.call('CodeSave', 'Staged', code=3, status='denied', invoked=False,
                  reason='ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED')
    native = s.call('CodeSave', 'Snapshot', code=3, status='denied', invoked=False,
                    reason='ROUTER_LEGACY_POWERSHELL_REQUIRED')
    need(save['handler_attempted'] is False and native['handler_attempted'] is False,
         'CODE_SAVE_GATE_DISPATCHED_HANDLER')


def issue_creation_boundary(s: Scenario, base: Path) -> None:
    eligible = s.call('IssueCreate', 'Eligibility', code=4, status='invalid', invoked=True)
    need(eligible['handler_result']['reason_code'] == 'ISSUE_ELIGIBILITY_CLI_REQUEST_INVALID',
         'ISSUE_ELIGIBILITY_INVALID_INPUT_UNEXPECTED')
    denied = s.call('IssueCreate', 'Create', code=3, status='denied', invoked=False,
                    reason='ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED')
    need(denied['handler_attempted'] is False,
         'ISSUE_CREATE_HOST_EXECUTION_ATTEMPTED')


def delivery_publication_boundary(s: Scenario, base: Path) -> None:
    preview = s.call('DeliveryPreview', 'Preview', code=4, status='invalid', invoked=False,
                     reason='ROUTER_DELIVERY_PREVIEW_FIELDS_INVALID')
    need(preview['handler_attempted'] is False, 'DELIVERY_INVALID_PREVIEW_EXECUTED')
    for act, mode in (('DeliverySend', 'Send'), ('DocsOnlyPublish', 'LocalSandbox'),
                      ('ReportPublish', 'PrivateTest')):
        result = s.call(act, mode, code=3, status='denied', invoked=False,
                        reason='ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED')
        need(result['handler_attempted'] is False,
             'EXTERNAL_PUBLISH_PATH_WAS_INVOKED')


def provider_network_boundary(s: Scenario, base: Path) -> None:
    result = s.call('Collect', 'ProposedPR', code=3, status='denied', invoked=False,
                    reason='ROUTER_NETWORK_OPT_IN_REQUIRED')
    need(result['handler_attempted'] is False and
         result['permissions_granted_by_router'] is False,
         'PROVIDER_NETWORK_REQUEST_BYPASSED_OPT_IN')


FLOW_EXECUTORS: dict[str, Callable[[Scenario, Path], None]] = {
    'schema_admission': schema_admission,
    'calendar_period': calendar_period,
    'cycle_source_chain': cycle_source_chain,
    'code_save_gates': code_save_gates,
    'issue_creation_boundary': issue_creation_boundary,
    'delivery_publication_boundary': delivery_publication_boundary,
    'provider_network_boundary': provider_network_boundary,
}


def execute(only: str | None = None) -> dict[str, Any]:
    plan, requests = load_plan()
    router = _router()
    flows = []
    for name in FLOW_IDS:
        if only is not None and only != name:
            continue
        scenario = Scenario(router, requests)
        try:
            with tempfile.TemporaryDirectory(prefix='ces-ec247-synthetic-') as folder:
                root = Path(folder)
                os.chmod(root, 0o700)
                FLOW_EXECUTORS[name](scenario, root)
            status, error = 'LOCAL_DEVELOPMENT_PASSED', None
        except RegressionError as exc:
            status, error = 'LOCAL_DEVELOPMENT_FAILED', str(exc)
        except Exception:
            # Do not export an exception that might contain private paths.
            status, error = 'LOCAL_DEVELOPMENT_FAILED', 'LOCAL_ENVIRONMENT_OR_UNEXPECTED_HANDLER_FAILURE'
        flows.append({'id': name, 'status': status, 'error_code': error,
                      'steps': scenario.observed})
    return {'schema': SCHEMA, 'package': 'V5.57/R247/EC247',
            'result': 'LOCAL_DEVELOPMENT_PASSED_NOT_FINAL_ACCEPTANCE'
                      if all(x['status'] == 'LOCAL_DEVELOPMENT_PASSED' for x in flows)
                      else 'LOCAL_DEVELOPMENT_INCOMPLETE',
            'flow_count': len(flows), 'flow_passed': sum(x['status'] == 'LOCAL_DEVELOPMENT_PASSED'
                                                      for x in flows),
            'native_smokes_mapped': len(plan['native_smokes']),
            'native_smokes_executed': False, 'real_network_tested': False,
            'business_permissions_granted': False,
            'enterprise_or_os_accepted': False, 'final_acceptance_started': False,
            'flows': flows}


def plan_only() -> dict[str, Any]:
    plan, _ = load_plan()
    return {'schema': 'ces.ec247.regression_plan.v1',
            'version': 'V5.57/R247',
            'native_smokes': [
                {'file': x['file'], 'sha256': x['sha256'],
                 'focus': x['focus'], 'status': 'NOT_RUN_NATIVE'}
                for x in plan['native_smokes']],
            'flows': plan['flows'],
            'scope': 'REPRODUCIBLE_SYNTHETIC_INPUTS_AND_LOCAL_DEVELOPMENT_ONLY',
            'final_acceptance': 'NOT_STARTED'}


def prepare(destination: str) -> dict[str, Any]:
    """Optional opt-in export: a NEW path outside this CES project, no overwrite.

    In addition to exact fixture bytes, individual request V1 JSON documents
    are immediately usable by the unchanged EC243 router with its V2 result.
    """
    _, requests = load_plan()
    path = Path(destination)
    need(path.is_absolute() and path != Path('/') and
         not path.resolve().is_relative_to(ROOT) and
         not ROOT.is_relative_to(path.resolve()),
         'EXPORT_DESTINATION_UNSAFE_OR_INSIDE_PACKAGE')
    need(not path.exists() and not path.is_symlink(), 'EXPORT_DESTINATION_ALREADY_EXISTS')
    # Never follow a symlink directory ancestor of the caller's destination.
    ancestor = path.parent
    while True:
        need(not ancestor.is_symlink(), 'EXPORT_SYMLINK_ANCESTOR')
        if ancestor == ancestor.parent:
            break
        ancestor = ancestor.parent
    need(path.parent.is_dir(), 'EXPORT_PARENT_MISSING')
    files: list[str] = []
    created = False

    def write_new(rel: str, raw: bytes) -> None:
        target = path / rel
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try: os.close(fd)
            except OSError: pass
            raise
        files.append(rel)

    try:
        path.mkdir(mode=0o700)
        created = True
        os.chmod(path, 0o700)
        for name in FIXTURE_NAMES:
            write_new(name, regular_bytes(FIX / name, MAX_FIXTURE))
        request_dir = path / 'requests'
        request_dir.mkdir(mode=0o700)
        os.chmod(request_dir, 0o700)
        commands = [
            '# EC247 local-only V1 request examples, not business execution proof.',
            '# From CES root; replace EXPORT_DIR with the absolute destination.',
            '# HOST_REQUIRED always denies; no network or private CES opt-in.',
        ]
        for action, mode in REQUEST_KEYS:
            request = requests[(action, mode)]
            name = (action + '-' + mode).lower() + '.json'
            relative = 'requests/' + name
            raw = (json.dumps(request, ensure_ascii=True, sort_keys=True,
                              allow_nan=False, separators=(',', ':')) + '\n').encode('ascii')
            write_new(relative, raw)
            commands.append(
                "python3 -I scripts/ces_router.py -Action " + action +
                " -Mode " + mode + " -RequestPath 'EXPORT_DIR/" + relative + "'")
        write_new('router-request-commands.txt',
                  ('\n'.join(commands) + '\n').encode('utf-8'))
        manual = [
            '# EC247 manual acceptance queue: NOT_RUN; requires approved PowerShell 7 + Git host.',
            '# Run from CES package root. Each original Smoke creates its own scratch repo.',
            '# DO NOT run on a user business repository; no outcome is pre-marked PASS.',
        ]
        for name in SMOKE_NAMES:
            manual.append("pwsh -NoProfile -File './tests/" + name + "'")
        write_new('native-smoke-commands.txt',
                  ('\n'.join(manual) + '\n').encode('utf-8'))
    except Exception as exc:
        if created and path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        if isinstance(exc, RegressionError):
            raise
        raise RegressionError('EXPORT_FAILED_NO_PARTIAL_OUTPUT') from exc
    return {'schema': 'ces.ec247.export_receipt.v1',
            'status': 'EXPORTED_FIXED_SYNTHETIC_DATA_NOT_EXECUTED',
            'file_count': len(files), 'files': files,
            'native_smokes_executed': False, 'final_acceptance_started': False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='EC247 reproducible synthetic cross-module cases; NEVER native final acceptance')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan', action='store_true', help='read-only map of 15 native Smoke and new local chains')
    group.add_argument('--run', action='store_true', help='run fixed local synthetic chains only')
    group.add_argument('--prepare', metavar='NEW_ABSOLUTE_DIRECTORY', help='export fixed test data; never run')
    p.add_argument('--only', choices=FLOW_IDS, help='select one fixed local chain (requires --run)')
    args = p.parse_args(argv)
    if args.only and not args.run:
        p.error('--only requires --run')
    try:
        if args.plan:
            data = plan_only()
        elif args.prepare:
            data = prepare(args.prepare)
        else:
            data = execute(args.only)
        rc = 0 if data.get('result') != 'LOCAL_DEVELOPMENT_INCOMPLETE' else 2
    except RegressionError as exc:
        data = {'schema': SCHEMA, 'result': 'REGRESSION_INPUT_REFUSED',
                'reason_code': str(exc), 'native_smokes_executed': False,
                'final_acceptance_started': False}
        rc = 4
    except Exception:
        data = {'schema': SCHEMA, 'result': 'REGRESSION_LOCAL_UNAVAILABLE',
                'reason_code': 'LOCAL_UNEXPECTED_FAILURE',
                'native_smokes_executed': False, 'final_acceptance_started': False}
        rc = 5
    print(json.dumps(data, ensure_ascii=True, allow_nan=False, sort_keys=True,
                     separators=(',', ':')))
    return rc


if __name__ == '__main__':
    raise SystemExit(main())

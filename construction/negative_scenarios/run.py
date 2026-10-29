#!/usr/bin/env python3
"""EC245: deterministic, read-only negative/offline/privacy/resource scenarios.

This is a *development fixture runner*, never a provider/host/enterprise test.
No request-supplied code or fixture locations, no live sockets, no real child
processes, no intentional persistent business writes, no business admission.
The existing EC243 CLI parser may use an anonymous bounded scratch temp file. Mocked transport or
child returns are observations of a local code path, not evidence of service
availability, organizational authorization, privacy release or a completed task.

Run `python -I -B construction/negative_scenarios/run.py --run` from any directory.
Only machine-safe IDs, finite counters and fixed outcome codes are emitted.
Raw provider/exception/credential/subject payloads are NEVER logged or stored.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from typing import Any, Callable
from unittest import mock
from urllib.error import HTTPError, URLError

sys.dont_write_bytecode = True
# -I deliberately removes script locations; add only this fixed bundled module dir.
_MODULE_DIR = str(Path(__file__).resolve().parent.parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

SCHEMA = 'ces.ec245.negative_case_report.v1'
FIXTURE_SCHEMA = 'ces.ec245.negative_cases.v1'
FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures/negative_scenarios/scenarios.json'
# Deliberately conspicuous purely invented canary. NEVER use a real token here.
CANARY = 'EC245_FAKE_PRIVATE_TOKEN_X7Q9_MUST_NOT_APPEAR'
MAX_FIXTURE_BYTES = 128 * 1024
MAX_CASES = 40
MAX_PRINT_BYTES = 20 * 1024
SAFE_ID = re.compile(r'[A-Z]{3}-[0-9]{2}\Z', re.ASCII)
SAFE_REASON = re.compile(r'[A-Z][A-Z0-9_]{2,127}\Z', re.ASCII)


class CaseError(Exception):
    """Do not include private original input or exception repr in errors."""


class FakeCITransport:
    """In-memory only; records GET intent but has zero real network egress."""
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        self.calls.append('SYNTHETIC_GET')
        if not self.responses:
            raise RuntimeError(CANARY + ': unplanned extra synthetic call')
        entry = self.responses.pop(0)
        if isinstance(entry, BaseException):
            raise entry
        return deepcopy(entry)


class FakePRTransport:
    def __init__(self, fail: Exception | None = None) -> None:
        self.calls = 0
        self.fail = fail

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        raise RuntimeError('SIMULATED_TRANSPORT_UNEXPECTED_READ_' + CANARY)


class FakeHTTPSResponse:
    def __init__(self, url: str, *, body: bytes, content_length: str | None = None) -> None:
        self.url = url
        self.status = 200
        self.body = body
        self.headers = {'Content-Type': 'application/json'}
        if content_length is not None:
            self.headers['Content-Length'] = content_length

    def geturl(self) -> str:
        return self.url

    def read(self, count: int) -> bytes:
        return self.body[:count]

    def __enter__(self) -> 'FakeHTTPSResponse':
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class FakeHTTPSOpener:
    def __init__(self, response: FakeHTTPSResponse | None = None,
                 failure: BaseException | None = None) -> None:
        self.response, self.failure = response, failure
        self.calls = 0

    def open(self, request: Any, *, timeout: float) -> FakeHTTPSResponse:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        if self.response is None:
            raise RuntimeError('NO_IN_MEMORY_RESPONSE_' + CANARY)
        return self.response


def _router_req(action: str, mode: str, **kwargs: Any) -> dict[str, Any]:
    import unified_action_router as router
    return {'schema': router.REQUEST_SCHEMA, 'action': action, 'mode': mode, **kwargs}


def _router_invoke(action: str, mode: str, **kwargs: Any) -> tuple[dict[str, Any], int]:
    import unified_action_router as router
    return router.dispatch(action, mode, _router_req(action, mode, **kwargs))


def _router(case: str) -> tuple[dict[str, Any], int]:
    """Actual EC243 dispatch, with real input gates; CLI fault injections use
    a fake subprocess that writes into the real bounded temporary output file.
    """
    import unified_action_router as router
    if case == 'NET-01':
        return _router_invoke('Collect', 'ProposedPR', argv=['--allow-network'])
    if case == 'PRV-01':
        return _router_invoke('DeliverySend', 'Send')
    if case == 'PRV-02':
        return _router_invoke('CodeSave', 'Staged', argv=[])
    if case == 'PRV-03':
        return _router_invoke('Due', 'Evaluate', parameters={},
                              credential=CANARY)
    if case == 'RES-01':
        return _router_invoke('SchemaReview', 'Inventory',
                              argv=['x' * (router.MAX_ARG + 1)])
    if case == 'RES-02':
        with mock.patch.object(router.subprocess, 'run', side_effect=
                subprocess.TimeoutExpired(['fake', CANARY], 0.0001,
                                          output=CANARY.encode('ascii'))):
            return _router_invoke('SchemaReview', 'Inventory', argv=[])
    if case in {'RES-03', 'PRV-04', 'CON-01'}:
        def child(command: list[str], *, stdout: Any, **kwargs: Any) -> subprocess.CompletedProcess:
            if case == 'RES-03':
                stdout.write(b'x' * (router.MAX_RESULT + 1))
            elif case == 'PRV-04':
                stdout.write(('{' + '"status":"success","Status":"'+ CANARY +'"}').encode('ascii'))
            else:
                stdout.write(b'{"status":"success","exit_code":0}')
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(router.subprocess, 'run', side_effect=child):
            return _router_invoke('SchemaReview', 'Inventory', argv=[])
    if case == 'PRV-05':
        import due_calendar
        with mock.patch.object(due_calendar.DueCalendar, 'evaluate',
                               side_effect=ValueError('private=' + CANARY)):
            return _router_invoke('Due', 'Evaluate', parameters={})
    raise CaseError('UNKNOWN_ROUTER_CASE')


def _router_case(case: str) -> tuple[dict[str, Any], int]:
    # Router's second return value is the normalized *exit code*, not an I/O count.
    result, exit_code = _router(case)
    if exit_code != result['normalized_exit_code']:
        raise CaseError('EC245_ROUTER_RETURN_CODE_MISMATCH')
    return result, 0


def _source(case: str) -> tuple[dict[str, Any], int]:
    import proposed_pr_source as src
    key = src.RequestKey('github', 'synthetic/project', 12)
    if case == 'NET-02':
        fake = FakePRTransport()
        supply_calls: list[str] = []
        def supplier() -> str:
            supply_calls.append('TOKEN_SUPPLIER_CALLED')
            return CANARY
        result = src.fetch_proposed_pr(key, allow_network=False,
                                       token_supplier=supplier, transport=fake)
        if supply_calls:
            raise CaseError('TOKEN_SUPPLIER_CALLED_WITHOUT_OPTIN')
        return result, fake.calls
    if case == 'NET-03':
        fake = FakePRTransport(URLError('private=' + CANARY))
        result = src.fetch_proposed_pr(key, allow_network=True,
                                       token_supplier=lambda: CANARY,
                                       transport=fake)
        return result, fake.calls
    if case in {'RES-04', 'NET-04'}:
        url = src._endpoint(key)  # fixed provider URL, never dispatched
        if case == 'RES-04':
            opener = FakeHTTPSOpener(
                FakeHTTPSResponse(url, body=b'z' * (src.MAX_BODY_BYTES + 1)))
        else:
            opener = FakeHTTPSOpener(failure=HTTPError(url, 302, 'private=' + CANARY,
                                                      {'Location': 'https://example.invalid/' + CANARY}, None))
        with mock.patch.object(src, 'build_opener', return_value=opener):
            try:
                src.StrictHttpsTransport().get_object(url, {'Authorization': 'Bearer ' + CANARY}, 2.0)
            except src.SourceFailure as e:
                return {'status': e.status, 'reason_code': e.reason,
                        'exit_code': 5, 'source': None}, opener.calls
        raise CaseError('PROVIDER_UNEXPECTED_ACCEPTANCE')
    raise CaseError('UNKNOWN_SOURCE_CASE')


def _ci_selection() -> Any:
    import quality_read_ci as ci
    return ci.CISelection('github', 'synthetic/project', 731, 991, 2300, 2,
                          350, 'main', 'a' * 40, 3600)


def _ci_responses() -> list[dict[str, Any]]:
    """Minimal real EC182 GH metadata projection; immutable time baseline."""
    run = {
        'id': 2300, 'workflow_id': 991, 'run_attempt': 2,
        'repository': {'id': 731, 'full_name': 'synthetic/project'},
        'head_branch': 'main', 'head_sha': 'a' * 40,
        'status': 'completed', 'conclusion': 'success',
        'created_at': '2026-10-22T19:45:00Z',
        'updated_at': '2026-10-22T19:58:00Z',
    }
    job = {'id': 350, 'run_id': 2300, 'head_sha': 'a'*40,
           'head_branch': 'main', 'status': 'completed', 'conclusion': 'success',
           'started_at': '2026-10-22T19:48:00Z', 'completed_at': '2026-10-22T19:55:00Z'}
    return [run, {'total_count': 1, 'jobs': [job]}, deepcopy(run)]


def _ci(case: str) -> tuple[dict[str, Any], int]:
    import quality_read_ci as ci
    now = datetime(2026, 10, 22, 20, 0, tzinfo=timezone.utc)
    if case == 'RES-05':
        run = _ci_responses()[0]
        responses = [run, {'total_count': ci.MAX_PAGES * ci.PAGE_SIZE + 1,
                           'jobs': []}]
    elif case == 'PRV-06':
        responses = [RuntimeError('private=' + CANARY)]
    else:
        responses = _ci_responses()
    fake = FakeCITransport(responses)
    def approved(req: dict[str, Any]) -> bool:
        return not (case == 'NET-05' and req['read_kind'] == 'FINALIZE_OBSERVATION')
    result = ci.QualityCIReader(fake, clock=lambda: now).read(
        _ci_selection(), credential=CANARY,
        allow_network=case != 'NET-06', allow_ci_metadata=True,
        authorize=approved)
    return result, len(fake.calls)


def _delivery(case: str) -> tuple[dict[str, Any], int]:
    import delivery_preview as dp
    dest = dp.Destination('INTERNAL_REVIEW', 'MANUAL_EXPORT',
                          'a' * 64, 'b' * 64, 'c' * 64)
    req = dp.DeliveryPreviewRequest(
        sources=(() if case == 'PRV-07' else (None,) * (dp.MAX_SOURCES + 1)),
        destination=dest, policy_revision_sha256='d'*64,
        requested_privacy_floor='CONFIDENTIAL',
        permit_local_preview=case != 'PRV-07',
        permit_private_source_metadata_read=True,
        permit_report_content_read_in_process=False,
        permit_finding_digest_details_read=False)
    return dp.preview_delivery(req), 0


def _redaction(case: str) -> tuple[dict[str, Any], int]:
    import delivery_redaction as dr
    vectors = {
        'PRV-08': ('Authorization: Bearer ' + CANARY, 'CREDENTIAL_OR_TOKEN_MATERIAL'),
        'PRV-09': ('See src/app/private_keys.env', 'REPOSITORY_PATH_OR_SOURCE_FILENAME'),
        'PRV-10': ('- Report slot: `irrelevant\u202e`', 'OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT'),
        'PRV-11': ('contact: fake_person@example.invalid', 'PERSON_OR_CONTACT_CONTENT'),
    }
    input_text, reason = vectors[case]
    # Never retain or return source content. The actual EC222 detector runs on it.
    reasons = dr._check_report_text(input_text)
    if reason not in reasons:
        raise CaseError('SENSITIVE_CONTENT_NOT_REJECTED')
    return {'status': 'denied', 'reason_code': reason, 'exit_code': 3,
            'source': None, 'redacted_metadata_only': True}, 0


def _render(case: str) -> tuple[dict[str, Any], int]:
    import report_render as rr
    result = rr.ReportRender().render(
        handoff_json='X' * (rr.MAX_HANDOFF + 1), prepare_json='{}',
        scope_json='{}', metrics_json='{}', release_policy={},
        review_policy={}, render_policy={})
    return result, 0


SCENARIOS: dict[str, Callable[[str], tuple[dict[str, Any], int]]] = {
    **{i: _router_case for i in (
        'NET-01', 'PRV-01', 'PRV-02', 'PRV-03', 'RES-01', 'RES-02',
        'RES-03', 'PRV-04', 'PRV-05', 'CON-01')},
    **{i: _source for i in ('NET-02', 'NET-03', 'NET-04', 'RES-04')},
    **{i: _ci for i in ('NET-05', 'NET-06', 'PRV-06', 'RES-05', 'CON-02')},
    **{i: _delivery for i in ('PRV-07', 'RES-06')},
    **{i: _redaction for i in ('PRV-08', 'PRV-09', 'PRV-10', 'PRV-11')},
    'RES-07': _render,
}


def load_cases() -> list[dict[str, Any]]:
    """Exact locally bundled, non-symlink, size-bounded fixture. No --path."""
    # Fixed path; bound bytes *before* allocation and recheck the same inode.
    fd = None
    try:
        if FIXTURES.is_symlink():
            raise CaseError('EC245_FIXTURE_MISSING_OR_SYMLINK')
        fd = os.open(FIXTURES, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_CLOEXEC', 0))
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FIXTURE_BYTES:
            raise CaseError('EC245_FIXTURE_SIZE_INVALID')
        raw = os.read(fd, MAX_FIXTURE_BYTES + 1)
        after = os.fstat(fd)
        if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise CaseError('EC245_FIXTURE_CHANGED_DURING_READ')
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            ret: dict[str, Any] = {}
            for key, value in pairs:
                if key in ret:
                    raise CaseError('EC245_FIXTURE_DUPLICATE_KEY')
                ret[key] = value
            return ret
        data = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except CaseError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise CaseError('EC245_FIXTURE_INVALID') from None
    finally:
        if fd is not None:
            os.close(fd)
    if type(data) is not dict or set(data) != {'schema', 'test_level', 'cases'} or \
            data['schema'] != FIXTURE_SCHEMA or data['test_level'] != 'LOCAL_SYNTHETIC_ONLY' or \
            type(data['cases']) is not list or not 1 <= len(data['cases']) <= MAX_CASES:
        raise CaseError('EC245_FIXTURE_ENVELOPE_INVALID')
    seen: set[str] = set()
    for case in data['cases']:
        if type(case) is not dict or set(case) != {'id', 'family', 'boundary',
                                                   'fault', 'expected', 'needs_external'}:
            raise CaseError('EC245_CASE_SHAPE_INVALID')
        cid = case['id']
        if type(cid) is not str or SAFE_ID.fullmatch(cid) is None or cid in seen or \
                cid not in SCENARIOS:
            raise CaseError('EC245_CASE_ID_INVALID')
        seen.add(cid)
        expected_family = {'NET': 'offline', 'PRV': 'privacy',
                           'RES': 'resource', 'CON': 'consistency'}[cid[:3]]
        if case['family'] != expected_family or \
                type(case['boundary']) is not str or \
                re.fullmatch(r'[A-Za-z0-9 ._→/-]{1,120}', case['boundary']) is None or \
                type(case['fault']) is not str or not 1 <= len(case['fault']) <= 160 or \
                case['needs_external'] is not True:
            raise CaseError('EC245_CASE_METADATA_INVALID')
        expected = case['expected']
        if type(expected) is not dict or set(expected) != {
                'status', 'reason_code', 'exit_code', 'injected_calls',
                'handler_attempted', 'handler_invoked', 'payload_retained'} or \
                expected['status'] not in {'partial', 'offline', 'denied', 'invalid',
                                           'invalid_input', 'unavailable'} or \
                type(expected['reason_code']) is not str or \
                SAFE_REASON.fullmatch(expected['reason_code']) is None or \
                type(expected['exit_code']) is not int or expected['exit_code'] not in (2, 3, 4, 5) or \
                type(expected['injected_calls']) is not int or not 0 <= expected['injected_calls'] <= 5 or \
                type(expected['handler_attempted']) not in (bool, type(None)) or \
                type(expected['handler_invoked']) not in (bool, type(None)) or \
                type(expected['payload_retained']) is not bool:
            raise CaseError('EC245_CASE_EXPECTED_INVALID')
        exit_for_status = {'partial': 2, 'offline': 3, 'denied': 3, 'invalid': 4,
                           'invalid_input': 4, 'unavailable': 5}
        if expected['exit_code'] != exit_for_status[expected['status']]:
            raise CaseError('EC245_CASE_EXIT_INCONSISTENT')
    if seen != set(SCENARIOS):
        raise CaseError('EC245_CASE_REGISTRY_INCOMPLETE')
    return data['cases']


def _no_external_side_effects() -> ExitStack:
    """Extra tripwires. All permitted simulated reads use injected transports.

    Not an OS sandbox: monkeypatching cannot prevent native extensions, hostile
    code, fork exec outside Python, DNS or imports executing their own effects.
    Only run against the trusted, locally reviewed CES package.
    """
    stack = ExitStack()
    def stop(*args: Any, **kwargs: Any) -> Any:
        raise CaseError('EC245_UNEXPECTED_EXTERNAL_EFFECT')
    stack.enter_context(mock.patch.object(socket.socket, 'connect', side_effect=stop))
    stack.enter_context(mock.patch.object(socket.socket, 'connect_ex', side_effect=stop))
    stack.enter_context(mock.patch.object(socket, 'create_connection', side_effect=stop))
    stack.enter_context(mock.patch.object(subprocess, 'run', side_effect=stop))
    stack.enter_context(mock.patch.object(subprocess, 'Popen', side_effect=stop))
    return stack


def inspect(case_id: str) -> dict[str, Any]:
    """Do not propagate raw results or traceback to diagnostic JSON."""
    try:
        with _no_external_side_effects():
            result, injected_calls = SCENARIOS[case_id](case_id)
        if type(result) is not dict or type(injected_calls) is not int:
            raise CaseError('EC245_HANDLER_RESULT_INVALID')
        raw = json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'))
        source = result.get('source', None)
        leaked = CANARY in raw
        effects = result.get('effects', {})
        flag_names = ('business_effect_verified', 'external_identity_authenticated_by_router',
                      'permissions_granted_by_router', 'tasks_advanced_by_router',
                      'write_authorized', 'write_performed', 'writes_performed',
                      'delivered', 'published', 'ready_to_send', 'authorized')
        claimed_effect = any(result.get(k) is True for k in flag_names) or (
            type(effects) is dict and any(effects.get(k) is True for k in flag_names))
        # For all denial outcomes `source` and `handler_result` may not contain
        # any returned private data. The positive synthetic CI case is only a
        # projection, explicitly NOT authenticated.
        retained = (source is not None or result.get('preview') is not None or
                    result.get('canonical_json') is not None or
                    (result.get('handler_result') is not None))
        permitted_synthetic_ci = (case_id == 'CON-02' and
            result.get('permission', {}).get('transport') == 'SYNTHETIC' and
            result.get('permission', {}).get('provider_read') == 'NOT_PROVEN_SYNTHETIC' and
            result.get('effects', {}).get('live_network_get_requests') == 0 and
            result.get('coverage', {}).get('test_execution_by_ces') is False)
        status, reason, code = (result.get('status'), result.get('reason_code'),
                                result.get('normalized_exit_code', result.get('exit_code')))
        if type(status) is not str or type(reason) is not str or \
                SAFE_REASON.fullmatch(reason) is None or type(code) is not int:
            raise CaseError('EC245_HANDLER_ENVELOPE_MALFORMED')
        return {'status': status, 'reason_code': reason, 'exit_code': code,
                'injected_calls': injected_calls,
                'handler_attempted': result.get('handler_attempted'),
                'handler_invoked': result.get('handler_invoked'),
                'payload_retained': retained,
                '_safe': not leaked and not claimed_effect and
                         (case_id != 'CON-02' or permitted_synthetic_ci),
                '_canary_absent': not leaked}
    except Exception:
        # This intentionally obscures private exception text and stack paths.
        return {'status': 'unavailable', 'reason_code': 'EC245_LOCAL_CASE_FAILURE',
                'exit_code': 5, 'injected_calls': -1,
                'handler_attempted': None, 'handler_invoked': None,
                'payload_retained': True, '_safe': False,
                '_canary_absent': False}


def execute(case_ids: set[str] | None = None) -> dict[str, Any]:
    cases = load_cases()
    if case_ids is not None:
        if not case_ids or case_ids - {c['id'] for c in cases}:
            raise CaseError('EC245_UNKNOWN_CASE_ID')
        cases = [c for c in cases if c['id'] in case_ids]
    summaries = []
    for case in cases:
        obs = inspect(case['id'])
        ok = obs['_safe'] and obs['_canary_absent'] and all(
            obs[k] == v for k, v in case['expected'].items())
        summaries.append({'id': case['id'], 'family': case['family'],
                          'boundary': case['boundary'],
                          'result': 'PASSED_LOCAL_SIMULATION' if ok else 'FAILED_LOCAL_SIMULATION',
                          'observed_status': obs['status'],
                          'observed_reason_code': obs['reason_code'],
                          'real_provider_or_host_verified': False})
    ok_count = sum(x['result'] == 'PASSED_LOCAL_SIMULATION' for x in summaries)
    report = {
        'schema': SCHEMA, 'version': 'V5.55', 'build': 'R245',
        'status': ('LOCAL_SIMULATION_PASSED_NOT_ONLINE_ACCEPTANCE'
                   if ok_count == len(summaries) else 'LOCAL_FIXTURE_FAILURE'),
        'cases_passed': ok_count, 'cases_failed': len(summaries) - ok_count,
        'cases_run': len(summaries), 'scenario_results': summaries,
        'scenario_level': 'LOCAL_SYNTHETIC_ONLY',
        'native_powershell7_tested': False,
        'full_15_smoke_tested': False,
        'real_network_outage_tested': False,
        'real_provider_response_tested': False,
        'real_enterprise_permissions_tested': False,
        'real_privacy_release_tested': False,
        'real_os_resource_limits_tested': False,
        'business_effect_verified': False,
        'final_user_assisted_acceptance': 'NOT_RUN',
        'limitations': ('Mocked faults, synthetic responses, and local output guards are not proof '
                        'of real provider availability/authorization, OS isolation or full run correctness.'),
    }
    if len(json.dumps(report, ensure_ascii=True)) > MAX_PRINT_BYTES:
        raise CaseError('EC245_REPORT_BUDGET_EXCEEDED')
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC245 local synthetic failure case runner; never live evidence')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--run', action='store_true', help='execute all bounded local fixtures')
    mode.add_argument('--list', action='store_true', help='list local fixture identities only')
    mode.add_argument('--case', action='append', metavar='CASE-ID', help='execute named bundled scenarios')
    args = parser.parse_args(argv)
    try:
        if args.list:
            cases = load_cases()
            report: dict[str, Any] = {
                'schema': SCHEMA, 'status': 'LOCAL_CASE_LIST_ONLY',
                'count': len(cases),
                'cases': [{'id': c['id'], 'family': c['family'], 'boundary': c['boundary']}
                          for c in cases],
                'external_validation': 'NOT_RUN',
            }
            code = 0
        else:
            report = execute(set(args.case) if args.case else None)
            code = 0 if report['cases_failed'] == 0 else 2
    except CaseError:
        report = {'schema': SCHEMA, 'status': 'INVALID_LOCAL_FIXTURE_OR_REQUEST',
                  'reason_code': 'EC245_LOCAL_SUITE_REFUSED',
                  'external_validation': 'NOT_RUN'}
        code = 4
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return code


if __name__ == '__main__':
    sys.exit(main())

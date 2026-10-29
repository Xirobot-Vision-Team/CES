#!/usr/bin/env python3
"""EC188 QualityShow: read-only, exactly scoped *projection* of EC181-187 outputs.

This is NOT a quality store, native PowerShell action, source/runner attestor,
or an execution adapter. Every receipt is caller supplied. Producer SHA256
checksums detect accidental alteration, not forgery. All pages re-authorize
both the exact scope and every supplied evidence item; an HMAC continuation is
integrity only, never a permission, source seal or completeness certificate.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Callable

import quality_detect as detect
import quality_read_ci as ci
import quality_sha_bind as sha
import quality_ci_evidence as ci_evidence
import quality_observation as obs
import quality_run_guard as run_guard
import quality_run_budget as run_budget

SCHEMA = 'ces.quality_show.v1'
CURSOR_SCHEMA = 'ces.quality_show_cursor.v1'
DOMAIN_SCOPE = b'CES-EC188-QUALITYSHOW-SCOPE-v1\0'
DOMAIN_QUERY = b'CES-EC188-QUALITYSHOW-QUERY-v1\0'
DOMAIN_RECORD = b'CES-EC188-QUALITYSHOW-RECORD-v1\0'
DOMAIN_REVISION = b'CES-EC188-QUALITYSHOW-REVISION-v1\0'
DOMAIN_CURSOR = b'CES-EC188-QUALITYSHOW-CURSOR-HMAC-v1\0'
MAX_RECORDS = 96
MAX_EVIDENCE_BYTES = 262144
MAX_BATCH_BYTES = 2 * 1024 * 1024
MAX_PAGE = 25
DEFAULT_PAGE = 10
MAX_CURSOR_BYTES = 2048
MAX_CURSOR_SECONDS = 300
MAX_RESULT_BYTES = 96 * 1024
MAX_SKEW_SECONDS = 10
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
REPO = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z')
STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z\Z')
TOKEN = re.compile(r'[A-Za-z0-9_-]+\.[0-9a-f]{64}\Z')
KINDS = {
    'config': detect.SCHEMA,
    'ci_metadata': ci.SCHEMA,
    'sha_binding': sha.SCHEMA,
    'ci_evidence': ci_evidence.SCHEMA,
    'observation': obs.SCHEMA,
    'run_preflight': run_guard.SCHEMA,
    'run_session': run_budget.SCHEMA,
}
CLASSIFICATIONS = frozenset({'pass', 'fail', 'partial', 'not_run', 'missing',
                              'not_applicable', 'unverified'})
REMOTE_MODES = frozenset({'DeliveredTarget', 'ProposedPR'})
# These are display-safe status tokens only. A provider's "success" or "pass"
# is never reinterpreted as CES-tested or independently authenticated.
PROVIDER_STATES = frozenset({'queued', 'in_progress', 'completed', 'pending',
    'running', 'created', 'waiting_for_resource', 'preparing', 'manual',
    'scheduled', 'success', 'failed', 'failure', 'canceled', 'cancelled',
    'skipped', 'unknown'})
PROVIDER_CONCLUSIONS = frozenset({'success', 'failed', 'failure', 'cancelled',
    'canceled', 'timed_out', 'action_required', 'skipped', 'neutral', 'stale',
    'startup_failure', 'manual', 'unknown'})
TRUST = ('CALLER_SUPPLIED_EC181_187_OUTPUT_CHECKSUMS_NOT_SIGNATURES; '
         'NO_GIT_BYTES_RUNNER_CI_PASS_BENCHMARK_OR_CROSS_SOURCE_PROOF')


class QualityShowError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(value: bool, code: str, status: str = 'invalid_input') -> None:
    if not value:
        raise QualityShowError(code, status)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def _copy_json(value: Any, *, max_bytes: int, code: str) -> tuple[Any, bytes]:
    raw = canonical(value)
    need(len(raw) <= max_bytes, code)
    return json.loads(raw), raw


def _timestamp(value: Any) -> datetime:
    need(type(value) is str and STAMP.fullmatch(value) is not None,
         'QUALITYSHOW_UTC_SECOND_TIMESTAMP_REQUIRED')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise QualityShowError('QUALITYSHOW_TIMESTAMP_INVALID') from exc
    need(result.utcoffset() == timedelta(0), 'QUALITYSHOW_NONUTC_TIMESTAMP')
    return result


def _now(clock: Callable[[], datetime] | None) -> datetime:
    current = (clock or (lambda: datetime.now(timezone.utc)))()
    need(isinstance(current, datetime) and current.tzinfo is not None and
         current.utcoffset() == timedelta(0), 'QUALITYSHOW_HOST_UTC_CLOCK_REQUIRED', 'unavailable')
    return current.astimezone(timezone.utc)


def _stamp(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _scope(raw: Any) -> dict[str, Any]:
    need(type(raw) is dict and type(raw.get('source_mode')) is str,
         'QUALITYSHOW_EXACT_SOURCE_SCOPE_REQUIRED')
    mode = raw['source_mode']
    if mode == 'WorkingTree':
        need(set(raw) == {'source_mode', 'root_pin_sha256'} and
             type(raw['root_pin_sha256']) is str and
             HEX64.fullmatch(raw['root_pin_sha256']) is not None,
             'QUALITYSHOW_LOCAL_SCOPE_INVALID')
    else:
        need(mode in REMOTE_MODES and set(raw) == {
            'source_mode', 'provider', 'repository', 'project_id',
            'commit_sha', 'proposal_number'}, 'QUALITYSHOW_REMOTE_SCOPE_INVALID')
        repo = raw['repository']
        need(raw['provider'] in ('github', 'gitlab') and type(repo) is str and
             len(repo) <= 180 and REPO.fullmatch(repo) is not None and
             all(s not in ('.', '..') for s in repo.split('/')) and
             type(raw['project_id']) is int and 1 <= raw['project_id'] <= 2**63-1 and
             type(raw['commit_sha']) is str and COMMIT.fullmatch(raw['commit_sha']) is not None,
             'QUALITYSHOW_REMOTE_IDENTITY_INVALID')
        number = raw['proposal_number']
        need((mode == 'ProposedPR' and type(number) is int and 1 <= number <= 2**63-1)
             or (mode == 'DeliveredTarget' and number is None),
             'QUALITYSHOW_PROPOSAL_SCOPE_INVALID')
    return dict(raw)


def _filters(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {'kinds': sorted(KINDS), 'classification': None,
                'from_utc': None, 'until_utc': None}
    need(type(raw) is dict and set(raw) <= {'kinds', 'classification', 'from_utc', 'until_utc'},
         'QUALITYSHOW_FILTER_FIELDS_INVALID')
    kinds = raw.get('kinds', sorted(KINDS))
    need(type(kinds) is list and 1 <= len(kinds) <= len(KINDS) and
         all(type(k) is str and k in KINDS for k in kinds) and
         len(set(kinds)) == len(kinds), 'QUALITYSHOW_FILTER_KINDS_INVALID')
    classification = raw.get('classification')
    need(classification is None or (type(classification) is str and
         classification in CLASSIFICATIONS), 'QUALITYSHOW_FILTER_CLASSIFICATION_INVALID')
    start, end = raw.get('from_utc'), raw.get('until_utc')
    if start is not None:
        _timestamp(start)
    if end is not None:
        _timestamp(end)
    need(start is None or end is None or _timestamp(start) <= _timestamp(end),
         'QUALITYSHOW_FILTER_TIME_REVERSED')
    return {'kinds': sorted(kinds), 'classification': classification,
            'from_utc': start, 'until_utc': end}


def _grant(callback: Any, facts: dict[str, Any], code: str) -> None:
    need(callable(callback), code, 'unavailable')
    try:
        allowed = callback(json.loads(canonical(facts)))
    except Exception as exc:
        raise QualityShowError(code, 'unavailable') from exc
    need(allowed is True, code, 'unavailable')


def _field(obj: Any, name: str) -> Any:
    need(type(obj) is dict and name in obj, 'QUALITYSHOW_EVIDENCE_SHAPE_INVALID')
    return obj[name]


def _is_digest(value: Any) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def _check_receipt(kind: str, result: Any) -> None:
    need(type(result) is dict and result.get('schema') == KINDS[kind] and
         result.get('status') == 'partial' and
         type(result.get('exit_code')) is int and result['exit_code'] == 2 and
         type(result.get('trust_boundary')) is str and
         'success' not in result and 'pass' not in result,
         'QUALITYSHOW_ONLY_PARTIAL_GENUINE_SCHEMA_RESULTS')
    if kind == 'config':
        names = ('source', 'files', 'languages', 'tools', 'profile_hints', 'coverage')
        hash_name = 'inventory_sha256'
        correct = detect._sha(detect.DOMAIN_INVENTORY, {k: _field(result, k) for k in names})
    elif kind == 'ci_metadata':
        names = ('source', 'observation', 'permission', 'coverage')
        hash_name = 'observation_sha256'
        correct = ci._hash({k: _field(result, k) for k in names})
    elif kind == 'sha_binding':
        names = ('source', 'ci_observation', 'binding', 'permission', 'coverage')
        hash_name = 'association_sha256'
        correct = sha.checksum({k: _field(result, k) for k in names})
    elif kind == 'ci_evidence':
        names = ('scope', 'test_evidence', 'report_evidence', 'classification',
                 'coverage', 'permission')
        hash_name = 'evidence_sha256'
        correct = ci_evidence.digest({k: _field(result, k) for k in names})
    elif kind == 'observation':
        names = ('observed_at_utc', 'source', 'observations', 'evidence_refs',
                 'execution_environment', 'grants', 'proof')
        hash_name = 'observation_sha256'
        correct = obs._hash({k: _field(result, k) for k in names})
    elif kind == 'run_preflight':
        names = ('prepared_at_utc', 'profile', 'source', 'authorization',
                 'isolation', 'context', 'plan', 'proof')
        hash_name = 'plan_sha256'
        correct = run_guard._digest(run_guard.DOMAIN_PLAN,
                                    {k: _field(result, k) for k in names})
    else:
        # EC187 intentionally DOES NOT expose a source pin or a signed result.
        # Its run events can only be separately shown as caller-linked claims.
        # A real cancellation before broker.begin is also a partial/2
        # EC187 result, but contains no session, output or proof object.
        execution = _field(result, 'execution')
        if execution is None:
            need(result.get('reason_code') ==
                 'QUALITYRUNBUDGET_CANCELLED_BEFORE_START' and
                 all(result.get(k) is None for k in
                     ('output', 'proof', 'profile_id', 'resources', 'limits')) and
                 type(result.get('effects')) is dict and
                 result['effects'].get('external_broker_begin_called') is False and
                 result['effects'].get('external_broker_session_reported') is False and
                 result['effects'].get('execute_authorized') is False,
                 'QUALITYSHOW_NO_RUN_SESSION_EVIDENCE', 'unavailable')
        else:
            need(type(execution) is dict and
                 type(_field(result, 'output')) is dict and
                 type(_field(result, 'proof')) is dict and
                 type(_field(result, 'effects')) is dict,
                 'QUALITYSHOW_NO_RUN_SESSION_EVIDENCE', 'unavailable')
        return
    need(_is_digest(result.get(hash_name)) and
         hmac.compare_digest(correct, result[hash_name]),
         'QUALITYSHOW_PRODUCER_DIGEST_MISMATCH', 'unavailable')


def _remote_match(src: Any, scope: dict[str, Any], *, include_mode: bool) -> None:
    for key in ('provider', 'repository', 'project_id', 'commit_sha'):
        need(type(src) is dict and type(src.get(key)) is type(scope[key]) and
             src[key] == scope[key], 'QUALITYSHOW_EVIDENCE_REMOTE_SCOPE_MISMATCH', 'unavailable')
    if include_mode:
        need(src.get('source_mode') == scope['source_mode'] and
             type(src.get('proposal_number')) is type(scope['proposal_number']) and
             src['proposal_number'] == scope['proposal_number'],
             'QUALITYSHOW_EVIDENCE_PROPOSAL_MODE_MISMATCH', 'unavailable')


def _provider_state(value: Any, allowed: frozenset[str]) -> str:
    return value if type(value) is str and value in allowed else 'unknown'


def _transport(value: Any) -> str:
    return value if type(value) is str and value in ('LIVE_HTTPS', 'SYNTHETIC') else 'UNTRUSTED_OR_UNAVAILABLE'


def _false(value: Any, key: str) -> None:
    need(type(value) is dict and value.get(key) is False,
         'QUALITYSHOW_UNSUPPORTED_VERIFIED_PROOF_FLAG', 'unavailable')


def _safe_nonnegative(value: Any, maximum: int = 1000000000) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def _projection(kind: str, d: dict[str, Any], scope: dict[str, Any],
                *, numeric: bool) -> tuple[dict[str, Any], str, str, list[str]]:
    """Allowlisted summary, classification, binding strength, gap labels."""
    mode = scope['source_mode']
    local = mode == 'WorkingTree'
    classification = 'not_applicable'
    strength = 'EMBEDDED_SOURCE_EXACT_UNAUTHENTICATED'
    gaps: list[str] = []
    view: dict[str, Any] = {'category': kind, 'quality_pass_verified': False}
    if kind == 'config':
        need(local and _field(d, 'source').get('source_mode') == 'WorkingTree' and
             d['source'].get('local_root_pin_sha256') == scope['root_pin_sha256'],
             'QUALITYSHOW_LOCAL_CONFIG_SCOPE_MISMATCH', 'unavailable')
        c = _field(d, 'coverage')
        _false(c, 'repository_wide_inventory_complete')
        _false(c, 'tests_executed')
        view.update(config_inventory_state='BOUNDED_SELECTED_PATHS_ONLY',
                    selected_config_paths=_safe_nonnegative(c.get('selected_paths')),
                    config_parse_gaps=_safe_nonnegative(c.get('unparsed_or_malformed_configs')))
        gaps.extend(['NOT_REPOSITORY_WIDE', 'CONFIG_IS_NOT_TEST_EXECUTION'])
    elif kind == 'ci_metadata':
        need(not local, 'QUALITYSHOW_CI_CANNOT_BIND_LOCAL_WORKTREE', 'unavailable')
        _remote_match(_field(d, 'source'), scope, include_mode=False)
        _false(_field(d, 'coverage'), 'git_sha_binding_verified')
        _false(_field(d, 'coverage'), 'test_execution_by_ces')
        strength = 'REMOTE_METADATA_SHA_MATCH_MODE_CALLER_SELECTED'
        observation = _field(d, 'observation')
        need(type(observation) is dict and type(observation.get('run')) is dict
             and type(observation.get('job')) is dict,
             'QUALITYSHOW_CI_OBSERVATION_SHAPE_INVALID', 'unavailable')
        view.update(ci_run_state='PROVIDER_METADATA_ONLY',
                    provider_run_state=_provider_state(observation['run'].get('state'),
                                                       PROVIDER_STATES),
                    provider_run_conclusion=_provider_state(
                        observation['run'].get('conclusion'), PROVIDER_CONCLUSIONS),
                    provider_job_state=_provider_state(observation['job'].get('state'),
                                                       PROVIDER_STATES),
                    provider_job_conclusion=_provider_state(
                        observation['job'].get('conclusion'), PROVIDER_CONCLUSIONS),
                    transport=_transport(_field(d, 'permission').get('transport')))
        gaps.extend(['SOURCE_MODE_NOT_IN_EC182_RECEIPT', 'GIT_OBJECT_NOT_HASHED',
                     'CI_TEST_NOT_INDEPENDENTLY_VERIFIED'])
    elif kind == 'sha_binding':
        need(not local, 'QUALITYSHOW_REMOTE_BINDING_NOT_LOCAL', 'unavailable')
        _remote_match(_field(d, 'source'), scope, include_mode=True)
        binding = _field(d, 'binding')
        need(binding.get('sha_equal') is True and
             binding.get('source_commit_sha') == scope['commit_sha'] and
             binding.get('ci_commit_sha') == scope['commit_sha'],
             'QUALITYSHOW_SOURCE_CI_SHA_ASSOCIATION_INVALID', 'unavailable')
        _false(binding, 'git_object_bytes_hashed')
        _false(binding, 'tests_executed_by_ces')
        view.update(association='PROVIDER_FIELD_CLAIM_SHA_EQUAL',
                    transport=_transport(_field(d, 'permission').get('transport')))
        gaps.extend(['PROVIDER_FIELD_EQUALITY_NOT_GIT_OBJECT_BYTES',
                     'REMOTE_ATOMIC_SNAPSHOT_NOT_PROVEN'])
    elif kind == 'ci_evidence':
        need(not local, 'QUALITYSHOW_CI_EVIDENCE_NOT_LOCAL', 'unavailable')
        _remote_match(_field(d, 'scope'), scope, include_mode=True)
        _false(_field(d, 'coverage'), 'actual_tests_executed_by_ces')
        _false(_field(d, 'coverage'), 'runner_integrity_verified')
        test = _field(d, 'test_evidence')
        report = _field(d, 'report_evidence')
        classification = _field(d, 'classification')
        need(classification in CLASSIFICATIONS - {'not_applicable', 'unverified'} and
             type(test) is dict and test.get('state') == classification and
             type(report) is dict, 'QUALITYSHOW_CI_CLASSIFICATION_INVALID')
        view.update(test_classification=classification,
                    test_provenance='PROVIDER_LOG_OR_REPORT_CLAIM_NOT_CES_EXECUTED',
                    job_log_availability=test.get('availability') if
                    test.get('availability') in ('present', 'missing', 'unavailable', 'partial', 'not_requested')
                    else 'unknown',
                    report_state=report.get('state') if type(report.get('state')) is str
                    and report['state'] in ('measured', 'partial', 'missing', 'not_requested',
                                            'pass', 'fail', 'not_run') else 'unknown',
                    report_scope=('RUN_LEVEL_ARTIFACT' if d['coverage'].get('github_report_run_only')
                                  else 'EXACT_JOB_OR_NOT_REQUESTED'))
        if numeric and type(test.get('counts')) is dict:
            view['provider_test_counts'] = {
                k: _safe_nonnegative(test['counts'].get(k), 10000000)
                for k in ('total', 'passed', 'failed', 'skipped')}
        if numeric and type(report.get('coverage_metrics')) is dict:
            metrics = report['coverage_metrics']
            view['provider_coverage_metrics'] = {
                'lines_total': _safe_nonnegative(metrics.get('lines_total')),
                'lines_covered': _safe_nonnegative(metrics.get('lines_covered')),
                'percent': metrics.get('percent') if
                type(metrics.get('percent')) in (float, int) and
                0 <= metrics['percent'] <= 100 else None}
        gaps.extend(['PROVIDER_CONTENT_CLAIM_NOT_INDEPENDENT_TEST_EXECUTION',
                     'RUN_LEVEL_REPORT_NOT_EXACT_JOB' if
                     d['coverage'].get('github_report_run_only') else
                     'CROSS_REQUEST_ATOMICITY_NOT_PROVEN'])
    elif kind == 'observation':
        source = _field(d, 'source')
        data = _field(d, 'observations')
        proof = _field(d, 'proof')
        for key in ('overall_quality_pass_verified', 'performance_measured',
                    'ci_test_execution_independently_verified', 'git_object_bytes_verified'):
            _false(proof, key)
        performance = _field(data, 'performance')
        need(performance.get('state') == 'not_measured' and
             performance.get('benchmark_samples') == 0 and
             performance.get('metrics') == [],
             'QUALITYSHOW_BENCHMARK_NEVER_MEASURED', 'unavailable')
        if local:
            inner = source.get('local')
            config = data.get('local_config')
            need(type(inner) is dict and type(config) is dict and
                 inner.get('pin_digest') == scope['root_pin_sha256'] and
                 config.get('pin_digest') == scope['root_pin_sha256'],
                 'QUALITYSHOW_OBSERVATION_LOCAL_SCOPE_MISMATCH', 'unavailable')
            view.update(observation_track='LOCAL_ONLY_EXTRACTED',
                        selected_config_paths=_safe_nonnegative(config.get('candidate_paths')))
            gaps.append('LOCAL_REMOTE_REVISION_NOT_CORRELATED')
        else:
            inner = source.get('remote')
            _remote_match(inner, scope, include_mode=True)
            tests = data.get('tests')
            coverage = data.get('coverage')
            need(type(tests) is dict and type(coverage) is dict and
                 tests.get('is_provider_content_claim') is True and
                 tests.get('ces_tests_executed') is False and
                 coverage.get('independently_measured_by_ces') is False,
                 'QUALITYSHOW_OBSERVATION_CLAIM_LEVEL_INVALID', 'unavailable')
            classification = tests.get('classification')
            need(classification in CLASSIFICATIONS - {'not_applicable', 'unverified'},
                 'QUALITYSHOW_OBSERVATION_TEST_STATE_INVALID')
            view.update(observation_track='REMOTE_ONLY_EXTRACTED',
                        test_classification=classification,
                        test_provenance='PROVIDER_PARSED_CLAIM_ONLY',
                        coverage_state=coverage.get('state') if coverage.get('state') in
                        ('not_requested', 'missing', 'partial', 'provider_reported')
                        else 'unknown')
            if numeric and type(tests.get('counts')) is dict:
                view['provider_test_counts'] = {
                    k: _safe_nonnegative(tests['counts'].get(k), 10000000)
                    for k in ('total', 'passed', 'failed', 'skipped')}
            if numeric and type(coverage.get('metrics')) is dict:
                metrics = coverage['metrics']
                view['provider_coverage_metrics'] = {
                    'lines_total': _safe_nonnegative(metrics.get('lines_total')),
                    'lines_covered': _safe_nonnegative(metrics.get('lines_covered')),
                    'percent': metrics.get('percent') if
                    type(metrics.get('percent')) in (int, float) and
                    0 <= metrics['percent'] <= 100 else None}
            gaps.extend(['CI_CLAIM_NOT_INDEPENDENT_TEST_PROOF',
                         'NO_BENCHMARK_OR_ATTESTED_RUNNER'])
        need(source.get('same_revision_proven') is False,
             'QUALITYSHOW_OBSERVATION_CROSS_SOURCE_PROOF_INVALID', 'unavailable')
    elif kind == 'run_preflight':
        need(local and _field(d, 'source').get('mode') == 'WorkingTree' and
             d['source'].get('source_pin_sha256') == scope['root_pin_sha256'],
             'QUALITYSHOW_RUN_PREFLIGHT_SCOPE_MISMATCH', 'unavailable')
        plan = _field(d, 'plan')
        proof = _field(d, 'proof')
        need(plan.get('state') == 'PREPARED_ONLY_NOT_EXECUTABLE' and
             plan.get('source_pin_sha256') == scope['root_pin_sha256'],
             'QUALITYSHOW_RUN_PREFLIGHT_NOT_ONLY_PLAN', 'unavailable')
        _false(proof, 'overall_quality_pass_verified')
        _false(proof, 'actual_isolation_verified_by_ces')
        view.update(profile_id=_field(d, 'profile').get('id') if
                    _field(d, 'profile').get('id') in ('python.pytest', 'python.ruff')
                    else None,
                    execution_state='NOT_EXECUTED_PREFLIGHT_ONLY')
        gaps.extend(['NO_HOST_EXECUTION_FROM_EC186', 'ISOLATION_NOT_INDEPENDENTLY_PROVEN'])
    else:  # run_session / EC187
        need(local, 'QUALITYSHOW_RUN_SESSION_REMOTE_SCOPE_NOT_SUPPORTED', 'unavailable')
        if d['execution'] is None:
            # Pre-broker cancellation is not a failed test, an exited host,
            # or a verified runner. It has no output and no source pin.
            effects = _field(d, 'effects')
            need(d.get('reason_code') ==
                 'QUALITYRUNBUDGET_CANCELLED_BEFORE_START' and
                 effects.get('external_broker_begin_called') is False and
                 effects.get('external_broker_session_reported') is False and
                 effects.get('execute_authorized') is False and
                 effects.get('stop_requested') is False and
                 effects.get('reaped_reported_by_host') is False,
                 'QUALITYSHOW_PRESTART_STATE_INVALID', 'unavailable')
            strength = 'CALLER_LINKED_NO_SOURCE_PIN_IN_EC187_RESULT'
            classification = 'not_run'
            view.update(profile_id=None,
                        execution_state='NOT_STARTED_CANCELLED_BEFORE_BROKER',
                        host_reported_exit_code=None,
                        host_reported_exit_zero_is_not_pass=False,
                        output_truncated=False,
                        output_complete_host_reported=False,
                        captured_bytes=0,
                        discarded_bytes=0,
                        termination_requested=False,
                        termination_reaped_host_reported=False)
            gaps.extend(['EC187_RESULT_HAS_NO_SOURCE_PIN_BINDING',
                         'NO_EC187_EXTERNAL_SESSION_STARTED'])
            return view, classification, strength, sorted(set(gaps))
        proof = _field(d, 'proof')
        for key in ('quality_pass_verified', 'kernel_isolation_independently_verified',
                    'test_execution_verified_by_ces', 'broker_identity_independently_authenticated'):
            _false(proof, key)
        need(proof.get('host_claims_only') is True,
             'QUALITYSHOW_RUN_RECEIPT_HOST_CLAIM_BOUNDARY_INVALID', 'unavailable')
        execution = _field(d, 'execution')
        output = _field(d, 'output')
        need(execution.get('state') in ('exited_host_reported', 'interrupted_or_unverified') and
             execution.get('overall_pass_verified') is False and
             execution.get('actual_process_exit_independently_verified') is False and
             type(output.get('truncated')) is bool and
             type(output.get('complete')) is bool and
             type(output.get('captured_bytes')) is int and
             type(output.get('discarded_bytes')) is int and
             0 <= output['captured_bytes'] <= 10000000 and
             0 <= output['discarded_bytes'] <= 10000000 and
             (not output['truncated'] or not output['complete']),
             'QUALITYSHOW_RUN_OUTPUT_STATE_INVALID', 'unavailable')
        strength = 'CALLER_LINKED_NO_SOURCE_PIN_IN_EC187_RESULT'
        code = execution.get('host_reported_exit_code')
        need(code is None or type(code) is int and 0 <= code <= 255,
             'QUALITYSHOW_HOST_EXIT_CODE_INVALID', 'unavailable')
        view.update(profile_id=d.get('profile_id') if d.get('profile_id') in
                    ('python.pytest', 'python.ruff') else None,
                    execution_state=execution['state'],
                    host_reported_exit_code=code,
                    host_reported_exit_zero_is_not_pass=(code == 0),
                    output_truncated=output['truncated'],
                    output_complete_host_reported=output['complete'],
                    captured_bytes=output['captured_bytes'],
                    discarded_bytes=output['discarded_bytes'],
                    termination_requested=_field(d, 'effects').get('stop_requested') is True,
                    termination_reaped_host_reported=d['effects'].get('reaped_reported_by_host') is True)
        gaps.extend(['EC187_RESULT_HAS_NO_SOURCE_PIN_BINDING',
                     'HOST_EXECUTION_AND_REAP_UNATTESTED'])
        if output['truncated']:
            gaps.append('CAPTURED_OUTPUT_PREFIX_ONLY')
        if execution['state'] == 'interrupted_or_unverified':
            gaps.append('INTERRUPTED_OR_UNCONFIRMED_TERMINATION')
        classification = 'unverified'
    return view, classification, strength, sorted(set(gaps))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _decode(encoded: str) -> bytes:
    need(type(encoded) is str and 1 <= len(encoded) <= MAX_CURSOR_BYTES and
         re.fullmatch(r'[A-Za-z0-9_-]+', encoded) is not None,
         'QUALITYSHOW_CURSOR_ENCODING_INVALID')
    try:
        raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise QualityShowError('QUALITYSHOW_CURSOR_ENCODING_INVALID') from exc
    need(_b64(raw) == encoded, 'QUALITYSHOW_CURSOR_ENCODING_NONCANONICAL')
    return raw


def _cursor_mac(key: bytes, body: bytes) -> str:
    return hmac.new(key, DOMAIN_CURSOR + body, hashlib.sha256).hexdigest()


def _encode_cursor(key: bytes, item: dict[str, Any]) -> str:
    body = canonical(item)
    token = _b64(body) + '.' + _cursor_mac(key, body)
    need(len(token) <= MAX_CURSOR_BYTES, 'QUALITYSHOW_CURSOR_TOO_LARGE', 'unavailable')
    return token


def _load_cursor(key: bytes, token: Any, *, now: datetime, scope_sha: str,
                 query_sha: str, revision_sha: str, count: int) -> tuple[int, datetime, datetime]:
    need(type(token) is str and len(token) <= MAX_CURSOR_BYTES and
         TOKEN.fullmatch(token) is not None, 'QUALITYSHOW_CURSOR_MALFORMED')
    encoded, signature = token.split('.')
    body = _decode(encoded)
    need(hmac.compare_digest(_cursor_mac(key, body), signature),
         'QUALITYSHOW_CURSOR_MAC_INVALID', 'unavailable')

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            need(k not in out, 'QUALITYSHOW_CURSOR_DUPLICATE_FIELD')
            out[k] = v
        return out

    try:
        item = json.loads(body, object_pairs_hook=unique,
                          parse_constant=lambda _: need(False, 'QUALITYSHOW_CURSOR_NONFINITE'))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise QualityShowError('QUALITYSHOW_CURSOR_JSON_INVALID') from exc
    need(type(item) is dict and set(item) == {'schema', 'scope_sha256',
         'query_sha256', 'revision_sha256', 'count', 'offset', 'issued_at_utc',
         'expires_at_utc'} and item['schema'] == CURSOR_SCHEMA and
         item['scope_sha256'] == scope_sha and item['query_sha256'] == query_sha and
         item['revision_sha256'] == revision_sha and
         type(item['count']) is int and item['count'] == count and
         type(item['offset']) is int and 0 < item['offset'] < count,
         'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED', 'unavailable')
    issued, expiry = _timestamp(item['issued_at_utc']), _timestamp(item['expires_at_utc'])
    need(issued <= now + timedelta(seconds=MAX_SKEW_SECONDS) and now < expiry and
         issued < expiry <= issued + timedelta(seconds=MAX_CURSOR_SECONDS),
         'QUALITYSHOW_CURSOR_EXPIRED_OR_CLOCK_REGRESSED', 'unavailable')
    return item['offset'], issued, expiry


def _effects() -> dict[str, bool]:
    return {'read_only': True, 'ces_store_written': False,
            'business_repository_written': False, 'provider_requests': False,
            'shell_or_tests_executed': False, 'stdout_or_source_disclosed': False,
            'actor_or_runner_authenticated': False, 'git_bytes_verified': False,
            'quality_pass_verified': False}


def _refusal(status: str, code: str) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status,
            'exit_code': {'invalid_input': 4, 'unavailable': 5}[status],
            'reason_code': code, 'scope': None, 'query_sha256': None,
            'revision_sha256': None, 'counts': None, 'coverage': None,
            'order': None, 'page_size': None, 'entries': [],
            'next_cursor': None, 'cursor_expires_at_utc': None,
            'proof': None, 'effects': _effects(), 'trust_boundary': TRUST}


class QualityShow:
    """A stateless, per-request authorized query over bounded supplied receipts.

    Host MUST keep cursor key (>=32 bytes) outside the analyzed repository,
    authorize exact source and every receipt on EVERY page, and supply all
    currently permitted receipts rather than assuming a complete history.
    No cursor, checksum or locally recomputed SHA authenticates their origins.
    """

    def __init__(self, *, cursor_key: bytes,
                 clock: Callable[[], datetime] | None = None) -> None:
        if type(cursor_key) is not bytes or len(cursor_key) < 32:
            raise ValueError('Host-controlled >=32-byte HMAC cursor key required')
        if clock is not None and not callable(clock):
            raise ValueError('Clock must be callable')
        self._key = cursor_key
        self._clock = clock

    def query(self, *, source_scope: dict[str, Any], evidence: list[dict[str, Any]],
              allow_query: bool = False, allow_evidence_read: bool = False,
              authorize_scope: Callable[[dict[str, Any]], bool] | None = None,
              authorize_evidence: Callable[[dict[str, Any]], bool] | None = None,
              filters: dict[str, Any] | None = None, page_size: int = DEFAULT_PAGE,
              cursor: str | None = None, include_numeric_metrics: bool = False,
              authorize_numeric_metrics: Callable[[dict[str, Any]], bool] | None = None,
              acknowledge_historical_proposal: bool = False) -> dict[str, Any]:
        try:
            need(allow_query is True and allow_evidence_read is True,
                 'QUALITYSHOW_QUERY_AND_EVIDENCE_GRANTS_REQUIRED', 'unavailable')
            need(type(page_size) is int and 1 <= page_size <= MAX_PAGE,
                 'QUALITYSHOW_PAGE_SIZE_INVALID')
            need(type(include_numeric_metrics) is bool and
                 type(acknowledge_historical_proposal) is bool,
                 'QUALITYSHOW_PERMISSION_FLAG_INVALID')
            scope = _scope(source_scope)
            if scope['source_mode'] == 'ProposedPR':
                need(acknowledge_historical_proposal,
                     'QUALITYSHOW_PROPOSED_PR_HISTORICAL_ACK_REQUIRED', 'unavailable')
            parsed_filters = _filters(filters)
            need(type(evidence) is list and len(evidence) <= MAX_RECORDS,
                 'QUALITYSHOW_EVIDENCE_LIST_LIMIT_INVALID')
            # Snapshot before untrusted callbacks. Refuse if callbacks mutate
            # input before finalization; never grant from a cursor alone.
            snap, raw_snapshot = _copy_json(evidence, max_bytes=MAX_BATCH_BYTES,
                                            code='QUALITYSHOW_EVIDENCE_BATCH_TOO_LARGE')
            scope_snapshot, scope_bytes = _copy_json(source_scope, max_bytes=512,
                                                     code='QUALITYSHOW_SCOPE_TOO_LARGE')
            scope_sha = digest(DOMAIN_SCOPE, scope)
            query_spec = {'scope_sha256': scope_sha, 'filters': parsed_filters,
                          'page_size': page_size,
                          'include_numeric_metrics': include_numeric_metrics,
                          'historical_proposal_ack': acknowledge_historical_proposal}
            query_sha = digest(DOMAIN_QUERY, query_spec)
            now = _now(self._clock)
            facts = {'source_scope': scope, 'source_scope_sha256': scope_sha,
                     'query_sha256': query_sha,
                     'purpose': 'QUALITYSHOW_READ_SCOPED_EVIDENCE',
                     'include_numeric_metrics': include_numeric_metrics}
            _grant(authorize_scope, {**facts, 'phase': 'BEFORE_READ'},
                   'QUALITYSHOW_SCOPE_READ_NOT_AUTHORIZED')
            if include_numeric_metrics:
                _grant(authorize_numeric_metrics, {**facts, 'phase': 'BEFORE_READ',
                       'purpose': 'QUALITYSHOW_NUMERIC_PROVIDER_METRICS'},
                       'QUALITYSHOW_NUMERIC_METRICS_NOT_AUTHORIZED')
            rows: list[dict[str, Any]] = []
            fingerprints: set[str] = set()
            classes: set[str] = set()
            gaps: set[str] = set()
            for item in snap:
                need(type(item) is dict and set(item) == {
                    'kind', 'result', 'source_scope', 'recorded_at_utc'},
                    'QUALITYSHOW_EVIDENCE_ITEM_SHAPE_INVALID')
                kind = item['kind']
                need(type(kind) is str and kind in KINDS,
                     'QUALITYSHOW_UNKNOWN_EVIDENCE_KIND')
                need(_scope(item['source_scope']) == scope,
                     'QUALITYSHOW_CROSS_SCOPE_EVIDENCE_FORBIDDEN', 'unavailable')
                recorded = _timestamp(item['recorded_at_utc'])
                need(recorded <= now + timedelta(seconds=MAX_SKEW_SECONDS),
                     'QUALITYSHOW_FUTURE_CAPTURE_TIMESTAMP', 'unavailable')
                result = item['result']
                _, payload = _copy_json(result, max_bytes=MAX_EVIDENCE_BYTES,
                                        code='QUALITYSHOW_SINGLE_EVIDENCE_TOO_LARGE')
                _check_receipt(kind, result)
                record_sha = digest(DOMAIN_RECORD, item)
                need(record_sha not in fingerprints,
                     'QUALITYSHOW_DUPLICATED_EVIDENCE_RECORD')
                fingerprints.add(record_sha)
                _grant(authorize_evidence, {'purpose': 'QUALITYSHOW_READ_EVIDENCE_ITEM',
                       'source_scope': scope, 'source_scope_sha256': scope_sha,
                       'kind': kind, 'receipt_sha256': hashlib.sha256(payload).hexdigest(),
                       'record_sha256': record_sha, 'recorded_at_utc': item['recorded_at_utc']},
                       'QUALITYSHOW_EVIDENCE_ITEM_NOT_AUTHORIZED')
                view, classification, binding, row_gaps = _projection(
                    kind, result, scope, numeric=include_numeric_metrics)
                classes.add(kind)
                gaps.update(row_gaps)
                rows.append({'evidence_id': record_sha, 'kind': kind,
                             'recorded_at_utc': item['recorded_at_utc'],
                             'binding_strength': binding,
                             'classification': classification,
                             'summary': view, 'incompleteness': row_gaps})
            # The revision uses *all* granted supplied records, not just a
            # filtered page: any addition/removal or modified item invalidates
            # old continuation rather than silently skipping/duplicating rows.
            revision_sha = digest(DOMAIN_REVISION, {
                'scope_sha256': scope_sha,
                'record_sha256s': sorted(fingerprints),
                'record_count': len(rows)})
            # Preserve deterministic ascending SHA tie-break within each second.
            rows.sort(key=lambda r: r['evidence_id'])
            rows.sort(key=lambda r: _timestamp(r['recorded_at_utc']), reverse=True)
            selected = [r for r in rows if r['kind'] in parsed_filters['kinds'] and
                        (parsed_filters['classification'] is None or
                         r['classification'] == parsed_filters['classification']) and
                        (parsed_filters['from_utc'] is None or
                         _timestamp(r['recorded_at_utc']) >= _timestamp(parsed_filters['from_utc'])) and
                        (parsed_filters['until_utc'] is None or
                         _timestamp(r['recorded_at_utc']) <= _timestamp(parsed_filters['until_utc']))]
            start, issued, expiry = 0, now, now + timedelta(seconds=MAX_CURSOR_SECONDS)
            if cursor is not None:
                start, issued, expiry = _load_cursor(
                    self._key, cursor, now=now, scope_sha=scope_sha,
                    query_sha=query_sha, revision_sha=revision_sha, count=len(selected))
            page = selected[start:start + page_size]
            more = start + len(page) < len(selected)
            next_cursor = (_encode_cursor(self._key, {
                'schema': CURSOR_SCHEMA, 'scope_sha256': scope_sha,
                'query_sha256': query_sha, 'revision_sha256': revision_sha,
                'count': len(selected), 'offset': start + len(page),
                'issued_at_utc': _stamp(issued), 'expires_at_utc': _stamp(expiry)})
                if more else None)
            # Second authorization cannot loosen data scope. Compare original
            # supplied payload (which callbacks can mutate) before publishing.
            _grant(authorize_scope, {**facts, 'phase': 'FINALIZE'},
                   'QUALITYSHOW_FINAL_SCOPE_PERMISSION_REVOKED')
            if include_numeric_metrics:
                _grant(authorize_numeric_metrics, {**facts, 'phase': 'FINALIZE',
                       'purpose': 'QUALITYSHOW_NUMERIC_PROVIDER_METRICS'},
                       'QUALITYSHOW_FINAL_NUMERIC_PERMISSION_REVOKED')
            need(canonical(evidence) == raw_snapshot and
                 canonical(source_scope) == scope_bytes,
                 'QUALITYSHOW_SOURCE_OR_RECEIPT_MUTATED_DURING_AUTHORIZATION', 'unavailable')
            counts_by_kind = {k: sum(1 for r in selected if r['kind'] == k)
                              for k in sorted(KINDS)}
            coverage = {
                'scope_exactly_authorized': True,
                'supplied_batch_integrity_sha256_only': True,
                'supplied_evidence_exhaustive': False,
                'missing_evidence_not_absence_proof': True,
                'query_is_read_only': True,
                'repository_wide_config_covered': False,
                'source_currentness_proven': False,
                'git_object_bytes_hashed_by_ces': False,
                'provider_or_actor_independently_authenticated': False,
                'runner_isolation_independently_verified': False,
                'quality_pass_independently_verified': False,
                'performance_benchmark_measured': False,
                'cross_source_mode_quality_equivalence_proven': False,
                'source_mode_historical_proposal_only': scope['source_mode'] == 'ProposedPR',
                'present_evidence_classes': sorted(classes),
                'not_supplied_classes': sorted(set(KINDS) - classes),
                'gaps_in_supplied_evidence': sorted(gaps),
                'caller_linked_ec187_count': sum(r['kind'] == 'run_session' for r in rows),
                'interrupted_ec187_count': sum(r['summary'].get('execution_state') ==
                                              'interrupted_or_unverified' for r in rows),
                'output_truncated_ec187_count': sum(r['summary'].get('output_truncated') is True
                                                  for r in rows),
                'ci_pass_claim_count_not_verified': sum(r['classification'] == 'pass' for r in rows),
                'filters_do_not_prove_absence_of_unmatched_evidence': True,
            }
            proof = {'verified_quality_pass': False, 'authenticated_source_snapshot': False,
                     'tested_execution_confirmed': False,
                     'cursor_is_permission_or_source_proof': False,
                     'receipt_checksum_is_authenticity_proof': False,
                     'host_claim_equivalent_to_independent_proof': False}
            result = {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                      'reason_code': ('QUALITYSHOW_NO_MATCH_IS_NOT_NO_EVIDENCE'
                                      if not selected else 'QUALITYSHOW_SCOPED_CLAIMS_ONLY'),
                      'scope': {
                          'source_mode': scope['source_mode'],
                          'scope_sha256': scope_sha,
                          'root_pin_sha256_claim': scope.get('root_pin_sha256'),
                          'commit_sha_claim': scope.get('commit_sha'),
                          'provider': scope.get('provider'),
                          'proposed_pr_historical_only': scope['source_mode'] == 'ProposedPR',
                          'source_identity_authenticated': False},
                      'query_sha256': query_sha,
                      'revision_sha256': revision_sha,
                      'counts': {'supplied': len(rows), 'matched': len(selected),
                                 'returned': len(page), 'matched_by_kind': counts_by_kind},
                      'coverage': coverage,
                      'order': 'RECORDED_AT_UTC_DESC_EVIDENCE_SHA256_ASC',
                      'page_size': page_size,
                      'entries': page, 'next_cursor': next_cursor,
                      'cursor_expires_at_utc': _stamp(expiry) if more else None,
                      'proof': proof, 'effects': _effects(), 'trust_boundary': TRUST}
            need(len(canonical(result)) <= MAX_RESULT_BYTES,
                 'QUALITYSHOW_QUERY_RESULT_TOO_LARGE', 'unavailable')
            return result
        except QualityShowError as exc:
            return _refusal(exc.status, exc.code)
        except (TypeError, ValueError, OverflowError, RecursionError, MemoryError,
                UnicodeError, AttributeError, KeyError, IndexError, OSError):
            return _refusal('unavailable', 'QUALITYSHOW_UNTRUSTED_DATA_OR_CALLBACK_FAILURE')

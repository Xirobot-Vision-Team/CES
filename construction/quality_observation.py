#!/usr/bin/env python3
"""EC185: one bounded, read-only Quality observation envelope.

This module *calls* EC181 QualityDetector and EC184 QualityCIEvidence; the
latter itself reuses EC182/EC183 receipts only after fresh independent
provider/source/CI reads. No receipt checksum grants authority. Local
WorkingTree and remote selected job are independent provenance tracks.
Neither parsed tests nor coverage asserts CES execution, trusted runner,
measured performance, local Git object verification or native PowerShell.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
import sys
import time
from typing import Any, Callable

import quality_detect as detect
import quality_ci_evidence as evidence
import quality_sha_bind as sha
import quality_read_ci as ci

SCHEMA = 'ces.quality_observation.v1'
DOMAIN = b'CES-EC185-QUALITY-OBSERVATION-v1\x00'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
REASON = 'QUALITYOBSERVATION_'
MAX_INPUT_BYTES = 192 * 1024
MAX_OUTPUT_BYTES = 192 * 1024
MAX_OVERALL_SECONDS = 170.0
CLOCK_SKEW_SECONDS = 30
SHA256 = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
TEST_STATES = frozenset({'missing', 'not_run', 'partial', 'fail', 'pass'})
REPORT_STATES = frozenset({'not_requested', 'missing', 'partial', 'pass', 'fail', 'not_run', 'measured'})


class ObservationError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(REASON + code)
        self.code, self.status = REASON + code, status


def require(ok: bool, code: str, status: str = 'unavailable') -> None:
    if not ok:
        raise ObservationError(code, status)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value: Any) -> str:
    return hashlib.sha256(DOMAIN + _canonical(value)).hexdigest()


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        v = ci._now(clock)
        require(type(v) is datetime and v.tzinfo is not None,
                'CLOCK_INVALID', 'invalid_input')
        return v
    except (ci.CIError, TypeError, ValueError):
        raise ObservationError('CLOCK_INVALID', 'invalid_input') from None


def _grant(callback: Callable[[dict[str, Any]], bool] | None,
           detail: dict[str, Any], code: str) -> None:
    require(callable(callback), code, 'invalid_input')
    try:
        allowed = callback(detail)
    except Exception:
        raise ObservationError(code) from None
    require(allowed is True, code)


def _identity(remote: sha.SourceSelection | None,
              local: 'LocalConfigSelection | None') -> dict[str, Any]:
    key = remote.ci if remote else None
    return {
        'remote': None if remote is None else {
            'provider': key.provider, 'repository': key.repository,
            'project_id': key.project_id, 'workflow_id': key.workflow_id,
            'run_id': key.run_id, 'attempt': key.attempt, 'job_id': key.job_id,
            'branch': key.branch, 'commit_sha': key.commit_sha,
            'source_mode': remote.mode, 'proposal_number': remote.proposal_number},
        # Authorizers need the real path; it is never copied to the result.
        'local': None if local is None else {
            'source_mode': 'WorkingTree', 'repo_root': local.repo_root,
            'candidate_paths': tuple(local.candidate_paths)},
    }


@dataclass(frozen=True)
class LocalConfigSelection:
    repo_root: str
    source_pin: dict[str, Any]
    candidate_paths: list[str]


def _valid_local(local: Any) -> None:
    require(type(local) is LocalConfigSelection and
            type(local.repo_root) is str and
            type(local.source_pin) is dict and
            type(local.candidate_paths) is list and
            1 <= len(local.candidate_paths) <= detect.MAX_PATHS,
            'LOCAL_SELECTION_INVALID', 'invalid_input')
    # All path and root permissions, stale root pins and no-follow checks are
    # enforced again by EC181, never delegated to an unchecked file result.
    require(len(_canonical(local.source_pin)) <= 4096 and
            len(_canonical(local.candidate_paths)) <= 16 * 1024,
            'LOCAL_SELECTION_TOO_LARGE', 'invalid_input')


def _local_observe(local: LocalConfigSelection, *, clock: Callable[[], datetime] | None,
                   authorize_source: Callable[[dict[str, Any]], bool] | None,
                   authorize_path: Callable[[dict[str, Any]], bool] | None) -> dict[str, Any]:
    require(callable(authorize_source) and callable(authorize_path),
            'LOCAL_SCOPED_GRANTS_MISSING', 'invalid_input')
    observed = detect.QualityDetector.detect(local.repo_root, local.source_pin,
        candidate_paths=local.candidate_paths,
        authorize_source=authorize_source, authorize_path=authorize_path,
        clock=clock)
    require(type(observed) is dict and observed.get('schema') == detect.SCHEMA and
            observed.get('status') == 'partial' and observed.get('exit_code') == 2 and
            type(observed.get('source')) is dict and
            type(observed.get('coverage')) is dict and
            type(observed.get('inventory_sha256')) is str and
            SHA256.fullmatch(observed['inventory_sha256']) is not None,
            'LOCAL_CONFIG_DISCOVERY_REFUSED')
    body = {k: observed[k] for k in ('source', 'files', 'languages', 'tools',
                                     'profile_hints', 'coverage')}
    require(detect._sha(detect.DOMAIN_INVENTORY, body) == observed['inventory_sha256'] and
            observed['coverage'].get('tests_executed') is False and
            observed['coverage'].get('ci_results_read') is False and
            observed['coverage'].get('repository_wide_inventory_complete') is False and
            observed['coverage'].get('git_sha_authenticated') is False and
            observed.get('effects', {}).get('executed_commands') is False and
            observed['effects'].get('network_access') is False and
            observed['effects'].get('writes_performed') is False,
            'LOCAL_EVIDENCE_OR_PROOF_INVALID')
    return observed


def _local_projection(data: dict[str, Any]) -> tuple[Any, ...]:
    # Exclude the sampling time. Equivalence is bounded content observations,
    # *not* an atomic snapshot or proof metadata-only files are unchanged.
    src = data['source']
    return (data['inventory_sha256'], src['local_root_pin_sha256'],
            src['root_identity_matched_on_scan'],
            _canonical({k: data[k] for k in ('files', 'languages', 'tools',
                                            'profile_hints', 'coverage')}))


def _local_view(data: dict[str, Any]) -> dict[str, Any]:
    c = data['coverage']
    return {'source_mode': 'WorkingTree',
            'pin_digest': data['source']['local_root_pin_sha256'],
            'root_observed_at_utc': data['source']['root_observed_at_utc'],
            'scanned_at_utc': data['source']['scanned_at_utc'],
            'path_redacted': True,
            'identity_checked_for_selected_paths': True,
            'config_inventory_sha256': data['inventory_sha256'],
            'inventory_complete_for_allowlist': True,
            'repository_wide_inventory_complete': False,
            'candidate_paths': c['selected_paths'],
            'present_paths': c['present_paths'], 'absent_paths': c['absent_selected_paths'],
            'parsed_configs': c['parsed_configs'],
            'unparsed_or_malformed_configs': c['unparsed_or_malformed_configs'],
            'read_config_bytes': c['read_config_bytes'],
            'languages': data['languages'], 'tools': data['tools'],
            'profile_hints': data['profile_hints'],
            'metadata_only_files_cannot_be_rechecked_by_content': True,
            'execution_state': 'CONFIG_HINTS_ONLY_NOT_RUN'}


def _validate_remote_output(out: Any, remote: sha.SourceSelection,
                            ci_receipt: dict[str, Any],
                            association_receipt: dict[str, Any],
                            synthetic: bool, chosen_report: evidence.ReportSelection) -> None:
    require(type(out) is dict and len(_canonical(out)) <= MAX_INPUT_BYTES and
            set(out) == {'schema', 'status', 'exit_code', 'reason_code', 'scope',
                         'test_evidence', 'report_evidence', 'classification',
                         'coverage', 'permission', 'evidence_sha256', 'effects',
                         'trust_boundary'} and
            out['schema'] == evidence.SCHEMA and out['status'] == 'partial' and
            type(out['exit_code']) is int and out['exit_code'] == 2 and
            out['reason_code'] == 'QUALITYCIEVIDENCE_BOUNDED_EVIDENCE_OBSERVED',
            'REMOTE_CI_EVIDENCE_REFUSED')
    payload = {k: out[k] for k in ('scope', 'test_evidence', 'report_evidence',
                                   'classification', 'coverage', 'permission')}
    require(all(type(payload[k]) is dict for k in
                ('scope', 'test_evidence', 'report_evidence', 'coverage', 'permission')) and
            type(out.get('evidence_sha256')) is str and
            SHA256.fullmatch(out['evidence_sha256']) is not None and
            evidence.digest(payload) == out['evidence_sha256'],
            'REMOTE_EVIDENCE_DIGEST_INVALID')
    s, test, report, proof, permission = (out[k] for k in
        ('scope', 'test_evidence', 'report_evidence', 'coverage', 'permission'))
    k = remote.ci
    expected = {'provider': k.provider, 'repository': k.repository,
                'project_id': k.project_id, 'workflow_id': k.workflow_id,
                'run_id': k.run_id, 'attempt': k.attempt, 'job_id': k.job_id,
                'branch': k.branch, 'commit_sha': k.commit_sha,
                'source_mode': remote.mode, 'proposal_number': remote.proposal_number,
                'association_receipt_sha256': association_receipt['association_sha256'],
                'ci_receipt_observation_sha256': ci_receipt['observation_sha256']}
    require(all(type(s.get(n)) is type(v) and s.get(n) == v
                for n, v in expected.items()) and
            type(s.get('observed_at')) is str and
            (ci._valid_id(s.get('source_proposal_object_id')) if remote.mode == 'ProposedPR'
             else s.get('source_proposal_object_id') is None) and
            permission.get('transport') == ('SYNTHETIC' if synthetic else 'LIVE_HTTPS') and
            permission.get('host_scope') == 'HOST_CALLBACK_ALLOWED' and
            permission.get('source_and_ci_scopes') == 'FRESHLY_RECHECKED' and
            permission.get('credential_identity') == 'NOT_ATTESTED' and
            type(permission.get('content_endpoint_grants')) is list and
            'FINALIZE_EVIDENCE' in permission['content_endpoint_grants'],
            'REMOTE_SCOPE_OR_PERMISSION_INVALID')
    require(out.get('classification') in TEST_STATES and
            test.get('state') == out['classification'] and
            test.get('job_conclusion') == ci_receipt['observation']['job']['conclusion'] and
            test.get('provider_claim_only') is True and
            test.get('availability') in ('present', 'missing') and
            test.get('source_scope') == ('EXACT_JOB_ATTEMPT_CI_RECHECKED' if
                k.provider == 'github' else 'EXACT_GITLAB_JOB_CI_RECHECKED') and
            report.get('availability') in ('not_requested', 'present', 'missing') and
            report.get('format') == chosen_report.kind and
            report.get('state') in REPORT_STATES and
            report.get('source_scope') == ('NOT_REQUESTED' if chosen_report.kind is None
                else ('RUN_ONLY_JOB_ATTEMPT_UNVERIFIED' if k.provider == 'github'
                      else 'EXACT_GITLAB_JOB')),
            'REMOTE_TEST_REPORT_INVALID')
    require(all(proof.get(f) is True for f in
               ('job_log_availability_checked', 'exact_job_identity_rechecked',
                'source_branch_commit_rechecked', 'association_freshness_checked',
                'content_size_and_type_checked')) and
            proof.get('exact_run_attempt_rechecked') is (k.provider == 'github') and
            proof.get('report_requested') is (chosen_report.kind is not None) and
            proof.get('report_is_job_attributed') is
              (k.provider == 'gitlab' and report['availability'] == 'present') and
            proof.get('github_report_run_only') is
              (k.provider == 'github' and chosen_report.kind is not None) and
            all(proof.get(f) is False for f in
                ('raw_content_disclosed', 'actual_tests_executed_by_ces',
                 'runner_integrity_verified', 'actor_identity_verified',
                 'git_object_bytes_verified', 'provider_cross_request_atomic',
                 'performance_measured')),
            'REMOTE_PROOF_INVALID')
    effects = out['effects']
    require(type(effects) is dict and effects.get('read_only') is True and
            all(effects.get(f) is False for f in
                ('commands_executed', 'tests_executed_by_ces',
                 'archive_written_or_extracted', 'writes_performed')) and
            all(type(effects.get(f)) is int and 0 <= effects[f] <= 100
                for f in ('content_get_calls', 'source_metadata_get_calls',
                          'ci_metadata_get_calls', 'live_content_get_requests')) and
            effects['live_content_get_requests'] ==
                (0 if synthetic else effects['content_get_calls']) and
            out['trust_boundary'] == ('SYNTHETIC_NO_PROVIDER_PROOF' if synthetic else
                                      'PROVIDER_LOG_AND_REPORT_CLAIMS_NO_TEST_EXECUTION_OR_ATOMICITY'),
            'REMOTE_EFFECTS_INVALID')
    counts = test.get('counts')
    if counts is not None:
        require(type(counts) is dict and set(counts) ==
                {'total', 'passed', 'failed', 'skipped'} and
                all(type(counts[f]) is int and 0 <= counts[f] <= 5000 for f in counts) and
                counts['total'] == counts['passed'] + counts['failed'] + counts['skipped'],
                'REMOTE_TEST_COUNTS_INVALID')
    require((test['availability'] == 'missing') == (test.get('sha256') is None) and
            type(test.get('byte_count')) is int and
            0 <= test['byte_count'] <= evidence.MAX_LOG_BYTES and
            (test.get('sha256') is None or
             (type(test['sha256']) is str and SHA256.fullmatch(test['sha256']) is not None)) and
            (report['availability'] == 'present') == (report.get('sha256') is not None) and
            (report.get('sha256') is None or
             (type(report['sha256']) is str and SHA256.fullmatch(report['sha256']) is not None)),
            'REMOTE_CONTENT_DIGEST_OR_AVAILABILITY_INVALID')
    rep_counts = report.get('test_counts')
    if rep_counts is not None:
        require(type(rep_counts) is dict and set(rep_counts) ==
                {'total', 'passed', 'failed', 'skipped'} and
                all(type(rep_counts[f]) is int and 0 <= rep_counts[f] <= 5000
                    for f in rep_counts) and
                rep_counts['total'] == rep_counts['passed'] + rep_counts['failed'] +
                rep_counts['skipped'], 'REPORT_TEST_COUNTS_INVALID')
    metrics = report.get('coverage_metrics')
    if metrics is not None:
        require(report.get('format') in ('coverage_json', 'cobertura_xml') and
                report['state'] == 'measured' and type(metrics) is dict and
                set(metrics) == {'lines_total', 'lines_covered', 'percent'} and
                type(metrics['lines_total']) is int and
                type(metrics['lines_covered']) is int and
                0 < metrics['lines_total'] <= 10000000 and
                0 <= metrics['lines_covered'] <= metrics['lines_total'] and
                type(metrics['percent']) in (int, float) and
                0 <= metrics['percent'] <= 100 and
                abs(metrics['percent'] - round(100*metrics['lines_covered']/
                             metrics['lines_total'], 2)) <= 0.01,
                'REMOTE_COVERAGE_METRICS_INVALID')
    require((out['classification'] != 'missing' or
                (test['counts'] is None and test['availability'] == 'missing')) and
            (out['classification'] != 'not_run' or
                (counts is None or counts['total'] == 0)) and
            (out['classification'] != 'pass' or
                (counts is not None and counts['passed'] > 0 and
                 counts['failed'] == 0 and counts['skipped'] == 0)) and
            (out['classification'] != 'fail' or
                (counts is not None and counts['failed'] > 0)) and
            not (out['classification'] == 'pass' and
                 test['job_conclusion'] != 'success') and
            not (out['classification'] == 'fail' and
                 test['job_conclusion'] != 'failure'),
            'REMOTE_CLASSIFICATION_CONTRADICTION')


def _ref(kind: str, digest: str | None, availability: str,
         scope: str, transport: str, observed_at: str, *,
         selector: dict[str, Any], byte_count: int | None) -> dict[str, Any]:
    # Deterministic selectors make evidence reproducible with retained input,
    # without exposing host-private root paths, signed URLs or report paths.
    # Both selector and content hashes are non-authenticating.
    return {'kind': kind, 'sha256': digest,
            'selector_sha256': _hash({'kind': kind, 'selector': selector}),
            'byte_count': byte_count, 'availability': availability,
            'scope': scope, 'transport': transport, 'observed_at_utc': observed_at,
            'digest_authenticates_origin': False}


def _remote_view(out: dict[str, Any], selection: sha.SourceSelection,
                 ci_receipt: dict[str, Any], association_receipt: dict[str, Any],
                 selected_report: evidence.ReportSelection
                 ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    s, test, report = out['scope'], out['test_evidence'], out['report_evidence']
    ci_obs = ci_receipt['observation']
    transport = out['permission']['transport']
    now = s['observed_at']
    source = {'provider': s['provider'], 'repository': s['repository'],
              'project_id': s['project_id'], 'workflow_id': s['workflow_id'],
              'run_id': s['run_id'], 'attempt': s['attempt'], 'job_id': s['job_id'],
              'branch': s['branch'], 'commit_sha': s['commit_sha'],
              'source_mode': s['source_mode'], 'proposal_number': s['proposal_number'],
              'proposal_object_id': s['source_proposal_object_id'],
              'ci_api_version': ci_receipt['source']['api_version'],
              'observed_at_utc': now, 'sha_association_level':
              'PROVIDER_FIELDS_RECHECKED_NOT_GIT_OBJECT_BYTES',
              'provenance': ('SYNTHETIC_DEVELOPMENT' if transport == 'SYNTHETIC'
                             else 'LIVE_PROVIDER_METADATA')}
    report_kind = report['format']
    if report_kind is None:
        # None means no report requested; EC184 uses a constant parse-format
        # placeholder independent of requested type.
        coverage_state = 'not_requested'
    elif report_kind == 'junit_xml':
        coverage_state = 'not_requested'
    elif report['availability'] == 'missing':
        coverage_state = 'missing'
    elif report['state'] == 'measured' and report['coverage_metrics'] is not None:
        coverage_state = 'provider_reported'
    else:
        coverage_state = 'partial'
    count_scope = ('EXACT_GITLAB_JOB_REPORT' if test.get('parse_format') == 'JUNIT_XML'
                   and s['provider'] == 'gitlab' else
                   'EXACT_JOB_LOG' if test.get('counts') is not None else 'NONE')
    tests = {'classification': out['classification'], 'counts': test['counts'],
             'counts_scope': count_scope, 'log_availability': test['availability'],
             'log_parse_format': test['parse_format'], 'report_format': report_kind,
             'junit_report_state': report['state'] if report_kind == 'junit_xml' else None,
             'junit_report_counts': report['test_counts'] if report_kind == 'junit_xml' else None,
             'ci_job_conclusion': test['job_conclusion'],
             'is_provider_content_claim': True,
             'ces_tests_executed': False,
             'execution_verified': False,
             'counts_verified_against_real_runner': False,
             'github_run_artifact_not_job_proof': (s['provider'] == 'github' and
                report_kind is not None)}
    coverage = {'state': coverage_state, 'report_kind': report_kind,
                'parser_state': report['state'] if report_kind in
                ('coverage_json', 'cobertura_xml') else 'not_requested',
                'metrics': report['coverage_metrics'] if coverage_state == 'provider_reported' else None,
                'report_scope': report['source_scope'],
                'is_provider_report_claim': coverage_state == 'provider_reported',
                'independently_measured_by_ces': False,
                'verified_runner': False}
    ci_result = {'job_state': ci_obs['job']['state'],
                 'job_conclusion': ci_obs['job']['conclusion'],
                 'run_state': ci_obs['run']['state'],
                 'run_conclusion': ci_obs['run']['conclusion'],
                 'selected_job_completed_at_utc': ci_obs['job']['completed_at'],
                 'run_updated_at_utc': ci_obs['run']['updated_at'],
                 'result_is_provider_metadata_claim': True}
    selector = {n: s[n] for n in ('provider', 'repository', 'project_id',
                 'workflow_id', 'run_id', 'attempt', 'job_id', 'branch',
                 'commit_sha', 'source_mode', 'proposal_number')}
    refs = [_ref('ci_metadata_receipt', ci_receipt['observation_sha256'], 'present',
                 'PROVIDER_RUN_JOB_METADATA', transport,
                 ci_receipt['source']['observed_at'], selector=selector,
                 byte_count=len(_canonical(ci_receipt))),
            _ref('sha_association_receipt', association_receipt['association_sha256'], 'present',
                 'PROVIDER_SOURCE_CI_ASSOCIATION', transport,
                 association_receipt['source']['observed_at'], selector=selector,
                 byte_count=len(_canonical(association_receipt))),
            _ref('job_log', test['sha256'], test['availability'],
                 'EXACT_JOB_LOG', transport, now, selector=selector,
                 byte_count=test['byte_count'])]
    if report_kind is not None:
        # The GitHub artifact ID and archive entry are retained in the caller's
        # ReportSelection, not exposed as a URL or unverified job association.
        report_selector = {**selector, 'report_kind': report_kind,
            'github_artifact_id': selected_report.github_artifact_id,
            'github_entry': selected_report.github_entry,
            'gitlab_path': selected_report.gitlab_path}
        refs.append(_ref('report', report['sha256'], report['availability'],
                         ('RUN_LEVEL_ARTIFACT' if s['provider'] == 'github'
                          else 'EXACT_JOB_ARTIFACT'), transport, now,
                         selector=report_selector, byte_count=report['byte_count']))
    refs.append(_ref('ci_evidence_receipt', out['evidence_sha256'], 'present',
                     'PARSED_PROVIDER_JOB_CLAIM', transport, now,
                     selector=selector, byte_count=len(_canonical(out))))
    return source, {'ci_metadata': ci_result, 'tests': tests,
                    'coverage': coverage}, refs


def _effects_empty() -> dict[str, Any]:
    return {'read_only': True, 'local_config_scans': 0,
            'remote_content_get_calls': 0, 'remote_source_metadata_get_calls': 0,
            'remote_ci_metadata_get_calls': 0, 'live_network_get_requests': 0,
            'executed_commands': False, 'tests_executed_by_ces': False,
            'benchmarks_executed': False, 'writes_performed': False}


def _refused(reason: str, status: str, effects: dict[str, Any]) -> dict[str, Any]:
    # Do not leak successful sub-results when a later track or grant refuses.
    return {'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
            'reason_code': reason, 'observed_at_utc': None,
            'source': None, 'observations': None, 'evidence_refs': [],
            'execution_environment': None, 'grants': None, 'proof': None,
            'effects': effects, 'observation_sha256': None,
            'trust_boundary': 'NO_AGGREGATED_EVIDENCE_ON_REFUSAL'}


class QualityObservation:
    """Independently consented, no-side-effect integration of EC181–EC184."""

    def __init__(self, *, ci_evidence: evidence.QualityCIEvidence | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.ci_evidence = (ci_evidence if ci_evidence is not None else
                            evidence.QualityCIEvidence(clock=clock))
        self.clock = clock

    def collect(self, *, local: LocalConfigSelection | None = None,
                remote: sha.SourceSelection | None = None,
                report: evidence.ReportSelection | None = None,
                ci_receipt: dict[str, Any] | None = None,
                association_receipt: dict[str, Any] | None = None,
                ci_credential: str | None = None,
                source_credential: str | None = None,
                allow_compose: bool = False,
                allow_local_config: bool = False,
                allow_remote_ci_evidence: bool = False,
                allow_network: bool = False,
                allow_ci_recheck: bool = False,
                allow_source_recheck: bool = False,
                allow_receipt_reuse: bool = False,
                allow_job_log: bool = False,
                allow_report: bool = False,
                authorize_compose: Callable[[dict[str, Any]], bool] | None = None,
                authorize_local_source: Callable[[dict[str, Any]], bool] | None = None,
                authorize_local_path: Callable[[dict[str, Any]], bool] | None = None,
                authorize_ci: Callable[[dict[str, Any]], bool] | None = None,
                authorize_source: Callable[[dict[str, Any]], bool] | None = None,
                authorize_content: Callable[[dict[str, Any]], bool] | None = None,
                allow_synthetic_development: bool = False) -> dict[str, Any]:
        effects = _effects_empty()
        try:
            require(type(self.ci_evidence) is evidence.QualityCIEvidence,
                    'EXACT_EC184_ADAPTER_REQUIRED', 'invalid_input')
            require(type(allow_compose) is bool and allow_compose and
                    type(allow_local_config) is bool and
                    type(allow_remote_ci_evidence) is bool and
                    (local is not None or remote is not None) and
                    allow_local_config is (local is not None) and
                    allow_remote_ci_evidence is (remote is not None),
                    'EXPLICIT_TRACK_OPTINS_REQUIRED', 'invalid_input')
            if local is not None:
                _valid_local(local)
            if remote is not None:
                remote = sha._scope(remote)
                require(type(ci_receipt) is dict and
                        type(association_receipt) is dict and
                        len(_canonical(ci_receipt)) <= sha.MAX_RECEIPT and
                        len(_canonical(association_receipt)) <= sha.MAX_RECEIPT,
                        'REMOTE_RECEIPTS_REQUIRED', 'invalid_input')
                if report is None:
                    report = evidence.ReportSelection()
                evidence._report_scope(report, remote.ci.provider)
            else:
                require(all(x is None for x in (ci_receipt, association_receipt,
                            ci_credential, source_credential, report)) and
                        all(x is False for x in (allow_network, allow_ci_recheck,
                            allow_source_recheck, allow_receipt_reuse,
                            allow_job_log, allow_report)),
                        'NO_REMOTE_SCOPE_WITHOUT_REMOTE_SELECTION', 'invalid_input')
            began = _now(self.clock)
            start = time.monotonic()
            selected_scope = _identity(remote, local)
            _grant(authorize_compose, {'operation': 'QUALITY_OBSERVATION_COMPOSE',
                   'schema': SCHEMA, 'stage': 'BEFORE_READ', **selected_scope},
                   'COMPOSITION_SCOPE_DENIED')
            local_out = None
            if local is not None:
                effects['local_config_scans'] += 1
                local_out = _local_observe(local, clock=self.clock,
                    authorize_source=authorize_local_source,
                    authorize_path=authorize_local_path)
            remote_out = None
            synthetic = False
            if remote is not None:
                # Explicitly call EC184. It validates EC182/183 receipts and
                # rebinds live source/CI *twice* across scoped log/report GETs.
                remote_out = self.ci_evidence.read(
                    remote, report=report, ci_receipt=ci_receipt,
                    association_receipt=association_receipt,
                    ci_credential=ci_credential, source_credential=source_credential,
                    allow_network=allow_network, allow_ci_recheck=allow_ci_recheck,
                    allow_source_recheck=allow_source_recheck,
                    allow_receipt_reuse=allow_receipt_reuse,
                    allow_job_log=allow_job_log, allow_report=allow_report,
                    authorize_ci=authorize_ci, authorize_source=authorize_source,
                    authorize_content=authorize_content,
                    allow_synthetic_development=allow_synthetic_development)
                if type(remote_out) is dict and type(remote_out.get('effects')) is dict:
                    remote_effect = remote_out['effects']
                    for src, dest in (('content_get_calls', 'remote_content_get_calls'),
                                      ('source_metadata_get_calls', 'remote_source_metadata_get_calls'),
                                      ('ci_metadata_get_calls', 'remote_ci_metadata_get_calls')):
                        val = remote_effect.get(src)
                        if type(val) is int and 0 <= val <= 1000:
                            effects[dest] = val
                synthetic = (self.ci_evidence.synthetic or
                             self.ci_evidence.binder.source_synthetic or
                             self.ci_evidence.binder.ci_reader.synthetic)
                if not synthetic:
                    effects['live_network_get_requests'] = (
                        effects['remote_content_get_calls'] +
                        effects['remote_source_metadata_get_calls'] +
                        effects['remote_ci_metadata_get_calls'])
                _validate_remote_output(remote_out, remote, ci_receipt,
                                        association_receipt, synthetic, report)
            if local is not None and remote is not None:
                # The first local sample may be stale after network reads.
                # Re-probe its allowlisted files with entirely fresh grants.
                effects['local_config_scans'] += 1
                later = _local_observe(local, clock=self.clock,
                    authorize_source=authorize_local_source,
                    authorize_path=authorize_local_path)
                require(_local_projection(later) == _local_projection(local_out),
                        'LOCAL_CONFIG_CHANGED_DURING_REMOTE_READ')
                local_out = later
            _grant(authorize_compose, {'operation': 'QUALITY_OBSERVATION_COMPOSE',
                   'schema': SCHEMA, 'stage': 'FINALIZE', **selected_scope},
                   'COMPOSITION_FINAL_GRANT_DENIED')
            finished = _now(self.clock)
            require(finished >= began - timedelta(seconds=CLOCK_SKEW_SECONDS) and
                    finished <= began + timedelta(seconds=MAX_OVERALL_SECONDS +
                                                  CLOCK_SKEW_SECONDS) and
                    time.monotonic() - start <= MAX_OVERALL_SECONDS,
                    'OBSERVATION_DEADLINE_EXCEEDED')
            local_view = _local_view(local_out) if local_out is not None else None
            refs: list[dict[str, Any]] = []
            if local_view is not None:
                refs.append(_ref('local_config_inventory',
                    local_view['config_inventory_sha256'], 'present', 'LOCAL_WORKINGTREE',
                    'LOCAL_POSIX', local_view['scanned_at_utc'],
                    selector={'repo_root': local.repo_root, 'source_pin': local.source_pin,
                              'candidate_paths': local.candidate_paths},
                    byte_count=local_view['read_config_bytes']))
            remote_source = None
            view = None
            if remote_out is not None:
                remote_source, view, r = _remote_view(remote_out, remote,
                                                     ci_receipt, association_receipt, report)
                refs.extend(r)
            source = {'local': (None if local_view is None else {
                'source_mode': 'WorkingTree', 'pin_digest': local_view['pin_digest'],
                'root_observed_at_utc': local_view['root_observed_at_utc'],
                'scanned_at_utc': local_view['scanned_at_utc'],
                'root_path_redacted': True}), 'remote': remote_source,
                'same_revision_proven': False}
            observations = {
                'local_config': local_view,
                'ci_metadata': None if view is None else view['ci_metadata'],
                'tests': None if view is None else view['tests'],
                'coverage': None if view is None else view['coverage'],
                'performance': {'state': 'not_measured', 'benchmark_samples': 0,
                                'metrics': [], 'hardware_spec': None,
                                'baseline': None, 'runtime_seconds': None,
                                'basis': 'NO_AUTHORIZED_BENCHMARK_OR_MEASUREMENT'}
            }
            env = {'local_os': None, 'local_arch': None,
                   'ci_runner_os': None, 'ci_runner_arch': None,
                   'ci_runner_image': None, 'ci_runner_identity': None,
                   'ci_actor_identity': None, 'installed_tool_versions': [],
                   'collector_platform': sys.platform,
                   'collector_python': f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}',
                   'collector_facts_unattested': True,
                   'environment_verified': False, 'runner_attested': False,
                   'facts_origin': 'PROVIDER_METADATA_AND_LOCAL_CONFIG_HINTS_ONLY'}
            grants = {'composition': 'HOST_CALLBACK_ALLOWED',
                      'local_config': ('SCOPED_READ_GRANTED' if local is not None
                                       else 'NOT_REQUESTED'),
                      'remote_ci': ('SCOPED_READ_GRANTED' if remote is not None
                                    else 'NOT_REQUESTED'),
                      'transport': ('SYNTHETIC' if synthetic else 'LIVE_HTTPS')
                                   if remote_out is not None else 'NOT_USED',
                      'credential_identity': 'NOT_ATTESTED',
                      'permission_is_human_identity_proof': False}
            proof = {'local_selected_config_observed': local_out is not None,
                     'provider_source_ci_fields_rechecked': remote_out is not None,
                     'selected_job_log_checked': remote_out is not None,
                     'local_remote_same_revision_verified': False,
                     'local_config_all_files_content_rechecked': False,
                     'git_object_bytes_verified': False,
                     'provider_cross_request_atomic_snapshot': False,
                     'runner_integrity_verified': False,
                     'actor_identity_verified': False,
                     'actual_tests_executed_by_ces': False,
                     'ci_test_execution_independently_verified': False,
                     'coverage_independently_measured_by_ces': False,
                     'benchmarks_executed_by_ces': False,
                     'performance_measured': False,
                     'environment_verified': False,
                     'overall_quality_pass_verified': False}
            payload = {'observed_at_utc': ci._fmt(finished), 'source': source,
                       'observations': observations, 'evidence_refs': refs,
                       'execution_environment': env, 'grants': grants, 'proof': proof}
            out = {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                   'reason_code': REASON + 'BOUNDED_OBSERVATION_COMPOSED',
                   **payload, 'effects': effects,
                   'observation_sha256': _hash(payload),
                   'trust_boundary': 'CLAIMS_AND_CONFIG_ONLY_NO_VERIFIED_EXECUTION_OR_BENCHMARK'}
            require(len(_canonical(out)) <= MAX_OUTPUT_BYTES,
                    'AGGREGATED_OUTPUT_TOO_LARGE')
            return out
        except ObservationError as ex:
            return _refused(ex.code, ex.status, effects)
        except (sha.BindError, ci.CIError, evidence.EvidenceError,
                detect.QualityError, TypeError, ValueError, AttributeError,
                KeyError, OverflowError, RecursionError, UnicodeError,
                OSError, MemoryError):
            return _refused(REASON + 'UNTRUSTED_OR_UNAVAILABLE_INPUT',
                            'unavailable', effects)

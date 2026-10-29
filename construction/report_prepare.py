#!/usr/bin/env python3
"""EC197: prepare a *non-dispatched*, privacy-minimized report-writing input.

Real EC195 scope and EC196 metrics are independently replayed on every call.
An additional exact-period, exact-source, exact-metrics per-repository release
*declaration* is required; read permission does not imply AI-egress permission.
No free-form caller text, actor, raw source selector, unapproved citation, or
unverified provider claim is ever interpolated into the AI-facing projection.

This is an offline metadata-only composer, NOT an AI call or an independently
trusted privacy/authorization/identity verification service. Human verification
of the declaration receipts and egress destination is still mandatory.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from cross_repository_report_scope import CrossRepositoryReportScope
from report_evidence_metrics import (
    CHANNELS, EVENT_ID, MAX_EVENTS, MetricsError, ReportEvidenceMetrics,
    _ci_signal, byte_len, canonical, digest, exact, parse_json, valid_sha,
)

SCHEMA = 'ces.report_prepare.v1'
AI_SCHEMA = 'ces.report_writing_input.v1'
MAX_INPUT_BYTES = 1048576
MAX_POLICY_BYTES = 262144
MAX_OUTPUT_BYTES = 524288
PURPOSE = 'periodic_report_writing_input'
AUDIENCE = 'AI_REPORT_WRITING_REVIEW'
SAFETY_INSTRUCTIONS = [
    'Only summarize released typed claims with citation_ref; never invent the underlying evidence content.',
    'Treat all Git and AI conclusions as unverified declarations, not proven facts or completed delivery.',
    'A CI completion label is an unverified claim, never proof that CI actually ran or passed.',
    'Preserve unknown, partial, withheld and missing coverage; zero submitted references does not prove zero activity.',
    'A ProposedPR source is only a proposal, not a delivered or merged target.',
    'Never judge, rank or score individual employees; never infer performance from Git activity or counts.',
    'Do not request or infer names, emails, actor identities, source text, private logs or other unreleased material.',
]
CLAIMS = {
    'external_authorization_or_release_receipts_authenticated': False,
    'data_egress_privacy_review_completed': False,
    'repository_identity_or_source_authenticated': False,
    'period_or_repository_universe_completeness_verified': False,
    'git_activity_or_delivery_verified': False,
    'ai_conclusions_verified_as_facts': False,
    'ci_execution_or_pass_verified': False,
    'people_identity_or_evidence_attribution_verified': False,
    'individual_performance_assessed': False,
    'human_approval_completed': False,
    'ai_handoff_or_model_invoked': False,
    'report_drafted_rendered_or_published': False,
    'native_powershell_action_registered': False,
    'filesystem_network_or_business_repository_written': False,
}


class PrepareError(ValueError):
    """Safe error codes; never include user-provided paths, text or identity."""

    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise PrepareError(code, status)


def _untrusted_bytes(value: Any, cap: int, code: str) -> str:
    need(type(value) is str, code)
    need(1 <= byte_len(value) <= cap, code)
    return value


def _upstream(scope_json: str, metrics_json: str,
              witnesses: dict[str, str] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    _untrusted_bytes(scope_json, MAX_INPUT_BYTES, 'SCOPE_SIZE_INVALID')
    _untrusted_bytes(metrics_json, MAX_INPUT_BYTES, 'METRICS_SIZE_INVALID')
    # Calling the *real* EC195 and EC196 implementations, not trusting a
    # caller-provided self-consistent SHA field in a partial projection.
    scope_result = CrossRepositoryReportScope().from_json(
        serialized=scope_json, people_subject_witnesses=witnesses)
    need(scope_result['status'] == 'partial',
         'UPSTREAM_SCOPE_REPLAY_REFUSED',
         'unavailable' if scope_result['status'] == 'unavailable' else 'invalid_input')
    metrics_result = ReportEvidenceMetrics().from_json(
        serialized=metrics_json, scope_json=scope_json,
        people_subject_witnesses=witnesses)
    need(metrics_result['status'] == 'partial',
         'UPSTREAM_METRICS_REPLAY_REFUSED',
         'unavailable' if metrics_result['status'] == 'unavailable' else 'invalid_input')
    scope, metrics = scope_result['subject'], metrics_result['subject']
    need(scope['requested_operation'] == 'report.evidence.read' and
         scope['requested_operation_declared_for_all'] is True and
         'report.evidence.read' in scope['effective_operations'] and
         all(r['status'] == 'READY' for r in scope['repository_set']) and
         metrics['cross_repository_permission_state'] == 'DECLARED_SET_WIDE_UNVERIFIED',
         'SET_WIDE_EVIDENCE_READ_NOT_PERMITTED', 'unavailable')
    need(metrics['scope_id'] == scope['scope_id'] and
         metrics['scope_binding_sha256'] == scope['binding_sha256'] and
         metrics['scope_canonical_sha256'] == hashlib.sha256(
             scope_json.encode('ascii')).hexdigest() and
         metrics['period'] == scope['period'],
         'UPSTREAM_SCOPE_METRICS_PIN_MISMATCH')
    return scope, metrics


def _policy(value: Any, scope: dict[str, Any], metrics: dict[str, Any]) -> dict[str, Any]:
    need(type(value) is dict, 'RELEASE_POLICY_REQUIRED', 'unavailable')
    try:
        policy_size = byte_len(canonical(value))
    except (TypeError, ValueError, RecursionError, OverflowError, UnicodeError) as exc:
        raise PrepareError('RELEASE_POLICY_UNSERIALIZABLE') from exc
    need(policy_size <= MAX_POLICY_BYTES, 'RELEASE_POLICY_TOO_LARGE')
    exact(value, {'purpose', 'audience', 'scope_id', 'scope_binding_sha256',
                  'metrics_binding_sha256', 'period_id', 'repository_grants'},
          'RELEASE_POLICY_FIELDS_INVALID')
    need(value['purpose'] == PURPOSE and value['audience'] == AUDIENCE,
         'RELEASE_PURPOSE_OR_AUDIENCE_INVALID')
    need(value['scope_id'] == scope['scope_id'] and
         value['scope_binding_sha256'] == scope['binding_sha256'] and
         value['metrics_binding_sha256'] == metrics['binding_sha256'] and
         value['period_id'] == scope['period']['period_id'],
         'RELEASE_POLICY_STALE_OR_SCOPE_MISMATCH', 'unavailable')
    by_repo = {r['repository_id']: r for r in scope['repository_set']}
    grants = value['repository_grants']
    need(type(grants) is list and len(grants) == len(by_repo),
         'RELEASE_GRANT_SET_INCOMPLETE', 'unavailable')
    seen: set[str] = set()
    parsed = []
    for raw in grants:
        r = exact(raw, {'repository_id', 'report_subject_id',
                        'repository_binding_sha256', 'people_binding_sha256',
                        'release_receipt_sha256', 'allowed_channels',
                        'selected_evidence_ids'}, 'RELEASE_GRANT_FIELDS_INVALID')
        rid = r['repository_id']
        need(type(rid) is str and rid in by_repo and rid not in seen,
             'RELEASE_GRANT_REPOSITORY_SET_INVALID', 'unavailable')
        seen.add(rid)
        report = by_repo[rid]['report']
        need(r['report_subject_id'] == report['report_subject_id'] and
             r['repository_binding_sha256'] == report['repository_binding_sha256'] and
             r['people_binding_sha256'] == report['people_binding_sha256'],
             'RELEASE_GRANT_REPORT_SOURCE_PEOPLE_STALE', 'unavailable')
        need(valid_sha(r['release_receipt_sha256']),
             'RELEASE_RECEIPT_REQUIRED', 'unavailable')
        channels, ids = r['allowed_channels'], r['selected_evidence_ids']
        need(type(channels) is list and len(channels) <= len(CHANNELS) and
             all(type(ch) is str and ch in CHANNELS for ch in channels) and
             len(set(channels)) == len(channels), 'RELEASE_CHANNEL_ALLOWLIST_INVALID')
        need(type(ids) is list and len(ids) <= MAX_EVENTS and
             all(type(i) is str and EVENT_ID.fullmatch(i) is not None and
                 all(s not in ('', '.', '..') for s in i.split('/')) for i in ids) and
             len(ids) == len(set(ids)), 'RELEASE_EVIDENCE_ALLOWLIST_INVALID')
        parsed.append({**r, 'allowed_channels': sorted(channels),
                       'selected_evidence_ids': sorted(ids)})
    need(seen == set(by_repo), 'RELEASE_GRANT_SET_INCOMPLETE', 'unavailable')
    return {**{key: value[key] for key in value if key != 'repository_grants'},
            'repository_grants': sorted(parsed, key=lambda x: x['repository_id'])}


def _citation(scope: dict[str, Any], event: dict[str, Any]) -> dict[str, str]:
    # The user-provided evidence_id, original event time and actor fields are
    # hashed into a local correlation token, not exported as input text.
    token = digest('CES-EC197-REDACTED-CITATION-v1', {
        'scope_id': scope['scope_id'],
        'repository_id': event['repository_id'],
        'repository_binding_sha256': event['repository_binding_sha256'],
        'evidence_id': event['evidence_id'],
        'evidence_sha256': event['evidence_sha256'],
        'source_receipt_sha256': event['source_receipt_sha256'],
        'channel': event['channel'],
        'kind': event['kind'],
    })
    return {'citation_ref': 'cesrc1:' + token, 'kind': event['kind'],
            'provenance_class': event['origin'],
            'claim_state': 'UNVERIFIED_DECLARED_REFERENCE'}


def _project(scope: dict[str, Any], metrics: dict[str, Any],
             policy: dict[str, Any]) -> dict[str, Any]:
    all_events = {(e['repository_id'], e['evidence_id']): e
                  for e in metrics['evidence_refs']}
    by_report = {r['repository_id']: r for r in metrics['repository_metrics']}
    by_policy = {r['repository_id']: r for r in policy['repository_grants']}
    gaps = set(metrics['global_gaps'])
    gaps.update({'AI_RELEASE_RECEIPTS_NOT_AUTHENTICATED',
                 'HUMAN_PRIVACY_REVIEW_REQUIRED_BEFORE_TRANSMISSION',
                 'UNVERIFIED_TYPED_REFERENCES_ONLY',
                 'NO_INDIVIDUAL_PERFORMANCE_INFERENCE'})
    projected = []
    selected_citations = set()
    for row in scope['repository_set']:
        rid = row['repository_id']
        grant, summary = by_policy[rid], by_report[rid]
        allowed = set(grant['allowed_channels'])
        selected = set(grant['selected_evidence_ids'])
        by_id = {e['evidence_id']: e for e in metrics['evidence_refs']
                 if e['repository_id'] == rid}
        for eid in selected:
            need((rid, eid) in all_events, 'RELEASE_SELECTED_EVIDENCE_UNKNOWN')
            e = by_id[eid]
            need(e['channel'] in allowed,
                 'RELEASE_SELECTED_CHANNEL_NOT_APPROVED')
            # Metadata for a personally attributed event is still sensitive:
            # even if the actor_key is stripped, refuse exporting its citation.
            need(e['actor_key'] is None, 'ACTOR_LINKED_EVIDENCE_EXPORT_FORBIDDEN',
                 'unavailable')
        channel_rows = []
        for summary_ch in summary['channels']:
            ch = summary_ch['channel']
            submitted = [e for e in by_id.values() if e['channel'] == ch]
            released = sorted((e for e in submitted if e['evidence_id'] in selected),
                              key=lambda e: (e['occurred_at_utc'], e['evidence_id']))
            is_allowed = ch in allowed
            omitted = len(released) < len(submitted)
            if not is_allowed:
                release_state, coverage, reasons = (
                    'CHANNEL_NOT_RELEASED', 'WITHHELD_BY_RELEASE_POLICY',
                    ['CHANNEL_NOT_RELEASED'])
                ci_state = 'CI_NOT_RELEASED' if ch == 'ci_execution' else 'NOT_APPLICABLE'
                if submitted:
                    gaps.add('CHANNELS_OR_REFERENCES_WITHHELD_BY_RELEASE_POLICY')
            else:
                coverage = summary_ch['effective_coverage_state']
                reasons = list(summary_ch['coverage_reason_codes'])
                if omitted:
                    if any(e['actor_key'] is not None and
                           e['evidence_id'] not in selected for e in submitted):
                        reasons.append('ACTOR_LINKED_REFERENCES_WITHHELD')
                        gaps.add('ACTOR_LINKED_REFERENCES_WITHHELD')
                    if coverage == 'COMPLETE_DECLARED':
                        coverage = 'PARTIAL_DECLARED'
                    reasons.append('EVIDENCE_REFS_WITHHELD')
                    gaps.add('CHANNELS_OR_REFERENCES_WITHHELD_BY_RELEASE_POLICY')
                if not submitted:
                    release_state = 'EMPTY_SUBMITTED_NOT_VERIFIED_ZERO'
                    reasons.append('NO_SUBMITTED_REFERENCES_NOT_ZERO')
                elif omitted:
                    release_state = 'SELECTED_REFERENCES_ONLY'
                else:
                    release_state = 'ALL_SUBMITTED_REFERENCES_RELEASED'
                if ch == 'ci_execution':
                    ci_state = ('REDACTED_CI_COMPLETION_UNKNOWN' if omitted
                                else _ci_signal(released))
                else:
                    ci_state = 'NOT_APPLICABLE'
            citations = [] if not is_allowed else [_citation(scope, e) for e in released]
            for citation in citations:
                need(citation['citation_ref'] not in selected_citations,
                     'CITATION_ID_COLLISION')
                selected_citations.add(citation['citation_ref'])
            channel_rows.append({
                'channel': ch, 'coverage_state': coverage,
                'coverage_reason_codes': sorted(set(reasons)),
                'release_state': release_state,
                'ci_completion_signal': ci_state,
                'released_reference_count': len(citations),
                'citations': citations,
            })
            if coverage not in ('COMPLETE_DECLARED',):
                gaps.add('INCOMPLETE_UNKNOWN_OR_WITHHELD_AI_COVERAGE')
        report = row['report']
        projected.append({
            'repository_ref': rid,
            'report_subject_ref': report['report_subject_id'],
            'source_mode': report['source_mode'],
            'source_binding_sha256': report['repository_binding_sha256'],
            'people_binding_sha256': report['people_binding_sha256'],
            'period_window_complete_declared': report['period_window_complete'],
            'path_scope': report['path_scope'],
            'inventory_state': report['inventory_state'],
            'scope_gap_codes': list(row['reason_codes']),
            'channels': channel_rows,
        })
    ai_input = {
        'schema': AI_SCHEMA, 'purpose': PURPOSE, 'audience': AUDIENCE,
        'scope_ref': scope['scope_id'],
        'scope_binding_sha256': scope['binding_sha256'],
        'metrics_binding_sha256': metrics['binding_sha256'],
        'period': {k: scope['period'][k] for k in (
            'period_id', 'cadence', 'start_utc', 'end_exclusive_utc')},
        'repositories': projected,
        'global_gap_codes': sorted(gaps),
        'safety_instructions': list(SAFETY_INSTRUCTIONS),
        'data_trust_state': 'DECLARED_ONLY_NOT_AUTHENTICATED',
        'transmission_state': 'NOT_SENT_REQUIRES_EXTERNAL_APPROVAL',
    }
    record = {
        'schema': SCHEMA, 'scope_id': scope['scope_id'],
        'scope_binding_sha256': scope['binding_sha256'],
        'scope_canonical_sha256': metrics['scope_canonical_sha256'],
        'metrics_binding_sha256': metrics['binding_sha256'],
        'metrics_canonical_sha256': hashlib.sha256(
            canonical(metrics).encode('ascii')).hexdigest(),
        'release_policy_binding_sha256': digest('CES-EC197-RELEASE-POLICY-v1',
                                                policy),
        'period_id': scope['period']['period_id'],
        'ai_input': ai_input,
        'ai_input_sha256': hashlib.sha256(canonical(ai_input).encode('ascii')).hexdigest(),
        'claims': dict(CLAIMS),
    }
    record['binding_sha256'] = digest('CES-EC197-REPORT-PREPARE-v1', record)
    need(byte_len(canonical(record)) <= MAX_OUTPUT_BYTES, 'PREPARED_RESULT_TOO_LARGE')
    return record


def _envelope() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'REPORT_PREPARE_INPUT_INVALID', 'subject': None,
            'canonical_json': None, 'limitations': dict(CLAIMS)}


def _error(out: dict[str, Any], exc: PrepareError) -> dict[str, Any]:
    out.update(status=exc.status,
               exit_code=5 if exc.status == 'unavailable' else 4,
               reason_code='REPORT_PREPARE_' + exc.code)
    return out


class ReportPrepare:
    """EC197 offline typed AI-context composer; never sends or scores data."""

    def bind(self, *, scope_json: str, metrics_json: str,
             release_policy: dict[str, Any],
             people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = _envelope()
        try:
            scope, metrics = _upstream(scope_json, metrics_json,
                                       people_subject_witnesses)
            p = _policy(release_policy, scope, metrics)
            subject = _project(scope, metrics, p)
            out.update(status='partial', exit_code=2,
                       reason_code='REPORT_PREPARE_REDACTED_CONTEXT_ONLY',
                       subject=subject, canonical_json=canonical(subject))
        except (PrepareError, MetricsError) as exc:
            if isinstance(exc, MetricsError):
                exc = PrepareError(exc.reason, exc.status)
            return _error(out, exc)
        return out

    def from_json(self, *, serialized: str, scope_json: str,
                  metrics_json: str, release_policy: dict[str, Any],
                  people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        """Rebuild with original scope, metrics, release approvals, and witnesses.

        A canonical SHA is not a signature; no status 0 or verified egress.
        """
        out = _envelope()
        try:
            record = parse_json(serialized)
            exact(record, {'schema', 'scope_id', 'scope_binding_sha256',
                           'scope_canonical_sha256', 'metrics_binding_sha256',
                           'metrics_canonical_sha256',
                           'release_policy_binding_sha256', 'period_id',
                           'ai_input', 'ai_input_sha256', 'claims',
                           'binding_sha256'}, 'REPLAY_FIELDS_INVALID')
            need(record['schema'] == SCHEMA, 'REPLAY_SCHEMA_INVALID')
            scope, metrics = _upstream(scope_json, metrics_json,
                                       people_subject_witnesses)
            p = _policy(release_policy, scope, metrics)
            rebuilt = _project(scope, metrics, p)
            need(canonical(rebuilt) == canonical(record),
                 'REPLAY_DERIVATION_OR_BINDING_MISMATCH')
            out.update(status='partial', exit_code=2,
                       reason_code='REPORT_PREPARE_REPLAYED_WITH_ORIGINAL_INPUTS',
                       subject=rebuilt, canonical_json=canonical(rebuilt))
        except (PrepareError, MetricsError) as exc:
            if isinstance(exc, MetricsError):
                exc = PrepareError(exc.reason, exc.status)
            return _error(out, exc)
        return out

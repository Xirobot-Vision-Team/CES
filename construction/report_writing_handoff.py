#!/usr/bin/env python3
"""EC198: offline, review-only report_writing Handoff *draft*.

Derives a bounded editorial outline from the original EC197 canonical result,
replaying EC197 -> EC196 -> EC195 (and their real upstreams) with original bytes
and independent read/release declarations. A new, separately declared
per-repository *review-only* policy authorizes this exact EC197 projection and
all of its already-redacted citations for internal drafting, not AI egress.

A SHA/receipt is NOT a signature, verified identity, consent, source proof, or
permission to transfer anything. This module never dispatches a model, calls
EC174's unsupported report_writing route, creates an EC171 live HandoffId,
reads/writes files, renders a report, or grades a person.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from report_evidence_metrics import MetricsError, byte_len, canonical, digest, parse_json, valid_sha
from report_prepare import ReportPrepare

SCHEMA = 'ces.report_writing_handoff.v1'
DRAFT_SCHEMA = 'ces.report_writing_handoff_draft.v1'
POLICY_SCHEMA = 'ces.report_writing_review_policy.v1'
TASK_KIND = 'report_writing'
ROUTE_ID = 'ces.route.report_writing.v1'  # EC174 registered ID, NOT an EC174 runnable input.
PURPOSE = 'report_writing_internal_review_draft_only'
AUDIENCE = 'HUMAN_REPORT_EDITOR_INTERNAL'
MAX_PREPARED_BYTES = 1048576
MAX_POLICY_BYTES = 262144
MAX_OUTPUT_BYTES = 1048576
CITATION_RE = re.compile(r'cesrc1:[0-9a-f]{64}\Z', re.ASCII)

HEADINGS = {
    'git_activity': ('Declared Git references',
                     'Only listed Git references are available; no verified change, delivery, effort or individual achievement follows.'),
    'ai_conclusion': ('Declared AI observations',
                      'These are references to unverified AI claims, not established technical or personnel facts.'),
    'ci_execution': ('Declared CI signals',
                     'CI completion is a declaration, never proof of executed or passing tests; omitted evidence prevents a pass conclusion.'),
    'unknown_signal': ('Unknowns and evidence limitations',
                       'Unknown, unavailable, uncollected and withheld evidence must remain unresolved, not be treated as zero.'),
}
SOURCE_NOTICES = {
    'WorkingTree': 'WorkingTree is a declared local working-tree scope, not an authenticated current snapshot.',
    'DeliveredTarget': 'DeliveredTarget is a source-mode claim; verified delivery or deployment is not established.',
    'ProposedPR': 'ProposedPR is a proposal, not a merged, delivered or deployed change.',
}
EDITOR_RULES = [
    'This is a review-only outline, not factual report prose or a model request authorized for transmission.',
    'Keep every repository separate, with its own source/people binding and period; do not silently combine actors or counts.',
    'Use only the copied released citation references and typed claims; never manufacture evidence descriptions or conclusions.',
    'Preserve withheld, partial, unknown, missing and empty-not-zero states visibly for human review.',
    'CI PASS, even if present as a claim, is NOT independently verified execution or a successful test result.',
    'A ProposedPR is not delivery; Git events are not proof of productivity or a human contribution.',
    'Never generate, rank, score or imply individual employee performance; no personal identities are supplied.',
    'Request separate trusted proof and privacy/egress approval before any model transfer or publication.',
]
CLAIMS = {
    'independent_review_receipts_authenticated': False,
    'ec197_release_or_privacy_egress_permission_verified': False,
    'repository_source_or_actor_identity_authenticated': False,
    'complete_repository_universe_or_evidence_verified': False,
    'git_delivery_or_ai_conclusions_verified': False,
    'ci_executed_or_passed_verified': False,
    'individual_employee_performance_assessed': False,
    'ec171_live_run_or_handoff_created': False,
    'ec174_report_writing_route_executed': False,
    'external_ai_or_adapter_invoked': False,
    'external_transfer_authorized_or_performed': False,
    'human_review_or_report_approval_completed': False,
    'report_rendered_saved_or_published': False,
    'native_powershell_route_registered': False,
    'filesystem_network_or_business_repository_written': False,
}


class HandoffDraftError(ValueError):
    """An error code safe to return without reflecting user-supplied strings."""

    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def require(condition: bool, code: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise HandoffDraftError(code, status)


def fields(value: Any, required: set[str], code: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == required, code)
    return value


def _bounded_json(value: Any, maximum: int, code: str) -> int:
    try:
        length = byte_len(canonical(value))
    except (MetricsError, ValueError, TypeError, RecursionError, OverflowError,
            UnicodeError) as exc:
        raise HandoffDraftError(code) from exc
    require(0 < length <= maximum, code)
    return length


def _replayed_prepare(*, prepare_json: Any, scope_json: str,
                      metrics_json: str, release_policy: dict[str, Any],
                      people_subject_witnesses: dict[str, str] | None) -> dict[str, Any]:
    require(type(prepare_json) is str, 'PREPARED_CANONICAL_JSON_REQUIRED')
    require(0 < byte_len(prepare_json) <= MAX_PREPARED_BYTES,
            'PREPARED_CANONICAL_JSON_SIZE_INVALID')
    # Enforce duplicate-key rejection, no floats, canonical ordering, and strict
    # byte-level recomputation. A self-consistent local hash is insufficient.
    original = parse_json(prepare_json)
    result = ReportPrepare().from_json(
        serialized=prepare_json, scope_json=scope_json, metrics_json=metrics_json,
        release_policy=release_policy, people_subject_witnesses=people_subject_witnesses)
    require(result['status'] == 'partial', 'EC197_OR_UPSTREAM_REPLAY_REFUSED',
            'unavailable' if result['status'] == 'unavailable' else 'invalid_input')
    subject = result['subject']
    require(canonical(subject) == prepare_json and subject == original,
            'PREPARED_ORIGINAL_BYTES_CHANGED')
    require(subject['schema'] == 'ces.report_prepare.v1' and
            subject['ai_input']['schema'] == 'ces.report_writing_input.v1' and
            subject['ai_input']['purpose'] == 'periodic_report_writing_input' and
            subject['ai_input']['transmission_state'] == 'NOT_SENT_REQUIRES_EXTERNAL_APPROVAL' and
            subject['ai_input']['data_trust_state'] == 'DECLARED_ONLY_NOT_AUTHENTICATED',
            'PREPARED_CONTEXT_NOT_REVIEWABLE', 'unavailable')
    return subject


def _citation_refs(repo: dict[str, Any]) -> list[str]:
    # Does not accept raw event IDs. EC197's replayed already-redacted values
    # are the *only* citations the writer may use in this round.
    return [c['citation_ref'] for channel in repo['channels'] for c in channel['citations']]


def _policy(value: Any, prepared: dict[str, Any],
            release_policy: Any) -> dict[str, Any]:
    require(type(value) is dict, 'REVIEW_POLICY_REQUIRED', 'unavailable')
    _bounded_json(value, MAX_POLICY_BYTES, 'REVIEW_POLICY_SIZE_OR_JSON_INVALID')
    p = fields(value, {
        'schema', 'purpose', 'audience', 'task_kind', 'route_id',
        'permit_review_only', 'prepare_binding_sha256', 'ai_input_sha256',
        'scope_binding_sha256', 'metrics_binding_sha256', 'period_id',
        'policy_receipt_sha256', 'repository_grants',
    }, 'REVIEW_POLICY_FIELDS_INVALID')
    require(p['schema'] == POLICY_SCHEMA and p['purpose'] == PURPOSE and
            p['audience'] == AUDIENCE and p['task_kind'] == TASK_KIND and
            p['route_id'] == ROUTE_ID and type(p['permit_review_only']) is bool and
            p['permit_review_only'] is True, 'REVIEW_PURPOSE_ROUTE_OR_OPTIN_INVALID',
            'unavailable')
    require(p['prepare_binding_sha256'] == prepared['binding_sha256'] and
            p['ai_input_sha256'] == prepared['ai_input_sha256'] and
            p['scope_binding_sha256'] == prepared['scope_binding_sha256'] and
            p['metrics_binding_sha256'] == prepared['metrics_binding_sha256'] and
            p['period_id'] == prepared['period_id'],
            'REVIEW_POLICY_PREPARE_SCOPE_OR_PERIOD_STALE', 'unavailable')
    require(valid_sha(p['policy_receipt_sha256']),
            'REVIEW_POLICY_RECEIPT_REQUIRED', 'unavailable')
    ai_repositories = prepared['ai_input']['repositories']
    expected = {r['repository_ref']: r for r in ai_repositories}
    grant_rows = p['repository_grants']
    require(type(grant_rows) is list and len(grant_rows) == len(expected),
            'REVIEW_REPOSITORY_GRANTS_INCOMPLETE', 'unavailable')
    # Independent receipts cannot simply reuse the upstream AI release claims.
    # Their authenticity is still NOT proven by this purely declarative check.
    require(type(release_policy) is dict and
            type(release_policy.get('repository_grants')) is list,
            'RELEASE_GRANTS_UNAVAILABLE', 'unavailable')
    prior_receipts = {r['release_receipt_sha256']
                      for r in release_policy['repository_grants']
                      if type(r) is dict and type(r.get('release_receipt_sha256')) is str}
    receipt_seen = {p['policy_receipt_sha256']}
    require(not (receipt_seen & prior_receipts),
            'REVIEW_RECEIPT_NOT_INDEPENDENT', 'unavailable')
    seen: set[str] = set()
    normalized = []
    for item in grant_rows:
        r = fields(item, {'repository_ref', 'report_subject_ref',
                          'source_binding_sha256', 'people_binding_sha256',
                          'permit_review_only', 'review_receipt_sha256',
                          'approved_citation_refs'}, 'REVIEW_REPOSITORY_GRANT_FIELDS_INVALID')
        rid = r['repository_ref']
        require(type(rid) is str and rid in expected and rid not in seen,
                'REVIEW_REPOSITORY_SET_INVALID', 'unavailable')
        seen.add(rid)
        source = expected[rid]
        require(r['report_subject_ref'] == source['report_subject_ref'] and
                r['source_binding_sha256'] == source['source_binding_sha256'] and
                r['people_binding_sha256'] == source['people_binding_sha256'],
                'REVIEW_REPOSITORY_SOURCE_OR_PEOPLE_STALE', 'unavailable')
        require(type(r['permit_review_only']) is bool and r['permit_review_only'] is True,
                'REVIEW_REPOSITORY_NOT_PERMITTED', 'unavailable')
        receipt = r['review_receipt_sha256']
        require(valid_sha(receipt) and receipt not in receipt_seen and
                receipt not in prior_receipts,
                'REVIEW_RECEIPT_NOT_INDEPENDENT', 'unavailable')
        receipt_seen.add(receipt)
        approved = r['approved_citation_refs']
        permitted = _citation_refs(source)
        require(type(approved) is list and len(approved) <= 512 and
                all(type(x) is str and CITATION_RE.fullmatch(x) is not None for x in approved) and
                len(approved) == len(set(approved)),
                'REVIEW_CITATION_ALLOWLIST_INVALID')
        # Fail closed instead of implicitly broadening to new citations or
        # silently dropping refs without recalculating EC197 coverage/CI.
        require(set(approved) == set(permitted) and len(approved) == len(permitted),
                'REVIEW_CITATIONS_NOT_EXACT_RELEASED_SET', 'unavailable')
        normalized.append({**r, 'approved_citation_refs': sorted(approved)})
    require(seen == set(expected), 'REVIEW_REPOSITORY_GRANTS_INCOMPLETE', 'unavailable')
    return {**{k: p[k] for k in p if k != 'repository_grants'},
            'repository_grants': sorted(normalized, key=lambda row: row['repository_ref'])}


def _outline(ai_input: dict[str, Any]) -> dict[str, Any]:
    repo_sections = []
    for repo in ai_input['repositories']:
        slots = []
        for ch in repo['channels']:
            title, note = HEADINGS[ch['channel']]
            slots.append({
                'channel': ch['channel'], 'heading': title, 'draft_note': note,
                'coverage_state': ch['coverage_state'],
                'coverage_reason_codes': list(ch['coverage_reason_codes']),
                'release_state': ch['release_state'],
                'ci_completion_signal': ch['ci_completion_signal'],
                'citations': copy.deepcopy(ch['citations']),
                'evidence_claim_state': (
                    'UNVERIFIED_RELEASED_REFERENCES_ONLY' if ch['citations'] else
                    'NO_RELEASED_REFERENCES_NOT_EVIDENCE_OF_NO_ACTIVITY'),
            })
        repo_sections.append({
            'repository_ref': repo['repository_ref'],
            'report_subject_ref': repo['report_subject_ref'],
            'source_mode': repo['source_mode'],
            'source_binding_sha256': repo['source_binding_sha256'],
            'people_binding_sha256': repo['people_binding_sha256'],
            'period_window_complete_declared': repo['period_window_complete_declared'],
            'path_scope': repo['path_scope'],
            'inventory_state': repo['inventory_state'],
            'scope_gap_codes': list(repo['scope_gap_codes']),
            'source_notice': SOURCE_NOTICES[repo['source_mode']],
            'section_state': 'PLACEHOLDER_NO_FACTUAL_NARRATIVE',
            'evidence_slots': slots,
        })
    return {
        'opening': {
            'heading': 'Scope and reporting period',
            'draft_note': 'This review covers only the explicitly named, declaration-bound repositories and UTC reporting period. Completeness and source authenticity are unverified.',
            'scope_ref': ai_input['scope_ref'],
            'period': copy.deepcopy(ai_input['period']),
        },
        'repository_sections': repo_sections,
        'closing': {
            'heading': 'Gaps, review decisions and outstanding proof',
            'draft_note': 'Before factual narrative or any external transfer, verify source claims, permission, privacy and evidence; retain each listed unknown or withheld gap.',
            'global_gap_codes': list(ai_input['global_gap_codes']),
        },
    }


def _compose(prepared: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    ai_input = prepared['ai_input']
    review_digest = digest('CES-EC198-REVIEW-POLICY-v1', review)
    pins = {
        'prepare_binding_sha256': prepared['binding_sha256'],
        'prepare_canonical_sha256': hashlib.sha256(canonical(prepared).encode('ascii')).hexdigest(),
        'ai_input_sha256': prepared['ai_input_sha256'],
        'scope_ref': prepared['scope_id'],
        'scope_binding_sha256': prepared['scope_binding_sha256'],
        'metrics_binding_sha256': prepared['metrics_binding_sha256'],
        'release_policy_binding_sha256': prepared['release_policy_binding_sha256'],
        'period_id': prepared['period_id'],
    }
    handoff = {
        'schema': DRAFT_SCHEMA, 'task_kind': TASK_KIND, 'route_id': ROUTE_ID,
        'route_state': 'STANDALONE_REVIEW_DRAFT_NOT_EC174_DISPATCH',
        'review_state': 'PENDING_HUMAN_SOURCE_AND_PRIVACY_REVIEW',
        'external_transfer_state': 'NOT_AUTHORIZED_NOT_DISPATCHED',
        'source_pins': copy.deepcopy(pins),
        'ai_input': copy.deepcopy(ai_input),
        'outline': _outline(ai_input),
        'editor_rules': list(EDITOR_RULES),
    }
    record = {
        'schema': SCHEMA, 'task_kind': TASK_KIND, 'route_id': ROUTE_ID,
        'source_pins': pins,
        'review_policy_binding_sha256': review_digest,
        'handoff_draft': handoff,
        'trust_claims': dict(CLAIMS),
    }
    record['draft_ref'] = 'cesrhd1:' + digest('CES-EC198-DRAFT-ID-v1', {
        'source_pins': pins, 'review_policy_binding_sha256': review_digest,
        'handoff': handoff,
    })
    record['binding_sha256'] = digest('CES-EC198-REPORT-WRITING-HANDOFF-v1', record)
    _bounded_json(record, MAX_OUTPUT_BYTES, 'DRAFT_OUTPUT_TOO_LARGE')
    return record


def _empty() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'REPORT_WRITING_HANDOFF_INPUT_INVALID',
            'subject': None, 'canonical_json': None, 'limitations': dict(CLAIMS)}


def _fail(out: dict[str, Any], exc: HandoffDraftError) -> dict[str, Any]:
    out['status'] = exc.status
    out['exit_code'] = 5 if exc.status == 'unavailable' else 4
    out['reason_code'] = 'REPORT_WRITING_HANDOFF_' + exc.code
    return out


class ReportWritingHandoff:
    """Offline EC198 draft composer. No live EC171 handoff, AI or writes."""

    def bind(self, *, prepare_json: str, scope_json: str, metrics_json: str,
             release_policy: dict[str, Any], review_policy: dict[str, Any],
             people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        result = _empty()
        try:
            prepared = _replayed_prepare(
                prepare_json=prepare_json, scope_json=scope_json,
                metrics_json=metrics_json, release_policy=release_policy,
                people_subject_witnesses=people_subject_witnesses)
            review = _policy(review_policy, prepared, release_policy)
            subject = _compose(prepared, review)
            result.update(status='partial', exit_code=2,
                          reason_code='REPORT_WRITING_HANDOFF_REVIEW_ONLY_DRAFT',
                          subject=subject, canonical_json=canonical(subject))
        except MetricsError as exc:
            return _fail(result, HandoffDraftError(exc.reason))
        except HandoffDraftError as exc:
            return _fail(result, exc)
        return result

    def from_json(self, *, serialized: str, prepare_json: str, scope_json: str,
                  metrics_json: str, release_policy: dict[str, Any],
                  review_policy: dict[str, Any],
                  people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        """Re-derive the entire draft from original EC197/196/195 + both grants."""
        result = _empty()
        try:
            raw = parse_json(serialized)
            fields(raw, {'schema', 'task_kind', 'route_id', 'source_pins',
                         'review_policy_binding_sha256', 'handoff_draft',
                         'trust_claims', 'draft_ref', 'binding_sha256'},
                   'REPLAY_FIELDS_INVALID')
            require(raw['schema'] == SCHEMA, 'REPLAY_SCHEMA_INVALID')
            built = self.bind(prepare_json=prepare_json, scope_json=scope_json,
                              metrics_json=metrics_json, release_policy=release_policy,
                              review_policy=review_policy,
                              people_subject_witnesses=people_subject_witnesses)
            require(built['status'] == 'partial', 'REPLAY_OR_UPSTREAM_REFUSED',
                    'unavailable' if built['status'] == 'unavailable' else 'invalid_input')
            require(canonical(raw) == built['canonical_json'],
                    'REPLAY_DERIVATION_OR_BINDING_MISMATCH')
            result.update(status='partial', exit_code=2,
                          reason_code='REPORT_WRITING_HANDOFF_REPLAYED_REVIEW_DRAFT',
                          subject=built['subject'], canonical_json=built['canonical_json'])
        except MetricsError as exc:
            return _fail(result, HandoffDraftError(exc.reason))
        except HandoffDraftError as exc:
            return _fail(result, exc)
        return result

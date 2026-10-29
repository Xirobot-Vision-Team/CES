#!/usr/bin/env python3
"""EC221: version-pinned, redacted, LOCAL-ONLY DeliveryPreview.

Read ONLY through the existing EC200 ReportHistory / EC179 FindingShower
interfaces, with their independent private-store read scopes. All sources are
selected and pinned BEFORE any read; none are accepted as caller-provided
'published', 'delivered', or verified content. No arbitrary source text, file
path, repository, recipient string, email address, URL or secret enters the
result. A bounded, fixed-vocabulary Markdown PREVIEW (not the real content)
is produced IN MEMORY. Reader internals may inspect private local source bytes.

This is NOT EC222 redaction policy, EC223 recipient verification, EC224 delivery
authorization or EC225 sending. It does not call AI, network, Git, PowerShell,
Issue/PR write APIs, storage writers or publication adapters. The private-store
readers' local hash checks do not authenticate human/org/source identities.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

try:
    from . import report_history as rh, report_render as rr, finding_show as fshow
except ImportError:
    import report_history as rh
    import report_render as rr
    import finding_show as fshow

SCHEMA = 'ces.delivery_preview.v1'
PREVIEW_FORMAT = 'text/markdown;charset=utf-8'
MAX_SOURCES = 8
MAX_PREVIEW_BYTES = 12288
MAX_POLICY_BYTES = 262144
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
PRIVACY = ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')
AUDIENCES = frozenset(('INTERNAL_REVIEW', 'NAMED_EXTERNAL', 'PUBLIC_DISTRIBUTION'))
CHANNELS = frozenset(('EMAIL', 'CHAT', 'DOCUMENT_PORTAL', 'MANUAL_EXPORT'))
REPORT_FORMAT = rr.FORMAT
FINDING_FORMAT = 'application/vnd.ces.finding-declaration-metadata+json'
DOMAIN = b'CES-EC221-DELIVERY-PREVIEW-v1\x00'
SOURCE_DOMAIN = b'CES-EC221-SOURCE-SELECTION-v1\x00'
DEST_DOMAIN = b'CES-EC221-DESTINATION-v1\x00'
CONTENT_DOMAIN = b'CES-EC221-EXACT-REDACTED-PREVIEW-v1\x00'

# Constant, machine-readable issues. We NEVER propagate third-party text or
# free-form source gap codes into an output/error/Markdown preview.
GAP_SOURCE_TRUST = 'SOURCE_AUTHORITY_NOT_EXTERNALLY_VERIFIED'
GAP_CONTENT = 'FULL_CONTENT_WITHHELD_PENDING_EC222_POLICY'
GAP_RECIPIENT = 'RECIPIENT_IDENTITY_UNVERIFIED_EC223'
GAP_CHANNEL = 'CHANNEL_IDENTITY_UNVERIFIED_EC223'
GAP_AUDIENCE = 'AUDIENCE_IDENTITY_UNVERIFIED_EC223'
GAP_APPROVAL = 'EXACT_DELIVERY_AUTHORIZATION_MISSING_EC224'
GAP_TRANSPORT = 'SEND_OR_PUBLISH_ADAPTER_NOT_AVAILABLE_EC225'
REQUIRED_APPROVALS = (
    'EC222_SENSITIVE_CONTENT_REVIEW',
    'EC223_RECIPIENT_AND_CHANNEL_VERIFICATION',
    'EC224_EXACT_CONTENT_AND_DESTINATION_APPROVAL',
    'EC225_CONTROLLED_SEND_ADAPTER',
)


@dataclass(frozen=True)
class Destination:
    """Identity commitments are UNVERIFIED sha256 strings, NOT addresses.

    Hashes alone do not identify or authorize a recipient. EC223 must resolve
    actual identities in a separate trusted host process; this step does NOT.
    """
    audience_kind: str
    channel_kind: str
    audience_identity_sha256: str | None
    channel_identity_sha256: str | None
    recipient_identity_sha256: str | None


@dataclass(frozen=True)
class ReportSelection:
    """Fully pinned EC200 locally saved report; one particular version.

    `read_policy` must be newly approved for the EC200 store read. An existing
    report draft, report_ref or `show` JSON alone is NOT an accepted source.
    """
    reader: rh.ReportHistory
    storage_root: str
    slot_key: str
    period_id: str
    slot_members: list[dict[str, str]]
    read_policy: dict[str, Any]
    selected_version: int
    expected_report_ref: str
    expected_entry_sha256: str
    expected_record_sha256: str
    expected_rendered_sha256: str
    expected_index_binding_sha256: str


@dataclass(frozen=True)
class FindingSelection:
    """One exact finding on a pinned EC179 HMAC store revision.

    Caller must first learn exact digests through a separately authorized
    FindingShow query; never accept an arbitrary Finding JSON as provenance.
    """
    reader: fshow.FindingShower
    expected_finding_store_pin: str
    authorized_source_binding: dict[str, Any]
    query_content_for: str
    finding_id: str
    expected_batch_sequence: int
    expected_record_sha256: str
    expected_original_finding_sha256: str
    expected_revision_sha256: str
    expected_query_sha256: str
    acknowledge_historical_proposal_metadata: bool = False


@dataclass(frozen=True)
class DeliveryPreviewRequest:
    sources: tuple[ReportSelection | FindingSelection, ...]
    destination: Destination
    policy_revision_sha256: str
    requested_privacy_floor: str
    permit_local_preview: bool
    permit_private_source_metadata_read: bool
    permit_report_content_read_in_process: bool
    permit_finding_digest_details_read: bool


class PreviewDenied(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(test: bool, code: str, status: str = 'invalid_input') -> None:
    if not test:
        raise PreviewDenied(code, status)


def valid_sha(v: Any) -> bool:
    return type(v) is str and SHA.fullmatch(v) is not None


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')


def sha(domain: bytes, obj: Any) -> str:
    return hashlib.sha256(domain + canonical(obj)).hexdigest()


def json_snapshot(obj: Any, *, max_bytes: int, code: str) -> Any:
    """Copy potentially mutable caller arguments without echoing contents."""
    try:
        b = canonical(obj)
        need(len(b) <= max_bytes, code)
        return json.loads(b)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise PreviewDenied(code) from None


def destination_shape(d: Destination) -> dict[str, Any]:
    need(type(d) is Destination, 'DESTINATION_REQUIRED')
    need(type(d.audience_kind) is str and d.audience_kind in AUDIENCES,
         'AUDIENCE_KIND_INVALID')
    need(type(d.channel_kind) is str and d.channel_kind in CHANNELS,
         'CHANNEL_KIND_INVALID')
    for v in (d.audience_identity_sha256, d.channel_identity_sha256,
              d.recipient_identity_sha256):
        need(v is None or valid_sha(v), 'DESTINATION_IDENTITY_MUST_BE_SHA256_OR_NULL')
    # Public distribution is NOT an anonymous sending permission. An explicit
    # recipient/group identity commitment is still required for future checks.
    return {
        'audience_kind': d.audience_kind, 'channel_kind': d.channel_kind,
        'audience_identity_sha256': d.audience_identity_sha256,
        'channel_identity_sha256': d.channel_identity_sha256,
        'recipient_identity_sha256': d.recipient_identity_sha256,
    }


def source_preflight(s: ReportSelection | FindingSelection) -> tuple[str, dict[str, Any]]:
    """Validate the FULL selection prior to ANY private read."""
    if type(s) is ReportSelection:
        need(type(s.reader) is rh.ReportHistory, 'REPORT_READER_REQUIRED')
        need(type(s.storage_root) is str and 0 < len(s.storage_root) <= 4096,
             'REPORT_STORE_ROOT_INVALID')
        need(type(s.slot_key) is str and rr.KEY.fullmatch(s.slot_key) is not None and
             type(s.period_id) is str and 0 < len(s.period_id) <= 256,
             'REPORT_SELECTOR_INVALID')
        need(type(s.selected_version) is int and 1 <= s.selected_version <= rr.MAX_VERSIONS,
             'REPORT_VERSION_INVALID')
        need(type(s.expected_report_ref) is str and rr.REPORT.fullmatch(s.expected_report_ref)
             is not None and all(valid_sha(x) for x in (
                 s.expected_entry_sha256, s.expected_record_sha256,
                 s.expected_rendered_sha256,
                 s.expected_index_binding_sha256)), 'REPORT_VERSION_HASH_PINS_REQUIRED')
        members = json_snapshot(s.slot_members, max_bytes=32768, code='REPORT_MEMBERS_INVALID')
        policy = json_snapshot(s.read_policy, max_bytes=MAX_POLICY_BYTES,
                               code='REPORT_READ_POLICY_INVALID')
        need(type(members) is list and 1 <= len(members) <= 32 and
             type(policy) is dict, 'REPORT_SELECTOR_INVALID')
        # Pure EC200 validations here, against caller-declared local binding.
        # Actual binding-to-live-store comparison still occurs IN show().
        try:
            selector = rh._selector(s.slot_key, s.period_id, members)
            rh._policy(policy, selector, policy.get('store_binding_sha256'))
        except (rh.RenderError, KeyError, TypeError, ValueError, AttributeError):
            raise PreviewDenied('REPORT_SELECTOR_OR_POLICY_INVALID') from None
        # Only the original report reader may interpret private policy fields.
        # Fingerprinting the policy does not make it an authenticated consent.
        return 'REPORT', {
            'storage_root': s.storage_root, 'slot_key': s.slot_key,
            'period_id': s.period_id, 'slot_members': members, 'read_policy': policy,
            'selected_version': s.selected_version,
            'expected_report_ref': s.expected_report_ref,
            'expected_entry_sha256': s.expected_entry_sha256,
            'expected_record_sha256': s.expected_record_sha256,
            'expected_rendered_sha256': s.expected_rendered_sha256,
            'expected_index_binding_sha256': s.expected_index_binding_sha256,
        }
    if type(s) is FindingSelection:
        need(type(s.reader) is fshow.FindingShower, 'FINDING_READER_REQUIRED')
        need(all(valid_sha(x) for x in (
            s.expected_finding_store_pin, s.finding_id, s.expected_record_sha256,
            s.expected_original_finding_sha256, s.expected_revision_sha256,
            s.expected_query_sha256)), 'FINDING_EXACT_HASH_PINS_REQUIRED')
        need(type(s.expected_batch_sequence) is int and 1 <= s.expected_batch_sequence <= 128,
             'FINDING_BATCH_VERSION_INVALID')
        need(type(s.query_content_for) is str and
             s.query_content_for in ('WorkingTree', 'DeliveredTarget', 'ProposedPR'),
             'FINDING_SOURCE_MODE_INVALID')
        need(type(s.acknowledge_historical_proposal_metadata) is bool and
             (s.query_content_for != 'ProposedPR' or
              s.acknowledge_historical_proposal_metadata is True),
             'HISTORICAL_PROPOSAL_ACK_REQUIRED')
        scope = json_snapshot(s.authorized_source_binding, max_bytes=8192,
                              code='FINDING_AUTHORIZED_SOURCE_BINDING_INVALID')
        need(type(scope) is dict and set(scope) == fshow.SOURCE_KEYS and
             scope.get('source_mode') == s.query_content_for,
             'FINDING_AUTHORIZED_SOURCE_BINDING_INVALID')
        try:
            fshow._binding(scope, s.query_content_for)
        except (fshow.FindingShowError, TypeError, ValueError, KeyError):
            raise PreviewDenied('FINDING_AUTHORIZED_SOURCE_BINDING_INVALID') from None
        # No arbitrary `filters`, `cursor`, page count, or expired audit input.
        return 'FINDING', {
            'expected_finding_store_pin': s.expected_finding_store_pin,
            'source_binding': scope,
            'query_content_for': s.query_content_for,
            'finding_id': s.finding_id,
            'expected_batch_sequence': s.expected_batch_sequence,
            'expected_record_sha256': s.expected_record_sha256,
            'expected_original_finding_sha256': s.expected_original_finding_sha256,
            'expected_revision_sha256': s.expected_revision_sha256,
            'expected_query_sha256': s.expected_query_sha256,
            'acknowledge_historical_proposal_metadata':
                s.acknowledge_historical_proposal_metadata,
        }
    raise PreviewDenied('UNSUPPORTED_SOURCE_KIND')


def report_source(s: ReportSelection, p: dict[str, Any]) -> dict[str, Any]:
    # EC200 read policy is verified by the actual owner-private store reader.
    # include_markdown=False EVEN IF another scope permits rendered Markdown.
    response = s.reader.show(
        storage_root=p['storage_root'], slot_key=p['slot_key'],
        period_id=p['period_id'], slot_members=p['slot_members'],
        read_policy=p['read_policy'], version=p['selected_version'],
        compare_to_version=None, include_markdown=False,
    )
    need(type(response) is dict and response.get('schema') == rh.SCHEMA and
         response.get('status') == 'partial' and response.get('exit_code') == 2,
         'REPORT_READ_NOT_AVAILABLE', 'unavailable')
    doc = response.get('subject')
    need(type(doc) is dict and doc.get('rendered_markdown') is None and
         doc.get('publication_state') == 'NOT_PUBLISHED' and
         doc.get('document_state') == 'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT' and
         doc.get('trust_state') == 'DECLARED_ONLY_NOT_AUTHENTICATED' and
         doc.get('store_read_state') ==
         'PRIVATE_LOCAL_STORE_BYTES_VERIFIED_NOT_EXTERNAL_AUTHENTICATION' and
         doc.get('selected_version') == p['selected_version'] and
         type(doc.get('latest_version')) is int and
         p['selected_version'] <= doc['latest_version'] <= rr.MAX_VERSIONS and
         doc.get('selected_report_ref') == p['expected_report_ref'] and
         doc.get('selected_entry_sha256') == p['expected_entry_sha256'] and
         doc.get('record_sha256') == p['expected_record_sha256'] and
         doc.get('rendered_sha256') == p['expected_rendered_sha256'] and
         doc.get('index_binding_sha256') == p['expected_index_binding_sha256'] and
         type(doc.get('history')) is list and
         len(doc['history']) == doc['latest_version'] and
         type(doc['history'][p['selected_version']-1]) is dict and
         doc['history'][p['selected_version']-1].get('report_ref') ==
         p['expected_report_ref'] and
         doc['history'][p['selected_version']-1].get('entry_sha256') ==
         p['expected_entry_sha256'] and
         doc['history'][p['selected_version']-1].get('record_sha256') ==
         p['expected_record_sha256'] and
         doc['history'][p['selected_version']-1].get('rendered_sha256') ==
         p['expected_rendered_sha256'] and
         doc.get('report_slot_ref') == p['read_policy'].get('report_slot_ref') and
         doc.get('slot_key') == p['slot_key'] and doc.get('period_id') == p['period_id'] and
         doc.get('slot_members') == p['slot_members'],
         'REPORT_VERSION_OR_LOCAL_STORE_DRIFT', 'unavailable')
    repos = doc.get('repositories')
    need(type(repos) is list and 1 <= len(repos) <= 32,
         'REPORT_COVERAGE_SHAPE_INVALID', 'unavailable')
    gaps: set[str] = {GAP_SOURCE_TRUST}
    withheld_channels = 0
    incomplete_channels = 0
    incomplete_repos = 0
    citation_count = 0
    for repo in repos:
        need(type(repo) is dict and type(repo.get('channels')) is list and
             len(repo['channels']) == len(rr.CHANNEL_ORDER) and
             type(repo.get('scope_gap_codes')) is list and
             type(repo.get('period_window_complete_declared')) is bool,
             'REPORT_COVERAGE_SHAPE_INVALID', 'unavailable')
        if (not repo['period_window_complete_declared'] or repo['scope_gap_codes'] or
                repo.get('inventory_state') != 'complete_declared'):
            incomplete_repos += 1
        for ch in repo['channels']:
            need(type(ch) is dict and ch.get('channel') in rr.CHANNEL_ORDER and
                 type(ch.get('citation_count')) is int and
                 0 <= ch['citation_count'] <= 512 and
                 type(ch.get('coverage_reason_codes')) is list,
                 'REPORT_CHANNEL_SHAPE_INVALID', 'unavailable')
            citation_count += ch['citation_count']
            if ch.get('coverage_state') != 'COMPLETE_DECLARED' or ch['coverage_reason_codes']:
                incomplete_channels += 1
            if ch.get('release_state') != 'ALL_SUBMITTED_REFERENCES_RELEASED':
                withheld_channels += 1
    if incomplete_repos:
        gaps.add('REPORT_REPOSITORY_OR_PERIOD_COVERAGE_GAP')
    if incomplete_channels:
        gaps.add('REPORT_CHANNEL_COVERAGE_INCOMPLETE_OR_UNVERIFIED')
    if withheld_channels:
        gaps.add('REPORT_REFERENCES_NOT_ALL_RELEASED')
    if doc['selected_version'] != doc['latest_version']:
        gaps.add('REPORT_EXPLICIT_HISTORICAL_VERSION')
    # Even COMPLETE_DECLARED never demonstrates Git/CI truth or full coverage.
    return {
        'source_kind': 'REPORT', 'source_version': doc['selected_version'],
        'latest_observed_version': doc['latest_version'],
        'source_record_sha256': doc['record_sha256'],
        'source_content_sha256': doc['rendered_sha256'],
        'content_digest_kind': 'RENDERED_MARKDOWN_SHA256',
        'content_format': REPORT_FORMAT,
        'source_version_sha256': sha(SOURCE_DOMAIN, {
            'store_binding_sha256': p['read_policy']['store_binding_sha256'],
            'report_slot_ref': doc['report_slot_ref'],
            'version': doc['selected_version'],
            'report_ref': doc['selected_report_ref'],
            'index_binding_sha256': doc['index_binding_sha256'],
            'entry_sha256': doc['selected_entry_sha256'],
            'record_sha256': doc['record_sha256'],
            'rendered_sha256': doc['rendered_sha256'],
        }),
        'store_revision_sha256': doc['index_binding_sha256'],
        'store_read_trust': 'EC200_LOCAL_HASH_LINKS_ONLY_NOT_EXTERNAL_AUTHORITY',
        'privacy_minimum': 'INTERNAL',
        'coverage': {
            'source_units_count': len(repos),
            'evidence_reference_count': citation_count,
            'incomplete_source_units_count': incomplete_repos,
            'incomplete_channel_count': incomplete_channels,
            'not_fully_released_channel_count': withheld_channels,
        },
        'gap_codes': sorted(gaps),
        'is_remote_delivery_evidence': False,
    }


def finding_source(s: FindingSelection, p: dict[str, Any]) -> dict[str, Any]:
    response = s.reader.query(
        expected_finding_store_pin=p['expected_finding_store_pin'],
        authorize_store_read=True, authorize_query=True,
        authorized_source_binding=p['source_binding'],
        query_content_for=p['query_content_for'],
        filters={'finding_id': p['finding_id']}, page_size=1, cursor=None,
        include_expired=False, authorize_expired_audit=False,
        authorize_path_digest_query=False,
        include_digest_details=True, authorize_digest_details=True,
        acknowledge_historical_proposal_metadata=
            p['acknowledge_historical_proposal_metadata'],
    )
    need(type(response) is dict and response.get('schema') == fshow.SCHEMA and
         response.get('status') == 'partial' and response.get('exit_code') == 2,
         'FINDING_READ_NOT_AVAILABLE', 'unavailable')
    rows = response.get('findings')
    scope = response.get('scope')
    provenance = response.get('provenance')
    effects = response.get('effects')
    need(response.get('save_store_pin') == p['expected_finding_store_pin'] and
         response.get('revision_sha256') == p['expected_revision_sha256'] and
         response.get('query_sha256') == p['expected_query_sha256'] and
         response.get('matched_count') == 1 and
         response.get('returned_count') == 1 and
         type(rows) is list and len(rows) == 1 and
         response.get('next_cursor') is None and
         type(scope) is dict and
         scope.get('source_mode') == p['query_content_for'] and
         scope.get('source_identity_sha256') ==
         p['source_binding']['source_identity_sha256'] and
         type(provenance) is dict and
         provenance.get('complete_private_manifest_key_and_hash_chain_checked') is True and
         provenance.get('objective_truth_current_git_ci_or_test_proven') is False and
         type(effects) is dict and
         effects.get('external_transfer') is False and
         effects.get('ces_records_written') is False,
         'FINDING_STORE_REVISION_OR_QUERY_DRIFT', 'unavailable')
    row = rows[0]
    details = row.get('digest_details') if type(row) is dict else None
    need(type(row) is dict and type(details) is dict and
         row.get('finding_id') == p['finding_id'] and
         row.get('batch_sequence') == p['expected_batch_sequence'] and
         details.get('record_sha256') == p['expected_record_sha256'] and
         details.get('original_finding_sha256') ==
         p['expected_original_finding_sha256'] and
         row.get('source_mode') == p['query_content_for'] and
         row.get('expired_at_query_time') is False and
         row.get('semantic_defect_verified') is False and
         row.get('actual_test_or_ci_verified') is False and
         row.get('current_git_verified') is False and
         type(row.get('positive_anchor_count')) is int and
         0 <= row['positive_anchor_count'] <= 32 and
         type(row.get('coverage_complete_for_selected_source')) is bool and
         type(row.get('coverage_missing_requirements_count')) is int and
         0 <= row['coverage_missing_requirements_count'] <= 512 and
         type(row.get('historical_proposal_only')) is bool and
         type(row.get('assessment_state')) is str and
         row['assessment_state'] in fshow.save.STATES,
         'FINDING_EXACT_RECORD_OR_TRUST_STATE_MISMATCH', 'unavailable')
    gaps: set[str] = {GAP_SOURCE_TRUST, 'FINDING_SEMANTIC_DEFECT_NOT_VERIFIED'}
    if (not row['coverage_complete_for_selected_source'] or
            row['coverage_missing_requirements_count']):
        gaps.add('FINDING_SOURCE_COVERAGE_INCOMPLETE')
    if row['assessment_state'] != 'REVIEWED':
        gaps.add('FINDING_LOCAL_REVIEW_NOT_COMPLETE')
    if row['historical_proposal_only'] or p['query_content_for'] == 'ProposedPR':
        gaps.add('FINDING_HISTORICAL_PROPOSAL_NOT_DELIVERED_TARGET')
    return {
        'source_kind': 'FINDING',
        'source_version': row['batch_sequence'],
        'latest_observed_version': None,  # HMAC store revision, not a batch sequence maximum
        'source_record_sha256': details['record_sha256'],
        'source_content_sha256': details['original_finding_sha256'],
        'content_digest_kind': 'ORIGINAL_FINDING_DECLARATION_SHA256_NOT_RAW_TEXT',
        'content_format': FINDING_FORMAT,
        'source_version_sha256': sha(SOURCE_DOMAIN, {
            'finding_store_pin': p['expected_finding_store_pin'],
            'source_binding': p['source_binding'], 'finding_id': p['finding_id'],
            'batch_sequence': row['batch_sequence'],
            'record_sha256': details['record_sha256'],
            'original_finding_sha256': details['original_finding_sha256'],
            'revision_sha256': p['expected_revision_sha256'],
        }),
        'store_revision_sha256': p['expected_revision_sha256'],
        'store_read_trust': 'EC179_LOCAL_HMAC_HASH_CHAIN_ONLY_NOT_EXTERNAL_AUTHORITY',
        'privacy_minimum': 'CONFIDENTIAL',
        'coverage': {
            'source_units_count': 1,
            'evidence_reference_count': row['positive_anchor_count'],
            'incomplete_source_units_count': int(not row['coverage_complete_for_selected_source']),
            'incomplete_channel_count': 0,
            'not_fully_released_channel_count': 0,
        },
        'gap_codes': sorted(gaps),
        'is_remote_delivery_evidence': False,
    }


def effects() -> dict[str, bool]:
    return {
        'external_network_requested': False,
        'recipient_contacted': False,
        'message_sent': False,
        'delivery_accepted': False,
        'delivered': False,
        'published': False,
        'issue_or_pr_created_or_modified': False,
        'git_or_business_files_written': False,
        'ces_records_written': False,
        'external_ai_invoked': False,
        'source_content_disclosed_in_preview': False,
        'recipient_identity_verified': False,
        'delivery_authorized': False,
    }


def refusal(status: str, code: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': 'DELIVERY_PREVIEW_' + code,
        'preview_id': None, 'preview': None, 'preview_markdown': None,
        'preview_content_sha256': None,
        'delivery_state': 'NO_DELIVERY_OR_PUBLICATION',
        'effects': effects(),
    }


def _markdown(sources: list[dict[str, Any]], privacy: str,
              destination: Destination, gaps: list[str]) -> str:
    # The only Markdown generation path. Never concatenate caller/provider text.
    lines = [
        '# Delivery preview — LOCAL ONLY', '',
        'This is a redacted manifest, not report text or a send-ready payload.', '',
        f'- Pinned local sources: {len(sources)}',
        f'- Requested audience category: {destination.audience_kind}',
        f'- Requested channel category: {destination.channel_kind}',
        f'- Effective minimum privacy: {privacy}',
        '- Recipient/channel verification: NOT PERFORMED',
        '- Delivery, publication and external transfer: NOT PERFORMED', '',
        '## Source commitments', '',
    ]
    for i, s in enumerate(sources, 1):
        lines.append(f'{i}. {s["source_kind"]} version {s["source_version"]} — '
                     f'version commitment `{s["source_version_sha256"]}`; '
                     'content concealed')
    lines += ['', '## Unresolved gates', '']
    lines.extend('- ' + gap for gap in gaps)
    lines += ['', 'Future independent content review, recipient verification, '
              'exact authorization and sending are required.', '']
    md = '\n'.join(lines)
    need(len(md.encode('utf-8')) <= MAX_PREVIEW_BYTES,
         'PREVIEW_OUTPUT_LIMIT', 'unavailable')
    return md


def preview_delivery(request: DeliveryPreviewRequest) -> dict[str, Any]:
    """Read pinned local sources; return one deterministic redacted preview.

    All selections are preflighted before any store read. Any unavailable source,
    stale version or missing local permission fails CLOSED with no partial source
    metadata. No I/O other than the explicit EC200/EC179 private read methods.
    """
    try:
        need(type(request) is DeliveryPreviewRequest, 'REQUEST_REQUIRED')
        flags = (request.permit_local_preview,
                 request.permit_private_source_metadata_read,
                 request.permit_report_content_read_in_process,
                 request.permit_finding_digest_details_read)
        need(all(type(f) is bool for f in flags), 'PREVIEW_READ_PERMISSION_TYPES_INVALID')
        need(request.permit_local_preview is True and
             request.permit_private_source_metadata_read is True,
             'INDEPENDENT_LOCAL_PREVIEW_AND_PRIVATE_READ_PERMISSION_REQUIRED',
             'unavailable')
        need(valid_sha(request.policy_revision_sha256),
             'PREVIEW_POLICY_REVISION_HASH_REQUIRED')
        need(type(request.requested_privacy_floor) is str and
             request.requested_privacy_floor in PRIVACY,
             'PRIVACY_FLOOR_INVALID')
        dest = destination_shape(request.destination)
        need(type(request.sources) is tuple and 1 <= len(request.sources) <= MAX_SOURCES,
             'SOURCES_COUNT_INVALID')
        # Validate and freeze EVERY argument and duplicate BEFORE first private
        # read; do not defer invalid source #2 until after reading source #1.
        prepared = [source_preflight(s) for s in request.sources]
        if any(kind == 'REPORT' for kind, _ in prepared):
            need(request.permit_report_content_read_in_process is True,
                 'REPORT_PRIVATE_CONTENT_READ_PERMISSION_REQUIRED', 'unavailable')
        if any(kind == 'FINDING' for kind, _ in prepared):
            need(request.permit_finding_digest_details_read is True,
                 'FINDING_DIGEST_DETAIL_PERMISSION_REQUIRED', 'unavailable')
        identities = []
        for kind, p in prepared:
            if kind == 'REPORT':
                identity = ('REPORT', p['read_policy'].get('store_binding_sha256'),
                            p['expected_report_ref'], p['selected_version'])
            else:
                identity = ('FINDING', p['expected_finding_store_pin'],
                            p['finding_id'], p['expected_record_sha256'])
            need(identity not in identities, 'DUPLICATE_SOURCE_SELECTED')
            identities.append(identity)
        sources = []
        for (kind, p), original in zip(prepared, request.sources):
            sources.append(report_source(original, p) if kind == 'REPORT'
                           else finding_source(original, p))
        privacy = PRIVACY[max([PRIVACY.index(request.requested_privacy_floor)] +
                              [PRIVACY.index(s['privacy_minimum']) for s in sources])]
        gaps = {GAP_CONTENT, GAP_RECIPIENT, GAP_CHANNEL, GAP_AUDIENCE,
                GAP_APPROVAL, GAP_TRANSPORT}
        for s in sources:
            gaps.update(s['gap_codes'])
        if dest['recipient_identity_sha256'] is None:
            gaps.add('RECIPIENT_IDENTITY_NOT_SELECTED')
        if dest['channel_identity_sha256'] is None:
            gaps.add('CHANNEL_IDENTITY_NOT_SELECTED')
        if dest['audience_identity_sha256'] is None:
            gaps.add('AUDIENCE_IDENTITY_NOT_SELECTED')
        if request.requested_privacy_floor != privacy:
            gaps.add('REQUESTED_PRIVACY_BELOW_SOURCE_MINIMUM')
        if privacy in ('CONFIDENTIAL', 'RESTRICTED'):
            gaps.add('SENSITIVE_SOURCE_REVIEW_REQUIRED')
        if dest['audience_kind'] != 'INTERNAL_REVIEW':
            gaps.add('EXTERNAL_AUDIENCE_NOT_CLEARED_FOR_CONTENT')
        gaps_sorted = sorted(gaps)
        md = _markdown(sources, privacy, request.destination, gaps_sorted)
        content_sha = hashlib.sha256(md.encode('utf-8')).hexdigest()
        binding = {
            'policy_revision_sha256': request.policy_revision_sha256,
            'destination': dest, 'requested_privacy_floor': request.requested_privacy_floor,
            'effective_privacy': privacy,
            'source_version_sha256': [s['source_version_sha256'] for s in sources],
            'content_sha256': [s['source_content_sha256'] for s in sources],
            'preview_markdown_sha256': content_sha,
        }
        preview_id = 'cesdp1:' + sha(DOMAIN, binding)
        preview = {
            'preview_id': preview_id,
            'render_format': PREVIEW_FORMAT,
            'destination': {**dest,
                'destination_binding_sha256': sha(DEST_DOMAIN, dest),
                'audience_verified': False, 'channel_verified': False,
                'recipient_verified': False},
            'sources': sources,
            'privacy': {
                'requested_floor': request.requested_privacy_floor,
                'effective_minimum_class': privacy,
                'independently_declassified': False,
                'content_policy_reviewed': False,
            },
            'coverage_and_permission_gaps': gaps_sorted,
            'required_future_approvals': list(REQUIRED_APPROVALS),
            'source_bytes_emitted': False,
            'cross_source_atomic_snapshot': False,
            'identity_or_source_trust_authenticated': False,
            'is_deliverable_payload': False,
            'ready_to_send': False,
            'delivery_evidence_present': False,
        }
        # Manifest hash binds the *exact* returned redacted payload too.
        preview['preview_manifest_sha256'] = sha(CONTENT_DOMAIN, preview)
        return {
            'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
            'reason_code': 'DELIVERY_PREVIEW_LOCAL_ONLY_NOT_SEND_READY',
            'preview_id': preview_id, 'preview': preview,
            'preview_markdown': md,
            'preview_content_sha256': content_sha,
            'delivery_state': 'NO_DELIVERY_OR_PUBLICATION',
            'effects': effects(),
        }
    except PreviewDenied as e:
        return refusal(e.status, e.code)
    except Exception:
        # Never echo exception strings; may include private URLs/paths/tokens.
        return refusal('unavailable', 'PRIVATE_SOURCE_READ_OR_PROJECTION_UNAVAILABLE')

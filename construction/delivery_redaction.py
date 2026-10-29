#!/usr/bin/env python3
"""EC222: local, fail-closed policy review of EC221 EXACT selected sources.

The EC221 manifest is not proof that any sensitive source text was inspected.
A fresh, separate opt-in is required here. EC200's actual saved Markdown is
read under its own per-repository Markdown grants and compared with the original
version/content/index pins. EC179 intentionally does not store raw Finding text:
a host-supplied IN-MEMORY original finding may be reviewed only after its
EC175 domain-separated exact original SHA is re-bound to the HMAC-verified
EC178 stored row and its EC179 revision. Otherwise the Finding is blocked.

This module returns ONLY fixed-vocabulary metadata; no source text, witness,
path, excerpts, recipient addresses, network, AI, send/publish, or file writes.
The fixed conservative local policy is not an authenticated organizational
declassification, privacy certification or general-purpose PII detector.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import hmac
import html
import json
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

try:
    from . import delivery_preview as dp
    from . import codevalidate_staged as cv
    from . import report_writing_handoff as wh
    from . import finding_show as fshow
    from . import finding_save as fsave
except ImportError:
    import delivery_preview as dp
    import codevalidate_staged as cv
    import report_writing_handoff as wh
    import finding_show as fshow
    import finding_save as fsave

SCHEMA = 'ces.delivery_redaction.v1'
MAX_REPORT_BYTES = 256 * 1024
MAX_WITNESS_BYTES = 128 * 1024
MAX_SUMMARY_BYTES = 8192
MAX_LINE_BYTES = 1024
POLICY_DOMAIN = b'CES-EC222-FIXED-SENSITIVE-POLICY-v1\x00'
REVIEW_DOMAIN = b'CES-EC222-EXACT-LOCAL-REVIEW-v1\x00'
SUMMARY_DOMAIN = b'CES-EC222-REDACTED-SUMMARY-v1\x00'

POLICY_SPEC = {
    'schema': 'ces.delivery_sensitive_policy.v1',
    'revision': 'EC222_FIXED_CONSERVATIVE_V1',
    'report_format': dp.REPORT_FORMAT,
    'finding_format': dp.FINDING_FORMAT,
    'reviewed_material': 'PINNED_LOCAL_REPORT_MARKDOWN_OR_HASH_BOUND_FINDING_ORIGINAL',
    'detectors': [
        'STRICT_REPORT_RENDERER_LINE_ALLOWLIST', 'PATCH_AND_DIFF',
        'REPOSITORY_AND_ABSOLUTE_PATH', 'CREDENTIAL_AND_HIGH_ENTROPY',
        'PERSON_ATTRIBUTION_AND_CONTACT', 'ENCODING_AND_FORMAT_AMBIGUITY',
        'EXACT_FINDING_ORIGINAL_HASH_AND_PRIVATE_ROW',
        'NARROW_NEUTRAL_FINDING_TEXT_ALLOWLIST',
    ],
    'missing_or_unclassifiable': 'BLOCK',
    'only_output': 'FIXED_VOCABULARY_REDACTED_METADATA',
    'declassification': False,
    'recipient_or_send_authorization': False,
}
# A policy identifier binds the entire shipped implementation source, not just
# the policy's human-readable detector names. It is NOT an organizational
# signature; host operators still must approve the local code and policy.
try:
    _IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
except OSError:
    _IMPLEMENTATION_SHA256 = None
ACTIVE_POLICY_SHA256 = (
    dp.sha(POLICY_DOMAIN, {**POLICY_SPEC,
                           'implementation_sha256': _IMPLEMENTATION_SHA256})
    if _IMPLEMENTATION_SHA256 is not None else None
)
REASON_CODES = frozenset((
    'PATCH_OR_DIFF_CONTENT', 'REPOSITORY_PATH_OR_SOURCE_FILENAME',
    'CREDENTIAL_OR_TOKEN_MATERIAL', 'PERSON_OR_CONTACT_CONTENT',
    'OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT', 'REPORT_LINE_OUTSIDE_STRICT_TEMPLATE',
    'FINDING_TEXT_NOT_AVAILABLE_IN_PRIVATE_STORE',
    'FINDING_ORIGINAL_WITNESS_HASH_MISMATCH',
    'FINDING_METADATA_OR_WITNESS_MISMATCH',
    'FINDING_LOCAL_REVIEW_NOT_COMPLETE', 'FINDING_HISTORICAL_PROPOSAL',
    'FINDING_TEXT_OUTSIDE_NARROW_SAFE_VOCABULARY',
))


@dataclass(frozen=True)
class FindingTextWitness:
    """Ephemeral original EC175 finding object. NEVER persisted or returned."""
    source_index: int  # zero-based index into EC221's exact sources tuple
    original_finding: dict[str, Any]


@dataclass(frozen=True)
class SensitiveReviewRequest:
    preview_request: dp.DeliveryPreviewRequest
    expected_preview_id: str
    expected_policy_sha256: str
    permit_independent_sensitive_policy_review: bool
    permit_exact_report_plaintext_review: bool
    permit_exact_finding_plaintext_review: bool
    finding_text_witnesses: tuple[FindingTextWitness, ...] = ()


class ReviewDenied(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def _need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise ReviewDenied(code, status)


def _refusal(code: str, status: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': 'DELIVERY_REDACTION_' + code,
        'review_id': None, 'review': None, 'redacted_markdown': None,
        'redacted_markdown_sha256': None,
        'delivery_state': 'NO_DELIVERY_OR_PUBLICATION', 'effects': dp.effects(),
    }


# Strictly recognize the EC198/EC199 generator's fixed English sentence stock.
# Versioned line allowlist is deliberate: changes to the renderer must first be
# re-reviewed and explicitly introduced in a later policy revision.
_REPORT_FIXED_LINES = frozenset((
    '', '# Internal periodic evidence report — review draft',
    '> INTERNAL ONLY · NOT PUBLISHED · Source, permissions and CI claims are unverified.',
    '> No employee performance assessment or verified delivery/CI result is expressed.',
    '## Scope and period',
    '- Coverage and provenance: declarations only; missing evidence is not zero activity.',
    '- Scope gaps: none declared (not verified)',
    '- Coverage reasons: none declared (not verified)',
    '- No released citations (NOT proof of no activity).',
    '- Released, unverified typed citations:',
    '## Unresolved global gaps and editorial requirements',
    '- All cited references are declared, not authenticated.',
    '- ProposedPR is a proposal, NOT a delivered or merged change.',
    '- An unverified completed_pass_claim is NOT an executed, passing CI result.',
    '- Unknown, withheld, empty, partial and missing states must stay visible.',
    '- Do not assess, score or rank employees or infer effort from Git/event counts.',
    '- Source and privacy approval must be established separately before publication.',
    'Global gap codes:', '---',
    'Unpublished internal evidence review · not ReportPublish',
)) | frozenset(
    text for channel, pair in wh.HEADINGS.items()
    for text in ('### ' + dp.rr.CHANNEL_LABELS[channel], pair[1])
) | frozenset(
    '- Source caveat: ' + note for note in wh.SOURCE_NOTICES.values()
)

# Only opaque, type-constrained identifiers, machine codes and fixed enum
# fields can appear in a report that is called locally classifiable.
_HASH = r'[0-9a-f]{64}'
_OPAQUE = rf'(?:ces[a-z0-9]+:{_HASH}|ces[a-z0-9]+:[A-Za-z0-9:_-]{{1,65}})'
_CODE = r'[A-Z][A-Z0-9_]{0,95}'
_CODES = rf'`{_CODE}`(?:, `{_CODE}`){{0,31}}'
_REPORT_PATTERNS = tuple(re.compile(r'\A' + p + r'\Z', re.ASCII) for p in (
    r'- Report slot: `[a-zA-Z0-9_-]{1,128}`',
    rf'- Scope reference: `{_OPAQUE}`',
    r'- Period ID: `[A-Za-z0-9:_-]{1,96}`',
    r'- UTC interval: `[0-9TZ:.-]{10,35}` to `[0-9TZ:.-]{10,35}` \(end exclusive\)',
    rf'## Repository `cesrepo1:{_HASH}`',
    rf'- Report subject: `{_OPAQUE}`',
    r'- Source mode: `(WorkingTree|DeliveredTarget|ProposedPR)`',
    rf'- Source binding SHA-256: `{_HASH}`',
    rf'- People binding SHA-256: `{_HASH}`',
    r'- Window completeness \(declared\): `(true|false)`',
    rf'- Path scope: `{_CODE}`',
    r'- Inventory state: `(complete_declared|partial_declared|unavailable_declared|unknown_declared)`',
    rf'- Scope gaps: {_CODES}',
    rf'- Coverage: `{_CODE}`',
    rf'- Release state: `{_CODE}`',
    rf'- CI completion: `{_CODE}` \(claim only, never authenticated PASS\)',
    rf'- Claim state: `{_CODE}`',
    rf'- Coverage reasons: {_CODES}',
    rf'  - `cesrc1:{_HASH}` · `[a-z][a-z_]+` · `{_CODE}` · `{_CODE}`',
    rf'- `{_CODE}`',
))
_NEUTRAL_FINDING_WORDS = frozenset(
    'a an and as at claim declared example for from generic in internal is'
    ' local metadata no not of only placeholder review sample source synthetic'
    ' test the this unverified observation observed text change without'
    ' available unknown safe reference line evidence checks need incomplete'
    ' requires confirmation draft note status finding record'.split()
)
_NEUTRAL_TEXT = re.compile(r"[A-Za-z]+(?:[ .,;:!?()'-][A-Za-z]+)*[.!?]?\Z")


def _suspicion_codes(text: str) -> set[str]:
    """Bounded conservative lexical screening; never returns matching substrings."""
    flags: set[str] = set()
    if type(text) is not str:
        return {'OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT'}
    raw = text.encode('utf-8', errors='surrogatepass')
    if len(raw) > MAX_REPORT_BYTES or not text.strip():
        return {'OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT'}
    if any((ord(c) < 32 and c not in '\r\n\t') or
           ord(c) in (0x7f, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff) or
           0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069
           for c in text):
        flags.add('OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT')
    if re.search(r'\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})|%[0-9a-fA-F]{2}|&#[xX0-9a-fA-F]+;|&(?:lt|gt|amp|quot);',
                 text):
        flags.add('OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT')
    normalized = unicodedata.normalize('NFKC', html.unescape(unquote(text)))
    if any(ord(c) > 0x02ff and c not in '—·' for c in normalized):
        # Unknown scripts/emoji/hidden Unicode can hold names or deceptive paths.
        flags.add('OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT')
    if re.search(r'(?im)(?:^|\n)\s*(?:diff --git\b|index [0-9a-f]{6,}\.\.|@@\s+-\d+|'
                 r'\+\+\+\s+[ab]/|---\s+[ab]/|\*\*\* Begin Patch|'
                 r'<<<<<<<|=======\s*$|>>>>>>>|```\s*(?:diff|patch))',
                 normalized):
        flags.add('PATCH_OR_DIFF_CONTENT')
    if re.search(r'(?i)(?:\b(?:src|lib|app|tests?|home|users|etc|var|opt)/'
                 r'[a-z0-9_.\-/]+|(?:^|[\s`"\'(])\.\.?/[A-Za-z0-9_.-]+|'
                 r'(?<![A-Za-z])/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+|'
                 r'\b[A-Za-z]:\\[^\s]+|\\\\[A-Za-z0-9_.-]+\\|'
                 r'\b[A-Za-z0-9_.-]+\.(?:py|js|ts|tsx|java|go|rs|cs|cpp|h|'
                 r'json|yaml|yml|env|ini|pem|key|sh|ps1)(?:\b|$)|'
                 r'file://|https?://|git@[\w.-]+:)',
                 normalized):
        flags.add('REPOSITORY_PATH_OR_SOURCE_FILENAME')
    if re.search(r'(?i)(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|OPENSSH) KEY-----|'
                 r'\b(?:password|passwd|api[_-]?key|secret|private[_-]?key|'
                 r'access[_-]?token|refresh[_-]?token|client[_-]?secret|'
                 r'authorization|bearer)\s*[:=]\s*\S+|'
                 r'\b(?:ghp_|github_pat_|glpat-|xox[baprs]-|sk_live_|sk_test_|'
                 r'AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,})|'
                 r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})',
                 normalized):
        flags.add('CREDENTIAL_OR_TOKEN_MATERIAL')
    # Unknown long high-entropy alphanumeric blobs are blocked unless clearly
    # recognized 64-hex digest commitments from the already pinned sources.
    for token in re.findall(r'(?<![A-Za-z0-9_])[A-Za-z0-9_+/=-]{40,}(?![A-Za-z0-9_])',
                            normalized):
        if not dp.valid_sha(token) and re.search(r'[A-Za-z]', token) and re.search(r'\d', token):
            flags.add('CREDENTIAL_OR_TOKEN_MATERIAL')
            break
    if re.search(r'(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b@[\w.-]{2,}\b|'
                 r'(?<!\w)\+\d[\d ().-]{8,}\d\b|\b\d{10,15}\b|'
                 r'\b(?:author|assignee|owner|reviewer|committer|employee|'
                 r'person|contact|姓名|电话|邮箱)\s*[:=]\s*\S+|'
                 r'\b(?:written|reviewed|created|committed)\s+by\s+[A-Z][a-z]+\b',
                 normalized):
        flags.add('PERSON_OR_CONTACT_CONTENT')
    if re.search(r'<[A-Za-z/]|!\[|\]\(|\x00', normalized):
        flags.add('OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT')
    return flags


def _check_report_text(markdown: str) -> list[str]:
    issues = _suspicion_codes(markdown)
    if type(markdown) is not str or len(markdown.encode('utf-8')) > MAX_REPORT_BYTES:
        issues.add('OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT')
    else:
        # Any unexpected prose or altered renderer layout is NOT presumed safe.
        for line in markdown.split('\n'):
            if len(line.encode('utf-8')) > MAX_LINE_BYTES or not (
                line in _REPORT_FIXED_LINES or
                any(pattern.fullmatch(line) for pattern in _REPORT_PATTERNS)
            ):
                issues.add('REPORT_LINE_OUTSIDE_STRICT_TEMPLATE')
                break
    return sorted(issues)


def _check_finding_text(original: dict[str, Any]) -> list[str]:
    # Original content is already SHA-bound. Still reject unknown text rather
    # than pretending regex-only screening can establish PII absence.
    issues: set[str] = set()
    try:
        texts: list[str] = [original['title'], original['analysis']]
        if original['suggested_action'] is not None:
            texts.append(original['suggested_action'])
        for anchor in original['anchors']:
            if anchor['source_path'] is not None:
                issues.add('REPOSITORY_PATH_OR_SOURCE_FILENAME')
            texts.extend((anchor['quote'], anchor['segment_label']))
        _need(len(texts) <= 80 and all(type(x) is str for x in texts),
              'FINDING_WITNESS_TEXT_INVALID')
        for value in texts:
            issues.update(_suspicion_codes(value))
            # Deliberately narrow: natural names, technical code, longer
            # free-form claims etc require an independent human content review.
            words = re.findall(r"[A-Za-z]+", value.casefold())
            if (not _NEUTRAL_TEXT.fullmatch(value) or len(value) > 180 or
                    not words or any(w not in _NEUTRAL_FINDING_WORDS for w in words)):
                issues.add('FINDING_TEXT_OUTSIDE_NARROW_SAFE_VOCABULARY')
    except (KeyError, TypeError, ValueError):
        issues.add('FINDING_METADATA_OR_WITNESS_MISMATCH')
    return sorted(issues)


def _read_report_text(sel: dp.ReportSelection, pins: dict[str, Any],
                      source: dict[str, Any]) -> str:
    result = sel.reader.show(
        storage_root=pins['storage_root'], slot_key=pins['slot_key'],
        period_id=pins['period_id'], slot_members=pins['slot_members'],
        read_policy=pins['read_policy'], version=pins['selected_version'],
        compare_to_version=None, include_markdown=True,
    )
    _need(type(result) is dict and result.get('status') == 'partial' and
          result.get('exit_code') == 2 and result.get('schema') == dp.rh.SCHEMA,
          'REPORT_MARKDOWN_READ_REFUSED', 'unavailable')
    doc = result.get('subject')
    _need(type(doc) is dict, 'REPORT_MARKDOWN_SHAPE_INVALID', 'unavailable')
    md = doc.get('rendered_markdown')
    _need(type(md) is str and len(md.encode('utf-8')) <= MAX_REPORT_BYTES and
          hashlib.sha256(md.encode('utf-8')).hexdigest() == pins['expected_rendered_sha256'],
          'REPORT_CONTENT_HASH_OR_SIZE_DRIFT', 'unavailable')
    _need(doc.get('index_binding_sha256') == pins['expected_index_binding_sha256'] and
          doc.get('selected_entry_sha256') == pins['expected_entry_sha256'] and
          doc.get('record_sha256') == pins['expected_record_sha256'] and
          doc.get('rendered_sha256') == pins['expected_rendered_sha256'] and
          doc.get('selected_report_ref') == pins['expected_report_ref'] and
          doc.get('selected_version') == pins['selected_version'] and
          doc.get('report_slot_ref') == pins['read_policy']['report_slot_ref'] and
          doc.get('slot_key') == pins['slot_key'] and
          doc.get('period_id') == pins['period_id'] and
          doc.get('slot_members') == pins['slot_members'] and
          doc.get('publication_state') == 'NOT_PUBLISHED' and
          doc.get('store_read_state') ==
          'PRIVATE_LOCAL_STORE_BYTES_VERIFIED_NOT_EXTERNAL_AUTHENTICATION' and
          source['source_content_sha256'] == pins['expected_rendered_sha256'] and
          source['store_revision_sha256'] == pins['expected_index_binding_sha256'] and
          source['source_record_sha256'] == pins['expected_record_sha256'],
          'REPORT_VERSION_OR_STORE_CHANGED_DURING_REVIEW', 'unavailable')
    return md


def _finding_row(sel: dp.FindingSelection, pins: dict[str, Any],
                 source: dict[str, Any]) -> dict[str, Any]:
    """Read exact HMAC-vetted stored metadata, NOT original Finding raw text."""
    with sel.reader.ledger._locked() as (fd, manifest, key, live_pins):
        _need(manifest is not None and key is not None and
              hmac.compare_digest(fsave._pin(manifest), pins['expected_finding_store_pin']),
              'FINDING_STORE_CHANGED_DURING_REVIEW', 'unavailable')
        records = sel.reader.ledger._all(fd, key, manifest)
        revision = fshow._sha(fshow.DOMAIN_REVISION, {
            'store_pin': pins['expected_finding_store_pin'],
            'batch_count': len(records), 'record_shas': [r['record_sha256'] for r in records],
        })
        _need(hmac.compare_digest(revision, pins['expected_revision_sha256']) and
              revision == source['store_revision_sha256'],
              'FINDING_REVISION_CHANGED_DURING_REVIEW', 'unavailable')
        matching = [
            (r, row) for r in records for row in r['findings']
            if r['sequence'] == pins['expected_batch_sequence'] and
            row['finding_id'] == pins['finding_id'] and
            r['source_binding'] == pins['source_binding']
        ]
        _need(len(matching) == 1, 'FINDING_NOT_AVAILABLE_AT_PINNED_REVISION', 'unavailable')
        rec, row = matching[0]
        # A version/revision hash cannot extend a Finding's saved TTL.
        now = fsave.st._now(sel.reader.clock)
        _need(now < fsave.st._parse_stamp(rec['expires_at_utc']) and
              now + fsave.timedelta(seconds=fsave.st.MAX_SKEW_SECONDS) >=
              fsave.st._parse_stamp(rec['committed_at_utc']),
              'FINDING_TTL_OR_CLOCK_CHANGED_DURING_REVIEW', 'unavailable')
        _need(rec['record_sha256'] == pins['expected_record_sha256'] and
              row['original_finding_sha256'] == pins['expected_original_finding_sha256'] and
              source['source_record_sha256'] == rec['record_sha256'] and
              source['source_content_sha256'] == row['original_finding_sha256'] and
              row['finding_id'] == pins['finding_id'],
              'FINDING_RECORD_OR_CONTENT_CHANGED_DURING_REVIEW', 'unavailable')
        sel.reader.ledger._live_pins(live_pins)
        return row.copy()


def _validate_witness(original: dict[str, Any], row: dict[str, Any],
                      pins: dict[str, Any]) -> list[str]:
    if cv._sha(cv.DOMAIN_FINDING, original) != pins['expected_original_finding_sha256']:
        return ['FINDING_ORIGINAL_WITNESS_HASH_MISMATCH']
    # A complete original SHA binds all fields including quoted source lines;
    # independent saved-field hashes additionally prevent accidental mismatches.
    try:
        texts = (original['title'], original['analysis'], original['suggested_action'])
        quote_hashes = [hashlib.sha256(a['quote'].encode('utf-8')).hexdigest()
                        for a in original['anchors']]
        text_hashes = [None if v is None else hashlib.sha256(v.encode('utf-8')).hexdigest()
                       for v in texts]
        matches = (
            type(original['ordinal']) is int and row['ordinal'] == original['ordinal'] and
            row['severity'] == original['severity'] and
            row['confidence_claim'] == original['confidence_claim'] and
            text_hashes == [row['title_sha256'], row['analysis_sha256'],
                            row['suggested_action_sha256']] and
            quote_hashes == row['positive_quote_sha256'] and
            len(original['anchors']) == len(row['positive_anchor_sha256']) and
            [a['anchor_sha256'] for a in original['anchors']] ==
            row['positive_anchor_sha256'] and
            original['verification'] == 'UNVERIFIED_AI_ASSERTION_NOT_PERSISTED_FINDING' and
            original['business_source_validation'] == 'NOT_RUN'
        )
        return [] if matches else ['FINDING_METADATA_OR_WITNESS_MISMATCH']
    except (KeyError, TypeError, ValueError, UnicodeError):
        return ['FINDING_METADATA_OR_WITNESS_MISMATCH']


def _redacted_markdown(preview: dict[str, Any], assessments: list[dict[str, Any]],
                       policy_sha: str) -> str:
    lines = [
        '# Local content policy review — REDACTED METADATA ONLY', '',
        'Content was inspected locally under separate, caller-declared permissions.',
        'No finding text, report body, repository path, patch, credential or personal content is included.',
        'Source trust, recipient identity and organization declassification are NOT verified.',
        'This is not a deliverable payload and cannot authorize a send or publication.', '',
        f'- Source count: {len(assessments)}',
        f'- Effective privacy minimum: {preview["privacy"]["effective_minimum_class"]}',
        f'- Sensitive policy revision SHA-256: `{policy_sha}`',
        f'- EC221 preview commitment: `{preview["preview_id"]}`', '',
        '## Redacted source commitments', '',
    ]
    for ix, row in enumerate(assessments, 1):
        lines.append(f'{ix}. {row["source_kind"]}: '
                     f'`{row["source_version_sha256"]}`; content fully withheld')
    lines += ['', '## Outstanding independent gates', '',
              '- Original data / Git / CI / human authority not authenticated.',
              '- EC223 recipient and channel identity verification required.',
              '- EC224 exact destination and content authorization required.',
              '- EC225 controlled send integration required.',
              '- No external communication or publication occurred.', '']
    md = '\n'.join(lines)
    _need(len(md.encode('utf-8')) <= MAX_SUMMARY_BYTES,
          'SUMMARY_LIMIT', 'unavailable')
    return md


def _prepare(req: SensitiveReviewRequest) -> tuple[list[tuple[str, dict[str, Any]]],
                                                     dict[int, dict[str, Any]]]:
    _need(type(req) is SensitiveReviewRequest and
          type(req.preview_request) is dp.DeliveryPreviewRequest, 'REQUEST_REQUIRED')
    _need(type(req.expected_preview_id) is str and
          re.fullmatch(r'cesdp1:[0-9a-f]{64}', req.expected_preview_id) is not None,
          'EXACT_EC221_PREVIEW_ID_REQUIRED')
    _need(_IMPLEMENTATION_SHA256 is not None and ACTIVE_POLICY_SHA256 is not None,
          'POLICY_IMPLEMENTATION_UNAVAILABLE', 'unavailable')
    try:
        current_implementation = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        raise ReviewDenied('POLICY_IMPLEMENTATION_UNAVAILABLE', 'unavailable') from None
    _need(hmac.compare_digest(_IMPLEMENTATION_SHA256, current_implementation),
          'POLICY_IMPLEMENTATION_DRIFT', 'unavailable')
    _need(req.expected_policy_sha256 == ACTIVE_POLICY_SHA256 and
          req.preview_request.policy_revision_sha256 == ACTIVE_POLICY_SHA256,
          'UNKNOWN_OR_MISMATCHED_POLICY_REVISION')
    for flag in (req.permit_independent_sensitive_policy_review,
                 req.permit_exact_report_plaintext_review,
                 req.permit_exact_finding_plaintext_review):
        _need(type(flag) is bool, 'SENSITIVE_REVIEW_GRANT_TYPE_INVALID')
    _need(req.permit_independent_sensitive_policy_review is True,
          'INDEPENDENT_SENSITIVE_POLICY_REVIEW_GRANT_REQUIRED', 'unavailable')
    selections = req.preview_request.sources
    _need(type(selections) is tuple and 1 <= len(selections) <= dp.MAX_SOURCES,
          'SOURCES_REQUIRED')
    prepared = [dp.source_preflight(s) for s in selections]
    if any(kind == 'REPORT' for kind, _ in prepared):
        _need(req.permit_exact_report_plaintext_review is True,
              'FRESH_REPORT_PLAINTEXT_REVIEW_GRANT_REQUIRED', 'unavailable')
        for kind, pins in prepared:
            if kind == 'REPORT':
                policy = pins['read_policy']
                _need(policy.get('permit_rendered_markdown') is True and
                      all(row.get('permit_rendered_markdown') is True
                          for row in policy.get('repository_grants', [])),
                      'EC200_EXACT_MARKDOWN_GRANTS_REQUIRED', 'unavailable')
    if any(kind == 'FINDING' for kind, _ in prepared):
        _need(req.permit_exact_finding_plaintext_review is True,
              'FRESH_FINDING_PLAINTEXT_REVIEW_GRANT_REQUIRED', 'unavailable')
    _need(type(req.finding_text_witnesses) is tuple and
          len(req.finding_text_witnesses) <= len(selections),
          'FINDING_WITNESS_COUNT_INVALID')
    witnesses: dict[int, dict[str, Any]] = {}
    for w in req.finding_text_witnesses:
        _need(type(w) is FindingTextWitness and type(w.source_index) is int and
              0 <= w.source_index < len(selections) and
              prepared[w.source_index][0] == 'FINDING' and
              w.source_index not in witnesses,
              'FINDING_WITNESS_SOURCE_OR_DUPLICATE_INVALID')
        obj = dp.json_snapshot(w.original_finding, max_bytes=MAX_WITNESS_BYTES,
                               code='FINDING_WITNESS_INVALID_OR_TOO_LARGE')
        _need(type(obj) is dict and len(obj) == 9 and set(obj) == {
            'ordinal', 'title', 'severity', 'confidence_claim', 'analysis',
            'suggested_action', 'anchors', 'verification', 'business_source_validation'
        }, 'FINDING_WITNESS_SHAPE_INVALID')
        witnesses[w.source_index] = obj
    return prepared, witnesses


def review_sensitive_delivery(request: SensitiveReviewRequest) -> dict[str, Any]:
    """Check an exact EC221 preview AND selected private content in memory.

    A blocked review is a negative decision, not a successful sanitization.
    Nothing here is an externally approved distribution/publication/PII policy.
    """
    try:
        prepared, witnesses = _prepare(request)  # NO private reads yet
        base = dp.preview_delivery(request.preview_request)
        _need(type(base) is dict and base.get('status') == 'partial' and
              base.get('exit_code') == 2 and
              base.get('preview_id') == request.expected_preview_id,
              'EXACT_EC221_PREVIEW_UNAVAILABLE_OR_STALE', 'unavailable')
        preview = base['preview']
        _need(preview['preview_manifest_sha256'] == dp.sha(dp.CONTENT_DOMAIN, {
            k: v for k, v in preview.items() if k != 'preview_manifest_sha256'
        }) and preview['ready_to_send'] is False and
              preview['is_deliverable_payload'] is False and
              preview['privacy']['content_policy_reviewed'] is False and
              len(preview['sources']) == len(prepared) and
              preview['preview_id'] == request.expected_preview_id and
              base['preview_content_sha256'] ==
              hashlib.sha256(base['preview_markdown'].encode('utf-8')).hexdigest(),
              'EC221_MANIFEST_INTEGRITY_UNAVAILABLE', 'unavailable')
        assessments = []
        reasons: set[str] = set()
        for index, ((kind, pins), sel, source) in enumerate(zip(
                prepared, request.preview_request.sources, preview['sources'])):
            _need(source['source_kind'] == kind, 'EC221_SOURCE_ORDER_DRIFT', 'unavailable')
            if kind == 'REPORT':
                text = _read_report_text(sel, pins, source)
                found = _check_report_text(text)
                examined = True
            else:
                row = _finding_row(sel, pins, source)
                original = witnesses.get(index)
                found = []
                examined = False
                if original is None:
                    found.append('FINDING_TEXT_NOT_AVAILABLE_IN_PRIVATE_STORE')
                else:
                    found += _validate_witness(original, row, pins)
                    if not found:
                        examined = True
                        found += _check_finding_text(original)
                if row['assessment_state'] != 'REVIEWED':
                    found.append('FINDING_LOCAL_REVIEW_NOT_COMPLETE')
                if pins['query_content_for'] == 'ProposedPR':
                    found.append('FINDING_HISTORICAL_PROPOSAL')
            found = sorted(set(found))
            _need(all(x in REASON_CODES for x in found),
                  'POLICY_REASONS_NOT_ALLOWLISTED', 'unavailable')
            reasons.update(found)
            assessments.append({
                'source_kind': kind,
                'source_version_sha256': source['source_version_sha256'],
                'source_content_sha256': source['source_content_sha256'],
                'store_revision_sha256': source['store_revision_sha256'],
                'content_examined': examined,
                'safe_under_fixed_local_policy': not found,
                'reason_codes': found,
            })
        is_safe = not reasons
        md = _redacted_markdown(preview, assessments, ACTIVE_POLICY_SHA256) if is_safe else None
        md_sha = hashlib.sha256(md.encode('utf-8')).hexdigest() if md is not None else None
        binding = {
            'policy_revision_sha256': ACTIVE_POLICY_SHA256,
            'base_preview_id': request.expected_preview_id,
            'base_manifest_sha256': preview['preview_manifest_sha256'],
            'destination_binding_sha256': preview['destination']['destination_binding_sha256'],
            'source_assessments': assessments,
            'redacted_markdown_sha256': md_sha,
            'verdict': 'SAFE_REDACTED_SUMMARY' if is_safe else 'BLOCKED',
        }
        review_id = 'cesdr1:' + dp.sha(REVIEW_DOMAIN, binding)
        result = {
            'schema': SCHEMA,
            'status': 'partial' if is_safe else 'blocked',
            'exit_code': 2 if is_safe else 5,
            'reason_code': ('DELIVERY_REDACTION_LOCAL_REDACTED_SUMMARY_ONLY' if is_safe
                            else 'DELIVERY_REDACTION_SENSITIVE_CONTENT_BLOCKED'),
            'review_id': review_id,
            'review': {
                'review_id': review_id, 'verdict': binding['verdict'],
                'policy_revision_sha256': ACTIVE_POLICY_SHA256,
                'base_preview_id': request.expected_preview_id,
                'base_preview_manifest_sha256': preview['preview_manifest_sha256'],
                'destination_binding_sha256':
                    preview['destination']['destination_binding_sha256'],
                'effective_minimum_privacy_class':
                    preview['privacy']['effective_minimum_class'],
                'source_assessments': assessments,
                'reason_codes': sorted(reasons),
                'source_bytes_emitted': False,
                'fixed_local_policy_only_not_human_or_org_declassification': True,
                'cross_source_atomic_snapshot': False,
                'recipient_or_channel_verified': False,
                'is_deliverable_payload': False,
                'safe_for_external_send': False,
                'ready_to_send': False,
                'message_sent': False, 'published': False,
            },
            'redacted_markdown': md,
            'redacted_markdown_sha256': md_sha,
            'delivery_state': 'NO_DELIVERY_OR_PUBLICATION',
            'effects': dp.effects(),
        }
        return result
    except (ReviewDenied, dp.PreviewDenied) as exc:
        return _refusal(exc.code, exc.status)
    except Exception:
        # No filesystem/reader exception details or user text may escape.
        return _refusal('PRIVATE_CONTENT_OR_POLICY_REVIEW_UNAVAILABLE', 'unavailable')

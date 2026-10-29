#!/usr/bin/env python3
"""EC199: bounded offline ReportRender and opt-in private immutable local saving.

A render is an *internal review artifact*, not ReportPublish. All outputs derive
from a freshly replayed EC198 Handoff with the complete EC197/196/195 originals.
The only prose is a fixed template; callers cannot inject narrative or claim
that Git, CI, employee performance, privacy grants or external sources are
verified. A separate render policy is required, and save additionally requires
private local storage and explicitly declared local-save permission.

Storage is supported only on POSIX hosts with dirfd, no-follow opens and flock.
The caller must supply a DEDICATED owner-private directory outside business
repositories. No external authorizer, egress, AI, scheduler or PowerShell route.
SHA-256 receipts demonstrate reproducibility, not the authenticity of approvals.
"""
from __future__ import annotations

import copy
try:
    import fcntl  # POSIX only; pure rendering must remain importable on Windows.
except ImportError:  # pragma: no cover - platform-specific
    fcntl = None
import hashlib
import os
import re
import secrets
import stat
from typing import Any

from report_evidence_metrics import (
    MetricsError, byte_len, canonical, digest, parse_json, valid_sha,
)
from report_writing_handoff import (
    ReportWritingHandoff, HandoffDraftError,
)

SCHEMA = 'ces.report_render.v1'
POLICY_SCHEMA = 'ces.report_render_policy.v1'
DOCUMENT_SCHEMA = 'ces.internal_report_document.v1'
INDEX_SCHEMA = 'ces.report_render_local_index.v1'
PURPOSE = 'periodic_report_internal_render_only'
AUDIENCE = 'HUMAN_REPORT_EDITOR_INTERNAL'
FORMAT = 'text/markdown;charset=utf-8'
MAX_HANDOFF = 1048576
MAX_POLICY = 262144
MAX_RECORD = 1048576
MAX_MARKDOWN = 524288
MAX_INDEX = 262144
MAX_VERSIONS = 64
STORAGE_SUBDIRECTORY = '.ces-report-render-v1'
CITE = re.compile(r'cesrc1:[0-9a-f]{64}\Z', re.ASCII)
KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,95}\Z', re.ASCII)
REPORT = re.compile(r'cesrr1:[0-9a-f]{64}\Z', re.ASCII)
SLOT = re.compile(r'cesrslot1:[0-9a-f]{64}\Z', re.ASCII)
CHANNEL_ORDER = ('ai_conclusion', 'ci_execution', 'git_activity', 'unknown_signal')
CHANNEL_LABELS = {
    'git_activity': 'Declared Git activity',
    'ai_conclusion': 'Declared AI conclusions',
    'ci_execution': 'Declared CI execution claims',
    'unknown_signal': 'Unknown signals and evidence gaps',
}
LIMITATIONS = {
    'external_authorization_or_review_receipts_authenticated': False,
    'report_contents_or_source_claims_independently_verified': False,
    'ci_execution_or_pass_verified': False,
    'repository_universe_or_identity_authenticated': False,
    'personal_performance_assessed_or_scored': False,
    'ai_model_or_external_provider_invoked': False,
    'external_publication_or_egress_authorized': False,
    'report_published': False,
    'native_powershell_report_render_registered': False,
    'local_storage_attacker_proof_or_cross_os_verified': False,
}


class RenderError(ValueError):
    """Privacy-preserving, constant error codes; never return raw user content."""

    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def require(yes: bool, code: str, status: str = 'invalid_input') -> None:
    if not yes:
        raise RenderError(code, status)


def fields(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, code)
    return value


def bounded(value: Any, limit: int, code: str) -> None:
    try:
        size = byte_len(canonical(value))
    except (TypeError, ValueError, RecursionError, UnicodeError, OverflowError,
            MetricsError) as exc:
        raise RenderError(code) from exc
    require(0 < size <= limit, code)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _exact_text(value: Any, limit: int, code: str) -> str:
    require(type(value) is str, code)
    require(0 < byte_len(value) <= limit, code)
    return value


def _replayed_handoff(*, handoff_json: str, prepare_json: str, scope_json: str,
                      metrics_json: str, release_policy: dict[str, Any],
                      review_policy: dict[str, Any],
                      people_subject_witnesses: dict[str, str] | None) -> dict[str, Any]:
    # Never accept a caller-invented partial outline, even with a matching
    # locally computed hash: replay full original EC198 -> 197 -> 196 -> 195.
    original = parse_json(_exact_text(handoff_json, MAX_HANDOFF, 'HANDOFF_SIZE_INVALID'))
    prior = ReportWritingHandoff().from_json(
        serialized=handoff_json, prepare_json=prepare_json,
        scope_json=scope_json, metrics_json=metrics_json,
        release_policy=release_policy, review_policy=review_policy,
        people_subject_witnesses=people_subject_witnesses)
    require(prior['status'] == 'partial', 'EC198_OR_UPSTREAM_REPLAY_REFUSED',
            'unavailable' if prior['status'] == 'unavailable' else 'invalid_input')
    require(prior['canonical_json'] == handoff_json and original == prior['subject'],
            'HANDOFF_ORIGINAL_BYTES_CHANGED')
    return prior['subject']


def _refs(repo: dict[str, Any]) -> list[str]:
    return [cite['citation_ref']
            for slot in repo['evidence_slots']
            for cite in slot['citations']]


def _render_policy(value: Any, handoff: dict[str, Any],
                   release_policy: dict[str, Any],
                   review_policy: dict[str, Any]) -> dict[str, Any]:
    require(type(value) is dict, 'RENDER_POLICY_REQUIRED', 'unavailable')
    bounded(value, MAX_POLICY, 'RENDER_POLICY_SIZE_INVALID')
    p = fields(value, {
        'schema', 'purpose', 'audience', 'permit_internal_render',
        'permit_local_save', 'slot_key', 'draft_ref',
        'draft_binding_sha256', 'review_policy_binding_sha256',
        'prepare_binding_sha256', 'ai_input_sha256', 'scope_binding_sha256',
        'metrics_binding_sha256', 'period_id', 'policy_receipt_sha256',
        'repository_grants',
    }, 'RENDER_POLICY_FIELDS_INVALID')
    require(p['schema'] == POLICY_SCHEMA and p['purpose'] == PURPOSE and
            p['audience'] == AUDIENCE and
            type(p['permit_internal_render']) is bool and p['permit_internal_render'],
            'RENDER_PURPOSE_OR_OPTIN_INVALID', 'unavailable')
    require(type(p['permit_local_save']) is bool,
            'RENDER_SAVE_OPTIN_INVALID')
    require(type(p['slot_key']) is str and KEY.fullmatch(p['slot_key']) is not None,
            'RENDER_SLOT_KEY_INVALID')
    pins = handoff['source_pins']
    require(
        p['draft_ref'] == handoff['draft_ref'] and
        p['draft_binding_sha256'] == handoff['binding_sha256'] and
        p['review_policy_binding_sha256'] == handoff['review_policy_binding_sha256'] and
        p['prepare_binding_sha256'] == pins['prepare_binding_sha256'] and
        p['ai_input_sha256'] == pins['ai_input_sha256'] and
        p['scope_binding_sha256'] == pins['scope_binding_sha256'] and
        p['metrics_binding_sha256'] == pins['metrics_binding_sha256'] and
        p['period_id'] == pins['period_id'],
        'RENDER_DRAFT_OR_SOURCE_PINS_STALE', 'unavailable')
    require(valid_sha(p['policy_receipt_sha256']),
            'RENDER_POLICY_RECEIPT_REQUIRED', 'unavailable')
    prior_receipts = set()
    for prior, key in ((release_policy, 'release_receipt_sha256'),
                       (review_policy, 'review_receipt_sha256')):
        require(type(prior) is dict and type(prior.get('repository_grants')) is list,
                'UPSTREAM_RECEIPTS_UNAVAILABLE', 'unavailable')
        for grant in prior['repository_grants']:
            if type(grant) is dict and valid_sha(grant.get(key)):
                prior_receipts.add(grant[key])
    if valid_sha(review_policy.get('policy_receipt_sha256')):
        prior_receipts.add(review_policy['policy_receipt_sha256'])
    # EC197 policy has no top-level receipt; the EC197 per-repo receipts
    # and EC198 top-level/per-repo review receipts remain disjoint.
    seen_receipts = set(prior_receipts)
    require(p['policy_receipt_sha256'] not in seen_receipts,
            'RENDER_RECEIPTS_NOT_INDEPENDENT', 'unavailable')
    seen_receipts.add(p['policy_receipt_sha256'])

    outline = handoff['handoff_draft']['outline']['repository_sections']
    expected = {r['repository_ref']: r for r in outline}
    ai_repos = {r['repository_ref']: r
                for r in handoff['handoff_draft']['ai_input']['repositories']}
    require(len(expected) == len(outline) == len(ai_repos),
            'RENDER_REPOSITORY_SET_INVALID')
    grants = p['repository_grants']
    require(type(grants) is list and len(grants) == len(expected),
            'RENDER_REPOSITORY_GRANTS_INCOMPLETE', 'unavailable')
    seen = set()
    normalized = []
    for value in grants:
        row = fields(value, {
            'repository_ref', 'report_subject_ref',
            'source_binding_sha256', 'people_binding_sha256',
            'permit_internal_render', 'permit_local_save',
            'render_receipt_sha256', 'approved_citation_refs',
        }, 'RENDER_GRANT_FIELDS_INVALID')
        rid = row['repository_ref']
        require(type(rid) is str and rid in expected and rid not in seen,
                'RENDER_REPOSITORY_SET_INVALID', 'unavailable')
        seen.add(rid)
        outline_row, ai_row = expected[rid], ai_repos[rid]
        require(
            row['report_subject_ref'] == outline_row['report_subject_ref'] ==
            ai_row['report_subject_ref'] and
            row['source_binding_sha256'] == outline_row['source_binding_sha256'] ==
            ai_row['source_binding_sha256'] and
            row['people_binding_sha256'] == outline_row['people_binding_sha256'] ==
            ai_row['people_binding_sha256'],
            'RENDER_REPOSITORY_SOURCE_PEOPLE_STALE', 'unavailable')
        require(type(row['permit_internal_render']) is bool and
                row['permit_internal_render'] and
                type(row['permit_local_save']) is bool,
                'RENDER_REPOSITORY_PERMISSION_MISSING', 'unavailable')
        if row['permit_local_save']:
            require(p['permit_local_save'], 'RENDER_SAVE_GRANT_SCOPE_INVALID',
                    'unavailable')
        receipt = row['render_receipt_sha256']
        require(valid_sha(receipt) and receipt not in seen_receipts,
                'RENDER_RECEIPTS_NOT_INDEPENDENT', 'unavailable')
        seen_receipts.add(receipt)
        approved = row['approved_citation_refs']
        actual = _refs(outline_row)
        require(type(approved) is list and len(approved) <= 512 and
                all(type(c) is str and CITE.fullmatch(c) for c in approved) and
                len(set(approved)) == len(approved),
                'RENDER_CITATION_ALLOWLIST_INVALID')
        require(len(approved) == len(actual) and set(approved) == set(actual),
                'RENDER_CITATIONS_NOT_EXACT_RELEASED_SET', 'unavailable')
        normalized.append({**row, 'approved_citation_refs': sorted(approved)})
    require(seen == set(expected), 'RENDER_REPOSITORY_GRANTS_INCOMPLETE',
            'unavailable')
    return {**{k: p[k] for k in p if k != 'repository_grants'},
            'repository_grants': sorted(normalized, key=lambda r: r['repository_ref'])}


def _safe(text: Any) -> str:
    """Single-line Markdown-safe rendering, never HTML or executable markdown."""
    require(type(text) is str and len(text) <= 4096, 'RENDER_LABEL_INVALID')
    return re.sub(r'([\\`*{}\[\]#|<>])', r'\\\1',
                  text.replace('\n', ' ').replace('\r', ' '))


def _markdown(handoff: dict[str, Any], slot_key: str) -> tuple[str, list[dict[str, Any]]]:
    draft = handoff['handoff_draft']
    outline = draft['outline']
    period = outline['opening']['period']
    lines = [
        '# Internal periodic evidence report — review draft',
        '',
        '> INTERNAL ONLY · NOT PUBLISHED · Source, permissions and CI claims are unverified.',
        '> No employee performance assessment or verified delivery/CI result is expressed.',
        '',
        '## Scope and period',
        '',
        '- Report slot: `' + _safe(slot_key) + '`',
        '- Scope reference: `' + _safe(outline['opening']['scope_ref']) + '`',
        '- Period ID: `' + _safe(period['period_id']) + '`',
        '- UTC interval: `' + _safe(period['start_utc']) + '` to `' +
        _safe(period['end_exclusive_utc']) + '` (end exclusive)',
        '- Coverage and provenance: declarations only; missing evidence is not zero activity.',
        '',
    ]
    manifests = []
    for repo in outline['repository_sections']:
        rid = repo['repository_ref']
        lines.extend([
            '## Repository `' + _safe(rid) + '`',
            '',
            '- Report subject: `' + _safe(repo['report_subject_ref']) + '`',
            '- Source mode: `' + _safe(repo['source_mode']) + '`',
            '- Source binding SHA-256: `' + _safe(repo['source_binding_sha256']) + '`',
            '- People binding SHA-256: `' + _safe(repo['people_binding_sha256']) + '`',
            '- Source caveat: ' + _safe(repo['source_notice']),
            '- Window completeness (declared): `' +
            str(repo['period_window_complete_declared']).lower() + '`',
            '- Path scope: `' + _safe(repo['path_scope']) + '`',
            '- Inventory state: `' + _safe(repo['inventory_state']) + '`',
            '- Scope gaps: ' + (', '.join('`' + _safe(g) + '`'
                                         for g in repo['scope_gap_codes'])
                                 if repo['scope_gap_codes'] else 'none declared (not verified)'),
            '',
        ])
        for slot in repo['evidence_slots']:
            ch = slot['channel']
            require(ch in CHANNEL_LABELS, 'RENDER_CHANNEL_INVALID')
            lines.extend([
                '### ' + CHANNEL_LABELS[ch],
                '',
                _safe(slot['draft_note']),
                '',
                '- Coverage: `' + _safe(slot['coverage_state']) + '`',
                '- Release state: `' + _safe(slot['release_state']) + '`',
                '- CI completion: `' + _safe(slot['ci_completion_signal']) +
                '` (claim only, never authenticated PASS)',
                '- Claim state: `' + _safe(slot['evidence_claim_state']) + '`',
                '- Coverage reasons: ' +
                (', '.join('`' + _safe(g) + '`' for g in slot['coverage_reason_codes'])
                 if slot['coverage_reason_codes'] else 'none declared (not verified)'),
            ])
            cites = slot['citations']
            if cites:
                lines.append('- Released, unverified typed citations:')
                for citation in cites:
                    lines.append('  - `' + _safe(citation['citation_ref']) + '` · `' +
                                 _safe(citation['kind']) + '` · `' +
                                 _safe(citation['claim_state']) + '` · `' +
                                 _safe(citation['provenance_class']) + '`')
            else:
                lines.append('- No released citations (NOT proof of no activity).')
            lines.append('')
            manifests.append({
                'repository_ref': rid,
                'report_subject_ref': repo['report_subject_ref'],
                'source_mode': repo['source_mode'],
                'source_binding_sha256': repo['source_binding_sha256'],
                'people_binding_sha256': repo['people_binding_sha256'],
                'period_window_complete_declared':
                    repo['period_window_complete_declared'],
                'path_scope': repo['path_scope'],
                'inventory_state': repo['inventory_state'],
                'scope_gap_codes': list(repo['scope_gap_codes']),
                'channel': ch,
                'coverage_state': slot['coverage_state'],
                'coverage_reason_codes': list(slot['coverage_reason_codes']),
                'release_state': slot['release_state'],
                'ci_completion_signal': slot['ci_completion_signal'],
                'citation_refs': [c['citation_ref'] for c in cites],
            })
    lines.extend([
        '## Unresolved global gaps and editorial requirements',
        '',
        '- All cited references are declared, not authenticated.',
        '- ProposedPR is a proposal, NOT a delivered or merged change.',
        '- An unverified completed_pass_claim is NOT an executed, passing CI result.',
        '- Unknown, withheld, empty, partial and missing states must stay visible.',
        '- Do not assess, score or rank employees or infer effort from Git/event counts.',
        '- Source and privacy approval must be established separately before publication.',
        '',
        'Global gap codes:',
    ])
    for g in outline['closing']['global_gap_codes']:
        lines.append('- `' + _safe(g) + '`')
    lines.extend(['', '---', 'Unpublished internal evidence review · not ReportPublish', ''])
    result = '\n'.join(lines)
    require(byte_len(result) <= MAX_MARKDOWN, 'RENDER_DOCUMENT_TOO_LARGE')
    return result, manifests


def _compose(handoff: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    rendered, manifests = _markdown(handoff, policy['slot_key'])
    sections = handoff['handoff_draft']['outline']['repository_sections']
    slot_members = sorted([{
        'repository_ref': r['repository_ref'],
        'report_subject_ref': r['report_subject_ref'],
    } for r in sections], key=lambda v: v['repository_ref'])
    slot_ref = 'cesrslot1:' + digest('CES-EC199-REPORT-SLOT-v1', {
        'slot_key': policy['slot_key'],
        'period_id': handoff['source_pins']['period_id'],
        'members': slot_members,
    })
    record: dict[str, Any] = {
        'schema': DOCUMENT_SCHEMA,
        'document_state': 'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT',
        'trust_state': 'DECLARED_ONLY_NOT_AUTHENTICATED',
        'render_format': FORMAT,
        'report_slot_ref': slot_ref,
        'slot_key': policy['slot_key'],
        'period_id': handoff['source_pins']['period_id'],
        'slot_members': slot_members,
        'source_pins': copy.deepcopy(handoff['source_pins']),
        'handoff_draft_ref': handoff['draft_ref'],
        'handoff_binding_sha256': handoff['binding_sha256'],
        'render_policy_binding_sha256': digest('CES-EC199-RENDER-POLICY-v1', policy),
        'sections_manifest': manifests,
        'rendered_markdown': rendered,
        'rendered_sha256': _sha(rendered),
        'limitations': dict(LIMITATIONS),
    }
    record['report_ref'] = 'cesrr1:' + digest('CES-EC199-REPORT-REF-v1', record)
    record['binding_sha256'] = digest('CES-EC199-REPORT-RENDER-v1', record)
    bounded(record, MAX_RECORD, 'RENDER_RECORD_TOO_LARGE')
    return record


def _envelope() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'REPORT_RENDER_INPUT_INVALID', 'subject': None,
            'canonical_json': None, 'storage': None, 'limitations': dict(LIMITATIONS)}


def _fail(out: dict[str, Any], exc: RenderError) -> dict[str, Any]:
    out.update(status=exc.status, exit_code=5 if exc.status == 'unavailable' else 4,
               reason_code='REPORT_RENDER_' + exc.code,
               subject=None, canonical_json=None, storage=None)
    return out


def _write_all(fd: int, data: bytes) -> None:
    pos = 0
    while pos < len(data):
        wrote = os.write(fd, data[pos:])
        if wrote <= 0:
            raise OSError('short write')
        pos += wrote
    os.fsync(fd)


def _private_dir_fd(path: str) -> int:
    require(os.name == 'posix' and fcntl is not None and hasattr(os, 'O_NOFOLLOW') and
            hasattr(os, 'O_DIRECTORY') and hasattr(os, 'getuid'),
            'SECURE_LOCAL_SAVE_UNSUPPORTED', 'unavailable')
    require(type(path) is str and path.startswith('/') and
            len(path) <= 2048 and '\x00' not in path and
            path == os.path.normpath(path) and path != '/',
            'STORAGE_ROOT_INVALID')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for segment in path.split('/')[1:]:
            require(segment not in ('', '.', '..'),
                    'STORAGE_ROOT_INVALID')
            nxt = os.open(segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=fd)
            # A dedicated CES local store must not live in a Git/Mercurial/
            # Subversion checkout. Look for VCS markers at every ancestor,
            # including worktrees where .git is a *file*, not a directory.
            try:
                for marker in ('.git', '.hg', '.svn'):
                    try:
                        os.stat(marker, dir_fd=nxt, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise RenderError('STORAGE_INSIDE_SOURCE_REPOSITORY',
                                      'unavailable')
            except BaseException:
                os.close(nxt)
                raise
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                (stat.S_IMODE(info.st_mode) & 0o077) == 0,
                'STORAGE_ROOT_NOT_OWNER_PRIVATE', 'unavailable')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _store_fd(root_fd: int) -> int:
    try:
        os.mkdir(STORAGE_SUBDIRECTORY, mode=0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    except FileExistsError:
        pass
    fd = os.open(STORAGE_SUBDIRECTORY,
                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            (stat.S_IMODE(info.st_mode) & 0o077) == 0):
        os.close(fd)
        raise RenderError('STORAGE_AREA_NOT_OWNER_PRIVATE', 'unavailable')
    return fd


def _read(store_fd: int, filename: str, maximum: int) -> bytes | None:
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=store_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                (stat.S_IMODE(info.st_mode) & 0o077) == 0 and
                0 <= info.st_size <= maximum,
                'STORAGE_FILE_UNSAFE_OR_OVERSIZE', 'unavailable')
        result = bytearray()
        while len(result) <= maximum:
            data = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not data:
                break
            result.extend(data)
        require(len(result) <= maximum, 'STORAGE_FILE_UNSAFE_OR_OVERSIZE',
                'unavailable')
        return bytes(result)
    finally:
        os.close(fd)


def _immutable(store_fd: int, filename: str, data: bytes) -> None:
    try:
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=store_fd)
    except FileExistsError:
        old = _read(store_fd, filename, max(len(data), MAX_RECORD))
        require(old == data, 'IMMUTABLE_CONTENT_COLLISION', 'unavailable')
        return
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)
    os.fsync(store_fd)


def _atomic_index(store_fd: int, filename: str, data: bytes) -> None:
    temp = '.pending-' + secrets.token_hex(16)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=store_fd)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)
    try:
        os.replace(temp, filename, src_dir_fd=store_fd, dst_dir_fd=store_fd)
        os.fsync(store_fd)
    finally:
        try:
            os.unlink(temp, dir_fd=store_fd)
        except FileNotFoundError:
            pass


def _index_digest(row: dict[str, Any]) -> str:
    return digest('CES-EC199-INDEX-v1', row)


def _entry_digest(row: dict[str, Any]) -> str:
    return digest('CES-EC199-INDEX-ENTRY-v1', row)


def _new_index(record: dict[str, Any]) -> dict[str, Any]:
    return {
        'schema': INDEX_SCHEMA,
        'report_slot_ref': record['report_slot_ref'],
        'period_id': record['period_id'],
        'slot_members': copy.deepcopy(record['slot_members']),
        'versions': [],
    }


def _valid_index(store_fd: int, value: dict[str, Any],
                 record: dict[str, Any]) -> dict[str, Any]:
    try:
        fields(value, {'schema', 'report_slot_ref', 'period_id', 'slot_members',
                       'versions', 'binding_sha256'}, 'STORAGE_INDEX_FIELDS_INVALID')
    except RenderError as exc:
        raise RenderError(exc.code, 'unavailable') from exc
    require(value['schema'] == INDEX_SCHEMA and
            value['report_slot_ref'] == record['report_slot_ref'] and
            value['period_id'] == record['period_id'] and
            value['slot_members'] == record['slot_members'],
            'STORAGE_INDEX_SCOPE_MISMATCH', 'unavailable')
    require(valid_sha(value['binding_sha256']) and
            value['binding_sha256'] == _index_digest(
                {k: v for k, v in value.items() if k != 'binding_sha256'}),
            'STORAGE_INDEX_BINDING_INVALID', 'unavailable')
    versions = value['versions']
    require(type(versions) is list and len(versions) <= MAX_VERSIONS,
            'STORAGE_INDEX_VERSION_INVALID', 'unavailable')
    operations, reports = set(), set()
    previous = None
    for position, entry in enumerate(versions, 1):
        try:
            fields(entry, {
                'version', 'operation_id', 'report_ref', 'record_sha256',
                'rendered_sha256', 'handoff_draft_ref',
                'previous_entry_sha256', 'entry_sha256',
            }, 'STORAGE_ENTRY_FIELDS_INVALID')
        except RenderError as exc:
            raise RenderError(exc.code, 'unavailable') from exc
        require(type(entry['version']) is int and entry['version'] == position and
                type(entry['operation_id']) is str and
                TOKEN.fullmatch(entry['operation_id']) is not None and
                type(entry['report_ref']) is str and
                REPORT.fullmatch(entry['report_ref']) is not None and
                valid_sha(entry['record_sha256']) and
                valid_sha(entry['rendered_sha256']) and
                type(entry['handoff_draft_ref']) is str and
                re.fullmatch(r'cesrhd1:[0-9a-f]{64}', entry['handoff_draft_ref']) and
                entry['previous_entry_sha256'] == previous and
                valid_sha(entry['entry_sha256']) and
                entry['entry_sha256'] == _entry_digest({
                    k: v for k, v in entry.items() if k != 'entry_sha256'}),
                'STORAGE_ENTRY_CHAIN_INVALID', 'unavailable')
        require(entry['operation_id'] not in operations and
                entry['report_ref'] not in reports,
                'STORAGE_INDEX_DUPLICATE_VERSION', 'unavailable')
        operations.add(entry['operation_id'])
        reports.add(entry['report_ref'])
        # Verify immutable report bytes and its Markdown independently. A
        # plausible index digest by itself does not establish intact records.
        key = entry['report_ref'][7:]
        raw = _read(store_fd, 'report-' + key + '.json', MAX_RECORD)
        md = _read(store_fd, 'report-' + key + '.md', MAX_MARKDOWN)
        require(raw is not None and md is not None and
                hashlib.sha256(raw).hexdigest() == entry['record_sha256'] and
                hashlib.sha256(md).hexdigest() == entry['rendered_sha256'],
                'STORAGE_REFERENCED_CONTENT_MISSING_OR_CHANGED', 'unavailable')
        try:
            decoded = raw.decode('ascii')
            item = parse_json(decoded)
            markdown = md.decode('utf-8')
        except (UnicodeError, MetricsError) as exc:
            raise RenderError('STORAGE_RECORD_NONCANONICAL', 'unavailable') from exc
        require(item.get('report_ref') == entry['report_ref'] and
                item.get('rendered_sha256') == entry['rendered_sha256'] and
                item.get('handoff_draft_ref') == entry['handoff_draft_ref'] and
                item.get('report_slot_ref') == record['report_slot_ref'] and
                item.get('rendered_markdown') == markdown and
                item.get('binding_sha256') == digest(
                    'CES-EC199-REPORT-RENDER-v1',
                    {k: v for k, v in item.items() if k != 'binding_sha256'}) and
                item.get('report_ref') == 'cesrr1:' + digest(
                    'CES-EC199-REPORT-REF-v1',
                    {k: v for k, v in item.items()
                     if k not in ('report_ref', 'binding_sha256')}),
                'STORAGE_RECORD_BINDING_INVALID', 'unavailable')
        previous = entry['entry_sha256']
    return value


def _local_save(record: dict[str, Any], root: str,
                expected_previous_version: int, operation_id: str) -> dict[str, Any]:
    require(type(expected_previous_version) is int and
            0 <= expected_previous_version <= MAX_VERSIONS,
            'EXPECTED_PREVIOUS_VERSION_INVALID')
    require(type(operation_id) is str and TOKEN.fullmatch(operation_id) is not None,
            'SAVE_OPERATION_ID_INVALID')
    root_fd = _private_dir_fd(root)
    try:
        fd = _store_fd(root_fd)
        try:
            # Whole-index POSIX advisory lock. This excludes cooperating
            # writers; it is NOT protection from malicious concurrent changes.
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                index_name = 'index-' + record['report_slot_ref'][len('cesrslot1:'):] + '.json'
                old = _read(fd, index_name, MAX_INDEX)
                if old is None:
                    idx = _new_index(record)
                else:
                    try:
                        idx = _valid_index(fd, parse_json(old.decode('ascii')), record)
                    except (UnicodeError, MetricsError) as exc:
                        raise RenderError('STORAGE_INDEX_NONCANONICAL',
                                          'unavailable') from exc
                for entry in idx['versions']:
                    if entry['operation_id'] == operation_id:
                        require(entry['report_ref'] == record['report_ref'],
                                'SAVE_OPERATION_CONFLICT', 'unavailable')
                        return _storage_receipt(record, idx, entry, 'REPLAY_ALREADY_SAVED')
                    if entry['report_ref'] == record['report_ref']:
                        return _storage_receipt(record, idx, entry, 'IDENTICAL_RENDER_EXISTS')
                require(len(idx['versions']) == expected_previous_version,
                        'STALE_INDEX_EXPECTED_VERSION_CONFLICT', 'unavailable')
                require(len(idx['versions']) < MAX_VERSIONS,
                        'SLOT_VERSION_LIMIT_REACHED', 'unavailable')
                record_bytes = canonical(record).encode('ascii')
                md_bytes = record['rendered_markdown'].encode('utf-8')
                stem = 'report-' + record['report_ref'][7:]
                _immutable(fd, stem + '.json', record_bytes)
                _immutable(fd, stem + '.md', md_bytes)
                prior = idx['versions'][-1]['entry_sha256'] if idx['versions'] else None
                entry = {
                    'version': len(idx['versions']) + 1,
                    'operation_id': operation_id,
                    'report_ref': record['report_ref'],
                    'record_sha256': hashlib.sha256(record_bytes).hexdigest(),
                    'rendered_sha256': record['rendered_sha256'],
                    'handoff_draft_ref': record['handoff_draft_ref'],
                    'previous_entry_sha256': prior,
                }
                entry['entry_sha256'] = _entry_digest(entry)
                idx['versions'].append(entry)
                idx.pop('binding_sha256', None)
                idx['binding_sha256'] = _index_digest(idx)
                payload = canonical(idx).encode('ascii')
                require(len(payload) <= MAX_INDEX, 'SLOT_INDEX_TOO_LARGE',
                        'unavailable')
                _atomic_index(fd, index_name, payload)
                return _storage_receipt(record, idx, entry, 'SAVED_NEW_VERSION')
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def _storage_receipt(record: dict[str, Any], index: dict[str, Any],
                     entry: dict[str, Any], state: str) -> dict[str, Any]:
    return {
        'state': state,
        'durability': 'LOCAL_POSIX_ATOMIC_INDEX_ADVISORY_LOCK_NOT_AUTHENTICATED',
        'report_slot_ref': record['report_slot_ref'],
        'report_ref': record['report_ref'],
        'version': entry['version'],
        'version_count': len(index['versions']),
        'index_binding_sha256': index['binding_sha256'],
        'entry_sha256': entry['entry_sha256'],
        'report_record_sha256': entry['record_sha256'],
        'rendered_sha256': entry['rendered_sha256'],
        'publication_state': 'NOT_PUBLISHED',
    }


class ReportRender:
    """EC199: replay-validated template renderer and separate opt-in local save."""

    def render(self, *, handoff_json: str, prepare_json: str, scope_json: str,
               metrics_json: str, release_policy: dict[str, Any],
               review_policy: dict[str, Any], render_policy: dict[str, Any],
               people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = _envelope()
        try:
            handoff = _replayed_handoff(
                handoff_json=handoff_json, prepare_json=prepare_json,
                scope_json=scope_json, metrics_json=metrics_json,
                release_policy=release_policy, review_policy=review_policy,
                people_subject_witnesses=people_subject_witnesses)
            p = _render_policy(render_policy, handoff, release_policy, review_policy)
            record = _compose(handoff, p)
            out.update(status='partial', exit_code=2,
                       reason_code='REPORT_RENDER_UNPUBLISHED_INTERNAL_DRAFT',
                       subject=record, canonical_json=canonical(record))
        except (MetricsError, HandoffDraftError) as exc:
            status = getattr(exc, 'status', 'invalid_input')
            return _fail(out, RenderError('UPSTREAM_INVALID', status))
        except RenderError as exc:
            return _fail(out, exc)
        return out

    def from_json(self, *, serialized: str, handoff_json: str, prepare_json: str,
                  scope_json: str, metrics_json: str, release_policy: dict[str, Any],
                  review_policy: dict[str, Any], render_policy: dict[str, Any],
                  people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = _envelope()
        try:
            original = parse_json(_exact_text(serialized, MAX_RECORD,
                                             'REPLAY_SIZE_INVALID'))
            fields(original, {
                'schema', 'document_state', 'trust_state', 'render_format',
                'report_slot_ref', 'slot_key', 'period_id', 'slot_members',
                'source_pins', 'handoff_draft_ref', 'handoff_binding_sha256',
                'render_policy_binding_sha256', 'sections_manifest',
                'rendered_markdown', 'rendered_sha256', 'limitations',
                'report_ref', 'binding_sha256',
            }, 'REPLAY_FIELDS_INVALID')
            built = self.render(
                handoff_json=handoff_json, prepare_json=prepare_json,
                scope_json=scope_json, metrics_json=metrics_json,
                release_policy=release_policy, review_policy=review_policy,
                render_policy=render_policy,
                people_subject_witnesses=people_subject_witnesses)
            require(built['status'] == 'partial',
                    'REPLAY_UPSTREAM_REFUSED',
                    'unavailable' if built['status'] == 'unavailable' else 'invalid_input')
            require(built['canonical_json'] == serialized,
                    'REPLAY_CONTENT_SOURCE_OR_POLICY_MISMATCH')
            out.update(status='partial', exit_code=2,
                       reason_code='REPORT_RENDER_REPLAYED_ORIGINAL_SOURCES',
                       subject=built['subject'], canonical_json=serialized)
        except (MetricsError, HandoffDraftError) as exc:
            return _fail(out, RenderError('REPLAY_UPSTREAM_INVALID',
                                          getattr(exc, 'status', 'invalid_input')))
        except RenderError as exc:
            return _fail(out, exc)
        return out

    def save(self, *, storage_root: str, expected_previous_version: int,
             operation_id: str, handoff_json: str, prepare_json: str,
             scope_json: str, metrics_json: str, release_policy: dict[str, Any],
             review_policy: dict[str, Any], render_policy: dict[str, Any],
             people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = self.render(
            handoff_json=handoff_json, prepare_json=prepare_json,
            scope_json=scope_json, metrics_json=metrics_json,
            release_policy=release_policy, review_policy=review_policy,
            render_policy=render_policy,
            people_subject_witnesses=people_subject_witnesses)
        if out['status'] != 'partial':
            return out
        try:
            # No derived record can override this explicit extra opt-in.
            p = _render_policy(render_policy, _replayed_handoff(
                handoff_json=handoff_json, prepare_json=prepare_json,
                scope_json=scope_json, metrics_json=metrics_json,
                release_policy=release_policy, review_policy=review_policy,
                people_subject_witnesses=people_subject_witnesses),
                release_policy, review_policy)
            require(p['permit_local_save'] and
                    all(g['permit_local_save'] for g in p['repository_grants']),
                    'LOCAL_SAVE_NOT_PERMITTED', 'unavailable')
            receipt = _local_save(out['subject'], storage_root,
                                  expected_previous_version, operation_id)
            out.update(reason_code='REPORT_RENDER_LOCAL_SAVED_NOT_PUBLISHED',
                       storage=receipt)
        except (MetricsError, HandoffDraftError) as exc:
            return _fail(out, RenderError('SAVE_UPSTREAM_INVALID',
                                          getattr(exc, 'status', 'invalid_input')))
        except RenderError as exc:
            return _fail(out, exc)
        except (OSError, OverflowError, UnicodeError) as exc:
            # Hide caller's local path and host OSError details from public result.
            return _fail(out, RenderError('LOCAL_STORAGE_IO_UNAVAILABLE',
                                          'unavailable'))
        return out

#!/usr/bin/env python3
"""EC200: private, read-only ReportShow and append-only corrected report versions.

This is not a trusted identity/approval verifier or ReportPublish. Read grants
are independent operator declarations; the POSIX directory owner and a bound
store (device/inode) limit accidental cross-store reads, not malicious owners.
The only correction writer delegates to EC199 ReportRender.save after replay.
"""
from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - fail closed on unsupported hosts
    fcntl = None

from report_evidence_metrics import MetricsError, byte_len, canonical, digest, parse_json, valid_sha
from report_render import (
    AUDIENCE, CHANNEL_ORDER, DOCUMENT_SCHEMA, FORMAT, INDEX_SCHEMA, KEY,
    LIMITATIONS, MAX_INDEX, MAX_MARKDOWN, MAX_RECORD, MAX_VERSIONS,
    REPORT, SLOT, STORAGE_SUBDIRECTORY, TOKEN, RenderError, ReportRender,
    _private_dir_fd, _read, _valid_index, fields, require,
)

SCHEMA = 'ces.report_history.v1'
READ_POLICY_SCHEMA = 'ces.report_history_read_policy.v1'
CORRECTION_POLICY_SCHEMA = 'ces.report_history_correction_policy.v1'
READ_PURPOSE = 'periodic_report_internal_history_read_only'
CORRECTION_PURPOSE = 'periodic_report_internal_correction_append_only'
MAX_POLICY = 262144
MAX_HISTORY = 2097152
MAX_REF_DIFF = 32
CATEGORIES = ('source', 'scope', 'permission', 'citation', 'coverage')
REPO = re.compile(r'cesrepo1:[0-9a-f]{64}\Z', re.ASCII)
SUBJECT = re.compile(r'cesrs1:[0-9a-f]{64}\Z', re.ASCII)
CITATION = re.compile(r'cesrc1:[0-9a-f]{64}\Z', re.ASCII)
RECEIPTS_NOTICE = (
    'Read/correction policies and SHA receipts are declared, not externally authenticated. '
    'Filesystem ownership/inode checks are not identity or business authorization.'
)
HISTORY_LIMITATIONS = {
    **LIMITATIONS,
    'historical_store_identity_cryptographically_authenticated': False,
    'correction_grants_and_reasons_externally_authenticated': False,
    'historic_render_permission_values_available': False,
    'correction_intent_persisted_in_ec199_index': False,
    'power_shell_report_show_registered': False,
}
RECORD_KEYS = {
    'schema', 'document_state', 'trust_state', 'render_format', 'report_slot_ref',
    'slot_key', 'period_id', 'slot_members', 'source_pins', 'handoff_draft_ref',
    'handoff_binding_sha256', 'render_policy_binding_sha256',
    'sections_manifest', 'rendered_markdown', 'rendered_sha256', 'limitations',
    'report_ref', 'binding_sha256',
}
MANIFEST_KEYS = {
    'repository_ref', 'report_subject_ref', 'source_mode',
    'source_binding_sha256', 'people_binding_sha256',
    'period_window_complete_declared', 'path_scope', 'inventory_state',
    'scope_gap_codes', 'channel', 'coverage_state', 'coverage_reason_codes',
    'release_state', 'ci_completion_signal', 'citation_refs',
}
PIN_KEYS = {
    'prepare_binding_sha256', 'prepare_canonical_sha256', 'ai_input_sha256',
    'scope_binding_sha256', 'metrics_binding_sha256',
    'release_policy_binding_sha256', 'scope_ref', 'period_id',
}


def _fail(out: dict[str, Any], code: str, status: str = 'unavailable') -> dict[str, Any]:
    # A failed post-commit display must not hide that a save already returned.
    # This receipt is still untrusted local evidence, not publication proof.
    committed = out.get('correction_storage')
    out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
               reason_code='REPORT_HISTORY_' + code, subject=None,
               canonical_json=None, correction_storage=committed)
    return out


def _base() -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
        'reason_code': 'REPORT_HISTORY_INVALID_INPUT', 'subject': None,
        'canonical_json': None, 'correction_storage': None,
        'limitations': dict(HISTORY_LIMITATIONS),
    }


def _check(condition: bool, code: str, status: str = 'invalid_input') -> None:
    require(condition, code, status)


def _members(value: Any) -> list[dict[str, str]]:
    _check(type(value) is list and 1 <= len(value) <= 32, 'MEMBERS_INVALID')
    selected = []
    for row in value:
        fields(row, {'repository_ref', 'report_subject_ref'}, 'MEMBERS_INVALID')
        _check(type(row['repository_ref']) is str and REPO.fullmatch(row['repository_ref']) is not None and
               type(row['report_subject_ref']) is str and SUBJECT.fullmatch(row['report_subject_ref']) is not None,
               'MEMBERS_INVALID')
        selected.append({'repository_ref': row['repository_ref'],
                         'report_subject_ref': row['report_subject_ref']})
    _check(selected == sorted(selected, key=lambda r: r['repository_ref']) and
           len({v['repository_ref'] for v in selected}) == len(selected) and
           len({v['report_subject_ref'] for v in selected}) == len(selected), 'MEMBERS_NOT_UNIQUE_SORTED')
    return selected


def _selector(slot_key: Any, period_id: Any, slot_members: Any) -> dict[str, Any]:
    _check(type(slot_key) is str and KEY.fullmatch(slot_key) is not None,
           'SLOT_KEY_INVALID')
    _check(type(period_id) is str and 1 <= len(period_id) <= 256 and
           '\x00' not in period_id and period_id.strip() == period_id,
           'PERIOD_ID_INVALID')
    members = _members(slot_members)
    slot = 'cesrslot1:' + digest('CES-EC199-REPORT-SLOT-v1', {
        'slot_key': slot_key, 'period_id': period_id, 'members': members,
    })
    return {'slot_key': slot_key, 'period_id': period_id,
            'slot_members': members, 'report_slot_ref': slot}


def _existing_store(root: int) -> int:
    _check(os.name == 'posix' and fcntl is not None and
           hasattr(os, 'O_DIRECTORY') and hasattr(os, 'O_NOFOLLOW'),
           'READ_ONLY_STORE_UNSUPPORTED', 'unavailable')
    fd = os.open(STORAGE_SUBDIRECTORY,
                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) & 0o077 == 0):
        os.close(fd)
        raise RenderError('STORAGE_AREA_NOT_OWNER_PRIVATE', 'unavailable')
    return fd


def _store_binding(root_fd: int, store_fd: int) -> str:
    a, b = os.fstat(root_fd), os.fstat(store_fd)
    return digest('CES-EC200-PRIVATE-STORE-IDENTITY-v1', {
        'root_device': a.st_dev, 'root_inode': a.st_ino, 'root_uid': a.st_uid,
        'store_device': b.st_dev, 'store_inode': b.st_ino, 'store_uid': b.st_uid,
    })


def local_store_binding(storage_root: str) -> str:
    """Identify an existing owner-private EC199 store; never creates a directory.

    Caller must pin this result via a *trusted* host-side authorization flow;
    it is a directory identity check, NOT an authorization token or signature.
    """
    r = _private_dir_fd(storage_root)
    try:
        s = _existing_store(r)
        try:
            return _store_binding(r, s)
        finally:
            os.close(s)
    finally:
        os.close(r)


def _policy(value: Any, selector: dict[str, Any], binding: str,
            *, correction: bool = False) -> dict[str, Any]:
    _check(type(value) is dict, 'CORRECTION_POLICY_REQUIRED' if correction else
           'READ_POLICY_REQUIRED', 'unavailable')
    _check(byte_len(canonical(value)) <= MAX_POLICY, 'POLICY_TOO_LARGE')
    shared = {
        'schema', 'purpose', 'audience', 'report_slot_ref', 'slot_key',
        'period_id', 'slot_members', 'store_binding_sha256',
        'policy_receipt_sha256', 'repository_grants',
    }
    unique = ({'permit_append_correction', 'expected_previous_version',
               'previous_report_ref', 'previous_entry_sha256', 'operation_id',
               'correction_categories'} if correction else
              {'permit_history_read', 'permit_rendered_markdown'})
    p = fields(value, shared | unique, 'POLICY_FIELDS_INVALID')
    _check(p['schema'] == (CORRECTION_POLICY_SCHEMA if correction else READ_POLICY_SCHEMA) and
           p['purpose'] == (CORRECTION_PURPOSE if correction else READ_PURPOSE) and
           p['audience'] == AUDIENCE,
           'POLICY_PURPOSE_INVALID', 'unavailable')
    for key in ('report_slot_ref', 'slot_key', 'period_id', 'slot_members'):
        _check(p[key] == selector[key], 'POLICY_SUBJECT_PERIOD_MISMATCH', 'unavailable')
    _check(type(p['store_binding_sha256']) is str and
           p['store_binding_sha256'] == binding and valid_sha(binding),
           'POLICY_STORE_BINDING_MISMATCH', 'unavailable')
    _check(valid_sha(p['policy_receipt_sha256']), 'POLICY_RECEIPT_INVALID', 'unavailable')
    if correction:
        _check(type(p['permit_append_correction']) is bool and
               p['permit_append_correction'], 'CORRECTION_NOT_PERMITTED', 'unavailable')
        _check(type(p['expected_previous_version']) is int and
               1 <= p['expected_previous_version'] < MAX_VERSIONS and
               type(p['previous_report_ref']) is str and
               REPORT.fullmatch(p['previous_report_ref']) is not None and
               valid_sha(p['previous_entry_sha256']) and
               type(p['operation_id']) is str and
               TOKEN.fullmatch(p['operation_id']) is not None,
               'CORRECTION_BASE_INVALID')
        cats = p['correction_categories']
        _check(type(cats) is list and 1 <= len(cats) <= len(CATEGORIES) and
               all(type(c) is str and c in CATEGORIES for c in cats) and
               cats == sorted(set(cats)), 'CORRECTION_CATEGORIES_INVALID')
    else:
        _check(type(p['permit_history_read']) is bool and p['permit_history_read'] and
               type(p['permit_rendered_markdown']) is bool,
               'READ_NOT_PERMITTED', 'unavailable')
    required = {'repository_ref', 'report_subject_ref',
                'correction_receipt_sha256' if correction else 'read_receipt_sha256',
                'permit_append_correction' if correction else 'permit_history_read'}
    if not correction:
        required.add('permit_rendered_markdown')
    grants = p['repository_grants']
    _check(type(grants) is list and len(grants) == len(selector['slot_members']),
           'REPOSITORY_GRANTS_INCOMPLETE', 'unavailable')
    permits = {r['repository_ref']: r['report_subject_ref']
               for r in selector['slot_members']}
    seen = set()
    receipts = {p['policy_receipt_sha256']}
    for g in grants:
        fields(g, required, 'REPOSITORY_GRANT_FIELDS_INVALID')
        rid = g['repository_ref']
        _check(type(rid) is str and rid in permits and rid not in seen and
               g['report_subject_ref'] == permits[rid],
               'REPOSITORY_GRANTS_INCOMPLETE', 'unavailable')
        seen.add(rid)
        option = 'permit_append_correction' if correction else 'permit_history_read'
        _check(type(g[option]) is bool and g[option],
               'REPOSITORY_GRANT_DENIED', 'unavailable')
        if not correction:
            _check(type(g['permit_rendered_markdown']) is bool and
                   (not g['permit_rendered_markdown'] or p['permit_rendered_markdown']),
                   'MARKDOWN_SCOPE_INVALID', 'unavailable')
        receipt = g['correction_receipt_sha256' if correction else 'read_receipt_sha256']
        _check(valid_sha(receipt) and receipt not in receipts,
               'REPOSITORY_RECEIPTS_NOT_INDEPENDENT', 'unavailable')
        receipts.add(receipt)
    return p


def _record(value: Any, selector: dict[str, Any]) -> dict[str, Any]:
    r = fields(value, RECORD_KEYS, 'STORAGE_RECORD_FIELDS_INVALID')
    _check(r['schema'] == DOCUMENT_SCHEMA and
           r['document_state'] == 'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT' and
           r['trust_state'] == 'DECLARED_ONLY_NOT_AUTHENTICATED' and
           r['render_format'] == FORMAT and r['limitations'] == LIMITATIONS,
           'STORAGE_RECORD_TRUST_STATE_INVALID', 'unavailable')
    for key in selector:
        _check(r[key] == selector[key], 'STORAGE_RECORD_SLOT_MISMATCH', 'unavailable')
    _check(type(r['source_pins']) is dict and set(r['source_pins']) == PIN_KEYS and
           r['source_pins']['period_id'] == selector['period_id'] and
           type(r['source_pins']['scope_ref']) is str and
           len(r['source_pins']['scope_ref']) <= 256 and
           all(valid_sha(r['source_pins'][k]) for k in PIN_KEYS - {'scope_ref', 'period_id'}),
           'STORAGE_RECORD_PINS_INVALID', 'unavailable')
    _check(valid_sha(r['handoff_binding_sha256']) and
           valid_sha(r['render_policy_binding_sha256']) and
           valid_sha(r['binding_sha256']) and valid_sha(r['rendered_sha256']) and
           type(r['rendered_markdown']) is str and 0 < byte_len(r['rendered_markdown']) <= MAX_MARKDOWN and
           hashlib.sha256(r['rendered_markdown'].encode('utf-8')).hexdigest() == r['rendered_sha256'],
           'STORAGE_RECORD_RENDER_INVALID', 'unavailable')
    members = {m['repository_ref']: m['report_subject_ref'] for m in selector['slot_members']}
    sections = r['sections_manifest']
    _check(type(sections) is list and len(sections) == len(members) * len(CHANNEL_ORDER),
           'STORAGE_MANIFEST_INCOMPLETE', 'unavailable')
    seen = set()
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for row in sections:
        fields(row, MANIFEST_KEYS, 'STORAGE_MANIFEST_FIELDS_INVALID')
        rid, ch = row['repository_ref'], row['channel']
        _check(type(rid) is str and rid in members and
               row['report_subject_ref'] == members[rid] and
               type(ch) is str and ch in CHANNEL_ORDER and (rid, ch) not in seen,
               'STORAGE_MANIFEST_LINKAGE_INVALID', 'unavailable')
        seen.add((rid, ch))
        _check(row['source_mode'] in ('WorkingTree', 'DeliveredTarget', 'ProposedPR') and
               valid_sha(row['source_binding_sha256']) and
               valid_sha(row['people_binding_sha256']) and
               type(row['period_window_complete_declared']) is bool and
               type(row['path_scope']) is str and 0 < len(row['path_scope']) <= 128 and
               type(row['inventory_state']) is str and 0 < len(row['inventory_state']) <= 128 and
               all(type(row[k]) is str and 0 < len(row[k]) <= 128 for k in
                   ('coverage_state', 'release_state', 'ci_completion_signal')),
               'STORAGE_MANIFEST_VALUES_INVALID', 'unavailable')
        for field in ('scope_gap_codes', 'coverage_reason_codes'):
            x = row[field]
            _check(type(x) is list and len(x) <= 64 and
                   len(x) == len(set(x)) and all(type(v) is str and 0 < len(v) <= 128 for v in x),
                   'STORAGE_MANIFEST_GAPS_INVALID', 'unavailable')
        refs = row['citation_refs']
        _check(type(refs) is list and len(refs) <= 512 and
               all(type(c) is str and CITATION.fullmatch(c) is not None for c in refs) and
               len(set(refs)) == len(refs), 'STORAGE_CITATION_SET_INVALID', 'unavailable')
        by_repo.setdefault(rid, []).append(row)
    for rows in by_repo.values():
        for key in ('report_subject_ref', 'source_mode', 'source_binding_sha256',
                    'people_binding_sha256', 'period_window_complete_declared',
                    'path_scope', 'inventory_state', 'scope_gap_codes'):
            _check(all(x[key] == rows[0][key] for x in rows),
                   'STORAGE_MANIFEST_CROSS_CHANNEL_MISMATCH', 'unavailable')
    return r


def _load(storage_root: str, selector: dict[str, Any], policy: dict[str, Any],
          *, correction: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root = _private_dir_fd(storage_root)
    try:
        store = _existing_store(root)  # NO mkdir, chmod, temp files or lock-file writes
        try:
            _policy(policy, selector, _store_binding(root, store), correction=correction)
            fcntl.flock(store, fcntl.LOCK_SH)
            try:
                index_name = 'index-' + selector['report_slot_ref'][len('cesrslot1:'):] + '.json'
                raw = _read(store, index_name, MAX_INDEX)
                _check(raw is not None, 'REPORT_SLOT_NOT_FOUND', 'unavailable')
                try:
                    idx = parse_json(raw.decode('ascii'))
                except (MetricsError, UnicodeError, ValueError) as exc:
                    raise RenderError('STORAGE_INDEX_NONCANONICAL', 'unavailable') from exc
                _check(raw == canonical(idx).encode('ascii'), 'STORAGE_INDEX_NONCANONICAL', 'unavailable')
                idx = _valid_index(store, idx, selector)
                _check(len(idx['versions']) > 0, 'STORAGE_EMPTY_INDEX', 'unavailable')
                records = []
                for entry in idx['versions']:
                    key = entry['report_ref'][len('cesrr1:'):]
                    report_bytes = _read(store, 'report-' + key + '.json', MAX_RECORD)
                    _check(report_bytes is not None, 'STORAGE_RECORD_NOT_FOUND', 'unavailable')
                    try:
                        record = parse_json(report_bytes.decode('ascii'))
                    except (MetricsError, UnicodeError, ValueError) as exc:
                        raise RenderError('STORAGE_RECORD_NONCANONICAL', 'unavailable') from exc
                    _check(report_bytes == canonical(record).encode('ascii'),
                           'STORAGE_RECORD_NONCANONICAL', 'unavailable')
                    try:
                        _record(record, selector)
                    except RenderError as exc:
                        raise RenderError(exc.code, 'unavailable') from exc
                    _check(entry['report_ref'] == record['report_ref'] and
                           entry['record_sha256'] == hashlib.sha256(report_bytes).hexdigest() and
                           entry['rendered_sha256'] == record['rendered_sha256'] and
                           entry['handoff_draft_ref'] == record['handoff_draft_ref'],
                           'STORAGE_INDEX_RECORD_LINKAGE_INVALID', 'unavailable')
                    records.append(record)
                return idx, records
            finally:
                fcntl.flock(store, fcntl.LOCK_UN)
        finally:
            os.close(store)
    finally:
        os.close(root)


def _grouped(record: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for slot in record['sections_manifest']:
        result.setdefault(slot['repository_ref'], {})[slot['channel']] = slot
    return result


def _comparison(before: dict[str, Any], after: dict[str, Any],
                before_version: int, after_version: int) -> dict[str, Any]:
    """Typed, bounded diff of persisted declarations, never an inferred fact."""
    changes: dict[str, list[dict[str, Any]]] = {name: [] for name in CATEGORIES}

    def add(cat: str, field: str, prev: Any, now: Any,
            repo: str | None = None, channel: str | None = None) -> None:
        if prev != now:
            changes[cat].append({'repository_ref': repo, 'channel': channel,
                                 'field': field, 'before': copy.deepcopy(prev),
                                 'after': copy.deepcopy(now)})

    for name in ('prepare_binding_sha256', 'prepare_canonical_sha256',
                 'ai_input_sha256', 'scope_binding_sha256',
                 'metrics_binding_sha256'):
        add('source', 'source_pins.' + name,
            before['source_pins'][name], after['source_pins'][name])
    for name in ('handoff_draft_ref', 'handoff_binding_sha256'):
        add('source', name, before[name], after[name])
    for name in ('slot_key', 'period_id', 'slot_members'):
        add('scope', name, before[name], after[name])
    add('scope', 'source_pins.scope_ref', before['source_pins']['scope_ref'],
        after['source_pins']['scope_ref'])
    add('permission', 'source_pins.release_policy_binding_sha256',
        before['source_pins']['release_policy_binding_sha256'],
        after['source_pins']['release_policy_binding_sha256'])
    add('permission', 'render_policy_binding_sha256',
        before['render_policy_binding_sha256'], after['render_policy_binding_sha256'])
    before_map, after_map = _grouped(before), _grouped(after)
    for repo in sorted(set(before_map) | set(after_map)):
        a_slots = before_map.get(repo, {})
        b_slots = after_map.get(repo, {})
        base_a, base_b = (next(iter(a_slots.values()), {}), next(iter(b_slots.values()), {}))
        for field in ('report_subject_ref', 'source_mode', 'source_binding_sha256',
                      'people_binding_sha256'):
            add('source', field, base_a.get(field), base_b.get(field), repo)
        for field in ('path_scope', 'inventory_state', 'scope_gap_codes'):
            add('scope', field, base_a.get(field), base_b.get(field), repo)
        add('coverage', 'period_window_complete_declared',
            base_a.get('period_window_complete_declared'),
            base_b.get('period_window_complete_declared'), repo)
        for ch in CHANNEL_ORDER:
            a, b = a_slots.get(ch, {}), b_slots.get(ch, {})
            add('permission', 'release_state', a.get('release_state'),
                b.get('release_state'), repo, ch)
            for field in ('coverage_state', 'coverage_reason_codes', 'ci_completion_signal'):
                add('coverage', field, a.get(field), b.get(field), repo, ch)
            prev_refs = set(a.get('citation_refs', []))
            now_refs = set(b.get('citation_refs', []))
            added, removed = sorted(now_refs - prev_refs), sorted(prev_refs - now_refs)
            if added or removed:
                changes['citation'].append({
                    'repository_ref': repo, 'channel': ch,
                    'field': 'citation_refs',
                    'before_count': len(prev_refs), 'after_count': len(now_refs),
                    'added_count': len(added), 'removed_count': len(removed),
                    'added_refs': added[:MAX_REF_DIFF],
                    'removed_refs': removed[:MAX_REF_DIFF],
                    'added_omitted_count': max(0, len(added) - MAX_REF_DIFF),
                    'removed_omitted_count': max(0, len(removed) - MAX_REF_DIFF),
                    'before_set_sha256': digest('CES-EC200-CITATIONS-v1', sorted(prev_refs)),
                    'after_set_sha256': digest('CES-EC200-CITATIONS-v1', sorted(now_refs)),
                })
    return {
        'before_version': before_version, 'after_version': after_version,
        'before_report_ref': before['report_ref'], 'after_report_ref': after['report_ref'],
        'changed_categories': [cat for cat in CATEGORIES if changes[cat]],
        'changes': changes,
        'permission_interpretation': 'HASH_AND_RELEASE_STATES_ONLY_UNVERIFIED_NO_HISTORIC_GRANT_VALUES',
        'citation_diff_limit_per_channel': MAX_REF_DIFF,
    }


def _projection(idx: dict[str, Any], records: list[dict[str, Any]],
                selected: int, comparison_version: int | None,
                markdown: bool) -> dict[str, Any]:
    entry, doc = idx['versions'][selected - 1], records[selected - 1]
    history = []
    for i, (row, r) in enumerate(zip(idx['versions'], records), 1):
        history.append({
            'version': i, 'report_ref': row['report_ref'],
            'entry_sha256': row['entry_sha256'],
            'record_sha256': row['record_sha256'],
            'rendered_sha256': row['rendered_sha256'],
            'handoff_draft_ref': row['handoff_draft_ref'],
            'render_policy_binding_sha256': r['render_policy_binding_sha256'],
            'version_intent': 'INITIAL_REPORT' if i == 1 else 'NOT_RECORDED_IN_EC199_INDEX',
        })
    sections = _grouped(doc)
    repositories = []
    for member in doc['slot_members']:
        rid = member['repository_ref']
        channels = sections[rid]
        representative = next(iter(channels.values()))
        repositories.append({
            'repository_ref': rid, 'report_subject_ref': member['report_subject_ref'],
            'source_mode': representative['source_mode'],
            'source_binding_sha256': representative['source_binding_sha256'],
            'people_binding_sha256': representative['people_binding_sha256'],
            'path_scope': representative['path_scope'],
            'inventory_state': representative['inventory_state'],
            'scope_gap_codes': copy.deepcopy(representative['scope_gap_codes']),
            'period_window_complete_declared': representative['period_window_complete_declared'],
            'channels': [{
                'channel': ch, 'coverage_state': channels[ch]['coverage_state'],
                'coverage_reason_codes': copy.deepcopy(channels[ch]['coverage_reason_codes']),
                'release_state': channels[ch]['release_state'],
                'ci_completion_signal': channels[ch]['ci_completion_signal'],
                'citation_count': len(channels[ch]['citation_refs']),
                'citation_refs': copy.deepcopy(channels[ch]['citation_refs']),
            } for ch in CHANNEL_ORDER],
        })
    compared = (_comparison(records[comparison_version - 1], doc,
                            comparison_version, selected)
                if comparison_version is not None else None)
    return {
        'report_slot_ref': idx['report_slot_ref'],
        'slot_key': doc['slot_key'], 'period_id': idx['period_id'],
        'slot_members': copy.deepcopy(idx['slot_members']),
        'selected_version': selected, 'latest_version': len(records),
        'selected_report_ref': doc['report_ref'],
        'selected_entry_sha256': entry['entry_sha256'],
        'index_binding_sha256': idx['binding_sha256'],
        'record_sha256': entry['record_sha256'],
        'rendered_sha256': entry['rendered_sha256'],
        'document_state': doc['document_state'], 'trust_state': doc['trust_state'],
        'publication_state': 'NOT_PUBLISHED',
        'source_pins': copy.deepcopy(doc['source_pins']),
        'render_policy_binding_sha256': doc['render_policy_binding_sha256'],
        'repositories': repositories,
        'history': history, 'comparison': compared,
        'rendered_markdown': doc['rendered_markdown'] if markdown else None,
        'store_read_state': 'PRIVATE_LOCAL_STORE_BYTES_VERIFIED_NOT_EXTERNAL_AUTHENTICATION',
        'policy_notice': RECEIPTS_NOTICE,
        'limitations': dict(HISTORY_LIMITATIONS),
    }


class ReportHistory:
    """EC200: safe historical display; correction only via EC199 append/CAS."""

    def show(self, *, storage_root: str, slot_key: str, period_id: str,
             slot_members: list[dict[str, str]], read_policy: dict[str, Any],
             version: int | None = None, compare_to_version: int | None = None,
             include_markdown: bool = False) -> dict[str, Any]:
        out = _base()
        try:
            selector = _selector(slot_key, period_id, slot_members)
            _check(version is None or (type(version) is int and 1 <= version <= MAX_VERSIONS),
                   'VERSION_INVALID')
            _check(compare_to_version is None or
                   (type(compare_to_version) is int and 1 <= compare_to_version <= MAX_VERSIONS),
                   'COMPARE_VERSION_INVALID')
            _check(type(include_markdown) is bool, 'MARKDOWN_REQUEST_INVALID')
            idx, docs = _load(storage_root, selector, read_policy)
            if include_markdown:
                _check(read_policy['permit_rendered_markdown'] and
                       all(g['permit_rendered_markdown'] for g in read_policy['repository_grants']),
                       'MARKDOWN_NOT_PERMITTED', 'unavailable')
            selected = version if version is not None else len(docs)
            _check(selected <= len(docs), 'VERSION_NOT_FOUND', 'unavailable')
            target = (compare_to_version if compare_to_version is not None else
                      (selected - 1 if selected > 1 else None))
            _check(target is None or target <= len(docs) and target != selected,
                   'COMPARE_VERSION_NOT_FOUND', 'unavailable')
            result = _projection(idx, docs, selected, target, include_markdown)
            payload = canonical(result)
            _check(byte_len(payload) <= MAX_HISTORY, 'RESPONSE_TOO_LARGE', 'unavailable')
            out.update(status='partial', exit_code=2,
                       reason_code='REPORT_HISTORY_READ_ONLY_NOT_PUBLISHED',
                       subject=result, canonical_json=payload)
        except RenderError as exc:
            return _fail(out, exc.code, exc.status)
        except (OSError, MetricsError, UnicodeError, OverflowError, TypeError,
                KeyError, IndexError, AttributeError, RecursionError, ValueError) as exc:
            return _fail(out, 'STORE_OR_RECORD_UNAVAILABLE')
        return out

    def correct(self, *, storage_root: str, read_policy: dict[str, Any],
                correction_policy: dict[str, Any],
                handoff_json: str, prepare_json: str, scope_json: str,
                metrics_json: str, release_policy: dict[str, Any],
                review_policy: dict[str, Any], render_policy: dict[str, Any],
                people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = _base()
        try:
            _check(type(correction_policy) is dict,
                   'CORRECTION_POLICY_REQUIRED', 'unavailable')
            selector = _selector(correction_policy.get('slot_key'),
                                 correction_policy.get('period_id'),
                                 correction_policy.get('slot_members'))
            _check(type(read_policy) is dict and
                   read_policy.get('policy_receipt_sha256') !=
                   correction_policy.get('policy_receipt_sha256'),
                   'READ_CORRECTION_PERMISSION_NOT_INDEPENDENT', 'unavailable')
            idx, docs = _load(storage_root, selector, read_policy)
            # A fresh read is not a signature, and a correction must own its
            # independent opt-in over the identical declared store/slot.
            _policy(correction_policy, selector,
                    read_policy['store_binding_sha256'], correction=True)
            p = correction_policy
            # Correction receipts must be disjoint from all caller-declared
            # EC197/198/199 stages and the independent EC200 read grants.
            previous_receipts = {read_policy['policy_receipt_sha256']}
            for grant in read_policy['repository_grants']:
                previous_receipts.add(grant['read_receipt_sha256'])
            for layer, receipt_key in ((release_policy, 'release_receipt_sha256'),
                                       (review_policy, 'review_receipt_sha256'),
                                       (render_policy, 'render_receipt_sha256')):
                if type(layer) is dict:
                    if valid_sha(layer.get('policy_receipt_sha256')):
                        previous_receipts.add(layer['policy_receipt_sha256'])
                    for grant in layer.get('repository_grants', []):
                        if type(grant) is dict and valid_sha(grant.get(receipt_key)):
                            previous_receipts.add(grant[receipt_key])
            _check(not ({p['policy_receipt_sha256']} |
                        {g['correction_receipt_sha256'] for g in p['repository_grants']}) &
                   previous_receipts,
                   'CORRECTION_RECEIPTS_NOT_INDEPENDENT', 'unavailable')
            previous = p['expected_previous_version']
            _check(previous <= len(docs), 'CORRECTION_BASE_NOT_FOUND', 'unavailable')
            old_entry = idx['versions'][previous - 1]
            _check(old_entry['report_ref'] == p['previous_report_ref'] and
                   old_entry['entry_sha256'] == p['previous_entry_sha256'],
                   'CORRECTION_BASE_MISMATCH', 'unavailable')
            _check(type(render_policy) is dict and
                   render_policy.get('permit_local_save') is True and
                   type(render_policy.get('repository_grants')) is list and
                   all(type(g) is dict and g.get('permit_local_save') is True
                       for g in render_policy['repository_grants']),
                   'CORRECTION_RENDER_SAVE_NOT_PERMITTED', 'unavailable')
            raw_inputs = dict(
                handoff_json=handoff_json, prepare_json=prepare_json,
                scope_json=scope_json, metrics_json=metrics_json,
                release_policy=release_policy, review_policy=review_policy,
                render_policy=render_policy,
                people_subject_witnesses=people_subject_witnesses,
            )
            candidate = ReportRender().render(**raw_inputs)
            _check(candidate['status'] == 'partial',
                   'CORRECTION_ORIGINAL_REPLAY_FAILED', 'unavailable')
            doc = candidate['subject']
            for name in selector:
                _check(doc[name] == selector[name],
                       'CORRECTION_REPORT_SLOT_CHANGED', 'unavailable')
            _check(doc['report_ref'] != docs[previous - 1]['report_ref'],
                   'CORRECTION_NO_DISTINCT_REPORT', 'unavailable')
            changes = _comparison(docs[previous - 1], doc, previous, previous + 1)
            for category in p['correction_categories']:
                _check(changes['changes'][category],
                       'CORRECTION_CATEGORY_WITHOUT_DELTA', 'unavailable')
            _check(changes['changed_categories'],
                   'CORRECTION_NO_EXPLICIT_DIFF', 'unavailable')
            # A declared correction scope must cover *every* real change,
            # including upstream source pins that moved while citations were
            # repaired. Otherwise a narrow consent would allow silent edits
            # to unapproved source, scope or evidence categories.
            _check(set(changes['changed_categories']) == set(p['correction_categories']),
                   'CORRECTION_UNDECLARED_CATEGORY_DELTA', 'unavailable')
            # EC199 lacks a signed correction-intent ledger. Replay is allowed
            # only for an exact immediate append by the same operation/token.
            if len(docs) != previous:
                _check(len(docs) >= previous + 1 and
                       idx['versions'][previous]['report_ref'] == doc['report_ref'] and
                       idx['versions'][previous]['operation_id'] == p['operation_id'],
                       'CORRECTION_STALE_HEAD', 'unavailable')
                storage = {
                    'state': 'REPLAY_ALREADY_SAVED',
                    'version': previous + 1,
                    'report_ref': doc['report_ref'],
                    'entry_sha256': idx['versions'][previous]['entry_sha256'],
                    'index_binding_sha256': idx['binding_sha256'],
                    'publication_state': 'NOT_PUBLISHED',
                }
                reason = 'REPORT_HISTORY_CORRECTION_REPLAY_EXISTING'
            else:
                saved = ReportRender().save(
                    storage_root=storage_root, expected_previous_version=previous,
                    operation_id=p['operation_id'], **raw_inputs)
                _check(saved['status'] == 'partial' and
                       saved['storage'] is not None and
                       saved['storage']['state'] in ('SAVED_NEW_VERSION', 'REPLAY_ALREADY_SAVED') and
                       saved['storage']['version'] == previous + 1,
                       'CORRECTION_APPEND_REFUSED', 'unavailable')
                storage = saved['storage']
                reason = 'REPORT_HISTORY_CORRECTION_APPENDED_NOT_PUBLISHED'
            out['correction_storage'] = storage  # retain receipt if post-save readback fails
            shown = self.show(
                storage_root=storage_root, slot_key=selector['slot_key'],
                period_id=selector['period_id'], slot_members=selector['slot_members'],
                read_policy=read_policy, version=previous + 1,
                compare_to_version=previous, include_markdown=False,
            )
            if shown['status'] != 'partial':
                out['correction_storage'] = storage
                return _fail(out, 'CORRECTION_COMMITTED_BUT_READBACK_UNAVAILABLE')
            result = shown['subject']
            _check(result['selected_report_ref'] == doc['report_ref'],
                   'CORRECTION_READBACK_REF_MISMATCH', 'unavailable')
            result['correction_declaration'] = {
                'correction_categories': copy.deepcopy(p['correction_categories']),
                'previous_version': previous,
                'previous_report_ref': p['previous_report_ref'],
                'previous_entry_sha256': p['previous_entry_sha256'],
                'correction_policy_receipt_sha256': p['policy_receipt_sha256'],
                'correction_authentication': 'DECLARED_ONLY_NOT_AUTHENTICATED',
                'permanent_index_intent': 'NOT_STORED_IN_EC199_INDEX',
            }
            payload = canonical(result)
            _check(byte_len(payload) <= MAX_HISTORY, 'RESPONSE_TOO_LARGE', 'unavailable')
            out.update(status='partial', exit_code=2, reason_code=reason,
                       subject=result, canonical_json=payload,
                       correction_storage=storage)
        except RenderError as exc:
            return _fail(out, exc.code, exc.status)
        except (OSError, MetricsError, UnicodeError, OverflowError, TypeError,
                KeyError, IndexError, AttributeError, RecursionError, ValueError) as exc:
            return _fail(out, 'CORRECTION_UNAVAILABLE')
        return out

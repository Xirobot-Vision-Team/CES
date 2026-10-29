#!/usr/bin/env python3
"""EC-158: offline, READ-ONLY CES v1 schema admission and upgrade preview.

This is NOT the PowerShell runtime, a migration writer, a repository verifier,
provenance attestation, or a proof of Git/source/finding/CI correctness. It
never serializes parsed inputs back to disk. CodeInsight IDs bind exact raw
UTF-8 bytes; v1 records must remain byte-for-byte immutable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

from response_contract import evaluate as evaluate_cli, load_contract

ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT / 'references' / 'schema-compatibility.v1.json'
MAX_DEPTH = 32
LIMITS = {
    'cli_response': 128 * 1024 * 1024,
    'collect_snapshot': 4 * 1024 * 1024,
    'code_packet': 64 * 1024 * 1024,
    'code_insight_draft': 256 * 1024,
    'code_insight_saved': 512 * 1024,
    'local_store_owner': 512,
}
KINDS = tuple(LIMITS)
RECORD_ID = re.compile(r'ci-[0-9a-f]{64}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
FINDING_ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,31}\Z')
RECORD_KEYS = (
    'schema_version', 'task_kind', 'source_root', 'source_mode',
    'saved_collect_sha256', 'packet_sha256', 'draft_sha256',
    'verification_scope', 'model_origin_authenticated',
    'source_provenance_authenticated', 'semantic_claims_verified',
    'claimed_line_numbers_verified', 'remote_delivery_verified', 'ci_verified',
    'summary', 'limitations', 'finding_count', 'checked_findings',
)
CHECKED_FINDING_KEYS = (
    'id', 'title', 'severity', 'confidence', 'layer', 'path',
    'path_endpoint', 'line_start_claimed', 'line_end_claimed',
    'line_numbers_verified', 'quote_sha256', 'quote_presence',
    'reasoning', 'impact', 'recommendation',
)
DRAFT_KEYS = (
    'schema_version', 'task_kind', 'packet_sha256', 'saved_collect_sha256',
    'summary', 'findings', 'limitations',
)
DRAFT_FINDING_KEYS = (
    'id', 'title', 'severity', 'confidence', 'layer', 'path',
    'evidence_quote', 'reasoning', 'impact', 'recommendation',
)
OWNER_BYTES = (b'{"schema_version":"ces.local_store.v1",'
               b'"owner":"CES","purpose":"local_code_insights"}')
HEX_COMMIT = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
TEXT_FORBIDDEN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


class SchemaInputError(Exception):
    """Input cannot be safely decoded, bounded, or parsed as one JSON object."""


class Validation:
    def __init__(self) -> None:
        self.issues: list[dict[str, str]] = []
        self.notes: list[str] = []

    def fail(self, code: str, field: str, description: str) -> None:
        self.issues.append({'code': code, 'field': field, 'detail': description})

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def keys(self, obj: Any, required: tuple[str, ...], field: str,
             optional: tuple[str, ...] = ()) -> bool:
        if not isinstance(obj, dict):
            self.fail('EXPECTED_OBJECT', field, 'Expected a JSON object.')
            return False
        for name in required:
            if name not in obj:
                self.fail('MISSING_FIELD', f'{field}.{name}', 'Required v1 field missing; no implicit default.')
        permitted = set(required + optional)
        for key in obj:
            if key not in permitted:
                self.fail('UNKNOWN_FIELD', f'{field}.{key}', 'v1 fixed-shape object does not allow extensions.')
        return True


def _pairs_no_case_collisions(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    observed: set[str] = set()
    for key, value in items:
        # .NET ordinal case-insensitive comparisons are not identical to
        # Unicode casefold, so use the stricter fail-closed rule offline.
        folded = key.casefold()
        if folded in observed:
            raise SchemaInputError('duplicate or case-colliding JSON property')
        observed.add(folded)
        result[key] = value
    return result


def _reject_constant(text: str) -> None:
    raise SchemaInputError(f'non-JSON number literal: {text}')


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise SchemaInputError('floating-point value exceeds JSON consumer limits')
    return value


def _walk_depth(value: Any, level: int = 1) -> None:
    if level > MAX_DEPTH:
        raise SchemaInputError('JSON object/array depth exceeds 32')
    if isinstance(value, dict):
        for name, item in value.items():
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in name):
                raise SchemaInputError('unpaired surrogate in JSON key')
            if isinstance(item, (dict, list)):
                _walk_depth(item, level + 1)
            elif isinstance(item, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                raise SchemaInputError('unpaired surrogate in JSON value')
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                _walk_depth(item, level + 1)
            elif isinstance(item, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in item):
                raise SchemaInputError('unpaired surrogate in JSON value')


def decode_one(raw: bytes, *, permit_bom: bool = False) -> dict[str, Any]:
    if raw.startswith(b'\xef\xbb\xbf'):
        if not permit_bom:
            raise SchemaInputError('UTF-8 BOM not allowed in this schema family')
        raw = raw[3:]
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'),
                           object_pairs_hook=_pairs_no_case_collisions,
                           parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SchemaInputError('invalid strict UTF-8 JSON') from exc
    if not isinstance(value, dict):
        raise SchemaInputError('root must be exactly one JSON object')
    _walk_depth(value)
    return value


def _file_bytes(path: str, size_limit: int) -> bytes:
    """Bounded read of a regular, non-link file. Not a filesystem sandbox."""
    if size_limit < 1:
        raise SchemaInputError('invalid byte budget')
    if path == '-':
        raw = sys.stdin.buffer.read(size_limit + 1)
        if len(raw) > size_limit:
            raise SchemaInputError('input exceeds the bounded byte budget')
        return raw
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise SchemaInputError('input path must be a regular file, not a link or special file')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb', closefd=True) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                raise SchemaInputError('input file changed between path probe and open')
            if info.st_size > size_limit:
                raise SchemaInputError('input exceeds the bounded byte budget')
            raw = stream.read(size_limit + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) > size_limit or len(raw) != info.st_size
                    or after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns):
                raise SchemaInputError('input oversized or changed during read')
            return raw
    except OSError as exc:
        raise SchemaInputError(f'cannot read input: {type(exc).__name__}') from exc


def _read_with_type_budget(path: str, kind: str) -> bytes:
    # To detect auto kind without enabling unlimited reads, use at most 128 MiB
    # for the FIRST bounded read, then enforce the chosen family's lower cap.
    return _file_bytes(path, LIMITS.get(kind, max(LIMITS.values())))


def _kind_from_tag(obj: Mapping[str, Any]) -> str | None:
    version = obj.get('schema_version')
    if version == 'ces.cli.v1':
        return 'collect_snapshot' if obj.get('action') == 'Collect' else 'cli_response'
    return {
        'ces.code_packet.v1': 'code_packet',
        'ces.code_insight_draft.v1': 'code_insight_draft',
        'ces.code_insight_saved.v1': 'code_insight_saved',
        'ces.local_store.v1': 'local_store_owner',
    }.get(version)


def _text(v: Validation, value: Any, field: str, lo: int, hi: int) -> None:
    if (not isinstance(value, str) or not lo <= len(value) <= hi or
            not value.strip() or TEXT_FORBIDDEN.search(value)):
        v.fail('BAD_TEXT', field, f'Expected nonblank printable text of {lo}..{hi} characters.')


def _hex(v: Validation, value: Any, field: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        v.fail('BAD_DIGEST', field, 'Expected lowercase 64-digit SHA-256.')


def _enum(v: Validation, value: Any, field: str, options: tuple[str, ...]) -> None:
    if type(value) is not str or value not in options:
        v.fail('BAD_ENUM', field, 'Value not allowed by the existing v1 producer.')


def _array_text(v: Validation, obj: Mapping[str, Any], field: str) -> None:
    arr = obj.get('limitations')
    if not isinstance(arr, list) or len(arr) > 20:
        v.fail('BAD_ARRAY', f'{field}.limitations', 'Expected <=20 limitations.')
        return
    for i, text in enumerate(arr):
        _text(v, text, f'{field}.limitations[{i}]', 1, 700)


def _common_finding(v: Validation, item: Mapping[str, Any], field: str,
                    encountered: set[str], source_mode: str | None = None) -> None:
    name = item.get('id')
    if not isinstance(name, str) or not FINDING_ID.fullmatch(name) or name.casefold() in encountered:
        v.fail('BAD_FINDING_ID', field + '.id', 'Invalid or duplicated case-insensitive v1 finding ID.')
    else:
        encountered.add(name.casefold())
    for name, lo, hi in (
        ('title', 4, 180), ('path', 1, 4096), ('reasoning', 8, 2400),
        ('impact', 8, 1200), ('recommendation', 8, 1200),
    ):
        _text(v, item.get(name), field + '.' + name, lo, hi)
    _enum(v, item.get('severity'), field + '.severity', ('critical','high','medium','low','info'))
    _enum(v, item.get('confidence'), field + '.confidence', ('high','medium','low'))
    _enum(v, item.get('layer'), field + '.layer', ('staged','unstaged','untracked','changes'))
    if source_mode == 'working_tree_diff' and item.get('layer') == 'changes':
        v.fail('INVALID_LAYER_FOR_MODE', field + '.layer', 'WorkingTree cannot claim delivered changes layer.')
    if source_mode == 'delivered_target_diff' and item.get('layer') != 'changes':
        v.fail('INVALID_LAYER_FOR_MODE', field + '.layer', 'DeliveredTarget only has changes layer.')


def _validate_saved(v: Validation, obj: Mapping[str, Any], raw: bytes,
                    path: str, expected_record_id: str | None) -> dict[str, Any]:
    if not v.keys(obj, RECORD_KEYS, 'record'):
        return {}
    if obj.get('task_kind') != 'code_analysis':
        v.fail('BAD_TASK_KIND', 'record.task_kind', 'Saved v1 only supports code_analysis.')
    _text(v, obj.get('source_root'), 'record.source_root', 1, 4096)
    source_mode = obj.get('source_mode')
    _enum(v, source_mode, 'record.source_mode', ('working_tree_diff','delivered_target_diff'))
    for key in ('saved_collect_sha256','packet_sha256','draft_sha256'):
        _hex(v, obj.get(key), 'record.' + key)
    if obj.get('verification_scope') != 'two_non_atomic_local_samples_and_pathspec_scoped_literal_quote_membership':
        v.fail('BAD_VERIFICATION_SCOPE', 'record.verification_scope', 'Unknown source-checking claim.')
    for key in ('model_origin_authenticated','source_provenance_authenticated',
                'semantic_claims_verified','claimed_line_numbers_verified',
                'remote_delivery_verified','ci_verified'):
        if obj.get(key) is not False:
            v.fail('UNSUPPORTED_PROOF_CLAIM', 'record.' + key, 'Existing v1 producer only stores false.')
    _text(v, obj.get('summary'), 'record.summary', 1, 4000)
    _array_text(v, obj, 'record')
    findings = obj.get('checked_findings')
    count = obj.get('finding_count')
    if (not isinstance(findings, list) or not isinstance(count, int) or type(count) is bool
            or not 0 <= count <= 40 or len(findings) != count):
        v.fail('BAD_FINDING_COUNT', 'record.checked_findings', 'Expected exact 0..40 bounded count/list.')
    else:
        ids: set[str] = set()
        for i, item in enumerate(findings):
            field = f'record.checked_findings[{i}]'
            if not v.keys(item, CHECKED_FINDING_KEYS, field):
                continue
            _common_finding(v, item, field, ids, source_mode if isinstance(source_mode,str) else None)
            _enum(v, item.get('path_endpoint'), field + '.path_endpoint', ('path','old_path'))
            _enum(v, item.get('quote_presence'), field + '.quote_presence',
                  ('diff_layer_literal_only','exact_untracked_file_literal','pathspec_scoped_tracked_diff_literal'))
            _hex(v, item.get('quote_sha256'), field + '.quote_sha256')
            if item.get('line_numbers_verified') is not False:
                v.fail('UNSUPPORTED_PROOF_CLAIM', field + '.line_numbers_verified', 'v1 does not verify claimed line numbers.')
            start, end = item.get('line_start_claimed'), item.get('line_end_claimed')
            if (start is None) != (end is None):
                v.fail('BAD_LINE_INTERVAL', field, 'Claimed start/end must both be null or integers.')
            elif start is not None and (type(start) is not int or type(end) is not int
                    or not 1 <= start <= end <= 10000000 or end - start > 200):
                v.fail('BAD_LINE_INTERVAL', field, 'Invalid 1-based claimed bounded interval.')
            layer = item.get('layer')
            if layer == 'untracked':
                if item.get('path_endpoint') != 'path' or item.get('quote_presence') != 'exact_untracked_file_literal':
                    v.fail('INVALID_PROOF_MARKER', field, 'Untracked record proof markers contradict v1 producer.')
            elif layer in ('staged','unstaged','changes'):
                if item.get('quote_presence') != 'pathspec_scoped_tracked_diff_literal':
                    v.fail('INVALID_PROOF_MARKER', field, 'Tracked record proof markers contradict v1 producer.')
    digest = hashlib.sha256(raw).hexdigest()
    derived_id = 'ci-' + digest
    filename_id = Path(path).name[:-5] if path != '-' and path.endswith('.json') else None
    is_bound = bool(filename_id and RECORD_ID.fullmatch(filename_id))
    if expected_record_id is not None and not RECORD_ID.fullmatch(expected_record_id):
        v.fail('INVALID_EXPECTED_RECORD_ID', 'record_id', 'Expected ci- followed by exactly 64 lowercase hex.')
    elif expected_record_id and expected_record_id != derived_id:
        v.fail('RECORD_ID_MISMATCH', 'record_id', 'SHA of exact input bytes differs from expected ID.')
    if is_bound and filename_id != derived_id:
        v.fail('FILENAME_HASH_MISMATCH', 'record_id', 'ci- filename does not match exact file content.')
    if is_bound and expected_record_id and expected_record_id != filename_id:
        v.fail('FILENAME_ID_MISMATCH', 'record_id', 'File name and supplied record ID disagree.')
    if not is_bound and expected_record_id is None:
        v.note('No ci-<sha256>.json filename or supplied --record-id; identity is computed but unbound.')
    v.note('Hash match detects ordinary corruption, not authorship, current Git state or atomic disk integrity.')
    return {
        'record_id_from_exact_bytes': derived_id,
        'record_id_bound': bool(is_bound or expected_record_id),
        'finding_count': count if type(count) is int else None,
    }


def _validate_draft(v: Validation, obj: Mapping[str, Any]) -> dict[str, Any]:
    if not v.keys(obj, DRAFT_KEYS, 'draft'):
        return {}
    if obj.get('task_kind') != 'code_analysis':
        v.fail('BAD_TASK_KIND', 'draft.task_kind', 'Draft v1 only supports code_analysis.')
    for key in ('packet_sha256','saved_collect_sha256'):
        _hex(v, obj.get(key), 'draft.' + key)
    _text(v, obj.get('summary'), 'draft.summary', 1, 4000)
    _array_text(v, obj, 'draft')
    findings = obj.get('findings')
    if not isinstance(findings, list) or len(findings) > 40:
        v.fail('BAD_ARRAY', 'draft.findings', 'Expected <=40 findings.')
    else:
        ids: set[str] = set()
        for i, item in enumerate(findings):
            field = f'draft.findings[{i}]'
            if not v.keys(item, DRAFT_FINDING_KEYS, field, ('line_start','line_end')):
                continue
            _common_finding(v, item, field, ids)
            _text(v, item.get('evidence_quote'), field + '.evidence_quote', 8, 900)
            if ('line_start' in item) != ('line_end' in item):
                v.fail('BAD_LINE_INTERVAL', field, 'line_start and line_end must be provided together.')
            elif 'line_start' in item:
                start, end = item['line_start'], item['line_end']
                if (type(start) is not int or type(end) is not int or
                        not 1 <= start <= end <= 10000000 or end - start > 200):
                    v.fail('BAD_LINE_INTERVAL', field, 'Invalid claimed line interval.')
    v.note('Draft shape is not evidence anchoring; native CodeValidate must independently inspect source.')
    return {'finding_count': len(findings) if isinstance(findings, list) else None}


def _validate_packet(v: Validation, obj: Mapping[str, Any]) -> dict[str, Any]:
    if not v.keys(obj, ('schema_version','task_kind','scope','layers','review_guidance','provenance'), 'packet'):
        return {}
    if obj.get('task_kind') != 'code_analysis':
        v.fail('BAD_TASK_KIND','packet.task_kind','Unexpected packet task kind.')
    scope = obj.get('scope')
    if not isinstance(scope, dict):
        v.fail('EXPECTED_OBJECT','packet.scope','Missing source scope.')
    else:
        _enum(v, scope.get('source_mode'), 'packet.scope.source_mode', ('working_tree_diff','delivered_target_diff'))
    if not isinstance(obj.get('layers'),dict):
        v.fail('EXPECTED_OBJECT','packet.layers','Expected layer mapping.')
    if (not isinstance(obj.get('review_guidance'),list) or
            not all(isinstance(s,str) for s in obj['review_guidance'])):
        v.fail('BAD_ARRAY','packet.review_guidance','Expected textual review guidance.')
    prov = obj.get('provenance')
    if not isinstance(prov,dict):
        v.fail('EXPECTED_OBJECT','packet.provenance','Expected provenance mapping.')
    else:
        _hex(v, prov.get('saved_collect_sha256'),'packet.provenance.saved_collect_sha256')
        if prov.get('independently_authenticated') is not False or prov.get('atomic_capture') is not False:
            v.fail('UNSUPPORTED_PROOF_CLAIM','packet.provenance','v1 packet is neither authenticated nor atomic.')
    v.note('Nested source excerpts are opaque/untrusted; this offline inspector does not reproduce them.')
    return {}


def _validate_envelope(v: Validation, obj: Mapping[str, Any], collect: bool) -> dict[str, Any]:
    # Reuse EC-156 for 16 required keys/31 known coverage booleans, statuses,
    # Action/CodeSave constraints. Deep data stays opaque (k1..56 invariant).
    assessment = evaluate_cli(obj, load_contract())
    for issue in assessment['issues']:
        v.fail(issue['code'], issue['field'], issue['detail'])
    for note in assessment['advisories']:
        v.note(note)
    # Validate only the EXISTING shallow, version-bearing inline markers.
    # The nested CodeShow data/Sequence k1..56 tree stays completely opaque.
    # Do not mistake CodeValidate.output_schema for an on-disk record format.
    data = obj.get('data')
    action = obj.get('action')
    if isinstance(data, dict):
        if action == 'CodeValidate' and ('output_schema' in data or data.get('validated') is True):
            if data.get('output_schema') != 'ces.code_insight_checked.v1':
                v.fail('UNSUPPORTED_EMBEDDED_VERSION', 'data.output_schema',
                       'Validated CodeInsight v1 uses checked output_schema, not an independent saved format.')
        if action == 'CodePrepare' and ('review_packet' in data or data.get('prepared') is True):
            packet = data.get('review_packet')
            if isinstance(packet, dict):
                if packet.get('schema_version') != 'ces.code_packet.v1':
                    v.fail('UNSUPPORTED_EMBEDDED_VERSION', 'data.review_packet.schema_version',
                           'Prepared packet is not a recognized v1 nested schema.')
            elif data.get('prepared') is True:
                v.fail('MISSING_PREPARED_PACKET', 'data.review_packet',
                       'Prepared=true requires a versioned review packet.')
        if action == 'CodeSave' and ('record_schema' in data or obj.get('status') == 'success'):
            if data.get('record_schema') != 'ces.code_insight_saved.v1':
                v.fail('UNSUPPORTED_EMBEDDED_VERSION', 'data.record_schema',
                       'Successful CodeSave only advertises existing saved-v1 records.')
            if obj.get('status') == 'success':
                rid, digest = data.get('record_id'), data.get('record_sha256')
                if (not isinstance(rid,str) or not RECORD_ID.fullmatch(rid) or
                        not isinstance(digest,str) or not SHA256.fullmatch(digest) or
                        rid[3:] != digest):
                    v.fail('SAVE_IDENTITY_INCONSISTENT', 'data.record_id',
                           'Successful CodeSave must report matching record ID and SHA-256.')
    if collect:
        if obj.get('action') != 'Collect':
            v.fail('BAD_ACTION', 'action', 'Expected Collect, not a general ces.cli.v1 response.')
        if obj.get('status') not in ('success','partial') or obj.get('read_only') is not True:
            v.fail('NOT_SAVED_COLLECT_EVIDENCE', 'status', 'Saved Collect must be success/partial, read_only=true.')
        data = obj.get('data')
        if not isinstance(data, dict):
            v.fail('EXPECTED_OBJECT','data','Collect requires the evidence data object.')
        else:
            subject = data.get('subject')
            if not isinstance(subject,dict) or subject.get('kind') != 'code':
                v.fail('BAD_COLLECT_SUBJECT','data.subject','Must identify a code subject.')
            else:
                _enum(v, subject.get('source_mode'), 'data.subject.source_mode',
                      ('working_tree_diff','delivered_target_diff'))
            snapshot = data.get('snapshot')
            if not isinstance(snapshot,dict) or snapshot.get('atomic') is not False:
                v.fail('BAD_SNAPSHOT','data.snapshot','Saved Collect v1 snapshot must state atomic=false.')
            if data.get('can_persist_ces_state') is not False:
                v.fail('UNSUPPORTED_PROOF_CLAIM','data.can_persist_ces_state','Collect is read-only.')
        v.note('Live source equivalence, commit selector and patch hashes require native Reconcile; not verified here.')
    else:
        v.note('Unknown extension fields are not authority; deep data/Sequence k1..56 are never normalized.')
    safe_actions = {'Inspect', 'Collect', 'Reconcile', 'CodePrepare',
                    'CodeValidate', 'CodeSave', 'CodeShow'}
    safe_statuses = {'success','partial','not_implemented','invalid_input','unavailable'}
    return {'action': obj.get('action') if isinstance(obj.get('action'),str)
                              and obj.get('action') in safe_actions else None,
            'status': obj.get('status') if isinstance(obj.get('status'),str)
                               and obj.get('status') in safe_statuses else None,
            'known_coverage_flags': len(assessment['coverage']['reported_true']) +
                                    len(assessment['coverage']['reported_false_or_not_established'])}


def _validate_owner(v: Validation, obj: Mapping[str, Any], raw: bytes) -> dict[str, Any]:
    v.keys(obj, ('schema_version','owner','purpose'), 'owner')
    if raw != OWNER_BYTES:
        v.fail('OWNER_BYTES_MISMATCH', 'owner', 'v1 owner marker must match exact authored UTF-8 bytes.')
    return {'exact_owner_marker': raw == OWNER_BYTES}


def _policy() -> dict[str, Any]:
    try:
        policy = decode_one(POLICY_PATH.read_bytes())
    except OSError as exc:
        raise SchemaInputError('schema policy file unavailable') from exc
    if policy.get('schema_version') != 'ces.schema_compatibility_policy.v1':
        raise SchemaInputError('unrecognized schema policy')
    return policy


def inspect_bytes(raw: bytes, *, kind: str = 'auto', path: str = '-',
                  record_id: str | None = None) -> dict[str, Any]:
    # Unlike the native readers, the offline classifier must accept a Collect
    # or draft UTF-8 BOM; saved records, owner markers and packets do not.
    has_bom = raw.startswith(b'\xef\xbb\xbf')
    obj = decode_one(raw, permit_bom=True)
    actual_kind = _kind_from_tag(obj)
    if kind != 'auto' and kind not in LIMITS:
        raise SchemaInputError('unknown inspector family')
    effective_kind = actual_kind if kind == 'auto' else kind
    version = obj.get('schema_version')
    v = Validation()
    # An explicit generic envelope request should also admit Collect, whose
    # outer wire schema IS ces.cli.v1. Auto mode applies a stricter Collect
    # evidence shape subset, but a generic consumer can intentionally opt out.
    family_matches = (actual_kind == effective_kind or
                      (actual_kind == 'collect_snapshot' and effective_kind == 'cli_response'))
    if actual_kind is None:
        v.fail('MISSING_VERSION' if version is None else 'UNSUPPORTED_VERSION',
               'schema_version', 'No compatible versioned v1 decoder; never guess or auto-upgrade.')
    elif not family_matches:
        v.fail('FAMILY_MISMATCH', 'schema_version',
               'Declared version/action does not match the selected schema family.')
    if effective_kind in LIMITS and len(raw) > LIMITS[effective_kind]:
        v.fail('FAMILY_BYTE_LIMIT', 'input', 'Payload exceeds family-specific native bound.')
    if has_bom and effective_kind not in ('collect_snapshot','code_insight_draft'):
        v.fail('BOM_NOT_ALLOWED', 'input', 'This v1 family rejects a UTF-8 BOM.')
    if has_bom and effective_kind in ('collect_snapshot','code_insight_draft'):
        v.note('BOM is tolerated by native v1 input reader; it is included in content SHA-256.')
    extra: dict[str, Any] = {}
    # A tag mismatch must NOT run a different family validator to claim conformance.
    if actual_kind is not None and family_matches:
        if effective_kind == 'code_insight_saved':
            extra = _validate_saved(v, obj, raw, path, record_id)
        elif effective_kind == 'code_insight_draft':
            extra = _validate_draft(v, obj)
        elif effective_kind == 'code_packet':
            extra = _validate_packet(v, obj)
        elif effective_kind == 'local_store_owner':
            extra = _validate_owner(v, obj, raw)
        elif effective_kind in ('cli_response','collect_snapshot'):
            extra = _validate_envelope(v, obj, effective_kind == 'collect_snapshot')
    if record_id is not None and effective_kind != 'code_insight_saved':
        v.fail('ID_NOT_APPLICABLE', 'record_id', '--record-id only applies to saved CodeInsight records.')
    valid = not v.issues
    return {
        'inspector': 'ces.schema_compat.v1',
        'disposition': ('READ_COMPATIBLE_V1' if valid else
                        'REJECT_UNVERSIONED_OR_UNKNOWN' if actual_kind is None else 'REJECT_INVALID_V1'),
        'compatible_for_offline_read': valid,
        'schema_version': version if isinstance(version,str) and len(version) <= 128 else None,
        'family': effective_kind,
        'raw_bytes': len(raw),
        'content_sha256': hashlib.sha256(raw).hexdigest(),
        'identity': extra,
        'issues': v.issues,
        'advisories': v.notes,
        'input_was_rewritten': False,
        'runtime_or_source_provenance_verified': False,
        'power_shell_code_show_unchanged': True,
    }


def inspect_file(path: str, kind: str, record_id: str | None = None) -> dict[str, Any]:
    raw = _read_with_type_budget(path, kind)
    return inspect_bytes(raw, kind=kind, path=path, record_id=record_id)


def preview_upgrade(report: Mapping[str, Any], target: str) -> dict[str, Any]:
    """No migration writer exists in EC-158; identity planning is the only valid path."""
    version = report['schema_version']
    readable = report['compatible_for_offline_read']
    same = readable and target == version
    return {
        'planner': 'ces.schema_upgrade_preview.v1',
        'source_schema_version': version,
        'target_schema_version': target,
        'source_compatible': readable,
        'disposition': 'NOOP_KEEP_ORIGINAL_BYTES' if same else 'BLOCKED_NO_AUTHORIZED_MIGRATION',
        'upgrade_executed': False,
        'requires_explicit_future_authorization': not same,
        'original_raw_sha256': report['content_sha256'],
        'original_record_id': report['identity'].get('record_id_from_exact_bytes'),
        'would_overwrite_original': False,
        'would_mutate_git_or_business_source': False,
        'rollback': 'Original bytes remain untouched; no new artifact was created.',
        'reason': ('Already at this version; no normalization or reserialization necessary.'
                   if same else
                   'No v2 writer/transform/commit protocol has been approved or implemented.'),
    }


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p_registry = sub.add_parser('policy', help='Print the read-only compatibility policy.')
    p_registry.add_argument('--json', action='store_true')
    for command in ('inspect', 'preview'):
        p = sub.add_parser(command, help='Inspect one local JSON object; never write or migrate.')
        p.add_argument('--input', required=True, help='JSON file or - for stdin.')
        p.add_argument('--kind', default='auto', choices=('auto', *KINDS))
        p.add_argument('--record-id', help='Expected ci-<64 lowercase hex> ID for saved CodeInsight.')
        if command == 'preview':
            p.add_argument('--target', required=True, help='Exact target schema_version; not a write authorization.')
        p.add_argument('--json', action='store_true', help='Structured metadata only, no original content.')
    args = parser.parse_args(argv)
    try:
        if args.command == 'policy':
            result = _policy()
            code = 0
        else:
            result = inspect_file(args.input, args.kind, args.record_id)
            if args.command == 'preview':
                result = {'source': result, 'upgrade_preview': preview_upgrade(result, args.target)}
                code = 0 if result['upgrade_preview']['disposition'] == 'NOOP_KEEP_ORIGINAL_BYTES' else 1
            else:
                code = 0 if result['compatible_for_offline_read'] else 1
    except SchemaInputError as exc:
        result = {'inspector': 'ces.schema_compat.v1', 'disposition': 'REJECT_UNREADABLE_INPUT',
                  'compatible_for_offline_read': False, 'error': str(exc),
                  'input_was_rewritten': False, 'runtime_or_source_provenance_verified': False}
        code = 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False))
    else:
        print(f"{result.get('disposition', 'SCHEMA_POLICY')} [tool exit={code}]")
        if args.command == 'preview' and 'upgrade_preview' in result:
            print('Upgrade preview:', result['upgrade_preview']['disposition'])
        if 'error' in result:
            print('Error:', result['error'])
        for item in result.get('issues', []):
            print(f"{item['code']} at {item['field']}: {item['detail']}")
        print('No input content was rewritten. Offline checks are not native acceptance.')
    return code


if __name__ == '__main__':
    sys.exit(run_cli())

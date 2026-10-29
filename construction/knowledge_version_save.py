#!/usr/bin/env python3
"""EC208: signature-gated immutable CES *metadata* knowledge versions.

One owner-private POSIX journal belongs to ONE explicitly pinned existing CES
Markdown chapter. A newly reviewed replacement for ONE byte-exact EC205-style
section is saved as an immutable full-body record in that journal, never into
its original knowledge snapshot (nor a business repository). An EC207 Handoff
is re-derived from EC206 candidate records and its original content grants;
that Handoff alone has *no* save authority.

Two independently configured Ed25519 approval keys (reviewer and knowledge
owner) must sign one exact version/contents/snapshot/section/candidate binding.
The configured key-role mapping, revocations and knowledge snapshot are local
operator trust inputs: their organizational custody or freshness is NOT proved.
Metadata versions are *not* published/current business architecture.

Requires a POSIX dirfd/nofollow/flock/owner-private environment. Unsupported
systems fail closed. EC209 concurrency retry and native CLI wiring are absent.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
import stat
from typing import Any, Iterator
import uuid

try:
    from . import knowledge_boundary as kb
    from . import knowledge_bootstrap as boot
    from . import knowledge_chapters as chapters
    from . import knowledge_candidate_store as kc
    from . import knowledge_update_handoff as kh
    from . import proposed_pr_evidence_store as fs
except ImportError:
    import knowledge_boundary as kb
    import knowledge_bootstrap as boot
    import knowledge_chapters as chapters
    import knowledge_candidate_store as kc
    import knowledge_update_handoff as kh
    import proposed_pr_evidence_store as fs

SCHEMA = 'ces.knowledge_version_save.v1'
REQUEST_SCHEMA = 'ces.knowledge_save_request.v1'
POLICY_SCHEMA = 'ces.knowledge_save_policy.v1'
APPROVALS_SCHEMA = 'ces.knowledge_save_approvals.v1'
STATEMENT_SCHEMA = 'ces.knowledge_save_approval_statement.v1'
MANIFEST_SCHEMA = 'ces.knowledge_version_manifest.v1'
RECORD_SCHEMA = 'ces.knowledge_version_record.v1'
PURPOSE = 'append_immutable_local_ces_knowledge_metadata_only'
APPROVAL_PURPOSE = 'approve_exact_local_ces_knowledge_metadata_version'
SIGNED_DOMAIN = b'CES-EC208-KNOWLEDGE-SAVE-APPROVAL-v1\0'
ROLES = ('independent_reviewer', 'knowledge_owner')
MAX_VERSIONS = 64
MAX_MARKDOWN = boot.MAX_FILE  # existing EC202 snapshot chapter cap, 16 KiB
MAX_REQUEST = 32768
MAX_POLICY = 8192
MAX_APPROVALS = 8192
MAX_RECORD = 80000
MAX_SUMMARY_BYTES = 1024
VERSION_NAME = re.compile(r'[0-9]{8}\.json\Z', re.ASCII)


class SaveError(ValueError):
    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def need(value: bool, code: str, status: str = 'invalid_input') -> None:
    if not value:
        raise SaveError(code, status)


def exact(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == keys, code)
    return value


def digest(domain: str, value: Any) -> str:
    return kb.digest('CES-EC208-' + domain + '-v1', value)


def raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> str:
    return kb.canonical(value)


def decode_json(text: str, limit: int) -> dict[str, Any]:
    try:
        return kb._json(text, limit)
    except kb.KnowledgeBoundaryError as exc:
        raise SaveError('INVALID_CANONICAL_JSON_' + exc.reason) from exc


def decode_b64(value: Any, limit: int, code: str) -> bytes:
    need(type(value) is str and 1 <= len(value) <= 4 * ((limit + 2) // 3), code)
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise SaveError(code) from None
    need(0 < len(result) <= limit and base64.b64encode(result).decode('ascii') == value, code)
    return result


def response(status: str, reason: str, *, subject: dict[str, Any] | None = None,
             version_written: bool = False, initialized: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'invalid_input': 4, 'unavailable': 5}[status],
        'reason_code': 'KNOWLEDGE_SAVE_' + reason, 'subject': subject,
        'local_version_metadata_written': version_written,
        'local_write_outcome_unknown': reason in (
            'APPEND_OUTCOME_UNKNOWN_INSPECT_BEFORE_ANY_RETRY',
            'INITIALIZATION_UNAVAILABLE_OR_OUTCOME_UNKNOWN'),
        'private_store_initialized': initialized,
        'source_knowledge_file_written': False, 'business_repository_written': False,
        'existing_version_overwritten': False, 'issue_or_provider_written': False,
        'published': False, 'candidate_promoted_to_verified_fact': False,
        'organizational_signer_identity_authenticated': False,
        'current_architecture_or_delivery_verified': False,
        'native_knowledge_route_registered': False,
    }


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: Any) -> datetime:
    try:
        return kb._time(value)
    except kb.KnowledgeBoundaryError as exc:
        raise SaveError('TIME_' + exc.reason) from exc


def _path(path: Any) -> str:
    try:
        boot._path(path)
    except boot.BootstrapError as exc:
        raise SaveError('CHAPTER_' + exc.reason) from exc
    need(path.lower().endswith(('.md', '.markdown')), 'CHAPTER_MUST_BE_MARKDOWN')
    return path


def _root_id(path: str) -> dict[str, int]:
    fd = None
    try:
        fd, _ = boot._open_bound_root(path, permit_missing=False)
        need(fd is not None, 'SOURCE_ROOT_MISSING', 'unavailable')
        st = os.fstat(fd)
        return {'dev': st.st_dev, 'ino': st.st_ino}
    except boot.BootstrapError as exc:
        raise SaveError('SOURCE_ROOT_' + exc.reason, 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _snapshot(api: 'KnowledgeVersionSave') -> dict[str, Any]:
    """Read bytes twice via nofollow dirfd. No trust in manifest claims alone."""
    fd = None
    try:
        fd, _ = boot._open_bound_root(api.store.knowledge_root, permit_missing=False)
        need(fd is not None, 'KNOWLEDGE_ROOT_MISSING', 'unavailable')
        root_id = {'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino}
        need(root_id == api._knowledge_root_id, 'KNOWLEDGE_ROOT_REPLACED', 'unavailable')
        state, manifest_raw = boot._read_file(fd, boot.MANIFEST_NAME, boot.MAX_MANIFEST)
        need(state == 'READ' and manifest_raw is not None, 'KNOWLEDGE_MANIFEST_' + state, 'unavailable')
        try:
            manifest = boot._manifest_obj(manifest_raw, {
                'repository_ref': api.store.repository_ref,
                'knowledge_space_key': api.store.knowledge_space_key,
                'source_policy_revision': api.store.source_policy_revision,
            })
        except boot.BootstrapError as exc:
            raise SaveError('KNOWLEDGE_MANIFEST_' + exc.reason, 'unavailable') from exc
        need(manifest['coverage'] == 'complete_declared' and manifest['captured_at_utc'] is not None,
             'KNOWLEDGE_SNAPSHOT_INCOMPLETE_OR_UNDATED', 'unavailable')
        entries = [e for e in manifest['entries'] if e['relative_path'] == api.chapter_path]
        need(len(entries) == 1, 'KNOWLEDGE_CHAPTER_NOT_IN_SNAPSHOT', 'unavailable')
        entry = entries[0]
        state, body = boot._read_file(fd, api.chapter_path, MAX_MARKDOWN)
        need(state == 'READ' and body is not None, 'KNOWLEDGE_CHAPTER_' + state, 'unavailable')
        need(len(body) == entry['size_bytes'] and raw_sha(body) == entry['sha256'],
             'KNOWLEDGE_SNAPSHOT_FILE_MISMATCH', 'unavailable')
        state2, manifest_again = boot._read_file(fd, boot.MANIFEST_NAME, boot.MAX_MANIFEST)
        state3, body_again = boot._read_file(fd, api.chapter_path, MAX_MARKDOWN)
        need(state2 == 'READ' and state3 == 'READ' and
             manifest_again == manifest_raw and body_again == body and
             root_id == {'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino},
             'KNOWLEDGE_SNAPSHOT_CHANGED_DURING_READ', 'unavailable')
        _parts(body)
        return {'snapshot_version': manifest['snapshot_version'],
                'manifest_sha256': raw_sha(manifest_raw),
                'content_sha256': raw_sha(body), 'content': body,
                'root_identity': root_id}
    except (OSError, UnicodeError) as exc:
        raise SaveError('KNOWLEDGE_SNAPSHOT_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _parts(raw: bytes) -> list[dict[str, Any]]:
    need(0 < len(raw) <= MAX_MARKDOWN, 'CHAPTER_EMPTY_OR_OVERSIZED', 'unavailable')
    try:
        return chapters._sections(raw)
    except chapters.ChapterError as exc:
        raise SaveError('CHAPTER_PARSE_' + exc.code, 'unavailable') from exc


def _registry_config(api: 'KnowledgeVersionSave') -> dict[str, Any]:
    return {'trusted_approvers': [
        {'signer_key_id': k, 'role': api.trusted_approvers[k]['role'],
         'ed25519_public_key_hex': api.trusted_approvers[k]['public_key'].hex()}
        for k in sorted(api.trusted_approvers)],
        'revoked_signer_key_ids': sorted(api.revoked_approvers)}


def _store_scope(manifest: dict[str, Any]) -> dict[str, Any]:
    return {k: manifest[k] for k in ('store_id', 'instance_id', 'root_path',
        'repository_ref', 'knowledge_space_key', 'period_id', 'source_policy_revision',
        'repository_root_identity', 'knowledge_root_identity', 'candidate_store_instance_id',
        'candidate_store_scope_binding_sha256', 'chapter_path',
        'baseline_snapshot_version', 'baseline_manifest_sha256',
        'baseline_chapter_sha256', 'baseline_chapter_size', 'approver_registry_sha256')}


def _check_manifest(api: 'KnowledgeVersionSave', manifest: dict[str, Any], fd: int) -> None:
    exact(manifest, {'schema', 'store_id', 'instance_id', 'root_path', 'repository_ref',
        'knowledge_space_key', 'period_id', 'source_policy_revision',
        'repository_root_identity', 'knowledge_root_identity', 'metadata_root_identity',
        'candidate_store_instance_id', 'candidate_store_scope_binding_sha256',
        'chapter_path', 'baseline_snapshot_version', 'baseline_manifest_sha256',
        'baseline_chapter_sha256', 'baseline_chapter_size', 'approver_registry_sha256',
        'store_scope_binding_sha256', 'local_integrity_key_hex'}, 'MANIFEST_FIELDS_INVALID')
    need(manifest['schema'] == MANIFEST_SCHEMA and manifest['store_id'] == api.store_id and
         manifest['root_path'] == api.root and manifest['repository_ref'] == api.store.repository_ref and
         manifest['knowledge_space_key'] == api.store.knowledge_space_key and
         manifest['period_id'] == api.store.period_id and
         manifest['source_policy_revision'] == api.store.source_policy_revision and
         manifest['chapter_path'] == api.chapter_path,
         'STORE_SCOPE_MISMATCH', 'unavailable')
    try:
        ident = uuid.UUID(manifest['instance_id'])
        need(ident.version == 4 and str(ident) == manifest['instance_id'],
             'STORE_INSTANCE_INVALID', 'unavailable')
    except (ValueError, TypeError, AttributeError):
        raise SaveError('STORE_INSTANCE_INVALID', 'unavailable') from None
    need(kb.sha(manifest['local_integrity_key_hex']) and
         kb.sha(manifest['baseline_chapter_sha256']) and
         kb.sha(manifest['baseline_manifest_sha256']) and
         kb.sha(manifest['candidate_store_scope_binding_sha256']) and
         type(manifest['baseline_chapter_size']) is int and
         0 < manifest['baseline_chapter_size'] <= MAX_MARKDOWN,
         'STORE_MANIFEST_DIGEST_INVALID', 'unavailable')
    need(manifest['approver_registry_sha256'] == digest('APPROVER-REGISTRY', _registry_config(api)),
         'APPROVER_REGISTRY_OR_REVOCATION_DRIFT', 'unavailable')
    need(manifest['repository_root_identity'] == _root_id(api.store.repository_root) and
         manifest['knowledge_root_identity'] == _root_id(api.store.knowledge_root) and
         manifest['metadata_root_identity'] == {'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino} and
         manifest['store_scope_binding_sha256'] == digest('STORE-SCOPE', _store_scope(manifest)),
         'STORE_OR_SOURCE_IDENTITY_DRIFT', 'unavailable')
    need(manifest['candidate_store_instance_id'] == api._candidate_instance_id and
         manifest['candidate_store_scope_binding_sha256'] == api._candidate_scope_sha,
         'CANDIDATE_STORE_IDENTITY_DRIFT', 'unavailable')
    api._disjoint()


def _mac(manifest: dict[str, Any], record: dict[str, Any]) -> str:
    return hmac.new(bytes.fromhex(manifest['local_integrity_key_hex']),
                    b'CES-EC208-LOCAL-RECORD-MAC-v1\0' + canonical(record).encode('ascii'),
                    hashlib.sha256).hexdigest()


def _filename(number: int) -> str:
    return f'{number:08d}.json'


def _verify_approvals(api: 'KnowledgeVersionSave', raw: Any, scope: str,
                      now: datetime) -> list[dict[str, Any]]:
    exact(raw, {'schema', 'statements'}, 'APPROVALS_FIELDS_INVALID')
    need(raw['schema'] == APPROVALS_SCHEMA and type(raw['statements']) is list and
         len(raw['statements']) == 2, 'TWO_INDEPENDENT_APPROVALS_REQUIRED', 'unavailable')
    normalized: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    seen_public_keys: set[bytes] = set()
    for row, role in zip(raw['statements'], ROLES):
        exact(row, {'statement', 'signature_base64'}, 'APPROVAL_ITEM_FIELDS_INVALID')
        statement = exact(row['statement'], {'schema', 'purpose', 'signer_key_id', 'role',
            'authorization_scope_sha256', 'review_state', 'issued_at_utc', 'expires_at_utc'},
            'APPROVAL_STATEMENT_FIELDS_INVALID')
        signer = statement['signer_key_id']
        need(statement['schema'] == STATEMENT_SCHEMA and
             statement['purpose'] == APPROVAL_PURPOSE and
             statement['role'] == role and kb.key(signer) and
             statement['authorization_scope_sha256'] == scope and
             statement['review_state'] == 'REVIEWED_APPROVED_FOR_THIS_VERSION_ONLY',
             'APPROVAL_SCOPE_ROLE_OR_DECISION_INVALID', 'unavailable')
        approved = api.trusted_approvers.get(signer)
        need(approved is not None and approved['role'] == role and
             signer not in api.revoked_approvers and signer not in seen_keys and
             approved['public_key'] not in seen_public_keys,
             'APPROVAL_SIGNER_UNTRUSTED_REVOKED_OR_NOT_INDEPENDENT', 'unavailable')
        seen_keys.add(signer)
        seen_public_keys.add(approved['public_key'])
        issued, expires = _time(statement['issued_at_utc']), _time(statement['expires_at_utc'])
        need(issued <= now + timedelta(minutes=5) and
             issued >= now - timedelta(hours=24) and
             now < expires <= issued + timedelta(hours=24) and issued < expires,
             'APPROVAL_EXPIRED_FUTURE_OR_TOO_OLD', 'unavailable')
        signature = decode_b64(row['signature_base64'], 64, 'APPROVAL_SIGNATURE_MALFORMED')
        need(len(signature) == 64, 'APPROVAL_SIGNATURE_MALFORMED')
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise SaveError('ED25519_VERIFIER_UNAVAILABLE', 'unavailable') from None
        try:
            Ed25519PublicKey.from_public_bytes(approved['public_key']).verify(
                signature, SIGNED_DOMAIN + canonical(statement).encode('ascii'))
        except (InvalidSignature, ValueError, TypeError):
            raise SaveError('APPROVAL_SIGNATURE_INVALID', 'unavailable') from None
        normalized.append(row)
    return normalized


def _validate_record(api: 'KnowledgeVersionSave', manifest: dict[str, Any],
                     record: dict[str, Any], number: int,
                     parent_id: str | None, parent_bytes: bytes) -> bytes:
    exact(record, {'schema', 'sequence', 'version_id', 'body', 'local_mac_sha256'},
          'RECORD_FIELDS_INVALID')
    need(record['schema'] == RECORD_SCHEMA and type(record['sequence']) is int and
         record['sequence'] == number and type(record['body']) is dict and
         kb.sha(record['version_id']) and kb.sha(record['local_mac_sha256']),
         'RECORD_HEADER_INVALID', 'unavailable')
    body = exact(record['body'], {
        'store_scope_binding_sha256', 'snapshot_version', 'snapshot_manifest_sha256',
        'snapshot_chapter_sha256', 'chapter_path', 'save_key', 'request_binding_sha256',
        'authorization_scope_sha256', 'parent_version_id', 'previous_content_sha256',
        'content_sha256', 'content_base64', 'section_index', 'before_section_sha256',
        'after_section_sha256', 'section_ref', 'save_request', 'ec207_selection_binding_sha256',
        'ec207_ai_input_sha256', 'candidate_keys', 'candidate_record_ids',
        'review_summary', 'approvals', 'permission_receipt_sha256', 'saved_at_utc'},
        'RECORD_BODY_FIELDS_INVALID')
    need(body['store_scope_binding_sha256'] == manifest['store_scope_binding_sha256'] and
         body['snapshot_version'] == manifest['baseline_snapshot_version'] and
         body['snapshot_manifest_sha256'] == manifest['baseline_manifest_sha256'] and
         body['snapshot_chapter_sha256'] == manifest['baseline_chapter_sha256'] and
         body['chapter_path'] == manifest['chapter_path'] and
         body['parent_version_id'] == parent_id and
         body['previous_content_sha256'] == raw_sha(parent_bytes) and
         kb.sha(body['request_binding_sha256']) and
         kb.sha(body['authorization_scope_sha256']) and
         kb.sha(body['ec207_selection_binding_sha256']) and
         kb.sha(body['ec207_ai_input_sha256']) and
         kb.sha(body['permission_receipt_sha256']) and
         type(body['save_key']) is str and kc.CANDIDATE_KEY.fullmatch(body['save_key']) is not None and
         type(body['review_summary']) is str and
         0 < len(body['review_summary'].encode('utf-8', 'strict')) <= MAX_SUMMARY_BYTES,
         'RECORD_SCOPE_OR_PARENT_MISMATCH', 'unavailable')
    need(type(body['candidate_keys']) is list and body['candidate_keys'] and
         body['candidate_keys'] == sorted(set(body['candidate_keys'])) and
         len(body['candidate_keys']) <= kh.MAX_CANDIDATES and
         all(type(x) is str and kc.CANDIDATE_KEY.fullmatch(x) is not None for x in body['candidate_keys']) and
         type(body['candidate_record_ids']) is list and
         len(body['candidate_record_ids']) == len(body['candidate_keys']) and
         all(kb.sha(x) for x in body['candidate_record_ids']),
         'RECORD_CANDIDATE_PINS_INVALID', 'unavailable')
    # Crucial: retain the WHOLE exact approved request. Otherwise a local owner
    # with access to the HMAC key could substitute different version bytes while
    # keeping an authentic signature on an orphaned authorization SHA. Recompute
    # the signed authorization scope and replacement transformation on replay.
    req, replacement = _request(canonical(body['save_request']), api)
    need(body['request_binding_sha256'] == digest('EXACT-SAVE-REQUEST', req) and
         body['authorization_scope_sha256'] == _auth_scope(manifest, req) and
         req['expected_snapshot_version'] == manifest['baseline_snapshot_version'] and
         req['expected_manifest_sha256'] == manifest['baseline_manifest_sha256'] and
         req['expected_baseline_chapter_sha256'] == manifest['baseline_chapter_sha256'] and
         req['expected_parent_version_id'] == parent_id and
         req['expected_parent_content_sha256'] == raw_sha(parent_bytes) and
         req['save_key'] == body['save_key'] and
         req['section_index'] == body['section_index'] and
         req['expected_section_sha256'] == body['before_section_sha256'] and
         req['replacement_section_sha256'] == body['after_section_sha256'] and
         req['section_ref'] == body['section_ref'] and
         req['selection_binding_sha256'] == body['ec207_selection_binding_sha256'] and
         req['ai_input_sha256'] == body['ec207_ai_input_sha256'] and
         req['candidate_keys'] == body['candidate_keys'] and
         req['candidate_record_ids'] == body['candidate_record_ids'] and
         req['review_summary'] == body['review_summary'] and
         req['save_permission_receipt_sha256'] == body['permission_receipt_sha256'],
         'RECORD_SIGNED_REQUEST_OR_AUTHORIZATION_UNBOUND', 'unavailable')
    content = decode_b64(body['content_base64'], MAX_MARKDOWN, 'RECORD_CONTENT_INVALID')
    need(body['content_sha256'] == raw_sha(content), 'RECORD_CONTENT_HASH_INVALID', 'unavailable')
    need(kb.sha(body['before_section_sha256']) and kb.sha(body['after_section_sha256']) and
         (body['section_ref'] is None or
          (type(body['section_ref']) is str and kc.SECTION.fullmatch(body['section_ref']) is not None)),
         'RECORD_SECTION_FINGERPRINT_INVALID', 'unavailable')
    need(content == _compose_checked(req, replacement, parent_bytes, parent_id),
         'RECORD_CONTENT_NOT_DERIVED_FROM_SIGNED_REQUEST', 'unavailable')
    need(record['version_id'] == digest('IMMUTABLE-VERSION', {'sequence': number, 'body': body}) and
         hmac.compare_digest(record['local_mac_sha256'], _mac(manifest, {
             'schema': RECORD_SCHEMA, 'sequence': number,
             'version_id': record['version_id'], 'body': body})),
         'RECORD_ID_OR_MAC_INVALID', 'unavailable')
    saved = _time(body['saved_at_utc'])
    _verify_approvals(api, body['approvals'], body['authorization_scope_sha256'], saved)
    return content


def _load_versions(api: 'KnowledgeVersionSave', fd: int,
                   manifest: dict[str, Any], baseline: bytes) -> list[dict[str, Any]]:
    names = os.listdir(fd)
    need(len(names) <= MAX_VERSIONS and all(type(name) is str and VERSION_NAME.fullmatch(name)
         for name in names), 'VERSION_LAYOUT_OR_CAPACITY_INVALID', 'unavailable')
    need(sorted(names) == [_filename(i) for i in range(1, len(names) + 1)],
         'VERSION_SEQUENCE_GAP_OR_CONFLICT', 'unavailable')
    out: list[dict[str, Any]] = []
    parent_id: str | None = None
    content = baseline
    used_keys: set[str] = set()
    for seq, name in enumerate(sorted(names), 1):
        try:
            record = fs._load_json(fd, name, MAX_RECORD)
        except fs.EvidenceGateError as exc:
            raise SaveError('VERSION_RECORD_UNSAFE_' + exc.reason, 'unavailable') from exc
        try:
            content = _validate_record(api, manifest, record, seq, parent_id, content)
        except SaveError as exc:
            raise SaveError('STORED_VERSION_INVALID_' + exc.reason, 'unavailable') from exc
        key = record['body']['save_key']
        need(key not in used_keys, 'VERSION_DUPLICATE_SAVE_KEY', 'unavailable')
        used_keys.add(key)
        parent_id = record['version_id']
        out.append(record)
    return out


def _compose_checked(req: dict[str, Any], replacement: bytes,
                     before: bytes, parent_id: str | None) -> bytes:
    need(req['expected_parent_version_id'] == parent_id and
         req['expected_parent_content_sha256'] == raw_sha(before),
         'OPTIMISTIC_PARENT_VERSION_CONFLICT', 'unavailable')
    spans = _parts(before)
    idx = req['section_index']
    need(idx < len(spans) and spans[idx]['sha256'] == req['expected_section_sha256'],
         'OPTIMISTIC_SECTION_FINGERPRINT_CONFLICT', 'unavailable')
    piece = spans[idx]
    after = before[:piece['start']] + replacement + before[piece['end']:]
    need(len(after) <= MAX_MARKDOWN and raw_sha(after) == req['expected_new_chapter_sha256'],
         'NEW_CHAPTER_DIGEST_OR_SIZE_MISMATCH', 'unavailable')
    _check_replacement(before, after, idx,
                       req['expected_section_sha256'], req['replacement_section_sha256'])
    return after


def _check_replacement(before: bytes, after: bytes, index: Any,
                       expected_before: str, expected_after: str) -> None:
    original = _parts(before)
    changed = _parts(after)
    need(type(index) is int and 0 <= index < len(original),
         'SECTION_INDEX_NOT_IN_CURRENT_CHAPTER', 'unavailable')
    need(len(original) == len(changed), 'SECTION_STRUCTURE_CHANGED', 'unavailable')
    a, b = original[index], changed[index]
    need(a['sha256'] == expected_before and b['sha256'] == expected_after and
         expected_before != expected_after and
         a['heading'] == b['heading'] and a['level'] == b['level'] and
         before[:a['start']] == after[:b['start']] and
         before[a['end']:] == after[b['end']:] and
         all(before[s['start']:s['end']] == after[t['start']:t['end']]
             for j, (s, t) in enumerate(zip(original, changed)) if j != index),
         'SECTION_SCOPE_OR_FINGERPRINT_CONFLICT', 'unavailable')


def _request(raw: str, api: 'KnowledgeVersionSave') -> tuple[dict[str, Any], bytes]:
    doc = exact(decode_json(raw, MAX_REQUEST), {
        'schema', 'operation', 'save_key', 'repository_ref', 'knowledge_space_key',
        'period_id', 'source_policy_revision', 'chapter_path',
        'expected_snapshot_version', 'expected_manifest_sha256',
        'expected_baseline_chapter_sha256', 'expected_parent_version_id',
        'expected_parent_content_sha256', 'section_index', 'expected_section_sha256',
        'section_ref', 'ec202_knowledge_source_binding_sha256', 'save_permission_receipt_sha256',
        'replacement_section_base64', 'replacement_section_sha256',
        'expected_new_chapter_sha256', 'selection_binding_sha256', 'ai_input_sha256',
        'candidate_keys', 'candidate_record_ids', 'review_summary'},
        'REQUEST_FIELDS_INVALID')
    need(doc['schema'] == REQUEST_SCHEMA and doc['operation'] == 'knowledge.save.metadata_version' and
         type(doc['save_key']) is str and kc.CANDIDATE_KEY.fullmatch(doc['save_key']) is not None and
         doc['repository_ref'] == api.store.repository_ref and
         doc['knowledge_space_key'] == api.store.knowledge_space_key and
         doc['period_id'] == api.store.period_id and
         doc['source_policy_revision'] == api.store.source_policy_revision and
         doc['chapter_path'] == api.chapter_path,
         'REQUEST_SCOPE_OR_OPERATION_INVALID', 'unavailable')
    need(type(doc['expected_snapshot_version']) is str and kb.key(doc['expected_snapshot_version']) and
         all(kb.sha(doc[k]) for k in ('expected_manifest_sha256',
             'expected_baseline_chapter_sha256', 'expected_parent_content_sha256',
             'expected_section_sha256', 'replacement_section_sha256',
             'expected_new_chapter_sha256', 'selection_binding_sha256', 'ai_input_sha256',
             'save_permission_receipt_sha256')) and
         (doc['expected_parent_version_id'] is None or kb.sha(doc['expected_parent_version_id'])) and
         (doc['section_ref'] is None or
             (type(doc['section_ref']) is str and kc.SECTION.fullmatch(doc['section_ref']) is not None)) and
         (doc['ec202_knowledge_source_binding_sha256'] is None or
             kb.sha(doc['ec202_knowledge_source_binding_sha256'])) and
         ((doc['section_ref'] is None) ==
          (doc['ec202_knowledge_source_binding_sha256'] is None)) and
         type(doc['section_index']) is int and 0 <= doc['section_index'] < chapters.MAX_SECTIONS,
         'REQUEST_VERSION_OR_SECTION_BINDING_INVALID')
    keys = doc['candidate_keys']
    record_ids = doc['candidate_record_ids']
    need(type(keys) is list and 1 <= len(keys) <= kh.MAX_CANDIDATES and
         keys == sorted(set(keys)) and
         all(type(key) is str and kc.CANDIDATE_KEY.fullmatch(key) is not None for key in keys) and
         type(record_ids) is list and len(record_ids) == len(keys) and
         all(kb.sha(v) for v in record_ids), 'REQUEST_CANDIDATE_PINS_INVALID')
    summary = doc['review_summary']
    need(type(summary) is str and summary.strip() and
         len(summary.encode('utf-8', 'strict')) <= MAX_SUMMARY_BYTES and
         not any((ord(ch) < 32 and ch not in ('\t', '\n')) or
                     ord(ch) == 127 or 0xd800 <= ord(ch) <= 0xdfff for ch in summary),
         'REVIEW_SUMMARY_INVALID')
    replacement = decode_b64(doc['replacement_section_base64'], MAX_MARKDOWN,
                             'REPLACEMENT_SECTION_ENCODING_INVALID')
    need(raw_sha(replacement) == doc['replacement_section_sha256'] and
         not kh._restricted_text(summary) and
         not kh._restricted_text(replacement.decode('utf-8', 'strict')),
         'REPLACEMENT_DIGEST_OR_SENSITIVE_CREDENTIAL_DENIED', 'unavailable')
    return doc, replacement


def _policy(raw: str, manifest: dict[str, Any], binding: str,
            restricted: bool, permission_receipt: str) -> dict[str, Any]:
    p = exact(decode_json(raw, MAX_POLICY), {
        'schema', 'purpose', 'store_instance_id', 'store_scope_binding_sha256',
        'authorization_scope_sha256', 'permission_receipt_sha256',
        'permit_local_version_append', 'permit_reviewed_text_local_persistence',
        'permit_restricted_local_persistence', 'permit_source_knowledge_overwrite',
        'permit_business_repository_write', 'permit_issue_or_provider_write',
        'permit_publish'}, 'POLICY_FIELDS_INVALID')
    need(p['schema'] == POLICY_SCHEMA and p['purpose'] == PURPOSE and
         p['store_instance_id'] == manifest['instance_id'] and
         p['store_scope_binding_sha256'] == manifest['store_scope_binding_sha256'] and
         p['authorization_scope_sha256'] == binding and
         p['permission_receipt_sha256'] == permission_receipt and
         kb.sha(p['permission_receipt_sha256']),
         'POLICY_SCOPE_OR_RECEIPT_MISMATCH', 'unavailable')
    flag_names = [k for k in p if k.startswith('permit_')]
    need(all(type(p[k]) is bool for k in flag_names) and
         p['permit_local_version_append'] and p['permit_reviewed_text_local_persistence'] and
         (not restricted or p['permit_restricted_local_persistence']) and
         not any(p[k] for k in ('permit_source_knowledge_overwrite',
             'permit_business_repository_write', 'permit_issue_or_provider_write',
             'permit_publish')), 'POLICY_PERMISSION_DENIED_OR_ESCALATION', 'unavailable')
    return p


def _auth_scope(manifest: dict[str, Any], request: dict[str, Any]) -> str:
    return digest('SAVE-AUTHORIZATION', {
        'purpose': PURPOSE, 'store_instance_id': manifest['instance_id'],
        'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
        'approver_registry_sha256': manifest['approver_registry_sha256'],
        'snapshot_manifest_sha256': manifest['baseline_manifest_sha256'],
        'snapshot_chapter_sha256': manifest['baseline_chapter_sha256'],
        'request_binding_sha256': digest('EXACT-SAVE-REQUEST', request),
    })


class KnowledgeVersionSave:
    """Pinned one-chapter, one-host private metadata version append adapter.

    Caller config for trusted_approvers: {'reviewer-id': {'role':
    'independent_reviewer', 'public_key': bytes32}, 'owner-id': {...}}.
    This config is an input of trust, not an independently certified identity.
    """

    def __init__(self, *, root: str, store_id: str, candidate_store: kc.KnowledgeCandidateStore,
                 chapter_path: str, trusted_approvers: dict[str, dict[str, Any]],
                 revoked_approvers: set[str] | frozenset[str] = frozenset()) -> None:
        need(isinstance(candidate_store, kc.KnowledgeCandidateStore), 'EC206_STORE_REQUIRED')
        need(type(store_id) is str and kc.STORE_ID.fullmatch(store_id) is not None,
             'STORE_ID_INVALID')
        self.root, self.store_id = root, store_id
        self.store = candidate_store
        self.chapter_path = _path(chapter_path)
        need(type(trusted_approvers) is dict and 2 <= len(trusted_approvers) <= 32,
             'TRUSTED_APPROVER_REGISTRY_INVALID')
        self.trusted_approvers: dict[str, dict[str, Any]] = {}
        for key, detail in trusted_approvers.items():
            need(kb.key(key) and type(detail) is dict and set(detail) == {'role', 'public_key'} and
                 detail['role'] in ROLES and type(detail['public_key']) is bytes and
                 len(detail['public_key']) == 32, 'TRUSTED_APPROVER_KEY_OR_ROLE_INVALID')
            self.trusted_approvers[key] = dict(detail)
        need(type(revoked_approvers) in (set, frozenset) and
             all(key in self.trusted_approvers for key in revoked_approvers),
             'REVOKED_APPROVER_SET_INVALID')
        self.revoked_approvers = frozenset(revoked_approvers)
        need(all(any(x['role'] == role and key not in self.revoked_approvers
                     for key, x in self.trusted_approvers.items()) for role in ROLES),
             'EACH_ROLE_REQUIRES_ACTIVE_TRUSTED_KEY')
        # Populated on every entry from independently reopened EC206 store.
        self._candidate_instance_id = ''
        self._candidate_scope_sha = ''
        self._knowledge_root_id: dict[str, int] = {}

    def _disjoint(self) -> None:
        fs._root_components(self.root)
        protected = (self.store.repository_root, self.store.knowledge_root, self.store.root)
        root = os.path.realpath(self.root)
        for path in protected:
            other = os.path.realpath(path)
            need(os.path.commonpath((root, other)) not in (root, other),
                 'METADATA_ROOT_OVERLAPS_PROTECTED_ROOT', 'unavailable')

    def _pins(self) -> None:
        self._disjoint()
        with self.store._open() as (candidate_manifest, _, _):
            self._candidate_instance_id = candidate_manifest['instance_id']
            self._candidate_scope_sha = candidate_manifest['scope_binding_sha256']
        self._knowledge_root_id = _root_id(self.store.knowledge_root)

    @contextmanager
    def _open(self, *, write: bool = False) -> Iterator[tuple[dict[str, Any], int, int]]:
        self._pins()
        try:
            with fs._opened_root(self.root) as root_fd:
                need(set(os.listdir(root_fd)) == {'manifest.json', 'transaction.lock', 'versions'},
                     'STORE_LAYOUT_UNKNOWN_OR_UNINITIALIZED', 'unavailable')
                manifest = fs._load_json(root_fd, 'manifest.json', 8192)
                _check_manifest(self, manifest, root_fd)
                lock_fd = os.open('transaction.lock', fs.FILE_FLAGS, dir_fd=root_fd)
                version_fd = -1
                try:
                    st = os.fstat(lock_fd)
                    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                         st.st_mode & 0o077 == 0 and st.st_nlink == 1 and st.st_size == 0,
                         'TRANSACTION_LOCK_UNSAFE', 'unavailable')
                    version_fd = os.open('versions', fs.DIR_FLAGS, dir_fd=root_fd)
                    fs._private_dir(version_fd, reason='VERSION_DIRECTORY_NOT_PRIVATE')
                    fs.fcntl.flock(lock_fd, fs.fcntl.LOCK_EX if write else fs.fcntl.LOCK_SH)
                    try:
                        _check_manifest(self, manifest, root_fd)
                        need(fs._root_pinned(self.root, root_fd),
                             'METADATA_ROOT_REPLACED', 'unavailable')
                        yield manifest, version_fd, root_fd
                    finally:
                        fs.fcntl.flock(lock_fd, fs.fcntl.LOCK_UN)
                finally:
                    if version_fd >= 0:
                        os.close(version_fd)
                    os.close(lock_fd)
        except fs.EvidenceGateError as exc:
            raise SaveError('POSIX_PRIVATE_GATE_' + exc.reason, 'unavailable') from exc
        except OSError:
            raise SaveError('LOCAL_METADATA_IO_UNAVAILABLE', 'unavailable') from None

    def initialize(self, *, allow_initialize: bool = False) -> dict[str, Any]:
        """Explicit creation in preexisting empty 0700 metadata root only."""
        try:
            need(type(allow_initialize) is bool and allow_initialize,
                 'INITIALIZATION_REQUIRES_EXPLICIT_ALLOW', 'unavailable')
            self._pins()
            baseline = _snapshot(self)
            _root_id(self.store.repository_root)
            with fs._opened_root(self.root) as root_fd:
                need(not os.listdir(root_fd), 'STORE_NOT_EMPTY', 'unavailable')
                manifest = {
                    'schema': MANIFEST_SCHEMA, 'store_id': self.store_id,
                    'instance_id': str(uuid.uuid4()), 'root_path': self.root,
                    'repository_ref': self.store.repository_ref,
                    'knowledge_space_key': self.store.knowledge_space_key,
                    'period_id': self.store.period_id,
                    'source_policy_revision': self.store.source_policy_revision,
                    'repository_root_identity': _root_id(self.store.repository_root),
                    'knowledge_root_identity': baseline['root_identity'],
                    'metadata_root_identity': {'dev': os.fstat(root_fd).st_dev,
                                               'ino': os.fstat(root_fd).st_ino},
                    'candidate_store_instance_id': self._candidate_instance_id,
                    'candidate_store_scope_binding_sha256': self._candidate_scope_sha,
                    'chapter_path': self.chapter_path,
                    'baseline_snapshot_version': baseline['snapshot_version'],
                    'baseline_manifest_sha256': baseline['manifest_sha256'],
                    'baseline_chapter_sha256': baseline['content_sha256'],
                    'baseline_chapter_size': len(baseline['content']),
                    'approver_registry_sha256': digest('APPROVER-REGISTRY', _registry_config(self)),
                    'local_integrity_key_hex': secrets.token_hex(32),
                }
                manifest['store_scope_binding_sha256'] = digest('STORE-SCOPE', _store_scope(manifest))
                need(fs._root_pinned(self.root, root_fd),
                     'METADATA_ROOT_REPLACED_BEFORE_INITIALIZATION', 'unavailable')
                os.mkdir('versions', 0o700, dir_fd=root_fd)
                fs._write_new(root_fd, 'transaction.lock', b'')
                fs._write_new(root_fd, 'manifest.json', (canonical(manifest) + '\n').encode('ascii'))
                os.fsync(root_fd)
            return response('partial', 'PRIVATE_VERSION_STORE_INITIALIZED', subject={
                'store_instance_id': manifest['instance_id'],
                'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
                'baseline_snapshot_version': baseline['snapshot_version'],
                'baseline_manifest_sha256': baseline['manifest_sha256'],
                'baseline_chapter_sha256': baseline['content_sha256'],
                'version_count': 0, 'save_permission_granted': False}, initialized=True)
        except (SaveError, kc.CandidateError) as exc:
            return response(exc.status, exc.reason)
        except (OSError, ValueError, TypeError, UnicodeError, OverflowError) as exc:
            return response('unavailable', 'INITIALIZATION_UNAVAILABLE_OR_OUTCOME_UNKNOWN')

    def _handoff(self, handoff_request_json: str, handoff_policy_json: str,
                 candidate_read_policies_json: str) -> dict[str, Any]:
        handoff = kh.KnowledgeUpdateHandoff(self.store).prepare(
            request_json=handoff_request_json, handoff_policy_json=handoff_policy_json,
            candidate_read_policies_json=candidate_read_policies_json)
        need(handoff['status'] == 'partial' and handoff['subject'] is not None,
             'EC207_HANDOFF_NOT_AUTHORIZED_OR_UNAVAILABLE', 'unavailable')
        return handoff['subject']

    def _context(self, req: dict[str, Any], manifest: dict[str, Any],
                 baseline: dict[str, Any], versions: list[dict[str, Any]],
                 handoff: dict[str, Any]) -> tuple[bytes, str | None, bool]:
        need(baseline['snapshot_version'] == manifest['baseline_snapshot_version'] and
             baseline['manifest_sha256'] == manifest['baseline_manifest_sha256'] and
             baseline['content_sha256'] == manifest['baseline_chapter_sha256'] and
             len(baseline['content']) == manifest['baseline_chapter_size'],
             'AUTHORITATIVE_KNOWLEDGE_BASELINE_DRIFT', 'unavailable')
        need(req['expected_snapshot_version'] == baseline['snapshot_version'] and
             req['expected_manifest_sha256'] == baseline['manifest_sha256'] and
             req['expected_baseline_chapter_sha256'] == baseline['content_sha256'],
             'REQUEST_EXPECTED_SNAPSHOT_STALE', 'unavailable')
        need(req['selection_binding_sha256'] == handoff['selection_binding_sha256'] and
             req['ai_input_sha256'] == handoff['ai_input_sha256'],
             'EC207_DRAFT_OR_SELECTION_PIN_MISMATCH', 'unavailable')
        evidence = handoff['ai_input']['candidate_evidence']
        need(req['candidate_keys'] == [r['candidate_key'] for r in evidence] and
             req['candidate_record_ids'] == [r['record_id'] for r in evidence],
             'CANDIDATE_RECORD_SELECTION_MISMATCH', 'unavailable')
        section_refs = {row['section_ref'] for row in evidence if row['section_ref'] is not None}
        need(not section_refs or section_refs == {req['section_ref']},
             'EC205_SECTION_REFERENCE_MISMATCH', 'unavailable')
        # EC205 computes its section ref from the EC202 knowledge-source
        # binding and bytes of a specific ordinal. EC206 only retained the
        # opaque section ref; require a fresh explicit witness here. This
        # proves internal SHA consistency, NOT the organizational truth of
        # a caller-supplied original EC202 source binding.
        if req['section_ref'] is not None:
            # The baseline source must be the witness target, not a later
            # locally saved draft whose ordinal SHA has legitimately changed.
            original_sections = _parts(baseline['content'])
            need(req['section_index'] < len(original_sections),
                 'EC205_BASELINE_ORDINAL_UNAVAILABLE', 'unavailable')
            expected_ref = 'cesksection1:' + kb.digest('CES-EC205-SECTION-v1', {
                'scope_binding_sha256': handoff['ai_input']['source_scope']['scope_binding_sha256'],
                'source_binding_sha256': req['ec202_knowledge_source_binding_sha256'],
                'ordinal': req['section_index'],
                'bytes_sha256': original_sections[req['section_index']]['sha256'],
            })
            need(expected_ref == req['section_ref'],
                 'EC205_SECTION_WITNESS_NOT_BASELINE_BOUND', 'unavailable')
        restricted = handoff['restricted_candidate_count'] > 0
        parent = versions[-1] if versions else None
        parent_id = parent['version_id'] if parent else None
        parent_bytes = (decode_b64(parent['body']['content_base64'], MAX_MARKDOWN,
                     'VERSION_CONTENT_INVALID') if parent else baseline['content'])
        return parent_bytes, parent_id, restricted

    def _build_new(self, req: dict[str, Any], replacement: bytes,
                   parent_bytes: bytes, parent_id: str | None) -> bytes:
        return _compose_checked(req, replacement, parent_bytes, parent_id)

    def _plan(self, request_json: str, handoff_request_json: str,
              handoff_policy_json: str, candidate_read_policies_json: str
              ) -> tuple[dict[str, Any], dict[str, Any]]:
        # Metadata lock held over all load/check/write steps. The EC206 store
        # is immutable, re-read with its own lock on EACH preview/save.
        req, replacement = _request(request_json, self)
        with self._open() as (manifest, version_fd, root_fd):
            baseline = _snapshot(self)
            need(baseline['content_sha256'] == manifest['baseline_chapter_sha256'],
                 'KNOWLEDGE_BASELINE_CONTENT_DRIFT', 'unavailable')
            versions = _load_versions(self, version_fd, manifest, baseline['content'])
            handoff = self._handoff(handoff_request_json, handoff_policy_json,
                                    candidate_read_policies_json)
            parent_bytes, parent_id, restricted = self._context(
                req, manifest, baseline, versions, handoff)
            binding = _auth_scope(manifest, req)
            existing = next((r for r in versions if r['body']['save_key'] == req['save_key']), None)
            if existing:
                need(existing['body']['request_binding_sha256'] == digest('EXACT-SAVE-REQUEST', req) and
                     existing['body']['authorization_scope_sha256'] == binding,
                     'SAVE_KEY_ALREADY_USED_FOR_DIFFERENT_VERSION', 'unavailable')
                return {'state': 'ALREADY_PERSISTED', 'request': req, 'binding': binding,
                        'manifest': manifest, 'existing': existing, 'version_count': len(versions),
                        'restricted': restricted}, {}
            new_bytes = self._build_new(req, replacement, parent_bytes, parent_id)
            need(len(versions) < MAX_VERSIONS, 'VERSION_CAPACITY_REACHED', 'unavailable')
            plan = {'state': 'NEW_VERSION', 'request': req, 'binding': binding,
                    'manifest': manifest, 'version_count': len(versions), 'parent_id': parent_id,
                    'parent_bytes': parent_bytes, 'new_bytes': new_bytes,
                    'restricted': restricted, 'baseline': baseline}
            return plan, {}

    def preview(self, *, request_json: str, handoff_request_json: str,
                handoff_policy_json: str, candidate_read_policies_json: str) -> dict[str, Any]:
        """Read-only exact authorization scope; does not grant write permissions."""
        try:
            plan, _ = self._plan(request_json, handoff_request_json,
                                 handoff_policy_json, candidate_read_policies_json)
            return response('partial', 'EXACT_VERSION_BINDING_PREVIEW_NO_WRITE', subject={
                'store_instance_id': plan['manifest']['instance_id'],
                'store_scope_binding_sha256': plan['manifest']['store_scope_binding_sha256'],
                'authorization_scope_sha256': plan['binding'],
                'save_key': plan['request']['save_key'],
                'state': plan['state'], 'version_count': plan['version_count'],
                'expected_parent_version_id': plan['request']['expected_parent_version_id'],
                'expected_new_chapter_sha256': plan['request']['expected_new_chapter_sha256'],
                'restricted_content': plan['restricted'],
                'write_authorized': False, 'body_disclosed': False})
        except (SaveError, kc.CandidateError) as exc:
            return response(exc.status, exc.reason)
        except (UnicodeError, ValueError, TypeError, OverflowError):
            return response('invalid_input', 'PREVIEW_INPUT_INVALID')

    def save(self, *, request_json: str, handoff_request_json: str,
             handoff_policy_json: str, candidate_read_policies_json: str,
             save_policy_json: str, approvals_json: str) -> dict[str, Any]:
        """Append one version only after complete EC207 grants and two signatures.

        A missing or malformed file after I/O interruption is an UNKNOWN result;
        no cleanup, blind retry or mutation of existing version is attempted.
        """
        try:
            req, replacement = _request(request_json, self)
            with self._open(write=True) as (manifest, version_fd, root_fd):
                baseline = _snapshot(self)
                versions = _load_versions(self, version_fd, manifest, baseline['content'])
                handoff = self._handoff(handoff_request_json, handoff_policy_json,
                                        candidate_read_policies_json)
                parent_bytes, parent_id, restricted = self._context(
                    req, manifest, baseline, versions, handoff)
                binding = _auth_scope(manifest, req)
                policy = _policy(save_policy_json, manifest, binding, restricted,
                                 req['save_permission_receipt_sha256'])
                approved = _verify_approvals(self, decode_json(approvals_json, MAX_APPROVALS),
                                             binding, _clock())
                existing = next((v for v in versions if v['body']['save_key'] == req['save_key']), None)
                if existing is not None:
                    need(existing['body']['request_binding_sha256'] ==
                         digest('EXACT-SAVE-REQUEST', req) and
                         existing['body']['authorization_scope_sha256'] == binding and
                         existing['body']['approvals'] == {'schema': APPROVALS_SCHEMA,
                                                            'statements': approved} and
                         existing['body']['permission_receipt_sha256'] == policy['permission_receipt_sha256'],
                         'SAVE_KEY_ALREADY_USED_WITH_DIFFERENT_PAYLOAD_OR_APPROVAL', 'unavailable')
                    return response('partial', 'ALREADY_SAVED_IDEMPOTENT_NO_WRITE', subject={
                        'save_key': req['save_key'], 'version_id': existing['version_id'],
                        'version_number': existing['sequence'], 'idempotent': True})
                new_bytes = self._build_new(req, replacement, parent_bytes, parent_id)
                need(len(versions) < MAX_VERSIONS, 'VERSION_CAPACITY_REACHED', 'unavailable')
                # Final snapshot and pin recheck BEFORE irreversible O_EXCL.
                check = _snapshot(self)
                need(check['snapshot_version'] == baseline['snapshot_version'] and
                     check['manifest_sha256'] == baseline['manifest_sha256'] and
                     check['content_sha256'] == baseline['content_sha256'] and
                     fs._root_pinned(self.root, root_fd) and
                     manifest['repository_root_identity'] == _root_id(self.store.repository_root),
                     'SNAPSHOT_OR_METADATA_ROOT_CHANGED_BEFORE_APPEND', 'unavailable')
                now = _clock().strftime('%Y-%m-%dT%H:%M:%SZ')
                body = {
                    'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
                    'snapshot_version': baseline['snapshot_version'],
                    'snapshot_manifest_sha256': baseline['manifest_sha256'],
                    'snapshot_chapter_sha256': baseline['content_sha256'],
                    'chapter_path': self.chapter_path, 'save_key': req['save_key'],
                    'request_binding_sha256': digest('EXACT-SAVE-REQUEST', req),
                    'authorization_scope_sha256': binding,
                    'parent_version_id': parent_id,
                    'previous_content_sha256': raw_sha(parent_bytes),
                    'content_sha256': raw_sha(new_bytes),
                    'content_base64': base64.b64encode(new_bytes).decode('ascii'),
                    'section_index': req['section_index'],
                    'before_section_sha256': req['expected_section_sha256'],
                    'after_section_sha256': req['replacement_section_sha256'],
                    'section_ref': req['section_ref'],
                    'save_request': req,
                    'ec207_selection_binding_sha256': req['selection_binding_sha256'],
                    'ec207_ai_input_sha256': req['ai_input_sha256'],
                    'candidate_keys': req['candidate_keys'],
                    'candidate_record_ids': req['candidate_record_ids'],
                    'review_summary': req['review_summary'],
                    'approvals': {'schema': APPROVALS_SCHEMA, 'statements': approved},
                    'permission_receipt_sha256': policy['permission_receipt_sha256'],
                    'saved_at_utc': now,
                }
                seq = len(versions) + 1
                unsigned = {'schema': RECORD_SCHEMA, 'sequence': seq,
                            'version_id': digest('IMMUTABLE-VERSION', {
                                'sequence': seq, 'body': body}), 'body': body}
                record = {**unsigned, 'local_mac_sha256': _mac(manifest, unsigned)}
                raw = (canonical(record) + '\n').encode('ascii')
                need(len(raw) <= MAX_RECORD, 'VERSION_RECORD_TOO_LARGE', 'unavailable')
                # No write after this point except a single create-exclusive version.
                try:
                    fs._write_new(version_fd, _filename(seq), raw)
                    os.fsync(version_fd)
                except OSError:
                    raise SaveError('APPEND_OUTCOME_UNKNOWN_INSPECT_BEFORE_ANY_RETRY',
                                    'unavailable') from None
                return response('partial', 'NEW_IMMUTABLE_LOCAL_VERSION_APPENDED', subject={
                    'save_key': req['save_key'], 'version_number': seq,
                    'version_id': record['version_id'], 'parent_version_id': parent_id,
                    'chapter_content_sha256': body['content_sha256'],
                    'metadata_store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
                    'reviewer_and_owner_signatures_locally_verified': True,
                    'organizational_approval_authority_unverified': True,
                    'source_knowledge_snapshot_untouched': True,
                    'content_projected': False, 'idempotent': False}, version_written=True)
        except (SaveError, kc.CandidateError) as exc:
            return response(exc.status, exc.reason)
        except (UnicodeError, TypeError, ValueError, OverflowError):
            return response('invalid_input', 'SAVE_INPUT_INVALID')

    def inspect(self) -> dict[str, Any]:
        """Read-only integrity-checked local metadata *hashes*, never draft text."""
        try:
            with self._open() as (manifest, fd, _):
                baseline = _snapshot(self)
                need(baseline['manifest_sha256'] == manifest['baseline_manifest_sha256'] and
                     baseline['content_sha256'] == manifest['baseline_chapter_sha256'] and
                     baseline['snapshot_version'] == manifest['baseline_snapshot_version'],
                     'KNOWLEDGE_BASELINE_DRIFT', 'unavailable')
                rows = _load_versions(self, fd, manifest, baseline['content'])
                head = rows[-1] if rows else None
                return response('partial', 'IMMUTABLE_METADATA_VERSIONS_INSPECTED', subject={
                    'store_instance_id': manifest['instance_id'],
                    'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
                    'chapter_path': manifest['chapter_path'],
                    'baseline_snapshot_version': manifest['baseline_snapshot_version'],
                    'baseline_chapter_sha256': manifest['baseline_chapter_sha256'],
                    'version_count': len(rows),
                    'head_version_id': head['version_id'] if head else None,
                    'head_content_sha256': (head['body']['content_sha256'] if head else
                                            baseline['content_sha256']),
                    'version_receipts': [
                        {'sequence': r['sequence'], 'version_id': r['version_id'],
                         'parent_version_id': r['body']['parent_version_id'],
                         'content_sha256': r['body']['content_sha256']}
                        for r in rows],
                    'draft_content_disclosed': False, 'organizational_authority_verified': False,
                })
        except (SaveError, kc.CandidateError) as exc:
            return response(exc.status, exc.reason)
        except (UnicodeError, ValueError, TypeError, OverflowError):
            return response('invalid_input', 'INSPECT_INPUT_INVALID')

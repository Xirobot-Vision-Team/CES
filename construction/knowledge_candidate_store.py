#!/usr/bin/env python3
"""EC206: explicitly authorized, append-only *candidate* knowledge quarantine.

Only owner-private, dedicated POSIX local storage is supported. The upstream
EC204/205 result is caller supplied, structurally cross-checked and pinned by
its canonical byte digest; this module NEVER attests its origin or repeats Git
signature verification. Even an EC205 local signed-target report remains an
unverified candidate, not authoritative CES knowledge or deployment truth.

No API writes to the repository, CES knowledge snapshot, issues or publishers.
No promotion API exists (EC207/208 and native route are separate future work).
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
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
    from . import proposed_pr_evidence_store as fs
except ImportError:
    import knowledge_boundary as kb
    import proposed_pr_evidence_store as fs

SCHEMA = 'ces.knowledge_candidate_store.v1'
PROPOSAL_SCHEMA = 'ces.knowledge_candidate_proposal.v1'
APPEND_POLICY_SCHEMA = 'ces.knowledge_candidate_append_policy.v1'
READ_POLICY_SCHEMA = 'ces.knowledge_candidate_read_policy.v1'
LIST_POLICY_SCHEMA = 'ces.knowledge_candidate_list_policy.v1'
MANIFEST_SCHEMA = 'ces.knowledge_candidate_store_manifest.v1'
RECORD_SCHEMA = 'ces.knowledge_candidate_record.v1'
APPEND_PURPOSE = 'append_private_candidate_only'
READ_PURPOSE = 'read_private_candidate_only'
LIST_PURPOSE = 'list_private_candidate_keys_only'
MAX_PROPOSAL_BYTES = 16384
MAX_RESULT_BYTES = 1048576
MAX_POLICY_BYTES = 8192
MAX_RECORD_BYTES = 32768
MAX_RECORDS = 256
KEY = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
STORE_ID = re.compile(r'[a-z][a-z0-9_-]{2,47}\Z', re.ASCII)
CANDIDATE_KEY = re.compile(r'[a-z][a-z0-9._-]{2,63}\Z', re.ASCII)
SECTION = re.compile(r'cesksection1:[0-9a-f]{64}\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
FILE = re.compile(r'([0-9a-f]{64})\.json\Z', re.ASCII)
ORIGINS = frozenset({'ec205_chapter_mapping', 'ec204_selected_change', 'manual_proposal'})
SENSITIVITIES = frozenset({'INTERNAL', 'RESTRICTED'})


class CandidateError(ValueError):
    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def need(ok: bool, reason: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise CandidateError(reason, status)


def _canonical(value: Any) -> str:
    return kb.canonical(value)


def _digest(domain: str, value: Any) -> str:
    return kb.digest('CES-EC206-' + domain + '-v1', value)


def _json(value: str, limit: int) -> dict[str, Any]:
    try:
        return kb._json(value, limit)
    except kb.KnowledgeBoundaryError as exc:
        raise CandidateError('NONCANONICAL_OR_INVALID_JSON_' + exc.reason) from exc


def _fields(value: Any, names: set[str], code: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == names, code)
    return value


def _bool_fields(obj: dict[str, Any], names: tuple[str, ...]) -> None:
    need(all(type(obj[n]) is bool for n in names), 'POLICY_BOOLEAN_TYPE_INVALID')


def _safe_text(value: Any, limit: int, code: str) -> None:
    need(type(value) is str and value.strip() and len(value.encode('utf-8', 'surrogatepass')) <= limit
         and not any((ord(ch) < 32 and ch not in '\t\n') or
                     0xd800 <= ord(ch) <= 0xdfff or ord(ch) == 127 for ch in value), code)


def _error_response(error: CandidateError) -> dict[str, Any]:
    return _response(error.status, error.reason)


def _response(status: str, reason: str, *, subject: Any = None,
              candidate_write: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'invalid_input': 4, 'unavailable': 5}[status],
        'reason_code': 'KNOWLEDGE_CANDIDATE_' + reason,
        'subject': subject,
        'local_candidate_write_performed': candidate_write,
        'authoritative_knowledge_write_performed': False,
        'repository_or_issue_write_performed': False,
        'publish_or_promotion_performed': False,
        'candidate_is_authoritative': False,
        'source_result_authenticated_by_store': False,
        'organizational_authorization_verified': False,
        'native_knowledge_route_registered': False,
    }


def _root_stat(path: str) -> dict[str, int]:
    need(type(path) is str, 'ROOT_PATH_INVALID')
    try:
        fs._root_components(path)
        st = os.stat(path)
        need(stat.S_ISDIR(st.st_mode), 'SOURCE_ROOT_NOT_DIRECTORY', 'unavailable')
        return {'dev': st.st_dev, 'ino': st.st_ino}
    except fs.EvidenceGateError as exc:
        raise CandidateError('ROOT_PATH_NOT_CANONICAL_' + exc.reason) from exc
    except OSError:
        raise CandidateError('SOURCE_ROOT_UNAVAILABLE', 'unavailable') from None


def _disjoint(candidate_root: str, repository_root: str, knowledge_root: str) -> None:
    # Check both directions, including aliases and nested paths. A parent of an
    # authoritative root is not a safe candidate area either.
    candidate = os.path.realpath(candidate_root)
    for protected in (os.path.realpath(repository_root), os.path.realpath(knowledge_root)):
        need(os.path.commonpath((candidate, protected)) not in (candidate, protected),
             'PRIVATE_ROOT_OVERLAPS_AUTHORITATIVE_SOURCE', 'unavailable')


def _scope(manifest: dict[str, Any]) -> dict[str, Any]:
    return {k: manifest[k] for k in ('store_id', 'instance_id', 'root_path',
             'repository_ref', 'knowledge_space_key', 'period_id',
             'source_policy_revision', 'repository_root_identity', 'knowledge_root_identity')}


def _check_manifest(obj: dict[str, Any], root: str, store_id: str,
                    repository_root: str, knowledge_root: str,
                    repository_ref: str, knowledge_space_key: str, period_id: str,
                    source_policy_revision: str, root_fd: int) -> None:
    _fields(obj, {'schema', 'store_id', 'instance_id', 'root_path',
        'repository_ref', 'knowledge_space_key', 'period_id', 'source_policy_revision',
        'repository_root', 'knowledge_root', 'repository_root_identity',
        'knowledge_root_identity', 'candidate_root_identity', 'scope_binding_sha256',
        'local_integrity_key_hex'}, 'STORE_MANIFEST_FIELDS_INVALID')
    need(obj['schema'] == MANIFEST_SCHEMA and obj['store_id'] == store_id and
         obj['root_path'] == root and obj['repository_root'] == repository_root and
         obj['knowledge_root'] == knowledge_root and
         obj['repository_ref'] == repository_ref and
         obj['knowledge_space_key'] == knowledge_space_key and
         obj['period_id'] == period_id and obj['source_policy_revision'] == source_policy_revision,
         'STORE_SCOPE_MISMATCH', 'unavailable')
    try:
        inst = uuid.UUID(obj['instance_id'])
        need(inst.version == 4 and str(inst) == obj['instance_id'], 'STORE_INSTANCE_INVALID', 'unavailable')
    except (AttributeError, TypeError, ValueError):
        raise CandidateError('STORE_INSTANCE_INVALID', 'unavailable') from None
    need(type(obj['local_integrity_key_hex']) is str and HEX.fullmatch(obj['local_integrity_key_hex']) is not None,
         'STORE_INTEGRITY_KEY_INVALID', 'unavailable')
    need(obj['repository_root_identity'] == _root_stat(repository_root) and
         obj['knowledge_root_identity'] == _root_stat(knowledge_root) and
         obj['candidate_root_identity'] == {'dev': os.fstat(root_fd).st_dev,
                                            'ino': os.fstat(root_fd).st_ino},
         'STORE_ROOT_IDENTITY_DRIFT', 'unavailable')
    _disjoint(root, repository_root, knowledge_root)
    need(obj['scope_binding_sha256'] == _digest('STORE-SCOPE', _scope(obj)),
         'STORE_SCOPE_DIGEST_MISMATCH', 'unavailable')


def _candidate_filename(candidate_key: str) -> str:
    return hashlib.sha256(b'CES-EC206-CANDIDATE-KEY-v1\0' + candidate_key.encode('ascii')).hexdigest() + '.json'


def _mac(manifest: dict[str, Any], value: dict[str, Any]) -> str:
    return hmac.new(bytes.fromhex(manifest['local_integrity_key_hex']),
                    b'CES-EC206-LOCAL-INTEGRITY-v1\0' + _canonical(value).encode('ascii'),
                    hashlib.sha256).hexdigest()


def _load_records(fd: int, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    names = os.listdir(fd)
    need(len(names) <= MAX_RECORDS and all(type(n) is str and FILE.fullmatch(n) for n in names),
         'STORE_RECORD_LAYOUT_OR_CAPACITY_INVALID', 'unavailable')
    all_records: dict[str, dict[str, Any]] = {}
    for filename in sorted(names):
        try:
            record = fs._load_json(fd, filename, MAX_RECORD_BYTES)
        except fs.EvidenceGateError as exc:
            raise CandidateError('STORE_RECORD_UNSAFE_' + exc.reason, 'unavailable') from exc
        need(type(record) is dict and set(record) == {'schema', 'record_id', 'body', 'local_mac_sha256'} and
             record['schema'] == RECORD_SCHEMA and type(record['body']) is dict,
             'STORE_RECORD_INVALID', 'unavailable')
        body = record['body']
        need(set(body) == {'store_scope_binding_sha256', 'candidate_binding_sha256',
             'candidate', 'provenance', 'recorded_at_utc', 'review_state'} and
             body['store_scope_binding_sha256'] == manifest['scope_binding_sha256'] and
             body['review_state'] == 'AWAITING_HUMAN_REVIEW' and
             type(body['candidate']) is dict and type(body['provenance']) is dict,
             'STORE_RECORD_BODY_INVALID', 'unavailable')
        key = body['candidate'].get('candidate_key')
        need(type(key) is str and CANDIDATE_KEY.fullmatch(key) is not None and
             _candidate_filename(key) == filename and key not in all_records and
             body['candidate_binding_sha256'] == _digest('CANDIDATE-BINDING',
                {'candidate': body['candidate'], 'provenance': body['provenance']}) and
             record['record_id'] == _digest('RECORD-ID', body) and
             type(record['local_mac_sha256']) is str and
             hmac.compare_digest(record['local_mac_sha256'], _mac(manifest,
                   {'schema': record['schema'], 'record_id': record['record_id'], 'body': body})),
             'STORE_RECORD_HASH_OR_SCOPE_MISMATCH', 'unavailable')
        all_records[key] = record
    return all_records


@contextmanager
def _store(root: str, store_id: str, repository_root: str, knowledge_root: str,
           repository_ref: str, knowledge_space_key: str, period_id: str,
           source_policy_revision: str, *, write: bool = False) -> Iterator[tuple[dict[str, Any], int, int]]:
    # POSIX nofollow path walk, owner-private directories, hardlink rejection
    # and flock are provided by the already-shipped EC169 gate primitives.
    try:
        with fs._opened_root(root) as root_fd:
            need(set(os.listdir(root_fd)) == {'manifest.json', 'transaction.lock', 'records'},
                 'STORE_NOT_INITIALIZED_OR_UNKNOWN_LAYOUT', 'unavailable')
            manifest = fs._load_json(root_fd, 'manifest.json', 4096)
            _check_manifest(manifest, root, store_id, repository_root, knowledge_root,
                            repository_ref, knowledge_space_key, period_id, source_policy_revision, root_fd)
            lock = os.open('transaction.lock', fs.FILE_FLAGS, dir_fd=root_fd)
            records = -1
            try:
                st = os.fstat(lock)
                need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                     st.st_mode & 0o077 == 0 and st.st_nlink == 1 and st.st_size == 0,
                     'STORE_LOCK_UNSAFE', 'unavailable')
                records = os.open('records', fs.DIR_FLAGS, dir_fd=root_fd)
                fs._private_dir(records, reason='STORE_RECORDS_NOT_PRIVATE')
                fs.fcntl.flock(lock, fs.fcntl.LOCK_EX if write else fs.fcntl.LOCK_SH)
                try:
                    # Recheck identities inside the lock to avoid trusting a
                    # stale manifest after root/scope changes.
                    _check_manifest(manifest, root, store_id, repository_root, knowledge_root,
                                    repository_ref, knowledge_space_key, period_id, source_policy_revision, root_fd)
                    yield manifest, records, root_fd
                finally:
                    fs.fcntl.flock(lock, fs.fcntl.LOCK_UN)
            finally:
                if records >= 0:
                    os.close(records)
                os.close(lock)
    except fs.EvidenceGateError as exc:
        raise CandidateError('PRIVATE_POSIX_GATE_' + exc.reason, 'unavailable') from exc
    except OSError:
        raise CandidateError('STORE_IO_OR_SYMLINK_UNAVAILABLE', 'unavailable') from None


def _proposal(json_text: str, manifest: dict[str, Any], source_result_json: str | None) -> tuple[dict[str, Any], dict[str, Any], str]:
    doc = _fields(_json(json_text, MAX_PROPOSAL_BYTES), {
        'schema', 'candidate_key', 'repository_ref', 'knowledge_space_key',
        'source_policy_revision', 'period_id', 'request_binding_sha256',
        'scope_binding_sha256', 'origin', 'source_key', 'section_ref', 'claim_text', 'reason_text',
        'sensitivity', 'proposer_key', 'proposed_at_utc'}, 'PROPOSAL_FIELDS_INVALID')
    need(doc['schema'] == PROPOSAL_SCHEMA and
         type(doc['candidate_key']) is str and CANDIDATE_KEY.fullmatch(doc['candidate_key']) is not None and
         doc['repository_ref'] == manifest['repository_ref'] and
         doc['knowledge_space_key'] == manifest['knowledge_space_key'] and
         doc['source_policy_revision'] == manifest['source_policy_revision'] and
         doc['period_id'] == manifest['period_id'] and
         type(doc['request_binding_sha256']) is str and HEX.fullmatch(doc['request_binding_sha256']) is not None and
         type(doc['period_id']) is str and KEY.fullmatch(doc['period_id']) is not None and
         type(doc['scope_binding_sha256']) is str and HEX.fullmatch(doc['scope_binding_sha256']) is not None and
         type(doc['source_key']) is str and KEY.fullmatch(doc['source_key']) is not None and
         type(doc['proposer_key']) is str and KEY.fullmatch(doc['proposer_key']) is not None and
         doc['origin'] in ORIGINS and doc['sensitivity'] in SENSITIVITIES,
         'PROPOSAL_SCOPE_OR_IDENTITY_INVALID')
    try:
        kb._time(doc['proposed_at_utc'])
    except kb.KnowledgeBoundaryError as exc:
        raise CandidateError('PROPOSAL_TIME_INVALID') from exc
    _safe_text(doc['claim_text'], 4096, 'PROPOSAL_CLAIM_TEXT_INVALID')
    _safe_text(doc['reason_text'], 1024, 'PROPOSAL_REASON_TEXT_INVALID')
    origin = doc['origin']
    if origin == 'manual_proposal':
        need(doc['section_ref'] is None and source_result_json is None,
             'MANUAL_SOURCE_RESULT_OR_SECTION_NOT_ALLOWED')
        provenance = {'source_result_schema': None, 'source_result_sha256': None,
                      'selection_kind': 'MANUAL_UNVERIFIED_ASSERTION',
                      'reported_delivery_state': 'NO_DELIVERY_EVIDENCE',
                      'reported_selected_change_kind': 'UNKNOWN',
                      'reported_comparison_state': 'UNKNOWN',
                      'source_result_is_caller_supplied': True,
                      'source_result_authenticity_verified': False,
                      'semantic_claim_verified': False}
    else:
        need(type(source_result_json) is str, 'UPSTREAM_RESULT_REQUIRED')
        source = _json(source_result_json, MAX_RESULT_BYTES)
        subject = source.get('subject')
        needed_schema = ('ces.knowledge_chapters.v1' if origin == 'ec205_chapter_mapping'
                         else 'ces.knowledge_impact.v1')
        expected_revision = ('EC205_EXPLICIT_EXISTING_CHAPTER_LINKS_ONLY' if
                             origin == 'ec205_chapter_mapping' else
                             'EC204_ATTESTED_SELECTED_GIT_CHANGE_SET_ONLY')
        need(source.get('schema') == needed_schema and
             type(source.get('limitations')) is dict and
             all(value is False for value in source['limitations'].values()) and
             type(subject) is dict and source.get('canonical_json') == _canonical(subject) and
             subject.get('model_revision') == expected_revision and
             type(source.get('reason_code')) is str and
             source['reason_code'].startswith('KNOWLEDGE_') and source.get('status') == 'partial' and
             source.get('exit_code') == 2 and type(subject) is dict and
             subject.get('repository_ref') == doc['repository_ref'] and
             subject.get('knowledge_space_key') == doc['knowledge_space_key'] and
             subject.get('period_id') == doc['period_id'] and
             subject.get('request_binding_sha256') == doc['request_binding_sha256'] and
             subject.get('scope_binding_sha256') == doc['scope_binding_sha256'] and
             subject.get('verified_delivered_facts') == [] and
             subject.get('no_write_actions_performed') is True,
             'UPSTREAM_RESULT_SCOPE_OR_STATUS_MISMATCH', 'unavailable')
        if origin == 'ec205_chapter_mapping':
            need(type(doc['section_ref']) is str and SECTION.fullmatch(doc['section_ref']) is not None,
                 'CHAPTER_SECTION_REFERENCE_REQUIRED')
            matches = [assoc for item in subject.get('chapter_documents', [])
                       if type(item) is dict and item.get('mapping_state') == 'SELECTED_SNAPSHOT_CHAPTERS_SCANNED'
                       for sec in item.get('sections', []) if type(sec) is dict and
                       sec.get('section_ref') == doc['section_ref']
                       for assoc in sec.get('associations', []) if type(assoc) is dict and
                       assoc.get('source_key') == doc['source_key']]
            need(len(matches) == 1 and type(matches[0].get('manual_review_candidate')) is bool and
                 matches[0].get('semantic_dependency_or_staleness_verified') is False and
                 subject.get('summary', {}).get('knowledge_update_authorized') is False,
                 'CHAPTER_EXPLICIT_SOURCE_LINK_NOT_PRESENT', 'unavailable')
            selected = matches[0]
            need(type(selected.get('selected_git_change_kind')) is str and
                 type(selected.get('selected_git_comparison_state')) is str,
                 'CHAPTER_SOURCE_OBSERVATION_INVALID', 'unavailable')
            kind = 'EXPLICIT_EXISTING_CHAPTER_ASSOCIATION'
            change = selected['selected_git_change_kind']
            comparison = selected['selected_git_comparison_state']
        else:
            need(doc['section_ref'] is None, 'IMPACT_CANNOT_CLAIM_CHAPTER_SECTION')
            matches = [row for row in subject.get('source_changes', [])
                       if type(row) is dict and row.get('kind') == 'repository' and
                       row.get('source_key') == doc['source_key']]
            need(len(matches) == 1 and
                 type(matches[0].get('comparison_state')) is str and
                 type(matches[0].get('change_kind')) is str and
                 subject.get('knowledge_sections_to_update') == [],
                 'IMPACT_SELECTED_SOURCE_NOT_PRESENT', 'unavailable')
            kind = 'SELECTED_GIT_CHANGE_OBSERVATION'
            change = matches[0]['change_kind']
            comparison = matches[0]['comparison_state']
        need(len(change) <= 80 and len(comparison) <= 100 and
             change in ('ADDED', 'MODIFIED', 'MODE_ONLY', 'UNCHANGED', 'UNKNOWN'),
             'UPSTREAM_CHANGE_LABEL_INVALID', 'unavailable')
        delivered = subject.get('target_delivery_state')
        label = ('SUPPLIED_RESULT_REPORTS_SIGNED_LOCAL_TARGET'
                 if delivered == 'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF'
                 else 'NO_VERIFIED_DELIVERY_IN_SUPPLIED_RESULT')
        provenance = {'source_result_schema': needed_schema,
                      'source_result_sha256': hashlib.sha256(source_result_json.encode('ascii')).hexdigest(),
                      'selection_kind': kind, 'reported_delivery_state': label,
                      'reported_selected_change_kind': change,
                      'reported_comparison_state': comparison,
                      'source_result_is_caller_supplied': True,
                      'source_result_authenticity_verified': False,
                      'semantic_claim_verified': False}
    binding = _digest('CANDIDATE-BINDING', {'candidate': doc, 'provenance': provenance})
    return doc, provenance, binding


def _scope_policy(manifest: dict[str, Any], binding: str, operation: str) -> str:
    return _digest('OPERATION-AUTHORIZATION-SCOPE', {
        'scope_binding_sha256': manifest['scope_binding_sha256'],
        'store_instance_id': manifest['instance_id'],
        'candidate_binding_sha256': binding, 'operation': operation})


def _append_policy(text: str, manifest: dict[str, Any], candidate: dict[str, Any], binding: str) -> None:
    policy = _fields(_json(text, MAX_POLICY_BYTES), {'schema', 'purpose', 'store_instance_id',
        'store_scope_binding_sha256', 'candidate_binding_sha256', 'authorization_scope_sha256',
        'permission_receipt_sha256', 'permit_candidate_append', 'permit_private_claim_store',
        'permit_restricted_claim_store', 'permit_upstream_result_intake',
        'permit_manual_proposal_intake', 'permit_repository_write',
        'permit_authoritative_knowledge_write', 'permit_issue_write', 'permit_publish'},
        'APPEND_POLICY_FIELDS_INVALID')
    need(policy['schema'] == APPEND_POLICY_SCHEMA and policy['purpose'] == APPEND_PURPOSE and
         policy['store_instance_id'] == manifest['instance_id'] and
         policy['store_scope_binding_sha256'] == manifest['scope_binding_sha256'] and
         policy['candidate_binding_sha256'] == binding and
         policy['authorization_scope_sha256'] == _scope_policy(manifest, binding, 'APPEND') and
         kb.sha(policy['permission_receipt_sha256']),
         'APPEND_POLICY_SCOPE_OR_RECEIPT_MISMATCH', 'unavailable')
    flags = ('permit_candidate_append', 'permit_private_claim_store',
             'permit_restricted_claim_store', 'permit_upstream_result_intake',
             'permit_manual_proposal_intake', 'permit_repository_write',
             'permit_authoritative_knowledge_write', 'permit_issue_write', 'permit_publish')
    _bool_fields(policy, flags)
    need(policy['permit_candidate_append'] and policy['permit_private_claim_store'] and
         (candidate['sensitivity'] != 'RESTRICTED' or policy['permit_restricted_claim_store']) and
         (candidate['origin'] == 'manual_proposal' and policy['permit_manual_proposal_intake'] or
          candidate['origin'] != 'manual_proposal' and policy['permit_upstream_result_intake']) and
         not any(policy[k] for k in ('permit_repository_write',
                  'permit_authoritative_knowledge_write', 'permit_issue_write', 'permit_publish')),
         'APPEND_PRIVILEGE_NOT_GRANTED_OR_ESCALATION', 'unavailable')


def _read_policy(text: str, manifest: dict[str, Any], key: str, binding: str,
                 sensitivity: str) -> dict[str, Any]:
    policy = _fields(_json(text, MAX_POLICY_BYTES), {'schema', 'purpose', 'store_instance_id',
        'store_scope_binding_sha256', 'candidate_key', 'candidate_binding_sha256',
        'authorization_scope_sha256', 'permission_receipt_sha256',
        'permit_candidate_metadata_read', 'permit_provenance_read',
        'permit_restricted_provenance_read', 'permit_claim_content_read', 'permit_restricted_claim_read',
        'permit_repository_write', 'permit_authoritative_knowledge_write', 'permit_publish'},
        'READ_POLICY_FIELDS_INVALID')
    need(policy['schema'] == READ_POLICY_SCHEMA and policy['purpose'] == READ_PURPOSE and
         policy['store_instance_id'] == manifest['instance_id'] and
         policy['store_scope_binding_sha256'] == manifest['scope_binding_sha256'] and
         policy['candidate_key'] == key and policy['candidate_binding_sha256'] == binding and
         policy['authorization_scope_sha256'] == _scope_policy(manifest, binding, 'READ') and
         kb.sha(policy['permission_receipt_sha256']),
         'READ_POLICY_SCOPE_OR_RECEIPT_MISMATCH', 'unavailable')
    flags = ('permit_candidate_metadata_read', 'permit_provenance_read',
             'permit_restricted_provenance_read', 'permit_claim_content_read', 'permit_restricted_claim_read',
             'permit_repository_write', 'permit_authoritative_knowledge_write', 'permit_publish')
    _bool_fields(policy, flags)
    need(policy['permit_candidate_metadata_read'] and
         (not policy['permit_restricted_provenance_read'] or policy['permit_provenance_read']) and
         (not policy['permit_provenance_read'] or sensitivity != 'RESTRICTED' or
          policy['permit_restricted_provenance_read']) and
         (not policy['permit_restricted_claim_read'] or policy['permit_claim_content_read']) and
         (not policy['permit_claim_content_read'] or sensitivity != 'RESTRICTED' or
          policy['permit_restricted_claim_read']) and
         not any(policy[k] for k in ('permit_repository_write',
                  'permit_authoritative_knowledge_write', 'permit_publish')),
         'READ_PRIVILEGE_NOT_GRANTED_OR_ESCALATION', 'unavailable')
    return policy


def _list_policy(text: str, manifest: dict[str, Any]) -> None:
    policy = _fields(_json(text, MAX_POLICY_BYTES), {'schema', 'purpose', 'store_instance_id',
        'store_scope_binding_sha256', 'authorization_scope_sha256',
        'permission_receipt_sha256', 'permit_candidate_keys_list',
        'permit_repository_write', 'permit_authoritative_knowledge_write', 'permit_publish'},
        'LIST_POLICY_FIELDS_INVALID')
    need(policy['schema'] == LIST_POLICY_SCHEMA and policy['purpose'] == LIST_PURPOSE and
         policy['store_instance_id'] == manifest['instance_id'] and
         policy['store_scope_binding_sha256'] == manifest['scope_binding_sha256'] and
         policy['authorization_scope_sha256'] == _scope_policy(manifest, '', 'LIST') and
         kb.sha(policy['permission_receipt_sha256']),
         'LIST_POLICY_SCOPE_OR_RECEIPT_MISMATCH', 'unavailable')
    _bool_fields(policy, ('permit_candidate_keys_list', 'permit_repository_write',
                          'permit_authoritative_knowledge_write', 'permit_publish'))
    need(policy['permit_candidate_keys_list'] and not any(policy[k] for k in
         ('permit_repository_write', 'permit_authoritative_knowledge_write', 'permit_publish')),
         'LIST_PRIVILEGE_NOT_GRANTED_OR_ESCALATION', 'unavailable')


class KnowledgeCandidateStore:
    """Host-configured isolated candidate store; all methods fail closed."""

    def __init__(self, *, root: str, store_id: str, repository_root: str,
                 knowledge_root: str, repository_ref: str,
                 knowledge_space_key: str, period_id: str, source_policy_revision: str) -> None:
        self.root, self.store_id = root, store_id
        self.repository_root, self.knowledge_root = repository_root, knowledge_root
        self.repository_ref = repository_ref
        self.knowledge_space_key = knowledge_space_key
        self.period_id = period_id
        self.source_policy_revision = source_policy_revision

    def _open(self, *, write: bool = False):
        return _store(self.root, self.store_id, self.repository_root, self.knowledge_root,
                      self.repository_ref, self.knowledge_space_key, self.period_id,
                      self.source_policy_revision, write=write)

    def initialize(self, *, allow_initialize: bool = False) -> dict[str, Any]:
        """One-time, explicit opt-in on a pre-existing empty 0700 directory."""
        try:
            need(type(allow_initialize) is bool and allow_initialize,
                 'INITIALIZATION_REQUIRES_EXPLICIT_GRANT', 'unavailable')
            need(type(self.store_id) is str and STORE_ID.fullmatch(self.store_id) is not None and
                 kb.REPO.fullmatch(self.repository_ref) is not None and
                 type(self.knowledge_space_key) is str and KEY.fullmatch(self.knowledge_space_key) is not None and
                 type(self.period_id) is str and KEY.fullmatch(self.period_id) is not None and
                 type(self.source_policy_revision) is str and KEY.fullmatch(self.source_policy_revision) is not None,
                 'INITIALIZATION_SCOPE_INVALID')
            _disjoint(self.root, self.repository_root, self.knowledge_root)
            repo_identity = _root_stat(self.repository_root)
            knowledge_identity = _root_stat(self.knowledge_root)
            with fs._opened_root(self.root) as fd:
                need(not os.listdir(fd), 'INITIALIZATION_REQUIRES_EMPTY_PRIVATE_ROOT', 'unavailable')
                root_stat = os.fstat(fd)
                manifest = {'schema': MANIFEST_SCHEMA, 'store_id': self.store_id,
                    'instance_id': str(uuid.uuid4()), 'root_path': self.root,
                    'repository_ref': self.repository_ref,
                    'knowledge_space_key': self.knowledge_space_key,
                    'period_id': self.period_id, 'source_policy_revision': self.source_policy_revision,
                    'repository_root': self.repository_root,
                    'knowledge_root': self.knowledge_root,
                    'repository_root_identity': repo_identity,
                    'knowledge_root_identity': knowledge_identity,
                    'candidate_root_identity': {'dev': root_stat.st_dev, 'ino': root_stat.st_ino},
                    'local_integrity_key_hex': secrets.token_hex(32)}
                manifest['scope_binding_sha256'] = _digest('STORE-SCOPE', _scope(manifest))
                need(fs._root_pinned(self.root, fd), 'ROOT_REPLACED_BEFORE_INITIALIZATION', 'unavailable')
                os.mkdir('records', 0o700, dir_fd=fd)
                fs._write_new(fd, 'transaction.lock', b'')
                fs._write_new(fd, 'manifest.json', (_canonical(manifest) + '\n').encode('ascii'))
                os.fsync(fd)
            return _response('partial', 'PRIVATE_STORE_INITIALIZED', subject={
                'store_id': self.store_id, 'store_instance_id': manifest['instance_id'],
                'store_scope_binding_sha256': manifest['scope_binding_sha256'],
                'append_right_granted': False}, candidate_write=True)
        except CandidateError as exc:
            return _error_response(exc)
        except (fs.EvidenceGateError, OSError, TypeError, ValueError):
            return _response('unavailable', 'INITIALIZATION_UNAVAILABLE_OR_OUTCOME_UNKNOWN')

    def preview(self, *, proposal_json: str, source_result_json: str | None = None) -> dict[str, Any]:
        """Read-only, no candidate body projection, grants no append rights."""
        try:
            with self._open() as (manifest, fd, _):
                candidate, provenance, binding = _proposal(proposal_json, manifest, source_result_json)
                records = _load_records(fd, manifest)
                existing = records.get(candidate['candidate_key'])
                state = ('NEW_CANDIDATE_KEY' if existing is None else
                    'IDEMPOTENT_RETRY' if existing['body']['candidate_binding_sha256'] == binding else
                    'IMMUTABLE_CANDIDATE_KEY_CONFLICT')
                return _response('partial', 'PREVIEW_ONLY_NO_WRITE', subject={
                    'store_id': self.store_id, 'store_instance_id': manifest['instance_id'],
                    'store_scope_binding_sha256': manifest['scope_binding_sha256'],
                    'candidate_key': candidate['candidate_key'],
                    'candidate_binding_sha256': binding,
                    'append_authorization_scope_sha256': _scope_policy(manifest, binding, 'APPEND'),
                    'read_authorization_scope_sha256': _scope_policy(manifest, binding, 'READ'),
                    'state': state, 'origin': candidate['origin'],
                    'sensitivity': candidate['sensitivity'],
                    'reported_delivery_state': provenance['reported_delivery_state'],
                    'review_state': 'AWAITING_HUMAN_REVIEW',
                    'claim_text_disclosed': False})
        except CandidateError as exc:
            return _error_response(exc)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return _response('invalid_input', 'PREVIEW_INPUT_INVALID')

    def append(self, *, proposal_json: str, append_policy_json: str,
               source_result_json: str | None = None) -> dict[str, Any]:
        """Explicitly authorized, durable, immutable append; same bytes => no-op."""
        try:
            with self._open(write=True) as (manifest, fd, root_fd):
                candidate, provenance, binding = _proposal(proposal_json, manifest, source_result_json)
                _append_policy(append_policy_json, manifest, candidate, binding)
                records = _load_records(fd, manifest)
                existing = records.get(candidate['candidate_key'])
                if existing is not None:
                    need(existing['body']['candidate_binding_sha256'] == binding,
                         'IMMUTABLE_CANDIDATE_KEY_CONFLICT', 'unavailable')
                    return _response('partial', 'ALREADY_PERSISTED_IDEMPOTENT_NO_WRITE', subject={
                        'candidate_key': candidate['candidate_key'],
                        'candidate_binding_sha256': binding,
                        'record_id': existing['record_id'],
                        'review_state': 'AWAITING_HUMAN_REVIEW'})
                need(len(records) < MAX_RECORDS, 'CANDIDATE_CAPACITY_REACHED', 'unavailable')
                need(fs._root_pinned(self.root, root_fd), 'CANDIDATE_ROOT_REPLACED', 'unavailable')
                _check_manifest(manifest, self.root, self.store_id, self.repository_root,
                                self.knowledge_root, self.repository_ref,
                                self.knowledge_space_key, self.period_id, self.source_policy_revision, root_fd)
                body = {'store_scope_binding_sha256': manifest['scope_binding_sha256'],
                    'candidate_binding_sha256': binding, 'candidate': candidate,
                    'provenance': provenance,
                    'recorded_at_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'review_state': 'AWAITING_HUMAN_REVIEW'}
                unsigned = {'schema': RECORD_SCHEMA, 'record_id': _digest('RECORD-ID', body), 'body': body}
                record = {**unsigned, 'local_mac_sha256': _mac(manifest, unsigned)}
                raw = (_canonical(record) + '\n').encode('ascii')
                need(len(raw) <= MAX_RECORD_BYTES, 'CANDIDATE_RECORD_TOO_LARGE')
                try:
                    fs._write_new(fd, _candidate_filename(candidate['candidate_key']), raw)
                    os.fsync(fd)
                except FileExistsError:
                    raise CandidateError('CANDIDATE_CREATE_RACE_REQUIRES_INSPECTION', 'unavailable') from None
                except OSError:
                    raise CandidateError('WRITE_OUTCOME_UNKNOWN_INSPECT_BEFORE_RETRY', 'unavailable') from None
                return _response('partial', 'CANDIDATE_APPENDED_IN_PRIVATE_QUARANTINE', subject={
                    'candidate_key': candidate['candidate_key'],
                    'candidate_binding_sha256': binding, 'record_id': record['record_id'],
                    'review_state': 'AWAITING_HUMAN_REVIEW',
                    'reported_delivery_state': provenance['reported_delivery_state']},
                    candidate_write=True)
        except CandidateError as exc:
            return _error_response(exc)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return _response('invalid_input', 'APPEND_INPUT_INVALID')

    def read(self, *, candidate_key: str, read_policy_json: str) -> dict[str, Any]:
        """Exact-key read. Claim and provenance need *separate* disclosure grants."""
        try:
            need(type(candidate_key) is str and CANDIDATE_KEY.fullmatch(candidate_key) is not None,
                 'READ_CANDIDATE_KEY_INVALID')
            with self._open() as (manifest, fd, _):
                records = _load_records(fd, manifest)
                record = records.get(candidate_key)
                need(record is not None, 'CANDIDATE_KEY_NOT_FOUND', 'unavailable')
                body = record['body']
                policy = _read_policy(read_policy_json, manifest, candidate_key,
                                      body['candidate_binding_sha256'],
                                      body['candidate']['sensitivity'])
                proposal = body['candidate']
                return _response('partial', 'PRIVATE_CANDIDATE_READ_ONLY', subject={
                    'candidate_key': candidate_key,
                    'candidate_binding_sha256': body['candidate_binding_sha256'],
                    'record_id': record['record_id'],
                    'origin': proposal['origin'],
                    'sensitivity': proposal['sensitivity'],
                    'review_state': body['review_state'],
                    'claim_text': proposal['claim_text'] if policy['permit_claim_content_read'] else None,
                    'reason_text': proposal['reason_text'] if policy['permit_claim_content_read'] else None,
                    'provenance': body['provenance'] if policy['permit_provenance_read'] else None,
                    'source_key': proposal['source_key'] if policy['permit_provenance_read'] else None,
                    'section_ref': proposal['section_ref'] if policy['permit_provenance_read'] else None,
                    'proposer_key': proposal['proposer_key'] if policy['permit_provenance_read'] else None,
                    'source_claim_not_authenticated': True})
        except CandidateError as exc:
            return _error_response(exc)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return _response('invalid_input', 'READ_INPUT_INVALID')

    def list_keys(self, *, list_policy_json: str) -> dict[str, Any]:
        """Explicitly permitted local list; never reveals text or source refs."""
        try:
            with self._open() as (manifest, fd, _):
                _list_policy(list_policy_json, manifest)
                records = _load_records(fd, manifest)
                return _response('partial', 'PRIVATE_CANDIDATE_KEYS_LISTED', subject={
                    'store_id': self.store_id, 'count': len(records),
                    'candidate_keys': sorted(records),
                    'content_or_provenance_projected': False})
        except CandidateError as exc:
            return _error_response(exc)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return _response('invalid_input', 'LIST_INPUT_INVALID')

    def list_binding_preview(self) -> dict[str, Any]:
        """No list disclosure; outputs the exact authorization binding."""
        try:
            with self._open() as (manifest, _, _):
                return _response('partial', 'LIST_BINDING_PREVIEW_ONLY', subject={
                    'store_instance_id': manifest['instance_id'],
                    'store_scope_binding_sha256': manifest['scope_binding_sha256'],
                    'authorization_scope_sha256': _scope_policy(manifest, '', 'LIST'),
                    'listing_granted': False})
        except CandidateError as exc:
            return _error_response(exc)

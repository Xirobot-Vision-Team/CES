#!/usr/bin/env python3
"""EC202 bounded, separately permitted local repository + CES snapshot reads.

This adapter accepts roots ONLY from a trusted host configuration, never from a
request JSON document. It observes local bytes but does not authenticate Git
objects/target delivery, organizational ACLs, or knowledge truth (EC203+).
No directory, file, manifest, knowledge record or business source is written.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from typing import Any

try:
    from . import knowledge_boundary as boundary
except ImportError:  # standalone construction/ execution
    import knowledge_boundary as boundary

SCHEMA = 'ces.knowledge_bootstrap.v1'
REQUEST_SCHEMA = 'ces.knowledge_bootstrap_request.v1'
POLICY_SCHEMA = 'ces.knowledge_bootstrap_read_policy.v1'
MANIFEST_SCHEMA = 'ces.knowledge_snapshot_manifest.v1'
PURPOSE = 'knowledge_bootstrap_local_read_only'
MANIFEST_NAME = 'ces-snapshot.v1.json'
MAX_REQUEST = 262144
MAX_POLICY = 65536
MAX_MANIFEST = 65536
MAX_SOURCES = 32
MAX_FILE = 16384
MAX_TOTAL = 262144
MAX_PATH = 256
SEGMENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
BLOCKED_SEGMENTS = frozenset({'.git', '.hg', '.svn', '.env'})
KINDS = frozenset({'repository', 'ces_knowledge'})
COVERAGE = boundary.COVERAGE
LIMITATIONS = {
    'target_git_oid_or_branch_authenticated': False,
    'delivered_source_authenticated': False,
    'repository_root_organizational_identity_authenticated': False,
    'source_or_permission_receipts_cryptographically_authenticated': False,
    'knowledge_manifest_semantics_authenticated': False,
    'current_architecture_verified': False,
    'candidate_promoted_to_current': False,
    'knowledge_impact_save_or_publication_performed': False,
    'any_business_git_issue_provider_or_file_write_performed': False,
    'native_powershell_knowledge_bootstrap_registered': False,
}


class BootstrapError(ValueError):
    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def require(condition: bool, code: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise BootstrapError(code, status)


def fields(value: Any, names: set[str], code: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == names, code)
    return value


def _path(path: Any) -> str:
    require(type(path) is str and 1 <= len(path) <= MAX_PATH and
            '\\' not in path and not path.startswith('/') and
            not path.endswith('/'), 'SOURCE_PATH_INVALID')
    parts = path.split('/')
    require(all(SEGMENT.fullmatch(part) and part not in BLOCKED_SEGMENTS
                for part in parts), 'SOURCE_PATH_INVALID')
    require(path != MANIFEST_NAME, 'MANIFEST_RESERVED_AS_SOURCE')
    return path


def _scope(value: Any) -> dict[str, Any]:
    """Reuse EC201's exact scoped period/target semantics; no observations."""
    try:
        boundary._request({
            'schema': boundary.REQUEST_SCHEMA,
            'operation': 'knowledge.boundary.inspect',
            'scope': value, 'observations': [],
        })
    except boundary.KnowledgeBoundaryError as exc:
        raise BootstrapError('SCOPE_' + exc.reason) from exc
    return value


def _request(value: Any) -> dict[str, Any]:
    fields(value, {'schema', 'operation', 'scope', 'expected_manifest_sha256',
                   'sources'}, 'REQUEST_FIELDS_INVALID')
    require(value['schema'] == REQUEST_SCHEMA and
            value['operation'] == 'knowledge.bootstrap.read', 'REQUEST_OPERATION_INVALID')
    _scope(value['scope'])
    expected = value['expected_manifest_sha256']
    require(expected is None or boundary.sha(expected), 'MANIFEST_DIGEST_INVALID')
    sources = value['sources']
    require(type(sources) is list and len(sources) <= MAX_SOURCES,
            'SOURCE_COUNT_INVALID')
    keys: list[str] = []
    paths: set[tuple[str, str]] = set()
    for source in sources:
        fields(source, {'source_key', 'kind', 'relative_path', 'expected_sha256',
                        'coverage'}, 'SOURCE_FIELDS_INVALID')
        require(boundary.key(source['source_key']), 'SOURCE_KEY_INVALID')
        require(type(source['kind']) is str and source['kind'] in KINDS,
                'SOURCE_KIND_INVALID')
        _path(source['relative_path'])
        require(source['expected_sha256'] is None or
                boundary.sha(source['expected_sha256']), 'SOURCE_DIGEST_INVALID')
        require(type(source['coverage']) is str and
                source['coverage'] in COVERAGE, 'SOURCE_COVERAGE_INVALID')
        keys.append(source['source_key'])
        pair = (source['kind'], source['relative_path'].casefold())
        require(pair not in paths, 'SOURCE_PATH_DUPLICATED')
        paths.add(pair)
    require(keys == sorted(set(keys)) and
            len({name.casefold() for name in keys}) == len(keys),
            'SOURCE_KEYS_NOT_SORTED_UNIQUE')
    return value


def _binding(request: dict[str, Any], roots: dict[str, str]) -> dict[str, Any]:
    return {
        'request_binding_sha256': boundary.digest('CES-EC202-REQUEST-v1', request),
        'scope_binding_sha256': boundary.digest('CES-EC202-SCOPE-v1', request['scope']),
        'repository_root_binding_sha256': roots['repository'],
        'knowledge_root_binding_sha256': roots['ces_knowledge'],
        'source_bindings': [
            {'source_key': row['source_key'],
             'source_binding_sha256': boundary.digest('CES-EC202-SOURCE-v1', row)}
            for row in request['sources']
        ],
    }


def _policy(value: Any, request: dict[str, Any], bind: dict[str, Any]) -> dict[str, Any]:
    fields(value, {'schema', 'purpose', 'repository_ref', 'knowledge_space_key',
                   'period_id', 'source_policy_revision',
                   'request_binding_sha256', 'scope_binding_sha256',
                   'repository_root_binding_sha256', 'knowledge_root_binding_sha256',
                   'permit_bootstrap_read', 'permit_repository_read',
                   'permit_knowledge_read', 'permit_manifest_read',
                   'permit_provenance_projection', 'permit_content_projection',
                   'permit_knowledge_write', 'permit_repository_write',
                   'permit_business_source_write', 'permit_issue_write',
                   'permit_publish', 'read_receipt_sha256',
                   'source_grants'}, 'POLICY_FIELDS_INVALID')
    require(value['schema'] == POLICY_SCHEMA and value['purpose'] == PURPOSE,
            'POLICY_PURPOSE_INVALID', 'unavailable')
    scope = request['scope']
    require(all(value[k] == scope[k] for k in
                ('repository_ref', 'knowledge_space_key', 'source_policy_revision')) and
            value['period_id'] == scope['period']['period_id'] and
            all(value[k] == bind[k] for k in
                ('request_binding_sha256', 'scope_binding_sha256',
                 'repository_root_binding_sha256', 'knowledge_root_binding_sha256')),
            'POLICY_BINDING_MISMATCH', 'unavailable')
    permits = ('permit_bootstrap_read', 'permit_repository_read',
               'permit_knowledge_read', 'permit_manifest_read',
               'permit_provenance_projection', 'permit_content_projection',
               'permit_knowledge_write', 'permit_repository_write',
               'permit_business_source_write', 'permit_issue_write', 'permit_publish')
    require(all(type(value[k]) is bool for k in permits), 'POLICY_PERMISSION_TYPE_INVALID')
    require(value['permit_bootstrap_read'] and boundary.sha(value['read_receipt_sha256']),
            'POLICY_READ_DENIED', 'unavailable')
    require(not any(value[k] for k in ('permit_knowledge_write',
                 'permit_repository_write', 'permit_business_source_write',
                 'permit_issue_write', 'permit_publish')),
            'POLICY_WRITE_INTENT_FORBIDDEN', 'unavailable')
    require(not value['permit_manifest_read'] or value['permit_knowledge_read'],
            'POLICY_MANIFEST_ESCALATION', 'unavailable')
    grants = value['source_grants']
    require(type(grants) is list and len(grants) == len(bind['source_bindings']),
            'POLICY_GRANTS_INCOMPLETE', 'unavailable')
    for grant, expected in zip(grants, bind['source_bindings']):
        fields(grant, {'source_key', 'source_binding_sha256',
                       'permit_source_read', 'permit_content_projection',
                       'read_receipt_sha256'}, 'POLICY_GRANT_FIELDS_INVALID')
        require(grant['source_key'] == expected['source_key'] and
                grant['source_binding_sha256'] == expected['source_binding_sha256'],
                'POLICY_SOURCE_BINDING_MISMATCH', 'unavailable')
        require(type(grant['permit_source_read']) is bool and
                type(grant['permit_content_projection']) is bool,
                'POLICY_GRANT_PERMISSION_TYPE_INVALID')
        require(grant['read_receipt_sha256'] is None or
                boundary.sha(grant['read_receipt_sha256']),
                'POLICY_GRANT_RECEIPT_INVALID')
        require(not grant['permit_source_read'] or
                boundary.sha(grant['read_receipt_sha256']),
                'POLICY_GRANT_READ_RECEIPT_MISSING', 'unavailable')
        require(not grant['permit_content_projection'] or
                (grant['permit_source_read'] and value['permit_content_projection']),
                'POLICY_CONTENT_ESCALATION', 'unavailable')
    return value


def _root_path(path: Any) -> tuple[str, list[str]]:
    require(type(path) is str and path.startswith('/') and '\x00' not in path and
            len(path) <= 4096 and path != '/', 'HOST_ROOT_INVALID')
    parts = path.split('/')[1:]
    require(all(p not in ('', '.', '..') and p not in BLOCKED_SEGMENTS for p in parts),
            'HOST_ROOT_INVALID')
    return path, parts


DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)


def _fingerprint(st: os.stat_result) -> dict[str, int]:
    return {'dev': st.st_dev, 'ino': st.st_ino, 'uid': st.st_uid,
            'mode': stat.S_IMODE(st.st_mode)}


def _open_bound_root(path: str, *, permit_missing: bool) -> tuple[int | None, str]:
    """Handle descriptor cleanup for all normal and exceptional root paths."""
    # Avoid returning leaked fds from early return/exception by implementing
    # the descriptor walk in one scope.
    raw, parts = _root_path(path)
    fd: int | None = None
    try:
        fd = os.open('/', DIRECTORY_FLAGS)
        for i, part in enumerate(parts):
            try:
                next_fd = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if permit_missing and i == len(parts) - 1:
                    pin = boundary.digest('CES-EC202-ROOT-v1', {
                        'path': raw, 'state': 'MISSING_FINAL',
                        'parent': _fingerprint(os.fstat(fd)),
                    })
                    return None, pin
                raise BootstrapError('HOST_ROOT_MISSING', 'unavailable')
            except OSError as exc:
                raise BootstrapError('HOST_ROOT_UNAVAILABLE', 'unavailable') from exc
            os.close(fd)
            fd = next_fd
        pin = boundary.digest('CES-EC202-ROOT-v1', {
            'path': raw, 'state': 'PRESENT', 'directory': _fingerprint(os.fstat(fd)),
        })
        result, fd = fd, None
        return result, pin
    except OSError as exc:
        raise BootstrapError('HOST_ROOT_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _read_file(root_fd: int, relative_path: str, limit: int) -> tuple[str, bytes | None]:
    fd: int | None = None
    dirs: list[int] = []
    try:
        parts = relative_path.split('/')
        parent = root_fd
        for component in parts[:-1]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=parent)
            dirs.append(child)
            parent = child
        fd = os.open(parts[-1], FILE_FLAGS, dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return 'UNSAFE_NODE', None
        if before.st_size > limit:
            return 'OVERSIZED', None
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (len(data) > limit or len(data) != after.st_size or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns)):
            return 'CHANGED_DURING_READ', None
        return 'READ', bytes(data)
    except FileNotFoundError:
        return 'MISSING', None
    except (OSError, ValueError):
        return 'UNAVAILABLE', None
    finally:
        if fd is not None:
            os.close(fd)
        for fd in reversed(dirs):
            os.close(fd)


def _empty_directory(fd: int) -> bool | None:
    try:
        with os.scandir(fd) as entries:
            return next(entries, None) is None
    except OSError:
        return None


def _manifest_obj(raw: bytes, scope: dict[str, Any]) -> dict[str, Any]:
    try:
        doc = boundary._json(raw.decode('utf-8', 'strict'), MAX_MANIFEST)
    except (UnicodeError, boundary.KnowledgeBoundaryError) as exc:
        raise BootstrapError('MANIFEST_INVALID', 'unavailable') from exc
    fields(doc, {'schema', 'repository_ref', 'knowledge_space_key',
                 'source_policy_revision', 'snapshot_version',
                 'captured_at_utc', 'coverage', 'entries'}, 'MANIFEST_FIELDS_INVALID')
    require(doc['schema'] == MANIFEST_SCHEMA and
            all(doc[k] == scope[k] for k in
                ('repository_ref', 'knowledge_space_key', 'source_policy_revision')),
            'MANIFEST_NAMESPACE_MISMATCH', 'unavailable')
    require(boundary.key(doc['snapshot_version']), 'MANIFEST_VERSION_INVALID')
    require(doc['captured_at_utc'] is None or
            isinstance(doc['captured_at_utc'], str), 'MANIFEST_TIME_INVALID')
    if doc['captured_at_utc'] is not None:
        try:
            boundary._time(doc['captured_at_utc'])
        except boundary.KnowledgeBoundaryError as exc:
            raise BootstrapError('MANIFEST_TIME_INVALID') from exc
    require(type(doc['coverage']) is str and doc['coverage'] in COVERAGE,
            'MANIFEST_COVERAGE_INVALID')
    entries = doc['entries']
    require(type(entries) is list and len(entries) <= MAX_SOURCES,
            'MANIFEST_ENTRY_COUNT_INVALID')
    paths = []
    for entry in entries:
        fields(entry, {'relative_path', 'sha256', 'size_bytes'},
               'MANIFEST_ENTRY_FIELDS_INVALID')
        _path(entry['relative_path'])
        require(boundary.sha(entry['sha256']) and
                type(entry['size_bytes']) is int and
                0 <= entry['size_bytes'] <= MAX_FILE,
                'MANIFEST_ENTRY_INVALID')
        paths.append(entry['relative_path'])
    require(paths == sorted(set(paths)) and len({p.casefold() for p in paths}) == len(paths),
            'MANIFEST_ENTRIES_NOT_SORTED_UNIQUE')
    return doc


def _manifest(root_fd: int | None, request: dict[str, Any],
              allowed: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    display = {
        'state': 'DENIED_NOT_INSPECTED', 'manifest_sha256': None,
        'snapshot_version': None, 'captured_at_utc': None,
        'period_relation': 'UNKNOWN', 'declared_coverage': 'unknown',
        'declared_entries': None, 'unselected_entries': None,
        'empty_initialization_proposal': None,
    }
    if not allowed:
        return display, None
    if root_fd is None:
        display['state'] = 'STORE_MISSING_UNINITIALIZED'
    else:
        state, content = _read_file(root_fd, MANIFEST_NAME, MAX_MANIFEST)
        if state == 'MISSING':
            empty = _empty_directory(root_fd)
            display['state'] = ('EMPTY_DIRECTORY_UNINITIALIZED' if empty is True else
                                'UNINDEXED_NONEMPTY_DIRECTORY' if empty is False else
                                'DIRECTORY_UNAVAILABLE')
        elif state != 'READ':
            display['state'] = 'MANIFEST_' + state
        elif content is not None:
            observed = hashlib.sha256(content).hexdigest()
            expected = request['expected_manifest_sha256']
            if expected is not None and expected != observed:
                display['state'] = 'MANIFEST_DIGEST_MISMATCH'
            else:
                try:
                    parsed = _manifest_obj(content, request['scope'])
                except BootstrapError:
                    display['state'] = 'MANIFEST_INVALID_OR_SCOPE_MISMATCH'
                else:
                    display['state'] = ('EMPTY_MANIFEST_DECLARED_UNVERIFIED' if
                                        not parsed['entries'] else
                                        'MANIFEST_READ_UNVERIFIED')
                    display['manifest_sha256'] = observed
                    display['snapshot_version'] = parsed['snapshot_version']
                    display['captured_at_utc'] = parsed['captured_at_utc']
                    display['declared_coverage'] = parsed['coverage']
                    display['declared_entries'] = len(parsed['entries'])
                    display['period_relation'] = boundary._period_relation(
                        parsed['captured_at_utc'], request['scope']['period'])
                    return display, parsed
    if display['state'] in ('STORE_MISSING_UNINITIALIZED',
                            'EMPTY_DIRECTORY_UNINITIALIZED'):
        display['empty_initialization_proposal'] = {
            'schema': MANIFEST_SCHEMA,
            'repository_ref': request['scope']['repository_ref'],
            'knowledge_space_key': request['scope']['knowledge_space_key'],
            'source_policy_revision': request['scope']['source_policy_revision'],
            'snapshot_version': 'bootstrap-v1', 'captured_at_utc': None,
            'coverage': 'unknown', 'entries': [],
        }
    return display, None


def _base() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'KNOWLEDGE_BOOTSTRAP_INVALID_INPUT',
            'subject': None, 'canonical_json': None, 'limitations': dict(LIMITATIONS)}


class KnowledgeBootstrap:
    """Read-only local source adapter configured by an independent trusted host.

    The root paths are host configuration, not request fields. Root pins and
    per-source grants are enforced; nobody may infer delivered Git status.
    """

    def __init__(self, *, repository_root: str, knowledge_root: str) -> None:
        self.repository_root, _ = _root_path(repository_root)
        self.knowledge_root, _ = _root_path(knowledge_root)
        require(self.repository_root != self.knowledge_root,
                'HOST_ROOTS_MUST_DIFFER')

    def _roots(self) -> tuple[dict[str, int | None], dict[str, str]]:
        repo_fd: int | None = None
        knowledge_fd: int | None = None
        try:
            repo_fd, repo_pin = _open_bound_root(self.repository_root, permit_missing=False)
            knowledge_fd, knowledge_pin = _open_bound_root(
                self.knowledge_root, permit_missing=True)
            return ({'repository': repo_fd, 'ces_knowledge': knowledge_fd},
                    {'repository': repo_pin, 'ces_knowledge': knowledge_pin})
        except Exception:
            if repo_fd is not None:
                os.close(repo_fd)
            if knowledge_fd is not None:
                os.close(knowledge_fd)
            raise

    @staticmethod
    def _close_roots(fds: dict[str, int | None]) -> None:
        for fd in fds.values():
            if fd is not None:
                os.close(fd)

    def binding_preview(self, *, request_json: str) -> dict[str, Any]:
        """Compute scope + local root inode pins without reading any file bytes."""
        out = _base()
        fds: dict[str, int | None] = {}
        try:
            req = _request(boundary._json(request_json, MAX_REQUEST))
            fds, roots = self._roots()
            subject = _binding(req, roots)
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_BOOTSTRAP_BINDINGS_ONLY',
                       subject=subject, canonical_json=boundary.canonical(subject))
        except (BootstrapError, boundary.KnowledgeBoundaryError) as exc:
            out.update(status=exc.status, exit_code=5 if exc.status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_BOOTSTRAP_' + exc.reason)
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_BOOTSTRAP_SOURCE_UNAVAILABLE')
        finally:
            self._close_roots(fds)
        return out

    def read(self, *, request_json: str, read_policy_json: str) -> dict[str, Any]:
        """Perform bounded nofollow local reads only after exact policy binding."""
        out = _base()
        fds: dict[str, int | None] = {}
        try:
            req = _request(boundary._json(request_json, MAX_REQUEST))
            fds, roots = self._roots()
            bind = _binding(req, roots)
            policy = _policy(boundary._json(read_policy_json, MAX_POLICY), req, bind)
            manifest_allowed = (policy['permit_knowledge_read'] and
                                policy['permit_manifest_read'])
            display, parsed_manifest = _manifest(fds['ces_knowledge'], req,
                                                 manifest_allowed)
            manifest_sha_internal = display['manifest_sha256']
            if not policy['permit_provenance_projection']:
                display['manifest_sha256'] = None
            entries = ({entry['relative_path']: entry for entry in parsed_manifest['entries']}
                       if parsed_manifest is not None else {})
            selected = {row['relative_path'] for row in req['sources']
                        if row['kind'] == 'ces_knowledge'}
            if parsed_manifest is not None:
                display['unselected_entries'] = len(set(entries) - selected)
            used = 0
            results = []
            gaps = []
            for row, pin, grant in zip(req['sources'], bind['source_bindings'],
                                       policy['source_grants']):
                kind, path, name = row['kind'], row['relative_path'], row['source_key']
                authorised = (grant['permit_source_read'] and
                              policy['permit_repository_read' if kind == 'repository'
                                     else 'permit_knowledge_read'])
                result = {
                    'source_key': name, 'source_binding_sha256': pin['source_binding_sha256'],
                    'kind': kind, 'relative_path': path,
                    'source_classification': ('LOCAL_REPOSITORY_BYTES_NOT_DELIVERED_PROOF'
                                              if kind == 'repository' else
                                              'CES_SNAPSHOT_BYTES_NOT_CURRENT_PROOF'),
                    'state': 'DENIED_NOT_INSPECTED', 'coverage': row['coverage'],
                    'expected_sha256': row['expected_sha256'] if
                                       policy['permit_provenance_projection'] else None,
                    'observed_sha256': None, 'size_bytes': None,
                    'source_ref': None, 'content_base64': None,
                    'manifest_entry_match': None,
                }
                if not authorised:
                    pass
                elif kind == 'ces_knowledge' and parsed_manifest is None:
                    result['state'] = 'SNAPSHOT_NOT_AVAILABLE'
                elif kind == 'ces_knowledge' and path not in entries:
                    result['state'] = 'NOT_IN_SNAPSHOT_MANIFEST'
                    result['manifest_entry_match'] = False
                elif fds[kind] is None:
                    result['state'] = 'ROOT_MISSING'
                elif used >= MAX_TOTAL:
                    result['state'] = 'TOTAL_READ_BUDGET_EXHAUSTED'
                else:
                    # The byte budget is charged on data that is read; when the
                    # budget is too small, reject rather than truncate source.
                    state, raw = _read_file(fds[kind], path,
                                            min(MAX_FILE, MAX_TOTAL - used))
                    result['state'] = state
                    if raw is not None and state == 'READ':
                        used += len(raw)
                        value_sha = hashlib.sha256(raw).hexdigest()
                        result['size_bytes'] = len(raw)
                        manifest_match = None
                        if kind == 'ces_knowledge':
                            entry = entries[path]
                            manifest_match = (entry['sha256'] == value_sha and
                                              entry['size_bytes'] == len(raw))
                            result['manifest_entry_match'] = manifest_match
                        if row['expected_sha256'] is not None and row['expected_sha256'] != value_sha:
                            result['state'] = 'EXPECTED_SHA_MISMATCH'
                        elif manifest_match is False:
                            result['state'] = 'MANIFEST_ENTRY_MISMATCH'
                        else:
                            result['state'] = 'READ_UNVERIFIED'
                        result['source_ref'] = 'ceskbootstrap1:' + boundary.digest(
                            'CES-EC202-OBSERVED-BYTES-v1', {
                                'scope': bind['scope_binding_sha256'],
                                'source': pin['source_binding_sha256'],
                                'sha256': value_sha, 'size_bytes': len(raw),
                                'manifest_sha256': manifest_sha_internal if
                                  kind == 'ces_knowledge' else None,
                            })
                        if policy['permit_provenance_projection']:
                            result['observed_sha256'] = value_sha
                        if (result['state'] == 'READ_UNVERIFIED' and
                            policy['permit_content_projection'] and
                            grant['permit_content_projection']):
                            result['content_base64'] = base64.b64encode(raw).decode('ascii')
                if result['state'] != 'READ_UNVERIFIED':
                    gaps.append({'source_key': name, 'gap_code': result['state']})
                results.append(result)
            if not manifest_allowed:
                gaps.append({'source_key': None, 'gap_code': 'MANIFEST_ACCESS_DENIED'})
            elif display['state'] not in ('MANIFEST_READ_UNVERIFIED',
                                           'EMPTY_MANIFEST_DECLARED_UNVERIFIED'):
                gaps.append({'source_key': None, 'gap_code': display['state']})
            if display['unselected_entries']:
                gaps.append({'source_key': None,
                             'gap_code': 'MANIFEST_ENTRIES_NOT_SELECTED'})
            if display['period_relation'] != 'WITHIN_DECLARED_PERIOD':
                gaps.append({'source_key': None,
                             'gap_code': 'SNAPSHOT_PERIOD_NOT_ESTABLISHED'})
            summary = {
                'requested_sources': len(results),
                'repository_sources_read': sum(r['kind'] == 'repository' and
                    r['state'] == 'READ_UNVERIFIED' for r in results),
                'knowledge_sources_read': sum(r['kind'] == 'ces_knowledge' and
                    r['state'] == 'READ_UNVERIFIED' for r in results),
                'sources_with_gaps': sum(r['state'] != 'READ_UNVERIFIED' for r in results),
                'selected_source_bytes_read': used,
                'declared_manifest_entries': display['declared_entries'],
                'authenticated_delivered_facts': 0,
            }
            scope = req['scope']
            subject = {
                'model_revision': 'EC202_LOCAL_SOURCE_BOOTSTRAP_ONLY',
                'repository_ref': scope['repository_ref'],
                'knowledge_space_key': scope['knowledge_space_key'],
                'period_id': scope['period']['period_id'],
                'source_policy_revision': scope['source_policy_revision'],
                'request_binding_sha256': bind['request_binding_sha256'],
                'scope_binding_sha256': bind['scope_binding_sha256'],
                'root_bindings': {
                    'repository': roots['repository'],
                    'ces_knowledge': roots['ces_knowledge'],
                },
                'read_policy_binding_sha256': boundary.digest(
                    'CES-EC202-READ-POLICY-v1', policy),
                'target_revision': (scope['target']['revision'] if
                                    policy['permit_provenance_projection'] else None),
                'knowledge_manifest': display,
                'sources': results, 'coverage_gaps': gaps, 'summary': summary,
                'current_architecture_state': 'UNKNOWN_NOT_AUTHENTICATED',
                'verified_delivered_facts': [],
                'no_write_actions_performed': True,
                'next_unimplemented': ['EC203_TRUSTED_TARGET_SHA_BINDING',
                    'EC204_KNOWLEDGE_IMPACT', 'EC206_CANDIDATE_STORE',
                    'EC208_KNOWLEDGE_SAVE', 'NATIVE_POWERSHELL_KNOWLEDGE_ROUTE'],
            }
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_BOOTSTRAP_LOCAL_BYTES_NOT_DELIVERY_PROOF',
                       subject=subject, canonical_json=boundary.canonical(subject))
        except (BootstrapError, boundary.KnowledgeBoundaryError) as exc:
            out.update(status=exc.status, exit_code=5 if exc.status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_BOOTSTRAP_' + exc.reason)
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_BOOTSTRAP_SOURCE_UNAVAILABLE')
        finally:
            self._close_roots(fds)
        return out

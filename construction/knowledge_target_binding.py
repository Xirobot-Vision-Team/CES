#!/usr/bin/env python3
"""EC203: actual Git object/ref checks + independently signed delivery binding.

The host, not request JSON, configures the local repository, target ref, and
Ed25519 verification keys. The detached signature is NOT a substitute for an
organization's key onboarding, revocation, or authorization infrastructure.
No remote reads, hooks, repository writes, knowledge writes, or promotions.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import selectors
import shutil
import subprocess
import time
from typing import Any

try:
    from . import knowledge_boundary as boundary
    from . import knowledge_bootstrap as bootstrap
except ImportError:
    import knowledge_boundary as boundary
    import knowledge_bootstrap as bootstrap

SCHEMA = 'ces.knowledge_target_binding.v1'
POLICY_SCHEMA = 'ces.knowledge_target_read_policy.v1'
STATEMENT_SCHEMA = 'ces.knowledge_target_delivery_statement.v1'
PURPOSE = 'knowledge_target_git_read_only'
STATEMENT_PURPOSE = 'knowledge_delivered_target_commit'
SIGNED_DOMAIN = b'CES-EC203-DELIVERY-STATEMENT-v1\0'
MAX_POLICY = 65536
MAX_STATEMENT = 8192
MAX_COMMIT = 131072
MAX_GIT_BYTES = bootstrap.MAX_FILE
REF_PART = re.compile(r'[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
GIT_OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z', re.ASCII)
LIMITATIONS = {
    'organizational_signer_enrollment_or_revocation_verified': False,
    'organizational_repository_identity_verified': False,
    'git_ref_immutability_or_future_stability_guaranteed': False,
    'knowledge_snapshot_semantic_truth_authenticated': False,
    'current_architecture_semantically_verified': False,
    'candidate_pr_or_worktree_promoted': False,
    'knowledge_impact_or_save_or_publication_performed': False,
    'business_git_issue_provider_or_file_write_performed': False,
    'native_powershell_knowledge_route_registered': False,
}


class TargetError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(condition: bool, code: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise TargetError(code, status)


def _ref(value: Any) -> str:
    need(type(value) is str and len(value) <= 256 and
         value.startswith(('refs/heads/', 'refs/remotes/')), 'HOST_TARGET_REF_INVALID')
    parts = value.split('/')
    need(len(parts) >= 3 and all(REF_PART.fullmatch(s) and s not in ('.', '..')
         and not s.endswith('.lock') and '..' not in s for s in parts[2:]),
         'HOST_TARGET_REF_INVALID')
    return value


def _digest_obj(domain: str, obj: Any) -> str:
    return boundary.digest(domain, obj)


def _signed_bytes(doc: dict[str, Any]) -> bytes:
    return SIGNED_DOMAIN + boundary.canonical(doc).encode('ascii')


def _statement(value: Any) -> dict[str, Any]:
    bootstrap.fields(value, {'schema', 'purpose', 'signer_key_id', 'repository_ref',
            'knowledge_space_key', 'source_policy_revision', 'period_id',
            'request_binding_sha256', 'scope_binding_sha256', 'target_ref',
            'target_revision', 'delivered_at_utc', 'knowledge_manifest_sha256'},
            'STATEMENT_FIELDS_INVALID')
    need(value['schema'] == STATEMENT_SCHEMA and
         value['purpose'] == STATEMENT_PURPOSE, 'STATEMENT_TYPE_INVALID')
    need(boundary.key(value['signer_key_id']), 'STATEMENT_SIGNER_INVALID')
    need(type(value['target_ref']) is str, 'STATEMENT_REF_INVALID')
    _ref(value['target_ref'])
    need(type(value['repository_ref']) is str and
         boundary.REPO.fullmatch(value['repository_ref']) is not None,
         'STATEMENT_REPOSITORY_INVALID')
    need(all(boundary.key(value[k]) for k in ('knowledge_space_key',
         'source_policy_revision', 'period_id')), 'STATEMENT_SCOPE_INVALID')
    need(boundary.sha(value['request_binding_sha256']) and
         boundary.sha(value['scope_binding_sha256']), 'STATEMENT_BINDING_INVALID')
    try:
        boundary._revision(value['target_revision'])
        boundary._time(value['delivered_at_utc'])
    except boundary.KnowledgeBoundaryError as exc:
        raise TargetError('STATEMENT_' + exc.reason) from exc
    need(value['knowledge_manifest_sha256'] is None or
         boundary.sha(value['knowledge_manifest_sha256']), 'STATEMENT_MANIFEST_INVALID')
    return value


def _verify_signature(doc: dict[str, Any], signature: Any,
                      trusted_keys: dict[str, bytes]) -> str:
    key = trusted_keys.get(doc['signer_key_id'])
    if key is None:
        return 'UNKNOWN_SIGNER_UNVERIFIED'
    if type(signature) is not str or len(signature) != 88:
        return 'SIGNATURE_MISSING_OR_MALFORMED'
    try:
        raw = base64.b64decode(signature, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode('ascii') != signature:
            return 'SIGNATURE_MISSING_OR_MALFORMED'
    except (binascii.Error, ValueError):
        return 'SIGNATURE_MISSING_OR_MALFORMED'
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return 'VERIFIER_DEPENDENCY_UNAVAILABLE'
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(raw, _signed_bytes(doc))
    except InvalidSignature:
        return 'SIGNATURE_INVALID'
    except (ValueError, TypeError):
        return 'SIGNATURE_INVALID'
    return 'SIGNATURE_VERIFIED_CONFIGURED_KEY'


def _period_matches(doc: dict[str, Any], request: dict[str, Any]) -> bool:
    period = request['scope']['period']
    # A periodless request cannot turn a claimed date into an authenticated
    # in-period delivery fact.
    return period['start_utc'] is not None and (period['start_utc'] <=
           doc['delivered_at_utc'] < period['end_utc'])


def _matches_scope(doc: dict[str, Any], req: dict[str, Any],
                   bind: dict[str, Any], host_ref: str) -> bool:
    s = req['scope']
    return (doc['repository_ref'] == s['repository_ref'] and
            doc['knowledge_space_key'] == s['knowledge_space_key'] and
            doc['source_policy_revision'] == s['source_policy_revision'] and
            doc['period_id'] == s['period']['period_id'] and
            doc['request_binding_sha256'] == bind['request_binding_sha256'] and
            doc['scope_binding_sha256'] == bind['scope_binding_sha256'] and
            doc['target_revision'] == s['target']['revision'] and
            doc['target_ref'] == host_ref and _period_matches(doc, req))


def _policy(value: Any, req: dict[str, Any], bind: dict[str, Any],
            bootstrap_policy: dict[str, Any]) -> dict[str, Any]:
    bootstrap.fields(value, {'schema', 'purpose', 'repository_ref', 'knowledge_space_key',
        'period_id', 'source_policy_revision', 'request_binding_sha256',
        'scope_binding_sha256', 'repository_root_binding_sha256',
        'knowledge_root_binding_sha256', 'git_root_binding_sha256',
        'target_config_binding_sha256', 'issuer_registry_binding_sha256',
        'bootstrap_read_policy_binding_sha256', 'permit_target_read',
        'permit_delivery_signature_verification', 'permit_git_object_read',
        'permit_source_blob_compare', 'permit_knowledge_manifest_bind',
        'permit_target_oid_projection', 'permit_source_digest_projection',
        'permit_repository_write', 'permit_knowledge_write',
        'permit_business_source_write', 'permit_issue_write', 'permit_publish',
        'read_receipt_sha256', 'source_grants'}, 'TARGET_POLICY_FIELDS_INVALID')
    s = req['scope']
    need(value['schema'] == POLICY_SCHEMA and value['purpose'] == PURPOSE,
         'TARGET_POLICY_PURPOSE_INVALID', 'unavailable')
    need(all(value[k] == s[k] for k in ('repository_ref', 'knowledge_space_key',
         'source_policy_revision')) and value['period_id'] == s['period']['period_id'],
         'TARGET_POLICY_SCOPE_MISMATCH', 'unavailable')
    for k in ('request_binding_sha256', 'scope_binding_sha256',
              'repository_root_binding_sha256', 'knowledge_root_binding_sha256',
              'git_root_binding_sha256', 'target_config_binding_sha256',
              'issuer_registry_binding_sha256'):
        need(value[k] == bind[k], 'TARGET_POLICY_BINDING_MISMATCH', 'unavailable')
    need(value['bootstrap_read_policy_binding_sha256'] == _digest_obj(
         'CES-EC202-READ-POLICY-v1', bootstrap_policy),
         'TARGET_POLICY_BOOTSTRAP_MISMATCH', 'unavailable')
    permits = ('permit_target_read', 'permit_delivery_signature_verification',
               'permit_git_object_read', 'permit_source_blob_compare',
               'permit_knowledge_manifest_bind', 'permit_target_oid_projection',
               'permit_source_digest_projection', 'permit_repository_write',
               'permit_knowledge_write', 'permit_business_source_write',
               'permit_issue_write', 'permit_publish')
    need(all(type(value[k]) is bool for k in permits), 'TARGET_POLICY_PERMIT_INVALID')
    need(value['permit_target_read'] and boundary.sha(value['read_receipt_sha256']),
         'TARGET_POLICY_READ_DENIED', 'unavailable')
    need(not any(value[k] for k in ('permit_repository_write',
            'permit_knowledge_write', 'permit_business_source_write',
            'permit_issue_write', 'permit_publish')), 'TARGET_POLICY_WRITE_FORBIDDEN',
         'unavailable')
    need(not value['permit_source_blob_compare'] or value['permit_git_object_read'],
         'TARGET_POLICY_BLOB_ESCALATION', 'unavailable')
    need(not value['permit_target_oid_projection'] or value['permit_git_object_read'],
         'TARGET_POLICY_OID_ESCALATION', 'unavailable')
    need(not value['permit_knowledge_manifest_bind'] or
         bootstrap_policy['permit_manifest_read'],
         'TARGET_POLICY_MANIFEST_ESCALATION', 'unavailable')
    grants = value['source_grants']
    need(type(grants) is list and len(grants) == len(bind['source_bindings']),
         'TARGET_POLICY_GRANTS_INCOMPLETE', 'unavailable')
    for grant, pin, row in zip(grants, bind['source_bindings'], req['sources']):
        bootstrap.fields(grant, {'source_key', 'source_binding_sha256',
              'permit_git_blob_compare', 'read_receipt_sha256'},
              'TARGET_POLICY_GRANT_FIELDS_INVALID')
        need(grant['source_key'] == pin['source_key'] and
             grant['source_binding_sha256'] == pin['source_binding_sha256'],
             'TARGET_POLICY_GRANT_BINDING_MISMATCH', 'unavailable')
        need(type(grant['permit_git_blob_compare']) is bool and
             (grant['read_receipt_sha256'] is None or
              boundary.sha(grant['read_receipt_sha256'])),
             'TARGET_POLICY_GRANT_INVALID')
        need(not grant['permit_git_blob_compare'] or
             (row['kind'] == 'repository' and value['permit_source_blob_compare']
              and boundary.sha(grant['read_receipt_sha256'])),
             'TARGET_POLICY_GRANT_ESCALATION', 'unavailable')
    return value


def _git_oid(raw: bytes, kind: str, algorithm: str) -> str:
    payload = kind.encode('ascii') + b' ' + str(len(raw)).encode('ascii') + b'\0' + raw
    return getattr(hashlib, algorithm)(payload).hexdigest()


def _git_sandbox(root_path: str) -> tuple[str, str]:
    """Allow the final reserved `.git` component only, opened nofollow.

    The main EC202 root walker deliberately prohibits `.git` in arbitrary
    paths. This dedicated path pins its inode through the opened repository fd.
    """
    git_dir = root_path + '/.git'
    repo_fd: int | None = None
    fd: int | None = None
    try:
        repo_fd, _ = bootstrap._open_bound_root(root_path, permit_missing=False)
        need(repo_fd is not None, 'GIT_REPOSITORY_ROOT_UNAVAILABLE', 'unavailable')
        fd = os.open('.git', bootstrap.DIRECTORY_FLAGS, dir_fd=repo_fd)
        pin = _digest_obj('CES-EC203-GIT-ROOT-v1', {
            'repository_root': root_path,
            'directory': bootstrap._fingerprint(os.fstat(fd))})
        for subdir in ('objects', 'refs'):
            sub_fd = os.open(subdir, bootstrap.DIRECTORY_FLAGS, dir_fd=fd)
            os.close(sub_fd)
        for forbidden in ('commondir', 'shallow', 'info/grafts',
                          'objects/info/alternates', 'objects/info/http-alternates'):
            try:
                parent = fd
                opened: list[int] = []
                try:
                    parts = forbidden.split('/')
                    for part in parts[:-1]:
                        parent_fd = os.open(part, bootstrap.DIRECTORY_FLAGS, dir_fd=parent)
                        opened.append(parent_fd)
                        parent = parent_fd
                    os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                finally:
                    for descriptor in reversed(opened):
                        os.close(descriptor)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise TargetError('GIT_LAYOUT_UNAVAILABLE', 'unavailable') from exc
            raise TargetError('GIT_INDIRECT_OBJECTS_FORBIDDEN', 'unavailable')
    except (FileNotFoundError, OSError, bootstrap.BootstrapError) as exc:
        raise TargetError('GIT_LAYOUT_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)
        if repo_fd is not None:
            os.close(repo_fd)
    return git_dir, pin


class _GitReader:
    """Bounded local plumbing calls, no shell/network, with controlled env/timeout."""

    def __init__(self, git_dir: str, executable: str) -> None:
        self.git_dir, self.executable = git_dir, executable

    def _run(self, args: list[str], limit: int = 2048) -> bytes:
        env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
               'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null',
               'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0',
               'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '0',
               'GIT_NO_LAZY_FETCH': '1'}
        cmd = [self.executable, '--no-replace-objects',
               '--git-dir=' + self.git_dir, *args]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                    env=env, close_fds=True)
        except OSError as exc:
            raise TargetError('GIT_EXEC_UNAVAILABLE', 'unavailable') from exc
        payload = bytearray()
        try:
            with selectors.DefaultSelector() as select:
                assert proc.stdout is not None
                select.register(proc.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 4.0
                while select.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TargetError('GIT_COMMAND_TIMEOUT', 'unavailable')
                    ready = select.select(remaining)
                    if not ready:
                        raise TargetError('GIT_COMMAND_TIMEOUT', 'unavailable')
                    for key, _ in ready:
                        chunk = os.read(key.fileobj.fileno(), min(8192, limit + 1 - len(payload)))
                        if not chunk:
                            select.unregister(key.fileobj)
                        else:
                            payload.extend(chunk)
                            if len(payload) > limit:
                                raise TargetError('GIT_OUTPUT_LIMIT', 'unavailable')
            try:
                code = proc.wait(timeout=max(0.05, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise TargetError('GIT_COMMAND_TIMEOUT', 'unavailable') from exc
            if code != 0:
                raise TargetError('GIT_COMMAND_FAILED', 'unavailable')
            return bytes(payload)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()

    def target_commit(self, revision: dict[str, str], target_ref: str) -> dict[str, str]:
        algorithm = revision['algorithm']
        fmt = self._run(['rev-parse', '--show-object-format=storage']).decode('ascii').strip()
        need(fmt == algorithm, 'GIT_OBJECT_FORMAT_MISMATCH', 'unavailable')
        oid = revision['oid']
        before = self._run(['show-ref', '--verify', '--hash', target_ref]).decode('ascii').strip()
        need(GIT_OID.fullmatch(before) is not None, 'GIT_REF_OUTPUT_INVALID', 'unavailable')
        kind = self._run(['cat-file', '-t', oid]).decode('ascii').strip()
        need(kind == 'commit', 'TARGET_NOT_COMMIT', 'unavailable')
        size_raw = self._run(['cat-file', '-s', oid]).decode('ascii').strip()
        need(size_raw.isascii() and size_raw.isdecimal() and int(size_raw) <= MAX_COMMIT,
             'COMMIT_SIZE_UNAVAILABLE', 'unavailable')
        content = self._run(['cat-file', 'commit', oid], MAX_COMMIT)
        need(len(content) == int(size_raw) and _git_oid(content, 'commit', algorithm) == oid,
             'COMMIT_OBJECT_HASH_MISMATCH', 'unavailable')
        return {'ref_before': before, 'object_format': algorithm, 'commit_oid': oid}

    def ref_after(self, target_ref: str) -> str:
        after = self._run(['show-ref', '--verify', '--hash', target_ref]).decode('ascii').strip()
        need(GIT_OID.fullmatch(after) is not None, 'GIT_REF_OUTPUT_INVALID', 'unavailable')
        return after

    def blob_at_path(self, commit: str, path: str, algorithm: str) -> tuple[str, str | None]:
        data = self._run(['ls-tree', '-rz', '--full-tree', commit, '--', path], 4096)
        if not data:
            return 'PATH_NOT_IN_TARGET_TREE', None
        records = data.rstrip(b'\0').split(b'\0')
        if len(records) != 1 or b'\t' not in records[0]:
            return 'TREE_PATH_AMBIGUOUS', None
        meta, raw_path = records[0].split(b'\t', 1)
        if raw_path != path.encode('ascii'):
            return 'TREE_PATH_AMBIGUOUS', None
        parts = meta.split(b' ')
        if len(parts) != 3 or parts[0] not in (b'100644', b'100755') or parts[1] != b'blob':
            return 'UNSAFE_GIT_ENTRY', None
        blob_oid = parts[2].decode('ascii')
        if (not GIT_OID.fullmatch(blob_oid) or
                len(blob_oid) != (40 if algorithm == 'sha1' else 64)):
            return 'TREE_BLOB_OID_INVALID', None
        size_bytes = self._run(['cat-file', '-s', blob_oid]).decode('ascii').strip()
        if not size_bytes.isascii() or not size_bytes.isdecimal():
            return 'TREE_BLOB_SIZE_INVALID', None
        if int(size_bytes) > MAX_GIT_BYTES:
            return 'TREE_BLOB_OVERSIZED', None
        raw = self._run(['cat-file', 'blob', blob_oid], MAX_GIT_BYTES)
        if len(raw) != int(size_bytes) or _git_oid(raw, 'blob', algorithm) != blob_oid:
            return 'TREE_BLOB_HASH_MISMATCH', None
        return 'GIT_BLOB_READ', hashlib.sha256(raw).hexdigest()


def _base() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'KNOWLEDGE_TARGET_INVALID_INPUT',
            'subject': None, 'canonical_json': None, 'limitations': dict(LIMITATIONS)}


class KnowledgeTargetBinding:
    """Host-pinned bridge from EC202 bytes to a signed exact Git target.

    Signatures are verified against *only* keys configured at construction; a
    submitted statement, OID, permission bit, or branch name grants no trust.
    """

    def __init__(self, *, repository_root: str, knowledge_root: str,
                 repository_ref: str, target_ref: str, trusted_ed25519_keys: dict[str, bytes],
                 git_executable: str | None = None) -> None:
        self.bootstrap = bootstrap.KnowledgeBootstrap(
            repository_root=repository_root, knowledge_root=knowledge_root)
        need(type(repository_ref) is str and
             boundary.REPO.fullmatch(repository_ref) is not None,
             'HOST_REPOSITORY_IDENTITY_INVALID')
        self.repository_ref = repository_ref
        self.target_ref = _ref(target_ref)
        need(type(trusted_ed25519_keys) is dict and len(trusted_ed25519_keys) <= 16,
             'HOST_SIGNERS_INVALID')
        self.keys = {}
        for key_id, pub in trusted_ed25519_keys.items():
            need(boundary.key(key_id) and type(pub) is bytes and len(pub) == 32,
                 'HOST_SIGNER_KEY_INVALID')
            self.keys[key_id] = pub
        executable = git_executable or shutil.which('git')
        need(executable is not None and type(executable) is str and
             os.path.isabs(executable) and os.path.isfile(executable),
             'HOST_GIT_EXECUTABLE_UNAVAILABLE', 'unavailable')
        self.git_executable = executable

    def _preview(self, req: dict[str, Any]) -> dict[str, Any]:
        need(req['scope']['repository_ref'] == self.repository_ref,
             'HOST_REPOSITORY_SCOPE_MISMATCH', 'unavailable')
        preview = self.bootstrap.binding_preview(request_json=boundary.canonical(req))
        if preview['status'] != 'partial':
            raise TargetError('BOOTSTRAP_ROOTS_UNAVAILABLE', 'unavailable')
        git_dir, git_pin = _git_sandbox(self.bootstrap.repository_root)
        original = preview['subject']
        return {**original, 'git_root_binding_sha256': git_pin,
                'target_config_binding_sha256': _digest_obj(
                    'CES-EC203-HOST-TARGET-v1', {
                       'target_ref': self.target_ref,
                       'repository_ref': self.repository_ref,
                       'repository_root_binding_sha256': original['repository_root_binding_sha256'],
                       'git_root_binding_sha256': git_pin}),
                'issuer_registry_binding_sha256': _digest_obj(
                    'CES-EC203-HOST-ISSUERS-v1', [
                     {'key_id': k, 'public_key_sha256': hashlib.sha256(v).hexdigest()}
                     for k, v in sorted(self.keys.items())])}

    def binding_preview(self, *, request_json: str) -> dict[str, Any]:
        out = _base()
        try:
            req = bootstrap._request(boundary._json(request_json, bootstrap.MAX_REQUEST))
            pins = self._preview(req)
            out.update(status='partial', exit_code=2,
                reason_code='KNOWLEDGE_TARGET_BINDINGS_ONLY', subject=pins,
                canonical_json=boundary.canonical(pins))
        except (TargetError, bootstrap.BootstrapError, boundary.KnowledgeBoundaryError) as ex:
            status = ex.status if hasattr(ex, 'status') else 'unavailable'
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_TARGET_' + getattr(ex, 'code', getattr(ex, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, ValueError, UnicodeError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_TARGET_SOURCE_UNAVAILABLE')
        return out

    def verify(self, *, request_json: str, bootstrap_read_policy_json: str,
               target_read_policy_json: str, delivery_statement_json: str | None = None,
               delivery_signature_base64: str | None = None) -> dict[str, Any]:
        out = _base()
        try:
            req = bootstrap._request(boundary._json(request_json, bootstrap.MAX_REQUEST))
            pins = self._preview(req)
            bp = boundary._json(bootstrap_read_policy_json, bootstrap.MAX_POLICY)
            # Validate EC202's entire policy shape and all grant/namespace pins
            # before EC203 inspects any of its permission fields.
            bootstrap._policy(bp, req, pins)
            policy = _policy(boundary._json(target_read_policy_json, MAX_POLICY), req, pins, bp)
            # Authorization must bind both reads; real EC202 byte observations
            # are obtained without creating a new, more permissive policy.
            observed = self.bootstrap.read(request_json=boundary.canonical(req),
                 read_policy_json=bootstrap_read_policy_json)
            if observed['status'] != 'partial':
                raise TargetError('BOOTSTRAP_READ_UNAVAILABLE', 'unavailable')
            bsubject = observed['subject']
            if bsubject['root_bindings'] != {
               'repository': pins['repository_root_binding_sha256'],
               'ces_knowledge': pins['knowledge_root_binding_sha256']}:
                raise TargetError('ROOT_CHANGED_SINCE_BINDING', 'unavailable')
            statement = None
            sigstate = 'ATTESTATION_MISSING'
            signed_scope = False
            if delivery_statement_json is not None:
                statement = _statement(boundary._json(delivery_statement_json, MAX_STATEMENT))
                if policy['permit_delivery_signature_verification']:
                    sigstate = _verify_signature(statement, delivery_signature_base64, self.keys)
                    signed_scope = _matches_scope(statement, req, pins, self.target_ref)
                    if sigstate == 'SIGNATURE_VERIFIED_CONFIGURED_KEY' and not signed_scope:
                        sigstate = 'SIGNED_STATEMENT_SCOPE_OR_PERIOD_MISMATCH'
                else:
                    sigstate = 'SIGNATURE_CHECK_DENIED_NOT_INSPECTED'
            revision = req['scope']['target']['revision']
            git_state = 'GIT_READ_DENIED_NOT_INSPECTED'
            ref_before: str | None = None
            ref_after: str | None = None
            fmt: str | None = None
            reader: _GitReader | None = None
            if policy['permit_git_object_read']:
                if revision is None:
                    git_state = 'TARGET_REVISION_UNKNOWN'
                else:
                    try:
                        _git_sandbox(self.bootstrap.repository_root)
                        reader = _GitReader(self.bootstrap.repository_root + '/.git',
                                            self.git_executable)
                        commit = reader.target_commit(revision, self.target_ref)
                        fmt = commit['object_format']
                        ref_before = commit['ref_before']
                        git_state = ('GIT_COMMIT_OBJECT_VERIFIED_REF_MATCH' if
                            ref_before == revision['oid'] else 'GIT_COMMIT_VERIFIED_REF_DIFFERENT')
                    except TargetError as exc:
                        git_state = exc.code
                        reader = None
            verified_target = False
            source_results: list[dict[str, Any]] = []
            for row, src, grant in zip(req['sources'], bsubject['sources'], policy['source_grants']):
                kind = row['kind']
                result = {'source_key': row['source_key'], 'kind': kind,
                    'relative_path': row['relative_path'],
                    'bootstrap_state': src['state'],
                    'target_blob_state': 'NOT_A_GIT_REPOSITORY_SOURCE' if kind != 'repository'
                                          else 'DENIED_NOT_INSPECTED',
                    'source_sha256': None, 'git_blob_sha256': None,
                    'matched_verified_delivery': False}
                if kind == 'repository' and grant['permit_git_blob_compare']:
                    if src['state'] != 'READ_UNVERIFIED':
                        result['target_blob_state'] = 'BOOTSTRAP_SOURCE_NOT_READ'
                    elif src['observed_sha256'] is None:
                        result['target_blob_state'] = 'BOOTSTRAP_PROVENANCE_NOT_GRANTED'
                    elif reader is None or git_state != 'GIT_COMMIT_OBJECT_VERIFIED_REF_MATCH':
                        result['target_blob_state'] = 'GIT_TARGET_NOT_VERIFIED_AT_REF'
                    else:
                        try:
                            state, digest = reader.blob_at_path(revision['oid'],
                                                     row['relative_path'], fmt)
                            result['target_blob_state'] = state
                            if state == 'GIT_BLOB_READ':
                                result['target_blob_state'] = ('TARGET_BLOB_BYTES_EQUAL' if
                                    digest == src['observed_sha256'] else
                                    'WORKTREE_DIFFERS_FROM_TARGET_BLOB')
                                if policy['permit_source_digest_projection']:
                                    result['source_sha256'] = src['observed_sha256']
                                    result['git_blob_sha256'] = digest
                        except TargetError as exc:
                            result['target_blob_state'] = exc.code
                source_results.append(result)
            if reader is not None:
                try:
                    ref_after = reader.ref_after(self.target_ref)
                except TargetError:
                    git_state = 'GIT_REF_FINAL_READ_UNAVAILABLE'
                else:
                    if ref_after != ref_before:
                        git_state = 'GIT_REF_CHANGED_DURING_CHECK'
                # Check pinned directory/root identity after git has run.
                try:
                    postpins = self._preview(req)
                    if any(postpins[field] != pins[field] for field in ('git_root_binding_sha256', 'repository_root_binding_sha256', 'knowledge_root_binding_sha256')):
                        git_state = 'GIT_ROOT_CHANGED_DURING_CHECK'
                except (TargetError, bootstrap.BootstrapError):
                    git_state = 'GIT_ROOT_CHANGED_DURING_CHECK'
            if (sigstate == 'SIGNATURE_VERIFIED_CONFIGURED_KEY' and signed_scope and
                git_state == 'GIT_COMMIT_OBJECT_VERIFIED_REF_MATCH' and
                ref_after == ref_before == revision['oid']):
                verified_target = True
            for result in source_results:
                if (result['kind'] == 'repository' and
                    result['target_blob_state'] == 'TARGET_BLOB_BYTES_EQUAL'):
                    result['target_blob_state'] = ('SIGNED_DELIVERY_TARGET_BLOB_MATCH' if
                        verified_target else 'LOCAL_GIT_BLOB_MATCH_DELIVERY_UNVERIFIED')
                    result['matched_verified_delivery'] = verified_target
            manifest = bsubject['knowledge_manifest']
            manifest_state = 'KNOWLEDGE_MANIFEST_NOT_GIT_DELIVERY_PROOF'
            if policy['permit_knowledge_manifest_bind'] and verified_target:
                manifest_state = ('SIGNED_MANIFEST_DIGEST_MATCH' if
                      statement is not None and
                      statement['knowledge_manifest_sha256'] is not None and
                      manifest['manifest_sha256'] == statement['knowledge_manifest_sha256']
                      and manifest['state'] in ('MANIFEST_READ_UNVERIFIED',
                         'EMPTY_MANIFEST_DECLARED_UNVERIFIED') else
                      'MANIFEST_NOT_PINNED_OR_NOT_READ')
            verified_keys = [r['source_key'] for r in source_results
                             if r['matched_verified_delivery']]
            all_repo = [r for r in source_results if r['kind'] == 'repository']
            eligible = bool(all_repo) and len(verified_keys) == len(all_repo)
            gaps = [{'source_key': r['source_key'], 'state': r['target_blob_state']}
                    for r in source_results if r['kind'] == 'repository' and
                    not r['matched_verified_delivery']]
            if not verified_target:
                gaps.append({'source_key': None, 'state': 'TARGET_DELIVERY_NOT_AUTHENTICATED'})
            if manifest_state != 'SIGNED_MANIFEST_DIGEST_MATCH':
                gaps.append({'source_key': None, 'state': 'KNOWLEDGE_SNAPSHOT_NOT_AUTHENTICATED'})
            if any(r['kind'] == 'ces_knowledge' and r['bootstrap_state'] != 'READ_UNVERIFIED'
                   for r in source_results):
                gaps.append({'source_key': None, 'state': 'KNOWLEDGE_SNAPSHOT_SOURCE_GAPS'})
            delivery_state = ('SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF' if verified_target
                              else 'TARGET_DELIVERY_UNKNOWN')
            subject = {'model_revision': 'EC203_BOUNDED_LOCAL_GIT_SIGNED_TARGET_BINDING',
                'repository_ref': req['scope']['repository_ref'],
                'knowledge_space_key': req['scope']['knowledge_space_key'],
                'period_id': req['scope']['period']['period_id'],
                'scope_binding_sha256': pins['scope_binding_sha256'],
                'request_binding_sha256': pins['request_binding_sha256'],
                'bootstrap_policy_binding_sha256': _digest_obj('CES-EC202-READ-POLICY-v1', bp),
                'target_policy_binding_sha256': _digest_obj('CES-EC203-TARGET-POLICY-v1', policy),
                'git_root_binding_sha256': pins['git_root_binding_sha256'],
                'target_config_binding_sha256': pins['target_config_binding_sha256'],
                'target_ref': self.target_ref if policy['permit_target_oid_projection'] else None,
                'target_revision': revision if policy['permit_target_oid_projection'] else None,
                'signature_state': sigstate,
                'git_object_state': git_state,
                'git_ref_relation': ('SAMPLED_MATCH' if revision is not None and
                                      ref_after is not None and ref_after == ref_before == revision['oid'] else
                                     'NOT_ESTABLISHED_OR_DIVERGED'),
                'delivery_state': delivery_state,
                'knowledge_manifest_state': manifest_state,
                'sources': source_results, 'coverage_gaps': gaps,
                'bootstrap_coverage_gaps': bsubject['coverage_gaps'],
                'summary': {'requested_sources': len(source_results),
                    'repository_sources': len(all_repo),
                    'target_sources_bound_to_signed_delivery': len(verified_keys),
                    'trusted_target_ref_sampled': verified_target,
                    'eligible_for_ec204_source_diff': eligible,
                    'verified_architecture_facts': 0},
                'verified_target_source_bindings': verified_keys,
                'verified_delivered_facts': [],
                'current_architecture_state': 'UNKNOWN_NOT_SEMANTICALLY_VERIFIED',
                'no_write_actions_performed': True,
                'next_unimplemented': ['EC204_KNOWLEDGE_IMPACT',
                       'EC206_CANDIDATE_SEPARATION', 'EC208_KNOWLEDGE_SAVE',
                       'NATIVE_POWERSHELL_KNOWLEDGE_ROUTE']}
            out.update(status='partial', exit_code=2,
                reason_code=('KNOWLEDGE_TARGET_SIGNED_GIT_BINDING_PARTIAL' if verified_target
                    else 'KNOWLEDGE_TARGET_DELIVERY_UNVERIFIED'),
                subject=subject, canonical_json=boundary.canonical(subject))
        except (TargetError, bootstrap.BootstrapError,
                boundary.KnowledgeBoundaryError) as exc:
            status = getattr(exc, 'status', 'unavailable')
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_TARGET_' + getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_TARGET_SOURCE_UNAVAILABLE')
        return out

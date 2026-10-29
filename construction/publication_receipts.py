#!/usr/bin/env python3
"""EC230: independently permitted private receipt readback and safe local cleanup.

Never invokes EC228 publish, EC229 push, a remote mutation, Git reset, or ref
removal. The original spent-once journals stay intact forever. Readback is
new, separately authorized, and journaled *before* any provider GET. A clean,
positively identified EC229 linked worktree may be removed with a separate
fresh custodian signature only after an independently recorded exact-ref proof.

The historical EC228/229 signatures can be cryptographically checked after
expiry. Such retrospective checks are NOT trusted timestamps or evidence that
the original publisher actually held live permission at the earlier edge.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import ssl

try:
    from . import delivery_authorization as da, delivery_preview as dp
    from . import report_publish as rp, docs_only_publish as gitp
    from . import delivery_send as ds
except ImportError:
    import delivery_authorization as da
    import delivery_preview as dp
    import report_publish as rp
    import docs_only_publish as gitp
    import delivery_send as ds

SCHEMA = 'ces.publication_receipt.v1'
READ_SCHEMA = 'ces.publication_receipt.read_grant.v1'
CLEAN_SCHEMA = 'ces.publication_receipt.cleanup_grant.v1'
PROVIDER_SCHEMA = 'ces.publication_receipt.provider_observation.v1'
PROBE_SCHEMA = 'ces.publication_receipt.provider_query.v1'
READ_DOMAIN = b'CES-EC230-INDEPENDENT-PUBLICATION-READ-GRANT-v1\0'
CLEAN_DOMAIN = b'CES-EC230-INDEPENDENT-WORKTREE-CLEANUP-GRANT-v1\0'
PROVIDER_DOMAIN = b'CES-EC230-PROVIDER-PRIVATE-RECEIPT-READBACK-v1\0'
CODE_DOMAIN = b'CES-EC230-RECEIPT-AND-ORIGINAL-PUBLISH-CODE-v1\0'
READ_ID_DOMAIN = b'CES-EC230-ONE-SIGNED-INSPECTION-v1\0'
OBS_DOMAIN = b'CES-EC230-EXACT-OBSERVATION-v1\0'
MODE_REPORT = 'EC228_PRIVATE_REPORT'
MODE_DOCS = 'EC229_PRIVATE_DOCS'
READ_PERMISSION = 'READ_ONE_PRIVATE_PUBLICATION_RECEIPT'
CLEAN_PERMISSION = 'REMOVE_ONLY_VERIFIED_CLEAN_LOCAL_LINKED_WORKTREE'
MAX_GRANT_SECONDS = 40
MAX_OBSERVATION_AGE = 60
MAX_RESPONSE_BYTES = 8192
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
NONCE = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
_ALLOWED_REPORT = frozenset(('00_RESERVED_DURABLE', '01_CAPABILITY_REQUESTED',
    '02_CAPABILITY_VERIFIED', '03_POST_ATTEMPTED', '04_POST_RETURNED', '05_POST_UNKNOWN'))
_ALLOWED_DOCS = frozenset(('00_CLAIM_DURABLE', '01_WORKTREE_ATTEMPTED',
    '02_WORKTREE_READY', '03_DOCS_WRITTEN', '04_COMMIT_ATTEMPTED',
    '05_COMMIT_CREATED', '06_PUSH_ATTEMPTED', '07_SANDBOX_REF_OBSERVED'))


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha(value: Any) -> bool:
    return type(value) is str and SHA.fullmatch(value) is not None


def _time() -> int:
    n = time.time()
    _need(type(n) in (int, float) and math.isfinite(n) and
          946684800 <= n <= 4102444800, 'TRUSTED_CLOCK_UNAVAILABLE', 'unavailable')
    return int(n)


def _code_hash() -> str | None:
    try:
        root = Path(__file__).resolve().parent
        return dp.sha(CODE_DOMAIN, {name: _hash((root / name).read_bytes()) for name in (
            'publication_receipts.py', 'report_publish.py', 'docs_only_publish.py',
            'delivery_authorization.py', 'delivery_preview.py')})
    except (OSError, ValueError, TypeError):
        return None


ACTIVE_CODE_SHA256 = _code_hash()


class ReceiptDenied(ValueError):
    def __init__(self, code: str, status: str = 'blocked'):
        super().__init__(code)
        self.code = code
        self.status = status


def _need(condition: bool, code: str, status: str = 'blocked') -> None:
    if not condition:
        raise ReceiptDenied(code, status)


def _safe_private_dir(path: str) -> tuple[str, tuple[int, int]]:
    try:
        actual, inode = gitp._safe_directory(path, private=True)
        fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            _need((st.st_dev, st.st_ino) == inode and st.st_uid == os.geteuid() and
                  stat.S_IMODE(st.st_mode) & 0o077 == 0,
                  'PRIVATE_DIRECTORY_RACED', 'unavailable')
        finally:
            os.close(fd)
        return actual, inode
    except gitp.DocsDenied:
        raise ReceiptDenied('PINNED_PRIVATE_DIRECTORY_UNAVAILABLE', 'unavailable') from None
    except OSError:
        raise ReceiptDenied('PRIVATE_DIRECTORY_UNAVAILABLE', 'unavailable') from None


def _window(doc: dict[str, Any], now: int, max_age: int = MAX_GRANT_SECONDS) -> None:
    i, e = doc.get('issued_at'), doc.get('expires_at')
    _need(type(i) is int and type(e) is int and
          946684800 <= i < e <= 4102444800 and e - i <= max_age and
          now - max_age <= i <= now + 5 and now < e,
          'FRESH_INDEPENDENT_GRANT_REQUIRED')


def _signed(statement: Any, key: bytes, domain: bytes,
            fields: set[str], label: str) -> dict[str, Any]:
    try:
        body, sig = da._snapshot_signed(statement, label)
        da.exact(body, fields, label + '_FIELDS_INVALID')
        da._verify_signature(key, domain, body, sig, label)
        return body
    except da.AuthorizationDenied as exc:
        raise ReceiptDenied(exc.code, exc.status) from None


def _historical_overlap(statements: tuple[da.SignedAuthorizationStatement, ...],
                        current: int) -> int:
    """Only find a signed-time intersection; no retrospective clock claim."""
    try:
        issuance = [s.statement['issued_at'] for s in statements]
        expiry = [s.statement['expires_at'] for s in statements]
        _need(all(type(n) is int for n in issuance + expiry),
              'ORIGINAL_SIGNED_INTERVAL_INVALID')
        t = max(issuance)
        _need(t < min(expiry) and t <= current + 5,
              'ORIGINAL_AUTHORIZATIONS_NEVER_OVERLAPPED')
        return t
    except (TypeError, AttributeError, KeyError, ValueError):
        raise ReceiptDenied('ORIGINAL_SIGNED_HISTORY_INVALID') from None


def _view_markers(root: str, slot: str, required: str, allowed: frozenset[str],
                  payload_markers: frozenset[str] = frozenset()
                  ) -> tuple[frozenset[str], dict[str, bytes], str]:
    """Owner-0700 slot, no symlinks, extra markers or nonempty arbitrary data.

    The digest is of the *observed* marker evidence, not a trusted clock, and
    is included in the inspection record. Never delete or change this slot.
    """
    base, _ = _safe_private_dir(root)
    path = base + '/' + slot
    try:
        _safe_private_dir(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = os.listdir(fd)
            _need(len(names) <= len(allowed) and len(names) == len(set(names)) and
                  required in names and set(names).issubset(allowed),
                  'ORIGINAL_JOURNAL_INCOMPLETE_OR_EXTRA_ENTRIES')
            payloads: dict[str, bytes] = {}
            for name in sorted(names):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                item = os.open(name, flags, dir_fd=fd)
                try:
                    st = os.fstat(item)
                    _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                          st.st_uid == os.geteuid() and
                          stat.S_IMODE(st.st_mode) & 0o077 == 0 and
                          st.st_size <= 1024,
                          'ORIGINAL_JOURNAL_MARKER_NOT_PRIVATE_REGULAR')
                    raw = os.read(item, 1025)
                    _need(len(raw) == st.st_size, 'ORIGINAL_JOURNAL_MARKER_RACED')
                    if name not in payload_markers:
                        _need(not raw, 'ORIGINAL_JOURNAL_MARKER_CONTENT_UNEXPECTED')
                    elif raw:
                        _need(len(raw) == 40 and gitp.GIT_SHA.fullmatch(
                              raw.decode('ascii', 'strict')) is not None,
                              'ORIGINAL_JOURNAL_COMMIT_MARKER_INVALID')
                    payloads[name] = raw
                finally:
                    os.close(item)
        finally:
            os.close(fd)
        seen = frozenset(names)
        if slot.startswith('ec228-'):
            _need(not ({'04_POST_RETURNED', '05_POST_UNKNOWN'} <= seen),
                  'CONTRADICTORY_ORIGINAL_HTTP_RESULT')
            if '03_POST_ATTEMPTED' in seen:
                _need({'00_RESERVED_DURABLE', '01_CAPABILITY_REQUESTED',
                       '02_CAPABILITY_VERIFIED'} <= seen,
                      'ORIGINAL_HTTP_STAGE_GAP')
            if '04_POST_RETURNED' in seen or '05_POST_UNKNOWN' in seen:
                _need('03_POST_ATTEMPTED' in seen, 'ORIGINAL_HTTP_STAGE_GAP')
        else:
            ordered = ('00_CLAIM_DURABLE', '01_WORKTREE_ATTEMPTED',
                       '02_WORKTREE_READY', '03_DOCS_WRITTEN',
                       '04_COMMIT_ATTEMPTED', '05_COMMIT_CREATED',
                       '06_PUSH_ATTEMPTED', '07_SANDBOX_REF_OBSERVED')
            for idx, name in enumerate(ordered):
                if name in seen:
                    _need(set(ordered[:idx]) <= seen, 'ORIGINAL_GIT_STAGE_GAP')
            if '07_SANDBOX_REF_OBSERVED' in seen:
                _need(payloads['07_SANDBOX_REF_OBSERVED'] ==
                      payloads['05_COMMIT_CREATED'] and
                      bool(payloads['05_COMMIT_CREATED']),
                      'ORIGINAL_GIT_MARKER_SHA_CONFLICT')
        digest = dp.sha(OBS_DOMAIN, {'markers': [
            {'name': name, 'payload_sha256': _hash(payloads[name])}
            for name in sorted(seen)]})
        return seen, payloads, digest
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        raise ReceiptDenied('ORIGINAL_JOURNAL_EVIDENCE_UNAVAILABLE', 'unavailable') from None


def _envelope(mode: str, operation: str | None, *, status: str = 'unavailable',
              reason: str = 'UNKNOWN_UNCONFIRMED', state: str = 'UNKNOWN_UNCONFIRMED',
              inspection_id: str | None = None, observation_sha256: str | None = None,
              provider_read_attempted: bool = False, clean_attempted: bool = False,
              clean_completed: bool = False, historical_journal_present: bool = False,
              evidence_kind: str = 'NONE') -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'mode': mode, 'operation_id': operation,
        'status': status, 'exit_code': 2 if status == 'partial' else
            4 if status in ('blocked', 'invalid_input') else 5,
        'reason_code': 'PUBLICATION_RECEIPT_' + reason,
        'receipt_state': state, 'inspection_id': inspection_id,
        'observation_sha256': observation_sha256, 'evidence_kind': evidence_kind,
        'historical_journal_present': historical_journal_present,
        'provider_receipt_read_attempted': provider_read_attempted,
        'cleanup_attempted': clean_attempted,
        'local_worktree_cleanup_confirmed': clean_completed,
        'public_or_production_published': False,
        'external_publication_confirmed': False,
        'original_post_or_push_retried': False,
        'remote_ref_or_provider_content_deleted': False,
        'original_journal_deleted': False,
        'original_source_or_index_modified': False,
    }


@dataclass(frozen=True)
class ReceiptRoots:
    read_public_key: bytes
    cleanup_public_key: bytes
    minimum_receipt_epoch: int


@dataclass(frozen=True)
class HostReceiptScope:
    roots: ReceiptRoots
    audit_root: str
    enable_readback: bool
    enable_clean_linked_worktree: bool
    allow_synthetic_receipt_reader_for_development: bool = False
    provider_read_credential: str = ''  # separately scoped, never the EC228 POST token


class ProviderReceiptPort(Protocol):
    def read(self, target: rp.HostPrivatePublishTarget, credential: str,
             challenge: dict[str, Any]) -> da.SignedAuthorizationStatement: ...


class HTTPSPrivateReceiptReader:
    """Only GET fixed /receipts/<operation>?nonce=<nonce>, no POST/retry/redirect."""
    def __init__(self, timeout_seconds: float = 5.0):
        if type(timeout_seconds) not in (int, float) or not 0.5 <= timeout_seconds <= 8:
            raise ValueError('BOUNDED_RECEIPT_TIMEOUT_REQUIRED')
        self.timeout = float(timeout_seconds)
        self.opener = build_opener(ProxyHandler({}), ds._NoRedirect(),
                                   HTTPSHandler(context=ssl.create_default_context()))

    def read(self, target: rp.HostPrivatePublishTarget, credential: str,
             challenge: dict[str, Any]) -> da.SignedAuthorizationStatement:
        _need(ds._url_ok(target.endpoint) and
              _sha(challenge['operation_id']) and
              type(challenge['challenge_nonce']) is str and
              NONCE.fullmatch(challenge['challenge_nonce']) is not None,
              'UNSAFE_PROVIDER_RECEIPT_ROUTE', 'unavailable')
        url = (target.endpoint.rstrip('/') + '/receipts/' +
               quote(challenge['operation_id'], safe='') + '?nonce=' +
               quote(challenge['challenge_nonce'], safe=''))
        req = Request(url, headers={
            'Authorization': 'Bearer ' + credential,
            'Accept': 'application/json', 'Cache-Control': 'no-store',
            'User-Agent': 'CES-EC230/1'}, method='GET')
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                _need(resp.status == 200, 'PROVIDER_RECEIPT_NOT_HTTP_200', 'unavailable')
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                _need(len(raw) <= MAX_RESPONSE_BYTES,
                      'PROVIDER_RECEIPT_TOO_LARGE', 'unavailable')
            def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
                _need(len(items) == len({key for key, _ in items}),
                      'PROVIDER_DUPLICATE_JSON_KEY', 'unavailable')
                return dict(items)
            obj = json.loads(raw, object_pairs_hook=pairs)
            _need(type(obj) is dict and set(obj) == {'statement', 'signature_hex'},
                  'PROVIDER_RECEIPT_ENVELOPE_INVALID', 'unavailable')
            return da.SignedAuthorizationStatement(obj['statement'], obj['signature_hex'])
        except ReceiptDenied:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError,
                UnicodeError, ValueError, TypeError, ConnectionError):
            raise ReceiptDenied('PROVIDER_RECEIPT_UNKNOWN_NO_RETRY', 'unavailable') from None


class AuditSlot:
    """New EC230-only append-once evidence slots. Original slots not modified."""
    def __init__(self, root: str):
        self.root = root
        self.parent: int | None = None
        self.slot: int | None = None

    def __enter__(self) -> 'AuditSlot':
        path, _ = _safe_private_dir(self.root)
        try:
            self.parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            return self
        except OSError:
            raise ReceiptDenied('RECEIPT_AUDIT_UNAVAILABLE', 'unavailable') from None

    def claim(self, name: str, first: dict[str, Any]) -> None:
        _need(re.fullmatch(r'ec230-(?:read|clean)-[a-f0-9]{64}', name) is not None and
              self.parent is not None, 'RECEIPT_AUDIT_KEY_INVALID')
        try:
            os.mkdir(name, 0o700, dir_fd=self.parent)
            self.slot = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.parent)
            os.fsync(self.slot)
            os.fsync(self.parent)
            self.mark('00_CLAIM', first)
        except FileExistsError:
            raise ReceiptDenied('RECEIPT_AUDIT_CLAIM_SPENT_NO_RETRY') from None
        except OSError:
            raise ReceiptDenied('RECEIPT_AUDIT_CLAIM_DURABILITY_UNKNOWN', 'unavailable') from None

    def mark(self, name: str, value: dict[str, Any]) -> None:
        _need(self.slot is not None and name in ('00_CLAIM', '01_ATTEMPT',
              '02_OBSERVATION', '03_REMOVE_COMPLETED') and type(value) is dict,
              'RECEIPT_AUDIT_MARK_INVALID', 'unavailable')
        raw = dp.canonical(value)
        _need(0 < len(raw) <= 4096, 'RECEIPT_AUDIT_MARK_TOO_LARGE', 'unavailable')
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.slot)
            try:
                written = 0
                while written < len(raw):
                    n = os.write(fd, raw[written:])
                    if n <= 0:
                        raise OSError('no forward progress')
                    written += n
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self.slot)
        except OSError:
            raise ReceiptDenied('RECEIPT_AUDIT_MARK_DURABILITY_UNKNOWN', 'unavailable') from None

    def __exit__(self, *_: Any) -> None:
        for fd in (self.slot, self.parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.slot = self.parent = None


def _read_observation(root: str, inspection_id: str) -> dict[str, Any]:
    _need(_sha(inspection_id), 'INSPECTION_ID_INVALID')
    try:
        base, _ = _safe_private_dir(root)
        path, _ = _safe_private_dir(base + '/ec230-read-' + inspection_id)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = os.listdir(fd)
            _need(set(names) == {'00_CLAIM', '01_ATTEMPT', '02_OBSERVATION'},
                  'INSPECTION_AUDIT_INCOMPLETE')
            data: dict[str, Any] = {}
            for name in names:
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    st = os.fstat(f)
                    _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                          st.st_uid == os.geteuid() and st.st_size <= 4096 and
                          stat.S_IMODE(st.st_mode) & 0o077 == 0,
                          'INSPECTION_AUDIT_FILE_UNSAFE')
                    raw = os.read(f, 4097)
                    _need(len(raw) == st.st_size, 'INSPECTION_AUDIT_FILE_DRIFT')
                    def unique(pairs):
                        _need(len(pairs) == len(set(k for k, _ in pairs)),
                              'INSPECTION_AUDIT_DUPLICATE_KEY')
                        return dict(pairs)
                    value = json.loads(raw, object_pairs_hook=unique)
                    _need(type(value) is dict and dp.canonical(value) == raw,
                          'INSPECTION_AUDIT_NONCANONICAL')
                    data[name] = value
                finally:
                    os.close(f)
        finally:
            os.close(fd)
        return data
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ReceiptDenied('INSPECTION_AUDIT_READ_FAILED', 'unavailable') from None


class PublicationReceiptService:
    """Authorized EC228/EC229 receipt readback + EC229-only local cleanup."""
    def __init__(self, host: HostReceiptScope,
                 *, reader: ProviderReceiptPort | None = None):
        _need(type(host) is HostReceiptScope and type(host.roots) is ReceiptRoots,
              'PINNED_RECEIPT_HOST_REQUIRED', 'invalid_input')
        keys = (host.roots.read_public_key, host.roots.cleanup_public_key)
        _need(all(type(k) is bytes and len(k) == 32 and k != bytes(32)
                  for k in keys) and len(set(keys)) == 2 and
              type(host.roots.minimum_receipt_epoch) is int and
              1 <= host.roots.minimum_receipt_epoch < 2**63 and
              type(host.enable_readback) is bool and
              type(host.enable_clean_linked_worktree) is bool and
              type(host.allow_synthetic_receipt_reader_for_development) is bool,
              'INDEPENDENT_RECEIPT_AND_CUSTODIAN_ROOTS_REQUIRED', 'invalid_input')
        self.host = host
        self.audit, self.audit_inode = _safe_private_dir(host.audit_root)
        self.reader = reader if reader is not None else HTTPSPrivateReceiptReader()
        _need(type(self.reader) is HTTPSPrivateReceiptReader or
              host.allow_synthetic_receipt_reader_for_development is True,
              'SYNTHETIC_RECEIPT_PORT_NOT_ALLOWED', 'unavailable')
        _need(type(host.provider_read_credential) is str and
              len(host.provider_read_credential) <= 2048 and
              all(0x21 <= ord(c) <= 0x7e for c in host.provider_read_credential),
              'INVALID_HOST_READ_ONLY_CREDENTIAL', 'invalid_input')

    def _base(self, mode: str, original: Any, access: Any
              ) -> tuple[Any, str, str, str, str, dict[str, Any]]:
        """Reauthenticate ORIGINAL signers/payload/pins, never invoke an effect.

        The overlap epoch validates historical structural consistency ONLY; it
        does not establish when a real process claimed its original ledger.
        """
        now = _time()
        audit, audit_inode = _safe_private_dir(self.audit)
        _need(audit == self.audit and audit_inode == self.audit_inode,
              'RECEIPT_AUDIT_ROOT_REPLACED', 'unavailable')
        # Audit receipts must never be placed in the historic journal, the
        # original report content store, private Git bare, worktree, or source.
        # Even if a host accidentally configures overlapping paths, refuse.
        protected_roots = ((access.outbox_root, original.storage_root)
                           if mode == MODE_REPORT and
                           type(access) is rp.HostPublishAccess and
                           type(original) is rp.ReportPublishRequest else
                           (access.repository_root, access.journal_root,
                            access.worktree_root, access.sandbox_bare_root)
                           if mode == MODE_DOCS and
                           type(access) is gitp.HostDocsScope else ())
        for protected in protected_roots:
            _need(type(protected) is str and os.path.isabs(protected),
                  'ORIGINAL_PINNED_PATH_INVALID', 'invalid_input')
            protected = os.path.abspath(protected)
            _need(not (self.audit == protected or
                       self.audit.startswith(protected + '/') or
                       protected.startswith(self.audit + '/')),
                  'AUDIT_ROOT_MUST_BE_INDEPENDENT_OF_ORIGINAL_DATA', 'unavailable')
        if mode == MODE_REPORT:
            _need(type(access) is rp.HostPublishAccess and
                  type(original) is rp.ReportPublishRequest,
                  'ORIGINAL_EC228_INPUT_REQUIRED', 'invalid_input')
            keys = (access.roots.organization_public_key, access.roots.route_public_key,
                    access.roots.revocation_public_key,
                    access.roots.content_reviewer_public_key,
                    access.roots.side_effect_public_key,
                    access.roots.provider_public_key)
            _need(len(set(keys + (self.host.roots.read_public_key,
                                  self.host.roots.cleanup_public_key))) == 8,
                  'RECEIPT_ROOTS_MUST_NOT_REUSE_ORIGINAL_ROOTS')
            # Original publish capability may have been revoked/disabled since
            # the attempt; recheck historic *signed* bytes without re-enabling
            # a network POST. Fresh EC230 read permission is independent.
            pub = rp.ReportPublisher(replace(access, enable_private_test_publish=True))
            epoch = _historical_overlap((original.organization, original.route,
                         original.revocation, original.content_review,
                         original.side_effect_grant), now)
            checked = pub._verify(original, epoch)
            pub._read_exact(original, checked)
            operation = dp.sha(rp.OP_DOMAIN, {
                'report_slot_ref': checked['selection']['report_slot_ref'],
                'report_ref': original.report_ref,
                'rendered_sha256': original.rendered_sha256,
                'target_sha256': pub._target,
                'project_id': access.target.project_id})
            signed_grant_sha = checked['grant_sha256']
            pins = {'report_ref': original.report_ref,
                    'rendered_sha256': original.rendered_sha256,
                    'provider_id': access.target.provider_id,
                    'account_id': access.target.account_id}
            return pub, operation, pub._target, signed_grant_sha, access.outbox_root, pins
        _need(mode == MODE_DOCS and type(access) is gitp.HostDocsScope and
              type(original) is gitp.DocsOnlyPublishRequest,
              'ORIGINAL_EC229_INPUT_REQUIRED', 'invalid_input')
        keys = (access.roots.policy_public_key, access.roots.reviewer_public_key,
                access.roots.revocation_public_key, access.roots.side_effect_public_key)
        _need(len(set(keys + (self.host.roots.read_public_key,
                              self.host.roots.cleanup_public_key))) == 6,
              'RECEIPT_ROOTS_MUST_NOT_REUSE_ORIGINAL_ROOTS')
        pub = gitp.DocsOnlyPublisher(replace(
            access, enable_private_local_sandbox_publish=True))
        epoch = _historical_overlap((original.repository_policy,
                     original.content_review, original.current_revocation,
                     original.one_use_grant), now)
        contents, checked = pub._verify(original, epoch)
        pub._host_still_pinned()
        pub.git.safe_config(pub.repo)
        pub.git.safe_config(pub.bare)
        pub._git_storage_safe()
        pub._sandbox_hooks_off()
        _need(pub.git.text(pub.bare, 'rev-parse', '--is-bare-repository') == 'true',
              'ORIGINAL_PRIVATE_BARE_NOT_REAL', 'unavailable')
        operation = dp.sha(gitp.OP_DOMAIN, {
            'repository_id': access.roots.repository_id,
            'project_id': access.roots.project_id,
            'base_commit': access.approved_base_commit,
            'manifest_sha256': checked['manifest_sha256'],
            'private_target_sha256': pub._target_binding})
        signed_grant_sha = _hash(dp.canonical(checked['grant']))
        return pub, operation, pub._target_binding, signed_grant_sha, pub.journalroot, {
            'contents': contents, 'manifest_sha256': checked['manifest_sha256']}

    def _read_grant(self, mode: str, permission: Any, *, operation: str,
                    target: str, grant_sha: str, nonce: str | None = None
                    ) -> tuple[str, dict[str, Any]]:
        now = _time()
        body = _signed(permission, self.host.roots.read_public_key, READ_DOMAIN, {
            'schema', 'mode', 'operation_id', 'target_sha256',
            'original_grant_sha256', 'inspection_nonce', 'receipt_epoch',
            'code_revision_sha256', 'permission', 'issued_at', 'expires_at'}, 'READ_GRANT')
        _window(body, now)
        _need(self.host.enable_readback is True and
              body['schema'] == READ_SCHEMA and body['mode'] == mode and
              body['operation_id'] == operation and
              body['target_sha256'] == target and
              body['original_grant_sha256'] == grant_sha and
              type(body['inspection_nonce']) is str and
              NONCE.fullmatch(body['inspection_nonce']) is not None and
              (nonce is None or body['inspection_nonce'] == nonce) and
              type(body['receipt_epoch']) is int and
              body['receipt_epoch'] >= self.host.roots.minimum_receipt_epoch and
              _sha(ACTIVE_CODE_SHA256) and
              body['code_revision_sha256'] == ACTIVE_CODE_SHA256 == _code_hash() and
              body['permission'] == READ_PERMISSION,
              'INSPECTION_NOT_EXACTLY_AUTHORIZED')
        read_id = dp.sha(READ_ID_DOMAIN, {'mode': mode, 'operation_id': operation,
                     'inspection_nonce': body['inspection_nonce'],
                     'target_sha256': target})
        return read_id, body

    def _observe_ref(self, pub: gitp.DocsOnlyPublisher, operation: str,
                     docs: dict[str, bytes], markers: frozenset[str],
                     payloads: dict[str, bytes]) -> tuple[str, str | None]:
        """Only real local private bare ref read and byte/parent/delta checks."""
        ref = gitp.REF_NAMESPACE + operation
        # Some Git releases return exit 1 for a missing quiet ref but 128
        # for a missing --hash ref. Use the quiet existence probe first;
        # unexpected errors must NOT be classified as authoritative absence.
        code, _ = pub.git.run(pub.bare, 'show-ref', '--verify', '--quiet', ref,
                              ok=(0, 1), limit=128)
        if code == 1:
            return 'UNKNOWN_PRIVATE_REF_ABSENT', None
        commit = pub.git.text(pub.bare, 'show-ref', '--verify', '--hash', ref)
        _need(gitp.GIT_SHA.fullmatch(commit) is not None and
              '06_PUSH_ATTEMPTED' in markers,
              'PRIVATE_REF_WITHOUT_AUTHORIZED_PUSH_MARKER')
        for m in ('05_COMMIT_CREATED', '07_SANDBOX_REF_OBSERVED'):
            if m in markers:
                _need(payloads[m] == commit.encode('ascii'),
                      'PRIVATE_REF_CONFLICTS_WITH_HISTORICAL_COMMIT')
        _need(pub.git.text(pub.bare, 'cat-file', '-t', commit) == 'commit' and
              pub.git.text(pub.bare, 'rev-list', '--parents', '-n', '1', commit) ==
              commit + ' ' + pub.access.approved_base_commit,
              'PRIVATE_COMMIT_PARENT_UNTRUSTED')
        base = pub.access.approved_base_commit
        delta = pub.git.run(pub.bare, 'diff-tree', '--no-commit-id',
                            '--name-status', '-r', '-z', base, commit)[1]
        expected = b''.join(b'A\0' + p.encode('ascii') + b'\0'
                            for p in sorted(docs))
        _need(delta == expected, 'PRIVATE_COMMIT_NOT_EXACT_ADD_ONLY_DOCS')
        for p, raw in docs.items():
            _need(pub.git.run(pub.bare, 'show', commit + ':' + p,
                              limit=gitp.MAX_FILE_BYTES + 1)[1] == raw,
                  'PRIVATE_COMMIT_DOC_BYTES_DIFFER')
        return 'VERIFIED_PRIVATE_LOCAL_REF_ONLY', commit

    def inspect_docs(self, original: gitp.DocsOnlyPublishRequest,
                     access: gitp.HostDocsScope,
                     read_grant: da.SignedAuthorizationStatement) -> dict[str, Any]:
        mode, op, read_id, attempted = MODE_DOCS, None, None, False
        present = False
        try:
            pub, op, target, grant_sha, journal, pins = self._base(mode, original, access)
            read_id, permit = self._read_grant(mode, read_grant, operation=op,
                                              target=target, grant_sha=grant_sha)
            markers, payloads, journal_sha = _view_markers(
                journal, 'ec229-' + op, '00_CLAIM_DURABLE', _ALLOWED_DOCS,
                frozenset(('05_COMMIT_CREATED', '07_SANDBOX_REF_OBSERVED')))
            present = True
            with AuditSlot(self.audit) as audit:
                audit.claim('ec230-read-' + read_id, {
                    'mode': mode, 'operation_id': op, 'original_grant_sha256': grant_sha,
                    'target_sha256': target, 'inspection_nonce': permit['inspection_nonce']})
                audit.mark('01_ATTEMPT', {'kind': 'LOCAL_PRIVATE_GIT_READ_ONLY',
                                         'journal_sha256': journal_sha})
                attempted = True
                state, commit = self._observe_ref(pub, op, pins['contents'], markers, payloads)
                observation = {
                    'mode': mode, 'operation_id': op, 'target_sha256': target,
                    'original_grant_sha256': grant_sha,
                    'journal_sha256': journal_sha,
                    'inspection_id': read_id, 'state': state,
                    'candidate_commit': commit, 'observed_at': _time(),
                }
                audit.mark('02_OBSERVATION', observation)
                digest = dp.sha(OBS_DOMAIN, observation)
                return _envelope(mode, op, status='partial', reason=state,
                    state=state, inspection_id=read_id, observation_sha256=digest,
                    historical_journal_present=True,
                    evidence_kind='LOCAL_GIT_PRIVATE_BARE_READBACK')
        except (ReceiptDenied, rp.PublishDenied, gitp.DocsDenied) as exc:
            return _envelope(mode, op, status=getattr(exc, 'status', 'unavailable'),
                reason=getattr(exc, 'code', 'HOST_UNAVAILABLE'),
                inspection_id=read_id, historical_journal_present=present)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            return _envelope(mode, op, reason='LOCAL_GIT_RECEIPT_AMBIGUOUS',
                inspection_id=read_id, historical_journal_present=present)

    def inspect_report(self, original: rp.ReportPublishRequest,
                       access: rp.HostPublishAccess,
                       read_grant: da.SignedAuthorizationStatement) -> dict[str, Any]:
        mode, op, read_id, read_attempted, present = MODE_REPORT, None, None, False, False
        try:
            pub, op, target, grant_sha, journal, pins = self._base(mode, original, access)
            read_id, permit = self._read_grant(mode, read_grant, operation=op,
                                              target=target, grant_sha=grant_sha)
            markers, _, journal_sha = _view_markers(journal, 'ec228-' + op,
                                         '00_RESERVED_DURABLE', _ALLOWED_REPORT)
            present = True
            _need('03_POST_ATTEMPTED' in markers,
                  'NO_DURABLE_EC228_POST_ATTEMPT_MARKER')
            _need(16 <= len(self.host.provider_read_credential) and
                  self.host.provider_read_credential != access.credential,
                  'INDEPENDENT_PROVIDER_RECEIPT_READ_CREDENTIAL_REQUIRED', 'unavailable')
            with AuditSlot(self.audit) as audit:
                audit.claim('ec230-read-' + read_id, {
                    'mode': mode, 'operation_id': op, 'original_grant_sha256': grant_sha,
                    'target_sha256': target, 'inspection_nonce': permit['inspection_nonce']})
                audit.mark('01_ATTEMPT', {'kind': 'SIGNED_PROVIDER_GET_ONLY',
                                         'journal_sha256': journal_sha})
                read_attempted = True
                challenge = {'schema': PROBE_SCHEMA, 'operation_id': op,
                             'target_sha256': target,
                             'report_ref': pins['report_ref'],
                             'rendered_sha256': pins['rendered_sha256'],
                             'challenge_nonce': secrets.token_hex(16)}
                signed = self.reader.read(access.target,
                                          self.host.provider_read_credential, challenge)
                doc = _signed(signed, access.roots.provider_public_key,
                    PROVIDER_DOMAIN, {'schema', 'provider_id', 'account_id',
                        'project_id', 'destination_id', 'target_sha256',
                        'operation_id', 'report_ref', 'rendered_sha256',
                        'challenge_nonce', 'record_state', 'record_id_sha256',
                        'private_sandbox', 'create_only', 'issued_at', 'expires_at'},
                    'PROVIDER_READBACK')
                _window(doc, _time(), 30)
                _need(doc['schema'] == PROVIDER_SCHEMA and
                      doc['provider_id'] == pins['provider_id'] and
                      doc['account_id'] == pins['account_id'] and
                      doc['project_id'] == access.target.project_id and
                      doc['destination_id'] == access.target.destination_id and
                      all(doc[k] == challenge[k] for k in ('operation_id',
                        'target_sha256', 'report_ref', 'rendered_sha256', 'challenge_nonce')) and
                      doc['private_sandbox'] is True and doc['create_only'] is True and
                      (doc['record_state'] == 'CREATED_PRIVATE_TEST' and
                       _sha(doc['record_id_sha256']) or
                       doc['record_state'] == 'NOT_FOUND' and
                       doc['record_id_sha256'] is None),
                      'UNTRUSTED_OR_CONFLICTING_PROVIDER_RECEIPT')
                state = ('SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED'
                         if doc['record_state'] == 'CREATED_PRIVATE_TEST' else
                         'UNKNOWN_PROVIDER_REPORTS_NOT_FOUND')
                observation = {
                    'mode': mode, 'operation_id': op, 'target_sha256': target,
                    'original_grant_sha256': grant_sha, 'journal_sha256': journal_sha,
                    'inspection_id': read_id, 'state': state,
                    'provider_record_id_sha256': doc['record_id_sha256'],
                    'signed_provider_statement_sha256': _hash(dp.canonical(doc)),
                    'observed_at': _time(),
                }
                audit.mark('02_OBSERVATION', observation)
                return _envelope(mode, op, status='partial', reason=state, state=state,
                    inspection_id=read_id, observation_sha256=dp.sha(OBS_DOMAIN, observation),
                    provider_read_attempted=True, historical_journal_present=True,
                    evidence_kind='SIGNED_PROVIDER_PRIVATE_RECEIPT_READBACK')
        except (ReceiptDenied, rp.PublishDenied, gitp.DocsDenied) as exc:
            return _envelope(mode, op, status=getattr(exc, 'status', 'unavailable'),
                reason=getattr(exc, 'code', 'HOST_UNAVAILABLE'), inspection_id=read_id,
                provider_read_attempted=read_attempted, historical_journal_present=present)
        except Exception:
            # No second GET is attempted, even on an unexpected provider
            # adapter bug after the durable inspection claim.
            return _envelope(mode, op, reason='PROVIDER_RECEIPT_UNKNOWN_NO_RETRY',
                inspection_id=read_id, provider_read_attempted=read_attempted,
                historical_journal_present=present)

    def _cleanup_grant(self, permission: Any, *, operation: str, target: str,
                       grant_sha: str, inspection_id: str, observation_sha: str,
                       candidate: str, work_inode: tuple[int, int]) -> None:
        doc = _signed(permission, self.host.roots.cleanup_public_key, CLEAN_DOMAIN, {
            'schema', 'mode', 'operation_id', 'target_sha256',
            'original_grant_sha256', 'inspection_id', 'observation_sha256',
            'candidate_commit_sha', 'worktree_inode', 'cleanup_epoch',
            'permission', 'code_revision_sha256', 'issued_at', 'expires_at'},
            'CLEANUP_GRANT')
        _window(doc, _time())
        _need(self.host.enable_clean_linked_worktree is True and
              doc['schema'] == CLEAN_SCHEMA and doc['mode'] == MODE_DOCS and
              doc['operation_id'] == operation and doc['target_sha256'] == target and
              doc['original_grant_sha256'] == grant_sha and
              doc['inspection_id'] == inspection_id and
              doc['observation_sha256'] == observation_sha and
              doc['candidate_commit_sha'] == candidate and
              type(doc['worktree_inode']) is list and
              doc['worktree_inode'] == list(work_inode) and
              type(doc['cleanup_epoch']) is int and
              doc['cleanup_epoch'] >= self.host.roots.minimum_receipt_epoch and
              doc['permission'] == CLEAN_PERMISSION and
              _sha(ACTIVE_CODE_SHA256) and
              doc['code_revision_sha256'] == ACTIVE_CODE_SHA256 == _code_hash(),
              'FRESH_EXACT_WORKTREE_CLEANUP_APPROVAL_REQUIRED')

    def _eligible_worktree(self, pub: gitp.DocsOnlyPublisher, op: str,
                           candidate: str, docs: dict[str, bytes]
                           ) -> tuple[str, tuple[int, int]]:
        """Conservative: only clean, owned exact linked worktree; no ignored files.

        This cannot defend against hostile same-UID races or multi-host storage.
        Hosts must externally enforce exclusive process/filesystem ownership.
        """
        path = pub.workroot + '/ec229-' + op
        real, inode = _safe_private_dir(path)
        _need(real == path and inode[0] == pub.work_inode[0],
              'WORKTREE_PATH_OR_FILESYSTEM_DRIFT', 'unavailable')
        gitlink = Path(path) / '.git'
        st = os.lstat(gitlink)
        _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
              st.st_uid == os.geteuid() and st.st_size <= 4096 and
              not os.path.islink(gitlink),
              'LINKED_WORKTREE_GIT_POINTER_NOT_REGULAR')
        text = gitlink.read_bytes()
        _need(text.startswith(b'gitdir: ') and text.endswith(b'\n') and
              b'\n' not in text[:-1], 'LINKED_WORKTREE_POINTER_MALFORMED')
        metadata = os.fsdecode(text[8:-1])
        root = pub.gitdir + '/worktrees/'
        _need(not os.path.islink(pub.gitdir + '/worktrees') and
              metadata.startswith(root) and
              re.fullmatch(r'[A-Za-z0-9._-]{1,120}', metadata[len(root):]) is not None and
              os.path.isdir(metadata) and not os.path.islink(metadata) and
              str(Path(metadata).resolve()) == metadata and
              pub.git.text(path, 'rev-parse', '--absolute-git-dir') == metadata,
              'LINKED_WORKTREE_METADATA_IDENTITY_UNPROVEN')
        listing = pub.git.run(pub.repo, 'worktree', 'list', '--porcelain', '-z')[1]
        entries = [part.split(b'\0') for part in listing.split(b'\0\0') if part]
        matching = [e for e in entries if b'worktree ' + os.fsencode(path) in e]
        _need(len(matching) == 1 and b'HEAD ' + candidate.encode() in matching[0] and
              b'detached' in matching[0], 'LINKED_WORKTREE_NOT_UNIQUELY_DETACHED')
        _need(pub.git.text(path, 'rev-parse', '--show-toplevel') == path and
              pub.git.text(path, 'rev-parse', '--verify', 'HEAD^{commit}') == candidate and
              pub.git.run(path, 'status', '--porcelain=v1', '-z',
                          '--untracked-files=all')[1] == b'',
              'LINKED_WORKTREE_DIRTY_OR_HEAD_CHANGED')
        pub._verify_isolated_commit(path, candidate, docs)
        tracked = pub.git.run(path, 'ls-files', '-z')[1].split(b'\0')
        expected_files = {os.fsdecode(p) for p in tracked if p} | {'.git'}
        _need(len(expected_files) == len([p for p in tracked if p]) + 1 and
              len(expected_files) <= gitp.MAX_TREE_FILES + gitp.MAX_FILES + 1,
              'LINKED_WORKTREE_TRACKED_SET_UNSAFE')
        found: set[str] = set()
        expected_dirs = {'.'}
        for name in expected_files - {'.git'}:
            p = Path(name)
            expected_dirs.update(str(d) for d in p.parents)
        count = 0
        for folder, dirs, files in os.walk(path, topdown=True, followlinks=False):
            rel = os.path.relpath(folder, path)
            _need(rel in expected_dirs, 'UNEXPECTED_LOCAL_WORKTREE_DIRECTORY')
            for d in dirs:
                child = os.path.join(folder, d)
                st = os.lstat(child)
                _need(stat.S_ISDIR(st.st_mode) and st.st_dev == inode[0] and
                      st.st_uid == os.geteuid() and
                      stat.S_IMODE(st.st_mode) & 0o022 == 0 and
                      os.path.relpath(child, path) in expected_dirs,
                      'WORKTREE_UNEXPECTED_DIRECTORY_OR_SYMLINK')
            for f in files:
                child = os.path.join(folder, f)
                st = os.lstat(child)
                relative = os.path.relpath(child, path)
                _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                      st.st_uid == os.geteuid() and st.st_dev == inode[0] and
                      relative in expected_files, 'UNEXPECTED_IGNORED_OR_LINKED_FILE')
                found.add(relative)
                count += 1
                _need(count <= len(expected_files), 'WORKTREE_FILE_BUDGET_EXCEEDED')
        _need(found == expected_files, 'LINKED_WORKTREE_MISSING_OR_EXTRA_FILES')
        return path, inode

    def cleanup_docs(self, original: gitp.DocsOnlyPublishRequest,
                     access: gitp.HostDocsScope, inspection_id: str,
                     cleanup_grant: da.SignedAuthorizationStatement) -> dict[str, Any]:
        mode, op, claimed, attempted, present = MODE_DOCS, None, False, False, False
        try:
            pub, op, target, grant_sha, journal, pins = self._base(mode, original, access)
            evidence = _read_observation(self.audit, inspection_id)
            claim, intent, observed = (evidence[n] for n in
                            ('00_CLAIM', '01_ATTEMPT', '02_OBSERVATION'))
            _need(claim == {'mode': mode, 'operation_id': op,
                    'original_grant_sha256': grant_sha,
                    'target_sha256': target, 'inspection_nonce': claim.get('inspection_nonce')} and
                  type(claim.get('inspection_nonce')) is str and
                  NONCE.fullmatch(claim['inspection_nonce']) is not None and
                  inspection_id == dp.sha(READ_ID_DOMAIN, {
                    'mode': mode, 'operation_id': op,
                    'inspection_nonce': claim['inspection_nonce'],
                    'target_sha256': target}) and
                  intent.get('kind') == 'LOCAL_PRIVATE_GIT_READ_ONLY' and
                  observed.get('inspection_id') == inspection_id and
                  observed.get('mode') == mode and observed.get('operation_id') == op and
                  observed.get('target_sha256') == target and
                  observed.get('original_grant_sha256') == grant_sha and
                  observed.get('state') == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
                  type(observed.get('observed_at')) is int and
                  0 <= _time() - observed['observed_at'] <= MAX_OBSERVATION_AGE,
                  'RECENT_POSITIVE_INSPECTION_REQUIRED')
            markers, payloads, journal_sha = _view_markers(journal,
                'ec229-' + op, '00_CLAIM_DURABLE', _ALLOWED_DOCS,
                frozenset(('05_COMMIT_CREATED', '07_SANDBOX_REF_OBSERVED')))
            present = True
            _need(journal_sha == observed.get('journal_sha256') ==
                  intent.get('journal_sha256') and
                  '06_PUSH_ATTEMPTED' in markers and
                  '05_COMMIT_CREATED' in markers,
                  'ORIGINAL_JOURNAL_CHANGED_SINCE_INSPECTION')
            state, candidate = self._observe_ref(pub, op, pins['contents'], markers, payloads)
            _need(state == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY' and
                  candidate == observed.get('candidate_commit'),
                  'PRIVATE_REF_CHANGED_SINCE_INSPECTION')
            pub._source_ready(pins['contents'])
            path, inode = self._eligible_worktree(pub, op, candidate, pins['contents'])
            obs_sha = dp.sha(OBS_DOMAIN, observed)
            self._cleanup_grant(cleanup_grant, operation=op, target=target,
                grant_sha=grant_sha, inspection_id=inspection_id,
                observation_sha=obs_sha, candidate=candidate, work_inode=inode)
            initial_source = pub._original_source_fingerprint()
            with AuditSlot(self.audit) as audit:
                audit.claim('ec230-clean-' + op, {
                    'mode': mode, 'operation_id': op,
                    'inspection_id': inspection_id, 'observation_sha256': obs_sha,
                    'worktree_inode': list(inode), 'candidate_commit_sha': candidate})
                claimed = True
                # The irreversible cleanup marker is fsynced FIRST. A crash
                # after it is UNKNOWN and requires manual recovery; no retry.
                audit.mark('01_ATTEMPT', {'kind': 'REMOVE_ONLY_EXACT_LOCAL_LINKED_WORKTREE',
                                          'worktree_inode': list(inode)})
                attempted = True
                _need(self._eligible_worktree(pub, op, candidate, pins['contents']) ==
                      (path, inode) and
                      self._observe_ref(pub, op, pins['contents'], markers, payloads) ==
                      (state, candidate) and
                      pub._original_source_fingerprint() == initial_source and
                      _code_hash() == ACTIVE_CODE_SHA256,
                      'CLEANUP_EDGE_IDENTITY_OR_CODE_DRIFT', 'unavailable')
                pub.git.run(pub.repo, 'worktree', 'remove', '--', path)
                _need(not os.path.lexists(path) and
                      pub._original_source_fingerprint() == initial_source and
                      pub.git.text(pub.bare, 'rev-parse', '--verify',
                                   gitp.REF_NAMESPACE + op + '^{commit}') == candidate,
                      'CLEANUP_LOCAL_EFFECT_UNCONFIRMED', 'unavailable')
                pub._source_ready(pins['contents'])
                audit.mark('03_REMOVE_COMPLETED', {
                    'kind': 'VERIFIED_LOCAL_WORKTREE_REMOVED', 'candidate_commit_sha': candidate})
            return _envelope(mode, op, status='partial',
                reason='VERIFIED_LOCAL_WORKTREE_REMOVED_KEEP_REF_AND_JOURNALS',
                state='VERIFIED_PRIVATE_LOCAL_REF_ONLY', inspection_id=inspection_id,
                observation_sha256=obs_sha, historical_journal_present=True,
                evidence_kind='LOCAL_GIT_PRIVATE_BARE_READBACK',
                clean_attempted=True, clean_completed=True)
        except (ReceiptDenied, rp.PublishDenied, gitp.DocsDenied) as exc:
            return _envelope(mode, op, status=getattr(exc, 'status', 'unavailable'),
                reason=getattr(exc, 'code', 'HOST_UNAVAILABLE'),
                inspection_id=inspection_id if _sha(inspection_id) else None,
                clean_attempted=attempted, historical_journal_present=present)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            return _envelope(mode, op, reason='CLEANUP_OUTCOME_UNKNOWN_NO_RETRY',
                inspection_id=inspection_id if _sha(inspection_id) else None,
                clean_attempted=attempted, historical_journal_present=present)

#!/usr/bin/env python3
"""EC262 operator-private, durable HMAC-linked strict-session audit journal.

This journal authenticates *locally recorded attempts*, not the Linux kernel,
remote identities, receipt delivery to a client, or independent CI verdicts.
It intentionally refuses uncertain, truncated, replaced or corrupt journals.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quality_host import broker as private
from quality_run_host import broker as runner
from lease_host import broker as lease

SCHEMA = 'ces.ec262.local_hmac_chained_session_audit.v1'
DOMAIN = b'CES/EC262/session-audit/v1\x00'
JOURNAL_NAME = 'events.jsonl'
HEAD_NAME = 'head.json'
HEAD_SCHEMA = 'ces.ec262.local_audit_head.v1'
HEAD_DOMAIN = b'CES/EC262/audit-head/v1\x00'
MAX_HEAD = 512
MAX_LINE = 1024
MAX_FILE = 32 * 1024 * 1024
MAX_EVENTS = 65536
ZERO = '0' * 64
TAG_RE = re.compile(r'[0-9a-f]{24}\Z')
REASON_RE = re.compile(r'[A-Z][A-Z0-9_]{0,95}\Z')
EVENTS = frozenset({
    'service_start', 'service_recovery_complete', 'service_failed',
    'service_closed', 'session_open', 'begin_authorized', 'begin_egress_attempt',
    'begin_egress_enqueued', 'poll_egress_attempt', 'poll_egress_enqueued',
    'stop_requested', 'stop_egress_attempt', 'stop_egress_enqueued',
    'session_denied', 'session_cleanup_state',
})
PAYLOAD_KEYS = frozenset({'schema', 'seq', 'prev_mac', 'event', 'run_id',
                          'session_tag', 'reason_code', 'utc_unix_ms'})


class AuditError(lease.LeaseHostError):
    """Stable, no-sensitive-data denial for local audit failures."""


def _fail(code: str) -> None:
    raise AuditError(code)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _mac(key: bytes, data: dict[str, Any]) -> str:
    return hmac.new(key, DOMAIN + _canonical(data), hashlib.sha256).hexdigest()


def _reason(value: str) -> str:
    """Exception messages are never journalled; unstable codes are redacted."""
    if type(value) is str and REASON_RE.fullmatch(value):
        return value
    return 'UNCLASSIFIED'


class AuditLog:
    """One host-scoped audit lock with a verified append-only HMAC chain.

    File is opened relative to an already checked private dirfd. Startup
    verifies every complete record before allowing worker/socket creation.
    Append checks inode, size and link count, writes one canonical JSON line
    and fsyncs it before returning. A failed append poisons this instance.
    """

    def __init__(self, audit_root: str, key_path: str, *, create: bool = True,
                 writable_existing: bool = False):
        if os.geteuid() == 0:
            _fail('EC262_AUDIT_NONROOT_REQUIRED')
        self.fd = -1
        self.dirfd = -1
        self.poisoned = False
        self.key = b''
        self.count = 0
        self.last_mac = ZERO
        self.size = 0
        self.run_id = os.urandom(12).hex()
        created_new = False
        try:
            root = runner._private_dir(audit_root)
            private._path(key_path)
            self.key = lease._key(key_path)
            self.dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                                 os.O_NOFOLLOW | os.O_CLOEXEC)
            if create:
                try:
                    self.fd = os.open(JOURNAL_NAME, os.O_RDWR | os.O_APPEND |
                                      os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                                      os.O_CLOEXEC, 0o600, dir_fd=self.dirfd)
                    os.fsync(self.dirfd)
                    created_new = True
                except FileExistsError:
                    self.fd = os.open(JOURNAL_NAME, os.O_RDWR | os.O_APPEND |
                                      os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.dirfd)
            else:
                # EC263: opt-in append to an EXISTING audited journal with no
                # O_CREAT fallback. Read-only legacy verification stays default.
                flags = (os.O_RDWR | os.O_APPEND if writable_existing else os.O_RDONLY)
                self.fd = os.open(JOURNAL_NAME, flags | os.O_NOFOLLOW |
                                  os.O_CLOEXEC, dir_fd=self.dirfd)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = self._identity()
            self._read_and_verify()
            if created_new:
                # HEAD is a second local HMAC high-water seal; it can detect
                # suffix removal but is NOT an external immutable anchor.
                if os.path.lexists(os.path.join(root, HEAD_NAME)):
                    _fail('EC262_AUDIT_HEAD_PREEXISTS_NEW_JOURNAL')
                self._write_head()
            self._check_head()
        except BaseException as exc:
            self.close()
            if isinstance(exc, AuditError):
                raise
            raise AuditError('EC262_AUDIT_STARTUP_UNAVAILABLE') from exc

    def _identity(self) -> tuple[int, int]:
        st = os.fstat(self.fd)
        entry = os.stat(JOURNAL_NAME, dir_fd=self.dirfd, follow_symlinks=False)
        if not (stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                st.st_mode & 0o077 == 0 and st.st_nlink == 1 and
                (st.st_dev, st.st_ino) == (entry.st_dev, entry.st_ino) and
                stat.S_ISREG(entry.st_mode)):
            _fail('EC262_AUDIT_FILE_UNSAFE')
        return st.st_dev, st.st_ino

    def _read_and_verify(self) -> None:
        st = os.fstat(self.fd)
        if not (0 <= st.st_size <= MAX_FILE):
            _fail('EC262_AUDIT_CAPACITY_EXCEEDED')
        size = st.st_size
        # A single bounded read is intentional: startup must verify all
        # committed evidence, never skip old records to accelerate boot.
        body = bytearray()
        offset = 0
        while offset < size:
            piece = os.pread(self.fd, min(65536, size - offset), offset)
            if not piece:
                _fail('EC262_AUDIT_TRUNCATED')
            body.extend(piece)
            offset += len(piece)
        if body and body[-1:] != b'\n':
            _fail('EC262_AUDIT_PARTIAL_RECORD')
        prev = ZERO
        count = 0
        for raw in body.splitlines():
            if not raw or len(raw) > MAX_LINE:
                _fail('EC262_AUDIT_LINE_INVALID')
            try:
                obj = json.loads(raw, parse_constant=lambda _: (_fail('EC262_AUDIT_JSON_INVALID')))
                if (type(obj) is not dict or set(obj) != PAYLOAD_KEYS | {'mac'} or
                        type(obj['mac']) is not str):
                    _fail('EC262_AUDIT_RECORD_FIELDS')
                payload = {k: obj[k] for k in PAYLOAD_KEYS}
                self._validate_record(payload, count + 1, prev)
                if _canonical(obj) != raw or not hmac.compare_digest(
                        obj['mac'], _mac(self.key, payload)):
                    _fail('EC262_AUDIT_MAC_INVALID')
            except (TypeError, ValueError, UnicodeDecodeError, KeyError) as exc:
                raise AuditError('EC262_AUDIT_JSON_INVALID') from exc
            prev = obj['mac']
            count += 1
            if count > MAX_EVENTS:
                _fail('EC262_AUDIT_CAPACITY_EXCEEDED')
        if self._identity() != self.identity or os.fstat(self.fd).st_size != size:
            _fail('EC262_AUDIT_RACED_ON_OPEN')
        self.count = count
        self.size = size
        self.last_mac = prev

    @staticmethod
    def _validate_record(data: dict[str, Any], seq: int, prev: str) -> None:
        if not (data['schema'] == SCHEMA and type(data['seq']) is int and
                data['seq'] == seq and data['prev_mac'] == prev and
                type(data['event']) is str and data['event'] in EVENTS and
                type(data['run_id']) is str and TAG_RE.fullmatch(data['run_id']) and
                type(data['session_tag']) is str and
                (data['session_tag'] == 'SERVICE' or
                 TAG_RE.fullmatch(data['session_tag'])) and
                type(data['reason_code']) is str and
                REASON_RE.fullmatch(data['reason_code']) and
                type(data['utc_unix_ms']) is int and data['utc_unix_ms'] > 0):
            _fail('EC262_AUDIT_RECORD_INVALID')

    def _head_payload(self) -> dict[str, Any]:
        return {'schema': HEAD_SCHEMA, 'event_count': self.count,
                'last_mac': self.last_mac, 'journal_size': self.size}

    def _head_bytes(self) -> bytes:
        payload = self._head_payload()
        tag = hmac.new(self.key, HEAD_DOMAIN + _canonical(payload),
                       hashlib.sha256).hexdigest()
        return _canonical({**payload, 'mac': tag}) + b'\n'

    def _check_head(self) -> None:
        fd = -1
        try:
            fd = os.open(HEAD_NAME, os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=self.dirfd)
            st = os.fstat(fd)
            if not (stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                    st.st_mode & 0o077 == 0 and st.st_nlink == 1 and
                    1 <= st.st_size <= MAX_HEAD):
                _fail('EC262_AUDIT_HEAD_UNSAFE')
            raw = os.read(fd, MAX_HEAD + 1)
            if len(raw) != st.st_size or raw != self._head_bytes():
                _fail('EC262_AUDIT_HEAD_MISMATCH')
        except AuditError:
            raise
        except (OSError, ValueError) as exc:
            raise AuditError('EC262_AUDIT_HEAD_UNAVAILABLE') from exc
        finally:
            if fd >= 0:
                os.close(fd)

    def _write_head(self) -> None:
        # Journal fsync always PRECEDES head replacement. If power fails
        # between the two, mismatch blocks restart pending operator review.
        name = '.head-' + os.urandom(12).hex()
        tmpfd = -1
        try:
            tmpfd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                            dir_fd=self.dirfd)
            raw = self._head_bytes()
            view = memoryview(raw)
            while view:
                n = os.write(tmpfd, view)
                if n <= 0:
                    _fail('EC262_AUDIT_HEAD_WRITE_INCOMPLETE')
                view = view[n:]
            os.fsync(tmpfd)
            os.close(tmpfd)
            tmpfd = -1
            os.replace(name, HEAD_NAME, src_dir_fd=self.dirfd,
                       dst_dir_fd=self.dirfd)
            os.fsync(self.dirfd)
        finally:
            if tmpfd >= 0:
                os.close(tmpfd)
            try:
                os.unlink(name, dir_fd=self.dirfd)
            except FileNotFoundError:
                pass

    def record(self, event: str, session_tag: str = 'SERVICE',
               reason_code: str = 'NONE') -> None:
        if self.poisoned:
            _fail('EC262_AUDIT_POISONED')
        if (type(event) is not str or event not in EVENTS or
                type(session_tag) is not str or
                not (session_tag == 'SERVICE' or TAG_RE.fullmatch(session_tag))):
            _fail('EC262_AUDIT_CALL_INVALID')
        try:
            if self._identity() != self.identity or os.fstat(self.fd).st_size != self.size:
                _fail('EC262_AUDIT_REPLACED_OR_CHANGED')
            if self.count >= MAX_EVENTS:
                _fail('EC262_AUDIT_CAPACITY_EXCEEDED')
            payload = {'schema': SCHEMA, 'seq': self.count + 1,
                       'prev_mac': self.last_mac, 'event': event,
                       'run_id': self.run_id, 'session_tag': session_tag,
                       'reason_code': _reason(reason_code),
                       'utc_unix_ms': time.time_ns() // 1_000_000}
            tag = _mac(self.key, payload)
            raw = _canonical({**payload, 'mac': tag}) + b'\n'
            if len(raw) - 1 > MAX_LINE or self.size + len(raw) > MAX_FILE:
                _fail('EC262_AUDIT_CAPACITY_EXCEEDED')
            view = memoryview(raw)
            while view:
                wrote = os.write(self.fd, view)
                if wrote <= 0:
                    _fail('EC262_AUDIT_WRITE_INCOMPLETE')
                view = view[wrote:]
            os.fsync(self.fd)
            if self._identity() != self.identity or os.fstat(self.fd).st_size != self.size + len(raw):
                _fail('EC262_AUDIT_POSTWRITE_CHANGED')
            self.count += 1
            self.size += len(raw)
            self.last_mac = tag
            self._write_head()
            self._check_head()
        except BaseException as exc:
            self.poisoned = True
            if isinstance(exc, AuditError):
                raise
            raise AuditError('EC262_AUDIT_WRITE_UNAVAILABLE') from exc

    def summary(self) -> dict[str, Any]:
        return {'status': 'partial', 'exit_code': 2,
                'reason_code': 'EC262_LOCAL_AUDIT_CHAIN_ONLY',
                'event_count': self.count, 'last_mac': self.last_mac,
                'local_journal_hmac_verified': True,
                'independent_external_log_anchor_verified': False,
                'live_rootless_oci_kernel_verified': False,
                'overall_quality_pass_verified': False}

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        if self.dirfd >= 0:
            os.close(self.dirfd)
            self.dirfd = -1

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

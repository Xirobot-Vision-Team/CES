#!/usr/bin/env python3
"""EC263: Ed25519 offline checkpoints for a *prefix* of an EC262 HMAC audit.

An operator signing key is used only by explicit offline commands, never by
host serving or verification. A deployment-pinned Ed25519 public-key digest
and a pinned signed-checkpoint digest prevent local same-key rewrites/rollback
of the attested prefix; they do not make the unanchored suffix immutable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quality_host import broker as private
from quality_run_host import broker as runner
from signed_audit_host.audit import (
    AuditLog, AuditError, MAX_EVENTS, MAX_FILE, MAX_LINE, _canonical,
)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
except ImportError:  # Fail closed with a stable message, never fall back to HMAC.
    InvalidSignature = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None
    serialization = None

SCHEMA = 'ces.ec263.offline_signed_audit_checkpoint.v1'
DOMAIN = b'CES/EC263/offline-audit-checkpoint/v1\x00'
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
NONCE_RE = re.compile(r'[0-9a-f]{32}\Z')
PAYLOAD_FIELDS = frozenset({
    'schema', 'event_count', 'journal_prefix_bytes',
    'journal_prefix_sha256', 'last_mac', 'signer_public_sha256', 'nonce',
})
SIGNED_FIELDS = PAYLOAD_FIELDS | {'signature_ed25519'}
MAX_CHECKPOINT = 1536
MAX_PROPOSAL = 1280


class AnchorError(AuditError):
    """Constant code, never includes secret paths or journal payloads."""


def _fail(code: str) -> None:
    raise AnchorError(code)


def _need_crypto() -> None:
    if Ed25519PrivateKey is None or Ed25519PublicKey is None:
        _fail('EC263_ED25519_LIBRARY_UNAVAILABLE')


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash(value: str, code: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _read_private(path: str, limit: int) -> bytes:
    try:
        return private._private_bytes(path, limit)
    except (OSError, ValueError, TypeError) as exc:
        raise AnchorError('EC263_PRIVATE_INPUT_UNAVAILABLE') from exc


def _atomic_new_private(path: str, raw: bytes) -> None:
    """Create once, never replace; fsync file and its private parent."""
    try:
        p = private._path(path)
        parent = runner._private_dir(os.path.dirname(p))
        dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd = os.open(os.path.basename(p), os.O_WRONLY | os.O_CREAT |
                         os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dirfd)
            try:
                view = memoryview(raw)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        _fail('EC263_OUTPUT_WRITE_INCOMPLETE')
                    view = view[n:]
                os.fsync(fd)
                os.fsync(dirfd)
            finally:
                os.close(fd)
        finally:
            os.close(dirfd)
    except AnchorError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise AnchorError('EC263_PRIVATE_OUTPUT_UNAVAILABLE') from exc


def _parse_canonical(raw: bytes, maxlen: int) -> dict[str, Any]:
    if not 0 < len(raw) <= maxlen or not raw.endswith(b'\n'):
        _fail('EC263_CHECKPOINT_ENCODING_INVALID')
    try:
        result = json.loads(raw)
        if (type(result) is not dict or
                _canonical(result) + b'\n' != raw):
            _fail('EC263_CHECKPOINT_NOT_CANONICAL')
        return result
    except AnchorError:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise AnchorError('EC263_CHECKPOINT_JSON_INVALID') from exc


def _validate_payload(payload: dict[str, Any]) -> None:
    if (type(payload) is not dict or set(payload) != PAYLOAD_FIELDS or
            payload.get('schema') != SCHEMA or
            type(payload['event_count']) is not int or
            not 1 <= payload['event_count'] <= MAX_EVENTS or
            type(payload['journal_prefix_bytes']) is not int or
            not 1 <= payload['journal_prefix_bytes'] <= MAX_FILE or
            type(payload['nonce']) is not str or
            NONCE_RE.fullmatch(payload['nonce']) is None):
        _fail('EC263_CHECKPOINT_PAYLOAD_INVALID')
    for field in ('journal_prefix_sha256', 'last_mac', 'signer_public_sha256'):
        _hash(payload[field], 'EC263_CHECKPOINT_HASH_INVALID')


def _fingerprint_prefix(fd: int, limit: int) -> tuple[str, int, str]:
    """Bounded streaming SHA256, newline count and final MAC of a journal prefix.

    No huge additional allocation and no reopening path while EC262's flock is
    held. The complete EC262 HMAC chain was checked at journal open.
    """
    digest = hashlib.sha256()
    offset = 0
    lines = 0
    tail = b''
    while offset < limit:
        piece = os.pread(fd, min(65536, limit - offset), offset)
        if not piece:
            _fail('EC263_JOURNAL_PREFIX_TRUNCATED')
        digest.update(piece)
        lines += piece.count(b'\n')
        tail = (tail + piece)[-(MAX_LINE + 2):]
        offset += len(piece)
    if not tail.endswith(b'\n'):
        _fail('EC263_PREFIX_TAIL_INVALID')
    last_line = tail[:-1].rsplit(b'\n', 1)[-1]
    if not 0 < len(last_line) <= MAX_LINE:
        _fail('EC263_PREFIX_TAIL_INVALID')
    try:
        mac = json.loads(last_line)['mac']
    except (ValueError, KeyError, TypeError) as exc:
        raise AnchorError('EC263_PREFIX_TAIL_INVALID') from exc
    if type(mac) is not str or SHA_RE.fullmatch(mac) is None:
        _fail('EC263_PREFIX_TAIL_INVALID')
    return digest.hexdigest(), lines, mac


def _prefix(audit: AuditLog, checkpoint: dict[str, Any]) -> None:
    """Read from EC262's locked verified FD, not a racy re-opened path."""
    end = checkpoint['journal_prefix_bytes']
    count = checkpoint['event_count']
    if audit.size < end or audit.count < count or audit.poisoned:
        _fail('EC263_JOURNAL_ROLLED_BACK')
    if audit._identity() != audit.identity or os.fstat(audit.fd).st_size != audit.size:
        _fail('EC263_JOURNAL_CHANGED')
    digest, lines, last_mac = _fingerprint_prefix(audit.fd, end)
    if lines != count or not hmac.compare_digest(
            digest, checkpoint['journal_prefix_sha256']):
        _fail('EC263_SIGNED_PREFIX_CHANGED')
    if not hmac.compare_digest(last_mac, checkpoint['last_mac']):
        _fail('EC263_PREFIX_LAST_MAC_CHANGED')
    if audit._identity() != audit.identity or os.fstat(audit.fd).st_size != audit.size:
        _fail('EC263_JOURNAL_CHANGED')


def _outside_audit(audit_root: str, path: str) -> None:
    root = runner._private_dir(audit_root)
    target = private._path(path)
    if os.path.commonpath((root, target)) == root:
        _fail('EC263_ANCHOR_FILES_MUST_BE_OUTSIDE_AUDIT_ROOT')


def public_bytes_from_signing_key(signing_key: bytes) -> bytes:
    _need_crypto()
    if len(signing_key) != 32:
        _fail('EC263_SIGNING_KEY_LENGTH_INVALID')
    return Ed25519PrivateKey.from_private_bytes(signing_key).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def generate_offline_keypair(signing_key_path: str, public_key_path: str) -> dict[str, Any]:
    """Operator offline utility. NEVER executed on the serving host."""
    _need_crypto()
    if signing_key_path == public_key_path:
        _fail('EC263_KEY_PATHS_MUST_DIFFER')
    key = Ed25519PrivateKey.generate()
    secret = key.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    pub = public_bytes_from_signing_key(secret)
    _atomic_new_private(signing_key_path, secret)
    _atomic_new_private(public_key_path, pub)
    return {'status': 'partial', 'exit_code': 2,
            'signer_public_sha256': _digest(pub),
            'signing_secret_never_loaded_by_host': True,
            'overall_quality_pass_verified': False}


def propose(audit_root: str, audit_key: str, signer_public_sha256: str,
            output_path: str) -> dict[str, Any]:
    """Locked, locally verified EC262 snapshot, NOT a signature or approval."""
    pub_hash = _hash(signer_public_sha256, 'EC263_PUBLIC_PIN_INVALID')
    _outside_audit(audit_root, output_path)
    with AuditLog(audit_root, audit_key, create=False) as audit:
        if audit.count == 0:
            _fail('EC263_EMPTY_JOURNAL_CANNOT_BE_ATTESTED')
        journal_digest, lines, last_mac = _fingerprint_prefix(audit.fd, audit.size)
        if lines != audit.count or not hmac.compare_digest(last_mac, audit.last_mac):
            _fail('EC263_JOURNAL_CHANGED_DURING_PROPOSAL')
        payload = {'schema': SCHEMA, 'event_count': audit.count,
                   'journal_prefix_bytes': audit.size,
                   'journal_prefix_sha256': journal_digest,
                   'last_mac': audit.last_mac,
                   'signer_public_sha256': pub_hash,
                   'nonce': os.urandom(16).hex()}
        _validate_payload(payload)
        _prefix(audit, payload)
        _atomic_new_private(output_path, _canonical(payload) + b'\n')
    return {'status': 'partial', 'exit_code': 2, 'proposal_sha256': _digest(
        _canonical(payload) + b'\n'), 'event_count': payload['event_count'],
        'requires_independent_offline_review_and_signing': True,
        'overall_quality_pass_verified': False}


def sign_offline(proposal_path: str, signing_key_path: str,
                 output_path: str) -> dict[str, Any]:
    """Offline command has no audit-root or host-key parameters."""
    _need_crypto()
    raw = _read_private(proposal_path, MAX_PROPOSAL)
    payload = _parse_canonical(raw, MAX_PROPOSAL)
    _validate_payload(payload)
    secret = _read_private(signing_key_path, 32)
    if len(secret) != 32:
        _fail('EC263_SIGNING_KEY_LENGTH_INVALID')
    pub = public_bytes_from_signing_key(secret)
    if not hmac.compare_digest(_digest(pub), payload['signer_public_sha256']):
        _fail('EC263_PROPOSAL_WRONG_SIGNER')
    signature = Ed25519PrivateKey.from_private_bytes(secret).sign(
        DOMAIN + _canonical(payload))
    signed = _canonical({**payload, 'signature_ed25519': signature.hex()}) + b'\n'
    _atomic_new_private(output_path, signed)
    return {'status': 'partial', 'exit_code': 2,
            'checkpoint_sha256': _digest(signed),
            'signer_public_sha256': _digest(pub),
            'attested_event_count': payload['event_count'],
            'requires_out_of_band_pin_distribution': True,
            'overall_quality_pass_verified': False}


class AnchoredAudit:
    """Opt-in, fail-closed EC262 journal with independently signed prefix.

    We re-read the small signed artifact and recompute the anchored prefix on
    EVERY record. This prevents silent same-size prefix editing during a live
    host service, but has a bounded per-event O(prefix_length) IO cost.
    """

    def __init__(self, audit_root: str, audit_key: str, checkpoint_path: str,
                 public_key_path: str, signer_public_sha256: str,
                 checkpoint_sha256: str, *, writable: bool = True):
        _need_crypto()
        if os.geteuid() == 0:
            _fail('EC263_NONROOT_REQUIRED')
        _outside_audit(audit_root, checkpoint_path)
        _outside_audit(audit_root, public_key_path)
        self.poisoned = False
        self.writable = writable
        self.journal: AuditLog | None = None
        self.checkpoint_path = checkpoint_path
        self.public_key_path = public_key_path
        self.checkpoint_sha256 = _hash(checkpoint_sha256, 'EC263_CHECKPOINT_PIN_INVALID')
        self.signer_sha256 = _hash(signer_public_sha256, 'EC263_PUBLIC_PIN_INVALID')
        try:
            self.journal = AuditLog(audit_root, audit_key, create=False,
                                    writable_existing=writable)
            self._read_and_validate_signed_checkpoint()
            self._validate_live_prefix()
        except BaseException:
            self.close()
            raise

    def _read_and_validate_signed_checkpoint(self) -> None:
        public_key = _read_private(self.public_key_path, 32)
        if len(public_key) != 32 or not hmac.compare_digest(
                _digest(public_key), self.signer_sha256):
            _fail('EC263_PUBLIC_KEY_PIN_MISMATCH')
        raw = _read_private(self.checkpoint_path, MAX_CHECKPOINT)
        if not hmac.compare_digest(_digest(raw), self.checkpoint_sha256):
            _fail('EC263_CHECKPOINT_PIN_MISMATCH')
        signed = _parse_canonical(raw, MAX_CHECKPOINT)
        if set(signed) != SIGNED_FIELDS:
            _fail('EC263_CHECKPOINT_FIELDS_INVALID')
        payload = {k: signed[k] for k in PAYLOAD_FIELDS}
        _validate_payload(payload)
        if payload['signer_public_sha256'] != self.signer_sha256:
            _fail('EC263_CHECKPOINT_SIGNER_MISMATCH')
        signature = signed['signature_ed25519']
        if (type(signature) is not str or len(signature) != 128 or
                re.fullmatch(r'[0-9a-f]{128}', signature) is None):
            _fail('EC263_CHECKPOINT_SIGNATURE_INVALID')
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                bytes.fromhex(signature), DOMAIN + _canonical(payload))
        except (InvalidSignature, ValueError) as exc:
            raise AnchorError('EC263_CHECKPOINT_SIGNATURE_INVALID') from exc
        self.payload = payload

    def _validate_live_prefix(self) -> None:
        assert self.journal is not None
        _prefix(self.journal, self.payload)

    def record(self, event: str, session_tag: str = 'SERVICE',
               reason_code: str = 'NONE') -> None:
        if not self.writable:
            _fail('EC263_READ_ONLY_CHECKPOINT_VERIFIER')
        if self.poisoned:
            _fail('EC263_CHECKPOINT_OR_JOURNAL_POISONED')
        try:
            self._read_and_validate_signed_checkpoint()
            self._validate_live_prefix()
            assert self.journal is not None
            self.journal.record(event, session_tag, reason_code)
        except BaseException as exc:
            self.poisoned = True
            if isinstance(exc, AuditError):
                raise
            raise AnchorError('EC263_ANCHORED_AUDIT_UNAVAILABLE') from exc

    def summary(self) -> dict[str, Any]:
        self._read_and_validate_signed_checkpoint()
        self._validate_live_prefix()
        assert self.journal is not None
        return {'status': 'partial', 'exit_code': 2,
                'reason_code': 'EC263_OFFLINE_SIGNATURE_OF_LOCAL_HMAC_PREFIX',
                'attested_event_count': self.payload['event_count'],
                'current_event_count': self.journal.count,
                'post_checkpoint_unattested_events': (
                    self.journal.count - self.payload['event_count']),
                'signer_public_sha256': self.signer_sha256,
                'checkpoint_sha256': self.checkpoint_sha256,
                'ed25519_offline_checkpoint_signature_verified': True,
                'ec262_full_journal_hmac_chain_verified': True,
                'external_worm_or_independent_timestamp_verified': False,
                'live_rootless_oci_kernel_verified': False,
                'overall_quality_pass_verified': False}

    def close(self) -> None:
        if self.journal is not None:
            self.journal.close()
            self.journal = None

    def __enter__(self) -> 'AnchoredAudit':
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

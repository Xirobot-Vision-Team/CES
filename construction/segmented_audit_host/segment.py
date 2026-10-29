#!/usr/bin/env python3
"""EC264: offline-authorized, non-destructive continuation of signed audit segments.

Existing EC262/263 journal formats stay byte-for-byte unchanged. Every closed
segment has a *full*, externally pinned EC263 Ed25519 checkpoint and a separate
signed EC264 continuation. The current segment is a different EC262 journal,
with a different HMAC key, created exactly once after offline approval.

A private, out-of-band SHA256-pinned chain config enumerates all old segments;
none can be dropped silently. This is NOT external WORM or a trusted timestamp.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quality_host import broker as private
from quality_run_host import broker as runner
from lease_host import broker as lease
from signed_audit_host.audit import AuditLog, AuditError, ZERO, _canonical
from offline_anchor_host import checkpoint as cp

SCHEMA = 'ces.ec264.offline_signed_audit_continuation.v1'
DOMAIN = b'CES/EC264/audit-continuation/v1\x00'
CONFIG_SCHEMA = 'ces.ec264.audit_segment_chain_config.v1'
GENESIS_SCHEMA = 'ces.ec264.audit_segment_genesis.v1'
FIELDS = frozenset({
    'schema', 'archive_checkpoint_sha256', 'archive_journal_sha256',
    'archive_event_count', 'archive_journal_bytes', 'archive_last_mac',
    'previous_continuation_sha256', 'next_audit_key_sha256',
    'next_segment_id', 'signer_public_sha256', 'nonce',
})
SIGNED_FIELDS = FIELDS | {'signature_ed25519'}
CONFIG_FIELDS = frozenset({'schema', 'signer_public_key', 'signer_public_sha256',
                           'archives', 'active'})
ARCHIVE_FIELDS = frozenset({'audit_root', 'audit_key', 'checkpoint',
                            'checkpoint_sha256', 'continuation',
                            'continuation_sha256'})
ACTIVE_FIELDS = frozenset({'audit_root', 'audit_key', 'segment_id'})
GENESIS_FIELDS = frozenset({'schema', 'segment_id', 'continuation_sha256',
                            'previous_continuation_sha256',
                            'audit_key_sha256'})
MAX_TRANSITION = 2048
MAX_PROPOSAL = 1792
MAX_CONFIG = 32768
MAX_ARCHIVES = 8
GENESIS_NAME = 'genesis.json'


class SegmentError(cp.AnchorError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def deny(code: str) -> None:
    raise SegmentError(code)


def _path(value: Any) -> str:
    try:
        return private._path(value)
    except (TypeError, ValueError, runner.HostRunError) as exc:
        raise SegmentError('EC264_PRIVATE_PATH_INVALID') from exc


def _sha(value: Any) -> str:
    if type(value) is not str or cp.SHA_RE.fullmatch(value) is None:
        deny('EC264_SHA256_INVALID')
    return value


def _nonce(value: Any) -> str:
    if type(value) is not str or cp.NONCE_RE.fullmatch(value) is None:
        deny('EC264_NONCE_INVALID')
    return value


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _raw_private(path: str, maxlen: int) -> bytes:
    try:
        return private._private_bytes(_path(path), maxlen)
    except (OSError, ValueError, TypeError, runner.HostRunError) as exc:
        raise SegmentError('EC264_PRIVATE_FILE_UNAVAILABLE') from exc


def _json_private(path: str, limit: int) -> tuple[bytes, dict[str, Any]]:
    raw = _raw_private(path, limit)
    try:
        obj = cp._parse_canonical(raw, limit)
    except cp.AnchorError as exc:
        raise SegmentError('EC264_CANONICAL_FILE_REQUIRED') from exc
    return raw, obj


def _validate_payload(payload: dict[str, Any]) -> None:
    if (type(payload) is not dict or set(payload) != FIELDS or
            payload.get('schema') != SCHEMA or
            type(payload['archive_event_count']) is not int or
            not 1 <= payload['archive_event_count'] <= cp.MAX_EVENTS or
            type(payload['archive_journal_bytes']) is not int or
            not 1 <= payload['archive_journal_bytes'] <= cp.MAX_FILE):
        deny('EC264_TRANSITION_FIELDS_INVALID')
    for name in ('archive_checkpoint_sha256', 'archive_journal_sha256',
                 'archive_last_mac', 'previous_continuation_sha256',
                 'next_audit_key_sha256', 'signer_public_sha256'):
        _sha(payload[name])
    _nonce(payload['next_segment_id'])
    _nonce(payload['nonce'])


def _public(public_key_path: str, signer_pin: str) -> bytes:
    _sha(signer_pin)
    public_key = _raw_private(public_key_path, 32)
    if len(public_key) != 32 or not _eq(cp._digest(public_key), signer_pin):
        deny('EC264_PUBLIC_SIGNER_PIN_MISMATCH')
    cp._need_crypto()
    return public_key


def _signed_transition(path: str, pin: str, public_key: bytes,
                       signer_pin: str) -> dict[str, Any]:
    raw, signed = _json_private(path, MAX_TRANSITION)
    if not _eq(cp._digest(raw), _sha(pin)):
        deny('EC264_TRANSITION_PIN_MISMATCH')
    if set(signed) != SIGNED_FIELDS:
        deny('EC264_TRANSITION_FIELDS_INVALID')
    payload = {k: signed[k] for k in FIELDS}
    _validate_payload(payload)
    if not _eq(payload['signer_public_sha256'], signer_pin):
        deny('EC264_TRANSITION_SIGNER_MISMATCH')
    sig = signed['signature_ed25519']
    if (type(sig) is not str or
            re.fullmatch(r'[0-9a-f]{128}', sig) is None):
        deny('EC264_TRANSITION_SIGNATURE_INVALID')
    try:
        cp.Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(sig), DOMAIN + _canonical(payload))
    except (cp.InvalidSignature, ValueError) as exc:
        raise SegmentError('EC264_TRANSITION_SIGNATURE_INVALID') from exc
    return payload


def _nonoverlap(roots: list[str], protected_paths: list[str]) -> None:
    dirs = [runner._private_dir(x) for x in roots]
    if len(set(dirs)) != len(dirs):
        deny('EC264_SEGMENT_ROOT_REUSED')
    for i, left in enumerate(dirs):
        for other in dirs[i + 1:]:
            if os.path.commonpath((left, other)) in (left, other):
                deny('EC264_SEGMENT_ROOTS_OVERLAP')
    for path in protected_paths:
        path = _path(path)
        if any(os.path.commonpath((root, path)) == root for root in dirs):
            deny('EC264_METADATA_OR_KEY_INSIDE_JOURNAL')


def _read_config(config_path: str, config_pin: str) -> dict[str, Any]:
    raw, config = _json_private(config_path, MAX_CONFIG)
    if not _eq(cp._digest(raw), _sha(config_pin)):
        deny('EC264_CHAIN_CONFIG_PIN_MISMATCH')
    if (set(config) != CONFIG_FIELDS or config.get('schema') != CONFIG_SCHEMA or
            type(config['archives']) is not list or
            not 1 <= len(config['archives']) <= MAX_ARCHIVES or
            type(config['active']) is not dict or
            set(config['active']) != ACTIVE_FIELDS):
        deny('EC264_CHAIN_CONFIG_FIELDS_INVALID')
    _path(config['signer_public_key'])
    _sha(config['signer_public_sha256'])
    for archive in config['archives']:
        if type(archive) is not dict or set(archive) != ARCHIVE_FIELDS:
            deny('EC264_CHAIN_ARCHIVE_FIELDS_INVALID')
        for field in ('audit_root', 'audit_key', 'checkpoint', 'continuation'):
            _path(archive[field])
        for field in ('checkpoint_sha256', 'continuation_sha256'):
            _sha(archive[field])
    for field in ('audit_root', 'audit_key'):
        _path(config['active'][field])
    _nonce(config['active']['segment_id'])
    roots = [a['audit_root'] for a in config['archives']] + [config['active']['audit_root']]
    keys = [a['audit_key'] for a in config['archives']] + [config['active']['audit_key']]
    if len(set(keys)) != len(keys):
        deny('EC264_AUDIT_KEY_REUSED')
    protected = keys + [config_path, config['signer_public_key']]
    for a in config['archives']:
        protected.extend([a['checkpoint'], a['continuation']])
    _nonoverlap(roots, protected)
    return config


def _genesis_for(transition: dict[str, Any], transition_pin: str) -> dict[str, Any]:
    return {'schema': GENESIS_SCHEMA,
            'segment_id': transition['next_segment_id'],
            'continuation_sha256': transition_pin,
            'previous_continuation_sha256': transition['previous_continuation_sha256'],
            'audit_key_sha256': transition['next_audit_key_sha256']}


def _verify_genesis(root: str, transition: dict[str, Any], pin: str) -> None:
    _, genesis = _json_private(os.path.join(root, GENESIS_NAME), 512)
    if set(genesis) != GENESIS_FIELDS or genesis != _genesis_for(transition, pin):
        deny('EC264_SEGMENT_GENESIS_MISMATCH')


def _key_hash(key_path: str) -> str:
    try:
        return cp._digest(lease._key(key_path))
    except (ValueError, OSError, runner.HostRunError) as exc:
        raise SegmentError('EC264_AUDIT_KEY_UNAVAILABLE') from exc


def propose_transition(archive_root: str, archive_key: str,
                       checkpoint: str, checkpoint_pin: str,
                       signer_public_key: str, signer_pin: str,
                       successor_key: str, parent_pin: str,
                       output: str) -> dict[str, Any]:
    """Read stopped/full-signed archive and propose ONE future segment.

    The proposal is not an authorization until separately reviewed and signed
    offline. Its parent pin must be operator reviewed; the online host later
    verifies the COMPLETE enumerated signed chain, not just this assertion.
    """
    _public(signer_public_key, signer_pin)
    _sha(checkpoint_pin)
    _sha(parent_pin)
    _nonoverlap([archive_root], [archive_key, checkpoint, signer_public_key,
                                 successor_key, output])
    new_key_hash = _key_hash(successor_key)
    if _eq(new_key_hash, _key_hash(archive_key)):
        deny('EC264_AUDIT_KEY_REUSED')
    with cp.AnchoredAudit(archive_root, archive_key, checkpoint,
                          signer_public_key, signer_pin, checkpoint_pin,
                          writable=False) as old:
        journal = old.journal
        assert journal is not None
        if (old.payload['event_count'] != journal.count or
                old.payload['journal_prefix_bytes'] != journal.size):
            deny('EC264_ARCHIVE_MUST_BE_SIGNED_TO_FINAL_BYTE')
        digest, lines, tail_mac = cp._fingerprint_prefix(journal.fd, journal.size)
        if (lines != journal.count or not _eq(tail_mac, journal.last_mac)):
            deny('EC264_ARCHIVE_CHANGED')
        payload = {
            'schema': SCHEMA,
            'archive_checkpoint_sha256': checkpoint_pin,
            'archive_journal_sha256': digest,
            'archive_event_count': journal.count,
            'archive_journal_bytes': journal.size,
            'archive_last_mac': journal.last_mac,
            'previous_continuation_sha256': parent_pin,
            'next_audit_key_sha256': new_key_hash,
            'next_segment_id': os.urandom(16).hex(),
            'signer_public_sha256': signer_pin,
            'nonce': os.urandom(16).hex(),
        }
        _validate_payload(payload)
        cp._atomic_new_private(output, _canonical(payload) + b'\n')
    return {'status': 'partial', 'exit_code': 2,
            'proposal_sha256': cp._digest(_canonical(payload) + b'\n'),
            'next_segment_id': payload['next_segment_id'],
            'archive_event_count': payload['archive_event_count'],
            'requires_offline_review_and_signing': True,
            'overall_quality_pass_verified': False}


def sign_transition_offline(proposal: str, signing_key: str,
                            output: str) -> dict[str, Any]:
    """Offline only: never takes a serving-host journal/key path."""
    cp._need_crypto()
    _, payload = _json_private(proposal, MAX_PROPOSAL)
    _validate_payload(payload)
    secret = _raw_private(signing_key, 32)
    if len(secret) != 32:
        deny('EC264_SIGNING_KEY_LENGTH_INVALID')
    pub = cp.public_bytes_from_signing_key(secret)
    if not _eq(cp._digest(pub), payload['signer_public_sha256']):
        deny('EC264_SIGNING_KEY_MISMATCH')
    signature = cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
        DOMAIN + _canonical(payload))
    signed = _canonical({**payload, 'signature_ed25519': signature.hex()}) + b'\n'
    cp._atomic_new_private(output, signed)
    return {'status': 'partial', 'exit_code': 2,
            'continuation_sha256': cp._digest(signed),
            'next_segment_id': payload['next_segment_id'],
            'requires_out_of_band_config_pin': True,
            'overall_quality_pass_verified': False}


class SegmentAudit:
    """Bounded chain of locked fully signed historical logs + one active log.

    Every operation checks the whole enumerated archive chain, including
    signatures, head HMAC and exact committed prefixes. The active segment's
    HMAC chain/head is re-validated from disk before writes (and compared to
    the state originally opened), so a same-size local rewrite cannot silently
    change the writer's view. Only locally anchored history is independently
    signed; current active events remain NOT independently attested.
    """

    def __init__(self, config_path: str, config_pin: str, *,
                 initialize: bool = False, writable: bool = True):
        if os.geteuid() == 0:
            deny('EC264_NONROOT_REQUIRED')
        self.config_path = config_path
        self.config_pin = _sha(config_pin)
        self.writable = writable
        self.poisoned = False
        self.archives: list[cp.AnchoredAudit] = []
        self.journal: AuditLog | None = None
        try:
            self.config = _read_config(config_path, config_pin)
            self.public = _public(self.config['signer_public_key'],
                                  self.config['signer_public_sha256'])
            self._open_archives()
            current = self.config['active']
            hashes = [_key_hash(entry['audit_key'])
                      for entry in self.config['archives']]
            self.live_key_hash = _key_hash(current['audit_key'])
            if len(set(hashes + [self.live_key_hash])) != len(hashes) + 1:
                deny('EC264_AUDIT_KEY_REUSED')
            self._check_archives()
            if initialize:
                self._initialize_active()
            else:
                self._check_active_genesis()
                self.journal = AuditLog(current['audit_root'], current['audit_key'],
                                        create=False, writable_existing=writable)
                self._check_active_state()
        except BaseException:
            self.close()
            raise

    def _open_archives(self) -> None:
        for entry in self.config['archives']:
            self.archives.append(cp.AnchoredAudit(
                entry['audit_root'], entry['audit_key'], entry['checkpoint'],
                self.config['signer_public_key'],
                self.config['signer_public_sha256'],
                entry['checkpoint_sha256'], writable=False))

    def _check_archives(self) -> None:
        config = _read_config(self.config_path, self.config_pin)
        if config != self.config:
            deny('EC264_CHAIN_CONFIG_CHANGED')
        public = _public(config['signer_public_key'], config['signer_public_sha256'])
        if public != self.public:
            deny('EC264_SIGNER_CHANGED')
        hashes = [_key_hash(entry['audit_key']) for entry in config['archives']]
        hashes.append(_key_hash(config['active']['audit_key']))
        if len(set(hashes)) != len(hashes):
            deny('EC264_AUDIT_KEY_REUSED')
        previous = ZERO
        transitions: list[dict[str, Any]] = []
        for idx, (entry, archive) in enumerate(zip(config['archives'], self.archives)):
            # Never accept a merely signed *prefix* as a completed segment.
            archive._read_and_validate_signed_checkpoint()
            archive._validate_live_prefix()
            audit = archive.journal
            assert audit is not None
            # The EC262 HMAC chain was fully checked at the locked FD open.
            # Rechecking the complete Ed25519-authenticated bytes now suffices
            # to detect any later change; there is no need for three separate
            # 32-MiB re-reads per append. The local high-water seal is checked
            # too and must still match the originally verified journal state.
            audit._check_head()
            if (archive.payload['event_count'] != audit.count or
                    archive.payload['journal_prefix_bytes'] != audit.size):
                deny('EC264_ARCHIVE_HAS_UNSIGNED_SUFFIX')
            transition = _signed_transition(entry['continuation'],
                                            entry['continuation_sha256'],
                                            public, config['signer_public_sha256'])
            if (not _eq(transition['archive_checkpoint_sha256'],
                        entry['checkpoint_sha256']) or
                    not _eq(transition['archive_journal_sha256'],
                            archive.payload['journal_prefix_sha256']) or
                    audit.count != transition['archive_event_count'] or
                    audit.size != transition['archive_journal_bytes'] or
                    not _eq(transition['archive_last_mac'], archive.payload['last_mac']) or
                    not _eq(archive.payload['last_mac'], audit.last_mac) or
                    not _eq(transition['previous_continuation_sha256'], previous)):
                deny('EC264_ARCHIVE_CONTINUATION_BROKEN')
            if idx:
                prior = config['archives'][idx - 1]
                _verify_genesis(entry['audit_root'], transitions[-1],
                                prior['continuation_sha256'])
                if not _eq(_key_hash(entry['audit_key']),
                           transitions[-1]['next_audit_key_sha256']):
                    deny('EC264_ARCHIVED_SUCCESSOR_KEY_MISMATCH')
            transitions.append(transition)
            previous = entry['continuation_sha256']
        last = transitions[-1]
        if (not _eq(hashes[-1], last['next_audit_key_sha256']) or
                not _eq(config['active']['segment_id'], last['next_segment_id'])):
            deny('EC264_ACTIVE_SUCCESSOR_MISMATCH')
        self.transitions = transitions

    def _check_active_genesis(self) -> None:
        self._check_archives()
        current = self.config['active']
        _verify_genesis(current['audit_root'], self.transitions[-1],
                        self.config['archives'][-1]['continuation_sha256'])

    def _check_active_state(self) -> None:
        assert self.journal is not None
        journal = self.journal
        saved = (journal.count, journal.size, journal.last_mac)
        journal._read_and_verify()
        journal._check_head()
        if saved != (journal.count, journal.size, journal.last_mac):
            deny('EC264_ACTIVE_AUDIT_REWRITTEN')

    def _initialize_active(self) -> None:
        if not self.writable:
            deny('EC264_INIT_MUST_BE_WRITABLE')
        current = self.config['active']
        root = runner._private_dir(current['audit_root'])
        # Requires a pristine pre-created 0700 directory, not an implicit
        # recreate/reset of a previously used journal. Failures preserve files.
        if os.listdir(root):
            deny('EC264_NEW_SEGMENT_NOT_EMPTY')
        self._check_archives()
        obj = _genesis_for(self.transitions[-1],
                           self.config['archives'][-1]['continuation_sha256'])
        cp._atomic_new_private(os.path.join(root, GENESIS_NAME),
                               _canonical(obj) + b'\n')
        with AuditLog(root, current['audit_key'], create=True) as audit:
            if audit.count != 0 or audit.size != 0:
                deny('EC264_NEW_SEGMENT_NOT_EMPTY')
        self._check_active_genesis()
        with AuditLog(root, current['audit_key'], create=False) as audit:
            if audit.count != 0 or audit.size != 0:
                deny('EC264_INITIAL_SEGMENT_NONEMPTY')

    def record(self, event: str, session_tag: str = 'SERVICE',
               reason_code: str = 'NONE') -> None:
        if not self.writable or self.journal is None:
            deny('EC264_READ_ONLY_OR_UNINITIALIZED')
        if self.poisoned:
            deny('EC264_SEGMENT_AUDIT_POISONED')
        try:
            self._check_active_genesis()
            self._check_active_state()
            self.journal.record(event, session_tag, reason_code)
        except BaseException as exc:
            self.poisoned = True
            if isinstance(exc, AuditError):
                raise
            raise SegmentError('EC264_AUDIT_WRITE_UNAVAILABLE') from exc

    def summary(self) -> dict[str, Any]:
        if self.poisoned:
            deny('EC264_SEGMENT_AUDIT_POISONED')
        if self.journal is None:
            deny('EC264_ACTIVE_SEGMENT_NOT_OPEN')
        self._check_active_genesis()
        self._check_active_state()
        return {
            'status': 'partial', 'exit_code': 2,
            'reason_code': 'EC264_SIGNED_CLOSED_SEGMENTS_ACTIVE_LOCAL_HMAC_ONLY',
            'sealed_archive_count': len(self.archives),
            'sealed_archive_event_count': sum(x.journal.count for x in self.archives),
            'active_segment_id': self.config['active']['segment_id'],
            'active_local_event_count': self.journal.count,
            'active_events_not_offline_signed': self.journal.count,
            'signed_historical_chain_verified': True,
            'external_worm_or_trusted_timestamp_verified': False,
            'live_rootless_oci_kernel_verified': False,
            'overall_quality_pass_verified': False,
        }

    def close(self) -> None:
        if self.journal is not None:
            self.journal.close()
            self.journal = None
        for old in reversed(self.archives):
            old.close()
        self.archives.clear()

    def __enter__(self) -> 'SegmentAudit':
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

#!/usr/bin/env python3
"""EC265: portable signed-segment custody, independent deposit receipts, live gate.

Three separate trust zones: the serving host exports fully EC264-validated
archives WITHOUT HMAC or Ed25519 secret keys; an independent custodian verifies
and deposits one bundle then signs a *deposit* receipt; an opt-in serving host
requires operator-pinned receipts before every protected audit append.

A signed deposit receipt is NOT proof of remote storage, WORM, retention, time,
archival availability, or custody signer independence. No network is used.
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
from ec262_signed_audit_host.audit import _canonical, ZERO, MAX_FILE, MAX_EVENTS
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import segment as seg
from ec252_quality_run_host import broker as runner

MANIFEST_SCHEMA = 'ces.ec265.custody_bundle_manifest.v1'
RECEIPT_SCHEMA = 'ces.ec265.independent_custody_deposit_receipt.v1'
GATE_SCHEMA = 'ces.ec265.pinned_custody_gate_config.v1'
RECEIPT_DOMAIN = b'CES/EC265/independent-custody-deposit/v1\x00'
FILE_LIMITS = {
    'events.jsonl': MAX_FILE,
    'head.json': 512,
    'checkpoint.json': seg.cp.MAX_CHECKPOINT,
    'continuation.json': seg.MAX_TRANSITION,
    'signer.pub': 32,
    'genesis.json': 512,
}
MAX_MANIFEST = 2048
MAX_RECEIPT = 2048
MAX_GATE = 8192
MANIFEST_FIELDS = frozenset({
    'schema', 'archive_index', 'checkpoint_sha256', 'continuation_sha256',
    'previous_continuation_sha256', 'signer_public_sha256',
    'journal_sha256', 'journal_bytes', 'event_count', 'last_mac',
    'next_segment_id', 'files',
})
FILE_INFO_FIELDS = frozenset({'sha256', 'bytes'})
RECEIPT_FIELDS = frozenset({
    'schema', 'archive_index', 'bundle_manifest_sha256',
    'checkpoint_sha256', 'continuation_sha256',
    'previous_continuation_sha256', 'signer_public_sha256',
    'journal_sha256', 'journal_bytes', 'event_count',
    'custody_public_sha256', 'nonce',
})
GATE_FIELDS = frozenset({'schema', 'custody_public_key',
                         'custody_public_sha256', 'receipts'})
GATE_ITEM_FIELDS = frozenset({'archive_index', 'receipt', 'receipt_sha256'})
CHUNK = 65536


class CustodyError(seg.SegmentError):
    """Fail-closed stable code, never a sensitive pathname or blob."""


def deny(code: str) -> None:
    raise CustodyError(code)


def _sha(value: Any) -> str:
    if type(value) is not str or cp.SHA_RE.fullmatch(value) is None:
        deny('EC265_SHA256_INVALID')
    return value


def _index(value: Any) -> int:
    if type(value) is not int or not 0 <= value < seg.MAX_ARCHIVES:
        deny('EC265_ARCHIVE_INDEX_INVALID')
    return value


def _path(value: Any) -> str:
    try:
        return seg._path(value)
    except (ValueError, TypeError) as exc:
        raise CustodyError('EC265_PRIVATE_PATH_INVALID') from exc


def _private(path: str, maximum: int) -> bytes:
    try:
        return seg._raw_private(path, maximum)
    except (OSError, ValueError, TypeError) as exc:
        raise CustodyError('EC265_PRIVATE_INPUT_UNAVAILABLE') from exc


def _json(path: str, maximum: int) -> tuple[bytes, dict[str, Any]]:
    raw = _private(path, maximum)
    try:
        return raw, cp._parse_canonical(raw, maximum)
    except (cp.AnchorError, TypeError, ValueError) as exc:
        raise CustodyError('EC265_CANONICAL_JSON_REQUIRED') from exc


def _canonical_file(payload: dict[str, Any]) -> bytes:
    return _canonical(payload) + b'\n'


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _files_for(index: int) -> tuple[str, ...]:
    return tuple(name for name in FILE_LIMITS if name != 'genesis.json' or index > 0)


def _safe_dir(path: str) -> str:
    try:
        return runner._private_dir(_path(path))
    except (ValueError, TypeError, OSError) as exc:
        raise CustodyError('EC265_PRIVATE_DIRECTORY_REQUIRED') from exc


def _no_overlap(target: str, roots: list[str]) -> None:
    target = _path(target)
    for root in roots:
        root = _path(root)
        if os.path.commonpath((target, root)) in (target, root):
            deny('EC265_OUTPUT_OVERLAPS_AUDIT_OR_SOURCE')


def _new_dir(path: str) -> str:
    path = _path(path)
    parent = _safe_dir(os.path.dirname(path))
    try:
        os.mkdir(path, mode=0o700)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise CustodyError('EC265_NEW_OUTPUT_DIRECTORY_UNAVAILABLE') from exc
    return _safe_dir(path)


def _store(path: str, raw: bytes) -> None:
    try:
        cp._atomic_new_private(path, raw)
    except (OSError, ValueError) as exc:
        raise CustodyError('EC265_OUTPUT_WRITE_UNAVAILABLE') from exc


def _copy_journal(fd: int, size: int, destination: str, expected_sha: str) -> None:
    """Stream from EC264's locked verified journal FD, O_EXCL destination."""
    if not 0 < size <= MAX_FILE:
        deny('EC265_JOURNAL_SIZE_INVALID')
    parent = _safe_dir(os.path.dirname(_path(destination)))
    name = os.path.basename(destination)
    dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
        try:
            digest = hashlib.sha256()
            off = 0
            while off < size:
                data = os.pread(fd, min(CHUNK, size - off), off)
                if not data:
                    deny('EC265_JOURNAL_TRUNCATED_DURING_EXPORT')
                digest.update(data)
                view = memoryview(data)
                while view:
                    n = os.write(out, view)
                    if n <= 0:
                        deny('EC265_JOURNAL_COPY_INCOMPLETE')
                    view = view[n:]
                off += len(data)
            if not hmac.compare_digest(digest.hexdigest(), _sha(expected_sha)):
                deny('EC265_SIGNED_JOURNAL_CHANGED_DURING_EXPORT')
            os.fsync(out)
            os.fsync(dirfd)
        finally:
            os.close(out)
    except OSError as exc:
        raise CustodyError('EC265_JOURNAL_EXPORT_UNAVAILABLE') from exc
    finally:
        os.close(dirfd)


def _validate_manifest(obj: dict[str, Any]) -> None:
    if (type(obj) is not dict or set(obj) != MANIFEST_FIELDS or
            obj.get('schema') != MANIFEST_SCHEMA or
            type(obj['journal_bytes']) is not int or
            not 1 <= obj['journal_bytes'] <= MAX_FILE or
            type(obj['event_count']) is not int or
            not 1 <= obj['event_count'] <= MAX_EVENTS or
            type(obj['files']) is not dict):
        deny('EC265_MANIFEST_FIELDS_INVALID')
    index = _index(obj['archive_index'])
    if set(obj['files']) != set(_files_for(index)):
        deny('EC265_MANIFEST_FILE_SET_INVALID')
    for field in ('checkpoint_sha256', 'continuation_sha256',
                  'previous_continuation_sha256', 'signer_public_sha256',
                  'journal_sha256', 'last_mac'):
        _sha(obj[field])
    if type(obj['next_segment_id']) is not str or cp.NONCE_RE.fullmatch(obj['next_segment_id']) is None:
        deny('EC265_MANIFEST_SEGMENT_ID_INVALID')
    for filename, metadata in obj['files'].items():
        if (type(metadata) is not dict or set(metadata) != FILE_INFO_FIELDS or
                type(metadata['bytes']) is not int or
                not 0 < metadata['bytes'] <= FILE_LIMITS[filename]):
            deny('EC265_MANIFEST_FILE_METADATA_INVALID')
        _sha(metadata['sha256'])
    if (obj['files']['events.jsonl']['bytes'] != obj['journal_bytes'] or
            not hmac.compare_digest(obj['files']['events.jsonl']['sha256'], obj['journal_sha256']) or
            not hmac.compare_digest(obj['files']['checkpoint.json']['sha256'], obj['checkpoint_sha256']) or
            not hmac.compare_digest(obj['files']['continuation.json']['sha256'], obj['continuation_sha256']) or
            not hmac.compare_digest(obj['files']['signer.pub']['sha256'], obj['signer_public_sha256']) or
            obj['files']['signer.pub']['bytes'] != 32 or
            (index == 0 and obj['previous_continuation_sha256'] != ZERO)):
        deny('EC265_MANIFEST_SELF_CONTRADICTION')


def _manifest_for(audit: seg.SegmentAudit, index: int) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Derive exact expected transfer bytes from fully validated, locked chain."""
    _index(index)
    if index >= len(audit.archives):
        deny('EC265_ARCHIVE_NOT_IN_CHAIN')
    entry = audit.config['archives'][index]
    archive = audit.archives[index]
    journal = archive.journal
    if journal is None:
        deny('EC265_ARCHIVE_NOT_LOCKED')
    cp_payload = archive.payload
    transition = audit.transitions[index]
    if not (journal.count == cp_payload['event_count'] == transition['archive_event_count'] and
            journal.size == cp_payload['journal_prefix_bytes'] == transition['archive_journal_bytes'] and
            journal.last_mac == cp_payload['last_mac'] == transition['archive_last_mac']):
        deny('EC265_ARCHIVE_NOT_FULLY_SIGNED')
    if index == 0 and os.path.lexists(os.path.join(entry['audit_root'], seg.GENESIS_NAME)):
        deny('EC265_UNEXPECTED_INITIAL_GENESIS')
    names = {
        'head.json': os.path.join(entry['audit_root'], 'head.json'),
        'checkpoint.json': entry['checkpoint'],
        'continuation.json': entry['continuation'],
        'signer.pub': audit.config['signer_public_key'],
    }
    if index:
        names['genesis.json'] = os.path.join(entry['audit_root'], seg.GENESIS_NAME)
    data = {name: _private(path, FILE_LIMITS[name]) for name, path in names.items()}
    files = {name: {'sha256': _digest(raw), 'bytes': len(raw)} for name, raw in data.items()}
    files['events.jsonl'] = {'sha256': cp_payload['journal_prefix_sha256'],
                             'bytes': journal.size}
    manifest = {
        'schema': MANIFEST_SCHEMA,
        'archive_index': index,
        'checkpoint_sha256': entry['checkpoint_sha256'],
        'continuation_sha256': entry['continuation_sha256'],
        'previous_continuation_sha256': transition['previous_continuation_sha256'],
        'signer_public_sha256': audit.config['signer_public_sha256'],
        'journal_sha256': cp_payload['journal_prefix_sha256'],
        'journal_bytes': journal.size,
        'event_count': journal.count,
        'last_mac': journal.last_mac,
        'next_segment_id': transition['next_segment_id'],
        'files': files,
    }
    _validate_manifest(manifest)
    for name, pin in (('checkpoint.json', entry['checkpoint_sha256']),
                      ('continuation.json', entry['continuation_sha256']),
                      ('signer.pub', audit.config['signer_public_sha256'])):
        if not hmac.compare_digest(_digest(data[name]), pin):
            deny('EC265_SOURCE_ANCHOR_CHANGED')
    if data['head.json'] != journal._head_bytes():
        deny('EC265_SOURCE_HIGH_WATER_CHANGED')
    return manifest, data


def export_archive(chain_path: str, chain_pin: str, index: int,
                   output_dir: str) -> dict[str, Any]:
    """Copy exactly one sealed archive; never copy online/offline secret keys."""
    with seg.SegmentAudit(chain_path, chain_pin, writable=False) as audit:
        _index(index)
        manifest, data = _manifest_for(audit, index)
        protected = ([entry['audit_root'] for entry in audit.config['archives']] +
                     [audit.config['active']['audit_root']])
        _no_overlap(output_dir, protected)
        _new_dir(output_dir)
        journal = audit.archives[index].journal
        assert journal is not None
        _copy_journal(journal.fd, journal.size, os.path.join(output_dir, 'events.jsonl'),
                      manifest['journal_sha256'])
        for filename, raw in data.items():
            _store(os.path.join(output_dir, filename), raw)
        raw_manifest = _canonical_file(manifest)
        _store(os.path.join(output_dir, 'manifest.json'), raw_manifest)
        # Revalidate original checked chain and copied bundle at both ends.
        audit._check_archives()
        _verify_bundle(output_dir, expected_index=index,
                       expected_checkpoint_pin=manifest['checkpoint_sha256'],
                       expected_continuation_pin=manifest['continuation_sha256'],
                       expected_parent_pin=manifest['previous_continuation_sha256'],
                       expected_signer_pin=manifest['signer_public_sha256'])
    return {'status': 'partial', 'exit_code': 2,
            'archive_index': index,
            'bundle_manifest_sha256': _digest(raw_manifest),
            'requires_independent_custodian_and_pins': True,
            'overall_quality_pass_verified': False}


def _verify_bundle(bundle_dir: str, *, expected_index: int,
                   expected_checkpoint_pin: str, expected_continuation_pin: str,
                   expected_parent_pin: str, expected_signer_pin: str,
                   allow_receipt: bool = False
                   ) -> tuple[dict[str, Any], bytes, dict[str, bytes]]:
    """Recipient verifies signed bytes without possessing host audit HMAC keys."""
    directory = _safe_dir(bundle_dir)
    raw_manifest, manifest = _json(os.path.join(directory, 'manifest.json'), MAX_MANIFEST)
    _validate_manifest(manifest)
    index = _index(expected_index)
    if (manifest['archive_index'] != index or
            not hmac.compare_digest(manifest['checkpoint_sha256'], _sha(expected_checkpoint_pin)) or
            not hmac.compare_digest(manifest['continuation_sha256'], _sha(expected_continuation_pin)) or
            not hmac.compare_digest(manifest['previous_continuation_sha256'], _sha(expected_parent_pin)) or
            not hmac.compare_digest(manifest['signer_public_sha256'], _sha(expected_signer_pin))):
        deny('EC265_BUNDLE_INDEPENDENT_PIN_MISMATCH')
    try:
        present = set(os.listdir(directory))
    except OSError as exc:
        raise CustodyError('EC265_BUNDLE_LIST_UNAVAILABLE') from exc
    expected_files = set(_files_for(index)) | {'manifest.json'}
    if allow_receipt:
        expected_files.add('receipt.json')
    if present != expected_files:
        deny('EC265_BUNDLE_UNEXPECTED_OR_MISSING_FILES')
    data = {name: _private(os.path.join(directory, name), FILE_LIMITS[name])
            for name in _files_for(index)}
    for name, raw in data.items():
        metadata = manifest['files'][name]
        if (len(raw) != metadata['bytes'] or
                not hmac.compare_digest(_digest(raw), metadata['sha256'])):
            deny('EC265_BUNDLE_FILE_DIGEST_MISMATCH')
    source_public = data['signer.pub']
    if len(source_public) != 32:
        deny('EC265_BUNDLE_SOURCE_KEY_INVALID')
    cp._need_crypto()
    _, checkpoint = _json(os.path.join(directory, 'checkpoint.json'), cp.MAX_CHECKPOINT)
    if set(checkpoint) != cp.SIGNED_FIELDS:
        deny('EC265_BUNDLE_CHECKPOINT_INVALID')
    payload = {name: checkpoint[name] for name in cp.PAYLOAD_FIELDS}
    cp._validate_payload(payload)
    if payload['signer_public_sha256'] != expected_signer_pin:
        deny('EC265_BUNDLE_CHECKPOINT_SIGNER_INVALID')
    signature = checkpoint['signature_ed25519']
    if type(signature) is not str or re.fullmatch('[0-9a-f]{128}', signature) is None:
        deny('EC265_BUNDLE_CHECKPOINT_SIGNATURE_INVALID')
    try:
        cp.Ed25519PublicKey.from_public_bytes(source_public).verify(
            bytes.fromhex(signature), cp.DOMAIN + _canonical(payload))
    except (cp.InvalidSignature, ValueError) as exc:
        raise CustodyError('EC265_BUNDLE_CHECKPOINT_SIGNATURE_INVALID') from exc
    transition = seg._signed_transition(os.path.join(directory, 'continuation.json'),
                                        expected_continuation_pin, source_public,
                                        expected_signer_pin)
    if (transition['archive_checkpoint_sha256'] != expected_checkpoint_pin or
            transition['archive_journal_sha256'] != manifest['journal_sha256'] or
            transition['archive_journal_bytes'] != manifest['journal_bytes'] or
            transition['archive_event_count'] != manifest['event_count'] or
            transition['archive_last_mac'] != manifest['last_mac'] or
            transition['previous_continuation_sha256'] != expected_parent_pin or
            transition['next_segment_id'] != manifest['next_segment_id'] or
            payload['journal_prefix_sha256'] != manifest['journal_sha256'] or
            payload['journal_prefix_bytes'] != manifest['journal_bytes'] or
            payload['event_count'] != manifest['event_count'] or
            payload['last_mac'] != manifest['last_mac']):
        deny('EC265_BUNDLE_SIGNED_CONTENT_INCONSISTENT')
    journal = data['events.jsonl']
    if not journal.endswith(b'\n') or journal.count(b'\n') != manifest['event_count']:
        deny('EC265_BUNDLE_JOURNAL_FRAMING_INVALID')
    try:
        tail = json.loads(journal[:-1].rsplit(b'\n', 1)[-1])
        if not (type(tail) is dict and
                hmac.compare_digest(tail.get('mac', ''), manifest['last_mac'])):
            deny('EC265_BUNDLE_LAST_MAC_MISMATCH')
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CustodyError('EC265_BUNDLE_LAST_RECORD_INVALID') from exc
    try:
        head = cp._parse_canonical(data['head.json'], FILE_LIMITS['head.json'])
    except cp.AnchorError as exc:
        raise CustodyError('EC265_BUNDLE_HEAD_INVALID') from exc
    if (set(head) != {'schema', 'event_count', 'last_mac', 'journal_size', 'mac'} or
            type(head['event_count']) is not int or
            type(head['journal_size']) is not int or
            head['schema'] != 'ces.ec262.local_audit_head.v1' or
            head['event_count'] != manifest['event_count'] or
            head['journal_size'] != manifest['journal_bytes'] or
            head['last_mac'] != manifest['last_mac'] or
            type(head['mac']) is not str or cp.SHA_RE.fullmatch(head['mac']) is None):
        deny('EC265_BUNDLE_HEAD_INCONSISTENT')
    if index:
        try:
            genesis = cp._parse_canonical(data['genesis.json'], FILE_LIMITS['genesis.json'])
        except cp.AnchorError as exc:
            raise CustodyError('EC265_BUNDLE_GENESIS_INVALID') from exc
        if (set(genesis) != seg.GENESIS_FIELDS or
                type(genesis['previous_continuation_sha256']) is not str or
                genesis['schema'] != seg.GENESIS_SCHEMA or
                genesis['continuation_sha256'] != expected_parent_pin or
                type(genesis['segment_id']) is not str or
                cp.NONCE_RE.fullmatch(genesis['segment_id']) is None or
                type(genesis['audit_key_sha256']) is not str or
                cp.SHA_RE.fullmatch(genesis['audit_key_sha256']) is None):
            deny('EC265_BUNDLE_GENESIS_INCONSISTENT')
        _sha(genesis['previous_continuation_sha256'])
    return manifest, raw_manifest, data


def _receipt_payload(manifest: dict[str, Any], raw_manifest: bytes,
                     custody_pin: str) -> dict[str, Any]:
    return {
        'schema': RECEIPT_SCHEMA,
        'archive_index': manifest['archive_index'],
        'bundle_manifest_sha256': _digest(raw_manifest),
        'checkpoint_sha256': manifest['checkpoint_sha256'],
        'continuation_sha256': manifest['continuation_sha256'],
        'previous_continuation_sha256': manifest['previous_continuation_sha256'],
        'signer_public_sha256': manifest['signer_public_sha256'],
        'journal_sha256': manifest['journal_sha256'],
        'journal_bytes': manifest['journal_bytes'],
        'event_count': manifest['event_count'],
        'custody_public_sha256': custody_pin,
    }


def _verify_receipt(path: str, receipt_pin: str, custody_public: bytes,
                    custody_pin: str, expected: dict[str, Any]) -> dict[str, Any]:
    raw, signed = _json(path, MAX_RECEIPT)
    if not hmac.compare_digest(_digest(raw), _sha(receipt_pin)):
        deny('EC265_RECEIPT_BYTES_PIN_MISMATCH')
    if set(signed) != RECEIPT_FIELDS | {'signature_ed25519'}:
        deny('EC265_RECEIPT_FIELDS_INVALID')
    if (signed['schema'] != RECEIPT_SCHEMA or
            type(signed['archive_index']) is not int or
            not 0 <= signed['archive_index'] < seg.MAX_ARCHIVES or
            type(signed['event_count']) is not int or
            not 1 <= signed['event_count'] <= MAX_EVENTS or
            type(signed['journal_bytes']) is not int or
            not 1 <= signed['journal_bytes'] <= MAX_FILE):
        deny('EC265_RECEIPT_PAYLOAD_INVALID')
    for field in ('bundle_manifest_sha256', 'checkpoint_sha256',
                  'continuation_sha256', 'previous_continuation_sha256',
                  'signer_public_sha256', 'journal_sha256',
                  'custody_public_sha256'):
        _sha(signed[field])
    for key, value in expected.items():
        if signed.get(key) != value:
            deny('EC265_RECEIPT_ARCHIVE_BINDING_MISMATCH')
    if signed['schema'] != RECEIPT_SCHEMA or signed['custody_public_sha256'] != custody_pin:
        deny('EC265_RECEIPT_CUSTODIAN_MISMATCH')
    nonce = signed['nonce']
    if type(nonce) is not str or cp.NONCE_RE.fullmatch(nonce) is None:
        deny('EC265_RECEIPT_NONCE_INVALID')
    signature = signed['signature_ed25519']
    if type(signature) is not str or re.fullmatch('[0-9a-f]{128}', signature) is None:
        deny('EC265_RECEIPT_SIGNATURE_INVALID')
    payload = {k: signed[k] for k in RECEIPT_FIELDS}
    try:
        cp.Ed25519PublicKey.from_public_bytes(custody_public).verify(
            bytes.fromhex(signature), RECEIPT_DOMAIN + _canonical(payload))
    except (cp.InvalidSignature, ValueError) as exc:
        raise CustodyError('EC265_RECEIPT_SIGNATURE_INVALID') from exc
    return signed


def receive_archive(bundle_dir: str, vault_root: str, signing_key: str,
                    custody_pin: str, *, expected_index: int,
                    expected_checkpoint_pin: str, expected_continuation_pin: str,
                    expected_parent_pin: str, expected_signer_pin: str) -> dict[str, Any]:
    """Offline independent receiver; deposits once, fsyncs, *then* signs receipt.

    Source HMAC and signer private key are NEVER accepted nor transferred.
    The custodian signing key is NEVER passed to the online host.
    """
    if os.geteuid() == 0:
        deny('EC265_NONROOT_REQUIRED')
    _sha(custody_pin)
    _sha(expected_signer_pin)
    if hmac.compare_digest(custody_pin, expected_signer_pin):
        deny('EC265_CUSTODY_SIGNER_MUST_BE_DISTINCT')
    source_key = _private(signing_key, 32)
    if len(source_key) != 32:
        deny('EC265_CUSTODY_PRIVATE_KEY_INVALID')
    custody_public = cp.public_bytes_from_signing_key(source_key)
    if not hmac.compare_digest(_digest(custody_public), custody_pin):
        deny('EC265_CUSTODY_SIGNER_PIN_MISMATCH')
    manifest, raw_manifest, data = _verify_bundle(bundle_dir,
        expected_index=expected_index, expected_checkpoint_pin=expected_checkpoint_pin,
        expected_continuation_pin=expected_continuation_pin,
        expected_parent_pin=expected_parent_pin, expected_signer_pin=expected_signer_pin)
    vault_root = _safe_dir(vault_root)
    _no_overlap(vault_root, [bundle_dir])
    if os.path.commonpath((vault_root, _path(signing_key))) == vault_root:
        deny('EC265_CUSTODY_PRIVATE_KEY_INSIDE_VAULT')
    # Full manifest digest names one deposit. Never overwrite/reuse a directory.
    deposit = os.path.join(vault_root, _digest(raw_manifest))
    _new_dir(deposit)
    for name, raw in data.items():
        _store(os.path.join(deposit, name), raw)
    _store(os.path.join(deposit, 'manifest.json'), raw_manifest)
    # Independently re-open deposited bytes and validate the *stored* copy,
    # not only the incoming/possibly swapped media.
    stored, stored_manifest, _ = _verify_bundle(deposit,
        expected_index=expected_index, expected_checkpoint_pin=expected_checkpoint_pin,
        expected_continuation_pin=expected_continuation_pin,
        expected_parent_pin=expected_parent_pin, expected_signer_pin=expected_signer_pin)
    if stored != manifest or stored_manifest != raw_manifest:
        deny('EC265_DEPOSIT_DIFFERS_FROM_ACCEPTED_BUNDLE')
    payload = {**_receipt_payload(manifest, raw_manifest, custody_pin),
               'nonce': os.urandom(16).hex()}
    signature = cp.Ed25519PrivateKey.from_private_bytes(source_key).sign(
        RECEIPT_DOMAIN + _canonical(payload))
    receipt_raw = _canonical_file({**payload, 'signature_ed25519': signature.hex()})
    _store(os.path.join(deposit, 'receipt.json'), receipt_raw)
    return {'status': 'partial', 'exit_code': 2,
            'deposit_id': _digest(raw_manifest),
            'archive_index': expected_index,
            'receipt_sha256': _digest(receipt_raw),
            'receipt_path': os.path.join(deposit, 'receipt.json'),
            'receipt_is_deposit_only_not_retention_or_worm_proof': True,
            'overall_quality_pass_verified': False}


def verify_deposit(vault_root: str, deposit_id: str, custody_public_path: str,
                   custody_pin: str, *, expected_index: int,
                   expected_checkpoint_pin: str, expected_continuation_pin: str,
                   expected_parent_pin: str, expected_signer_pin: str,
                   receipt_pin: str) -> dict[str, Any]:
    """Read current retained bytes and signature; no time/WORM proof."""
    deposit_id = _sha(deposit_id)
    root = _safe_dir(vault_root)
    deposit = os.path.join(root, deposit_id)
    manifest, raw, _ = _verify_bundle(deposit,
        expected_index=expected_index, expected_checkpoint_pin=expected_checkpoint_pin,
        expected_continuation_pin=expected_continuation_pin,
        expected_parent_pin=expected_parent_pin, expected_signer_pin=expected_signer_pin,
        allow_receipt=True)
    if _digest(raw) != deposit_id:
        deny('EC265_STORED_DEPOSIT_ID_MISMATCH')
    if set(os.listdir(deposit)) != set(_files_for(expected_index)) | {'manifest.json', 'receipt.json'}:
        deny('EC265_DEPOSIT_UNEXPECTED_OR_MISSING_FILES')
    public = _private(custody_public_path, 32)
    if (len(public) != 32 or
            not hmac.compare_digest(_digest(public), _sha(custody_pin)) or
            hmac.compare_digest(custody_pin, expected_signer_pin)):
        deny('EC265_CUSTODY_PUBLIC_KEY_UNTRUSTED')
    expected = _receipt_payload(manifest, raw, custody_pin)
    _verify_receipt(os.path.join(deposit, 'receipt.json'), receipt_pin,
                    public, custody_pin, expected)
    return {'status': 'partial', 'exit_code': 2,
            'archive_index': expected_index,
            'deposit_bytes_present_and_match_at_check': True,
            'physical_external_custody_worm_retention_verified': False,
            'overall_quality_pass_verified': False}


class CustodyAudit(seg.SegmentAudit):
    """Strict opt-in EC264 host with independently pinned EC265 custody gate."""

    def __init__(self, chain: str, chain_pin: str, gate: str, gate_pin: str,
                 *, writable: bool = True):
        self.gate_path = _path(gate)
        self.gate_pin = _sha(gate_pin)
        self.gate_config: dict[str, Any] | None = None
        self.custody_public = b''
        super().__init__(chain, chain_pin, writable=writable)
        try:
            self._init_gate()
            self._check_receipts()
        except BaseException:
            self.close()
            raise

    def _read_gate(self) -> dict[str, Any]:
        raw, config = _json(self.gate_path, MAX_GATE)
        if not hmac.compare_digest(_digest(raw), self.gate_pin):
            deny('EC265_GATE_CONFIG_PIN_MISMATCH')
        if (set(config) != GATE_FIELDS or config.get('schema') != GATE_SCHEMA or
                type(config['receipts']) is not list or
                len(config['receipts']) != len(self.archives)):
            deny('EC265_GATE_RECEIPT_COVERAGE_INVALID')
        _path(config['custody_public_key'])
        _sha(config['custody_public_sha256'])
        if config['custody_public_sha256'] == self.config['signer_public_sha256']:
            deny('EC265_CUSTODY_AND_AUDIT_SIGNER_SAME')
        for index, entry in enumerate(config['receipts']):
            if (type(entry) is not dict or set(entry) != GATE_ITEM_FIELDS or
                    type(entry['archive_index']) is not int or
                    entry['archive_index'] != index):
                deny('EC265_GATE_RECEIPT_ORDER_INVALID')
            _path(entry['receipt'])
            _sha(entry['receipt_sha256'])
        sources = [x['audit_root'] for x in self.config['archives']] + [self.config['active']['audit_root']]
        for item in [self.gate_path, config['custody_public_key']] + [
                x['receipt'] for x in config['receipts']]:
            for root in sources:
                if os.path.commonpath((_path(root), item)) == _path(root):
                    deny('EC265_GATE_METADATA_INSIDE_AUDIT_ROOT')
        return config

    def _init_gate(self) -> None:
        self.gate_config = self._read_gate()
        self.custody_public = _private(self.gate_config['custody_public_key'], 32)
        if len(self.custody_public) != 32 or not hmac.compare_digest(
                _digest(self.custody_public), self.gate_config['custody_public_sha256']):
            deny('EC265_GATE_CUSTODY_KEY_PIN_MISMATCH')
        cp._need_crypto()

    def _check_receipts(self) -> None:
        config = self._read_gate()
        if config != self.gate_config:
            deny('EC265_GATE_CONFIG_CHANGED')
        public = _private(config['custody_public_key'], 32)
        if public != self.custody_public:
            deny('EC265_GATE_SIGNER_CHANGED')
        for index, entry in enumerate(config['receipts']):
            manifest, _ = _manifest_for(self, index)
            expected = _receipt_payload(manifest, _canonical_file(manifest),
                                        config['custody_public_sha256'])
            _verify_receipt(entry['receipt'], entry['receipt_sha256'],
                            public, config['custody_public_sha256'], expected)

    def record(self, event: str, session_tag: str = 'SERVICE',
               reason_code: str = 'NONE') -> None:
        if self.poisoned:
            deny('EC265_CUSTODY_AUDIT_POISONED')
        try:
            self._check_receipts()
            super().record(event, session_tag, reason_code)
        except BaseException:
            self.poisoned = True
            raise

    def summary(self) -> dict[str, Any]:
        self._check_archives()
        self._check_active_state()
        self._check_receipts()
        result = super().summary()
        result.update({
            'reason_code': 'EC265_INDEPENDENT_DEPOSIT_RECEIPTS_NOT_REMOTE_RETENTION_PROOF',
            'custody_receipts_verified': len(self.archives),
            'custody_receipt_signer_independent_key_required': True,
            'actual_external_worm_and_retention_verified': False,
            'overall_quality_pass_verified': False,
        })
        return result

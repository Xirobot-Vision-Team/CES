#!/usr/bin/env python3
"""EC317: lossless transport and re-verification of original EC316 signatures.

No source, claim, manifest, signature, certificate, or signed original is
rewritten. A complete source-read trace (not a guessed document schema walk)
is captured during a real EC316->EC294 replay. The archived original bytes are
replayed again under a strictly enumerated, temporary, private read-only path
binding, and are cryptographically reverified again on the receiver machine.

The binding is transport metadata, NOT a new signed authorization or trusted
filesystem identity. All four independent SHA pins and both custodian identities
and keys MUST come from outside the bundle on the receiving side.
"""
from __future__ import annotations

import hashlib
import hmac
from io import BytesIO
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import zipfile

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from dual_custodian_checkpoint import checkpoint as c

SCHEMA = 'ces.ec317.original_sha_portable_binding_manifest.v1'
RESULT_SCHEMA = 'ces.ec317.original_sha_rebinding_result.v1'
DENIAL_SCHEMA = 'ces.ec317.original_sha_rebinding_denial.v1'
MEMBER_FIELDS = frozenset({'original_absolute_path', 'original_raw_sha256',
                           'raw_size', 'source_format'})
ROOT_FIELDS = frozenset({'chain_file', 'expected_chain_sha256',
    'ledger_manifest_file', 'expected_ledger_manifest_sha256',
    'expected_latest_certificate_sha256', 'expected_latest_challenge_sha256',
    'trust'})
MANIFEST_FIELDS = frozenset({'schema', 'root', 'sources',
                             'replayed_result_original_sha256'})
MAX_SOURCES = 768
MAX_JSON_SOURCE_BYTES = 1_000_000
MAX_PER_SOURCE = b.MAX_BUNDLE_BYTES  # EC302 ZIP must remain whole and raw-byte pinned.
MAX_TOTAL_SOURCE_BYTES = 96_000_000
MAX_MANIFEST_BYTES = 800_000
MAX_ARCHIVE_BYTES = 105_000_000
OBJECT_PATTERN = re.compile(r'objects/[0-9a-f]{64}\.(?:json|zip)\Z')
SECRET_FIELD = re.compile(r'(?:^|_)(?:private_key|password|secret|credential|'
                          r'access_token|refresh_token|api_key|hmac_key)(?:_|$)',
                          re.IGNORECASE)


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise a.AnchorError('EC317_' + reason, status)


def _raw_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_path(value: Any) -> bool:
    # The existing original full-byte signatures intentionally refer to POSIX
    # absolute paths. No rewriting to Windows, relative paths, or ../ aliases.
    return (type(value) is str and 1 < len(value) <= 4000 and
            value.startswith('/') and not value.startswith('//') and
            '\x00' not in value and '\\' not in value and
            os.path.normpath(value) == value)


def _root(*, chain_file: str, expected_chain_sha256: str,
          ledger_manifest_file: str, expected_ledger_manifest_sha256: str,
          expected_latest_certificate_sha256: str,
          expected_latest_challenge_sha256: str, trust: dict) -> dict:
    c._trust(trust)
    need(all(_valid_path(path) for path in (chain_file, ledger_manifest_file)),
         'EXTERNAL_ORIGINAL_ABSOLUTE_ROOT_PATHS_REQUIRED', 'invalid_input')
    need(all(c._sha(pin) for pin in (
        expected_chain_sha256, expected_ledger_manifest_sha256,
        expected_latest_certificate_sha256, expected_latest_challenge_sha256)),
        'FOUR_OFF_BUNDLE_NONZERO_WHOLE_SHA_PINS_REQUIRED', 'invalid_input')
    return {'chain_file':chain_file, 'expected_chain_sha256':expected_chain_sha256,
            'ledger_manifest_file':ledger_manifest_file,
            'expected_ledger_manifest_sha256':expected_ledger_manifest_sha256,
            'expected_latest_certificate_sha256':expected_latest_certificate_sha256,
            'expected_latest_challenge_sha256':expected_latest_challenge_sha256,
            'trust':dict(trust)}


def _replay(root: dict) -> dict:
    return c.verify(**root)


def _scan_safe(value: Any, depth: int = 0) -> None:
    need(depth <= 48, 'SOURCE_RECURSION_BUDGET_EXCEEDED', 'invalid_input')
    if type(value) is dict:
        for key, child in value.items():
            need(type(key) is str, 'NONSTRING_EVIDENCE_KEY_INVALID')
            if SECRET_FIELD.search(key):
                permitted_hash = (key.endswith('_sha256') and type(child) is str and
                                  b.HEX64.fullmatch(child) is not None)
                permitted_negative = (key.endswith('_returned') and child is False)
                need(permitted_hash or permitted_negative,
                     'NO_RAW_PRIVATE_KEYS_SECRETS_OR_CREDENTIAL_FIELDS_IN_TRANSFER')
            _scan_safe(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _scan_safe(child, depth + 1)
    elif type(value) is str:
        need('-----BEGIN PRIVATE KEY-----' not in value and
             '-----BEGIN OPENSSH PRIVATE KEY-----' not in value,
             'NO_PEM_PRIVATE_KEYS_IN_TRANSFER')


def _source_format(original: str, raw: bytes) -> str:
    if raw.startswith(b'{'):
        need(len(raw) <= MAX_JSON_SOURCE_BYTES,
             'CANONICAL_JSON_SOURCE_EXCEEDS_BOUND', 'invalid_input')
        document = io.parse(raw, MAX_JSON_SOURCE_BYTES)
        need(hmac.compare_digest(raw, b.canonical(document)),
             'ORIGINAL_BYTES_MUST_BE_CANONICAL_LF_JSON')
        need(type(document.get('schema')) is str and
             document['schema'].startswith('ces.'),
             'ONLY_TYPED_CES_JSON_EVIDENCE_ALLOWED', 'invalid_input')
        _scan_safe(document)
        return 'json'
    # EC306->EC303 intentionally re-verifies an ORIGINAL binary EC302 ZIP.
    # Such ZIP bytes must not be UTF-8 parsed or rewritten as JSON; old EC302
    # will independently validate full ZIP pin, inner manifest and signatures.
    need(original.endswith('.zip') and raw.startswith(b'PK\x03\x04'),
         'ONLY_CANONICAL_JSON_OR_ORIGINAL_EC302_ZIP_ALLOWED', 'invalid_input')
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            need(1 < len(infos) <= b.MAX_DOCUMENTS + 1 and
                 len({x.filename for x in infos}) == len(infos) and
                 sum(x.file_size for x in infos) <= b.MAX_TOTAL_DOCUMENT_BYTES +
                     b.MAX_MANIFEST_BYTES and
                 'manifest.json' in {x.filename for x in infos},
                 'INNER_EC302_ZIP_EXCEEDS_BUDGET', 'invalid_input')
            inner = io.parse(archive.read('manifest.json'), b.MAX_MANIFEST_BYTES)
            need(inner.get('schema') == b.SCHEMA,
                 'ONLY_ORIGINAL_EC302_BOUNDED_ZIP_ALLOWED', 'invalid_input')
    except (a.AnchorError, io.HostError):
        # Preserve specific fail-closed denial reasons: AnchorError subclasses
        # ValueError, so catching ValueError first erases valid policy denials.
        raise
    except (zipfile.BadZipFile, ValueError, KeyError, EOFError,
            OverflowError, RuntimeError) as exc:
        raise a.AnchorError('EC317_ORIGINAL_EC302_ZIP_INVALID',
                            'invalid_input') from exc
    return 'zip'


def _source_bytes(original: str, raw: bytes) -> str:
    need(_valid_path(original), 'ORIGINAL_PATH_NOT_CANONICAL_ABSOLUTE', 'invalid_input')
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PER_SOURCE,
         'ORIGINAL_SOURCE_SIZE_OUTSIDE_BOUNDS', 'invalid_input')
    _source_format(original, raw)
    return _raw_sha(raw)


def _record_source(captured: dict[str, bytes], original: str, raw: bytes) -> None:
    _source_bytes(original, raw)
    previous = captured.get(original)
    need(previous is None or hmac.compare_digest(previous, raw),
         'SAME_ORIGINAL_PATH_CHANGED_DURING_REPLAY', 'unavailable')
    if previous is None:
        need(len(captured) < MAX_SOURCES and
             sum(map(len, captured.values())) + len(raw) <= MAX_TOTAL_SOURCE_BYTES,
             'READ_ONLY_SOURCE_CLOSURE_EXCEEDS_BOUND', 'invalid_input')
        captured[original] = raw


def _strict_private_originals(captured: dict[str, bytes]) -> None:
    # `_open_regular` itself performs O_NOFOLLOW/fstat identity and size checks.
    # This second restriction prevents bundling accidentally public originals,
    # hard links or unowned objects. The only imported objects are original
    # bytes, never the signing key files used by EC316 `sign`.
    for original, expected in captured.items():
        target = b._private_parent(original)
        before = os.lstat(target)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
             'SOURCE_OWNER_0600_SINGLE_LINK_REQUIRED')
        raw = io._open_regular(original, MAX_PER_SOURCE, private=True)
        after = os.lstat(target)
        need(tuple(getattr(before, k) for k in (
            'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')) ==
             tuple(getattr(after, k) for k in (
            'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')) and
             hmac.compare_digest(raw, expected),
             'ORIGINAL_SOURCE_CHANGED_AFTER_CAPTURE', 'unavailable')


def _write_private_bytes(path: str, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _replay_relocated(root: dict, captured: dict[str, bytes]) -> dict:
    need(1 <= len(captured) <= MAX_SOURCES, 'NONEMPTY_BOUNDED_SOURCE_CLOSURE_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='ces-ec317-rebound-') as folder:
        bindings = {}
        stored = {}
        for original in sorted(captured):
            sha = _source_bytes(original, captured[original])
            if sha not in stored:
                stored[sha] = str(Path(folder) / (sha + '.' +
                    _source_format(original, captured[original])))
                _write_private_bytes(stored[sha], captured[original])
            bindings[original] = stored[sha]
        folder_fd = os.open(folder, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
        visited: dict[str, bytes] = {}
        with io._scoped_original_source_reads(
                bindings=bindings,
                observer=lambda path, raw: _record_source(visited, path, raw)):
            result = _replay(root)
        need(set(visited) == set(captured),
             'MISSING_OR_UNUSED_REBOUND_SOURCE_DETECTED')
        need(all(hmac.compare_digest(captured[p], visited[p]) for p in captured),
             'REBOUND_REPLAY_READ_DIFFERENT_BYTES_THAN_ARCHIVED')
    return result


def _manifest(root: dict, captured: dict[str, bytes], result: dict) -> dict:
    return {'schema':SCHEMA, 'root':root,
            'sources':[{'original_absolute_path':p,
                        'original_raw_sha256':_raw_sha(captured[p]),
                        'raw_size':len(captured[p]),
                        'source_format':_source_format(p, captured[p])}
                       for p in sorted(captured)],
            'replayed_result_original_sha256':b.digest(b.canonical(result))}


def _archive_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _write_archive(out: str, manifest: dict, captured: dict[str, bytes]) -> str:
    target = b._private_parent(out)
    raw_manifest = b.canonical(manifest)
    need(len(raw_manifest) <= MAX_MANIFEST_BYTES,
         'PORTABLE_MANIFEST_EXCEEDS_BOUND', 'invalid_input')
    blobs = {(_raw_sha(raw), _source_format(path,raw)):raw
             for path,raw in captured.items()}
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError as exc:
        raise a.AnchorError('EC317_ARCHIVE_EXISTS_NO_OVERWRITE') from exc
    successful = False
    try:
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', allowZip64=False) as archive:
                archive.writestr(_archive_info('manifest.json'), raw_manifest)
                for (sha, suffix), raw in sorted(blobs.items()):
                    archive.writestr(_archive_info('objects/' + sha + '.' + suffix), raw)
            stream.flush()
            os.fsync(stream.fileno())
        need(os.stat(target).st_size <= MAX_ARCHIVE_BYTES,
             'ARCHIVE_WHOLE_BYTES_EXCEED_BOUND', 'invalid_input')
        parent_fd = os.open(str(target.parent), os.O_RDONLY |
                            getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        successful = True
        return _raw_sha(io._open_regular(str(target), MAX_ARCHIVE_BYTES, private=True))
    finally:
        if not successful:
            try:
                os.unlink(target)
            except FileNotFoundError:
                pass


def _manifest_sources(manifest: dict) -> dict[str, tuple[str, int, str]]:
    a.exact(manifest, MANIFEST_FIELDS, 'EC317_PORTABLE_MANIFEST_FIELDS_INVALID')
    need(manifest['schema'] == SCHEMA, 'PORTABLE_MANIFEST_SCHEMA_INVALID', 'invalid_input')
    a.exact(manifest['root'], ROOT_FIELDS, 'EC317_ROOT_FIELDS_INVALID')
    need(c._sha(manifest['replayed_result_original_sha256']),
         'SOURCE_REPLAY_PROJECTION_SHA_REQUIRED', 'invalid_input')
    sources = manifest['sources']
    need(type(sources) is list and 1 <= len(sources) <= MAX_SOURCES,
         'ONE_TO_MAX_BOUNDED_SOURCES_REQUIRED', 'invalid_input')
    mapping: dict[str, tuple[str, int, str]] = {}
    previous = ''
    total = 0
    for row in sources:
        a.exact(row, MEMBER_FIELDS, 'EC317_SOURCE_ROW_FIELDS_INVALID')
        path, sha, size, kind = (row['original_absolute_path'],
            row['original_raw_sha256'], row['raw_size'], row['source_format'])
        need(_valid_path(path) and path > previous,
             'ORIGINAL_PATHS_MUST_BE_SORTED_UNIQUE_CANONICAL', 'invalid_input')
        need(c._sha(sha) and type(size) is int and 0 < size <= MAX_PER_SOURCE and
             kind in ('json', 'zip') and
             (kind != 'json' or size <= MAX_JSON_SOURCE_BYTES),
             'SOURCE_HASH_OR_EXACT_SIZE_INVALID', 'invalid_input')
        total += size
        need(total <= MAX_TOTAL_SOURCE_BYTES,
             'TOTAL_SOURCE_BYTES_EXCEED_BOUND', 'invalid_input')
        mapping[path] = (sha, size, kind)
        previous = path
    return mapping


def _read_archive(bundle_file: str, expected_bundle_sha256: str,
                  root: dict) -> tuple[dict, dict[str, bytes]]:
    need(_valid_path(bundle_file) and c._sha(expected_bundle_sha256),
         'PRIVATE_ARCHIVE_AND_OFF_BUNDLE_WHOLE_SHA_REQUIRED', 'invalid_input')
    target = b._private_parent(bundle_file)
    before = os.lstat(target)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'ARCHIVE_OWNER_0600_SINGLE_LINK_REQUIRED')
    raw = io._open_regular(bundle_file, MAX_ARCHIVE_BYTES, private=True)
    after = os.lstat(target)
    need(tuple(getattr(before, k) for k in (
        'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')) ==
         tuple(getattr(after, k) for k in (
        'st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),
         'ARCHIVE_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(_raw_sha(raw), expected_bundle_sha256),
         'ARCHIVE_DIFFERS_FROM_INDEPENDENT_WHOLE_SHA_PIN')
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            need(2 <= len(infos) <= MAX_SOURCES + 1 and
                 len({i.filename for i in infos}) == len(infos),
                 'DUPLICATE_OR_EXCESSIVE_ZIP_ENTRIES', 'invalid_input')
            for info in infos:
                need(info.compress_type == zipfile.ZIP_STORED and
                     info.flag_bits == 0 and info.extra == b'' and
                     info.comment == b'' and info.create_system == 3 and
                     info.date_time == (1980,1,1,0,0,0) and
                     (info.external_attr >> 16) == (stat.S_IFREG | 0o600) and
                     not info.is_dir() and
                     (info.filename == 'manifest.json' or
                      OBJECT_PATTERN.fullmatch(info.filename) is not None) and
                     info.file_size == info.compress_size,
                     'ONLY_FIXED_0600_UNCOMPRESSED_TYPED_ZIP_ENTRIES_ALLOWED',
                     'invalid_input')
            manifest_info = archive.getinfo('manifest.json')
            need(manifest_info.file_size <= MAX_MANIFEST_BYTES,
                 'PORTABLE_MANIFEST_EXCEEDS_BOUND', 'invalid_input')
            manifest_raw = archive.read(manifest_info)
            manifest = io.parse(manifest_raw, MAX_MANIFEST_BYTES)
            need(hmac.compare_digest(manifest_raw, b.canonical(manifest)),
                 'MANIFEST_NOT_CANONICAL_ORIGINAL_BYTES')
            mapping = _manifest_sources(manifest)
            need(manifest['root'] == root,
                 'ARCHIVE_ROOT_DOES_NOT_MATCH_ALL_INDEPENDENT_EXTERNAL_PINS')
            referenced = {(sha, kind) for sha, _, kind in mapping.values()}
            need({i.filename for i in infos} ==
                 {'manifest.json'} | {'objects/' + sha + '.' + kind for sha, kind in referenced},
                 'MISSING_OR_UNREFERENCED_TRANSPORT_OBJECTS', 'invalid_input')
            captured = {}
            unique_blobs = {}
            for path, (sha, size, kind) in mapping.items():
                key = (sha, kind)
                if key not in unique_blobs:
                    item = archive.getinfo('objects/' + sha + '.' + kind)
                    need(item.file_size == size,
                         'OBJECT_BYTE_LENGTH_DIFFERS_FROM_BINDING', 'invalid_input')
                    content = archive.read(item)
                    need(_raw_sha(content) == sha,
                         'OBJECT_ORIGINAL_WHOLE_BYTES_SHA_INVALID')
                    unique_blobs[key] = content
                content = unique_blobs[key]
                need(len(content) == size and _source_bytes(path, content) == sha and
                     _source_format(path, content) == kind,
                     'SOURCE_ORIGINAL_BYTES_NOT_EQUAL_TRANSPORT_BINDING')
                captured[path] = content
            return manifest, captured
    except (a.AnchorError, io.HostError):
        # Explicit transport and external-pin denials must not get flattened
        # into a generic ZIP error (AnchorError inherits ValueError).
        raise
    except (zipfile.BadZipFile, KeyError, EOFError, ValueError,
            RuntimeError, OverflowError) as exc:
        raise a.AnchorError('EC317_ARCHIVE_CORRUPT_OR_UNSUPPORTED',
                            'invalid_input') from exc


def export(*, out: str, **context: Any) -> dict:
    """Replay live originals, freeze the exact read closure, replay the copy."""
    root = _root(**context)
    # Fail before any source replays if caller supplied an unsafe destination.
    b._private_parent(out)
    need(not os.path.lexists(out), 'ARCHIVE_EXISTS_NO_OVERWRITE')
    captured: dict[str, bytes] = {}
    with io._scoped_original_source_reads(
            observer=lambda path, raw: _record_source(captured, path, raw)):
        original_result = _replay(root)
    _strict_private_originals(captured)
    copy_result = _replay_relocated(root, captured)
    need(original_result == copy_result,
         'COPY_REPLAY_RESULT_DIFFERS_FROM_ORIGINAL_REPLAY', 'unavailable')
    manifest = _manifest(root, captured, original_result)
    archive_sha = _write_archive(out, manifest, captured)
    return {'status':'original_bytes_exported_and_replayed_under_strict_portable_binding',
            'exit_code':0, 'bundle_original_raw_sha256':archive_sha,
            'source_reference_count':len(captured),
            'distinct_byte_object_count':len({_raw_sha(x) for x in captured.values()}),
            'replayed_result_original_sha256':manifest['replayed_result_original_sha256'],
            'latest_certificate_original_raw_sha256':
                original_result['latest_certificate_original_raw_sha256'],
            'every_original_ec316_to_ec294_signature_replayed':True,
            'old_signed_original_bytes_rewritten':False,
            'external_global_latest_or_physical_cas_proven':False,
            'external_business_writes_performed':False}


def verify(*, bundle_file: str, expected_bundle_sha256: str,
           **context: Any) -> dict:
    """Receiver: only offline-pinned originals; no live path fallbacks or writes."""
    root = _root(**context)
    manifest, captured = _read_archive(bundle_file, expected_bundle_sha256, root)
    result = _replay_relocated(root, captured)
    need(b.digest(b.canonical(result)) ==
         manifest['replayed_result_original_sha256'],
         'RECEIVER_ORIGINAL_REPLAY_PROJECTION_MISMATCH')
    return {'status':'relocated_original_bytes_fully_reverified_without_original_paths',
            'exit_code':0, 'bundle_original_raw_sha256':expected_bundle_sha256,
            'source_reference_count':len(captured),
            'distinct_byte_object_count':len({_raw_sha(x) for x in captured.values()}),
            'replayed_result_original_sha256':manifest['replayed_result_original_sha256'],
            'latest_certificate_original_raw_sha256':
                result['latest_certificate_original_raw_sha256'],
            'every_original_ec316_to_ec294_signature_replayed':True,
            'old_signed_original_bytes_rewritten':False,
            'external_global_latest_or_physical_cas_proven':False,
            'external_business_writes_performed':False}

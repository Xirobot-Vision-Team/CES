#!/usr/bin/env python3
"""EC302: closed, portable and bounded EC301 signed-evidence transport bundle.

No private keys, provider tokens, HMAC secrets, original business writes,
network transfers or implicit newest-tip discovery are accepted. The bundle
contains only the exact typed EC301->300->299->297->295/296 proof dependency
closure, with local *transport paths* replaced by opaque document references.

Before export, and after rebinding, the unmodified original EC301 verifier
replays ALL original signatures using four caller-supplied off-bundle pins.
ZIP SHA is separately supplied on import. This makes verification portable;
it does NOT attest external immutable custody, recipients, or trusted time.
"""
from __future__ import annotations

import hashlib
import hmac
import io as bytesio
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import zipfile
from typing import Any, Iterator

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec296_anchor_rotation import rotation as r
from ec297_anchor_lineage import lineage as l
from ec299_witness_consistency import witness as w
from ec300_bilateral_gossip import gossip as g
from ec301_offline_handoff import handoff as h

SCHEMA = 'ces.ec302.offline_portable_evidence_bundle.v1'
RESULT_SCHEMA = 'ces.ec302.portable_bundle_operation_result.v1'
DENIAL_SCHEMA = 'ces.ec302.portable_bundle_denial.v1'
ROOT_ID = 'docs/0001.json'
REF_PREFIX = 'ces.ec302.document:'
MANIFEST_FILE = 'manifest.json'
MAX_DOCUMENTS = 2048
MAX_BUNDLE_BYTES = 24_000_000
MAX_TOTAL_DOCUMENT_BYTES = 22_000_000
MAX_MANIFEST_BYTES = 300_000
MAX_PER_DOCUMENT_BYTES = l.MAX_INPUT_BYTES
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
DOC_ID = re.compile(r'docs/[0-9]{4}\.json\Z')
SECRET_FIELD = re.compile(r'(?:private[_-]?key|secret|password|credential|api[_-]?key|'
                          r'access[_-]?token|refresh[_-]?token|hmac[_-]?key|'
                          r'auth[_-]?token|bearer)', re.IGNORECASE)

JOURNAL = h.JOURNAL_SCHEMA
RECEIPT = h.RECEIPT_SCHEMA
HISTORY = g.HISTORY_SCHEMA
SESSION = g.SESSION_SCHEMA
MANIFEST299 = w.MANIFEST_SCHEMA
OBSERVATION = w.RECEIPT_SCHEMA
INPUTS297 = l.INPUT_SCHEMA
COMMITMENT297 = l.COMMITMENT_SCHEMA
POLICY295 = a.POLICY_SCHEMA
CHECKPOINT295 = a.CHECKPOINT_SCHEMA
BRIDGE296 = r.BRIDGE_SCHEMA
LIMITS = {
    JOURNAL: h.MAX_JOURNAL_BYTES,
    RECEIPT: h.MAX_RECEIPT_BYTES,
    HISTORY: g.MAX_HISTORY_BYTES,
    SESSION: g.MAX_SESSION_BYTES,
    MANIFEST299: w.MAX_MANIFEST_BYTES,
    OBSERVATION: w.MAX_RECEIPT_BYTES,
    INPUTS297: l.MAX_INPUT_BYTES,
    COMMITMENT297: l.MAX_COMMITMENT_BYTES,
    POLICY295: a.MAX_POLICY_BYTES,
    CHECKPOINT295: a.MAX_CHECKPOINT_BYTES,
    BRIDGE296: r.MAX_BRIDGE_BYTES,
}
LEAVES = frozenset((RECEIPT, SESSION, OBSERVATION, COMMITMENT297,
                    POLICY295, CHECKPOINT295, BRIDGE296))
MANIFEST_FIELDS = frozenset({'schema', 'root_document', 'documents',
                             'external_pin_claims', 'reverified_ec301_report_sha256',
                             'reverified_exit_code', 'reverified_status'})
ENTRY_FIELDS = frozenset({'id', 'schema', 'sha256', 'size'})
PINS = ('a_id','a_public_hex','a_tip','b_id','b_public_hex','b_tip',
        'session_tip','receipt_tip')


def deny(reason: str, *, status: str = 'permission_denied') -> None:
    raise a.AnchorError('EC302_'+reason, status)


def required(condition: Any, reason: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        deny(reason, status=status)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(doc: Any) -> bytes:
    return a.canonical(doc) + b'\n'


def _pins(pins: dict) -> dict:
    required(type(pins) is dict and set(pins) == set(PINS), 'EIGHT_PIN_FIELDS_REQUIRED')
    g.check_identities(pins['a_id'], pins['a_public_hex'],
                       pins['b_id'], pins['b_public_hex'])
    required(all(l.sha_pin(pins[k]) for k in
                 ('a_tip','b_tip','session_tip','receipt_tip')),
             'FOUR_INDEPENDENT_LATEST_SHA_PINS_REQUIRED')
    return dict(pins)


def verify_original(journal: dict, pins: dict) -> dict:
    report, _ = h.verify_journal(journal, **_pins(pins))
    return report


def _slots(doc: dict) -> Iterator[tuple[dict | list, str | int, str]]:
    """ONLY recognized transport locations; anything else is not a file ref."""
    schema = doc['schema']
    if schema == JOURNAL:
        for entry in doc['entries']:
            yield entry, 'signed_receipt_file', RECEIPT
            yield entry, 'ec300_history_file', HISTORY
    elif schema == HISTORY:
        for entry in doc['sessions']:
            yield entry, 'signed_session_file', SESSION
            yield entry, 'witness_manifest_file', MANIFEST299
    elif schema == MANIFEST299:
        for role in ('a','b'):
            for entry in doc[role]['observations']:
                yield entry, 'signed_observation_file', OBSERVATION
                yield entry, 'inputs_file', INPUTS297
                yield entry, 'commitment_file', COMMITMENT297
    elif schema == INPUTS297:
        for epoch in doc['epochs']:
            yield epoch, 'policy_file', POLICY295
            for i in range(len(epoch['checkpoint_files'])):
                yield epoch['checkpoint_files'], i, CHECKPOINT295
        for bridge in doc['bridges']:
            yield bridge, 'bridge_file', BRIDGE296
    elif schema not in LEAVES:
        deny('UNKNOWN_DOCUMENT_TYPE_IN_REFERENCE_GRAPH')


def _safe_public_data(value: Any) -> None:
    """Block obvious secrets, source paths and PEM text from ALL raw evidence.

    Structured original signatures may still contain personally sensitive
    metadata; human data-classification and encrypted offline media are still
    required outside this code. Nothing here is called a general DLP scanner.
    """
    if type(value) is dict:
        for key, val in value.items():
            required(type(key) is str, 'INVALID_EVIDENCE_KEY')
            if SECRET_FIELD.search(key):
                allowed_digest = (key.endswith('_sha256') and
                                  type(val) is str and HEX64.fullmatch(val) is not None)
                allowed_negative = (key.endswith('_returned') and val is False)
                required(allowed_digest or allowed_negative,
                         'PRIVATE_OR_CREDENTIAL_FIELD_NOT_EXPORTABLE')
            _safe_public_data(val)
    elif type(value) is list:
        for val in value:
            _safe_public_data(val)
    elif type(value) is str:
        required(not value.startswith(('/', '\\\\', 'file://', '-----BEGIN ')) and
                 not (len(value) >= 3 and value[1:3] in (':\\', ':/') and
                      value[0].isalpha()) and
                 not any(tag in value for tag in ('PRIVATE KEY-----', '\x00')),
                 'LOCAL_PATH_OR_PRIVATE_KEY_TEXT_IN_BUNDLE')


def _collect(journal_file: str) -> dict[str, tuple[str, dict | bytes]]:
    """DFS discovery IDs stable by protocol order; no original path in output."""
    found: dict[str, str] = {}
    types: dict[str, str] = {}
    result: dict[str, tuple[str, dict | bytes]] = {}

    def visit(path: str, schema: str) -> str:
        if path in found:
            required(types[path] == schema, 'SOURCE_REUSED_AS_DIFFERENT_DOCUMENT_TYPE')
            return found[path]
        required(len(found) < MAX_DOCUMENTS, 'DOCUMENT_COUNT_BUDGET_EXCEEDED')
        name = f'docs/{len(found)+1:04d}.json'
        found[path], types[path] = name, schema
        raw = io._open_regular(path, LIMITS[schema])
        doc = io.parse(raw, LIMITS[schema])
        required(doc.get('schema') == schema, 'SOURCE_SCHEMA_NOT_THE_EXPECTED_TYPE')
        if schema in LEAVES:
            # Preserve raw bytes of EC295 POLICY: its original externally
            # signed SHA is of the *raw bytes*, not canonical parsed JSON.
            _safe_public_data(doc)
            result[name] = (schema, raw)
        else:
            for container, key, expected in _slots(doc):
                link = container[key]
                required(l.absolute_file(link), 'NESTED_SOURCE_PATH_NOT_ABSOLUTE')
                container[key] = REF_PREFIX + visit(link, expected)
            _safe_public_data(doc)
            result[name] = (schema, doc)
        return name

    required(l.absolute_file(journal_file), 'ABSOLUTE_SOURCE_JOURNAL_REQUIRED')
    required(visit(journal_file, JOURNAL) == ROOT_ID, 'BAD_BUNDLE_ROOT')
    return result


def _encode(nodes: dict[str, tuple[str, dict | bytes]]) -> dict[str, bytes]:
    encoded = {}
    total = 0
    for name, (_, node) in nodes.items():
        raw = node if type(node) is bytes else canonical(node)
        required(len(raw) <= MAX_PER_DOCUMENT_BYTES, 'DOCUMENT_BYTES_EXCEED_BUDGET')
        total += len(raw)
        required(total <= MAX_TOTAL_DOCUMENT_BYTES, 'TOTAL_EVIDENCE_BUDGET_EXCEEDED')
        encoded[name] = raw
    return encoded


def _manifest(nodes: dict[str, tuple[str, dict | bytes]],
              encoded: dict[str, bytes], pins: dict, report: dict) -> dict:
    return {'schema':SCHEMA,'root_document':ROOT_ID,
            'documents':[{'id':key,'schema':nodes[key][0],
                          'sha256':digest(encoded[key]),'size':len(encoded[key])}
                         for key in sorted(nodes)],
            'external_pin_claims':_pins(pins),
            'reverified_ec301_report_sha256':a.sha(report),
            'reverified_exit_code':report['exit_code'],
            'reverified_status':report['status']}


def _parse_doc(raw: bytes, limit: int) -> dict:
    required(type(raw) is bytes and 0 < len(raw) <= limit,
             'BUNDLE_DOCUMENT_LENGTH_INVALID')
    return io.parse(raw, limit)


def _decode(manifest: dict, entries: dict[str, bytes], pins: dict) -> dict[str, tuple[str, dict | bytes]]:
    l.exact(manifest, MANIFEST_FIELDS, 'MANIFEST_FIELDS_INVALID')
    required(manifest['schema'] == SCHEMA and
             manifest['root_document'] == ROOT_ID and
             manifest['external_pin_claims'] == _pins(pins) and
             type(manifest['reverified_exit_code']) is int and
             manifest['reverified_exit_code'] in (0,2) and
             l.sha_pin(manifest['reverified_ec301_report_sha256']) and
             type(manifest['reverified_status']) is str,
             'BUNDLE_MANIFEST_IDENTITY_PINS_OR_STATUS_INVALID')
    records = manifest['documents']
    required(type(records) is list and 1 <= len(records) <= MAX_DOCUMENTS,
             'BUNDLE_DOCUMENT_INDEX_INVALID')
    names = [r.get('id') if type(r) is dict else None for r in records]
    required(names == [f'docs/{i:04d}.json' for i in range(1, len(records)+1)] and
             set(entries) == {MANIFEST_FILE, *names},
             'BUNDLE_MISSING_EXTRA_OR_NONCONSECUTIVE_DOCUMENT')
    result: dict[str, tuple[str, dict | bytes]] = {}
    for record in records:
        l.exact(record,ENTRY_FIELDS,'BUNDLE_DOCUMENT_RECORD_FIELDS_INVALID')
        name, schema = record['id'], record['schema']
        required(type(schema) is str and schema in LIMITS and
                 type(record['size']) is int and record['size'] > 0 and
                 record['size'] <= LIMITS[schema] and
                 type(record['sha256']) is str and HEX64.fullmatch(record['sha256']) is not None,
                 'BUNDLE_DOCUMENT_RECORD_INVALID')
        raw = entries[name]
        required(len(raw) == record['size'] and
                 hmac.compare_digest(digest(raw),record['sha256']),
                 'BUNDLE_DOCUMENT_HASH_OR_SIZE_MISMATCH')
        doc = _parse_doc(raw,LIMITS[schema])
        required(doc.get('schema') == schema, 'BUNDLE_DOCUMENT_SCHEMA_MISMATCH')
        if schema in LEAVES:
            _safe_public_data(doc)
            result[name] = (schema,raw)
        else:
            required(raw == canonical(doc),'PATH_REF_DOCUMENT_NOT_CANONICAL')
            # Reference strings stay abstract until secure materialization.
            for parent, key, expected in _slots(doc):
                token = parent[key]
                required(type(token) is str and token.startswith(REF_PREFIX) and
                         DOC_ID.fullmatch(token[len(REF_PREFIX):]) is not None,
                         'DOCUMENT_REFERENCE_NOT_A_CLOSED_BUNDLE_ID')
            _safe_public_data(doc)
            result[name] = (schema, doc)
    # Check all edges are known, typed, and all files are actually needed.
    seen = set()
    def traverse(name: str, expected: str) -> None:
        required(name in result and result[name][0] == expected,
                 'CROSS_DOCUMENT_REFERENCE_SCHEMA_MISMATCH')
        if name in seen:
            return
        seen.add(name)
        kind, node = result[name]
        if type(node) is dict:
            for parent,key,expected_child in _slots(node):
                traverse(parent[key][len(REF_PREFIX):], expected_child)
    traverse(ROOT_ID, JOURNAL)
    required(seen == set(result), 'BUNDLE_UNREFERENCED_OR_HIDDEN_EVIDENCE')
    return result


def _write(path: Path, raw: bytes) -> None:
    required(len(raw) <= MAX_PER_DOCUMENT_BYTES, 'DOCUMENT_WRITE_BUDGET_INVALID')
    fd = None
    try:
        fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                     getattr(os,'O_NOFOLLOW',0), 0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=True) as out:
            fd = None
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    except OSError as exc:
        raise a.AnchorError('EC302_PRIVATE_EXCLUSIVE_MATERIALIZATION_FAILED',
                            'unavailable') from exc
    finally:
        if fd is not None: os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|
                 getattr(os,'O_NOFOLLOW',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def _private_parent(path: str) -> Path:
    # EC317: only the scoped read-side relocation bridge is consulted here.
    # Original manifest bytes and signed logical references are unchanged.
    # Ordinary operations (including all outputs) keep native original paths.
    path = io._original_source_read_path(path)
    required(type(path) is str and l.absolute_file(path) and
             len(path) <= 4000 and os.path.normpath(path) == path and
             not path.startswith('//'),
             'ABSOLUTE_NORMALIZED_PRIVATE_DESTINATION_REQUIRED')
    p = Path(path)
    try:
        required(not any(x.is_symlink() for x in (p, *p.parents)),
                 'SYMLINK_DESTINATION_OR_ANCESTOR_FORBIDDEN')
        info = os.lstat(p.parent)
        required(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and
                 (stat.S_IMODE(info.st_mode) & 0o077)==0,
                 'DESTINATION_PARENT_MUST_BE_OWNER_PRIVATE_0700')
    except OSError as exc:
        raise a.AnchorError('EC302_PRIVATE_DESTINATION_PARENT_UNAVAILABLE',
                            'unavailable') from exc
    return p


def _materialize(dest: Path, nodes: dict[str, tuple[str, dict | bytes]],
                 manifest: dict) -> Path:
    """Caller owns fresh private root; never writes outside its fixed docs dir."""
    docs = dest / 'docs'
    docs.mkdir(mode=0o700)
    for name in sorted(nodes):
        schema, node = nodes[name]
        if type(node) is bytes:
            raw = node
        else:
            # Copy parsed object so verification never mutates archive inputs.
            cloned = json.loads(canonical(node))
            for parent,key,_ in _slots(cloned):
                ref = parent[key][len(REF_PREFIX):]
                required(DOC_ID.fullmatch(ref) is not None and ref in nodes,
                         'INVALID_REBOUND_REFERENCE')
                parent[key] = str(dest/ref)
            raw = canonical(cloned)
            required(len(raw) <= LIMITS[schema], 'REBOUND_DOCUMENT_TOO_LARGE')
        _write(dest/name,raw)
    _write(dest/MANIFEST_FILE,canonical(manifest))
    _fsync_dir(docs)
    _fsync_dir(dest)
    return dest / ROOT_ID


def _verify_snapshot(dest: Path, nodes: dict[str, tuple[str, dict | bytes]],
                     manifest: dict, pins: dict) -> dict:
    journal_file = _materialize(dest,nodes,manifest)
    # EC317: only these precisely named files were generated by the old EC302
    # typed, bounded, hash-checked decoder. Permit their internally derived
    # absolute references during relocation; never fall back to arbitrary
    # source-machine absolute paths not present in the pinned external bundle.
    with io._scoped_verified_snapshot_reads(
            frozenset(str(dest/name) for name in nodes) |
            {str(dest/MANIFEST_FILE)}):
        journal = io.read_doc(str(journal_file),h.MAX_JOURNAL_BYTES)
        report = verify_original(journal,pins)
    required(report['exit_code'] == manifest['reverified_exit_code'] and
             report['status'] == manifest['reverified_status'] and
             hmac.compare_digest(a.sha(report),manifest['reverified_ec301_report_sha256']),
             'REBOUND_REPORT_DIFFERS_FROM_ORIGINAL_FULL_SIGNED_PROOF')
    return report


def _read_zip(path: str, expected_sha: str) -> tuple[dict,dict[str,bytes]]:
    required(l.absolute_file(path) and type(expected_sha) is str and
             HEX64.fullmatch(expected_sha) is not None and expected_sha != a.GENESIS,
             'EXTERNAL_BUNDLE_BYTES_SHA_REQUIRED')
    raw = io._open_regular(path,MAX_BUNDLE_BYTES,private=True)
    required(hmac.compare_digest(digest(raw),expected_sha),
             'EXTERNAL_BUNDLE_SHA_MISMATCH')
    try:
        with zipfile.ZipFile(bytesio.BytesIO(raw),'r') as z:
            infos=z.infolist()
            required(1 <= len(infos) <= MAX_DOCUMENTS+1,
                     'ZIP_ENTRY_COUNT_BUDGET_INVALID')
            names=[f.filename for f in infos]
            required(len(names)==len(set(names)) and
                     all(name==MANIFEST_FILE or DOC_ID.fullmatch(name) for name in names),
                     'ZIP_ENTRY_NAME_OR_DUPLICATE_INVALID')
            required(MANIFEST_FILE in names and
                     all(f.compress_type == zipfile.ZIP_STORED and
                         not f.flag_bits & 1 and
                         (f.external_attr>>16 & 0o170000) in (0,0o100000) and
                         0 < f.file_size <= MAX_PER_DOCUMENT_BYTES and
                         f.compress_size == f.file_size for f in infos),
                     'ZIP_COMPRESSION_ENCRYPTION_OR_FILE_TYPE_FORBIDDEN')
            required(sum(f.file_size for f in infos)<=MAX_TOTAL_DOCUMENT_BYTES+MAX_MANIFEST_BYTES,
                     'ZIP_TOTAL_UNCOMPRESSED_BUDGET_INVALID')
            entries={f.filename:z.read(f) for f in infos}
    except (OSError,zipfile.BadZipFile,RuntimeError,EOFError,ValueError) as exc:
        raise a.AnchorError('EC302_BUNDLE_ZIP_READ_OR_FORMAT_INVALID','invalid_input') from exc
    required(len(entries[MANIFEST_FILE])<=MAX_MANIFEST_BYTES,
             'MANIFEST_BUDGET_INVALID')
    manifest=_parse_doc(entries[MANIFEST_FILE], MAX_MANIFEST_BYTES)
    required(entries[MANIFEST_FILE]==canonical(manifest),
             'MANIFEST_BYTES_NOT_CANONICAL')
    return manifest,entries


def build_bundle(journal_file: str, pins: dict, out: str) -> dict:
    pins=_pins(pins)
    original=io.read_doc(journal_file,h.MAX_JOURNAL_BYTES)
    report=verify_original(original,pins)
    nodes=_collect(journal_file)
    encoded=_encode(nodes)
    manifest=_manifest(nodes,encoded,pins,report)
    required(len(canonical(manifest))<=MAX_MANIFEST_BYTES,
             'MANIFEST_BUDGET_EXCEEDED')
    # Double check EXACT copied, privacy-screened snapshot, not merely original
    # files that might have changed between initial replay and collection.
    with tempfile.TemporaryDirectory(prefix='ces-ec302-verify-') as temp:
        _verify_snapshot(Path(temp),nodes,manifest,pins)
    outpath=_private_parent(out)
    required(not outpath.exists() and not outpath.is_symlink(),
             'BUNDLE_OUTPUT_EXISTS_NO_OVERWRITE')
    # Produce deterministic stored ZIP in the destination directory, atomically
    # publish with O_EXCL semantics via hard-link, then parent fsync.
    fd=None
    tmppath=None
    try:
        fd, filename=tempfile.mkstemp(prefix='.ces-ec302-',suffix='.tmp',dir=outpath.parent)
        tmppath=Path(filename)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=True) as sink:
            fd=None
            with zipfile.ZipFile(sink,'w',allowZip64=False) as z:
                payload={MANIFEST_FILE:canonical(manifest),**encoded}
                for name in sorted(payload):
                    record=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                    record.compress_type=zipfile.ZIP_STORED
                    record.create_system=3
                    record.external_attr=(stat.S_IFREG|0o600)<<16
                    z.writestr(record,payload[name])
            sink.flush();os.fsync(sink.fileno())
        required(tmppath.stat().st_size<=MAX_BUNDLE_BYTES,
                 'GENERATED_ZIP_EXCEEDS_BUDGET')
        os.link(tmppath,outpath,follow_symlinks=False)
        _fsync_dir(outpath.parent)
    except (OSError,zipfile.BadZipFile,RuntimeError) as exc:
        raise a.AnchorError('EC302_PRIVATE_ATOMIC_BUNDLE_WRITE_UNAVAILABLE','unavailable') from exc
    finally:
        if fd is not None:os.close(fd)
        if tmppath is not None:tmppath.unlink(missing_ok=True)
    return {'bundle_sha256':digest(io._open_regular(str(outpath),MAX_BUNDLE_BYTES)),
            'manifest_sha256':digest(canonical(manifest)),
            'evidence_document_count':len(nodes),'report_sha256':a.sha(report),
            'status':report['status'],'exit_code':report['exit_code']}


def verify_bundle(bundle_file: str, expected_bundle_sha256: str, pins: dict,
                  *, destination: str | None = None) -> dict:
    pins=_pins(pins)
    manifest,entries=_read_zip(bundle_file,expected_bundle_sha256)
    nodes=_decode(manifest,entries,pins)
    if destination is None:
        with tempfile.TemporaryDirectory(prefix='ces-ec302-inspect-') as temp:
            report=_verify_snapshot(Path(temp),nodes,manifest,pins)
            rebound=None
    else:
        dest=_private_parent(destination)
        # A malicious archive must not leave invalid signed evidence behind.
        # Preflight full original signatures in a separate private workspace
        # before the persistent receiver destination is ever created.
        with tempfile.TemporaryDirectory(prefix='ces-ec302-preflight-') as temp:
            _verify_snapshot(Path(temp),nodes,manifest,pins)
        required(not dest.exists() and not dest.is_symlink(),
                 'DESTINATION_EXISTS_NO_OVERWRITE')
        try:
            dest.mkdir(mode=0o700)
        except OSError as exc:
            raise a.AnchorError('EC302_PRIVATE_IMPORT_ROOT_CREATE_FAILED','unavailable') from exc
        # If an I/O or cryptographic error occurs after creation, leave the
        # private destination as explicit INCOMPLETE forensic evidence; never
        # publish a claimed-success status or silently merge with prior data.
        report=_verify_snapshot(dest,nodes,manifest,pins)
        rebound=str(dest / ROOT_ID)
    return {'bundle_sha256':expected_bundle_sha256,
            'manifest_sha256':digest(canonical(manifest)),
            'evidence_document_count':len(nodes),'report_sha256':a.sha(report),
            'status':report['status'],'exit_code':report['exit_code'],
            'rebound_journal_file':rebound}

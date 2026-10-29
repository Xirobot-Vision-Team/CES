#!/usr/bin/env python3
"""EC321: portable, exact-original-byte EC320 registrar fork case handoff.

Only a genuine sixth-signed, two-branch original registrar fork is exportable.
The receiver must separately pin the CASE ZIP's entire raw SHA, the sixth
witness's entire raw SHA, BOTH independent registrar snapshot/head pins, the
common genesis, and all public keys, identities and witness challenge.

Original files (including the entire EC317 original ZIP) remain byte-for-byte
unchanged. Local unsigned paths are NOT copied: they are built afresh in an
owner-private ephemeral directory after exact archive validation. Both full
EC320->EC294 source histories are then reverified with no original path
fallback, no private keys, no network and no business writes. This certifies
an observed local fork, not a winning branch, global latest or trusted CAS.
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

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as anchor
from ec302_portable_bundle import bundle as bundle
from ec317_original_rebinding import rebinding as original
from ec318_bilateral_transfer_receipt import receipt
from ec319_offline_transfer_registry import registry as reg
from ec320_fork_witness import witness

SCHEMA = 'ces.ec321.portable_genuine_signed_registrar_fork_case.v1'
RESULT_SCHEMA = 'ces.ec321.portable_fork_case_result.v1'
DENIAL_SCHEMA = 'ces.ec321.portable_fork_case_denial.v1'
MAX_ARCHIVE = 128_000_000
MAX_MANIFEST = 32_000
MAX_OBJECTS = 28  # EC317 ZIP + two EC319 branches + EC320 + 2*4*3 EC318 docs
MAX_RECEIPTS = reg.MAX_ENTRIES
MAX_JSON_OBJECT = reg.MAX_SNAPSHOT
FILE_RE = re.compile(r'objects/([0-9a-f]{64})\.(json|zip)\Z')
ROW_FIELDS = frozenset({'sequence','offer_sha256','ack_sha256','closure_sha256'})
OBJECT_FIELDS = frozenset({'raw_sha256','raw_size','source_format'})
PIN_FIELDS = frozenset({
    'case_id','witness_id','witness_public_hex','witness_challenge_sha256',
    'expected_witness_sha256','expected_left_sha256','expected_right_sha256',
    'expected_left_head_raw_sha256','expected_right_head_raw_sha256',
    'expected_genesis_raw_sha256','registrar_id','registrar_public_hex',
})
MANIFEST_FIELDS = frozenset({
    'schema','external_pins','original_transfer_bundle_raw_sha256',
    'left_receipts','right_receipts','objects',
})


def need(ok: Any, code: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC321_' + code, status)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def raw_json(doc: dict) -> bytes:
    return reg.raw_doc(doc)


def _pins(**values: str) -> dict:
    anchor.exact(values, PIN_FIELDS, 'EC321_ALL_EXTERNAL_PINS_REQUIRED')
    witness._external(case_id=values['case_id'], witness_id=values['witness_id'],
        witness_public_hex=values['witness_public_hex'],
        witness_challenge_sha256=values['witness_challenge_sha256'],
        registrar_id=values['registrar_id'],
        registrar_public_hex=values['registrar_public_hex'],
        expected_genesis_raw_sha256=values['expected_genesis_raw_sha256'],
        expected_left_sha256=values['expected_left_sha256'],
        expected_right_sha256=values['expected_right_sha256'],
        expected_left_head_raw_sha256=values['expected_left_head_raw_sha256'],
        expected_right_head_raw_sha256=values['expected_right_head_raw_sha256'])
    need(reg.custody._sha(values['expected_witness_sha256']),
         'SIGNED_WITNESS_WHOLE_ORIGINAL_SHA_REQUIRED', 'invalid_input')
    return values


def _witness_args(pins: dict, source_paths: dict) -> dict:
    return dict(pins, **source_paths)


def _authenticated_fork(pins: dict, paths: dict) -> dict:
    result = witness.verify(**_witness_args(pins, paths))
    need(result.get('exit_code') == 2 and
        result.get('status') ==
            'independent_sixth_signature_and_both_complete_original_forks_reverified' and
        result.get('sixth_witness_ed25519_signature_verified') is True and
        result.get('both_registrar_siblings_and_all_originals_replayed') is True and
        result.get('external_global_latest_or_winner_proven') is False,
        'ONLY_TWO_FULLY_REPLAYED_SIXTH_SIGNED_BRANCHES_EXPORTABLE')
    return result


def _raw(path: str, expected_sha: str, limit: int, label: str) -> bytes:
    need(original._valid_path(path) and reg.custody._sha(expected_sha),
         label + '_ABSOLUTE_SOURCE_AND_SIGNED_SHA_REQUIRED','invalid_input')
    data = reg._private_read(path, limit, label)
    need(hmac.compare_digest(sha(data), expected_sha),
         label + '_RAW_ORIGINAL_NOT_EQUAL_SIGNED_SHA')
    return data


def _register(blobs: dict[str, tuple[str, bytes]], *, path: str,
              expected_sha: str, kind: str, label: str) -> None:
    limit = original.MAX_ARCHIVE_BYTES if kind == 'zip' else MAX_JSON_OBJECT
    data = _raw(path, expected_sha, limit, label)
    if kind == 'json':
        doc = io.parse(data, limit)
        need(hmac.compare_digest(data, raw_json(doc)) and
             type(doc.get('schema')) is str and doc['schema'].startswith('ces.'),
             label + '_EXACT_TYPED_CANONICAL_LF_JSON_REQUIRED', 'invalid_input')
    else:
        need(data.startswith(b'PK\x03\x04') and path.endswith('.zip'),
             'ORIGINAL_EC317_BUNDLE_ZIP_BYTES_REQUIRED', 'invalid_input')
    prior = blobs.get(expected_sha)
    need(prior is None or (prior[0] == kind and
         hmac.compare_digest(prior[1], data)),
         'SAME_RAW_SHA_CANNOT_CLAIM_DIFFERENT_ORIGINAL_BYTES_OR_TYPE')
    blobs[expected_sha] = kind, data
    need(len(blobs) <= MAX_OBJECTS and
         sum(len(blob) for _, blob in blobs.values()) <= MAX_ARCHIVE - MAX_MANIFEST - 8000,
         'PORTABLE_CASE_OBJECT_COUNT_OR_BYTES_EXCEED_BOUND', 'invalid_input')


def _receipt_rows(snapshot: dict, materials: dict,
                  signed_bundle_sha: str, blobs: dict,
                  label: str) -> list[dict]:
    # The signed records, not unsigned materials or the manifest, choose
    # every evidence SHA. Only local file paths come from unsigned materials.
    need(len(materials['receipts']) == len(snapshot['records'])-1,
         label + '_EXACT_RECEIPT_CLOSURE_REQUIRED','invalid_input')
    _register(blobs, path=materials['genesis_bundle_file'],
              expected_sha=signed_bundle_sha, kind='zip', label=label+'_GENESIS_ZIP')
    rows = []
    for sequence, (record, paths) in enumerate(zip(
            snapshot['records'][1:], materials['receipts']), 1):
        claim = record['claim']
        need(paths['sequence'] == sequence,
             label + '_RECEIPT_SEQUENCE_NOT_SAME_AS_SIGNED_REGISTRY', 'invalid_input')
        _register(blobs, path=paths['bundle_file'],
                  expected_sha=signed_bundle_sha, kind='zip', label=label+'_TRANSFER_ZIP')
        row = {'sequence':sequence}
        for slot, signed_field, key in (
                ('offer', 'offer_original_raw_sha256','offer_sha256'),
                ('ack', 'ack_original_raw_sha256','ack_sha256'),
                ('closure', 'closure_original_raw_sha256','closure_sha256')):
            pinned = claim[signed_field]
            _register(blobs, path=paths[slot+'_file'], expected_sha=pinned,
                      kind='json', label=label+'_'+slot.upper())
            row[key] = pinned
        rows.append(row)
    return rows


def _manifest_from_live(pins: dict, paths: dict) -> tuple[dict, dict]:
    left = reg._load(paths['left_file'],pins['expected_left_sha256'],
                     reg.MAX_SNAPSHOT,'LEFT_CASE_SNAPSHOT')
    right = reg._load(paths['right_file'],pins['expected_right_sha256'],
                      reg.MAX_SNAPSHOT,'RIGHT_CASE_SNAPSHOT')
    lm = reg._materials(paths['left_materials_file'])
    rm = reg._materials(paths['right_materials_file'])
    need(left['records'][0] == right['records'][0],
         'CASE_MUST_HAVE_EXACT_SAME_SIGNED_GENESIS', 'invalid_input')
    genesis = left['records'][0]['claim']
    signed_bundle_sha = genesis['transfer_bundle_raw_sha256']
    blobs: dict[str, tuple[str, bytes]] = {}
    for label, path, signed_sha in (
            ('LEFT',paths['left_file'],pins['expected_left_sha256']),
            ('RIGHT',paths['right_file'],pins['expected_right_sha256']),
            ('WITNESS',paths['witness_file'],pins['expected_witness_sha256'])):
        _register(blobs,path=path,expected_sha=signed_sha,kind='json',label=label)
    lrows = _receipt_rows(left,lm,signed_bundle_sha,blobs,'LEFT')
    rrows = _receipt_rows(right,rm,signed_bundle_sha,blobs,'RIGHT')
    objects = [{'raw_sha256':hash_, 'raw_size':len(data),'source_format':kind}
               for hash_,(kind,data) in sorted(blobs.items())]
    manifest = {'schema':SCHEMA,'external_pins':dict(pins),
        'original_transfer_bundle_raw_sha256':signed_bundle_sha,
        'left_receipts':lrows,'right_receipts':rrows,'objects':objects}
    need(len(raw_json(manifest)) <= MAX_MANIFEST,
         'MANIFEST_BYTES_EXCEED_BOUND', 'invalid_input')
    return manifest, blobs


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (1980,1,1,0,0,0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _store_archive(out: str, manifest: dict,
                   blobs: dict[str, tuple[str,bytes]]) -> str:
    target = bundle._private_parent(out)
    need(not os.path.lexists(target), 'CASE_ZIP_MUST_NOT_EXIST_OR_OVERWRITE_SOURCE')
    try:
        fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                     getattr(os,'O_NOFOLLOW',0), 0o600)
    except FileExistsError as exc:
        raise anchor.AnchorError('EC321_CASE_ZIP_EXISTS_NO_OVERWRITE') from exc
    complete = False
    try:
        with os.fdopen(fd,'wb') as stream:
            with zipfile.ZipFile(stream,'w',allowZip64=False) as archive:
                archive.writestr(_zip_info('case-manifest.json'),raw_json(manifest))
                for hash_,(kind,data) in sorted(blobs.items()):
                    archive.writestr(_zip_info('objects/'+hash_+'.'+kind),data)
            stream.flush()
            os.fsync(stream.fileno())
        need(os.stat(target).st_size <= MAX_ARCHIVE,
             'FINAL_CASE_ZIP_EXCEEDS_BOUND','invalid_input')
        fd_dir = os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)
        complete = True
        return sha(reg._private_read(str(target),MAX_ARCHIVE,'NEW_CASE_ZIP'))
    finally:
        if not complete:
            try: os.unlink(target)
            except FileNotFoundError: pass


def _validate_manifest(manifest: dict, pins: dict) -> dict[str, tuple[str,int]]:
    anchor.exact(manifest,MANIFEST_FIELDS,'EC321_CASE_MANIFEST_FIELDS_EXACT')
    need(manifest['schema']==SCHEMA and manifest['external_pins']==pins,
         'CASE_MANIFEST_NOT_EQUAL_ALL_INDEPENDENT_EXTERNAL_PINS','invalid_input')
    need(reg.custody._sha(manifest['original_transfer_bundle_raw_sha256']),
         'CASE_TRANSFER_ZIP_SHA_INVALID','invalid_input')
    objects = manifest['objects']
    need(type(objects) is list and 4 <= len(objects) <= MAX_OBJECTS,
         'CASE_OBJECTS_OUTSIDE_EXACT_BOUNDS','invalid_input')
    source_map: dict[str,tuple[str,int]] = {}
    previous = ''
    total=0
    for row in objects:
        anchor.exact(row,OBJECT_FIELDS,'EC321_OBJECT_EXACT_FIELDS')
        hash_,size,kind = row['raw_sha256'],row['raw_size'],row['source_format']
        need(reg.custody._sha(hash_) and hash_ > previous and
             type(size) is int and size > 0 and
             kind in ('json','zip') and
             size <= (original.MAX_ARCHIVE_BYTES if kind=='zip' else MAX_JSON_OBJECT),
             'CASE_OBJECT_UNIQUE_ORDER_SIZE_FORMAT_SHA_INVALID','invalid_input')
        total += size
        need(total<=MAX_ARCHIVE-MAX_MANIFEST-8000,
             'CASE_TOTAL_UNCOMPRESSED_BYTES_EXCEED_BUDGET','invalid_input')
        source_map[hash_] = kind,size
        previous=hash_
    required = {x:'json' for x in (pins['expected_left_sha256'],
         pins['expected_right_sha256'],pins['expected_witness_sha256'])}
    expected_bundle_sha = manifest['original_transfer_bundle_raw_sha256']
    need(expected_bundle_sha not in required,
         'ZIP_AND_JSON_ORIGINAL_SHA_CANNOT_COLLIDE','invalid_input')
    required[expected_bundle_sha]='zip'
    for side in ('left_receipts','right_receipts'):
        rows=manifest[side]
        need(type(rows) is list and 1 <= len(rows) <= MAX_RECEIPTS,
             'EACH_FORK_NEEDS_ONE_TO_FOUR_SIGNED_RECEIPTS','invalid_input')
        for n,row in enumerate(rows,1):
            anchor.exact(row,ROW_FIELDS,'EC321_SIGNED_RECEIPT_REF_FIELDS')
            need(type(row['sequence']) is int and row['sequence']==n,
                 'RECEIPT_SEQUENCE_MUST_BE_EXACT_ORDER','invalid_input')
            for key in ('offer_sha256','ack_sha256','closure_sha256'):
                hash_=row[key]
                need(reg.custody._sha(hash_) and hash_ != expected_bundle_sha,
                     'RECEIPT_MUST_REFERENCE_VALID_SIGNED_ORIGINAL_SHA','invalid_input')
                required[hash_]='json'
    need(len(required)==len(source_map) and
         all(source_map.get(h,(None,))[0]==kind for h,kind in required.items()),
         'MISSING_EXTRA_OR_CROSS_TYPED_SIGNED_ORIGINAL_OBJECTS','invalid_input')
    return source_map


def _load_case(bundle_file: str, expected_bundle_sha256: str,
               pins: dict) -> tuple[dict,dict[str,bytes]]:
    need(original._valid_path(bundle_file) and
         reg.custody._sha(expected_bundle_sha256),
         'CASE_FILE_AND_INDEPENDENT_ENTIRE_ZIP_SHA_REQUIRED','invalid_input')
    raw = reg._private_read(bundle_file, MAX_ARCHIVE, 'WHOLE_PORTABLE_CASE_ZIP')
    need(hmac.compare_digest(sha(raw),expected_bundle_sha256),
         'CASE_ZIP_WHOLE_RAW_SHA_NOT_EQUAL_EXTERNAL_PIN')
    blobs={}
    try:
        with zipfile.ZipFile(BytesIO(raw),'r') as archive:
            infos=archive.infolist()
            need(5 <= len(infos) <= MAX_OBJECTS+1 and
                 len({info.filename for info in infos})==len(infos) and
                 archive.comment==b'',
                 'CASE_ZIP_DUPLICATE_OR_EXTRA_ENTRIES_OR_COMMENT','invalid_input')
            for info in infos:
                need(info.compress_type==zipfile.ZIP_STORED and
                     info.flag_bits==0 and info.extra==b'' and info.comment==b'' and
                     info.create_system==3 and
                     info.date_time==(1980,1,1,0,0,0) and
                     (info.external_attr >>16)==(stat.S_IFREG|0o600) and
                     info.file_size==info.compress_size and not info.is_dir() and
                     (info.filename=='case-manifest.json' or
                      FILE_RE.fullmatch(info.filename) is not None),
                     'UNSAFE_NONCANONICAL_OR_COMPRESSED_CASE_ZIP_ENTRY','invalid_input')
            member=archive.getinfo('case-manifest.json')
            need(0 < member.file_size <= MAX_MANIFEST,
                 'CASE_MANIFEST_SIZE_OUTSIDE_BOUNDS','invalid_input')
            man_raw=archive.read(member)
            manifest=io.parse(man_raw,MAX_MANIFEST)
            need(hmac.compare_digest(man_raw,raw_json(manifest)),
                 'CASE_MANIFEST_NOT_EXACT_CANONICAL_LF_JSON','invalid_input')
            mapping=_validate_manifest(manifest,pins)
            filenames={'case-manifest.json'} | {'objects/'+h+'.'+kind
                 for h,(kind,_) in mapping.items()}
            need({x.filename for x in infos}==filenames,
                 'ARCHIVE_MEMBERSHIP_NOT_EXACT_BOUND_CASE_CLOSURE','invalid_input')
            for h,(kind,size) in mapping.items():
                entry=archive.getinfo('objects/'+h+'.'+kind)
                need(entry.file_size==size,
                     'OBJECT_ORIGINAL_BYTE_COUNT_DIFFERS_FROM_MANIFEST','invalid_input')
                data=archive.read(entry)
                need(len(data)==size and hmac.compare_digest(sha(data),h),
                     'CASE_OBJECT_RAW_BYTES_SHA_INVALID')
                if kind=='json':
                    doc=io.parse(data,MAX_JSON_OBJECT)
                    need(hmac.compare_digest(raw_json(doc),data) and
                         type(doc.get('schema')) is str and doc['schema'].startswith('ces.'),
                         'CASE_JSON_ORIGINAL_NOT_CANONICAL_TYPED_LF','invalid_input')
                else:
                    need(data.startswith(b'PK\x03\x04'),
                         'CASE_EC317_ZIP_ORIGINAL_MAGIC_INVALID','invalid_input')
                blobs[h]=data
    except (anchor.AnchorError,io.HostError):
        raise
    except (zipfile.BadZipFile,KeyError,EOFError,ValueError,OverflowError,
            RuntimeError) as exc:
        raise anchor.AnchorError('EC321_CASE_ZIP_CORRUPT_OR_UNSUPPORTED',
                                 'invalid_input') from exc
    return manifest,blobs


def _temp_file(path: Path, raw: bytes) -> str:
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                 getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return str(path)


def _temp_materials(dest: Path, side: str, manifest: dict,
                    blobs: dict[str,bytes]) -> str:
    original_bundle=manifest['original_transfer_bundle_raw_sha256']
    def obj(hash_: str) -> str:
        ext = 'zip' if hash_==original_bundle else 'json'
        return str(dest / (hash_+'.'+ext))
    receipt_rows=[]
    for row in manifest[side+'_receipts']:
        receipt_rows.append({'sequence':row['sequence'],
            'bundle_file':obj(original_bundle),
            'offer_file':obj(row['offer_sha256']),
            'ack_file':obj(row['ack_sha256']),
            'closure_file':obj(row['closure_sha256'])})
    material = {'schema':reg.MATERIALS_SCHEMA,
                'genesis_bundle_file':obj(original_bundle),
                'receipts':receipt_rows}
    return _temp_file(dest/(side+'-local-materials.json'),raw_json(material))


def _result(pins: dict, archive_sha: str, manifest: dict,
            verified: dict, status: str) -> dict:
    return {'status':status,'exit_code':2,
        'case_id':pins['case_id'],'witness_id':pins['witness_id'],
        'registrar_id':pins['registrar_id'],
        'fork_sequence':verified['fork_sequence'],
        'case_bundle_original_raw_sha256':archive_sha,
        'original_ec320_attestation_raw_sha256':pins['expected_witness_sha256'],
        'left_snapshot_original_raw_sha256':pins['expected_left_sha256'],
        'right_snapshot_original_raw_sha256':pins['expected_right_sha256'],
        'source_object_count':len(manifest['objects']),
        'left_transfer_count':len(manifest['left_receipts']),
        'right_transfer_count':len(manifest['right_receipts']),
        'ec320_sixth_signature_and_both_complete_original_forks_replayed':True,
        'lossless_exact_original_bytes_rebound_without_source_paths':True,
        'external_latest_winner_or_atomic_cas_proven':False,
        'new_receiver_signature_or_organizational_authority_proven':False,
        'business_or_external_store_writes_performed':False}


def export(*, out: str, witness_file: str, left_file: str,
           left_materials_file: str, right_file: str,
           right_materials_file: str, **external_pins: str) -> dict:
    pins=_pins(**external_pins)
    paths=dict(witness_file=witness_file,left_file=left_file,
        left_materials_file=left_materials_file,right_file=right_file,
        right_materials_file=right_materials_file)
    need(all(original._valid_path(x) for x in paths.values()) and
         len(set(paths.values()))==5 and original._valid_path(out) and
         out not in paths.values(),
         'EXPORT_INPUT_FILES_DISTINCT_AND_OUTPUT_SAFE','invalid_input')
    bundle._private_parent(out)
    need(not os.path.lexists(out),'EXPORT_OUTPUT_EXISTS_NO_OVERWRITE')
    result=_authenticated_fork(pins,paths)
    manifest,blobs=_manifest_from_live(pins,paths)
    archive_sha=_store_archive(out,manifest,blobs)
    return _result(pins,archive_sha,manifest,result,
        'original_sixth_signed_registrar_fork_exported_as_pinned_portable_case')


def verify(*, bundle_file: str, expected_bundle_sha256: str,
           **external_pins: str) -> dict:
    pins=_pins(**external_pins)
    manifest,blobs=_load_case(bundle_file,expected_bundle_sha256,pins)
    with tempfile.TemporaryDirectory(prefix='ces-ec321-fork-receive-') as work:
        home=Path(work)
        types={x['raw_sha256']:x['source_format'] for x in manifest['objects']}
        for hash_,raw in blobs.items():
            _temp_file(home/(hash_+'.'+types[hash_]),raw)
        paths=dict(witness_file=str(home/(pins['expected_witness_sha256']+'.json')),
            left_file=str(home/(pins['expected_left_sha256']+'.json')),
            right_file=str(home/(pins['expected_right_sha256']+'.json')),
            left_materials_file=_temp_materials(home,'left',manifest,blobs),
            right_materials_file=_temp_materials(home,'right',manifest,blobs))
        # A signed EC319 claim is authoritative for each receipt raw SHA.
        # Reject even a wholly independently pinned ZIP if its unsigned
        # material row has been rearranged/relabeled relative to that claim.
        # EC336: only the exact newly materialized SHA-named originals and
        # self-generated materials files are readable during a rebound replay.
        # The signed source paths and pinned ZIP objects remain unchanged.
        local_imports = frozenset(
            str(home/(hash_+'.'+types[hash_])) for hash_ in blobs
        ) | frozenset((paths['left_materials_file'], paths['right_materials_file']))
        with io._scoped_verified_local_import_reads(local_imports):
            for side in ('left','right'):
                snapshot=reg._load(paths[side+'_file'],pins['expected_'+side+'_sha256'],
                                   reg.MAX_SNAPSHOT,side.upper()+'_IMPORTED_SNAPSHOT')
                rows=manifest[side+'_receipts']
                need(len(rows)==len(snapshot['records'])-1,
                     'IMPORT_SIGNED_RECEIPT_COUNT_NOT_EQUAL_MANIFEST','invalid_input')
                for row,record in zip(rows,snapshot['records'][1:]):
                    claim=record['claim']
                    need(all(row[key]==claim[field] for key,field in (
                        ('offer_sha256','offer_original_raw_sha256'),
                        ('ack_sha256','ack_original_raw_sha256'),
                        ('closure_sha256','closure_original_raw_sha256'))),
                        'IMPORT_RECEIPT_SHA_NOT_EQUAL_SIGNED_REGISTRAR_CLAIM',
                        'invalid_input')
                need(snapshot['records'][0]['claim']['transfer_bundle_raw_sha256']==
                     manifest['original_transfer_bundle_raw_sha256'],
                     'IMPORT_ZIP_NOT_EQUAL_SIGNED_REGISTRY_GENESIS','invalid_input')
            replay=_authenticated_fork(pins,paths)
    return _result(pins,expected_bundle_sha256,manifest,replay,
        'independent_receiver_verified_unmodified_original_fork_after_pathless_import')

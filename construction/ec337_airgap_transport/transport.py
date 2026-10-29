#!/usr/bin/env python3
"""EC337: bounded offline shipment of the EC335 *observed* original closure.

This module provides a deterministic, uncompressed byte-preserving transport ZIP
and an explicitly authorized receiver installer. It is NOT a signature, a
custody attestation, an encryption layer, or a remote CAS/Host interaction.

Trust is NEVER bootstrapped from the unsigned archive: a receiver must obtain
seven exact whole-file hashes (archive, plan, closure, map, and the three EC333
historical roots) independently via a trusted channel. All originals remain
byte-for-byte unchanged; the existing EC336 verifier MUST still be run after
install to validate full signed history under unchanged logical old paths.
"""
from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import hashlib
import hmac
import os
from pathlib import Path
import stat
import struct
from typing import Any, Iterator
import zipfile

from ec295_delivery_anchor import anchor
from ec302_portable_bundle import bundle as private
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec334_portable_source_inventory import inventory as first
from ec335_nested_source_closure import closure

SCHEMA = 'ces.ec337.unsigned_whole_original_offline_transport_manifest.v1'
RESULT_SCHEMA = 'ces.ec337.airgap_bundle_verified_or_installed_local_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec337.airgap_transport_denial.v1'
MAX_MANIFEST = 350_000
MAX_ARCHIVE = closure.MAX_TOTAL_BYTES + 9_000_000
CHUNK = 1024 * 1024
FROZEN_TIME = (1980, 1, 1, 0, 0, 0)
CONTROL_NAMES = ('controls/ec334-plan.json', 'controls/ec335-closure.json',
                 'controls/ec335-map.json')
LOCAL_CONTROL_FILES = ('ec334-plan.json', 'ec335-closure.json', 'ec335-map.json')
MANIFEST_NAME = 'manifest.json'
CUSTODY_SLOTS_NAME = 'custody/BLANK_EXTERNAL_TRUST_SLOTS.json'
FALSE_FIELDS = (
    'archive_or_manifest_self_sha_proves_independent_external_custody',
    'original_signature_messages_absolute_paths_or_original_bytes_rewritten',
    'transport_archive_is_signed_or_confers_institutional_authority',
    'installed_bytes_alone_prove_full_ec294_to_ec333_signature_replay',
    'old_signed_physical_path_identity_automatically_rebound_to_receiver',
    'all_dormant_history_or_absent_originals_proven_to_exist',
    'cross_file_transfer_or_install_is_an_atomic_immutable_snapshot',
    'remote_cas_worm_actual_nonexecution_latest_winner_or_submission_proven',
    'business_store_host_provider_network_or_external_signing_write_performed',
)
MANIFEST_FIELDS = frozenset({
    'schema','format','plan_original_raw_sha256','closure_original_raw_sha256',
    'map_original_raw_sha256','handoff_original_raw_sha256',
    'left_manifest_original_raw_sha256','right_manifest_original_raw_sha256',
    'source_count','original_total_byte_length','embedded_original_member_count',
    'members','custody_state','offline_unresolved_exit_code', *FALSE_FIELDS,
})
MEMBER_FIELDS = frozenset({'name','source_original_raw_sha256','byte_length'})
ROOT_KEYS = ('expected_handoff_sha256','left_expected_manifest_sha256',
             'right_expected_manifest_sha256')


def need(ok: Any, reason: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC337_' + reason, status)


def _pin_sha(value: str, label: str) -> None:
    need(receipt._sha(value) and value != '0'*64,
         label + '_SEPARATE_EXTERNAL_RAW_SHA_REQUIRED', 'invalid_input')


def _name(index: int) -> str:
    return f'originals/{index:04d}.bin'


def _control_state(*, first_hop_plan_file: str,
                   expected_first_hop_plan_sha256: str,
                   closure_file: str, expected_closure_sha256: str,
                   map_file: str, expected_map_sha256: str,
                   expected_handoff_sha256: str,
                   left_expected_manifest_sha256: str,
                   right_expected_manifest_sha256: str) -> tuple[dict,dict,dict,tuple[bytes,...]]:
    for label, value in (
        ('PLAN',expected_first_hop_plan_sha256),
        ('CLOSURE',expected_closure_sha256),('MAP',expected_map_sha256),
        ('HANDOFF',expected_handoff_sha256),
        ('LEFT_MANIFEST',left_expected_manifest_sha256),
        ('RIGHT_MANIFEST',right_expected_manifest_sha256),
    ):
        _pin_sha(value, label)
    paths = (first_hop_plan_file, closure_file, map_file)
    need(len(set(paths)) == 3 and all(first._path(p) for p in paths),
         'THREE_DISTINCT_ABSOLUTE_CANONICAL_CONTROL_PATHS_REQUIRED','invalid_input')
    plan, plan_raw = first._load_plan(first_hop_plan_file,
                                     expected_first_hop_plan_sha256)
    doc, doc_raw = closure._load_closure(closure_file, expected_closure_sha256,
                    plan, expected_first_hop_plan_sha256, first_hop_plan_file)
    mapping, map_raw = closure._load_map(map_file, expected_map_sha256, doc,
                    expected_closure_sha256, set(paths[:2]))
    need((plan['handoff_original_raw_sha256'],
          plan['left_manifest_original_raw_sha256'],
          plan['right_manifest_original_raw_sha256']) ==
         (expected_handoff_sha256,left_expected_manifest_sha256,
          right_expected_manifest_sha256),
         'INDEPENDENT_HISTORICAL_ROOT_PINS_DO_NOT_MATCH_OLD_PLAN')
    return plan, doc, mapping, (plan_raw, doc_raw, map_raw)


def _blank_custody_slots() -> bytes:
    # An explicitly blank, unsigned worksheet for a SEPARATE external channel.
    # It must never be parsed or consumed as an automatic trust source.
    return receipt._raw({
        'schema':'ces.ec337.untrusted_blank_external_custody_worksheet.v1',
        'instruction':('Copy OUTSIDE this ZIP and complete using independent '
                       'witnessed records. Never copy unsigned archive self-hashes '
                       'into trusted CLI flags without independent custody.'),
        'outside_bundle_bundle_whole_sha256':None,
        'outside_bundle_plan_whole_sha256':None,
        'outside_bundle_closure_whole_sha256':None,
        'outside_bundle_map_whole_sha256':None,
        'outside_bundle_handoff_whole_sha256':None,
        'outside_bundle_left_manifest_whole_sha256':None,
        'outside_bundle_right_manifest_whole_sha256':None,
        'independent_custodian_identity':None,
        'independent_channel_identity':None,
        'receiver_authorization_or_signature':None,
        'cross_machine_physical_file_identity_proven':False,
        'remote_cas_worm_or_no_submission_proven':False,
        'custody_verified_by_this_bundle':False,
    })


def _manifest(plan: dict, doc: dict, mapping: dict, pins: dict) -> dict:
    members = []
    for filename, raw_field, raw_size in zip(CONTROL_NAMES,
        ('expected_first_hop_plan_sha256','expected_closure_sha256',
         'expected_map_sha256'),(pins['_plan_size'],pins['_closure_size'],
         pins['_map_size'])):
        members.append({'name':filename,
                        'source_original_raw_sha256':pins[raw_field],
                        'byte_length':raw_size})
    worksheet=_blank_custody_slots()
    members.insert(0,{'name':CUSTODY_SLOTS_NAME,
                      'source_original_raw_sha256':case.sha(worksheet),
                      'byte_length':len(worksheet)})
    for index, row in enumerate(doc['sources'],1):
        members.append({'name':_name(index),
                        'source_original_raw_sha256':row['source_original_raw_sha256'],
                        'byte_length':row['byte_length']})
    return {
        'schema':SCHEMA,'format':'ZIP_STORED_FIXED_1980_UNIX_0600_NO_EXTRA_V1',
        'plan_original_raw_sha256':pins['expected_first_hop_plan_sha256'],
        'closure_original_raw_sha256':pins['expected_closure_sha256'],
        'map_original_raw_sha256':pins['expected_map_sha256'],
        'handoff_original_raw_sha256':pins['expected_handoff_sha256'],
        'left_manifest_original_raw_sha256':pins['left_expected_manifest_sha256'],
        'right_manifest_original_raw_sha256':pins['right_expected_manifest_sha256'],
        'source_count':doc['source_count'],
        'original_total_byte_length':doc['total_source_byte_length'],
        'embedded_original_member_count':doc['embedded_original_member_count'],
        'members':members,
        'custody_state':'UNSIGNED_LOCAL_MEASUREMENT_EXTERNAL_WITNESS_NOT_PROVIDED',
        'offline_unresolved_exit_code':2,
        **{key:False for key in FALSE_FIELDS},
    }


def _check_manifest(value: Any, expected: dict) -> None:
    need(type(value) is dict and set(value) == MANIFEST_FIELDS and
         value.get('schema') == SCHEMA and value.get('format') ==
           'ZIP_STORED_FIXED_1980_UNIX_0600_NO_EXTRA_V1' and
         type(value.get('members')) is list and
         len(value['members']) == len(expected['members']) and
         all(type(m) is dict and set(m) == MEMBER_FIELDS and
             type(m['name']) is str and receipt._sha(m['source_original_raw_sha256']) and
             type(m['byte_length']) is int and m['byte_length'] > 0
             for m in value['members']) and
         value == expected,
         'ARCHIVE_MANIFEST_MUST_BE_EXACTLY_REBUILT_FROM_SIX_CALLER_PINS_AND_OLD_CONTROLS',
         'invalid_input')


def _zip_info(name: str) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name, FROZEN_TIME)
    zi.compress_type = zipfile.ZIP_STORED
    zi.create_system = 3
    zi.external_attr = (stat.S_IFREG | 0o600) << 16
    zi.flag_bits = 0
    return zi


def _private_output(path: str, forbidden: set[str]) -> tuple[int, os.stat_result]:
    need(first._path(path) and path not in forbidden,
         'OUTPUT_MUST_BE_DISTINCT_CANONICAL_PRIVATE_FILE','invalid_input')
    private._private_parent(path)
    need(not os.path.lexists(path),'OUTPUT_ALREADY_EXISTS','invalid_input')
    try:
        fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                     getattr(os,'O_NOFOLLOW',0),0o600)
    except FileExistsError as exc:
        raise anchor.AnchorError('EC337_OUTPUT_ALREADY_EXISTS','invalid_input') from exc
    os.fchmod(fd,0o600)
    return fd, os.fstat(fd)


def _cleanup_owned(path: str, identity: os.stat_result) -> None:
    try:
        now = os.lstat(path)
        if (stat.S_ISREG(now.st_mode) and
            (now.st_dev,now.st_ino)==(identity.st_dev,identity.st_ino)):
            os.unlink(path)
    except OSError:
        pass


def _fsync_dir(path: str) -> None:
    fd = os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|
                 getattr(os,'O_NOFOLLOW',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def _read_private_archive(fd: int, *, expected: str) -> str:
    _pin_sha(expected,'BUNDLE')
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink == 1 and
         0 < before.st_size <= MAX_ARCHIVE,
         'PRIVATE_BUNDLE_0600_OWNER_NLINK_AND_BYTE_CAP_REQUIRED')
    hashed = hashlib.sha256()
    os.lseek(fd,0,os.SEEK_SET)
    while True:
        part = os.read(fd,CHUNK)
        if not part:break
        hashed.update(part)
    after = os.fstat(fd)
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
         'BUNDLE_CHANGED_DURING_SHA_READ','unavailable')
    digest = hashed.hexdigest()
    need(hmac.compare_digest(digest,expected),
         'BUNDLE_WHOLE_RAW_SHA_MISMATCH_WITH_SEPARATE_TRUST_PIN')
    return digest


@contextmanager
def _archive(path: str, expected: str) -> Iterator[tuple[Any,int]]:
    need(first._path(path),'CANONICAL_PRIVATE_BUNDLE_PATH_REQUIRED','invalid_input')
    private._private_parent(path)
    fd = os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        digest = _read_private_archive(fd,expected=expected)
        # Pass a duplicate, preserving the original pinned inode for the final rehash.
        with os.fdopen(os.dup(fd),'rb') as stream:
            with zipfile.ZipFile(stream,mode='r') as z:
                yield z,fd
        _read_private_archive(fd,expected=digest)
    finally:
        os.close(fd)


def _check_zip_members(z: zipfile.ZipFile, expected_names: list[str],
                       lengths: list[int]) -> None:
    infos = z.infolist()
    need(len(infos)==len(expected_names) and
         [i.filename for i in infos]==expected_names and
         z.comment==b'' and all(i.date_time==FROZEN_TIME and
         i.compress_type==zipfile.ZIP_STORED and i.flag_bits==0 and
         i.create_system==3 and i.extra==b'' and i.comment==b'' and
         i.external_attr==((stat.S_IFREG|0o600)<<16) and
         i.file_size==expected_length and i.compress_size==expected_length and
         i.file_size>0 and not i.is_dir()
         for i,expected_length in zip(infos,lengths)),
         'EXACT_ARCHIVE_NAMES_ORDER_STORED_UNIX_MODE_AND_LENGTHS_REQUIRED',
         'invalid_input')
    # Refuse hidden local-header gaps, prefixed polyglots, ZIP comments,
    # trailing bytes and data descriptors. This v1 transport is below ZIP64.
    f = z.fp
    need(f is not None,'ARCHIVE_HANDLE_REQUIRED','unavailable')
    offset = 0
    for info in infos:
        need(info.header_offset==offset,
             'ARCHIVE_NONCONTIGUOUS_OR_PREFIXED_LOCAL_ENTRY','invalid_input')
        f.seek(offset)
        header = f.read(30)
        need(len(header)==30 and header[:4]==b'PK\x03\x04',
             'ARCHIVE_LOCAL_HEADER_REQUIRED','invalid_input')
        sig,ver,flags,method,t,d,crc,compressed,uncompressed,nlen,elen=struct.unpack(
            '<IHHHHHIIIHH',header)
        encoded=info.filename.encode('ascii')
        need(flags==0 and method==0 and compressed==info.file_size and
             uncompressed==info.file_size and crc==info.CRC and
             nlen==len(encoded) and elen==0 and f.read(nlen)==encoded,
             'ARCHIVE_LOCAL_HEADER_METADATA_MUST_MATCH_CENTRAL_DIRECTORY',
             'invalid_input')
        offset+=30+nlen+info.file_size
    need(offset==z.start_dir,
         'ARCHIVE_HIDDEN_DATA_BEFORE_CENTRAL_DIRECTORY','invalid_input')
    f.seek(0,os.SEEK_END)
    size=f.tell()
    need(size<=MAX_ARCHIVE and size>=offset+22,
         'ARCHIVE_TOTAL_SIZE_OUT_OF_BOUNDS','invalid_input')
    f.seek(size-22)
    trailer=f.read(22)
    need(len(trailer)==22 and trailer[:4]==b'PK\x05\x06',
         'ARCHIVE_NO_TRAILING_DATA_OR_COMMENT_ALLOWED','invalid_input')
    (_sig,disk,cdisk,on_disk,total,central_size,central_offset,comment_len)=struct.unpack(
        '<IHHHHIIH',trailer)
    need(disk==0 and cdisk==0 and on_disk==len(infos) and
         total==len(infos) and comment_len==0 and central_offset==offset and
         central_size==size-22-offset,
         'ARCHIVE_EOCD_MUST_MATCH_EXACT_SINGLE_DISK_MEMBER_COUNT',
         'invalid_input')


def _bytes(z: zipfile.ZipFile, name: str, sha: str, length: int) -> bytes:
    need(0<length<=first.MAX_SOURCE_BYTES,
         'ARCHIVE_SOURCE_TOO_LARGE','invalid_input')
    with z.open(name,'r') as stream:
        data=stream.read(length+1)
        need(len(data)==length and stream.read(1)==b'' and
             hmac.compare_digest(case.sha(data),sha),
             'ARCHIVED_SOURCE_BYTES_NOT_EXACT_SHA_LENGTH')
        return data


def _nested_zip_originals_from_transport(z: zipfile.ZipFile, doc: dict) -> None:
    """Actually traverse every nested ZIP from archive bytes, with EC335 bounds.

    EC335 source-side lists cannot certify these member contents merely by
    counting JSON rows. The receiver inspect command performs this walk in
    memory, without unpacking even one member to the filesystem.
    """
    objects=[]
    total=[0]

    def walk(owner: str, chain: list[str], raw: bytes, depth: int) -> None:
        need(depth<=closure.MAX_EMBEDDED_DEPTH,
             'NESTED_ARCHIVE_RECURSION_LIMIT','invalid_input')
        try:
            with zipfile.ZipFile(BytesIO(raw)) as inner:
                infos=inner.infolist()
                need(0<len(infos)<=closure.MAX_ZIP_ENTRIES and
                     len({i.filename for i in infos})==len(infos) and
                     inner.comment==b'',
                     'INNER_ZIP_MEMBER_SET_COMMENT_INVALID','invalid_input')
                for meta in infos:
                    name=meta.filename
                    need(type(name) is str and 0<len(name)<=300 and
                         not name.startswith('/') and not name.endswith('/') and
                         '\\' not in name and '\x00' not in name and
                         all(part not in ('','.','..') for part in name.split('/'))
                         and not meta.is_dir() and
                         meta.compress_type==zipfile.ZIP_STORED and
                         meta.file_size==meta.compress_size and
                         0<meta.file_size<=closure.MAX_SOURCE_BYTES and
                         stat.S_IFMT(meta.external_attr>>16) in (0,stat.S_IFREG) and
                         meta.flag_bits==0,
                         'INNER_ZIP_ONLY_CANONICAL_BOUNDED_STORED_REGULAR_ENTRIES',
                         'invalid_input')
                    need(len(objects)<closure.MAX_EMBEDDED and
                         total[0]+meta.file_size<=closure.MAX_EMBEDDED_BYTES,
                         'INNER_ZIP_COUNT_AND_BYTE_BUDGET','invalid_input')
                    entry=inner.read(meta)
                    need(len(entry)==meta.file_size,
                         'INNER_ZIP_ORIGINAL_LENGTH_MISMATCH')
                    total[0]+=len(entry)
                    seq=chain+[name]
                    fmt=closure._format(entry)
                    objects.append({
                        'owner_source_path':owner,'member_chain':seq,
                        'embedded_raw_sha256':case.sha(entry),
                        'byte_length':len(entry),'original_format':fmt,
                    })
                    if fmt=='original_zip':
                        walk(owner,seq,entry,depth+1)
        except (anchor.AnchorError,):
            raise
        except (zipfile.BadZipFile,EOFError,RuntimeError,ValueError,
                OverflowError,KeyError) as exc:
            raise anchor.AnchorError('EC337_INNER_ZIP_CANNOT_BE_READ',
                                     'invalid_input') from exc

    for i,row in enumerate(doc['sources'],1):
        if row['original_format']=='original_zip':
            raw=_bytes(z,_name(i),row['source_original_raw_sha256'],
                       row['byte_length'])
            walk(row['source_path'],[],raw,1)
    objects.sort(key=lambda x:(x['owner_source_path'],tuple(x['member_chain'])))
    need(objects==doc['embedded'] and total[0]==doc['embedded_total_byte_length'],
         'ALL_NESTED_ZIP_MEMBER_BYTES_MUST_MATCH_EC335_OBSERVED_CLOSURE')


def _inspect_open(z: zipfile.ZipFile, pins: dict) -> tuple[dict,dict,dict,dict,tuple[bytes,...]]:
    # Controls are read out of ZIP, but only checked against *separately supplied*
    # expected raw SHA. Verify schema with legacy validators without writing.
    raw_controls = []
    for name,key,limit in zip(CONTROL_NAMES,(
        'expected_first_hop_plan_sha256','expected_closure_sha256',
        'expected_map_sha256'),(first.MAX_PLAN_BYTES,closure.MAX_CLOSURE_BYTES,
        closure.MAX_MAP_BYTES)):
        info=z.getinfo(name)
        need(0 < info.file_size <= limit,
             'CONTROL_SOURCE_EXCEEDS_LEGACY_LIMIT','invalid_input')
        raw_controls.append(_bytes(z,name,pins[key],info.file_size))
    plan_raw,closure_raw,map_raw=raw_controls
    from ec279_finding_query_host import protocol as io
    plan=io.parse(plan_raw,first.MAX_PLAN_BYTES)
    first._validate_plan(plan)
    need(plan_raw==receipt._raw(plan),
         'PLAN_NOT_ORIGINAL_CANONICAL_LF_JSON','invalid_input')
    doc=io.parse(closure_raw,closure.MAX_CLOSURE_BYTES)
    closure._check_closure(doc,plan,pins['expected_first_hop_plan_sha256'])
    need(closure_raw==receipt._raw(doc),
         'CLOSURE_NOT_ORIGINAL_CANONICAL_LF_JSON','invalid_input')
    mapping=io.parse(map_raw,closure.MAX_MAP_BYTES)
    # Equivalent to EC335 _load_map, except the originals are still inside
    # the unsigned ZIP; no archive-produced SHA becomes independent trust.
    need(type(mapping) is dict and set(mapping)==closure.MAP_FIELDS and
         mapping.get('schema')==closure.MAP_SCHEMA and
         mapping.get('closure_original_raw_sha256')==pins['expected_closure_sha256']
         and type(mapping.get('locations')) is list and
         len(mapping['locations'])==doc['source_count'],
         'MAP_SCHEMA_CLOSURE_AND_ENTIRE_SOURCE_COUNT_REQUIRED','invalid_input')
    originals={row['source_path'] for row in doc['sources']}
    destinations=set()
    for row,loc in zip(doc['sources'],mapping['locations']):
        need(type(loc) is dict and set(loc)==closure.LOCATION_FIELDS and
             loc.get('source_path')==row['source_path'] and
             first._path(loc.get('destination_path')) and
             loc['destination_path'] not in destinations and
             loc['destination_path'] not in originals,
             'MAP_NOT_UNIQUE_CANONICAL_AND_NONALIAS','invalid_input')
        destinations.add(loc['destination_path'])
    need(map_raw==receipt._raw(mapping) and
         (plan['handoff_original_raw_sha256'],
          plan['left_manifest_original_raw_sha256'],
          plan['right_manifest_original_raw_sha256']) ==
         (pins['expected_handoff_sha256'],
          pins['left_expected_manifest_sha256'],
          pins['right_expected_manifest_sha256']),
         'MAP_NONCANONICAL_OR_HISTORICAL_ROOT_PIN_MISMATCH','invalid_input')
    sized=dict(pins,_plan_size=len(plan_raw),_closure_size=len(closure_raw),
               _map_size=len(map_raw))
    rebuilt=_manifest(plan,doc,mapping,sized)
    expected_names=[MANIFEST_NAME]+[m['name'] for m in rebuilt['members']]
    expected_lengths=[len(receipt._raw(rebuilt))]+[m['byte_length'] for m in rebuilt['members']]
    _check_zip_members(z,expected_names,expected_lengths)
    manifest=_bytes(z,MANIFEST_NAME,case.sha(receipt._raw(rebuilt)),
                    expected_lengths[0])
    worksheet=_blank_custody_slots()
    need(_bytes(z,CUSTODY_SLOTS_NAME,case.sha(worksheet),len(worksheet))==worksheet,
         'CUSTODY_WORKSHEET_MUST_BE_UNFILLED_UNTRUSTED_PLACEHOLDER')
    need(len(manifest)<=MAX_MANIFEST,'MANIFEST_EXCEEDS_BOUND','invalid_input')
    candidate=io.parse(manifest,MAX_MANIFEST)
    _check_manifest(candidate,rebuilt)
    # Actual raw SHA for every source, not only ZIP CRC or embedded declaration.
    for i,row in enumerate(doc['sources'],1):
        _bytes(z,_name(i),row['source_original_raw_sha256'],row['byte_length'])
    _nested_zip_originals_from_transport(z,doc)
    return plan,doc,mapping,rebuilt,tuple(raw_controls)


def _pins(**values) -> dict:
    return values


def _result(command: str, pins: dict, doc: dict, bundle_sha: str, *,
            installed: bool = False) -> dict:
    return {
        'schema':RESULT_SCHEMA,'command':command,'exit_code':2,
        'status':('receiver_originals_and_controls_installed_and_ec335_rechecked_unresolved'
                  if installed else 'all_transport_members_match_separate_pins_unresolved'),
        'bundle_original_raw_sha256':bundle_sha,
        'plan_original_raw_sha256':pins['expected_first_hop_plan_sha256'],
        'closure_original_raw_sha256':pins['expected_closure_sha256'],
        'map_original_raw_sha256':pins['expected_map_sha256'],
        'handoff_original_raw_sha256':pins['expected_handoff_sha256'],
        'left_manifest_original_raw_sha256':pins['left_expected_manifest_sha256'],
        'right_manifest_original_raw_sha256':pins['right_expected_manifest_sha256'],
        'persistent_original_source_count':doc['source_count'],
        'transported_original_byte_length':doc['total_source_byte_length'],
        'nested_zip_member_identity_declared_count':doc['embedded_original_member_count'],
        'nested_zip_member_identity_verified_count':doc['embedded_original_member_count'],
        'all_archive_members_whole_sha_verified':True,
        'blank_external_custody_worksheet_byte_verified':True,
        'receiver_installed_sources_and_controls_byte_rechecked':installed,
        'full_ec336_signed_history_receiver_replay_must_be_run_separately':True,
        'caller_supplied_sha_is_not_independently_custodied_by_implementation':True,
        'offline_unresolved_exit_code':2,
        **{name:False for name in FALSE_FIELDS},
    }


def create_bundle(*, out: str, first_hop_plan_file: str,
                  expected_first_hop_plan_sha256: str,
                  closure_file: str, expected_closure_sha256: str,
                  map_file: str, expected_map_sha256: str,
                  expected_handoff_sha256: str,
                  left_expected_manifest_sha256: str,
                  right_expected_manifest_sha256: str) -> dict:
    pins=locals().copy()
    plan,doc,mapping,raw_controls=_control_state(**{
        key:value for key,value in pins.items() if key!='out'})
    sized=dict(pins,_plan_size=len(raw_controls[0]),
               _closure_size=len(raw_controls[1]),_map_size=len(raw_controls[2]))
    manifest=_manifest(plan,doc,mapping,sized)
    raw_manifest=receipt._raw(manifest)
    need(len(raw_manifest)<=MAX_MANIFEST,
         'SIGNED_SOURCE_COUNT_MANIFEST_EXCEEDS_BUDGET','invalid_input')
    forbidden={first_hop_plan_file,closure_file,map_file,
               *[row['source_path'] for row in doc['sources']],
               *[row['destination_path'] for row in mapping['locations']]}
    fd,identity=_private_output(out,forbidden)
    try:
        with os.fdopen(fd,'w+b',closefd=True) as stream:
            with zipfile.ZipFile(stream,'w',allowZip64=False) as z:
                z.writestr(_zip_info(MANIFEST_NAME),raw_manifest)
                z.writestr(_zip_info(CUSTODY_SLOTS_NAME),_blank_custody_slots())
                for name,raw in zip(CONTROL_NAMES,raw_controls):
                    z.writestr(_zip_info(name),raw)
                for i,row in enumerate(doc['sources'],1):
                    raw=first._pin(row['source_path'],
                                  row['source_original_raw_sha256'],
                                  row['byte_length'],'EC337_SOURCE_WHOLE_BYTES')
                    z.writestr(_zip_info(_name(i)),raw)
            stream.flush();os.fsync(stream.fileno())
        _fsync_dir(str(Path(out).parent))
        bundle_sha=_sha_path(out)
        inspect_bundle(bundle_file=out,expected_bundle_sha256=bundle_sha,
                       **{key:value for key,value in pins.items() if key not in (
                           'out','first_hop_plan_file','closure_file','map_file')})
        # The locally calculated bundle SHA remains only a custody handoff
        # candidate, never an attestation that a separate witness accepted it.
        for path,digest,limit in zip((first_hop_plan_file,closure_file,map_file),(
            expected_first_hop_plan_sha256,expected_closure_sha256,
            expected_map_sha256),(first.MAX_PLAN_BYTES,closure.MAX_CLOSURE_BYTES,
            closure.MAX_MAP_BYTES)):
            first._pin(path,digest,None,'EC337_FINAL_CONTROL_REPIN')
        for row in doc['sources']:
            first._pin(row['source_path'],row['source_original_raw_sha256'],
                       row['byte_length'],'EC337_FINAL_SOURCE_REPIN')
        need(_sha_path(out)==bundle_sha,
             'CREATED_BUNDLE_CHANGED_DURING_FINAL_SOURCE_RECHECK')
        return _result('create-bundle',pins,doc,bundle_sha)
    except Exception:
        _cleanup_owned(out,identity)
        raise


def _sha_path(path: str) -> str:
    private._private_parent(path)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and
             stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and
             0<before.st_size<=MAX_ARCHIVE,
             'WHOLE_ARCHIVE_PRIVATE_OWNER_AND_MAX_BYTES_REQUIRED')
        h=hashlib.sha256()
        while True:
            b=os.read(fd,CHUNK)
            if not b:break
            h.update(b)
        after=os.fstat(fd)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,
              before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,
              after.st_ctime_ns),
             'WHOLE_ARCHIVE_CHANGED_DURING_HASH','unavailable')
        return h.hexdigest()
    finally:os.close(fd)


def inspect_bundle(*, bundle_file: str, expected_bundle_sha256: str,
                   expected_first_hop_plan_sha256: str,
                   expected_closure_sha256: str,
                   expected_map_sha256: str,
                   expected_handoff_sha256: str,
                   left_expected_manifest_sha256: str,
                   right_expected_manifest_sha256: str) -> dict:
    pins=locals().copy()
    for key in ('expected_first_hop_plan_sha256','expected_closure_sha256',
                'expected_map_sha256',*ROOT_KEYS):
        _pin_sha(pins[key],key)
    with _archive(bundle_file,expected_bundle_sha256) as (z,fd):
        _,doc,_,_,_=_inspect_open(z,pins)
    return _result('inspect-bundle',pins,doc,expected_bundle_sha256)


def _verify_directory(path: str) -> None:
    need(first._valid_root(path),'CANONICAL_EXPLICIT_PRIVATE_DIRECTORY_REQUIRED',
         'invalid_input')
    private._private_parent(path+'/__ec337_sentinel__')
    s=os.lstat(path)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
         (stat.S_IMODE(s.st_mode)&0o077)==0,
         'DESTINATION_ROOT_MUST_EXIST_OWNER_PRIVATE_0700')


def _open_under(root: str, relative: str, created_dirs: list[tuple[str,int,int]]) -> tuple[int,str]:
    """Walk only root-relative components using O_NOFOLLOW dirfds."""
    parts=relative.split('/')
    need(parts and all(p not in ('','.','..') and '/' not in p and '\\' not in p
                       for p in parts),
         'RELATIVE_DESTINATION_COMPONENTS_INVALID','invalid_input')
    fd=os.open(root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|
               getattr(os,'O_NOFOLLOW',0))
    current=root
    try:
        root_info=os.fstat(fd)
        need(stat.S_ISDIR(root_info.st_mode) and
             root_info.st_uid==os.geteuid() and
             (stat.S_IMODE(root_info.st_mode)&0o077)==0,
             'ROOT_INODE_MUST_REMAIN_OWNER_PRIVATE')
        for part in parts[:-1]:
            next_path=current+'/'+part
            try:
                os.mkdir(part,mode=0o700,dir_fd=fd)
                made=os.stat(part,dir_fd=fd,follow_symlinks=False)
                created_dirs.append((next_path,made.st_dev,made.st_ino))
            except FileExistsError:
                pass
            nf=os.open(part,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|
                       getattr(os,'O_NOFOLLOW',0),dir_fd=fd)
            s=os.fstat(nf)
            need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
                 (stat.S_IMODE(s.st_mode)&0o077)==0,
                 'DESTINATION_ANCESTOR_NOT_PRIVATE_0700')
            os.close(fd);fd=nf;current=next_path
        return fd,parts[-1]
    except Exception:
        os.close(fd)
        raise


def _exclusive_bytes(root: str, relative: str, raw: bytes,
                     created_files: list[tuple[str,int,int]],
                     created_dirs: list[tuple[str,int,int]]) -> None:
    fd,leaf=_open_under(root,relative,created_dirs)
    try:
        try:
            f=os.open(leaf,os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                      getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=fd)
        except FileExistsError as exc:
            raise anchor.AnchorError('EC337_RECEIVER_REFUSES_OVERWRITE',
                                     'invalid_input') from exc
        inode=os.fstat(f)
        full=root+'/'+relative
        created_files.append((full,inode.st_dev,inode.st_ino))
        try:
            os.fchmod(f,0o600)
            with os.fdopen(f,'wb',closefd=True) as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(fd)
        except Exception:
            try:os.close(f)
            except OSError:pass
            raise
    finally:os.close(fd)


def _rollback_files(created: list[tuple[str,int,int]],
                    dirs: list[tuple[str,int,int]]) -> None:
    for path,dev,ino in reversed(created):
        try:
            now=os.lstat(path)
            if (stat.S_ISREG(now.st_mode) and now.st_dev==dev and now.st_ino==ino):
                os.unlink(path)
        except OSError:
            pass
    for path,dev,ino in reversed(dirs):
        try:
            now=os.lstat(path)
            if (stat.S_ISDIR(now.st_mode) and now.st_dev==dev and now.st_ino==ino):
                os.rmdir(path)  # Only if still empty.
        except OSError:
            pass


def install_bundle(*, bundle_file: str, expected_bundle_sha256: str,
                   expected_first_hop_plan_sha256: str,
                   expected_closure_sha256: str,
                   expected_map_sha256: str,
                   expected_handoff_sha256: str,
                   left_expected_manifest_sha256: str,
                   right_expected_manifest_sha256: str,
                   control_root: str, destination_root: str) -> dict:
    """Explicit receiver-only install: no overwrite, control and source repins.

    Both roots must already exist and be private. This is not a global atomic
    transaction. On failure, best-effort rollback only of inodes we created;
    no pre-existing file is deleted or replaced. Call EC336 separately.
    """
    pins=locals().copy()
    for key in ('expected_first_hop_plan_sha256','expected_closure_sha256',
                'expected_map_sha256',*ROOT_KEYS):
        _pin_sha(pins[key],key)
    _verify_directory(control_root);_verify_directory(destination_root)
    need(control_root!=destination_root and
         not control_root.startswith(destination_root+'/') and
         not destination_root.startswith(control_root+'/'),
         'CONTROL_AND_ORIGINAL_DESTINATION_ROOTS_MUST_NOT_OVERLAP','invalid_input')
    control_paths=[control_root+'/'+n for n in LOCAL_CONTROL_FILES]
    need(bundle_file not in control_paths and
         not bundle_file.startswith(destination_root+'/') and
         not bundle_file.startswith(control_root+'/'),
         'INPUT_BUNDLE_CANNOT_BE_RECEIVER_OUTPUT','invalid_input')
    created=[]
    dirs=[]
    try:
        with _archive(bundle_file,expected_bundle_sha256) as (z,fd):
            plan,doc,mapping,rebuilt,raw_controls=_inspect_open(z,pins)
            destinations=[loc['destination_path'] for loc in mapping['locations']]
            need(all(dest.startswith(destination_root+'/') for dest in destinations) and
                 not any(dest.startswith(control_root+'/') for dest in destinations) and
                 all(dest not in control_paths for dest in destinations),
                 'MAP_DESTINATIONS_MUST_BE_STRICTLY_INSIDE_EXPLICIT_RECEIVER_ROOT',
                 'invalid_input')
            need(all(not os.path.lexists(path) for path in control_paths+destinations),
                 'INSTALL_MUST_NOT_OVERWRITE_ANY_EXISTING_CONTROL_OR_ORIGINAL',
                 'invalid_input')
            for n,raw in zip(LOCAL_CONTROL_FILES,raw_controls):
                _exclusive_bytes(control_root,n,raw,created,dirs)
            for i,(row,dest) in enumerate(zip(doc['sources'],destinations),1):
                data=_bytes(z,_name(i),row['source_original_raw_sha256'],
                            row['byte_length'])
                rel=dest[len(destination_root)+1:]
                _exclusive_bytes(destination_root,rel,data,created,dirs)
            verified=closure.verify_copies(
                first_hop_plan_file=control_paths[0],
                expected_first_hop_plan_sha256=expected_first_hop_plan_sha256,
                closure_file=control_paths[1],
                expected_closure_sha256=expected_closure_sha256,
                map_file=control_paths[2],
                expected_map_sha256=expected_map_sha256)
            need(verified['exit_code']==2 and
                 verified['destination_all_observed_copy_bytes_verified'] is True and
                 verified['embedded_original_member_count']==
                      doc['embedded_original_member_count'],
                 'EC335_REAL_RECEIVER_NESTED_COPY_RECHECK_REQUIRED')
            # Additional whole archive rehash is done by the context manager,
            # before the public call may return an installed result.
        # Re-read each installed control+destination once more after ZIP close.
        for path,digest in zip(control_paths,(
            expected_first_hop_plan_sha256,expected_closure_sha256,
            expected_map_sha256)):
            first._pin(path,digest,None,'EC337_LATE_INSTALLED_CONTROL')
        for row,loc in zip(doc['sources'],mapping['locations']):
            first._pin(loc['destination_path'],row['source_original_raw_sha256'],
                       row['byte_length'],'EC337_LATE_INSTALLED_ORIGINAL')
        need(_sha_path(bundle_file)==expected_bundle_sha256,
             'INSTALL_BUNDLE_CHANGED_DURING_POST_WRITE_VERIFICATION')
        return _result('install-bundle',pins,doc,expected_bundle_sha256,installed=True)
    except Exception:
        _rollback_files(created,dirs)
        raise

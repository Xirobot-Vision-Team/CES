#!/usr/bin/env python3
"""EC323: portable two-original fork case capsule, NOT a new attestation.

The capsule carries the exact EC321 ZIP and original EC322 seventh-party ACK,
not a new signature or a substitute for any of their externally fixed trust
pins. Both on export and after import it invokes the production EC322 verifier,
which replays the EC321 -> EC320 -> EC319 -> EC318 -> EC294 signed originals.
An authentic registrar fork is still a fork (exit 2), never a CAS winner.
"""
from __future__ import annotations

import hmac
from io import BytesIO
import os
from pathlib import Path
import stat
import tempfile
from typing import Any
import zipfile

from finding_query_host import protocol as io
from delivery_anchor import anchor
from portable_bundle import bundle
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from receiver_fork_ack import ack

SCHEMA = 'ces.ec323.portable_sealed_original_case_and_seventh_ack.v1'
RESULT_SCHEMA = 'ces.ec323.portable_original_case_ack_capsule_result.v1'
DENIAL_SCHEMA = 'ces.ec323.portable_original_case_ack_capsule_denial.v1'
MANIFEST_FILE = 'capsule-manifest.json'
CASE_MEMBER = 'original-case.zip'
ACK_MEMBER = 'original-seventh-ack.json'
MEMBERS = (MANIFEST_FILE, CASE_MEMBER, ACK_MEMBER)
MAX_MANIFEST = 16_000
# ZIP_STORED only; limit includes three LF/ZIP entries and ZIP directory.
MAX_ARCHIVE = case.MAX_ARCHIVE + ack.MAX_RECEIPT + MAX_MANIFEST + 8_192
MANIFEST_FIELDS = frozenset({
    'schema', 'ec321_case_original_raw_sha256',
    'ec322_ack_original_raw_sha256', 'ec321_external_pins',
    'seventh_receiver_external_trust', 'original_members',
    'global_latest_fork_winner_or_external_cas_proven',
})
MEMBER_FIELDS = frozenset({'name','raw_size','raw_sha256'})


def need(ok: Any, code: str, status: str = 'permission_denied') -> None:
    if ok is not True:
        raise anchor.AnchorError('EC323_' + code, status)


def _trust(*, ack_id: str, seventh_receiver_id: str,
           seventh_receiver_public_hex: str,
           seventh_receiver_challenge_sha256: str,
           external_pins: dict) -> tuple[dict,dict]:
    # Every value comes from independently selected operator input, NEVER
    # recovered as a trusted value from the unsigned capsule manifest.
    receiver = ack._receiver(ack_id=ack_id,
        seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256)
    pins = case._pins(**external_pins)
    return receiver, pins


def _file(path: str, size: int, expected_sha: str, label: str) -> bytes:
    need(case.original._valid_path(path) and reg.custody._sha(expected_sha),
         label + '_NORMALIZED_PRIVATE_PATH_AND_INDEPENDENT_SHA_REQUIRED',
         'invalid_input')
    raw = reg._private_read(path, size, label)
    need(hmac.compare_digest(case.sha(raw), expected_sha),
         label + '_ORIGINAL_WHOLE_SHA_MISMATCH')
    return raw


def _manifest(pins: dict, receiver: dict, case_sha: str, ack_sha: str,
              case_size: int, ack_size: int) -> dict:
    need(reg.custody._sha(case_sha) and reg.custody._sha(ack_sha) and
         case_sha != ack_sha and
         type(case_size) is int and 0 < case_size <= case.MAX_ARCHIVE and
         type(ack_size) is int and 0 < ack_size <= ack.MAX_RECEIPT,
         'TWO_DISTINCT_BOUNDED_ORIGINALS_AND_EXTERNAL_SHA_REQUIRED',
         'invalid_input')
    doc = {
        'schema': SCHEMA,
        'ec321_case_original_raw_sha256':case_sha,
        'ec322_ack_original_raw_sha256':ack_sha,
        'ec321_external_pins':dict(pins),
        'seventh_receiver_external_trust':dict(receiver),
        'original_members':[
            {'name':CASE_MEMBER, 'raw_sha256':case_sha,'raw_size':case_size},
            {'name':ACK_MEMBER, 'raw_sha256':ack_sha,'raw_size':ack_size},
        ],
        'global_latest_fork_winner_or_external_cas_proven':False,
    }
    need(len(reg.raw_doc(doc)) <= MAX_MANIFEST,
         'MANIFEST_OUTSIDE_EXACT_BYTE_BUDGET','invalid_input')
    return doc


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name,(1980,1,1,0,0,0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _serialize(manifest_raw: bytes, original_case: bytes,
               original_ack: bytes) -> bytes:
    # Fixed order, fixed names, exact historical bytes, no compression,
    # timestamps, symlinks, comments, custom fields, or hidden extra files.
    output = BytesIO()
    with zipfile.ZipFile(output,'w',allowZip64=False) as archive:
        for name, raw in zip(MEMBERS,(manifest_raw,original_case,original_ack)):
            archive.writestr(_zip_info(name),raw)
    result = output.getvalue()
    need(len(result) <= MAX_ARCHIVE,
         'CAPSULE_EXCEEDS_WHOLE_ARCHIVE_BUDGET','invalid_input')
    return result


def _validated_originals(raw: bytes, pins: dict, receiver: dict,
                         original_case_sha: str, original_ack_sha: str
                         ) -> tuple[bytes,bytes]:
    need(0 < len(raw) <= MAX_ARCHIVE,
         'CAPSULE_SIZE_OUTSIDE_FIXED_BOUND','invalid_input')
    try:
        with zipfile.ZipFile(BytesIO(raw),'r',allowZip64=False) as archive:
            entries = archive.infolist()
            need(len(entries)==3 and tuple(e.filename for e in entries)==MEMBERS
                 and archive.comment==b'',
                 'CAPSULE_EXACT_THREE_ORDERED_FIXED_MEMBERS_REQUIRED',
                 'invalid_input')
            for entry, limit in zip(entries,
                    (MAX_MANIFEST,case.MAX_ARCHIVE,ack.MAX_RECEIPT)):
                need(entry.compress_type==zipfile.ZIP_STORED and
                     entry.flag_bits==0 and entry.extra==b'' and
                     entry.comment==b'' and entry.create_system==3 and
                     entry.date_time==(1980,1,1,0,0,0) and
                     (entry.external_attr >> 16)==(stat.S_IFREG|0o600) and
                     not entry.is_dir() and entry.file_size==entry.compress_size and
                     0 < entry.file_size <= limit,
                     'UNSAFE_NONCANONICAL_COMPRESSED_OR_OVERSIZE_MEMBER',
                     'invalid_input')
            manifest_raw, case_raw, ack_raw = tuple(archive.read(e) for e in entries)
    except (anchor.AnchorError, io.HostError):
        raise
    except (zipfile.BadZipFile, KeyError, ValueError, RuntimeError,
            EOFError, OverflowError, NotImplementedError, OSError) as exc:
        raise anchor.AnchorError('EC323_CAPSULE_ZIP_INVALID_OR_UNSUPPORTED',
                                 'invalid_input') from exc
    manifest = io.parse(manifest_raw, MAX_MANIFEST)
    need(hmac.compare_digest(manifest_raw,reg.raw_doc(manifest)),
         'CAPSULE_MANIFEST_MUST_BE_CANONICAL_LF_JSON','invalid_input')
    anchor.exact(manifest,MANIFEST_FIELDS,'EC323_MANIFEST_EXACT_FIELDS')
    need(type(manifest['original_members']) is list and
         len(manifest['original_members']) == 2,
         'CAPSULE_ORIGINAL_MEMBERS_EXACT_TWO','invalid_input')
    for entry in manifest['original_members']:
        anchor.exact(entry,MEMBER_FIELDS,'EC323_MEMBER_RECORD_EXACT_FIELDS')
    anchor.exact(manifest['ec321_external_pins'],case.PIN_FIELDS,
                 'EC323_HISTORICAL_EXTERNAL_PIN_FIELDS')
    anchor.exact(manifest['seventh_receiver_external_trust'],ack.RECEIVER_FIELDS,
                 'EC323_SEVENTH_EXTERNAL_TRUST_FIELDS')
    expected = _manifest(pins,receiver,original_case_sha,original_ack_sha,
                         len(case_raw),len(ack_raw))
    need(manifest == expected,
         'CAPSULE_MANIFEST_NOT_EQUAL_ALL_OUTSIDE_TRUST_AND_ORIGINAL_BYTES',
         'invalid_input')
    need(hmac.compare_digest(case.sha(case_raw),original_case_sha) and
         hmac.compare_digest(case.sha(ack_raw),original_ack_sha),
         'CAPSULE_MEMBER_ORIGINAL_BYTES_NOT_EQUAL_EXTERNAL_RAW_SHA')
    # Reject trailing payloads, extra ZIP structures, data descriptors and
    # noncanonical bytes even if the CRC and external whole SHA were re-pinned.
    need(hmac.compare_digest(raw,_serialize(manifest_raw,case_raw,ack_raw)),
         'CAPSULE_NOT_EXACT_DETERMINISTIC_ZIP_BYTES','invalid_input')
    return case_raw,ack_raw


def _replay(*, bundle_file: str, ack_file: str,
            case_sha: str, ack_sha: str, receiver: dict, pins: dict) -> dict:
    verified = ack.verify(bundle_file=bundle_file,
        expected_bundle_sha256=case_sha,ack_file=ack_file,
        expected_ack_sha256=ack_sha,**receiver,**pins)
    need(verified.get('exit_code')==2 and
         verified.get('status')==
            'independent_seventh_signature_and_entire_original_fork_case_reverified' and
         verified.get('signed_receiver_ack_original_raw_sha256')==ack_sha and
         verified.get('case_bundle_original_raw_sha256')==case_sha and
         verified.get('seventh_receiver_ed25519_signature_verified') is True and
         verified.get('ec321_case_and_complete_ec320_to_ec294_original_forks_reverified') is True and
         verified.get('all_visible_original_roles_and_challenges_distinct_from_seventh') is True and
         verified.get('external_cas_latest_or_fork_winner_proven') is False and
         verified.get('receiver_physical_or_organizational_authority_proven') is False and
         verified.get('business_or_external_store_writes_performed') is False,
         'PREEXISTING_SEVENTH_SIGNED_ACK_AND_ALL_OLDER_ORIGINALS_MUST_REPLAY')
    return verified


def _exclusive_write(out: str, raw: bytes) -> None:
    target = bundle._private_parent(out)
    need(not os.path.lexists(target),
         'OUTPUT_EXISTS_OR_COULD_OVERWRITE_EXISTING_FILE','invalid_input')
    fd = -1
    created = False
    complete = False
    try:
        fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                     getattr(os,'O_NOFOLLOW',0),0o600)
        created = True
        with os.fdopen(fd,'wb') as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        dirfd = os.open(target.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        complete = True
    except FileExistsError as exc:
        raise anchor.AnchorError('EC323_OUTPUT_EXISTS_NO_OVERWRITE',
                                 'invalid_input') from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if created and not complete:
            try: os.unlink(target)
            except FileNotFoundError: pass


def _result(receiver: dict,pins: dict,original_case_sha: str,
            original_ack_sha: str,capsule_sha: str,observed: dict,
            status: str) -> dict:
    return {
        'status':status, 'exit_code':2,
        'capsule_original_raw_sha256':capsule_sha,
        'case_bundle_original_raw_sha256':original_case_sha,
        'signed_receiver_ack_original_raw_sha256':original_ack_sha,
        'case_id':pins['case_id'], 'ack_id':receiver['ack_id'],
        'seventh_receiver_id':receiver['seventh_receiver_id'],
        'seventh_receiver_public_hex':receiver['seventh_receiver_public_hex'],
        'original_sixth_witness_raw_sha256':pins['expected_witness_sha256'],
        'fork_sequence':observed['fork_sequence'],
        'both_original_member_raw_sha256_preserved':True,
        'seventh_ed25519_and_entire_original_signed_history_reverified':True,
        'portable_capsule_itself_is_a_new_signature':False,
        'external_latest_winner_cas_or_organizational_authority_proven':False,
        'business_or_external_store_writes_performed':False,
    }


def seal(*, out: str, bundle_file: str, expected_bundle_sha256: str,
         ack_file: str, expected_ack_sha256: str,
         ack_id: str, seventh_receiver_id: str,
         seventh_receiver_public_hex: str,
         seventh_receiver_challenge_sha256: str,
         **external_pins: str) -> dict:
    """Verify both authentic originals, then seal them byte-for-byte once."""
    receiver,pins = _trust(ack_id=ack_id,
        seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256,
        external_pins=external_pins)
    need(all(case.original._valid_path(path) for path in
             (out,bundle_file,ack_file)) and
         len({out,bundle_file,ack_file})==3,
         'THREE_DISTINCT_NORMALIZED_ABSOLUTE_FILE_PATHS_REQUIRED',
         'invalid_input')
    bundle._private_parent(out)
    need(not os.path.lexists(out),
         'OUTPUT_EXISTS_OR_COULD_OVERWRITE_EXISTING_FILE','invalid_input')
    case_raw = _file(bundle_file,case.MAX_ARCHIVE,expected_bundle_sha256,
                     'ORIGINAL_EC321_CASE')
    ack_raw = _file(ack_file,ack.MAX_RECEIPT,expected_ack_sha256,
                    'ORIGINAL_EC322_ACK')
    observed = _replay(bundle_file=bundle_file,ack_file=ack_file,
        case_sha=expected_bundle_sha256,ack_sha=expected_ack_sha256,
        receiver=receiver,pins=pins)
    # The original files are read again under their full independent pins;
    # if a concurrent replacement happened during the costly full replay,
    # only these same fully verified original bytes may be sealed.
    need(hmac.compare_digest(case_raw,_file(bundle_file,case.MAX_ARCHIVE,
            expected_bundle_sha256,'RECHECKED_EC321_CASE')) and
         hmac.compare_digest(ack_raw,_file(ack_file,ack.MAX_RECEIPT,
            expected_ack_sha256,'RECHECKED_EC322_ACK')),
         'SOURCE_ORIGINAL_BYTES_CHANGED_DURING_SIGNED_REPLAY','unavailable')
    manifest = _manifest(pins,receiver,expected_bundle_sha256,
                         expected_ack_sha256,len(case_raw),len(ack_raw))
    archive = _serialize(reg.raw_doc(manifest),case_raw,ack_raw)
    _exclusive_write(out,archive)
    return _result(receiver,pins,expected_bundle_sha256,expected_ack_sha256,
        case.sha(archive),observed,
        'authentic_original_case_and_seventh_ack_sealed_without_resigning')


def verify(*, capsule_file: str, expected_capsule_sha256: str,
           expected_bundle_sha256: str, expected_ack_sha256: str,
           ack_id: str, seventh_receiver_id: str,
           seventh_receiver_public_hex: str,
           seventh_receiver_challenge_sha256: str,
           **external_pins: str) -> dict:
    """Recreate two private local originals, then replay true EC322->EC294."""
    receiver,pins = _trust(ack_id=ack_id,
        seventh_receiver_id=seventh_receiver_id,
        seventh_receiver_public_hex=seventh_receiver_public_hex,
        seventh_receiver_challenge_sha256=seventh_receiver_challenge_sha256,
        external_pins=external_pins)
    raw = _file(capsule_file,MAX_ARCHIVE,expected_capsule_sha256,
                'EXTERNALLY_PINNED_WHOLE_EC323_CAPSULE')
    case_raw,ack_raw = _validated_originals(raw,pins,receiver,
        expected_bundle_sha256,expected_ack_sha256)
    # No source paths, signing key, network, original receipt maps, or
    # application writes. The only extraction paths are our fixed filenames
    # inside a fresh owner-private auto-deleted temporary directory.
    with tempfile.TemporaryDirectory(prefix='ces-ec323-import-') as tmp:
        local_case = case._temp_file(Path(tmp)/CASE_MEMBER,case_raw)
        local_ack = case._temp_file(Path(tmp)/ACK_MEMBER,ack_raw)
        # EC336: the only read exemptions are two verified, privately
        # materialized files from this exact pinned capsule.
        with io._scoped_verified_local_import_reads(frozenset((local_case,local_ack))):
            observed = _replay(bundle_file=local_case,ack_file=local_ack,
                case_sha=expected_bundle_sha256,ack_sha=expected_ack_sha256,
                receiver=receiver,pins=pins)
    return _result(receiver,pins,expected_bundle_sha256,expected_ack_sha256,
        expected_capsule_sha256,observed,
        'independent_portable_original_case_seventh_ack_and_all_histories_reverified')

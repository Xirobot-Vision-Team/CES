#!/usr/bin/env python3
"""EC303: path-independent receiver-signed acknowledgement of an EC302 import.

Issuance requires: independently pinned portable ZIP, all original EC301..294
signatures reverified, exact owner-private imported bytes rechecked, a fresh
caller-supplied transfer challenge, and a NEW Ed25519 receiver signing key.

The result is a cryptographically checkable claim by that key, not proof that
there were separate machines/people, that an external challenge was fresh, or
that either institution maintains an immutable latest-ack registry. Neither
this module nor its CLI transports data or performs any original business IO.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec297_anchor_lineage import lineage as l
from ec302_portable_bundle import bundle as b

DOMAIN = b'CES/EC303/DeliveryAudit/OfflineVerifiedBundleReceipt/v1\0'
CLAIM_SCHEMA = 'ces.ec303.verified_private_import_receipt_claim.v1'
ACK_SCHEMA = 'ces.ec303.receiver_signed_offline_bundle_acknowledgement.v1'
RESULT_SCHEMA = 'ces.ec303.offline_bundle_acknowledgement_result.v1'
DENIAL_SCHEMA = 'ces.ec303.offline_bundle_acknowledgement_denial.v1'
MAX_ACK_BYTES = 8192
ID = re.compile(r'[a-z][a-z0-9_-]{1,31}\Z')
CLAIM_FIELDS = frozenset({
    'schema', 'sender_id', 'receiver_id', 'receiver_public_hex',
    'external_exchange_challenge_sha256', 'bundle_sha256',
    'bundle_manifest_sha256', 'original_ec301_report_sha256',
    'original_evidence_document_count', 'independently_pinned_original_chain',
    'original_chain_status', 'private_import_byte_identity_reverified',
})
ACK_FIELDS = frozenset({'schema','claim','receiver_signature_ed25519'})


def require(condition: Any, reason: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC303_'+reason, status)


def _context(pins: dict, expected_bundle_sha256: str, *, sender_id: str,
             receiver_id: str, receiver_public_hex: str,
             challenge_sha256: str) -> dict:
    pins = b._pins(pins)
    require(type(expected_bundle_sha256) is str and
            b.HEX64.fullmatch(expected_bundle_sha256) is not None and
            expected_bundle_sha256 != a.GENESIS,
            'INDEPENDENT_RAW_BUNDLE_SHA_REQUIRED')
    require(type(sender_id) is str and ID.fullmatch(sender_id) is not None and
            type(receiver_id) is str and ID.fullmatch(receiver_id) is not None and
            sender_id != receiver_id,
            'DISTINCT_EXTERNAL_SENDER_AND_RECEIVER_IDENTITIES_REQUIRED')
    require(type(receiver_public_hex) is str and a.valid_pub(receiver_public_hex) and
            receiver_public_hex not in (pins['a_public_hex'],pins['b_public_hex']),
            'SEPARATE_INDEPENDENT_RECEIVER_ED25519_PUBLIC_KEY_REQUIRED')
    require(l.sha_pin(challenge_sha256),
            'INDEPENDENT_NONZERO_EXCHANGE_CHALLENGE_SHA_REQUIRED')
    return pins


def _claim(pins: dict, proof: dict, *, expected_bundle_sha256: str,
           sender_id: str, receiver_id: str, receiver_public_hex: str,
           challenge_sha256: str) -> dict:
    require(proof['exit_code'] == 0 and
            proof['status'] == 'all_supplied_offline_handoffs_cryptographically_consistent',
            'ORIGINAL_SIGNED_HISTORY_CONFLICT_OR_INCONCLUSIVE_NO_POSITIVE_ACK')
    return {
        'schema':CLAIM_SCHEMA, 'sender_id':sender_id, 'receiver_id':receiver_id,
        'receiver_public_hex':receiver_public_hex,
        'external_exchange_challenge_sha256':challenge_sha256,
        'bundle_sha256':expected_bundle_sha256,
        'bundle_manifest_sha256':proof['manifest_sha256'],
        'original_ec301_report_sha256':proof['report_sha256'],
        'original_evidence_document_count':proof['evidence_document_count'],
        'independently_pinned_original_chain':dict(pins),
        'original_chain_status':proof['status'],
        # This is an explicit signed *receiver assertion*, not a cryptographic
        # proof of the actual receiver's identity or future storage retention.
        'private_import_byte_identity_reverified':True,
    }


def _private_import_dir(path: str) -> Path:
    require(type(path) is str and l.absolute_file(path) and
            0 < len(path) <= 3500 and os.path.normpath(path) == path and
            not path.startswith('//'),
            'NORMALIZED_ABSOLUTE_IMPORTED_DIRECTORY_REQUIRED')
    root = b._private_parent(path)  # owner-only parent + no symlink ancestry
    for directory in (root,root/'docs'):
        try:
            info = os.lstat(directory)
        except OSError as exc:
            raise a.AnchorError('EC303_IMPORTED_DIRECTORY_UNAVAILABLE','unavailable') from exc
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700 and info.st_nlink >= 2,
                'IMPORTED_DIRECTORY_OWNER_AND_0700_REQUIRED')
    return root


def _content_names(directory: Path) -> set[str]:
    try:
        with os.scandir(directory) as items:
            names = {entry.name for entry in items}
    except OSError as exc:
        raise a.AnchorError('EC303_IMPORTED_DIRECTORY_LIST_UNAVAILABLE','unavailable') from exc
    return names


def _private_exact_file(path: Path, expected: bytes, limit: int) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise a.AnchorError('EC303_IMPORTED_DOCUMENT_UNAVAILABLE','unavailable') from exc
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'IMPORTED_DOCUMENT_MUST_BE_EXCLUSIVE_OWNER_0600_REGULAR')
    actual = io._open_regular(str(path),limit,private=True)
    require(hmac.compare_digest(actual,expected),
            'IMPORTED_MATERIAL_DIFFERS_FROM_EXACT_PINNED_ZIP_BYTES')


def _rebound_bytes(root: Path, schema: str, doc: dict | bytes,
                   nodes: dict[str, tuple[str,dict|bytes]]) -> bytes:
    if type(doc) is bytes:
        return doc
    copied = json.loads(b.canonical(doc))
    for container, key, child_schema in b._slots(copied):
        ref = container[key]
        require(type(ref) is str and ref.startswith(b.REF_PREFIX) and
                b.DOC_ID.fullmatch(ref[len(b.REF_PREFIX):]) is not None and
                ref[len(b.REF_PREFIX):] in nodes and
                nodes[ref[len(b.REF_PREFIX):]][0] == child_schema,
                'IMPORTED_REFERENCE_NOT_EXACT_ALLOWED_EVIDENCE')
        container[key] = str(root/ref[len(b.REF_PREFIX):])
    raw = b.canonical(copied)
    require(len(raw) <= b.LIMITS[schema],
            'REBOUND_IMPORTED_DOCUMENT_BUDGET_EXCEEDED')
    return raw


def _import_bytes_equal(root: Path, nodes: dict, manifest: dict) -> None:
    """Reject extra evidence and verify exact EC302 materialization bytes.

    Repeated before and after the original full verifier to make accidental
    changes during a local check fail, without claiming OS-level snapshotting
    or resistance to an actively malicious owner process racing this verifier.
    """
    require(_content_names(root) == {'docs',b.MANIFEST_FILE},
            'IMPORTED_ROOT_HAS_EXTRA_OR_MISSING_FILES')
    require(_content_names(root/'docs') ==
            {n.removeprefix('docs/') for n in nodes},
            'IMPORTED_DOCS_HAVE_EXTRA_OR_MISSING_FILES')
    _private_exact_file(root/b.MANIFEST_FILE,
                        b.canonical(manifest),b.MAX_MANIFEST_BYTES)
    for name,(schema,data) in nodes.items():
        expected = _rebound_bytes(root,schema,data,nodes)
        _private_exact_file(root/name,expected,b.LIMITS[schema])


def _verify_import(root: Path, nodes: dict, manifest: dict, pins: dict,
                   full_bundle_proof: dict) -> None:
    _import_bytes_equal(root,nodes,manifest)
    journal = io.read_doc(str(root/b.ROOT_ID),b.LIMITS[b.JOURNAL],private=True)
    report = b.verify_original(journal,pins)
    require(report['exit_code'] == full_bundle_proof['exit_code'] and
            report['status'] == full_bundle_proof['status'] and
            hmac.compare_digest(a.sha(report),full_bundle_proof['report_sha256']),
            'IMPORTED_REAL_ORIGINAL_SIGNATURE_REPORT_MISMATCH')
    _import_bytes_equal(root,nodes,manifest)
    require(report['exit_code'] == 0,
            'IMPORTED_HISTORICAL_CONFLICT_NO_POSITIVE_ACK')


def issue_ack(*, bundle_file: str, expected_bundle_sha256: str,
              pins: dict, imported_dir: str, sender_id: str,
              receiver_id: str, receiver_public_hex: str,
              challenge_sha256: str, receiver_private_key_file: str,
              out: str) -> dict:
    pins = _context(pins,expected_bundle_sha256,sender_id=sender_id,
                    receiver_id=receiver_id,receiver_public_hex=receiver_public_hex,
                    challenge_sha256=challenge_sha256)
    root = _private_import_dir(imported_dir)
    destination = b._private_parent(out)
    require(destination != root and root not in destination.parents and
            not destination.exists() and not destination.is_symlink(),
            'ACK_DESTINATION_MUST_BE_NEW_AND_OUTSIDE_IMPORTED_TREE')
    # Original EC302 verification performs complete source replays inside a
    # separate owner-private snapshot, before touching the receiver signing key.
    proof = b.verify_bundle(bundle_file,expected_bundle_sha256,pins)
    claim = _claim(pins,proof,expected_bundle_sha256=expected_bundle_sha256,
                   sender_id=sender_id,receiver_id=receiver_id,
                   receiver_public_hex=receiver_public_hex,
                   challenge_sha256=challenge_sha256)
    manifest,entries = b._read_zip(bundle_file,expected_bundle_sha256)
    nodes = b._decode(manifest,entries,pins)
    _verify_import(root,nodes,manifest,pins,proof)
    key = io.private_from_file(receiver_private_key_file)
    actual_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    require(hmac.compare_digest(actual_public,receiver_public_hex),
            'RECEIVER_PRIVATE_KEY_NOT_EQUAL_EXTERNAL_PUBLIC_PIN')
    ack = {'schema':ACK_SCHEMA,'claim':claim,
           'receiver_signature_ed25519':key.sign(DOMAIN+a.canonical(claim)).hex()}
    require(len(b.canonical(ack)) <= MAX_ACK_BYTES,'ACK_LENGTH_BUDGET_EXCEEDED')
    # The original store performs owner-private parent checks + O_EXCL, 0600,
    # file fsync and parent fsync; no copy of the receiver key is ever stored.
    store.store(str(destination),ack,MAX_ACK_BYTES)
    return {'status':'signed_receiver_observation_after_exact_private_import',
            'acknowledgement_sha256':b.digest(b.canonical(ack)),
            'bundle_sha256':expected_bundle_sha256,
            'report_sha256':proof['report_sha256'],
            'evidence_document_count':proof['evidence_document_count'],
            'exit_code':0}


def verify_ack(*, bundle_file: str, expected_bundle_sha256: str, pins: dict,
               acknowledgement_file: str, expected_acknowledgement_sha256: str,
               sender_id: str, receiver_id: str, receiver_public_hex: str,
               challenge_sha256: str) -> dict:
    pins = _context(pins,expected_bundle_sha256,sender_id=sender_id,
                    receiver_id=receiver_id,receiver_public_hex=receiver_public_hex,
                    challenge_sha256=challenge_sha256)
    require(type(expected_acknowledgement_sha256) is str and
            b.HEX64.fullmatch(expected_acknowledgement_sha256) is not None and
            expected_acknowledgement_sha256 != a.GENESIS,
            'EXTERNAL_EXACT_ACKNOWLEDGEMENT_RAW_SHA_REQUIRED')
    raw = io._open_regular(acknowledgement_file,MAX_ACK_BYTES,private=True)
    require(hmac.compare_digest(b.digest(raw),expected_acknowledgement_sha256),
            'ACKNOWLEDGEMENT_NOT_EQUAL_EXTERNAL_RAW_SHA_PIN')
    ack = io.parse(raw,MAX_ACK_BYTES)
    require(raw == b.canonical(ack),'ACKNOWLEDGEMENT_NOT_CANONICAL')
    l.exact(ack,ACK_FIELDS,'ACKNOWLEDGEMENT_FIELDS_INVALID')
    require(ack['schema'] == ACK_SCHEMA,'ACKNOWLEDGEMENT_SCHEMA_INVALID')
    claim = l.exact(ack['claim'],CLAIM_FIELDS,'ACK_CLAIM_FIELDS_INVALID')
    require(claim['schema'] == CLAIM_SCHEMA,'ACK_CLAIM_SCHEMA_INVALID')
    sig = ack['receiver_signature_ed25519']
    require(type(sig) is str and a.SIG.fullmatch(sig) is not None,
            'RECEIVER_ED25519_SIGNATURE_FORMAT_INVALID')
    try:
        io.pub_from_hex(receiver_public_hex).verify(
            bytes.fromhex(sig),DOMAIN+a.canonical(claim))
    except (InvalidSignature,ValueError,TypeError,io.HostError) as exc:
        raise a.AnchorError('EC303_RECEIVER_ED25519_SIGNATURE_INVALID',
                            'permission_denied') from exc
    # Never accept a signed claim of archive verification as proof of itself.
    # Re-run ORIGINAL EC301..294 signatures from the exact pinned ZIP now.
    proof = b.verify_bundle(bundle_file,expected_bundle_sha256,pins)
    expected = _claim(pins,proof,expected_bundle_sha256=expected_bundle_sha256,
                      sender_id=sender_id,receiver_id=receiver_id,
                      receiver_public_hex=receiver_public_hex,
                      challenge_sha256=challenge_sha256)
    require(hmac.compare_digest(a.canonical(claim),a.canonical(expected)),
            'SIGNED_ACK_NOT_EQUAL_INDEPENDENTLY_REVERIFIED_EXPECTATIONS')
    return {'status':'receiver_signature_and_original_pinned_bundle_reverified',
            'acknowledgement_sha256':expected_acknowledgement_sha256,
            'bundle_sha256':expected_bundle_sha256,
            'report_sha256':proof['report_sha256'],
            'evidence_document_count':proof['evidence_document_count'],
            'exit_code':0}

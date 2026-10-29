#!/usr/bin/env python3
"""EC405 offline genuine WARC/1.1 response records + RFC3161 token receiver.

Production runs unchanged EC404.audit (and all inherited real source audits) first.
The accepted WARC grammar is an explicitly strict, useful WARC/1.1 subset:
three response records, uncompressed exact HTTP response payloads, bounded
headers, unique record IDs, sha256 block/payload digests and canonical dates.
Genuine RFC3161 CMS/TSTInfo imprint/signature/cert-path and supplied CRLs are
verified by unchanged EC350 crypto.  Offline evidence cannot authenticate
third-party custody, actual network events, legal authority or calibrated UTC.
No network, private-key, signer, source mutation or business write paths.
"""
from __future__ import annotations

import base64
from datetime import timezone
import hashlib
import json
import re
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from ec295_delivery_anchor import anchor as errors
from ec350_tsa_timestamp import timestamp as tsa
from ec372_historical_authority import authority_archive as original_io
from ec394_registered_witness import registered_witness as original_readers
from ec404_public_access import protocol as parent

RESULT_SCHEMA = 'ces.ec405.original_warc_rfc3161_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec405.unsigned_warc_rfc3161_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec405.original_warc_rfc3161_denial.v1'
BUNDLE_SCHEMA = 'ces.ec405.original_warc_timestamp_bundle.v1'
TRUST_SCHEMA = 'ces.ec405.outside_pinned_offline_tsa_roster.v1'
INVENTORY_SCHEMA = 'ces.ec405.unsigned_warc_rfc3161_inventory.v1'
MAX_BUNDLE = 150_000
MAX_TRUST = 32_000
MAX_WARC_HEADER = 8192
MAX_WARC = (parent.MAX_HTTP_SOURCE + parent.MAX_HTTP_PDF +
            parent.MAX_HTTP_XML + 3*(MAX_WARC_HEADER + 4))
MAX_CERT = tsa.MAX_CERT_BYTES
MAX_CRL = tsa.MAX_CRL_BYTES
MAX_TOKEN = tsa.MAX_DER_BYTES
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_warc_timestamp_bundle_file',
    'expected_historical_ec339_warc_timestamp_bundle_sha256',
    'expected_outside_ec405_tsa_roster_sha256',
    'expected_outside_ec405_tsa_a_root_der_sha256',
    'expected_outside_ec405_tsa_b_root_der_sha256',
    'expected_outside_ec405_first_a_warc_sha256',
    'expected_outside_ec405_first_b_warc_sha256',
    'expected_outside_ec405_first_a_rfc3161_sha256',
    'expected_outside_ec405_first_b_rfc3161_sha256',
    'ec405_tsa_evaluation_utc',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_warc_timestamp_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_warc_timestamp_epoch_inventory_shas',
     '--historical-ec339-warc-timestamp-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_warc_timestamp_publisher_counts',
     '--minimum-historical-ec339-joint-warc-timestamp-publisher-count'),
)
REPEAT_NAMES = tuple(name for name, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec404_public_access_and_ancestors_disputed',
    'outside_warc_roster_first_epoch_or_whole_inventory_sha_or_floor_disagrees',
    'one_or_more_later_warc_or_rfc3161_originals_missing',
    'rfc3161_signed_time_after_outside_cutoff_or_before_signed_claim_or_after_evaluation',
    'bounded_supplied_signed_tsa_crls_missing_stale_or_revoked',
    'joint_warc_timestamp_and_real_ec404_parent_coverage_incomplete',
    'physical_public_http_request_or_independent_archival_custody_not_proven',
    'external_tsa_root_provenance_and_legally_qualified_clock_not_proven',
    'official_authority_global_revocation_hidden_forks_worm_final_not_proven',
)
OUTCOMES = (
    'ec405_real_ec404_parent_source_chain_disputed',
    'ec405_outside_original_warc_tsa_or_inventory_anchors_disagree',
    'ec405_warc_or_original_signed_timestamp_missing',
    'ec405_authenticated_token_time_conflicts_with_claimed_cutoff_or_evaluation',
    'ec405_offline_tsa_crl_window_revocation_or_coverage_unresolved',
    'ec405_two_role_timestamp_and_real_source_joint_coverage_incomplete',
    'ec405_actual_network_event_and_third_party_custody_not_established',
    'ec405_externally_trusted_legally_qualified_tsa_and_clock_not_established',
    'ec405_legal_state_global_fork_revocation_worm_acceptance_not_established',
)
NEGATIVES = (
    'warc_response_bytes_prove_real_historical_http_request_or_public_availability',
    'warc_date_header_is_an_independent_authenticated_time',
    'supplied_tsa_root_or_policy_oid_proves_public_qualified_tsa_identity',
    'genuine_local_cms_timestamp_proves_calibrated_legally_qualified_utc',
    'two_distinct_local_tsa_roots_prove_independent_institutional_custody',
    'bounded_crls_prove_worldwide_revocation_or_hidden_fork_completeness',
    'warc_payload_equality_proves_signed_pdf_visible_page_meaning',
    'new_warc_or_tsa_fixes_adverse_real_ec404_or_earlier_parent',
    'receiver_manufactured_historical_warc_rfc3161_signature_or_tsa_root',
    'receiver_used_network_private_key_provider_ps1_git_ci_or_worm_writer',
    'full_unmocked_real_original_history_native_ps7_smoke_or_final_acceptance_proven',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec404_original_public_access_bundle_original',
                 'outside_tsa_roster_original', 'epochs'}
TRUST_FIELDS = {'schema', 'claimed_directory_lineage_id', 'authorities'}
AUTHORITY_FIELDS = {'publisher_id', 'tsa_authority_id',
                    'root_certificate_original', 'root_certificate_der_sha256',
                    'expected_tsa_policy_oid', 'crl_originals'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
ROLE_FIELDS = {'publisher_id', 'warc_original', 'rfc3161_original', 'tsa_authority_id'}
WARC_HEADER_FIELDS = {'WARC-Type', 'WARC-Target-URI', 'WARC-Date',
                      'WARC-Record-ID', 'WARC-Block-Digest',
                      'Content-Type', 'Content-Length'}
WARC_OPTIONAL_FIELDS = {'WARC-Payload-Digest'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
OID = re.compile(r'[0-2](?:\.(?:0|[1-9][0-9]{0,12})){2,20}\Z')
DECIMAL = re.compile(r'(?:0|[1-9][0-9]{0,8})\Z')
B32_DIGEST = re.compile(r'sha256:[A-Z2-7]{52}\Z')
RECORD_ID = re.compile(r'<urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})>\Z')


def need(condition, code, status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC405_' + code, status)


def exact(obj, fields, code):
    need(type(obj) is dict and set(obj) == fields,
         code + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cdigest(value):
    return parent.cdigest(value)


def ref(value):
    return parent.ref(value)


def utc(value):
    return parent._utc(value)


def _b32(raw):
    return 'sha256:' + base64.b32encode(hashlib.sha256(raw).digest()).decode('ascii').rstrip('=')


def _warc_records(raw: bytes, expected: list[dict], record_ids: set[str],
                  claimed_capture_utc: str) -> list[dict]:
    """Verify exactly three byte-framed WARC/1.1 response records; no JSON stand-in.

    Payload is a complete already authenticated EC404 raw HTTP response, not
    merely its body or a chosen digest.  This supports common uncompressed
    WARC response records, not arbitrary WARC containers or warc.gz.
    """
    need(type(raw) is bytes and 0 < len(raw) <= MAX_WARC and len(expected) == 3,
         'BOUNDED_THREE_RESPONSE_WARC_BYTES_REQUIRED', 'permission_denied')
    offset = 0
    observations = []
    for kind, capture in zip(parent.CAPTURES, expected, strict=True):
        need(capture['kind'] == kind, 'SIGNED_EC404_CAPTURE_ORDER_INVALID',
             'permission_denied')
        end = raw.find(b'\r\n\r\n', offset, min(len(raw), offset+MAX_WARC_HEADER+4))
        need(end > offset and end-offset <= MAX_WARC_HEADER,
             'WARC_HEADER_TERMINATOR_MISSING_OR_OVERSIZED', 'permission_denied')
        raw_header = raw[offset:end]
        need(b'\x00' not in raw_header and
             b'\n' not in raw_header.replace(b'\r\n', b'') and
             b'\r' not in raw_header.replace(b'\r\n', b''),
             'WARC_CRLF_CONTROL_OR_FOLDING_INVALID', 'permission_denied')
        lines = raw_header.split(b'\r\n')
        need(len(lines) in (8,9) and lines[0] == b'WARC/1.1',
             'WARC_1_1_EXACT_RECORD_HEADER_REQUIRED', 'permission_denied')
        headers = {}
        for line in lines[1:]:
            need(0 < len(line) <= 2048 and b': ' in line and
                 not line.startswith((b' ', b'\t')),
                 'WARC_INVALID_OR_FOLDED_FIELD', 'permission_denied')
            key, val = line.split(b': ', 1)
            try:
                k, v = key.decode('ascii'), val.decode('ascii')
            except UnicodeDecodeError as exc:
                raise errors.AnchorError('EC405_WARC_NONASCII_HEADER',
                                         'permission_denied') from exc
            need(k in (WARC_HEADER_FIELDS | WARC_OPTIONAL_FIELDS) and
                 k not in headers and v and all(32 <= ord(c) < 127 for c in v),
                 'WARC_UNKNOWN_DUPLICATE_OR_AMBIGUOUS_FIELD', 'permission_denied')
            headers[k] = v
        need(WARC_HEADER_FIELDS <= headers.keys() and
             set(headers) <= WARC_HEADER_FIELDS | WARC_OPTIONAL_FIELDS and
             headers['WARC-Type'] == 'response' and
             headers['Content-Type'] == 'application/http; msgtype=response' and
             headers['WARC-Target-URI'] == capture['public_url'] and
             headers['WARC-Date'] == claimed_capture_utc and
             DECIMAL.fullmatch(headers['Content-Length']) is not None and
             B32_DIGEST.fullmatch(headers['WARC-Block-Digest']) is not None,
             'WARC_CONTENT_TYPE_DATE_TARGET_LENGTH_OR_DIGEST_INVALID',
             'permission_denied')
        record_id = RECORD_ID.fullmatch(headers['WARC-Record-ID'])
        need(record_id is not None, 'WARC_CANONICAL_UUID_RECORD_ID_REQUIRED',
             'permission_denied')
        try:
            parsed_uuid = UUID(record_id.group(1))
        except ValueError as exc:
            raise errors.AnchorError('EC405_WARC_INVALID_RECORD_ID',
                                     'permission_denied') from exc
        need(parsed_uuid.version in (1,4,7) and
             str(parsed_uuid) == record_id.group(1) and
             record_id.group(1) not in record_ids,
             'WARC_RECORD_ID_DUPLICATE_OR_NONCANONICAL', 'permission_denied')
        record_ids.add(record_id.group(1))
        start = end+4
        n = int(headers['Content-Length'])
        need(n == len(capture['http_raw']) and
             start+n+4 <= len(raw) and
             raw[start:start+n] == capture['http_raw'] and
             raw[start+n:start+n+4] == b'\r\n\r\n' and
             headers['WARC-Block-Digest'] == _b32(capture['http_raw']),
             'WARC_ACTUAL_HTTP_ORIGINAL_BLOCK_AND_DIGEST_MISMATCH',
             'permission_denied')
        payload_digest = headers.get('WARC-Payload-Digest')
        if payload_digest is not None:
            http_head_end = capture['http_raw'].find(b'\r\n\r\n')
            need(http_head_end >= 0 and
                 payload_digest == _b32(capture['http_raw'][http_head_end+4:]),
                 'WARC_HTTP_BODY_DIGEST_MISMATCH', 'permission_denied')
        observations.append({'kind': kind, 'record_id': record_id.group(1),
                             'public_target_uri': capture['public_url'],
                             'raw_http_original_sha256': sha(capture['http_raw']),
                             'warc_block_digest': headers['WARC-Block-Digest'],
                             'warc_payload_digest_present': payload_digest is not None})
        offset = start+n+4
    need(offset == len(raw), 'WARC_EXTRA_TRAILING_OR_MISSING_RECORDS',
         'permission_denied')
    return observations


def _inputs(opts, deriving):
    wanted = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        wanted.update(AUDIT_ONLY)
    need(set(opts) == wanted, 'COMPLETE_REAL_EC404_PARENT_AND_EC405_ARGS_REQUIRED')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    original_io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                                   'EC405_ORIGINAL_WARC_BUNDLE')
    for k in NEW_SCALARS[2:9]:
        need(parent.x509core.valid_sha(opts[k]), 'OUTSIDE_ROOT_OR_FIRST_ORIGINAL_SHA_INVALID')
    need(len({opts[k] for k in NEW_SCALARS[3:9]}) == 6,
         'ROOT_FIRST_WARC_AND_TOKEN_SHAS_MUST_BE_DISTINCT', 'permission_denied')
    if not deriving:
        need(parent.x509core.valid_sha(opts[AUDIT_ONLY[0]]),
             'RETAINED_WHOLE_WARC_TIMESTAMP_INVENTORY_SHA_INVALID')
    utc(opts[NEW_SCALARS[9]])
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_REAL_PARENT_EPOCHS_REQUIRED')
    for name in REPEAT_NAMES:
        vals = opts[name]
        need(type(vals) is list and len(vals) == n,
             'PER_EPOCH_WARC_TIMESTAMP_SHA_AND_FLOOR_REQUIRED')
        if name.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in vals),
                 'MAX_TWO_JOINT_WARC_ROLES_PER_EPOCH')
        else:
            need(all(parent.x509core.valid_sha(v) for v in vals),
                 'EPOCH_WARC_TIMESTAMP_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code', 'offline_unresolved_exit_code',
              'verified_live_ec403_report_sha256',
              'verified_live_ec403_inventory_sha256',
              'original_public_access_bundle_sha256',
              'receiver_verified_public_access_inventory_sha256',
              'verified_joint_archive_and_real_parent_publishers',
              'public_access_epoch_reviews',
              'bounded_local_public_access_and_real_ec403_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-public-access' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_public_access_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_public_access_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(parent.x509core.valid_sha(report.get(k)) for k in (
            'verified_live_ec403_report_sha256',
            'verified_live_ec403_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('bounded_local_public_access_and_real_ec403_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status') == next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
             if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'ACTUAL_UNCHANGED_EC404_PARENT_REPORT_CONTRACT_INVALID', 'unavailable')
    rows = report.get('public_access_epoch_reviews')
    rowfields = {'epoch_index', 'actual_verified_archive_receipt_count',
                 'claimed_before_cutoff_count', 'joint_verified_archive_and_parent_count',
                 'public_access_epoch_inventory_sha256',
                 'real_ec403_parent_joint_xml_pdf_count'}
    n = len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows) == n and all(
        type(row) is dict and set(row) == rowfields and
        type(row['epoch_index']) is int and row['epoch_index'] == i and
        type(row['actual_verified_archive_receipt_count']) is int and
        0 <= row['actual_verified_archive_receipt_count'] <= 2 and
        type(row['claimed_before_cutoff_count']) is int and
        0 <= row['claimed_before_cutoff_count'] <= row['actual_verified_archive_receipt_count'] and
        type(row['joint_verified_archive_and_parent_count']) is int and
        0 <= row['joint_verified_archive_and_parent_count'] <= row['claimed_before_cutoff_count'] and
        type(row['real_ec403_parent_joint_xml_pdf_count']) is int and
        0 <= row['real_ec403_parent_joint_xml_pdf_count'] <= 2 and
        row['joint_verified_archive_and_parent_count'] <= row['real_ec403_parent_joint_xml_pdf_count'] and
        parent.x509core.valid_sha(row['public_access_epoch_inventory_sha256'])
        for i, row in enumerate(rows)) and
        type(report.get('verified_joint_archive_and_real_parent_publishers')) is int and
        report['verified_joint_archive_and_real_parent_publishers'] == sum(
          row['joint_verified_archive_and_parent_count'] for row in rows),
         'REAL_EC404_PARENT_EPOCH_JOINT_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _find_ref_paths(value, used):
    if type(value) is dict:
        if set(value) == {'path', 'sha256'}:
            x = ref(value)
            used.add(x['path'])
        else:
            for inner in value.values():
                _find_ref_paths(inner, used)
    elif type(value) is list:
        for inner in value:
            _find_ref_paths(inner, used)


def _trust(roster, roles, opts, read, protected):
    exact(roster, TRUST_FIELDS, 'TSA_ROSTER')
    need(roster['schema'] == TRUST_SCHEMA and
         roster['claimed_directory_lineage_id'] == opts['claimed_historical_directory_lineage_id'] and
         type(roster['authorities']) is list and len(roster['authorities']) == 2,
         'EXACTLY_TWO_EXTERNALLY_PINNED_TSA_ROOTS_REQUIRED', 'permission_denied')
    authorities, roots, ids = {}, set(), set()
    for entry in roster['authorities']:
        exact(entry, AUTHORITY_FIELDS, 'TSA_AUTHORITY')
        role, aid = entry['publisher_id'], entry['tsa_authority_id']
        need(type(role) is str and role in roles and role not in authorities and
             type(aid) is str and parent.ARCHIVE_ID.fullmatch(aid) is not None and
             aid not in ids and type(entry['expected_tsa_policy_oid']) is str and
             OID.fullmatch(entry['expected_tsa_policy_oid']) is not None,
             'DISTINCT_TSA_ROLE_ID_AND_POLICY_REQUIRED', 'permission_denied')
        rootref = ref(entry['root_certificate_original'])
        need(rootref['path'] not in protected,
             'TSA_ROOT_PATH_ALIASES_INHERITED_OR_OTHER_ORIGINAL', 'permission_denied')
        root_bytes = read(rootref, 'ec405_pinned_tsa_root', MAX_CERT)
        root = tsa._certificate(root_bytes)
        der_sha = root.fingerprint(hashes.SHA256()).hex()
        expected_sha = opts[NEW_SCALARS[3 if role == roles[0] else 4]]
        need(der_sha == entry['root_certificate_der_sha256'] == expected_sha and
             der_sha not in roots,
             'TSA_ROOT_CERT_DER_SHA_NOT_EXTERNALLY_PINNED_OR_UNIQUE',
             'permission_denied')
        roots.add(der_sha)
        ids.add(aid)
        protected.add(rootref['path'])
        crlrefs = entry['crl_originals']
        need(type(crlrefs) is list and len(crlrefs) <= 4,
             'TSA_MAX_FOUR_SIGNED_CRL_ORIGINALS_REQUIRED', 'permission_denied')
        crls = []
        for record in crlrefs:
            r = ref(record)
            need(r['path'] not in protected, 'TSA_CRL_PATH_ALIASES_OTHER_ORIGINAL',
                 'permission_denied')
            protected.add(r['path'])
            crls.append(tsa._crl(read(r, 'ec405_signed_tsa_crl', MAX_CRL)))
        authorities[role] = {'id': aid, 'root': root, 'root_sha': der_sha,
                             'crls': crls, 'policy': entry['expected_tsa_policy_oid']}
    need(set(authorities) == set(roles), 'TRUE_EC404_TWO_ROLE_TSA_COVERAGE_REQUIRED',
         'permission_denied')
    return authorities


def _verified_tsa_token(token, warc, root, policy):
    """Reuse EC350 without bypassing its canonical CMS signature checks.

    asn1crypto 1.5 caches ContentType's reverse OID map before the timestamp
    module dynamically registers id-ct-TSTInfo.  Importing old PDF/CMS modules
    ahead of RFC3161 can leave that cached map stale; then the inherited
    force-DER roundtrip raises ValueError on the valid string 'tst_info'.
    Reconcile only that library-internal OID map, never token/source bytes,
    signed attributes, imprint, signer, trust root, policy or CRL rules.
    """
    from asn1crypto import cms, tsp  # noqa: F401  (register TSTInfo OID)
    for cls in (cms.ContentType, cms.CMSAttributeType):
        # Additional RFC3161 registration appends id-aa-signingCertificateV2.
        if cls._map is not None and cls._reverse_map is not None and any(
            cls._reverse_map.get(name) != oid for oid, name in cls._map.items()
        ):
            cls._reverse_map = {name: oid for oid, name in cls._map.items()}
    return tsa._tsa_token(token, warc, root, policy)


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # unchanged REAL EC404 in production
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = original_readers._readers()
    b405 = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b404 = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    bundle = doc(b405, 'ec405_original_warc_timestamp_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'WARC_TIMESTAMP_BUNDLE')
    trust_ref = ref(bundle['outside_tsa_roster_original'])
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec404_original_public_access_bundle_original'] == b404 and
         trust_ref['sha256'] == opts[NEW_SCALARS[2]] and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'WARC_BUNDLE_LINK_TO_REAL_EC404_OR_EXTERNAL_TSA_ROSTER_INVALID',
         'permission_denied')
    older = doc(b404, 'ec405_true_ec404_public_access_bundle', parent.MAX_BUNDLE)
    exact(older, parent.BUNDLE_FIELDS, 'REOPENED_REAL_EC404_BUNDLE')
    need(older['schema'] == parent.BUNDLE_SCHEMA and
         older['claimed_directory_lineage_id'] == lineage and
         len(older['epochs']) == n and
         older['outside_archive_roster_original'] is not None,
         'REAL_EC404_EPOCH_AND_LINEAGE_MISMATCH', 'permission_denied')
    archive_ref = ref(older['outside_archive_roster_original'])
    archives = doc(archive_ref, 'ec405_actual_parent_archives', parent.MAX_ROSTER)
    exact(archives, parent.ROSTER_FIELDS, 'REAL_ARCHIVE_ROSTER')
    need(archives['schema'] == parent.ROSTER_SCHEMA and
         archives['claimed_directory_lineage_id'] == lineage and
         archive_ref['sha256'] == opts[parent.NEW_SCALARS[2]],
         'REAL_ARCHIVE_ROSTER_BUNDLE_EXTERNAL_PIN_MISMATCH', 'permission_denied')
    roles = sorted(row['publisher_id'] for row in archives['archives'])
    need(len(roles) == 2 and len(set(roles)) == 2,
         'REAL_EC404_TWO_PUBLISHER_ROLES_REQUIRED', 'permission_denied')
    protected = {b405['path'], b404['path'], trust_ref['path'], archive_ref['path']}
    _find_ref_paths(older, protected)
    _find_ref_paths(archives, protected)
    for name, value in opts.items():
        if name in (*PARENT_SCALARS,) and name.endswith('_file') and type(value) is str:
            protected.add(value)
    trust = doc(trust_ref, 'ec405_outside_pinned_tsa_roster', MAX_TRUST)
    authorities = _trust(trust, roles, opts, read, protected)
    flags = {k: False for k in FLAGS}
    flags[FLAGS[0]] = (not live['bounded_local_public_access_and_real_ec403_parent_consistency'] or
                       any(r['joint_verified_archive_and_parent_count'] != 2
                           for r in live['public_access_epoch_reviews']))
    cutoff = utc(opts[parent.NEW_SCALARS[7]])
    evaluation = utc(opts[NEW_SCALARS[9]])
    first_warc, first_token, last_time, record_ids = {}, {}, {}, set()
    reviews, inventory_epochs, joint_total = [], [], 0
    token_signer_sha_by_role = {}
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, EPOCH_FIELDS, 'WARC_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i and
             type(epoch['publishers']) is list and len(epoch['publishers']) == 2,
             'WARC_EXACT_TWO_ROLE_EPOCH_REQUIRED', 'permission_denied')
        old_epoch = older['epochs'][i]
        exact(old_epoch, parent.EPOCH_FIELDS, 'REAL_EC404_EPOCH')
        need(type(old_epoch['epoch_index']) is int and old_epoch['epoch_index'] == i and
             type(old_epoch['publishers']) is list and len(old_epoch['publishers']) == 2,
             'REAL_EC404_EPOCH_INDEX_OR_ROLE_MISMATCH', 'permission_denied')
        original_roles = {}
        for row in old_epoch['publishers']:
            exact(row, parent.PUBLISHER_FIELDS, 'REAL_ARCHIVED_HTTP_ROW')
            rid = row['publisher_id']
            need(rid in roles and rid not in original_roles,
                 'REAL_HTTP_ROLE_REPEATED_OR_UNKNOWN', 'permission_denied')
            original_roles[rid] = row
        need(set(original_roles) == set(roles), 'REAL_EC404_COMPLETE_ROLE_SET_REQUIRED',
             'permission_denied')
        # Claim unique original identities for this epoch *before* parsing any
        # role: a future role cannot hide a shared path behind a content error.
        epoch_paths = set()
        for candidate in epoch['publishers']:
            exact(candidate, ROLE_FIELDS, 'WARC_ROLE_PRECHECK')
            for field in ('warc_original', 'rfc3161_original'):
                if candidate[field] is None:
                    continue
                path = ref(candidate[field])['path']
                need(path not in protected and path not in epoch_paths,
                     'NEW_WARC_OR_TOKEN_PATH_ALIASES_REAL_PARENT_OR_SIBLING',
                     'permission_denied')
                epoch_paths.add(path)
        seen, members, verified_warc, verified_token = set(), [], 0, 0
        qualified, clipped = 0, 0
        for row in epoch['publishers']:
            exact(row, ROLE_FIELDS, 'WARC_ROLE')
            role = row['publisher_id']
            need(type(role) is str and role in roles and role not in seen,
                 'WARC_ROLE_DUPLICATE_OR_UNKNOWN', 'permission_denied')
            seen.add(role)
            auth = authorities[role]
            need(row['tsa_authority_id'] == auth['id'],
                 'WRONG_TSA_ROLE_AUTHORITY_ID', 'permission_denied')
            wref = ref(row['warc_original']) if row['warc_original'] else None
            tref = ref(row['rfc3161_original']) if row['rfc3161_original'] else None
            if wref is None:
                need(i != 0 and tref is None,
                     'FIRST_ORIGINAL_WARC_AND_RFC3161_MANDATORY_NO_ORPHAN_TOKEN',
                     'permission_denied')
                flags[FLAGS[2]] = True
                members.append({'publisher_id': role, 'warc_original_sha256': None,
                                'rfc3161_original_sha256': None,
                                'actual_response_records': None,
                                'signed_gen_time_utc': None,
                                'verified_tsa_signer_cert_sha256': None,
                                'verified_tsa_root_der_sha256': None,
                                'imprint_algorithm': None,
                                'supplied_tsa_crls_sufficient': None,
                                'before_outside_cutoff': None})
                continue
            need(wref['path'] not in protected and
                 (tref is None or tref['path'] not in protected | {wref['path']}),
                 'NEW_WARC_OR_TOKEN_PATH_ALIASES_REAL_PARENT', 'permission_denied')
            protected.add(wref['path'])
            if tref:
                protected.add(tref['path'])
            oldrow = original_roles[role]
            receipt_ref = ref(oldrow['signed_archive_receipt_original']) if oldrow[
                'signed_archive_receipt_original'] else None
            need(receipt_ref is not None and type(oldrow['captures']) is list and
                 len(oldrow['captures']) == 3,
                 'WARC_REQUIRES_REAL_ORIGINAL_EC404_SIGNED_RECEIPT', 'permission_denied')
            receipt = doc(receipt_ref, 'ec405_true_signed_ec404_receipt', parent.MAX_RECEIPT)
            exact(receipt, parent.RECEIPT_FIELDS, 'REAL_SIGNED_HTTP_RECEIPT')
            claim = receipt['claim']
            exact(claim, parent.CLAIM_FIELDS, 'REAL_SIGNED_HTTP_CLAIM')
            need(receipt['schema'] == parent.RECEIPT_SCHEMA and
                 claim['schema'] == parent.CLAIM_SCHEMA and
                 claim['publisher_id'] == role and
                 claim['directory_lineage_id'] == lineage and
                 claim['epoch_index'] == i and
                 type(claim['captures']) is list and len(claim['captures']) == 3,
                 'REOPENED_REAL_SIGNED_CAPTURE_CLAIM_INVALID', 'permission_denied')
            signed_time = claim['claimed_capture_utc']
            utc(signed_time)
            actual = []
            for kind, capref, capclaim in zip(parent.CAPTURES, oldrow['captures'],
                                               claim['captures'], strict=True):
                exact(capref, parent.CAPTURE_REF_FIELDS, 'REAL_HTTP_REF')
                exact(capclaim, parent.CLAIM_CAPTURE_FIELDS, 'SIGNED_HTTP_SOURCE')
                need(capref['kind'] == capclaim['kind'] == kind and
                     capclaim['http_response_sha256'] == ref(
                         capref['http_response_original'])['sha256'],
                     'AUTHENTIC_EC404_SIGNED_HTTP_CAPTURE_SHA_LINK_INVALID',
                     'permission_denied')
                original_ref = ref(capref['http_response_original'])
                maxcap = {'gazette':parent.MAX_HTTP_SOURCE,
                          'signed_pdf':parent.MAX_HTTP_PDF,
                          'signed_xml':parent.MAX_HTTP_XML}[kind]
                content = read(original_ref, 'ec405_actual_ec404_http_original', maxcap)
                actual.append({'kind':kind, 'public_url':capclaim['public_url'],
                               'http_raw':content})
            warc = read(wref, 'ec405_original_three_response_warc', MAX_WARC)
            observations = _warc_records(warc, actual, record_ids, signed_time)
            verified_warc += 1
            if i == 0:
                first_warc[role] = wref['sha256']
            token_sha, gen, crl_ok, before = None, None, None, None
            token_signer_sha, token_root_sha, imprint_alg = None, None, None
            if tref is None:
                need(i != 0, 'FIRST_WARC_RFC3161_TOKEN_ORIGINAL_REQUIRED',
                     'permission_denied')
                flags[FLAGS[2]] = True
            else:
                token = read(tref, 'ec405_real_original_rfc3161_der', MAX_TOKEN)
                verification = _verified_tsa_token(token, warc, auth['root'], auth['policy'])
                check = tsa._check_crls(verification['certificate_path'], auth['crls'],
                                       verification['token_gen_time'], evaluation)
                gen = verification['token_gen_time']
                gen_utc = gen.isoformat(timespec='microseconds').replace('+00:00','Z')
                if gen.microsecond == 0:
                    gen_utc = gen_utc.replace('.000000Z','Z')
                token_signer_sha = verification['tsa_signer_cert_sha256']
                token_root_sha = verification['tsa_root_cert_der_sha256']
                imprint_alg = verification['imprint_digest_algorithm']
                before = (gen <= cutoff and gen >= utc(signed_time) and gen <= evaluation and
                          (role not in last_time or gen >= last_time[role]))
                if not before:
                    flags[FLAGS[3]] = True
                crl_ok = check['all_chain_edges_have_single_fresh_crl_as_furnished']
                if not crl_ok or check['revoked_at_or_before_gen_time']:
                    flags[FLAGS[4]] = True
                verified_token += 1
                switched = (role in token_signer_sha_by_role and
                            token_signer_sha_by_role[role] != token_signer_sha)
                if switched:
                    # Forbid credit on an unaccounted signer rollover even
                    # though both new and old signatures verified locally.
                    flags[FLAGS[4]] = True
                if before and crl_ok and not switched:
                    qualified += 1
                if before:
                    clipped += 1
                token_sha = tref['sha256']
                if i == 0:
                    first_token[role] = token_sha
                last_time[role] = gen
                token_signer_sha_by_role[role] = token_signer_sha
            members.append({'publisher_id': role, 'warc_original_sha256': wref['sha256'],
                            'rfc3161_original_sha256': token_sha,
                            'actual_response_records': observations,
                            'signed_gen_time_utc': gen_utc if tref is not None else None,
                            'verified_tsa_signer_cert_sha256': token_signer_sha,
                            'verified_tsa_root_der_sha256': token_root_sha,
                            'imprint_algorithm': imprint_alg,
                            'supplied_tsa_crls_sufficient': crl_ok,
                            'before_outside_cutoff': before})
        need(seen == set(roles), 'TWO_WARC_ROLE_SET_INCOMPLETE', 'permission_denied')
        members.sort(key=lambda v: v['publisher_id'])
        joint = (qualified if
                 live['bounded_local_public_access_and_real_ec403_parent_consistency'] and
                 live['public_access_epoch_reviews'][i]['joint_verified_archive_and_parent_count'] == 2 else 0)
        if joint != 2:
            flags[FLAGS[5]] = True
        inv = {'epoch_index': i, 'publishers': members,
               'verified_warc_original_count': verified_warc,
               'verified_rfc3161_token_count': verified_token,
               'signed_time_before_cutoff_count': clipped,
               'joint_warc_timestamp_and_parent_count': joint}
        digest = cdigest(inv)
        if digest != opts[REPEAT_NAMES[0]][i] or joint < opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]] = True
        inventory_epochs.append(inv)
        reviews.append({'epoch_index': i,
                        'actual_verified_warc_count': verified_warc,
                        'actual_verified_rfc3161_count': verified_token,
                        'timestamp_and_crl_before_cutoff_count': qualified,
                        'joint_warc_timestamp_and_real_parent_count': joint,
                        'warc_timestamp_epoch_inventory_sha256': digest,
                        'real_ec404_parent_joint_capture_count': live[
                            'public_access_epoch_reviews'][i]['joint_verified_archive_and_parent_count']})
        joint_total += joint
    need(len(first_warc) == len(first_token) == 2 and
         all(role in first_warc and role in first_token for role in roles),
         'TWO_FIRST_WARC_AND_REAL_SIGNED_TOKENS_REQUIRED', 'permission_denied')
    for j, name in enumerate(NEW_SCALARS[5:9]):
        expected = (first_warc[roles[j]] if j < 2 else first_token[roles[j-2]])
        if opts[name] != expected:
            flags[FLAGS[1]] = True
    if len(set(token_signer_sha_by_role.values())) != len(token_signer_sha_by_role):
        need(False, 'TSA_SIGNER_CERT_SHARED_BETWEEN_INDEPENDENT_ROOTS',
             'permission_denied')
    inventory = {'schema': INVENTORY_SCHEMA, 'directory_lineage_id': lineage,
                 'verified_real_ec404_report_sha256': live_sha,
                 'verified_real_ec404_inventory_sha256': live[
                     'receiver_verified_public_access_inventory_sha256'],
                 'original_ec404_public_access_bundle_sha256': b404['sha256'],
                 'original_warc_timestamp_bundle_sha256': b405['sha256'],
                 'outside_tsa_roster_sha256': trust_ref['sha256'],
                 'outside_claimed_dispute_cutoff_utc': opts[parent.NEW_SCALARS[7]],
                 'ec405_evaluation_utc': opts[NEW_SCALARS[9]],
                 'outside_first_warc_shas': [opts[NEW_SCALARS[5]], opts[NEW_SCALARS[6]]],
                 'outside_first_rfc3161_shas': [opts[NEW_SCALARS[7]], opts[NEW_SCALARS[8]]],
                 'epochs': inventory_epochs}
    inv_sha = cdigest(inventory)
    if not deriving and inv_sha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    for path, (digest, cap) in late.items():
        raw = original_io._read({'path': path, 'sha256': digest},
                                'ec405_final_original_reread', cap, {}, {}, set())
        need(sha(raw) == digest, 'ORIGINAL_CHANGED_DURING_FINAL_READBACK',
             'permission_denied')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': ('derive-historical-ec339-warc-timestamp-inventory' if deriving
                        else 'audit-historical-ec339-warc-timestamp'),
            'status': next((OUTCOMES[i] for i, key in enumerate(FLAGS) if flags[key]),
                           OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec404_report_sha256': live_sha,
            'verified_live_ec404_inventory_sha256': live[
                'receiver_verified_public_access_inventory_sha256'],
            'original_warc_timestamp_bundle_sha256': b405['sha256'],
            'receiver_verified_warc_timestamp_inventory_sha256': inv_sha,
            'verified_joint_warc_timestamp_and_real_parent_publishers': joint_total,
            'warc_timestamp_epoch_reviews': reviews,
            'bounded_local_warc_timestamp_and_real_ec404_parent_consistency':
                not any(flags[k] for k in FLAGS[:6]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{k: False for k in NEGATIVES},
            **({'unsigned_warc_timestamp_evidence_inventory': inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)

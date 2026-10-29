#!/usr/bin/env python3
"""EC414: original WARC/1.1 OCSP distribution snapshots + two signed witnesses.

Read-only, SHA-pinned original-byte protocol. Mandatory unchanged EC413.audit
(and all EC412 -> EC407 -> earlier actual production auditors) runs first.
WARC bytes and genuinely signed Ed25519 *claims* are not verified historical
network traffic, institutionally independent trust, official LOTL status, or
qualified timestamps; no positive legal PASS is possible.
"""
from __future__ import annotations

import base64
from datetime import timedelta
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
import json
import re
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509 import ocsp

from delivery_anchor import anchor as errors
from historical_authority import authority_archive as io
from registered_witness import registered_witness as readers
from lotl_ocsp import protocol as parent

lotl = parent.lotl
RESULT_SCHEMA = 'ces.ec414.original_ocsp_publication_witness_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec414.unsigned_ocsp_publication_witness_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec414.ocsp_publication_witness_denial.v1'
BUNDLE_SCHEMA = 'ces.ec414.original_ocsp_publication_bundle.v1'
ROSTER_SCHEMA = 'ces.ec414.outside_pinned_ocsp_witness_roster.v1'
RECEIPT_SCHEMA = 'ces.ec414.original_signed_ocsp_observation.v1'
CLAIM_SCHEMA = 'ces.ec414.signed_ocsp_observation_claim.v1'
INVENTORY_SCHEMA = 'ces.ec414.unsigned_ocsp_publication_inventory.v1'
DOMAIN = b'CES/EC414/OriginalOCSPPublicationObservation/Ed25519/v1\x00'
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_lotl_ocsp_publication_bundle_file',
    'expected_historical_ec339_lotl_ocsp_publication_bundle_sha256',
    'expected_outside_ec414_publication_witness_roster_sha256',
    'expected_outside_ec414_publisher_key_sha256',
    'expected_outside_ec414_observer_key_sha256',
    'expected_outside_ec414_first_historical_warc_sha256',
    'expected_outside_ec414_first_evaluation_warc_sha256',
    'expected_outside_ec414_first_historical_publisher_receipt_sha256',
    'expected_outside_ec414_first_historical_observer_receipt_sha256',
    'expected_outside_ec414_first_evaluation_publisher_receipt_sha256',
    'expected_outside_ec414_first_evaluation_observer_receipt_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_lotl_ocsp_publication_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_lotl_ocsp_publication_epoch_inventory_shas',
     '--historical-ec339-lotl-ocsp-publication-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_ocsp_publication_publisher_counts',
     '--minimum-historical-ec339-joint-ocsp-publication-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec413_original_ocsp_and_older_ancestry_adverse',
    'outside_publication_original_roster_first_epoch_or_retained_pin_disagrees',
    'one_or_more_later_original_ocsp_warc_or_signed_witness_receipts_missing',
    'genuine_witness_claimed_time_or_cross_witness_chronology_inconsistent',
    'verified_dual_warc_witness_and_real_ec413_parent_coverage_incomplete',
    'official_publisher_and_observer_identity_or_independence_unproven',
    'historical_real_http_distribution_and_qualified_utc_not_proven',
    'full_unmocked_originals_worm_native_and_final_acceptance_unproven',
)
OUTCOMES = (
    'ec414_inherited_real_ec413_original_ocsp_or_older_ancestry_adverse',
    'ec414_outside_original_publication_inventory_and_first_pins_disagree',
    'ec414_later_original_ocsp_warc_or_witness_receipts_missing',
    'ec414_signed_observation_clock_or_cross_witness_chronology_inconsistent',
    'ec414_actual_original_publication_and_parent_joint_coverage_incomplete',
    'ec414_external_publisher_observer_authority_and_independence_unproven',
    'ec414_historic_network_distribution_and_independent_qualified_time_unproven',
    'ec414_unmocked_source_history_worm_native_final_acceptance_unproven',
)
NEGATIVES = (
    'valid_warc_bytes_prove_real_historical_http_network_delivery',
    'signed_warc_date_or_ed25519_claim_proves_independent_calibrated_utc',
    'different_ed25519_keys_prove_third_party_institutional_independence',
    'outside_pinned_observer_is_official_commission_or_ojeu_authority',
    'witness_signed_good_status_overrides_revoked_unknown_or_adverse_parent',
    'two_witnesses_establish_exhaustive_global_ocsp_or_no_hidden_forks',
    'signed_url_implies_actual_online_public_https_access_or_tls_authentication',
    'local_warc_signatures_establish_full_etsi_eidas_or_legal_pass',
    'receiver_minted_keys_signed_originals_or_historical_archive_timestamps',
    'receiver_used_network_private_keys_business_writes_git_ci_or_powershell',
    'full_external_unmocked_history_native_worm_and_acceptance_proven',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec413_original_lotl_ocsp_bundle_original',
                 'outside_publication_witness_roster_original', 'epochs'}
ROSTER_FIELDS = {'schema', 'claimed_directory_lineage_id', 'https_origin',
                 'publisher', 'observer'}
ROSTER_ROLE_FIELDS = {'witness_id', 'public_key_original'}
EPOCH_FIELDS = {'epoch_index', 'historical', 'evaluation'}
WINDOW_FIELDS = {'original_two_ocsp_warc', 'publisher_signed_receipt_original',
                 'observer_signed_receipt_original'}
RECEIPT_FIELDS = {'schema', 'claim', 'signature_hex'}
CLAIM_FIELDS = {'schema', 'directory_lineage_id', 'epoch_index', 'window',
                'witness_role', 'witness_id', 'event_id',
                'claimed_observation_utc', 'https_publication_urls',
                'original_lotl_ocsp_bundle_sha256', 'original_signed_lotl_xml_sha256',
                'original_two_ocsp_warc_sha256', 'original_ocsp_der_sha256s',
                'previous_role_receipt_sha256', 'publisher_receipt_sha256'}
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')
EVENT = re.compile(r'[A-Za-z][A-Za-z0-9._:-]{3,127}\Z')
SIGNATURE_HEX = re.compile(r'[0-9a-f]{128}\Z')
MAX_BUNDLE = 180_000
MAX_ROSTER = 16_000
MAX_RECEIPT = 24_000
MAX_WARC = 4_200_000
MAX_HEADER = 8192
WINDOWS = ('historical', 'evaluation')
ROLES = ('root', 'intermediate')
WITNESSES = ('publisher', 'observer')
ZERO_SHA = '0' * 64
SKEW = timedelta(minutes=5)
OBSERVER_DELAY = timedelta(days=1)
MAX_OBSERVATION_DELAY = timedelta(days=7)


def need(cond, code, status='permission_denied'):
    if cond is not True:
        raise errors.AnchorError('EC414_' + code, status)


def exact(obj, fields, context):
    need(type(obj) is dict and set(obj) == fields,
         context + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return parent.digest(value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _inputs(opts, deriving):
    required = {*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES}
    if not deriving:
        required.update(AUDIT_ONLY)
    need(set(opts) == required, 'EXACT_REAL_EC413_AND_PUBLICATION_ARGUMENTS_REQUIRED',
         'invalid_input')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC414_ORIGINAL_OCSP_PUBLICATION_BUNDLE')
    for k in (*NEW_SCALARS[2:], *((AUDIT_ONLY) if not deriving else ())):
        need(lotl.good_sha(opts[k]), 'OUTSIDE_ORIGINAL_SHA256_REQUIRED',
             'invalid_input')
    need(len({opts[k] for k in NEW_SCALARS[3:]}) == len(NEW_SCALARS[3:]),
         'DISTINCT_FIRST_KEY_WARC_AND_RECEIPT_PINS_REQUIRED', 'invalid_input')
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_REAL_PARENT_EPOCHS_REQUIRED', 'invalid_input')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == n,
             'ONE_PUBLICATION_EPOCH_PIN_AND_FLOOR_PER_REAL_SOURCE_EPOCH',
             'invalid_input')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'PUBLICATION_FLOOR_MUST_BE_0_TO_2', 'invalid_input')
        else:
            need(all(lotl.good_sha(v) for v in values),
                 'PUBLICATION_EPOCH_INVENTORY_SHA_REQUIRED', 'invalid_input')
    return inherited


def _parent_report(r, opts):
    fields = {'schema', 'command', 'status', 'exit_code',
              'offline_unresolved_exit_code', 'verified_live_ec412_report_sha256',
              'verified_live_ec412_inventory_sha256',
              'original_lotl_issuer_ocsp_bundle_sha256',
              'receiver_verified_lotl_issuer_ocsp_inventory_sha256',
              'verified_joint_ocsp_and_real_ec412_parent_publishers',
              'lotl_issuer_ocsp_epoch_reviews',
              'bounded_original_issuer_ocsp_and_real_ec412_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    row_fields = {'epoch_index', 'verified_four_original_issuer_ocsp_documents',
                  'signed_good_contemporaneous_four_source_windows',
                  'joint_original_issuer_ocsp_and_real_ec412_parent_publishers',
                  'original_lotl_ocsp_epoch_inventory_sha256',
                  'real_ec412_crl_joint_publisher_count'}
    rows = r.get('lotl_issuer_ocsp_epoch_reviews') if type(r) is dict else None
    n = len(opts['historical_directory_root_shas'])
    need(type(r) is dict and set(r) == fields and
         r.get('schema') == parent.RESULT_SCHEMA and
         r.get('command') == 'audit-historical-ec339-lotl-ocsp' and
         r.get('exit_code') == r.get('offline_unresolved_exit_code') == 2 and
         r.get('original_lotl_issuer_ocsp_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         r.get('receiver_verified_lotl_issuer_ocsp_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(lotl.good_sha(r.get(k)) for k in (
             'verified_live_ec412_report_sha256',
             'verified_live_ec412_inventory_sha256')) and
         type(r.get('bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'))
             is bool and
         r['bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'] is
             (not any(r.get(k) for k in parent.FLAGS[:6])) and
         all(type(r.get(k)) is bool for k in parent.FLAGS) and
         all(r[k] is True for k in parent.FLAGS[-3:]) and
         all(r.get(k) is False for k in parent.NEGATIVES) and
         r.get('sender_origin_path_required_or_read') is False and
         r.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed')
             is False and
         r.get('status') == next((parent.OUTCOMES[i] for i, key in enumerate(parent.FLAGS)
             if r[key]), parent.OUTCOMES[-1]) + '_unresolved' and
         type(rows) is list and len(rows) == n and all(
             type(row) is dict and set(row) == row_fields and
             type(row['epoch_index']) is int and row['epoch_index'] == i and
             type(row['verified_four_original_issuer_ocsp_documents']) is int and
             row['verified_four_original_issuer_ocsp_documents'] in (0, 1) and
             type(row['signed_good_contemporaneous_four_source_windows']) is int and
             row['signed_good_contemporaneous_four_source_windows'] in (0, 1) and
             all(type(row[k]) is int and 0 <= row[k] <= 2 for k in (
                 'joint_original_issuer_ocsp_and_real_ec412_parent_publishers',
                 'real_ec412_crl_joint_publisher_count')) and
             (row['verified_four_original_issuer_ocsp_documents'] == 1 or
              row['joint_original_issuer_ocsp_and_real_ec412_parent_publishers'] == 0) and
             (row['signed_good_contemporaneous_four_source_windows'] == 1 or
              row['joint_original_issuer_ocsp_and_real_ec412_parent_publishers'] == 0) and
             row['joint_original_issuer_ocsp_and_real_ec412_parent_publishers'] <=
                 row['real_ec412_crl_joint_publisher_count'] and
             lotl.good_sha(row['original_lotl_ocsp_epoch_inventory_sha256'])
             for i, row in enumerate(rows)) and
         type(r.get('verified_joint_ocsp_and_real_ec412_parent_publishers')) is int and
         r['verified_joint_ocsp_and_real_ec412_parent_publishers'] == sum(
             row['joint_original_issuer_ocsp_and_real_ec412_parent_publishers']
             for row in rows),
         'UNCHANGED_REAL_EC413_SIGNED_OCSP_REPORT_CONTRACT_INVALID', 'unavailable')
    return digest(r)


def _https(value):
    if type(value) is not str or len(value) > 2048 or any(ord(c) > 127 or
            ord(c) < 33 for c in value) or '\\' in value or '#' in value:
        return False
    try:
        u = urlsplit(value)
        return (u.scheme == 'https' and bool(u.netloc) and
                u.hostname is not None and u.hostname.lower() == u.hostname and
                u.username is None and u.password is None and
                u.port in (None, 443) and bool(u.path.startswith('/')) and
                not u.hostname.startswith('localhost') and
                u.hostname not in ('127.0.0.1', '::1', '0.0.0.0') and
                not (u.path.startswith('//')) and u.netloc == u.netloc.lower())
    except ValueError:
        return False


def _origin(value):
    if not _https(value):
        return None
    u = urlsplit(value)
    return u.scheme + '://' + u.netloc


def _b32(value):
    return 'sha256:' + base64.b32encode(hashlib.sha256(value).digest()).decode().rstrip('=')


def _fields(raw, required, context):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_HEADER and
         b'\r\n' in raw and b'\n' not in raw.replace(b'\r\n', b''),
         context + '_HEADER_SIZE_OR_CRLF_INVALID')
    lines = raw.split(b'\r\n')
    need(len(lines) == len(required) + 1, context + '_HEADER_COUNT_INVALID')
    result = {}
    for line in lines[1:]:
        need(b': ' in line and line.count(b': ') == 1 and
             not any(x < 32 or x > 126 for x in line) and
             not line.startswith((b' ', b'\t')),
             context + '_UNFOLDED_CANONICAL_ASCII_HEADER_REQUIRED')
        k, v = line.split(b': ', 1)
        try:
            key, value = k.decode('ascii'), v.decode('ascii')
        except UnicodeError as exc:
            raise errors.AnchorError('EC414_' + context + '_HEADER_NONASCII',
                                     'permission_denied') from exc
        need(key in required and key not in result and value != '' and
             value.strip() == value,
             context + '_UNKNOWN_DUPLICATE_OR_EMPTY_HEADER')
        result[key] = value
    need(set(result) == required, context + '_REQUIRED_HEADERS_MISSING')
    return lines[0], result


def _warc(raw, originals, urls, capture_utc, record_ids):
    """Strict WARC/1.1: exactly two RFC-compatible response records, DER bodies.

    WARC and HTTP asserted dates are source text, NOT a trusted wall clock.
    No gzip, redirects, chunked transport, hidden framing or extra records.
    """
    need(type(raw) is bytes and 0 < len(raw) <= MAX_WARC,
         'BOUNDED_TWO_RESPONSE_WARC_ORIGINAL_REQUIRED')
    offset, results = 0, {}
    warc_fields = {'WARC-Type', 'WARC-Target-URI', 'WARC-Date', 'WARC-Record-ID',
                   'Content-Type', 'Content-Length', 'WARC-Block-Digest',
                   'WARC-Payload-Digest'}
    http_fields = {'Content-Type', 'Content-Length', 'Date'}
    for role in ROLES:
        end = raw.find(b'\r\n\r\n', offset, offset + MAX_HEADER + 4)
        need(end > offset, 'WARC_HEADER_MISSING_OR_TOO_LONG')
        first, wh = _fields(raw[offset:end], warc_fields, 'WARC')
        need(first == b'WARC/1.1' and wh['WARC-Type'] == 'response' and
             wh['WARC-Target-URI'] == urls[role] and
             wh['WARC-Date'] == capture_utc and
             wh['Content-Type'] == 'application/http; msgtype=response',
             'WARC_RESPONSE_URI_DATE_AND_TYPE_MISMATCH')
        match = re.fullmatch(r'<urn:uuid:([0-9a-f-]{36})>', wh['WARC-Record-ID'])
        need(match is not None, 'WARC_CANONICAL_RECORD_ID_REQUIRED')
        try:
            u = UUID(match.group(1))
        except ValueError as exc:
            raise errors.AnchorError('EC414_WARC_INVALID_UUID',
                                     'permission_denied') from exc
        need(str(u) == match.group(1) and u.version == 4 and
             wh['WARC-Record-ID'] not in record_ids,
             'WARC_RECORD_ID_NONCANONICAL_OR_REPLAY')
        record_ids.add(wh['WARC-Record-ID'])
        length = wh['Content-Length']
        need(re.fullmatch(r'[1-9][0-9]{0,6}', length) is not None and
             0 < int(length) <= parent.MAX_OCSP + MAX_HEADER,
             'WARC_BLOCK_LENGTH_NOT_BOUNDED_CANONICAL')
        body_start = end + 4
        block = raw[body_start:body_start+int(length)]
        need(len(block) == int(length) and
             raw[body_start+int(length):body_start+int(length)+4] == b'\r\n\r\n' and
             wh['WARC-Block-Digest'] == _b32(block),
             'WARC_ACTUAL_HTTP_BLOCK_DIGEST_OR_FRAMING_MISMATCH')
        offset = body_start + int(length) + 4
        http_end = block.find(b'\r\n\r\n', 0, MAX_HEADER + 4)
        need(http_end > 0, 'WARC_HTTP_HEADER_MISSING')
        status, hh = _fields(block[:http_end], http_fields, 'HTTP')
        der = block[http_end+4:]
        need(status == b'HTTP/1.1 200 OK' and
             hh['Content-Type'] == 'application/ocsp-response' and
             re.fullmatch(r'[1-9][0-9]{0,6}', hh['Content-Length']) is not None and
             int(hh['Content-Length']) == len(der) and
             wh['WARC-Payload-Digest'] == _b32(der) and
             der == originals[role],
             'WARC_HTTP_200_OCSP_EXACT_ORIGINAL_DER_REQUIRED')
        try:
            dt = parsedate_to_datetime(hh['Date'])
            need(dt.tzinfo is not None and
                 format_datetime(dt, usegmt=True) == hh['Date'] and
                 dt.strftime('%Y-%m-%dT%H:%M:%SZ') == capture_utc,
                 'WARC_HTTP_DATE_NOT_CANONICAL_CAPTURE_UTC')
        except (ValueError, TypeError, OverflowError) as exc:
            raise errors.AnchorError('EC414_WARC_HTTP_DATE_INVALID',
                                     'permission_denied') from exc
        results[role] = {'original_ocsp_der_sha256': sha(der),
                         'https_target_uri': urls[role],
                         'warc_record_id': wh['WARC-Record-ID'],
                         'actual_http_200_ocsp_body_byte_equal': True}
    need(offset == len(raw), 'WARC_TRAILING_OR_EXTRA_RESPONSE_BYTES_DENIED')
    return results


def _receipt(value, key, who, identity, lineage, i, window, *, expected,
             previous, publisher_sha):
    exact(value, RECEIPT_FIELDS, 'SIGNED_OCSP_OBSERVATION')
    need(value['schema'] == RECEIPT_SCHEMA and
         type(value['signature_hex']) is str and
         SIGNATURE_HEX.fullmatch(value['signature_hex']) is not None,
         'ORIGINAL_ED25519_RECEIPT_SCHEMA_OR_SIGNATURE_INVALID')
    claim = value['claim']
    exact(claim, CLAIM_FIELDS, 'ORIGINAL_SIGNED_OBSERVATION_CLAIM')
    need(claim['schema'] == CLAIM_SCHEMA and
         claim['directory_lineage_id'] == lineage and
         type(claim['epoch_index']) is int and claim['epoch_index'] == i and
         claim['window'] == window and claim['witness_role'] == who and
         claim['witness_id'] == identity and
         type(claim['event_id']) is str and EVENT.fullmatch(claim['event_id']) is not None and
         claim['previous_role_receipt_sha256'] == previous and
         claim['publisher_receipt_sha256'] == publisher_sha and
         all(claim[k] == v for k, v in expected.items()),
         'SIGNED_WITNESS_CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')
    when = lotl.utc(claim['claimed_observation_utc'])
    try:
        key.verify(bytes.fromhex(value['signature_hex']), DOMAIN + canonical(claim))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise errors.AnchorError('EC414_TRUE_ED25519_OBSERVATION_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return when, claim['event_id']


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)   # UNMODIFIED REAL EC413 + every ancestor.
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = readers._readers()
    bundle_ref = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    p413_ref = {'path': opts[parent.NEW_SCALARS[0]],
                'sha256': opts[parent.NEW_SCALARS[1]]}
    original = doc(bundle_ref, 'ec414_original_signed_ocsp_publication_bundle', MAX_BUNDLE)
    exact(original, BUNDLE_FIELDS, 'OCSP_PUBLICATION_BUNDLE')
    need(original['schema'] == BUNDLE_SCHEMA and
         original['claimed_directory_lineage_id'] == lineage and
         original['parent_ec413_original_lotl_ocsp_bundle_original'] == p413_ref and
         type(original['epochs']) is list and len(original['epochs']) == n,
         'PUBLICATION_BUNDLE_NOT_BOUND_TO_REAL_EC413_AND_EPOCH_COUNT')
    old413 = doc(p413_ref, 'ec414_reopen_original_ec413_issuer_ocsp_bundle',
                 parent.MAX_BUNDLE)
    exact(old413, parent.BUNDLE_FIELDS, 'REOPEN_EC413_ORIGINAL_OCSP_BUNDLE')
    need(old413['schema'] == parent.BUNDLE_SCHEMA and
         old413['claimed_directory_lineage_id'] == lineage and
         len(old413['epochs']) == n,
         'REOPENED_EC413_ORIGINAL_SOURCE_LINEAGE_MISMATCH')
    roster_ref = lotl.ref(original['outside_publication_witness_roster_original'])
    need(roster_ref['sha256'] == opts[NEW_SCALARS[2]],
         'PUBLICATION_WITNESS_ROSTER_NOT_OUTSIDE_PINNED')
    roster = doc(roster_ref, 'ec414_outside_pinned_original_witness_roster',
                 MAX_ROSTER)
    exact(roster, ROSTER_FIELDS, 'PUBLICATION_WITNESS_ROSTER')
    need(roster['schema'] == ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage and
         _https(roster['https_origin'] + '/check') and
         _origin(roster['https_origin'] + '/check') == roster['https_origin'],
         'PINNED_HTTPS_PUBLICATION_ORIGIN_INVALID')
    old_lotl_ref = {'path': opts[lotl.NEW_SCALARS[0]],
                    'sha256': opts[lotl.NEW_SCALARS[1]]}
    old_lotl = doc(old_lotl_ref, 'ec414_reopen_original_ec410_signed_lotl_bundle',
                   lotl.MAX_BUNDLE)
    exact(old_lotl, lotl.BUNDLE_FIELDS, 'REAL_EC410_SIGNED_LOTL_BUNDLE')
    need(old_lotl['schema'] == lotl.BUNDLE_SCHEMA and
         old_lotl['claimed_directory_lineage_id'] == lineage and
         len(old_lotl['epochs']) == n,
         'REAL_EC410_SIGNED_LOTL_EPOCHS_NOT_BOUND')
    old_crl_ref = {'path': opts[parent.parent.NEW_SCALARS[0]],
                   'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    old_crl = doc(old_crl_ref, 'ec414_reopen_original_ec412_signed_crl_bundle',
                  parent.parent.MAX_BUNDLE)
    exact(old_crl, parent.parent.BUNDLE_FIELDS, 'REAL_EC412_ISSUER_CRL_BUNDLE')
    need(old_crl['schema'] == parent.parent.BUNDLE_SCHEMA and
         old_crl['claimed_directory_lineage_id'] == lineage and
         len(old_crl['epochs']) == n and
         old413['parent_ec412_original_lotl_crl_bundle_original'] == old_crl_ref,
         'EC413_MUST_REFERENCE_GENUINE_EC412_SIGNED_CRL_BUNDLE')
    # Reopen protected ancestors and forbid new source paths/digests aliasing
    # ANY of their actual original references, including sibling originals.
    protected_paths, protected_shas = set(), set()
    for value in (p413_ref, old_crl_ref, old_lotl_ref, bundle_ref, roster_ref,
                  old413, old_crl, old_lotl):
        parent._protected_refs(value, protected_paths, protected_shas)
    for key in PARENT_SCALARS:
        if key.endswith('_file') and type(opts[key]) is str:
            protected_paths.add(opts[key])
    keys, ids = {}, set()
    for who in WITNESSES:
        assignment = roster[who]
        exact(assignment, ROSTER_ROLE_FIELDS, 'EXTERNAL_' + who.upper())
        name = assignment['witness_id']
        need(type(name) is str and IDENT.fullmatch(name) is not None and
             name not in ids, 'TWO_DISTINCT_WITNESS_IDENTITIES_REQUIRED')
        ids.add(name)
        key_ref = lotl.ref(assignment['public_key_original'])
        pinned = opts[NEW_SCALARS[3 if who == 'publisher' else 4]]
        need(key_ref['sha256'] == pinned and
             key_ref['sha256'] not in protected_shas and
             key_ref['path'] not in protected_paths,
             'WITNESS_KEY_NOT_DISTINCT_OUTSIDE_PINNED_OR_ALIASES_ANCESTOR')
        key_bytes = read(key_ref, 'ec414_external_' + who + '_ed25519_key', 32)
        need(len(key_bytes) == 32, 'WITNESS_ED25519_RAW_PUBLIC_KEY_32_BYTES_REQUIRED')
        try:
            pub = Ed25519PublicKey.from_public_bytes(key_bytes)
        except ValueError as exc:
            raise errors.AnchorError('EC414_UNSUPPORTED_ED25519_PUBLIC_KEY',
                                     'permission_denied') from exc
        keys[who] = pub
        protected_paths.add(key_ref['path'])
        protected_shas.add(key_ref['sha256'])
    need(opts[NEW_SCALARS[3]] != opts[NEW_SCALARS[4]],
         'TWO_WITNESS_KEYS_NOT_DISTINCT')
    flags = {key: False for key in FLAGS}
    flags[FLAGS[0]] = (
        not live['bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'] or
        any(row['joint_original_issuer_ocsp_and_real_ec412_parent_publishers'] != 2
            for row in live['lotl_issuer_ocsp_epoch_reviews']))
    expected_first = {}
    prior_shas = {k: None for k in WITNESSES}
    prior_times = {k: None for k in WITNESSES}
    seen_event_ids, seen_warc_ids = set(), set()
    missing, records, reviews, total = False, [], [], 0
    for i, epoch in enumerate(original['epochs']):
        exact(epoch, EPOCH_FIELDS, 'ORIGINAL_PUBLICATION_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i,
             'PUBLICATION_EPOCH_INDEX_MISMATCH')
        old_epoch = old413['epochs'][i]
        old_xml = old_lotl['epochs'][i]
        exact(old_epoch, parent.EPOCH_FIELDS, 'REOPENED_EC413_EPOCH')
        exact(old_xml, lotl.EPOCH_FIELDS, 'REOPENED_EC410_EPOCH')
        windows, verified_count, time_count = {}, 0, 0
        for window in WINDOWS:
            item = epoch[window]
            if item is None:
                need(i > 0, 'FIRST_EPOCH_ORIGINAL_PUBLICATION_WINDOW_MISSING')
                missing = True
                flags[FLAGS[2]] = flags[FLAGS[4]] = True
                windows[window] = None
                continue
            exact(item, WINDOW_FIELDS, 'PUBLICATION_' + window.upper() + '_WINDOW')
            need(not missing and all(item[k] is not None for k in WINDOW_FIELDS),
                 'PARTIAL_OR_REAPPEARING_PUBLICATION_SOURCE_WINDOW')
            source_refs, source_bytes, status_times = {}, {}, {}
            for role in ROLES:
                source = lotl.ref(old_epoch[window + '_' + role + '_ca_ocsp_original'])
                raw = read(source, 'ec414_reopened_true_' + window + '_' + role +
                           '_signed_ocsp', parent.MAX_OCSP)
                # The mandatory real EC413 audited the actual issuer signature,
                # SHA256 CertID, status and this/next/producedAt first.
                response = ocsp.load_der_ocsp_response(raw)
                need(response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL,
                     'REOPENED_PARENT_SIGNED_OCSP_STATUS_NOT_SUCCESSFUL')
                one = next(iter(response.responses))
                source_refs[role] = source
                source_bytes[role] = raw
                status_times[role] = (response.produced_at_utc,
                                      one.this_update_utc, one.next_update_utc)
            xml_ref = lotl.ref(old_xml['original_' + window + '_signed_lotl_xml'])
            warc_ref = lotl.ref(item['original_two_ocsp_warc'])
            refs = {'warc': warc_ref}
            for who in WITNESSES:
                refs[who] = lotl.ref(item[who + '_signed_receipt_original'])
            for newref in refs.values():
                need(newref['path'] not in protected_paths and
                     newref['sha256'] not in protected_shas,
                     'WARC_OR_SIGNED_RECEIPT_ALIASES_ANY_PREVIOUS_ORIGINAL')
                protected_paths.add(newref['path'])
                protected_shas.add(newref['sha256'])
            receipt_docs = {
                who: doc(refs[who], 'ec414_' + window + '_' + who + '_real_ed25519_receipt',
                         MAX_RECEIPT)
                for who in WITNESSES}
            publisher_claim = receipt_docs['publisher'].get('claim')
            need(type(publisher_claim) is dict and
                 type(publisher_claim.get('https_publication_urls')) is dict and
                 set(publisher_claim['https_publication_urls']) == set(ROLES),
                 'PUBLISHER_MUST_SIGN_BOTH_EXACT_HTTPS_OCSP_URLS')
            urls = publisher_claim['https_publication_urls']
            need(all(_https(v) and _origin(v) == roster['https_origin']
                     for v in urls.values()) and urls['root'] != urls['intermediate'],
                 'PUBLISHER_HTTPS_OCSP_URLS_INVALID_OR_NOT_ROSTER_BOUND')
            pub_dt = lotl.utc(publisher_claim['claimed_observation_utc'])
            pub_utc = publisher_claim['claimed_observation_utc']
            warc_raw = read(warc_ref, 'ec414_two_actual_original_warc_ocsp_responses',
                            MAX_WARC)
            capture = _warc(warc_raw, source_bytes, urls, pub_utc, seen_warc_ids)
            expected = {
                'https_publication_urls': urls,
                'original_lotl_ocsp_bundle_sha256': p413_ref['sha256'],
                'original_signed_lotl_xml_sha256': xml_ref['sha256'],
                'original_two_ocsp_warc_sha256': warc_ref['sha256'],
                'original_ocsp_der_sha256s': {r: source_refs[r]['sha256'] for r in ROLES},
            }
            receipt_times = {}
            for who in WITNESSES:
                dt, event = _receipt(receipt_docs[who], keys[who], who,
                                     roster[who]['witness_id'], lineage, i,
                                     window, expected=expected,
                                     previous=prior_shas[who],
                                     publisher_sha=(refs['publisher']['sha256']
                                                    if who == 'observer' else None))
                need(event not in seen_event_ids,
                     'WITNESS_SIGNED_EVENT_ID_REPLAYED')
                seen_event_ids.add(event)
                receipt_times[who] = dt
                prior_shas[who] = refs[who]['sha256']
            covered = True
            for dt in receipt_times.values():
                for produced, this, nxt in status_times.values():
                    covered &= (produced - SKEW <= dt < nxt and
                                this <= dt and dt - produced <= MAX_OBSERVATION_DELAY)
            time_ok = bool(covered and
                           pub_dt - SKEW <= receipt_times['observer'] <=
                               pub_dt + OBSERVER_DELAY and
                           all(prior_times[who] is None or
                               receipt_times[who] > prior_times[who]
                               for who in WITNESSES))
            for who in WITNESSES:
                prior_times[who] = receipt_times[who]
            if not time_ok:
                flags[FLAGS[3]] = True
            verified_count += 2
            time_count += int(time_ok)
            if i == 0:
                expected_first[window] = {
                    'warc': warc_ref['sha256'],
                    **{who: refs[who]['sha256'] for who in WITNESSES}}
            windows[window] = {
                'original_two_response_warc_sha256': warc_ref['sha256'],
                'original_http_200_der_response_checks': capture,
                'two_distinct_valid_ed25519_signed_claims': True,
                'signed_claim_times_inside_true_issuer_ocsp_windows': time_ok,
                'publisher_claimed_observation_utc': pub_utc,
                'observer_claimed_observation_utc':
                    receipt_docs['observer']['claim']['claimed_observation_utc'],
                'signed_publisher_receipt_sha256': refs['publisher']['sha256'],
                'signed_observer_receipt_sha256': refs['observer']['sha256'],
            }
        parent_count = live['lotl_issuer_ocsp_epoch_reviews'][i][
            'joint_original_issuer_ocsp_and_real_ec412_parent_publishers']
        joint = (2 if verified_count == 4 and time_count == 2 and
                 parent_count == 2 and not flags[FLAGS[0]] else 0)
        if joint < 2:
            flags[FLAGS[4]] = True
        epoch_record = {
            'epoch_index': i, 'historical': windows['historical'],
            'evaluation': windows['evaluation'],
            'verified_http_200_original_ocsp_warc_response_count': verified_count,
            'verified_signed_witness_claim_time_window_count': time_count,
            'joint_original_publication_and_real_ec413_publisher_count': joint,
        }
        epoch_digest = digest(epoch_record)
        if epoch_digest != opts[REPEAT_NAMES[0]][i] or joint < opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]] = True
        reviews.append({
            'epoch_index': i,
            'verified_http_200_original_ocsp_warc_response_count': verified_count,
            'verified_signed_witness_claim_time_window_count': time_count,
            'joint_original_publication_and_real_ec413_publisher_count': joint,
            'original_publication_epoch_inventory_sha256': epoch_digest,
            'real_ec413_original_ocsp_parent_joint_publisher_count': parent_count,
        })
        records.append(epoch_record)
        total += joint
    need(len(expected_first) == 2,
         'FIRST_EPOCH_BOTH_GENUINE_WARC_AND_FOUR_SIGNED_RECEIPTS_REQUIRED')
    outside_first = {
        'historical': dict(zip(('warc', 'publisher', 'observer'),
                               (opts[NEW_SCALARS[5]], opts[NEW_SCALARS[7]],
                                opts[NEW_SCALARS[8]]))),
        'evaluation': dict(zip(('warc', 'publisher', 'observer'),
                               (opts[NEW_SCALARS[6]], opts[NEW_SCALARS[9]],
                                opts[NEW_SCALARS[10]]))),
    }
    if expected_first != outside_first:
        flags[FLAGS[1]] = True
    inventory = {
        'schema': INVENTORY_SCHEMA,
        'directory_lineage_id': lineage,
        'verified_real_ec413_original_report_sha256': live_sha,
        'verified_real_ec413_original_inventory_sha256':
            live['receiver_verified_lotl_issuer_ocsp_inventory_sha256'],
        'original_real_ec413_issuer_ocsp_bundle_sha256': p413_ref['sha256'],
        'outside_pinned_original_publication_roster_sha256': roster_ref['sha256'],
        'two_outside_pinned_ed25519_public_key_sha256s':
            [opts[NEW_SCALARS[3]], opts[NEW_SCALARS[4]]],
        'first_two_original_warc_and_four_signed_witness_receipt_sha256s':
            expected_first,
        'restricted_profile': 'TWO_STRICT_WARC11_HTTP200_DER_OCSP_AND_TWO_DOMAIN_SEPARATED_ED25519_SIGNED_CLAIMS',
        'epochs': records,
    }
    invsha = digest(inventory)
    if not deriving and invsha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # Explicit final source re-read; parent source bytes remain immutable.
    for path, (original_sha, size_limit) in late.items():
        raw = io._read({'path': path, 'sha256': original_sha},
                       'ec414_final_original_source_readback',
                       size_limit, {}, {}, set())
        need(sha(raw) == original_sha, 'SOURCE_CHANGED_AFTER_SIGNATURE_AUDIT')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {
        'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
        'command': ('derive-historical-ec339-lotl-ocsp-publication-inventory'
                    if deriving else 'audit-historical-ec339-lotl-ocsp-publication'),
        'status': next((OUTCOMES[i] for i, flag in enumerate(FLAGS) if flags[flag]),
                       OUTCOMES[-1]) + '_unresolved',
        'exit_code': 2, 'offline_unresolved_exit_code': 2,
        'verified_live_ec413_report_sha256': live_sha,
        'verified_live_ec413_inventory_sha256':
            live['receiver_verified_lotl_issuer_ocsp_inventory_sha256'],
        'original_ocsp_publication_bundle_sha256': bundle_ref['sha256'],
        'receiver_verified_ocsp_publication_inventory_sha256': invsha,
        'verified_joint_publication_and_real_ec413_publishers': total,
        'ocsp_publication_epoch_reviews': reviews,
        'bounded_dual_witness_original_publication_and_real_ec413_parent_consistency':
            not any(flags[k] for k in FLAGS[:5]),
        'sender_origin_path_required_or_read': False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
        **flags,
        **{key: False for key in NEGATIVES},
        **({'unsigned_ocsp_publication_inventory': inventory} if deriving else {}),
    }


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)

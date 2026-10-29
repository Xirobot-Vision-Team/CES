#!/usr/bin/env python3
"""EC404: strictly offline, read-only signed public-access capture receipts.

An independently SHA-pinned *claimed* archive key signs a compact canonical
receipt binding three complete raw HTTP response originals to the actual EC398
source, EC402 signed PDF, and EC403 XMLDSig original bytes.  The production
receiver ALWAYS executes the unchanged real EC403 -> EC402 -> ... ancestor
chain.  This is deliberately NOT an attestation of an actual network request,
a trusted time source, corporate independence, legal authorization or prior
availability.  No writer, network client, or certificate issuer lives here.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec399_official_certificate import protocol as x509core
from ec398_official_notice import protocol as gazette
from ec403_signed_xml import protocol as parent

RESULT_SCHEMA = 'ces.ec404.public_access_capture_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec404.unsigned_public_access_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec404.public_access_capture_denial.v1'
BUNDLE_SCHEMA = 'ces.ec404.original_public_access_bundle.v1'
ROSTER_SCHEMA = 'ces.ec404.externally_pinned_archive_roster.v1'
RECEIPT_SCHEMA = 'ces.ec404.original_signed_public_access_receipt.v1'
CLAIM_SCHEMA = 'ces.ec404.public_access_capture_claim.v1'
INVENTORY_SCHEMA = 'ces.ec404.unsigned_public_access_inventory.v1'
DOMAIN = b'CES/EC404/OriginalCapturedHTTPReceipt/Ed25519/v1\x00'
MAX_BUNDLE = 160_000
MAX_ROSTER = 16_000
MAX_RECEIPT = 32_000
MAX_HTTP_HEADER = 8192
MAX_HTTP_PDF = parent.parent.MAX_PDF + MAX_HTTP_HEADER
MAX_HTTP_XML = parent.MAX_XML + MAX_HTTP_HEADER
MAX_HTTP_SOURCE = gazette.MAX_SOURCE + MAX_HTTP_HEADER
CAPTURES = ('gazette', 'signed_pdf', 'signed_xml')
TYPES = {'gazette': 'application/octet-stream', 'signed_pdf': 'application/pdf',
         'signed_xml': 'application/xml'}
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS,
                  *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_public_access_bundle_file',
    'expected_historical_ec339_public_access_bundle_sha256',
    'expected_outside_retained_ec404_archive_roster_sha256',
    'expected_outside_retained_ec404_archive_a_key_sha256',
    'expected_outside_retained_ec404_archive_b_key_sha256',
    'expected_outside_retained_ec404_first_a_receipt_sha256',
    'expected_outside_retained_ec404_first_b_receipt_sha256',
    'expected_outside_ec404_dispute_cutoff_utc',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_public_access_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_public_access_epoch_inventory_shas',
     '--historical-ec339-public-access-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_public_access_publisher_counts',
     '--minimum-historical-ec339-joint-public-access-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec403_xmldsig_and_signed_pdf_chain_disputed',
    'external_archive_roster_first_original_epoch_or_whole_sha_or_floor_disagrees',
    'one_or_more_external_archive_receipt_originals_missing',
    'claimed_capture_not_before_outside_dispute_cutoff',
    'joint_archive_capture_and_real_ec403_parent_coverage_incomplete',
    'actual_external_public_download_or_separate_archive_control_not_proven',
    'legal_publication_authority_and_qualified_independent_time_not_proven',
    'actual_pre_dispute_prior_archive_global_revocation_worm_final_not_proven',
)
OUTCOMES = (
    'ec404_real_ec403_xml_pdf_and_deep_ancestors_disputed',
    'ec404_outside_archive_originals_or_count_constraints_disagree',
    'ec404_public_access_receipt_original_missing',
    'ec404_claimed_capture_later_than_outside_cutoff',
    'ec404_capture_and_real_parent_publisher_joint_coverage_incomplete',
    'ec404_actual_public_http_access_and_archivist_independence_not_proven',
    'ec404_legal_publication_and_independent_qualified_time_not_established',
    'ec404_prior_public_archive_worm_revocation_acceptance_not_established',
)
NEGATIVES = (
    'signed_capture_receipt_proves_an_actual_http_request_or_public_server_response',
    'outside_sha_pinned_archive_keys_prove_institutional_independence',
    'claim_of_capture_utc_proves_independent_qualified_pre_dispute_time',
    'signed_receipt_proves_official_government_or_court_authorization',
    'three_matching_http_response_bodies_prove_pdf_page_semantics',
    'custom_ed25519_json_receipt_is_a_standard_legal_notarization',
    'archive_receipts_repair_disputed_ec403_ec402_ocsp_crl_cms_parent',
    'two_archive_signatures_prove_global_public_fork_or_revocation_completeness',
    'receiver_generated_capture_keys_originals_signatures_or_time_proofs',
    'receiver_sent_network_requests_or_wrote_to_pdf_xml_ps1_git_ci_worm',
    'full_unmocked_history_native_ps7_smoke_or_final_acceptance_proven',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec403_original_xmldsig_bundle_original',
                 'outside_archive_roster_original', 'epochs'}
ROSTER_FIELDS = {'schema', 'claimed_directory_lineage_id', 'archives'}
ARCHIVE_FIELDS = {'publisher_id', 'archive_id', 'archive_public_key_original',
                  'allowed_public_origin'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
PUBLISHER_FIELDS = {'publisher_id', 'signed_archive_receipt_original', 'captures'}
CAPTURE_REF_FIELDS = {'kind', 'http_response_original'}
RECEIPT_FIELDS = {'schema', 'claim', 'signature_hex'}
CLAIM_FIELDS = {'schema', 'directory_lineage_id', 'publisher_id', 'archive_id',
                'epoch_index', 'sequence', 'previous_receipt_sha256',
                'claimed_capture_utc', 'source_original_sha256',
                'signed_pdf_original_sha256', 'signed_xml_original_sha256',
                'captures'}
CLAIM_CAPTURE_FIELDS = {'kind', 'public_url', 'http_response_sha256'}
DNS_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
ARCHIVE_ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')
URL_PATH = re.compile(r'/[A-Za-z0-9._~!$&\x27()*+,;=:@%/?-]{1,1023}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
HEX_SIG = re.compile(r'[0-9a-f]{128}\Z')


def need(yes, code, status='invalid_input'):
    if yes is not True:
        raise errors.AnchorError('EC404_' + code, status)


def exact(obj, fields, code):
    need(type(obj) is dict and set(obj) == fields,
         code + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(value):
    return parent.ref(value)


def cdigest(value):
    return parent.cdigest(value)


def _utc(value):
    try:
        result = x509core._utc(value)
        need(type(value) is str and value == result.isoformat().replace('+00:00', 'Z'),
             'NONCANONICAL_UTC', 'permission_denied')
        return result
    except errors.AnchorError:
        raise
    except (ValueError, TypeError, OverflowError, AttributeError) as exc:
        raise errors.AnchorError('EC404_INVALID_UTC', 'permission_denied') from exc


def _origin(value, *, only_origin):
    need(type(value) is str and 12 <= len(value) <= 1200 and value.isascii()
         and not any(ord(c) <= 32 or ord(c) == 127 or c == '\\' for c in value),
         'HTTPS_URL_ASCII_AND_LENGTH_REQUIRED', 'permission_denied')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise errors.AnchorError('EC404_INVALID_HTTPS_URL', 'permission_denied') from exc
    need(parsed.scheme == 'https' and parsed.username is None and
         parsed.password is None and not parsed.fragment and port in (None, 443) and
         host is not None and parsed.netloc == host and not parsed.query.startswith('#') and
         len(host) <= 253 and host == host.lower() and '.' in host and
         all(DNS_LABEL.fullmatch(label) for label in host.split('.')),
         'NONCANONICAL_PUBLIC_DNS_HTTPS_ORIGIN', 'permission_denied')
    base = 'https://' + host
    if only_origin:
        need(value == base and not parsed.path and not parsed.query,
             'EXPECTED_EXACT_PUBLIC_ORIGIN', 'permission_denied')
    else:
        path = parsed.path
        need(URL_PATH.fullmatch(path) is not None and
             '//' not in path and '/./' not in path and '/../' not in path and
             not path.endswith(('/.', '/..')) and
             '%' not in path and not parsed.query and value == base + path,
             'RESTRICTED_CANONICAL_CAPTURE_URL_REQUIRED', 'permission_denied')
    return base


def _inputs(opts, deriving):
    wanted = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        wanted.update(AUDIT_ONLY)
    need(set(opts) == wanted, 'INCOMPLETE_MANDATORY_REAL_EC403_AND_ARCHIVE_ARGUMENTS')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC404_PUBLIC_CAPTURE_BUNDLE')
    for k in (*NEW_SCALARS[2:7], *(() if deriving else AUDIT_ONLY)):
        need(x509core.valid_sha(opts[k]), 'EXTERNALLY_RETAINED_SHA_INVALID')
    need(len({opts[k] for k in NEW_SCALARS[3:7]}) == 4,
         'EXTERNAL_ARCHIVE_KEY_AND_FIRST_RECEIPT_SHAS_MUST_DIFFER',
         'permission_denied')
    _utc(opts[NEW_SCALARS[7]])
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_PARENT_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        vals = opts[k]
        need(type(vals) is list and len(vals) == n,
             'ARCHIVE_EPOCH_SHA_OR_FLOOR_MISSING')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in vals),
                 'ARCHIVE_JOINT_COUNT_FLOOR_INVALID')
        else:
            need(all(x509core.valid_sha(v) for v in vals),
                 'ARCHIVE_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code', 'offline_unresolved_exit_code',
              'verified_live_ec402_report_sha256', 'verified_live_ec402_inventory_sha256',
              'original_xmldsig_bundle_sha256',
              'receiver_verified_original_xmldsig_inventory_sha256',
              'verified_joint_parent_pdf_and_xmlsig_publishers',
              'original_xmldsig_epoch_reviews',
              'bounded_local_original_xmldsig_and_real_ec402_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    n = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-original-xmldsig' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_xmldsig_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_original_xmldsig_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(x509core.valid_sha(report.get(k)) for k in (
             'verified_live_ec402_report_sha256',
             'verified_live_ec402_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('bounded_local_original_xmldsig_and_real_ec402_parent_consistency') is
            (not any(report[k] for k in parent.FLAGS[:4])) and
         report.get('status') == next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
                                       if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'UNCHANGED_REAL_EC403_PARENT_CONTRACT_OR_SHA_MISMATCH', 'unavailable')
    rows = report.get('original_xmldsig_epoch_reviews')
    fields = {'epoch_index', 'actual_verified_xmlsig_count',
              'joint_verified_xmlsig_and_parent_pdf_count',
              'original_xmlsig_epoch_inventory_sha256',
              'real_ec402_parent_joint_pdf_ocsp_count'}
    need(type(rows) is list and len(rows) == n and all(
         type(r) is dict and set(r) == fields and
         type(r['epoch_index']) is int and r['epoch_index'] == i and
         type(r['actual_verified_xmlsig_count']) is int and
         0 <= r['actual_verified_xmlsig_count'] <= 2 and
         type(r['joint_verified_xmlsig_and_parent_pdf_count']) is int and
         0 <= r['joint_verified_xmlsig_and_parent_pdf_count'] <= r['actual_verified_xmlsig_count'] and
         type(r['real_ec402_parent_joint_pdf_ocsp_count']) is int and
         0 <= r['real_ec402_parent_joint_pdf_ocsp_count'] <= 2 and
         x509core.valid_sha(r['original_xmlsig_epoch_inventory_sha256'])
         for i, r in enumerate(rows)) and
         type(report.get('verified_joint_parent_pdf_and_xmlsig_publishers')) is int and
         report['verified_joint_parent_pdf_and_xmlsig_publishers'] == sum(
             r['joint_verified_xmlsig_and_parent_pdf_count'] for r in rows),
         'REAL_EC403_PARENT_EPOCH_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _http_response(raw, kind, original):
    """Accept a deliberately bounded, uncompressed HTTP/1.1 200 capture only.

    Header bytes are part of the signed raw-response SHA; no network is used.
    This cannot establish that a server actually sent these locally held bytes.
    """
    cut = raw.find(b'\r\n\r\n')
    need(0 < cut <= MAX_HTTP_HEADER and raw[:cut].startswith(b'HTTP/1.1 200 OK\r\n') and
         raw.count(b'\r\n\r\n') >= 1 and b'\x00' not in raw[:cut] and
         b'\n' not in raw[:cut].replace(b'\r\n', b''),
         'HTTP_RESPONSE_200_CRLF_HEAD_REQUIRED', 'permission_denied')
    header = raw[:cut].split(b'\r\n')
    need(3 <= len(header) <= 16 and header[0] == b'HTTP/1.1 200 OK',
         'HTTP_HEADER_COUNT_OR_STATUS_INVALID', 'permission_denied')
    headers = {}
    allowed = {'content-length', 'content-type', 'date', 'cache-control',
               'etag', 'last-modified', 'server'}
    for line in header[1:]:
        need(0 < len(line) <= 1024 and b':' in line and not line.startswith((b' ', b'\t')),
             'HTTP_FOLDED_OR_INVALID_HEADER', 'permission_denied')
        key, value = line.split(b':', 1)
        try:
            k = key.decode('ascii').lower()
            v = value.decode('ascii').strip(' ')
        except UnicodeDecodeError as exc:
            raise errors.AnchorError('EC404_NONASCII_HTTP_HEADER', 'permission_denied') from exc
        need(re.fullmatch('[a-z-]+', k) is not None and k in allowed and
             k not in headers and value.startswith(b' ') and
             v and all(32 <= ord(x) < 127 for x in v),
             'HTTP_DUPLICATE_UNKNOWN_OR_AMBIGUOUS_HEADER', 'permission_denied')
        headers[k] = v
    length = headers.get('content-length', '')
    need(re.fullmatch('(?:0|[1-9][0-9]{0,8})', length) is not None and
         headers.get('content-type') == TYPES[kind] and
         int(length) == len(raw) - cut - 4 and len(original) == int(length) and
         raw[cut+4:] == original,
         'HTTP_CAPTURE_BODY_OR_CONTENT_LENGTH_TYPE_MISMATCH', 'permission_denied')
    return {'http_original_sha256': sha(raw), 'content_original_sha256': sha(original),
            'content_length': len(original), 'content_type': TYPES[kind]}


def _signed_receipt(receipt_ref, claim_expected, public_key, doc):
    document = doc(receipt_ref, 'ec404_read_true_signed_capture_receipt', MAX_RECEIPT)
    exact(document, RECEIPT_FIELDS, 'ARCHIVE_RECEIPT')
    need(document['schema'] == RECEIPT_SCHEMA, 'ARCHIVE_RECEIPT_SCHEMA',
         'permission_denied')
    claim = document['claim']
    exact(claim, CLAIM_FIELDS, 'ARCHIVE_SIGNED_CLAIM')
    need(claim['schema'] == CLAIM_SCHEMA and
         all(claim.get(k) == v and type(claim.get(k)) is type(v)
             for k, v in claim_expected.items()) and
         type(claim['epoch_index']) is int and
         type(claim['sequence']) is int and
         claim['sequence'] == claim['epoch_index'] + 1 and
         type(claim['captures']) is list and len(claim['captures']) == 3 and
         type(document['signature_hex']) is str and
         HEX_SIG.fullmatch(document['signature_hex']) is not None,
         'ARCHIVE_SIGNED_ORIGINAL_CLAIM_OR_SEQUENCE_INVALID', 'permission_denied')
    wire = DOMAIN + json.dumps(claim, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False).encode('ascii')
    try:
        public_key.verify(bytes.fromhex(document['signature_hex']), wire)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise errors.AnchorError('EC404_ARCHIVE_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return claim


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # always real in production
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = parent.parent.parent.parent.parent.parent.parent.parent.parent.prior._readers()
    b404 = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b403 = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    b402 = {'path': opts[parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    b398 = {'path': opts[gazette.NEW_SCALARS[0]],
            'sha256': opts[gazette.NEW_SCALARS[1]]}
    bundle = doc(b404, 'ec404_original_public_access_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'ARCHIVE_BUNDLE')
    roster_ref = ref(bundle['outside_archive_roster_original'])
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec403_original_xmldsig_bundle_original'] == b403 and
         roster_ref['sha256'] == opts[NEW_SCALARS[2]] and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'ARCHIVE_BUNDLE_OR_EXTERNAL_ROSTER_OR_REAL_PARENT_LINK_INVALID',
         'permission_denied')
    p403 = doc(b403, 'ec404_reopen_unchanged_ec403_xml_bundle', parent.MAX_BUNDLE)
    p402 = doc(b402, 'ec404_reopen_unchanged_ec402_pdf_bundle', parent.parent.MAX_BUNDLE)
    p398 = doc(b398, 'ec404_reopen_unchanged_ec398_gazette_bundle', gazette.MAX_BUNDLE)
    for payload, fields, schema in (
        (p403, parent.BUNDLE_FIELDS, parent.BUNDLE_SCHEMA),
        (p402, parent.parent.BUNDLE_FIELDS, parent.parent.BUNDLE_SCHEMA),
        (p398, gazette.BUNDLE_FIELDS, gazette.BUNDLE_SCHEMA),
    ):
        exact(payload, fields, 'AUTHENTIC_INHERITED_BUNDLE')
        need(payload['schema'] == schema and
             payload['claimed_directory_lineage_id'] == lineage and
             len(payload['epochs']) == n,
             'REAL_PARENT_BUNDLE_EPOCH_OR_LINEAGE_INVALID', 'permission_denied')
    need(p403['parent_ec402_signed_pdf_bundle_original'] == b402,
         'EC403_TO_EC402_AUTHENTIC_PARENT_SHA_LINK_INVALID', 'permission_denied')
    # The unchanged true EC403 audit already checked EC398->EC402, but the
    # readback below additionally binds the *actual* independently held source.
    roster = doc(roster_ref, 'ec404_reopen_outside_archive_roster', MAX_ROSTER)
    exact(roster, ROSTER_FIELDS, 'ARCHIVE_ROSTER')
    need(roster['schema'] == ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage and
         type(roster['archives']) is list and len(roster['archives']) == 2,
         'TWO_OUTSIDE_ARCHIVE_KEYS_REQUIRED', 'permission_denied')
    # EC399 has the actual original publisher keys. Enforce archive keys do
    # not alias any of those authentic original leaf signer public keys.
    p399ref = {
        'path': opts[x509core.NEW_SCALARS[0]], 'sha256': opts[x509core.NEW_SCALARS[1]]}
    p399 = doc(p399ref, 'ec404_reopen_real_ec399_x509_bundle', x509core.MAX_BUNDLE)
    exact(p399, x509core.BUNDLE_FIELDS, 'EC399_CERT_BUNDLE')
    need(p399['schema'] == x509core.BUNDLE_SCHEMA and
         p399['claimed_directory_lineage_id'] == lineage and
         p399['parent_ec398_external_notice_bundle_original'] == b398,
         'REAL_EC399_AND_EC398_SOURCE_LINK_REQUIRED', 'permission_denied')
    r399 = ref(p399['outside_publisher_roster_original'])
    publisher_roster = doc(r399, 'ec404_real_ec399_publisher_roster', x509core.MAX_ROSTER)
    exact(publisher_roster, x509core.ROSTER_FIELDS, 'TRUE_PUBLISHER_ROSTER')
    need(publisher_roster['schema'] == x509core.ROSTER_SCHEMA and
         r399['sha256'] == opts[x509core.NEW_SCALARS[2]] and
         len(publisher_roster['publishers']) == 2,
         'TRUE_PARENT_PUBLISHER_ROSTER_INCONSISTENT', 'permission_denied')
    ids = sorted(entry['publisher_id'] for entry in publisher_roster['publishers'])
    need(len(set(ids)) == 2, 'TRUE_PUBLISHERS_NOT_DISTINCT', 'permission_denied')
    publisher_keys = set()
    for entry in publisher_roster['publishers']:
        chain = x509core._chain(entry, opts, read)
        pub = chain['certs'][0].public_key()
        if isinstance(pub, Ed25519PublicKey):
            publisher_keys.add(pub.public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw))
    # Include every nested original from the immediate signed parent bundles
    # and the independently maintained EC395..EC401 ancestors.  The EC403
    # production audit already verified these originals; reopening them here
    # prevents capture or archive-key labels from reusing their source paths.
    p401ref = ref(p402['parent_ec401_issuer_ocsp_bundle_original'])
    p401 = doc(p401ref, 'ec404_reopen_real_ec401_ocsp', parent.parent.parent.MAX_BUNDLE)
    p400ref = ref(p401['parent_ec400_native_cms_bundle_original'])
    p400 = doc(p400ref, 'ec404_reopen_real_ec400_cms',
               parent.parent.parent.parent.MAX_BUNDLE)
    p397ref = ref(p398['parent_ec397_publication_bundle_original'])
    p397 = doc(p397ref, 'ec404_reopen_real_ec397_publication', gazette.parent.MAX_BUNDLE)
    p396ref = ref(p397['parent_ec396_public_integrity_bundle_original'])
    p396 = doc(p396ref, 'ec404_reopen_real_ec396_public_integrity',
               gazette.parent.parent.MAX_BUNDLE)
    p395ref = ref(p396['parent_ec395_credential_gossip_bundle_original'])
    p395 = doc(p395ref, 'ec404_reopen_real_ec395_gossip',
               gazette.parent.parent.parent.MAX_BUNDLE)
    need(p403['parent_ec402_signed_pdf_bundle_original'] == b402 and
         p402['parent_ec401_issuer_ocsp_bundle_original'] == p401ref and
         p401['parent_ec400_native_cms_bundle_original'] == p400ref and
         p400['parent_ec399_official_certificate_bundle_original'] == p399ref and
         p399['parent_ec398_external_notice_bundle_original'] == b398,
         'REOPENED_ORIGINAL_PARENT_CHAIN_MUST_BE_UNCHANGED',
         'permission_denied')
    protected = {b['path'] for b in (b404, b403, b402, b398, p399ref,
                                    p400ref, p401ref, p397ref, p396ref, p395ref,
                                    roster_ref, r399)}
    for item in (p403, p402, p401, p400, p399, p398, p397, p396, p395,
                 publisher_roster):
        gazette._collect_sources(item, protected)
    used = set(protected)
    archives = {}
    archive_keys = set()
    archive_ids = set()
    for row in roster['archives']:
        exact(row, ARCHIVE_FIELDS, 'ARCHIVE_ROLE')
        role = row['publisher_id']
        need(type(role) is str and role in ids and role not in archives and
             type(row['archive_id']) is str and
             ARCHIVE_ID.fullmatch(row['archive_id']) is not None and
             row['archive_id'] not in archive_ids,
             'DISTINCT_OUTSIDE_ARCHIVE_ROLE_AND_ID_REQUIRED', 'permission_denied')
        _origin(row['allowed_public_origin'], only_origin=True)
        key_ref = ref(row['archive_public_key_original'])
        need(key_ref['path'] not in used and
             key_ref['sha256'] == opts[NEW_SCALARS[3 if role == ids[0] else 4]],
             'EXTERNALLY_PINNED_ARCHIVE_KEY_MISMATCH_OR_ALIASED',
             'permission_denied')
        key_bytes = read(key_ref, 'ec404_external_archive_ed25519_public_key', 32)
        need(len(key_bytes) == 32 and key_bytes not in archive_keys and
             key_bytes not in publisher_keys,
             'ARCHIVE_KEY_MUST_DIFFER_FROM_OTHER_ARCHIVE_AND_PUBLISHERS',
             'permission_denied')
        try:
            key = Ed25519PublicKey.from_public_bytes(key_bytes)
        except ValueError as exc:
            raise errors.AnchorError('EC404_INVALID_ARCHIVE_ED25519_KEY',
                                     'permission_denied') from exc
        used.add(key_ref['path'])
        archive_keys.add(key_bytes)
        archive_ids.add(row['archive_id'])
        archives[role] = (row, key)
    need(set(archives) == set(ids), 'ARCHIVES_NOT_BOUND_TO_TRUE_TWO_PUBLISHERS',
         'permission_denied')
    flags = {k: False for k in FLAGS}
    flags[FLAGS[0]] = (
        not live['bounded_local_original_xmldsig_and_real_ec402_parent_consistency'] or
        any(r['joint_verified_xmlsig_and_parent_pdf_count'] != 2
            for r in live['original_xmldsig_epoch_reviews']))
    cutoff = _utc(opts[NEW_SCALARS[7]])
    first, previous, seen_times, reviews, epoch_rows = {}, {}, {}, [], []
    joint_total = 0
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, EPOCH_FIELDS, 'ARCHIVE_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i and
             type(epoch['publishers']) is list and len(epoch['publishers']) == 2,
             'ARCHIVE_EXACTLY_TWO_PUBLISHERS_PER_EPOCH', 'permission_denied')
        # Each epoch uses the *same actual EC398 source*, with distinct real
        # authentic EC402+EC403 publisher originals.
        srce = p398['epochs'][i]
        exact(srce, gazette.EPOCH_FIELDS, 'EC398_EPOCH')
        need(type(srce['epoch_index']) is int and srce['epoch_index'] == i,
             'EC398_REAL_SOURCE_EPOCH_INVALID', 'permission_denied')
        source_ref = ref(srce['source_notice_original'])
        real_source = read(source_ref, 'ec404_true_ec398_source', gazette.MAX_SOURCE)
        notice_ref = ref(srce['notice']['signed_original'])
        _, signed_stamp, sig = gazette._signed(
            notice_ref, read, gazette.NOTICE_SCHEMA, gazette.NOTICE_CLAIM,
            gazette.NOTICE_CLAIM_FIELDS, 'EC404_REAL_EC398_REGISTRAR_NOTICE')
        nr = ref(p398['outside_notice_roster_original'])
        notice_roster = doc(nr, 'ec404_real_registrar_roster', gazette.MAX_ROSTER)
        exact(notice_roster, gazette.ROSTER_FIELDS, 'EC398_REGISTRAR_ROSTER')
        gazette._sign(notice_roster['registrar'], sig, gazette.NOTICE_DOMAIN,
                      signed_stamp, 'EC404_REVERIFY_GENUINE_EC398_NOTICE')
        need(signed_stamp.get('source_notice_original_sha256') == source_ref['sha256'] and
             signed_stamp.get('epoch_index') == i and
             signed_stamp.get('directory_lineage_id') == lineage,
             'PARENT_GENUINE_SIGNED_PUBLISH_UTC_LINK_REQUIRED',
             'permission_denied')
        published = _utc(signed_stamp['claimed_published_utc'])
        roles_xml, roles_pdf = {}, {}
        xml_epoch, pdf_epoch = p403['epochs'][i], p402['epochs'][i]
        exact(xml_epoch, parent.EPOCH_FIELDS, 'EC403_XML_EPOCH')
        exact(pdf_epoch, parent.parent.EPOCH_FIELDS, 'EC402_PDF_EPOCH')
        need(xml_epoch['epoch_index'] == pdf_epoch['epoch_index'] == i and
             len(xml_epoch['publishers']) == len(pdf_epoch['publishers']) == 2,
             'PARENT_EPOCH_ROLE_COUNT_INVALID', 'permission_denied')
        for xr in xml_epoch['publishers']:
            exact(xr, parent.ROLE_FIELDS, 'REAL_XML_PUBLISHER')
            need(xr['publisher_id'] in ids and xr['publisher_id'] not in roles_xml,
                 'REAL_PARENT_XML_PUBLISHER_ALIASED', 'permission_denied')
            roles_xml[xr['publisher_id']] = (ref(xr['signed_xml_original'])
                                               if xr['signed_xml_original'] else None)
        for pr in pdf_epoch['publishers']:
            exact(pr, parent.parent.PUBLISHER_FIELDS, 'REAL_PDF_PUBLISHER')
            need(pr['publisher_id'] in ids and pr['publisher_id'] not in roles_pdf,
                 'REAL_PARENT_PDF_PUBLISHER_ALIASED', 'permission_denied')
            roles_pdf[pr['publisher_id']] = (ref(pr['signed_pdf_original'])
                                               if pr['signed_pdf_original'] else None)
        need(set(roles_xml) == set(ids) and set(roles_pdf) == set(ids),
             'REAL_XML_AND_PDF_PARENT_ROLE_COVERAGE_INVALID', 'permission_denied')
        members, verified, captured_before_cutoff, seen = [], 0, 0, set()
        for row in epoch['publishers']:
            exact(row, PUBLISHER_FIELDS, 'ARCHIVE_PUBLISHER')
            role = row['publisher_id']
            need(type(role) is str and role in ids and role not in seen,
                 'REPEATED_ARCHIVE_PUBLISHER_ID', 'permission_denied')
            seen.add(role)
            receipt_ref = (ref(row['signed_archive_receipt_original'])
                           if row['signed_archive_receipt_original'] else None)
            if receipt_ref is None:
                need(i != 0 and row['captures'] == [],
                     'FIRST_ORIGINAL_RECEIPT_MANDATORY_AND_NO_ORPHAN_CAPTURES',
                     'permission_denied')
                flags[FLAGS[2]] = True
                members.append({'publisher_id': role,
                                'archive_receipt_original_sha256': None,
                                'verified_three_original_http_captures': None,
                                'claimed_capture_before_outside_cutoff': None})
                continue
            need(receipt_ref['path'] not in used and
                 roles_xml[role] is not None and roles_pdf[role] is not None,
                 'RECEIPT_ALIASES_PRIOR_SOURCE_OR_PARENT_MISSING',
                 'permission_denied')
            used.add(receipt_ref['path'])
            archive, key = archives[role]
            expected = {'directory_lineage_id': lineage, 'publisher_id': role,
                        'archive_id': archive['archive_id'], 'epoch_index': i,
                        'sequence': i+1,
                        'previous_receipt_sha256': previous.get(role)}
            claim = _signed_receipt(receipt_ref, expected, key, doc)
            captured = _utc(claim['claimed_capture_utc'])
            need(captured >= published and
                 (role not in seen_times or captured > seen_times[role]) and
                 claim['source_original_sha256'] == source_ref['sha256'] and
                 claim['signed_pdf_original_sha256'] == roles_pdf[role]['sha256'] and
                 claim['signed_xml_original_sha256'] == roles_xml[role]['sha256'],
                 'SIGNED_RECEIPT_CHRONOLOGY_OR_TRUE_PARENT_SHA_MISMATCH',
                 'permission_denied')
            need(type(row['captures']) is list and len(row['captures']) == 3,
                 'THREE_ORIGINAL_CAPTURE_REFERENCES_REQUIRED', 'permission_denied')
            cap_refs = {}
            for item in row['captures']:
                exact(item, CAPTURE_REF_FIELDS, 'HTTP_ORIGINAL_CAPTURE_REF')
                kind = item['kind']
                need(type(kind) is str and kind in CAPTURES and kind not in cap_refs,
                     'CAPTURE_KIND_REPEATED_OR_UNKNOWN', 'permission_denied')
                capture_ref = ref(item['http_response_original'])
                need(capture_ref['path'] not in used,
                     'CAPTURE_ORIGINAL_ALIASES_OLDER_OR_OTHER_CAPTURE',
                     'permission_denied')
                used.add(capture_ref['path'])
                cap_refs[kind] = capture_ref
            need(set(cap_refs) == set(CAPTURES), 'THREE_KINDS_OF_CAPTURE_REQUIRED',
                 'permission_denied')
            originals = {'gazette': (real_source, source_ref['sha256']),
                         'signed_pdf': (read(roles_pdf[role], 'ec404_actual_pdf',
                                             parent.parent.MAX_PDF), roles_pdf[role]['sha256']),
                         'signed_xml': (read(roles_xml[role], 'ec404_actual_xml',
                                             parent.MAX_XML), roles_xml[role]['sha256'])}
            used_urls, verified_rows = set(), []
            for expected_kind, row_claim in zip(CAPTURES, claim['captures']):
                exact(row_claim, CLAIM_CAPTURE_FIELDS, 'SIGNED_HTTP_CAPTURE_CLAIM')
                need(row_claim['kind'] == expected_kind,
                     'SIGNED_CAPTURE_ORDER_MUST_BE_GAZETTE_PDF_XML',
                     'permission_denied')
                url = row_claim['public_url']
                need(_origin(url, only_origin=False) == archive['allowed_public_origin'] and
                     url not in used_urls and
                     row_claim['http_response_sha256'] == cap_refs[expected_kind]['sha256'],
                     'PUBLIC_URL_OR_TRUE_HTTP_SHA_NOT_SIGNED_AS_EXPECTED',
                     'permission_denied')
                used_urls.add(url)
                maximum = {'gazette': MAX_HTTP_SOURCE, 'signed_pdf': MAX_HTTP_PDF,
                           'signed_xml': MAX_HTTP_XML}[expected_kind]
                raw = read(cap_refs[expected_kind], 'ec404_original_http_' + expected_kind,
                           maximum)
                check = _http_response(raw, expected_kind, originals[expected_kind][0])
                need(check['content_original_sha256'] == originals[expected_kind][1],
                     'HTTP_RESPONSE_BODY_DIFFERS_FROM_TRUE_EC398_EC402_EC403_ORIGINAL',
                     'permission_denied')
                verified_rows.append({'kind': expected_kind, 'public_url': url,
                                      'captured_original_http_sha256': cap_refs[expected_kind]['sha256'],
                                      'body_original_sha256': check['content_original_sha256']})
            previous[role] = receipt_ref['sha256']
            seen_times[role] = captured
            before = captured <= cutoff
            if not before:
                flags[FLAGS[3]] = True
            else:
                captured_before_cutoff += 1
            verified += 1
            if i == 0:
                first[role] = receipt_ref['sha256']
            members.append({'publisher_id': role,
                            'archive_receipt_original_sha256': receipt_ref['sha256'],
                            'verified_three_original_http_captures': verified_rows,
                            'claimed_capture_before_outside_cutoff': before})
        need(seen == set(ids), 'TWO_ARCHIVE_ROLE_COVERAGE_REQUIRED',
             'permission_denied')
        members.sort(key=lambda r: r['publisher_id'])
        joint = (captured_before_cutoff if
                 live['bounded_local_original_xmldsig_and_real_ec402_parent_consistency'] and
                 live['original_xmldsig_epoch_reviews'][i][
                     'joint_verified_xmlsig_and_parent_pdf_count'] == 2 else 0)
        if joint != 2:
            flags[FLAGS[4]] = True
        inv = {'epoch_index': i, 'publishers': members,
               'actual_verified_archive_receipt_count': verified,
               'claimed_before_cutoff_count': captured_before_cutoff,
               'joint_verified_archive_and_parent_count': joint}
        digest = cdigest(inv)
        if digest != opts[REPEAT_NAMES[0]][i] or joint < opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]] = True
        epoch_rows.append(inv)
        reviews.append({'epoch_index': i, 'actual_verified_archive_receipt_count': verified,
                        'claimed_before_cutoff_count': captured_before_cutoff,
                        'joint_verified_archive_and_parent_count': joint,
                        'public_access_epoch_inventory_sha256': digest,
                        'real_ec403_parent_joint_xml_pdf_count': live[
                            'original_xmldsig_epoch_reviews'][i][
                                'joint_verified_xmlsig_and_parent_pdf_count']})
        joint_total += joint
    need(len(first) == 2 and all(first.get(role) for role in ids),
         'TWO_FIRST_EXTERNALLY_PINNED_GENUINE_RECEIPTS_REQUIRED',
         'permission_denied')
    if [first[role] for role in ids] != [opts[NEW_SCALARS[5]], opts[NEW_SCALARS[6]]]:
        flags[FLAGS[1]] = True
    inventory = {'schema': INVENTORY_SCHEMA, 'directory_lineage_id': lineage,
                 'verified_real_ec403_report_sha256': live_sha,
                 'verified_real_ec403_inventory_sha256': live[
                     'receiver_verified_original_xmldsig_inventory_sha256'],
                 'original_ec403_bundle_sha256': b403['sha256'],
                 'original_public_access_bundle_sha256': b404['sha256'],
                 'outside_archive_roster_sha256': roster_ref['sha256'],
                 'outside_claimed_dispute_cutoff_utc': opts[NEW_SCALARS[7]],
                 'outside_first_original_receipt_shas': [opts[NEW_SCALARS[5]],
                                                         opts[NEW_SCALARS[6]]],
                 'epochs': epoch_rows}
    inv_sha = cdigest(inventory)
    if not deriving and inv_sha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # Reopen every actually read new AND genuine parent original by exact SHA
    # immediately before completing the bounded local result.
    for path, (digest, cap) in late.items():
        content = io._read({'path': path, 'sha256': digest},
                           'ec404_final_original_byte_reread', cap, {}, {}, set())
        need(sha(content) == digest, 'ORIGINAL_CHANGED_DURING_AUDIT',
             'permission_denied')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': ('derive-historical-ec339-public-access-inventory'
                        if deriving else 'audit-historical-ec339-public-access'),
            'status': next((OUTCOMES[i] for i, k in enumerate(FLAGS) if flags[k]),
                           OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec403_report_sha256': live_sha,
            'verified_live_ec403_inventory_sha256': live[
                'receiver_verified_original_xmldsig_inventory_sha256'],
            'original_public_access_bundle_sha256': b404['sha256'],
            'receiver_verified_public_access_inventory_sha256': inv_sha,
            'verified_joint_archive_and_real_parent_publishers': joint_total,
            'public_access_epoch_reviews': reviews,
            'bounded_local_public_access_and_real_ec403_parent_consistency':
                not any(flags[k] for k in FLAGS[:5]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{k: False for k in NEGATIVES},
            **({'unsigned_public_access_evidence_inventory': inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)

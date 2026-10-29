#!/usr/bin/env python3
"""EC413: offline original issuer-direct RFC6960 OCSP for EC412 LOTL CA chain.

This verifies SHA-pinned actual DER OCSP signatures and historical/evaluation
certificate statuses, not real-world official accreditation, independently
witnessed historical public availability, qualified time or global revocation.
Production first executes the UNMODIFIED EC412 -> EC411 -> ... original audit.
No network, signing, certificate issuance, source edits or positive PASS.
"""
from __future__ import annotations

from datetime import timedelta
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec412_lotl_crl import protocol as parent

lotl = parent.lotl
xades = parent.parent
cms = parent.cms

RESULT_SCHEMA = 'ces.ec413.original_lotl_ca_ocsp_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec413.unsigned_lotl_ca_ocsp_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec413.lotl_ca_ocsp_denial.v1'
BUNDLE_SCHEMA = 'ces.ec413.original_lotl_ca_ocsp_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec413.unsigned_lotl_ca_ocsp_inventory.v1'

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_lotl_ocsp_bundle_file',
    'expected_historical_ec339_lotl_ocsp_bundle_sha256',
    'expected_outside_ec413_first_historical_root_ocsp_sha256',
    'expected_outside_ec413_first_historical_intermediate_ocsp_sha256',
    'expected_outside_ec413_first_evaluation_root_ocsp_sha256',
    'expected_outside_ec413_first_evaluation_intermediate_ocsp_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_lotl_ocsp_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_lotl_ocsp_epoch_inventory_shas',
     '--historical-ec339-lotl-ocsp-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_lotl_ocsp_publisher_counts',
     '--minimum-historical-ec339-joint-lotl-ocsp-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
WINDOWS = ('historical', 'evaluation')
ROLES = ('root', 'intermediate')
FLAGS = (
    'inherited_real_ec412_and_older_original_ancestry_adverse',
    'outside_original_lotl_ocsp_first_epoch_or_retained_pin_disagrees',
    'one_or_more_later_original_lotl_ocsp_sets_missing',
    'genuine_issuer_ocsp_reports_revoked_or_unknown_lotl_certificate',
    'original_issuer_ocsp_signed_time_window_or_freshness_incomplete',
    'verified_issuer_ocsp_and_real_ec412_parent_joint_coverage_incomplete',
    'independent_official_lotl_ca_root_and_ocsp_responder_authorization_unproven',
    'real_historical_public_ocsp_delivery_qualified_time_and_global_status_unproven',
    'full_unmocked_external_originals_native_worm_and_acceptance_unproven',
)
OUTCOMES = (
    'ec413_inherited_real_ec412_or_older_originals_adverse',
    'ec413_outside_original_lotl_ocsp_inventory_pins_disagree',
    'ec413_later_original_issuer_ocsp_sources_missing',
    'ec413_genuine_issuer_ocsp_lotl_certificate_adverse_status',
    'ec413_signed_ocsp_historical_evaluation_freshness_incomplete',
    'ec413_joint_original_ocsp_and_real_ec412_parent_coverage_incomplete',
    'ec413_actual_official_ca_and_responder_authority_unproven',
    'ec413_public_ocsp_source_history_and_exhaustive_status_unproven',
    'ec413_unmocked_original_history_native_and_final_acceptance_unproven',
)
NEGATIVES = (
    'issuer_direct_signed_ocsp_or_sha_pin_proves_official_commission_accreditation',
    'signed_original_ocsp_proves_real_independent_historical_public_distribution',
    'ocsp_producedat_is_an_independent_qualified_tsa_timestamp',
    'issuer_ocsp_good_overrides_adverse_parent_crl_or_signed_lotl',
    'single_ca_ocsp_good_establishes_global_exhaustive_revocation_status',
    'issuer_direct_ocsp_verification_implicitly_trusts_delegated_responder',
    'valid_crypto_establishes_full_etsi_eidas_or_legal_pass',
    'receiver_signed_ocsp_issued_ca_certs_or_used_private_issuer_keys',
    'receiver_fetched_ocsp_urls_or_changed_business_original_source_files',
    'receiver_ran_real_external_unmocked_history_worm_native_or_final_acceptance',
)
BUNDLE_FIELDS = {
    'schema', 'claimed_directory_lineage_id',
    'parent_ec412_original_lotl_crl_bundle_original', 'epochs',
}
EPOCH_FIELDS = {
    'epoch_index',
    'historical_root_ca_ocsp_original',
    'historical_intermediate_ca_ocsp_original',
    'evaluation_root_ca_ocsp_original',
    'evaluation_intermediate_ca_ocsp_original',
}
MAX_BUNDLE = 140_000
MAX_OCSP = 2_000_000
SKEW = timedelta(minutes=5)
MAX_LIFETIME = timedelta(days=14)
MAX_PRODUCED_AGE = timedelta(days=7)


def need(cond, code, status='permission_denied'):
    if cond is not True:
        raise errors.AnchorError('EC413_' + code, status)


def exact(obj, fields, context):
    need(type(obj) is dict and set(obj) == fields, context + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return parent.digest(value)


def _inputs(opts, deriving):
    required = {*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES}
    if not deriving:
        required.update(AUDIT_ONLY)
    need(set(opts) == required, 'EXACT_PARENT_EC412_AND_OCSP_ARGUMENT_CONTRACT',
         'invalid_input')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    # Derive must also have an independently pinned complete EC412 audit.
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC413_ORIGINAL_LOTL_OCSP_BUNDLE')
    for key in (*NEW_SCALARS[2:], *((AUDIT_ONLY) if not deriving else ())):
        need(lotl.good_sha(opts[key]), 'INDEPENDENT_ORIGINAL_OCSP_SHA_REQUIRED',
             'invalid_input')
    need(len({opts[k] for k in NEW_SCALARS[2:]}) == 4,
         'FOUR_DISTINCT_FIRST_ISSUER_OCSP_OUTSIDE_PINS_REQUIRED', 'invalid_input')
    count = len(opts['historical_directory_root_shas'])
    need(1 <= count <= 3, 'ONE_TO_THREE_REAL_PARENT_SOURCE_EPOCHS', 'invalid_input')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == count,
             'ONE_OCSP_PIN_AND_JOINT_FLOOR_PER_SOURCE_EPOCH', 'invalid_input')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'OCSP_JOINT_SOURCE_PUBLISHER_FLOOR_OUT_OF_RANGE', 'invalid_input')
        else:
            need(all(lotl.good_sha(v) for v in values),
                 'OCSP_EPOCH_INVENTORY_SHA_REQUIRED', 'invalid_input')
    return inherited


def _parent_report(report, opts):
    fields = {
        'schema', 'command', 'status', 'exit_code', 'offline_unresolved_exit_code',
        'verified_live_ec411_report_sha256',
        'verified_live_ec411_inventory_sha256',
        'original_lotl_ca_crl_bundle_sha256',
        'receiver_verified_lotl_ca_crl_inventory_sha256',
        'verified_joint_crl_and_real_ec411_parent_publishers',
        'lotl_ca_crl_epoch_reviews',
        'bounded_original_ca_crl_and_real_ec411_parent_consistency',
        'sender_origin_path_required_or_read',
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
        *parent.FLAGS, *parent.NEGATIVES,
    }
    rows = report.get('lotl_ca_crl_epoch_reviews') if type(report) is dict else None
    row_fields = {
        'epoch_index',
        'verified_original_ca_crl_historical_evaluation_four_documents',
        'joint_genuine_crl_and_real_ec411_parent_publisher_count',
        'lotl_ca_crl_epoch_inventory_sha256',
        'genuine_ec411_parent_xades_v2_joint_publisher_count',
    }
    n = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-lotl-crl' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('original_lotl_ca_crl_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_lotl_ca_crl_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(lotl.good_sha(report.get(k)) for k in (
             'verified_live_ec411_report_sha256',
             'verified_live_ec411_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         report.get('bounded_original_ca_crl_and_real_ec411_parent_consistency')
             is (not any(report[k] for k in parent.FLAGS[:4])) and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed')
             is False and
         report.get('status') == next((parent.OUTCOMES[i]
             for i, flag in enumerate(parent.FLAGS) if report[flag]),
             parent.OUTCOMES[-1]) + '_unresolved' and
         type(rows) is list and len(rows) == n and all(
             type(row) is dict and set(row) == row_fields and
             type(row['epoch_index']) is int and row['epoch_index'] == i and
             type(row['verified_original_ca_crl_historical_evaluation_four_documents'])
                 is int and row['verified_original_ca_crl_historical_evaluation_four_documents']
                 in (0, 1) and
             all(type(row[k]) is int and 0 <= row[k] <= 2 for k in (
                'joint_genuine_crl_and_real_ec411_parent_publisher_count',
                'genuine_ec411_parent_xades_v2_joint_publisher_count')) and
             (row['verified_original_ca_crl_historical_evaluation_four_documents'] == 1
              or row['joint_genuine_crl_and_real_ec411_parent_publisher_count'] == 0) and
             row['joint_genuine_crl_and_real_ec411_parent_publisher_count'] <=
                 row['genuine_ec411_parent_xades_v2_joint_publisher_count'] and
             lotl.good_sha(row['lotl_ca_crl_epoch_inventory_sha256'])
             for i, row in enumerate(rows)) and
         type(report.get('verified_joint_crl_and_real_ec411_parent_publishers')) is int and
         report['verified_joint_crl_and_real_ec411_parent_publishers'] == sum(
             row['joint_genuine_crl_and_real_ec411_parent_publisher_count']
             for row in rows),
         'UNCHANGED_REAL_EC412_CRL_ORIGINAL_REPORT_CONTRACT_INVALID', 'unavailable')
    return digest(report)


def _protected_refs(tree, paths, shas):
    """Block OCSP aliasing ANY reference from the reopened ancestor manifests."""
    if type(tree) is dict:
        if type(tree.get('path')) is str and type(tree.get('sha256')) is str:
            paths.add(tree['path'])
            shas.add(tree['sha256'])
        for child in tree.values():
            _protected_refs(child, paths, shas)
    elif type(tree) is list:
        for child in tree:
            _protected_refs(child, paths, shas)


def _verify_ocsp(raw, issuer, target, times, *, previous=None):
    """Verify exact direct-issuer SHA256 DER OCSP, signed status and freshness.

    A sound signature with a revoked/unknown status is evidence of *adversity*,
    not an invalid signature. It must NEVER count as a locally good window.
    The producer's signed date is a CA claim, NOT external proof of receipt.
    """
    need(type(raw) is bytes and 0 < len(raw) <= MAX_OCSP, 'OCSP_DER_SIZE_INVALID')
    try:
        response = ocsp.load_der_ocsp_response(raw)
        need(response.public_bytes(serialization.Encoding.DER) == raw,
             'OCSP_MUST_BE_CANONICAL_EXACT_DER')
        need(response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL,
             'OCSP_MUST_BE_SUCCESSFUL_BASIC_RESPONSE')
        singles = list(response.responses)
        need(len(singles) == 1 and len(response.certificates) == 0 and
             len(response.extensions) == 0,
             'OCSP_ONE_DIRECT_ISSUER_RESPONSE_NO_EMBEDDED_CERT_OR_EXTENSIONS')
        one = singles[0]
        need(len(response.single_extensions) == 0 and
             one.hash_algorithm is not None and
             type(one.hash_algorithm) is hashes.SHA256,
             'OCSP_SINGLE_CERTID_SHA256_NO_EXTENSION_REQUIRED')
        expected = ocsp.OCSPRequestBuilder().add_certificate(
            target, issuer, hashes.SHA256()).build()
        need(one.serial_number == target.serial_number == expected.serial_number and
             one.issuer_name_hash == expected.issuer_name_hash and
             one.issuer_key_hash == expected.issuer_key_hash,
             'OCSP_SHA256_CERTID_NOT_ACTUAL_PINNED_CA_CHAIN_LINK')
        use = issuer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        basic = issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        need(basic.ca and use.key_cert_sign,
             'OCSP_REAL_PINNED_ISSUER_NOT_CA_OR_CERTSIGN')
        calculated_keyid = x509.SubjectKeyIdentifier.from_public_key(
            issuer.public_key()).digest
        need(((response.responder_key_hash == calculated_keyid and
               response.responder_name is None) or
              (response.responder_name == issuer.subject and
               response.responder_key_hash is None)),
             'OCSP_RESPONDER_ID_NOT_ACTUAL_DIRECT_ISSUER')
        key = issuer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            need(key.key_size >= 2048 and
                 response.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256 and
                 isinstance(response.signature_hash_algorithm, hashes.SHA256),
                 'OCSP_ONLY_RSA2048_PKCS1V15_SHA256')
            key.verify(response.signature, response.tbs_response_bytes,
                       padding.PKCS1v15(), hashes.SHA256())
        else:
            need(isinstance(key, ec.EllipticCurvePublicKey) and
                 isinstance(key.curve, ec.SECP256R1) and
                 response.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256 and
                 isinstance(response.signature_hash_algorithm, hashes.SHA256),
                 'OCSP_ONLY_ECDSA_P256_SHA256')
            key.verify(response.signature, response.tbs_response_bytes,
                       ec.ECDSA(hashes.SHA256()))
        produced, this, nxt = (response.produced_at_utc, one.this_update_utc,
                                one.next_update_utc)
        need(produced is not None and this is not None and nxt is not None and
             this < nxt and nxt - this <= MAX_LIFETIME and
             this - SKEW <= produced <= nxt + SKEW and
             this.microsecond == nxt.microsecond == produced.microsecond == 0 and
             issuer.not_valid_before_utc <= produced <= issuer.not_valid_after_utc,
             'OCSP_SIGNED_PRODUCED_THIS_NEXT_AND_CA_VALIDITY_INVALID')
        if previous is not None:
            need(this > previous['this'] and produced >= previous['produced'],
                 'OCSP_SIGNED_THISUPDATE_OR_PRODUCEDAT_SOURCE_ROLLBACK')
        status = one.certificate_status
        need(status in (ocsp.OCSPCertStatus.GOOD, ocsp.OCSPCertStatus.REVOKED,
                        ocsp.OCSPCertStatus.UNKNOWN),
             'OCSP_UNSUPPORTED_CERTIFICATE_STATUS')
        if status is ocsp.OCSPCertStatus.REVOKED:
            need(one.revocation_time_utc is not None and
                 one.revocation_time_utc <= produced + SKEW,
                 'OCSP_REVOKED_WITH_IMPOSSIBLE_FUTURE_TIME')
        need(type(times) is list and bool(times),
             'OCSP_ACTUAL_SIGNED_PARENT_SOURCE_TIMES_REQUIRED')
        covers = all(this <= when < nxt and
                     target.not_valid_before_utc <= when <= target.not_valid_after_utc and
                     issuer.not_valid_before_utc <= when <= issuer.not_valid_after_utc
                     for when in times)
        # All historical signer and independent CMS-claimed custody instants
        # must be contemporaneous with claimed OCSP production; a later CA
        # answer may be cryptographically real but cannot rewrite history.
        fresh = all(-SKEW <= when - produced <= MAX_PRODUCED_AGE
                    for when in times)
        good = bool(covers and fresh and status is ocsp.OCSPCertStatus.GOOD)
        return {
            'original_ocsp_sha256': sha(raw),
            'actual_ca_certificate_sha256': sha(issuer.public_bytes(
                serialization.Encoding.DER)),
            'checked_target_certificate_sha256': sha(target.public_bytes(
                serialization.Encoding.DER)),
            'actual_sha256_certid_and_direct_ca_signature_verified': True,
            'responder_authorization': 'direct_pinned_issuer_only',
            'signed_certificate_status': status.name.lower(),
            'signed_revocation_time_utc': (one.revocation_time_utc.strftime(
                '%Y-%m-%dT%H:%M:%SZ') if status is ocsp.OCSPCertStatus.REVOKED else None),
            'signed_produced_at_utc': produced.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'signed_this_update_utc': this.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'signed_next_update_utc': nxt.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'covers_all_real_parent_signed_source_instants': bool(covers),
            'bounded_fresh_signed_source_claims': bool(fresh),
            'local_good_temporal_certificate_consistency': good,
            '_state': {'this': this, 'produced': produced},
        }
    except errors.AnchorError:
        raise
    except (InvalidSignature, ValueError, TypeError, OverflowError,
            AttributeError, x509.ExtensionNotFound) as exc:
        raise errors.AnchorError('EC413_INVALID_OR_UNSUPPORTED_TRUE_ISSUER_OCSP',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)   # Unchanged REAL EC412 -> EC411 -> all older
    live_sha = _parent_report(live, opts)
    lineage = opts['claimed_historical_directory_lineage_id']
    count = len(opts['historical_directory_root_shas'])
    read, doc, late = readers._readers()
    new_ref = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    crl_ref = {'path': opts[parent.NEW_SCALARS[0]],
               'sha256': opts[parent.NEW_SCALARS[1]]}
    lotl_ref = {'path': opts[lotl.NEW_SCALARS[0]],
                'sha256': opts[lotl.NEW_SCALARS[1]]}
    ec407_ref = {'path': opts[cms.NEW_SCALARS[0]],
                 'sha256': opts[cms.NEW_SCALARS[1]]}
    bundle = doc(new_ref, 'ec413_original_lotl_ca_ocsp_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'ORIGINAL_LOTL_CA_OCSP_BUNDLE')
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec412_original_lotl_crl_bundle_original'] == crl_ref and
         type(bundle['epochs']) is list and len(bundle['epochs']) == count,
         'OCSP_MUST_BIND_UNCHANGED_EC412_CRL_BUNDLE_AND_EPOCHS')
    old_crls = doc(crl_ref, 'ec413_reopen_real_ec412_signed_crl_bundle',
                   parent.MAX_BUNDLE)
    old_lotl = doc(lotl_ref, 'ec413_reopen_real_ec410_lotl_bundle',
                   lotl.MAX_BUNDLE)
    old_cms = doc(ec407_ref, 'ec413_reopen_real_ec407_cms_bundle', cms.MAX_BUNDLE)
    exact(old_crls, parent.BUNDLE_FIELDS, 'REAL_EC412_CRL_BUNDLE')
    exact(old_lotl, lotl.BUNDLE_FIELDS, 'REAL_EC410_LOTL_BUNDLE')
    exact(old_cms, cms.BUNDLE_FIELDS, 'REAL_EC407_CMS_BUNDLE')
    need(old_crls['schema'] == parent.BUNDLE_SCHEMA and
         old_lotl['schema'] == lotl.BUNDLE_SCHEMA and
         old_cms['schema'] == cms.BUNDLE_SCHEMA and
         all(d['claimed_directory_lineage_id'] == lineage and
             type(d['epochs']) is list and len(d['epochs']) == count
             for d in (old_crls, old_lotl, old_cms)) and
         old_crls['parent_ec410_signed_lotl_bundle_original'] == lotl_ref,
         'REAL_EC412_EC410_EC407_ORIGINAL_ANCESTRY_NOT_BOUND')
    roster_ref = lotl.ref(old_lotl['outside_lotl_operator_roster_original'])
    need(roster_ref == old_crls['parent_ec410_outside_operator_roster_original']
         and roster_ref['sha256'] == opts[lotl.NEW_SCALARS[2]],
         'MUST_REOPEN_REAL_OUTSIDE_PINNED_EC410_ROSTER')
    roster = doc(roster_ref, 'ec413_original_pinned_ec410_ca_roster', lotl.MAX_ROSTER)
    exact(roster, lotl.ROSTER_FIELDS, 'ACTUAL_EC410_PINNED_CA_ROSTER')
    need(roster['schema'] == lotl.ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage,
         'REAL_EC410_PINNED_ROSTER_LINEAGE_MISMATCH')
    cert_refs = {
        'root': lotl.ref(roster['lotl_trust_anchor_certificate_original']),
        'intermediate': lotl.ref(roster['lotl_intermediate_ca_certificate_original']),
        'signer': lotl.ref(roster['lotl_signer_certificate_original']),
    }
    for index, role in enumerate(('root', 'intermediate', 'signer')):
        need(cert_refs[role]['sha256'] == opts[lotl.NEW_SCALARS[index + 3]],
             'OCSP_PINNED_CA_CHAIN_MUST_EQUAL_REAL_EC410_OUTSIDE_CERT_PINS')
    originals = {role: read(ref, 'ec413_real_original_' + role + '_certificate',
                            lotl.MAX_CERT) for role, ref in cert_refs.items()}
    chain = lotl._chain({'root': originals['root'],
                         'mid': originals['intermediate'],
                         'signer': originals['signer']}, [])
    claims, actual_ec407_ref = parent._ec407_historical_claims(
        opts, count, lineage, doc)
    need(actual_ec407_ref == ec407_ref,
         'REAL_EC407_SIGNED_CUSTODY_ORIGINAL_NOT_MATCHED')
    evaluated = lotl.utc(opts['ec407_institutional_evaluation_utc'])
    paths, shas = set(), set()
    for reference in (new_ref, crl_ref, lotl_ref, roster_ref, ec407_ref):
        _protected_refs(reference, paths, shas)
    for tree in (old_crls, old_lotl, old_cms, roster):
        _protected_refs(tree, paths, shas)
    for path_key in PARENT_SCALARS:
        if path_key.endswith('_file') and type(opts.get(path_key)) is str:
            paths.add(opts[path_key])
    flags = {name: False for name in FLAGS}
    flags[FLAGS[0]] = (
        not live['bounded_original_ca_crl_and_real_ec411_parent_consistency'] or
        any(row['joint_genuine_crl_and_real_ec411_parent_publisher_count'] != 2
            for row in live['lotl_ca_crl_epoch_reviews']))
    missing = False
    previous = {role: None for role in ROLES}
    first_shas = []
    epochs, reviews, total = [], [], 0
    for i, row in enumerate(bundle['epochs']):
        exact(row, EPOCH_FIELDS, 'EC413_LOTL_OCSP_EPOCH')
        need(type(row['epoch_index']) is int and row['epoch_index'] == i,
             'REAL_SOURCE_OCSP_EPOCH_INDEX_MISMATCH')
        ec412_epoch = old_crls['epochs'][i]
        ec410_epoch = old_lotl['epochs'][i]
        exact(ec412_epoch, parent.EPOCH_FIELDS, 'REAL_EC412_CRL_EPOCH')
        exact(ec410_epoch, lotl.EPOCH_FIELDS, 'REAL_EC410_LOTL_EPOCH')
        parent_complete = bool(live['lotl_ca_crl_epoch_reviews'][i][
            'verified_original_ca_crl_historical_evaluation_four_documents'])
        values = [row[w + '_' + r + '_ca_ocsp_original']
                  for w in WINDOWS for r in ROLES]
        if all(value is None for value in values):
            need(i > 0 and not parent_complete,
                 'FIRST_OR_PARENT_COMPLETE_ISSUER_OCSP_SET_MISSING')
            missing = True
            flags[FLAGS[2]] = flags[FLAGS[5]] = True
            record = {
                'epoch_index': i, 'historical': None, 'evaluation': None,
                'four_issuer_signed_original_ocsp_documents': False,
                'four_signed_good_and_contemporaneous_source_windows': False,
                'joint_real_ec412_crl_and_issuer_ocsp_publisher_count': 0,
            }
        else:
            need(all(value is not None for value in values) and not missing and
                 parent_complete,
                 'PARTIAL_REAPPEARING_OR_ADVERSE_PARENT_OCSP_SOURCE_SET')
            signed = {}
            for window in WINDOWS:
                source_ref = lotl.ref(ec410_epoch[
                    'original_' + window + '_signed_lotl_xml'])
                expected = {
                    'original_signed_lotl_sha256': source_ref['sha256'],
                    'original_lotl_signer_certificate_sha256': sha(originals['signer']),
                    'xmlsig_reference_count': 2,
                    'xades_signed_properties_verified': True,
                }
                signed_xml = xades._verify_signed_original(
                    source_ref, originals['signer'], expected, read)
                signed[window] = lotl.utc(signed_xml['authenticated_signing_time_utc'])
            coverage = {
                'historical': [signed['historical'], *claims[i]],
                'evaluation': [signed['evaluation'], evaluated],
            }
            records = {}
            four_good = True
            for window in WINDOWS:
                records[window] = {}
                for role in ROLES:
                    source_ref = lotl.ref(row[window + '_' + role +
                                              '_ca_ocsp_original'])
                    need(source_ref['path'] not in paths and
                         source_ref['sha256'] not in shas,
                         'OCSP_SOURCE_PATH_OR_SHA_ALIASES_PREVIOUS_ORIGINAL')
                    paths.add(source_ref['path'])
                    shas.add(source_ref['sha256'])
                    raw = read(source_ref, 'ec413_original_' + window + '_' +
                               role + '_real_issuer_signed_ocsp', MAX_OCSP)
                    issuer = chain['root'] if role == 'root' else chain['mid']
                    target = chain['mid'] if role == 'root' else chain['signer']
                    result = _verify_ocsp(raw, issuer, target, coverage[window],
                                          previous=previous[role])
                    previous[role] = result.pop('_state')
                    if result['signed_certificate_status'] != 'good':
                        flags[FLAGS[3]] = True
                    if not (result['covers_all_real_parent_signed_source_instants'] and
                            result['bounded_fresh_signed_source_claims']):
                        flags[FLAGS[4]] = True
                    four_good = four_good and result[
                        'local_good_temporal_certificate_consistency']
                    records[window][role] = result
                    if i == 0:
                        first_shas.append(source_ref['sha256'])
            joint = (2 if four_good and not flags[FLAGS[0]] and
                     live['lotl_ca_crl_epoch_reviews'][i][
                         'joint_genuine_crl_and_real_ec411_parent_publisher_count'] == 2
                     else 0)
            if joint != 2:
                flags[FLAGS[5]] = True
            record = {
                'epoch_index': i,
                'historical': records['historical'],
                'evaluation': records['evaluation'],
                'four_issuer_signed_original_ocsp_documents': True,
                'four_signed_good_and_contemporaneous_source_windows': bool(four_good),
                'joint_real_ec412_crl_and_issuer_ocsp_publisher_count': joint,
            }
        epoch_sha = digest(record)
        if (epoch_sha != opts[REPEAT_NAMES[0]][i] or
            record['joint_real_ec412_crl_and_issuer_ocsp_publisher_count'] <
                opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]] = True
        epochs.append(record)
        reviews.append({
            'epoch_index': i,
            'verified_four_original_issuer_ocsp_documents': int(
                record['four_issuer_signed_original_ocsp_documents']),
            'signed_good_contemporaneous_four_source_windows': int(
                record['four_signed_good_and_contemporaneous_source_windows']),
            'joint_original_issuer_ocsp_and_real_ec412_parent_publishers':
                record['joint_real_ec412_crl_and_issuer_ocsp_publisher_count'],
            'original_lotl_ocsp_epoch_inventory_sha256': epoch_sha,
            'real_ec412_crl_joint_publisher_count': live['lotl_ca_crl_epoch_reviews'][i][
                'joint_genuine_crl_and_real_ec411_parent_publisher_count'],
        })
        total += record['joint_real_ec412_crl_and_issuer_ocsp_publisher_count']
    need(len(first_shas) == 4, 'FOUR_FIRST_ORIGINAL_ISSUER_SIGNED_OCSP_REQUIRED')
    if first_shas != [opts[k] for k in NEW_SCALARS[2:]]:
        flags[FLAGS[1]] = True
    inventory = {
        'schema': INVENTORY_SCHEMA,
        'directory_lineage_id': lineage,
        'verified_real_ec412_report_sha256': live_sha,
        'verified_real_ec412_inventory_sha256':
            live['receiver_verified_lotl_ca_crl_inventory_sha256'],
        'original_real_ec412_crl_bundle_sha256': crl_ref['sha256'],
        'original_outside_pinned_ec410_ca_chain_sha256s':
            [cert_refs[k]['sha256'] for k in ('root', 'intermediate', 'signer')],
        'actual_original_ec407_cms_bundle_sha256': ec407_ref['sha256'],
        'first_four_original_issuer_ocsp_sha256s': first_shas,
        'restricted_profile': 'DIRECT_ISSUER_ONLY_SHA256_RSA2048_OR_P256_ONE_BASIC_RESPONSE_FRESH_GOOD',
        'epochs': epochs,
    }
    invsha = digest(inventory)
    if not deriving and invsha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # Reread all original sources known to this receiver: verify TOCTOU drift.
    for path, (original_sha, size_limit) in late.items():
        raw = io._read({'path': path, 'sha256': original_sha},
                       'ec413_final_original_source_readback',
                       size_limit, {}, {}, set())
        need(sha(raw) == original_sha,
             'ORIGINAL_SOURCE_BYTES_CHANGED_DURING_RECEIVER')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {
        'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
        'command': ('derive-historical-ec339-lotl-ocsp-inventory' if deriving
                    else 'audit-historical-ec339-lotl-ocsp'),
        'status': next((OUTCOMES[i] for i, key in enumerate(FLAGS) if flags[key]),
                       OUTCOMES[-1]) + '_unresolved',
        'exit_code': 2,
        'offline_unresolved_exit_code': 2,
        'verified_live_ec412_report_sha256': live_sha,
        'verified_live_ec412_inventory_sha256':
            live['receiver_verified_lotl_ca_crl_inventory_sha256'],
        'original_lotl_issuer_ocsp_bundle_sha256': new_ref['sha256'],
        'receiver_verified_lotl_issuer_ocsp_inventory_sha256': invsha,
        'verified_joint_ocsp_and_real_ec412_parent_publishers': total,
        'lotl_issuer_ocsp_epoch_reviews': reviews,
        'bounded_original_issuer_ocsp_and_real_ec412_parent_consistency':
            not any(flags[k] for k in FLAGS[:6]),
        'sender_origin_path_required_or_read': False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
        **flags,
        **{k: False for k in NEGATIVES},
        **({'unsigned_lotl_issuer_ocsp_inventory': inventory} if deriving else {}),
    }


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)

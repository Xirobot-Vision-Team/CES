#!/usr/bin/env python3
"""EC401 offline read-only RFC6960 OCSP original evidence receiver.

Production MUST rerun the unchanged EC400 audit with its authentic EC399 CRLs,
X.509 certificates, EC398 gazette bytes, CMS signatures and all ancestors.
An authentic signed OCSP Response is an issuer/delegate statement about a named
certificate and claimed interval, NOT evidence of a legally accredited public
issuer, independent historical delivery, global revocation coverage or final PASS.
No network, signing, private keys, provider access, CAS write or PowerShell edit.
"""
from __future__ import annotations

from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, ObjectIdentifier

from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec400_native_cms import protocol as parent

RESULT_SCHEMA = 'ces.ec401.issuer_signed_ocsp_evidence_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec401.unsigned_ocsp_evidence_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec401.issuer_signed_ocsp_denial.v1'
BUNDLE_SCHEMA = 'ces.ec401.issuer_signed_ocsp_originals_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec401.unsigned_ocsp_evidence_inventory.v1'
MAX_BUNDLE = 180_000
MAX_OCSP = 2_000_000
MAX_RESPONDER_CERT = 32_000
SKEW = timedelta(minutes=5)
OCSP_NOCHECK = ObjectIdentifier('1.3.6.1.5.5.7.48.1.5')

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_issuer_ocsp_bundle_file',
    'expected_historical_ec339_issuer_ocsp_bundle_sha256',
    'expected_outside_retained_ec401_first_a_historical_ocsp_sha256',
    'expected_outside_retained_ec401_first_b_historical_ocsp_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_issuer_ocsp_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_issuer_ocsp_epoch_inventory_shas',
     '--historical-ec339-issuer-ocsp-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_ocsp_publisher_counts',
     '--minimum-historical-ec339-joint-ocsp-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec400_cms_x509_crl_parent_disputed',
    'outside_original_ocsp_epoch_inventory_or_count_pin_disagrees',
    'signed_historical_or_evaluation_ocsp_original_missing',
    'ocsp_good_and_contemporaneous_two_epoch_coverage_incomplete',
    'ocsp_reveals_revocation_or_unknown_certificate_status',
    'real_official_issuer_authorization_and_original_public_source_not_proven',
    'global_ocsp_crl_census_and_independent_prior_public_access_not_proven',
    'qualified_tsa_worm_unmocked_history_and_final_acceptance_not_proven',
)
OUTCOMES = (
    'ec401_real_ec400_parent_original_or_cryptography_disputed',
    'ec401_outside_ocsp_original_epoch_or_count_constraints_disagree',
    'ec401_signed_ocsp_historical_or_current_original_unavailable',
    'ec401_original_ocsp_good_contemporaneous_coverage_incomplete',
    'ec401_genuine_ocsp_revoked_or_unknown_certificate',
    'ec401_real_world_official_issuer_authorization_not_established',
    'ec401_global_revocation_or_prior_public_source_not_established',
    'ec401_qualified_tsa_worm_unmocked_history_final_acceptance_not_proven',
)
NEGATIVES = (
    'ocsp_response_good_proves_a_real_official_government_or_court_ca',
    'issuer_signed_ocsp_is_an_independently_qualified_legal_timestamp',
    'a_furnished_responder_original_proves_pre_dispute_public_availability',
    'signed_local_ocsp_and_crls_prove_complete_global_revocation_coverage',
    'ocsp_response_can_repair_failed_parent_ec399_crl_or_cms_signatures',
    'delegated_responder_accepted_without_direct_issuer_authorization',
    'responder_certificate_revocation_globally_proven_by_nocheck',
    'issuer_or_delegate_signed_in_the_receiver_or_retrieved_from_network',
    'receiver_wrote_cas_worm_git_ci_powershell_or_external_provider_state',
    'original_full_unmocked_history_native_ps7_or_user_acceptance_passed',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec400_native_cms_bundle_original', 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
PUBLISHER_FIELDS = {'publisher_id', 'chain_links'}
LINK_FIELDS = {'subject_certificate_sha256', 'issuer_certificate_sha256',
               'historical_ocsp_response_original',
               'evaluation_ocsp_response_original',
               'historical_responder_certificate_original',
               'evaluation_responder_certificate_original'}


def need(cond, reason, status='invalid_input'):
    if cond is not True:
        raise errors.AnchorError('EC401_' + reason, status)


def exact(value, keys, label):
    need(type(value) is dict and set(value) == keys,
         label + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def ref(value):
    return parent.ref(value)


def sha(value):
    return parent.sha(value)


def cdigest(value):
    return parent.cdigest(value)


def _inputs(opts, deriving):
    expected = set((*PARENT_SCALARS, *PARENT_REPEATS,
                    *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        expected.update(AUDIT_ONLY)
    need(set(opts) == expected, 'INCOMPLETE_PARENT_AND_OCSP_ARGUMENTS')
    inherited = {key: opts[key] for key in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC401_OCSP_ORIGINAL_BUNDLE')
    for key in NEW_SCALARS[2:] + (() if deriving else AUDIT_ONLY):
        need(parent.parent.valid_sha(opts[key]), 'OUTSIDE_OCSP_SHA_INVALID')
    need(opts[NEW_SCALARS[2]] != opts[NEW_SCALARS[3]],
         'TWO_FIRST_OCSP_ORIGINALS_MUST_DIFFER', 'permission_denied')
    count = len(opts['historical_directory_root_shas'])
    need(1 <= count <= 3, 'ONE_TO_THREE_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == count,
             'OCSP_EPOCH_OUTSIDE_CONSTRAINT_COUNT_INVALID')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'OCSP_TWO_PUBLISHER_FLOOR_INVALID')
        else:
            need(all(parent.parent.valid_sha(v) for v in values),
                 'OCSP_EPOCH_INVENTORY_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code',
              'offline_unresolved_exit_code', 'verified_live_ec399_report_sha256',
              'verified_live_ec399_inventory_sha256',
              'original_native_cms_bundle_sha256',
              'receiver_verified_native_cms_inventory_sha256',
              'verified_parent_and_native_cms_joint_signer_count',
              'cms_epoch_reviews',
              'bounded_local_native_cms_original_and_ec399_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    count = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-native-cms' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_native_cms_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_native_cms_inventory_sha256') == opts[parent.AUDIT_ONLY[0]] and
         all(parent.parent.valid_sha(report.get(k)) for k in (
             'verified_live_ec399_report_sha256',
             'verified_live_ec399_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-4:] ) and
         report.get('bounded_local_native_cms_original_and_ec399_consistency') is
             (not any(report[k] for k in parent.FLAGS[:4])) and
         report.get('status') == next((parent.OUTCOMES[i]
             for i, k in enumerate(parent.FLAGS) if report[k]),
             parent.OUTCOMES[-1]) + '_unresolved',
         'REAL_EC400_PARENT_REPORT_OR_STATUS_INVALID', 'unavailable')
    rows = report.get('cms_epoch_reviews')
    required = {'epoch_index', 'cms_original_sha256',
                'verified_native_cms_signer_count',
                'genuine_parent_certificates_and_crls_credited',
                'cms_original_inventory_sha256'}
    need(type(rows) is list and len(rows) == count and all(
         type(r) is dict and set(r) == required and
         type(r['epoch_index']) is int and r['epoch_index'] == i and
         (r['cms_original_sha256'] is None or
          parent.parent.valid_sha(r['cms_original_sha256'])) and
         type(r['verified_native_cms_signer_count']) is int and
         r['verified_native_cms_signer_count'] in (0, 2) and
         type(r['genuine_parent_certificates_and_crls_credited']) is int and
         0 <= r['genuine_parent_certificates_and_crls_credited'] <= 2 and
         parent.parent.valid_sha(r['cms_original_inventory_sha256'])
         for i, r in enumerate(rows)) and
         type(report.get('verified_parent_and_native_cms_joint_signer_count')) is int and
         report['verified_parent_and_native_cms_joint_signer_count'] == sum(
             r['verified_native_cms_signer_count'] for r in rows),
         'REAL_EC400_PARENT_SIGNER_EPOCH_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _signed_by(pub, signature, payload, algorithm_oid):
    parent.parent._verify_signature(pub, signature, payload, algorithm_oid)


def _responder_certificate(original, response, issuer, time, read):
    """Require issuer-signed delegated certificate, exact embedded DER, and NoCheck.

    NoCheck is issuer permission to avoid separate responder revocation checks,
    NOT proof that responder revocation is globally absent.
    """
    r = ref(original)
    raw = read(r, 'ec401_original_delegated_ocsp_responder_certificate',
               MAX_RESPONDER_CERT)
    try:
        certificate = x509.load_der_x509_certificate(raw)
        need(certificate.public_bytes(serialization.Encoding.DER) == raw,
             'DELEGATE_CERT_NOT_CANONICAL_DER', 'permission_denied')
    except (ValueError, TypeError) as exc:
        raise errors.AnchorError('EC401_INVALID_DELEGATE_CERT_DER', 'permission_denied') from exc
    need(len(response.certificates) == 1 and
         response.certificates[0].public_bytes(serialization.Encoding.DER) == raw,
         'DELEGATE_MUST_EQUAL_SINGLE_EMBEDDED_ORIGINAL_CERT', 'permission_denied')
    need(certificate.issuer == issuer.subject and
         certificate.not_valid_before_utc <= time <= certificate.not_valid_after_utc,
         'DELEGATE_ISSUER_OR_VALIDITY_INVALID', 'permission_denied')
    _signed_by(issuer.public_key(), certificate.signature,
               certificate.tbs_certificate_bytes, certificate.signature_algorithm_oid)
    need(parent.parent._ext(certificate, ExtensionOID.BASIC_CONSTRAINTS).ca is False,
         'DELEGATE_MUST_NOT_BE_CA', 'permission_denied')
    usage = parent.parent._ext(certificate, ExtensionOID.KEY_USAGE)
    need(usage.digital_signature and not usage.key_cert_sign and not usage.crl_sign,
         'DELEGATE_KEY_USAGE_FORBIDDEN', 'permission_denied')
    eku = parent.parent._ext(certificate, ExtensionOID.EXTENDED_KEY_USAGE)
    need(ExtendedKeyUsageOID.OCSP_SIGNING in eku,
         'DELEGATE_MISSING_OCSP_SIGNING_EKU', 'permission_denied')
    nocheck = parent.parent._ext(certificate, OCSP_NOCHECK)
    need(isinstance(nocheck, x509.OCSPNoCheck),
         'DELEGATE_REQUIRES_EXPLICIT_ISSUER_NOCHECK', 'permission_denied')
    known = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
             ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
             ExtensionOID.AUTHORITY_KEY_IDENTIFIER, OCSP_NOCHECK}
    need(all(not ext.critical or ext.oid in known for ext in certificate.extensions),
         'DELEGATE_HAS_UNSUPPORTED_CRITICAL_EXTENSION', 'permission_denied')
    return certificate, r


def _verify_original(original, delegated, subject, issuer, at, evaluated, read,
                     *, historical):
    if original is None:
        need(delegated is None, 'MISSING_OCSP_CANNOT_HAVE_DELEGATE', 'permission_denied')
        return {'response_original_sha256': None, 'responder_certificate_sha256': None,
                'responder_authorization': None, 'claimed_produced_at_utc': None,
                'this_update_utc': None, 'next_update_utc': None,
                'certificate_status': 'missing', 'signed_ocsp_valid': False,
                'covers_requested_time': False, 'contemporaneous_claim': False,
                'local_good_coverage': False}
    original_ref = ref(original)
    raw = read(original_ref, 'ec401_signed_original_der_ocsp', MAX_OCSP)
    try:
        response = ocsp.load_der_ocsp_response(raw)
        need(response.public_bytes(serialization.Encoding.DER) == raw,
             'OCSP_NONCANONICAL_DER_OR_TRAILING_DATA', 'permission_denied')
        responses = list(response.responses) if response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL else []
        need(response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and
             len(responses) == 1,
             'OCSP_SUCCESSFUL_SINGLE_BASIC_RESPONSE_REQUIRED', 'permission_denied')
        one = responses[0]
        need(one.hash_algorithm is not None and
             one.hash_algorithm.name in ('sha256', 'sha384', 'sha512'),
             'OCSP_CERTID_SHA1_OR_WEAK_HASH_FORBIDDEN', 'permission_denied')
        built = (ocsp.OCSPRequestBuilder()
                 .add_certificate(subject, issuer, one.hash_algorithm).build())
        need(one.serial_number == built.serial_number and
             one.issuer_key_hash == built.issuer_key_hash and
             one.issuer_name_hash == built.issuer_name_hash,
             'OCSP_CERTID_NOT_BOUND_TO_REAL_EC399_CHAIN_LINK', 'permission_denied')
        need(len(response.extensions) == 0 and len(response.single_extensions) == 0,
             'OCSP_UNSUPPORTED_RESPONSE_OR_SINGLE_EXTENSIONS', 'permission_denied')
        produced, started, ending = (response.produced_at_utc,
                                     one.this_update_utc, one.next_update_utc)
        need(produced is not None and started is not None and ending is not None and
             started < ending and started - SKEW <= produced <= ending + SKEW and
             produced <= evaluated,
             'OCSP_BAD_PRODUCED_THIS_NEXT_OR_FUTURE_TIME', 'permission_denied')
        need(issuer.not_valid_before_utc <= produced <= issuer.not_valid_after_utc and
             subject.not_valid_before_utc <= at <= subject.not_valid_after_utc,
             'OCSP_ISSUER_OR_SUBJECT_CERTIFICATE_TIME_INVALID', 'permission_denied')
        # Only issuer signing or a very strictly authorized/embedded OCSP delegate.
        if delegated is None:
            need(len(response.certificates) == 0,
                 'ISSUER_OCSP_UNTRUSTED_EXTRA_EMBEDDED_CERT', 'permission_denied')
            cert, certref, label = issuer, None, 'direct_issuer'
        else:
            cert, certref = _responder_certificate(delegated, response, issuer,
                                                  produced, read)
            label = 'issuer_delegated_nocheck'
        key_hash = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        by_key = response.responder_key_hash == key_hash and response.responder_name is None
        by_name = response.responder_name == cert.subject and response.responder_key_hash is None
        need(by_key or by_name, 'OCSP_RESPONDER_ID_NOT_BOUND_TO_SIGNER',
             'permission_denied')
        _signed_by(cert.public_key(), response.signature,
                   response.tbs_response_bytes, response.signature_algorithm_oid)
        claimed_status = one.certificate_status
        need(claimed_status in (ocsp.OCSPCertStatus.GOOD, ocsp.OCSPCertStatus.REVOKED,
                                ocsp.OCSPCertStatus.UNKNOWN),
             'OCSP_INVALID_SINGLE_CERTIFICATE_STATUS', 'permission_denied')
        if claimed_status == ocsp.OCSPCertStatus.REVOKED:
            need(one.revocation_time_utc is not None and
                 one.revocation_time_utc <= evaluated + SKEW,
                 'OCSP_REVOCATION_IN_FUTURE_OR_WITHOUT_TIME', 'permission_denied')
        covers = started <= at <= ending
        contemporaneous = produced <= at + SKEW if historical else at - SKEW <= produced <= at + SKEW
        # A response created later may retrospectively cover the date, but does
        # not itself attest historical availability at the claimed instant.
        good = bool(covers and contemporaneous and claimed_status == ocsp.OCSPCertStatus.GOOD)
        return {'response_original_sha256': original_ref['sha256'],
                'responder_certificate_sha256': certref['sha256'] if certref else None,
                'responder_authorization': label,
                'claimed_produced_at_utc': produced.isoformat(),
                'this_update_utc': started.isoformat(),
                'next_update_utc': ending.isoformat(),
                'certificate_status': claimed_status.name.lower(),
                'signed_ocsp_valid': True, 'covers_requested_time': covers,
                'contemporaneous_claim': contemporaneous,
                'local_good_coverage': good}
    except errors.AnchorError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, AttributeError,
            x509.ExtensionNotFound) as exc:
        raise errors.AnchorError('EC401_INVALID_OR_UNSUPPORTED_OCSP_OR_SIGNER',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # absolutely mandatory real EC400 -> EC399 -> all ancestors
    parent_sha = _parent_report(live, opts)
    lineage = opts['claimed_historical_directory_lineage_id']
    n = len(opts['historical_directory_root_shas'])
    evaluation = parent.parent._utc(opts['ec391_tsa_evaluation_utc'])
    read, doc, late = parent.parent.parent.parent.parent.parent.prior._readers()
    b401ref = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b400ref = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    b399ref = {'path': opts[parent.parent.NEW_SCALARS[0]],
               'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    b398ref = {'path': opts[parent.parent.parent.NEW_SCALARS[0]],
               'sha256': opts[parent.parent.parent.NEW_SCALARS[1]]}
    bundle = doc(b401ref, 'ec401_signed_original_ocsp_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'ORIGINAL_OCSP_BUNDLE')
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec400_native_cms_bundle_original'] == b400ref and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'OCSP_BUNDLE_DOES_NOT_BIND_REAL_EC400_OR_EPOCHS', 'permission_denied')
    p400 = doc(b400ref, 'reopened_ec400_cms_original_bundle', parent.MAX_BUNDLE)
    p399 = doc(b399ref, 'reopened_ec399_real_certificate_bundle',
               parent.parent.MAX_BUNDLE)
    p398 = doc(b398ref, 'reopened_ec398_real_signed_notice_bundle',
               parent.parent.parent.MAX_BUNDLE)
    for obj, fields, label in ((p400, parent.BUNDLE_FIELDS, 'PARENT_EC400_BUNDLE'),
                               (p399, parent.parent.BUNDLE_FIELDS, 'PARENT_EC399_BUNDLE'),
                               (p398, parent.parent.parent.BUNDLE_FIELDS, 'PARENT_EC398_BUNDLE')):
        exact(obj, fields, label)
        need(obj['claimed_directory_lineage_id'] == lineage,
             label + '_LINEAGE_INVALID', 'permission_denied')
    need(p400['schema'] == parent.BUNDLE_SCHEMA and
         p400['parent_ec399_official_certificate_bundle_original'] == b399ref and
         p399['schema'] == parent.parent.BUNDLE_SCHEMA and
         p399['parent_ec398_external_notice_bundle_original'] == b398ref and
         p398['schema'] == parent.parent.parent.BUNDLE_SCHEMA and
         len(p400['epochs']) == len(p399['epochs']) == len(p398['epochs']) == n,
         'PARENT_ORIGINAL_BUNDLE_CHAIN_REPLACED', 'permission_denied')
    rosterref = ref(p399['outside_publisher_roster_original'])
    roster = doc(rosterref, 'ec401_genuine_ec399_certificate_roster',
                 parent.parent.MAX_ROSTER)
    exact(roster, parent.parent.ROSTER_FIELDS, 'REAL_EC399_CERTIFICATE_ROSTER')
    need(roster['schema'] == parent.parent.ROSTER_SCHEMA and
         rosterref['sha256'] == opts[parent.parent.NEW_SCALARS[2]] and
         roster['claimed_directory_lineage_id'] == lineage and
         type(roster['publishers']) is list and len(roster['publishers']) == 2,
         'REAL_EC399_TWO_PUBLISHER_ROSTER_WRONG', 'permission_denied')
    chains = [parent.parent._chain(role, opts, read) for role in roster['publishers']]
    ids = [c['role']['publisher_id'] for c in chains]
    need(len(set(ids)) == 2 and len({c['role']['site_id'] for c in chains}) == 2 and
         all(c['refs'][-1]['sha256'] == opts[parent.parent.NEW_SCALARS[3+i]] and
             c['spkis'][0] == opts[parent.parent.NEW_SCALARS[5+i]]
             for i, c in enumerate(chains)),
         'REAL_EC399_TWO_PINNED_CERTIFICATE_CHAINS_MISMATCH', 'permission_denied')
    # Every original from the three preceding bundles, rosters, source and
    # signer certificate/CRL sets is protected from role reuse as new OCSP bytes.
    protected = {b401ref['path'], b400ref['path'], b399ref['path'],
                 b398ref['path'], rosterref['path']}
    for prev in (p400, p399, p398, roster):
        parent.parent.parent._collect_sources(prev, protected)
    # Protect deeply nested, authentic EC397/396/395 originals too, so an OCSP
    # path cannot re-use any older signed receipt, source or original CRL role.
    p397ref = ref(p398['parent_ec397_publication_bundle_original'])
    p397 = doc(p397ref, 'ec401_genuine_ec397_original',
               parent.parent.parent.parent.MAX_BUNDLE)
    p396ref = ref(p397['parent_ec396_public_integrity_bundle_original'])
    p396 = doc(p396ref, 'ec401_genuine_ec396_original',
               parent.parent.parent.parent.parent.MAX_BUNDLE)
    p395ref = ref(p396['parent_ec395_credential_gossip_bundle_original'])
    p395 = doc(p395ref, 'ec401_genuine_ec395_original',
               parent.parent.parent.parent.parent.parent.MAX_BUNDLE)
    for rr, original in ((p397ref, p397), (p396ref, p396),
                         (p395ref, p395)):
        protected.add(rr['path'])
        parent.parent.parent._collect_sources(original, protected)
    for original, name in ((p397, 'outside_observer_roster_original'),
                           (p396, 'outside_authority_roster_original'),
                           (p395, 'external_role_roster_original')):
        if original.get(name) is not None:
            rr = ref(original[name])
            protected.add(rr['path'])
            parent.parent.parent._collect_sources(doc(
                rr, 'ec401_genuine_ancestor_original_roster',
                parent.parent.parent.MAX_ROSTER), protected)
    protected.update(r['path'] for c in chains for r in c['refs'])
    p398_rosterref = ref(p398['outside_notice_roster_original'])
    protected.add(p398_rosterref['path'])
    p398_roster = doc(p398_rosterref, 'genuine_ec398_original_notice_roster',
                      parent.parent.parent.MAX_ROSTER)
    parent.parent.parent._collect_sources(p398_roster, protected)
    flags = {key: False for key in FLAGS}
    flags[FLAGS[0]] = (not live['bounded_local_native_cms_original_and_ec399_consistency'] or
                       live['verified_parent_and_native_cms_joint_signer_count'] != 2 * n)
    output_rows, inventory_rows, first = [], [], {}
    total = 0
    used = set(protected)
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, EPOCH_FIELDS, 'OCSP_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i and
             type(epoch['publishers']) is list and len(epoch['publishers']) == 2,
             'OCSP_EPOCH_OR_PUBLISHER_COUNT_INVALID', 'permission_denied')
        cms_epoch = p400['epochs'][i]
        exact(cms_epoch, parent.EPOCH_FIELDS, 'REAL_EC400_CMS_EPOCH')
        need(type(cms_epoch['epoch_index']) is int and cms_epoch['epoch_index'] == i and
             live['cms_epoch_reviews'][i]['cms_original_sha256'] == (
                ref(cms_epoch['cms_signed_data_original'])['sha256']
                if cms_epoch['cms_signed_data_original'] is not None else None),
             'REAL_EC400_CMS_EPOCH_DOES_NOT_MATCH_REAUDIT', 'permission_denied')
        # Authentication of this claimed UTC comes from a real EC398 signature
        # verified during mandatory parent audit; re-check here against original.
        notice_entry = p398['epochs'][i]
        exact(notice_entry, parent.parent.parent.EPOCH_FIELDS, 'REAL_EC398_NOTICE_EPOCH')
        notice = notice_entry['notice']
        exact(notice, parent.parent.parent.STAMP_FIELDS, 'REAL_EC398_SIGNED_NOTICE')
        need(notice['signed_original'] is not None,
             'OCSP_REQUIRES_AUTHENTIC_EC398_SIGNED_NOTICE', 'permission_denied')
        signedref = ref(notice['signed_original'])
        _, claim, sig = parent.parent.parent._signed(
            signedref, read, parent.parent.parent.NOTICE_SCHEMA,
            parent.parent.parent.NOTICE_CLAIM,
            parent.parent.parent.NOTICE_CLAIM_FIELDS, 'EC401_REOPEN_REAL_SIGNED_NOTICE')
        parent.parent.parent._sign(p398_roster['registrar'], sig,
                                   parent.parent.parent.NOTICE_DOMAIN, claim,
                                   'EC401_REVERIFY_TRUE_EC398_NOTICE')
        need(claim['directory_lineage_id'] == lineage and
             type(claim['epoch_index']) is int and claim['epoch_index'] == i and
             claim['source_notice_original_sha256'] == ref(
                 notice_entry['source_notice_original'])['sha256'],
             'REAL_EC398_SIGNED_NOTICE_IDENTITY_MISMATCH', 'permission_denied')
        historical = parent.parent._utc(claim['claimed_published_utc'])
        need(historical <= evaluation, 'OCSP_HISTORICAL_TIME_AFTER_EVALUATION',
             'permission_denied')
        seen_roles, row_publishers = set(), []
        count = 0
        for item in epoch['publishers']:
            exact(item, PUBLISHER_FIELDS, 'OCSP_PUBLISHER')
            role = item['publisher_id']
            need(role in ids and role not in seen_roles,
                 'OCSP_UNKNOWN_OR_DUPLICATED_PUBLISHER_ROLE', 'permission_denied')
            seen_roles.add(role)
            chain = next(c for c in chains if c['role']['publisher_id'] == role)
            links = item['chain_links']
            need(type(links) is list and len(links) == len(chain['certs']) - 1,
                 'OCSP_ONE_ROW_PER_REAL_CERTIFICATE_CHAIN_LINK_REQUIRED',
                 'permission_denied')
            verified_links = []
            credit = True
            for j, link in enumerate(links):
                exact(link, LINK_FIELDS, 'OCSP_CERTIFICATE_CHAIN_LINK')
                sub, issuer = chain['certs'][j:j+2]
                need(link['subject_certificate_sha256'] == chain['refs'][j]['sha256'] and
                     link['issuer_certificate_sha256'] == chain['refs'][j+1]['sha256'],
                     'OCSP_SUBJECT_OR_ISSUER_CHAIN_LINK_SWAPPED', 'permission_denied')
                for field in ('historical_ocsp_response_original',
                              'evaluation_ocsp_response_original',
                              'historical_responder_certificate_original',
                              'evaluation_responder_certificate_original'):
                    if link[field] is not None:
                        rr = ref(link[field])
                        need(rr['path'] not in used,
                             'OCSP_OR_DELEGATE_ORIGINAL_REUSED_OR_PARENT_ALIAS',
                             'permission_denied')
                        used.add(rr['path'])
                h = _verify_original(link['historical_ocsp_response_original'],
                         link['historical_responder_certificate_original'],
                         sub, issuer, historical, evaluation, read, historical=True)
                e = _verify_original(link['evaluation_ocsp_response_original'],
                         link['evaluation_responder_certificate_original'],
                         sub, issuer, evaluation, evaluation, read, historical=False)
                if j == 0 and i == 0:
                    first[role] = h['response_original_sha256']
                if not h['signed_ocsp_valid'] or not e['signed_ocsp_valid']:
                    flags[FLAGS[2]] = True
                if h['certificate_status'] in ('revoked', 'unknown') or\
                   e['certificate_status'] in ('revoked', 'unknown'):
                    flags[FLAGS[4]] = True
                if not (h['local_good_coverage'] and e['local_good_coverage']):
                    flags[FLAGS[3]] = True
                    credit = False
                verified_links.append({
                    'subject_certificate_sha256': chain['refs'][j]['sha256'],
                    'issuer_certificate_sha256': chain['refs'][j+1]['sha256'],
                    'historical': h, 'evaluation': e})
            if credit and not flags[FLAGS[0]] and live['cms_epoch_reviews'][i][
                    'verified_native_cms_signer_count'] == 2:
                count += 1
            row_publishers.append({'publisher_id': role,
                                   'locally_good_issuer_ocsp_and_parent': bool(
                                       credit and not flags[FLAGS[0]] and
                                       live['cms_epoch_reviews'][i][
                                         'verified_native_cms_signer_count'] == 2),
                                   'real_chain_link_ocsp': verified_links})
        need(seen_roles == set(ids), 'OCSP_NOT_BOTH_GENUINE_PUBLISHER_ROLES',
             'permission_denied')
        row_publishers.sort(key=lambda x: x['publisher_id'])
        row = {'epoch_index': i, 'publishers': row_publishers,
               'locally_credited_joint_publisher_count': count}
        row_sha = cdigest(row)
        if row_sha != opts[REPEAT_NAMES[0]][i] or count < opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]] = True
        output_rows.append({'epoch_index': i,
                            'joint_verified_ocsp_publisher_count': count,
                            'ocsp_original_inventory_sha256': row_sha,
                            'authentic_parent_cms_joint_signer_count': live[
                                'cms_epoch_reviews'][i]['verified_native_cms_signer_count']})
        inventory_rows.append(row)
        total += count
    need(len(first) == 2, 'OCSP_FIRST_TWO_PUBLISHER_ORIGINALS_MISSING',
         'permission_denied')
    if [first.get(ids[0]), first.get(ids[1])] != [
            opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]]]:
        flags[FLAGS[1]] = True
    inv = {'schema': INVENTORY_SCHEMA, 'directory_lineage_id': lineage,
           'real_ec400_report_sha256': parent_sha,
           'real_ec400_verified_inventory_sha256': live[
               'receiver_verified_native_cms_inventory_sha256'],
           'original_ec400_bundle_sha256': b400ref['sha256'],
           'original_ec401_ocsp_bundle_sha256': b401ref['sha256'],
           'outside_first_two_historical_ocsp_shas': [opts[NEW_SCALARS[2]],
                                                       opts[NEW_SCALARS[3]]],
           'epochs': inventory_rows}
    inventory_sha = cdigest(inv)
    if not deriving and inventory_sha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # Detect modification between first and final in-process reading of every
    # evidence original opened by this receiver (in addition to parent audit).
    for path, (initial, cap) in late.items():
        actual = io._read({'path': path, 'sha256': initial},
                          'ec401_final_original_byte_readback', cap, {}, {}, set())
        need(sha(actual) == initial, 'OCSP_OR_PARENT_ORIGINAL_MUTATED',
             'permission_denied')
    for flag in FLAGS[-3:]:
        flags[flag] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': 'derive-historical-ec339-issuer-ocsp-inventory'
                       if deriving else 'audit-historical-ec339-issuer-ocsp',
            'status': next((OUTCOMES[i] for i, k in enumerate(FLAGS) if flags[k]),
                           OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec400_report_sha256': parent_sha,
            'verified_live_ec400_inventory_sha256': live[
                'receiver_verified_native_cms_inventory_sha256'],
            'original_ocsp_bundle_sha256': b401ref['sha256'],
            'receiver_verified_ocsp_inventory_sha256': inventory_sha,
            'verified_joint_parent_cms_crl_and_local_good_ocsp_publishers': total,
            'ocsp_epoch_reviews': output_rows,
            'bounded_local_issuer_ocsp_and_real_parent_consistency':
                not any(flags[k] for k in FLAGS[:5]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{k: False for k in NEGATIVES},
            **({'unsigned_ocsp_evidence_inventory': inv} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)

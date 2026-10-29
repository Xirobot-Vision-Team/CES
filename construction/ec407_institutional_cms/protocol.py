#!/usr/bin/env python3
"""EC407. Verify original independently certificate-signed custody statements.

Unchanged real EC406.audit is obligatory. This verifies *cryptography*, not that a
self-described external issuer is an official/accredited or even independent
institution, nor that its claimed signing time is a qualified timestamp. No
network access, signing, certificate issuance, original edits or PASS path.
"""
from __future__ import annotations

from datetime import timezone
import hashlib
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as original_readers
from ec350_tsa_timestamp import timestamp as tsa
from ec406_custody_witness import protocol as parent

RESULT_SCHEMA = 'ces.ec407.external_custody_original_cms_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec407.unsigned_external_custody_cms_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec407.external_custody_original_cms_denial.v1'
BUNDLE_SCHEMA = 'ces.ec407.original_external_custody_cms_bundle.v1'
ROSTER_SCHEMA = 'ces.ec407.outside_pinned_institutional_certificate_roster.v1'
STATEMENT_SCHEMA = 'ces.ec407.original_institutional_custody_statement.v1'
INVENTORY_SCHEMA = 'ces.ec407.unsigned_external_custody_cms_inventory.v1'
MAX_BUNDLE, MAX_ROSTER = 130_000, 35_000
MAX_CERT, MAX_CRL, MAX_STATEMENT, MAX_CMS = 30_000, 90_000, 18_000, 55_000
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')
OID = re.compile(r'[0-2](?:\.[0-9]+){2,15}\Z')
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS,
                  *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_institutional_cms_bundle_file',
    'expected_historical_ec339_institutional_cms_bundle_sha256',
    'expected_outside_ec407_institutional_roster_sha256',
    'expected_outside_ec407_a_root_certificate_der_sha256',
    'expected_outside_ec407_b_root_certificate_der_sha256',
    'expected_outside_ec407_a_leaf_certificate_der_sha256',
    'expected_outside_ec407_b_leaf_certificate_der_sha256',
    'expected_outside_ec407_first_a_statement_sha256',
    'expected_outside_ec407_first_b_statement_sha256',
    'expected_outside_ec407_first_a_cms_sha256',
    'expected_outside_ec407_first_b_cms_sha256',
    'ec407_institutional_evaluation_utc',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_institutional_cms_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_institutional_cms_epoch_inventory_shas',
     '--historical-ec339-institutional-cms-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_institutional_cms_publisher_counts',
     '--minimum-historical-ec339-joint-institutional-cms-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'unchanged_real_ec406_custody_witness_or_earlier_originals_disputed',
    'outside_institutional_root_leaf_first_epoch_or_whole_original_pins_disagree',
    'one_or_more_later_original_institutional_statements_or_cms_missing',
    'certificate_historical_validity_or_issuer_signed_crl_window_adverse',
    'joint_signed_institutional_and_real_ec406_parent_coverage_incomplete',
    'independent_real_world_institutional_issuer_identity_or_custody_unproven',
    'official_historical_trust_list_qualified_tsa_legal_status_unproven',
    'public_prior_external_originals_global_revocation_worm_final_acceptance_unproven',
)
OUTCOMES = (
    'ec407_real_ec406_and_earlier_original_chain_disputed',
    'ec407_externally_retained_certificate_statement_or_inventory_pins_disagree',
    'ec407_later_signed_institutional_originals_missing',
    'ec407_certificate_or_issuer_signed_crl_historical_window_unresolved',
    'ec407_two_role_signed_institutional_and_parent_joint_coverage_incomplete',
    'ec407_actual_independent_institutional_issuer_and_custody_unproven',
    'ec407_official_trust_list_qualified_tsa_or_judicial_status_unproven',
    'ec407_real_prior_public_custody_global_history_worm_and_acceptance_unproven',
)
NEGATIVES = (
    'caller_pinned_self_signed_root_is_a_government_or_accredited_institution',
    'distinct_certificate_roots_alone_prove_independent_organizational_ownership',
    'cms_signed_signing_time_is_qualified_or_independently_calibrated_utc',
    'issuer_crl_without_external_publication_proves_global_revocation_absence',
    'outside_sha_anchor_proves_real_prior_external_custody_or_dispute_cutoff',
    'certificate_policy_oid_proves_official_trust_registry_or_qualified_tsa_status',
    'signed_statement_repairs_any_missing_or_adverse_real_ec406_parent',
    'cms_custody_signature_proves_pdf_visual_semantics_or_legally_authorized_official',
    'receiver_issued_institutional_certificates_crl_or_signed_cms_evidence',
    'receiver_used_network_private_keys_provider_powershell_git_ci_or_worm_writer',
    'receiver_performed_complete_unmocked_external_ancestry_or_final_acceptance',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec406_original_custody_witness_bundle_original',
                 'outside_institutional_certificate_roster_original', 'epochs'}
ROSTER_FIELDS = {'schema', 'claimed_directory_lineage_id', 'assignments'}
ASSIGNMENT_FIELDS = {'publisher_id', 'institutional_signer_id',
                     'root_certificate_original', 'leaf_certificate_original',
                     'issuer_crl_originals', 'expected_certificate_policy_oid'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
ROLE_FIELDS = {'publisher_id', 'institutional_signer_id',
               'original_custody_statement', 'original_detached_cms'}
STATEMENT_FIELDS = {'schema', 'directory_lineage_id', 'publisher_id',
                    'institutional_signer_id', 'epoch_index', 'sequence',
                    'previous_cms_original_sha256', 'custody_event_id',
                    'ec406_original_accession_sha256', 'ec406_original_witness_sha256',
                    'ec405_original_warc_sha256', 'ec405_original_rfc3161_sha256',
                    'claimed_custody_utc'}


def need(test, code, status='invalid_input'):
    if test is not True:
        raise errors.AnchorError('EC407_' + code, status)


def exact(obj, fields, code):
    need(type(obj) is dict and set(obj) == fields,
         code + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cdigest(obj):
    return parent.cdigest(obj)


def ref(value):
    return parent.ref(value)


def utc(value):
    return parent.utc(value)


def _inputs(opts, deriving):
    required = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        required.update(AUDIT_ONLY)
    need(set(opts) == required, 'COMPLETE_REAL_EC406_AND_INSTITUTIONAL_INPUTS_REQUIRED')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC407_INSTITUTIONAL_BUNDLE')
    for k in (*NEW_SCALARS[2:11], *(AUDIT_ONLY if not deriving else ())):
        need(parent.parent.parent.x509core.valid_sha(opts[k]),
             'OUTSIDE_INSTITUTIONAL_SHA_INVALID')
    need(len({opts[k] for k in NEW_SCALARS[3:11]}) == 8,
         'EIGHT_DISTINCT_EXTERNAL_CERTIFICATE_AND_FIRST_ORIGINAL_SHA_REQUIRED',
         'permission_denied')
    utc(opts[NEW_SCALARS[11]])
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_EC406_EPOCHS_REQUIRED')
    for name in REPEAT_NAMES:
        values = opts[name]
        need(type(values) is list and len(values) == n,
             'EPOCH_INVENTORY_SHA_AND_JOINT_FLOOR_REQUIRED')
        if name.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'INSTITUTIONAL_JOINT_FLOOR_ZERO_TO_TWO_REQUIRED')
        else:
            need(all(parent.parent.parent.x509core.valid_sha(v) for v in values),
                 'INSTITUTIONAL_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code', 'offline_unresolved_exit_code',
              'verified_live_ec405_report_sha256', 'verified_live_ec405_inventory_sha256',
              'original_custody_witness_bundle_sha256',
              'receiver_verified_custody_witness_inventory_sha256',
              'verified_joint_custody_witness_and_real_parent_publishers',
              'custody_witness_epoch_reviews',
              'bounded_local_custody_witness_and_real_ec405_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-custody-witness' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_custody_witness_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_custody_witness_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(parent.parent.parent.x509core.valid_sha(report.get(k)) for k in (
             'verified_live_ec405_report_sha256', 'verified_live_ec405_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('bounded_local_custody_witness_and_real_ec405_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status') == next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
                                     if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'UNCHANGED_REAL_EC406_PARENT_REPORT_INVALID', 'unavailable')
    rows = report.get('custody_witness_epoch_reviews')
    rowfields = {'epoch_index', 'verified_signed_accession_count',
                 'verified_signed_witness_count', 'claimed_times_in_window_count',
                 'joint_signed_custody_witness_and_parent_count',
                 'custody_witness_epoch_inventory_sha256',
                 'real_ec405_parent_joint_warc_timestamp_count'}
    n = len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows) == n and all(
         type(r) is dict and set(r) == rowfields and
         type(r['epoch_index']) is int and r['epoch_index'] == i and
         all(type(r[k]) is int and 0 <= r[k] <= 2 for k in (
             'verified_signed_accession_count', 'verified_signed_witness_count',
             'claimed_times_in_window_count', 'joint_signed_custody_witness_and_parent_count',
             'real_ec405_parent_joint_warc_timestamp_count')) and
         r['joint_signed_custody_witness_and_parent_count'] <=
             r['claimed_times_in_window_count'] <= r['verified_signed_witness_count'] <=
             r['verified_signed_accession_count'] and
         r['joint_signed_custody_witness_and_parent_count'] <=
             r['real_ec405_parent_joint_warc_timestamp_count'] and
         parent.parent.parent.x509core.valid_sha(r['custody_witness_epoch_inventory_sha256'])
         for i, r in enumerate(rows)) and
         type(report.get('verified_joint_custody_witness_and_real_parent_publishers')) is int and
         report['verified_joint_custody_witness_and_real_parent_publishers'] == sum(
             r['joint_signed_custody_witness_and_parent_count'] for r in rows),
         'REAL_EC406_PARENT_COVERAGE_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _cert(raw, name):
    try:
        cert = x509.load_der_x509_certificate(raw)
    except (TypeError, ValueError) as exc:
        raise errors.AnchorError('EC407_' + name + '_MALFORMED_DER',
                                 'permission_denied') from exc
    need(cert.public_bytes(serialization.Encoding.DER) == raw,
         name + '_NONEXACT_DER', 'permission_denied')
    return cert


def _extension(cert, cls, name):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound as exc:
        raise errors.AnchorError('EC407_' + name + '_CERT_EXTENSION_REQUIRED',
                                 'permission_denied') from exc


def _rsa_key(cert, role, *, ca):
    need(all(not ext.critical or ext.oid in (
         ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
         ExtensionOID.CERTIFICATE_POLICIES, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
         ExtensionOID.AUTHORITY_KEY_IDENTIFIER) for ext in cert.extensions),
         role + '_UNSUPPORTED_CRITICAL_CERT_EXTENSION', 'permission_denied')
    bc = _extension(cert, x509.BasicConstraints, role)
    ku = _extension(cert, x509.KeyUsage, role)
    need(bc.ca is ca and (ku.key_cert_sign and ku.crl_sign if ca else
         (ku.digital_signature and not ku.key_cert_sign)),
         role + '_CERTIFICATE_CA_OR_SIGNING_KEY_USAGE_INVALID', 'permission_denied')
    need(cert.extensions.get_extension_for_class(x509.BasicConstraints).critical,
         role + '_CA_CONSTRAINTS_NOT_CRITICAL', 'permission_denied')
    pub = cert.public_key()
    need(isinstance(pub, rsa.RSAPublicKey) and 2048 <= pub.key_size <= 8192,
         role + '_STRICT_RSA2048_TO_8192_REQUIRED', 'permission_denied')
    return pub


def _signed_crls(originals, issuer, leaf, read, used):
    need(type(originals) is list and 1 <= len(originals) <= 4,
         'ONE_TO_FOUR_ORIGINAL_COMPLETE_SIGNED_ISSUER_CRLS_REQUIRED',
         'permission_denied')
    crls, previous_update = [], None
    for source in originals:
        cr = ref(source)
        need(cr['path'] not in used, 'CRL_PATH_ALIASES_OTHER_ORIGINAL',
             'permission_denied')
        used.add(cr['path'])
        raw = read(cr, 'ec407_original_issuer_signed_crl', MAX_CRL)
        try:
            value = x509.load_der_x509_crl(raw)
        except (ValueError, TypeError) as exc:
            raise errors.AnchorError('EC407_INVALID_ISSUER_CRL_DER',
                                     'permission_denied') from exc
        need(value.public_bytes(serialization.Encoding.DER) == raw and
             value.next_update_utc is not None,
             'CRL_NONDER_OR_MISSING_NEXT_UPDATE', 'permission_denied')
        need(not any(ext.oid in (
             ExtensionOID.DELTA_CRL_INDICATOR,
             ExtensionOID.ISSUING_DISTRIBUTION_POINT,
             ExtensionOID.FRESHEST_CRL) for ext in value.extensions),
             'CRL_PARTIAL_DELTA_OR_INDIRECT_SCOPE_UNSUPPORTED',
             'permission_denied')
        need(all(not ext.critical or ext.oid in (
             ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                 for ext in value.extensions),
             'CRL_UNKNOWN_CRITICAL_EXTENSION', 'permission_denied')
        tsa._crl_signed_by(value, issuer)
        need(value.last_update_utc < value.next_update_utc and
             (previous_update is None or value.last_update_utc > previous_update),
             'CRL_NONMONOTONE_UPDATE_SEQUENCE', 'permission_denied')
        previous_update = value.last_update_utc
        crls.append(value)
    return crls


def _crl_covered(crls, leaf, at):
    applicable = [c for c in crls if c.last_update_utc <= at <= c.next_update_utc]
    if not applicable:
        return False
    current = max(applicable, key=lambda c: c.last_update_utc)
    revoked = current.get_revoked_certificate_by_serial_number(leaf.serial_number)
    return revoked is None or revoked.revocation_date_utc > at


def _registry(roster, roles, opts, read, used, forbidden_spkis):
    exact(roster, ROSTER_FIELDS, 'INSTITUTIONAL_ROSTER')
    need(roster['schema'] == ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] ==
             opts['claimed_historical_directory_lineage_id'] and
         type(roster['assignments']) is list and len(roster['assignments']) == 2,
         'INSTITUTIONAL_ROSTER_EXACT_TWO_PUBLISHER_ASSIGNMENTS_REQUIRED',
         'permission_denied')
    pairs, identities, keys = {}, set(), set()
    for assignment in roster['assignments']:
        exact(assignment, ASSIGNMENT_FIELDS, 'INSTITUTIONAL_ASSIGNMENT')
        role, institutional_id = (assignment['publisher_id'],
                                  assignment['institutional_signer_id'])
        need(type(role) is str and role in roles and role not in pairs and
             type(institutional_id) is str and IDENT.fullmatch(institutional_id) and
             institutional_id not in identities and
             type(assignment['expected_certificate_policy_oid']) is str and
             OID.fullmatch(assignment['expected_certificate_policy_oid']) is not None,
             'INSTITUTIONAL_ROLE_ID_AND_POLICY_REQUIRED', 'permission_denied')
        identities.add(institutional_id)
        originals = []
        for field, pos in (('root_certificate_original', 3),
                           ('leaf_certificate_original', 5)):
            r = ref(assignment[field])
            need(r['path'] not in used, 'CERTIFICATE_ORIGINAL_PATH_ALIASES_PARENT',
                 'permission_denied')
            used.add(r['path'])
            blob = read(r, 'ec407_original_'+field, MAX_CERT)
            cert = _cert(blob, field)
            expected = opts[NEW_SCALARS[pos if role == roles[0] else pos+1]]
            need(r['sha256'] == expected and sha(blob) == expected and
                 expected not in keys,
                 'EXTERNALLY_PINNED_CERTIFICATE_DER_SHA_MISMATCH_OR_REUSED',
                 'permission_denied')
            keys.add(expected)
            originals.append(cert)
        root, leaf = originals
        root_pub = _rsa_key(root, 'ROOT', ca=True)
        leaf_pub = _rsa_key(leaf, 'LEAF', ca=False)
        need(root.subject == root.issuer and root.subject != leaf.subject and
             root.serial_number != leaf.serial_number,
             'ROOT_SELF_ISSUED_AND_LEAF_DISTINCT_REQUIRED', 'permission_denied')
        tsa._cert_signed_by(root, root)
        tsa._cert_signed_by(leaf, root)
        need(root_pub.public_bytes(serialization.Encoding.DER,
              serialization.PublicFormat.SubjectPublicKeyInfo) !=
             leaf_pub.public_bytes(serialization.Encoding.DER,
              serialization.PublicFormat.SubjectPublicKeyInfo),
             'ROOT_LEAF_PUBLIC_KEYS_REUSED', 'permission_denied')
        policies = _extension(leaf, x509.CertificatePolicies, 'LEAF')
        need(ObjectIdentifier(assignment['expected_certificate_policy_oid']) in
             {p.policy_identifier for p in policies},
             'LEAF_ORIGINAL_CERTIFICATE_POLICY_OID_MISMATCH',
             'permission_denied')
        root_spki = root_pub.public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
        leaf_spki = leaf_pub.public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
        need(root_spki not in keys and leaf_spki not in keys and
             root_spki not in forbidden_spkis and leaf_spki not in forbidden_spkis,
             'INSTITUTIONAL_RSA_PUBLIC_KEY_REUSED_WITH_ANCESTOR_OR_SIGNER',
             'permission_denied')
        keys.update((root_spki, leaf_spki))
        crls = _signed_crls(assignment['issuer_crl_originals'], root, leaf,
                            read, used)
        pairs[role] = {'id':institutional_id, 'root':root, 'leaf':leaf,
                       'root_sha':opts[NEW_SCALARS[3 if role==roles[0] else 4]],
                       'leaf_sha':opts[NEW_SCALARS[5 if role==roles[0] else 6]],
                       'crls':crls}
    need(set(pairs)==set(roles), 'TWO_PUBLISHER_INSTITUTIONAL_CERTS_REQUIRED',
         'permission_denied')
    return pairs



def _protected_ancestor_signers(opts, earlier406, earlier405, roles, read, doc, used):
    """Reopen genuine EC399/EC405 source signers; disallow disguised key reuse.

    A distinct file path, label, CA name or fingerprint never makes a signer
    independent if its actual SPKI matches an inherited publisher or TSA key.
    Also protect every nested original public key/certificate/CRL path from
    being reused as a supposedly new EC407 institution's original.
    """
    roster406_ref = ref(earlier406['outside_custody_witness_roster_original'])
    custodian_roster = doc(roster406_ref, 'ec407_reopen_original_ec406_signer_roster',
                          parent.MAX_ROSTER)
    exact(custodian_roster, parent.ROSTER_FIELDS, 'REAL_EC406_SIGNER_ROSTER')
    need(roster406_ref['sha256'] == opts[parent.NEW_SCALARS[2]] and
         custodian_roster['schema'] == parent.ROSTER_SCHEMA and
         custodian_roster['claimed_directory_lineage_id'] ==
             opts['claimed_historical_directory_lineage_id'],
         'REAL_EC406_SIGNER_ROSTER_EXTERNAL_SHA_INVALID', 'permission_denied')
    parent.parent._find_ref_paths(custodian_roster, used)
    used.add(roster406_ref['path'])

    tsaref = ref(earlier405['outside_tsa_roster_original'])
    tsadoc = doc(tsaref, 'ec407_reopen_ec405_actual_tsa_registry',
                 parent.parent.MAX_TRUST)
    need(tsaref['sha256'] == opts[parent.parent.NEW_SCALARS[2]],
         'EC405_REAL_TSA_ROSTER_OUTSIDE_PIN_MISMATCH', 'permission_denied')
    used.add(tsaref['path'])
    authorities = parent.parent._trust(tsadoc, roles, opts, read, used)
    parent.parent._find_ref_paths(tsadoc, used)
    forbidden = {authority['root'].public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
        for authority in authorities.values()}

    x509core = parent.parent.parent.x509core
    r399 = {'path':opts[x509core.NEW_SCALARS[0]],
            'sha256':opts[x509core.NEW_SCALARS[1]]}
    prior399 = doc(r399, 'ec407_reopen_real_ec399_certification_bundle',
                   x509core.MAX_BUNDLE)
    exact(prior399, x509core.BUNDLE_FIELDS, 'REAL_EC399_CERTIFICATION_BUNDLE')
    need(prior399['schema'] == x509core.BUNDLE_SCHEMA and
         prior399['claimed_directory_lineage_id'] ==
             opts['claimed_historical_directory_lineage_id'],
         'REAL_EC399_CERTIFICATION_BUNDLE_INVALID', 'permission_denied')
    r399roster = ref(prior399['outside_publisher_roster_original'])
    roster399 = doc(r399roster, 'ec407_reopen_ec399_actual_publisher_roster',
                    x509core.MAX_ROSTER)
    exact(roster399, x509core.ROSTER_FIELDS, 'REAL_EC399_PUBLISHER_ROSTER')
    need(r399roster['sha256'] == opts[x509core.NEW_SCALARS[2]] and
         roster399['schema'] == x509core.ROSTER_SCHEMA and
         type(roster399['publishers']) is list and
         len(roster399['publishers']) == 2 and
         set(p['publisher_id'] for p in roster399['publishers']) == set(roles),
         'REAL_EC399_PUBLISHER_ROSTER_INDEPENDENT_PIN_INVALID',
         'permission_denied')
    for row in roster399['publishers']:
        chain = x509core._chain(row, opts, read)
        forbidden.update(cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
            for cert in chain['certs'])
    used.update((r399['path'],r399roster['path']))
    parent.parent._find_ref_paths(prior399, used)
    parent.parent._find_ref_paths(roster399, used)
    return forbidden

def _cms_verify(original, statement_bytes, original_leaf):
    """Verify strict DER CMS detached RFC5652 SignedData over exact original bytes."""
    try:
        from asn1crypto import cms, x509 as asn1_x509
    except ImportError as exc:
        raise errors.AnchorError('EC407_ASN1CRYPTO_UNAVAILABLE',
                                 'unavailable') from exc
    try:
        ci = cms.ContentInfo.load(original, strict=True)
        need(ci.dump(force=True) == original,
             'CMS_ORIGINAL_DER_MUST_BE_BYTE_CANONICAL', 'permission_denied')
        need(ci['content_type'].native == 'signed_data',
             'CMS_SIGNED_DATA_REQUIRED', 'permission_denied')
        data = ci['content']
        need(data['encap_content_info']['content_type'].native == 'data' and
             data['encap_content_info']['content'].native is None and
             data['crls'].native is None,
             'CMS_MUST_BE_DETACHED_NO_EMBEDDED_CRL', 'permission_denied')
        need(data['version'].native == 'v1' and len(data['signer_infos']) == 1 and
             len(data['digest_algorithms']) == 1 and
             data['digest_algorithms'][0]['algorithm'].native == 'sha256',
             'CMS_ONE_SHA256_SIGNER_ONLY_REQUIRED', 'permission_denied')
        embedded = data['certificates']
        need(embedded.native is not None and len(embedded) == 1 and
             embedded[0].name == 'certificate' and
             sha(embedded[0].chosen.dump()) ==
                 original_leaf.fingerprint(hashes.SHA256()).hex(),
             'CMS_EMBEDDED_LEAF_NOT_EXACT_EXTERNAL_CERT_OR_EXTRA_CERT',
             'permission_denied')
        signer = data['signer_infos'][0]
        old = asn1_x509.Certificate.load(original_leaf.public_bytes(
            serialization.Encoding.DER), strict=True)
        sid = signer['sid']
        need(signer['version'].native == 'v1' and sid.name == 'issuer_and_serial_number' and
             sid.chosen['serial_number'].native == original_leaf.serial_number and
             sid.chosen['issuer'].dump() == old['tbs_certificate']['issuer'].dump() and
             signer['digest_algorithm']['algorithm'].native == 'sha256',
             'CMS_SIGNER_IDENTIFIER_MISMATCH_PINNED_LEAF', 'permission_denied')
        attrs = signer['signed_attrs']
        need(attrs is not None and attrs.native is not None and len(attrs) == 3 and
             len({a['type'].dotted for a in attrs}) == 3 and
             [a.dump() for a in attrs] == sorted(a.dump() for a in attrs),
             'CMS_REQUIRES_EXACT_THREE_CANONICAL_AUTHENTICATED_ATTRS',
             'permission_denied')
        signed_set = attrs.untag().dump(force=True)
        need(signed_set[:1] == b'\x31' and attrs.dump() == b'\xa0' + signed_set[1:],
             'CMS_SIGNED_ATTRIBUTES_MUST_BE_DER_SET', 'permission_denied')
        names = {a['type'].native: a for a in attrs}
        need(set(names) == {'content_type', 'message_digest', 'signing_time'} and
             all(len(a['values']) == 1 for a in attrs) and
             names['content_type']['values'][0].native == 'data' and
             names['message_digest']['values'][0].native == hashlib.sha256(
                 statement_bytes).digest(),
             'CMS_AUTHENTICATED_SOURCE_CONTENT_DIGEST_MISMATCH',
             'permission_denied')
        signed_at = names['signing_time']['values'][0].native
        need(hasattr(signed_at, 'tzinfo') and signed_at.tzinfo is not None and
             signed_at.microsecond == 0,
             'CMS_SIGNING_TIME_CANONICAL_REQUIRED', 'permission_denied')
        signed_at = signed_at.astimezone(timezone.utc)
        signature = signer['signature'].native
        need(type(signature) is bytes and 128 <= len(signature) <= 1024 and
             signer['unsigned_attrs'].native is None and
             signer['signature_algorithm']['algorithm'].native in
                 ('rsassa_pkcs1v15', 'sha256_rsa'),
             'CMS_RSA_SHA256_SIGNATURE_AND_NO_UNSIGNED_ATTRS_REQUIRED',
             'permission_denied')
        original_leaf.public_key().verify(signature, signed_set,
                                         padding.PKCS1v15(), hashes.SHA256())
        return signed_at
    except errors.AnchorError:
        raise
    except (InvalidSignature, ValueError, TypeError, KeyError, IndexError,
            OverflowError, AssertionError) as exc:
        raise errors.AnchorError('EC407_MALFORMED_OR_FORGED_CMS_SIGNED_ORIGINAL',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # REAL, unchanged EC406 -> EC405 -> all older
    live_sha = _parent_report(live, opts)
    lineage = opts['claimed_historical_directory_lineage_id']
    n = len(opts['historical_directory_root_shas'])
    read, doc, late = original_readers._readers()
    b407 = {'path':opts[NEW_SCALARS[0]], 'sha256':opts[NEW_SCALARS[1]]}
    b406 = {'path':opts[parent.NEW_SCALARS[0]], 'sha256':opts[parent.NEW_SCALARS[1]]}
    b405 = {'path':opts[parent.parent.NEW_SCALARS[0]],
            'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    bundle = doc(b407, 'ec407_original_institutional_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'INSTITUTIONAL_BUNDLE')
    rosterref = ref(bundle['outside_institutional_certificate_roster_original'])
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec406_original_custody_witness_bundle_original']==b406 and
         rosterref['sha256']==opts[NEW_SCALARS[2]] and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'BUNDLE_ORIGINAL_EC406_PARENT_AND_EXTERNAL_ROSTER_MISMATCH',
         'permission_denied')
    prior = doc(b406, 'ec407_reopen_real_ec406_bundle', parent.MAX_BUNDLE)
    real405 = doc(b405, 'ec407_reopen_real_ec405_bundle', parent.parent.MAX_BUNDLE)
    exact(prior, parent.BUNDLE_FIELDS, 'REOPEN_EC406_BUNDLE')
    exact(real405, parent.parent.BUNDLE_FIELDS, 'REOPEN_EC405_BUNDLE')
    need(prior['schema']==parent.BUNDLE_SCHEMA and
         real405['schema']==parent.parent.BUNDLE_SCHEMA and
         prior['claimed_directory_lineage_id']==
             real405['claimed_directory_lineage_id']==lineage and
         prior['parent_ec405_original_warc_timestamp_bundle_original']==b405 and
         len(prior['epochs'])==len(real405['epochs'])==n,
         'REAL_EC406_EC405_LINK_AND_EPOCHS_REQUIRED', 'permission_denied')
    used = {b407['path'],b406['path'],b405['path'],rosterref['path']}
    parent.parent._find_ref_paths(prior, used)
    parent.parent._find_ref_paths(real405, used)
    for k in PARENT_SCALARS:
        if k.endswith('_file') and type(opts.get(k)) is str:
            used.add(opts[k])
    roles = sorted(row['publisher_id'] for row in prior['epochs'][0]['publishers'])
    need(len(roles)==2 and len(set(roles))==2,
         'TWO_UNIQUE_REAL_EC406_PUBLISHER_ROLES_REQUIRED', 'permission_denied')
    roster = doc(rosterref, 'ec407_original_outside_institutional_roster',MAX_ROSTER)
    forbidden = _protected_ancestor_signers(opts, prior, real405, roles,
                                            read, doc, used)
    pairs = _registry(roster,roles,opts,read,used,forbidden)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=(not live['bounded_local_custody_witness_and_real_ec405_parent_consistency'] or
                     any(r['joint_signed_custody_witness_and_parent_count']!=2
                         for r in live['custody_witness_epoch_reviews']))
    cutoff=utc(opts[parent.parent.parent.NEW_SCALARS[7]])
    evaluation=utc(opts[NEW_SCALARS[11]])
    first_statements, first_cms = {}, {}
    previous, previous_times, missing, event_ids = {}, {}, set(), set()
    reviews, epoch_inventory, total= [], [], 0
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch,EPOCH_FIELDS,'INSTITUTIONAL_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'INSTITUTIONAL_EPOCH_INDEX_AND_TWO_ROLES_REQUIRED','permission_denied')
        e406,e405=prior['epochs'][i],real405['epochs'][i]
        exact(e406,parent.EPOCH_FIELDS,'REAL_EC406_EPOCH')
        exact(e405,parent.parent.EPOCH_FIELDS,'REAL_EC405_EPOCH')
        need(e406['epoch_index']==e405['epoch_index']==i and
             type(e406['publishers']) is list and len(e406['publishers'])==2 and
             type(e405['publishers']) is list and len(e405['publishers'])==2,
             'REAL_PARENT_EPOCH_STRUCTURE_MISMATCH','permission_denied')
        p406={r['publisher_id']:r for r in e406['publishers']}
        p405={r['publisher_id']:r for r in e405['publishers']}
        need(len(p406)==len(p405)==2 and set(p406)==set(p405)==set(roles),
             'REAL_PARENT_ROLE_SET_MISMATCH', 'permission_denied')
        seen, upcoming=set(),set()
        for row in epoch['publishers']:
            exact(row,ROLE_FIELDS,'INSTITUTIONAL_ROLE')
            role=row['publisher_id']
            need(type(role) is str and role in roles and role not in seen and
                 row['institutional_signer_id']==pairs[role]['id'],
                 'INSTITUTIONAL_ROLE_OR_SIGNER_ID_UNKNOWN_OR_DUPLICATE',
                 'permission_denied')
            seen.add(role)
            for key in ('original_custody_statement','original_detached_cms'):
                if row[key] is None:
                    continue
                r=ref(row[key])
                need(r['path'] not in used and r['path'] not in upcoming,
                     'INSTITUTIONAL_SIGNED_ORIGINAL_PATH_REUSED_OR_ALIASED',
                     'permission_denied')
                upcoming.add(r['path'])
        need(seen==set(roles),'INSTITUTIONAL_EPOCH_ROLES_MISSING','permission_denied')
        valid_count, timely_count, members=0,0,[]
        for role in roles:
            row=next(r for r in epoch['publishers'] if r['publisher_id']==role)
            stmt_ref=ref(row['original_custody_statement']) if row['original_custody_statement'] else None
            cms_ref=ref(row['original_detached_cms']) if row['original_detached_cms'] else None
            if stmt_ref is None or cms_ref is None:
                need(i>0 and stmt_ref is None and cms_ref is None,
                     'FIRST_TWO_STATEMENT_CMS_ORIGINALS_REQUIRED_NO_PARTIAL_PAIR',
                     'permission_denied')
                missing.add(role)
                flags[FLAGS[2]]=True
                members.append({'publisher_id':role, 'institutional_signer_id':pairs[role]['id'],
                                'statement_original_sha256':None,
                                'cms_original_sha256':None,
                                'custody_event_id':None,'claimed_custody_utc':None,
                                'certificate_and_crl_windows_covered':None,
                                'claimed_time_in_source_window':None})
                continue
            need(role not in missing,'MISSING_SIGNED_EPOCH_CANNOT_RESUME',
                 'permission_denied')
            used.add(stmt_ref['path']);used.add(cms_ref['path'])
            prev406,prev405=p406[role],p405[role]
            exact(prev406,parent.ROLE_FIELDS,'REAL_EC406_ROLE')
            exact(prev405,parent.parent.ROLE_FIELDS,'REAL_EC405_ROLE')
            a=ref(prev406['signed_accession_original']) if prev406['signed_accession_original'] else None
            w=ref(prev406['signed_cross_witness_original']) if prev406['signed_cross_witness_original'] else None
            wr=ref(prev405['warc_original']) if prev405['warc_original'] else None
            tok=ref(prev405['rfc3161_original']) if prev405['rfc3161_original'] else None
            need(all(v is not None for v in (a,w,wr,tok)),
                 'INSTITUTIONAL_STATEMENT_REQUIRES_TRUE_EC406_AND_EC405_ORIGINALS',
                 'permission_denied')
            statement_raw=read(stmt_ref,'ec407_actual_original_unsigned_json_statement',
                               MAX_STATEMENT)
            statement=doc(stmt_ref,'ec407_actual_original_institutional_statement',
                          MAX_STATEMENT)
            exact(statement,STATEMENT_FIELDS,'INSTITUTIONAL_SOURCE_STATEMENT')
            expected={'schema':STATEMENT_SCHEMA,'directory_lineage_id':lineage,
                      'publisher_id':role,'institutional_signer_id':pairs[role]['id'],
                      'epoch_index':i,'sequence':i+1,
                      'previous_cms_original_sha256':previous.get(role),
                      'ec406_original_accession_sha256':a['sha256'],
                      'ec406_original_witness_sha256':w['sha256'],
                      'ec405_original_warc_sha256':wr['sha256'],
                      'ec405_original_rfc3161_sha256':tok['sha256']}
            need(all(type(statement.get(k)) is type(v) and statement.get(k)==v
                     for k,v in expected.items()) and
                 type(statement['custody_event_id']) is str and
                 IDENT.fullmatch(statement['custody_event_id']) and
                 statement['custody_event_id'] not in event_ids,
                 'ACTUAL_SIGNED_STATEMENT_REAL_PARENT_SHA_CHAIN_OR_EVENT_ID_INVALID',
                 'permission_denied')
            event_ids.add(statement['custody_event_id'])
            signed_at=_cms_verify(read(cms_ref,'ec407_real_original_detached_cms',MAX_CMS),
                                  statement_raw,pairs[role]['leaf'])
            claimed=utc(statement['claimed_custody_utc'])
            need(claimed==signed_at,
                 'CMS_SIGNED_SIGNING_TIME_MUST_EQUAL_STATEMENT_CLAIM',
                 'permission_denied')
            valid_count+=1
            # Reopen signed prior witness claim for source-relative chronology,
            # not simply an unsigned epoch or SHA asserted by the new statement.
            witness=doc(w,'ec407_reopen_earlier_signed_witness_original',parent.MAX_SIGNED)
            exact(witness,parent.SIGNED_FIELDS,'REAL_EC406_WITNESS')
            need(witness['schema']==parent.WITNESS_SCHEMA and
                 type(witness['claim']) is dict and
                 witness['claim'].get('signed_accession_original_sha256')==a['sha256'],
                 'REAL_EC406_SIGNED_WITNESS_ORIGINAL_SOURCE_MISMATCH',
                 'permission_denied')
            witness_time=utc(witness['claim']['claimed_witness_utc'])
            timely=(witness_time<=claimed<=cutoff and claimed<=evaluation and
                    (role not in previous_times or claimed>=previous_times[role]))
            if not timely:flags[FLAGS[3]]=True
            leaf,root,crls=pairs[role]['leaf'],pairs[role]['root'],pairs[role]['crls']
            valid_at=(root.not_valid_before_utc<=claimed<=root.not_valid_after_utc and
                      leaf.not_valid_before_utc<=claimed<=leaf.not_valid_after_utc and
                      root.not_valid_before_utc<=evaluation<=root.not_valid_after_utc and
                      _crl_covered(crls,leaf,claimed) and _crl_covered(crls,leaf,evaluation))
            if not valid_at:flags[FLAGS[3]]=True
            if timely and valid_at:timely_count+=1
            previous[role]=cms_ref['sha256'];previous_times[role]=claimed
            if i==0:
                first_statements[role]=stmt_ref['sha256']
                first_cms[role]=cms_ref['sha256']
            members.append({'publisher_id':role, 'institutional_signer_id':pairs[role]['id'],
                            'statement_original_sha256':stmt_ref['sha256'],
                            'cms_original_sha256':cms_ref['sha256'],
                            'custody_event_id':statement['custody_event_id'],
                            'claimed_custody_utc':statement['claimed_custody_utc'],
                            'certificate_and_crl_windows_covered':valid_at,
                            'claimed_time_in_source_window':timely})
        parent_joint=live['custody_witness_epoch_reviews'][i][
            'joint_signed_custody_witness_and_parent_count']
        # Never allow a new attestation to credit or repair any incomplete parent.
        joint=timely_count if (not flags[FLAGS[0]] and parent_joint==2) else 0
        if joint != 2:flags[FLAGS[4]]=True
        inv={'epoch_index':i,'publishers':members,
             'verified_original_cms_statement_count':valid_count,
             'historical_crl_and_claimed_window_count':timely_count,
             'joint_real_ec406_and_institutional_cms_count':joint}
        digest=cdigest(inv)
        if (digest!=opts[REPEAT_NAMES[0]][i] or
            joint<opts[REPEAT_NAMES[1]][i]):flags[FLAGS[1]]=True
        epoch_inventory.append(inv)
        reviews.append({'epoch_index':i,'verified_original_cms_statement_count':valid_count,
                        'historical_crl_and_claimed_window_count':timely_count,
                        'joint_real_ec406_and_institutional_cms_count':joint,
                        'institutional_cms_epoch_inventory_sha256':digest,
                        'real_ec406_parent_joint_custody_witness_count':parent_joint})
        total+=joint
    need(len(first_statements)==len(first_cms)==2,
         'FIRST_TWO_GENUINE_INSTITUTIONAL_STATEMENT_CMS_ORIGINALS_REQUIRED',
         'permission_denied')
    for j,key in enumerate(NEW_SCALARS[7:11]):
        actual=(first_statements[roles[j]] if j<2 else first_cms[roles[j-2]])
        if opts[key]!=actual:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
               'verified_real_ec406_report_sha256':live_sha,
               'verified_real_ec406_inventory_sha256':live[
                   'receiver_verified_custody_witness_inventory_sha256'],
               'original_ec406_custody_witness_bundle_sha256':b406['sha256'],
               'original_ec407_institutional_bundle_sha256':b407['sha256'],
               'outside_institutional_roster_sha256':rosterref['sha256'],
               'outside_root_certificate_der_shas':[opts[NEW_SCALARS[3]],opts[NEW_SCALARS[4]]],
               'outside_leaf_certificate_der_shas':[opts[NEW_SCALARS[5]],opts[NEW_SCALARS[6]]],
               'outside_first_statement_shas':[opts[NEW_SCALARS[7]],opts[NEW_SCALARS[8]]],
               'outside_first_cms_shas':[opts[NEW_SCALARS[9]],opts[NEW_SCALARS[10]]],
               'evaluation_utc':opts[NEW_SCALARS[11]],'epochs':epoch_inventory}
    invsha=cdigest(inventory)
    if not deriving and invsha!=opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]]=True
    # Preserve the existing immutable original readback invariant after all
    # cross-epoch processing; no local snapshots are generated as evidence.
    for path,(digest,limit) in late.items():
        reread=io._read({'path':path,'sha256':digest},
                        'ec407_final_original_sha_readback',limit,{},{},set())
        need(sha(reread)==digest,'ORIGINAL_CHANGED_BEFORE_FINAL_READBACK',
             'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command':('derive-historical-ec339-institutional-cms-inventory' if deriving else
                       'audit-historical-ec339-institutional-cms'),
            'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                          OUTCOMES[-1])+'_unresolved',
            'exit_code':2,'offline_unresolved_exit_code':2,
            'verified_live_ec406_report_sha256':live_sha,
            'verified_live_ec406_inventory_sha256':live[
                'receiver_verified_custody_witness_inventory_sha256'],
            'original_institutional_cms_bundle_sha256':b407['sha256'],
            'receiver_verified_institutional_cms_inventory_sha256':invsha,
            'verified_joint_institutional_cms_and_real_parent_publishers':total,
            'institutional_cms_epoch_reviews':reviews,
            'bounded_local_institutional_cms_and_real_ec406_parent_consistency':
                not any(flags[k] for k in FLAGS[:5]),
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **flags,**{k:False for k in NEGATIVES},
            **({'unsigned_institutional_cms_evidence_inventory':inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True,**opts)


def audit(**opts):
    return _engine(False,**opts)
